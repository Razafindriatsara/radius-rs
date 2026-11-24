//! Async-UDP-Server. Jeder Port (Auth 1812, Accounting 1813) läuft in einer eigenen Task.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::auth::Authenticator;
use crate::config::{ClientConfig, Clients};
use crate::dedup::{DedupCache, Key, Lookup};
use crate::handler::Handler;
use crate::packet::MAX_PACKET_LEN;

#[derive(Clone, Copy)]
pub enum Service {
    Auth,
    Acct,
}

/// Wie lange Antworten für Duplikate aufbewahrt werden. NAS-Geräte wiederholen
/// typischerweise nach 3–5 s, maximal ein paar Mal.
const DEDUP_TTL: Duration = Duration::from_secs(30);
const DEDUP_MAX_ENTRIES: usize = 65_536;

pub async fn serve<A: Authenticator + 'static>(
    addr: &str,
    service: Service,
    handler: Arc<Handler<A>>,
    clients: Arc<Clients>,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Kann {addr} nicht öffnen ({e}). Läuft schon ein anderer Server auf dem Port?"))?;
    serve_socket(Arc::new(socket), service, handler, clients).await
}

/// Wie [`serve`], aber mit bereits gebundenem Socket (praktisch für Tests mit Port 0).
pub async fn serve_socket<A: Authenticator + 'static>(
    socket: Arc<UdpSocket>,
    service: Service,
    handler: Arc<Handler<A>>,
    clients: Arc<Clients>,
) -> anyhow::Result<()> {
    tracing::info!(addr = %socket.local_addr()?, "lausche");
    let dedup = Arc::new(DedupCache::new(DEDUP_TTL, DEDUP_MAX_ENTRIES));

    let mut buf = vec![0u8; MAX_PACKET_LEN];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let data = buf[..n].to_vec();

        // Nur bekannte NAS-Clients bekommen eine Antwort.
        let Some(client) = clients.find(&peer.ip()).cloned() else {
            tracing::warn!(%peer, "Paket von unbekanntem Client verworfen");
            continue;
        };

        let Some(key) = Key::from_datagram(peer, &data) else {
            tracing::warn!(%peer, len = n, "zu kurzes Paket verworfen");
            continue;
        };
        match dedup.lookup(&key) {
            Lookup::New => {}
            Lookup::InProgress => {
                tracing::debug!(%peer, id = key.identifier, "Duplikat während Verarbeitung verworfen");
                continue;
            }
            Lookup::Cached(resp) => {
                tracing::info!(%peer, id = key.identifier, "Duplikat: sende gespeicherte Antwort erneut");
                let _ = socket.send_to(&resp, peer).await;
                continue;
            }
        }

        let socket = socket.clone();
        let handler = handler.clone();
        let dedup = dedup.clone();
        tokio::spawn(async move {
            respond(&socket, peer, data, client, service, handler, dedup, key).await;
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn respond<A: Authenticator + 'static>(
    socket: &UdpSocket,
    peer: SocketAddr,
    data: Vec<u8>,
    client: ClientConfig,
    service: Service,
    handler: Arc<Handler<A>>,
    dedup: Arc<DedupCache>,
    key: Key,
) {
    // Argon2 und SQLite blockieren. Damit sie die Async-Worker nicht ausbremsen,
    // läuft die Protokoll-Logik im Blocking-Threadpool von tokio.
    let secret = client.secret.clone();
    let nas_ip = peer.ip().to_string();
    let result = tokio::task::spawn_blocking(move || match service {
        Service::Auth => handler.handle_auth(&data, secret.as_bytes()),
        Service::Acct => handler.handle_acct(&data, secret.as_bytes(), &nas_ip),
    })
    .await;
    let Ok(result) = result else {
        tracing::error!(%peer, "Handler-Task abgebrochen");
        dedup.forget(&key);
        return;
    };
    match result {
        Ok(resp) => {
            dedup.complete(key, resp.clone());
            if let Err(e) = socket.send_to(&resp, peer).await {
                tracing::error!(%peer, error = %e, "Senden fehlgeschlagen");
            }
        }
        Err(reason) => {
            dedup.forget(&key);
            tracing::warn!(%peer, nas = client.name, ?reason, "Paket verworfen");
        }
    }
}
