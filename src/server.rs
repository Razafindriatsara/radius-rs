//! Async-UDP-Server. Jeder Port (Auth 1812, Accounting 1813) läuft in einer eigenen Task.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::auth::Authenticator;
use crate::config::ClientConfig;
use crate::handler::Handler;
use crate::packet::MAX_PACKET_LEN;

#[derive(Clone, Copy)]
pub enum Service {
    Auth,
    Acct,
}

pub async fn serve<A: Authenticator + 'static>(
    addr: &str,
    service: Service,
    handler: Arc<Handler<A>>,
    clients: Arc<HashMap<IpAddr, ClientConfig>>,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    tracing::info!(%addr, "lausche");

    let mut buf = vec![0u8; MAX_PACKET_LEN];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let data = buf[..n].to_vec();

        // Nur bekannte NAS-Clients bekommen eine Antwort.
        let Some(client) = clients.get(&peer.ip()).cloned() else {
            tracing::warn!(%peer, "Paket von unbekanntem Client verworfen");
            continue;
        };

        let socket = socket.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            respond(&socket, peer, &data, &client, service, &handler).await;
        });
    }
}

async fn respond<A: Authenticator>(
    socket: &UdpSocket,
    peer: SocketAddr,
    data: &[u8],
    client: &ClientConfig,
    service: Service,
    handler: &Handler<A>,
) {
    let secret = client.secret.as_bytes();
    let result = match service {
        Service::Auth => handler.handle_auth(data, secret),
        Service::Acct => handler.handle_acct(data, secret),
    };
    match result {
        Ok(resp) => {
            if let Err(e) = socket.send_to(&resp, peer).await {
                tracing::error!(%peer, error = %e, "Senden fehlgeschlagen");
            }
        }
        Err(reason) => tracing::warn!(%peer, nas = client.name, ?reason, "Paket verworfen"),
    }
}
