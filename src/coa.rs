//! Disconnect-Messages nach RFC 5176: Der Server bittet einen NAS, eine
//! laufende Sitzung zu beenden (z.B. „Trennen“ in der Admin-Oberfläche).
//!
//! Der Request Authenticator wird wie bei Accounting gebildet
//! (MD5 über das Paket mit 16 Nullbytes und das Secret), die Antwort
//! (ACK/NAK) wie ein Response Authenticator.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::attributes::*;
use crate::client::{ClientError, random_bytes};
use crate::crypto;
use crate::packet::{Code, Packet};

/// RFC 5176 Abschnitt 3.5: Error-Cause „Session Context Not Found“
pub const ERROR_SESSION_NOT_FOUND: u32 = 503;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectResult {
    /// Der NAS hat die Sitzung beendet.
    Ack,
    /// Der NAS hat abgelehnt, mit Error-Cause, falls angegeben.
    Nak(Option<u32>),
}

/// Sendet einen Disconnect-Request und wartet auf ACK oder NAK.
pub async fn send_disconnect(
    nas: SocketAddr,
    secret: &str,
    user: &str,
    session_id: &str,
    timeout: Duration,
) -> Result<DisconnectResult, ClientError> {
    let id = random_bytes::<1>()?[0];
    let mut req = Packet::new(Code::DisconnectRequest, id, [0u8; 16]);
    req.add(USER_NAME, user.as_bytes().to_vec());
    req.add(ACCT_SESSION_ID, session_id.as_bytes().to_vec());
    let mut bytes = req
        .encode()
        .map_err(|_| ClientError::InvalidResponse("Anfrage zu groß"))?;
    crypto::sign_accounting_request(&mut bytes, secret.as_bytes());
    let ra: [u8; 16] = bytes[4..20].try_into().expect("16 Byte");

    let sock = UdpSocket::bind(if nas.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
    sock.connect(nas).await?;
    let mut buf = vec![0u8; 4096];
    for _ in 0..2 {
        sock.send(&bytes).await?;
        let Ok(Ok(n)) = tokio::time::timeout(timeout, sock.recv(&mut buf)).await else {
            continue;
        };
        let raw = &buf[..n];
        let resp = Packet::decode(raw).map_err(|_| ClientError::InvalidResponse("fehlerhaftes Paket"))?;
        if resp.identifier != id {
            continue;
        }
        let mut check = raw.to_vec();
        crypto::sign_response(&mut check, &ra, secret.as_bytes());
        if check != raw {
            return Err(ClientError::InvalidResponse(
                "Antwort des NAS nicht gültig signiert (falsches Secret?)",
            ));
        }
        return match resp.code {
            Code::DisconnectAck => Ok(DisconnectResult::Ack),
            Code::DisconnectNak => Ok(DisconnectResult::Nak(
                resp.get(ERROR_CAUSE)
                    .and_then(|v| v.try_into().ok())
                    .map(u32::from_be_bytes),
            )),
            _ => Err(ClientError::InvalidResponse("unerwarteter Antwortcode")),
        };
    }
    Err(ClientError::Timeout)
}

/// NAS-Seite: prüft einen Disconnect-Request und baut die Antwort.
/// `end_session(user, acct_session_id)` beendet die Sitzung und meldet, ob es sie gab.
/// `None` = ungültiges Paket (falsches Secret, falscher Code): still verwerfen.
pub fn handle_disconnect(
    data: &[u8],
    secret: &str,
    end_session: impl FnOnce(Option<String>, Option<String>) -> bool,
) -> Option<Vec<u8>> {
    let req = Packet::decode(data).ok()?;
    if req.code != Code::DisconnectRequest || !crypto::verify_accounting_request(data, secret.as_bytes()) {
        return None;
    }
    let found = end_session(req.get_string(USER_NAME), req.get_string(ACCT_SESSION_ID));
    let mut resp = Packet::new(
        if found {
            Code::DisconnectAck
        } else {
            Code::DisconnectNak
        },
        req.identifier,
        [0; 16],
    );
    if !found {
        resp.add_u32(ERROR_CAUSE, ERROR_SESSION_NOT_FOUND);
    }
    let mut encoded = resp.encode().ok()?;
    crypto::sign_response(&mut encoded, &req.authenticator, secret.as_bytes());
    Some(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disconnect_ack_nak_and_wrong_secret() {
        let nas = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = nas.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let (n, peer) = nas.recv_from(&mut buf).await.unwrap();
                let reply = handle_disconnect(&buf[..n], "geheim", |user, sid| {
                    user.as_deref() == Some("martin") && sid.as_deref() == Some("s-1")
                });
                if let Some(r) = reply {
                    nas.send_to(&r, peer).await.unwrap();
                }
            }
        });
        let t = Duration::from_millis(300);
        assert_eq!(
            send_disconnect(addr, "geheim", "martin", "s-1", t).await.unwrap(),
            DisconnectResult::Ack
        );
        assert_eq!(
            send_disconnect(addr, "geheim", "martin", "gibt-es-nicht", t)
                .await
                .unwrap(),
            DisconnectResult::Nak(Some(ERROR_SESSION_NOT_FOUND))
        );
        // Falsches Secret: der NAS verwirft still, der Server bekommt eine Zeitüberschreitung
        assert!(matches!(
            send_disconnect(addr, "falsch", "martin", "s-1", t).await,
            Err(ClientError::Timeout)
        ));
    }
}
