//! End-to-End-Test: echter UDP-Server auf localhost, Client schickt Access-Requests.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use radius_rs::attributes::*;
use radius_rs::auth::{hash_password, StaticUsers};
use radius_rs::config::{ClientConfig, UserConfig};
use radius_rs::crypto;
use radius_rs::handler::Handler;
use radius_rs::packet::{Code, Packet};
use radius_rs::server::{serve, Service};
use tokio::net::UdpSocket;

const SECRET: &str = "testing123";

fn build_request(id: u8, user: &str, password: &str, with_ma: bool) -> (Vec<u8>, [u8; 16]) {
    let ra: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(id));
    let mut p = Packet::new(Code::AccessRequest, id, ra);
    if with_ma {
        p.add(MESSAGE_AUTHENTICATOR, vec![0u8; 16]);
    }
    p.add(USER_NAME, user.as_bytes().to_vec());
    p.add(USER_PASSWORD, crypto::encrypt_user_password(password.as_bytes(), SECRET.as_bytes(), &ra));
    let mut bytes = p.encode().unwrap();
    if with_ma {
        assert!(crypto::sign_request_message_authenticator(&mut bytes, SECRET.as_bytes()));
    }
    (bytes, ra)
}

async fn start_server(addr: &str) {
    let mut clients = HashMap::new();
    clients.insert(
        "127.0.0.1".parse().unwrap(),
        ClientConfig { name: "test-nas".into(), address: "127.0.0.1".parse().unwrap(), secret: SECRET.into() },
    );
    let handler = Arc::new(Handler {
        auth: StaticUsers::new(vec![UserConfig {
            name: "martin".into(),
            password_hash: hash_password("geheim123").unwrap(),
            session_timeout: Some(3600),
            reply_message: Some("Willkommen".into()),
        }]),
        require_message_authenticator: true,
    });
    let addr = addr.to_string();
    tokio::spawn(async move { serve(&addr, Service::Auth, handler, Arc::new(clients)).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;
}

async fn send(server: &str, data: &[u8]) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(data, server).await.unwrap();
    let mut buf = [0u8; 4096];
    match tokio::time::timeout(Duration::from_millis(500), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// Prüft den Response Authenticator so, wie ein NAS es tut.
fn verify_response(resp: &[u8], ra: &[u8; 16]) -> bool {
    let mut check = resp.to_vec();
    crypto::sign_response(&mut check, ra, SECRET.as_bytes());
    check == resp
}

#[tokio::test]
async fn accept_reject_and_drop() {
    let server = "127.0.0.1:18120";
    start_server(server).await;

    // Richtiges Passwort -> Access-Accept mit Session-Timeout
    let (req, ra) = build_request(1, "martin", "geheim123", true);
    let resp = send(server, &req).await.expect("keine Antwort");
    let p = Packet::decode(&resp).unwrap();
    assert_eq!(p.code, Code::AccessAccept);
    assert_eq!(p.identifier, 1);
    assert_eq!(p.get(SESSION_TIMEOUT), Some(&3600u32.to_be_bytes()[..]));
    assert!(verify_response(&resp, &ra));

    // Falsches Passwort -> Access-Reject
    let (req, ra) = build_request(2, "martin", "falsch", true);
    let resp = send(server, &req).await.expect("keine Antwort");
    assert_eq!(Packet::decode(&resp).unwrap().code, Code::AccessReject);
    assert!(verify_response(&resp, &ra));

    // Ohne Message-Authenticator -> stillschweigend verworfen (BlastRADIUS-Schutz)
    let (req, _) = build_request(3, "martin", "geheim123", false);
    assert!(send(server, &req).await.is_none());

    // Müll -> verworfen, Server läuft weiter
    assert!(send(server, &[0xff; 7]).await.is_none());
    let (req, _) = build_request(4, "martin", "geheim123", true);
    assert!(send(server, &req).await.is_some());
}
