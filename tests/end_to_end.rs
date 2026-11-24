//! End-to-End-Tests: echter UDP-Server auf localhost (zufälliger Port), Client schickt Requests.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use radius_rs::accounting::AccountingStore;
use radius_rs::attributes::*;
use radius_rs::auth::{AuthResult, Authenticator, StaticUsers, hash_password};
use radius_rs::config::{ClientConfig, Clients, UserConfig};
use radius_rs::crypto;
use radius_rs::handler::Handler;
use radius_rs::packet::{Code, Packet};
use radius_rs::server::{Service, serve_socket};
use tokio::net::UdpSocket;

const SECRET: &str = "testing123";

/// Zählt, wie oft wirklich ein Passwort geprüft wurde (für den Duplikat-Test).
struct Counting {
    inner: StaticUsers,
    calls: Arc<AtomicUsize>,
}

impl Authenticator for Counting {
    fn authenticate_pap(&self, user: &str, password: &[u8]) -> AuthResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.authenticate_pap(user, password)
    }
}

struct TestServer {
    auth: SocketAddr,
    acct: SocketAddr,
    handler: Arc<Handler<Counting>>,
    auth_calls: Arc<AtomicUsize>,
}

async fn start_server() -> TestServer {
    let clients = Arc::new(Clients::new(vec![ClientConfig {
        name: "test-nas".into(),
        address: "127.0.0.0/8".parse().unwrap(),
        secret: SECRET.into(),
    }]));
    let calls = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(Handler {
        auth: Counting {
            inner: StaticUsers::new(vec![UserConfig {
                name: "martin".into(),
                password_hash: hash_password("geheim123").unwrap(),
                session_timeout: Some(3600),
                reply_message: Some("Willkommen".into()),
            }]),
            calls: calls.clone(),
        },
        require_message_authenticator: true,
        accounting: Some(AccountingStore::in_memory().unwrap()),
    });

    let auth_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let acct_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (auth, acct) = (auth_sock.local_addr().unwrap(), acct_sock.local_addr().unwrap());
    tokio::spawn(serve_socket(auth_sock, Service::Auth, handler.clone(), clients.clone()));
    tokio::spawn(serve_socket(acct_sock, Service::Acct, handler.clone(), clients));
    TestServer {
        auth,
        acct,
        handler,
        auth_calls: calls,
    }
}

fn build_request(id: u8, user: &str, password: &str, with_ma: bool) -> (Vec<u8>, [u8; 16]) {
    let ra: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(id));
    let mut p = Packet::new(Code::AccessRequest, id, ra);
    if with_ma {
        p.add(MESSAGE_AUTHENTICATOR, vec![0u8; 16]);
    }
    p.add(USER_NAME, user.as_bytes().to_vec());
    p.add(
        USER_PASSWORD,
        crypto::encrypt_user_password(password.as_bytes(), SECRET.as_bytes(), &ra),
    );
    let mut bytes = p.encode().unwrap();
    if with_ma {
        assert!(crypto::sign_request_message_authenticator(
            &mut bytes,
            SECRET.as_bytes()
        ));
    }
    (bytes, ra)
}

fn build_acct(id: u8, status: u32, session: &str, extra: &[(u8, u32)]) -> Vec<u8> {
    let mut p = Packet::new(Code::AccountingRequest, id, [0u8; 16]);
    p.add_u32(ACCT_STATUS_TYPE, status);
    p.add(USER_NAME, b"martin".to_vec());
    p.add(ACCT_SESSION_ID, session.as_bytes().to_vec());
    p.add(NAS_IDENTIFIER, b"ap-flur".to_vec());
    for (t, v) in extra {
        p.add_u32(*t, *v);
    }
    let mut b = p.encode().unwrap();
    crypto::sign_accounting_request(&mut b, SECRET.as_bytes());
    b
}

async fn send_from(sock: &UdpSocket, server: SocketAddr, data: &[u8], wait_ms: u64) -> Option<Vec<u8>> {
    sock.send_to(data, server).await.unwrap();
    let mut buf = [0u8; 4096];
    match tokio::time::timeout(Duration::from_millis(wait_ms), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// Antwort erwartet: großzügiges Timeout, damit langsame CI-Rechner nicht scheitern.
async fn send(server: SocketAddr, data: &[u8]) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send_from(&sock, server, data, 5000).await
}

/// Verwerfen erwartet: kurzes Timeout reicht.
async fn send_expect_drop(server: SocketAddr, data: &[u8]) -> bool {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send_from(&sock, server, data, 500).await.is_none()
}

/// Prüft den Response Authenticator so, wie ein NAS es tut.
fn verify_response(resp: &[u8], ra: &[u8; 16]) -> bool {
    let mut check = resp.to_vec();
    crypto::sign_response(&mut check, ra, SECRET.as_bytes());
    check == resp
}

#[tokio::test]
async fn accept_reject_and_drop() {
    let s = start_server().await;

    // Richtiges Passwort -> Access-Accept mit Session-Timeout
    let (req, ra) = build_request(1, "martin", "geheim123", true);
    let resp = send(s.auth, &req).await.expect("keine Antwort");
    let p = Packet::decode(&resp).unwrap();
    assert_eq!(p.code, Code::AccessAccept);
    assert_eq!(p.identifier, 1);
    assert_eq!(p.get(SESSION_TIMEOUT), Some(&3600u32.to_be_bytes()[..]));
    assert!(verify_response(&resp, &ra));

    // Falsches Passwort -> Access-Reject
    let (req, ra) = build_request(2, "martin", "falsch", true);
    let resp = send(s.auth, &req).await.expect("keine Antwort");
    assert_eq!(Packet::decode(&resp).unwrap().code, Code::AccessReject);
    assert!(verify_response(&resp, &ra));

    // Ohne Message-Authenticator -> stillschweigend verworfen (BlastRADIUS-Schutz)
    let (req, _) = build_request(3, "martin", "geheim123", false);
    assert!(send_expect_drop(s.auth, &req).await);

    // Müll -> verworfen, Server läuft weiter
    assert!(send_expect_drop(s.auth, &[0xff; 7]).await);
    let (req, _) = build_request(4, "martin", "geheim123", true);
    assert!(send(s.auth, &req).await.is_some());
}

#[tokio::test]
async fn duplicate_request_gets_cached_response() {
    let s = start_server().await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (req, _) = build_request(9, "martin", "geheim123", true);

    let first = send_from(&sock, s.auth, &req, 5000).await.expect("keine Antwort");
    // Gleiche Quelle, gleicher Identifier, gleicher Authenticator = Wiederholung durch den NAS
    let second = send_from(&sock, s.auth, &req, 5000)
        .await
        .expect("keine Antwort auf Duplikat");

    assert_eq!(first, second, "Duplikat muss identische Antwort bekommen");
    assert_eq!(
        s.auth_calls.load(Ordering::SeqCst),
        1,
        "Passwort darf nur einmal geprüft werden"
    );

    // Neuer Request (anderer Identifier) wird wieder geprüft
    let (req, _) = build_request(10, "martin", "geheim123", true);
    send_from(&sock, s.auth, &req, 5000).await.expect("keine Antwort");
    assert_eq!(s.auth_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn accounting_is_stored() {
    let s = start_server().await;

    let resp = send(s.acct, &build_acct(1, 1, "sess-42", &[]))
        .await
        .expect("keine Antwort auf Start");
    assert_eq!(Packet::decode(&resp).unwrap().code, Code::AccountingResponse);

    let stop = build_acct(
        2,
        2,
        "sess-42",
        &[
            (ACCT_SESSION_TIME, 600),
            (ACCT_INPUT_OCTETS, 1000),
            (ACCT_OUTPUT_OCTETS, 2000),
            (ACCT_TERMINATE_CAUSE, 1),
        ],
    );
    send(s.acct, &stop).await.expect("keine Antwort auf Stop");

    let sessions = s.handler.accounting.as_ref().unwrap().recent(10).unwrap();
    assert_eq!(sessions.len(), 1);
    let sess = &sessions[0];
    assert_eq!(sess.session_id, "sess-42");
    assert_eq!(sess.nas, "ap-flur");
    assert_eq!(sess.session_time, 600);
    assert_eq!(sess.output_octets, 2000);
    assert!(sess.stopped_at.is_some());

    // Falsches Secret -> verworfen, nichts gespeichert
    let mut bad = build_acct(3, 1, "boese", &[]);
    crypto::sign_accounting_request(&mut bad, b"falsch");
    assert!(send_expect_drop(s.acct, &bad).await);
    assert_eq!(s.handler.accounting.as_ref().unwrap().recent(10).unwrap().len(), 1);
}
