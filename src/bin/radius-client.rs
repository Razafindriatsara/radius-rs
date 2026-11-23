//! Minimaler RADIUS-Testclient.
//!
//! Aufruf:
//!   radius-client <benutzer> <passwort> [server:port] [secret]
//!   radius-client status [server:port] [secret]
//!   radius-client acct <start|interim|stop> <benutzer> <session-id> [server:port] [secret]
//!
//! Standard: 127.0.0.1:1812 (bzw. :1813 für acct), Secret "testing123".
//! Exit-Code 0 = Erfolg (Accept bzw. Accounting bestätigt), 1 = Reject/keine Antwort, 2 = Aufruffehler.

use std::net::UdpSocket;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use md5::{Digest, Md5};
use radius_rs::attributes::{self, *};
use radius_rs::crypto;
use radius_rs::packet::{Code, Packet};

const USAGE: &str = "\
Aufruf:
  radius-client <benutzer> <passwort> [server:port] [secret]
  radius-client status [server:port] [secret]
  radius-client acct <start|interim|stop> <benutzer> <session-id> [server:port] [secret]";

enum Mode<'a> {
    Auth {
        user: &'a str,
        password: &'a str,
    },
    Status,
    Acct {
        status: u32,
        user: &'a str,
        session_id: &'a str,
    },
}

fn main() {
    match run() {
        Ok(true) => std::process::exit(0),
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("Fehler: {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    }
}

fn run() -> anyhow::Result<bool> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();

    let (mode, rest) = match a.as_slice() {
        ["status", rest @ ..] => (Mode::Status, rest),
        ["acct", status, user, session_id, rest @ ..] => {
            let status = match *status {
                "start" => 1,
                "stop" => 2,
                "interim" => 3,
                other => {
                    anyhow::bail!("unbekannter Accounting-Typ '{other}' (start, interim, stop)")
                }
            };
            (
                Mode::Acct {
                    status,
                    user,
                    session_id,
                },
                rest,
            )
        }
        ["acct", ..] => anyhow::bail!("zu wenige Argumente für acct"),
        [user, password, rest @ ..] => (Mode::Auth { user, password }, rest),
        _ => anyhow::bail!("zu wenige Argumente"),
    };
    let default_server = if matches!(mode, Mode::Acct { .. }) {
        "127.0.0.1:1813"
    } else {
        "127.0.0.1:1812"
    };
    let server = rest.first().copied().unwrap_or(default_server);
    let secret = rest.get(1).copied().unwrap_or("testing123").as_bytes();

    // Request Authenticator: muss unvorhersehbar sein. Für einen Testclient reicht
    // ein Hash aus Zeit und Prozess-ID. Ein produktiver Client nutzt einen CSPRNG.
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let ra: [u8; 16] = Md5::new()
        .chain_update(nanos.to_be_bytes())
        .chain_update(std::process::id().to_be_bytes())
        .finalize()
        .into();
    let id = (nanos & 0xff) as u8;

    let bytes = match &mode {
        Mode::Auth { user, password } => {
            let mut req = Packet::new(Code::AccessRequest, id, ra);
            req.add(MESSAGE_AUTHENTICATOR, vec![0u8; 16]);
            req.add(USER_NAME, user.as_bytes().to_vec());
            req.add(
                USER_PASSWORD,
                crypto::encrypt_user_password(password.as_bytes(), secret, &ra),
            );
            req.add(NAS_IDENTIFIER, b"radius-client".to_vec());
            let mut b = req.encode()?;
            crypto::sign_request_message_authenticator(&mut b, secret);
            b
        }
        Mode::Status => {
            let mut req = Packet::new(Code::StatusServer, id, ra);
            req.add(MESSAGE_AUTHENTICATOR, vec![0u8; 16]);
            let mut b = req.encode()?;
            crypto::sign_request_message_authenticator(&mut b, secret);
            b
        }
        Mode::Acct {
            status,
            user,
            session_id,
        } => {
            let mut req = Packet::new(Code::AccountingRequest, id, [0u8; 16]);
            req.add_u32(ACCT_STATUS_TYPE, *status);
            req.add(USER_NAME, user.as_bytes().to_vec());
            req.add(ACCT_SESSION_ID, session_id.as_bytes().to_vec());
            req.add(NAS_IDENTIFIER, b"radius-client".to_vec());
            req.add(FRAMED_IP_ADDRESS, vec![10, 0, 0, 42]);
            if *status != 1 {
                // Demo-Werte: Dauer und Datenmengen abhängig von der aktuellen Zeit
                let secs = (nanos / 1_000_000_000 % 3600) as u32 + 60;
                req.add_u32(ACCT_SESSION_TIME, secs);
                req.add_u32(ACCT_INPUT_OCTETS, secs * 12_345);
                req.add_u32(ACCT_OUTPUT_OCTETS, secs * 98_765);
            }
            if *status == 2 {
                req.add_u32(ACCT_TERMINATE_CAUSE, 1); // User-Request
            }
            let mut b = req.encode()?;
            crypto::sign_accounting_request(&mut b, secret);
            b
        }
    };
    // Bei Accounting ist der Request Authenticator das, was im Paket steht.
    let ra: [u8; 16] = bytes[4..20].try_into()?;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(3)))?;
    println!("Sende {:?} (ID {id}) an {server} ...", Code::from(bytes[0]));
    let start = Instant::now();
    sock.send_to(&bytes, server)?;

    let mut buf = [0u8; 4096];
    let n = match sock.recv(&mut buf) {
        Ok(n) => n,
        Err(_) => {
            println!("Keine Antwort nach 3 s.");
            println!(
                "Mögliche Ursachen: falsches Secret, Client-IP nicht in config.toml, Server läuft nicht, Firewall."
            );
            return Ok(false);
        }
    };
    let elapsed = start.elapsed();
    let raw = &buf[..n];
    let resp = Packet::decode(raw)?;

    // Response Authenticator prüfen
    let mut check = raw.to_vec();
    crypto::sign_response(&mut check, &ra, secret);
    let auth_ok = check == raw;

    println!(
        "Antwort: {:?} (ID {}) in {:.1} ms",
        resp.code,
        resp.identifier,
        elapsed.as_secs_f64() * 1000.0
    );
    println!(
        "  Response Authenticator: {}",
        if auth_ok { "gültig" } else { "UNGÜLTIG" }
    );

    // Message-Authenticator prüfen (mit Request Authenticator im Header).
    // Accounting-Antworten enthalten keinen.
    let ma_ok = if matches!(mode, Mode::Acct { .. }) {
        true
    } else {
        let mut ma_buf = raw.to_vec();
        ma_buf[4..20].copy_from_slice(&ra);
        let ok = crypto::verify_message_authenticator(&ma_buf, secret);
        println!(
            "  Message-Authenticator:  {}",
            if ok { "gültig" } else { "fehlt/UNGÜLTIG" }
        );
        ok
    };

    for a in &resp.attributes {
        if a.typ == MESSAGE_AUTHENTICATOR {
            continue;
        }
        let value = match a.typ {
            REPLY_MESSAGE => String::from_utf8_lossy(&a.value).into_owned(),
            _ if a.value.len() == 4 => u32::from_be_bytes(a.value[..4].try_into()?).to_string(),
            _ => format!("{:02x?}", a.value),
        };
        println!("  {}: {}", attributes::name(a.typ), value);
    }

    let expected = if matches!(mode, Mode::Acct { .. }) {
        Code::AccountingResponse
    } else {
        Code::AccessAccept
    };
    Ok(resp.code == expected && auth_ok && ma_ok)
}
