//! Minimaler RADIUS-Testclient (PAP + Message-Authenticator).
//!
//! Aufruf:
//!   radius-client <benutzer> <passwort> [server:port] [secret]
//!   radius-client status [server:port] [secret]
//!
//! Standard: 127.0.0.1:1812, Secret "testing123".

use std::net::UdpSocket;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use md5::{Digest, Md5};
use radius_rs::attributes::{self, *};
use radius_rs::crypto;
use radius_rs::packet::{Code, Packet};

fn main() {
    if let Err(e) = run() {
        eprintln!("Fehler: {e}");
        std::process::exit(2);
    }
}

fn run() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let status_mode = args.first().map(String::as_str) == Some("status");

    let (user, password, rest) = if status_mode {
        (None, None, &args[1..])
    } else if args.len() >= 2 {
        (Some(args[0].as_str()), Some(args[1].as_str()), &args[2..])
    } else {
        anyhow::bail!(
            "Aufruf: radius-client <benutzer> <passwort> [server:port] [secret]\n       radius-client status [server:port] [secret]"
        );
    };
    let server = rest.first().map(String::as_str).unwrap_or("127.0.0.1:1812");
    let secret = rest.get(1).map(String::as_str).unwrap_or("testing123").as_bytes();

    // Request Authenticator: muss unvorhersehbar sein. Für einen Testclient reicht
    // ein Hash aus Zeit und Prozess-ID. Ein produktiver Client nutzt einen CSPRNG.
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let ra: [u8; 16] = Md5::new()
        .chain_update(nanos.to_be_bytes())
        .chain_update(std::process::id().to_be_bytes())
        .finalize()
        .into();
    let id = (nanos & 0xff) as u8;

    let code = if status_mode { Code::StatusServer } else { Code::AccessRequest };
    let mut req = Packet::new(code, id, ra);
    req.add(MESSAGE_AUTHENTICATOR, vec![0u8; 16]);
    if let (Some(u), Some(p)) = (user, password) {
        req.add(USER_NAME, u.as_bytes().to_vec());
        req.add(USER_PASSWORD, crypto::encrypt_user_password(p.as_bytes(), secret, &ra));
        req.add(NAS_IDENTIFIER, b"radius-client".to_vec());
    }
    let mut bytes = req.encode()?;
    crypto::sign_request_message_authenticator(&mut bytes, secret);

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(3)))?;
    println!("Sende {:?} (ID {id}) an {server} ...", code);
    let start = Instant::now();
    sock.send_to(&bytes, server)?;

    let mut buf = [0u8; 4096];
    let n = match sock.recv(&mut buf) {
        Ok(n) => n,
        Err(_) => {
            println!("Keine Antwort nach 3 s.");
            println!("Mögliche Ursachen: falsches Secret, Client-IP nicht in config.toml, Server läuft nicht, Firewall.");
            std::process::exit(1);
        }
    };
    let elapsed = start.elapsed();
    let raw = &buf[..n];
    let resp = Packet::decode(raw)?;

    // Response Authenticator prüfen
    let mut check = raw.to_vec();
    crypto::sign_response(&mut check, &ra, secret);
    let auth_ok = check == raw;

    // Message-Authenticator prüfen (mit Request Authenticator im Header)
    let mut ma_buf = raw.to_vec();
    ma_buf[4..20].copy_from_slice(&ra);
    let ma_ok = crypto::verify_message_authenticator(&ma_buf, secret);

    println!("Antwort: {:?} (ID {}) in {:.1} ms", resp.code, resp.identifier, elapsed.as_secs_f64() * 1000.0);
    println!("  Response Authenticator: {}", if auth_ok { "gültig" } else { "UNGÜLTIG" });
    println!("  Message-Authenticator:  {}", if ma_ok { "gültig" } else { "fehlt/UNGÜLTIG" });
    for a in &resp.attributes {
        if a.typ == MESSAGE_AUTHENTICATOR {
            continue;
        }
        let value = match a.typ {
            REPLY_MESSAGE => String::from_utf8_lossy(&a.value).into_owned(),
            _ if a.value.len() == 4 => u32::from_be_bytes(a.value[..4].try_into().unwrap()).to_string(),
            _ => format!("{:02x?}", a.value),
        };
        println!("  {}: {}", attributes::name(a.typ), value);
    }

    let accepted = resp.code == Code::AccessAccept && auth_ok && ma_ok;
    std::process::exit(if accepted { 0 } else { 1 });
}
