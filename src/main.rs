use std::path::{Path, PathBuf};
use std::sync::Arc;

use radius_rs::accounting::{AccountingStore, terminate_cause_name};
use radius_rs::auth::{StaticUsers, hash_password};
use radius_rs::config::Config;
use radius_rs::handler::Handler;
use radius_rs::server::{Service, serve};

const USAGE: &str = "\
radius-rs: RADIUS-Server

Aufruf:
  radius-rs [config.toml]                 Server starten
  radius-rs hash-password <passwort>      Argon2-Hash für die Konfiguration erzeugen
  radius-rs sessions [config.toml] [n]    Die letzten n Accounting-Sessions anzeigen (Standard 20)
  radius-rs --version                     Version anzeigen";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Farben nur im Terminal, nicht in Docker-Logs oder Dateien
    let ansi = std::io::IsTerminal::is_terminal(&std::io::stdout());
    tracing_subscriber::fmt().with_target(false).with_ansi(ansi).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("-V" | "--version") => {
            println!("radius-rs {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("-h" | "--help" | "help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some("hash-password") => {
            let pw = args
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("Aufruf: radius-rs hash-password <passwort>"))?;
            println!("{}", hash_password(pw)?);
            Ok(())
        }
        Some("sessions") => {
            let config = Config::load(Path::new(args.get(1).map(String::as_str).unwrap_or("config.toml")))?;
            let limit = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
            print_sessions(&config, limit)
        }
        path => run_server(PathBuf::from(path.unwrap_or("config.toml"))).await,
    }
}

async fn run_server(path: PathBuf) -> anyhow::Result<()> {
    let config = Config::load(&path)?;
    tracing::info!(
        clients = config.clients.len(),
        users = config.users.len(),
        "Konfiguration geladen"
    );

    let accounting = if config.accounting.database.is_empty() {
        tracing::info!("Accounting ohne Datenbank (nur Log)");
        None
    } else {
        tracing::info!(database = config.accounting.database, "Accounting-Datenbank geöffnet");
        Some(AccountingStore::open(Path::new(&config.accounting.database))?)
    };

    let clients = Arc::new(config.client_list());
    let handler = Arc::new(Handler {
        auth: StaticUsers::new(config.users.clone()),
        require_message_authenticator: config.server.require_message_authenticator,
        accounting,
    });

    tokio::select! {
        r = serve(&config.server.auth_listen, Service::Auth, handler.clone(), clients.clone()) => r?,
        r = serve(&config.server.acct_listen, Service::Acct, handler.clone(), clients.clone()) => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("beende"),
    }
    Ok(())
}

fn print_sessions(config: &Config, limit: u32) -> anyhow::Result<()> {
    anyhow::ensure!(
        !config.accounting.database.is_empty(),
        "In der Konfiguration ist keine Accounting-Datenbank gesetzt."
    );
    let store = AccountingStore::open(Path::new(&config.accounting.database))?;
    let sessions = store.recent(limit)?;
    if sessions.is_empty() {
        println!("Noch keine Sessions gespeichert.");
        return Ok(());
    }
    println!(
        "{:<14} {:<12} {:<14} {:<8} {:>9} {:>12} {:>12}  Ende",
        "Session", "Benutzer", "NAS", "Status", "Dauer", "Download", "Upload"
    );
    for s in sessions {
        let status = if s.stopped_at.is_some() { "beendet" } else { "aktiv" };
        let ende = s.terminate_cause.map(terminate_cause_name).unwrap_or("");
        println!(
            "{:<14} {:<12} {:<14} {:<8} {:>9} {:>12} {:>12}  {}",
            truncate(&s.session_id, 14),
            truncate(&s.user, 12),
            truncate(&s.nas, 14),
            status,
            duration(s.session_time),
            bytes(s.output_octets), // Output aus Sicht des NAS = Download des Nutzers
            bytes(s.input_octets),
            ende
        );
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n - 1).collect::<String>() + "…"
    }
}

fn duration(secs: i64) -> String {
    format!("{}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

fn bytes(b: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}
