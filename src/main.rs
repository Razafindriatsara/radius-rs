use std::path::PathBuf;
use std::sync::Arc;

use radius_rs::auth::{hash_password, StaticUsers};
use radius_rs::config::Config;
use radius_rs::handler::Handler;
use radius_rs::server::{serve, Service};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_target(false).init();

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("hash-password") {
        let pw = args.get(2).ok_or_else(|| anyhow::anyhow!("Aufruf: radius-rs hash-password <passwort>"))?;
        println!("{}", hash_password(pw)?);
        return Ok(());
    }

    let path = PathBuf::from(args.get(1).map(String::as_str).unwrap_or("config.toml"));
    let config = Config::load(&path)?;
    tracing::info!(clients = config.clients.len(), users = config.users.len(), "Konfiguration geladen");

    let clients = Arc::new(config.client_secrets());
    let handler = Arc::new(Handler {
        auth: StaticUsers::new(config.users.clone()),
        require_message_authenticator: config.server.require_message_authenticator,
    });

    tokio::select! {
        r = serve(&config.server.auth_listen, Service::Auth, handler.clone(), clients.clone()) => r?,
        r = serve(&config.server.acct_listen, Service::Acct, handler.clone(), clients.clone()) => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("beende"),
    }
    Ok(())
}
