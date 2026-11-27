//! Eingangsportal (Captive Portal) für radius-rs.
//!
//! Konfiguration über Umgebungsvariablen:
//!   PORTAL_LISTEN        Adresse der Weboberfläche   (Standard 0.0.0.0:8080)
//!   PORTAL_TITLE         Überschrift                 (Standard "Gäste-WLAN")
//!   RADIUS_SERVER        Auth-Server                 (Standard 127.0.0.1:1812)
//!   RADIUS_ACCT_SERVER   Accounting-Server           (Standard 127.0.0.1:1813)
//!   RADIUS_SECRET        Shared Secret               (Standard testing123)
//!   NAS_IDENTIFIER       Name gegenüber dem Server   (Standard radius-portal)
//!   PORTAL_SECURE_COOKIE 1 = Cookie nur über HTTPS
//!   PORTAL_MAX_FAILURES  Fehlversuche pro IP in 5 Minuten (Standard 5)
//!   PORTAL_COA_LISTEN    UDP-Adresse für Disconnect-Requests (Standard 0.0.0.0:3799, leer = aus)

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ansi = std::io::IsTerminal::is_terminal(&std::io::stdout());
    tracing_subscriber::fmt().with_target(false).with_ansi(ansi).init();
    if matches!(std::env::args().nth(1).as_deref(), Some("-V" | "--version")) {
        println!("radius-portal {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    radius_rs::portal::run(radius_rs::portal::PortalConfig::from_env()).await
}
