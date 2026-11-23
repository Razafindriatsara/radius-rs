//! Konfiguration aus einer TOML-Datei.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub clients: Vec<ClientConfig>,
    #[serde(default)]
    pub users: Vec<UserConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_auth_addr")]
    pub auth_listen: String,
    #[serde(default = "default_acct_addr")]
    pub acct_listen: String,
    /// Access-Requests ohne gültigen Message-Authenticator verwerfen (BlastRADIUS-Schutz).
    #[serde(default = "default_true")]
    pub require_message_authenticator: bool,
}

/// Ein NAS (Access Point, Switch, VPN-Gateway), der Anfragen schicken darf.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub name: String,
    pub address: IpAddr,
    pub secret: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    pub name: String,
    /// Argon2-Hash im PHC-Format, z.B. erzeugt mit `radius-rs hash-password`.
    pub password_hash: String,
    #[serde(default)]
    pub session_timeout: Option<u32>,
    #[serde(default)]
    pub reply_message: Option<String>,
}

fn default_auth_addr() -> String { "0.0.0.0:1812".into() }
fn default_acct_addr() -> String { "0.0.0.0:1813".into() }
fn default_true() -> bool { true }

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    pub fn client_secrets(&self) -> HashMap<IpAddr, ClientConfig> {
        self.clients.iter().map(|c| (c.address, c.clone())).collect()
    }
}
