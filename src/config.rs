//! Konfiguration aus einer TOML-Datei.

use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Deserializer};

use crate::net::IpNet;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub clients: Vec<ClientConfig>,
    #[serde(default)]
    pub users: Vec<UserConfig>,
    #[serde(default)]
    pub accounting: AccountingConfig,
    /// Admin-Oberfläche; fehlt der Abschnitt, ist sie aus.
    #[serde(default)]
    pub admin: Option<AdminConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    /// Adresse der Admin-Oberfläche. Standard nur lokal erreichbar.
    #[serde(default = "default_admin_listen")]
    pub listen: String,
    /// Argon2-Hash des Admin-Passworts (`radius-rs hash-password …`)
    pub password_hash: String,
    #[serde(default = "default_admin_title")]
    pub title: String,
}

fn default_admin_listen() -> String {
    "127.0.0.1:8090".into()
}

fn default_admin_title() -> String {
    "radius-rs Admin".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountingConfig {
    /// Pfad zur SQLite-Datenbank. Leer = Accounting nur loggen.
    #[serde(default = "default_db")]
    pub database: String,
}

impl Default for AccountingConfig {
    fn default() -> Self {
        Self { database: default_db() }
    }
}

fn default_db() -> String {
    "accounting.db".into()
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
/// `address` ist eine einzelne IP (`192.168.1.10`) oder ein Netz (`192.168.1.0/24`).
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub name: String,
    #[serde(deserialize_with = "deserialize_net")]
    pub address: IpNet,
    pub secret: String,
    /// Port, auf dem der NAS Disconnect-Requests annimmt (RFC 5176, Standard 3799)
    #[serde(default = "default_coa_port")]
    pub coa_port: u16,
}

pub fn default_coa_port() -> u16 {
    3799
}

fn deserialize_net<'de, D: Deserializer<'de>>(d: D) -> Result<IpNet, D::Error> {
    let s = String::deserialize(d)?;
    s.parse().map_err(serde::de::Error::custom)
}

/// Alle bekannten NAS-Clients. Bei überlappenden Einträgen gewinnt der
/// spezifischste (längster Präfix), wie bei FreeRADIUS.
#[derive(Debug, Clone, Default)]
pub struct Clients(Vec<ClientConfig>);

impl Clients {
    pub fn new(mut clients: Vec<ClientConfig>) -> Self {
        clients.sort_by_key(|c| std::cmp::Reverse(c.address.prefix()));
        Self(clients)
    }

    pub fn find(&self, ip: &IpAddr) -> Option<&ClientConfig> {
        self.0.iter().find(|c| c.address.contains(ip))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
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

fn default_auth_addr() -> String {
    "0.0.0.0:1812".into()
}
fn default_acct_addr() -> String {
    "0.0.0.0:1813".into()
}
fn default_true() -> bool {
    true
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        use anyhow::Context;
        let text = std::fs::read_to_string(path).with_context(|| {
            format!(
                "Konfiguration '{}' nicht gefunden oder nicht lesbar. Tipp: config.example.toml nach config.toml kopieren.",
                path.display()
            )
        })?;
        toml::from_str(&text).with_context(|| format!("Fehler in der Konfiguration '{}'", path.display()))
    }

    pub fn client_list(&self) -> Clients {
        Clients::new(self.clients.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(name: &str, addr: &str) -> ClientConfig {
        ClientConfig {
            name: name.into(),
            address: addr.parse().unwrap(),
            secret: "s".into(),
            coa_port: 3799,
        }
    }

    #[test]
    fn most_specific_client_wins() {
        let c = Clients::new(vec![client("netz", "10.0.0.0/8"), client("ap-1", "10.1.2.3")]);
        assert_eq!(c.find(&"10.1.2.3".parse().unwrap()).unwrap().name, "ap-1");
        assert_eq!(c.find(&"10.9.9.9".parse().unwrap()).unwrap().name, "netz");
        assert!(c.find(&"192.168.0.1".parse().unwrap()).is_none());
    }

    #[test]
    fn parses_address_forms_from_toml() {
        let cfg: Config = toml::from_str(
            r#"
            [server]
            [[clients]]
            name = "einzeln"
            address = "127.0.0.1"
            secret = "a"
            [[clients]]
            name = "docker"
            address = "172.28.0.0/16"
            secret = "b"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.client_list().len(), 2);

        let bad: Result<Config, _> =
            toml::from_str("[server]\n[[clients]]\nname='x'\naddress='10.0.0.0/40'\nsecret='s'");
        assert!(bad.is_err());
    }
}
