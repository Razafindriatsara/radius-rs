//! radius-rs: ein schlanker RADIUS-Server (RFC 2865 / RFC 2866) in Rust.
//!
//! Module:
//! - [`packet`]     Codec für RADIUS-Pakete und Attribute (TLV)
//! - [`admin`]      Admin-Oberfläche (Sitzungen, Benutzer, Gast-Zugänge)
//! - [`accounting`] Speicherung der Accounting-Sessions in SQLite
//! - [`dedup`]      Erkennung doppelter Requests (RFC 5080)
//! - [`attributes`] Dictionary der unterstützten Attribut-Typen
//! - [`crypto`]     PAP-Passwortverschlüsselung, Authenticators, Message-Authenticator
//! - [`config`]     Konfiguration (Clients/Shared Secrets, Benutzer)
//! - [`client`]     Asynchroner RADIUS-Client (NAS-Seite), genutzt vom Eingangsportal
//! - [`coa`]        Disconnect-Requests nach RFC 5176
//! - [`auth`]       Authentifizierungs-Backend
//! - [`net`]        IP-Netze (CIDR) für die Zuordnung von NAS-Clients
//! - [`handler`]    Protokoll-Logik: Request rein, Response raus
//! - [`portal`]     Eingangsportal (Captive Portal) mit Weboberfläche
//! - [`users`]      Benutzerverwaltung in SQLite, Gast-Zugänge
//! - [`server`]     Async-UDP-Server (tokio)

pub mod accounting;
pub mod admin;
pub mod attributes;
pub mod auth;
pub mod client;
pub mod coa;
pub mod config;
pub mod crypto;
pub mod dedup;
pub mod handler;
pub mod net;
pub mod packet;
pub mod portal;
pub mod server;
pub mod users;
pub mod web;
