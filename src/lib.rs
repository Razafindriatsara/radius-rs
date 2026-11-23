//! radius-rs: ein schlanker RADIUS-Server (RFC 2865 / RFC 2866) in Rust.
//!
//! Module:
//! - [`packet`]     Codec für RADIUS-Pakete und Attribute (TLV)
//! - [`attributes`] Dictionary der unterstützten Attribut-Typen
//! - [`crypto`]     PAP-Passwortverschlüsselung, Authenticators, Message-Authenticator
//! - [`config`]     Konfiguration (Clients/Shared Secrets, Benutzer)
//! - [`auth`]       Authentifizierungs-Backend
//! - [`handler`]    Protokoll-Logik: Request rein, Response raus
//! - [`server`]     Async-UDP-Server (tokio)

pub mod attributes;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod handler;
pub mod packet;
pub mod server;
