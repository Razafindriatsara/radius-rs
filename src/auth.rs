//! Authentifizierungs-Backend. Aktuell: Benutzer aus der Konfiguration mit Argon2-Hashes.
//! Später austauschbar gegen SQLite/Postgres oder LDAP über den Trait [`Authenticator`].
//!
//! Hinweis: PAP erlaubt gehashte Passwörter auf dem Server, CHAP dagegen braucht
//! das Klartext-Passwort. Dieser Zielkonflikt ist der Grund, warum hier nur PAP
//! implementiert ist.

use std::collections::HashMap;

use argon2::{Argon2, PasswordHash, PasswordVerifier};

use crate::config::UserConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Accept { session_timeout: Option<u32>, reply_message: Option<String> },
    Reject,
}

pub trait Authenticator: Send + Sync {
    fn authenticate_pap(&self, user: &str, password: &[u8]) -> AuthResult;
}

pub struct StaticUsers {
    users: HashMap<String, UserConfig>,
}

impl StaticUsers {
    pub fn new(users: Vec<UserConfig>) -> Self {
        Self { users: users.into_iter().map(|u| (u.name.clone(), u)).collect() }
    }
}

impl Authenticator for StaticUsers {
    fn authenticate_pap(&self, user: &str, password: &[u8]) -> AuthResult {
        let Some(u) = self.users.get(user) else {
            return AuthResult::Reject;
        };
        let Ok(hash) = PasswordHash::new(&u.password_hash) else {
            tracing::error!(user, "ungültiger Passwort-Hash in der Konfiguration");
            return AuthResult::Reject;
        };
        if Argon2::default().verify_password(password, &hash).is_ok() {
            AuthResult::Accept { session_timeout: u.session_timeout, reply_message: u.reply_message.clone() }
        } else {
            AuthResult::Reject
        }
    }
}

/// Erzeugt einen Argon2-Hash im PHC-Format für die Konfigurationsdatei.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    use argon2::PasswordHasher;
    let hash = Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow::anyhow!("Hashing fehlgeschlagen: {e}"))?;
    Ok(hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_correct_and_rejects_wrong_password() {
        let users = StaticUsers::new(vec![UserConfig {
            name: "martin".into(),
            password_hash: hash_password("geheim123").unwrap(),
            session_timeout: Some(3600),
            reply_message: None,
        }]);
        assert!(matches!(users.authenticate_pap("martin", b"geheim123"), AuthResult::Accept { .. }));
        assert_eq!(users.authenticate_pap("martin", b"falsch"), AuthResult::Reject);
        assert_eq!(users.authenticate_pap("niemand", b"geheim123"), AuthResult::Reject);
    }
}
