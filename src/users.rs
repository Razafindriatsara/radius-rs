//! Benutzerverwaltung in SQLite (über die Admin-Oberfläche pflegbar, ohne Neustart).
//!
//! [`Directory`] fragt zuerst die Datenbank und dann die Benutzer aus der
//! Konfigurationsdatei. So funktionieren bestehende Installationen unverändert weiter.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use rusqlite::{Connection, OptionalExtension, params};

use crate::auth::{AuthResult, Authenticator, StaticUsers, hash_password};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
    name            TEXT    PRIMARY KEY,
    password_hash   TEXT    NOT NULL,
    session_timeout INTEGER,
    reply_message   TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    expires_at      INTEGER,
    is_guest        INTEGER NOT NULL DEFAULT 0,
    note            TEXT,
    created_at      INTEGER NOT NULL
);
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub session_timeout: Option<u32>,
    pub reply_message: Option<String>,
    pub enabled: bool,
    pub expires_at: Option<i64>,
    pub is_guest: bool,
    pub note: Option<String>,
    pub created_at: i64,
}

impl User {
    pub fn expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|e| now >= e)
    }
}

/// Daten für einen neuen Benutzer.
#[derive(Debug, Clone, Default)]
pub struct NewUser {
    pub name: String,
    pub password: String,
    pub session_timeout: Option<u32>,
    pub reply_message: Option<String>,
    pub expires_at: Option<i64>,
    pub is_guest: bool,
    pub note: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("Benutzername ungültig (1 bis 64 Zeichen: Buchstaben, Ziffern, . _ - @)")]
    InvalidName,
    #[error("Passwort muss mindestens 8 Zeichen haben")]
    WeakPassword,
    #[error("Benutzer existiert bereits")]
    Exists,
    #[error("Benutzer nicht gefunden")]
    NotFound,
    #[error("Datenbankfehler: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("{0}")]
    Other(String),
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 64 && n.chars().all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c))
}

pub struct UserStore {
    conn: Mutex<Connection>,
}

impl UserStore {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn in_memory() -> anyhow::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> anyhow::Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn create(&self, u: &NewUser) -> Result<(), UserError> {
        if !valid_name(&u.name) {
            return Err(UserError::InvalidName);
        }
        if u.password.chars().count() < 8 {
            return Err(UserError::WeakPassword);
        }
        let hash = hash_password(&u.password).map_err(|e| UserError::Other(e.to_string()))?;
        let conn = self.conn.lock().expect("DB-Mutex vergiftet");
        let r = conn.execute(
            "INSERT INTO users (name, password_hash, session_timeout, reply_message, expires_at, is_guest, note, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![u.name, hash, u.session_timeout, u.reply_message, u.expires_at, u.is_guest, u.note, now()],
        );
        match r {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => {
                Err(UserError::Exists)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn list(&self) -> Result<Vec<User>, UserError> {
        let conn = self.conn.lock().expect("DB-Mutex vergiftet");
        let mut stmt = conn.prepare(
            "SELECT name, session_timeout, reply_message, enabled, expires_at, is_guest, note, created_at
             FROM users ORDER BY is_guest, name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(User {
                name: r.get(0)?,
                session_timeout: r.get(1)?,
                reply_message: r.get(2)?,
                enabled: r.get(3)?,
                expires_at: r.get(4)?,
                is_guest: r.get(5)?,
                note: r.get(6)?,
                created_at: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn exists(&self, name: &str) -> Result<bool, UserError> {
        let conn = self.conn.lock().expect("DB-Mutex vergiftet");
        Ok(conn.prepare("SELECT 1 FROM users WHERE name = ?1")?.exists([name])?)
    }

    pub fn set_enabled(&self, name: &str, enabled: bool) -> Result<(), UserError> {
        self.update(name, "UPDATE users SET enabled = ?2 WHERE name = ?1", enabled)
    }

    pub fn set_password(&self, name: &str, password: &str) -> Result<(), UserError> {
        if password.chars().count() < 8 {
            return Err(UserError::WeakPassword);
        }
        let hash = hash_password(password).map_err(|e| UserError::Other(e.to_string()))?;
        self.update(name, "UPDATE users SET password_hash = ?2 WHERE name = ?1", hash)
    }

    pub fn delete(&self, name: &str) -> Result<(), UserError> {
        let conn = self.conn.lock().expect("DB-Mutex vergiftet");
        if conn.execute("DELETE FROM users WHERE name = ?1", [name])? == 0 {
            return Err(UserError::NotFound);
        }
        Ok(())
    }

    /// Entfernt abgelaufene Gast-Zugänge, die älter als `grace` Sekunden sind.
    pub fn purge_expired_guests(&self, grace: i64) -> Result<usize, UserError> {
        let conn = self.conn.lock().expect("DB-Mutex vergiftet");
        Ok(conn.execute(
            "DELETE FROM users WHERE is_guest = 1 AND expires_at IS NOT NULL AND expires_at < ?1",
            [now() - grace],
        )?)
    }

    fn update(&self, name: &str, sql: &str, value: impl rusqlite::ToSql) -> Result<(), UserError> {
        let conn = self.conn.lock().expect("DB-Mutex vergiftet");
        if conn.execute(sql, params![name, value])? == 0 {
            return Err(UserError::NotFound);
        }
        Ok(())
    }

    /// Prüft einen Benutzer. `None` = in der Datenbank unbekannt (dann fragt [`Directory`] die Konfiguration).
    fn check(&self, user: &str, password: &[u8]) -> Option<AuthResult> {
        let row = {
            let conn = self.conn.lock().expect("DB-Mutex vergiftet");
            conn.query_row(
                "SELECT password_hash, session_timeout, reply_message, enabled, expires_at FROM users WHERE name = ?1",
                [user],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<u32>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, bool>(3)?,
                        r.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .optional()
            .ok()
            .flatten()?
        };
        let (hash, timeout, reply, enabled, expires) = row;
        let now = now();
        let ok = PasswordHash::new(&hash).is_ok_and(|h| Argon2::default().verify_password(password, &h).is_ok());
        if !ok || !enabled || expires.is_some_and(|e| now >= e) {
            return Some(AuthResult::Reject);
        }
        // Die Sitzung endet spätestens, wenn der Zugang abläuft.
        let left = expires.map(|e| (e - now).clamp(1, u32::MAX as i64) as u32);
        let session_timeout = match (timeout, left) {
            (Some(t), Some(l)) => Some(t.min(l)),
            (t, l) => t.or(l),
        };
        Some(AuthResult::Accept {
            session_timeout,
            reply_message: reply,
        })
    }
}

/// Benutzerquelle des Servers: Datenbank (falls vorhanden), dann Konfigurationsdatei.
pub struct Directory {
    pub db: Option<Arc<UserStore>>,
    pub config: StaticUsers,
}

impl Authenticator for Directory {
    fn authenticate_pap(&self, user: &str, password: &[u8]) -> AuthResult {
        if let Some(r) = self.db.as_ref().and_then(|db| db.check(user, password)) {
            return r;
        }
        self.config.authenticate_pap(user, password)
    }
}

/// Erzeugt einen Gast-Zugang mit zufälligem Namen und Passwort ohne verwechselbare Zeichen (0/O, 1/l/I).
pub fn generate_guest_credentials() -> Result<(String, String), UserError> {
    const ALPHA: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut buf = [0u8; 14];
    getrandom::fill(&mut buf).map_err(|_| UserError::Other("Zufallsgenerator nicht verfügbar".into()))?;
    let pick = |b: u8| ALPHA[(b as usize) % ALPHA.len()] as char;
    let name: String = buf[..4].iter().map(|b| pick(*b)).collect();
    let pw: String = buf[4..].iter().map(|b| pick(*b)).collect();
    Ok((format!("gast-{name}"), pw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UserConfig;

    fn store_with(u: NewUser) -> Directory {
        let db = Arc::new(UserStore::in_memory().unwrap());
        db.create(&u).unwrap();
        Directory {
            db: Some(db),
            config: StaticUsers::new(vec![UserConfig {
                name: "alt".into(),
                password_hash: hash_password("altpasswort").unwrap(),
                session_timeout: None,
                reply_message: None,
            }]),
        }
    }

    fn user(name: &str) -> NewUser {
        NewUser {
            name: name.into(),
            password: "geheim1234".into(),
            session_timeout: Some(600),
            ..Default::default()
        }
    }

    #[test]
    fn db_user_config_user_and_unknown() {
        let d = store_with(user("anna"));
        assert!(matches!(
            d.authenticate_pap("anna", b"geheim1234"),
            AuthResult::Accept {
                session_timeout: Some(600),
                ..
            }
        ));
        assert_eq!(d.authenticate_pap("anna", b"falsch"), AuthResult::Reject);
        assert!(matches!(
            d.authenticate_pap("alt", b"altpasswort"),
            AuthResult::Accept { .. }
        ));
        assert_eq!(d.authenticate_pap("niemand", b"x"), AuthResult::Reject);
    }

    #[test]
    fn disabled_and_expired_users_are_rejected() {
        let d = store_with(user("bob"));
        let db = d.db.clone().unwrap();
        db.set_enabled("bob", false).unwrap();
        assert_eq!(d.authenticate_pap("bob", b"geheim1234"), AuthResult::Reject);
        db.set_enabled("bob", true).unwrap();
        assert!(matches!(
            d.authenticate_pap("bob", b"geheim1234"),
            AuthResult::Accept { .. }
        ));

        let mut g = user("gast-alt");
        g.expires_at = Some(now() - 10);
        db.create(&g).unwrap();
        assert_eq!(d.authenticate_pap("gast-alt", b"geheim1234"), AuthResult::Reject);
    }

    #[test]
    fn session_timeout_capped_by_expiry() {
        let mut g = user("gast-x");
        g.session_timeout = Some(86_400);
        g.expires_at = Some(now() + 120);
        let d = store_with(g);
        match d.authenticate_pap("gast-x", b"geheim1234") {
            AuthResult::Accept {
                session_timeout: Some(t),
                ..
            } => assert!((115..=120).contains(&t), "{t}"),
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn validation_duplicates_password_change_delete() {
        let db = UserStore::in_memory().unwrap();
        assert!(matches!(
            db.create(&NewUser {
                name: "a b".into(),
                password: "geheim1234".into(),
                ..Default::default()
            }),
            Err(UserError::InvalidName)
        ));
        assert!(matches!(
            db.create(&NewUser {
                name: "kurz".into(),
                password: "1234".into(),
                ..Default::default()
            }),
            Err(UserError::WeakPassword)
        ));
        db.create(&user("carl")).unwrap();
        assert!(matches!(db.create(&user("carl")), Err(UserError::Exists)));
        db.set_password("carl", "neuespasswort").unwrap();
        let d = Directory {
            db: Some(Arc::new(db)),
            config: StaticUsers::new(vec![]),
        };
        assert!(matches!(
            d.authenticate_pap("carl", b"neuespasswort"),
            AuthResult::Accept { .. }
        ));
        let db = d.db.unwrap();
        db.delete("carl").unwrap();
        assert!(matches!(db.delete("carl"), Err(UserError::NotFound)));
    }

    #[test]
    fn guest_credentials_are_unambiguous() {
        let (n, p) = generate_guest_credentials().unwrap();
        assert!(n.starts_with("gast-") && n.len() == 9 && valid_name(&n));
        assert_eq!(p.len(), 10);
        assert!(!p.contains(['0', 'o', '1', 'l', 'i']));
    }
}
