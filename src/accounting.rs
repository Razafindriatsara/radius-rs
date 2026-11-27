//! Speichert Accounting-Sessions (RFC 2866) in SQLite.
//!
//! Eine Session wird über `Acct-Session-Id` + NAS identifiziert:
//! - Start          legt sie an
//! - Interim-Update aktualisiert Zähler (Zeit, Bytes)
//! - Stop           schließt sie ab, inkl. Grund (Acct-Terminate-Cause)
//!
//! Die Aufrufe laufen im Blocking-Threadpool (siehe server.rs), deshalb reicht
//! eine synchrone Verbindung hinter einem Mutex.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};

use crate::attributes::*;
use crate::packet::Packet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusType {
    Start,
    Stop,
    InterimUpdate,
    AccountingOn,
    AccountingOff,
    Unknown(u32),
}

impl From<u32> for StatusType {
    fn from(v: u32) -> Self {
        match v {
            1 => Self::Start,
            2 => Self::Stop,
            3 => Self::InterimUpdate,
            7 => Self::AccountingOn,
            8 => Self::AccountingOff,
            x => Self::Unknown(x),
        }
    }
}

/// Die für eine Session relevanten Felder, aus einem Accounting-Request gelesen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub status: StatusType,
    pub session_id: String,
    pub user: String,
    pub nas: String,
    /// Absender-IP des Accounting-Pakets, Ziel für Disconnect-Requests (RFC 5176)
    pub nas_addr: Option<String>,
    pub framed_ip: Option<String>,
    pub session_time: Option<u32>,
    pub input_octets: Option<u64>,
    pub output_octets: Option<u64>,
    pub terminate_cause: Option<u32>,
}

fn u32_attr(p: &Packet, t: u8) -> Option<u32> {
    p.get(t).and_then(|v| v.try_into().ok()).map(u32::from_be_bytes)
}

/// Zähler mit Gigawords zusammensetzen: echte Bytes = Gigawords * 2^32 + Octets.
fn octets(p: &Packet, low: u8, high: u8) -> Option<u64> {
    let lo = u32_attr(p, low)? as u64;
    let hi = u32_attr(p, high).unwrap_or(0) as u64;
    Some((hi << 32) | lo)
}

impl Record {
    pub fn from_packet(p: &Packet, nas_ip: &str) -> Option<Self> {
        let status = StatusType::from(u32_attr(p, ACCT_STATUS_TYPE)?);
        let nas = p
            .get_string(NAS_IDENTIFIER)
            .or_else(|| {
                p.get(NAS_IP_ADDRESS)
                    .filter(|v| v.len() == 4)
                    .map(|v| format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3]))
            })
            .unwrap_or_else(|| nas_ip.to_string());
        Some(Self {
            status,
            session_id: p.get_string(ACCT_SESSION_ID).unwrap_or_default(),
            user: p.get_string(USER_NAME).unwrap_or_default(),
            nas,
            nas_addr: Some(nas_ip.to_string()),
            framed_ip: p
                .get(FRAMED_IP_ADDRESS)
                .filter(|v| v.len() == 4)
                .map(|v| format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3])),
            session_time: u32_attr(p, ACCT_SESSION_TIME),
            input_octets: octets(p, ACCT_INPUT_OCTETS, ACCT_INPUT_GIGAWORDS),
            output_octets: octets(p, ACCT_OUTPUT_OCTETS, ACCT_OUTPUT_GIGAWORDS),
            terminate_cause: u32_attr(p, ACCT_TERMINATE_CAUSE),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub session_id: String,
    pub user: String,
    pub nas: String,
    pub nas_addr: Option<String>,
    pub framed_ip: Option<String>,
    pub started_at: i64,
    pub stopped_at: Option<i64>,
    pub session_time: i64,
    pub input_octets: i64,
    pub output_octets: i64,
    pub terminate_cause: Option<i64>,
}

pub struct AccountingStore {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT    NOT NULL,
    nas             TEXT    NOT NULL,
    user            TEXT    NOT NULL,
    framed_ip       TEXT,
    started_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    stopped_at      INTEGER,
    session_time    INTEGER NOT NULL DEFAULT 0,
    input_octets    INTEGER NOT NULL DEFAULT 0,
    output_octets   INTEGER NOT NULL DEFAULT 0,
    terminate_cause INTEGER,
    PRIMARY KEY (session_id, nas)
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user);
";

const SESSION_COLUMNS: &str = "session_id, user, nas, nas_addr, framed_ip, started_at, stopped_at, session_time,
                    input_octets, output_octets, terminate_cause";

fn session_from_row(row: &rusqlite::Row) -> rusqlite::Result<Session> {
    Ok(Session {
        session_id: row.get(0)?,
        user: row.get(1)?,
        nas: row.get(2)?,
        nas_addr: row.get(3)?,
        framed_ip: row.get(4)?,
        started_at: row.get(5)?,
        stopped_at: row.get(6)?,
        session_time: row.get(7)?,
        input_octets: row.get(8)?,
        output_octets: row.get(9)?,
        terminate_cause: row.get(10)?,
    })
}

/// Filter für die Sitzungsliste der Admin-Oberfläche.
#[derive(Debug, Clone, Default)]
pub struct SessionFilter {
    /// Teil des Benutzernamens
    pub user: Option<String>,
    pub active_only: bool,
    pub limit: u32,
}

/// Kennzahlen für die Übersicht.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub active: i64,
    pub sessions_since: i64,
    pub input_octets_since: i64,
    pub output_octets_since: i64,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl AccountingStore {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn in_memory() -> anyhow::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> anyhow::Result<Self> {
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch(SCHEMA)?;
        // Migration von 0.2.0: Spalte nas_addr nachrüsten
        let has_addr: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('sessions') WHERE name = 'nas_addr'")?
            .exists([])?;
        if !has_addr {
            conn.execute_batch("ALTER TABLE sessions ADD COLUMN nas_addr TEXT;")?;
        }
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Verarbeitet einen Accounting-Datensatz. Gibt `false` zurück, wenn nichts gespeichert wurde.
    pub fn record(&self, r: &Record) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().expect("DB-Mutex vergiftet");
        let ts = now();
        match r.status {
            StatusType::Start | StatusType::InterimUpdate | StatusType::Stop if r.session_id.is_empty() => Ok(false),
            StatusType::Start => {
                // Ein wiederholter Start (z.B. nach Neustart des NAS) überschreibt die alte Session.
                conn.execute(
                    "INSERT INTO sessions (session_id, nas, user, framed_ip, started_at, updated_at, nas_addr)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)
                     ON CONFLICT(session_id, nas) DO UPDATE SET
                        user = excluded.user, framed_ip = excluded.framed_ip, nas_addr = excluded.nas_addr,
                        started_at = excluded.started_at, updated_at = excluded.updated_at,
                        stopped_at = NULL, session_time = 0, input_octets = 0,
                        output_octets = 0, terminate_cause = NULL",
                    params![r.session_id, r.nas, r.user, r.framed_ip, ts, r.nas_addr],
                )?;
                Ok(true)
            }
            StatusType::InterimUpdate | StatusType::Stop => {
                let stopped = (r.status == StatusType::Stop).then_some(ts);
                // Fehlt der Start (Paket verloren), wird die Session hier angelegt.
                // Startzeit dann rückgerechnet aus Acct-Session-Time.
                let started = ts - r.session_time.unwrap_or(0) as i64;
                conn.execute(
                    "INSERT INTO sessions (session_id, nas, user, framed_ip, started_at, updated_at,
                                           stopped_at, session_time, input_octets, output_octets, terminate_cause, nas_addr)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, COALESCE(?8, 0), COALESCE(?9, 0), COALESCE(?10, 0), ?11, ?12)
                     ON CONFLICT(session_id, nas) DO UPDATE SET
                        updated_at      = excluded.updated_at,
                        nas_addr        = COALESCE(excluded.nas_addr, sessions.nas_addr),
                        stopped_at      = COALESCE(excluded.stopped_at, sessions.stopped_at),
                        framed_ip       = COALESCE(excluded.framed_ip, sessions.framed_ip),
                        session_time    = COALESCE(?8, sessions.session_time),
                        input_octets    = COALESCE(?9, sessions.input_octets),
                        output_octets   = COALESCE(?10, sessions.output_octets),
                        terminate_cause = COALESCE(excluded.terminate_cause, sessions.terminate_cause)",
                    params![
                        r.session_id,
                        r.nas,
                        r.user,
                        r.framed_ip,
                        started,
                        ts,
                        stopped,
                        r.session_time,
                        r.input_octets.map(|v| v as i64),
                        r.output_octets.map(|v| v as i64),
                        r.terminate_cause,
                        r.nas_addr
                    ],
                )?;
                Ok(true)
            }
            // Accounting-Off: NAS fährt herunter, alle offenen Sessions dieses NAS schließen.
            StatusType::AccountingOn | StatusType::AccountingOff => {
                let n = conn.execute(
                    "UPDATE sessions SET stopped_at = ?1, updated_at = ?1 WHERE nas = ?2 AND stopped_at IS NULL",
                    params![ts, r.nas],
                )?;
                Ok(n > 0)
            }
            StatusType::Unknown(_) => Ok(false),
        }
    }

    /// Die letzten Sessions, neueste zuerst.
    pub fn recent(&self, limit: u32) -> rusqlite::Result<Vec<Session>> {
        self.query(&SessionFilter {
            limit,
            ..Default::default()
        })
    }

    /// Sitzungen nach Filter, neueste zuerst.
    pub fn query(&self, f: &SessionFilter) -> rusqlite::Result<Vec<Session>> {
        let conn = self.conn.lock().expect("DB-Mutex vergiftet");
        let like = f
            .user
            .as_deref()
            .filter(|u| !u.is_empty())
            .map(|u| format!("%{}%", u.replace(['%', '_'], "")));
        let sql = format!(
            "SELECT {SESSION_COLUMNS} FROM sessions
             WHERE (?1 IS NULL OR user LIKE ?1) AND (?2 = 0 OR stopped_at IS NULL)
             ORDER BY updated_at DESC, started_at DESC LIMIT ?3"
        );
        let mut stmt = conn.prepare(&sql)?;
        let limit = if f.limit == 0 { 100 } else { f.limit };
        stmt.query_map(params![like, f.active_only as i64, limit], session_from_row)?
            .collect()
    }

    pub fn find(&self, session_id: &str, nas: &str) -> rusqlite::Result<Option<Session>> {
        let conn = self.conn.lock().expect("DB-Mutex vergiftet");
        let sql = format!("SELECT {SESSION_COLUMNS} FROM sessions WHERE session_id = ?1 AND nas = ?2");
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query_map(params![session_id, nas], session_from_row)?;
        rows.next().transpose()
    }

    /// Markiert eine offene Sitzung als beendet (z.B. wenn der NAS nicht mehr antwortet).
    pub fn mark_stopped(&self, session_id: &str, nas: &str, cause: u32) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().expect("DB-Mutex vergiftet");
        let ts = now();
        let n = conn.execute(
            "UPDATE sessions SET stopped_at = ?1, updated_at = ?1, terminate_cause = ?2,
                    session_time = MAX(session_time, ?1 - started_at)
             WHERE session_id = ?3 AND nas = ?4 AND stopped_at IS NULL",
            params![ts, cause, session_id, nas],
        )?;
        Ok(n > 0)
    }

    /// Aktive Sitzungen sowie Anzahl und Datenvolumen der Sitzungen seit `since` (Unix-Zeit).
    pub fn stats(&self, since: i64) -> rusqlite::Result<Stats> {
        let conn = self.conn.lock().expect("DB-Mutex vergiftet");
        let active = conn.query_row("SELECT COUNT(*) FROM sessions WHERE stopped_at IS NULL", [], |r| {
            r.get(0)
        })?;
        let (sessions_since, input_octets_since, output_octets_since) = conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(input_octets), 0), COALESCE(SUM(output_octets), 0)
             FROM sessions WHERE started_at >= ?1",
            [since],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        Ok(Stats {
            active,
            sessions_since,
            input_octets_since,
            output_octets_since,
        })
    }
}

/// Lesbarer Name für Acct-Terminate-Cause (RFC 2866 Abschnitt 5.10, Auswahl).
pub fn terminate_cause_name(c: i64) -> &'static str {
    match c {
        1 => "User-Request",
        2 => "Lost-Carrier",
        3 => "Lost-Service",
        4 => "Idle-Timeout",
        5 => "Session-Timeout",
        6 => "Admin-Reset",
        7 => "Admin-Reboot",
        8 => "Port-Error",
        9 => "NAS-Error",
        10 => "NAS-Request",
        11 => "NAS-Reboot",
        _ => "Other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(status: StatusType, sid: &str) -> Record {
        Record {
            status,
            session_id: sid.into(),
            user: "martin".into(),
            nas: "ap-1".into(),
            nas_addr: Some("10.0.0.1".into()),
            framed_ip: None,
            session_time: None,
            input_octets: None,
            output_octets: None,
            terminate_cause: None,
        }
    }

    #[test]
    fn start_interim_stop_lifecycle() {
        let db = AccountingStore::in_memory().unwrap();
        assert!(db.record(&rec(StatusType::Start, "s1")).unwrap());

        let mut interim = rec(StatusType::InterimUpdate, "s1");
        interim.session_time = Some(60);
        interim.input_octets = Some(1_000);
        db.record(&interim).unwrap();

        let mut stop = rec(StatusType::Stop, "s1");
        stop.session_time = Some(120);
        stop.input_octets = Some(5_000_000_000); // > 4 GiB, braucht Gigawords
        stop.output_octets = Some(42);
        stop.terminate_cause = Some(1);
        db.record(&stop).unwrap();

        let s = &db.recent(10).unwrap()[0];
        assert_eq!(s.session_time, 120);
        assert_eq!(s.input_octets, 5_000_000_000);
        assert_eq!(s.output_octets, 42);
        assert_eq!(s.terminate_cause, Some(1));
        assert!(s.stopped_at.is_some());
    }

    #[test]
    fn stop_without_start_creates_session() {
        let db = AccountingStore::in_memory().unwrap();
        let mut stop = rec(StatusType::Stop, "verloren");
        stop.session_time = Some(300);
        db.record(&stop).unwrap();
        let s = &db.recent(10).unwrap()[0];
        assert_eq!(s.session_time, 300);
        assert_eq!(s.stopped_at.unwrap() - s.started_at, 300);
    }

    #[test]
    fn accounting_off_closes_open_sessions() {
        let db = AccountingStore::in_memory().unwrap();
        db.record(&rec(StatusType::Start, "a")).unwrap();
        db.record(&rec(StatusType::Start, "b")).unwrap();
        db.record(&rec(StatusType::AccountingOff, "")).unwrap();
        assert!(db.recent(10).unwrap().iter().all(|s| s.stopped_at.is_some()));
    }

    #[test]
    fn query_filter_mark_stopped_and_stats() {
        let db = AccountingStore::in_memory().unwrap();
        db.record(&rec(StatusType::Start, "a")).unwrap();
        let mut other = rec(StatusType::Start, "b");
        other.user = "gast-1234".into();
        db.record(&other).unwrap();

        let active = db
            .query(&SessionFilter {
                active_only: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(active.len(), 2);
        let gast = db
            .query(&SessionFilter {
                user: Some("gast".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(gast.len(), 1);
        assert_eq!(gast[0].nas_addr.as_deref(), Some("10.0.0.1"));

        assert!(db.mark_stopped("a", "ap-1", 6).unwrap());
        assert!(!db.mark_stopped("a", "ap-1", 6).unwrap(), "zweimal beenden geht nicht");
        assert_eq!(db.find("a", "ap-1").unwrap().unwrap().terminate_cause, Some(6));
        let st = db.stats(0).unwrap();
        assert_eq!((st.active, st.sessions_since), (1, 2));
    }

    #[test]
    fn interim_without_counters_keeps_old_values() {
        let db = AccountingStore::in_memory().unwrap();
        let mut a = rec(StatusType::InterimUpdate, "x");
        a.input_octets = Some(777);
        db.record(&a).unwrap();
        db.record(&rec(StatusType::InterimUpdate, "x")).unwrap();
        assert_eq!(db.recent(1).unwrap()[0].input_octets, 777);
    }
}
