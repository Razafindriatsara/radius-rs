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
                    "INSERT INTO sessions (session_id, nas, user, framed_ip, started_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                     ON CONFLICT(session_id, nas) DO UPDATE SET
                        user = excluded.user, framed_ip = excluded.framed_ip,
                        started_at = excluded.started_at, updated_at = excluded.updated_at,
                        stopped_at = NULL, session_time = 0, input_octets = 0,
                        output_octets = 0, terminate_cause = NULL",
                    params![r.session_id, r.nas, r.user, r.framed_ip, ts],
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
                                           stopped_at, session_time, input_octets, output_octets, terminate_cause)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, COALESCE(?8, 0), COALESCE(?9, 0), COALESCE(?10, 0), ?11)
                     ON CONFLICT(session_id, nas) DO UPDATE SET
                        updated_at      = excluded.updated_at,
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
                        r.terminate_cause
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
        let conn = self.conn.lock().expect("DB-Mutex vergiftet");
        let mut stmt = conn.prepare(
            "SELECT session_id, user, nas, framed_ip, started_at, stopped_at, session_time,
                    input_octets, output_octets, terminate_cause
             FROM sessions ORDER BY updated_at DESC, started_at DESC LIMIT ?1",
        )?;
        stmt.query_map([limit], |row| {
            Ok(Session {
                session_id: row.get(0)?,
                user: row.get(1)?,
                nas: row.get(2)?,
                framed_ip: row.get(3)?,
                started_at: row.get(4)?,
                stopped_at: row.get(5)?,
                session_time: row.get(6)?,
                input_octets: row.get(7)?,
                output_octets: row.get(8)?,
                terminate_cause: row.get(9)?,
            })
        })?
        .collect()
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
    fn interim_without_counters_keeps_old_values() {
        let db = AccountingStore::in_memory().unwrap();
        let mut a = rec(StatusType::InterimUpdate, "x");
        a.input_octets = Some(777);
        db.record(&a).unwrap();
        db.record(&rec(StatusType::InterimUpdate, "x")).unwrap();
        assert_eq!(db.recent(1).unwrap()[0].input_octets, 777);
    }
}
