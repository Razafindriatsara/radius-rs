//! Erkennung doppelter Requests (RFC 5080 Abschnitt 2.2.2).
//!
//! Geht eine Antwort verloren, schickt der NAS denselben Request erneut: gleiche
//! Quelle (IP + Port), gleicher Identifier, gleicher Request Authenticator.
//! Der Server soll dann dieselbe Antwort noch einmal senden, statt neu zu
//! rechnen. Das ist wichtig, weil sonst z.B. Accounting doppelt gezählt würde
//! und Argon2 unnötig CPU kostet.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    pub peer: SocketAddr,
    pub identifier: u8,
    pub authenticator: [u8; 16],
}

impl Key {
    /// Liest die Schlüsselfelder direkt aus den Rohdaten (ohne vollständiges Parsen).
    pub fn from_datagram(peer: SocketAddr, data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&data[4..20]);
        Some(Self {
            peer,
            identifier: data[1],
            authenticator,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Neuer Request: verarbeiten und danach [`DedupCache::complete`] aufrufen.
    New,
    /// Wird gerade noch verarbeitet: Duplikat verwerfen.
    InProgress,
    /// Schon beantwortet: diese Antwort erneut senden.
    Cached(Vec<u8>),
}

enum Entry {
    Pending(Instant),
    Done(Instant, Vec<u8>),
}

pub struct DedupCache {
    ttl: Duration,
    max_entries: usize,
    entries: Mutex<HashMap<Key, Entry>>,
}

impl DedupCache {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn lookup(&self, key: &Key) -> Lookup {
        let now = Instant::now();
        let mut map = self.entries.lock().expect("Dedup-Mutex vergiftet");

        if let Some(entry) = map.get(key) {
            match entry {
                Entry::Pending(t) if now.duration_since(*t) < self.ttl => {
                    return Lookup::InProgress;
                }
                Entry::Done(t, resp) if now.duration_since(*t) < self.ttl => {
                    return Lookup::Cached(resp.clone());
                }
                _ => {} // abgelaufen: wie neu behandeln
            }
        }

        if map.len() >= self.max_entries {
            let ttl = self.ttl;
            map.retain(|_, e| match e {
                Entry::Pending(t) | Entry::Done(t, _) => now.duration_since(*t) < ttl,
            });
        }
        if map.len() >= self.max_entries {
            // Immer noch voll (Flut von Requests): lieber ohne Cache weiterarbeiten
            // als unbegrenzt Speicher zu belegen.
            return Lookup::New;
        }
        map.insert(key.clone(), Entry::Pending(now));
        Lookup::New
    }

    /// Antwort für spätere Duplikate speichern.
    pub fn complete(&self, key: Key, response: Vec<u8>) {
        let mut map = self.entries.lock().expect("Dedup-Mutex vergiftet");
        map.insert(key, Entry::Done(Instant::now(), response));
    }

    /// Request wurde verworfen: Eintrag entfernen, damit eine korrigierte Wiederholung möglich ist.
    pub fn forget(&self, key: &Key) {
        self.entries.lock().expect("Dedup-Mutex vergiftet").remove(key);
    }

    pub fn len(&self) -> usize {
        self.entries.lock().expect("Dedup-Mutex vergiftet").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: u8) -> Key {
        Key {
            peer: "127.0.0.1:5000".parse().unwrap(),
            identifier: id,
            authenticator: [id; 16],
        }
    }

    #[test]
    fn new_in_progress_cached() {
        let c = DedupCache::new(Duration::from_secs(30), 100);
        assert_eq!(c.lookup(&key(1)), Lookup::New);
        assert_eq!(c.lookup(&key(1)), Lookup::InProgress);
        c.complete(key(1), vec![1, 2, 3]);
        assert_eq!(c.lookup(&key(1)), Lookup::Cached(vec![1, 2, 3]));
        assert_eq!(c.lookup(&key(2)), Lookup::New);
    }

    #[test]
    fn different_authenticator_is_new_request() {
        let c = DedupCache::new(Duration::from_secs(30), 100);
        c.lookup(&key(1));
        let mut k = key(1);
        k.authenticator = [99; 16];
        assert_eq!(c.lookup(&k), Lookup::New);
    }

    #[test]
    fn expires_after_ttl() {
        let c = DedupCache::new(Duration::from_millis(20), 100);
        c.lookup(&key(1));
        c.complete(key(1), vec![1]);
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(c.lookup(&key(1)), Lookup::New);
    }

    #[test]
    fn bounded_size() {
        let c = DedupCache::new(Duration::from_secs(30), 10);
        for i in 0..50 {
            c.lookup(&key(i));
        }
        assert!(c.len() <= 10);
    }

    #[test]
    fn forget_allows_retry() {
        let c = DedupCache::new(Duration::from_secs(30), 100);
        c.lookup(&key(1));
        c.forget(&key(1));
        assert_eq!(c.lookup(&key(1)), Lookup::New);
    }
}
