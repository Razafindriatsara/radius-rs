//! Asynchroner RADIUS-Client (NAS-Seite): Access-Request mit PAP und
//! Accounting-Request, inklusive Prüfung der Antworten.
//!
//! Wird vom Eingangsportal (`radius-portal`) genutzt, eignet sich aber für
//! jeden Dienst, der Benutzer gegen einen RADIUS-Server prüfen will.

use std::time::Duration;

use thiserror::Error;
use tokio::net::UdpSocket;

use crate::attributes::*;
use crate::crypto;
use crate::packet::{Code, Packet};

#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Adresse für Access-Requests, z.B. "127.0.0.1:1812" oder "radius:1812"
    pub auth_server: String,
    /// Adresse für Accounting-Requests, z.B. "127.0.0.1:1813"
    pub acct_server: String,
    pub secret: String,
    pub nas_identifier: String,
    /// Wartezeit pro Versuch
    pub timeout: Duration,
    /// Weitere Versuche nach dem ersten. Der Server erkennt Wiederholungen (RFC 5080).
    pub retries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    Accept {
        session_timeout: Option<u32>,
        reply_message: Option<String>,
    },
    Reject {
        reply_message: Option<String>,
    },
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("RADIUS-Server antwortet nicht")]
    Timeout,
    #[error("Netzwerkfehler: {0}")]
    Io(#[from] std::io::Error),
    #[error("ungültige Antwort vom RADIUS-Server: {0}")]
    InvalidResponse(&'static str),
    #[error("Zufallsgenerator nicht verfügbar")]
    Random,
}

/// Daten einer Accounting-Meldung.
#[derive(Debug, Clone, Default)]
pub struct AcctRequest {
    /// 1 = Start, 2 = Stop, 3 = Interim-Update
    pub status: u32,
    pub user: String,
    pub session_id: String,
    pub session_time: Option<u32>,
    pub terminate_cause: Option<u32>,
    pub calling_station_id: Option<String>,
    pub framed_ip: Option<[u8; 4]>,
}

pub const ACCT_START: u32 = 1;
pub const ACCT_STOP: u32 = 2;
pub const CAUSE_USER_REQUEST: u32 = 1;
pub const CAUSE_SESSION_TIMEOUT: u32 = 5;
pub const CAUSE_ADMIN_RESET: u32 = 6;

#[derive(Debug, Clone)]
pub struct RadiusClient {
    cfg: ClientConfig,
}

/// 16 Byte aus dem Zufallsgenerator des Betriebssystems (Request Authenticator, Session-IDs).
pub fn random_bytes<const N: usize>() -> Result<[u8; N], ClientError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| ClientError::Random)?;
    Ok(b)
}

impl RadiusClient {
    pub fn new(cfg: ClientConfig) -> Self {
        Self { cfg }
    }

    pub fn config(&self) -> &ClientConfig {
        &self.cfg
    }

    /// Prüft Benutzername und Passwort per PAP.
    pub async fn authenticate(
        &self,
        user: &str,
        password: &str,
        calling_station_id: Option<&str>,
    ) -> Result<AuthOutcome, ClientError> {
        let secret = self.cfg.secret.as_bytes();
        let ra: [u8; 16] = random_bytes()?;
        let id = random_bytes::<1>()?[0];

        let mut req = Packet::new(Code::AccessRequest, id, ra);
        req.add(MESSAGE_AUTHENTICATOR, vec![0u8; 16]);
        req.add(USER_NAME, user.as_bytes().to_vec());
        req.add(
            USER_PASSWORD,
            crypto::encrypt_user_password(password.as_bytes(), secret, &ra),
        );
        req.add(NAS_IDENTIFIER, self.cfg.nas_identifier.as_bytes().to_vec());
        if let Some(c) = calling_station_id {
            req.add(CALLING_STATION_ID, c.as_bytes().to_vec());
        }
        let mut bytes = req
            .encode()
            .map_err(|_| ClientError::InvalidResponse("Anfrage zu groß"))?;
        crypto::sign_request_message_authenticator(&mut bytes, secret);

        let raw = self.exchange(&self.cfg.auth_server, &bytes).await?;
        let resp = self.verify(&raw, id, &ra)?;

        // Message-Authenticator der Antwort prüfen (mit Request Authenticator im Header)
        let mut check = raw.clone();
        check[4..20].copy_from_slice(&ra);
        if !crypto::verify_message_authenticator(&check, secret) {
            return Err(ClientError::InvalidResponse(
                "Message-Authenticator fehlt oder ist falsch",
            ));
        }

        let reply_message = resp.get_string(REPLY_MESSAGE);
        match resp.code {
            Code::AccessAccept => Ok(AuthOutcome::Accept {
                session_timeout: resp
                    .get(SESSION_TIMEOUT)
                    .and_then(|v| v.try_into().ok())
                    .map(u32::from_be_bytes),
                reply_message,
            }),
            Code::AccessReject => Ok(AuthOutcome::Reject { reply_message }),
            _ => Err(ClientError::InvalidResponse("unerwarteter Antwortcode")),
        }
    }

    /// Sendet eine Accounting-Meldung und wartet auf die Bestätigung.
    pub async fn accounting(&self, a: &AcctRequest) -> Result<(), ClientError> {
        let secret = self.cfg.secret.as_bytes();
        let id = random_bytes::<1>()?[0];
        let mut req = Packet::new(Code::AccountingRequest, id, [0u8; 16]);
        req.add_u32(ACCT_STATUS_TYPE, a.status);
        req.add(USER_NAME, a.user.as_bytes().to_vec());
        req.add(ACCT_SESSION_ID, a.session_id.as_bytes().to_vec());
        req.add(NAS_IDENTIFIER, self.cfg.nas_identifier.as_bytes().to_vec());
        if let Some(t) = a.session_time {
            req.add_u32(ACCT_SESSION_TIME, t);
        }
        if let Some(c) = a.terminate_cause {
            req.add_u32(ACCT_TERMINATE_CAUSE, c);
        }
        if let Some(c) = &a.calling_station_id {
            req.add(CALLING_STATION_ID, c.as_bytes().to_vec());
        }
        if let Some(ip) = a.framed_ip {
            req.add(FRAMED_IP_ADDRESS, ip.to_vec());
        }
        let mut bytes = req
            .encode()
            .map_err(|_| ClientError::InvalidResponse("Anfrage zu groß"))?;
        crypto::sign_accounting_request(&mut bytes, secret);
        let ra: [u8; 16] = bytes[4..20].try_into().expect("16 Byte");

        let raw = self.exchange(&self.cfg.acct_server, &bytes).await?;
        let resp = self.verify(&raw, id, &ra)?;
        if resp.code != Code::AccountingResponse {
            return Err(ClientError::InvalidResponse("unerwarteter Antwortcode"));
        }
        Ok(())
    }

    /// Sendet das Paket und wiederholt es bei Zeitüberschreitung unverändert.
    async fn exchange(&self, server: &str, bytes: &[u8]) -> Result<Vec<u8>, ClientError> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(server).await?;
        let mut buf = vec![0u8; 4096];
        for _ in 0..=self.cfg.retries {
            sock.send(bytes).await?;
            if let Ok(Ok(n)) = tokio::time::timeout(self.cfg.timeout, sock.recv(&mut buf)).await {
                return Ok(buf[..n].to_vec());
            }
        }
        Err(ClientError::Timeout)
    }

    /// Prüft Identifier und Response Authenticator.
    fn verify(&self, raw: &[u8], id: u8, ra: &[u8; 16]) -> Result<Packet, ClientError> {
        let resp = Packet::decode(raw).map_err(|_| ClientError::InvalidResponse("fehlerhaftes Paket"))?;
        if resp.identifier != id {
            return Err(ClientError::InvalidResponse("falscher Identifier"));
        }
        let mut check = raw.to_vec();
        crypto::sign_response(&mut check, ra, self.cfg.secret.as_bytes());
        if check != raw {
            return Err(ClientError::InvalidResponse(
                "Response Authenticator ungültig (falsches Secret?)",
            ));
        }
        Ok(resp)
    }
}
