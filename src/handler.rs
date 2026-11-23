//! Protokoll-Logik, unabhängig vom Netzwerk und damit gut testbar:
//! Bytes eines Requests rein, Bytes einer Antwort (oder nichts) raus.

use crate::accounting::{AccountingStore, Record, StatusType};
use crate::attributes::*;
use crate::auth::{AuthResult, Authenticator};
use crate::crypto;
use crate::packet::{Code, Packet};

pub struct Handler<A: Authenticator> {
    pub auth: A,
    pub require_message_authenticator: bool,
    /// Optional: ohne Datenbank werden Accounting-Requests nur geloggt und bestätigt.
    pub accounting: Option<AccountingStore>,
}

/// Warum ein Paket stillschweigend verworfen wurde. RFC 2865 verlangt,
/// ungültige Pakete ohne Antwort zu verwerfen.
#[derive(Debug, PartialEq, Eq)]
pub enum Drop {
    Malformed,
    UnexpectedCode,
    MissingMessageAuthenticator,
    BadMessageAuthenticator,
    BadAccountingAuthenticator,
    MissingUserName,
    /// RFC 2866: Antwort nur senden, wenn der Datensatz gespeichert werden konnte.
    AccountingStorageFailed,
}

impl<A: Authenticator> Handler<A> {
    pub fn handle_auth(&self, data: &[u8], secret: &[u8]) -> Result<Vec<u8>, Drop> {
        let req = Packet::decode(data).map_err(|_| Drop::Malformed)?;

        match req.code {
            Code::AccessRequest => {}
            Code::StatusServer => return self.status_server(&req, data, secret),
            _ => return Err(Drop::UnexpectedCode),
        }

        let has_ma = req.get(MESSAGE_AUTHENTICATOR).is_some();
        if has_ma && !crypto::verify_message_authenticator(data, secret) {
            return Err(Drop::BadMessageAuthenticator);
        }
        if !has_ma && (self.require_message_authenticator || req.get(EAP_MESSAGE).is_some()) {
            return Err(Drop::MissingMessageAuthenticator);
        }

        let user = req.get_string(USER_NAME).ok_or(Drop::MissingUserName)?;

        let result = match req.get(USER_PASSWORD) {
            Some(cipher) => match crypto::decrypt_user_password(cipher, secret, &req.authenticator) {
                Some(pw) => self.auth.authenticate_pap(&user, &pw),
                None => AuthResult::Reject,
            },
            None => AuthResult::Reject, // CHAP/EAP noch nicht unterstützt
        };

        let resp = match result {
            AuthResult::Accept {
                session_timeout,
                reply_message,
            } => {
                tracing::info!(user, "Access-Accept");
                let mut p = Packet::new(Code::AccessAccept, req.identifier, [0; 16]);
                if let Some(t) = session_timeout {
                    p.add_u32(SESSION_TIMEOUT, t);
                }
                if let Some(m) = reply_message {
                    p.add(REPLY_MESSAGE, m.into_bytes());
                }
                p
            }
            AuthResult::Reject => {
                tracing::info!(user, "Access-Reject");
                Packet::new(Code::AccessReject, req.identifier, [0; 16])
            }
        };

        Ok(crypto::finalize_response(resp, &req.authenticator, secret))
    }

    /// RFC 5997: Status-Server muss einen gültigen Message-Authenticator haben.
    fn status_server(&self, req: &Packet, data: &[u8], secret: &[u8]) -> Result<Vec<u8>, Drop> {
        if !crypto::verify_message_authenticator(data, secret) {
            return Err(Drop::BadMessageAuthenticator);
        }
        let mut p = Packet::new(Code::AccessAccept, req.identifier, [0; 16]);
        p.add(REPLY_MESSAGE, b"radius-rs alive".to_vec());
        Ok(crypto::finalize_response(p, &req.authenticator, secret))
    }

    pub fn handle_acct(&self, data: &[u8], secret: &[u8], nas_ip: &str) -> Result<Vec<u8>, Drop> {
        let req = Packet::decode(data).map_err(|_| Drop::Malformed)?;
        if req.code != Code::AccountingRequest {
            return Err(Drop::UnexpectedCode);
        }
        if !crypto::verify_accounting_request(data, secret) {
            return Err(Drop::BadAccountingAuthenticator);
        }

        let record = Record::from_packet(&req, nas_ip).ok_or(Drop::Malformed)?;
        tracing::info!(
            user = record.user,
            session = record.session_id,
            nas = record.nas,
            status = ?record.status,
            "Accounting"
        );
        if let StatusType::Unknown(x) = record.status {
            tracing::warn!(status = x, "unbekannter Acct-Status-Type");
        }

        if let Some(store) = &self.accounting
            && let Err(e) = store.record(&record)
        {
            // Keine Antwort: der NAS wiederholt den Request später, nichts geht verloren.
            tracing::error!(error = %e, "Accounting konnte nicht gespeichert werden");
            return Err(Drop::AccountingStorageFailed);
        }

        let mut encoded = Packet::new(Code::AccountingResponse, req.identifier, [0; 16])
            .encode()
            .map_err(|_| Drop::Malformed)?;
        crypto::sign_response(&mut encoded, &req.authenticator, secret);
        Ok(encoded)
    }
}
