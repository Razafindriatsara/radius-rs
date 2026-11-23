//! Kryptografie im RADIUS-Protokoll.
//!
//! - User-Password (PAP), RFC 2865 Abschnitt 5.2
//! - Response Authenticator, RFC 2865 Abschnitt 3
//! - Message-Authenticator (HMAC-MD5), RFC 3579 Abschnitt 3.2
//!
//! MD5 ist hier vom Protokoll vorgegeben und kein Designfehler dieses Projekts.
//! Für echten Transportschutz ist RadSec (RADIUS über TLS, RFC 6614) vorgesehen.

use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};

use crate::attributes::MESSAGE_AUTHENTICATOR;
use crate::packet::{Packet, HEADER_LEN};

type HmacMd5 = Hmac<Md5>;

/// Vergleich in konstanter Zeit, damit Timing keine Information verrät.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Entschlüsselt ein PAP User-Password:
/// b1 = MD5(S + RA), p1 = c1 XOR b1; bi = MD5(S + c(i-1)), pi = ci XOR bi
pub fn decrypt_user_password(cipher: &[u8], secret: &[u8], request_auth: &[u8; 16]) -> Option<Vec<u8>> {
    if cipher.is_empty() || !cipher.len().is_multiple_of(16) || cipher.len() > 128 {
        return None;
    }
    let mut plain = Vec::with_capacity(cipher.len());
    let mut prev: &[u8] = request_auth;
    for chunk in cipher.chunks(16) {
        let b = Md5::new().chain_update(secret).chain_update(prev).finalize();
        plain.extend(chunk.iter().zip(b.iter()).map(|(c, k)| c ^ k));
        prev = chunk;
    }
    while plain.last() == Some(&0) {
        plain.pop(); // Null-Padding entfernen
    }
    Some(plain)
}

/// Gegenstück zu [`decrypt_user_password`], wird für Tests und einen Testclient gebraucht.
pub fn encrypt_user_password(plain: &[u8], secret: &[u8], request_auth: &[u8; 16]) -> Vec<u8> {
    let mut padded = plain.to_vec();
    let pad = (16 - padded.len() % 16) % 16;
    padded.resize(padded.len() + if padded.is_empty() { 16 } else { pad }, 0);

    let mut cipher = Vec::with_capacity(padded.len());
    let mut prev = request_auth.to_vec();
    for chunk in padded.chunks(16) {
        let b = Md5::new().chain_update(secret).chain_update(&prev).finalize();
        let c: Vec<u8> = chunk.iter().zip(b.iter()).map(|(p, k)| p ^ k).collect();
        cipher.extend_from_slice(&c);
        prev = c;
    }
    cipher
}

/// Response Authenticator = MD5(Code + ID + Length + RequestAuth + Attributes + Secret).
/// Setzt das Feld direkt im enkodierten Antwortpaket.
pub fn sign_response(encoded: &mut [u8], request_auth: &[u8; 16], secret: &[u8]) {
    encoded[4..20].copy_from_slice(request_auth);
    let digest = Md5::new().chain_update(&*encoded).chain_update(secret).finalize();
    encoded[4..20].copy_from_slice(&digest);
}

/// Berechnet den Message-Authenticator über ein enkodiertes Paket.
/// Das Feld selbst wird dabei als 16 Nullbytes gerechnet. `auth_override` ersetzt
/// den Authenticator im Header (bei Antworten: der Request Authenticator).
fn compute_message_authenticator(encoded: &[u8], secret: &[u8], auth_override: Option<&[u8; 16]>) -> Option<[u8; 16]> {
    let mut buf = encoded.to_vec();
    if let Some(a) = auth_override {
        buf[4..20].copy_from_slice(a);
    }
    let offset = find_attribute_offset(&buf, MESSAGE_AUTHENTICATOR)?;
    buf[offset + 2..offset + 18].fill(0);

    let mut mac = HmacMd5::new_from_slice(secret).ok()?;
    mac.update(&buf);
    Some(mac.finalize().into_bytes().into())
}

/// Prüft den Message-Authenticator eines empfangenen Requests.
pub fn verify_message_authenticator(encoded: &[u8], secret: &[u8]) -> bool {
    let Some(offset) = find_attribute_offset(encoded, MESSAGE_AUTHENTICATOR) else {
        return false;
    };
    if encoded[offset + 1] != 18 {
        return false;
    }
    match compute_message_authenticator(encoded, secret, None) {
        Some(expected) => ct_eq(&expected, &encoded[offset + 2..offset + 18]),
        None => false,
    }
}

/// Enkodiert eine Antwort inklusive Message-Authenticator und Response Authenticator.
/// Reihenfolge laut RFC 3579: erst Message-Authenticator, dann Response Authenticator.
pub fn finalize_response(mut response: Packet, request_auth: &[u8; 16], secret: &[u8]) -> Vec<u8> {
    response.attributes.retain(|a| a.typ != MESSAGE_AUTHENTICATOR);
    // RFC 3579 / BlastRADIUS-Empfehlung: Message-Authenticator als erstes Attribut.
    response.attributes.insert(0, crate::packet::Attribute { typ: MESSAGE_AUTHENTICATOR, value: vec![0u8; 16] });

    let mut encoded = response.encode().expect("Antwortpaket zu groß");
    let ma = compute_message_authenticator(&encoded, secret, Some(request_auth)).expect("Attribut fehlt");
    let off = find_attribute_offset(&encoded, MESSAGE_AUTHENTICATOR).unwrap();
    encoded[off + 2..off + 18].copy_from_slice(&ma);

    sign_response(&mut encoded, request_auth, secret);
    encoded
}

/// Client-Seite: füllt einen vorhandenen (genullten) Message-Authenticator in einem
/// enkodierten Access-Request aus. Wird für Tests und einen späteren Testclient genutzt.
pub fn sign_request_message_authenticator(encoded: &mut [u8], secret: &[u8]) -> bool {
    let Some(off) = find_attribute_offset(encoded, MESSAGE_AUTHENTICATOR) else {
        return false;
    };
    let Some(ma) = compute_message_authenticator(encoded, secret, None) else {
        return false;
    };
    encoded[off + 2..off + 18].copy_from_slice(&ma);
    true
}

/// Accounting-Request Authenticator (RFC 2866 Abschnitt 3):
/// MD5(Code + ID + Length + 16 Nullbytes + Attributes + Secret).
pub fn verify_accounting_request(encoded: &[u8], secret: &[u8]) -> bool {
    let mut buf = encoded.to_vec();
    buf[4..20].fill(0);
    let digest = Md5::new().chain_update(&buf).chain_update(secret).finalize();
    ct_eq(&digest, &encoded[4..20])
}

fn find_attribute_offset(encoded: &[u8], typ: u8) -> Option<usize> {
    let length = u16::from_be_bytes([encoded[2], encoded[3]]) as usize;
    let mut off = HEADER_LEN;
    while off + 2 <= length {
        let len = encoded[off + 1] as usize;
        if len < 2 || off + len > length {
            return None;
        }
        if encoded[off] == typ && len == 18 {
            return Some(off);
        }
        off += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attributes::*;
    use crate::packet::Packet;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
    }

    /// Beispiel aus RFC 2865 Abschnitt 7.1: Benutzer "nemo", Passwort "arctangent",
    /// Shared Secret "xyzzy5461".
    const RFC_REQUEST: &str = "01 00 00 38 0f 40 3f 94 73 97 80 57 bd 83 d5 cb 98 f4 22 7a \
        01 06 6e 65 6d 6f 02 12 0d be 70 8d 93 d4 13 ce 31 96 e4 3f 78 2a 0a ee \
        04 06 c0 a8 01 10 05 06 00 00 00 03";
    const RFC_RESPONSE: &str = "02 00 00 26 86 fe 22 0e 76 24 ba 2a 10 05 f6 bf 9b 55 e0 b2 \
        06 06 00 00 00 01 0f 06 00 00 00 00 0e 06 c0 a8 01 03";
    const SECRET: &[u8] = b"xyzzy5461";

    #[test]
    fn rfc2865_pap_decryption() {
        let req = Packet::decode(&hex(RFC_REQUEST)).unwrap();
        assert_eq!(req.get_string(USER_NAME).as_deref(), Some("nemo"));
        let pw = decrypt_user_password(req.get(USER_PASSWORD).unwrap(), SECRET, &req.authenticator).unwrap();
        assert_eq!(pw, b"arctangent");
    }

    #[test]
    fn rfc2865_response_authenticator() {
        let req = Packet::decode(&hex(RFC_REQUEST)).unwrap();
        let expected = hex(RFC_RESPONSE);
        let mut resp = expected.clone();
        resp[4..20].fill(0);
        sign_response(&mut resp, &req.authenticator, SECRET);
        assert_eq!(resp, expected);
    }

    #[test]
    fn pap_roundtrip_long_password() {
        let ra = [9u8; 16];
        let pw = b"ein-deutlich-laengeres-passwort-ueber-16-byte";
        let c = encrypt_user_password(pw, b"geheim", &ra);
        assert_eq!(c.len(), 48);
        assert_eq!(decrypt_user_password(&c, b"geheim", &ra).unwrap(), pw);
    }

    #[test]
    fn message_authenticator_roundtrip() {
        let ra = [1u8; 16];
        let resp = Packet::new(crate::packet::Code::AccessAccept, 5, [0u8; 16]);
        let encoded = finalize_response(resp, &ra, b"secret");
        // Zur Prüfung den Request Authenticator wieder einsetzen, wie es der Client tut.
        let mut check = encoded.clone();
        check[4..20].copy_from_slice(&ra);
        assert!(verify_message_authenticator(&check, b"secret"));
        assert!(!verify_message_authenticator(&check, b"falsch"));
    }
}
