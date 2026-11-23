//! RADIUS-Paketformat (RFC 2865, Abschnitt 3):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Code      |  Identifier   |            Length             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Authenticator (16 Byte)               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Attributes (Type, Length, Value) ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-
//! ```

use thiserror::Error;

pub const HEADER_LEN: usize = 20;
pub const MIN_PACKET_LEN: usize = 20;
pub const MAX_PACKET_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    AccessRequest,
    AccessAccept,
    AccessReject,
    AccountingRequest,
    AccountingResponse,
    AccessChallenge,
    StatusServer,
    StatusClient,
    Other(u8),
}

impl From<u8> for Code {
    fn from(v: u8) -> Self {
        match v {
            1 => Code::AccessRequest,
            2 => Code::AccessAccept,
            3 => Code::AccessReject,
            4 => Code::AccountingRequest,
            5 => Code::AccountingResponse,
            11 => Code::AccessChallenge,
            12 => Code::StatusServer,
            13 => Code::StatusClient,
            x => Code::Other(x),
        }
    }
}

impl From<Code> for u8 {
    fn from(c: Code) -> u8 {
        match c {
            Code::AccessRequest => 1,
            Code::AccessAccept => 2,
            Code::AccessReject => 3,
            Code::AccountingRequest => 4,
            Code::AccountingResponse => 5,
            Code::AccessChallenge => 11,
            Code::StatusServer => 12,
            Code::StatusClient => 13,
            Code::Other(x) => x,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub typ: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub code: Code,
    pub identifier: u8,
    pub authenticator: [u8; 16],
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("Paket zu kurz: {0} Byte")]
    TooShort(usize),
    #[error("Length-Feld ({field}) passt nicht zur Datagrammgröße ({actual})")]
    BadLength { field: usize, actual: usize },
    #[error("Attribut mit ungültiger Länge {len} an Offset {offset}")]
    BadAttribute { offset: usize, len: usize },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncodeError {
    #[error("Attributwert zu lang ({0} Byte, max. 253)")]
    AttributeTooLong(usize),
    #[error("Paket zu lang ({0} Byte, max. 4096)")]
    PacketTooLong(usize),
}

impl Packet {
    pub fn new(code: Code, identifier: u8, authenticator: [u8; 16]) -> Self {
        Self {
            code,
            identifier,
            authenticator,
            attributes: Vec::new(),
        }
    }

    /// Dekodiert ein Datagramm. Bytes hinter `Length` werden laut RFC 2865 ignoriert.
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < MIN_PACKET_LEN {
            return Err(DecodeError::TooShort(buf.len()));
        }
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if !(MIN_PACKET_LEN..=MAX_PACKET_LEN).contains(&length) || length > buf.len() {
            return Err(DecodeError::BadLength {
                field: length,
                actual: buf.len(),
            });
        }

        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&buf[4..20]);

        let mut attributes = Vec::new();
        let mut offset = HEADER_LEN;
        while offset < length {
            if offset + 2 > length {
                return Err(DecodeError::BadAttribute { offset, len: 0 });
            }
            let typ = buf[offset];
            let len = buf[offset + 1] as usize;
            if len < 2 || offset + len > length {
                return Err(DecodeError::BadAttribute { offset, len });
            }
            attributes.push(Attribute {
                typ,
                value: buf[offset + 2..offset + len].to_vec(),
            });
            offset += len;
        }

        Ok(Self {
            code: buf[0].into(),
            identifier: buf[1],
            authenticator,
            attributes,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(64);
        out.push(self.code.into());
        out.push(self.identifier);
        out.extend_from_slice(&[0, 0]); // Platzhalter für Length
        out.extend_from_slice(&self.authenticator);
        for a in &self.attributes {
            if a.value.len() > 253 {
                return Err(EncodeError::AttributeTooLong(a.value.len()));
            }
            out.push(a.typ);
            out.push((a.value.len() + 2) as u8);
            out.extend_from_slice(&a.value);
        }
        if out.len() > MAX_PACKET_LEN {
            return Err(EncodeError::PacketTooLong(out.len()));
        }
        let len = (out.len() as u16).to_be_bytes();
        out[2] = len[0];
        out[3] = len[1];
        Ok(out)
    }

    pub fn get(&self, typ: u8) -> Option<&[u8]> {
        self.attributes
            .iter()
            .find(|a| a.typ == typ)
            .map(|a| a.value.as_slice())
    }

    pub fn get_string(&self, typ: u8) -> Option<String> {
        self.get(typ).map(|v| String::from_utf8_lossy(v).into_owned())
    }

    pub fn add(&mut self, typ: u8, value: impl Into<Vec<u8>>) {
        self.attributes.push(Attribute {
            typ,
            value: value.into(),
        });
    }

    pub fn add_u32(&mut self, typ: u8, value: u32) {
        self.add(typ, value.to_be_bytes().to_vec());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn roundtrip() {
        let mut p = Packet::new(Code::AccessRequest, 42, [7u8; 16]);
        p.add(crate::attributes::USER_NAME, b"martin".to_vec());
        p.add_u32(crate::attributes::NAS_PORT, 3);
        let bytes = p.encode().unwrap();
        assert_eq!(bytes.len(), 20 + 8 + 6);
        assert_eq!(Packet::decode(&bytes).unwrap(), p);
    }

    #[test]
    fn rejects_short_and_bad_lengths() {
        assert_eq!(Packet::decode(&[0u8; 10]), Err(DecodeError::TooShort(10)));
        let mut buf = [0u8; 20];
        buf[3] = 200; // Length größer als Datagramm
        assert!(matches!(Packet::decode(&buf), Err(DecodeError::BadLength { .. })));
    }

    #[test]
    fn rejects_zero_length_attribute() {
        let mut buf = vec![1, 1, 0, 22];
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(&[1, 0]); // Attribut mit Länge 0 -> Endlosschleife verhindern
        assert!(matches!(Packet::decode(&buf), Err(DecodeError::BadAttribute { .. })));
    }

    proptest! {
        /// Der Parser darf bei beliebigen Eingaben nie panicken.
        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = Packet::decode(&data);
        }

        /// Alles, was dekodiert werden kann, wird identisch wieder enkodiert.
        #[test]
        fn decode_encode_roundtrip(attrs in proptest::collection::vec(
            (any::<u8>(), proptest::collection::vec(any::<u8>(), 0..50)), 0..10)
        ) {
            let mut p = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
            for (t, v) in attrs { p.add(t, v); }
            let bytes = p.encode().unwrap();
            prop_assert_eq!(Packet::decode(&bytes).unwrap(), p);
        }
    }
}
