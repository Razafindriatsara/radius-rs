//! Attribut-Typen nach RFC 2865 Abschnitt 5 (Auswahl) und RFC 3579.

pub const USER_NAME: u8 = 1;
pub const USER_PASSWORD: u8 = 2;
pub const CHAP_PASSWORD: u8 = 3;
pub const NAS_IP_ADDRESS: u8 = 4;
pub const NAS_PORT: u8 = 5;
pub const SERVICE_TYPE: u8 = 6;
pub const FRAMED_PROTOCOL: u8 = 7;
pub const FRAMED_IP_ADDRESS: u8 = 8;
pub const REPLY_MESSAGE: u8 = 18;
pub const STATE: u8 = 24;
pub const CLASS: u8 = 25;
pub const SESSION_TIMEOUT: u8 = 27;
pub const CALLED_STATION_ID: u8 = 30;
pub const CALLING_STATION_ID: u8 = 31;
pub const NAS_IDENTIFIER: u8 = 32;
pub const ACCT_STATUS_TYPE: u8 = 40;
pub const ACCT_INPUT_OCTETS: u8 = 42;
pub const ACCT_OUTPUT_OCTETS: u8 = 43;
pub const ACCT_SESSION_ID: u8 = 44;
pub const ACCT_SESSION_TIME: u8 = 46;
pub const ACCT_TERMINATE_CAUSE: u8 = 49;
pub const ACCT_INPUT_GIGAWORDS: u8 = 52;
pub const ACCT_OUTPUT_GIGAWORDS: u8 = 53;
pub const FRAMED_COMPRESSION: u8 = 13;
pub const FRAMED_MTU: u8 = 12;
pub const LOGIN_IP_HOST: u8 = 14;
pub const LOGIN_SERVICE: u8 = 15;
pub const EAP_MESSAGE: u8 = 79;
/// RFC 3579: HMAC-MD5 über das gesamte Paket. Pflicht seit BlastRADIUS (CVE-2024-3596).
pub const MESSAGE_AUTHENTICATOR: u8 = 80;

/// Menschlich lesbarer Name für Logs.
pub fn name(t: u8) -> &'static str {
    match t {
        USER_NAME => "User-Name",
        USER_PASSWORD => "User-Password",
        CHAP_PASSWORD => "CHAP-Password",
        NAS_IP_ADDRESS => "NAS-IP-Address",
        NAS_PORT => "NAS-Port",
        SERVICE_TYPE => "Service-Type",
        FRAMED_PROTOCOL => "Framed-Protocol",
        FRAMED_IP_ADDRESS => "Framed-IP-Address",
        FRAMED_MTU => "Framed-MTU",
        FRAMED_COMPRESSION => "Framed-Compression",
        LOGIN_IP_HOST => "Login-IP-Host",
        LOGIN_SERVICE => "Login-Service",
        REPLY_MESSAGE => "Reply-Message",
        STATE => "State",
        CLASS => "Class",
        SESSION_TIMEOUT => "Session-Timeout",
        CALLED_STATION_ID => "Called-Station-Id",
        CALLING_STATION_ID => "Calling-Station-Id",
        NAS_IDENTIFIER => "NAS-Identifier",
        ACCT_STATUS_TYPE => "Acct-Status-Type",
        ACCT_INPUT_OCTETS => "Acct-Input-Octets",
        ACCT_OUTPUT_OCTETS => "Acct-Output-Octets",
        ACCT_SESSION_ID => "Acct-Session-Id",
        ACCT_SESSION_TIME => "Acct-Session-Time",
        ACCT_TERMINATE_CAUSE => "Acct-Terminate-Cause",
        ACCT_INPUT_GIGAWORDS => "Acct-Input-Gigawords",
        ACCT_OUTPUT_GIGAWORDS => "Acct-Output-Gigawords",
        EAP_MESSAGE => "EAP-Message",
        MESSAGE_AUTHENTICATOR => "Message-Authenticator",
        _ => "Unknown",
    }
}
