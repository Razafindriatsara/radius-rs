//! Gemeinsame Bausteine für die Weboberflächen (Eingangsportal und Admin).

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};

/// Schützt vor HTML-Injection: alle Werte werden vor der Ausgabe maskiert.
pub fn html_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Liest ein Cookie, das nur aus `len` Hex-Zeichen bestehen darf (Sitzungs-IDs).
pub fn hex_cookie(headers: &HeaderMap, name: &str, len: usize) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| {
            let (k, v) = c.trim().split_once('=')?;
            (k == name && v.len() == len && v.bytes().all(|b| b.is_ascii_hexdigit())).then(|| v.to_string())
        })
}

pub fn fmt_duration(secs: u32) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

pub fn fmt_bytes(b: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

pub fn asset(ct: &'static str, body: impl Into<String>) -> Response {
    let mut r = body.into().into_response();
    r.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(ct));
    r.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600"));
    r
}

pub fn page(code: StatusCode, html: String) -> Response {
    let mut r = (code, Html(html)).into_response();
    r.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

pub async fn security_headers(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    r
}

/// Vergleich in konstanter Zeit (CSRF-Token).
pub fn ct_eq_str(a: &str, b: &str) -> bool {
    crate::crypto::ct_eq(a.as_bytes(), b.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_formats() {
        assert_eq!(
            html_escape(r#"<a href="x">&'"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
        assert_eq!(fmt_duration(3725), "1:02:05");
        assert_eq!(fmt_bytes(52_428_800), "50.0 MB");
        assert!(ct_eq_str("abc", "abc") && !ct_eq_str("abc", "abd"));
    }
}
