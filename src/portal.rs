//! Eingangsportal (Captive Portal) für radius-rs.
//!
//! Das Portal arbeitet selbst als NAS: Es prüft Benutzername und Passwort per
//! RADIUS (PAP), legt bei Erfolg eine Sitzung an, meldet sie per Accounting
//! (Start/Stop) und beendet sie nach dem Session-Timeout des Servers.
//!
//! Hinweis: Das Portal steuert keine Firewall. In einem echten Hotspot gibt
//! ein Router/Gateway den Internetzugang frei; dieses Portal liefert die
//! Anmeldeseite, die Sitzungsverwaltung und die Anbindung an RADIUS.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::{ConnectInfo, Form, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{AppendHeaders, Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use crate::client::{
    ACCT_START, ACCT_STOP, AcctRequest, AuthOutcome, CAUSE_SESSION_TIMEOUT, CAUSE_USER_REQUEST, ClientConfig,
    ClientError, RadiusClient, random_bytes,
};

const COOKIE_NAME: &str = "portal_session";

#[derive(Debug, Clone)]
pub struct PortalConfig {
    pub listen: String,
    /// Überschrift der Anmeldeseite, z.B. "Gäste-WLAN Hotel Isar"
    pub title: String,
    pub client: ClientConfig,
    /// Cookie nur über HTTPS senden (hinter einem TLS-Proxy einschalten)
    pub secure_cookie: bool,
    /// Fehlversuche pro IP, bevor weitere Versuche gesperrt werden
    pub max_failures: u32,
    pub failure_window: Duration,
}

impl PortalConfig {
    /// Liest die Konfiguration aus Umgebungsvariablen (praktisch für Docker).
    pub fn from_env() -> Self {
        let var = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        Self {
            listen: var("PORTAL_LISTEN", "0.0.0.0:8080"),
            title: var("PORTAL_TITLE", "Gäste-WLAN"),
            client: ClientConfig {
                auth_server: var("RADIUS_SERVER", "127.0.0.1:1812"),
                acct_server: var("RADIUS_ACCT_SERVER", "127.0.0.1:1813"),
                secret: var("RADIUS_SECRET", "testing123"),
                nas_identifier: var("NAS_IDENTIFIER", "radius-portal"),
                timeout: Duration::from_secs(3),
                retries: 1,
            },
            secure_cookie: var("PORTAL_SECURE_COOKIE", "0") == "1",
            max_failures: var("PORTAL_MAX_FAILURES", "5").parse().unwrap_or(5),
            failure_window: Duration::from_secs(300),
        }
    }
}

#[derive(Debug, Clone)]
struct Session {
    user: String,
    acct_id: String,
    started: Instant,
    started_unix: u64,
    timeout: Option<u32>,
    reply: Option<String>,
    ip: IpAddr,
}

impl Session {
    fn elapsed(&self) -> u32 {
        self.started.elapsed().as_secs().min(u32::MAX as u64) as u32
    }
    fn expired(&self) -> bool {
        self.timeout.is_some_and(|t| self.elapsed() >= t)
    }
}

pub struct AppState {
    cfg: PortalConfig,
    client: RadiusClient,
    sessions: Mutex<HashMap<String, Session>>,
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl AppState {
    pub fn new(cfg: PortalConfig) -> Arc<Self> {
        Arc::new(Self {
            client: RadiusClient::new(cfg.client.clone()),
            cfg,
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
        })
    }

    /// Anzahl aktiver Sitzungen (für Tests und Monitoring).
    pub fn active_sessions(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    fn locked_out(&self, ip: IpAddr) -> bool {
        let mut f = self.failures.lock().unwrap();
        match f.get(&ip) {
            Some((n, since)) if since.elapsed() < self.cfg.failure_window => *n >= self.cfg.max_failures,
            Some(_) => {
                f.remove(&ip);
                false
            }
            None => false,
        }
    }

    fn record_failure(&self, ip: IpAddr) {
        let mut f = self.failures.lock().unwrap();
        let e = f.entry(ip).or_insert((0, Instant::now()));
        if e.1.elapsed() >= self.cfg.failure_window {
            *e = (0, Instant::now());
        }
        e.0 += 1;
    }

    /// Beendet eine Sitzung und meldet das Ende per Accounting.
    async fn end_session(&self, s: Session, cause: u32) {
        let req = AcctRequest {
            status: ACCT_STOP,
            user: s.user.clone(),
            session_id: s.acct_id.clone(),
            session_time: Some(s.elapsed()),
            terminate_cause: Some(cause),
            calling_station_id: Some(s.ip.to_string()),
            framed_ip: ipv4(s.ip),
        };
        if let Err(e) = self.client.accounting(&req).await {
            tracing::warn!(user = s.user, error = %e, "Accounting-Stop fehlgeschlagen");
        }
        tracing::info!(user = s.user, cause, "Sitzung beendet");
    }

    /// Beendet abgelaufene Sitzungen (Session-Timeout vom RADIUS-Server).
    pub async fn expire_sessions(&self) {
        let expired: Vec<Session> = {
            let mut map = self.sessions.lock().unwrap();
            let keys: Vec<String> = map
                .iter()
                .filter(|(_, s)| s.expired())
                .map(|(k, _)| k.clone())
                .collect();
            keys.iter().filter_map(|k| map.remove(k)).collect()
        };
        for s in expired {
            self.end_session(s, CAUSE_SESSION_TIMEOUT).await;
        }
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/login", post(login))
        .route("/status", get(status))
        .route("/logout", post(logout))
        .route("/health", get(|| async { "ok" }))
        .route("/app.css", get(|| async { asset("text/css; charset=utf-8", APP_CSS) }))
        .route(
            "/app.js",
            get(|| async { asset("text/javascript; charset=utf-8", APP_JS) }),
        )
        .route("/icon.svg", get(|| async { asset("image/svg+xml", ICON_SVG) }))
        .route("/manifest.webmanifest", get(manifest))
        .layer(axum::middleware::map_response(security_headers))
        .with_state(state)
}

/// Startet das Portal und den Hintergrund-Task für abgelaufene Sitzungen.
pub async fn run(cfg: PortalConfig) -> anyhow::Result<()> {
    let listen = cfg.listen.clone();
    let state = AppState::new(cfg);
    let bg = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            bg.expire_sessions().await;
        }
    });
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|e| anyhow::anyhow!("Kann {listen} nicht öffnen ({e})"))?;
    tracing::info!(addr = %listen, radius = state.cfg.client.auth_server, "Eingangsportal läuft");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}

// ---------------------------------------------------------------- Handler

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

async fn index(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if session_id(&headers).is_some_and(|id| st.sessions.lock().unwrap().contains_key(&id)) {
        return Redirect::to("/status").into_response();
    }
    page(StatusCode::OK, login_page(&st.cfg.title, None, ""))
}

async fn login(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Form(f): Form<LoginForm>,
) -> Response {
    let ip = peer.ip();
    let user = f.username.trim().to_string();
    let title = &st.cfg.title;

    if st.locked_out(ip) {
        let msg = "Zu viele Fehlversuche. Bitte warten Sie einige Minuten.";
        return page(StatusCode::TOO_MANY_REQUESTS, login_page(title, Some(msg), &user));
    }
    if user.is_empty() || user.len() > 64 || f.password.is_empty() || f.password.len() > 128 {
        let msg = "Bitte Benutzername und Passwort eingeben.";
        return page(StatusCode::BAD_REQUEST, login_page(title, Some(msg), &user));
    }

    match st.client.authenticate(&user, &f.password, Some(&ip.to_string())).await {
        Ok(AuthOutcome::Accept {
            session_timeout,
            reply_message,
        }) => {
            let (Ok(sid), Ok(aid)) = (random_bytes::<16>(), random_bytes::<8>()) else {
                return page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    login_page(title, Some("Interner Fehler."), &user),
                );
            };
            let (sid, acct_id) = (hex(&sid), format!("portal-{}", hex(&aid)));
            let session = Session {
                user: user.clone(),
                acct_id: acct_id.clone(),
                started: Instant::now(),
                started_unix: now_unix(),
                timeout: session_timeout,
                reply: reply_message,
                ip,
            };
            let start = AcctRequest {
                status: ACCT_START,
                user: user.clone(),
                session_id: acct_id,
                calling_station_id: Some(ip.to_string()),
                framed_ip: ipv4(ip),
                ..Default::default()
            };
            if let Err(e) = st.client.accounting(&start).await {
                tracing::warn!(user, error = %e, "Accounting-Start fehlgeschlagen");
            }
            st.sessions.lock().unwrap().insert(sid.clone(), session);
            tracing::info!(user, %ip, "Anmeldung erfolgreich");
            let max_age = session_timeout.unwrap_or(86_400);
            let cookie = format!(
                "{COOKIE_NAME}={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
                if st.cfg.secure_cookie { "; Secure" } else { "" }
            );
            (AppendHeaders([(SET_COOKIE, cookie)]), Redirect::to("/status")).into_response()
        }
        Ok(AuthOutcome::Reject { .. }) => {
            st.record_failure(ip);
            tracing::info!(user, %ip, "Anmeldung abgelehnt");
            let msg = "Benutzername oder Passwort ist falsch.";
            page(StatusCode::UNAUTHORIZED, login_page(title, Some(msg), &user))
        }
        Err(e) => {
            tracing::error!(error = %e, "RADIUS-Anfrage fehlgeschlagen");
            let msg = match e {
                ClientError::Timeout => "Der Anmeldedienst ist gerade nicht erreichbar. Bitte später erneut versuchen.",
                _ => "Die Anmeldung ist fehlgeschlagen. Bitte später erneut versuchen.",
            };
            page(StatusCode::SERVICE_UNAVAILABLE, login_page(title, Some(msg), &user))
        }
    }
}

async fn status(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(id) = session_id(&headers) else {
        return Redirect::to("/").into_response();
    };
    let session = st.sessions.lock().unwrap().get(&id).cloned();
    let Some(s) = session else {
        return Redirect::to("/").into_response();
    };
    if s.expired() {
        st.sessions.lock().unwrap().remove(&id);
        st.end_session(s, CAUSE_SESSION_TIMEOUT).await;
        return page(
            StatusCode::OK,
            message_page(&st.cfg.title, "Sitzung abgelaufen", "Ihre Nutzungszeit ist abgelaufen."),
        );
    }
    page(StatusCode::OK, status_page(&st.cfg.title, &s))
}

async fn logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let session = session_id(&headers).and_then(|id| st.sessions.lock().unwrap().remove(&id));
    if let Some(s) = session {
        st.end_session(s, CAUSE_USER_REQUEST).await;
    }
    let clear = format!("{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    let body = message_page(&st.cfg.title, "Abgemeldet", "Sie wurden sicher abgemeldet. Bis bald!");
    (AppendHeaders([(SET_COOKIE, clear)]), page(StatusCode::OK, body)).into_response()
}

async fn manifest(State(st): State<Arc<AppState>>) -> Response {
    let body = format!(
        r##"{{"name":"{t}","short_name":"WLAN","start_url":"/","display":"standalone","background_color":"#0f172a","theme_color":"#2563eb","icons":[{{"src":"/icon.svg","sizes":"any","type":"image/svg+xml","purpose":"any maskable"}}]}}"##,
        t = json_escape(&st.cfg.title)
    );
    asset("application/manifest+json", body)
}

// ---------------------------------------------------------------- Hilfsfunktionen

fn session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| {
            let (k, v) = c.trim().split_once('=')?;
            (k == COOKIE_NAME && v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit())).then(|| v.to_string())
        })
}

fn ipv4(ip: IpAddr) -> Option<[u8; 4]> {
    match ip {
        IpAddr::V4(v4) => Some(v4.octets()),
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v| v.octets()),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Schützt vor HTML-Injection: alle Werte (auch die Reply-Message vom Server) werden maskiert.
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

fn json_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect(),
            c if c.is_control() => vec![],
            c => vec![c],
        })
        .collect()
}

fn asset(ct: &'static str, body: impl Into<String>) -> Response {
    let mut r = body.into().into_response();
    r.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(ct));
    r.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600"));
    r
}

fn page(code: StatusCode, html: String) -> Response {
    let mut r = (code, Html(html)).into_response();
    r.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

async fn security_headers(mut r: Response) -> Response {
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

// ---------------------------------------------------------------- Seiten

fn shell(title: &str, body: &str) -> String {
    format!(
        r##"<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#2563eb">
<meta name="apple-mobile-web-app-capable" content="yes">
<title>{t}</title>
<link rel="manifest" href="/manifest.webmanifest">
<link rel="icon" href="/icon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/icon.svg">
<link rel="stylesheet" href="/app.css">
<script src="/app.js" defer></script>
</head>
<body>
<main class="app">
<header class="hero">
  <div class="logo" aria-hidden="true">{wifi}</div>
  <h1>{t}</h1>
</header>
{body}
<footer class="foot">Gesichert mit radius-rs · RADIUS nach RFC 2865</footer>
</main>
</body>
</html>"##,
        t = html_escape(title),
        wifi = WIFI_SVG,
    )
}

pub fn login_page(title: &str, error: Option<&str>, user: &str) -> String {
    let err = error
        .map(|e| format!(r#"<div class="alert" role="alert">{}</div>"#, html_escape(e)))
        .unwrap_or_default();
    shell(
        title,
        &format!(
            r#"<section class="card">
  <h2>Willkommen</h2>
  <p class="muted">Melden Sie sich an, um das Internet zu nutzen.</p>
  {err}
  <form method="post" action="/login" class="form" data-busy="Verbinde …">
    <label class="field">
      <span>Benutzername</span>
      <input name="username" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="64" required value="{u}">
    </label>
    <label class="field">
      <span>Passwort</span>
      <div class="pw">
        <input name="password" type="password" autocomplete="current-password" maxlength="128" required>
        <button type="button" class="toggle" aria-label="Passwort anzeigen">Anzeigen</button>
      </div>
    </label>
    <label class="check"><input type="checkbox" required> <span>Ich akzeptiere die Nutzungsbedingungen.</span></label>
    <button class="btn" type="submit">Verbinden</button>
  </form>
</section>"#,
            u = html_escape(user)
        ),
    )
}

fn status_page(title: &str, s: &Session) -> String {
    let (ring, remaining) = match s.timeout {
        Some(t) => {
            let left = t.saturating_sub(s.elapsed());
            let end_ms = (s.started_unix + t as u64) * 1000;
            (
                format!(
                    r#"<div class="ring" data-end="{end_ms}" data-total="{t}" data-p="{p:.4}">
  <svg viewBox="0 0 120 120" aria-hidden="true"><circle class="track" cx="60" cy="60" r="52"/><circle class="bar" cx="60" cy="60" r="52"/></svg>
  <div class="ring-text"><strong class="left">{l}</strong><span>verbleibend</span></div>
</div>"#,
                    p = left as f64 / t.max(1) as f64,
                    l = fmt_duration(left)
                ),
                fmt_duration(left),
            )
        }
        None => (
            r#"<div class="ring"><div class="ring-text"><strong>∞</strong><span>unbegrenzt</span></div></div>"#
                .to_string(),
            "unbegrenzt".to_string(),
        ),
    };
    let reply = s
        .reply
        .as_deref()
        .map(|r| format!(r#"<p class="welcome">{}</p>"#, html_escape(r)))
        .unwrap_or_default();
    shell(
        title,
        &format!(
            r#"<section class="card center">
  <div class="ok" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg></div>
  <h2>Verbunden</h2>
  {reply}
  {ring}
  <dl class="info">
    <div><dt>Benutzer</dt><dd>{u}</dd></div>
    <div><dt>Gerät</dt><dd>{ip}</dd></div>
    <div><dt>Restzeit</dt><dd class="left">{remaining}</dd></div>
  </dl>
  <form method="post" action="/logout" data-busy="Melde ab …"><button class="btn ghost" type="submit">Abmelden</button></form>
</section>"#,
            u = html_escape(&s.user),
            ip = html_escape(&s.ip.to_string()),
        ),
    )
}

fn message_page(title: &str, heading: &str, text: &str) -> String {
    shell(
        title,
        &format!(
            r#"<section class="card center">
  <h2>{h}</h2>
  <p class="muted">{t}</p>
  <a class="btn" href="/">Erneut anmelden</a>
</section>"#,
            h = html_escape(heading),
            t = html_escape(text)
        ),
    )
}

pub fn fmt_duration(secs: u32) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

// ---------------------------------------------------------------- Assets

const WIFI_SVG: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M2 8.5a15 15 0 0 1 20 0"/><path d="M5 12a10 10 0 0 1 14 0"/><path d="M8.5 15.5a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1.2" fill="currentColor"/></svg>"#;

const ICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="112" fill="#2563eb"/><g fill="none" stroke="#fff" stroke-width="36" stroke-linecap="round"><path d="M96 212a228 228 0 0 1 320 0"/><path d="M150 268a152 152 0 0 1 212 0"/><path d="M204 322a76 76 0 0 1 104 0"/></g><circle cx="256" cy="380" r="26" fill="#fff"/></svg>"##;

const APP_JS: &str = r#"// Passwort anzeigen, Ladezustand, Countdown-Ring
document.querySelectorAll('.toggle').forEach(b => b.addEventListener('click', () => {
  const i = b.parentElement.querySelector('input');
  const show = i.type === 'password';
  i.type = show ? 'text' : 'password';
  b.textContent = show ? 'Verbergen' : 'Anzeigen';
  b.setAttribute('aria-label', show ? 'Passwort verbergen' : 'Passwort anzeigen');
}));
document.querySelectorAll('form[data-busy]').forEach(f => f.addEventListener('submit', () => {
  const btn = f.querySelector('button[type=submit]');
  if (btn) { btn.disabled = true; btn.classList.add('busy'); btn.textContent = f.dataset.busy; }
}));
const ring = document.querySelector('.ring[data-end]');
if (ring) {
  const end = Number(ring.dataset.end), total = Number(ring.dataset.total);
  const bar = ring.querySelector('.bar');
  bar.style.setProperty('--p', ring.dataset.p);
  const fmt = s => { const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60;
    return h > 0 ? `${h}:${String(m).padStart(2,'0')}:${String(x).padStart(2,'0')}` : `${m}:${String(x).padStart(2,'0')}`; };
  const tick = () => {
    const left = Math.max(0, Math.round((end - Date.now()) / 1000));
    document.querySelectorAll('.left').forEach(e => e.textContent = fmt(left));
    bar.style.setProperty('--p', (left / total).toFixed(4));
    if (left === 0) { setTimeout(() => location.reload(), 1500); return; }
    setTimeout(tick, 1000);
  };
  tick();
}
"#;

const APP_CSS: &str = r#":root{--bg:#f1f5f9;--card:#fff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--brand:#2563eb;--brand2:#7c3aed;--ok:#16a34a;--err:#dc2626;--field:#f8fafc;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#0b1220;--card:#111a2e;--ink:#e2e8f0;--muted:#94a3b8;--line:#1e293b;--field:#0b1220}}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
.app{min-height:100dvh;display:flex;flex-direction:column;align-items:center;padding:0 16px calc(24px + env(safe-area-inset-bottom))}
.hero{width:calc(100% + 32px);padding:calc(40px + env(safe-area-inset-top)) 24px 72px;text-align:center;color:#fff;background:linear-gradient(135deg,var(--brand),var(--brand2));border-radius:0 0 32px 32px}
.hero h1{margin:12px 0 0;font-size:22px;font-weight:650;letter-spacing:.2px}
.logo{width:64px;height:64px;margin:0 auto;display:grid;place-items:center;border-radius:20px;background:rgba(255,255,255,.18);backdrop-filter:blur(6px)}
.logo svg{width:34px;height:34px}
.card{width:100%;max-width:420px;margin-top:-44px;background:var(--card);border-radius:24px;padding:28px 22px;box-shadow:0 10px 30px rgba(15,23,42,.12);animation:rise .35s ease-out}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.card h2{margin:0 0 4px;font-size:24px}
.center{text-align:center}
.muted{color:var(--muted);margin:0 0 20px}
.form{display:grid;gap:16px}
.field{display:grid;gap:6px;font-size:14px;font-weight:600;color:var(--muted)}
.field input{width:100%;height:52px;padding:0 16px;font:inherit;font-size:17px;color:var(--ink);background:var(--field);border:1.5px solid var(--line);border-radius:14px;outline:none;transition:border-color .15s,box-shadow .15s}
.field input:focus{border-color:var(--brand);box-shadow:0 0 0 4px rgba(37,99,235,.15)}
.pw{position:relative}
.pw input{padding-right:104px}
.toggle{position:absolute;right:6px;top:6px;height:40px;padding:0 14px;border:0;border-radius:10px;background:transparent;color:var(--brand);font:inherit;font-size:14px;font-weight:600;cursor:pointer}
.check{display:flex;gap:10px;align-items:flex-start;font-size:14px;color:var(--muted)}
.check input{width:20px;height:20px;margin:1px 0 0;accent-color:var(--brand)}
.btn{display:flex;align-items:center;justify-content:center;width:100%;height:54px;margin-top:4px;border:0;border-radius:16px;background:linear-gradient(135deg,var(--brand),var(--brand2));color:#fff;font:inherit;font-size:17px;font-weight:650;text-decoration:none;cursor:pointer;box-shadow:0 8px 20px rgba(37,99,235,.3);transition:transform .1s,opacity .15s}
.btn:active{transform:scale(.98)}
.btn.busy{opacity:.7}
.btn.ghost{background:transparent;color:var(--err);border:1.5px solid var(--line);box-shadow:none}
.alert{margin:0 0 16px;padding:12px 14px;border-radius:12px;background:rgba(220,38,38,.1);color:var(--err);font-size:15px;font-weight:500}
.ok{width:64px;height:64px;margin:0 auto 12px;border-radius:50%;background:rgba(22,163,74,.12);display:grid;place-items:center}
.ok svg{width:34px;height:34px;fill:none;stroke:var(--ok);stroke-width:2.5;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:24;stroke-dashoffset:24;animation:draw .5s .15s ease-out forwards}
@keyframes draw{to{stroke-dashoffset:0}}
.welcome{margin:0 0 8px;color:var(--muted)}
.ring{position:relative;width:180px;height:180px;margin:12px auto 20px}
.ring svg{width:100%;height:100%;transform:rotate(-90deg)}
.ring circle{fill:none;stroke-width:10}
.ring .track{stroke:var(--line)}
.ring .bar{stroke:var(--brand);stroke-linecap:round;stroke-dasharray:326.73;stroke-dashoffset:calc(326.73 * (1 - var(--p,1)));transition:stroke-dashoffset 1s linear}
.ring-text{position:absolute;inset:0;display:grid;place-content:center;gap:2px}
.ring-text strong{font-size:32px;font-variant-numeric:tabular-nums}
.ring-text span{font-size:13px;color:var(--muted)}
.info{margin:0 0 20px;border:1.5px solid var(--line);border-radius:16px;text-align:left}
.info div{display:flex;justify-content:space-between;gap:12px;padding:12px 16px}
.info div+div{border-top:1.5px solid var(--line)}
.info dt{color:var(--muted)}
.info dd{margin:0;font-weight:600;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.foot{margin-top:auto;padding-top:28px;font-size:12px;color:var(--muted)}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html() {
        assert_eq!(
            html_escape(r#"<script>alert("x")</script>&'"#),
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;&#39;"
        );
    }

    #[test]
    fn formats_duration() {
        assert_eq!(fmt_duration(59), "0:59");
        assert_eq!(fmt_duration(3600), "1:00:00");
        assert_eq!(fmt_duration(3725), "1:02:05");
    }

    #[test]
    fn reads_only_valid_session_cookie() {
        let mut h = HeaderMap::new();
        h.insert(
            COOKIE,
            HeaderValue::from_static("a=1; portal_session=0123456789abcdef0123456789abcdef; b=2"),
        );
        assert_eq!(session_id(&h).as_deref(), Some("0123456789abcdef0123456789abcdef"));
        let mut bad = HeaderMap::new();
        bad.insert(COOKIE, HeaderValue::from_static("portal_session=../../etc"));
        assert!(session_id(&bad).is_none());
    }

    #[test]
    fn login_page_escapes_username() {
        let html = login_page("WLAN", Some("<b>"), r#""><script>"#);
        assert!(!html.contains("<script>\""));
        assert!(html.contains("&quot;&gt;&lt;script&gt;"));
        assert!(html.contains("&lt;b&gt;"));
    }
}
