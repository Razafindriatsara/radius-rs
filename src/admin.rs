//! Admin-Oberfläche: Übersicht, aktive Sitzungen mit „Trennen“ (RFC 5176),
//! Verlauf mit CSV-Export, Benutzerverwaltung und Gast-Zugänge.
//!
//! Läuft im Prozess des RADIUS-Servers und nutzt dieselbe Datenbank.
//! Anmeldung mit eigenem Admin-Passwort (Argon2), alle Änderungen sind
//! durch ein CSRF-Token geschützt.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::Router;
use axum::extract::{ConnectInfo, Form, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{AppendHeaders, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use crate::accounting::{AccountingStore, Session, SessionFilter, terminate_cause_name};
use crate::client::{CAUSE_ADMIN_RESET, random_bytes};
use crate::coa::{DisconnectResult, ERROR_SESSION_NOT_FOUND, send_disconnect};
use crate::config::{AdminConfig, Clients};
use crate::users::{NewUser, User, UserError, UserStore, generate_guest_credentials, now};
use crate::web::{asset, ct_eq_str, fmt_bytes, fmt_duration, hex, hex_cookie, html_escape, page, security_headers};

const COOKIE_NAME: &str = "admin_session";
const LOGIN_LIFETIME: Duration = Duration::from_secs(8 * 3600);

pub struct AdminState {
    cfg: AdminConfig,
    users: Arc<UserStore>,
    sessions: Arc<AccountingStore>,
    clients: Arc<Clients>,
    /// Benutzer aus config.toml (nur zur Anzeige, dort nicht änderbar)
    config_users: Vec<String>,
    logins: Mutex<HashMap<String, (String, Instant)>>,
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    coa_timeout: Duration,
}

impl AdminState {
    pub fn new(
        cfg: AdminConfig,
        users: Arc<UserStore>,
        sessions: Arc<AccountingStore>,
        clients: Arc<Clients>,
        config_users: Vec<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            users,
            sessions,
            clients,
            config_users,
            logins: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            coa_timeout: Duration::from_secs(3),
        })
    }

    /// Prüft das Login-Cookie und liefert das CSRF-Token der Anmeldung.
    fn csrf(&self, headers: &HeaderMap) -> Option<String> {
        let token = hex_cookie(headers, COOKIE_NAME, 32)?;
        let mut logins = self.logins.lock().unwrap();
        match logins.get(&token) {
            Some((csrf, since)) if since.elapsed() < LOGIN_LIFETIME => Some(csrf.clone()),
            Some(_) => {
                logins.remove(&token);
                None
            }
            None => None,
        }
    }
}

pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/login", get(login_form).post(login))
        .route("/logout", post(logout))
        .route("/sessions", get(sessions))
        .route("/sessions.csv", get(sessions_csv))
        .route("/sessions/disconnect", post(disconnect))
        .route("/sessions/close", post(close_session))
        .route("/users", get(users_page).post(create_user))
        .route("/users/action", post(user_action))
        .route("/guests", get(guest_form).post(create_guest))
        .route(
            "/admin.css",
            get(|| async { asset("text/css; charset=utf-8", ADMIN_CSS) }),
        )
        .route(
            "/admin.js",
            get(|| async { asset("text/javascript; charset=utf-8", ADMIN_JS) }),
        )
        .route(
            "/icon.svg",
            get(|| async { asset("image/svg+xml", crate::portal::ICON_SVG) }),
        )
        .layer(axum::middleware::map_response(security_headers))
        .with_state(state)
}

pub async fn run(state: Arc<AdminState>) -> anyhow::Result<()> {
    let listen = state.cfg.listen.clone();
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|e| anyhow::anyhow!("Kann Admin-Oberfläche auf {listen} nicht öffnen ({e})"))?;
    tracing::info!(addr = %listen, "Admin-Oberfläche läuft");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------- Anmeldung

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

async fn login_form(State(st): State<Arc<AdminState>>) -> Response {
    page(StatusCode::OK, login_page(&st.cfg.title, None))
}

async fn login(
    State(st): State<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Form(f): Form<LoginForm>,
) -> Response {
    let ip = peer.ip();
    {
        let mut fails = st.failures.lock().unwrap();
        if let Some((n, since)) = fails.get(&ip).copied() {
            if since.elapsed() >= Duration::from_secs(300) {
                fails.remove(&ip);
            } else if n >= 5 {
                let msg = "Zu viele Fehlversuche. Bitte in einigen Minuten erneut versuchen.";
                return page(StatusCode::TOO_MANY_REQUESTS, login_page(&st.cfg.title, Some(msg)));
            }
        }
    }
    let hash = st.cfg.password_hash.clone();
    let pw = f.password;
    // Argon2 ist absichtlich rechenintensiv: nicht im Async-Worker ausführen
    let ok = tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash).is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
    })
    .await
    .unwrap_or(false);
    if !ok {
        let mut fails = st.failures.lock().unwrap();
        let e = fails.entry(ip).or_insert((0, Instant::now()));
        e.0 += 1;
        tracing::warn!(%ip, "Admin-Anmeldung fehlgeschlagen");
        return page(
            StatusCode::UNAUTHORIZED,
            login_page(&st.cfg.title, Some("Das Passwort ist falsch.")),
        );
    }
    let (Ok(t), Ok(c)) = (random_bytes::<16>(), random_bytes::<16>()) else {
        return page(
            StatusCode::INTERNAL_SERVER_ERROR,
            login_page(&st.cfg.title, Some("Interner Fehler.")),
        );
    };
    let token = hex(&t);
    st.logins
        .lock()
        .unwrap()
        .insert(token.clone(), (hex(&c), Instant::now()));
    st.failures.lock().unwrap().remove(&ip);
    tracing::info!(%ip, "Admin angemeldet");
    let cookie = format!(
        "{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        LOGIN_LIFETIME.as_secs()
    );
    (AppendHeaders([(SET_COOKIE, cookie)]), Redirect::to("/")).into_response()
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

async fn logout(State(st): State<Arc<AdminState>>, headers: HeaderMap, Form(f): Form<CsrfForm>) -> Response {
    if let Some(r) = guard(&st, &headers, &f.csrf) {
        return r;
    }
    if let Some(t) = hex_cookie(&headers, COOKIE_NAME, 32) {
        st.logins.lock().unwrap().remove(&t);
    }
    let clear = format!("{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    (AppendHeaders([(SET_COOKIE, clear)]), Redirect::to("/login")).into_response()
}

/// Prüft Anmeldung und CSRF-Token für ändernde Aktionen.
fn guard(st: &AdminState, headers: &HeaderMap, csrf: &str) -> Option<Response> {
    match st.csrf(headers) {
        None => Some(Redirect::to("/login").into_response()),
        Some(expected) if !ct_eq_str(&expected, csrf) => Some(page(
            StatusCode::FORBIDDEN,
            simple_page("Sitzung ungültig", "Bitte laden Sie die Seite neu."),
        )),
        Some(_) => None,
    }
}

// ---------------------------------------------------------------- Übersicht und Sitzungen

#[derive(Deserialize, Default)]
struct Flash {
    m: Option<String>,
}

async fn dashboard(State(st): State<Arc<AdminState>>, headers: HeaderMap, Query(fl): Query<Flash>) -> Response {
    let Some(csrf) = st.csrf(&headers) else {
        return Redirect::to("/login").into_response();
    };
    let stats = st.sessions.stats(now() - 86_400).unwrap_or_default();
    let active = st
        .sessions
        .query(&SessionFilter {
            active_only: true,
            limit: 200,
            ..Default::default()
        })
        .unwrap_or_default();
    let user_count = st.users.list().map(|u| u.len()).unwrap_or(0) + st.config_users.len();

    let tiles = format!(
        r#"<div class="tiles">
  <div class="tile"><span>Aktive Sitzungen</span><strong>{}</strong></div>
  <div class="tile"><span>Sitzungen (24 h)</span><strong>{}</strong></div>
  <div class="tile"><span>Download (24 h)</span><strong>{}</strong></div>
  <div class="tile"><span>Benutzer</span><strong>{}</strong></div>
</div>"#,
        stats.active,
        stats.sessions_since,
        fmt_bytes(stats.output_octets_since),
        user_count
    );
    let rows: String = active
        .iter()
        .map(|s| {
            format!(
                r#"<tr><td><strong>{u}</strong></td><td>{nas}</td><td>{ip}</td><td>{start}</td><td class="num">{dur}</td>
<td><div class="actions">{disc}{close}</div></td></tr>"#,
                u = html_escape(&s.user),
                nas = html_escape(&s.nas),
                ip = html_escape(s.framed_ip.as_deref().unwrap_or("–")),
                start = time_tag(s.started_at),
                dur = fmt_duration((now() - s.started_at).clamp(0, u32::MAX as i64) as u32),
                disc = session_button("/sessions/disconnect", "Trennen", "btn small danger", s, &csrf),
                close = session_button("/sessions/close", "Als beendet markieren", "btn small ghost", s, &csrf),
            )
        })
        .collect();
    let table = if active.is_empty() {
        r#"<p class="empty">Gerade ist niemand verbunden.</p>"#.to_string()
    } else {
        format!(
            r#"<div class="table"><table><thead><tr><th>Benutzer</th><th>NAS</th><th>Gerät</th><th>Beginn</th><th class="num">Dauer</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>"#
        )
    };
    let body = format!(
        r#"{tiles}<section class="card"><div class="card-head"><h2>Aktive Sitzungen</h2><a class="link" href="/sessions">Verlauf ansehen</a></div>{table}
<p class="hint">„Trennen“ sendet einen Disconnect-Request nach RFC 5176 an den NAS. Antwortet er nicht (zum Beispiel weil er das nicht unterstützt), lässt sich die Sitzung als beendet markieren.</p></section>"#
    );
    page(
        StatusCode::OK,
        shell(&st.cfg.title, "home", &csrf, flash(fl.m.as_deref()), &body),
    )
}

fn session_button(action: &str, label: &str, class: &str, s: &Session, csrf: &str) -> String {
    format!(
        r#"<form method="post" action="{action}"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="session_id" value="{sid}"><input type="hidden" name="nas" value="{nas}"><button class="{class}">{label}</button></form>"#,
        sid = html_escape(&s.session_id),
        nas = html_escape(&s.nas),
    )
}

#[derive(Deserialize)]
struct SessionForm {
    csrf: String,
    session_id: String,
    nas: String,
}

async fn disconnect(State(st): State<Arc<AdminState>>, headers: HeaderMap, Form(f): Form<SessionForm>) -> Response {
    if let Some(r) = guard(&st, &headers, &f.csrf) {
        return r;
    }
    let Ok(Some(s)) = st.sessions.find(&f.session_id, &f.nas) else {
        return Redirect::to("/?m=unknown").into_response();
    };
    let Some(ip) = s.nas_addr.as_deref().and_then(|a| a.parse::<IpAddr>().ok()) else {
        return Redirect::to("/?m=noaddr").into_response();
    };
    let Some(client) = st.clients.find(&ip).cloned() else {
        return Redirect::to("/?m=noaddr").into_response();
    };
    let target = SocketAddr::new(ip, client.coa_port);
    let code = match send_disconnect(target, &client.secret, &s.user, &s.session_id, st.coa_timeout).await {
        Ok(DisconnectResult::Ack) => {
            tracing::info!(user = s.user, nas = s.nas, "Sitzung getrennt (Disconnect-ACK)");
            // Der NAS meldet das Ende per Accounting-Stop; kurz warten, damit die Übersicht stimmt.
            for _ in 0..10 {
                if st
                    .sessions
                    .find(&s.session_id, &s.nas)
                    .ok()
                    .flatten()
                    .is_some_and(|x| x.stopped_at.is_some())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            "disconnected"
        }
        Ok(DisconnectResult::Nak(Some(ERROR_SESSION_NOT_FOUND))) => "nak-unknown",
        Ok(DisconnectResult::Nak(_)) => "nak",
        Err(e) => {
            tracing::warn!(user = s.user, nas = s.nas, %target, error = %e, "Disconnect fehlgeschlagen");
            "timeout"
        }
    };
    Redirect::to(&format!("/?m={code}")).into_response()
}

async fn close_session(State(st): State<Arc<AdminState>>, headers: HeaderMap, Form(f): Form<SessionForm>) -> Response {
    if let Some(r) = guard(&st, &headers, &f.csrf) {
        return r;
    }
    let code = match st.sessions.mark_stopped(&f.session_id, &f.nas, CAUSE_ADMIN_RESET) {
        Ok(true) => "closed",
        _ => "unknown",
    };
    Redirect::to(&format!("/?m={code}")).into_response()
}

#[derive(Deserialize, Default)]
struct SessionQuery {
    user: Option<String>,
    active: Option<String>,
}

impl SessionQuery {
    fn filter(&self, limit: u32) -> SessionFilter {
        SessionFilter {
            user: self.user.clone(),
            active_only: self.active.as_deref() == Some("1"),
            limit,
        }
    }
}

async fn sessions(State(st): State<Arc<AdminState>>, headers: HeaderMap, Query(q): Query<SessionQuery>) -> Response {
    let Some(csrf) = st.csrf(&headers) else {
        return Redirect::to("/login").into_response();
    };
    let list = st.sessions.query(&q.filter(500)).unwrap_or_default();
    let rows: String = list
        .iter()
        .map(|s| {
            let status = match (s.stopped_at, s.terminate_cause) {
                (None, _) => r#"<span class="badge ok">aktiv</span>"#.to_string(),
                (Some(_), Some(c)) => format!(r#"<span class="badge">{}</span>"#, terminate_cause_name(c)),
                (Some(_), None) => r#"<span class="badge">beendet</span>"#.to_string(),
            };
            format!(
                r#"<tr><td>{start}</td><td><strong>{u}</strong></td><td>{nas}</td><td class="num">{dur}</td><td class="num">{down}</td><td class="num">{up}</td><td>{status}</td></tr>"#,
                start = time_tag(s.started_at),
                u = html_escape(&s.user),
                nas = html_escape(&s.nas),
                dur = fmt_duration(s.session_time.clamp(0, u32::MAX as i64) as u32),
                down = fmt_bytes(s.output_octets),
                up = fmt_bytes(s.input_octets),
            )
        })
        .collect();
    let user = html_escape(q.user.as_deref().unwrap_or(""));
    let checked = if q.active.as_deref() == Some("1") {
        " checked"
    } else {
        ""
    };
    let csv = format!(
        "/sessions.csv?user={}&active={}",
        urlencode(q.user.as_deref().unwrap_or("")),
        q.active.as_deref().unwrap_or("")
    );
    let body = format!(
        r#"<section class="card"><div class="card-head"><h2>Verlauf</h2><a class="btn small ghost" href="{csv}">CSV exportieren</a></div>
<form class="filters" method="get" action="/sessions"><input name="user" placeholder="Benutzer suchen" value="{user}"><label class="check"><input type="checkbox" name="active" value="1"{checked}> nur aktive</label><button class="btn small">Filtern</button></form>
<div class="table"><table><thead><tr><th>Beginn</th><th>Benutzer</th><th>NAS</th><th class="num">Dauer</th><th class="num">Download</th><th class="num">Upload</th><th>Ende</th></tr></thead><tbody>{rows}</tbody></table></div>
<p class="hint">{n} Sitzungen angezeigt (höchstens 500).</p></section>"#,
        n = list.len()
    );
    page(
        StatusCode::OK,
        shell(&st.cfg.title, "sessions", &csrf, String::new(), &body),
    )
}

async fn sessions_csv(
    State(st): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(q): Query<SessionQuery>,
) -> Response {
    if st.csrf(&headers).is_none() {
        return Redirect::to("/login").into_response();
    }
    let list = st.sessions.query(&q.filter(100_000)).unwrap_or_default();
    let mut out = String::from(
        "session_id;user;nas;nas_addr;framed_ip;started_at;stopped_at;session_time_s;download_bytes;upload_bytes;terminate_cause\r\n",
    );
    for s in &list {
        let fields = [
            csv_field(&s.session_id),
            csv_field(&s.user),
            csv_field(&s.nas),
            csv_field(s.nas_addr.as_deref().unwrap_or("")),
            csv_field(s.framed_ip.as_deref().unwrap_or("")),
            iso_utc(s.started_at),
            s.stopped_at.map(iso_utc).unwrap_or_default(),
            s.session_time.to_string(),
            s.output_octets.to_string(),
            s.input_octets.to_string(),
            s.terminate_cause
                .map(|c| terminate_cause_name(c).to_string())
                .unwrap_or_default(),
        ];
        out.push_str(&fields.join(";"));
        out.push_str("\r\n");
    }
    let mut r = out.into_response();
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/csv; charset=utf-8"));
    r.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"radius-sitzungen.csv\""),
    );
    r
}

/// CSV-Feld in Anführungszeichen; Formeln (=, +, -, @) werden entschärft (CSV-Injection).
fn csv_field(v: &str) -> String {
    let v = if v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{v}")
    } else {
        v.to_string()
    };
    format!("\"{}\"", v.replace('"', "\"\""))
}

// ---------------------------------------------------------------- Benutzer

async fn users_page(State(st): State<Arc<AdminState>>, headers: HeaderMap, Query(fl): Query<Flash>) -> Response {
    let Some(csrf) = st.csrf(&headers) else {
        return Redirect::to("/login").into_response();
    };
    let users = st.users.list().unwrap_or_default();
    let t = now();
    let rows: String = users.iter().map(|u| user_row(u, t, &csrf)).collect::<String>()
        + &st
            .config_users
            .iter()
            .map(|n| {
                format!(
                    r#"<tr><td><strong>{}</strong> <span class="badge">config.toml</span></td><td><span class="badge ok">aktiv</span></td><td>–</td><td>–</td><td class="muted small">in config.toml verwaltet</td></tr>"#,
                    html_escape(n)
                )
            })
            .collect::<String>();
    let body = format!(
        r#"<section class="card"><h2>Neuer Benutzer</h2>
<form class="grid-form" method="post" action="/users"><input type="hidden" name="csrf" value="{csrf}">
<label><span>Benutzername</span><input name="name" required maxlength="64" pattern="[A-Za-z0-9._@\-]+" autocomplete="off"></label>
<label><span>Passwort (mind. 8 Zeichen)</span><input name="password" type="password" required minlength="8" autocomplete="new-password"></label>
<label><span>Max. Sitzungsdauer (Minuten, leer = unbegrenzt)</span><input name="session_minutes" inputmode="numeric" pattern="[0-9]*"></label>
<label><span>Begrüßung (optional)</span><input name="reply_message" maxlength="200"></label>
<label class="wide"><span>Notiz (optional)</span><input name="note" maxlength="200"></label>
<button class="btn">Benutzer anlegen</button></form></section>
<section class="card"><h2>Benutzer</h2><div class="table"><table><thead><tr><th>Name</th><th>Status</th><th>Sitzung</th><th>Gültig bis</th><th>Aktionen</th></tr></thead><tbody>{rows}</tbody></table></div></section>"#
    );
    page(
        StatusCode::OK,
        shell(&st.cfg.title, "users", &csrf, flash(fl.m.as_deref()), &body),
    )
}

fn user_row(u: &User, t: i64, csrf: &str) -> String {
    let status = if u.expired(t) {
        r#"<span class="badge warn">abgelaufen</span>"#
    } else if !u.enabled {
        r#"<span class="badge err">gesperrt</span>"#
    } else {
        r#"<span class="badge ok">aktiv</span>"#
    };
    let kind = if u.is_guest {
        r#" <span class="badge">Gast</span>"#
    } else {
        ""
    };
    let note = u
        .note
        .as_deref()
        .map(|n| format!(r#"<div class="muted small">{}</div>"#, html_escape(n)))
        .unwrap_or_default();
    let name = html_escape(&u.name);
    let act = |action: &str, label: &str, class: &str| {
        format!(
            r#"<form method="post" action="/users/action"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="name" value="{name}"><input type="hidden" name="action" value="{action}"><button class="{class}"{confirm}>{label}</button></form>"#,
            confirm = if action == "delete" {
                r#" data-confirm="Benutzer wirklich löschen?""#
            } else {
                ""
            }
        )
    };
    let toggle = if u.enabled {
        act("disable", "Sperren", "btn small ghost")
    } else {
        act("enable", "Entsperren", "btn small ghost")
    };
    let pw = format!(
        r#"<form method="post" action="/users/action" class="inline"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="name" value="{name}"><input type="hidden" name="action" value="password"><input name="password" type="password" minlength="8" placeholder="Neues Passwort" required autocomplete="new-password"><button class="btn small ghost">Setzen</button></form>"#
    );
    format!(
        r#"<tr><td><strong>{name}</strong>{kind}{note}</td><td>{status}</td><td>{sess}</td><td>{exp}</td><td><div class="actions">{toggle}{pw}{del}</div></td></tr>"#,
        sess = u
            .session_timeout
            .map(fmt_duration)
            .unwrap_or_else(|| "unbegrenzt".into()),
        exp = u.expires_at.map(time_tag).unwrap_or_else(|| "–".into()),
        del = act("delete", "Löschen", "btn small danger"),
    )
}

#[derive(Deserialize)]
struct UserForm {
    csrf: String,
    name: String,
    password: String,
    #[serde(default)]
    session_minutes: String,
    #[serde(default)]
    reply_message: String,
    #[serde(default)]
    note: String,
}

async fn create_user(State(st): State<Arc<AdminState>>, headers: HeaderMap, Form(f): Form<UserForm>) -> Response {
    if let Some(r) = guard(&st, &headers, &f.csrf) {
        return r;
    }
    let name = f.name.trim().to_string();
    if st.config_users.iter().any(|n| n == &name) {
        return Redirect::to("/users?m=exists").into_response();
    }
    let session_timeout = match f.session_minutes.trim() {
        "" => None,
        m => match m.parse::<u32>() {
            Ok(v) if v > 0 => Some(v.saturating_mul(60)),
            _ => return Redirect::to("/users?m=badnumber").into_response(),
        },
    };
    let u = NewUser {
        name,
        password: f.password,
        session_timeout,
        reply_message: Some(f.reply_message.trim().to_string()).filter(|s| !s.is_empty()),
        note: Some(f.note.trim().to_string()).filter(|s| !s.is_empty()),
        ..Default::default()
    };
    let users = st.users.clone();
    let r = tokio::task::spawn_blocking(move || users.create(&u)).await;
    Redirect::to(&format!("/users?m={}", user_result(r, "created"))).into_response()
}

#[derive(Deserialize)]
struct ActionForm {
    csrf: String,
    name: String,
    action: String,
    #[serde(default)]
    password: String,
}

async fn user_action(State(st): State<Arc<AdminState>>, headers: HeaderMap, Form(f): Form<ActionForm>) -> Response {
    if let Some(r) = guard(&st, &headers, &f.csrf) {
        return r;
    }
    let users = st.users.clone();
    let (name, action, pw) = (f.name, f.action, f.password);
    let ok_code = match action.as_str() {
        "enable" => "enabled",
        "disable" => "disabled",
        "delete" => "deleted",
        "password" => "password",
        _ => return Redirect::to("/users?m=error").into_response(),
    };
    let r = tokio::task::spawn_blocking(move || match action.as_str() {
        "enable" => users.set_enabled(&name, true),
        "disable" => users.set_enabled(&name, false),
        "delete" => users.delete(&name),
        _ => users.set_password(&name, &pw),
    })
    .await;
    Redirect::to(&format!("/users?m={}", user_result(r, ok_code))).into_response()
}

fn user_result(r: Result<Result<(), UserError>, tokio::task::JoinError>, ok: &'static str) -> &'static str {
    match r {
        Ok(Ok(())) => ok,
        Ok(Err(UserError::InvalidName)) => "badname",
        Ok(Err(UserError::WeakPassword)) => "weak",
        Ok(Err(UserError::Exists)) => "exists",
        Ok(Err(UserError::NotFound)) => "notfound",
        _ => "error",
    }
}

// ---------------------------------------------------------------- Gast-Zugänge

async fn guest_form(State(st): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some(csrf) = st.csrf(&headers) else {
        return Redirect::to("/login").into_response();
    };
    let body = format!(
        r#"<section class="card narrow"><h2>Gast-Zugang erstellen</h2><p class="muted">Erzeugt Benutzername und Passwort zum Ausdrucken oder Weitergeben. Der Zugang erlischt automatisch.</p>
<form class="grid-form one" method="post" action="/guests"><input type="hidden" name="csrf" value="{csrf}">
<label><span>Gültig für</span><select name="hours"><option value="1">1 Stunde</option><option value="4">4 Stunden</option><option value="8">8 Stunden</option><option value="24" selected>24 Stunden</option><option value="72">3 Tage</option><option value="168">7 Tage</option></select></label>
<label><span>Notiz (z.B. Zimmer 12)</span><input name="note" maxlength="100"></label>
<button class="btn">Zugang erstellen</button></form></section>"#
    );
    page(
        StatusCode::OK,
        shell(&st.cfg.title, "guests", &csrf, String::new(), &body),
    )
}

#[derive(Deserialize)]
struct GuestForm {
    csrf: String,
    hours: u32,
    #[serde(default)]
    note: String,
}

async fn create_guest(State(st): State<Arc<AdminState>>, headers: HeaderMap, Form(f): Form<GuestForm>) -> Response {
    if let Some(r) = guard(&st, &headers, &f.csrf) {
        return r;
    }
    let csrf = st.csrf(&headers).unwrap_or_default();
    let hours = f.hours.clamp(1, 24 * 30);
    let expires = now() + hours as i64 * 3600;
    let note = Some(f.note.trim().to_string()).filter(|s| !s.is_empty());
    let users = st.users.clone();
    let n2 = note.clone();
    let created = tokio::task::spawn_blocking(move || {
        for _ in 0..5 {
            let (name, password) = generate_guest_credentials()?;
            let u = NewUser {
                name: name.clone(),
                password: password.clone(),
                session_timeout: Some(hours * 3600),
                expires_at: Some(expires),
                is_guest: true,
                note: n2.clone(),
                ..Default::default()
            };
            match users.create(&u) {
                Ok(()) => return Ok((name, password)),
                Err(UserError::Exists) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(UserError::Exists)
    })
    .await;
    let Ok(Ok((name, password))) = created else {
        return Redirect::to("/users?m=error").into_response();
    };
    tracing::info!(user = name, hours, "Gast-Zugang erstellt");
    let body = format!(
        r#"<section class="voucher">
  <div class="voucher-head"><img src="/icon.svg" alt=""><div><strong>WLAN-Zugang</strong><span>{title}</span></div></div>
  <dl><div><dt>Benutzername</dt><dd class="mono">{name}</dd></div><div><dt>Passwort</dt><dd class="mono">{password}</dd></div><div><dt>Gültig bis</dt><dd>{exp}</dd></div></dl>
  {note}
  <p class="muted small">Mit dem WLAN verbinden, Browser öffnen und mit diesen Daten anmelden.</p>
</section>
<div class="voucher-actions no-print"><button class="btn" data-print>Drucken</button><a class="btn ghost" href="/guests">Weiteren Zugang erstellen</a></div>"#,
        title = html_escape(&st.cfg.title),
        name = html_escape(&name),
        password = html_escape(&password),
        exp = time_tag(expires),
        note = note
            .map(|n| format!(r#"<p class="voucher-note">{}</p>"#, html_escape(&n)))
            .unwrap_or_default(),
    );
    page(
        StatusCode::OK,
        shell(&st.cfg.title, "guests", &csrf, String::new(), &body),
    )
}

// ---------------------------------------------------------------- Seitenrahmen

fn flash(code: Option<&str>) -> String {
    let (kind, text) = match code.unwrap_or("") {
        "disconnected" => ("ok", "Sitzung getrennt. Der NAS hat den Disconnect-Request bestätigt."),
        "closed" => ("ok", "Sitzung als beendet markiert."),
        "nak-unknown" => (
            "warn",
            "Der NAS kennt diese Sitzung nicht mehr. Sie können sie als beendet markieren.",
        ),
        "nak" => ("err", "Der NAS hat das Trennen abgelehnt."),
        "timeout" => (
            "err",
            "Der NAS antwortet nicht auf Disconnect-Requests. Sie können die Sitzung als beendet markieren.",
        ),
        "noaddr" => (
            "err",
            "Für diese Sitzung ist keine NAS-Adresse bekannt oder der NAS ist nicht als Client eingetragen.",
        ),
        "unknown" => ("err", "Sitzung nicht gefunden oder bereits beendet."),
        "created" => ("ok", "Benutzer angelegt."),
        "enabled" => ("ok", "Benutzer entsperrt."),
        "disabled" => (
            "ok",
            "Benutzer gesperrt. Laufende Sitzungen bleiben bis zum Trennen bestehen.",
        ),
        "deleted" => ("ok", "Benutzer gelöscht."),
        "password" => ("ok", "Passwort geändert."),
        "exists" => ("err", "Diesen Benutzernamen gibt es bereits."),
        "badname" => (
            "err",
            "Benutzername ungültig: 1 bis 64 Zeichen, nur Buchstaben, Ziffern und . _ - @",
        ),
        "weak" => ("err", "Das Passwort muss mindestens 8 Zeichen haben."),
        "badnumber" => ("err", "Die Sitzungsdauer muss eine positive ganze Zahl sein."),
        "notfound" => ("err", "Benutzer nicht gefunden."),
        "error" => ("err", "Die Aktion ist fehlgeschlagen."),
        _ => return String::new(),
    };
    format!(r#"<div class="flash {kind}" role="status">{text}</div>"#)
}

fn shell(title: &str, active: &str, csrf: &str, flash: String, body: &str) -> String {
    let tab = |id: &str, href: &str, label: &str| {
        format!(
            r#"<a href="{href}"{}>{label}</a>"#,
            if id == active {
                r#" class="active" aria-current="page""#
            } else {
                ""
            }
        )
    };
    format!(
        r##"<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#2563eb"><title>{t}</title><link rel="icon" href="/icon.svg"><link rel="stylesheet" href="/admin.css"><script src="/admin.js" defer></script></head>
<body><header class="bar no-print"><div class="brand"><img src="/icon.svg" alt=""><span>{t}</span></div>
<nav>{home}{sessions}{users}{guests}</nav>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{csrf}"><button class="btn small ghost light">Abmelden</button></form></header>
<main class="wrap">{flash}{body}</main></body></html>"##,
        t = html_escape(title),
        home = tab("home", "/", "Übersicht"),
        sessions = tab("sessions", "/sessions", "Verlauf"),
        users = tab("users", "/users", "Benutzer"),
        guests = tab("guests", "/guests", "Gast-Zugang"),
    )
}

fn login_page(title: &str, error: Option<&str>) -> String {
    let err = error
        .map(|e| format!(r#"<div class="flash err" role="alert">{}</div>"#, html_escape(e)))
        .unwrap_or_default();
    format!(
        r##"<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#2563eb"><title>{t}</title><link rel="icon" href="/icon.svg"><link rel="stylesheet" href="/admin.css"></head>
<body class="login"><main class="login-card"><img src="/icon.svg" alt="" class="login-icon"><h1>{t}</h1><p class="muted">Bitte mit dem Admin-Passwort anmelden.</p>{err}
<form method="post" action="/login"><label><span>Passwort</span><input name="password" type="password" required autocomplete="current-password" autofocus></label><button class="btn">Anmelden</button></form></main></body></html>"##,
        t = html_escape(title)
    )
}

fn simple_page(h: &str, text: &str) -> String {
    format!(
        r#"<!doctype html><html lang="de"><head><meta charset="utf-8"><link rel="stylesheet" href="/admin.css"></head><body class="login"><main class="login-card"><h1>{}</h1><p class="muted">{}</p><a class="btn" href="/">Zur Übersicht</a></main></body></html>"#,
        html_escape(h),
        html_escape(text)
    )
}

/// Zeitpunkt als `<time>`: der Browser zeigt ihn in Ortszeit an, ohne JavaScript erscheint UTC.
fn time_tag(ts: i64) -> String {
    format!(
        r#"<time data-ts="{ts}">{}</time>"#,
        iso_utc(ts).replace('T', " ").replace('Z', " UTC")
    )
}

/// Unix-Zeit als ISO 8601 in UTC (ohne zusätzliche Bibliothek).
pub fn iso_utc(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    // Algorithmus „civil_from_days“ (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

const ADMIN_JS: &str = r#"// Ortszeit anzeigen, Löschen bestätigen, Drucken
document.querySelectorAll('time[data-ts]').forEach(t => {
  const d = new Date(Number(t.dataset.ts) * 1000);
  t.title = t.textContent;
  t.textContent = d.toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' });
});
document.querySelectorAll('[data-confirm]').forEach(b => b.addEventListener('click', e => {
  if (!window.confirm(b.dataset.confirm)) e.preventDefault();
}));
document.querySelectorAll('[data-print]').forEach(b => b.addEventListener('click', () => window.print()));
"#;

const ADMIN_CSS: &str = r#":root{--bg:#f1f5f9;--card:#fff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--brand:#2563eb;--brand2:#7c3aed;--ok:#16a34a;--warn:#d97706;--err:#dc2626;--field:#f8fafc;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#0b1220;--card:#111a2e;--ink:#e2e8f0;--muted:#94a3b8;--line:#1e293b;--field:#0b1220}}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
.bar{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:20px;padding:12px 24px;color:#fff;background:linear-gradient(135deg,var(--brand),var(--brand2));box-shadow:0 2px 12px rgba(15,23,42,.15);flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;font-weight:650;font-size:16px}
.brand img{width:30px;height:30px;border-radius:8px}
nav{display:flex;gap:4px;flex:1;overflow-x:auto}
nav a{padding:8px 14px;border-radius:10px;color:rgba(255,255,255,.85);text-decoration:none;font-weight:550;white-space:nowrap}
nav a:hover{background:rgba(255,255,255,.12)}
nav a.active{background:rgba(255,255,255,.22);color:#fff}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px 48px;display:grid;gap:20px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
.tile{background:var(--card);border-radius:18px;padding:18px 20px;box-shadow:0 4px 16px rgba(15,23,42,.06);display:grid;gap:4px}
.tile span{color:var(--muted);font-size:13px;font-weight:600}
.tile strong{font-size:30px;font-variant-numeric:tabular-nums}
.card{background:var(--card);border-radius:20px;padding:22px;box-shadow:0 4px 16px rgba(15,23,42,.06)}
.card.narrow{max-width:520px}
.card h2{margin:0 0 14px;font-size:19px}
.card-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px}
.card-head h2{margin:0}
.link{color:var(--brand);font-weight:600;text-decoration:none}
.table{overflow-x:auto;margin:0 -6px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--muted);font-weight:600;font-size:12.5px;text-transform:uppercase;letter-spacing:.03em;padding:8px 10px;border-bottom:1.5px solid var(--line);white-space:nowrap}
td{padding:10px;border-bottom:1px solid var(--line);vertical-align:middle}
tbody tr:hover{background:rgba(37,99,235,.04)}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.actions{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.actions form{margin:0}
.inline{display:flex;gap:6px}
.inline input{width:150px;height:34px;padding:0 10px;font:inherit;font-size:13px;color:var(--ink);background:var(--field);border:1.5px solid var(--line);border-radius:10px}
.btn{display:inline-flex;align-items:center;justify-content:center;height:46px;padding:0 20px;border:0;border-radius:14px;background:linear-gradient(135deg,var(--brand),var(--brand2));color:#fff;font:inherit;font-weight:650;text-decoration:none;cursor:pointer;white-space:nowrap}
.btn.small{height:34px;padding:0 12px;border-radius:10px;font-size:13px}
.btn.ghost{background:transparent;color:var(--brand);border:1.5px solid var(--line)}
.btn.ghost.light{color:#fff;border-color:rgba(255,255,255,.4)}
.btn.danger{background:transparent;color:var(--err);border:1.5px solid rgba(220,38,38,.35)}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;background:var(--line);color:var(--muted)}
.badge.ok{background:rgba(22,163,74,.12);color:var(--ok)}
.badge.warn{background:rgba(217,119,6,.14);color:var(--warn)}
.badge.err{background:rgba(220,38,38,.12);color:var(--err)}
.flash{padding:12px 16px;border-radius:14px;font-weight:550}
.flash.ok{background:rgba(22,163,74,.12);color:var(--ok)}
.flash.warn{background:rgba(217,119,6,.14);color:var(--warn)}
.flash.err{background:rgba(220,38,38,.1);color:var(--err)}
.muted{color:var(--muted)}
.small{font-size:12.5px}
.hint{margin:14px 0 0;color:var(--muted);font-size:13px}
.empty{color:var(--muted);text-align:center;padding:24px 0}
.grid-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;align-items:end}
.grid-form.one{grid-template-columns:1fr}
.grid-form .wide{grid-column:1/-1}
label{display:grid;gap:6px;font-size:13px;font-weight:600;color:var(--muted)}
input,select{width:100%;height:44px;padding:0 14px;font:inherit;font-size:15px;color:var(--ink);background:var(--field);border:1.5px solid var(--line);border-radius:12px;outline:none}
input:focus,select:focus{border-color:var(--brand);box-shadow:0 0 0 4px rgba(37,99,235,.15)}
.filters{display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
.filters input[name=user]{max-width:260px}
.check{display:flex;align-items:center;gap:8px;font-weight:500}
.check input{width:18px;height:18px;accent-color:var(--brand)}
.voucher{max-width:420px;margin:0 auto;background:var(--card);border:2px dashed var(--line);border-radius:20px;padding:24px}
.voucher-head{display:flex;gap:12px;align-items:center;margin-bottom:16px}
.voucher-head img{width:48px;height:48px;border-radius:12px}
.voucher-head strong{display:block;font-size:20px}
.voucher-head span{color:var(--muted)}
.voucher dl{margin:0 0 12px;display:grid;gap:10px}
.voucher dt{font-size:12.5px;font-weight:600;color:var(--muted)}
.voucher dd{margin:0;font-size:18px;font-weight:600}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:24px!important;letter-spacing:.06em}
.voucher-note{margin:0 0 8px;font-weight:600}
.voucher-actions{display:flex;gap:10px;justify-content:center;flex-wrap:wrap}
body.login{min-height:100dvh;display:grid;place-items:center;padding:16px;background:linear-gradient(160deg,var(--brand),var(--brand2))}
.login-card{width:100%;max-width:380px;background:var(--card);border-radius:24px;padding:30px 24px;box-shadow:0 20px 50px rgba(15,23,42,.3);display:grid;gap:14px;text-align:center}
.login-card h1{margin:0;font-size:22px}
.login-card p{margin:0}
.login-card form{display:grid;gap:14px;text-align:left}
.login-icon{width:60px;height:60px;margin:0 auto;border-radius:16px}
@media (max-width:640px){.bar{padding:10px 14px;gap:10px}.wrap{padding:16px 12px 40px}.tile strong{font-size:24px}}
@media print{.no-print{display:none!important}body{background:#fff}.wrap{padding:0}.voucher{border-color:#999}}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_dates() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(1_795_000_000), "2026-11-18T11:06:40Z");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn csv_injection_is_neutralised() {
        assert_eq!(csv_field("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_field("martin"), "\"martin\"");
    }

    #[test]
    fn flash_codes_are_fixed_texts() {
        assert!(flash(Some("<script>")).is_empty());
        assert!(flash(Some("disconnected")).contains("getrennt"));
    }
}
