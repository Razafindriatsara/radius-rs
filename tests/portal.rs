//! End-to-End-Tests für das Eingangsportal: Portal (HTTP) → RADIUS (UDP) → Accounting (SQLite).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use radius_rs::accounting::AccountingStore;
use radius_rs::auth::{StaticUsers, hash_password};
use radius_rs::client::ClientConfig;
use radius_rs::config::{ClientConfig as NasConfig, Clients, UserConfig};
use radius_rs::handler::Handler;
use radius_rs::portal::{AppState, PortalConfig, router};
use radius_rs::server::{Service, serve_socket};
use tokio::net::UdpSocket;
use tower::ServiceExt;

const SECRET: &str = "testing123";

struct Env {
    handler: Arc<Handler<StaticUsers>>,
    auth: SocketAddr,
    acct: SocketAddr,
}

async fn start_radius() -> Env {
    let clients = Arc::new(Clients::new(vec![NasConfig {
        name: "portal".into(),
        address: "127.0.0.0/8".parse().unwrap(),
        secret: SECRET.into(),
    }]));
    let handler = Arc::new(Handler {
        auth: StaticUsers::new(vec![
            UserConfig {
                name: "martin".into(),
                password_hash: hash_password("geheim123").unwrap(),
                session_timeout: Some(3600),
                reply_message: Some("Willkommen im Netz".into()),
            },
            UserConfig {
                name: "kurz".into(),
                password_hash: hash_password("kurz123").unwrap(),
                session_timeout: Some(1),
                reply_message: None,
            },
        ]),
        require_message_authenticator: true,
        accounting: Some(AccountingStore::in_memory().unwrap()),
    });
    let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (auth, acct) = (a.local_addr().unwrap(), b.local_addr().unwrap());
    tokio::spawn(serve_socket(a, Service::Auth, handler.clone(), clients.clone()));
    tokio::spawn(serve_socket(b, Service::Acct, handler.clone(), clients));
    Env { handler, auth, acct }
}

fn portal(auth: SocketAddr, acct: SocketAddr) -> (Arc<AppState>, PortalConfig) {
    let cfg = PortalConfig {
        listen: "127.0.0.1:0".into(),
        title: "Testnetz".into(),
        client: ClientConfig {
            auth_server: auth.to_string(),
            acct_server: acct.to_string(),
            secret: SECRET.into(),
            nas_identifier: "test-portal".into(),
            timeout: Duration::from_secs(5),
            retries: 0,
        },
        secure_cookie: false,
        max_failures: 5,
        failure_window: Duration::from_secs(300),
    };
    (AppState::new(cfg.clone()), cfg)
}

fn app(state: Arc<AppState>, ip: [u8; 4]) -> Router {
    router(state).layer(MockConnectInfo(SocketAddr::from((ip, 50000))))
}

async fn call(app: Router, req: Request<Body>) -> (StatusCode, Option<String>, Option<String>, String) {
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let loc = res
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap().to_string());
    let cookie = res
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().to_string());
    let body = String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    (status, loc, cookie, body)
}

fn post_login(user: &str, pw: &str) -> Request<Body> {
    Request::post("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("username={user}&password={pw}")))
        .unwrap()
}

fn with_cookie(method: &str, uri: &str, cookie: &str) -> Request<Body> {
    let c = cookie.split(';').next().unwrap();
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, c)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn login_status_logout_with_accounting() {
    let env = start_radius().await;
    let (state, _) = portal(env.auth, env.acct);
    let ip = [127, 0, 0, 10];

    let (code, _, _, body) = call(app(state.clone(), ip), Request::get("/").body(Body::empty()).unwrap()).await;
    assert_eq!(code, StatusCode::OK);
    assert!(body.contains("Willkommen") && body.contains("Testnetz"));

    let (code, _, cookie, body) = call(app(state.clone(), ip), post_login("martin", "falsch")).await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    assert!(body.contains("Passwort ist falsch"));
    assert!(cookie.is_none());

    let (code, loc, cookie, _) = call(app(state.clone(), ip), post_login("martin", "geheim123")).await;
    assert_eq!(code, StatusCode::SEE_OTHER);
    assert_eq!(loc.as_deref(), Some("/status"));
    let cookie = cookie.expect("Session-Cookie fehlt");
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict") && cookie.contains("Max-Age=3600"));
    assert_eq!(state.active_sessions(), 1);

    let (code, _, _, body) = call(app(state.clone(), ip), with_cookie("GET", "/status", &cookie)).await;
    assert_eq!(code, StatusCode::OK);
    assert!(body.contains("Verbunden") && body.contains("martin") && body.contains("Willkommen im Netz"));

    let store = env.handler.accounting.as_ref().unwrap();
    let s = &store.recent(10).unwrap()[0];
    assert!(s.session_id.starts_with("portal-"));
    assert_eq!((s.user.as_str(), s.nas.as_str()), ("martin", "test-portal"));
    assert!(s.stopped_at.is_none(), "Sitzung muss nach Start aktiv sein");

    let (code, _, clear, body) = call(app(state.clone(), ip), with_cookie("POST", "/logout", &cookie)).await;
    assert_eq!(code, StatusCode::OK);
    assert!(body.contains("Abgemeldet"));
    assert!(clear.unwrap().contains("Max-Age=0"));
    assert_eq!(state.active_sessions(), 0);
    let s = &store.recent(10).unwrap()[0];
    assert!(s.stopped_at.is_some());
    assert_eq!(s.terminate_cause, Some(1), "User-Request");

    // Nach dem Abmelden führt /status zurück zur Anmeldung
    let (code, loc, _, _) = call(app(state.clone(), ip), with_cookie("GET", "/status", &cookie)).await;
    assert_eq!((code, loc.as_deref()), (StatusCode::SEE_OTHER, Some("/")));
}

#[tokio::test]
async fn session_timeout_ends_session() {
    let env = start_radius().await;
    let (state, _) = portal(env.auth, env.acct);
    let (code, _, _, _) = call(app(state.clone(), [127, 0, 0, 11]), post_login("kurz", "kurz123")).await;
    assert_eq!(code, StatusCode::SEE_OTHER);
    assert_eq!(state.active_sessions(), 1);

    tokio::time::sleep(Duration::from_millis(1200)).await;
    state.expire_sessions().await;
    assert_eq!(state.active_sessions(), 0);
    let s = &env.handler.accounting.as_ref().unwrap().recent(10).unwrap()[0];
    assert_eq!(s.terminate_cause, Some(5), "Session-Timeout");
}

#[tokio::test]
async fn too_many_failures_lock_out_ip() {
    let env = start_radius().await;
    let (state, _) = portal(env.auth, env.acct);
    let ip = [127, 0, 0, 12];
    for _ in 0..5 {
        let (code, _, _, _) = call(app(state.clone(), ip), post_login("martin", "falsch")).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }
    let (code, _, _, body) = call(app(state.clone(), ip), post_login("martin", "geheim123")).await;
    assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
    assert!(body.contains("Zu viele Fehlversuche"));
    // Andere IP ist nicht betroffen
    let (code, _, _, _) = call(app(state.clone(), [127, 0, 0, 13]), post_login("martin", "geheim123")).await;
    assert_eq!(code, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn unreachable_radius_shows_friendly_error() {
    let unused = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap(); // Port, auf dem niemand antwortet
    let (_, mut cfg) = portal(unused, unused);
    cfg.client.timeout = Duration::from_millis(300);
    let state = AppState::new(cfg);
    let (code, _, _, body) = call(app(state, [127, 0, 0, 14]), post_login("martin", "geheim123")).await;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("nicht erreichbar"));
}

#[tokio::test]
async fn security_headers_and_assets() {
    let env = start_radius().await;
    let (state, _) = portal(env.auth, env.acct);
    let res = app(state.clone(), [127, 0, 0, 15])
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let csp = res.headers().get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.contains("default-src 'self'") && csp.contains("frame-ancestors 'none'"));
    assert_eq!(res.headers().get("cache-control").unwrap(), "no-store");
    for path in ["/app.css", "/app.js", "/icon.svg", "/manifest.webmanifest", "/health"] {
        let (code, _, _, body) = call(
            app(state.clone(), [127, 0, 0, 15]),
            Request::get(path).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{path}");
        assert!(!body.is_empty(), "{path}");
    }
}
