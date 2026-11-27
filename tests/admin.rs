//! End-to-End-Tests der Admin-Oberfläche:
//! Admin (HTTP) → Benutzer-DB → Portal (HTTP) → RADIUS (UDP) → Disconnect (RFC 5176) → Accounting.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use radius_rs::accounting::AccountingStore;
use radius_rs::admin::{AdminState, router as admin_router};
use radius_rs::auth::{StaticUsers, hash_password};
use radius_rs::client::ClientConfig;
use radius_rs::config::{AdminConfig, ClientConfig as NasConfig, Clients, UserConfig};
use radius_rs::handler::Handler;
use radius_rs::portal::{AppState, PortalConfig, router as portal_router, serve_coa};
use radius_rs::server::{Service, serve_socket};
use radius_rs::users::{Directory, UserStore};
use tokio::net::UdpSocket;
use tower::ServiceExt;

const SECRET: &str = "testing123";
const ADMIN_PW: &str = "admin-geheim";

struct Env {
    admin: Arc<AdminState>,
    portal: Arc<AppState>,
    sessions: Arc<AccountingStore>,
}

async fn setup() -> Env {
    let users = Arc::new(UserStore::in_memory().unwrap());
    let sessions = Arc::new(AccountingStore::in_memory().unwrap());

    // Portal mit Disconnect-Empfänger auf zufälligem Port
    let coa = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let coa_port = coa.local_addr().unwrap().port();
    let clients = Arc::new(Clients::new(vec![NasConfig {
        name: "portal".into(),
        address: "127.0.0.0/8".parse().unwrap(),
        secret: SECRET.into(),
        coa_port,
    }]));

    let handler = Arc::new(Handler {
        auth: Directory {
            db: Some(users.clone()),
            config: StaticUsers::new(vec![UserConfig {
                name: "martin".into(),
                password_hash: hash_password("geheim123").unwrap(),
                session_timeout: Some(3600),
                reply_message: None,
            }]),
        },
        require_message_authenticator: true,
        accounting: Some(sessions.clone()),
    });
    let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (auth, acct) = (a.local_addr().unwrap(), b.local_addr().unwrap());
    tokio::spawn(serve_socket(a, Service::Auth, handler.clone(), clients.clone()));
    tokio::spawn(serve_socket(b, Service::Acct, handler.clone(), clients.clone()));

    let portal = AppState::new(PortalConfig {
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
        coa_listen: None,
    });
    tokio::spawn(serve_coa(portal.clone(), coa));

    let admin = AdminState::new(
        AdminConfig {
            listen: "127.0.0.1:0".into(),
            password_hash: hash_password(ADMIN_PW).unwrap(),
            title: "Admin".into(),
        },
        users,
        sessions.clone(),
        clients,
        vec!["martin".into()],
    );
    Env {
        admin,
        portal,
        sessions,
    }
}

fn app(r: Router, ip: [u8; 4]) -> Router {
    r.layer(MockConnectInfo(SocketAddr::from((ip, 40000))))
}

struct Resp {
    code: StatusCode,
    location: Option<String>,
    cookie: Option<String>,
    body: String,
}

async fn call(r: Router, req: Request<Body>) -> Resp {
    let res = r.oneshot(req).await.unwrap();
    let code = res.status();
    let location = res
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap().to_string());
    let cookie = res
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string());
    let body = String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    Resp {
        code,
        location,
        cookie,
        body,
    }
}

fn form(uri: &str, cookie: Option<&str>, body: &str) -> Request<Body> {
    let mut b = Request::post(uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn get(uri: &str, cookie: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap()
}

fn csrf_of(html: &str) -> String {
    let i = html.find(r#"name="csrf" value=""#).expect("CSRF-Feld fehlt") + 19;
    html[i..i + 32].to_string()
}

/// Meldet den Admin an und liefert Cookie und CSRF-Token.
async fn admin_login(env: &Env) -> (String, String) {
    let r = call(
        app(admin_router(env.admin.clone()), [127, 0, 0, 1]),
        form("/login", None, &format!("password={ADMIN_PW}")),
    )
    .await;
    assert_eq!(r.code, StatusCode::SEE_OTHER);
    let cookie = r.cookie.unwrap();
    let dash = call(app(admin_router(env.admin.clone()), [127, 0, 0, 1]), get("/", &cookie)).await;
    assert_eq!(dash.code, StatusCode::OK);
    let csrf = csrf_of(&dash.body);
    (cookie, csrf)
}

async fn portal_login(env: &Env, user: &str, pw: &str) -> StatusCode {
    call(
        app(portal_router(env.portal.clone()), [127, 0, 0, 20]),
        form("/login", None, &format!("username={user}&password={pw}")),
    )
    .await
    .code
}

#[tokio::test]
async fn login_required_and_csrf_checked() {
    let env = setup().await;
    let adm = || app(admin_router(env.admin.clone()), [127, 0, 0, 2]);

    let r = call(adm(), Request::get("/").body(Body::empty()).unwrap()).await;
    assert_eq!((r.code, r.location.as_deref()), (StatusCode::SEE_OTHER, Some("/login")));

    let r = call(adm(), form("/login", None, "password=falsch")).await;
    assert_eq!(r.code, StatusCode::UNAUTHORIZED);
    assert!(r.cookie.is_none());

    let (cookie, csrf) = admin_login(&env).await;
    // Ändernde Aktion ohne gültiges CSRF-Token wird abgewiesen
    let r = call(
        adm(),
        form(
            "/users",
            Some(&cookie),
            "csrf=00000000000000000000000000000000&name=x1&password=geheim1234",
        ),
    )
    .await;
    assert_eq!(r.code, StatusCode::FORBIDDEN);
    let list = call(adm(), get("/users", &cookie)).await;
    assert!(!list.body.contains("<strong>x1</strong>"));
    // Mit gültigem Token klappt es
    let r = call(
        adm(),
        form(
            "/users",
            Some(&cookie),
            &format!("csrf={csrf}&name=x1&password=geheim1234"),
        ),
    )
    .await;
    assert_eq!(r.location.as_deref(), Some("/users?m=created"));
}

#[tokio::test]
async fn user_lifecycle_and_disconnect_via_rfc5176() {
    let env = setup().await;
    let (cookie, csrf) = admin_login(&env).await;
    let adm = || app(admin_router(env.admin.clone()), [127, 0, 0, 1]);

    // Benutzer anlegen
    let r = call(
        adm(),
        form(
            "/users",
            Some(&cookie),
            &format!("csrf={csrf}&name=anna&password=anna-geheim&session_minutes=30&reply_message=Hallo+Anna&note="),
        ),
    )
    .await;
    assert_eq!(r.location.as_deref(), Some("/users?m=created"));
    let list = call(adm(), get("/users", &cookie)).await;
    assert!(
        list.body.contains("anna") && list.body.contains("config.toml"),
        "DB- und Konfigurationsbenutzer werden angezeigt"
    );

    // Anmelden am Portal mit dem neuen Benutzer
    assert_eq!(portal_login(&env, "anna", "anna-geheim").await, StatusCode::SEE_OTHER);
    assert_eq!(env.portal.active_sessions(), 1);
    let dash = call(adm(), get("/", &cookie)).await;
    assert!(dash.body.contains("anna") && dash.body.contains("Trennen"));

    // Trennen: Disconnect-Request an das Portal, Portal meldet Accounting-Stop mit Admin-Reset
    let s = env
        .sessions
        .query(&Default::default())
        .unwrap()
        .into_iter()
        .find(|s| s.user == "anna")
        .unwrap();
    assert_eq!(s.nas_addr.as_deref(), Some("127.0.0.1"));
    let r = call(
        adm(),
        form(
            "/sessions/disconnect",
            Some(&cookie),
            &format!("csrf={csrf}&session_id={}&nas={}", s.session_id, s.nas),
        ),
    )
    .await;
    assert_eq!(r.location.as_deref(), Some("/?m=disconnected"));
    assert_eq!(env.portal.active_sessions(), 0, "Portal hat die Sitzung beendet");
    let s = env.sessions.find(&s.session_id, &s.nas).unwrap().unwrap();
    assert!(s.stopped_at.is_some());
    assert_eq!(s.terminate_cause, Some(6), "Admin-Reset");

    // Sperren: Anmeldung wird abgelehnt
    let r = call(
        adm(),
        form(
            "/users/action",
            Some(&cookie),
            &format!("csrf={csrf}&name=anna&action=disable"),
        ),
    )
    .await;
    assert_eq!(r.location.as_deref(), Some("/users?m=disabled"));
    assert_eq!(
        portal_login(&env, "anna", "anna-geheim").await,
        StatusCode::UNAUTHORIZED
    );

    // Entsperren und neues Passwort
    call(
        adm(),
        form(
            "/users/action",
            Some(&cookie),
            &format!("csrf={csrf}&name=anna&action=enable"),
        ),
    )
    .await;
    let r = call(
        adm(),
        form(
            "/users/action",
            Some(&cookie),
            &format!("csrf={csrf}&name=anna&action=password&password=ganz-neu-123"),
        ),
    )
    .await;
    assert_eq!(r.location.as_deref(), Some("/users?m=password"));
    assert_eq!(
        portal_login(&env, "anna", "anna-geheim").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(portal_login(&env, "anna", "ganz-neu-123").await, StatusCode::SEE_OTHER);

    // Löschen
    let r = call(
        adm(),
        form(
            "/users/action",
            Some(&cookie),
            &format!("csrf={csrf}&name=anna&action=delete"),
        ),
    )
    .await;
    assert_eq!(r.location.as_deref(), Some("/users?m=deleted"));

    // Name eines Konfigurationsbenutzers ist belegt
    let r = call(
        adm(),
        form(
            "/users",
            Some(&cookie),
            &format!("csrf={csrf}&name=martin&password=geheim1234"),
        ),
    )
    .await;
    assert_eq!(r.location.as_deref(), Some("/users?m=exists"));
}

#[tokio::test]
async fn guest_voucher_works_at_the_portal() {
    let env = setup().await;
    let (cookie, csrf) = admin_login(&env).await;
    let adm = || app(admin_router(env.admin.clone()), [127, 0, 0, 1]);

    let r = call(
        adm(),
        form("/guests", Some(&cookie), &format!("csrf={csrf}&hours=4&note=Zimmer+12")),
    )
    .await;
    assert_eq!(r.code, StatusCode::OK);
    assert!(r.body.contains("WLAN-Zugang") && r.body.contains("Zimmer 12") && r.body.contains("data-print"));
    let grab = |label: &str| {
        let needle = format!("<dt>{label}</dt><dd class=\"mono\">");
        let i = r.body.find(&needle).unwrap() + needle.len();
        r.body[i..].split('<').next().unwrap().to_string()
    };
    let (user, pw) = (grab("Benutzername"), grab("Passwort"));
    assert!(user.starts_with("gast-") && pw.len() == 10, "{user} {pw}");

    assert_eq!(portal_login(&env, &user, &pw).await, StatusCode::SEE_OTHER);
    let users = call(adm(), get("/users", &cookie)).await;
    assert!(users.body.contains(&user) && users.body.contains("Gast"));
}

#[tokio::test]
async fn history_csv_and_mark_stopped() {
    let env = setup().await;
    let (cookie, csrf) = admin_login(&env).await;
    let adm = || app(admin_router(env.admin.clone()), [127, 0, 0, 1]);

    assert_eq!(portal_login(&env, "martin", "geheim123").await, StatusCode::SEE_OTHER);
    let s = env.sessions.query(&Default::default()).unwrap().remove(0);

    let hist = call(adm(), get("/sessions?user=mart&active=1", &cookie)).await;
    assert!(hist.body.contains("martin") && hist.body.contains("aktiv"));

    let csv = call(adm(), get("/sessions.csv", &cookie)).await;
    assert!(csv.body.starts_with("session_id;user;nas"));
    assert!(csv.body.contains("\"martin\";\"test-portal\""));

    // „Als beendet markieren“ ohne NAS-Beteiligung
    let r = call(
        adm(),
        form(
            "/sessions/close",
            Some(&cookie),
            &format!("csrf={csrf}&session_id={}&nas={}", s.session_id, s.nas),
        ),
    )
    .await;
    assert_eq!(r.location.as_deref(), Some("/?m=closed"));
    assert_eq!(
        env.sessions
            .find(&s.session_id, &s.nas)
            .unwrap()
            .unwrap()
            .terminate_cause,
        Some(6)
    );

    // Abmelden beendet die Admin-Sitzung
    let r = call(adm(), form("/logout", Some(&cookie), &format!("csrf={csrf}"))).await;
    assert_eq!(r.location.as_deref(), Some("/login"));
    let r = call(adm(), get("/", &cookie)).await;
    assert_eq!(r.location.as_deref(), Some("/login"));
}
