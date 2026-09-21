//! Disposable authenticated browser acceptance server.
//!
//! Uses a deterministic in-process verifier and a fixed test account so the
//! real frontend can exercise cookie-authenticated reconciliation in isolated
//! browser profiles without any external auth or billing. It must only be run
//! against a disposable database.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use axum::http::header::{ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER};
use axum::http::{HeaderName, HeaderValue, Method};
use axum::middleware;
use task_server::http::{
    AuthError, AuthenticatedAccount, RequestRateLimiter, SessionVerifier, SyncHttpState,
    add_request_id, health_router, metrics_router, protected_sync_router,
};
use task_server::metrics::Metrics;
use task_server::postgres::PostgresSyncStore;
use tokio::sync::RwLock;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use uuid::Uuid;

const TEST_SESSION_COOKIE: &str = "browser-acceptance-session";

#[derive(Clone, Default)]
struct TestVerifier {
    sessions: Arc<RwLock<HashMap<String, AuthenticatedAccount>>>,
}

#[async_trait]
impl SessionVerifier for TestVerifier {
    async fn verify(&self, bearer_token: &str) -> Result<AuthenticatedAccount, AuthError> {
        self.sessions
            .read()
            .await
            .get(bearer_token)
            .cloned()
            .ok_or(AuthError::VerificationFailed)
    }
}

#[tokio::main]
async fn main() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required");
    let store = PostgresSyncStore::connect(&database_url)
        .await
        .expect("browser acceptance database should be reachable");
    store
        .migrate()
        .await
        .expect("browser acceptance migrations should apply");
    let account_id = std::env::var("TASK_SPACE_BROWSER_TEST_ACCOUNT")
        .unwrap_or_else(|_| format!("browser-acceptance-{}", Uuid::new_v4()));

    let verifier = TestVerifier::default();
    verifier.sessions.write().await.insert(
        TEST_SESSION_COOKIE.to_owned(),
        AuthenticatedAccount {
            user_id: format!("{account_id}-user"),
            account_id: account_id.clone(),
            session_id: format!("{account_id}-session"),
        },
    );

    let origin = std::env::var("TASK_SPACE_BROWSER_TEST_ORIGIN")
        .unwrap_or_else(|_| "http://127.0.0.1:3301".to_owned());
    let metrics = Metrics::default();
    let app = health_router(store.pool().clone(), metrics.clone())
        .merge(metrics_router(metrics.clone(), None))
        .merge(protected_sync_router(SyncHttpState {
            store,
            verifier: Arc::new(verifier),
            session_cookie_name: "task_space_session".to_owned(),
            allowed_origins: Arc::new(vec![origin.clone()]),
            rate_limiter: RequestRateLimiter::default(),
            metrics,
        }))
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::exact(
                    HeaderValue::from_str(&origin).expect("browser origin should be valid"),
                ))
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([
                    ACCEPT,
                    AUTHORIZATION,
                    CACHE_CONTROL,
                    CONTENT_TYPE,
                    HeaderName::from_static("last-event-id"),
                    HeaderName::from_static("x-request-id"),
                ])
                .expose_headers([
                    HeaderName::from_static("x-request-id"),
                    HeaderName::from_static("x-task-space-error-code"),
                    RETRY_AFTER,
                ])
                .allow_credentials(true),
        )
        .layer(middleware::from_fn(add_request_id));

    let static_dir = std::env::var_os("TASK_SPACE_BROWSER_STATIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("apps/web/dist"));
    let index = static_dir.join("index.html");
    let app = app
        .route_service("/", ServeFile::new(index.clone()))
        .route_service("/app", ServeFile::new(index.clone()))
        .route_service("/app/", ServeFile::new(index))
        .fallback_service(ServeDir::new(static_dir));
    let port = std::env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(3301);
    let address = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("browser acceptance server should bind");
    println!(
        "browser acceptance server listening on http://127.0.0.1:{port}/app account={account_id} session_cookie={TEST_SESSION_COOKIE}"
    );
    axum::serve(listener, app)
        .await
        .expect("browser acceptance server should run");
}
