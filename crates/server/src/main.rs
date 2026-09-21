use std::sync::Arc;

use axum::http::header::{ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER};
use axum::http::{HeaderName, HeaderValue, Method};
use axum::middleware;
use sqlx::PgPool;
use mybox_server::auth::{LocalAuth, LocalAuthConfig};
use mybox_server::http::{
    RequestRateLimiter, SyncHttpState, add_request_id, health_router, metrics_router,
    protected_api_router,
};
use mybox_server::metrics::Metrics;
use mybox_server::postgres::PostgresSyncStore;
use tower_http::cors::{AllowOrigin, CorsLayer};
use url::Url;

#[tokio::main]
async fn main() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is not configured");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("database should be reachable");
    let store = PostgresSyncStore::new(pool.clone());
    store
        .migrate()
        .await
        .expect("database migrations should run");
    let auth_config =
        LocalAuthConfig::from_env().expect("auth environment is not configured");
    let auth = Arc::new(LocalAuth::new(pool.clone(), auth_config));
    auth.check_readiness()
        .await
        .expect("auth database readiness check should pass");
    let metrics = Metrics::default();
    let configured_origins = allowed_origins();
    if std::env::var("MYBOX_ALLOWED_ORIGINS").is_ok() && configured_origins.is_empty() {
        panic!("MYBOX_ALLOWED_ORIGINS did not contain a valid HTTP(S) origin");
    }
    let local_cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate({
            let allowed_origins = configured_origins.clone();
            move |origin: &HeaderValue, _| {
                origin
                    .to_str()
                    .ok()
                    .is_some_and(|origin| allowed_origins.iter().any(|allowed| allowed == origin))
            }
        }))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            ACCEPT,
            AUTHORIZATION,
            CACHE_CONTROL,
            CONTENT_TYPE,
            HeaderName::from_static("x-request-id"),
        ])
        .expose_headers([
            HeaderName::from_static("x-request-id"),
            HeaderName::from_static("x-mybox-error-code"),
            RETRY_AFTER,
        ])
        .allow_credentials(true);
    let app = mybox_server::auth::router(auth.clone())
        .merge(health_router(store.pool().clone(), metrics.clone()))
        .merge(metrics_router(
            metrics.clone(),
            std::env::var("MYBOX_METRICS_TOKEN").ok(),
        ))
        .merge(protected_api_router(SyncHttpState {
            store,
            verifier: auth.clone(),
            session_cookie_name: auth.cookie_name().to_owned(),
            allowed_origins: Arc::new(configured_origins),
            rate_limiter: RequestRateLimiter::default(),
            metrics,
        }))
        .layer(local_cors)
        .layer(middleware::from_fn(add_request_id));
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_owned());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("server should bind");
    println!("mybox server listening on {listener:?}");
    axum::serve(listener, app).await.expect("server should run");
}

fn allowed_origins() -> Vec<String> {
    if let Ok(value) = std::env::var("MYBOX_ALLOWED_ORIGINS") {
        // Presence of the explicit variable is authoritative, even if an
        // operator mistyped an origin. Falling back in that case could widen
        // a deliberately restricted production policy.
        return value.split(',').filter_map(normalize_origin).collect();
    }
    let mut origins = vec![
        "http://localhost".to_owned(),
        "http://localhost:8080".to_owned(),
        "http://localhost:3000".to_owned(),
        "http://127.0.0.1".to_owned(),
        "http://127.0.0.1:8080".to_owned(),
        "http://127.0.0.1:3000".to_owned(),
        "http://[::1]".to_owned(),
        "http://[::1]:8080".to_owned(),
        "http://[::1]:3000".to_owned(),
    ];
    // Derive the browser origin from server-owned redirect URLs when the
    // explicit allowlist is omitted. Prefer the new AUTH_* variable but keep
    // the legacy WorkOS/Dodo names as fallback during the cutover.
    for variable in [
        "AUTH_POST_LOGIN_REDIRECT",
        "WORKOS_POST_LOGIN_REDIRECT_URI",
        "DODO_PAYMENTS_RETURN_URL",
        "WORKOS_REDIRECT_URI",
    ] {
        if let Ok(value) = std::env::var(variable)
            && let Some(origin) = origin_from_url(&value)
            && !origins.iter().any(|existing| existing == &origin)
        {
            origins.push(origin);
        }
    }
    origins
}

fn normalize_origin(value: &str) -> Option<String> {
    let url = Url::parse(value.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    origin_from_parsed_url(&url)
}

fn origin_from_url(value: &str) -> Option<String> {
    let url = Url::parse(value.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    origin_from_parsed_url(&url)
}

fn origin_from_parsed_url(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    Some(format!("{}://{authority}", url.scheme()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_urls_reduce_to_the_exact_browser_origin() {
        assert_eq!(
            origin_from_url("https://adnate-anesthetically-jenice.ngrok-free.dev/auth/callback"),
            Some("https://adnate-anesthetically-jenice.ngrok-free.dev".to_owned())
        );
        assert_eq!(
            origin_from_url("https://app.example.test/app?checkout=1"),
            Some("https://app.example.test".to_owned())
        );
    }

    #[test]
    fn origin_derivation_rejects_credentials() {
        assert!(origin_from_url("https://user:password@app.example.test/app").is_none());
        assert!(normalize_origin("https://app.example.test/app").is_none());
    }
}
