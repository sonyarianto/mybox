//! Local auth: email+password with opaque Postgres sessions, plus OAuth.
//!
//! Replaces WorkOS. Sessions are random 32-byte tokens; only SHA-256(token)
//! is stored. `account_id` == local `users.id`, so existing sync handlers
//! keep working unchanged.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header::{COOKIE, SET_COOKIE}};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::http::{AuthError, AuthenticatedAccount, RequestRateLimiter, SessionVerifier};

const SESSION_TOKEN_BYTES: usize = 32;
const SESSION_TTL_DEFAULT_SECS: i64 = 30 * 24 * 60 * 60;
const MAX_EMAIL_LEN: usize = 320;
const MIN_PASSWORD_LEN: usize = 8;
const MAX_PASSWORD_LEN: usize = 256;
const OAUTH_STATE_TTL_SECS: i64 = 600;
const RESET_TOKEN_TTL_SECS: i64 = 3600;
const VERIFY_CODE_TTL_SECS: i64 = 24 * 3600;

#[derive(Clone, Debug)]
pub struct OAuthProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    /// e.g. https://api.example.com/auth/callback
    pub redirect_uri: String,
}

#[derive(Clone, Debug)]
pub struct LocalAuthConfig {
    pub cookie_name: String,
    pub post_login_redirect: String,
    pub session_ttl_secs: i64,
    pub google: Option<OAuthProviderConfig>,
    pub github: Option<OAuthProviderConfig>,
}

impl LocalAuthConfig {
    pub fn from_env() -> Result<Self, AuthError> {
        let cookie_name = std::env::var("AUTH_SESSION_COOKIE")
            .or_else(|_| std::env::var("WORKOS_SESSION_COOKIE"))
            .unwrap_or_else(|_| "task_space_session".to_owned());
        let post_login_redirect = std::env::var("AUTH_POST_LOGIN_REDIRECT")
            .or_else(|_| std::env::var("WORKOS_POST_LOGIN_REDIRECT_URI"))
            .unwrap_or_else(|_| "/app".to_owned());
        let session_ttl_secs = std::env::var("AUTH_SESSION_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(SESSION_TTL_DEFAULT_SECS);
        let google = match (
            std::env::var("OAUTH_GOOGLE_CLIENT_ID").ok(),
            std::env::var("OAUTH_GOOGLE_CLIENT_SECRET").ok(),
        ) {
            (Some(id), Some(secret)) if !id.trim().is_empty() && !secret.trim().is_empty() => {
                Some(OAuthProviderConfig {
                    client_id: id,
                    client_secret: secret,
                    redirect_uri: std::env::var("OAUTH_GOOGLE_REDIRECT_URI")
                        .unwrap_or_else(|_| "http://localhost:3000/auth/callback".to_owned()),
                })
            }
            _ => None,
        };
        let github = match (
            std::env::var("OAUTH_GITHUB_CLIENT_ID").ok(),
            std::env::var("OAUTH_GITHUB_CLIENT_SECRET").ok(),
        ) {
            (Some(id), Some(secret)) if !id.trim().is_empty() && !secret.trim().is_empty() => {
                Some(OAuthProviderConfig {
                    client_id: id,
                    client_secret: secret,
                    redirect_uri: std::env::var("OAUTH_GITHUB_REDIRECT_URI")
                        .unwrap_or_else(|_| "http://localhost:3000/auth/callback".to_owned()),
                })
            }
            _ => None,
        };
        Ok(Self {
            cookie_name,
            post_login_redirect,
            session_ttl_secs,
            google,
            github,
        })
    }
}

#[derive(Clone)]
pub struct LocalAuth {
    inner: Arc<LocalAuthInner>,
}

struct LocalAuthInner {
    pool: PgPool,
    config: LocalAuthConfig,
    client: reqwest::Client,
    rate_limiter: RequestRateLimiter,
}

impl LocalAuth {
    pub fn new(pool: PgPool, config: LocalAuthConfig) -> Self {
        Self {
            inner: Arc::new(LocalAuthInner {
                pool,
                config,
                client: reqwest::Client::new(),
                rate_limiter: RequestRateLimiter::default(),
            }),
        }
    }

    pub fn cookie_name(&self) -> &str {
        &self.inner.config.cookie_name
    }

    pub async fn check_readiness(&self) -> Result<(), AuthError> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.inner.pool)
            .await
            .map(|_| ())
            .map_err(|_| AuthError::VerificationFailed)
    }

    fn normalize_email(email: &str) -> Option<(String, String)> {
        let trimmed = email.trim().to_owned();
        if trimmed.is_empty() || trimmed.len() > MAX_EMAIL_LEN || !trimmed.contains('@') {
            return None;
        }
        Some((trimmed.clone(), trimmed.to_lowercase()))
    }

    fn hash_password(password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut rand::thread_rng());
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|_| AuthError::VerificationFailed)
    }

    fn verify_password(hash: &str, password: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(hash) else {
            return false;
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    }

    fn new_token() -> (String, Vec<u8>) {
        let mut bytes = [0u8; SESSION_TOKEN_BYTES];
        rand::thread_rng().fill_bytes(&mut bytes);
        let raw = hex_encode(&bytes);
        let digest = Sha256::digest(raw.as_bytes()).to_vec();
        (raw, digest)
    }

    fn token_hash(token: &str) -> Vec<u8> {
        Sha256::digest(token.trim().as_bytes()).to_vec()
    }

    async fn create_session(
        &self,
        user_id: Uuid,
        ip: Option<String>,
        user_agent: &str,
    ) -> Result<String, AuthError> {
        let (raw, digest) = Self::new_token();
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, ip, user_agent)
             VALUES ($1, $2, NOW() + make_interval(secs => $3), $4::inet, $5)",
        )
        .bind(&digest)
        .bind(user_id)
        .bind(self.inner.config.session_ttl_secs as f64)
        .bind(ip.as_deref())
        .bind(&user_agent[..user_agent.len().min(512)])
        .execute(&self.inner.pool)
        .await
        .map_err(|_| AuthError::VerificationFailed)?;
        Ok(raw)
    }

    fn session_cookie(&self, token: &str) -> String {
        // Opaque session cookie. Secure is set by the TLS-terminating proxy
        // config in production; keep SameSite=Lax so top-level OAuth
        // redirects still send it for GETs while POSTs stay CSRF-gated.
        format!(
            "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
            self.inner.config.cookie_name,
            token,
            self.inner.config.session_ttl_secs
        )
    }

    fn clear_cookie(&self) -> String {
        format!(
            "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
            self.inner.config.cookie_name
        )
    }

    fn client_ip(headers: &HeaderMap) -> Option<String> {
        for name in ["x-real-ip", "x-forwarded-for"] {
            if let Some(v) = headers.get(name).and_then(|v| v.to_str().ok()) {
                if let Some(first) = v.split(',').next().map(str::trim) {
                    if first.parse::<std::net::IpAddr>().is_ok() {
                        return Some(first.to_owned());
                    }
                }
            }
        }
        None
    }

    fn user_agent(headers: &HeaderMap) -> String {
        headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

#[async_trait::async_trait]
impl SessionVerifier for LocalAuth {
    async fn verify(&self, bearer_token: &str) -> Result<AuthenticatedAccount, AuthError> {
        let token = bearer_token.trim();
        if token.is_empty() || token.len() > 512 {
            return Err(AuthError::VerificationFailed);
        }
        let digest = Self::token_hash(token);
        let rec: Option<(Uuid,)> = sqlx::query_as(
            "SELECT s.user_id FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = $1 AND s.expires_at > NOW()",
        )
        .bind(&digest)
        .fetch_optional(&self.inner.pool)
        .await
        .map_err(|_| AuthError::VerificationFailed)?;
        let Some((user_id,)) = rec else {
            return Err(AuthError::VerificationFailed);
        };
        // Best-effort activity bump; auth stays valid even if this fails.
        let _ = sqlx::query("UPDATE sessions SET last_seen_at = NOW() WHERE token_hash = $1")
            .bind(&digest)
            .execute(&self.inner.pool)
            .await;
        let id = user_id.to_string();
        Ok(AuthenticatedAccount {
            user_id: id.clone(),
            account_id: id.clone(),
            session_id: hex_encode(&digest)[..16].to_owned(),
        })
    }
}

// ---------- HTTP ----------

#[derive(Debug, Deserialize)]
struct PasswordPayload {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AuthApiResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyPayload {
    #[allow(dead_code)]
    code: String,
}

#[derive(Debug, Deserialize)]
struct ResetRequestPayload {
    email: String,
}

#[derive(Debug, Deserialize)]
struct ResetConfirmPayload {
    token: String,
    new_password: String,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

fn json_ok(account_id: &str) -> Json<AuthApiResponse> {
    Json(AuthApiResponse {
        status: "ok".to_owned(),
        message: None,
        account_id: Some(account_id.to_owned()),
    })
}

fn json_err(status: StatusCode, message: &str) -> Response {
    let mut resp = (
        status,
        Json(AuthApiResponse {
            status: "error".to_owned(),
            message: Some(message.to_owned()),
            account_id: None,
        }),
    )
        .into_response();
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    resp
}

fn validate_password(password: &str) -> Result<(), Response> {
    if password.len() < MIN_PASSWORD_LEN || password.len() > MAX_PASSWORD_LEN {
        return Err(json_err(
            StatusCode::BAD_REQUEST,
            "password must be 8-256 characters",
        ));
    }
    Ok(())
}

async fn handle_password_sign_up(
    State(auth): State<LocalAuth>,
    headers: HeaderMap,
    Json(payload): Json<PasswordPayload>,
) -> Response {
    if !auth
        .inner
        .rate_limiter
        .allow_ip(&headers, "auth-signup", 20, Duration::from_secs(60))
    {
        return json_err(StatusCode::TOO_MANY_REQUESTS, "too many requests");
    }
    let Some((email, normalized)) = LocalAuth::normalize_email(&payload.email) else {
        return json_err(StatusCode::BAD_REQUEST, "enter a valid email");
    };
    if let Err(e) = validate_password(&payload.password) {
        return e;
    }
    let hash = match LocalAuth::hash_password(&payload.password) {
        Ok(h) => h,
        Err(_) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, "signup failed"),
    };
    let id: Result<Uuid, AuthError> = async {
        let rec: Option<(Uuid,)> = sqlx::query_as(
            "INSERT INTO users (email, email_normalized, password_hash, email_verified_at)
             VALUES ($1, $2, $3, CASE WHEN $4 THEN NOW() ELSE NULL END)
             ON CONFLICT (email_normalized) DO NOTHING
             RETURNING id",
        )
        .bind(&email)
        .bind(&normalized)
        // Self-host v1: no SMTP yet, so mark email verified immediately and
        // log this. Flip to false once SMTP verification lands.
        .bind(&hash)
        .bind(true)
        .fetch_optional(&auth.inner.pool)
        .await
        .map_err(|_| AuthError::VerificationFailed)?;
        rec.map(|(id,)| id).ok_or(AuthError::VerificationFailed)
    }
    .await;
    let user_id = match id {
        Ok(id) => id,
        Err(_) => return json_err(StatusCode::CONFLICT, "that email is already registered"),
    };
    let token = match auth
        .create_session(
            user_id,
            LocalAuth::client_ip(&headers),
            &LocalAuth::user_agent(&headers),
        )
        .await
    {
        Ok(t) => t,
        Err(_) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, "signup failed"),
    };
    let mut resp = (StatusCode::CREATED, json_ok(&user_id.to_string())).into_response();
    resp.headers_mut().append(
        SET_COOKIE,
        HeaderValue::from_str(&auth.session_cookie(&token)).unwrap(),
    );
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    resp
}

async fn handle_password_sign_in(
    State(auth): State<LocalAuth>,
    headers: HeaderMap,
    Json(payload): Json<PasswordPayload>,
) -> Response {
    if !auth
        .inner
        .rate_limiter
        .allow_ip(&headers, "auth-signin", 20, Duration::from_secs(60))
    {
        return json_err(StatusCode::TOO_MANY_REQUESTS, "too many requests");
    }
    let Some((_, normalized)) = LocalAuth::normalize_email(&payload.email) else {
        return json_err(StatusCode::UNAUTHORIZED, "invalid email or password");
    };
    let rec: Option<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, password_hash FROM users WHERE email_normalized = $1",
    )
    .bind(&normalized)
    .fetch_optional(&auth.inner.pool)
    .await
    .unwrap_or(None);
    let Some((user_id, Some(hash))) = rec else {
        return json_err(StatusCode::UNAUTHORIZED, "invalid email or password");
    };
    if !LocalAuth::verify_password(&hash, &payload.password) {
        return json_err(StatusCode::UNAUTHORIZED, "invalid email or password");
    }
    let token = match auth
        .create_session(
            user_id,
            LocalAuth::client_ip(&headers),
            &LocalAuth::user_agent(&headers),
        )
        .await
    {
        Ok(t) => t,
        Err(_) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, "sign-in failed"),
    };
    let mut resp = (StatusCode::OK, json_ok(&user_id.to_string())).into_response();
    resp.headers_mut().append(
        SET_COOKIE,
        HeaderValue::from_str(&auth.session_cookie(&token)).unwrap(),
    );
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    resp
}

async fn logout(State(auth): State<LocalAuth>, headers: HeaderMap) -> Response {
    if let Some(token) = headers
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| cookie_value(c, auth.cookie_name()))
    {
        let digest = LocalAuth::token_hash(&token);
        let _ = sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(&digest)
            .execute(&auth.inner.pool)
            .await;
    }
    let mut resp = (StatusCode::OK, json_ok("")).into_response();
    resp.headers_mut().append(
        SET_COOKIE,
        HeaderValue::from_str(&auth.clear_cookie()).unwrap(),
    );
    resp
}

async fn refresh(State(auth): State<LocalAuth>, headers: HeaderMap) -> Response {
    // Opaque sessions need no refresh; re-issue only if the cookie is valid
    // so multi-tab refresh storms stay cheap and idempotent.
    let Some(token) = headers
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| cookie_value(c, auth.cookie_name()))
    else {
        return json_err(StatusCode::UNAUTHORIZED, "session required");
    };
    match auth.verify(&token).await {
        Ok(account) => (StatusCode::OK, json_ok(&account.account_id)).into_response(),
        Err(_) => json_err(StatusCode::UNAUTHORIZED, "session expired"),
    }
}

async fn verify_email(State(auth): State<LocalAuth>, Json(payload): Json<VerifyPayload>) -> Response {
    // V1 self-host: emails are auto-verified at signup (no SMTP). Accept any
    // call as ok so future SMTP enforcement can tighten this without a
    // frontend change.
    let _ = (&auth, &payload);
    (StatusCode::OK, json_ok("")).into_response()
}

async fn request_password_reset(
    State(auth): State<LocalAuth>,
    headers: HeaderMap,
    Json(payload): Json<ResetRequestPayload>,
) -> Response {
    if !auth
        .inner
        .rate_limiter
        .allow_ip(&headers, "auth-reset", 20, Duration::from_secs(60))
    {
        return json_err(StatusCode::TOO_MANY_REQUESTS, "too many requests");
    }
    let Some((_, normalized)) = LocalAuth::normalize_email(&payload.email) else {
        // Always return ok to avoid account enumeration.
        return (StatusCode::OK, json_ok("")).into_response();
    };
    let rec: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM users WHERE email_normalized = $1")
            .bind(&normalized)
            .fetch_optional(&auth.inner.pool)
            .await
            .unwrap_or(None);
    if let Some((user_id,)) = rec {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let raw = hex_encode(&bytes);
        let digest = Sha256::digest(raw.as_bytes()).to_vec();
        let _ = sqlx::query(
            "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at)
             VALUES ($1, $2, NOW() + make_interval(secs => $3))
             ON CONFLICT (token_hash) DO NOTHING",
        )
        .bind(&digest)
        .bind(user_id)
        .bind(RESET_TOKEN_TTL_SECS as f64)
        .execute(&auth.inner.pool)
        .await;
        // No SMTP in v1: log the token so a self-host operator can deliver it.
        eprintln!("password reset requested for user {user_id}; token: {raw}");
    }
    (StatusCode::OK, json_ok("")).into_response()
}

async fn confirm_password_reset(
    State(auth): State<LocalAuth>,
    Json(payload): Json<ResetConfirmPayload>,
) -> Response {
    if let Err(e) = validate_password(&payload.new_password) {
        return e;
    }
    let digest = Sha256::digest(payload.token.trim().as_bytes()).to_vec();
    let rec: Option<(Uuid,)> = sqlx::query_as(
        "DELETE FROM password_reset_tokens WHERE token_hash = $1 AND expires_at > NOW() RETURNING user_id",
    )
    .bind(&digest)
    .fetch_optional(&auth.inner.pool)
    .await
    .unwrap_or(None);
    let Some((user_id,)) = rec else {
        return json_err(StatusCode::BAD_REQUEST, "reset link is invalid or expired");
    };
    let hash = match LocalAuth::hash_password(&payload.new_password) {
        Ok(h) => h,
        Err(_) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, "reset failed"),
    };
    let _ = sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
        .bind(&hash)
        .bind(user_id)
        .execute(&auth.inner.pool)
        .await;
    let _ = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(&auth.inner.pool)
        .await;
    (StatusCode::OK, json_ok(&user_id.to_string())).into_response()
}

fn cookie_value(cookies: &str, name: &str) -> Option<String> {
    cookies.split(';').find_map(|c| {
        let (k, v) = c.trim().split_once('=')?;
        (k == name && !v.trim().is_empty()).then(|| v.trim().to_owned())
    })
}

// ---------- OAuth (Google + GitHub) ----------

async fn oauth_start(State(auth): State<LocalAuth>, Path(provider): Path<String>) -> Response {
    let provider = provider.to_lowercase();
    let cfg = match provider.as_str() {
        "google" => auth.inner.config.google.clone(),
        "github" => auth.inner.config.github.clone(),
        _ => None,
    };
    let Some(cfg) = cfg else {
        return json_err(StatusCode::NOT_IMPLEMENTED, "oauth provider not configured");
    };
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    let state = hex_encode(&bytes);
    let _ = sqlx::query(
        "INSERT INTO oauth_states (state, provider, redirect_uri, expires_at)
         VALUES ($1, $2, $3, NOW() + make_interval(secs => $4))",
    )
    .bind(&state)
    .bind(&provider)
    .bind(&cfg.redirect_uri)
    .bind(OAUTH_STATE_TTL_SECS as f64)
    .execute(&auth.inner.pool)
    .await;
    let url = match provider.as_str() {
        "google" => format!(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}&access_type=online&prompt=select_account",
            urlencoding(&cfg.client_id),
            urlencoding(&cfg.redirect_uri),
            urlencoding(&state),
        ),
        "github" => format!(
            "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read:user%20user:email&state={}",
            urlencoding(&cfg.client_id),
            urlencoding(&cfg.redirect_uri),
            urlencoding(&state),
        ),
        _ => return json_err(StatusCode::NOT_IMPLEMENTED, "oauth provider not configured"),
    };
    Redirect::temporary(&url).into_response()
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn oauth_callback(
    State(auth): State<LocalAuth>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let (Some(code), Some(state)) = (query.code, query.state) else {
        return json_err(StatusCode::BAD_REQUEST, "oauth callback missing code/state");
    };
    let rec: Option<(String,)> = sqlx::query_as(
        "DELETE FROM oauth_states WHERE state = $1 AND expires_at > NOW() RETURNING provider",
    )
    .bind(&state)
    .fetch_optional(&auth.inner.pool)
    .await
    .unwrap_or(None);
    let Some((provider,)) = rec else {
        return json_err(StatusCode::BAD_REQUEST, "oauth state expired; try again");
    };
    let cfg = match provider.as_str() {
        "google" => auth.inner.config.google.clone(),
        "github" => auth.inner.config.github.clone(),
        _ => None,
    };
    let Some(cfg) = cfg else {
        return json_err(StatusCode::NOT_IMPLEMENTED, "oauth provider not configured");
    };
    let (email, sub) = match fetch_oauth_identity(&auth, &provider, &cfg, &code).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let Some((email, normalized)) = LocalAuth::normalize_email(&email) else {
        return json_err(StatusCode::BAD_GATEWAY, "oauth provider returned no email");
    };
    // Find or create user, link oauth account.
    let user_id: Uuid = async {
        if let Some((uid,)) = sqlx::query_as::<_, (Uuid,)>(
            "SELECT user_id FROM oauth_accounts WHERE provider = $1 AND provider_sub = $2",
        )
        .bind(&provider)
        .bind(&sub)
        .fetch_optional(&auth.inner.pool)
        .await
        .unwrap_or(None)
        {
            return Ok::<_, AuthError>(uid);
        }
        if let Some((uid,)) = sqlx::query_as::<_, (Uuid,)>(
            "SELECT id FROM users WHERE email_normalized = $1",
        )
        .bind(&normalized)
        .fetch_optional(&auth.inner.pool)
        .await
        .unwrap_or(None)
        {
            let _ = sqlx::query(
                "INSERT INTO oauth_accounts (provider, provider_sub, user_id)
                 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            )
            .bind(&provider)
            .bind(&sub)
            .bind(uid)
            .execute(&auth.inner.pool)
            .await;
            return Ok(uid);
        }
        let rec: (Uuid,) = sqlx::query_as(
            "INSERT INTO users (email, email_normalized, email_verified_at)
             VALUES ($1, $2, NOW()) RETURNING id",
        )
        .bind(&email)
        .bind(&normalized)
        .fetch_one(&auth.inner.pool)
        .await
        .map_err(|_| AuthError::VerificationFailed)?;
        let _ = sqlx::query(
            "INSERT INTO oauth_accounts (provider, provider_sub, user_id)
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(&provider)
        .bind(&sub)
        .bind(rec.0)
        .execute(&auth.inner.pool)
        .await;
        Ok(rec.0)
    }
    .await
    .unwrap_or_else(|_| Uuid::nil());
    if user_id.is_nil() {
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, "oauth sign-in failed");
    }
    let token = match auth
        .create_session(
            user_id,
            LocalAuth::client_ip(&headers),
            &LocalAuth::user_agent(&headers),
        )
        .await
    {
        Ok(t) => t,
        Err(_) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, "oauth sign-in failed"),
    };
    let mut resp = Redirect::temporary(&auth.inner.config.post_login_redirect).into_response();
    resp.headers_mut().append(
        SET_COOKIE,
        HeaderValue::from_str(&auth.session_cookie(&token)).unwrap(),
    );
    resp
}

async fn fetch_oauth_identity(
    auth: &LocalAuth,
    provider: &str,
    cfg: &OAuthProviderConfig,
    code: &str,
) -> Result<(String, String), Response> {
    match provider {
        "google" => {
            let token_resp: serde_json::Value = auth
                .inner
                .client
                .post("https://oauth2.googleapis.com/token")
                .form(&[
                    ("code", code),
                    ("client_id", cfg.client_id.as_str()),
                    ("client_secret", cfg.client_secret.as_str()),
                    ("redirect_uri", cfg.redirect_uri.as_str()),
                    ("grant_type", "authorization_code"),
                ])
                .send()
                .await
                .map_err(|_| json_err(StatusCode::BAD_GATEWAY, "oauth exchange failed"))?
                .json()
                .await
                .map_err(|_| json_err(StatusCode::BAD_GATEWAY, "oauth exchange failed"))?;
            let access = token_resp
                .get("access_token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| json_err(StatusCode::BAD_GATEWAY, "oauth exchange failed"))?;
            let info: serde_json::Value = auth
                .inner
                .client
                .get("https://openidconnect.googleapis.com/v1/userinfo")
                .bearer_auth(access)
                .send()
                .await
                .map_err(|_| json_err(StatusCode::BAD_GATEWAY, "oauth userinfo failed"))?
                .json()
                .await
                .map_err(|_| json_err(StatusCode::BAD_GATEWAY, "oauth userinfo failed"))?;
            let email = info
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            let sub = info
                .get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            if email.is_empty() || sub.is_empty() {
                return Err(json_err(StatusCode::BAD_GATEWAY, "oauth provider returned no email"));
            }
            Ok((email, sub))
        }
        "github" => {
            let token_resp: serde_json::Value = auth
                .inner
                .client
                .post("https://github.com/login/oauth/access_token")
                .header("Accept", "application/json")
                .form(&[
                    ("code", code),
                    ("client_id", cfg.client_id.as_str()),
                    ("client_secret", cfg.client_secret.as_str()),
                    ("redirect_uri", cfg.redirect_uri.as_str()),
                ])
                .send()
                .await
                .map_err(|_| json_err(StatusCode::BAD_GATEWAY, "oauth exchange failed"))?
                .json()
                .await
                .map_err(|_| json_err(StatusCode::BAD_GATEWAY, "oauth exchange failed"))?;
            let access = token_resp
                .get("access_token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| json_err(StatusCode::BAD_GATEWAY, "oauth exchange failed"))?;
            let user: serde_json::Value = auth
                .inner
                .client
                .get("https://api.github.com/user")
                .header("User-Agent", "task-space")
                .bearer_auth(access)
                .send()
                .await
                .map_err(|_| json_err(StatusCode::BAD_GATEWAY, "oauth userinfo failed"))?
                .json()
                .await
                .map_err(|_| json_err(StatusCode::BAD_GATEWAY, "oauth userinfo failed"))?;
            let sub = user
                .get("id")
                .map(|v| v.to_string())
                .unwrap_or_default();
            let mut email = user
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            if email.is_empty() {
                let emails: serde_json::Value = auth
                    .inner
                    .client
                    .get("https://api.github.com/user/emails")
                    .header("User-Agent", "task-space")
                    .bearer_auth(access)
                    .send()
                    .await
                    .map_err(|_| json_err(StatusCode::BAD_GATEWAY, "oauth userinfo failed"))?
                    .json()
                    .await
                    .map_err(|_| json_err(StatusCode::BAD_GATEWAY, "oauth userinfo failed"))?;
                if let Some(list) = emails.as_array() {
                    for entry in list {
                        if entry.get("primary").and_then(|v| v.as_bool()).unwrap_or(false)
                            && entry.get("verified").and_then(|v| v.as_bool()).unwrap_or(false)
                        {
                            email = entry
                                .get("email")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_owned();
                            break;
                        }
                    }
                    if email.is_empty() {
                        email = list
                            .iter()
                            .find_map(|e| e.get("email").and_then(|v| v.as_str()))
                            .unwrap_or_default()
                            .to_owned();
                    }
                }
            }
            if email.is_empty() || sub.is_empty() {
                return Err(json_err(StatusCode::BAD_GATEWAY, "oauth provider returned no email"));
            }
            Ok((email, sub))
        }
        _ => Err(json_err(
            StatusCode::NOT_IMPLEMENTED,
            "oauth provider not configured",
        )),
    }
}

#[derive(Debug, Serialize)]
struct OAuthProvidersResponse {
    google: bool,
    github: bool,
}

async fn oauth_providers(State(auth): State<LocalAuth>) -> Json<OAuthProvidersResponse> {
    Json(OAuthProvidersResponse {
        google: auth.inner.config.google.is_some(),
        github: auth.inner.config.github.is_some(),
    })
}

/// Public auth router mounted alongside the API (no session middleware).
/// Keeps WorkOS-compatible paths so the existing frontend keeps working.
pub fn router(auth: Arc<LocalAuth>) -> Router {
    let state = (*auth).clone();
    Router::new()
        .route("/auth/sign-in", get(sign_in_redirect).post(handle_password_sign_in))
        .route("/auth/sign-up", get(sign_up_redirect).post(handle_password_sign_up))
        .route("/auth/callback", get(callback))
        .route("/auth/oauth/{provider}", get(oauth_start))
        .route("/auth/oauth-providers", get(oauth_providers))
        .route("/auth/verify-email", post(verify_email_route))
        .route("/auth/password-reset", post(request_password_reset_route))
        .route(
            "/auth/password-reset/confirm",
            post(confirm_password_reset_route),
        )
        .route("/auth/refresh", post(refresh_route))
        .route("/auth/logout", post(logout_route))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}

async fn sign_in_redirect() -> Response {
    Redirect::temporary("/signin").into_response()
}
async fn sign_up_redirect() -> Response {
    Redirect::temporary("/signup").into_response()
}

async fn callback(
    State(auth): State<LocalAuth>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    // OAuth providers redirect here; plain GETs without code go to the app.
    if query.code.is_some() {
        return oauth_callback(State(auth), headers, Query(query)).await;
    }
    Redirect::temporary(&auth.inner.config.post_login_redirect).into_response()
}

async fn verify_email_route(
    State(auth): State<LocalAuth>,
    Json(payload): Json<VerifyPayload>,
) -> Response {
    verify_email(State(auth), Json(payload)).await
}
async fn request_password_reset_route(
    State(auth): State<LocalAuth>,
    headers: HeaderMap,
    Json(payload): Json<ResetRequestPayload>,
) -> Response {
    request_password_reset(State(auth), headers, Json(payload)).await
}
async fn confirm_password_reset_route(
    State(auth): State<LocalAuth>,
    Json(payload): Json<ResetConfirmPayload>,
) -> Response {
    confirm_password_reset(State(auth), Json(payload)).await
}
async fn refresh_route(State(auth): State<LocalAuth>, headers: HeaderMap) -> Response {
    refresh(State(auth), headers).await
}
async fn logout_route(State(auth): State<LocalAuth>, headers: HeaderMap) -> Response {
    logout(State(auth), headers).await
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[allow(dead_code)]
const _KEEP_VERIFY_TTL: i64 = VERIFY_CODE_TTL_SECS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalization_rejects_garbage() {
        assert!(LocalAuth::normalize_email("not-an-email").is_none());
        assert!(LocalAuth::normalize_email("  A@Example.COM  ")
            .map(|(_, n)| n)
            .as_deref()
            == Some("a@example.com"));
    }

    #[test]
    fn token_hash_is_stable_hex() {
        let digest = LocalAuth::token_hash("abc");
        assert_eq!(digest.len(), 32);
        assert_eq!(hex_encode(&[0xabu8, 0x01]), "ab01");
    }
}
