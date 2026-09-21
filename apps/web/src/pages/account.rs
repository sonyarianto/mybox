use std::cell::RefCell;

use gloo_net::http::Request;
use serde::{Deserialize, Serialize};

/// Local entitlement: billing is dropped, every signed-in account syncs.
/// Extra server fields are ignored so older/newer payloads keep decoding.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct Entitlement {
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub plan: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub sync_enabled: bool,
    #[serde(default)]
    pub max_spaces: u32,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub provider_customer_id: Option<String>,
}

impl Entitlement {
    pub fn can_sync(&self) -> bool {
        self.sync_enabled
    }
    pub fn can_sync_at(&self, _now_secs: u64) -> bool {
        self.sync_enabled
    }
}

use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::{JsFuture, future_to_promise};
use web_sys::{RequestCredentials, Storage};

use super::api::{api_url, send_with_timeout};

const AUTHENTICATED_SESSION_STORAGE_KEY: &str = "mybox_authenticated_session";
const ACTIVE_ACCOUNT_ID_STORAGE_KEY: &str = "mybox_active_account_id";

thread_local! {
    static REFRESH_IN_FLIGHT: RefCell<Option<js_sys::Promise>> = const { RefCell::new(None) };
}

#[wasm_bindgen(inline_js = r#"
const myboxAuthRefreshLockKey = "mybox:auth-refresh-lock";
const myboxAuthRefreshOwner = globalThis.crypto?.randomUUID?.()
  || `${Date.now()}-${Math.random()}`;
const myboxAuthRefreshLeaseMs = 20_000;
const myboxAuthRefreshWaitMs = myboxAuthRefreshLeaseMs + 2_000;
let myboxAuthRefreshLock = null;
let myboxAuthRefreshRequest = null;

function myboxAcquireAuthRefreshStorageLock() {
  return new Promise((resolve) => {
    let storage;
    try {
      storage = globalThis.localStorage;
      if (!storage) {
        resolve("unavailable");
        return;
      }
    } catch (_) {
      resolve("unavailable");
      return;
    }
    const deadline = Date.now() + myboxAuthRefreshWaitMs;
    const attempt = () => {
      const now = Date.now();
      if (now > deadline) {
        // A live holder should finish within the request timeout. If it was
        // suspended, its expiring lease is now eligible for takeover. Keep
        // the result bounded instead of waiting on an unbounded Web Lock.
        resolve("busy");
        return;
      }
      try {
        const current = JSON.parse(storage.getItem(myboxAuthRefreshLockKey) || "null");
        if (current?.owner !== myboxAuthRefreshOwner && Number(current?.expiresAt) > now) {
          setTimeout(attempt, 100);
          return;
        }
        const lease = {
          owner: myboxAuthRefreshOwner,
          expiresAt: now + myboxAuthRefreshLeaseMs,
        };
        storage.setItem(myboxAuthRefreshLockKey, JSON.stringify(lease));
        const verified = JSON.parse(storage.getItem(myboxAuthRefreshLockKey) || "null");
        if (verified?.owner !== lease.owner) {
          setTimeout(attempt, 100);
          return;
        }
        myboxAuthRefreshLock = { owner: lease.owner, storage: true };
        resolve("acquired");
      } catch (_) {
        resolve("unavailable");
      }
    };
    attempt();
  });
}

function myboxAcquireAuthRefreshWebLock() {
  const locks = globalThis.navigator?.locks;
  if (!locks || typeof locks.request !== "function") return Promise.resolve(false);
  return new Promise((resolve) => {
    const deadline = Date.now() + myboxAuthRefreshWaitMs;
    const attempt = () => {
      if (Date.now() > deadline) {
        resolve(false);
        return;
      }
      locks.request("mybox-auth-refresh", { mode: "exclusive", ifAvailable: true }, (lock) => {
        if (!lock) {
          setTimeout(attempt, 100);
          return undefined;
        }
        let release;
        const hold = new Promise((releaseLock) => { release = releaseLock; });
        myboxAuthRefreshLock = { release, storage: false };
        resolve(true);
        return hold;
      }).catch(() => resolve(false));
    };
    attempt();
  });
}

export function myboxAcquireAuthRefreshLock() {
  if (myboxAuthRefreshLock) return Promise.resolve(true);
  if (myboxAuthRefreshRequest) return myboxAuthRefreshRequest;
  const promise = myboxAcquireAuthRefreshStorageLock().then((result) => {
    if (result === "acquired") return true;
    if (result === "busy") return false;
    // Storage can be denied in private/restricted profiles. Native Web Locks
    // remain useful there, but ifAvailable plus a deadline prevents a frozen
    // tab from blocking authentication forever.
    if (globalThis.navigator?.locks?.request) {
      return myboxAcquireAuthRefreshWebLock();
    }
    // There is no cross-tab primitive left. Preserve the old best-effort
    // behavior for this exceptional profile while keeping the normal path
    // serialized by the expiring storage lease.
    myboxAuthRefreshLock = { storage: false, bestEffort: true };
    return true;
  });
  myboxAuthRefreshRequest = promise;
  promise.finally(() => {
    if (myboxAuthRefreshRequest === promise) myboxAuthRefreshRequest = null;
  });
  return promise;
}

export function myboxReleaseAuthRefreshLock() {
  const lock = myboxAuthRefreshLock;
  myboxAuthRefreshLock = null;
  if (lock?.storage) {
    try {
      const storage = globalThis.localStorage;
      const current = JSON.parse(storage?.getItem(myboxAuthRefreshLockKey) || "null");
      if (current?.owner === lock.owner) storage?.removeItem(myboxAuthRefreshLockKey);
    } catch (_) {}
  }
  if (typeof lock?.release === "function") lock.release();
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = myboxAcquireAuthRefreshLock)]
    fn acquire_auth_refresh_lock() -> js_sys::Promise;

    #[wasm_bindgen(js_name = myboxReleaseAuthRefreshLock)]
    fn release_auth_refresh_lock();
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum AccountState {
    Checking,
    Guest,
    /// The browser previously had an authenticated account, but the access
    /// and refresh sessions can no longer be renewed. Keep its local
    /// namespace visible and pause cloud sync until the user signs in again.
    Expired,
    SignedIn(Entitlement),
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckoutReturnState {
    None,
    Pending,
    Failed,
}

impl AccountState {
    pub fn is_authenticated(&self) -> bool {
        matches!(self, Self::SignedIn(_))
    }

    #[allow(dead_code)]
    pub fn entitlement(&self) -> Option<&Entitlement> {
        match self {
            Self::SignedIn(entitlement) => Some(entitlement),
            _ => None,
        }
    }
}

pub fn remember_authenticated_session() {
    for storage in auth_storages() {
        let _ = storage.set_item(AUTHENTICATED_SESSION_STORAGE_KEY, "true");
    }
}

pub fn forget_authenticated_session() {
    for storage in auth_storages() {
        let _ = storage.remove_item(AUTHENTICATED_SESSION_STORAGE_KEY);
        let _ = storage.remove_item(ACTIVE_ACCOUNT_ID_STORAGE_KEY);
    }
}

fn auth_storages() -> Vec<Storage> {
    let Some(window) = web_sys::window() else {
        return Vec::new();
    };
    let mut storages = Vec::new();
    if let Ok(Some(storage)) = window.local_storage() {
        storages.push(storage);
    }
    if let Ok(Some(storage)) = window.session_storage() {
        storages.push(storage);
    }
    storages
}

pub fn remember_authenticated_account(account_id: &str) {
    remember_authenticated_session();
    if account_id.trim().is_empty() {
        return;
    }
    // Keep the account marker in both stores. Some privacy-focused browsers
    // partition or clear localStorage while leaving sessionStorage intact;
    // losing this marker on an expired session makes the account workspace
    // look like a brand-new empty guest board.
    for storage in auth_storages() {
        let _ = storage.set_item(ACTIVE_ACCOUNT_ID_STORAGE_KEY, account_id);
    }
}

pub fn remembered_account_principal() -> Option<String> {
    auth_storages().into_iter().find_map(|storage| {
        let authenticated = storage
            .get_item(AUTHENTICATED_SESSION_STORAGE_KEY)
            .ok()
            .flatten()
            .is_some_and(|value| value == "true");
        if !authenticated {
            return None;
        }
        storage
            .get_item(ACTIVE_ACCOUNT_ID_STORAGE_KEY)
            .ok()
            .flatten()
            .filter(|account_id| !account_id.trim().is_empty())
            .map(|account_id| format!("account:{account_id}"))
    })
}

fn state_after_session_expiry() -> AccountState {
    state_after_session_expiry_for(remembered_account_principal().is_some())
}

fn state_after_session_expiry_for(has_remembered_account: bool) -> AccountState {
    if has_remembered_account {
        AccountState::Expired
    } else {
        AccountState::Guest
    }
}

pub async fn load_account_state() -> AccountState {
    let mut refresh_attempted = false;
    loop {
        let Ok(session) = auth_session().await else {
            return AccountState::Unavailable;
        };
        if session.status() == 401 {
            if !refresh_attempted && refresh_session_once().await {
                refresh_attempted = true;
                continue;
            }
            return state_after_session_expiry();
        }
        if !(200..300).contains(&session.status()) {
            return AccountState::Unavailable;
        }

        let Ok(response) = account_entitlement().await else {
            return AccountState::Unavailable;
        };
        if response.status() == 401 && !refresh_attempted && refresh_session_once().await {
            refresh_attempted = true;
            continue;
        }
        return match response.status() {
            200..=299 => response
                .json::<Entitlement>()
                .await
                .map(|entitlement| {
                    remember_authenticated_account(&entitlement.account_id);
                    AccountState::SignedIn(entitlement)
                })
                .unwrap_or(AccountState::Unavailable),
            401 => state_after_session_expiry(),
            _ => AccountState::Unavailable,
        };
    }
}

/// Refresh the cookie session once, sharing a single in-flight rotation among
/// concurrent callers so refresh-token rotation cannot race.
pub async fn refresh_session_once() -> bool {
    if let Some(existing) = REFRESH_IN_FLIGHT.with(|flight| flight.borrow().clone()) {
        return JsFuture::from(existing)
            .await
            .ok()
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
    }
    let promise = future_to_promise(async {
        let lock_acquired = JsFuture::from(acquire_auth_refresh_lock())
            .await
            .ok()
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        if !lock_acquired {
            return Ok(JsValue::from_bool(false));
        }
        // Another tab may have completed the rotation while this tab was
        // waiting for the shared lock. Re-check the access cookie before
        // rotating again; this avoids invalidating a fresh refresh token.
        let already_authenticated = auth_session()
            .await
            .is_ok_and(|response| (200..300).contains(&response.status()));
        let success = if already_authenticated {
            true
        } else {
            send_with_timeout(
                Request::post(&api_url("/auth/refresh")).credentials(RequestCredentials::Include),
            )
            .await
            .is_ok_and(|response| (200..300).contains(&response.status()))
        };
        release_auth_refresh_lock();
        Ok(JsValue::from_bool(success))
    });
    REFRESH_IN_FLIGHT.with(|flight| flight.replace(Some(promise.clone())));
    let result = JsFuture::from(promise)
        .await
        .ok()
        .and_then(|value| value.as_bool());
    REFRESH_IN_FLIGHT.with(|flight| {
        flight.borrow_mut().take();
    });
    result.unwrap_or(false)
}

async fn account_entitlement() -> Result<gloo_net::http::Response, gloo_net::Error> {
    // A guest 401 must not be reused after a successful sign-in on the same
    // browser. The entitlement is session state, so it should never be cached.
    let url = format!(
        "{}?check={}",
        api_url("/account/entitlement"),
        js_sys::Date::now()
    );
    send_with_timeout(Request::get(&url).credentials(RequestCredentials::Include)).await
}

async fn auth_session() -> Result<gloo_net::http::Response, gloo_net::Error> {
    let url = format!("{}?check={}", api_url("/auth/session"), js_sys::Date::now());
    send_with_timeout(Request::get(&url).credentials(RequestCredentials::Include)).await
}

pub async fn start_checkout(_interval: &'static str) -> Result<String, String> {
    Err("paid sync was removed; every signed-in account syncs".to_owned())
}

pub async fn start_billing_portal() -> Result<String, String> {
    Err("paid sync was removed; every signed-in account syncs".to_owned())
}

fn checkout_return_state_from_search(search: &str) -> CheckoutReturnState {
    let mut has_checkout_parameter = false;
    let mut returned_status = None;

    for parameter in search.trim_start_matches('?').split('&') {
        let Some((name, value)) = parameter.split_once('=') else {
            continue;
        };
        if matches!(name, "payment_id" | "subscription_id" | "status") {
            has_checkout_parameter = true;
        }
        if name == "status" {
            returned_status = Some(value.to_ascii_lowercase());
        }
    }

    if returned_status
        .as_deref()
        .is_some_and(|status| matches!(status, "failed" | "cancelled" | "canceled" | "expired"))
    {
        CheckoutReturnState::Failed
    } else if has_checkout_parameter {
        CheckoutReturnState::Pending
    } else {
        CheckoutReturnState::None
    }
}

pub fn checkout_return_state() -> CheckoutReturnState {
    let Some(window) = web_sys::window() else {
        return CheckoutReturnState::None;
    };
    let Ok(search) = window.location().search() else {
        return CheckoutReturnState::None;
    };
    checkout_return_state_from_search(&search)
}

/// A successful checkout redirects back before the webhook is guaranteed to
/// have reached us. Give the server a short window to apply the verified
/// subscription event before showing the upgrade gate again.
pub async fn load_account_state_after_checkout() -> AccountState {
    load_account_state().await
}

pub async fn sign_out() {
    forget_authenticated_session();
    let _ = send_with_timeout(
        Request::post(&api_url("/auth/logout")).credentials(RequestCredentials::Include),
    )
    .await;
    if let Some(window) = web_sys::window() {
        let _ = window.location().set_href("/");
    }
}

#[cfg(test)]
mod tests {
    use super::{CheckoutReturnState, checkout_return_state_from_search};

    #[test]
    fn recognizes_failed_checkout_returns() {
        assert_eq!(
            checkout_return_state_from_search("?subscription_id=sub_123&status=failed"),
            CheckoutReturnState::Failed
        );
        assert_eq!(
            checkout_return_state_from_search("?status=cancelled"),
            CheckoutReturnState::Failed
        );
    }

    #[test]
    fn recognizes_checkout_returns_that_may_be_waiting_for_a_webhook() {
        assert_eq!(
            checkout_return_state_from_search("?payment_id=pay_123&status=succeeded"),
            CheckoutReturnState::Pending
        );
        assert_eq!(
            checkout_return_state_from_search("?subscription_id=sub_123"),
            CheckoutReturnState::Pending
        );
        assert_eq!(
            checkout_return_state_from_search("?unrelated=value"),
            CheckoutReturnState::None
        );
    }

    #[test]
    fn expired_sessions_keep_a_known_account_namespace_distinct_from_guests() {
        assert_eq!(
            super::state_after_session_expiry_for(true),
            super::AccountState::Expired
        );
        assert_eq!(
            super::state_after_session_expiry_for(false),
            super::AccountState::Guest
        );
    }
}
