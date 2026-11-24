use futures::FutureExt;
use isideload::{
    anisette::remote_v3::{ANISETTE_STATE_KEY, ANISETTE_STATE_URL_KEY, RemoteV3AnisetteProvider},
    auth::apple_account::AppleAccount,
    dev::{
        app_ids::{AppIdsApi, ListAppIdsResponse},
        certificates::{CertificatesApi, DevelopmentCertificate},
        developer_session::DeveloperSession,
    },
    sideload::{SideloaderBuilder, builder::MaxCertsBehavior, sideloader::Sideloader},
};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    panic::AssertUnwindSafe,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tauri::{AppHandle, Emitter, Listener, Manager, State, Window};
use tauri_plugin_store::StoreExt;
use tracing::{debug, warn};

use crate::{
    anisette_patch::{AKD_CLIENT_INFO, AKD_USER_AGENT, akd_client_info},
    error::AppError,
    secure_storage::{create_sideloading_storage, keyring_available},
    sideload::{SideloaderGuard, SideloaderMutex},
};

#[tauri::command]
pub async fn login_new(
    handle: AppHandle,
    window: Window,
    sideloader_state: State<'_, SideloaderMutex>,
    email: String,
    password: String,
    anisette_server: String,
    save_credentials: bool,
) -> Result<(), AppError> {
    let account = login(&handle, &window, &email, &password, anisette_server).await?;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = Some(account);

    if save_credentials {
        let pass_entry = Entry::new("wander-installer", &email).map_err(|e| {
            AppError::KeyringWithMessage(
                "Failed to create entry for credentials".into(),
                e.to_string(),
            )
        })?;
        pass_entry.set_password(&password).map_err(|e| {
            AppError::KeyringWithMessage("Failed to save credentials".into(), e.to_string())
        })?;
        let store = handle
            .store("data.json")
            .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
        let mut existing_ids = store
            .get("ids")
            .unwrap_or_else(|| Value::Array(vec![]))
            .as_array()
            .cloned()
            .unwrap_or_else(std::vec::Vec::new);
        let value = Value::String(email.clone());
        if !existing_ids.contains(&value) {
            existing_ids.push(value);
        }
        store.set("ids", Value::Array(existing_ids));
    }
    Ok(())
}

#[tauri::command]
pub async fn login_stored(
    handle: AppHandle,
    window: Window,
    email: String,
    anisette_server: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let pass_entry = Entry::new("wander-installer", &email).map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for credentials".to_string(),
            e.to_string(),
        )
    })?;
    let password = pass_entry.get_password().map_err(|e| {
        AppError::KeyringWithMessage("Failed to get credentials".to_string(), e.to_string())
    })?;
    let account = login(&handle, &window, &email, &password, anisette_server).await?;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = Some(account);

    Ok(())
}

#[tauri::command]
pub fn delete_account(handle: AppHandle, email: String) -> Result<(), AppError> {
    let store = handle
        .store("data.json")
        .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
    let mut existing_ids = store
        .get("ids")
        .unwrap_or_else(|| Value::Array(vec![]))
        .as_array()
        .cloned()
        .unwrap_or_else(std::vec::Vec::new);
    existing_ids.retain(|v| v.as_str().is_none_or(|s| s != email));
    store.set("ids", Value::Array(existing_ids));
    let pass_entry = Entry::new("wander-installer", &email).map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for credentials".into(),
            e.to_string(),
        )
    })?;
    pass_entry.delete_credential().map_err(|e| {
        AppError::KeyringWithMessage("Failed to delete credentials".into(), e.to_string())
    })?;
    Ok(())
}

#[tauri::command]
pub fn logged_in_as(sideloader_state: State<'_, SideloaderMutex>) -> Option<String> {
    let sideloader_guard = sideloader_state.lock().unwrap();
    if let Some(account) = &*sideloader_guard {
        return Some(account.get_email().to_string());
    }
    None
}

#[tauri::command]
pub fn invalidate_account(sideloader_state: State<'_, SideloaderMutex>) {
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = None;
}

/// Anisette keys that "Reset Anisette State" removes: the provisioned state and the marker
/// recording which server it was provisioned against.
const ANISETTE_STORAGE_KEYS: [&str; 2] = [ANISETTE_STATE_KEY, ANISETTE_STATE_URL_KEY];

/// Delete the FsStorage copies of the anisette keys in `dir` (the app data directory).
/// Returns whether the provisioned state file existed.
fn delete_fs_anisette_state(dir: &Path) -> std::io::Result<bool> {
    let mut deleted_state = false;
    for key in ANISETTE_STORAGE_KEYS {
        match std::fs::remove_file(dir.join(key)) {
            Ok(()) => {
                if key == ANISETTE_STATE_KEY {
                    deleted_state = true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(deleted_state)
}

/// Delete the keyring copies of the anisette keys. Returns whether the state entry existed.
fn delete_keyring_anisette_state() -> Result<bool, keyring::Error> {
    let mut deleted_state = false;
    for key in ANISETTE_STORAGE_KEYS {
        match Entry::new("wander-installer", key)?.delete_credential() {
            Ok(()) => {
                if key == ANISETTE_STATE_KEY {
                    deleted_state = true;
                }
            }
            Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(deleted_state)
}

/// Remove cached anisette state. The app defaults to filesystem storage (secure_storage.rs),
/// where the state is a file in the app data directory; before 2.3.3 this only deleted the
/// keyring entry, so the button did nothing for most users.
#[tauri::command]
pub fn reset_anisette_state(handle: AppHandle) -> Result<bool, AppError> {
    let data_dir = handle
        .path()
        .app_data_dir()
        .map_err(|e| AppError::Misc(format!("Failed to get app data directory: {:?}", e)))?;
    // Same directory create_sideloading_storage hands to FsStorage.
    reset_anisette_state_in(&data_dir, keyring_available(), delete_keyring_anisette_state)
}

/// Delete the anisette files in `data_dir` and, only when the keyring is the storage in use,
/// the keyring entries. With the keyring off (the default), anisette is read from the files
/// only, so stale keychain items are never used, and touching them could make macOS ask for
/// the login keychain password (the reason secure_storage.rs avoids the keychain).
fn reset_anisette_state_in(
    data_dir: &Path,
    keyring_in_use: bool,
    delete_keyring: impl FnOnce() -> Result<bool, keyring::Error>,
) -> Result<bool, AppError> {
    let fs_deleted = delete_fs_anisette_state(data_dir).map_err(|e| {
        AppError::Filesystem("Failed to delete anisette state file".into(), e.to_string())
    })?;
    if fs_deleted {
        debug!("Anisette state file deleted.");
    }
    if !keyring_in_use {
        return Ok(fs_deleted);
    }

    let keyring_deleted = match delete_keyring() {
        Ok(deleted) => deleted,
        // A keyring error must not hide a successful file reset.
        Err(e) if !fs_deleted => {
            return Err(AppError::KeyringWithMessage(
                "Failed to delete anisette state".into(),
                e.to_string(),
            ));
        }
        Err(e) => {
            warn!("Could not clear anisette state from keyring: {}", e);
            false
        }
    };
    if keyring_deleted {
        debug!("Anisette state deleted from keyring.");
    }

    Ok(fs_deleted || keyring_deleted)
}

/// File in the app data directory that records which client identity (`AKD_CLIENT_INFO` and
/// `AKD_USER_AGENT`) the saved anisette state was provisioned under. State provisioned under an
/// older identity makes Apple refuse the first sign-in with -22410 (nab138/iloader#1304), so it
/// is cleared once, before the first sign-in after the identity changes.
const IDENTITY_MARKER_FILE: &str = "anisette_identity";

/// The marker contents for the identity this build sends.
fn current_identity() -> String {
    format!("{}\n{}", AKD_CLIENT_INFO, AKD_USER_AGENT)
}

/// Clear saved anisette state once if it belongs to a different client identity. Never stops
/// the sign-in: any error is logged and the sign-in goes ahead with whatever state exists.
fn clear_anisette_if_identity_changed(app: &AppHandle) {
    let data_dir = match app.path().app_data_dir() {
        Ok(dir) => dir,
        Err(e) => {
            warn!("Could not find the app data directory: {:?}", e);
            return;
        }
    };
    match clear_anisette_if_identity_changed_in(
        &data_dir,
        &current_identity(),
        keyring_available(),
        delete_keyring_anisette_state,
    ) {
        Ok(true) => debug!("Cleared anisette state saved under an older client identity."),
        Ok(false) => {}
        Err(e) => warn!("Could not check the saved sign-in identity: {:?}", e),
    }
}

/// Returns whether saved anisette state was cleared. The marker is opened for writing BEFORE
/// anything is cleared, so a marker that cannot be written never causes a clear (otherwise
/// every sign-in would wipe freshly provisioned state). It is filled in only after the clear
/// succeeds; if the clear fails it is left empty and the next sign-in tries again.
fn clear_anisette_if_identity_changed_in(
    data_dir: &Path,
    identity: &str,
    keyring_in_use: bool,
    delete_keyring: impl FnOnce() -> Result<bool, keyring::Error>,
) -> Result<bool, AppError> {
    use std::io::Write;
    let marker = data_dir.join(IDENTITY_MARKER_FILE);
    let fs_err = |what: &str, e: std::io::Error| AppError::Filesystem(what.into(), e.to_string());
    match std::fs::read(&marker) {
        // Anything that is not exactly this identity (old identity, empty, not text) is a mismatch.
        Ok(saved) if saved.trim_ascii() == identity.as_bytes() => return Ok(false),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        // Unreadable marker: leave the state alone rather than risk clearing it on every sign-in.
        Err(e) => return Err(fs_err("Failed to read the sign-in identity marker", e)),
    }
    std::fs::create_dir_all(data_dir)
        .map_err(|e| fs_err("Failed to create the app data directory", e))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&marker)
        .map_err(|e| fs_err("Failed to open the sign-in identity marker", e))?;
    let cleared = reset_anisette_state_in(data_dir, keyring_in_use, delete_keyring)?;
    file.write_all(identity.as_bytes())
        .map_err(|e| fs_err("Failed to write the sign-in identity marker", e))?;
    Ok(cleared)
}

/// Set while a sign-in runs. Each sign-in asks Apple for a new trusted-device code, and a new
/// code cancels the one before it, so a second sign-in started on top of the first (clicking
/// Login again while "Logging in..." shows) makes the code the user types fail with -27589.
static LOGIN_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// Holds the single sign-in slot and frees it when dropped, on every return path.
struct LoginFlight;

impl LoginFlight {
    fn acquire() -> Result<Self, AppError> {
        LOGIN_IN_PROGRESS
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| LoginFlight)
            .map_err(|_| AppError::LoginInProgress)
    }
}

impl Drop for LoginFlight {
    fn drop(&mut self) {
        LOGIN_IN_PROGRESS.store(false, Ordering::Release);
    }
}

/// How long the 2FA prompt waits for a code. Long enough for the "Didn't get a code?" steps
/// in the dialog (Airplane Mode, then Settings > Sign-In & Security > Get Verification Code).
const TWO_FACTOR_TIMEOUT: Duration = Duration::from_secs(300);

/// Upper bound for the network steps of one sign-in, added up. Time spent waiting for the
/// user to type a code is not counted (see `UserWait`), so a stalled server is given up on
/// after this long whether or not a code was asked for, and a code typed late is never cut
/// off. Neither HTTP client in isideload sets a request timeout, so a server that accepts the
/// connection and never answers would otherwise hold the single sign-in slot (and keep Login
/// disabled) until the app is quit. A normal sign-in needs about 10 seconds of network time
/// (installer log, 2026-11-17).
const LOGIN_NETWORK_BUDGET: Duration = Duration::from_secs(90);

/// Time one sign-in has spent waiting for the user (the 2FA prompt), in milliseconds.
#[derive(Clone, Default)]
struct UserWait(Arc<AtomicU64>);

impl UserWait {
    fn add(&self, waited: Duration) {
        self.0
            .fetch_add(waited.as_millis() as u64, Ordering::AcqRel);
    }

    fn total(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::Acquire))
    }
}

async fn login(
    app: &AppHandle,
    window: &Window,
    email: &str,
    password: &str,
    anisette_server: String,
) -> Result<Sideloader, AppError> {
    let user_wait = UserWait::default();
    // The future does nothing until it is polled, so building it before the slot is taken
    // starts no second sign-in.
    single_login_with_deadline(
        LOGIN_NETWORK_BUDGET,
        &user_wait,
        login_inner(app, window, email, password, anisette_server, &user_wait),
    )
    .await
}

/// Runs one sign-in while holding the single sign-in slot. Gives up once the sign-in has used
/// `network_budget` of time outside `user_wait`. Dropping the timed-out future drops
/// everything it holds, and `_flight` is released when this returns, on every path, so Login
/// works again. A panic inside the sign-in becomes an error: Tauri sends no reply for a
/// command that panics, and the UI would show "Logging in..." until the app is restarted.
async fn single_login_with_deadline<T>(
    network_budget: Duration,
    user_wait: &UserWait,
    sign_in: impl std::future::Future<Output = Result<T, AppError>>,
) -> Result<T, AppError> {
    let _flight = LoginFlight::acquire()?;
    let started = Instant::now();
    let sign_in = AssertUnwindSafe(sign_in).catch_unwind();
    tokio::pin!(sign_in);
    loop {
        let on_network = started.elapsed().saturating_sub(user_wait.total());
        let remaining = network_budget.saturating_sub(on_network);
        if remaining.is_zero() {
            warn!(
                "Sign-in did not finish within {:?} of network time",
                network_budget
            );
            return Err(AppError::LoginTimedOut);
        }
        // The 2FA prompt blocks inside the sign-in's poll, so the timer can only fire after
        // it. When it does, go round again: the time the prompt took is not network time.
        match tokio::time::timeout(remaining, &mut sign_in).await {
            Ok(Ok(result)) => return result,
            Ok(Err(_panic)) => {
                // The panic text can quote what the user typed, so it is not copied into the
                // message.
                warn!("Sign-in panicked");
                return Err(AppError::Misc(
                    "The sign-in stopped because of an internal error.".into(),
                ));
            }
            Err(_) => continue,
        }
    }
}

async fn login_inner(
    app: &AppHandle,
    window: &Window,
    email: &str,
    password: &str,
    anisette_server: String,
    user_wait: &UserWait,
) -> Result<Sideloader, AppError> {
    let user_wait = user_wait.clone();
    let tfa_canceled = Arc::new(AtomicBool::new(false));
    let window_clone = window.clone();
    let tfa_canceled_clone = tfa_canceled.clone();
    let tfa_closure = move || -> Option<String> {
        window_clone
            .emit("2fa-required", ())
            .expect("Failed to emit 2fa-required event");

        // None means the user pressed Cancel in the 2FA dialog.
        let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
        let code_tx = tx.clone();
        let handler_id = window_clone.listen("2fa-recieved", move |event| {
            let code = event.payload();
            let _ = code_tx.send(Some(code.to_string()));
        });
        let cancel_id = window_clone.listen("2fa-cancelled", move |_| {
            let _ = tx.send(None);
        });

        let asked = Instant::now();
        let result = rx.recv_timeout(TWO_FACTOR_TIMEOUT);
        user_wait.add(asked.elapsed());
        window_clone.unlisten(handler_id);
        window_clone.unlisten(cancel_id);

        match result {
            Ok(Some(code)) => {
                let code = code.trim_matches('"').to_string();
                Some(code)
            }
            Ok(None) => {
                tfa_canceled_clone.store(true, Ordering::Release);
                None
            }
            Err(_) => None,
        }
    };

    let anisette_url = if !anisette_server.starts_with("http") {
        format!("https://{}", anisette_server)
    } else {
        anisette_server
    };

    clear_anisette_if_identity_changed(app);

    let mut account = AppleAccount::builder(&email.to_lowercase())
        .anisette_provider(
            RemoteV3AnisetteProvider::default()?
                .set_serial_number("0".to_string())
                .set_storage(create_sideloading_storage(app)?)
                // As iloader 2.4.1 (isideload 20b06c7): report the Mac akd client info
                // instead of the server's, without fetching /v3/client_info.
                .set_client_info_override(Some(akd_client_info()))
                .set_url(&anisette_url),
        )
        .login(password, tfa_closure)
        .await
        .map_err(|e| {
            if tfa_canceled.load(Ordering::Acquire) {
                AppError::Canceled("Sign-in".into())
            } else {
                AppError::from(e)
            }
        })?;

    debug!("Logged in");

    let dev_session = DeveloperSession::from_account(&mut account).await?;

    debug!("Created developer session");

    let max_certs_callback = {
        let window_clone = window.clone();
        move |certs: &Vec<DevelopmentCertificate>| -> Option<Vec<String>> {
            let cert_infos: Vec<CertificateInfo> = certs
                .iter()
                .map(|cert| CertificateInfo {
                    name: cert.name.clone(),
                    certificate_id: cert.certificate_id.clone(),
                    serial_number: cert.serial_number.clone(),
                    machine_name: cert.machine_name.clone(),
                    machine_id: cert.machine_id.clone(),
                })
                .collect();
            window_clone
                .emit("max-certs-reached", cert_infos)
                .expect("Failed to emit max-certs-reached event");

            let (tx, rx) = std::sync::mpsc::channel::<Option<Vec<String>>>();
            let handler_id = window_clone.listen("max-certs-response", move |event| {
                let certs = event.payload();
                let certs = serde_json::from_str::<Option<Vec<String>>>(certs).unwrap_or(None);
                let _ = tx.send(certs);
            });

            let result = rx.recv_timeout(Duration::from_secs(300));
            window_clone.unlisten(handler_id);
            result.unwrap_or(None)
        }
    };

    // TODO: Team Selection

    let sideloader = SideloaderBuilder::new(dev_session, email.to_lowercase())
        .machine_name("wander-installer".into())
        .storage(create_sideloading_storage(app)?)
        .max_certs_behavior(MaxCertsBehavior::Prompt(Box::new(max_certs_callback)))
        .build();

    debug!("Built sideloader");

    Ok(sideloader)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub name: Option<String>,
    pub certificate_id: Option<String>,
    pub serial_number: Option<String>,
    pub machine_name: Option<String>,
    pub machine_id: Option<String>,
}

#[tauri::command]
pub async fn get_certificates(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<Vec<CertificateInfo>, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let certificates = dev_session.list_all_development_certs(&team, None).await?;

    Ok(certificates
        .into_iter()
        .map(|cert| CertificateInfo {
            name: cert.name,
            certificate_id: cert.certificate_id,
            serial_number: cert.serial_number,
            machine_name: cert.machine_name,
            machine_id: cert.machine_id,
        })
        .collect())
}

#[tauri::command]
pub async fn revoke_certificate(
    serial_number: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    dev_session
        .revoke_development_cert(&team, &serial_number, None)
        .await?;

    Ok(())
}

#[tauri::command]
pub async fn list_app_ids(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<ListAppIdsResponse, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let response = dev_session.list_app_ids(&team, None).await?;

    Ok(response.clone())
}

#[tauri::command]
pub async fn delete_app_id(
    app_id_id: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    dev_session.delete_app_id(&team, &app_id_id, None).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use isideload::util::{fs_storage::FsStorage, storage::SideloadingStorage};
    use std::cell::Cell;

    /// The sign-in slot is one static, so the tests that take it must not run side by side.
    static SLOT_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn run<F: std::future::Future>(f: F) -> F::Output {
        let _serial = SLOT_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(f)
    }

    async fn slot_is_free() -> bool {
        single_login_with_deadline(Duration::from_secs(5), &UserWait::default(), async {
            Ok(())
        })
        .await
        .is_ok()
    }

    #[test]
    fn stalled_sign_in_times_out_and_frees_the_slot() {
        run(async {
            // A server that accepts the connection and never answers.
            let stalled = std::future::pending::<Result<(), AppError>>();
            let started = Instant::now();
            let result = single_login_with_deadline(
                Duration::from_millis(50),
                &UserWait::default(),
                stalled,
            )
            .await;
            assert!(
                matches!(result, Err(AppError::LoginTimedOut)),
                "{:?}",
                result
            );
            assert!(started.elapsed() < Duration::from_secs(2));
            // Login is usable again: the slot was released.
            assert!(slot_is_free().await);
        });
    }

    /// Stands in for the 2FA prompt: blocks the poll, as `tfa_closure` does, and records the
    /// wait.
    fn user_types_a_code(user_wait: &UserWait, takes: Duration) {
        let asked = Instant::now();
        std::thread::sleep(takes);
        user_wait.add(asked.elapsed());
    }

    #[test]
    fn time_spent_typing_codes_is_not_network_time() {
        run(async {
            let user_wait = UserWait::default();
            let prompts = user_wait.clone();
            // Two code prompts, each far longer than the whole network budget, with a short
            // network step after each one.
            let sign_in = async move {
                for _ in 0..2 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    user_types_a_code(&prompts, Duration::from_millis(300));
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok(7)
            };
            let result =
                single_login_with_deadline(Duration::from_millis(150), &user_wait, sign_in).await;
            assert!(matches!(result, Ok(7)), "{:?}", result);
        });
    }

    #[test]
    fn a_stall_after_the_code_still_times_out() {
        run(async {
            let user_wait = UserWait::default();
            let prompts = user_wait.clone();
            let sign_in = async move {
                user_types_a_code(&prompts, Duration::from_millis(300));
                std::future::pending::<Result<(), AppError>>().await
            };
            let started = Instant::now();
            let result =
                single_login_with_deadline(Duration::from_millis(100), &user_wait, sign_in).await;
            assert!(
                matches!(result, Err(AppError::LoginTimedOut)),
                "{:?}",
                result
            );
            // The code wait plus the network budget, not more.
            let took = started.elapsed();
            assert!(took >= Duration::from_millis(400), "{:?}", took);
            assert!(took < Duration::from_secs(2), "{:?}", took);
            assert!(slot_is_free().await);
        });
    }

    #[test]
    fn a_panic_in_the_sign_in_becomes_an_error_and_frees_the_slot() {
        run(async {
            let sign_in = async {
                if true {
                    panic!("test panic: the sign-in future blew up");
                }
                Ok(())
            };
            let result =
                single_login_with_deadline(Duration::from_secs(5), &UserWait::default(), sign_in)
                    .await;
            match result {
                // The panic text must not reach the user: it can quote what they typed.
                Err(AppError::Misc(message)) => assert!(!message.contains("test panic")),
                other => panic!("expected a misc error, got {:?}", other),
            }
            assert!(slot_is_free().await);
        });
    }

    #[test]
    fn a_second_sign_in_is_refused_while_one_runs() {
        run(async {
            let first =
                single_login_with_deadline(Duration::from_secs(5), &UserWait::default(), async {
                    let second = single_login_with_deadline(
                        Duration::from_secs(5),
                        &UserWait::default(),
                        async { Ok(()) },
                    )
                    .await;
                    assert!(
                        matches!(second, Err(AppError::LoginInProgress)),
                        "{:?}",
                        second
                    );
                    Ok(())
                })
                .await;
            assert!(first.is_ok(), "{:?}", first);
        });
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wander-anisette-reset-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Write the state and marker exactly as the app does (FsStorage over the data dir).
    fn store_anisette_like_the_app(dir: &std::path::Path) {
        let storage = FsStorage::new(dir.to_path_buf());
        storage.store_data(ANISETTE_STATE_KEY, b"<plist/>").unwrap();
        storage
            .store(ANISETTE_STATE_URL_KEY, "https://ani.846969.xyz")
            .unwrap();
        storage.store("unrelated", "keep").unwrap();
        assert!(storage.retrieve_data(ANISETTE_STATE_KEY).unwrap().is_some());
    }

    #[test]
    fn reset_deletes_what_fs_storage_wrote() {
        let dir = temp_dir("fs");
        store_anisette_like_the_app(&dir);

        assert!(delete_fs_anisette_state(&dir).unwrap());
        let storage = FsStorage::new(dir.clone());
        assert!(storage.retrieve_data(ANISETTE_STATE_KEY).unwrap().is_none());
        assert!(storage.retrieve(ANISETTE_STATE_URL_KEY).unwrap().is_none());
        assert!(storage.retrieve("unrelated").unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reset_with_nothing_on_disk_reports_false() {
        let dir = temp_dir("empty");
        assert!(!delete_fs_anisette_state(&dir).unwrap());
        // A missing data directory is not an error either.
        assert!(!delete_fs_anisette_state(&dir.join("missing")).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reset_with_keyring_off_never_touches_the_keychain() {
        let dir = temp_dir("keyring-off");
        store_anisette_like_the_app(&dir);
        let touched = Cell::new(false);
        let result = reset_anisette_state_in(&dir, false, || {
            touched.set(true);
            Ok(true)
        });
        assert!(result.unwrap());
        assert!(!touched.get(), "keychain must not be touched when the keyring is off");
        assert!(!dir.join(ANISETTE_STATE_KEY).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reset_with_keyring_on_clears_both() {
        let dir = temp_dir("keyring-on");
        let touched = Cell::new(false);
        let result = reset_anisette_state_in(&dir, true, || {
            touched.set(true);
            Ok(true)
        });
        assert!(result.unwrap());
        assert!(touched.get());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keyring_error_only_fails_when_no_file_was_deleted() {
        let dir = temp_dir("keyring-err");
        let failing = || Err(keyring::Error::PlatformFailure("locked".into()));
        assert!(matches!(
            reset_anisette_state_in(&dir, true, failing),
            Err(AppError::KeyringWithMessage(_, _))
        ));
        store_anisette_like_the_app(&dir);
        assert!(reset_anisette_state_in(&dir, true, failing).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Run the identity check with the keyring off.
    fn check_identity(dir: &std::path::Path, identity: &str) -> bool {
        clear_anisette_if_identity_changed_in(dir, identity, false, || Ok(false)).unwrap()
    }

    fn marker(dir: &std::path::Path) -> String {
        std::fs::read_to_string(dir.join(IDENTITY_MARKER_FILE)).unwrap()
    }

    #[test]
    fn identity_change_clears_old_state_once() {
        let dir = temp_dir("identity-change");
        store_anisette_like_the_app(&dir);
        // Upgrading from 2.3.3: state exists, no marker yet.
        assert!(check_identity(&dir, "new-id"));
        assert!(!dir.join(ANISETTE_STATE_KEY).exists());
        assert_eq!(marker(&dir), "new-id");
        // State provisioned again under the new identity is kept on later sign-ins.
        store_anisette_like_the_app(&dir);
        assert!(!check_identity(&dir, "new-id"));
        assert!(dir.join(ANISETTE_STATE_KEY).exists());
        // A later identity change clears it again.
        assert!(check_identity(&dir, "newer-id"));
        assert!(!dir.join(ANISETTE_STATE_KEY).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_marker_on_a_fresh_install_just_records_the_identity() {
        let dir = temp_dir("identity-fresh").join("not-created-yet");
        assert!(!check_identity(&dir, "id"));
        assert_eq!(marker(&dir), "id");
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn identity_check_with_keyring_off_never_touches_the_keychain() {
        let dir = temp_dir("identity-keyring-off");
        store_anisette_like_the_app(&dir);
        let touched = Cell::new(false);
        clear_anisette_if_identity_changed_in(&dir, "id", false, || {
            touched.set(true);
            Ok(true)
        })
        .unwrap();
        assert!(!touched.get());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_marker_that_is_not_text_counts_as_a_mismatch() {
        let dir = temp_dir("identity-binary");
        store_anisette_like_the_app(&dir);
        std::fs::write(dir.join(IDENTITY_MARKER_FILE), [0xff, 0xfe, 0x00]).unwrap();
        assert!(check_identity(&dir, "id"));
        assert_eq!(marker(&dir), "id");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn identity_marker_that_cannot_be_written_never_clears_state() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("identity-readonly");
        store_anisette_like_the_app(&dir);
        let m = dir.join(IDENTITY_MARKER_FILE);
        std::fs::write(&m, "old-id").unwrap();
        std::fs::set_permissions(&m, std::fs::Permissions::from_mode(0o444)).unwrap();
        let result = clear_anisette_if_identity_changed_in(&dir, "new-id", false, || Ok(false));
        assert!(result.is_err());
        assert!(
            dir.join(ANISETTE_STATE_KEY).exists(),
            "state must survive an unwritable marker"
        );
        std::fs::set_permissions(&m, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
