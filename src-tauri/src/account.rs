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
use std::{path::Path, time::Duration};
use tauri::{AppHandle, Emitter, Listener, Manager, State, Window};
use tauri_plugin_store::StoreExt;
use tracing::{debug, warn};

use crate::{
    anisette_patch::akd_client_info,
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

async fn login(
    app: &AppHandle,
    window: &Window,
    email: &str,
    password: &str,
    anisette_server: String,
) -> Result<Sideloader, AppError> {
    let window_clone = window.clone();
    let tfa_closure = move || -> Option<String> {
        window_clone
            .emit("2fa-required", ())
            .expect("Failed to emit 2fa-required event");

        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let handler_id = window_clone.listen("2fa-recieved", move |event| {
            let code = event.payload();
            let _ = tx.send(code.to_string());
        });

        let result = rx.recv_timeout(Duration::from_secs(120));
        window_clone.unlisten(handler_id);

        match result {
            Ok(code) => {
                let code = code.trim_matches('"').to_string();
                Some(code)
            }
            Err(_) => None,
        }
    };

    let anisette_url = if !anisette_server.starts_with("http") {
        format!("https://{}", anisette_server)
    } else {
        anisette_server
    };

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
        .await?;

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
}
