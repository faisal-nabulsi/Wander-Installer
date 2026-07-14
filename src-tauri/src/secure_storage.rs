use std::sync::atomic::{AtomicBool, Ordering};

use isideload::util::{
    fs_storage::FsStorage, keyring_storage::KeyringStorage, storage::SideloadingStorage,
};
use tauri::{AppHandle, Manager};
use tracing::warn;

use crate::error::AppError;

// Default to filesystem storage instead of the macOS login keychain. Wander Installer
// ships UNSIGNED (no paid Apple Developer cert), and macOS re-prompts for the login
// keychain password on every access by an unsigned app — spamming users during login.
// Storing sideloading data (Apple ID session / anisette / pairing) in a file in the app's
// data dir avoids the keychain entirely, so there are no repeated password prompts.
static FORCE_DISABLE_KEYRING: AtomicBool = AtomicBool::new(true);

#[tauri::command]
pub fn force_disable_keyring(force: bool) {
    FORCE_DISABLE_KEYRING.store(force, Ordering::Relaxed);

    if force {
        warn!("Keyring has been forcefully disabled by the user.");
    } else {
        let available = check_keyring_available();
        if !available {
            warn!("Keyring is not available and cannot be enabled.");
        }
    }
}

#[tauri::command]
pub fn keyring_available() -> bool {
    !FORCE_DISABLE_KEYRING.load(Ordering::Relaxed) && check_keyring_available()
}

fn check_keyring_available() -> bool {
    let entry = keyring::Entry::new("wander-installer", "test");
    if let Ok(entry) = entry {
        return entry.set_password("test").is_ok() && entry.get_password().is_ok();
    }
    false
}

pub fn create_sideloading_storage(
    app: &AppHandle,
) -> Result<Box<dyn SideloadingStorage>, AppError> {
    if keyring_available() {
        Ok(Box::new(KeyringStorage::new("wander-installer".to_string())))
    } else {
        warn!(
            "Keyring is not available, falling back to filesystem storage for sideloading data. This is insecure!"
        );
        Ok(Box::new(FsStorage::new(
            app.path().app_data_dir().map_err(|e| {
                AppError::Misc(format!("Failed to get app data directory: {:?}", e))
            })?,
        )))
    }
}
