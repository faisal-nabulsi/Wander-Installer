use idevice::IdeviceError;
use isideload::SideloadError;
use rootcause::Report;
use serde::Serialize;
use serde::ser::{SerializeStruct, Serializer};

#[derive(Debug, thiserror::Error, Clone, strum::AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum AppError {
    #[error("{0}")]
    MaxApps(String),
    #[error("{0}")]
    NotEnoughAppIds(String),
    #[error("{0}")]
    DeviceComs(String),
    #[error("{0}")]
    Underage(String),
    #[error("{0}")]
    AccountLocked(String),
    #[error("{0}")]
    Developer(String),
    #[error("{0}")]
    Auth(String),
    #[error("{0}")]
    Download(String),
    #[error("{0}: {1}")]
    HouseArrest(String, String),
    #[error("{0}")]
    RemotePairing(String),
    #[error("{0}: {1}")]
    LockdownPairing(String, String),
    #[error("{0} canceled")]
    Canceled(String),
    #[error("Failed to emit status to frontend: {0}")]
    OperationUpdate(String),
    #[error("{0}: {1}")]
    DeviceComsWithMessage(String, String),
    #[error("{0}: {1}")]
    Usbmuxd(String, String),
    #[error("Not logged in")]
    NotLoggedIn,
    #[error("No device selected")]
    NoDeviceSelected,
    #[error("{0}")]
    Anisette(String),
    #[error("{0}")]
    AppleAuthUnavailable(String),
    #[error("{0}")]
    AppleRateLimited(String),
    #[error("{0}")]
    Keyring(String),
    #[error("Keyring error: {0} - {1}")]
    KeyringWithMessage(String, String),
    #[error("{0}: {1}")]
    Storage(String, String),
    #[error("{0}")]
    Misc(String),
    #[error("{0}: {1}")]
    Filesystem(String, String),
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AppError", 2)?;
        state.serialize_field("type", self.as_ref())?;
        state.serialize_field("message", &self.to_string())?;
        state.end()
    }
}

// from rootcause report
impl From<Report> for AppError {
    fn from(report: Report) -> Self {
        let report_str = report.to_string();

        // Apple's GrandSlam sign-in edge (gsa.apple.com) can turn the request away before it
        // ever looks at the credentials: since ~2026-09-10 it answers a POST whose
        // X-Mme-Client-Info names com.apple.dt.Xcode with a 190-byte HTTP 503 page. Every
        // public anisette server still serves that string, so this is neither the user's Apple
        // ID nor their anisette server -- it needs a build that reports a different client info.
        //
        // Checked BEFORE the loop below so an outer string context cannot claim the report
        // first (the walk is outermost-first). Restricted to 5xx on purpose: the 2FA calls
        // (trustedDeviceSecondaryAuth, validateCode, secondaryAuth) all hit this same host, and
        // a mistyped code or a 429 must keep its own message instead of being relabelled as a
        // stale-installer problem.
        for cause in report.iter_reports() {
            if let Some(err) = cause.downcast_current_context::<reqwest::Error>() {
                let is_grandslam = err
                    .url()
                    .and_then(|url| url.host_str())
                    .is_some_and(|host| host == "gsa.apple.com");
                if is_grandslam && err.status().is_some_and(|s| s.as_u16() == 429) {
                    // Apple's edge also keeps a per-network budget of sign-in requests. Retrying
                    // straight away keeps it exhausted, so the advice is to wait, not to retry.
                    return AppError::AppleRateLimited(report_str);
                }
                if is_grandslam && err.status().is_some_and(|s| s.is_server_error()) {
                    return AppError::AppleAuthUnavailable(report_str);
                }
            }
        }

        for cause in report.iter_reports() {
            if cause.downcast_current_context::<keyring::Error>().is_some() {
                return AppError::Keyring(report_str);
            }
            if let Some(err) = cause.downcast_current_context::<SideloadError>() {
                match err {
                    &SideloadError::AuthWithMessage(code, _) => match code {
                        -20209 => return AppError::AccountLocked(report_str),
                        _ => {
                            return AppError::Auth(report_str);
                        }
                    },
                    &SideloadError::DeveloperError(code, _) => match code {
                        1102 => return AppError::Underage(report_str),
                        _ => {
                            return AppError::Developer(report_str);
                        }
                    },
                    SideloadError::IdeviceError(idev_err) => match idev_err {
                        IdeviceError::Socket(_) => {
                            return AppError::DeviceComs(report_str);
                        }
                        IdeviceError::ApplicationVerificationFailed(e) => {
                            if e.contains("maximum number of installed apps") {
                                return AppError::MaxApps(report_str);
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            let cause_str = cause.to_string();
            if cause_str.contains("Not enough available app IDs") {
                return AppError::NotEnoughAppIds(report_str);
            }
            if cause_str.contains("Failed to get anisette data for login")
                || cause_str.contains("Failed to get anisette client info")
                || cause_str.contains("Failed to get anisette headers")
            {
                return AppError::Anisette(report_str);
            }
        }

        AppError::Misc(report_str)
    }
}
