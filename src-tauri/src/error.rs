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
    AppleIdBlocked(String),
    #[error("{0}")]
    SigningIdentityRejected(String),
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
    TwoFactorRejected(String),
    #[error("A sign-in is already in progress")]
    LoginInProgress,
    #[error("Sign-in timed out")]
    LoginTimedOut,
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
    AnisetteRejected(String),
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

/// Sign-in error codes that mean Apple (or the anisette server) refused the device identity
/// rather than the Apple ID: -80045 (anisette platform does not match the client info, since
/// 2026-10-12), -80046 (Android-generated anisette refused at the token step, since
/// 2026-10-22) and -45061 (anisette not provisioned for this server).
pub const ANISETTE_REJECTED_CODES: [i64; 3] = [-80045, -80046, -45061];

pub fn is_anisette_rejected_code(code: i64) -> bool {
    ANISETTE_REJECTED_CODES.contains(&code)
}

/// Sign-in error code Apple returned once, on 2026-11-17, right after a trusted-device code
/// was typed. Apple does not document it. Observed once, while several sign-ins were running
/// at the same time; the likely cause is a code from an earlier attempt, not a confirmed one.
/// The installer log from that session has no line with the `ec`/`em` values (the error was
/// only read off the UI), so this mapping rests on that single observation.
pub const TWO_FACTOR_REJECTED_CODE: i64 = -27589;

/// Context isideload adds when Apple's answer to a submitted trusted-device code is an error
/// (`verify_trusted_device_2fa`). -27589 only means "code rejected" under this context; from
/// any other step (for example the password step) it stays a generic auth error.
const TWO_FACTOR_SUBMIT_CONTEXT: &str = "Trusted device 2FA rejected";

/// The two ways a device reports, at install time, that Apple refuses apps signed by this
/// Apple ID. Signing has already succeeded when either appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleInstallBlock {
    /// `0xe8008024 (The provisioning profile is banned.)`: Apple has blocked the Apple ID's
    /// signing team. First reported in July 2026; nothing a signer controls (certificate, key,
    /// bundle ID, profile) gets past it, and the same account fails in other sideloading tools.
    AppleIdBlocked,
    /// `0xe8008018 (The identity used to sign the executable is no longer valid.)`: the same
    /// block as seen by older iOS versions, or an ordinary revoked certificate. The text does
    /// not say which, so the advice covers both.
    SigningIdentityRejected,
}

/// Recognises Apple's install-time block in an error text, by hex code or by phrase, ignoring
/// case. The banned-profile code wins when a text holds both, because it is the specific one.
pub fn apple_install_block(text: &str) -> Option<AppleInstallBlock> {
    let text = text.to_lowercase();
    if text.contains("0xe8008024") || text.contains("the provisioning profile is banned") {
        return Some(AppleInstallBlock::AppleIdBlocked);
    }
    if text.contains("0xe8008018")
        || text.contains("the identity used to sign the executable is no longer valid")
    {
        return Some(AppleInstallBlock::SigningIdentityRejected);
    }
    None
}

// from rootcause report
impl From<Report> for AppError {
    fn from(report: Report) -> Self {
        let report_str = report.to_string();
        let at_two_factor_submit = report
            .iter_reports()
            .any(|cause| cause.to_string().contains(TWO_FACTOR_SUBMIT_CONTEXT));

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
            // The anisette server kept answering -45061 even after the automatic
            // re-provisioning. Checked here, before the generic anisette match below, because
            // that one would otherwise claim it through its outer "Failed to get anisette data"
            // context.
            if let Some(SideloadError::AnisetteProvisioningExhausted(_)) =
                cause.downcast_current_context::<SideloadError>()
            {
                return AppError::AnisetteRejected(report_str);
            }
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
                        TWO_FACTOR_REJECTED_CODE if at_two_factor_submit => {
                            return AppError::TwoFactorRejected(report_str);
                        }
                        code if is_anisette_rejected_code(code) => {
                            return AppError::AnisetteRejected(report_str);
                        }
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

        // Apple's install-time refusal of this Apple ID. Matched on the whole report text, so
        // it is found whichever error shape carries the device's message. Last, so it cannot
        // claim a report that one of the matches above recognises.
        match apple_install_block(&report_str) {
            Some(AppleInstallBlock::AppleIdBlocked) => AppError::AppleIdBlocked(report_str),
            Some(AppleInstallBlock::SigningIdentityRejected) => {
                AppError::SigningIdentityRejected(report_str)
            }
            None => AppError::Misc(report_str),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rootcause::prelude::*;

    fn classify(err: SideloadError) -> AppError {
        let report: Report = report!(err)
            .context("GrandSlam error during initial login request")
            .context("Failed to log in to Apple ID")
            .into_dynamic();
        AppError::from(report)
    }

    #[test]
    fn anisette_rejections_get_their_own_error() {
        // Hard-coded on purpose: the test checks the constant, so it must not loop over it.
        for code in [-80045, -80046, -45061] {
            let err = classify(SideloadError::AuthWithMessage(
                code,
                "This action cannot be completed at this time.".into(),
            ));
            assert!(
                matches!(err, AppError::AnisetteRejected(_)),
                "code {code} -> {:?}",
                err
            );
            assert_eq!(err.as_ref(), "anisette_rejected");
        }
    }

    #[test]
    fn other_auth_codes_keep_their_mapping() {
        assert!(matches!(
            classify(SideloadError::AuthWithMessage(-20209, "locked".into())),
            AppError::AccountLocked(_)
        ));
        assert!(matches!(
            classify(SideloadError::AuthWithMessage(
                -22406,
                "bad password".into()
            )),
            AppError::Auth(_)
        ));
    }

    #[test]
    fn rejected_two_factor_code_gets_its_own_error() {
        // The message is a placeholder: Apple's `em` text for -27589 was not captured.
        let report: Report = report!(SideloadError::AuthWithMessage(
            -27589,
            "placeholder message".into()
        ))
        .context("Trusted device 2FA rejected")
        .context("Failed to log in to Apple ID")
        .into_dynamic();
        let err = AppError::from(report);
        assert!(matches!(err, AppError::TwoFactorRejected(_)), "{:?}", err);
        assert_eq!(err.as_ref(), "two_factor_rejected");
    }

    #[test]
    fn minus_27589_outside_the_code_submission_stays_auth() {
        // Same code, but from the password step: the user typed no code, so "Apple rejected
        // the code" would be wrong.
        let err = classify(SideloadError::AuthWithMessage(
            -27589,
            "Unknown error".into(),
        ));
        assert!(matches!(err, AppError::Auth(_)), "{:?}", err);
    }

    #[test]
    fn login_in_progress_serializes_with_its_own_type() {
        assert_eq!(AppError::LoginInProgress.as_ref(), "login_in_progress");
        assert_eq!(AppError::LoginTimedOut.as_ref(), "login_timed_out");
    }

    // The device's wording, as quoted in nab138/iloader issue 583 (the staging path is the
    // one from that report).
    const BANNED_PROFILE_TEXT: &str = "Failed to verify code signature of /var/installd/Library/Caches/com.apple.mobile.installd.staging/temp.KpAV22/extracted/LiveContainer.app : 0xe8008024 (The provisioning profile is banned.)";
    const INVALID_IDENTITY_TEXT: &str = "Failed to verify code signature of /var/installd/Library/Caches/com.apple.mobile.installd.staging/temp.KpAV22/extracted/LiveContainer.app : 0xe8008018 (The identity used to sign the executable is no longer valid.)";

    /// The report `Sideloader::install_app` returns when the device refuses the install.
    fn install_failure(device_text: &str) -> AppError {
        let report: Report = report!(SideloadError::IdeviceError(
            IdeviceError::ApplicationVerificationFailed(device_text.into())
        ))
        .context("Failed to install app on device")
        .into_dynamic();
        AppError::from(report)
    }

    #[test]
    fn install_block_matches_the_hex_code_or_the_phrase() {
        use AppleInstallBlock::*;
        // Hard-coded on purpose, so a changed needle in the matcher fails here.
        let cases = [
            (BANNED_PROFILE_TEXT, Some(AppleIdBlocked)),
            ("status 0xe8008024", Some(AppleIdBlocked)),
            ("The provisioning profile is banned.", Some(AppleIdBlocked)),
            (INVALID_IDENTITY_TEXT, Some(SigningIdentityRejected)),
            ("status 0xe8008018", Some(SigningIdentityRejected)),
            (
                "The identity used to sign the executable is no longer valid.",
                Some(SigningIdentityRejected),
            ),
            // A text with both is the banned profile.
            ("0xe8008018, then 0xe8008024", Some(AppleIdBlocked)),
            // Neighbouring codes and other verification failures are not the block.
            (
                "0xe8008015 (A valid provisioning profile for this executable was not found.)",
                None,
            ),
            ("0xe800801c (No code signature found.)", None),
            (
                "This device has reached the maximum number of installed apps",
                None,
            ),
            ("e8008024", None),
            ("", None),
        ];
        for (text, expected) in cases {
            assert_eq!(apple_install_block(text), expected, "{text:?}");
        }
    }

    #[test]
    fn install_block_matching_ignores_case() {
        use AppleInstallBlock::*;
        assert_eq!(apple_install_block("0XE8008024"), Some(AppleIdBlocked));
        assert_eq!(
            apple_install_block("THE PROVISIONING PROFILE IS BANNED"),
            Some(AppleIdBlocked)
        );
        assert_eq!(
            apple_install_block("0xE8008018"),
            Some(SigningIdentityRejected)
        );
        assert_eq!(
            apple_install_block("the Identity Used To Sign The Executable Is No Longer Valid"),
            Some(SigningIdentityRejected)
        );
    }

    #[test]
    fn banned_profile_at_install_is_apple_id_blocked() {
        let err = install_failure(BANNED_PROFILE_TEXT);
        assert!(matches!(err, AppError::AppleIdBlocked(_)), "{:?}", err);
        assert_eq!(err.as_ref(), "apple_id_blocked");
        // The device's own text stays in the message for "More details" and support.
        assert!(err.to_string().contains("0xe8008024"), "{err}");
    }

    #[test]
    fn invalid_identity_at_install_is_signing_identity_rejected() {
        let err = install_failure(INVALID_IDENTITY_TEXT);
        assert!(
            matches!(err, AppError::SigningIdentityRejected(_)),
            "{:?}",
            err
        );
        assert_eq!(err.as_ref(), "signing_identity_rejected");
        assert!(err.to_string().contains("0xe8008018"), "{err}");
    }

    #[test]
    fn install_block_is_found_outside_the_typed_install_error() {
        // The same device text arriving as plain text, not as ApplicationVerificationFailed.
        let report: Report =
            report!("installd said: 0xE8008024 (the provisioning profile is banned.)")
                .context("Failed to install app on device")
                .into_dynamic();
        let err = AppError::from(report);
        assert!(matches!(err, AppError::AppleIdBlocked(_)), "{:?}", err);
    }

    #[test]
    fn other_install_failures_keep_their_mapping() {
        assert!(matches!(
            install_failure("This device has reached the maximum number of installed apps"),
            AppError::MaxApps(_)
        ));
        assert!(matches!(
            install_failure(
                "0xe8008015 (A valid provisioning profile for this executable was not found.)"
            ),
            AppError::Misc(_)
        ));
    }

    #[test]
    fn anisette_server_giving_up_on_45061_is_anisette_rejected() {
        // The same typed error AnisetteDataGenerator raises, under the context login adds.
        let report: Report = report!(SideloadError::AnisetteProvisioningExhausted(3))
            .context("Failed to get anisette data for login")
            .context("Failed to log in to Apple ID")
            .into_dynamic();
        assert!(matches!(
            AppError::from(report),
            AppError::AnisetteRejected(_)
        ));
    }
}
