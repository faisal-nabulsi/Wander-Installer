use std::sync::Arc;

use crate::{
    SideloadError,
    anisette::{AnisetteData, AnisetteDataGenerator},
    auth::{
        builder::AppleAccountBuilder,
        grandslam::{GrandSlam, GrandSlamErrorChecker},
    },
    util::plist::{PlistDataExtract, SensitivePlistAttachment},
};
use aes::{
    Aes256,
    cipher::{block_padding::Pkcs7, consts::U16},
};
use aes_gcm::{AeadInOut, AesGcm, KeyInit, Nonce};
use base64::{Engine, prelude::BASE64_STANDARD};
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use hmac::{Hmac, Mac};
use plist::Dictionary;
use plist_macro::plist;
use reqwest::header::{HeaderMap, HeaderValue};
use rootcause::prelude::*;
use sha2::{Digest, Sha256};
use srp::{ClientVerifier, groups::G2048};
use tracing::{debug, info, warn};

pub struct AppleAccount {
    pub email: String,
    pub spd: Option<plist::Dictionary>,
    pub anisette_generator: AnisetteDataGenerator,
    pub grandslam_client: Arc<GrandSlam>,
    login_state: LoginState,
    debug: bool,
}

#[derive(Debug)]
pub enum LoginState {
    LoggedIn,
    /// Apple wants a trusted-device code and has not sent one yet: request it, then verify.
    NeedsDevice2FA,
    /// A trusted-device code is already on its way (requested by us, or pushed by Apple with
    /// hsc 409). Only ask the user for it and verify; requesting again cancels the pushed code.
    NeedsDevice2FAVerification,
    NeedsSMS2FA,
    NeedsExtraStep(String),
    NeedsLogin,
}

/// GrandSlam / ADI error: the machine's anisette is not provisioned (or provisioned for a
/// different anisette server).
pub const ANISETTE_NOT_PROVISIONED: i64 = -45061;

/// How many times a GrandSlam -45061 at the init step may trigger a fresh anisette
/// provisioning before giving up (so at most this + 1 init requests).
pub const MAX_GRANDSLAM_REPROVISIONS: usize = 2;

/// Map the `Status` dictionary of the SRP "complete" response to the next login step.
///
/// Backport of nab138/isideload fdb1788: when Apple has already pushed a code to the user's
/// trusted devices it answers `hsc = 409` and omits `au`. Treat that as trusted-device 2FA
/// whose code is already sent, so the login loop does not call
/// /auth/verify/trusteddevice again (which cancels the pushed code).
pub(crate) fn login_state_from_status(status: &Dictionary) -> LoginState {
    if let Some(plist::Value::String(s)) = status.get("au") {
        return match s.as_str() {
            "trustedDeviceSecondaryAuth" => LoginState::NeedsDevice2FA,
            "secondaryAuth" => LoginState::NeedsSMS2FA,
            "repair" => LoginState::LoggedIn, // Just means that you don't have 2FA set up
            unknown => LoginState::NeedsExtraStep(unknown.to_string()),
        };
    }

    if let Some(plist::Value::Integer(hsc)) = status.get("hsc") {
        match hsc.as_signed() {
            Some(200) => {}
            Some(409) => {
                info!("2FA code already sent to trusted devices (hsc 409)");
                return LoginState::NeedsDevice2FAVerification;
            }
            Some(code) => warn!("Unknown hsc status code {} in login response", code),
            None => warn!("Unknown hsc status code (invalid integer) in login response"),
        }
    }

    LoginState::LoggedIn
}

/// Extracts the resync SIM (base64 `X-Apple-I-MD-DATA`) from a GSA response that demands an
/// anisette resync (`Status.hsc == 434`); `None` otherwise. From nab138/isideload ac8976d.
pub(crate) fn resync_sim(resp: &Dictionary) -> Option<String> {
    let status = resp.get("Status")?.as_dictionary()?;
    if status.get("hsc").and_then(plist::Value::as_signed_integer) != Some(434) {
        return None;
    }
    match status.get("X-Apple-I-MD-DATA")? {
        plist::Value::Data(d) => Some(BASE64_STANDARD.encode(d)),
        plist::Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// Whether a GrandSlam error at the init step should discard anisette and provision again,
/// given how many re-provisions this login already did.
pub(crate) fn should_reprovision_after(err: &SideloadError, reprovisions_done: usize) -> bool {
    matches!(
        err,
        SideloadError::AuthWithMessage(ANISETTE_NOT_PROVISIONED, _)
    ) && reprovisions_done < MAX_GRANDSLAM_REPROVISIONS
}

/// The two actions of the SRP init step, split out so the -45061 retry loop can be tested
/// without the network.
pub(crate) trait InitSteps {
    /// Fetch anisette and send `o = init` (plus the hsc 434 resync). Returns the raw GrandSlam
    /// reply, not yet checked for errors, and the client-provided data that was sent.
    async fn attempt_init(&mut self) -> Result<(Dictionary, Dictionary), Report>;
    /// Discard the cached anisette and provision from scratch.
    async fn reprovision(&mut self) -> Result<(), Report>;
}

/// Send the init request; when GrandSlam answers -45061, re-provision anisette and try
/// again, at most `MAX_GRANDSLAM_REPROVISIONS` times (so at most that + 1 init requests).
pub(crate) async fn init_with_reprovision<S: InitSteps>(
    steps: &mut S,
) -> Result<(Dictionary, Dictionary), Report> {
    let mut reprovisions = 0;
    loop {
        let (raw_response, cpd) = steps.attempt_init().await?;
        let checked = raw_response.check_grandslam_error();
        if let Err(ref err) = checked
            && should_reprovision_after(err.current_context(), reprovisions)
        {
            reprovisions += 1;
            warn!(
                "Apple says the anisette is not provisioned (-45061); provisioning again ({}/{})",
                reprovisions, MAX_GRANDSLAM_REPROVISIONS
            );
            steps
                .reprovision()
                .await
                .context("Failed to provision anisette again after -45061")?;
            continue;
        }
        let response = checked.context("GrandSlam error during initial login request")?;
        return Ok((response, cpd));
    }
}

struct LiveInit<'a> {
    account: &'a mut AppleAccount,
    gs_service_url: &'a str,
    a_pub: &'a [u8],
}

impl InitSteps for LiveInit<'_> {
    async fn attempt_init(&mut self) -> Result<(Dictionary, Dictionary), Report> {
        let account = &mut *self.account;
        let anisette_data = account
            .anisette_generator
            .get_anisette_data(account.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for login")?;
        let cpd = anisette_data.get_client_provided_data();

        let mut raw_response = account
            .send_init_request(self.gs_service_url, &cpd, self.a_pub)
            .await
            .context("Failed to send initial login request")?;

        if let Some(sim) = resync_sim(&raw_response) {
            debug!("Anisette resync required (hsc 434); syncing then retrying init");
            let fresh = account
                .anisette_generator
                .resync(&sim)
                .await
                .context("Anisette resync failed")?;
            raw_response = account
                .send_init_request(
                    self.gs_service_url,
                    &fresh.get_client_provided_data(),
                    self.a_pub,
                )
                .await
                .context("Failed to send resynced init request")?;
        }
        Ok((raw_response, cpd))
    }

    async fn reprovision(&mut self) -> Result<(), Report> {
        let account = &mut *self.account;
        account
            .anisette_generator
            .force_reprovision(account.grandslam_client.clone())
            .await
    }
}

/// Most steps one sign-in may take after the first SRP exchange.
pub const MAX_LOGIN_STEPS: usize = 10;

/// The actions the post-init login loop can take, split out so the loop can be tested
/// without the network.
pub(crate) trait LoginSteps {
    /// Run the SRP exchange again and map the reply to the next state.
    async fn login_again(&mut self) -> Result<LoginState, Report>;
    /// Ask Apple to push a code to the trusted devices (GET trustedDeviceSecondaryAuth).
    async fn request_device_2fa(&mut self) -> Result<(), Report>;
    /// Ask the user for the code that is already on its way and submit it.
    async fn verify_device_2fa(&mut self) -> Result<(), Report>;
    /// Request an SMS code, ask the user for it and submit it.
    async fn sms_2fa(&mut self) -> Result<(), Report>;
    /// Whether the session already holds a PET token (lets an unknown `au` step pass).
    fn has_pet(&self) -> bool;
}

/// Drive the login state machine until signed in. `state` always holds the latest state,
/// also when this returns an error.
pub(crate) async fn drive_login<S: LoginSteps>(
    steps: &mut S,
    state: &mut LoginState,
) -> Result<(), Report> {
    let mut attempts = 0;
    loop {
        attempts += 1;
        if attempts > MAX_LOGIN_STEPS {
            bail!(
                "Couldn't login after {} attempts, aborting (current state: {:?})",
                MAX_LOGIN_STEPS,
                state
            );
        }
        match state {
            LoginState::LoggedIn => {
                info!("Successfully logged in to Apple ID");
                return Ok(());
            }
            LoginState::NeedsDevice2FA => {
                steps
                    .request_device_2fa()
                    .await
                    .context("Failed to complete trusted device 2FA")?;
                *state = LoginState::NeedsDevice2FAVerification;
            }
            LoginState::NeedsDevice2FAVerification => {
                // Never request here: the code is already on its way (requested above, or
                // pushed by Apple with hsc 409), and requesting again cancels it.
                steps
                    .verify_device_2fa()
                    .await
                    .context("Failed to complete trusted device 2FA")?;
                debug!("Trusted device 2FA completed, need to login again");
                *state = LoginState::NeedsLogin;
            }
            LoginState::NeedsSMS2FA => {
                info!("SMS 2FA required");
                steps
                    .sms_2fa()
                    .await
                    .context("Failed to complete SMS 2FA")?;
                debug!("SMS 2FA completed, need to login again");
                *state = LoginState::NeedsLogin;
            }
            LoginState::NeedsExtraStep(s) => {
                info!("Additional authentication step required: {}", s);
                if !steps.has_pet() {
                    bail!("Additional authentication required: {}", s);
                }
                *state = LoginState::LoggedIn;
            }
            LoginState::NeedsLogin => {
                debug!("Logging in again...");
                *state = steps
                    .login_again()
                    .await
                    .context("Failed to login again")?;
            }
        }
    }
}

struct LiveLogin<'a, F> {
    account: &'a mut AppleAccount,
    password: &'a str,
    two_factor_callback: &'a F,
}

impl<F: Fn() -> Option<String>> LoginSteps for LiveLogin<'_, F> {
    async fn login_again(&mut self) -> Result<LoginState, Report> {
        self.account.login_inner(self.password).await
    }

    async fn request_device_2fa(&mut self) -> Result<(), Report> {
        self.account.request_trusted_device_2fa().await
    }

    async fn verify_device_2fa(&mut self) -> Result<(), Report> {
        self.account
            .verify_trusted_device_2fa(self.two_factor_callback)
            .await
    }

    async fn sms_2fa(&mut self) -> Result<(), Report> {
        self.account.sms_2fa(self.two_factor_callback).await
    }

    fn has_pet(&self) -> bool {
        self.account.get_pet().is_ok()
    }
}

impl AppleAccount {
    /// Create a new AppleAccountBuilder with the given email
    ///
    /// # Arguments
    /// - `email`: The Apple ID email address
    pub fn builder(email: &str) -> AppleAccountBuilder {
        AppleAccountBuilder::new(email)
    }

    /// Build the apple account with the given email
    ///
    /// Reccomended to use the AppleAccountBuilder instead
    /// # Arguments
    /// - `email`: The Apple ID email address
    /// - `anisette_provider`: The anisette provider to use
    /// - `debug`: DANGER, If true, accept invalid certificates and enable verbose connection
    pub async fn new(
        email: &str,
        anisette_generator: AnisetteDataGenerator,
        debug: bool,
    ) -> Result<Self, Report> {
        if debug {
            warn!("Debug mode enabled: this is a security risk!");
        }

        let client_info = anisette_generator
            .get_client_info()
            .await
            .context("Failed to get anisette client info")?;

        let grandslam_client = GrandSlam::new(client_info, debug).await?;

        Ok(AppleAccount {
            email: email.to_string(),
            spd: None,
            anisette_generator,
            grandslam_client: Arc::new(grandslam_client),
            debug,
            login_state: LoginState::NeedsLogin,
        })
    }

    /// Log in to the Apple ID account
    /// # Arguments
    /// - `password`: The Apple ID password
    /// - `two_factor_callback`: A callback function that returns the two-factor authentication code
    /// # Errors
    /// Returns an error if the login fails
    pub async fn login(
        &mut self,
        password: &str,
        two_factor_callback: impl Fn() -> Option<String>,
    ) -> Result<(), Report> {
        info!("Logging in to Apple ID: {}", censor_email(&self.email));
        if self.debug {
            warn!("Debug mode enabled: this is a security risk!");
        }

        self.login_state = self
            .login_inner(password)
            .await
            .context("Failed to log in to Apple ID")?;

        debug!("Initial login successful");

        let mut state = std::mem::replace(&mut self.login_state, LoginState::NeedsLogin);
        let result = {
            let mut steps = LiveLogin {
                account: self,
                password,
                two_factor_callback: &two_factor_callback,
            };
            drive_login(&mut steps, &mut state).await
        };
        self.login_state = state;
        result
    }

    /// Get the user's first and last name associated with the Apple ID
    pub fn get_name(&self) -> Result<(String, String), Report> {
        let spd = self
            .spd
            .as_ref()
            .ok_or_else(|| report!("SPD not available, cannot get name"))?;

        Ok((spd.get_string("fn")?, spd.get_string("ln")?))
    }

    fn get_pet(&self) -> Result<String, Report> {
        let spd = self
            .spd
            .as_ref()
            .ok_or_else(|| report!("SPD not available, cannot get pet"))?;

        let pet = spd
            .get_dict("t")?
            .get_dict("com.apple.gs.idms.pet")?
            .get_string("token")?;

        Ok(pet)
    }

    /// Ask Apple to push a code to the user's trusted devices.
    async fn request_trusted_device_2fa(&mut self) -> Result<(), Report> {
        debug!("Trusted device 2FA required");

        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for 2FA")?;

        let request_code_url = self
            .grandslam_client
            .get_url("trustedDeviceSecondaryAuth")?;

        self.grandslam_client
            .get(&request_code_url)?
            .headers(self.build_2fa_headers(&anisette_data).await?)
            .send()
            .await
            .context("Failed to request trusted device 2fa")?
            .error_for_status()
            .context("Trusted device 2FA request failed")?;

        info!("Trusted device 2FA request sent");

        Ok(())
    }

    /// Ask the user for the trusted-device code that is already on its way and submit it.
    async fn verify_trusted_device_2fa(
        &mut self,
        two_factor_callback: impl Fn() -> Option<String>,
    ) -> Result<(), Report> {
        let code =
            two_factor_callback().ok_or_else(|| report!("No 2FA code provided, aborting"))?;

        // Fetched after the user typed the code (which can take up to two minutes) so the
        // one-time password is fresh, instead of reusing the one from before the prompt.
        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for 2FA")?;

        let submit_code_url = self.grandslam_client.get_url("validateCode")?;

        let res = self
            .grandslam_client
            .get(&submit_code_url)?
            .headers(self.build_2fa_headers(&anisette_data).await?)
            .header("security-code", code)
            .send()
            .await
            .context("Failed to submit trusted device 2fa code")?
            .error_for_status()
            .context("Trusted device 2FA code submission failed")?
            .text()
            .await
            .context("Failed to read trusted device 2FA response text")?;

        let plist: Dictionary = plist::from_bytes(res.as_bytes())
            .context("Failed to parse trusted device response plist")
            .attach_with(|| res.clone())?;
        plist
            .check_grandslam_error()
            .context("Trusted device 2FA rejected")?;

        Ok(())
    }

    async fn sms_2fa(
        &mut self,
        two_factor_callback: impl Fn() -> Option<String>,
    ) -> Result<(), Report> {
        debug!("SMS 2FA required");

        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for 2FA")?;

        let request_code_url = self.grandslam_client.get_url("secondaryAuth")?;

        self.grandslam_client
            .get_sms(&request_code_url)?
            .headers(self.build_2fa_headers(&anisette_data).await?)
            .send()
            .await
            .context("Failed to request SMS 2FA")?
            .error_for_status()
            .context("SMS 2FA request failed")?;

        info!("SMS 2FA request sent");

        let code =
            two_factor_callback().ok_or_else(|| report!("No 2FA code provided, aborting"))?;

        // Fresh anisette for the submission: the user may have taken a while to type the code.
        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for 2FA")?;

        let body = serde_json::json!({
            "securityCode": {
                "code": code
            },
            "phoneNumber": {
                "id": 1
            },
            "mode": "sms"
        });

        let mut headers = self.build_2fa_headers(&anisette_data).await?;
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));
        headers.insert(
            "Accept",
            HeaderValue::from_static("application/json, text/javascript, */*; q=0.01"),
        );

        let res = self
            .grandslam_client
            .post("https://gsa.apple.com/auth/verify/phone/securitycode")?
            .headers(headers)
            .body(body.to_string())
            .send()
            .await
            .context("Failed to submit SMS 2FA code")?;

        if !res.status().is_success() {
            let status = res.status();
            let text = res
                .text()
                .await
                .context("Failed to read SMS 2FA error response text")?;
            // try to parse as json, if it fails, just bail with the text
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
                && let Some(service_errors) = json.get("serviceErrors")
                && let Some(first_error) = service_errors.as_array().and_then(|arr| arr.first())
            {
                let code = first_error
                    .get("code")
                    .and_then(|c| c.as_str())
                    .unwrap_or("unknown");
                let title = first_error
                    .get("title")
                    .and_then(|t| t.as_str())
                    .unwrap_or("No title provided");
                let message = first_error
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("No message provided");
                bail!(
                    "SMS 2FA code submission failed (code {}): {} - {}",
                    code,
                    title,
                    message
                );
            }
            bail!(
                "SMS 2FA code submission failed with http status {}: {}",
                status,
                text
            );
        };

        Ok(())
    }

    async fn build_2fa_headers(&self, anisette_data: &AnisetteData) -> Result<HeaderMap, Report> {
        let mut headers = anisette_data.get_header_map()?;

        let spd = self
            .spd
            .as_ref()
            .ok_or_else(|| report!("SPD data not available, cannot build 2FA headers"))?;

        let adsid = spd
            .get_str("adsid")
            .context("Failed to build 2FA headers")?;
        let token = spd
            .get_str("GsIdmsToken")
            .context("Failed to build 2FA headers")?;
        let identity = BASE64_STANDARD.encode(format!("{}:{}", adsid, token));

        headers.insert(
            "X-Apple-Identity-Token",
            reqwest::header::HeaderValue::from_str(&identity)?,
        );
        headers.insert(
            "X-Apple-I-MD-RINFO",
            reqwest::header::HeaderValue::from_str(&anisette_data.routing_info)?,
        );

        Ok(headers)
    }

    async fn login_inner(&mut self, password: &str) -> Result<LoginState, Report> {
        let gs_service_url = self.grandslam_client.get_url("gsService")?;
        debug!("GrandSlam service URL: {}", gs_service_url);

        let srp_client = srp::Client::<G2048, Sha256>::new_with_options(false);
        let a: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let a_pub = srp_client.compute_public_ephemeral(&a);

        let (response, cpd) = init_with_reprovision(&mut LiveInit {
            account: self,
            gs_service_url: &gs_service_url,
            a_pub: &a_pub,
        })
        .await?;

        debug!("Login step 1 completed");

        let salt = response
            .get_data("s")
            .context("Failed to parse initial login response")?;
        let b_pub = response
            .get_data("B")
            .context("Failed to parse initial login response")?;
        let iters = response
            .get_signed_integer("i")
            .context("Failed to parse initial login response")?;
        let c = response
            .get_str("c")
            .context("Failed to parse initial login response")?;
        let selected_protocol = response
            .get_str("sp")
            .context("Failed to parse initial login response")?;

        debug!(
            "Selected SRP protocol: {}, iterations: {}",
            selected_protocol, iters
        );

        if selected_protocol != "s2k" && selected_protocol != "s2k_fo" {
            bail!("Unsupported SRP protocol selected: {}", selected_protocol);
        }

        let hashed_password = Sha256::digest(password.as_bytes());

        let password_hash = if selected_protocol == "s2k_fo" {
            hex::encode(hashed_password).into_bytes()
        } else {
            hashed_password.to_vec()
        };

        let mut password_buf = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(&password_hash, salt, iters as u32, &mut password_buf)
            .context("Failed to derive password using PBKDF2")?;

        let verifier = srp_client
            .process_reply(&a, self.email.as_bytes(), &password_buf, salt, b_pub)
            .context("Failed to compute SRP proof")?;

        let req2 = plist!(dict {
            "Header": {
                "Version": "1.0.1"
            },
            "Request": {
                "M1": verifier.proof().to_vec(), // A2k = client public ephemeral
                "c": c, // c = client proof from step 1
                "cpd": cpd, // cpd = client provided data
                "o": "complete", // o = operation
                "u": self.email.clone(), // u = username
            }
        });

        debug!("Sending proof login request");

        let mut close_headers = HeaderMap::new();
        close_headers.insert("Connection", HeaderValue::from_static("close"));

        let response2 = self
            .grandslam_client
            .plist_request(&gs_service_url, &req2, Some(close_headers))
            .await
            .context("Failed to send proof login request")?
            .check_grandslam_error()
            .context("GrandSlam error during proof login request")?;

        debug!("Login step 2 response received, verifying server proof");

        let m2 = response2
            .get_data("M2")
            .context("Failed to parse proof login response")?;
        verifier
            .verify_server(m2)
            .map_err(|e| report!("Negotiation failed, server proof mismatch: {}", e))?;

        debug!("Server proof verified");

        let spd_encrypted = response2
            .get_data("spd")
            .context("Failed to get SPD from login response")?;

        let spd_decrypted = Self::decrypt_cbc(&verifier, spd_encrypted)
            .context("Failed to decrypt SPD from login response")?;
        let spd: plist::Dictionary =
            plist::from_bytes(&spd_decrypted).context("Failed to parse decrypted SPD plist")?;

        self.spd = Some(spd);

        let status = response2
            .get_dict("Status")
            .context("Failed to parse proof login response")?;

        debug!("Login step 2 completed");

        Ok(login_state_from_status(status))
    }

    async fn send_init_request(
        &self,
        gs_service_url: &str,
        cpd: &Dictionary,
        a_pub: &[u8],
    ) -> Result<Dictionary, Report> {
        let req1 = plist!(dict {
            "Header": {
                "Version": "1.0.1"
            },
            "Request": {
                "A2k": a_pub.to_vec(), // A2k = client public ephemeral
                "cpd": cpd.clone(), // cpd = client provided data
                "o": "init", // o = operation
                "ps": [ // ps = protocols supported
                    "s2k",
                    "s2k_fo"
                ],
                "u": self.email.clone(), // u = username
            }
        });

        debug!("Sending initial login request");

        self.grandslam_client
            .plist_request(gs_service_url, &req1, None)
            .await
    }

    pub async fn get_app_token(&mut self, app: &str) -> Result<AppToken, Report> {
        let app = if app.contains("com.apple.gs.") {
            app.to_string()
        } else {
            format!("com.apple.gs.{}", app)
        };

        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for login")?;

        let spd = self
            .spd
            .as_ref()
            .ok_or_else(|| report!("SPD data not available, cannot get app token"))?;

        let dsid = spd.get_str("adsid").context("Failed to get app token")?;
        let auth_token = spd
            .get_str("GsIdmsToken")
            .context("Failed to get app token")?;
        let session_key = spd.get_data("sk").context("Failed to get app token")?;
        let c = spd.get_data("c").context("Failed to get app token")?;

        let checksum = Hmac::<Sha256>::new_from_slice(session_key)
            .context("Failed to create HMAC for app token checksum")
            .attach_with(|| SensitivePlistAttachment::new(spd.clone()))?
            .chain_update("apptokens".as_bytes())
            .chain_update(dsid.as_bytes())
            .chain_update(app.as_bytes())
            .finalize()
            .into_bytes()
            .to_vec();

        let gs_service_url = self.grandslam_client.get_url("gsService")?;
        let cpd = anisette_data.get_client_provided_data();

        let request = plist!(dict {
            "Header": {
                "Version": "1.0.1"
            },
            "Request": {
                "app": [app.clone()],
                "c": c,
                "checksum": checksum,
                "cpd": cpd,
                "o": "apptokens",
                "u": dsid,
                "t": auth_token
            }
        });

        let resp = self
            .grandslam_client
            .plist_request(&gs_service_url, &request, None)
            .await
            .context("Failed to send app token request")?
            .check_grandslam_error()
            .context("GrandSlam error during app token request")?;

        let encrypted_token = resp
            .get_data("et")
            .context("Failed to get encrypted token")?;

        debug!("Acquired encrypted token for {}", app);
        let decrypted_token = Self::decrypt_gcm(encrypted_token, session_key)
            .context("Failed to decrypt app token")?;
        debug!("Decrypted app token for {}", app);

        let token: Dictionary = plist::from_bytes(&decrypted_token)
            .context("Failed to parse decrypted app token plist")?;

        let status = token
            .get_signed_integer("status-code")
            .context("Failed to get status code from app token")?;
        if status != 200 {
            bail!("App token request failed with status code {}", status);
        }
        let token_dict = token
            .get_dict("t")
            .context("Failed to get token dictionary from app token")?;
        let app_token = token_dict
            .get_dict(&app)
            .context("Failed to get app token string")?;

        let app_token = AppToken {
            token: app_token
                .get_str("token")
                .context("Failed to get app token string")?
                .to_string(),
            duration: app_token
                .get_signed_integer("duration")
                .context("Failed to get app token duration")? as u64,
            expiry: app_token
                .get_signed_integer("expiry")
                .context("Failed to get app token expiry")? as u64,
        };

        info!("Successfully retrieved app token for {}", app);

        Ok(app_token)
    }

    fn create_session_key(usr: &ClientVerifier<Sha256>, name: &str) -> Result<Vec<u8>, Report> {
        Ok(Hmac::<Sha256>::new_from_slice(usr.key())?
            .chain_update(name.as_bytes())
            .finalize()
            .into_bytes()
            .to_vec())
    }

    fn decrypt_cbc(usr: &ClientVerifier<Sha256>, data: &[u8]) -> Result<Vec<u8>, Report> {
        let extra_data_key = Self::create_session_key(usr, "extra data key:")?;
        let extra_data_iv = Self::create_session_key(usr, "extra data iv:")?;
        let extra_data_iv = &extra_data_iv[..16];

        Ok(
            cbc::Decryptor::<aes::Aes256>::new_from_slices(&extra_data_key, extra_data_iv)?
                .decrypt_padded_vec::<Pkcs7>(data)?,
        )
    }

    fn decrypt_gcm(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Report> {
        if data.len() < 3 + 16 + 16 {
            bail!(
                "Encrypted token is too short to be valid (only {} bytes)",
                data.len()
            );
        }
        let header = &data[0..3];
        if header != b"XYZ" {
            bail!(
                "Encrypted token is in an unknown format: {}",
                String::from_utf8_lossy(header)
            );
        }
        let iv = &data[3..19];
        let ciphertext_and_tag = &data[19..];

        if key.len() != 32 {
            bail!("Session key is not the correct length: {} bytes", key.len());
        }
        if iv.len() != 16 {
            bail!("IV is not the correct length: {} bytes", iv.len());
        }

        debug!(
            "Decrypting GCM data with key of length {} and IV of length {}",
            key.len(),
            iv.len()
        );
        let key = aes_gcm::Key::<AesGcm<Aes256, U16>>::try_from(key)?;
        debug!("GCM key created successfully");
        let cipher = AesGcm::<Aes256, U16>::new(&key);
        debug!("GCM cipher initialized successfully");
        let nonce = Nonce::<U16>::try_from(iv)?;
        debug!("GCM nonce created successfully");

        let mut buf = ciphertext_and_tag.to_vec();

        cipher
            .decrypt_in_place(&nonce, header, &mut buf)
            .map_err(|e| report!("Failed to decrypt gcm: {}", e))?;
        debug!("GCM decryption successful");

        Ok(buf)
    }
}

impl std::fmt::Display for AppleAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Apple Account: ")?;
        match self.get_name() {
            Ok((first, last)) => write!(f, "{} {} ", first, last),
            Err(_) => Ok(()),
        }?;
        write!(f, "{} ({:?})", self.email, self.login_state)
    }
}

#[derive(Debug, Clone)]
pub struct AppToken {
    pub token: String,
    pub duration: u64,
    pub expiry: u64,
}

fn censor_email(email: &str) -> String {
    if std::env::var("DEBUG_SENSITIVE").is_ok() {
        return email.to_string();
    }
    // By character, not by byte: slicing bytes panicked on an empty local part ("@x.com")
    // and on a first or last letter that is not ASCII, and login() calls this first.
    if let Some(at_pos) = email.find('@') {
        let (local, domain) = email.split_at(at_pos);
        let mut chars = local.chars();
        let first = chars.next().map(String::from).unwrap_or_default();
        match (chars.next_back(), chars.next_back()) {
            // Three or more characters: show the first and the last.
            (Some(last), Some(_)) => format!("{}***{}{}", first, last, domain),
            _ => format!("{}***{}", first, domain),
        }
    } else {
        "***".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn censor_email_keeps_its_output_and_never_panics() {
        if std::env::var("DEBUG_SENSITIVE").is_ok() {
            return;
        }
        // Unchanged for ordinary addresses.
        assert_eq!(censor_email("jane.doe@example.com"), "j***e@example.com");
        assert_eq!(censor_email("abc@example.com"), "a***c@example.com");
        assert_eq!(censor_email("ab@example.com"), "a***@example.com");
        assert_eq!(censor_email("a@example.com"), "a***@example.com");
        assert_eq!(censor_email("no-at-sign"), "***");
        // These panicked before (byte slicing).
        assert_eq!(censor_email("@example.com"), "***@example.com");
        assert_eq!(
            censor_email("\u{44f}@example.com"),
            "\u{44f}***@example.com"
        );
        assert_eq!(
            censor_email("\u{44f}\u{43d}\u{430}@example.com"),
            "\u{44f}***\u{430}@example.com"
        );
        assert_eq!(
            censor_email("jos\u{e9}@example.com"),
            "j***\u{e9}@example.com"
        );
    }

    fn status(entries: Vec<(&str, plist::Value)>) -> Dictionary {
        let mut d = Dictionary::new();
        for (k, v) in entries {
            d.insert(k.to_string(), v);
        }
        d
    }

    #[test]
    fn hsc_409_without_au_means_code_already_pushed() {
        let s = status(vec![("hsc", plist::Value::Integer(409.into()))]);
        assert!(matches!(
            login_state_from_status(&s),
            LoginState::NeedsDevice2FAVerification
        ));
    }

    #[test]
    fn au_takes_precedence_over_hsc() {
        let s = status(vec![
            (
                "au",
                plist::Value::String("trustedDeviceSecondaryAuth".into()),
            ),
            ("hsc", plist::Value::Integer(409.into())),
        ]);
        assert!(matches!(
            login_state_from_status(&s),
            LoginState::NeedsDevice2FA
        ));
    }

    #[test]
    fn au_values_map_as_before() {
        let sms = status(vec![("au", plist::Value::String("secondaryAuth".into()))]);
        assert!(matches!(
            login_state_from_status(&sms),
            LoginState::NeedsSMS2FA
        ));
        let repair = status(vec![("au", plist::Value::String("repair".into()))]);
        assert!(matches!(
            login_state_from_status(&repair),
            LoginState::LoggedIn
        ));
        let other = status(vec![("au", plist::Value::String("somethingNew".into()))]);
        assert!(
            matches!(login_state_from_status(&other), LoginState::NeedsExtraStep(ref s) if s == "somethingNew")
        );
    }

    #[test]
    fn hsc_200_or_nothing_is_logged_in() {
        assert!(matches!(
            login_state_from_status(&status(vec![])),
            LoginState::LoggedIn
        ));
        let ok = status(vec![("hsc", plist::Value::Integer(200.into()))]);
        assert!(matches!(login_state_from_status(&ok), LoginState::LoggedIn));
    }

    #[test]
    fn resync_sim_only_for_hsc_434() {
        let sim_bytes = vec![1u8, 2, 3];
        let resp_434 = status(vec![(
            "Status",
            plist::Value::Dictionary(status(vec![
                ("hsc", plist::Value::Integer(434.into())),
                ("X-Apple-I-MD-DATA", plist::Value::Data(sim_bytes.clone())),
            ])),
        )]);
        assert_eq!(
            resync_sim(&resp_434),
            Some(BASE64_STANDARD.encode(&sim_bytes))
        );

        let resp_string = status(vec![(
            "Status",
            plist::Value::Dictionary(status(vec![
                ("hsc", plist::Value::Integer(434.into())),
                ("X-Apple-I-MD-DATA", plist::Value::String("AQID".into())),
            ])),
        )]);
        assert_eq!(resync_sim(&resp_string), Some("AQID".to_string()));

        let resp_409 = status(vec![(
            "Status",
            plist::Value::Dictionary(status(vec![("hsc", plist::Value::Integer(409.into()))])),
        )]);
        assert_eq!(resync_sim(&resp_409), None);
        assert_eq!(resync_sim(&status(vec![])), None);
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    }

    fn gs_error(code: i64) -> Dictionary {
        status(vec![(
            "Status",
            plist::Value::Dictionary(status(vec![
                ("ec", plist::Value::Integer(code.into())),
                ("em", plist::Value::String("msg".into())),
            ])),
        )])
    }

    fn gs_ok() -> Dictionary {
        status(vec![
            (
                "Status",
                plist::Value::Dictionary(status(vec![("ec", plist::Value::Integer(0.into()))])),
            ),
            ("sp", plist::Value::String("s2k".into())),
        ])
    }

    /// Replays scripted GrandSlam init replies; errors once the script runs out, so a
    /// runaway loop fails the test instead of hanging it.
    struct ScriptedInit {
        replies: Vec<Dictionary>,
        inits: usize,
        reprovisions: usize,
    }

    impl ScriptedInit {
        fn new(replies: Vec<Dictionary>) -> Self {
            Self {
                replies,
                inits: 0,
                reprovisions: 0,
            }
        }
    }

    impl InitSteps for ScriptedInit {
        async fn attempt_init(&mut self) -> Result<(Dictionary, Dictionary), Report> {
            self.inits += 1;
            if self.replies.is_empty() {
                bail!("script exhausted: init sent too many times");
            }
            Ok((self.replies.remove(0), Dictionary::new()))
        }
        async fn reprovision(&mut self) -> Result<(), Report> {
            self.reprovisions += 1;
            Ok(())
        }
    }

    fn error_code(err: &Report) -> Option<i64> {
        err.iter_reports().find_map(|r| {
            match r.downcast_current_context::<SideloadError>() {
                Some(SideloadError::AuthWithMessage(code, _)) => Some(*code),
                _ => None,
            }
        })
    }

    #[test]
    fn grandslam_minus_45061_reprovisions_a_bounded_number_of_times() {
        let mut steps = ScriptedInit::new(vec![
            gs_error(ANISETTE_NOT_PROVISIONED);
            MAX_GRANDSLAM_REPROVISIONS + 1
        ]);
        let err = rt()
            .block_on(init_with_reprovision(&mut steps))
            .expect_err("must give up");
        assert_eq!(error_code(&err), Some(ANISETTE_NOT_PROVISIONED), "{err}");
        assert_eq!(steps.inits, MAX_GRANDSLAM_REPROVISIONS + 1);
        assert_eq!(steps.reprovisions, MAX_GRANDSLAM_REPROVISIONS);
    }

    #[test]
    fn grandslam_minus_45061_once_then_success() {
        let mut steps = ScriptedInit::new(vec![gs_error(ANISETTE_NOT_PROVISIONED), gs_ok()]);
        let (response, _cpd) = rt().block_on(init_with_reprovision(&mut steps)).unwrap();
        assert_eq!(response.get("sp"), Some(&plist::Value::String("s2k".into())));
        assert_eq!(steps.inits, 2);
        assert_eq!(steps.reprovisions, 1);
    }

    #[test]
    fn other_init_errors_fail_without_reprovisioning() {
        let mut steps = ScriptedInit::new(vec![gs_error(-80045)]);
        let err = rt()
            .block_on(init_with_reprovision(&mut steps))
            .expect_err("-80045 is fatal");
        assert_eq!(error_code(&err), Some(-80045));
        assert_eq!(steps.inits, 1);
        assert_eq!(steps.reprovisions, 0);
    }

    #[derive(Debug, PartialEq)]
    enum Call {
        Login,
        Request,
        Verify,
        Sms,
    }

    struct ScriptedLogin {
        logins: Vec<LoginState>,
        calls: Vec<Call>,
        pet: bool,
    }

    impl ScriptedLogin {
        fn new(logins: Vec<LoginState>) -> Self {
            Self {
                logins,
                calls: Vec::new(),
                pet: false,
            }
        }
    }

    impl LoginSteps for ScriptedLogin {
        async fn login_again(&mut self) -> Result<LoginState, Report> {
            self.calls.push(Call::Login);
            if self.logins.is_empty() {
                bail!("script exhausted");
            }
            Ok(self.logins.remove(0))
        }
        async fn request_device_2fa(&mut self) -> Result<(), Report> {
            self.calls.push(Call::Request);
            Ok(())
        }
        async fn verify_device_2fa(&mut self) -> Result<(), Report> {
            self.calls.push(Call::Verify);
            Ok(())
        }
        async fn sms_2fa(&mut self) -> Result<(), Report> {
            self.calls.push(Call::Sms);
            Ok(())
        }
        fn has_pet(&self) -> bool {
            self.pet
        }
    }

    fn drive(steps: &mut ScriptedLogin, initial: LoginState) -> (Result<(), Report>, LoginState) {
        let mut state = initial;
        let result = rt().block_on(drive_login(steps, &mut state));
        (result, state)
    }

    #[test]
    fn pushed_code_is_verified_without_requesting_a_new_one() {
        // hsc 409: Apple already pushed the code. Requesting again would cancel it.
        let mut steps = ScriptedLogin::new(vec![LoginState::LoggedIn]);
        let (result, state) = drive(&mut steps, LoginState::NeedsDevice2FAVerification);
        result.unwrap();
        assert!(matches!(state, LoginState::LoggedIn));
        assert_eq!(steps.calls, vec![Call::Verify, Call::Login]);
    }

    #[test]
    fn trusted_device_2fa_requests_once_then_verifies() {
        let mut steps = ScriptedLogin::new(vec![LoginState::LoggedIn]);
        let (result, _) = drive(&mut steps, LoginState::NeedsDevice2FA);
        result.unwrap();
        assert_eq!(steps.calls, vec![Call::Request, Call::Verify, Call::Login]);
    }

    #[test]
    fn sms_2fa_then_login() {
        let mut steps = ScriptedLogin::new(vec![LoginState::LoggedIn]);
        let (result, _) = drive(&mut steps, LoginState::NeedsSMS2FA);
        result.unwrap();
        assert_eq!(steps.calls, vec![Call::Sms, Call::Login]);
    }

    #[test]
    fn extra_step_needs_a_pet() {
        let mut steps = ScriptedLogin::new(vec![]);
        let (result, _) = drive(&mut steps, LoginState::NeedsExtraStep("x".into()));
        assert!(result.is_err());
        let mut steps = ScriptedLogin::new(vec![]);
        steps.pet = true;
        let (result, state) = drive(&mut steps, LoginState::NeedsExtraStep("x".into()));
        result.unwrap();
        assert!(matches!(state, LoginState::LoggedIn));
    }

    #[test]
    fn login_loop_is_capped() {
        let mut steps = ScriptedLogin::new((0..20).map(|_| LoginState::NeedsLogin).collect());
        let (result, state) = drive(&mut steps, LoginState::NeedsLogin);
        let err = result.expect_err("must give up").to_string();
        assert!(err.contains("Couldn't login after 10 attempts"), "{err}");
        assert!(matches!(state, LoginState::NeedsLogin));
        assert_eq!(steps.calls.len(), MAX_LOGIN_STEPS);
    }

    #[test]
    fn other_grandslam_errors_do_not_reprovision() {
        for code in [-80045, -80046, -22406, -20209] {
            let err = SideloadError::AuthWithMessage(code, "x".into());
            assert!(!should_reprovision_after(&err, 0), "code {code}");
        }
        assert!(!should_reprovision_after(
            &SideloadError::DeveloperError(ANISETTE_NOT_PROVISIONED, "x".into()),
            0
        ));
    }

    #[test]
    fn check_grandslam_error_exposes_the_code_for_the_retry_decision() {
        let resp = status(vec![(
            "Status",
            plist::Value::Dictionary(status(vec![
                ("ec", plist::Value::Integer(ANISETTE_NOT_PROVISIONED.into())),
                ("em", plist::Value::String("not provisioned".into())),
            ])),
        )]);
        let err = resp.check_grandslam_error().expect_err("ec != 0");
        assert!(should_reprovision_after(err.current_context(), 0));
    }
}
