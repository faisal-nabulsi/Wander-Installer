mod state;

use std::sync::Arc;
use std::time::SystemTime;

use base64::prelude::*;
use plist_macro::plist;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use rootcause::option_ext::OptionExt;
use rootcause::prelude::*;
use serde::Deserialize;
use tokio::time::{Duration, timeout};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::anisette::remote_v3::state::AnisetteState;
use crate::anisette::{AnisetteClientInfo, AnisetteData, AnisetteDataResponse, AnisetteProvider};
use crate::auth::grandslam::GrandSlam;
use crate::util::plist::PlistDataExtract;
use crate::util::storage::{SideloadingStorage, new_storage};
use futures_util::{SinkExt, StreamExt};

pub const DEFAULT_ANISETTE_V3_URL: &str = "https://mac-ani.jkcoxson.com";
/// Storage key of the provisioned anisette state (an XML plist).
pub const ANISETTE_STATE_KEY: &str = "anisette_state";
/// Storage key of the server URL `ANISETTE_STATE_KEY` was provisioned against.
pub const ANISETTE_STATE_URL_KEY: &str = "anisette_state_url";

pub struct RemoteV3AnisetteProvider {
    pub state: Option<AnisetteState>,
    url: String,
    storage: Box<dyn SideloadingStorage>,
    serial_number: String,
    client_info: Option<AnisetteClientInfo>,
    /// Backport of nab138/isideload 20b06c7: when set, this is reported as the client info
    /// and the server's /v3/client_info is never fetched.
    client_info_override: Option<AnisetteClientInfo>,
    client: reqwest::Client,
}

impl RemoteV3AnisetteProvider {
    /// Create a new RemoteV3AnisetteProvider with the given URL and config path
    ///
    /// # Arguments
    /// - `url`: The URL of the remote anisette service
    /// - `storage`: The storage backend for anisette data
    /// - `serial_number`: The serial number of the device
    pub fn new(
        url: &str,
        storage: Box<dyn SideloadingStorage>,
        serial_number: String,
    ) -> Result<Self, Report> {
        Ok(Self {
            state: None,
            url: url.to_string(),
            storage,
            serial_number,
            client_info: None,
            client_info_override: None,
            client: reqwest::ClientBuilder::new()
                .build()
                .context("Failed to build HTTP client")?,
        })
    }

    pub fn default() -> Result<Self, Report> {
        Self::new(
            DEFAULT_ANISETTE_V3_URL,
            Box::new(new_storage()),
            "0".to_string(),
        )
    }

    pub fn set_url(mut self, url: &str) -> RemoteV3AnisetteProvider {
        self.url = url.to_string();
        self
    }

    pub fn set_storage(mut self, storage: Box<dyn SideloadingStorage>) -> RemoteV3AnisetteProvider {
        self.storage = storage;
        self
    }

    pub fn set_serial_number(mut self, serial_number: String) -> RemoteV3AnisetteProvider {
        self.serial_number = serial_number;
        self
    }

    /// Report this client info instead of the server's /v3/client_info (nab138/isideload
    /// 20b06c7). With an override set, the server's client_info endpoint is never contacted.
    pub fn set_client_info_override(
        mut self,
        client_info_override: Option<AnisetteClientInfo>,
    ) -> RemoteV3AnisetteProvider {
        self.client_info_override = client_info_override;
        self
    }

    /// The client info headers are built from: the override, else what the server reported.
    fn effective_client_info(&self) -> Option<&AnisetteClientInfo> {
        self.client_info_override
            .as_ref()
            .or(self.client_info.as_ref())
    }
}

#[async_trait::async_trait]
impl AnisetteProvider for RemoteV3AnisetteProvider {
    async fn get_anisette_data(&self) -> Result<AnisetteDataResponse, Report> {
        self.fetch_headers(None).await
    }

    async fn resync(&self, sim: &str) -> Result<AnisetteDataResponse, Report> {
        self.fetch_headers(Some(sim)).await
    }

    async fn get_client_info(&mut self) -> Result<AnisetteClientInfo, Report> {
        if let Some(client_info_override) = self.client_info_override.as_ref() {
            return Ok(client_info_override.clone());
        }
        match self.client_info {
            Some(ref info) => Ok(info.clone()),
            None => {
                let resp = self
                    .client
                    .get(format!("{}/v3/client_info", self.url))
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<AnisetteClientInfo>()
                    .await?;

                self.client_info = Some(resp.clone());
                Ok(resp)
            }
        }
    }

    async fn provision(&mut self, gs: Arc<GrandSlam>, force_reset: bool) -> Result<(), Report> {
        self.get_client_info().await?;
        self.get_state(gs, force_reset).await?;
        Ok(())
    }
}

/// Server identity used to decide whether stored state belongs to the configured server:
/// lowercased, scheme kept, trailing slashes dropped.
pub fn normalize_anisette_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_ascii_lowercase()
}

/// Stored anisette state is only reused when it was provisioned against the server that is
/// configured now. State from before 2.3.3 has no marker, so it was provisioned against an
/// old (Android-backed) server and must not be reused either.
pub fn stored_state_matches_server(stored_url: Option<&str>, current_url: &str) -> bool {
    match stored_url {
        Some(stored) if !stored.trim().is_empty() => {
            normalize_anisette_url(stored) == normalize_anisette_url(current_url)
        }
        _ => false,
    }
}

/// The anisette-v3 server reports ADI error -45061 when the identifier/adi_pb it was given
/// is not provisioned for it (for example after switching servers).
pub fn is_incorrectly_provisioned_message(message: &str) -> bool {
    message.contains("-45061")
}

/// Turn a /v3/get_headers reply into what the generator acts on. A -45061 from the server
/// means "re-provision", not a failed sign-in (nab138/isideload 8ca39b6).
fn headers_to_response(
    headers: AnisetteHeaders,
    state: &AnisetteState,
    client_info: &AnisetteClientInfo,
) -> Result<AnisetteDataResponse, Report> {
    match headers {
        AnisetteHeaders::Headers {
            machine_id,
            one_time_password,
            routing_info,
        } => Ok(AnisetteDataResponse::Data(AnisetteData {
            machine_id,
            one_time_password,
            routing_info,
            _device_description: client_info.client_info.clone(),
            device_unique_identifier: state.get_device_id(),
            _local_user_id: hex::encode(state.get_md_lu()),
            generated_at: SystemTime::now(),
        })),
        AnisetteHeaders::GetHeadersError { message } => {
            if is_incorrectly_provisioned_message(&message) {
                warn!("Anisette server says this state is not provisioned (-45061)");
                return Ok(AnisetteDataResponse::IncorrectlyProvisioned);
            }
            Err(report!("Failed to get anisette headers").attach(message))
        }
    }
}

/// Pick the state to provision or use: a fresh one on `force_reset`; the state already in
/// memory if there is one; otherwise the stored state, but only when its server marker
/// matches `url` (else a fresh one).
fn select_state(
    current: Option<AnisetteState>,
    storage: &dyn SideloadingStorage,
    url: &str,
    force_reset: bool,
) -> AnisetteState {
    if force_reset {
        warn!("Discarding cached anisette state and provisioning again");
        return AnisetteState::new();
    }
    if let Some(state) = current {
        return state;
    }
    let stored_url = storage.retrieve(ANISETTE_STATE_URL_KEY).ok().flatten();
    if !stored_state_matches_server(stored_url.as_deref(), url) {
        info!("Anisette server changed (or state predates the server marker), provisioning again");
        return AnisetteState::new();
    }
    match storage.retrieve_data(ANISETTE_STATE_KEY) {
        Ok(Some(bytes)) => match plist::from_bytes(&bytes) {
            Ok(state) => {
                info!("Loaded existing anisette state");
                state
            }
            Err(_) => {
                warn!("Failed to parse existing anisette state, starting fresh");
                AnisetteState::new()
            }
        },
        _ => {
            info!("No existing anisette state found");
            AnisetteState::new()
        }
    }
}

/// Store the state together with the marker of the server it was provisioned against.
fn save_state(
    storage: &dyn SideloadingStorage,
    url: &str,
    state: &AnisetteState,
) -> Result<(), Report> {
    let mut writer = std::io::BufWriter::new(Vec::new());
    plist::to_writer_xml(&mut writer, state)?;
    storage.store_data(ANISETTE_STATE_KEY, &writer.into_inner()?)?;
    storage.store(ANISETTE_STATE_URL_KEY, &normalize_anisette_url(url))?;
    Ok(())
}

impl RemoteV3AnisetteProvider {
    async fn fetch_headers(&self, sim: Option<&str>) -> Result<AnisetteDataResponse, Report> {
        let Some(state) = self.state.as_ref() else {
            return Ok(AnisetteDataResponse::NeedsProvisioning);
        };
        let Some(adi_pb) = state.adi_pb.as_ref() else {
            return Ok(AnisetteDataResponse::NeedsProvisioning);
        };
        let Some(client_info) = self.effective_client_info() else {
            return Ok(AnisetteDataResponse::NeedsProvisioning);
        };

        let mut body = serde_json::json!({
            "identifier": BASE64_STANDARD.encode(state.keychain_identifier),
            "adi_pb": BASE64_STANDARD.encode(adi_pb),
        });
        if let Some(sim) = sim {
            body["sim"] = serde_json::Value::String(sim.to_string());
            body["device_id"] = serde_json::Value::String(state.get_device_id());
            body["md_lu"] = serde_json::Value::String(hex::encode(state.get_md_lu()));
        }

        let headers = self
            .client
            .post(format!("{}/v3/get_headers", self.url))
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await?
            .error_for_status()?
            .json::<AnisetteHeaders>()
            .await?;

        headers_to_response(headers, state, client_info)
    }

    async fn get_state(
        &mut self,
        gs: Arc<GrandSlam>,
        force_reset: bool,
    ) -> Result<&mut AnisetteState, Report> {
        let current = self.state.take();
        self.state = Some(select_state(
            current,
            self.storage.as_ref(),
            &self.url,
            force_reset,
        ));

        let state = self.state.as_mut().ok_or_report()?;
        if !state.is_provisioned() {
            info!("Provisioning required...");
            Self::provision(state, gs, &self.url)
                .await
                .context("Failed to provision")?;
        }
        save_state(self.storage.as_ref(), &self.url, state)?;

        Ok(state)
    }

    async fn provisioning_headers(state: &AnisetteState) -> Result<HeaderMap, Report> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Apple-I-MD-LU",
            HeaderValue::from_str(&hex::encode(state.get_md_lu()))?,
        );
        // headers.insert(
        //     "X-Apple-I-Client-Time",
        //     HeaderValue::from_str(
        //         &Utc::now()
        //             .round_subsecs(0)
        //             .format("%+")
        //             .to_string()
        //             .replace("+00:00", "Z"),
        //     )?,
        // );
        // headers.insert("X-Apple-I-TimeZone", HeaderValue::from_static("UTC"));
        // headers.insert("X-Apple-Locale", HeaderValue::from_static("en_US"));
        headers.insert(
            "X-Mme-Device-Id",
            HeaderValue::from_str(&state.get_device_id())?,
        );

        Ok(headers)
    }
    async fn provision(
        state: &mut AnisetteState,
        gs: Arc<GrandSlam>,
        url: &str,
    ) -> Result<(), Report> {
        let start_provisioning = gs.get_url("midStartProvisioning")?;
        let end_provisioning = gs.get_url("midFinishProvisioning")?;

        let websocket_url = format!("{}/v3/provisioning_session", url)
            .replace("https://", "wss://")
            .replace("http://", "ws://");

        debug!("Starting provisioning at {}", websocket_url);
        let (mut ws_stream, _) = timeout(
            Duration::from_secs(30),
            tokio_tungstenite::connect_async(&websocket_url),
        )
        .await
        .map_err(|_| {
            report!("Timed out connecting to provisioning socket. Try a different anisette server.")
        })
        .context("Failed to connect to provisioning socket")?
        .context("Failed to connect to provisioning socket")?;

        debug!("Connected to provisioning socket");

        loop {
            let Some(msg) = ws_stream.next().await else {
                continue;
            };
            let msg = msg.context("Failed to read anisette provisioning socket message")?;
            if msg.is_close() {
                bail!("Anisette provisioning socket closed unexpectedly");
            }
            let msg = msg
                .into_text()
                .context("Failed to parse provisioning message")?;

            debug!("Received provisioning message: {}", msg);
            let provision_msg: ProvisioningMessage =
                serde_json::from_str(&msg).context("Unknown provisioning message")?;

            match provision_msg {
                ProvisioningMessage::GiveIdentifier => {
                    ws_stream
                        .send(Message::Text(
                            serde_json::json!({
                                "identifier": BASE64_STANDARD.encode(state.keychain_identifier),
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .context("Failed to send identifier")?;
                }
                ProvisioningMessage::GiveStartProvisioningData => {
                    let body = plist!(dict {
                        "Header": {},
                        "Request": {}
                    });

                    let response = gs
                        .plist_request(
                            &start_provisioning,
                            &body,
                            Some(Self::provisioning_headers(state).await?),
                        )
                        .await
                        .context("Failed to send start provisioning request")?;

                    let spim = response
                        .get_str("spim")
                        .context("Start provisioning response missing spim")?;

                    ws_stream
                        .send(Message::Text(
                            serde_json::json!({
                                "spim": spim,
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .context("Failed to send start provisioning data")?;
                }
                ProvisioningMessage::GiveEndProvisioningData { cpim } => {
                    let body = plist!(dict {
                        "Header": {},
                        "Request": {
                            "cpim": cpim,
                        }
                    });

                    let response = gs
                        .plist_request(
                            &end_provisioning,
                            &body,
                            Some(Self::provisioning_headers(state).await?),
                        )
                        .await
                        .context("Failed to send end provisioning request")?;

                    ws_stream
                        .send(Message::Text(
                            serde_json::json!({
                                "ptm": response
                                    .get_str("ptm")
                                    .context("End provisioning response missing ptm")?,
                                "tk": response
                                    .get_str("tk")
                                    .context("End provisioning response missing tk")?,
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .context("Failed to send start provisioning data")?;
                }
                ProvisioningMessage::ProvisioningSuccess { adi_pb } => {
                    state.adi_pb = Some(BASE64_STANDARD.decode(adi_pb)?);
                    ws_stream.close(None).await?;
                    info!("Provisioning successful");
                    break;
                }
                ProvisioningMessage::Timeout => bail!("Anisette provisioning timed out"),
                ProvisioningMessage::InvalidIdentifier => {
                    bail!("Anisette provisioning failed: invalid identifier")
                }
                ProvisioningMessage::StartProvisioningError { message } => {
                    return Err(
                        report!("Anisette provisioning failed: start provisioning error")
                            .attach(message),
                    );
                }
                ProvisioningMessage::EndProvisioningError { message } => {
                    return Err(
                        report!("Anisette provisioning failed: end provisioning error")
                            .attach(message),
                    );
                }
            }
        }

        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(tag = "result")]
enum ProvisioningMessage {
    GiveIdentifier,
    GiveStartProvisioningData,
    GiveEndProvisioningData { cpim: String },
    ProvisioningSuccess { adi_pb: String },
    Timeout,
    InvalidIdentifier,
    StartProvisioningError { message: String },
    EndProvisioningError { message: String },
}

#[derive(Deserialize)]
#[serde(tag = "result")]
enum AnisetteHeaders {
    GetHeadersError {
        message: String,
    },
    Headers {
        #[serde(rename = "X-Apple-I-MD-M")]
        machine_id: String,
        #[serde(rename = "X-Apple-I-MD")]
        one_time_password: String,
        #[serde(rename = "X-Apple-I-MD-RINFO")]
        routing_info: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::storage::InMemoryStorage;

    #[test]
    fn stored_state_is_reused_only_for_the_same_server() {
        let url = "https://mac-ani.jkcoxson.com";
        assert!(stored_state_matches_server(Some(url), url));
        assert!(stored_state_matches_server(
            Some("https://MAC-ANI.jkcoxson.com/"),
            url
        ));
        assert!(!stored_state_matches_server(
            Some("https://ani.846969.xyz"),
            url
        ));
    }

    #[test]
    fn state_without_a_server_marker_is_not_reused() {
        // Everything stored by 2.3.2 and earlier: provisioned against an Android server.
        assert!(!stored_state_matches_server(
            None,
            "https://ani.iloader.app"
        ));
        assert!(!stored_state_matches_server(
            Some(""),
            "https://ani.iloader.app"
        ));
        assert!(!stored_state_matches_server(
            Some("  "),
            "https://ani.iloader.app"
        ));
    }

    #[test]
    fn detects_minus_45061_in_server_error_message() {
        assert!(is_incorrectly_provisioned_message(
            "ADI error: -45061 (not provisioned)"
        ));
        assert!(!is_incorrectly_provisioned_message("ADI error: -45054"));
    }

    fn client_info() -> AnisetteClientInfo {
        AnisetteClientInfo {
            client_info: "ci".into(),
            user_agent: "ua".into(),
        }
    }

    fn parse(body: &str) -> AnisetteHeaders {
        serde_json::from_str(body).unwrap()
    }

    #[test]
    fn get_headers_minus_45061_maps_to_incorrectly_provisioned() {
        let state = AnisetteState::new();
        let response = headers_to_response(
            parse(r#"{"result":"GetHeadersError","message":"ADI error: -45061"}"#),
            &state,
            &client_info(),
        )
        .expect("-45061 must not be a hard error");
        assert!(matches!(
            response,
            AnisetteDataResponse::IncorrectlyProvisioned
        ));
    }

    #[test]
    fn other_get_headers_errors_stay_errors() {
        let state = AnisetteState::new();
        let result = headers_to_response(
            parse(r#"{"result":"GetHeadersError","message":"ADI error: -45054"}"#),
            &state,
            &client_info(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn headers_map_to_data_for_this_state() {
        let state = AnisetteState::new();
        let response = headers_to_response(
            parse(
                r#"{"result":"Headers","X-Apple-I-MD-M":"mid","X-Apple-I-MD":"otp","X-Apple-I-MD-RINFO":"17106176"}"#,
            ),
            &state,
            &client_info(),
        )
        .unwrap();
        let AnisetteDataResponse::Data(data) = response else {
            panic!("expected Data");
        };
        let headers = data.get_headers();
        assert_eq!(headers["X-Apple-I-MD-M"], "mid");
        assert_eq!(headers["X-Apple-I-MD"], "otp");
        assert_eq!(headers["X-Mme-Device-Id"], state.get_device_id());
        assert_eq!(data.routing_info, "17106176");
    }

    fn provisioned_state() -> AnisetteState {
        let mut state = AnisetteState::new();
        state.adi_pb = Some(vec![7, 7, 7]);
        state
    }

    #[test]
    fn saved_state_is_reloaded_for_the_same_server() {
        let storage = InMemoryStorage::new();
        let saved = provisioned_state();
        save_state(&storage, "https://MAC-ANI.jkcoxson.com/", &saved).unwrap();
        assert_eq!(
            storage.retrieve(ANISETTE_STATE_URL_KEY).unwrap().as_deref(),
            Some("https://mac-ani.jkcoxson.com")
        );

        let loaded = select_state(None, &storage, "https://mac-ani.jkcoxson.com", false);
        assert_eq!(loaded.keychain_identifier, saved.keychain_identifier);
        assert_eq!(loaded.adi_pb, saved.adi_pb);
    }

    #[test]
    fn saved_state_from_another_server_is_not_used() {
        let storage = InMemoryStorage::new();
        let saved = provisioned_state();
        save_state(&storage, "https://ani.846969.xyz", &saved).unwrap();

        let loaded = select_state(None, &storage, "https://mac-ani.jkcoxson.com", false);
        assert!(!loaded.is_provisioned());
        assert_ne!(loaded.keychain_identifier, saved.keychain_identifier);
    }

    #[test]
    fn saved_state_without_a_marker_is_not_used() {
        // What 2.3.2 left behind: the state, but no anisette_state_url.
        let storage = InMemoryStorage::new();
        let saved = provisioned_state();
        save_state(&storage, "https://mac-ani.jkcoxson.com", &saved).unwrap();
        storage.delete(ANISETTE_STATE_URL_KEY).unwrap();

        let loaded = select_state(None, &storage, "https://mac-ani.jkcoxson.com", false);
        assert!(!loaded.is_provisioned());
    }

    #[test]
    fn force_reset_discards_memory_and_storage() {
        let storage = InMemoryStorage::new();
        let saved = provisioned_state();
        save_state(&storage, "https://mac-ani.jkcoxson.com", &saved).unwrap();

        let fresh = select_state(
            Some(saved.clone()),
            &storage,
            "https://mac-ani.jkcoxson.com",
            true,
        );
        assert!(!fresh.is_provisioned());
        assert_ne!(fresh.keychain_identifier, saved.keychain_identifier);
    }

    #[test]
    fn state_in_memory_is_kept_without_force_reset() {
        let storage = InMemoryStorage::new();
        let current = provisioned_state();
        let kept = select_state(
            Some(current.clone()),
            &storage,
            "https://mac-ani.jkcoxson.com",
            false,
        );
        assert_eq!(kept.keychain_identifier, current.keychain_identifier);
        assert!(kept.is_provisioned());
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    }

    #[test]
    fn client_info_override_is_returned_without_contacting_the_server() {
        // Port 9 (discard) on localhost: any request would fail, so success proves none is made.
        let override_info = AnisetteClientInfo {
            client_info: "<Mac15,7> override".into(),
            user_agent: "akd/1.0 CFNetwork/811.5.4".into(),
        };
        let mut provider = RemoteV3AnisetteProvider::new(
            "http://127.0.0.1:9",
            Box::new(InMemoryStorage::new()),
            "0".into(),
        )
        .unwrap()
        .set_client_info_override(Some(override_info.clone()));
        let info = rt().block_on(provider.get_client_info()).unwrap();
        assert_eq!(info.client_info, override_info.client_info);
        assert_eq!(info.user_agent, override_info.user_agent);
        assert_eq!(
            provider.effective_client_info().unwrap().client_info,
            override_info.client_info
        );
    }

    #[test]
    fn without_an_override_and_without_server_info_headers_need_provisioning() {
        let mut provider = RemoteV3AnisetteProvider::new(
            "http://127.0.0.1:9",
            Box::new(InMemoryStorage::new()),
            "0".into(),
        )
        .unwrap();
        provider.state = Some(provisioned_state());
        assert!(provider.effective_client_info().is_none());
        let response = rt().block_on(provider.fetch_headers(None)).unwrap();
        assert!(matches!(response, AnisetteDataResponse::NeedsProvisioning));
    }
}
