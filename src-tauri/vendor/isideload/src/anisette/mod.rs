pub mod remote_v3;

use crate::SideloadError;
use crate::auth::grandslam::GrandSlam;
use plist::Dictionary;
use plist_macro::plist;
use reqwest::header::HeaderMap;
use rootcause::prelude::*;
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc, time::SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, warn};

#[derive(Deserialize, Debug, Clone)]
pub struct AnisetteClientInfo {
    pub client_info: String,
    pub user_agent: String,
}

#[derive(Debug, Clone)]
pub struct AnisetteData {
    machine_id: String,
    one_time_password: String,
    pub routing_info: String,
    _device_description: String,
    device_unique_identifier: String,
    _local_user_id: String,
    generated_at: SystemTime,
}

// Some headers don't seem to be required. I guess not including them is technically more efficient soooo
impl AnisetteData {
    pub fn get_headers(&self) -> HashMap<String, String> {
        //let dt: DateTime<Utc> = Utc::now().round_subsecs(0);

        HashMap::from_iter([
            // (
            //     "X-Apple-I-Client-Time".to_string(),
            //     dt.format("%+").to_string().replace("+00:00", "Z"),
            // ),
            // ("X-Apple-I-SRL-NO".to_string(), serial),
            // ("X-Apple-I-TimeZone".to_string(), "UTC".to_string()),
            // ("X-Apple-Locale".to_string(), "en_US".to_string()),
            // ("X-Apple-I-MD-RINFO".to_string(), self.routing_info.clone()),
            // ("X-Apple-I-MD-LU".to_string(), self.local_user_id.clone()),
            (
                "X-Mme-Device-Id".to_string(),
                self.device_unique_identifier.clone(),
            ),
            ("X-Apple-I-MD".to_string(), self.one_time_password.clone()),
            ("X-Apple-I-MD-M".to_string(), self.machine_id.clone()),
            // (
            //     "X-Mme-Client-Info".to_string(),
            //     self.device_description.clone(),
            // ),
        ])
    }

    pub fn get_header_map(&self) -> Result<HeaderMap, Report> {
        let headers_map = self.get_headers();
        let mut header_map = HeaderMap::new();

        for (key, value) in headers_map {
            header_map.insert(
                reqwest::header::HeaderName::from_bytes(key.as_bytes())?,
                reqwest::header::HeaderValue::from_str(&value)?,
            );
        }

        Ok(header_map)
    }

    pub fn get_client_provided_data(&self) -> Dictionary {
        let headers = self.get_headers();

        let mut cpd = plist!(dict {
            "bootstrap": "true",
            "icscrec": "true",
            "loc": "en_US",
            "pbe": "false",
            "prkgen": "true",
            "svct": "iCloud"
        });

        for (key, value) in headers {
            cpd.insert(key.to_string(), plist::Value::String(value));
        }

        cpd
    }

    pub fn needs_refresh(&self) -> bool {
        let elapsed = self.generated_at.elapsed();
        match elapsed {
            Ok(elapsed) => elapsed.as_secs() > 60,
            Err(_) => {
                warn!("Unable to determine anisette data age, treating as expired");
                true
            }
        }
    }
}

/// What a provider returned for a headers request (backport of nab138/isideload 8ca39b6).
#[derive(Debug, Clone)]
pub enum AnisetteDataResponse {
    /// Fresh anisette headers.
    Data(AnisetteData),
    /// No usable state loaded yet (nothing provisioned, or state not loaded from storage).
    NeedsProvisioning,
    /// The anisette server answered -45061: the stored state is not valid for it. Discard
    /// the cached state and provision from scratch.
    IncorrectlyProvisioned,
}

/// Total provider round trips allowed per `get_anisette_data` call. Worst case is
/// "load state from storage -> server says -45061 -> re-provision from scratch -> data",
/// which is three (same budget as upstream 8ca39b6).
pub const MAX_ANISETTE_ATTEMPTS: usize = 3;

#[async_trait::async_trait]
pub trait AnisetteProvider {
    async fn get_anisette_data(&self) -> Result<AnisetteDataResponse, Report>;

    /// Ask the server for corrected headers after GrandSlam demanded a resync
    /// (hsc 434, nab138/isideload ac8976d). `sim` is the base64 `X-Apple-I-MD-DATA`.
    async fn resync(&self, _sim: &str) -> Result<AnisetteDataResponse, Report> {
        Err(report!("anisette resync not supported by this provider"))
    }

    async fn get_client_info(&mut self) -> Result<AnisetteClientInfo, Report>;

    /// Load or create provisioning state. `force_reset` discards any cached/stored state
    /// first and provisions from scratch.
    async fn provision(&mut self, gs: Arc<GrandSlam>, force_reset: bool) -> Result<(), Report>;
}

#[derive(Clone)]
pub struct AnisetteDataGenerator {
    provider: Arc<RwLock<dyn AnisetteProvider + Send + Sync>>,
    data: Option<Arc<AnisetteData>>,
}

impl AnisetteDataGenerator {
    pub fn new(provider: Arc<RwLock<dyn AnisetteProvider + Send + Sync>>) -> Self {
        AnisetteDataGenerator {
            provider,
            data: None,
        }
    }

    pub async fn get_anisette_data(
        &mut self,
        gs: Arc<GrandSlam>,
    ) -> Result<Arc<AnisetteData>, Report> {
        if let Some(data) = &self.data
            && !data.needs_refresh()
        {
            return Ok(data.clone());
        }

        let data = self
            .get_data_or_provision(&gs, MAX_ANISETTE_ATTEMPTS)
            .await?;
        let arc_data = Arc::new(data);
        self.data = Some(arc_data.clone());
        Ok(arc_data)
    }

    async fn get_data_or_provision(
        &mut self,
        gs: &Arc<GrandSlam>,
        max_attempts: usize,
    ) -> Result<AnisetteData, Report> {
        for attempt in 1..=max_attempts {
            // trying to avoid locking as write unless necessary to promote concurrency
            let provider = self.provider.read().await;
            let response = provider.get_anisette_data().await?;
            drop(provider);

            let force_reset = match response {
                AnisetteDataResponse::Data(data) => return Ok(data),
                AnisetteDataResponse::NeedsProvisioning => false,
                AnisetteDataResponse::IncorrectlyProvisioned => true,
            };
            debug!(
                "Anisette attempt {}/{}: provisioning (force_reset = {})",
                attempt, max_attempts, force_reset
            );
            let mut provider_write = self.provider.write().await;
            provider_write.provision(gs.clone(), force_reset).await?;
        }
        bail!(SideloadError::AnisetteProvisioningExhausted(max_attempts))
    }

    /// Throw away cached anisette (in memory and on disk) and provision from scratch. Used
    /// when GrandSlam itself answers -45061.
    pub async fn force_reprovision(&mut self, gs: Arc<GrandSlam>) -> Result<(), Report> {
        self.data = None;
        let mut provider = self.provider.write().await;
        provider.provision(gs, true).await
    }

    pub async fn get_client_info(&self) -> Result<AnisetteClientInfo, Report> {
        let mut provider = self.provider.write().await;
        provider.get_client_info().await
    }

    /// Perform a login anisette resync with the server, returning corrected data.
    pub async fn resync(&mut self, sim: &str) -> Result<Arc<AnisetteData>, Report> {
        let provider = self.provider.read().await;
        let data = match provider.resync(sim).await? {
            AnisetteDataResponse::Data(data) => data,
            _ => bail!("Anisette provider failed to provide data for resync, needs provisioning"),
        };
        drop(provider);
        let arc_data = Arc::new(data);
        self.data = Some(arc_data.clone());
        Ok(arc_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn sample_data() -> AnisetteData {
        AnisetteData {
            machine_id: "m".into(),
            one_time_password: "otp".into(),
            routing_info: "17106176".into(),
            _device_description: "desc".into(),
            device_unique_identifier: "id".into(),
            _local_user_id: "lu".into(),
            generated_at: SystemTime::now(),
        }
    }

    /// Replays a scripted sequence of responses and records every call.
    struct ScriptedProvider {
        responses: Mutex<Vec<AnisetteDataResponse>>,
        data_calls: Arc<Mutex<usize>>,
        provisions: Arc<Mutex<Vec<bool>>>,
    }

    #[async_trait::async_trait]
    impl AnisetteProvider for ScriptedProvider {
        async fn get_anisette_data(&self) -> Result<AnisetteDataResponse, Report> {
            *self.data_calls.lock().unwrap() += 1;
            let mut r = self.responses.lock().unwrap();
            if r.is_empty() {
                bail!("script exhausted");
            }
            Ok(r.remove(0))
        }
        async fn get_client_info(&mut self) -> Result<AnisetteClientInfo, Report> {
            Ok(AnisetteClientInfo {
                client_info: "ci".into(),
                user_agent: "ua".into(),
            })
        }
        async fn provision(
            &mut self,
            _gs: Arc<GrandSlam>,
            force_reset: bool,
        ) -> Result<(), Report> {
            self.provisions.lock().unwrap().push(force_reset);
            Ok(())
        }
    }

    struct Harness {
        generator: AnisetteDataGenerator,
        data_calls: Arc<Mutex<usize>>,
        provisions: Arc<Mutex<Vec<bool>>>,
        rt: tokio::runtime::Runtime,
    }

    impl Harness {
        fn new(script: Vec<AnisetteDataResponse>) -> Self {
            let data_calls = Arc::new(Mutex::new(0));
            let provisions = Arc::new(Mutex::new(Vec::new()));
            let provider = ScriptedProvider {
                responses: Mutex::new(script),
                data_calls: data_calls.clone(),
                provisions: provisions.clone(),
            };
            Harness {
                generator: AnisetteDataGenerator::new(Arc::new(RwLock::new(provider))),
                data_calls,
                provisions,
                rt: tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap(),
            }
        }

        fn get(&mut self) -> Result<Arc<AnisetteData>, Report> {
            self.rt.block_on(
                self.generator
                    .get_anisette_data(Arc::new(GrandSlam::test_dummy())),
            )
        }

        fn force_reprovision(&mut self) -> Result<(), Report> {
            self.rt.block_on(
                self.generator
                    .force_reprovision(Arc::new(GrandSlam::test_dummy())),
            )
        }

        fn data_calls(&self) -> usize {
            *self.data_calls.lock().unwrap()
        }

        fn provisions(&self) -> Vec<bool> {
            self.provisions.lock().unwrap().clone()
        }
    }

    fn run(script: Vec<AnisetteDataResponse>) -> (Result<Arc<AnisetteData>, Report>, Vec<bool>) {
        let mut h = Harness::new(script);
        let result = h.get();
        (result, h.provisions())
    }

    #[test]
    fn data_on_first_try_needs_no_provisioning() {
        let (result, provisions) = run(vec![AnisetteDataResponse::Data(sample_data())]);
        assert!(result.is_ok());
        assert!(provisions.is_empty());
    }

    #[test]
    fn needs_provisioning_provisions_without_reset() {
        let (result, provisions) = run(vec![
            AnisetteDataResponse::NeedsProvisioning,
            AnisetteDataResponse::Data(sample_data()),
        ]);
        assert!(result.is_ok());
        assert_eq!(provisions, vec![false]);
    }

    #[test]
    fn minus_45061_forces_a_fresh_provision_then_succeeds() {
        // Worst case from upstream: load from storage, server says -45061, start over.
        let (result, provisions) = run(vec![
            AnisetteDataResponse::NeedsProvisioning,
            AnisetteDataResponse::IncorrectlyProvisioned,
            AnisetteDataResponse::Data(sample_data()),
        ]);
        assert!(result.is_ok());
        assert_eq!(provisions, vec![false, true]);
    }

    #[test]
    fn persistent_minus_45061_gives_up_after_the_attempt_budget() {
        let (result, provisions) = run(vec![
            AnisetteDataResponse::IncorrectlyProvisioned,
            AnisetteDataResponse::IncorrectlyProvisioned,
            AnisetteDataResponse::IncorrectlyProvisioned,
            // Never reached: the budget is spent first.
            AnisetteDataResponse::Data(sample_data()),
        ]);
        let err = result.expect_err("must give up");
        assert!(
            matches!(
                err.downcast_current_context::<SideloadError>(),
                Some(SideloadError::AnisetteProvisioningExhausted(MAX_ANISETTE_ATTEMPTS))
            ),
            "{err}"
        );
        assert_eq!(provisions, vec![true; MAX_ANISETTE_ATTEMPTS]);
    }

    #[test]
    fn cached_data_is_reused_while_fresh() {
        let mut h = Harness::new(vec![AnisetteDataResponse::Data(sample_data())]);
        h.get().unwrap();
        h.get().unwrap();
        assert_eq!(h.data_calls(), 1);
    }

    #[test]
    fn force_reprovision_drops_the_cached_data() {
        // Without clearing the cache, the GrandSlam -45061 retry would resend the same
        // headers (they count as fresh for 60 s) and both re-provisions would be wasted.
        let mut h = Harness::new(vec![
            AnisetteDataResponse::Data(sample_data()),
            AnisetteDataResponse::Data(sample_data()),
        ]);
        h.get().unwrap();
        h.force_reprovision().unwrap();
        h.get().unwrap();
        assert_eq!(h.data_calls(), 2);
        assert_eq!(h.provisions(), vec![true]);
    }
}
