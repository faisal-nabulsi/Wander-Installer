//! Apple's GrandSlam edge began returning HTTP 503 for any request whose
//! `X-Mme-Client-Info` header names `com.apple.dt.Xcode` (started ~2026-09-10).
//! Every public v3 anisette server still serves that blocked string from
//! `/v3/client_info`, and isideload 0.2.22 forwards whatever the server says
//! straight into the GrandSlam headers -- so sign-in 503s on every server.
//!
//! This wrapper delegates everything to the real provider but reports the
//! client as `akd`, the daemon that actually performs these requests on macOS.
//! Upstream isideload made the same change on its `apple-codesign-quick` branch.

use std::sync::Arc;

use isideload::{
    anisette::{AnisetteClientInfo, AnisetteData, AnisetteProvider},
    auth::grandslam::GrandSlam,
};
use rootcause::prelude::*;

/// The client identifier Apple's GSA edge still accepts.
const AKD_CLIENT_INFO: &str =
    "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
const AKD_USER_AGENT: &str = "akd/1.0 CFNetwork/808.1.4";

pub struct AkdClientInfoProvider<P: AnisetteProvider>(pub P);

#[async_trait::async_trait]
impl<P: AnisetteProvider + Send + Sync> AnisetteProvider for AkdClientInfoProvider<P> {
    async fn get_anisette_data(&self) -> Result<AnisetteData, Report> {
        self.0.get_anisette_data().await
    }

    async fn get_client_info(&mut self) -> Result<AnisetteClientInfo, Report> {
        Ok(AnisetteClientInfo {
            client_info: AKD_CLIENT_INFO.to_string(),
            user_agent: AKD_USER_AGENT.to_string(),
        })
    }

    fn needs_provisioning(&self) -> Result<bool, Report> {
        self.0.needs_provisioning()
    }

    async fn provision(&mut self, gs: Arc<GrandSlam>) -> Result<(), Report> {
        self.0.provision(gs).await
    }
}
