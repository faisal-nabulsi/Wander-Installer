//! The client info Wander reports to Apple's GrandSlam sign-in service, instead of whatever
//! the anisette server returns from `/v3/client_info`.
//!
//! History:
//! - 2.3.1 (~2026-09-10): Apple's edge began answering HTTP 503 to any request whose
//!   `X-Mme-Client-Info` names `com.apple.dt.Xcode`, which the public anisette servers served
//!   at the time. Wander started reporting the client as `akd`, the macOS daemon that really
//!   makes these requests, as upstream isideload did (232c7f3).
//! - 2.3.3 (October 2026): Apple now refuses anisette from Android-ADI-backed servers when the
//!   client claims to be a Mac (-80045, -80046), so the presets moved to Mac-ADI-backed servers.
//!   Those servers report a Mac client info themselves
//!   (`<MacBookPro13,3> <Mac OS X;10.12.6;16G29> ... (com.apple.akd/1.0)`), but iloader 2.4.1
//!   still overrides it with the Mac15,7 string below ("just temporary while waiting for the
//!   anisette servers to start reporting this"), so Wander does the same.
//!
//! The override is applied with `RemoteV3AnisetteProvider::set_client_info_override`
//! (backport of nab138/isideload 20b06c7), so the server's `/v3/client_info` is never
//! fetched: sign-in no longer depends on that endpoint, exactly as upstream.

use isideload::anisette::AnisetteClientInfo;

/// The client identifier upstream (isideload 232c7f3, iloader 2.4.1) sends.
pub const AKD_CLIENT_INFO: &str =
    "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
/// Matches iloader 2.4.1 (nab138/iloader d319ce7). The Mac servers report the same CFNetwork
/// build plus a `Darwin/16.7.0` suffix.
pub const AKD_USER_AGENT: &str = "akd/1.0 CFNetwork/811.5.4";

/// The client info to pass to `set_client_info_override`.
pub fn akd_client_info() -> AnisetteClientInfo {
    AnisetteClientInfo {
        client_info: AKD_CLIENT_INFO.to_string(),
        user_agent: AKD_USER_AGENT.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_info_matches_upstream_2_4_1() {
        let info = akd_client_info();
        assert_eq!(info.user_agent, "akd/1.0 CFNetwork/811.5.4");
        assert_eq!(
            info.client_info,
            "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        );
        assert!(!info.client_info.contains("com.apple.dt.Xcode"));
    }
}
