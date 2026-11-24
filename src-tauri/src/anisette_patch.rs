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
//! - 2.3.4 (2026-11-23): since about 2026-11-19 gsa.apple.com answers HTTP 503 to any
//!   `X-Mme-Client-Info` containing `<macOS;` (SideStore#1745, AltStore#1875). It must say
//!   `Mac OS X`, as Apple's own frameworks do. iloader 2.4.2 went back to the 10.12.6 identity,
//!   which passes the 503 but is refused later for many accounts (-22410, -23782, 403 on the
//!   trusted phone numbers; iloader#1204, #1199, #1197). Wander uses the current identity and
//!   matching user agent that iloader#1203 / #1205 report signing in and installing end to end,
//!   including 2FA and Advanced Data Protection accounts. Anisette state provisioned under the
//!   old identity makes the first sign-in fail with -22410 (iloader#1304), so `account.rs`
//!   clears it once when this identity changes (see `IDENTITY_MARKER_FILE`).
//!
//! The override is applied with `RemoteV3AnisetteProvider::set_client_info_override`
//! (backport of nab138/isideload 20b06c7), so the server's `/v3/client_info` is never
//! fetched: sign-in no longer depends on that endpoint, exactly as upstream.

use isideload::anisette::AnisetteClientInfo;

/// A current macOS akd identity, spelled `Mac OS X` (the `macOS;` spelling gets HTTP 503).
/// Pair verified end to end in nab138/iloader#1203 and proposed in #1205.
pub const AKD_CLIENT_INFO: &str =
    "<MacBookAir10,1> <Mac OS X;27.3;26C5035r> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
/// The user agent sent with `AKD_CLIENT_INFO` in the build iloader#1203 verified end to end.
/// (SideStore#1745 found the user agent does not affect the 503; AltStore#1851 reports 503s with
/// mismatched pairs, so keep the verified pair together.)
pub const AKD_USER_AGENT: &str = "akd/1.0 CFNetwork/3896.300.31 Darwin/27.3.0";

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
    fn client_info_is_a_current_mac_os_x_identity() {
        let info = akd_client_info();
        assert_eq!(
            info.user_agent,
            "akd/1.0 CFNetwork/3896.300.31 Darwin/27.3.0"
        );
        assert_eq!(
            info.client_info,
            "<MacBookAir10,1> <Mac OS X;27.3;26C5035r> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        );
        // gsa.apple.com answers 503 to `macOS;` (since ~2026-11-19) and to `com.apple.dt.Xcode`.
        assert!(!info.client_info.contains("macOS;"));
        assert!(info.client_info.contains("<Mac OS X;"));
        assert!(!info.client_info.contains("com.apple.dt.Xcode"));
        assert!(info.client_info.contains("(com.apple.akd/1.0)"));
    }
}
