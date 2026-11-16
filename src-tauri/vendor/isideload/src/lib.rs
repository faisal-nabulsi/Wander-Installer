use idevice::IdeviceError;
use rootcause::{
    hooks::{Hooks, context_formatter::ContextFormatterHook},
    prelude::*,
};

pub mod anisette;
pub mod auth;
pub mod dev;
pub mod sideload;
pub mod util;

#[derive(Debug, thiserror::Error)]
pub enum SideloadError {
    #[error("Auth error {0}: {1}")]
    AuthWithMessage(i64, String),

    #[error("Plist parse error: {0}")]
    PlistParseError(String),

    #[error("Failed to get anisette data, anisette not provisioned")]
    AnisetteNotProvisioned,

    /// Wander 2.3.3: the anisette server kept answering -45061 after every re-provisioning
    /// attempt (`AnisetteDataGenerator`, backport of nab138/isideload 8ca39b6). A typed variant
    /// so the app can classify it without matching on message text.
    #[error(
        "Max anisette provisioning attempts reached ({0}): the anisette server keeps reporting -45061 (incorrectly provisioned)"
    )]
    AnisetteProvisioningExhausted(usize),

    #[error("Developer error {0}: {1}")]
    DeveloperError(i64, String),

    #[error("Invalid bundle: {0}")]
    InvalidBundle(String),

    #[error("{0}")]
    IdeviceError(#[from] IdeviceError),
}

// The default reqwest error formatter sucks and provides no info
struct ReqwestErrorFormatter;

impl ContextFormatterHook<reqwest::Error> for ReqwestErrorFormatter {
    fn display(
        &self,
        report: rootcause::ReportRef<'_, reqwest::Error, markers::Uncloneable, markers::Local>,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        writeln!(f, "{}", report.format_current_context_unhooked())?;
        let mut source = report.current_context_error_source();
        while let Some(s) = source {
            writeln!(f, "Caused by: {:?}", s)?;
            source = s.source();
        }
        Ok(())
    }
}

pub fn init() -> Result<(), Report> {
    Hooks::new()
        .context_formatter::<reqwest::Error, _>(ReqwestErrorFormatter)
        .install()
        .context("Failed to install error reporting hooks")?;
    Ok(())
}
