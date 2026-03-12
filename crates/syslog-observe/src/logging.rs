//! Structured JSON logging via `tracing-subscriber`.
//!
//! Initialises a global tracing subscriber that writes structured JSON to
//! stdout with an env-filter controlled by the given log level.
//!
//! Returns a [`LogReloadHandle`] that allows changing the log filter at
//! runtime (e.g. on SIGHUP config reload).

use tracing_subscriber::{
    EnvFilter, Registry, fmt, layer::SubscriberExt, reload, util::SubscriberInitExt,
};

/// Error returned when logging initialization fails.
#[derive(Debug, thiserror::Error)]
pub enum LoggingInitError {
    /// The supplied filter directive was invalid.
    #[error("invalid log filter directive: {0}")]
    InvalidFilter(#[from] tracing_subscriber::filter::ParseError),

    /// The global subscriber has already been set.
    #[error("global tracing subscriber already set: {0}")]
    SetGlobal(#[from] tracing_subscriber::util::TryInitError),

    /// The reload handle rejected the new filter.
    #[error("failed to reload log filter: {0}")]
    Reload(#[from] reload::Error),
}

/// Handle for dynamically reloading the log filter at runtime.
///
/// Obtained from [`init_logging`] and typically held by the main event loop
/// so that a SIGHUP handler can update the log level without restarting.
#[derive(Clone)]
pub struct LogReloadHandle {
    inner: reload::Handle<EnvFilter, Registry>,
}

impl LogReloadHandle {
    /// Replace the active log filter with a new level/directive string.
    ///
    /// # Errors
    ///
    /// Returns [`LoggingInitError`] if the directive is invalid or the
    /// reload fails.
    pub fn reload_level(&self, level: &str) -> Result<(), LoggingInitError> {
        let filter = EnvFilter::try_new(level)?;
        self.inner.reload(filter)?;
        Ok(())
    }
}

/// Initialise structured JSON logging with the given filter `level`.
///
/// `level` is any valid `tracing` env-filter directive, e.g. `"info"`,
/// `"syslog_relay=debug,warn"`, or an `RUST_LOG`-style string.
///
/// Returns a [`LogReloadHandle`] that can be used to change the filter
/// at runtime.
///
/// # Errors
///
/// Returns [`LoggingInitError`] if the filter string is invalid or the
/// global subscriber has already been set.
pub fn init_logging(level: &str) -> Result<LogReloadHandle, LoggingInitError> {
    let filter = EnvFilter::try_new(level)?;
    let (filter_layer, reload_handle) = reload::Layer::new(filter);

    let json_layer = fmt::layer()
        .json()
        .with_target(true)
        .with_timer(fmt::time::SystemTime);

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(json_layer)
        .try_init()?;

    Ok(LogReloadHandle {
        inner: reload_handle,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_filter_returns_error() {
        // A completely empty string is valid ("" means default), so use a
        // known-bad directive.
        let result = init_logging("not_a_real_level[invalid");
        assert!(result.is_err());
    }
}
