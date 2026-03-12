//! Structured JSON logging via `tracing-subscriber`.
//!
//! Initialises a global tracing subscriber that writes structured JSON to
//! stdout with an env-filter controlled by the given log level.

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Error returned when logging initialization fails.
#[derive(Debug, thiserror::Error)]
pub enum LoggingInitError {
    /// The supplied filter directive was invalid.
    #[error("invalid log filter directive: {0}")]
    InvalidFilter(#[from] tracing_subscriber::filter::ParseError),

    /// The global subscriber has already been set.
    #[error("global tracing subscriber already set: {0}")]
    SetGlobal(#[from] tracing_subscriber::util::TryInitError),
}

/// Initialise structured JSON logging with the given filter `level`.
///
/// `level` is any valid `tracing` env-filter directive, e.g. `"info"`,
/// `"syslog_relay=debug,warn"`, or an `RUST_LOG`-style string.
///
/// # Errors
///
/// Returns [`LoggingInitError`] if the filter string is invalid or the
/// global subscriber has already been set.
pub fn init_logging(level: &str) -> Result<(), LoggingInitError> {
    let filter = EnvFilter::try_new(level)?;

    let json_layer = fmt::layer()
        .json()
        .with_target(true)
        .with_timer(fmt::time::SystemTime);

    tracing_subscriber::registry()
        .with(filter)
        .with(json_layer)
        .try_init()?;

    Ok(())
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
