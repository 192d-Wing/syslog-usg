//! Parse mode configuration.

/// Controls how strictly the parser validates input.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParseMode {
    /// Strict validation per RFC 5424. Rejects any non-conformant input.
    Strict,
    /// Lenient parsing that attempts best-effort extraction from
    /// malformed or non-standard messages.
    #[default]
    Lenient,
}
