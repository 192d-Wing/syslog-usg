//! Configuration error types.

use thiserror::Error;

/// Errors that can occur during configuration loading and validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to read the configuration file from disk.
    #[error("failed to read config file: {0}")]
    ReadFile(#[from] std::io::Error),

    /// The TOML content could not be parsed.
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    /// A semantic validation check failed.
    #[error("validation error: {0}")]
    Validation(String),

    /// A required configuration field was not provided.
    #[error("missing required field: {0}")]
    MissingField(String),

    /// A referenced environment variable is not set and has no default.
    #[error("environment variable not set: ${{{name}}}")]
    EnvVarNotSet { name: String },

    /// A field references something that does not exist in the config.
    #[error("undefined reference: {field} references unknown {kind} '{name}'")]
    UndefinedReference {
        field: String,
        kind: String,
        name: String,
    },
}
