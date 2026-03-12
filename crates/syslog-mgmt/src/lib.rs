//! Syslog management model (RFC 5427 / RFC 9742).
//!
//! This crate implements the syslog management information base (MIB)
//! textual conventions from RFC 5427 and the YANG data model from RFC 9742.
//!
//! # Modules
//!
//! - [`convention`] — RFC 5427 §3 textual conventions and constants
//! - [`selector`] — Message selectors (which messages to act on)
//! - [`pattern`] — Regex-based pattern matching
//! - [`action`] — Action types (what to do with matching messages)
//! - [`feature`] — Feature/capability flags
//! - [`state`] — Runtime state and counters
//! - [`model`] — Top-level management configuration model
//! - [`error`] — Error types

pub mod action;
pub mod convention;
pub mod error;
pub mod feature;
pub mod model;
pub mod pattern;
pub mod selector;
pub mod state;

pub use action::{Action, ActionType, TransportProtocol};
pub use convention::{
    FACILITY_COUNT, MAX_MESSAGE_SIZE, SEVERITY_COUNT, SYSLOG_MIB_OID_PREFIX, all_facilities,
    facility_name, max_message_size, severity_name,
};
pub use error::MgmtError;
pub use feature::SyslogFeatures;
pub use model::SyslogConfig;
pub use pattern::Pattern;
pub use selector::Selector;
pub use state::{MessageCounters, SyslogState};
