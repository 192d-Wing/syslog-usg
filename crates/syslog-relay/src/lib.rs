//! Syslog relay pipeline — filter, route, queue, and fan-out.
//!
//! The relay pipeline connects listeners to outputs through a series
//! of processing stages connected by bounded async channels.
//!
//! # Architecture
//!
//! ```text
//! [Ingress] → [Filter] → [Output 1]
//!                       → [Output 2]
//!                       → ...
//! ```
//!
//! Messages enter through a [`PipelineIngress`] channel, are optionally
//! filtered by severity, and then fanned out to all configured outputs.

pub mod alarm_filter;
pub mod alarm_state;
pub mod error;
pub mod filter;
pub mod output;
pub mod pipeline;
pub mod queue;
pub mod routing;
pub mod signing;
pub mod verification;

pub use alarm_filter::{AlarmFilter, AlarmFilterBuilder, NonAlarmPolicy};
pub use alarm_state::{AlarmEntry, AlarmKey, AlarmStateChange, AlarmStateTable};
pub use error::RelayError;
pub use filter::{MessageFilter, SeverityFilter};
pub use output::{BufferOutput, DropPolicy, FileOutput, ForwardOutput, Output};
pub use pipeline::{Pipeline, PipelineIngress, ShutdownHandle};
pub use queue::BoundedQueue;
pub use routing::{RoutingRule, RoutingTable};
pub use signing::SigningStage;
pub use verification::{VerificationResult, VerificationStage};
