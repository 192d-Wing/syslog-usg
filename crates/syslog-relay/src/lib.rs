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

pub mod error;
pub mod filter;
pub mod output;
pub mod pipeline;
pub mod queue;

pub use error::RelayError;
pub use filter::SeverityFilter;
pub use output::{DropPolicy, ForwardOutput, Output};
pub use pipeline::{Pipeline, PipelineIngress, ShutdownHandle};
pub use queue::BoundedQueue;
