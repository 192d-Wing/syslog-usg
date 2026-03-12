//! Observability infrastructure — metrics, tracing, and health endpoints.
//!
//! Provides Prometheus metrics exposition, structured JSON logging,
//! and HTTP health/readiness/liveness endpoints.

pub mod health;
pub mod logging;
pub mod metrics;

// Re-export the primary entry points for convenience.
pub use health::{HealthState, health_router};
pub use logging::init_logging;
pub use metrics::init_metrics;
