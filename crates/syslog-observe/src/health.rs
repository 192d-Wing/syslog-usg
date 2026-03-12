//! HTTP health, readiness, and metrics endpoints.
//!
//! Exposes an [`axum::Router`] with:
//! - `GET /healthz`  — liveness probe (always 200)
//! - `GET /readyz`   — readiness probe (200 when ready, 503 otherwise)
//! - `GET /metrics`  — Prometheus scrape endpoint

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use metrics_exporter_prometheus::PrometheusHandle;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Shared state for the health/metrics router.
#[derive(Clone)]
pub struct HealthState {
    /// Prometheus handle used to render the scrape output.
    metrics_handle: PrometheusHandle,
    /// Readiness flag — when `false`, `/readyz` returns 503.
    ready: Arc<AtomicBool>,
}

impl HealthState {
    /// Create a new [`HealthState`].
    ///
    /// The readiness flag defaults to `false`; call [`HealthState::set_ready`]
    /// once the application is fully initialised.
    #[must_use]
    pub fn new(metrics_handle: PrometheusHandle) -> Self {
        Self {
            metrics_handle,
            ready: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Mark the application as ready (or not ready).
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    /// Returns `true` when the application is ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build an [`axum::Router`] with `/healthz`, `/readyz`, and `/metrics`.
pub fn health_router(state: HealthState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Liveness probe — always returns 200 OK.
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Readiness probe — returns 200 when ready, 503 otherwise.
async fn readyz(State(state): State<HealthState>) -> impl IntoResponse {
    if state.is_ready() {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

/// Prometheus metrics scrape endpoint.
async fn metrics_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let body = state.metrics_handle.render();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    /// Helper: build a test app with a fresh Prometheus handle.
    fn test_app(ready: bool) -> Router {
        // We cannot call `install_recorder` more than once globally, so we
        // build a recorder without installing it and extract a handle.
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        // We intentionally drop the recorder — we only need the handle for
        // rendering in tests.
        drop(recorder);

        let state = HealthState::new(handle);
        state.set_ready(ready);
        health_router(state)
    }

    /// Build a test request for the given URI.
    fn test_request(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn healthz_returns_200() {
        let app = test_app(false);
        let response = app
            .oneshot(test_request("/healthz"))
            .await
            .ok()
            .filter(|r| r.status() == StatusCode::OK);
        assert!(response.is_some(), "expected 200 OK from /healthz");
    }

    #[tokio::test]
    async fn readyz_returns_503_when_not_ready() {
        let app = test_app(false);
        let response = app
            .oneshot(test_request("/readyz"))
            .await
            .ok()
            .filter(|r| r.status() == StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            response.is_some(),
            "expected 503 from /readyz when not ready"
        );
    }

    #[tokio::test]
    async fn readyz_returns_200_when_ready() {
        let app = test_app(true);
        let response = app
            .oneshot(test_request("/readyz"))
            .await
            .ok()
            .filter(|r| r.status() == StatusCode::OK);
        assert!(
            response.is_some(),
            "expected 200 OK from /readyz when ready"
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_text() {
        let app = test_app(false);
        let response = app.oneshot(test_request("/metrics")).await.ok();
        let status_ok = response
            .as_ref()
            .map(|r| r.status() == StatusCode::OK)
            .unwrap_or(false);
        assert!(status_ok, "expected 200 OK from /metrics");

        let content_type = response
            .as_ref()
            .and_then(|r| r.headers().get("content-type"))
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            content_type.contains("text/plain"),
            "expected text/plain content-type, got {content_type}"
        );
    }
}
