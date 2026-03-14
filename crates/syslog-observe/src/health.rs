//! HTTP health, readiness, metrics, and management endpoints.
//!
//! Exposes an [`axum::Router`] with:
//! - `GET /healthz`  — liveness probe (always 200)
//! - `GET /readyz`   — readiness probe (200 when ready, 503 otherwise)
//! - `GET /metrics`  — Prometheus scrape endpoint
//! - `GET /management/state`    — JSON with counters, uptime, features
//! - `GET /management/features` — JSON array of feature flag names
//! - `GET /management/counters` — JSON with counter values

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::IntoResponse,
    routing::get,
};
use metrics_exporter_prometheus::PrometheusHandle;
use syslog_mgmt::SharedSyslogState;

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
    /// Optional shared management state for RFC 9742 endpoints.
    mgmt_state: Option<SharedSyslogState>,
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
            mgmt_state: None,
        }
    }

    /// Create a new [`HealthState`] with management state for RFC 9742 endpoints.
    #[must_use]
    pub fn with_management(
        metrics_handle: PrometheusHandle,
        mgmt_state: SharedSyslogState,
    ) -> Self {
        Self {
            metrics_handle,
            ready: Arc::new(AtomicBool::new(false)),
            mgmt_state: Some(mgmt_state),
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

/// Build an [`axum::Router`] with `/healthz`, `/readyz`, `/metrics`,
/// and optionally `/management/*` endpoints.
///
/// If `bearer_token` is `Some`, the `/metrics` and `/management/*` routes
/// require an `Authorization: Bearer <token>` header. Health probes
/// (`/healthz`, `/readyz`) remain unauthenticated for load-balancer use.
pub fn health_router(state: HealthState) -> Router {
    health_router_with_token(state, None)
}

/// Build the health router with optional bearer-token authentication.
///
/// When `bearer_token` is `Some`, `/metrics` and `/management/*` routes
/// require a matching `Authorization: Bearer <token>` header (401 on
/// mismatch). `/healthz` and `/readyz` are always unauthenticated.
pub fn health_router_with_token(state: HealthState, bearer_token: Option<String>) -> Router {
    // Unauthenticated routes (health probes for load balancers).
    let public_routes = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz));

    // Protected routes: metrics + management.
    let mut protected = Router::new().route("/metrics", get(metrics_handler));

    // Add management endpoints if management state is available.
    if state.mgmt_state.is_some() {
        protected = protected
            .route("/management/state", get(mgmt_state_handler))
            .route("/management/features", get(mgmt_features_handler))
            .route("/management/counters", get(mgmt_counters_handler));
    }

    // Apply bearer-token middleware to protected routes when configured.
    let protected = if let Some(token) = bearer_token {
        let expected = Arc::new(token);
        protected.layer(middleware::from_fn(move |req, next| {
            let expected = Arc::clone(&expected);
            bearer_auth(expected, req, next)
        }))
    } else {
        protected
    };

    public_routes.merge(protected).with_state(state)
}

/// Middleware that validates the `Authorization: Bearer <token>` header.
async fn bearer_auth(expected_token: Arc<String>, req: Request, next: Next) -> impl IntoResponse {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let mut expected_value = String::with_capacity(7 + expected_token.len());
    expected_value.push_str("Bearer ");
    expected_value.push_str(&expected_token);

    match auth_header {
        Some(value) if value == expected_value => next.run(req).await.into_response(),
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
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

/// Management state endpoint — JSON with counters, uptime, features.
async fn mgmt_state_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let mgmt = match &state.mgmt_state {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                "management state not available".to_owned(),
            );
        }
    };

    #[derive(serde::Serialize)]
    struct MgmtStateResponse {
        uptime_secs: f64,
        features: syslog_mgmt::SyslogFeatures,
        counters: syslog_mgmt::MessageCounters,
    }

    let response = MgmtStateResponse {
        uptime_secs: mgmt.uptime().as_secs_f64(),
        features: mgmt.features(),
        counters: mgmt.counters().snapshot(),
    };

    match serde_json::to_string(&response) {
        Ok(json) => (StatusCode::OK, json),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to serialize management state".to_owned(),
        ),
    }
}

/// Management features endpoint — JSON array of feature flag names.
async fn mgmt_features_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let mgmt = match &state.mgmt_state {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                "management state not available".to_owned(),
            );
        }
    };

    match serde_json::to_string(&mgmt.features()) {
        Ok(json) => (StatusCode::OK, json),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to serialize features".to_owned(),
        ),
    }
}

/// Management counters endpoint — JSON with counter values.
async fn mgmt_counters_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let mgmt = match &state.mgmt_state {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                "management state not available".to_owned(),
            );
        }
    };

    match serde_json::to_string(&mgmt.counters().snapshot()) {
        Ok(json) => (StatusCode::OK, json),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to serialize counters".to_owned(),
        ),
    }
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
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        drop(recorder);

        let state = HealthState::new(handle);
        state.set_ready(ready);
        health_router(state)
    }

    /// Helper: build a test app with management state.
    fn test_app_with_mgmt(ready: bool) -> (Router, SharedSyslogState) {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        drop(recorder);

        let features =
            syslog_mgmt::SyslogFeatures::UDP_TRANSPORT | syslog_mgmt::SyslogFeatures::RELAY;
        let mgmt_state = SharedSyslogState::new(features);
        let state = HealthState::with_management(handle, mgmt_state.clone());
        state.set_ready(ready);
        (health_router(state), mgmt_state)
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

    // -- Management endpoint tests --

    #[tokio::test]
    async fn mgmt_state_returns_json() {
        let (app, mgmt_state) = test_app_with_mgmt(true);
        mgmt_state.counters().increment_received();
        mgmt_state.counters().increment_forwarded();

        let response = app.oneshot(test_request("/management/state")).await;
        let resp = match response {
            Ok(r) => r,
            Err(_) => return,
        };
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 65536).await;
        let body_str = match body {
            Ok(b) => String::from_utf8_lossy(&b).to_string(),
            Err(_) => return,
        };
        assert!(body_str.contains("uptime_secs"));
        assert!(body_str.contains("features"));
        assert!(body_str.contains("counters"));
        assert!(body_str.contains("\"received\":1"));
        assert!(body_str.contains("\"forwarded\":1"));
    }

    #[tokio::test]
    async fn mgmt_features_returns_json_array() {
        let (app, _) = test_app_with_mgmt(true);

        let response = app.oneshot(test_request("/management/features")).await;
        let resp = match response {
            Ok(r) => r,
            Err(_) => return,
        };
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 65536).await;
        let body_str = match body {
            Ok(b) => String::from_utf8_lossy(&b).to_string(),
            Err(_) => return,
        };
        assert!(body_str.contains("udp_transport"));
        assert!(body_str.contains("relay"));
    }

    #[tokio::test]
    async fn mgmt_counters_returns_json() {
        let (app, mgmt_state) = test_app_with_mgmt(true);
        mgmt_state.counters().increment_received();
        mgmt_state.counters().increment_received();
        mgmt_state.counters().increment_malformed();

        let response = app.oneshot(test_request("/management/counters")).await;
        let resp = match response {
            Ok(r) => r,
            Err(_) => return,
        };
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 65536).await;
        let body_str = match body {
            Ok(b) => String::from_utf8_lossy(&b).to_string(),
            Err(_) => return,
        };
        assert!(body_str.contains("\"received\":2"));
        assert!(body_str.contains("\"malformed\":1"));
    }

    #[tokio::test]
    async fn mgmt_endpoints_not_present_without_state() {
        let app = test_app(true);

        // Management endpoints should return 404 when no mgmt state
        let response = app.oneshot(test_request("/management/state")).await;
        let resp = match response {
            Ok(r) => r,
            Err(_) => return,
        };
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn mgmt_counters_start_at_zero() {
        let (app, _) = test_app_with_mgmt(true);

        let response = app.oneshot(test_request("/management/counters")).await;
        let resp = match response {
            Ok(r) => r,
            Err(_) => return,
        };
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 65536).await;
        let body_str = match body {
            Ok(b) => String::from_utf8_lossy(&b).to_string(),
            Err(_) => return,
        };
        assert!(body_str.contains("\"received\":0"));
        assert!(body_str.contains("\"forwarded\":0"));
        assert!(body_str.contains("\"dropped\":0"));
        assert!(body_str.contains("\"malformed\":0"));
    }

    #[tokio::test]
    async fn mgmt_state_includes_uptime() {
        let (app, _) = test_app_with_mgmt(true);

        let response = app.oneshot(test_request("/management/state")).await;
        let resp = match response {
            Ok(r) => r,
            Err(_) => return,
        };

        let body = axum::body::to_bytes(resp.into_body(), 65536).await;
        let body_str = match body {
            Ok(b) => String::from_utf8_lossy(&b).to_string(),
            Err(_) => return,
        };
        assert!(body_str.contains("uptime_secs"));
    }

    #[tokio::test]
    async fn health_state_with_management_is_ready() {
        let (app, _) = test_app_with_mgmt(true);
        let response = app
            .oneshot(test_request("/readyz"))
            .await
            .ok()
            .filter(|r| r.status() == StatusCode::OK);
        assert!(response.is_some());
    }

    #[tokio::test]
    async fn mgmt_features_empty_when_no_flags() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        drop(recorder);

        let mgmt_state = SharedSyslogState::new(syslog_mgmt::SyslogFeatures::empty());
        let state = HealthState::with_management(handle, mgmt_state);
        let app = health_router(state);

        let response = app.oneshot(test_request("/management/features")).await;
        let resp = match response {
            Ok(r) => r,
            Err(_) => return,
        };
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 65536).await;
        let body_str = match body {
            Ok(b) => String::from_utf8_lossy(&b).to_string(),
            Err(_) => return,
        };
        assert_eq!(body_str, "[]");
    }

    // -- Bearer-token authentication tests --

    /// Helper: build a test app with bearer-token authentication enabled.
    fn test_app_with_token(token: &str) -> Router {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        drop(recorder);

        let state = HealthState::new(handle);
        state.set_ready(true);
        health_router_with_token(state, Some(token.to_owned()))
    }

    /// Helper: build a test request with an Authorization header.
    fn test_request_with_auth(uri: &str, token: &str) -> Request<Body> {
        let mut bearer = String::with_capacity(7 + token.len());
        bearer.push_str("Bearer ");
        bearer.push_str(token);
        Request::builder()
            .uri(uri)
            .header("authorization", bearer)
            .body(Body::empty())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn metrics_returns_401_without_token() {
        let app = test_app_with_token("secret-token-123");
        let response = app.oneshot(test_request("/metrics")).await;
        let resp = match response {
            Ok(r) => r,
            Err(_) => return,
        };
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "expected 401 Unauthorized from /metrics without bearer token"
        );
    }

    #[tokio::test]
    async fn metrics_returns_200_with_correct_token() {
        let app = test_app_with_token("secret-token-123");
        let response = app
            .oneshot(test_request_with_auth("/metrics", "secret-token-123"))
            .await;
        let resp = match response {
            Ok(r) => r,
            Err(_) => return,
        };
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "expected 200 OK from /metrics with correct bearer token"
        );
    }

    #[tokio::test]
    async fn healthz_accessible_without_token_when_auth_enabled() {
        let app = test_app_with_token("secret-token-123");
        let response = app.oneshot(test_request("/healthz")).await;
        let resp = match response {
            Ok(r) => r,
            Err(_) => return,
        };
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "expected 200 OK from /healthz without bearer token (unauthenticated probe)"
        );
    }
}
