//! Prometheus-compatible metrics endpoint (/metrics)
//! Exposes all runtime counters in OpenMetrics text format.
//! Compatible with: Prometheus, Grafana, Datadog, Elastic APM.
//!
//! Metrics exposed:
//!   thor_packets_processed_total
//!   thor_packets_dropped_total
//!   thor_active_flows
//!   thor_alerts_total
//!   thor_ioc_entries
//!   thor_websocket_clients
//!   thor_audit_entries_total
//!   thor_api_requests_total{endpoint, status}
//!   thor_uptime_seconds

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use dashmap::DashMap;

// ─── Per-endpoint request counter ────────────────────────────────────────────

pub struct EndpointCounter {
    counts: DashMap<(String, u16), AtomicU64>,
}

impl EndpointCounter {
    pub fn new() -> Self {
        Self { counts: DashMap::new() }
    }

    pub fn inc(&self, endpoint: &str, status: u16) {
        self.counts
            .entry((endpoint.to_string(), status))
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        let mut lines = Vec::new();
        for entry in self.counts.iter() {
            let (endpoint, status) = entry.key();
            let count = entry.value().load(Ordering::Relaxed);
            lines.push(format!(
                r#"thor_api_requests_total{{endpoint="{endpoint}",status="{status}"}} {count}"#
            ));
        }
        lines.join("\n")
    }
}

impl Default for EndpointCounter {
    fn default() -> Self { Self::new() }
}

// ─── Metrics collector ────────────────────────────────────────────────────────

pub struct ThorMetrics {
    pub start_time: Instant,
    pub endpoint_counter: EndpointCounter,
    pub audit_entries: AtomicU64,
}

impl ThorMetrics {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            endpoint_counter: EndpointCounter::new(),
            audit_entries: AtomicU64::new(0),
        }
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render(&self, state: &crate::state::ThorState) -> String {
        let stats = state.stats();
        let uptime = self.start_time.elapsed().as_secs();
        let audit_count = self.audit_entries.load(Ordering::Relaxed);

        let endpoint_metrics = self.endpoint_counter.render();

        format!(
            "# HELP thor_packets_processed_total Total packets seen by XDP\n\
             # TYPE thor_packets_processed_total counter\n\
             thor_packets_processed_total {packets_in}\n\
             \n\
             # HELP thor_packets_dropped_total Total packets dropped by XDP\n\
             # TYPE thor_packets_dropped_total counter\n\
             thor_packets_dropped_total {packets_dropped}\n\
             \n\
             # HELP thor_active_flows Current tracked network flows\n\
             # TYPE thor_active_flows gauge\n\
             thor_active_flows {flows}\n\
             \n\
             # HELP thor_alerts_total Total security alerts generated\n\
             # TYPE thor_alerts_total counter\n\
             thor_alerts_total {alerts}\n\
             \n\
             # HELP thor_ioc_entries Current IOC database size\n\
             # TYPE thor_ioc_entries gauge\n\
             thor_ioc_entries {iocs}\n\
             \n\
             # HELP thor_websocket_clients Current WebSocket subscribers\n\
             # TYPE thor_websocket_clients gauge\n\
             thor_websocket_clients {ws_clients}\n\
             \n\
             # HELP thor_audit_entries_total Total audit log entries written\n\
             # TYPE thor_audit_entries_total counter\n\
             thor_audit_entries_total {audit}\n\
             \n\
             # HELP thor_uptime_seconds Agent uptime in seconds\n\
             # TYPE thor_uptime_seconds counter\n\
             thor_uptime_seconds {uptime}\n\
             \n\
             # HELP thor_api_requests_total API requests by endpoint and status\n\
             # TYPE thor_api_requests_total counter\n\
             {endpoints}\n",
            packets_in      = stats.packets_processed,
            packets_dropped = stats.packets_dropped,
            flows           = stats.active_flows,
            alerts          = stats.total_alerts,
            iocs            = stats.ioc_count,
            ws_clients      = stats.ws_clients,
            audit           = audit_count,
            uptime          = uptime,
            endpoints       = endpoint_metrics,
        )
    }
}

impl Default for ThorMetrics {
    fn default() -> Self { Self::new() }
}

pub type SharedMetrics = Arc<ThorMetrics>;

/// Start Prometheus metrics HTTP server
pub async fn serve(addr: std::net::SocketAddr, metrics: Arc<ThorMetrics>) {
    use axum::{Router, routing::get, extract::State, response::Response};
    use tower_http::trace::TraceLayer;

    async fn metrics_handler(State(m): State<Arc<ThorMetrics>>) -> Response {
        let body = m.render_prometheus();
        axum::response::Response::builder()
            .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            .body(axum::body::Body::from(body))
            .unwrap()
    }

    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(metrics)
        .layer(TraceLayer::new_for_http());

    tracing::info!("📊 Metrics server: http://{}/metrics", addr);
    if let Ok(listener) = tokio::net::TcpListener::bind(addr).await {
        axum::serve(listener, app).await.ok();
    }
}
