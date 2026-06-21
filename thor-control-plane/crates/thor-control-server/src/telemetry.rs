//! OpenTelemetry Distributed Tracing for Thor Control Plane
//!
//! Exports traces via OTLP to Jaeger/Grafana Tempo for end-to-end
//! visibility of every Policy Push, Agent Registration, and Action flow.

use opentelemetry::global;
use opentelemetry::trace::TraceError;
use opentelemetry_sdk::runtime;
use opentelemetry_sdk::trace::{self as sdktrace, Config};
use opentelemetry_otlp::WithExportConfig;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use opentelemetry_sdk::Resource;
use opentelemetry::KeyValue;

/// Initialise the global tracer, exporting to OTLP endpoint (Jaeger/Tempo).
/// Call this at the top of `main()` before any async work.
pub fn init_tracer(service_name: &'static str) -> Result<sdktrace::Tracer, TraceError> {
    let otlp_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://jaeger:4317".to_string());

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(otlp_endpoint),
        )
        .with_trace_config(
            Config::default().with_resource(Resource::new(vec![
                KeyValue::new("service.name", service_name),
                KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                KeyValue::new("deployment.environment", "production"),
            ])),
        )
        .install_batch(runtime::Tokio)?;

    Ok(tracer)
}

/// Initialize the full tracing stack: OpenTelemetry + formatted console logs.
pub fn init_tracing(service_name: &'static str) {
    let tracer = match init_tracer(service_name) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("⚠️  OpenTelemetry init failed: {e}. Falling back to console-only logs.");
            // Fallback: just structured console logging
            tracing_subscriber::registry()
                .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
                .with(tracing_subscriber::fmt::layer().json())
                .init();
            return;
        }
    };

    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer().json()) // Structured JSON for log aggregation
        .with(otel_layer)                              // OTel trace context propagation
        .init();

    tracing::info!("✅ OpenTelemetry tracing initialized for service: {}", service_name);
}

/// Gracefully flush and shutdown the tracer before process exit.
pub fn shutdown_tracer() {
    global::shutdown_tracer_provider();
}
