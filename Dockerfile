# ═══════════════════════════════════════════════════════════════════════════════
# Thor Firewall Smart — Production Dockerfile (Phase 5 hardened)
# Multi-stage: builder → runtime (non-root, minimal attack surface)
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Stage 1: Builder ────────────────────────────────────────────────────────
FROM rust:1.79-slim-bookworm AS builder

# Build args
ARG BUILD_DATE
ARG GIT_COMMIT
ARG VERSION=dev

LABEL stage=builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libclang-dev \
    libbpf-dev \
    linux-headers-generic \
    pkg-config \
    libssl-dev \
    libyara-dev \
    lld \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies: copy manifests first
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY bpf/ bpf/

# Build with release optimizations
ENV CARGO_INCREMENTAL=0
ENV CARGO_NET_RETRY=10
RUN cargo build --release --bin thor-agent

# ─── Stage 2: Runtime (hardened) ─────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

ARG BUILD_DATE
ARG GIT_COMMIT
ARG VERSION=dev

LABEL org.opencontainers.image.title="Thor Firewall Smart" \
      org.opencontainers.image.description="eBPF-based cybersecurity detection & response platform" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.source="https://github.com/mhmsdfhwhegggggggg/Thor-Firewall-Smart" \
      org.opencontainers.image.licenses="MIT"

# Runtime deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libyara10 \
    libssl3 \
    iproute2 \
    iptables \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for the API process
# Note: eBPF probes still need capabilities (added via docker run --cap-add)
RUN groupadd -r thor && useradd -r -g thor -s /sbin/nologin thor

WORKDIR /app

# Copy binary + assets
COPY --from=builder /app/target/release/thor-agent /app/thor-agent
COPY rules/ /app/rules/
COPY models/ /app/models/
COPY migrations/ /app/migrations/

# Create runtime dirs with correct ownership
RUN mkdir -p /var/lib/thor/quarantine /var/lib/thor/forensics \
    && chmod 700 /var/lib/thor \
    && chown -R thor:thor /var/lib/thor /app/rules /app/models

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

# Required capabilities documented (added at runtime):
#   --cap-add NET_ADMIN NET_RAW SYS_ADMIN PERFMON BPF
# API runs as non-root user; eBPF loader runs with inherited capabilities.

USER thor

EXPOSE 8080 9090

ENTRYPOINT ["/app/thor-agent"]
