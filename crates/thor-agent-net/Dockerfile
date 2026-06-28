# ═══════════════════════════════════════════════════════════════════════════════
# Thor Firewall Smart — thor-agent-net Dockerfile
# Multi-stage: builder (Rust + eBPF deps) → hardened runtime (non-root, ro-fs)
# ═══════════════════════════════════════════════════════════════════════════════

ARG RUST_VERSION=1.79

# ─── Stage 1: dependency cache ────────────────────────────────────────────────
FROM rust:1.79-slim-bookworm AS deps

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libclang-dev libbpf-dev pkg-config \
    libssl-dev libyara-dev lld ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

# Pre-build deps (cache layer)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    CARGO_INCREMENTAL=0 cargo fetch

# ─── Stage 2: builder ─────────────────────────────────────────────────────────
FROM deps AS builder

ARG BUILD_DATE
ARG GIT_COMMIT=unknown
ARG VERSION=dev
ARG AGENT_NAME=thor-agent-net

COPY bpf/ bpf/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    CARGO_INCREMENTAL=0 \
    CARGO_NET_RETRY=10 \
    RUSTFLAGS="-C link-arg=-fuse-ld=lld -C target-cpu=native" \
    cargo build --release --bin $AGENT_NAME && \
    cp /build/target/release/$AGENT_NAME /build/agent-bin

# ─── Stage 3: hardened runtime ────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

ARG BUILD_DATE
ARG GIT_COMMIT=unknown
ARG VERSION=dev

LABEL org.opencontainers.image.title="thor-agent-net" \
      org.opencontainers.image.description="Thor Firewall Smart — L3/L4 XDP/eBPF Network Agent" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.source="https://github.com/mhmsdfhwhegggggggg/Thor-Firewall-Smart" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

# Copy binary from builder
COPY --from=builder /build/agent-bin /usr/local/bin/agent

# Copy runtime config and rules
COPY thor.yaml          /etc/thor/thor.yaml
COPY rules/             /etc/thor/rules/
COPY models/            /etc/thor/models/

# Non-root user (distroless nonroot = uid 65532)
USER nonroot:nonroot

# Health probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/agent", "--health-check"]

EXPOSE 8081

ENTRYPOINT ["/usr/local/bin/agent"]
CMD ["--config", "/etc/thor/thor.yaml"]
