# Multi-stage build for Thor Firewall Smart
FROM rust:1.79-slim-bookworm AS builder

# Install build deps
RUN apt-get update && apt-get install -y \
    clang llvm libclang-dev libbpf-dev \
    linux-headers-generic \
    pkg-config libssl-dev \
    libyara-dev \
    lld \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build release binary
RUN cargo build --release --bin thor-agent

# ─── Runtime Stage ───────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    libyara10 \
    libssl3 \
    iproute2 \
    iptables \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/thor-agent /app/thor-agent
COPY rules/ /app/rules/
COPY models/ /app/models/

# Create runtime directories
RUN mkdir -p /var/lib/thor/quarantine /var/lib/thor/forensics \
    && chmod 700 /var/lib/thor

EXPOSE 8080

ENTRYPOINT ["/app/thor-agent"]
