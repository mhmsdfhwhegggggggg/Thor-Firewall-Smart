#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Thor Firewall Smart — One-shot installation script
# ═══════════════════════════════════════════════════════════════════════════════
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/mhmsdfhwhegggggggg/Thor-Firewall-Smart/main/scripts/install.sh | sudo bash
#
# Or with options:
#   sudo bash install.sh --interface eth0 --api-port 8080
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
RED="\033[0;31m"
RESET="\033[0m"

THOR_VERSION="${THOR_VERSION:-0.3.0}"
THOR_USER="thor"
INSTALL_DIR="/opt/thor"
CONFIG_DIR="/etc/thor"
RULES_DIR="/etc/thor/rules"
DATA_DIR="/var/lib/thor"
LOG_DIR="/var/log/thor"
INTERFACE="${INTERFACE:-eth0}"
API_PORT="${API_PORT:-8080}"
METRICS_PORT="${METRICS_PORT:-9090}"

info()  { printf "${CYAN}[INFO]${RESET}  %s\n" "$*"; }
ok()    { printf "${GREEN}[OK]${RESET}    %s\n" "$*"; }
fail()  { printf "${RED}[ERROR]${RESET} %s\n" "$*" >&2; exit 1; }

# ─── Checks ──────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fail "Must run as root (sudo bash install.sh)"

KERNEL=$(uname -r | cut -d. -f1,2)
KERNEL_MAJ=$(echo $KERNEL | cut -d. -f1)
KERNEL_MIN=$(echo $KERNEL | cut -d. -f2)
if [[ $KERNEL_MAJ -lt 5 ]] || { [[ $KERNEL_MAJ -eq 5 ]] && [[ $KERNEL_MIN -lt 4 ]]; }; then
    fail "Linux kernel 5.4+ required (current: $KERNEL)"
fi
info "Kernel: $KERNEL — OK"

ARCH=$(uname -m)
[[ "$ARCH" != "x86_64" ]] && fail "Only x86_64 supported (current: $ARCH)"

# ─── Install system dependencies ────────────────────────────────────────────
info "Installing system dependencies..."
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        libyara4 libc6 libssl3 ca-certificates curl systemd \
        linux-headers-$(uname -r) iproute2 2>/dev/null || true
elif command -v yum &>/dev/null; then
    yum install -y libyara openssl-libs ca-certificates curl iproute 2>/dev/null || true
fi
ok "Dependencies installed"

# ─── Create system user ───────────────────────────────────────────────────────
info "Creating system user: $THOR_USER"
if ! id "$THOR_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /sbin/nologin "$THOR_USER"
fi
ok "User: $THOR_USER"

# ─── Create directories ───────────────────────────────────────────────────────
info "Creating directories..."
mkdir -p "$INSTALL_DIR/bin" "$CONFIG_DIR" "$RULES_DIR" "$DATA_DIR" "$LOG_DIR"
chown -R "$THOR_USER:$THOR_USER" "$DATA_DIR" "$LOG_DIR"
chmod 750 "$CONFIG_DIR" "$DATA_DIR"
ok "Directories created"

# ─── Download binaries ────────────────────────────────────────────────────────
RELEASE_URL="https://github.com/mhmsdfhwhegggggggg/Thor-Firewall-Smart/releases/download/v${THOR_VERSION}"

info "Downloading thor-agent v${THOR_VERSION}..."
if ! curl -fsSL "${RELEASE_URL}/thor-agent-x86_64-linux" -o "$INSTALL_DIR/bin/thor-agent"; then
    info "No prebuilt binary found — building from source..."
    if ! command -v cargo &>/dev/null; then
        info "Installing Rust toolchain..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
    apt-get install -y --no-install-recommends \
        clang llvm libclang-dev libbpf-dev pkg-config libssl-dev libyara-dev lld 2>/dev/null || true
    TMPDIR=$(mktemp -d)
    cd "$TMPDIR"
    curl -fsSL "https://github.com/mhmsdfhwhegggggggg/Thor-Firewall-Smart/archive/refs/tags/v${THOR_VERSION}.tar.gz" | tar xz
    cd "Thor-Firewall-Smart-${THOR_VERSION}"
    CARGO_INCREMENTAL=0 cargo build --release --bin thor-agent
    cp target/release/thor-agent "$INSTALL_DIR/bin/thor-agent"
    cd / && rm -rf "$TMPDIR"
fi
chmod 755 "$INSTALL_DIR/bin/thor-agent"
chown root:root "$INSTALL_DIR/bin/thor-agent"
ok "thor-agent installed"

# ─── Config ──────────────────────────────────────────────────────────────────
info "Installing configuration..."
if [[ ! -f "$CONFIG_DIR/thor.yaml" ]]; then
    cat > "$CONFIG_DIR/thor.yaml" <<EOF
interface: ${INTERFACE}
api_addr: "0.0.0.0:${API_PORT}"
metrics_bind: "0.0.0.0:${METRICS_PORT}"
sigma_rules_dir: "${RULES_DIR}/sigma"
yara_rules_dir: "${RULES_DIR}/yara"
ids_rules_dir: "${RULES_DIR}/suricata"
data_dir: "${DATA_DIR}"
log_dir: "${LOG_DIR}"
EOF
    chmod 640 "$CONFIG_DIR/thor.yaml"
    chown root:"$THOR_USER" "$CONFIG_DIR/thor.yaml"
fi
ok "Configuration written to $CONFIG_DIR/thor.yaml"

# ─── Systemd unit ────────────────────────────────────────────────────────────
info "Installing systemd service..."
cat > /etc/systemd/system/thor-agent.service <<EOF
[Unit]
Description=Thor Firewall Smart Agent
Documentation=https://github.com/mhmsdfhwhegggggggg/Thor-Firewall-Smart
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${INSTALL_DIR}/bin/thor-agent --config ${CONFIG_DIR}/thor.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=${DATA_DIR} ${LOG_DIR}
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_BPF CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_BPF CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable thor-agent
ok "Systemd service installed and enabled"

# ─── Done ────────────────────────────────────────────────────────────────────
printf "\n${GREEN}${BOLD}✓ Thor Firewall Smart installed successfully!${RESET}\n\n"
printf "  Config:  ${CONFIG_DIR}/thor.yaml\n"
printf "  Logs:    ${LOG_DIR}/\n"
printf "  Start:   ${BOLD}systemctl start thor-agent${RESET}\n"
printf "  Status:  ${BOLD}systemctl status thor-agent${RESET}\n"
printf "  API:     ${BOLD}http://localhost:${API_PORT}/swagger-ui${RESET}\n"
printf "  Metrics: ${BOLD}http://localhost:${METRICS_PORT}/metrics${RESET}\n\n"
printf "${CYAN}Review ${CONFIG_DIR}/thor.yaml before starting.${RESET}\n"
