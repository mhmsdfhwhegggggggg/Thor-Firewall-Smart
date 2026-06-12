#!/usr/bin/env bash
# Thor Firewall Smart — Prerequisites Installer
# Supports: Ubuntu 22.04+, Debian 11+, Fedora 38+, Arch Linux
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ──────────────────────────────────────────────────────────
info "🛡️  Thor Firewall Smart — Setup Script"
echo ""

# Root check
if [[ $EUID -ne 0 ]]; then
  warn "Not root — some steps may need sudo"
fi

# OS detection
detect_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "$ID"
  else
    echo "unknown"
  fi
}
OS=$(detect_os)
info "Detected OS: $OS"

# ──────────────────────────────────────────────────────────
# 1. Kernel version check (5.4+ required for eBPF CO-RE)
KERNEL=$(uname -r | cut -d. -f1-2)
KMIN=5.4
if awk "BEGIN{exit !($KERNEL >= $KMIN)}"; then
  success "Kernel version: $KERNEL (>= $KMIN ✓)"
else
  error "Kernel $KERNEL too old. Thor requires Linux 5.4+. Upgrade with: apt upgrade linux-image-generic"
fi

# ──────────────────────────────────────────────────────────
# 2. Install system dependencies
info "Installing system dependencies..."
case "$OS" in
  ubuntu|debian)
    apt-get update -qq
    apt-get install -y \
      clang llvm libclang-dev libbpf-dev libbpf0 \
      linux-headers-$(uname -r) \
      pkg-config libssl-dev \
      libyara-dev yara \
      iproute2 iptables \
      lld \
      curl wget git
    ;;
  fedora|rhel|centos)
    dnf install -y \
      clang llvm libbpf-devel \
      kernel-headers \
      openssl-devel \
      yara yara-devel \
      iproute iptables \
      lld \
      curl wget git
    ;;
  arch)
    pacman -Sy --noconfirm \
      clang llvm libbpf \
      linux-headers \
      openssl \
      yara \
      iproute2 iptables \
      lld \
      curl wget git
    ;;
  *)
    warn "Unknown OS — install manually: clang, llvm, libbpf-dev, libyara-dev, lld"
    ;;
esac
success "System dependencies installed"

# ──────────────────────────────────────────────────────────
# 3. Install Rust (stable + bpf target)
if ! command -v rustc &>/dev/null; then
  info "Installing Rust..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  source "$HOME/.cargo/env"
else
  RUST_VER=$(rustc --version)
  success "Rust already installed: $RUST_VER"
fi

# Add BPF target
info "Adding BPF compilation target..."
rustup target add bpfel-unknown-none 2>/dev/null && success "BPF target added" || warn "BPF target already present"
rustup component add rust-src clippy rustfmt 2>/dev/null || true

# ──────────────────────────────────────────────────────────
# 4. Enable BPF filesystem (if not already mounted)
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  info "Mounting BPF filesystem..."
  mount -t bpf bpf /sys/fs/bpf || warn "Cannot mount bpffs — may already be mounted"
else
  success "BPF filesystem mounted at /sys/fs/bpf"
fi

# ──────────────────────────────────────────────────────────
# 5. Increase kernel BPF limits
info "Setting kernel BPF parameters..."
sysctl -w net.core.rmem_max=134217728 2>/dev/null || true
sysctl -w net.core.wmem_max=134217728 2>/dev/null || true
sysctl -w kernel.perf_event_paranoid=0 2>/dev/null || warn "Cannot set perf_event_paranoid"
sysctl -w kernel.unprivileged_bpf_disabled=0 2>/dev/null || true
success "Kernel parameters configured"

# ──────────────────────────────────────────────────────────
# 6. Create runtime directories
info "Creating runtime directories..."
mkdir -p /var/lib/thor/{quarantine,forensics}
chmod 700 /var/lib/thor
success "Runtime directories created at /var/lib/thor/"

# ──────────────────────────────────────────────────────────
# 7. ML model (optional)
if [[ ! -f "models/thor_ueba_model.onnx" ]]; then
  info "ONNX model not found. To train:"
  echo "  pip install scikit-learn skl2onnx numpy"
  echo "  python scripts/train_and_export.py"
  warn "Agent will run in rule-only mode until model is provided"
else
  success "ONNX model found: models/thor_ueba_model.onnx"
fi

# ──────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}✅  Setup complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "  Build:   cargo build --release"
echo "  Run:     sudo ./target/release/thor-agent --interface eth0"
echo "  Demo:    sudo ./scripts/demo.sh"
echo "  API:     http://localhost:8080/swagger-ui"
echo "  WS:      ws://localhost:8080/ws/events"
echo ""
