#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════════
# Thor Firewall Smart — Kubernetes Deployment Script
# Full production deployment with pre-flight checks.
#
# Usage:
#   bash scripts/k8s_deploy.sh install   # fresh install
#   bash scripts/k8s_deploy.sh upgrade   # rolling update
#   bash scripts/k8s_deploy.sh status    # show deployment status
#   bash scripts/k8s_deploy.sh rollback  # rollback to previous version
#   bash scripts/k8s_deploy.sh uninstall # remove everything
# ════════════════════════════════════════════════════════════════════════════════

set -euo pipefail

VERSION="${THOR_VERSION:-latest}"
NS="thor-firewall"
TIMEOUT="600s"
IMAGE="ghcr.io/mhmsdfhwhegggggggg/thor-firewall-smart:${VERSION}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${GREEN}[DEPLOY]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}   $1"; }
err()  { echo -e "${RED}[ERROR]${NC}  $1"; exit 1; }
info() { echo -e "${BLUE}[INFO]${NC}   $1"; }

# ── Pre-flight checks ─────────────────────────────────────────────────────────
preflight() {
    log "Running pre-flight checks..."

    command -v kubectl >/dev/null 2>&1 || err "kubectl not found"
    command -v openssl >/dev/null 2>&1 || err "openssl not found"

    kubectl cluster-info >/dev/null 2>&1 || err "Cannot connect to Kubernetes cluster"
    log "  ✓ kubectl connected"

    # Check required namespace
    kubectl get namespace "$NS" >/dev/null 2>&1 || warn "Namespace $NS not yet created"

    # Verify secrets file is not using placeholder values
    if grep -q "CHANGE_ME" k8s/thor-secrets.yaml 2>/dev/null; then
        err "k8s/thor-secrets.yaml contains placeholder values — fill them in first"
    fi

    # Verify certs exist
    [ -f "certs/ca/ca.crt" ]              || err "CA cert not found — run: bash scripts/generate_certs.sh"
    [ -f "certs/thor-agent/agent.crt" ]   || err "Agent cert not found"
    [ -f "certs/nginx/server.crt" ]       || err "Nginx cert not found"

    # Check cert expiry
    log "  Checking certificate expiry..."
    for cert in certs/ca/ca.crt certs/thor-agent/agent.crt certs/nginx/server.crt; do
        expiry=$(openssl x509 -enddate -noout -in "$cert" | cut -d= -f2)
        days=$(( ( $(date -d "$expiry" +%s) - $(date +%s) ) / 86400 ))
        if [ "$days" -le 0 ]; then
            err "Certificate EXPIRED: $cert — run: bash scripts/generate_certs.sh --renew"
        elif [ "$days" -le 30 ]; then
            warn "Certificate expiring in $days days: $cert"
        else
            log "  ✓ $cert (expires in $days days)"
        fi
    done

    log "Pre-flight checks passed"
}

# ── Install ───────────────────────────────────────────────────────────────────
install() {
    preflight
    log "Installing Thor Firewall Smart v${VERSION}..."

    # 1. Namespace and RBAC
    log "[1/7] Creating namespace and RBAC..."
    kubectl apply -f k8s/namespace.yaml
    sleep 2

    # 2. Secrets (from k8s secrets dir, not the template)
    log "[2/7] Creating secrets..."
    if [ -f "certs/k8s-secrets/thor-tls-certs.yaml" ]; then
        kubectl apply -f certs/k8s-secrets/thor-tls-certs.yaml
    else
        err "TLS secret not found — run: bash scripts/generate_certs.sh"
    fi

    # 3. Storage (Kafka + Redis + Postgres + Audit)
    log "[3/7] Deploying storage layer..."
    kubectl apply -f k8s/thor-postgres.yaml
    kubectl apply -f k8s/thor-redis.yaml
    kubectl apply -f k8s/thor-kafka.yaml

    log "Waiting for storage to be ready..."
    kubectl rollout status statefulset/kafka   -n "$NS" --timeout="$TIMEOUT"
    kubectl rollout status statefulset/redis   -n "$NS" --timeout="$TIMEOUT"
    kubectl rollout status statefulset/postgres -n "$NS" --timeout="$TIMEOUT" 2>/dev/null || true

    # 4. Initialize Kafka topics
    log "[4/7] Initializing Kafka topics..."
    kubectl apply -f k8s/thor-kafka.yaml  # includes the Job
    kubectl wait job/kafka-topic-init -n "$NS" --for=condition=complete --timeout=120s || \
        warn "Topic init job not complete yet — verify manually"

    # 5. Network policies
    log "[5/7] Applying zero-trust network policies..."
    kubectl apply -f k8s/network-policy.yaml

    # 6. Thor Agent DaemonSet
    log "[6/7] Deploying Thor Agent..."
    kubectl apply -f k8s/thor-agent.yaml
    kubectl rollout status daemonset/thor-agent -n "$NS" --timeout="$TIMEOUT"

    # 7. Ingress + TLS
    log "[7/7] Configuring Ingress and TLS..."
    kubectl apply -f k8s/thor-ingress.yaml

    status
}

# ── Upgrade ───────────────────────────────────────────────────────────────────
upgrade() {
    log "Upgrading Thor Agent to v${VERSION}..."
    kubectl set image daemonset/thor-agent thor-agent="$IMAGE" -n "$NS"
    kubectl rollout status daemonset/thor-agent -n "$NS" --timeout="$TIMEOUT"
    log "Upgrade complete"
    status
}

# ── Status ────────────────────────────────────────────────────────────────────
status() {
    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo "  Thor Firewall Smart — Deployment Status"
    echo "═══════════════════════════════════════════════════════"
    echo ""
    kubectl get daemonset,statefulset,service,ingress -n "$NS" 2>/dev/null
    echo ""
    info "Pods:"
    kubectl get pods -n "$NS" -o wide 2>/dev/null
    echo ""
    info "API health: curl -sk https://thor.security.internal/health"
    info "Metrics:    curl -sk https://thor.security.internal/metrics"
    info "Grafana:    https://thor.security.internal/grafana"
}

# ── Rollback ──────────────────────────────────────────────────────────────────
rollback() {
    warn "Rolling back Thor Agent..."
    kubectl rollout undo daemonset/thor-agent -n "$NS"
    kubectl rollout status daemonset/thor-agent -n "$NS" --timeout=120s
    log "Rollback complete"
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
uninstall() {
    warn "This will DELETE all Thor resources. Type 'yes' to confirm: "
    read -r confirm
    [ "$confirm" = "yes" ] || { log "Aborted"; exit 0; }
    kubectl delete namespace "$NS" --timeout=60s || true
    log "Uninstall complete"
}

# ── Entry ─────────────────────────────────────────────────────────────────────
case "${1:-help}" in
    install)   install   ;;
    upgrade)   upgrade   ;;
    status)    status    ;;
    rollback)  rollback  ;;
    uninstall) uninstall ;;
    *)
        echo "Usage: $0 {install|upgrade|status|rollback|uninstall}"
        exit 1
        ;;
esac
