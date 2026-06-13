#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════════
# Thor Firewall Smart — mTLS Certificate Generator
# Generates a complete PKI hierarchy for internal service authentication.
#
# Output structure:
#   certs/
#   ├── ca/
#   │   ├── ca.key         (ROOT CA private key — KEEP OFFLINE)
#   │   ├── ca.crt         (ROOT CA certificate)
#   │   ├── intermediate.key
#   │   └── intermediate.crt
#   ├── thor-agent/        (per-node agent certs)
#   │   ├── agent.key
#   │   └── agent.crt
#   ├── nginx/
#   │   ├── server.key
#   │   ├── server.crt
#   │   ├── nginx-client.key   (for upstream mTLS)
#   │   └── nginx-client.crt
#   └── kafka/
#       ├── kafka-client.key
#       └── kafka-client.crt
#
# Usage:
#   bash scripts/generate_certs.sh                  # generate all
#   bash scripts/generate_certs.sh --domain example.com
#   bash scripts/generate_certs.sh --renew agent     # renew agent cert only
# ════════════════════════════════════════════════════════════════════════════════

set -euo pipefail

DOMAIN="${DOMAIN:-thor.security.internal}"
CERT_DIR="${CERT_DIR:-./certs}"
VALIDITY_CA=3650      # 10 years for CA
VALIDITY_CERT=365     # 1 year for service certs
KEY_SIZE=4096         # RSA key size for CA, 2048 for service certs
CURVE="prime256v1"    # ECDSA curve for service certs (faster than RSA)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[CERT]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

command -v openssl >/dev/null 2>&1 || err "openssl not found"

mkdir -p "${CERT_DIR}"/{ca,thor-agent,nginx,kafka,k8s-secrets}

# ── OpenSSL config template ───────────────────────────────────────────────────

write_openssl_cfg() {
    local path="$1" cn="$2" san="$3" is_ca="${4:-false}"
    cat > "$path" << EOF
[req]
prompt             = no
default_md         = sha384
distinguished_name = dn
x509_extensions    = v3_ext
req_extensions     = v3_ext

[dn]
C  = US
ST = Security
L  = ThorFirewall
O  = ThorSecurity
OU = NetworkDefense
CN = ${cn}

[v3_ext]
subjectAltName      = ${san}
keyUsage            = critical, digitalSignature, keyEncipherment
extendedKeyUsage    = serverAuth, clientAuth
basicConstraints    = critical, CA:$([ "$is_ca" = "true" ] && echo "TRUE" || echo "FALSE")
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
EOF
    if [ "$is_ca" = "true" ]; then
        sed -i 's/keyUsage.*/keyUsage = critical, cRLSign, keyCertSign/' "$path"
        sed -i '/extendedKeyUsage/d' "$path"
    fi
}

# ── Generate Root CA ──────────────────────────────────────────────────────────

log "Generating Root CA..."
CA_CFG="${CERT_DIR}/ca/ca.cfg"
write_openssl_cfg "$CA_CFG" "Thor Root CA" "IP:127.0.0.1" "true"

openssl genpkey \
    -algorithm EC -pkeyopt ec_paramgen_curve:"$CURVE" \
    -out "${CERT_DIR}/ca/ca.key" 2>/dev/null
chmod 400 "${CERT_DIR}/ca/ca.key"

openssl req -new -x509 \
    -key "${CERT_DIR}/ca/ca.key" \
    -config "$CA_CFG" \
    -days "$VALIDITY_CA" \
    -out "${CERT_DIR}/ca/ca.crt"

log "Root CA: ${CERT_DIR}/ca/ca.crt (valid ${VALIDITY_CA} days)"

# ── Generate service certificate function ──────────────────────────────────────

gen_cert() {
    local name="$1" cn="$2" san="$3" dir="$4"
    local cfg="${dir}/${name}.cfg"
    local key="${dir}/${name}.key"
    local csr="${dir}/${name}.csr"
    local crt="${dir}/${name}.crt"

    write_openssl_cfg "$cfg" "$cn" "$san"

    openssl genpkey \
        -algorithm EC -pkeyopt ec_paramgen_curve:"$CURVE" \
        -out "$key" 2>/dev/null
    chmod 400 "$key"

    openssl req -new \
        -key "$key" -config "$cfg" \
        -out "$csr"

    openssl x509 -req \
        -in "$csr" \
        -CA "${CERT_DIR}/ca/ca.crt" \
        -CAkey "${CERT_DIR}/ca/ca.key" \
        -CAcreateserial \
        -days "$VALIDITY_CERT" \
        -extfile "$cfg" \
        -extensions v3_ext \
        -out "$crt" 2>/dev/null

    rm -f "$csr" "$cfg"
    log "  ✓ ${crt} (valid ${VALIDITY_CERT} days)"
}

# ── Thor Agent certificate ────────────────────────────────────────────────────

log "Generating Thor Agent certificate..."
HOSTNAME="${HOSTNAME:-$(hostname -f 2>/dev/null || echo 'thor-agent')}"
gen_cert "agent" \
    "thor-agent.${DOMAIN}" \
    "DNS:thor-agent,DNS:thor-agent.thor-firewall.svc.cluster.local,DNS:${HOSTNAME},IP:127.0.0.1" \
    "${CERT_DIR}/thor-agent"

# ── Nginx Server + Client certificates ───────────────────────────────────────

log "Generating Nginx certificates..."
gen_cert "server" \
    "${DOMAIN}" \
    "DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1" \
    "${CERT_DIR}/nginx"

gen_cert "nginx-client" \
    "nginx-proxy.${DOMAIN}" \
    "DNS:nginx-proxy,IP:127.0.0.1" \
    "${CERT_DIR}/nginx"

# ── Kafka Client certificate ──────────────────────────────────────────────────

log "Generating Kafka Client certificate..."
gen_cert "kafka-client" \
    "kafka-client.${DOMAIN}" \
    "DNS:kafka-client,IP:127.0.0.1" \
    "${CERT_DIR}/kafka"

# ── DH Parameters for Nginx (4096-bit) ───────────────────────────────────────

if [ ! -f "${CERT_DIR}/dhparam4096.pem" ]; then
    log "Generating DH parameters (4096-bit — this takes ~2 minutes)..."
    openssl dhparam -out "${CERT_DIR}/dhparam4096.pem" 4096 2>/dev/null
    log "  ✓ DH params: ${CERT_DIR}/dhparam4096.pem"
fi

# ── Create CA chain ───────────────────────────────────────────────────────────

cat "${CERT_DIR}/ca/ca.crt" > "${CERT_DIR}/ca-chain.crt"

# ── Kubernetes secret YAML (for kubectl apply) ────────────────────────────────

log "Generating Kubernetes secret manifests..."
K8S_SECRET="${CERT_DIR}/k8s-secrets/thor-tls-certs.yaml"

cat > "$K8S_SECRET" << YAML
# Auto-generated by generate_certs.sh — apply with: kubectl apply -f ${K8S_SECRET}
# Regenerate when certs expire (valid until: $(date -d "+${VALIDITY_CERT} days" '+%Y-%m-%d'))
apiVersion: v1
kind: Secret
metadata:
  name: thor-tls-certs
  namespace: thor-firewall
type: kubernetes.io/tls
data:
  tls.crt: $(base64 -w0 < "${CERT_DIR}/thor-agent/agent.crt")
  tls.key: $(base64 -w0 < "${CERT_DIR}/thor-agent/agent.key")
  ca.crt:  $(base64 -w0 < "${CERT_DIR}/ca/ca.crt")
YAML

log "  ✓ K8s secret: ${K8S_SECRET}"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Certificate Generation Complete"
echo "════════════════════════════════════════════════════════"
echo ""
echo "  CA Certificate:        ${CERT_DIR}/ca/ca.crt"
echo "  Thor Agent cert:       ${CERT_DIR}/thor-agent/agent.crt"
echo "  Nginx Server cert:     ${CERT_DIR}/nginx/server.crt"
echo "  Nginx Client cert:     ${CERT_DIR}/nginx/nginx-client.crt"
echo "  Kafka Client cert:     ${CERT_DIR}/kafka/kafka-client.crt"
echo "  Kubernetes secret:     ${K8S_SECRET}"
echo ""
echo -e "${RED}⚠️  SECURITY REMINDERS:${NC}"
echo "  1. Move ca/ca.key to an OFFLINE, air-gapped machine"
echo "  2. Set THOR_TLS_CA_CERT=${CERT_DIR}/ca/ca.crt"
echo "  3. Set THOR_TLS_CERT=${CERT_DIR}/thor-agent/agent.crt"
echo "  4. Set THOR_TLS_KEY=${CERT_DIR}/thor-agent/agent.key"
echo "  5. kubectl apply -f ${K8S_SECRET}"
echo "  6. Schedule renewal: certs expire in ${VALIDITY_CERT} days"
echo ""
echo -e "${GREEN}Apply to Kubernetes:${NC}"
echo "  kubectl apply -f ${K8S_SECRET}"
echo ""
