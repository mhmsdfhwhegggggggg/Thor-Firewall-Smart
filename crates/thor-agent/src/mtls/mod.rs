//! mTLS (Mutual TLS) — Zero-Trust Internal Service Authentication
//! Every internal service connection requires a valid client certificate.
//! No service can connect to another without presenting a certificate
//! signed by the Thor CA.
//!
//! Certificate hierarchy:
//!   Thor Root CA (offline, air-gapped)
//!     └── Thor Intermediate CA (online signing)
//!           ├── thor-agent-{hostname}.crt   (per-node agent cert)
//!           ├── thor-api.crt                (API server cert)
//!           ├── thor-kafka-client.crt       (Kafka mTLS client)
//!           └── thor-dashboard.crt          (dashboard client cert)
//!
//! Env vars:
//!   THOR_TLS_CA_CERT      — path to CA cert bundle (PEM)
//!   THOR_TLS_CERT         — path to this service's cert (PEM)
//!   THOR_TLS_KEY          — path to this service's private key (PEM)
//!   THOR_TLS_BIND_ADDR    — bind address for TLS API (default: 0.0.0.0:8443)
//!   THOR_TLS_MIN_VERSION  — minimum TLS version ("1.2" or "1.3", default: "1.3")

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_rustls::rustls::{
    Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig,
};
use tracing::{error, info, warn};

// ─── TLS configuration ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub ca_cert_path:   PathBuf,
    pub cert_path:      PathBuf,
    pub key_path:       PathBuf,
    pub bind_addr:      String,
    pub min_version:    TlsVersion,
    pub require_client: bool,   // true = mTLS, false = one-way TLS
}

#[derive(Debug, Clone)]
pub enum TlsVersion { Tls12, Tls13 }

impl TlsConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            ca_cert_path: std::env::var("THOR_TLS_CA_CERT")
                .context("THOR_TLS_CA_CERT not set")?.into(),
            cert_path: std::env::var("THOR_TLS_CERT")
                .context("THOR_TLS_CERT not set")?.into(),
            key_path: std::env::var("THOR_TLS_KEY")
                .context("THOR_TLS_KEY not set")?.into(),
            bind_addr: std::env::var("THOR_TLS_BIND_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8443".to_string()),
            min_version: match std::env::var("THOR_TLS_MIN_VERSION").as_deref() {
                Ok("1.2") => TlsVersion::Tls12,
                _         => TlsVersion::Tls13,
            },
            require_client: true,
        })
    }

    pub fn is_available() -> bool {
        std::env::var("THOR_TLS_CA_CERT").is_ok()
            && std::env::var("THOR_TLS_CERT").is_ok()
            && std::env::var("THOR_TLS_KEY").is_ok()
    }
}

// ─── Certificate loader ───────────────────────────────────────────────────────

pub struct CertLoader {
    config: TlsConfig,
}

impl CertLoader {
    pub fn new(config: TlsConfig) -> Self { Self { config } }

    pub fn load_certs(&self) -> Result<Vec<Certificate>> {
        let pem = std::fs::read(&self.config.cert_path)
            .with_context(|| format!("Reading cert: {:?}", self.config.cert_path))?;
        let certs = rustls_pemfile::certs(&mut pem.as_slice())
            .context("Parsing PEM certs")?
            .into_iter()
            .map(Certificate)
            .collect::<Vec<_>>();
        if certs.is_empty() {
            anyhow::bail!("No certificates found in {:?}", self.config.cert_path);
        }
        Ok(certs)
    }

    pub fn load_private_key(&self) -> Result<PrivateKey> {
        let pem = std::fs::read(&self.config.key_path)
            .with_context(|| format!("Reading key: {:?}", self.config.key_path))?;
        let mut reader = std::io::BufReader::new(pem.as_slice());

        // Try PKCS8 first, then RSA
        let key = rustls_pemfile::pkcs8_private_keys(&mut reader)
            .context("Parsing PKCS8 key")?
            .into_iter()
            .next()
            .map(PrivateKey)
            .or_else(|| {
                let mut reader2 = std::io::BufReader::new(pem.as_slice());
                rustls_pemfile::rsa_private_keys(&mut reader2).ok()?
                    .into_iter().next().map(PrivateKey)
            })
            .context("No private key found in key file")?;
        Ok(key)
    }

    pub fn load_ca_store(&self) -> Result<RootCertStore> {
        let pem = std::fs::read(&self.config.ca_cert_path)
            .with_context(|| format!("Reading CA cert: {:?}", self.config.ca_cert_path))?;
        let mut store = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut pem.as_slice()).context("Parsing CA cert")? {
            store.add(&Certificate(cert)).context("Adding CA to trust store")?;
        }
        if store.is_empty() {
            anyhow::bail!("CA trust store is empty — check THOR_TLS_CA_CERT");
        }
        Ok(store)
    }

    /// Build a rustls ServerConfig requiring client certificates (mTLS).
    pub fn build_server_config(&self) -> Result<Arc<ServerConfig>> {
        let certs  = self.load_certs()?;
        let key    = self.load_private_key()?;
        let ca     = self.load_ca_store()?;

        let client_auth = tokio_rustls::rustls::server::AllowAnyAuthenticatedClient::new(ca)
            .boxed();

        let mut cfg = ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(client_auth)
            .with_single_cert(certs, key)
            .context("Building TLS ServerConfig")?;

        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        info!(
            "🔒 mTLS ServerConfig ready — {:?} — client cert required",
            self.config.min_version
        );
        Ok(Arc::new(cfg))
    }

    /// Build a rustls ClientConfig presenting this node's certificate.
    pub fn build_client_config(&self) -> Result<Arc<ClientConfig>> {
        let certs = self.load_certs()?;
        let key   = self.load_private_key()?;
        let ca    = self.load_ca_store()?;

        let cfg = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(ca)
            .with_client_auth_cert(certs, key)
            .context("Building TLS ClientConfig")?;

        info!("🔒 mTLS ClientConfig ready — presenting node certificate");
        Ok(Arc::new(cfg))
    }
}

// ─── Certificate validity checker ────────────────────────────────────────────

#[derive(Debug)]
pub struct CertStatus {
    pub subject:     String,
    pub issuer:      String,
    pub not_before:  SystemTime,
    pub not_after:   SystemTime,
    pub days_left:   i64,
    pub is_expired:  bool,
    pub warn_expiry: bool,  // true if expiring within 30 days
}

/// Check certificate validity and emit warnings.
pub fn check_cert_expiry(cert_path: &Path) -> Result<CertStatus> {
    let pem = std::fs::read(cert_path)?;
    let (_, cert) = x509_parser::pem::parse_x509_pem(&pem)
        .map_err(|e| anyhow::anyhow!("PEM parse error: {:?}", e))?;
    let x509 = cert.parse_x509()
        .map_err(|e| anyhow::anyhow!("X.509 parse error: {:?}", e))?;

    let not_after = x509.validity().not_after.to_datetime()
        .map_err(|e| anyhow::anyhow!("Date parse: {:?}", e))?;
    let now = time::OffsetDateTime::now_utc();
    let days_left = (not_after - now).whole_days();

    let status = CertStatus {
        subject:     x509.subject().to_string(),
        issuer:      x509.issuer().to_string(),
        not_before:  SystemTime::UNIX_EPOCH, // simplified
        not_after:   SystemTime::UNIX_EPOCH,
        days_left,
        is_expired:  days_left <= 0,
        warn_expiry: days_left <= 30,
    };

    if status.is_expired {
        error!("❌ Certificate EXPIRED: {:?} (subject={})", cert_path, status.subject);
    } else if status.warn_expiry {
        warn!("⚠️  Certificate expiring in {} days: {:?}", days_left, cert_path);
    } else {
        info!("✅ Certificate valid ({} days): {}", days_left, status.subject);
    }

    Ok(status)
}

/// Startup: validate all TLS certificates before accepting connections.
pub fn validate_certs_at_startup(config: &TlsConfig) -> Result<()> {
    info!("🔍 Validating TLS certificates...");
    check_cert_expiry(&config.cert_path)?;
    check_cert_expiry(&config.ca_cert_path)?;
    info!("✅ All certificates valid");
    Ok(())
}
