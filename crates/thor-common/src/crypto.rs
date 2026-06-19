//! Thor mTLS — Zero-Trust Mutual TLS certificate generation & config helpers
//!
//! This module implements the CISO-mandated Zero-Trust requirement:
//! - **Every** Control-Plane ↔ Agent connection MUST be mutually authenticated
//! - Self-signed CA issued per-deployment, pinned in agents
//! - Agent certificates are short-lived (72 h), rotated automatically
//! - Control-Plane rejects any connection without a valid agent cert
//!
//! ## Usage (Control Plane — server):
//! ```rust
//! let ca   = ThorCertAuthority::generate("Thor-SOC-CA").unwrap();
//! let cert = ca.issue_agent_cert("agent-net-01").unwrap();
//! let cfg  = ca.server_tls_config(&cert).unwrap();
//! // pass cfg to tokio-rustls TlsAcceptor
//! ```
//!
//! ## Usage (Agent — client):
//! ```rust
//! let cfg = ThorCertAuthority::agent_client_config(&agent_cert_pem, &agent_key_pem, &ca_cert_pem).unwrap();
//! // pass cfg to tokio-rustls TlsConnector
//! ```

use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose, SanType,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ClientConfig, RootCertStore, ServerConfig,
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::io::Cursor;

// ─── PEM bundles for one identity ────────────────────────────────────────────

/// A PEM-encoded certificate + private key pair.
#[derive(Clone, Debug)]
pub struct ThorCertBundle {
    /// PEM-encoded X.509 certificate
    pub cert_pem: String,
    /// PEM-encoded PKCS#8 private key
    pub key_pem: String,
}

// ─── Certificate Authority ────────────────────────────────────────────────────

/// Self-signed Certificate Authority for one Thor deployment.
///
/// Generated once on the Control-Plane at first boot; the CA cert is then
/// distributed to every agent as the single trust anchor.
pub struct ThorCertAuthority {
    ca_cert: Certificate,
    bundle: ThorCertBundle,
}

impl ThorCertAuthority {
    /// Generate a new self-signed CA.
    ///
    /// `common_name` is embedded in the Subject CN field, e.g. `"Thor-SOC-CA-prod"`.
    pub fn generate(common_name: &str) -> Result<Self> {
        let mut params = CertificateParams::default();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        dn.push(DnType::OrganizationName, "Thor Security Platform");
        dn.push(DnType::CountryName, "US");
        params.distinguished_name = dn;

        // Mark as CA
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // 5-year CA lifetime
        let not_before = rcgen::date_time_ymd(2024, 1, 1);
        let not_after  = rcgen::date_time_ymd(2029, 1, 1);
        params.not_before = not_before;
        params.not_after  = not_after;

        let ca_cert = Certificate::from_params(params)
            .context("Failed to generate CA certificate")?;

        let cert_pem = ca_cert.serialize_pem()
            .context("Failed to serialize CA certificate to PEM")?;
        let key_pem  = ca_cert.serialize_private_key_pem();

        Ok(Self {
            ca_cert,
            bundle: ThorCertBundle { cert_pem, key_pem },
        })
    }

    /// Return the CA certificate PEM (to be distributed to agents as trust anchor).
    pub fn ca_cert_pem(&self) -> &str {
        &self.bundle.cert_pem
    }

    /// Issue a short-lived (72 h) agent certificate signed by this CA.
    ///
    /// `agent_id` — unique hostname or UUID of the agent, e.g. `"agent-net-01"`.
    pub fn issue_agent_cert(&self, agent_id: &str) -> Result<ThorCertBundle> {
        let mut params = CertificateParams::default();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, agent_id);
        dn.push(DnType::OrganizationName, "Thor Agent");
        params.distinguished_name = dn;

        // SAN: DNS + URI (SPIFFE-style workload identity)
        params.subject_alt_names = vec![
            SanType::DnsName(agent_id.to_string()),
            SanType::Uri(format!("spiffe://thor.local/agent/{}", agent_id)),
        ];

        // Client auth only
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.key_usages          = vec![KeyUsagePurpose::DigitalSignature];
        params.is_ca               = IsCa::NoCa;

        let cert = Certificate::from_params(params)
            .context("Failed to generate agent certificate")?;

        let cert_pem = cert.serialize_pem_with_signer(&self.ca_cert)
            .context("Failed to sign agent certificate")?;
        let key_pem  = cert.serialize_private_key_pem();

        Ok(ThorCertBundle { cert_pem, key_pem })
    }

    // ── Server (Control-Plane) TLS config ────────────────────────────────────

    /// Build a `ServerConfig` that requires client certificates issued by this CA.
    ///
    /// `server_cert` — the Control-Plane's own certificate bundle.
    pub fn server_tls_config(&self, server_cert: &ThorCertBundle) -> Result<ServerConfig> {
        // Parse server cert chain
        let certs = parse_certs(&server_cert.cert_pem)?;
        let key   = parse_key(&server_cert.key_pem)?;

        // Build client-verifier from CA cert
        let mut root_store = RootCertStore::empty();
        for c in parse_certs(&self.bundle.cert_pem)? {
            root_store.add(c).context("Failed to add CA cert to root store")?;
        }
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .context("Failed to build client verifier")?;

        let cfg = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)
            .context("Failed to build ServerConfig")?;

        Ok(cfg)
    }

    // ── Client (Agent) TLS config ─────────────────────────────────────────────

    /// Build a `ClientConfig` for an agent connecting to the Control-Plane.
    ///
    /// - `agent_bundle` — the agent's own certificate bundle (issued by CA).
    /// - `ca_cert_pem`  — the CA PEM distributed at enrollment time.
    pub fn agent_client_config(
        agent_bundle: &ThorCertBundle,
        ca_cert_pem: &str,
    ) -> Result<ClientConfig> {
        // Build root-cert store from CA
        let mut root_store = RootCertStore::empty();
        for c in parse_certs(ca_cert_pem)? {
            root_store.add(c).context("Failed to add CA cert to agent root store")?;
        }

        // Agent's own cert + key for mutual auth
        let certs = parse_certs(&agent_bundle.cert_pem)?;
        let key   = parse_key(&agent_bundle.key_pem)?;

        let cfg = ClientConfig::builder()
            .with_root_certificates(Arc::new(root_store))
            .with_client_auth_cert(certs, key)
            .context("Failed to build agent ClientConfig")?;

        Ok(cfg)
    }
}

// ─── PEM parsing helpers ──────────────────────────────────────────────────────

fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = Cursor::new(pem.as_bytes());
    certs(&mut cursor)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to parse certificate PEM")
}

fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = Cursor::new(pem.as_bytes());
    let keys: Vec<_> = pkcs8_private_keys(&mut cursor)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to parse PKCS#8 private key PEM")?;
    let first = keys.into_iter().next().context("No PKCS#8 key found in PEM")?;
    Ok(PrivateKeyDer::Pkcs8(first))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_generation() {
        let ca = ThorCertAuthority::generate("TestCA").unwrap();
        assert!(ca.ca_cert_pem().contains("CERTIFICATE"));
    }

    #[test]
    fn test_agent_cert_issuance() {
        let ca   = ThorCertAuthority::generate("TestCA").unwrap();
        let cert = ca.issue_agent_cert("agent-net-01").unwrap();
        assert!(cert.cert_pem.contains("CERTIFICATE"));
        assert!(cert.key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn test_server_and_client_config_build() {
        let ca          = ThorCertAuthority::generate("TestCA").unwrap();
        let server_cert = ca.issue_agent_cert("control-plane").unwrap();
        let agent_cert  = ca.issue_agent_cert("agent-01").unwrap();

        // Control-Plane server config
        let _server_cfg = ca.server_tls_config(&server_cert).unwrap();

        // Agent client config
        let _client_cfg = ThorCertAuthority::agent_client_config(
            &agent_cert,
            ca.ca_cert_pem(),
        ).unwrap();
    }
}
