pub mod tls {
    use rustls::{ClientConfig, ServerConfig, Certificate, PrivateKey};
    
    // Future mTLS helpers here
    pub fn build_client_config() -> ClientConfig {
        // Will implement mTLS
        ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(std::sync::Arc::new(rustls::client::NoServerCertVerifier)) // TODO: strict mTLS
            .with_no_client_auth()
    }
}
