use anyhow::{Context, Result};
use rcgen::generate_simple_self_signed;
use std::fs;
use std::path::Path;

pub fn ensure_self_signed_cert(cert_path: &Path, key_path: &Path) -> Result<()> {
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }

    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let subject_alt_names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];

    let cert = generate_simple_self_signed(subject_alt_names)
        .context("Failed to generate self-signed certificate")?;

    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    fs::write(cert_path, cert_pem).context("Failed to write TLS certificate file")?;
    fs::write(key_path, key_pem).context("Failed to write TLS private key file")?;

    Ok(())
}
