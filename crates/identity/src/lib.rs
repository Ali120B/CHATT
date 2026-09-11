//! Device identity: one Ed25519 signing key per device.
//!
//! The same 32-byte secret backs three roles:
//!
//! * the long-term **device identity** (signatures, friend-request auth),
//! * the Iroh network endpoint key (so the network ID is the device ID),
//! * key derivation context for the separate X25519 encryption key is
//!   deliberately *independent*: encryption uses its own secret so a signing
//!   oracle can never become a decryption oracle.
//!
//! Secrets live in the OS credential store ([`OsKeyringStore`]) when one is
//! available and fall back to a `0600` file ([`FileStore`]) otherwise.
//! [`load_or_generate`] reports which backend holds the key so the UI can say
//! so honestly instead of claiming "secure enclave" everywhere.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const SERVICE_NAME: &str = "org.hearth.chat";

/// Secrets for one device. Keep out of logs; only pubkeys leave this struct.
#[derive(Clone)]
pub struct DeviceIdentity {
    pub device_id: Uuid,
    pub ed_secret: [u8; 32],
    pub x_secret: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevicePublic {
    pub device_id: Uuid,
    pub ed_pubkey: [u8; 32],
    pub x_pubkey: [u8; 32],
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        Self {
            device_id: Uuid::new_v4(),
            ed_secret: chat_crypto::random_32(),
            x_secret: chat_crypto::random_32(),
        }
    }

    fn ed_signing_key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.ed_secret)
    }

    pub fn public(&self) -> DevicePublic {
        DevicePublic {
            device_id: self.device_id,
            ed_pubkey: self.ed_signing_key().verifying_key().to_bytes(),
            x_pubkey: chat_crypto::x_public_from_secret(&self.x_secret),
        }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.ed_signing_key().sign(message).to_bytes()
    }

    pub fn verify(ed_pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
        use ed25519_dalek::Verifier;
        let key = ed25519_dalek::VerifyingKey::from_bytes(ed_pubkey)
            .map_err(|e| anyhow::anyhow!("bad ed25519 pubkey: {e}"))?;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        key.verify(message, &sig)
            .map_err(|e| anyhow::anyhow!("bad signature: {e}"))
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 64);
        out.extend_from_slice(self.device_id.as_bytes());
        out.extend_from_slice(&self.ed_secret);
        out.extend_from_slice(&self.x_secret);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 80 {
            bail!("device secret has wrong length {}", bytes.len());
        }
        let device_id = Uuid::from_slice(&bytes[..16]).context("device id")?;
        let mut ed_secret = [0u8; 32];
        let mut x_secret = [0u8; 32];
        ed_secret.copy_from_slice(&bytes[16..48]);
        x_secret.copy_from_slice(&bytes[48..80]);
        Ok(Self {
            device_id,
            ed_secret,
            x_secret,
        })
    }
}

// X25519 derivation is owned by chat-crypto (reviewed primitives only);
// identity keeps no crypto of its own beyond the Ed25519 signing key.

/// Which store actually holds the secret. Surfaced to the UI/settings screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyBackend {
    OsKeyring,
    File,
}

/// OS credential store (Secret Service on Linux, Keychain/Credential Manager
/// elsewhere) via the `keyring` crate.
pub struct OsKeyringStore {
    pub service: String,
    pub account: String,
}

impl OsKeyringStore {
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }

    fn entry(&self) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, &self.account).context("open keyring entry")
    }

    pub fn save(&self, identity: &DeviceIdentity) -> Result<()> {
        self.entry()?
            .set_secret(&identity.encode())
            .context("keyring store failed")
    }

    pub fn load(&self) -> Result<Option<DeviceIdentity>> {
        match self.entry()?.get_secret() {
            Ok(bytes) => Ok(Some(DeviceIdentity::decode(&bytes)?)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => anyhow::bail!("keyring load failed: {e}"),
        }
    }
}

/// File fallback with `0600` permissions, used when no OS keyring answers
/// (headless machines, minimal containers) or when the user opts out.
pub struct FileStore {
    pub path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn save(&self, identity: &DeviceIdentity) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        use std::io::Write;
        options.open(&self.path)?.write_all(&identity.encode())?;
        Ok(())
    }

    pub fn load(&self) -> Result<Option<DeviceIdentity>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(DeviceIdentity::decode(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => anyhow::bail!("key file read failed: {e}"),
        }
    }
}

/// Load the device identity, generating and persisting one on first launch.
/// Prefers the OS keyring; falls back to the file store and reports which
/// backend won so settings can display it truthfully.
pub fn load_or_generate(key_dir: &Path) -> Result<(DeviceIdentity, KeyBackend)> {
    let account = "device-identity";
    let os = OsKeyringStore::new(SERVICE_NAME, account);
    match os.load() {
        Ok(Some(identity)) => return Ok((identity, KeyBackend::OsKeyring)),
        Ok(None) => {}
        Err(_) => {}
    }
    let file = FileStore::new(key_dir.join("device.key"));
    if let Some(identity) = file.load()? {
        return Ok((identity, KeyBackend::File));
    }
    let identity = DeviceIdentity::generate();
    // Prefer the keyring for new secrets; only keep the file copy when the
    // keyring refuses to store.
    if os.save(&identity).is_ok() {
        Ok((identity, KeyBackend::OsKeyring))
    } else {
        file.save(&identity)?;
        Ok((identity, KeyBackend::File))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let device = DeviceIdentity::generate();
        let public = device.public();
        let message = b"friend-request:ada>bob";
        let signature = device.sign(message);
        assert!(DeviceIdentity::verify(&public.ed_pubkey, message, &signature).is_ok());
        assert!(DeviceIdentity::verify(&public.ed_pubkey, b"tampered", &signature).is_err());
    }

    #[test]
    fn file_store_roundtrip_with_strict_permissions() {
        let dir = std::env::temp_dir().join(format!("hearth-key-test-{}", Uuid::new_v4()));
        let store = FileStore::new(dir.join("device.key"));
        assert!(store.load().unwrap().is_none());
        let identity = DeviceIdentity::generate();
        store.save(&identity).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&store.path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.device_id, identity.device_id);
        assert_eq!(loaded.ed_secret, identity.ed_secret);
    }

    #[test]
    fn rejects_corrupt_secret_blob() {
        assert!(DeviceIdentity::decode(&[0u8; 10]).is_err());
    }
}
