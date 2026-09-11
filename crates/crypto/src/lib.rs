//! Reviewed-primitive encryption wrappers. No custom constructions.
//!
//! * Direct messages: NaCl `crypto_box` (X25519 + XSalsa20-Poly1305,
//!   authenticated public-key encryption) via the RustCrypto `crypto_box`
//!   crate.
//! * Groups (V1): a random 32-byte group key used with ChaCha20-Poly1305;
//!   the group key itself is distributed wrapped in `crypto_box` to each
//!   member. Membership changes rotate the key (new epoch) so removed members
//!   cannot read future messages. This is standard hybrid encryption from
//!   reviewed primitives; the [`../plan.md`] migration seam to full MLS
//!   (OpenMLS) is tracked for a later phase.
//! * Integrity: SHA-256 manifests for file transfers.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub use crypto_box::{PublicKey as XPublicKey, SecretKey as XSecretKey};

// ---------------------------------------------------------------------------
// X25519 key helpers
// ---------------------------------------------------------------------------

/// Derive the X25519 public key for a 32-byte secret.
pub fn x_public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    let sec = XSecretKey::from(*secret);
    sec.public_key().as_bytes().to_owned()
}

/// OS randomness. Failure here is fatal: there is no safe fallback.
pub fn random_32() -> [u8; 32] {
    use rand::TryRng;
    let mut out = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut out)
        .expect("OS RNG unavailable");
    out
}

pub fn generate_x_secret() -> [u8; 32] {
    random_32()
}

// ---------------------------------------------------------------------------
// Direct-message boxes
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` so only the holder of `recipient_pub` can read it,
/// authenticated as coming from `sender_secret`.
///
/// `crypto_box` accepts no associated data, so `context` (e.g. the
/// conversation id) is length-framed into the plaintext before sealing. The
/// opener must present the identical context, which binds the ciphertext to
/// its conversation and defeats cross-context replay.
pub fn seal_dm(
    sender_secret: &[u8; 32],
    recipient_pub: &[u8; 32],
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    use crypto_box::aead::Aead;
    if context.len() > u16::MAX as usize {
        anyhow::bail!("dm context too long");
    }
    let sender = XSecretKey::from(*sender_secret);
    let recipient = XPublicKey::from(*recipient_pub);
    let seal: crypto_box::SalsaBox = crypto_box::CryptoBox::new(&recipient, &sender);
    let mut nonce_bytes = [0u8; 24];
    {
        use rand::TryRng;
        rand::rngs::SysRng
            .try_fill_bytes(&mut nonce_bytes)
            .expect("OS RNG unavailable");
    }
    let nonce = crypto_box::Nonce::from(nonce_bytes);
    let mut framed = (context.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(context);
    framed.extend_from_slice(plaintext);
    let mut out = nonce_bytes.to_vec();
    let ciphertext = seal
        .encrypt(&nonce, framed.as_slice())
        .map_err(|e| anyhow::anyhow!("dm seal failed: {e}"))?;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a box created by [`seal_dm`], enforcing the expected `context`.
pub fn open_dm(
    recipient_secret: &[u8; 32],
    sender_pub: &[u8; 32],
    expected_context: &[u8],
    boxed: &[u8],
) -> Result<Vec<u8>> {
    use crypto_box::aead::Aead;
    if boxed.len() < 24 {
        anyhow::bail!("dm box too short");
    }
    let recipient = XSecretKey::from(*recipient_secret);
    let sender = XPublicKey::from(*sender_pub);
    let open: crypto_box::SalsaBox = crypto_box::CryptoBox::new(&sender, &recipient);
    let nonce = crypto_box::Nonce::from_slice(&boxed[..24]);
    let framed = open
        .decrypt(nonce, &boxed[24..])
        .map_err(|e| anyhow::anyhow!("dm open failed (wrong key or tampered): {e}"))?;
    if framed.len() < 2 {
        anyhow::bail!("dm frame too short");
    }
    let context_len = u16::from_be_bytes([framed[0], framed[1]]) as usize;
    if framed.len() < 2 + context_len {
        anyhow::bail!("dm frame truncated");
    }
    if &framed[2..2 + context_len] != expected_context {
        anyhow::bail!("dm context mismatch (possible cross-conversation replay)");
    }
    Ok(framed[2 + context_len..].to_vec())
}

// ---------------------------------------------------------------------------
// Group keys (V1 hybrid scheme, MLS migration seam)
// ---------------------------------------------------------------------------

/// A wrapped group key for one member: `crypto_box` sealed by the sender.
pub const GROUP_KEY_CONTEXT: &[u8] = b"hearth/group-key/v1";

pub fn wrap_group_key(
    sender_secret: &[u8; 32],
    member_pub: &[u8; 32],
    group_key: &[u8; 32],
) -> Result<Vec<u8>> {
    seal_dm(sender_secret, member_pub, GROUP_KEY_CONTEXT, group_key)
}

pub fn unwrap_group_key(
    member_secret: &[u8; 32],
    sender_pub: &[u8; 32],
    wrapped: &[u8],
) -> Result<[u8; 32]> {
    let raw = open_dm(member_secret, sender_pub, GROUP_KEY_CONTEXT, wrapped)
        .context("unwrap group key")?;
    if raw.len() != 32 {
        anyhow::bail!("group key has wrong length {}", raw.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn group_nonce(sequence: u64) -> chacha20poly1305::Nonce {
    // 96-bit nonce = 32-bit fixed prefix || 64-bit per-key-unique sequence.
    // The sender's per-conversation sequence is unique per group key epoch,
    // so (key, nonce) pairs never repeat within an epoch.
    let mut bytes = [0u8; 12];
    bytes[..4].copy_from_slice(b"HG1G");
    bytes[4..].copy_from_slice(&sequence.to_be_bytes());
    chacha20poly1305::Nonce::from(bytes)
}

/// Encrypt a group message with the epoch's group key.
pub fn seal_group(group_key: &[u8; 32], sequence: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    use aead06::{Aead, KeyInit, Payload};
    let key: chacha20poly1305::Key = chacha20poly1305::Key::try_from(group_key.as_slice())
        .map_err(|_| anyhow::anyhow!("bad key length"))?;
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(&key);
    let nonce = group_nonce(sequence);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: b"hearth/group/v1",
            },
        )
        .map_err(|e| anyhow::anyhow!("group seal failed: {e}"))?;
    let mut out = nonce.as_slice().to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a group message. The caller supplies the expected sequence so a
/// replayed or reordered ciphertext cannot be silently accepted as another
/// message; mismatches fail authentication.
pub fn open_group(group_key: &[u8; 32], sequence: u64, boxed: &[u8]) -> Result<Vec<u8>> {
    use aead06::{Aead, KeyInit, Payload};
    if boxed.len() < 12 + 16 {
        anyhow::bail!("group box too short");
    }
    let key: chacha20poly1305::Key = chacha20poly1305::Key::try_from(group_key.as_slice())
        .map_err(|_| anyhow::anyhow!("bad key length"))?;
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(&key);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&boxed[..12]);
    let expected = group_nonce(sequence);
    if nonce_bytes.as_slice() != expected.as_slice() {
        anyhow::bail!("group message sequence mismatch (possible replay)");
    }
    let nonce: chacha20poly1305::Nonce = chacha20poly1305::Nonce::try_from(&boxed[..12])
        .map_err(|_| anyhow::anyhow!("bad nonce"))?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &boxed[12..],
                aad: b"hearth/group/v1",
            },
        )
        .map_err(|e| anyhow::anyhow!("group open failed (wrong key or tampered): {e}"))
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex_encode(&sha2::Sha256::digest(data))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkManifest {
    pub chunk_bytes: u32,
    pub chunk_hashes: Vec<String>,
    pub total_bytes: u64,
}

impl ChunkManifest {
    pub fn build(data: &[u8], chunk_bytes: u32) -> Self {
        let mut hashes = Vec::new();
        for chunk in data.chunks(chunk_bytes as usize) {
            hashes.push(sha256_hex(chunk));
        }
        Self {
            chunk_bytes,
            chunk_hashes: hashes,
            total_bytes: data.len() as u64,
        }
    }

    pub fn verify_chunk(&self, index: usize, chunk: &[u8]) -> bool {
        self.chunk_hashes
            .get(index)
            .map(|h| *h == sha256_hex(chunk))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dm_roundtrip() {
        let alice = generate_x_secret();
        let bob = generate_x_secret();
        let bob_pub = x_public_from_secret(&bob);
        let alice_pub = x_public_from_secret(&alice);
        let boxed = seal_dm(&alice, &bob_pub, b"conv-1", b"hello bob").unwrap();
        let opened = open_dm(&bob, &alice_pub, b"conv-1", &boxed).unwrap();
        assert_eq!(opened, b"hello bob");
    }

    #[test]
    fn dm_rejects_tampered_ciphertext() {
        let alice = generate_x_secret();
        let bob = generate_x_secret();
        let bob_pub = x_public_from_secret(&bob);
        let alice_pub = x_public_from_secret(&alice);
        let mut boxed = seal_dm(&alice, &bob_pub, b"conv-1", b"hello").unwrap();
        let last = boxed.len() - 1;
        boxed[last] ^= 0x01;
        assert!(open_dm(&bob, &alice_pub, b"conv-1", &boxed).is_err());
    }

    #[test]
    fn dm_rejects_wrong_recipient() {
        let alice = generate_x_secret();
        let bob = generate_x_secret();
        let mallory = generate_x_secret();
        let bob_pub = x_public_from_secret(&bob);
        let alice_pub = x_public_from_secret(&alice);
        let boxed = seal_dm(&alice, &bob_pub, b"conv-1", b"hello").unwrap();
        assert!(open_dm(&mallory, &alice_pub, b"conv-1", &boxed).is_err());
    }

    #[test]
    fn group_key_wrap_and_message_roundtrip() {
        let alice = generate_x_secret();
        let bob = generate_x_secret();
        let bob_pub = x_public_from_secret(&bob);
        let alice_pub = x_public_from_secret(&alice);
        let group_key = random_32();
        let wrapped = wrap_group_key(&alice, &bob_pub, &group_key).unwrap();
        let unwrapped = unwrap_group_key(&bob, &alice_pub, &wrapped).unwrap();
        assert_eq!(unwrapped, group_key);
        let sealed = seal_group(&group_key, 7, b"group hello").unwrap();
        assert_eq!(open_group(&group_key, 7, &sealed).unwrap(), b"group hello");
        assert!(open_group(&group_key, 8, &sealed).is_err());
    }

    #[test]
    fn chunk_manifest_detects_corruption() {
        let data = b"The quick brown fox jumps over the lazy dog".repeat(100);
        let manifest = ChunkManifest::build(&data, 64);
        assert!(manifest.verify_chunk(0, &data[..64]));
        let mut bad = data[..64].to_vec();
        bad[0] ^= 1;
        assert!(!manifest.verify_chunk(0, &bad));
        assert!(!manifest.verify_chunk(9999, &data[..64]));
    }
}
