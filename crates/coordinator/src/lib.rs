#![allow(async_fn_in_trait)] // trait is closed-crate by design (see AnyCoordinator); no auto-trait bounds needed
//! Coordination: username directory, device records, friend-request
//! metadata, endpoint discovery, and the encrypted offline mailbox.
//!
//! The [`Coordinator`] trait keeps the cloud replaceable (plan constraint
//! 11). Two implementations ship:
//!
//! * [`LocalCoordinator`] — works with no account and no network: a JSON
//!   directory file plus the local SQLite mailbox spool. Remote peers are
//!   added through invite codes exchanged out of band. Direct P2P still works
//!   when both sides are online; offline delivery to a *remote* peer needs a
//!   shared coordinator.
//! * [`CloudflareCoordinator`] — HTTP client for the Worker in
//!   `cloud/worker`. Deploy it with `wrangler` and point the app at the URL;
//!   the server only ever sees ciphertext, key material never leaves the
//!   device.
//!
//! Nothing here handles plaintext messages: mailbox payloads are serialized
//! [`chat_protocol::ProtocolEnvelope`] values, which are ciphertext-only by
//! construction.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Public directory entry for one user. Alias, not identity proof: callers
/// must verify `ed_pubkey` out of band (invite code) or via trust-on-first-use
/// prompts before sending anything sensitive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryRecord {
    pub username: String,
    pub display_name: String,
    pub ed_pubkey_hex: String,
    pub x_pubkey_hex: String,
    pub endpoint_id: String,
    /// Serialized endpoint address bundle (JSON `EndpointAddr`, base64url).
    /// Opaque to the coordinator.
    pub endpoint_bundle: String,
    pub updated_at_ms: i64,
}

/// Ciphertext mailbox object waiting for an offline recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxObject {
    pub id: String,
    pub envelope_json: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

/// Pending friend-request metadata (no message content).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendDirective {
    pub id: String,
    pub from_username: String,
    pub from_display_name: String,
    pub from_ed_pubkey_hex: String,
    pub from_x_pubkey_hex: String,
    pub status: String,
    pub created_at_ms: i64,
}

pub const MAILBOX_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;

pub trait Coordinator: Send + Sync {
    fn name(&self) -> &'static str;
    async fn register(&self, record: &DirectoryRecord) -> Result<()>;
    async fn lookup(&self, username: &str) -> Result<Option<DirectoryRecord>>;
    async fn publish_friend_request(
        &self,
        directive: &FriendDirective,
        to_username: &str,
    ) -> Result<()>;
    async fn fetch_friend_requests(&self, username: &str) -> Result<Vec<FriendDirective>>;
    async fn mailbox_put(&self, to_username: &str, object: &MailboxObject) -> Result<()>;
    async fn mailbox_get(&self, username: &str, now_ms: i64) -> Result<Vec<MailboxObject>>;
    async fn mailbox_ack(&self, username: &str, id: &str) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Local coordinator
// ---------------------------------------------------------------------------

/// Zero-account coordinator. The directory is a JSON file on this machine;
/// the mailbox only holds objects addressed to the local user (loopback and
/// LAN-drop use), because without a shared server there is nowhere else to
/// leave them. `mailbox_put` to any other recipient fails loudly instead of
/// pretending delivery worked.
pub struct LocalCoordinator {
    pub dir: PathBuf,
    pub owner_username: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LocalDirectory {
    users: HashMap<String, DirectoryRecord>,
    requests: HashMap<String, Vec<FriendDirective>>,
}

impl LocalCoordinator {
    pub fn new(dir: impl AsRef<Path>, owner_username: &str) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
            owner_username: owner_username.to_string(),
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.join("coordinator.json")
    }

    fn read(&self) -> Result<LocalDirectory> {
        match std::fs::read_to_string(self.path()) {
            Ok(text) => serde_json::from_str(&text).context("parse local directory"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(LocalDirectory::default()),
            Err(e) => Err(e).context("read local directory"),
        }
    }

    fn write(&self, directory: &LocalDirectory) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(self.path(), serde_json::to_vec_pretty(directory)?)?;
        Ok(())
    }
}

impl Coordinator for LocalCoordinator {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn register(&self, record: &DirectoryRecord) -> Result<()> {
        let mut directory = self.read()?;
        directory
            .users
            .insert(record.username.clone(), record.clone());
        self.write(&directory)
    }

    async fn lookup(&self, username: &str) -> Result<Option<DirectoryRecord>> {
        Ok(self.read()?.users.get(username).cloned())
    }

    async fn publish_friend_request(
        &self,
        directive: &FriendDirective,
        to_username: &str,
    ) -> Result<()> {
        if to_username != self.owner_username {
            anyhow::bail!(
                "local coordinator has no shared server: deliver the invite code for @{to_username} directly (friend request saved locally only)"
            );
        }
        let mut directory = self.read()?;
        directory
            .requests
            .entry(to_username.to_string())
            .or_default()
            .push(directive.clone());
        self.write(&directory)
    }

    async fn fetch_friend_requests(&self, username: &str) -> Result<Vec<FriendDirective>> {
        Ok(self
            .read()?
            .requests
            .get(username)
            .cloned()
            .unwrap_or_default())
    }

    async fn mailbox_put(&self, to_username: &str, _object: &MailboxObject) -> Result<()> {
        if to_username != self.owner_username {
            anyhow::bail!(
                "recipient @{to_username} is offline and no shared mailbox is configured; message stays queued"
            );
        }
        Ok(())
    }

    async fn mailbox_get(&self, _username: &str, _now_ms: i64) -> Result<Vec<MailboxObject>> {
        // Local spool reads go through SQLite (`mailbox_spool`); there is no
        // second server-side store in local mode.
        Ok(Vec::new())
    }

    async fn mailbox_ack(&self, _username: &str, _id: &str) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Cloudflare coordinator (HTTP client for cloud/worker)
// ---------------------------------------------------------------------------

/// Client for a deployed Hearth Worker. All payloads remain ciphertext; the
/// worker maps usernames to endpoint bundles and holds encrypted mailbox
/// objects until they expire or are acknowledged.
pub struct CloudflareCoordinator {
    pub base_url: String,
    client: reqwest::Client,
}

impl CloudflareCoordinator {
    pub fn new(base_url: &str) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .context("build http client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

impl Coordinator for CloudflareCoordinator {
    fn name(&self) -> &'static str {
        "cloudflare"
    }

    async fn register(&self, record: &DirectoryRecord) -> Result<()> {
        let response = self
            .client
            .post(self.url("/v1/directory"))
            .json(record)
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("directory register failed: {}", response.status());
        }
        Ok(())
    }

    async fn lookup(&self, username: &str) -> Result<Option<DirectoryRecord>> {
        let response = self
            .client
            .get(self.url(&format!("/v1/directory/{username}")))
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            anyhow::bail!("directory lookup failed: {}", response.status());
        }
        Ok(Some(response.json().await?))
    }

    async fn publish_friend_request(
        &self,
        directive: &FriendDirective,
        to_username: &str,
    ) -> Result<()> {
        let response = self
            .client
            .post(self.url(&format!("/v1/friends/{to_username}/requests")))
            .json(directive)
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("friend request publish failed: {}", response.status());
        }
        Ok(())
    }

    async fn fetch_friend_requests(&self, username: &str) -> Result<Vec<FriendDirective>> {
        let response = self
            .client
            .get(self.url(&format!("/v1/friends/{username}/requests")))
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("friend request fetch failed: {}", response.status());
        }
        Ok(response.json().await?)
    }

    async fn mailbox_put(&self, to_username: &str, object: &MailboxObject) -> Result<()> {
        let response = self
            .client
            .post(self.url(&format!("/v1/mailbox/{to_username}")))
            .json(object)
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("mailbox put failed: {}", response.status());
        }
        Ok(())
    }

    async fn mailbox_get(&self, username: &str, _now_ms: i64) -> Result<Vec<MailboxObject>> {
        let response = self
            .client
            .get(self.url(&format!("/v1/mailbox/{username}")))
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("mailbox get failed: {}", response.status());
        }
        Ok(response.json().await?)
    }

    async fn mailbox_ack(&self, username: &str, id: &str) -> Result<()> {
        let response = self
            .client
            .delete(self.url(&format!("/v1/mailbox/{username}/{id}")))
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("mailbox ack failed: {}", response.status());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Invite codes (no mandatory IP exchange)
// ---------------------------------------------------------------------------

/// Self-contained invite: identity + current endpoint bundle, exchanged out of
/// band (QR, copy/paste). The recipient gets cryptographic identity AND a
/// network address without either side typing an IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCode {
    pub username: String,
    pub display_name: String,
    pub ed_pubkey_hex: String,
    pub x_pubkey_hex: String,
    pub endpoint_id: String,
    pub endpoint_bundle: String,
}

impl InviteCode {
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self)?;
        Ok(format!("hearth1{}", base64_url(&json)))
    }

    pub fn decode(code: &str) -> Result<Self> {
        let payload = code
            .strip_prefix("hearth1")
            .context("not a hearth invite code")?;
        let json = unbase64_url(payload)?;
        serde_json::from_slice(&json).context("bad invite payload")
    }
}

fn base64_url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut n = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            n |= (*b as u32) << (16 - 8 * i);
        }
        let chars = (chunk.len() * 8).div_ceil(6);
        for i in 0..chars {
            let shift = 18 - 6 * i;
            out.push(ALPHABET[((n >> shift) & 63) as usize] as char);
        }
    }
    out
}

fn unbase64_url(text: &str) -> Result<Vec<u8>> {
    let mut values = Vec::with_capacity(text.len());
    for c in text.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '-' => 62,
            '_' => 63,
            _ => anyhow::bail!("bad base64url char"),
        };
        values.push(v);
    }
    let mut out = Vec::new();
    for chunk in values.chunks(4) {
        let mut n = 0u32;
        for (i, v) in chunk.iter().enumerate() {
            n |= v << (18 - 6 * i);
        }
        let bytes = chunk.len() * 6 / 8;
        for i in 0..bytes {
            out.push(((n >> (16 - 8 * i)) & 0xFF) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("hearth-coord-{name}-{}", uuid::Uuid::new_v4()))
    }

    fn record(username: &str) -> DirectoryRecord {
        DirectoryRecord {
            username: username.into(),
            display_name: "Test".into(),
            ed_pubkey_hex: "aa".into(),
            x_pubkey_hex: "bb".into(),
            endpoint_id: "node1".into(),
            endpoint_bundle: "bundle".into(),
            updated_at_ms: 1,
        }
    }

    #[tokio::test]
    async fn local_register_and_lookup() {
        let coord = LocalCoordinator::new(test_dir("reg"), "ada");
        assert!(coord.lookup("bob").await.unwrap().is_none());
        coord.register(&record("bob")).await.unwrap();
        assert_eq!(
            coord.lookup("bob").await.unwrap().unwrap().endpoint_id,
            "node1"
        );
    }

    #[tokio::test]
    async fn local_remote_mailbox_fails_loudly() {
        let coord = LocalCoordinator::new(test_dir("mbox"), "ada");
        let object = MailboxObject {
            id: "m1".into(),
            envelope_json: "{}".into(),
            created_at_ms: 1,
            expires_at_ms: 99,
        };
        assert!(coord.mailbox_put("bob", &object).await.is_err());
        assert!(coord.mailbox_put("ada", &object).await.is_ok());
    }

    #[test]
    fn invite_code_roundtrip() {
        let invite = InviteCode {
            username: "ada".into(),
            display_name: "Ada".into(),
            ed_pubkey_hex: "aa".into(),
            x_pubkey_hex: "bb".into(),
            endpoint_id: "node1".into(),
            endpoint_bundle: "bund-le_/~data".into(),
        };
        let code = invite.encode().unwrap();
        assert!(code.starts_with("hearth1"));
        let decoded = InviteCode::decode(&code).unwrap();
        assert_eq!(decoded.username, "ada");
        assert_eq!(decoded.endpoint_bundle, "bund-le_/~data");
        assert!(InviteCode::decode("nope").is_err());
    }
}
