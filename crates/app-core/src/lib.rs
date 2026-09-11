//! Product-facing state transitions for Hearth.
//!
//! Design rules enforced here:
//!
//! * Every outbound message is persisted to SQLite **before** transport is
//!   attempted, and retries reuse the same message id (idempotent sync).
//! * Envelopes are Ed25519-signed by the sending device; chat content from
//!   unknown devices is rejected — DMs/groups are friend-gated.
//! * Typing and presence state never touch SQLite ([`presence`]).
//! * This crate performs no I/O itself (no sockets, no HTTP). Network effects
//!   are expressed as [`OutboundWork`] values that the Tauri shell executes,
//!   which keeps all of this unit-testable.

pub mod files;
pub mod friends;
pub mod groups;
pub mod presence;
pub mod sync;

use anyhow::{Context, Result, bail};
use chat_database::{Database, Message};
use chat_identity::DeviceIdentity;
use chat_protocol::{CURRENT_PROTOCOL_VERSION, MessageType, ProtocolEnvelope};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Validation (Phase 2)
// ---------------------------------------------------------------------------

pub fn normalize_username(raw: &str) -> Result<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.len() < 3
        || normalized.len() > 32
        || !normalized
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
    {
        bail!("Username must be 3–32 lowercase letters, numbers, or underscores.");
    }
    const RESERVED: &[&str] = &["system", "admin", "hearth", "support", "null", "unknown"];
    if RESERVED.contains(&normalized.as_str()) {
        bail!("That username is reserved.");
    }
    Ok(normalized)
}

pub fn validate_display_name(raw: &str) -> Result<String> {
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() || trimmed.chars().count() > 64 {
        bail!("Display name must be between 1 and 64 characters.");
    }
    Ok(trimmed)
}

pub fn create_profile(
    database: &Database,
    username: &str,
    display_name: &str,
    now_ms: i64,
) -> Result<()> {
    let normalized = normalize_username(username)?;
    let display = validate_display_name(display_name)?;
    database.save_profile(&normalized, &display, now_ms)
}

// ---------------------------------------------------------------------------
// Encrypted chat payloads (Phase 5)
// ---------------------------------------------------------------------------

/// Plaintext content model. Always serialized then sealed (DM key or group
/// key) before it becomes envelope ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChatPayload {
    Text {
        from: String,
        body: String,
        reply_to: Option<String>,
        epoch: Option<i64>,
    },
    Edit {
        from: String,
        ref_id: String,
        body: String,
        epoch: Option<i64>,
    },
    Delete {
        from: String,
        ref_id: String,
        epoch: Option<i64>,
    },
    Read {
        from: String,
        ref_ids: Vec<String>,
    },
    Typing {
        from: String,
        typing: bool,
    },
    /// Carries one member's wrapped group key for an epoch rotation.
    GroupKey {
        from: String,
        group_id: String,
        epoch: i64,
        members: Vec<String>,
        group_name: String,
        /// crypto_box wrap of the epoch key, sealed for exactly one member.
        wrapped_key: Vec<u8>,
        wrapper_x_pub_hex: String,
    },
    GroupMeta {
        from: String,
        group_id: String,
        name: String,
        epoch: Option<i64>,
    },
    FileOffer {
        from: String,
        file: files::FileOfferBody,
    },
    FileChunk {
        from: String,
        file_id: String,
        index: u32,
        data: Vec<u8>,
    },
    FileAccept {
        from: String,
        file_id: String,
        have: Vec<u32>,
    },
    FileCancel {
        from: String,
        file_id: String,
    },
    SyncRequest {
        from: String,
        conversation_id: String,
        after_sequence: i64,
    },
    FriendAsk {
        from: String,
        display_name: String,
        ed_pubkey_hex: String,
        x_pubkey_hex: String,
        endpoint_bundle: String,
    },
    FriendAnswer {
        from: String,
        accepted: bool,
        endpoint_bundle: String,
    },
    Presence {
        from: String,
        status: PresenceStatus,
    },
}

/// Presence state. `Offline` is never sent — it is derived locally when no
/// transport or fresh heartbeat exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresenceStatus {
    Online,
    Away,
    Dnd,
    Offline,
}

impl PresenceStatus {
    pub fn label(self) -> &'static str {
        match self {
            PresenceStatus::Online => "online",
            PresenceStatus::Away => "away",
            PresenceStatus::Dnd => "do not disturb",
            PresenceStatus::Offline => "offline",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "online" => Some(PresenceStatus::Online),
            "away" => Some(PresenceStatus::Away),
            "dnd" | "do not disturb" | "disturb" => Some(PresenceStatus::Dnd),
            _ => None,
        }
    }
}

impl ChatPayload {
    /// Epoch hint carried by group-channel payloads (None on DMs).
    pub fn epoch(&self) -> Option<i64> {
        match self {
            ChatPayload::Text { epoch, .. }
            | ChatPayload::Edit { epoch, .. }
            | ChatPayload::Delete { epoch, .. }
            | ChatPayload::GroupMeta { epoch, .. } => *epoch,
            _ => None,
        }
    }

    pub fn sender(&self) -> &str {
        match self {
            ChatPayload::Text { from, .. }
            | ChatPayload::Edit { from, .. }
            | ChatPayload::Delete { from, .. }
            | ChatPayload::Read { from, .. }
            | ChatPayload::Typing { from, .. }
            | ChatPayload::GroupKey { from, .. }
            | ChatPayload::GroupMeta { from, .. }
            | ChatPayload::FileOffer { from, .. }
            | ChatPayload::FileChunk { from, .. }
            | ChatPayload::FileAccept { from, .. }
            | ChatPayload::FileCancel { from, .. }
            | ChatPayload::SyncRequest { from, .. }
            | ChatPayload::FriendAsk { from, .. }
            | ChatPayload::FriendAnswer { from, .. }
            | ChatPayload::Presence { from, .. } => from,
        }
    }

    pub fn message_type(&self) -> MessageType {
        match self {
            ChatPayload::Text { .. } => MessageType::Message,
            ChatPayload::Edit { .. } => MessageType::MessageEdit,
            ChatPayload::Delete { .. } => MessageType::MessageDelete,
            ChatPayload::Read { .. } => MessageType::ReadAck,
            ChatPayload::Typing { .. } => MessageType::Typing,
            ChatPayload::GroupKey { .. } => MessageType::GroupCommit,
            ChatPayload::GroupMeta { .. } => MessageType::GroupMessage,
            ChatPayload::FileOffer { .. } => MessageType::FileOffer,
            ChatPayload::FileChunk { .. } => MessageType::FileChunk,
            ChatPayload::FileAccept { .. } => MessageType::FileAccept,
            ChatPayload::FileCancel { .. } => MessageType::FileComplete,
            ChatPayload::SyncRequest { .. } => MessageType::SyncRequest,
            ChatPayload::FriendAsk { .. } => MessageType::FriendRequest,
            ChatPayload::FriendAnswer { .. } => MessageType::FriendResponse,
            ChatPayload::Presence { .. } => MessageType::Presence,
        }
    }
}

/// Work the shell must perform on the network for one stored message.
#[derive(Debug, Clone)]
pub struct OutboundWork {
    /// Username of the intended recipient (DM peer or group member).
    pub peer_username: String,
    pub envelope: ProtocolEnvelope,
}

/// Lowercase hex encode/decode for key material in invites and directory records.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn hex_decode_32(hex: &str) -> Result<[u8; 32]> {
    let text = hex.trim();
    if text.len() != 64 {
        anyhow::bail!("expected 32-byte hex");
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)
            .map_err(|_| anyhow::anyhow!("bad hex"))?;
    }
    Ok(out)
}

/// Bytes covered by the envelope signature.
pub fn envelope_sign_bytes(envelope: &ProtocolEnvelope) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(envelope.message_id.as_bytes());
    bytes.extend_from_slice(envelope.conversation_id.as_bytes());
    bytes.extend_from_slice(format!("{:?}", envelope.message_type).as_bytes());
    bytes.extend_from_slice(&envelope.sequence.to_be_bytes());
    bytes.extend_from_slice(&envelope.ciphertext);
    bytes
}

pub fn sign_envelope(identity: &DeviceIdentity, envelope: &mut ProtocolEnvelope) {
    let bytes = envelope_sign_bytes(envelope);
    envelope.sender_sig = identity.sign(&bytes).to_vec();
}

pub fn verify_envelope_signature(ed_pubkey: &[u8; 32], envelope: &ProtocolEnvelope) -> Result<()> {
    if envelope.sender_sig.len() != 64 {
        bail!("missing envelope signature");
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&envelope.sender_sig);
    DeviceIdentity::verify(ed_pubkey, &envelope_sign_bytes(envelope), &sig)
}

/// Seal a payload for a DM peer. `conversation_id` binds the ciphertext to
/// its conversation (cross-conversation replay fails to open).
pub fn seal_dm_payload(
    sender_secret: &[u8; 32],
    recipient_pub: &[u8; 32],
    conversation_id: &str,
    payload: &ChatPayload,
) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(payload)?;
    chat_crypto::seal_dm(
        sender_secret,
        recipient_pub,
        conversation_id.as_bytes(),
        &json,
    )
}

pub fn open_dm_payload(
    recipient_secret: &[u8; 32],
    sender_pub: &[u8; 32],
    conversation_id: &str,
    boxed: &[u8],
) -> Result<ChatPayload> {
    let json = chat_crypto::open_dm(
        recipient_secret,
        sender_pub,
        conversation_id.as_bytes(),
        boxed,
    )?;
    serde_json::from_slice(&json).context("bad dm payload")
}

/// Seal a presence heartbeat for one friend. The context names both parties
/// (`presence:{from}>{to}`) so heartbeats cannot be replayed at a third user.
pub fn seal_presence_payload(
    sender_secret: &[u8; 32],
    recipient_pub: &[u8; 32],
    from: &str,
    to: &str,
    status: PresenceStatus,
) -> Result<Vec<u8>> {
    let payload = ChatPayload::Presence {
        from: from.to_string(),
        status,
    };
    let json = serde_json::to_vec(&payload)?;
    let context = format!("presence:{from}>{to}");
    chat_crypto::seal_dm(sender_secret, recipient_pub, context.as_bytes(), &json)
}

pub fn open_presence_payload(
    recipient_secret: &[u8; 32],
    sender_pub: &[u8; 32],
    from: &str,
    to: &str,
    boxed: &[u8],
) -> Result<ChatPayload> {
    let context = format!("presence:{from}>{to}");
    let json = chat_crypto::open_dm(recipient_secret, sender_pub, context.as_bytes(), boxed)?;
    let payload: ChatPayload = serde_json::from_slice(&json).context("bad presence payload")?;
    match payload {
        ChatPayload::Presence { .. } => Ok(payload),
        _ => anyhow::bail!("not a presence payload"),
    }
}

/// Seal a payload with the group's epoch key.
pub fn seal_group_payload(
    group_key: &[u8; 32],
    sequence: u64,
    payload: &ChatPayload,
) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(payload)?;
    chat_crypto::seal_group(group_key, sequence, &json)
}

pub fn open_group_payload(
    group_key: &[u8; 32],
    sequence: u64,
    boxed: &[u8],
) -> Result<ChatPayload> {
    let json = chat_crypto::open_group(group_key, sequence, boxed)?;
    serde_json::from_slice(&json).context("bad group payload")
}

#[allow(clippy::too_many_arguments)] // domain params stay explicit; no context-object indirection
pub fn build_envelope(
    identity: &DeviceIdentity,
    device_uuid: Uuid,
    conversation_id: Uuid,
    message_id: Uuid,
    message_type: MessageType,
    sequence: u64,
    ciphertext: Vec<u8>,
    now_ms: i64,
) -> ProtocolEnvelope {
    let mut envelope = ProtocolEnvelope {
        version: CURRENT_PROTOCOL_VERSION,
        message_id,
        conversation_id,
        sender_device_id: device_uuid,
        message_type,
        sequence,
        created_at_ms: now_ms,
        ciphertext,
        sender_sig: Vec::new(),
    };
    sign_envelope(identity, &mut envelope);
    envelope
}

/// Persist-then-return: store the plaintext locally and hand the caller the
/// envelope plus per-recipient outbound work. The caller sends, then flips
/// the row to delivered/queued.
#[allow(clippy::too_many_arguments)] // domain params stay explicit; no context-object indirection
pub fn stage_message(
    db: &Database,
    identity: &DeviceIdentity,
    device_uuid: Uuid,
    my_username: &str,
    conversation: &chat_database::Conversation,
    payload: &ChatPayload,
    body_preview: &str,
    ciphertext: Vec<u8>,
    now_ms: i64,
) -> Result<(Message, ProtocolEnvelope)> {
    let message_id = Uuid::new_v4();
    let conversation_uuid = Uuid::parse_str(&conversation.id).unwrap_or_else(|_| Uuid::new_v4());
    let sequence = db.next_sequence(&conversation.id, &device_uuid.to_string())?;
    let envelope = build_envelope(
        identity,
        device_uuid,
        conversation_uuid,
        message_id,
        payload.message_type(),
        sequence as u64,
        ciphertext,
        now_ms,
    );
    let message = Message {
        id: message_id.to_string(),
        conversation_id: conversation.id.clone(),
        sender_device_id: device_uuid.to_string(),
        sender_username: my_username.to_string(),
        message_type: format!("{:?}", payload.message_type()),
        body: body_preview.to_string(),
        ciphertext: envelope.ciphertext.clone(),
        sequence,
        status: "local".to_string(),
        reply_to: match payload {
            ChatPayload::Text { reply_to, .. } => reply_to.clone(),
            _ => None,
        },
        created_at_ms: now_ms,
        edited_at_ms: None,
        deleted_at_ms: None,
    };
    db.insert_message(&message)?;
    Ok((message, envelope))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_identity_setup() {
        let db = Database::in_memory().unwrap();
        assert!(create_profile(&db, "Ada", "Ada Lovelace", 0).is_ok());
        assert!(create_profile(&db, "?", "Ada", 0).is_err());
        assert!(create_profile(&db, "admin", "Admin", 0).is_err());
        assert_eq!(normalize_username("  BOB_99 ").unwrap(), "bob_99");
    }

    #[test]
    fn dm_payload_seal_open_roundtrip() {
        let alice = chat_crypto::generate_x_secret();
        let bob = chat_crypto::generate_x_secret();
        let bob_pub = chat_crypto::x_public_from_secret(&bob);
        let alice_pub = chat_crypto::x_public_from_secret(&alice);
        let payload = ChatPayload::Text {
            from: "ada".into(),
            body: "hi".into(),
            reply_to: None,
            epoch: None,
        };
        let sealed = seal_dm_payload(&alice, &bob_pub, "conv-1", &payload).unwrap();
        assert_eq!(
            open_dm_payload(&bob, &alice_pub, "conv-1", &sealed).unwrap(),
            payload
        );
        assert!(open_dm_payload(&bob, &alice_pub, "conv-other", &sealed).is_err());
    }

    #[test]
    fn presence_payload_roundtrip_with_named_context() {
        let alice = chat_crypto::generate_x_secret();
        let bob = chat_crypto::generate_x_secret();
        let bob_pub = chat_crypto::x_public_from_secret(&bob);
        let alice_pub = chat_crypto::x_public_from_secret(&alice);
        let sealed =
            seal_presence_payload(&alice, &bob_pub, "ada", "bob", PresenceStatus::Away).unwrap();
        let opened = open_presence_payload(&bob, &alice_pub, "ada", "bob", &sealed).unwrap();
        match opened {
            ChatPayload::Presence { from, status } => {
                assert_eq!(from, "ada");
                assert_eq!(status, PresenceStatus::Away);
            }
            _ => panic!("expected presence"),
        }
        // Retargeted at a third user fails to open.
        assert!(open_presence_payload(&bob, &alice_pub, "ada", "mallory", &sealed).is_err());
    }

    #[test]
    fn envelope_signature_verifies_and_rejects_tampering() {
        let device = DeviceIdentity::generate();
        let public = device.public();
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&public.ed_pubkey);
        let mut envelope = build_envelope(
            &device,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            MessageType::Message,
            1,
            vec![9, 9],
            5,
        );
        assert!(verify_envelope_signature(&ed, &envelope).is_ok());
        envelope.ciphertext.push(1);
        assert!(verify_envelope_signature(&ed, &envelope).is_err());
    }
}
