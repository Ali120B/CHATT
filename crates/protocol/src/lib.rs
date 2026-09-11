//! Versioned application envelopes shared by every transport.
//!
//! Encryption is deliberately outside this crate: transports receive
//! ciphertext only. The [`ProtocolEnvelope::validate`] gate rejects
//! unsupported versions and empty ciphertext so a missing encryption layer
//! can never be mistaken for a working one.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const CURRENT_PROTOCOL_VERSION: u16 = 1;

/// ALPN identifying the Hearth chat protocol on an Iroh connection.
pub const HEARTH_ALPN: &[u8] = b"hearth/chat/1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolEnvelope {
    pub version: u16,
    pub message_id: Uuid,
    pub conversation_id: Uuid,
    pub sender_device_id: Uuid,
    pub message_type: MessageType,
    pub sequence: u64,
    pub created_at_ms: i64,
    /// Authenticated ciphertext. Plaintext never belongs in an envelope.
    pub ciphertext: Vec<u8>,
    /// Ed25519 signature over the envelope (message_id, conversation_id,
    /// sequence, message_type, ciphertext). Empty only for pre-auth
    /// handshake frames; the app layer rejects unsigned chat content.
    #[serde(default)]
    pub sender_sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageType {
    Hello,
    Identity,
    Auth,
    Ping,
    Pong,
    FriendRequest,
    FriendResponse,
    Message,
    MessageEdit,
    MessageDelete,
    MessageReply,
    DeliveryAck,
    ReadAck,
    Typing,
    Presence,
    SyncRequest,
    SyncResponse,
    GroupCommit,
    GroupMessage,
    GroupSync,
    FileOffer,
    FileAccept,
    FileChunk,
    FileAck,
    FileComplete,
    Error,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("ciphertext must not be empty")]
    EmptyCiphertext,
}

impl ProtocolEnvelope {
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.version != CURRENT_PROTOCOL_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(self.version));
        }
        if self.ciphertext.is_empty() {
            return Err(EnvelopeError::EmptyCiphertext);
        }
        Ok(())
    }

    /// Length-prefixed binary framing used on QUIC streams.
    pub fn encode_frame(&self) -> anyhow::Result<Vec<u8>> {
        let body = serde_json::to_vec(self)?;
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    pub fn decode_frame(len_prefix: [u8; 4], body: &[u8]) -> anyhow::Result<Self> {
        let len = u32::from_be_bytes(len_prefix) as usize;
        anyhow::ensure!(
            len == body.len(),
            "frame length prefix {len} does not match body {}",
            body.len()
        );
        let envelope: Self = serde_json::from_slice(body)?;
        envelope.validate()?;
        Ok(envelope)
    }
}

impl MessageType {
    /// Ephemeral frames never touch SQLite history.
    pub fn is_ephemeral(&self) -> bool {
        matches!(
            self,
            MessageType::Typing | MessageType::Ping | MessageType::Pong | MessageType::Presence
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn envelope() -> ProtocolEnvelope {
        ProtocolEnvelope {
            version: CURRENT_PROTOCOL_VERSION,
            message_id: Uuid::new_v4(),
            conversation_id: Uuid::new_v4(),
            sender_device_id: Uuid::new_v4(),
            message_type: MessageType::Message,
            sequence: 1,
            created_at_ms: 0,
            ciphertext: vec![1],
            sender_sig: vec![7],
        }
    }
    #[test]
    fn accepts_current_ciphertext_envelope() {
        assert_eq!(envelope().validate(), Ok(()));
    }
    #[test]
    fn rejects_plaintext_placeholder() {
        let mut value = envelope();
        value.ciphertext.clear();
        assert_eq!(value.validate(), Err(EnvelopeError::EmptyCiphertext));
    }
    #[test]
    fn rejects_unknown_version() {
        let mut value = envelope();
        value.version = CURRENT_PROTOCOL_VERSION + 1;
        assert_eq!(
            value.validate(),
            Err(EnvelopeError::UnsupportedVersion(
                CURRENT_PROTOCOL_VERSION + 1
            ))
        );
    }
    #[test]
    fn unsigned_envelope_defaults_sig_to_empty() {
        let mut json = serde_json::to_vec(&envelope()).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        value.as_object_mut().unwrap().remove("sender_sig");
        json = serde_json::to_vec(&value).unwrap();
        let decoded: ProtocolEnvelope = serde_json::from_slice(&json).unwrap();
        assert!(decoded.sender_sig.is_empty());
    }
    #[test]
    fn frame_roundtrip_preserves_envelope() {
        let original = envelope();
        let frame = original.encode_frame().unwrap();
        let (prefix, body) = frame.split_at(4);
        let decoded = ProtocolEnvelope::decode_frame(prefix.try_into().unwrap(), body).unwrap();
        assert_eq!(original, decoded);
    }
    #[test]
    fn frame_rejects_length_mismatch() {
        let original = envelope();
        let frame = original.encode_frame().unwrap();
        let (prefix, body) = frame.split_at(4);
        assert!(
            ProtocolEnvelope::decode_frame(prefix.try_into().unwrap(), &body[..body.len() - 1])
                .is_err()
        );
    }
    #[test]
    fn frame_rejects_empty_ciphertext() {
        let mut tampered = envelope();
        tampered.ciphertext.clear();
        let body = serde_json::to_vec(&tampered).unwrap();
        let prefix = (body.len() as u32).to_be_bytes();
        assert_eq!(
            ProtocolEnvelope::decode_frame(prefix, &body)
                .unwrap_err()
                .to_string(),
            "ciphertext must not be empty"
        );
    }
}
