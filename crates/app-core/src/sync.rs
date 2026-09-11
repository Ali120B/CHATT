//! Sync + retry (Phases 5–6): idempotent resends, backoff, catch-up.
//!
//! Every outbound message keeps its id across retries, so a dropped
//! connection can neither lose nor duplicate a message: the receiver's
//! `INSERT OR IGNORE` makes redelivery safe.

use anyhow::Result;
use chat_database::{Database, Message, PendingItem};
use chat_protocol::MessageType;
use uuid::Uuid;

use crate::{ChatPayload, build_envelope};

/// Retry delay in ms: `min(5min, 1s * 2^attempt)` plus up-to-25% jitter.
pub fn retry_delay_ms(attempt: u32) -> i64 {
    let base = 1000i64.saturating_mul(1i64 << attempt.min(8));
    let capped = base.min(300_000);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    capped + (capped as f64 * 0.25 * ((nanos % 10_000) as f64 / 10_000.0)) as i64
}

pub fn due_pending(db: &Database, now_ms: i64) -> Result<Vec<PendingItem>> {
    db.list_due_pending(now_ms, 50)
}

/// Messages in `conversation_id` after `after_sequence`, oldest first.
pub fn messages_after(
    db: &Database,
    conversation_id: &str,
    after_sequence: i64,
    limit: i64,
) -> Result<Vec<Message>> {
    Ok(db
        .list_messages(conversation_id, limit + 200)?
        .into_iter()
        .filter(|m| m.sequence > after_sequence)
        .take(limit as usize)
        .collect())
}

pub fn parse_message_type(raw: &str) -> MessageType {
    match raw {
        "MessageEdit" => MessageType::MessageEdit,
        "MessageDelete" => MessageType::MessageDelete,
        "MessageReply" => MessageType::Message,
        "DeliveryAck" => MessageType::DeliveryAck,
        "ReadAck" => MessageType::ReadAck,
        "Typing" => MessageType::Typing,
        "Presence" => MessageType::Presence,
        "SyncRequest" => MessageType::SyncRequest,
        "SyncResponse" => MessageType::SyncResponse,
        "GroupCommit" => MessageType::GroupCommit,
        "GroupMessage" => MessageType::GroupMessage,
        "GroupSync" => MessageType::GroupSync,
        "FileOffer" => MessageType::FileOffer,
        "FileAccept" => MessageType::FileAccept,
        "FileChunk" => MessageType::FileChunk,
        "FileAck" => MessageType::FileAck,
        "FileComplete" => MessageType::FileComplete,
        "FriendRequest" => MessageType::FriendRequest,
        "FriendResponse" => MessageType::FriendResponse,
        _ => MessageType::Message,
    }
}

/// Rebuild a sendable envelope for a stored message (same ids, fresh
/// signature + timestamp) so retries and catch-up sync stay idempotent.
pub fn resend_envelope(
    identity: &chat_identity::DeviceIdentity,
    device_uuid: Uuid,
    conversation_uuid: Uuid,
    message: &Message,
    now_ms: i64,
) -> Result<chat_protocol::ProtocolEnvelope> {
    let message_id = Uuid::parse_str(&message.id).unwrap_or_else(|_| Uuid::new_v4());
    Ok(build_envelope(
        identity,
        device_uuid,
        conversation_uuid,
        message_id,
        parse_message_type(&message.message_type),
        message.sequence as u64,
        message.ciphertext.clone(),
        now_ms,
    ))
}

/// Apply an incoming read receipt: messages I sent that the reader has now
/// seen become `read`.
pub fn apply_read_receipt(
    db: &Database,
    conversation_id: &str,
    reader: &str,
    ref_ids: &[String],
) -> Result<usize> {
    let mut applied = 0;
    for message in db.list_messages(conversation_id, 5000)? {
        if ref_ids.iter().any(|id| id == &message.id) && message.sender_username != reader {
            db.set_message_status(&message.id, "read")?;
            applied += 1;
        }
    }
    Ok(applied)
}

/// Handle an incoming SyncRequest: the payloads to send back are the stored
/// envelopes after the peer's cursor. Returns message ids to resend.
pub fn sync_gap(db: &Database, conversation_id: &str, after_sequence: i64) -> Result<Vec<String>> {
    Ok(messages_after(db, conversation_id, after_sequence, 200)?
        .into_iter()
        .map(|m| m.id)
        .collect())
}

pub fn payload_preview(payload: &ChatPayload) -> String {
    match payload {
        ChatPayload::Text { body, .. } => body.chars().take(120).collect(),
        ChatPayload::Edit { body, .. } => body.chars().take(120).collect(),
        ChatPayload::Delete { .. } => "Message deleted".to_string(),
        ChatPayload::FileOffer { file, .. } => format!("File: {}", file.filename),
        ChatPayload::GroupMeta { name, .. } => format!("Group renamed to {name}"),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_grows_and_caps() {
        assert!(retry_delay_ms(0) >= 1000 && retry_delay_ms(0) < 1300);
        assert!(retry_delay_ms(9) <= 375_000);
        assert!(retry_delay_ms(100) <= 375_000);
    }

    #[test]
    fn sync_gap_lists_only_missing() {
        let db = Database::in_memory().unwrap();
        db.create_conversation("c1", "dm", "", &["bob".to_string()], 1)
            .unwrap();
        for i in 1..=3 {
            db.insert_message(&Message {
                id: format!("m{i}"),
                conversation_id: "c1".into(),
                sender_device_id: "d".into(),
                sender_username: "ada".into(),
                message_type: "Message".into(),
                body: format!("m{i}"),
                ciphertext: vec![i as u8],
                sequence: i,
                status: "delivered".into(),
                reply_to: None,
                created_at_ms: i,
                edited_at_ms: None,
                deleted_at_ms: None,
            })
            .unwrap();
        }
        assert_eq!(
            sync_gap(&db, "c1", 1).unwrap(),
            vec!["m2".to_string(), "m3".to_string()]
        );
        assert!(sync_gap(&db, "c1", 3).unwrap().is_empty());
    }

    #[test]
    fn read_receipts_only_mark_my_messages() {
        let db = Database::in_memory().unwrap();
        db.create_conversation("c1", "dm", "", &["bob".to_string()], 1)
            .unwrap();
        for (id, sender) in [("m1", "ada"), ("m2", "bob")] {
            db.insert_message(&Message {
                id: id.into(),
                conversation_id: "c1".into(),
                sender_device_id: "d".into(),
                sender_username: sender.into(),
                message_type: "Message".into(),
                body: id.into(),
                ciphertext: vec![1],
                sequence: if id == "m1" { 1 } else { 2 },
                status: "delivered".into(),
                reply_to: None,
                created_at_ms: 2,
                edited_at_ms: None,
                deleted_at_ms: None,
            })
            .unwrap();
        }
        assert_eq!(
            apply_read_receipt(&db, "c1", "bob", &["m1".to_string(), "m2".to_string()]).unwrap(),
            1
        );
    }
}
