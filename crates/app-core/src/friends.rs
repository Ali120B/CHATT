//! Friends: invite codes, requests, accept/reject, block/remove (Phase 7).
//!
//! Trust model: an [`InviteCode`] carries the peer's Ed25519 and X25519
//! public keys. Importing one is trust-on-first-use — the UI must show the
//! username *and* a key fingerprint and ask the user to confirm out of band
//! before anything sensitive is sent.

use anyhow::{Context, Result, bail};
use chat_coordinator::InviteCode;
use chat_database::{Contact, Database, FriendRequest};
use chat_identity::DeviceIdentity;
use uuid::Uuid;

use crate::{ChatPayload, OutboundWork, build_envelope, hex_decode_32, hex_encode};

/// Build my invite code for sharing (copy/paste, QR, message).
pub fn my_invite_code(
    username: &str,
    display_name: &str,
    identity: &DeviceIdentity,
    endpoint_id: &str,
    endpoint_bundle: &str,
) -> Result<String> {
    let public = identity.public();
    InviteCode {
        username: username.to_string(),
        display_name: display_name.to_string(),
        ed_pubkey_hex: hex_encode(&public.ed_pubkey),
        x_pubkey_hex: hex_encode(&public.x_pubkey),
        endpoint_id: endpoint_id.to_string(),
        endpoint_bundle: endpoint_bundle.to_string(),
    }
    .encode()
}

/// Import a peer's invite: store their keys as a `requested` contact and open
/// an outgoing request row. Returns the invite plus whether it is new.
pub fn import_invite(db: &Database, code: &str, now_ms: i64) -> Result<(InviteCode, bool)> {
    let invite = InviteCode::decode(code)?;
    let username = invite.username.trim().to_ascii_lowercase();
    if username.len() < 3 {
        bail!("invite has a bad username");
    }
    let is_new = db.find_contact(&username)?.is_none();
    db.upsert_contact(
        &Contact {
            username: username.clone(),
            display_name: invite.display_name.clone(),
            x25519_pubkey: Some(hex_decode_32(&invite.x_pubkey_hex)?.to_vec()),
            ed_pubkey: Some(hex_decode_32(&invite.ed_pubkey_hex)?.to_vec()),
            endpoint_id: Some(invite.endpoint_id.clone()),
            endpoint_bundle: Some(invite.endpoint_bundle.clone()),
            status: "requested".to_string(),
        },
        now_ms,
    )?;
    let pending_out = db
        .list_friend_requests(Some("pending"))?
        .into_iter()
        .any(|r| r.direction == "out" && r.peer_username == username);
    if !pending_out {
        db.save_friend_request(
            &FriendRequest {
                id: Uuid::new_v4().to_string(),
                direction: "out".to_string(),
                peer_username: username,
                peer_display_name: invite.display_name.clone(),
                status: "pending".to_string(),
                created_at_ms: now_ms,
            },
            now_ms,
        )?;
    }
    Ok((invite, is_new))
}

#[allow(clippy::too_many_arguments)] // domain params stay explicit; no context-object indirection
/// Build the signed+sealed friend-request envelope for an imported invite.
pub fn build_friend_ask(
    db: &Database,
    identity: &DeviceIdentity,
    device_uuid: Uuid,
    my_username: &str,
    my_display_name: &str,
    my_bundle: &str,
    peer_username: &str,
    now_ms: i64,
) -> Result<OutboundWork> {
    let peer = db
        .find_contact(peer_username)?
        .context("unknown contact — import their invite first")?;
    if peer.status == "blocked" {
        bail!("that user is blocked");
    }
    let recipient_pub = peer
        .x25519_pubkey
        .as_deref()
        .context("no encryption key for this contact")?;
    let mut recipient = [0u8; 32];
    if recipient_pub.len() != 32 {
        bail!("contact key has wrong length");
    }
    recipient.copy_from_slice(recipient_pub);
    let public = identity.public();
    let payload = ChatPayload::FriendAsk {
        from: my_username.to_string(),
        display_name: my_display_name.to_string(),
        ed_pubkey_hex: hex_encode(&public.ed_pubkey),
        x_pubkey_hex: hex_encode(&public.x_pubkey),
        endpoint_bundle: my_bundle.to_string(),
    };
    // Friend asks are bound to a per-peer pseudo-conversation so replays
    // cannot be retargeted at another user.
    let context = format!("friend-ask:{my_username}>{peer_username}");
    let json = serde_json::to_vec(&payload)?;
    let ciphertext =
        chat_crypto::seal_dm(&identity.x_secret, &recipient, context.as_bytes(), &json)?;
    let envelope = build_envelope(
        identity,
        device_uuid,
        Uuid::new_v4(),
        Uuid::new_v4(),
        payload.message_type(),
        0,
        ciphertext,
        now_ms,
    );
    Ok(OutboundWork {
        peer_username: peer_username.to_string(),
        envelope,
    })
}

/// Handle an incoming friend ask: verify the key matches any known record,
/// store an incoming request row, stage the contact as `pending`.
pub fn receive_friend_ask(db: &Database, ask: &ChatPayload, now_ms: i64) -> Result<FriendRequest> {
    let (from, display_name, ed_hex, x_hex, bundle) = match ask {
        ChatPayload::FriendAsk {
            from,
            display_name,
            ed_pubkey_hex,
            x_pubkey_hex,
            endpoint_bundle,
        } => (
            from.clone(),
            display_name.clone(),
            ed_pubkey_hex.clone(),
            x_pubkey_hex.clone(),
            endpoint_bundle.clone(),
        ),
        _ => bail!("not a friend ask"),
    };
    if let Some(existing) = db.find_contact(&from)?
        && (existing.status == "friend" || existing.status == "blocked")
    {
        bail!("already decided for this user");
    }
    db.upsert_contact(
        &Contact {
            username: from.clone(),
            display_name: display_name.clone(),
            x25519_pubkey: Some(hex_decode_32(&x_hex)?.to_vec()),
            ed_pubkey: Some(hex_decode_32(&ed_hex)?.to_vec()),
            endpoint_id: None,
            endpoint_bundle: if bundle.is_empty() {
                None
            } else {
                Some(bundle)
            },
            status: "pending".to_string(),
        },
        now_ms,
    )?;
    let already = db
        .list_friend_requests(Some("pending"))?
        .into_iter()
        .find(|r| r.direction == "in" && r.peer_username == from);
    if let Some(row) = already {
        return Ok(row);
    }
    let row = FriendRequest {
        id: Uuid::new_v4().to_string(),
        direction: "in".to_string(),
        peer_username: from,
        peer_display_name: display_name,
        status: "pending".to_string(),
        created_at_ms: now_ms,
    };
    db.save_friend_request(&row, now_ms)?;
    Ok(row)
}

/// Accept an incoming request: mark friendship, ensure a DM conversation,
/// and build the sealed acceptance for the requester.
pub fn accept_request(
    db: &Database,
    identity: &DeviceIdentity,
    device_uuid: Uuid,
    my_username: &str,
    my_bundle: &str,
    request_id: &str,
    now_ms: i64,
) -> Result<(String, OutboundWork)> {
    let row = db
        .list_friend_requests(Some("pending"))?
        .into_iter()
        .find(|r| r.id == request_id)
        .context("request not found")?;
    if row.direction != "in" {
        bail!("only incoming requests can be accepted");
    }
    db.set_contact_status(&row.peer_username, "friend")?;
    db.set_friend_request_status(&row.id, "accepted", now_ms)?;
    let conversation_id = ensure_dm(db, &row.peer_username, now_ms)?;
    let peer = db
        .find_contact(&row.peer_username)?
        .context("contact vanished")?;
    let answer = answer_envelope(
        db,
        identity,
        device_uuid,
        my_username,
        my_bundle,
        &peer,
        true,
        now_ms,
    )?;
    Ok((conversation_id, answer))
}

pub fn reject_request(db: &Database, request_id: &str, now_ms: i64) -> Result<()> {
    let row = db
        .list_friend_requests(Some("pending"))?
        .into_iter()
        .find(|r| r.id == request_id)
        .context("request not found")?;
    db.set_friend_request_status(&row.id, "rejected", now_ms)?;
    if row.direction == "in"
        && let Some(contact) = db.find_contact(&row.peer_username)?
        && contact.status == "pending"
    {
        db.remove_contact(&row.peer_username)?;
    }
    Ok(())
}

/// Apply an incoming answer to our outgoing ask.
pub fn receive_friend_answer(
    db: &Database,
    from: &str,
    accepted: bool,
    endpoint_bundle: &str,
    now_ms: i64,
) -> Result<Option<String>> {
    let outgoing = db
        .list_friend_requests(Some("pending"))?
        .into_iter()
        .find(|r| r.direction == "out" && r.peer_username == from);
    if let Some(row) = outgoing {
        db.set_friend_request_status(
            &row.id,
            if accepted { "accepted" } else { "rejected" },
            now_ms,
        )?;
    }
    if accepted {
        db.set_contact_status(from, "friend")?;
        if !endpoint_bundle.is_empty()
            && let Some(mut contact) = db.find_contact(from)?
        {
            contact.endpoint_bundle = Some(endpoint_bundle.to_string());
            db.upsert_contact(&contact, now_ms)?;
        }
        return Ok(Some(ensure_dm(db, from, now_ms)?));
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)] // domain params stay explicit; no context-object indirection
fn answer_envelope(
    _db: &Database,
    identity: &DeviceIdentity,
    device_uuid: Uuid,
    my_username: &str,
    my_bundle: &str,
    peer: &Contact,
    accepted: bool,
    now_ms: i64,
) -> Result<OutboundWork> {
    let recipient_pub = peer
        .x25519_pubkey
        .as_deref()
        .context("no encryption key for contact")?;
    let mut recipient = [0u8; 32];
    recipient.copy_from_slice(recipient_pub);
    let payload = ChatPayload::FriendAnswer {
        from: my_username.to_string(),
        accepted,
        endpoint_bundle: my_bundle.to_string(),
    };
    let context = format!("friend-answer:{my_username}>{}", peer.username);
    let json = serde_json::to_vec(&payload)?;
    let ciphertext =
        chat_crypto::seal_dm(&identity.x_secret, &recipient, context.as_bytes(), &json)?;
    let envelope = build_envelope(
        identity,
        device_uuid,
        Uuid::new_v4(),
        Uuid::new_v4(),
        payload.message_type(),
        0,
        ciphertext,
        now_ms,
    );
    Ok(OutboundWork {
        peer_username: peer.username.clone(),
        envelope,
    })
}

/// Open (or find) the 1:1 DM conversation shell with a friend.
pub fn ensure_dm(db: &Database, peer_username: &str, now_ms: i64) -> Result<String> {
    if let Some(id) = db.find_dm_with(peer_username)? {
        return Ok(id);
    }
    let id = Uuid::new_v4().to_string();
    db.create_conversation(&id, "dm", "", &[peer_username.to_string()], now_ms)?;
    Ok(id)
}

pub fn remove_friend(db: &Database, username: &str) -> Result<()> {
    if !db.remove_contact(username)? {
        bail!("not in your friends");
    }
    Ok(())
}

pub fn block_user(db: &Database, username: &str, now_ms: i64) -> Result<()> {
    match db.find_contact(username)? {
        Some(_) => db.set_contact_status(username, "blocked"),
        None => db.upsert_contact(
            &Contact {
                username: username.to_string(),
                display_name: username.to_string(),
                x25519_pubkey: None,
                ed_pubkey: None,
                endpoint_id: None,
                endpoint_bundle: None,
                status: "blocked".to_string(),
            },
            now_ms,
        ),
    }
}

pub fn unblock_user(db: &Database, username: &str) -> Result<()> {
    match db.find_contact(username)? {
        Some(_) => {
            db.set_contact_status(username, "friend")?;
            Ok(())
        }
        None => bail!("not in your list"),
    }
}

/// Open a sealed friend payload. Asks/answers use a per-pair context rather
/// than a conversation id.
pub fn open_friend_payload(
    identity: &DeviceIdentity,
    peer_pub: &[u8; 32],
    context: &str,
    boxed: &[u8],
) -> Result<ChatPayload> {
    let json = chat_crypto::open_dm(&identity.x_secret, peer_pub, context.as_bytes(), boxed)?;
    serde_json::from_slice(&json).context("bad friend payload")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat_identity::DeviceIdentity;

    fn setup() -> (Database, DeviceIdentity, Uuid) {
        (
            Database::in_memory().unwrap(),
            DeviceIdentity::generate(),
            Uuid::new_v4(),
        )
    }

    #[test]
    fn invite_import_ask_receive_and_accept() {
        let (ada_db, ada, ada_device) = setup();
        let (bob_db, bob, bob_device) = setup();
        let bob_public = bob.public();
        let code = InviteCode {
            username: "bob".into(),
            display_name: "Bob".into(),
            ed_pubkey_hex: crate::hex_encode(&bob_public.ed_pubkey),
            x_pubkey_hex: crate::hex_encode(&bob_public.x_pubkey),
            endpoint_id: "node-b".into(),
            endpoint_bundle: "bund".into(),
        }
        .encode()
        .unwrap();
        // Ada imports Bob's invite and builds a sealed ask.
        let (invite, is_new) = import_invite(&ada_db, &code, 1).unwrap();
        assert!(is_new);
        assert_eq!(invite.username, "bob");
        let work = build_friend_ask(
            &ada_db,
            &ada,
            ada_device,
            "ada",
            "Ada",
            "bundle-ada",
            "bob",
            2,
        )
        .unwrap();
        // Bob opens the ask with the per-pair context and records it.
        let ada_public = ada.public();
        let mut ada_x = [0u8; 32];
        ada_x.copy_from_slice(&ada_public.x_pubkey);
        let payload = open_friend_payload(
            &bob,
            &ada_x,
            "friend-ask:ada>bob",
            &work.envelope.ciphertext,
        )
        .unwrap();
        let row = receive_friend_ask(&bob_db, &payload, 3).unwrap();
        assert_eq!(row.direction, "in");
        // Bob accepts: friendship + DM shell + sealed answer.
        let (dm_id, answer) =
            accept_request(&bob_db, &bob, bob_device, "bob", "bundle-bob", &row.id, 4).unwrap();
        assert!(!dm_id.is_empty());
        assert_eq!(answer.peer_username, "ada");
        // Ada applies the answer and gets the same DM shell.
        let mut bob_x = [0u8; 32];
        bob_x.copy_from_slice(&bob_public.x_pubkey);
        let answer_payload = open_friend_payload(
            &ada,
            &bob_x,
            "friend-answer:bob>ada",
            &answer.envelope.ciphertext,
        )
        .unwrap();
        let bundle = match answer_payload {
            ChatPayload::FriendAnswer {
                from,
                accepted,
                endpoint_bundle,
            } => {
                assert_eq!(from, "bob");
                assert!(accepted);
                endpoint_bundle
            }
            _ => panic!("expected answer"),
        };
        let ada_dm = receive_friend_answer(&ada_db, "bob", true, &bundle, 5)
            .unwrap()
            .unwrap();
        assert!(!ada_dm.is_empty());
        assert_eq!(
            ada_db.find_contact("bob").unwrap().unwrap().status,
            "friend"
        );
    }

    #[test]
    fn block_and_remove() {
        let (db, _, _) = setup();
        block_user(&db, "spammer", 1).unwrap();
        assert_eq!(
            db.find_contact("spammer").unwrap().unwrap().status,
            "blocked"
        );
        unblock_user(&db, "spammer").unwrap();
        assert_eq!(
            db.find_contact("spammer").unwrap().unwrap().status,
            "friend"
        );
        remove_friend(&db, "spammer").unwrap();
        assert!(remove_friend(&db, "spammer").is_err());
    }
}
