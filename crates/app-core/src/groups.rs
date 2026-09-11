//! Groups (Phase 8): creation, membership, key rotation, group messaging.
//!
//! V1 group encryption is standard hybrid encryption from reviewed
//! primitives: a random 32-byte key per epoch, sealed with ChaCha20-Poly1305
//! for messages and distributed wrapped in `crypto_box` to each member.
//! Every membership change rotates the key (new epoch) so removed members
//! cannot read future messages. The migration seam to full MLS (OpenMLS,
//! RFC 9420) is the epoch/key-distribution boundary: replace
//! [`rotate_epoch`] + [`open_group_text`] with MLS commits/messages and the
//! surrounding app logic (SQLite history, outbound work, sync) is unchanged.

use anyhow::{Context, Result, bail};
use chat_database::{Contact, Database};
use chat_identity::DeviceIdentity;
use uuid::Uuid;

use crate::{
    ChatPayload, OutboundWork, build_envelope, hex_decode_32, open_group_payload, seal_dm_payload,
    seal_group_payload,
};

/// Create a group: conversation shell + epoch-1 key wrapped for every member
/// (including us). Returns the group id and one GroupKey envelope per member.
pub fn create_group(
    db: &Database,
    identity: &DeviceIdentity,
    device_uuid: Uuid,
    my_username: &str,
    name: &str,
    members: &[String],
    now_ms: i64,
) -> Result<(String, Vec<OutboundWork>)> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 64 {
        bail!("Group name must be 1–64 characters.");
    }
    if members.is_empty() {
        bail!("A group needs at least one other member.");
    }
    let mut all = members.to_vec();
    if !all.iter().any(|m| m == my_username) {
        all.push(my_username.to_string());
    }
    for member in &all {
        if member == my_username {
            continue;
        }
        match db.find_contact(member)? {
            Some(c) if c.status == "friend" => {}
            _ => bail!("{member} is not a friend yet"),
        }
    }
    let group_id = Uuid::new_v4().to_string();
    db.create_conversation(&group_id, "group", trimmed, &all, now_ms)?;
    db.save_group(&group_id, trimmed, 1, now_ms)?;
    let group_key = chat_crypto::random_32();
    let works = distribute_epoch_key(
        db,
        identity,
        device_uuid,
        my_username,
        &group_id,
        trimmed,
        &all,
        1,
        &group_key,
        now_ms,
    )?;
    Ok((group_id, works))
}

/// Rotate the epoch key and inform every remaining member of their wrap.
/// Call after any add/remove (and store our own wrap too).
pub fn rotate_epoch(
    db: &Database,
    identity: &DeviceIdentity,
    device_uuid: Uuid,
    my_username: &str,
    group_id: &str,
    now_ms: i64,
) -> Result<Vec<OutboundWork>> {
    let group = db.load_group(group_id)?.context("unknown group")?;
    let epoch = group.current_epoch + 1;
    let members = db.conversation_members(group_id)?;
    db.save_group(group_id, &group.name, epoch, now_ms)?;
    let group_key = chat_crypto::random_32();
    distribute_epoch_key(
        db,
        identity,
        device_uuid,
        my_username,
        group_id,
        &group.name,
        &members,
        epoch,
        &group_key,
        now_ms,
    )
}

#[allow(clippy::too_many_arguments)] // domain params stay explicit; no context-object indirection
fn distribute_epoch_key(
    db: &Database,
    identity: &DeviceIdentity,
    device_uuid: Uuid,
    my_username: &str,
    group_id: &str,
    group_name: &str,
    members: &[String],
    epoch: i64,
    group_key: &[u8; 32],
    now_ms: i64,
) -> Result<Vec<OutboundWork>> {
    let my_public = identity.public();
    let mut works = Vec::new();
    for member in members {
        if member == my_username {
            // Our own wrap is sealed to ourselves so every epoch uses one code path.
            let wrapped = chat_crypto::wrap_group_key(
                &identity.x_secret,
                &identity.public().x_pubkey,
                group_key,
            )?;
            db.save_wrapped_group_key_from(group_id, epoch, member, &wrapped, &my_public.x_pubkey)?;
            continue;
        }
        let contact = member_contact(db, member)?;
        let member_pub = contact_pub(&contact)?;
        let wrapped = chat_crypto::wrap_group_key(&identity.x_secret, &member_pub, group_key)?;
        db.save_wrapped_group_key_from(group_id, epoch, member, &wrapped, &my_public.x_pubkey)?;
        let payload = ChatPayload::GroupKey {
            from: my_username.to_string(),
            group_id: group_id.to_string(),
            epoch,
            members: members.to_vec(),
            group_name: group_name.to_string(),
            wrapped_key: wrapped.clone(),
            wrapper_x_pub_hex: crate::hex_encode(&my_public.x_pubkey),
        };
        let ciphertext = seal_dm_payload(&identity.x_secret, &member_pub, group_id, &payload)?;
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
        works.push(OutboundWork {
            peer_username: member.clone(),
            envelope,
        });
    }
    Ok(works)
}

/// Apply an incoming GroupKey rotation: sync the shell + membership and
/// store our own wrapped copy of the epoch key.
pub fn receive_group_key(
    db: &Database,
    my_username: &str,
    payload: &ChatPayload,
    now_ms: i64,
) -> Result<()> {
    let (group_id, epoch, members, group_name, wrapped_key, wrapper_hex) = match payload {
        ChatPayload::GroupKey {
            from: _,
            group_id,
            epoch,
            members,
            group_name,
            wrapped_key,
            wrapper_x_pub_hex,
        } => (
            group_id.clone(),
            *epoch,
            members.clone(),
            group_name.clone(),
            wrapped_key.clone(),
            wrapper_x_pub_hex.clone(),
        ),
        _ => bail!("not a group key"),
    };
    if !members.iter().any(|m| m == my_username) {
        // We were removed: drop our key material, keep history readable.
        db.delete_wrapped_keys_for(&group_id, my_username)?;
        db.set_conversation_members(&group_id, &members, now_ms)?;
        return Ok(());
    }
    if db
        .load_group(&group_id)?
        .map(|g| g.current_epoch)
        .unwrap_or(0)
        >= epoch
    {
        return Ok(());
    }
    db.create_conversation(&group_id, "group", &group_name, &members, now_ms)?;
    db.set_conversation_members(&group_id, &members, now_ms)?;
    db.save_group(&group_id, &group_name, epoch, now_ms)?;
    let wrapper = contact_pub_from_hex(&wrapper_hex)?;
    store_own_epoch_wrap(db, &group_id, epoch, my_username, &wrapped_key, &wrapper)?;
    Ok(())
}

/// Store our own wrapped copy of an epoch key (extracted from a GroupKey DM
/// addressed to us — the ciphertext is ours, so we keep the sealed bytes).
pub fn store_own_epoch_wrap(
    db: &Database,
    group_id: &str,
    epoch: i64,
    my_username: &str,
    wrapped_for_me: &[u8],
    wrapper_x_pub: &[u8; 32],
) -> Result<()> {
    db.save_wrapped_group_key_from(group_id, epoch, my_username, wrapped_for_me, wrapper_x_pub)
}

/// Unwrap our epoch key. `wrapper_x_pub` is the member who rotated (stored
/// alongside our wrap, or the sender of the GroupKey DM).
pub fn own_epoch_key(
    db: &Database,
    identity: &DeviceIdentity,
    group_id: &str,
    epoch: i64,
    my_username: &str,
) -> Result<[u8; 32]> {
    let (wrapped, wrapper) = db
        .load_wrapped_group_key_with_sender(group_id, epoch, my_username)?
        .context("no key for this epoch")?;
    let wrapper_pub = match wrapper {
        Some(bytes) => {
            if bytes.len() != 32 {
                bail!("bad wrapper key");
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            out
        }
        None => identity.public().x_pubkey,
    };
    chat_crypto::unwrap_group_key(&identity.x_secret, &wrapper_pub, &wrapped)
}

/// Seal a group text message with the current epoch key.
pub fn seal_group_text(
    db: &Database,
    identity: &DeviceIdentity,
    group_id: &str,
    my_username: &str,
    body: &str,
    reply_to: Option<String>,
    sequence: u64,
) -> Result<(Vec<u8>, i64)> {
    let group = db.load_group(group_id)?.context("unknown group")?;
    let key = own_epoch_key(db, identity, group_id, group.current_epoch, my_username)?;
    let payload = ChatPayload::Text {
        from: my_username.to_string(),
        body: body.to_string(),
        reply_to,
        epoch: Some(group.current_epoch),
    };
    Ok((
        seal_group_payload(&key, sequence, &payload)?,
        group.current_epoch,
    ))
}

pub fn open_group_text(
    db: &Database,
    identity: &DeviceIdentity,
    group_id: &str,
    epoch: i64,
    my_username: &str,
    sequence: u64,
    boxed: &[u8],
) -> Result<ChatPayload> {
    let key = own_epoch_key(db, identity, group_id, epoch, my_username)?;
    open_group_payload(&key, sequence, boxed)
}

/// Open a group envelope without trusting any claimed epoch: try the newest
/// epoch first, then older ones we still hold wraps for. Returns the payload
/// and the epoch that authenticated it.
pub fn open_group_best(
    db: &Database,
    identity: &DeviceIdentity,
    group_id: &str,
    my_username: &str,
    sequence: u64,
    boxed: &[u8],
    hint_epoch: Option<i64>,
) -> Result<(ChatPayload, i64)> {
    let current = db
        .load_group(group_id)?
        .map(|g| g.current_epoch)
        .unwrap_or(1);
    let mut candidates = Vec::new();
    if let Some(hint) = hint_epoch {
        candidates.push(hint);
    }
    candidates.push(current);
    let mut epoch = current;
    while epoch > 1 && candidates.len() < 8 {
        epoch -= 1;
        candidates.push(epoch);
    }
    let mut last_error = anyhow::anyhow!("no group key available");
    for candidate in candidates {
        match open_group_text(
            db,
            identity,
            group_id,
            candidate,
            my_username,
            sequence,
            boxed,
        ) {
            Ok(payload) => return Ok((payload, candidate)),
            Err(e) => last_error = e,
        }
    }
    Err(last_error)
}

pub fn add_members(
    db: &Database,
    identity: &DeviceIdentity,
    device_uuid: Uuid,
    my_username: &str,
    group_id: &str,
    new_members: &[String],
    now_ms: i64,
) -> Result<Vec<OutboundWork>> {
    for member in new_members {
        if member == my_username {
            continue;
        }
        match db.find_contact(member)? {
            Some(c) if c.status == "friend" => {}
            _ => bail!("{member} is not a friend yet"),
        }
        db.create_conversation(group_id, "group", "", std::slice::from_ref(member), now_ms)?;
    }
    rotate_epoch(db, identity, device_uuid, my_username, group_id, now_ms)
}

pub fn remove_members(
    db: &Database,
    identity: &DeviceIdentity,
    device_uuid: Uuid,
    my_username: &str,
    group_id: &str,
    remove: &[String],
    now_ms: i64,
) -> Result<Vec<OutboundWork>> {
    for member in remove {
        if member == my_username {
            bail!("use leave instead of removing yourself");
        }
        db.remove_conversation_member(group_id, member)?;
        db.delete_wrapped_keys_for(group_id, member)?;
    }
    rotate_epoch(db, identity, device_uuid, my_username, group_id, now_ms)
}

pub fn rename_group(
    db: &Database,
    identity: &DeviceIdentity,
    device_uuid: Uuid,
    my_username: &str,
    group_id: &str,
    name: &str,
    now_ms: i64,
) -> Result<(chat_protocol::ProtocolEnvelope, Vec<String>)> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 64 {
        bail!("Group name must be 1–64 characters.");
    }
    let group = db.load_group(group_id)?.context("unknown group")?;
    db.rename_conversation(group_id, trimmed, now_ms)?;
    db.save_group(group_id, trimmed, group.current_epoch, now_ms)?;
    let key = own_epoch_key(db, identity, group_id, group.current_epoch, my_username)?;
    let sequence = db.next_sequence(group_id, &device_uuid.to_string())?;
    let payload = ChatPayload::GroupMeta {
        from: my_username.to_string(),
        group_id: group_id.to_string(),
        name: trimmed.to_string(),
        epoch: Some(group.current_epoch),
    };
    let ciphertext = seal_group_payload(&key, sequence as u64, &payload)?;
    let conversation_uuid = Uuid::parse_str(group_id).unwrap_or_else(|_| Uuid::new_v4());
    let envelope = build_envelope(
        identity,
        device_uuid,
        conversation_uuid,
        Uuid::new_v4(),
        payload.message_type(),
        sequence as u64,
        ciphertext,
        now_ms,
    );
    let members = db
        .conversation_members(group_id)?
        .into_iter()
        .filter(|m| m != my_username)
        .collect();
    Ok((envelope, members))
}

fn member_contact(db: &Database, member: &str) -> Result<Contact> {
    db.find_contact(member)?
        .with_context(|| format!("{member} is not a friend yet"))
}

fn contact_pub(contact: &Contact) -> Result<[u8; 32]> {
    match &contact.x25519_pubkey {
        Some(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(bytes);
            Ok(out)
        }
        _ => bail!("no encryption key for {}", contact.username),
    }
}

pub fn contact_pub_from_hex(hex: &str) -> Result<[u8; 32]> {
    hex_decode_32(hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat_identity::DeviceIdentity;

    fn member_db(name: &str, friend: &str, friend_x_hex: &str) -> Database {
        let db = Database::in_memory().unwrap();
        db.upsert_contact(
            &Contact {
                username: friend.into(),
                display_name: friend.into(),
                x25519_pubkey: Some(hex_decode_32(friend_x_hex).unwrap().to_vec()),
                ed_pubkey: None,
                endpoint_id: Some(format!("node-{friend}")),
                endpoint_bundle: None,
                status: "friend".into(),
            },
            1,
        )
        .unwrap();
        let _ = name;
        db
    }

    #[test]
    fn group_create_message_and_rotation() {
        let ada = DeviceIdentity::generate();
        let bob = DeviceIdentity::generate();
        let ada_pub = ada.public();
        let bob_pub = bob.public();
        let ada_hex = crate::hex_encode(&ada_pub.x_pubkey);
        let bob_hex = crate::hex_encode(&bob_pub.x_pubkey);
        let ada_db = member_db("ada", "bob", &bob_hex);
        let bob_db = member_db("bob", "ada", &ada_hex);
        let device = Uuid::new_v4();

        // Ada creates the group; Bob gets a GroupKey envelope.
        let (group_id, works) = create_group(
            &ada_db,
            &ada,
            device,
            "ada",
            "Roblox squad",
            &["bob".to_string()],
            10,
        )
        .unwrap();
        assert_eq!(works.len(), 1);
        let key_payload = crate::open_dm_payload(
            &bob.x_secret,
            &ada_pub.x_pubkey,
            &group_id,
            &works[0].envelope.ciphertext,
        )
        .unwrap();
        let epoch = match &key_payload {
            ChatPayload::GroupKey { epoch, .. } => *epoch,
            _ => panic!("expected group key"),
        };
        assert_eq!(epoch, 1);
        // Bob syncs the shell and stores his wrap, then both sides can chat.
        receive_group_key(&bob_db, "bob", &key_payload, 11).unwrap();
        let bob_group = bob_db.load_group(&group_id).unwrap().unwrap();
        assert_eq!(bob_group.members.len(), 2);

        // Ada seals a group text; Bob opens it with the epoch key.
        let (ciphertext, used_epoch) =
            seal_group_text(&ada_db, &ada, &group_id, "ada", "ready up", None, 1).unwrap();
        assert_eq!(used_epoch, 1);
        let opened = open_group_text(&bob_db, &bob, &group_id, 1, "bob", 1, &ciphertext).unwrap();
        match opened {
            ChatPayload::Text { from, body, .. } => {
                assert_eq!(from, "ada");
                assert_eq!(body, "ready up");
            }
            _ => panic!("expected text"),
        }

        // Rotation on member change: epoch bumps and the removed member's
        // wraps are deleted.
        let cara = DeviceIdentity::generate();
        let cara_pub = cara.public();
        for (d, name, hex) in [
            (&ada_db, "cara", crate::hex_encode(&cara_pub.x_pubkey)),
            (&bob_db, "cara", crate::hex_encode(&cara_pub.x_pubkey)),
        ] {
            d.upsert_contact(
                &Contact {
                    username: name.into(),
                    display_name: name.into(),
                    x25519_pubkey: Some(hex_decode_32(&hex).unwrap().to_vec()),
                    ed_pubkey: None,
                    endpoint_id: Some(format!("node-{name}")),
                    endpoint_bundle: None,
                    status: "friend".into(),
                },
                12,
            )
            .unwrap();
        }
        let rotation = add_members(
            &ada_db,
            &ada,
            device,
            "ada",
            &group_id,
            &["cara".to_string()],
            13,
        )
        .unwrap();
        assert_eq!(rotation.len(), 2); // bob + cara each get a GroupKey DM
        assert_eq!(
            ada_db.load_group(&group_id).unwrap().unwrap().current_epoch,
            2
        );

        // Bob receives his epoch-2 rotation (the shell's exact path) and can
        // read new messages, while epoch-1 history still opens.
        let bob_work = rotation.iter().find(|w| w.peer_username == "bob").unwrap();
        let bob_key_payload = crate::open_dm_payload(
            &bob.x_secret,
            &ada_pub.x_pubkey,
            &group_id,
            &bob_work.envelope.ciphertext,
        )
        .unwrap();
        receive_group_key(&bob_db, "bob", &bob_key_payload, 14).unwrap();
        assert_eq!(
            bob_db.load_group(&group_id).unwrap().unwrap().current_epoch,
            2
        );
        let (cipher2, epoch2) =
            seal_group_text(&ada_db, &ada, &group_id, "ada", "welcome cara", None, 2).unwrap();
        assert_eq!(epoch2, 2);
        let (opened2, used) =
            open_group_best(&bob_db, &bob, &group_id, "bob", 2, &cipher2, None).unwrap();
        assert_eq!(used, 2);
        match opened2 {
            ChatPayload::Text { body, .. } => assert_eq!(body, "welcome cara"),
            _ => panic!("expected text"),
        }
        // Old epoch still readable after rotation.
        let (opened1, used1) =
            open_group_best(&bob_db, &bob, &group_id, "bob", 1, &ciphertext, None).unwrap();
        assert_eq!(used1, 1);
        match opened1 {
            ChatPayload::Text { body, .. } => assert_eq!(body, "ready up"),
            _ => panic!("expected text"),
        }
    }
}
