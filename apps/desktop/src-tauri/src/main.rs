//! Hearth desktop shell (Phase 1): floating window, tray, notifications,
//! global shortcut, background sync — plus the command surface for chat,
//! friends, groups, and files (Phases 2–9).
//!
//! Layering: every product decision lives in `chat-app-core` (pure,
//! unit-tested). This file only wires Tauri: windows, events, background
//! workers, and network execution of [`OutboundWork`] values.

use chat_app_core::{
    ChatPayload, OutboundWork, PresenceStatus, files as app_files, friends as app_friends,
    groups as app_groups,
    presence::{PresenceTracker, TypingTracker},
    sync as app_sync,
};
use chat_coordinator::{
    CloudflareCoordinator, Coordinator as _, DirectoryRecord, LocalCoordinator, MAILBOX_TTL_MS,
    MailboxObject,
};
use chat_database::{Contact, Database, DeviceRecord, FileTransfer, Message};
use chat_identity::{DeviceIdentity, KeyBackend};
use chat_protocol::{MessageType, ProtocolEnvelope};
use chat_transport::{EndpointAddr, EndpointId, InboundEnvelope, Transport, TransportDiagnostics};
use serde::Serialize;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;

const SHORTCUT: &str = "Alt+Slash";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

struct AppState {
    db: Mutex<Database>,
    identity: DeviceIdentity,
    device_uuid: Uuid,
    transport: tokio::sync::Mutex<Option<Transport>>,
    typing: Mutex<TypingTracker>,
    presence: Mutex<PresenceTracker>,
    /// Latest dialable address per peer endpoint id.
    peer_addrs: Mutex<HashMap<String, EndpointAddr>>,
    file_accepts: Mutex<HashMap<String, i64>>,
    data_dir: PathBuf,
    files_dir: PathBuf,
    /// Our current endpoint bundle string (for invites/payloads).
    local_bundle: Mutex<String>,
    key_backend: KeyBackend,
    shortcut_ok: Mutex<bool>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn my_username(state: &AppState) -> Result<String, String> {
    let db = state.db.lock().map_err(|_| "database lock unavailable")?;
    db.load_profile()
        .map_err(|e| e.to_string())?
        .map(|(username, _)| username)
        .ok_or_else(|| "no local profile yet".to_string())
}

fn my_display_name(state: &AppState) -> String {
    state
        .db
        .lock()
        .ok()
        .and_then(|db| db.load_profile().ok().flatten().map(|(_, display)| display))
        .unwrap_or_else(|| "Me".to_string())
}

/// Any user-initiated command resets the idle clock for auto-away.
fn mark_activity(state: &AppState) {
    if let Ok(mut tracker) = state.presence.lock() {
        tracker.activity();
    }
}

fn local_bundle_of(state: &AppState) -> String {
    state
        .local_bundle
        .lock()
        .map(|b| b.clone())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppStateView {
    profile_exists: bool,
    username: Option<String>,
    display_name: Option<String>,
    key_backend: String,
    coordinator: String,
    worker_url: String,
    relay_enabled: bool,
    shortcut_ok: bool,
    always_on_top: bool,
    connection: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ChatSummary {
    id: String,
    kind: String,
    name: String,
    members: Vec<String>,
    preview: Option<String>,
    updated_at_ms: i64,
    unread: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatDetail {
    conversation: ChatSummary,
    messages: Vec<Message>,
    files: Vec<FileTransfer>,
    typists: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FriendView {
    username: String,
    display_name: String,
    status: String,
    seen: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FriendsView {
    contacts: Vec<FriendView>,
    incoming: Vec<chat_database::FriendRequest>,
    outgoing: Vec<chat_database::FriendRequest>,
}

fn chat_display_name(db: &Database, conv: &chat_database::Conversation) -> String {
    if conv.kind == "group" {
        if conv.name.is_empty() {
            format!("Group ({} members)", conv.members.len().max(1))
        } else {
            conv.name.clone()
        }
    } else {
        let peer = conv.members.first().map(|s| s.as_str()).unwrap_or("?");
        db.find_contact(peer)
            .ok()
            .flatten()
            .map(|c| {
                if c.display_name.is_empty() {
                    format!("@{peer}")
                } else {
                    c.display_name
                }
            })
            .unwrap_or_else(|| format!("@{peer}"))
    }
}

fn summarize(db: &Database, me: &str, conv: chat_database::Conversation) -> ChatSummary {
    let unread = db.unread_count(&conv.id, me).unwrap_or(0);
    ChatSummary {
        id: conv.id.clone(),
        kind: conv.kind.clone(),
        name: chat_display_name(db, &conv),
        members: conv.members.clone(),
        preview: conv.last_message_preview.clone(),
        updated_at_ms: conv.updated_at_ms,
        unread,
    }
}

// ---------------------------------------------------------------------------
// Network execution
// ---------------------------------------------------------------------------

fn dial_target(
    db: &Database,
    peer_addrs: &HashMap<String, EndpointAddr>,
    username: &str,
) -> anyhow::Result<EndpointAddr> {
    let contact = db
        .find_contact(username)?
        .ok_or_else(|| anyhow::anyhow!("unknown contact @{username}"))?;
    if let Some(bundle) = contact.endpoint_bundle.as_deref()
        && let Ok(addr) = chat_transport::decode_bundle(bundle)
    {
        return Ok(addr);
    }
    if let Some(id) = contact.endpoint_id.as_deref() {
        if let Some(cached) = peer_addrs.get(id) {
            return Ok(cached.clone());
        }
        // ID-only dial: Iroh resolves current addresses through its address
        // lookup when online. Fails loudly offline.
        let endpoint_id: EndpointId = id.parse().map_err(|_| anyhow::anyhow!("bad endpoint id"))?;
        return Ok(EndpointAddr {
            id: endpoint_id,
            addrs: Default::default(),
        });
    }
    anyhow::bail!("no address for @{username} yet — they need to come online once")
}

/// Box-free coordinator handle: the trait uses native async fns, which are
/// not dyn-compatible, so dispatch over a closed enum instead.
enum AnyCoordinator {
    Local(LocalCoordinator),
    Cloud(CloudflareCoordinator),
}

impl AnyCoordinator {
    fn name(&self) -> &'static str {
        match self {
            AnyCoordinator::Local(_) => "local",
            AnyCoordinator::Cloud(_) => "cloudflare",
        }
    }
    async fn register(&self, record: &DirectoryRecord) -> anyhow::Result<()> {
        match self {
            AnyCoordinator::Local(c) => c.register(record).await,
            AnyCoordinator::Cloud(c) => c.register(record).await,
        }
    }
    async fn mailbox_put(&self, to: &str, object: &MailboxObject) -> anyhow::Result<()> {
        match self {
            AnyCoordinator::Local(c) => c.mailbox_put(to, object).await,
            AnyCoordinator::Cloud(c) => c.mailbox_put(to, object).await,
        }
    }
    async fn mailbox_get(&self, username: &str, now_ms: i64) -> anyhow::Result<Vec<MailboxObject>> {
        match self {
            AnyCoordinator::Local(c) => c.mailbox_get(username, now_ms).await,
            AnyCoordinator::Cloud(c) => c.mailbox_get(username, now_ms).await,
        }
    }
    async fn mailbox_ack(&self, username: &str, id: &str) -> anyhow::Result<()> {
        match self {
            AnyCoordinator::Local(c) => c.mailbox_ack(username, id).await,
            AnyCoordinator::Cloud(c) => c.mailbox_ack(username, id).await,
        }
    }
    async fn fetch_friend_requests(
        &self,
        username: &str,
    ) -> anyhow::Result<Vec<chat_coordinator::FriendDirective>> {
        match self {
            AnyCoordinator::Local(c) => c.fetch_friend_requests(username).await,
            AnyCoordinator::Cloud(c) => c.fetch_friend_requests(username).await,
        }
    }
    async fn publish_friend_request(
        &self,
        directive: &chat_coordinator::FriendDirective,
        to_username: &str,
    ) -> anyhow::Result<()> {
        match self {
            AnyCoordinator::Local(c) => c.publish_friend_request(directive, to_username).await,
            AnyCoordinator::Cloud(c) => c.publish_friend_request(directive, to_username).await,
        }
    }
}

fn coordinator_for(state: &AppState) -> anyhow::Result<AnyCoordinator> {
    let (kind, url) = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock unavailable"))?;
        (
            db.get_setting("coordinator")
                .ok()
                .flatten()
                .unwrap_or_else(|| "local".to_string()),
            db.get_setting("worker_url")
                .ok()
                .flatten()
                .unwrap_or_default(),
        )
    };
    if kind == "cloudflare" && !url.is_empty() {
        Ok(AnyCoordinator::Cloud(CloudflareCoordinator::new(&url)?))
    } else {
        let owner = my_username(state).unwrap_or_else(|_| "unknown".to_string());
        Ok(AnyCoordinator::Local(LocalCoordinator::new(
            state.data_dir.join("coordinator"),
            &owner,
        )))
    }
}

/// Worker URL when a shared coordinator is configured.
fn cloud_worker_url(state: &AppState) -> Option<String> {
    let db = state.db.lock().ok()?;
    let kind = db.get_setting("coordinator").ok().flatten()?;
    let url = db
        .get_setting("worker_url")
        .ok()
        .flatten()
        .unwrap_or_default();
    if kind == "cloudflare" && !url.is_empty() {
        Some(url)
    } else {
        None
    }
}

/// Queue a friend ask for offline pickup (ciphertext-free metadata only).
async fn publish_ask_to_queue(state: &AppState, peer_username: &str) -> anyhow::Result<()> {
    if cloud_worker_url(state).is_none() {
        anyhow::bail!("local mode");
    }
    let coord = coordinator_for(state)?;
    let me = my_username(state).map_err(|e| anyhow::anyhow!(e))?;
    let display = my_display_name(state);
    let public = state.identity.public();
    coord
        .publish_friend_request(
            &chat_coordinator::FriendDirective {
                id: Uuid::new_v4().to_string(),
                from_username: me,
                from_display_name: display,
                from_ed_pubkey_hex: chat_app_core::hex_encode(&public.ed_pubkey),
                from_x_pubkey_hex: chat_app_core::hex_encode(&public.x_pubkey),
                status: "pending".to_string(),
                created_at_ms: now_ms(),
            },
            peer_username,
        )
        .await
}

/// Publish our directory record (username → keys + endpoint bundle) so
/// friends can discover and dial us. Ciphertext never appears here — only
/// public identity material.
async fn register_self_async(app: &AppHandle) -> anyhow::Result<()> {
    let state: tauri::State<AppState> = app.state();
    register_self(&state).await
}

async fn register_self(state: &AppState) -> anyhow::Result<()> {
    let me = my_username(state).map_err(|e| anyhow::anyhow!(e))?;
    let display = my_display_name(state);
    let public = state.identity.public();
    let bundle = local_bundle_of(state);
    let endpoint_id = {
        let cache = state
            .peer_addrs
            .lock()
            .map_err(|_| anyhow::anyhow!("peer cache lock"))?;
        cache
            .get("__self__")
            .map(|a| a.id.to_string())
            .unwrap_or_default()
    };
    let record = DirectoryRecord {
        username: me,
        display_name: display,
        ed_pubkey_hex: chat_app_core::hex_encode(&public.ed_pubkey),
        x_pubkey_hex: chat_app_core::hex_encode(&public.x_pubkey),
        endpoint_id,
        endpoint_bundle: bundle,
        updated_at_ms: now_ms(),
    };
    let coord = coordinator_for(state)?;
    coord.register(&record).await?;
    Ok(())
}

/// Send one envelope to one peer. Updates the peer cache and clears that
/// peer's pending row on stream-acked delivery.
async fn exec_outbound(
    state: &AppState,
    peer_username: &str,
    envelope: &ProtocolEnvelope,
    message_id: &str,
) -> anyhow::Result<TransportDiagnostics> {
    let target = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock unavailable"))?;
        let cache = state
            .peer_addrs
            .lock()
            .map_err(|_| anyhow::anyhow!("peer cache lock"))?;
        dial_target(&db, &cache, peer_username)?
    };
    {
        let mut cache = state
            .peer_addrs
            .lock()
            .map_err(|_| anyhow::anyhow!("peer cache lock"))?;
        cache.insert(target.id.to_string(), target.clone());
    }
    let diagnostics = {
        // Clone the endpoint handle under a brief lock, then release it:
        // network I/O must never hold the shared transport mutex, or one
        // slow peer stalls every other sender (and every status check).
        let handle = {
            let guard = state.transport.lock().await;
            guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("transport unavailable"))?
                .endpoint_handle()
        };
        let result = chat_transport::send_via(&handle, &target, envelope).await;
        let guard = state.transport.lock().await;
        guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("transport unavailable"))?
            .finish_send(target.id, result)?
    };
    if let Ok(db) = state.db.lock() {
        let _ = db.dequeue_pending_for(message_id, peer_username);
    }
    Ok(diagnostics)
}

/// Record a failed send: backoff queue, plus encrypted mailbox fallback on
/// the shared coordinator once direct attempts keep failing.
async fn note_send_failure(
    state: &AppState,
    peer_username: &str,
    envelope: &ProtocolEnvelope,
    message_id: &str,
) {
    let now = now_ms();
    let attempt = {
        let db = match state.db.lock() {
            Ok(db) => db,
            Err(_) => return,
        };
        let attempt = db
            .get_pending(message_id, peer_username)
            .ok()
            .flatten()
            .map(|p| p.attempt_count)
            .unwrap_or(0);
        let delay = app_sync::retry_delay_ms(attempt as u32);
        let _ = db.enqueue_pending(
            &Uuid::new_v4().to_string(),
            message_id,
            peer_username,
            now + delay,
            "retrying",
        );
        let _ = db.set_message_status(message_id, "queued");
        attempt
    };
    if attempt >= 2 {
        let object = MailboxObject {
            id: Uuid::new_v4().to_string(),
            envelope_json: serde_json::to_string(envelope).unwrap_or_default(),
            created_at_ms: now,
            expires_at_ms: now + MAILBOX_TTL_MS,
        };
        if let Ok(coord) = coordinator_for(state)
            && coord.name() == "cloudflare"
            && coord.mailbox_put(peer_username, &object).await.is_ok()
            && let Ok(db) = state.db.lock()
        {
            let _ = db.dequeue_pending_for(message_id, peer_username);
        }
    }
}

fn emit_refresh(app: &AppHandle) {
    let _ = app.emit("hearth://refresh", ());
}

/// True when the Iroh endpoint is bound (transport exists at all).
fn transport_up(state: &AppState) -> bool {
    state
        .transport
        .try_lock()
        .map(|t| t.is_some())
        .unwrap_or(false)
}

fn notify(app: &AppHandle, title: &str, body: &str) {
    let state: tauri::State<AppState> = app.state();
    let dnd = state
        .presence
        .lock()
        .map(|tracker| tracker.effective(transport_up(&state)) == PresenceStatus::Dnd)
        .unwrap_or(false);
    if dnd {
        return;
    }
    let focused = app
        .get_webview_window("main")
        .and_then(|w| w.is_focused().ok())
        .unwrap_or(false);
    if focused {
        return;
    }
    use tauri_plugin_notification::NotificationExt;
    let preview: String = body.chars().take(120).collect();
    let _ = app
        .notification()
        .builder()
        .title(title)
        .body(preview)
        .show();
}

// ---------------------------------------------------------------------------
// Inbound routing
// ---------------------------------------------------------------------------

/// Identify which friend sent an envelope: endpoint match first, then
/// signature trial over known (non-blocked) keys. Returns (username, ed key).
fn identify_sender(
    db: &Database,
    envelope: &ProtocolEnvelope,
    from_endpoint: &str,
) -> Option<(String, [u8; 32])> {
    let contacts = db.list_contacts().ok()?;
    let mut ordered: Vec<&Contact> = contacts.iter().collect();
    ordered.sort_by_key(|c| c.endpoint_id.as_deref() != Some(from_endpoint));
    for contact in ordered {
        if contact.status == "blocked" {
            continue;
        }
        if let Some(ed) = contact.ed_pubkey.as_deref() {
            if ed.len() != 32 {
                continue;
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(ed);
            if chat_app_core::verify_envelope_signature(&key, envelope).is_ok() {
                return Some((contact.username.clone(), key));
            }
        }
    }
    None
}

fn contact_x_pub(contact: &Contact) -> Option<[u8; 32]> {
    contact.x25519_pubkey.as_deref().and_then(|b| {
        if b.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(b);
            Some(out)
        } else {
            None
        }
    })
}

fn note_endpoint(db: &Database, username: &str, endpoint_id: &str, now: i64) {
    if let Ok(Some(mut contact)) = db.find_contact(username)
        && contact.endpoint_id.as_deref() != Some(endpoint_id)
    {
        contact.endpoint_id = Some(endpoint_id.to_string());
        let _ = db.upsert_contact(&contact, now);
    }
}

struct RouteOutcome {
    works: Vec<OutboundWork>,
    notify: Option<(String, String)>,
    /// In-app toast, shown even when the window is focused (unlike `notify`,
    /// which only fires OS notifications when unfocused).
    toast: Option<String>,
    changed: bool,
}

/// Open a handshake frame with a contact's keys, enforcing that the sealed
/// sender name matches the contact it verified against.
fn open_handshake(
    state: &AppState,
    me: &str,
    contact: &Contact,
    envelope: &ProtocolEnvelope,
) -> anyhow::Result<ChatPayload> {
    let peer_x = contact_x_pub(contact).ok_or_else(|| anyhow::anyhow!("no key"))?;
    let context = match envelope.message_type {
        MessageType::FriendRequest => format!("friend-ask:{}>{me}", contact.username),
        MessageType::FriendResponse => format!("friend-answer:{}>{me}", contact.username),
        _ => anyhow::bail!("not a handshake frame"),
    };
    let payload =
        app_friends::open_friend_payload(&state.identity, &peer_x, &context, &envelope.ciphertext)?;
    if payload.sender() != contact.username {
        anyhow::bail!("handshake sender mismatch");
    }
    Ok(payload)
}

#[allow(clippy::too_many_arguments)]
fn handle_friend_ask(
    state: &AppState,
    db: &Database,
    me: &str,
    from: &str,
    contact: &Contact,
    envelope: &ProtocolEnvelope,
    from_endpoint: &str,
    now: i64,
    outcome: &mut RouteOutcome,
) -> anyhow::Result<()> {
    let _ = me;
    let payload = open_handshake(state, me, contact, envelope)?;
    let ChatPayload::FriendAsk {
        endpoint_bundle, ..
    } = &payload
    else {
        anyhow::bail!("not a friend ask")
    };
    let row = app_friends::receive_friend_ask(db, &payload, now)?;
    if !endpoint_bundle.is_empty()
        && let Some(mut contact) = db.find_contact(from)?
    {
        contact.endpoint_bundle = Some(endpoint_bundle.clone());
        db.upsert_contact(&contact, now)?;
    }
    note_endpoint(db, from, from_endpoint, now);
    outcome.notify = Some((
        "Friend request".to_string(),
        format!("@{from} wants to chat"),
    ));
    outcome.changed = true;
    let _ = row;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_friend_answer(
    state: &AppState,
    db: &Database,
    me: &str,
    from: &str,
    contact: &Contact,
    envelope: &ProtocolEnvelope,
    from_endpoint: &str,
    now: i64,
    outcome: &mut RouteOutcome,
) -> anyhow::Result<()> {
    let _ = me;
    let payload = open_handshake(state, me, contact, envelope)?;
    if let ChatPayload::FriendAnswer {
        accepted,
        endpoint_bundle,
        ..
    } = payload
    {
        if accepted {
            app_friends::receive_friend_answer(db, from, true, &endpoint_bundle, now)?;
            note_endpoint(db, from, from_endpoint, now);
            outcome.notify = Some((
                "Friend added".to_string(),
                format!("@{from} accepted your request"),
            ));
        } else {
            app_friends::receive_friend_answer(db, from, false, "", now)?;
            outcome.notify = Some(("Request declined".to_string(), format!("@{from} declined")));
        }
        outcome.changed = true;
    }
    Ok(())
}

/// Keep a handshake envelope we cannot open yet (unknown sender). It is
/// trial-opened after the matching invite is imported, so exchanging codes
/// in either order works. Bounded by message id + 7-day TTL.
fn stash_unknown(
    _state: &AppState,
    db: &Database,
    envelope: &ProtocolEnvelope,
    from_endpoint: &str,
    now: i64,
    outcome: &mut RouteOutcome,
) -> anyhow::Result<()> {
    let json = serde_json::to_string(envelope)?;
    db.stash_envelope(
        &envelope.message_id.to_string(),
        from_endpoint,
        &json,
        now,
        now + MAILBOX_TTL_MS,
    )?;
    outcome.toast = Some(
        "Got a friend request from an unknown device — paste their invite code to read it."
            .to_string(),
    );
    outcome.changed = true;
    Ok(())
}

/// After importing `username`'s invite, trial-open stashed envelopes with
/// their key and route whatever authenticates. Returns surfaced requests.
fn drain_stash_for(state: &AppState, username: &str) -> usize {
    let now = now_ms();
    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return 0,
    };
    let me = my_username(state).unwrap_or_default();
    if me.is_empty() {
        return 0;
    }
    let contact = match db.find_contact(username) {
        Ok(Some(contact)) => contact,
        _ => return 0,
    };
    if contact_x_pub(&contact).is_none() {
        return 0;
    }
    let stashed = db.list_stash(now).unwrap_or_default();
    if stashed.is_empty() {
        return 0;
    }
    let mut surfaced = 0;
    for item in stashed {
        let parsed: Result<ProtocolEnvelope, _> = serde_json::from_str(&item.envelope_json);
        let routed = (|| -> anyhow::Result<bool> {
            let envelope = parsed?;
            // Trial against ONLY the new contact: cheap and precise.
            let mut ed = [0u8; 32];
            let ed_bytes = contact
                .ed_pubkey
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("no ed key"))?;
            if ed_bytes.len() != 32 {
                anyhow::bail!("bad ed key");
            }
            ed.copy_from_slice(ed_bytes);
            chat_app_core::verify_envelope_signature(&ed, &envelope)?;
            let mut outcome = RouteOutcome {
                works: Vec::new(),
                notify: None,
                toast: None,
                changed: false,
            };
            match envelope.message_type {
                MessageType::FriendRequest => {
                    handle_friend_ask(
                        state,
                        &db,
                        &me,
                        username,
                        &contact,
                        &envelope,
                        &item.endpoint_id,
                        now,
                        &mut outcome,
                    )?;
                }
                MessageType::FriendResponse => {
                    handle_friend_answer(
                        state,
                        &db,
                        &me,
                        username,
                        &contact,
                        &envelope,
                        &item.endpoint_id,
                        now,
                        &mut outcome,
                    )?;
                }
                _ => anyhow::bail!("not stashed handshake"),
            }
            if outcome.changed {
                surfaced += 1;
            }
            Ok(true)
        })();
        // Authenticated (or provably not ours): never retry the same bytes.
        if routed.is_ok() {
            let _ = db.unstash(&item.message_id);
        }
    }
    surfaced
}

fn route_inbound(state: &AppState, inbound: &InboundEnvelope) -> anyhow::Result<RouteOutcome> {
    let now = now_ms();
    let envelope = &inbound.envelope;
    let from_endpoint = inbound.from.map(|id| id.to_string()).unwrap_or_default();
    let mut outcome = RouteOutcome {
        works: Vec::new(),
        notify: None,
        toast: None,
        changed: false,
    };
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("database lock unavailable"))?;
    let me = db
        .load_profile()?
        .map(|(username, _)| username)
        .unwrap_or_default();

    // -- Friend handshake frames. Known senders open immediately; unknown
    // senders stash undecrypted until their invite is imported (drain on
    // import trial-opens with the new keys). Either order of exchanging
    // invite codes works.
    if envelope.message_type == MessageType::FriendRequest {
        match identify_sender(&db, envelope, &from_endpoint) {
            Some((from, _)) => {
                let contact = db
                    .find_contact(&from)?
                    .ok_or_else(|| anyhow::anyhow!("unknown contact"))?;
                handle_friend_ask(
                    state,
                    &db,
                    &me,
                    &from,
                    &contact,
                    envelope,
                    &from_endpoint,
                    now,
                    &mut outcome,
                )?;
            }
            None => {
                stash_unknown(state, &db, envelope, &from_endpoint, now, &mut outcome)?;
            }
        }
        return Ok(outcome);
    }
    if envelope.message_type == MessageType::FriendResponse {
        match identify_sender(&db, envelope, &from_endpoint) {
            Some((from, _)) => {
                let contact = db
                    .find_contact(&from)?
                    .ok_or_else(|| anyhow::anyhow!("unknown contact"))?;
                handle_friend_answer(
                    state,
                    &db,
                    &me,
                    &from,
                    &contact,
                    envelope,
                    &from_endpoint,
                    now,
                    &mut outcome,
                )?;
            }
            None => {
                stash_unknown(state, &db, envelope, &from_endpoint, now, &mut outcome)?;
            }
        }
        return Ok(outcome);
    }

    // -- Presence heartbeats (ephemeral, no conversation needed) --
    if envelope.message_type == MessageType::Presence {
        let (from, _) = identify_sender(&db, envelope, &from_endpoint)
            .ok_or_else(|| anyhow::anyhow!("presence from unknown device"))?;
        if from != me {
            let contact = db
                .find_contact(&from)?
                .ok_or_else(|| anyhow::anyhow!("unknown contact"))?;
            if contact.status == "blocked" {
                anyhow::bail!("ignoring presence from blocked user");
            }
            let peer_x = contact_x_pub(&contact).ok_or_else(|| anyhow::anyhow!("no key"))?;
            let payload = chat_app_core::open_presence_payload(
                &state.identity.x_secret,
                &peer_x,
                &from,
                &me,
                &envelope.ciphertext,
            )?;
            if let ChatPayload::Presence { status, .. } = payload {
                if let Ok(mut tracker) = state.presence.lock() {
                    tracker.peer_update(&from, status);
                }
                note_endpoint(&db, &from, &from_endpoint, now);
                outcome.changed = true;
            }
        }
        return Ok(outcome);
    }

    // -- Friend-gated chat content --
    let (from, _) = identify_sender(&db, envelope, &from_endpoint).ok_or_else(|| {
        anyhow::anyhow!("message from unknown device — add them as a friend first")
    })?;
    if from == me {
        return Ok(outcome);
    }
    let contact = db
        .find_contact(&from)?
        .ok_or_else(|| anyhow::anyhow!("unknown contact"))?;
    if contact.status == "blocked" {
        anyhow::bail!("ignoring message from blocked user");
    }
    let peer_x = contact_x_pub(&contact).ok_or_else(|| anyhow::anyhow!("no encryption key"))?;
    note_endpoint(&db, &from, &from_endpoint, now);

    let conversation_id = envelope.conversation_id.to_string();
    let conversation = db
        .list_conversations()?
        .into_iter()
        .find(|c| c.id == conversation_id)
        .ok_or_else(|| anyhow::anyhow!("unknown conversation"))?;

    if conversation.kind == "dm" {
        let peer = conversation.members.first().cloned().unwrap_or_default();
        if peer != from {
            anyhow::bail!("dm sender is not the conversation peer");
        }
        let payload = chat_app_core::open_dm_payload(
            &state.identity.x_secret,
            &peer_x,
            &conversation_id,
            &envelope.ciphertext,
        )?;
        if payload.sender() != from {
            anyhow::bail!("payload sender mismatch");
        }
        apply_dm_payload(
            state,
            &db,
            &from,
            &conversation_id,
            envelope,
            payload,
            now,
            &mut outcome,
        )?;
    } else {
        if !conversation.members.contains(&from) {
            anyhow::bail!("sender is not a group member");
        }
        if envelope.message_type == MessageType::GroupCommit {
            // Epoch rotation addressed to us, DM-sealed.
            let payload = chat_app_core::open_dm_payload(
                &state.identity.x_secret,
                &peer_x,
                &conversation_id,
                &envelope.ciphertext,
            )?;
            app_groups::receive_group_key(&db, &me, &payload, now)?;
            outcome.notify = Some((
                "Group updated".to_string(),
                "Encryption rotated for a group".to_string(),
            ));
            outcome.changed = true;
            return Ok(outcome);
        }
        // Group payloads are opened newest-epoch-first (see open_group_best).
        let (payload, _used_epoch) = app_groups::open_group_best(
            &db,
            &state.identity,
            &conversation_id,
            &me,
            envelope.sequence,
            &envelope.ciphertext,
            None,
        )?;
        if payload.sender() != from {
            anyhow::bail!("payload sender mismatch");
        }
        apply_group_payload(
            state,
            &db,
            &from,
            &conversation_id,
            envelope,
            payload,
            now,
            &mut outcome,
        )?;
    }
    let _ = db.update_sync_cursor(&from, &conversation_id, envelope.sequence as i64, now);
    Ok(outcome)
}

fn store_message(
    db: &Database,
    envelope: &ProtocolEnvelope,
    conversation_id: &str,
    from: &str,
    message_type: &str,
    body: String,
    reply_to: Option<String>,
) -> anyhow::Result<bool> {
    db.insert_message(&Message {
        id: envelope.message_id.to_string(),
        conversation_id: conversation_id.to_string(),
        sender_device_id: envelope.sender_device_id.to_string(),
        sender_username: from.to_string(),
        message_type: message_type.to_string(),
        body,
        ciphertext: envelope.ciphertext.clone(),
        sequence: envelope.sequence as i64,
        status: "delivered".to_string(),
        reply_to,
        created_at_ms: envelope.created_at_ms,
        edited_at_ms: None,
        deleted_at_ms: None,
    })
}

#[allow(clippy::too_many_arguments)] // domain params stay explicit; no context-object indirection
fn apply_dm_payload(
    state: &AppState,
    db: &Database,
    from: &str,
    conversation_id: &str,
    envelope: &ProtocolEnvelope,
    payload: ChatPayload,
    now: i64,
    outcome: &mut RouteOutcome,
) -> anyhow::Result<()> {
    match payload {
        ChatPayload::Text { body, reply_to, .. } => {
            if store_message(
                db,
                envelope,
                conversation_id,
                from,
                "Message",
                body.clone(),
                reply_to,
            )? {
                outcome.changed = true;
                outcome.notify = Some((format!("@{from}"), body.chars().take(80).collect()));
            }
        }
        ChatPayload::Edit { ref_id, body, .. } => {
            if let Some(original) = db.get_message(&ref_id)?
                && original.sender_username == from
            {
                db.edit_message(&ref_id, &body, &envelope.ciphertext, now)?;
                outcome.changed = true;
            }
        }
        ChatPayload::Delete { ref_id, .. } => {
            if let Some(original) = db.get_message(&ref_id)?
                && original.sender_username == from
            {
                db.tombstone_message(&ref_id, now)?;
                outcome.changed = true;
            }
        }
        ChatPayload::Read { ref_ids, .. } => {
            if app_sync::apply_read_receipt(db, conversation_id, from, &ref_ids)? > 0 {
                outcome.changed = true;
            }
        }
        ChatPayload::Typing { typing, .. } => {
            if let Ok(mut tracker) = state.typing.lock() {
                tracker.set_typing(conversation_id, from, typing);
                outcome.changed = true;
            }
        }
        ChatPayload::FileOffer { file, .. } => {
            receive_file_offer(state, db, from, conversation_id, envelope, file, outcome)?;
        }
        ChatPayload::FileChunk {
            file_id,
            index,
            data,
            ..
        } => {
            receive_file_chunk(
                state,
                db,
                from,
                conversation_id,
                &file_id,
                index,
                &data,
                outcome,
            )?;
        }
        ChatPayload::FileAccept { file_id, have, .. } => {
            send_missing_chunks(state, db, from, conversation_id, &file_id, &have, outcome)?;
        }
        ChatPayload::FileCancel { file_id, .. } => {
            if let Some(row) = db.load_file(&file_id)? {
                db.save_file(
                    &FileTransfer {
                        state: "cancelled".to_string(),
                        ..row
                    },
                    now,
                )?;
                app_files::cancel_incoming(&state.files_dir, &file_id);
                outcome.changed = true;
            }
        }
        ChatPayload::SyncRequest {
            conversation_id: requested,
            after_sequence,
            ..
        } => {
            for id in app_sync::sync_gap(db, &requested, after_sequence)? {
                if let Some(message) = db.get_message(&id)? {
                    let conversation_uuid = envelope.conversation_id;
                    let fresh = app_sync::resend_envelope(
                        &state.identity,
                        state.device_uuid,
                        conversation_uuid,
                        &message,
                        now,
                    )?;
                    outcome.works.push(OutboundWork {
                        peer_username: from.to_string(),
                        envelope: fresh,
                    });
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // domain params stay explicit; no context-object indirection
fn apply_group_payload(
    state: &AppState,
    db: &Database,
    from: &str,
    conversation_id: &str,
    envelope: &ProtocolEnvelope,
    payload: ChatPayload,
    now: i64,
    outcome: &mut RouteOutcome,
) -> anyhow::Result<()> {
    match payload {
        ChatPayload::Text { body, reply_to, .. } => {
            if store_message(
                db,
                envelope,
                conversation_id,
                from,
                "Message",
                body.clone(),
                reply_to,
            )? {
                outcome.changed = true;
                outcome.notify = Some((format!("@{from}"), body.chars().take(80).collect()));
            }
        }
        ChatPayload::Edit { ref_id, body, .. } => {
            if let Some(original) = db.get_message(&ref_id)?
                && original.sender_username == from
            {
                db.edit_message(&ref_id, &body, &envelope.ciphertext, now)?;
                outcome.changed = true;
            }
        }
        ChatPayload::Delete { ref_id, .. } => {
            if let Some(original) = db.get_message(&ref_id)?
                && original.sender_username == from
            {
                db.tombstone_message(&ref_id, now)?;
                outcome.changed = true;
            }
        }
        ChatPayload::Read { ref_ids, .. } => {
            if app_sync::apply_read_receipt(db, conversation_id, from, &ref_ids)? > 0 {
                outcome.changed = true;
            }
        }
        ChatPayload::Typing { typing, .. } => {
            if let Ok(mut tracker) = state.typing.lock() {
                tracker.set_typing(conversation_id, from, typing);
                outcome.changed = true;
            }
        }
        ChatPayload::GroupMeta { name, .. } => {
            db.rename_conversation(conversation_id, &name, now)?;
            if store_message(
                db,
                envelope,
                conversation_id,
                from,
                "GroupMessage",
                format!("@{from} renamed the group to {name}"),
                None,
            )? {
                outcome.changed = true;
            }
        }
        ChatPayload::FileOffer { file, .. } => {
            receive_file_offer(state, db, from, conversation_id, envelope, file, outcome)?;
        }
        ChatPayload::FileChunk {
            file_id,
            index,
            data,
            ..
        } => {
            receive_file_chunk(
                state,
                db,
                from,
                conversation_id,
                &file_id,
                index,
                &data,
                outcome,
            )?;
        }
        ChatPayload::FileAccept { file_id, have, .. } => {
            send_missing_chunks(state, db, from, conversation_id, &file_id, &have, outcome)?;
        }
        ChatPayload::FileCancel { file_id, .. } => {
            if let Some(row) = db.load_file(&file_id)? {
                db.save_file(
                    &FileTransfer {
                        state: "cancelled".to_string(),
                        ..row
                    },
                    now,
                )?;
                app_files::cancel_incoming(&state.files_dir, &file_id);
                outcome.changed = true;
            }
        }
        _ => {}
    }
    Ok(())
}

fn receive_file_offer(
    _state: &AppState,
    db: &Database,
    from: &str,
    conversation_id: &str,
    envelope: &ProtocolEnvelope,
    offer: app_files::FileOfferBody,
    outcome: &mut RouteOutcome,
) -> anyhow::Result<()> {
    if db.load_file(&offer.file_id)?.is_some() {
        return Ok(());
    }
    let now = now_ms();
    db.save_file(
        &FileTransfer {
            id: offer.file_id.clone(),
            conversation_id: conversation_id.to_string(),
            filename: offer.filename.clone(),
            mime_type: offer.mime_type.clone(),
            size_bytes: offer.size_bytes as i64,
            sha256_hex: offer.sha256_hex.clone(),
            state: "incoming".to_string(),
            bytes_done: 0,
            local_path: None,
            created_at_ms: now,
        },
        now,
    )?;
    db.save_offer_json(&offer.file_id, &serde_json::to_string(&offer)?)?;
    if store_message(
        db,
        envelope,
        conversation_id,
        from,
        "FileOffer",
        format!("File: {}", offer.filename),
        None,
    )? {
        outcome.changed = true;
    }
    outcome.notify = Some((format!("@{from}"), format!("Sent file {}", offer.filename)));
    Ok(())
}

#[allow(clippy::too_many_arguments)] // domain params stay explicit; no context-object indirection
fn receive_file_chunk(
    state: &AppState,
    db: &Database,
    from: &str,
    conversation_id: &str,
    file_id: &str,
    index: u32,
    data: &[u8],
    outcome: &mut RouteOutcome,
) -> anyhow::Result<()> {
    let now = now_ms();
    let offer_json = db
        .load_offer_json(file_id)?
        .ok_or_else(|| anyhow::anyhow!("no offer for file"))?;
    let offer: app_files::FileOfferBody = serde_json::from_str(&offer_json)?;
    let progress = app_files::apply_chunk(&state.files_dir, &offer, index, data)?;
    if let Some(mut row) = db.load_file(file_id)? {
        row.bytes_done = (progress.received_chunks * app_files::CHUNK_BYTES)
            .min(offer.size_bytes as usize) as i64;
        if progress.complete {
            row.state = "complete".to_string();
            row.local_path = Some(
                state
                    .files_dir
                    .join(&offer.filename)
                    .to_string_lossy()
                    .to_string(),
            );
        }
        db.save_file(&row, now)?;
    }
    outcome.changed = true;
    if progress.complete {
        let me = my_username(state).map_err(|e| anyhow::anyhow!(e))?;
        let accept = ChatPayload::FileAccept {
            from: me,
            file_id: file_id.to_string(),
            have: (0..progress.total_chunks as u32).collect(),
        };
        if let Some(envelope) = seal_control(state, db, conversation_id, accept, now)? {
            outcome.works.push(OutboundWork {
                peer_username: from.to_string(),
                envelope,
            });
        }
        outcome.notify = Some(("Download complete".to_string(), offer.filename.clone()));
    }
    Ok(())
}

fn send_missing_chunks(
    state: &AppState,
    db: &Database,
    from: &str,
    conversation_id: &str,
    file_id: &str,
    have: &[u32],
    outcome: &mut RouteOutcome,
) -> anyhow::Result<()> {
    let now = now_ms();
    let offer_json = db
        .load_offer_json(file_id)?
        .ok_or_else(|| anyhow::anyhow!("unknown file"))?;
    let offer: app_files::FileOfferBody = serde_json::from_str(&offer_json)?;
    let total = offer.manifest.chunk_hashes.len() as u32;
    if have.len() as u32 >= total {
        if let Some(row) = db.load_file(file_id)? {
            db.save_file(
                &FileTransfer {
                    state: "complete".to_string(),
                    ..row
                },
                now,
            )?;
            let _ = std::fs::remove_file(state.files_dir.join(format!("{file_id}.src")));
        }
        outcome.changed = true;
        return Ok(());
    }
    let src = std::fs::read(state.files_dir.join(format!("{file_id}.src")))?;
    let me = my_username(state).map_err(|e| anyhow::anyhow!(e))?;
    for index in 0..total {
        if have.contains(&index) {
            continue;
        }
        let start = index as usize * app_files::CHUNK_BYTES;
        let end = (start + app_files::CHUNK_BYTES).min(src.len());
        let sealed = app_files::seal_chunk(&offer.file_key, index, &src[start..end])?;
        let payload = ChatPayload::FileChunk {
            from: me.clone(),
            file_id: file_id.to_string(),
            index,
            data: sealed,
        };
        if let Some(envelope) = seal_control(state, db, conversation_id, payload, now)? {
            outcome.works.push(OutboundWork {
                peer_username: from.to_string(),
                envelope,
            });
        }
    }
    Ok(())
}

/// Seal a control payload (acks, typing, chunk flow) without staging a
/// message row. Group control seals ride a reserved high sequence lane so
/// they can never collide with staged message sequences.
/// Seal a presence heartbeat for one friend (no conversation, no staging).
fn seal_presence_envelope(
    state: &AppState,
    db: &Database,
    peer_username: &str,
    status: PresenceStatus,
    now: i64,
) -> anyhow::Result<ProtocolEnvelope> {
    let me = my_username(state).map_err(|e| anyhow::anyhow!(e))?;
    let contact = db
        .find_contact(peer_username)?
        .ok_or_else(|| anyhow::anyhow!("unknown contact"))?;
    let peer_x = contact_x_pub(&contact).ok_or_else(|| anyhow::anyhow!("no key"))?;
    let ciphertext = chat_app_core::seal_presence_payload(
        &state.identity.x_secret,
        &peer_x,
        &me,
        peer_username,
        status,
    )?;
    Ok(chat_app_core::build_envelope(
        &state.identity,
        state.device_uuid,
        Uuid::new_v4(),
        Uuid::new_v4(),
        MessageType::Presence,
        0,
        ciphertext,
        now,
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerPresenceView {
    username: String,
    status: String,
    label: String,
    fresh: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PresenceView {
    status: String,
    label: String,
    peers: Vec<PeerPresenceView>,
}

fn seal_control(
    state: &AppState,
    db: &Database,
    conversation_id: &str,
    payload: ChatPayload,
    now: i64,
) -> anyhow::Result<Option<ProtocolEnvelope>> {
    let me = my_username(state).map_err(|e| anyhow::anyhow!(e))?;
    let conversation = db
        .list_conversations()?
        .into_iter()
        .find(|c| c.id == conversation_id)
        .ok_or_else(|| anyhow::anyhow!("unknown conversation"))?;
    let (ciphertext, seq) = if conversation.kind == "dm" {
        let peer = conversation.members.first().cloned().unwrap_or_default();
        let contact = db
            .find_contact(&peer)?
            .ok_or_else(|| anyhow::anyhow!("unknown contact"))?;
        let peer_x = contact_x_pub(&contact).ok_or_else(|| anyhow::anyhow!("no key"))?;
        (
            chat_app_core::seal_dm_payload(
                &state.identity.x_secret,
                &peer_x,
                conversation_id,
                &payload,
            )?,
            0u64,
        )
    } else {
        let group = db
            .load_group(conversation_id)?
            .ok_or_else(|| anyhow::anyhow!("unknown group"))?;
        let key = app_groups::own_epoch_key(
            db,
            &state.identity,
            conversation_id,
            group.current_epoch,
            &me,
        )?;
        let lane = (u32::MAX as u64) - (now as u64 % 1_000_000);
        (
            chat_app_core::seal_group_payload(&key, lane, &payload)?,
            lane,
        )
    };
    let conversation_uuid = Uuid::parse_str(conversation_id).unwrap_or_else(|_| Uuid::new_v4());
    Ok(Some(chat_app_core::build_envelope(
        &state.identity,
        state.device_uuid,
        conversation_uuid,
        Uuid::new_v4(),
        payload.message_type(),
        seq,
        ciphertext,
        now,
    )))
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn app_state(app: AppHandle) -> Result<AppStateView, String> {
    let state: tauri::State<AppState> = app.state();
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let profile = db.load_profile().map_err(|e| e.to_string())?;
    let coordinator = db
        .get_setting("coordinator")
        .map_err(|e| e.to_string())?
        .unwrap_or_else(|| "local".to_string());
    let worker_url = db
        .get_setting("worker_url")
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let relay_enabled = db
        .get_setting("relay_enabled")
        .map_err(|e| e.to_string())?
        .map(|v| v != "0")
        .unwrap_or(true);
    drop(db);
    let always_on_top = app
        .get_webview_window("main")
        .and_then(|w| w.is_always_on_top().ok())
        .unwrap_or(true);
    let connection = {
        let guard = state.transport.try_lock().map_err(|_| "busy".to_string())?;
        match guard.as_ref() {
            Some(_) => "Ready",
            None => "Offline",
        }
        .to_string()
    };
    Ok(AppStateView {
        profile_exists: profile.is_some(),
        username: profile.clone().map(|(username, _)| username),
        display_name: profile.map(|(_, display)| display),
        key_backend: match state.key_backend {
            KeyBackend::OsKeyring => "os-keyring",
            KeyBackend::File => "file-0600",
        }
        .to_string(),
        coordinator,
        worker_url,
        relay_enabled,
        shortcut_ok: state.shortcut_ok.lock().map(|v| *v).unwrap_or(false),
        always_on_top,
        connection,
    })
}

#[tauri::command]
fn create_profile(app: AppHandle, username: String, display_name: String) -> Result<(), String> {
    let state: tauri::State<AppState> = app.state();
    {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        chat_app_core::create_profile(&db, &username, &display_name, now_ms())
            .map_err(|e| e.to_string())?;
        let (stored_username, _) = db
            .load_profile()
            .map_err(|e| e.to_string())?
            .ok_or("profile missing")?;
        let public = state.identity.public();
        db.save_device(&DeviceRecord {
            id: state.device_uuid.to_string(),
            username: stored_username,
            device_name: "Desktop".to_string(),
            ed25519_pubkey: public.ed_pubkey.to_vec(),
            x25519_pubkey: public.x_pubkey.to_vec(),
            iroh_endpoint_id: String::new(),
            created_at_ms: now_ms(),
            revoked_at_ms: None,
        })
        .map_err(|e| e.to_string())?;
    }
    {
        let app_clone = app.clone();
        tauri::async_runtime::spawn(async move {
            let _ = register_self_async(&app_clone).await;
        });
    }
    emit_refresh(&app);
    Ok(())
}

#[tauri::command]
fn search_messages(
    app: AppHandle,
    conversation_id: String,
    query: String,
) -> Result<Vec<Message>, String> {
    let trimmed = query.trim();
    if trimmed.chars().count() < 2 || trimmed.chars().count() > 80 {
        return Err("Search needs 2–80 characters.".to_string());
    }
    let state: tauri::State<AppState> = app.state();
    mark_activity(&state);
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.search_messages(&conversation_id, trimmed, 50)
        .map_err(|e| e.to_string())
}

/// Log out: wipe profile, friends, chats, requests and related state from
/// this device. Device keys and transport stay (installation-bound), so a
/// fresh profile on the same install just works. App settings survive.
#[tauri::command]
fn logout(app: AppHandle) -> Result<(), String> {
    let state: tauri::State<AppState> = app.state();
    {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        db.wipe_user_data().map_err(|e| e.to_string())?;
    }
    if let Ok(mut typing) = state.typing.lock() {
        *typing = TypingTracker::new();
    }
    if let Ok(mut presence) = state.presence.lock() {
        *presence = PresenceTracker::new();
    }
    if let Ok(mut cache) = state.peer_addrs.lock() {
        cache.retain(|key, _| key == "__self__");
    }
    if let Ok(mut accepts) = state.file_accepts.lock() {
        accepts.clear();
    }
    emit_refresh(&app);
    Ok(())
}

#[tauri::command]
fn list_chats(app: AppHandle) -> Result<Vec<ChatSummary>, String> {
    let state: tauri::State<AppState> = app.state();
    let me = my_username(&state).unwrap_or_default();
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.list_conversations()
        .map(|convs| convs.into_iter().map(|c| summarize(&db, &me, c)).collect())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn open_chat(app: AppHandle, conversation_id: String) -> Result<ChatDetail, String> {
    let state: tauri::State<AppState> = app.state();
    mark_activity(&state);
    let me = my_username(&state).unwrap_or_default();
    let detail = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let conv = db
            .list_conversations()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|c| c.id == conversation_id)
            .ok_or_else(|| "conversation not found".to_string())?;
        let messages = db
            .list_messages(&conversation_id, 500)
            .map_err(|e| e.to_string())?;
        let files = db.list_files(&conversation_id).map_err(|e| e.to_string())?;
        let typists = state
            .typing
            .lock()
            .map(|mut t| t.active_typists(&conversation_id))
            .unwrap_or_default();
        ChatDetail {
            conversation: summarize(&db, &me, conv),
            messages,
            files,
            typists,
        }
    };
    let read_ids: Vec<String> = detail
        .messages
        .iter()
        .filter(|m| m.sender_username != me && m.status == "delivered")
        .map(|m| m.id.clone())
        .collect();
    if !read_ids.is_empty() {
        let app_clone = app.clone();
        tauri::async_runtime::spawn(async move {
            let _ = mark_read_inner(&app_clone, &conversation_id, &read_ids).await;
        });
    }
    Ok(detail)
}

async fn mark_read_inner(
    app: &AppHandle,
    conversation_id: &str,
    read_ids: &[String],
) -> anyhow::Result<()> {
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let works = {
        let db = state.db.lock().map_err(|_| anyhow::anyhow!("db lock"))?;
        let me = my_username(&state).map_err(|e| anyhow::anyhow!(e))?;
        for id in read_ids {
            let _ = db.set_message_status(id, "read");
        }
        let conversation = db
            .list_conversations()?
            .into_iter()
            .find(|c| c.id == conversation_id)
            .ok_or_else(|| anyhow::anyhow!("unknown conversation"))?;
        let payload = ChatPayload::Read {
            from: me.clone(),
            ref_ids: read_ids.to_vec(),
        };
        let envelope = seal_control(&state, &db, conversation_id, payload, now)?
            .ok_or_else(|| anyhow::anyhow!("seal failed"))?;
        conversation
            .members
            .into_iter()
            .filter(|m| m != &me)
            .map(|peer| OutboundWork {
                peer_username: peer,
                envelope: envelope.clone(),
            })
            .collect::<Vec<_>>()
    };
    for work in works {
        let id = work.envelope.message_id.to_string();
        let _ = exec_outbound(&state, &work.peer_username, &work.envelope, &id).await;
    }
    emit_refresh(app);
    Ok(())
}

#[tauri::command]
async fn send_text(
    app: AppHandle,
    conversation_id: String,
    body: String,
    reply_to: Option<String>,
) -> Result<String, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 2000 {
        return Err("Message must be 1–2000 characters.".to_string());
    }
    let state: tauri::State<AppState> = app.state();
    mark_activity(&state);
    let now = now_ms();
    // NOTE: the db lock is held across peek-seal-stage so the peeked group
    // sequence and the staged sequence cannot diverge.
    let (message_id, envelope, peers): (String, ProtocolEnvelope, Vec<String>) = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let me = my_username(&state)?;
        let conversation = db
            .list_conversations()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|c| c.id == conversation_id)
            .ok_or_else(|| "conversation not found".to_string())?;
        let (ciphertext, payload) = if conversation.kind == "dm" {
            let peer = conversation
                .members
                .first()
                .cloned()
                .ok_or("dm has no peer")?;
            let contact = db
                .find_contact(&peer)
                .map_err(|e| e.to_string())?
                .ok_or("unknown contact")?;
            if contact.status != "friend" {
                return Err("that user is not a friend".to_string());
            }
            let peer_x = contact_x_pub(&contact).ok_or("no encryption key")?;
            let payload = ChatPayload::Text {
                from: me.clone(),
                body: trimmed.to_string(),
                reply_to: reply_to.clone(),
                epoch: None,
            };
            let sealed = chat_app_core::seal_dm_payload(
                &state.identity.x_secret,
                &peer_x,
                &conversation_id,
                &payload,
            )
            .map_err(|e| e.to_string())?;
            (sealed, payload)
        } else {
            let seq = db
                .next_sequence(&conversation_id, &state.device_uuid.to_string())
                .map_err(|e| e.to_string())? as u64;
            let (sealed, _epoch) = app_groups::seal_group_text(
                &db,
                &state.identity,
                &conversation_id,
                &me,
                trimmed,
                reply_to.clone(),
                seq,
            )
            .map_err(|e| e.to_string())?;
            let payload = ChatPayload::Text {
                from: me.clone(),
                body: trimmed.to_string(),
                reply_to: reply_to.clone(),
                epoch: None,
            };
            (sealed, payload)
        };
        let (message, envelope) = chat_app_core::stage_message(
            &db,
            &state.identity,
            state.device_uuid,
            &me,
            &conversation,
            &payload,
            trimmed,
            ciphertext,
            now,
        )
        .map_err(|e| e.to_string())?;
        let peers: Vec<String> = conversation
            .members
            .into_iter()
            .filter(|m| m != &me)
            .collect();
        (message.id.clone(), envelope, peers)
    };
    let mut failures = 0;
    for peer in &peers {
        if exec_outbound(&state, peer, &envelope, &message_id)
            .await
            .is_err()
        {
            failures += 1;
            note_send_failure(&state, peer, &envelope, &message_id).await;
        }
    }
    {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let _ = db.set_message_status(
            &message_id,
            if failures == 0 { "delivered" } else { "queued" },
        );
    }
    emit_refresh(&app);
    Ok(message_id)
}

#[tauri::command]
async fn edit_message(app: AppHandle, message_id: String, body: String) -> Result<(), String> {
    let trimmed = body.trim().to_string();
    if trimmed.is_empty() || trimmed.chars().count() > 2000 {
        return Err("Message must be 1–2000 characters.".to_string());
    }
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let (envelope, peers): (ProtocolEnvelope, Vec<String>) = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let me = my_username(&state)?;
        let original = db
            .get_message(&message_id)
            .map_err(|e| e.to_string())?
            .ok_or("message not found")?;
        if original.sender_username != me {
            return Err("only your own messages can be edited".to_string());
        }
        let conversation = db
            .list_conversations()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|c| c.id == original.conversation_id)
            .ok_or("conversation not found")?;
        let envelope = if conversation.kind == "dm" {
            let peer = conversation.members.first().cloned().unwrap_or_default();
            let contact = db
                .find_contact(&peer)
                .map_err(|e| e.to_string())?
                .ok_or("unknown contact")?;
            let peer_x = contact_x_pub(&contact).ok_or("no encryption key")?;
            let payload = ChatPayload::Edit {
                from: me.clone(),
                ref_id: message_id.clone(),
                body: trimmed.clone(),
                epoch: None,
            };
            let ciphertext = chat_app_core::seal_dm_payload(
                &state.identity.x_secret,
                &peer_x,
                &conversation.id,
                &payload,
            )
            .map_err(|e| e.to_string())?;
            let seq = db
                .next_sequence(&conversation.id, &state.device_uuid.to_string())
                .map_err(|e| e.to_string())? as u64;
            let conversation_uuid =
                Uuid::parse_str(&conversation.id).unwrap_or_else(|_| Uuid::new_v4());
            chat_app_core::build_envelope(
                &state.identity,
                state.device_uuid,
                conversation_uuid,
                Uuid::new_v4(),
                payload.message_type(),
                seq,
                ciphertext,
                now,
            )
        } else {
            let group = db
                .load_group(&conversation.id)
                .map_err(|e| e.to_string())?
                .ok_or("unknown group")?;
            let key = app_groups::own_epoch_key(
                &db,
                &state.identity,
                &conversation.id,
                group.current_epoch,
                &me,
            )
            .map_err(|e| e.to_string())?;
            let seq = db
                .next_sequence(&conversation.id, &state.device_uuid.to_string())
                .map_err(|e| e.to_string())? as u64;
            let payload = ChatPayload::Edit {
                from: me.clone(),
                ref_id: message_id.clone(),
                body: trimmed.clone(),
                epoch: Some(group.current_epoch),
            };
            let ciphertext = chat_app_core::seal_group_payload(&key, seq, &payload)
                .map_err(|e| e.to_string())?;
            let conversation_uuid =
                Uuid::parse_str(&conversation.id).unwrap_or_else(|_| Uuid::new_v4());
            chat_app_core::build_envelope(
                &state.identity,
                state.device_uuid,
                conversation_uuid,
                Uuid::new_v4(),
                payload.message_type(),
                seq,
                ciphertext,
                now,
            )
        };
        db.edit_message(&message_id, &trimmed, &envelope.ciphertext, now)
            .map_err(|e| e.to_string())?;
        let peers: Vec<String> = conversation
            .members
            .into_iter()
            .filter(|m| m != &me)
            .collect();
        (envelope, peers)
    };
    for peer in &peers {
        let _ = exec_outbound(&state, peer, &envelope, &message_id).await;
    }
    emit_refresh(&app);
    Ok(())
}

#[tauri::command]
async fn delete_message(app: AppHandle, message_id: String) -> Result<(), String> {
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let (envelope, peers): (ProtocolEnvelope, Vec<String>) = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let me = my_username(&state)?;
        let original = db
            .get_message(&message_id)
            .map_err(|e| e.to_string())?
            .ok_or("message not found")?;
        if original.sender_username != me {
            return Err("only your own messages can be deleted".to_string());
        }
        let conversation = db
            .list_conversations()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|c| c.id == original.conversation_id)
            .ok_or("conversation not found")?;
        let envelope = if conversation.kind == "dm" {
            let peer = conversation.members.first().cloned().unwrap_or_default();
            let contact = db
                .find_contact(&peer)
                .map_err(|e| e.to_string())?
                .ok_or("unknown contact")?;
            let peer_x = contact_x_pub(&contact).ok_or("no encryption key")?;
            let payload = ChatPayload::Delete {
                from: me.clone(),
                ref_id: message_id.clone(),
                epoch: None,
            };
            let ciphertext = chat_app_core::seal_dm_payload(
                &state.identity.x_secret,
                &peer_x,
                &conversation.id,
                &payload,
            )
            .map_err(|e| e.to_string())?;
            let seq = db
                .next_sequence(&conversation.id, &state.device_uuid.to_string())
                .map_err(|e| e.to_string())? as u64;
            let conversation_uuid =
                Uuid::parse_str(&conversation.id).unwrap_or_else(|_| Uuid::new_v4());
            chat_app_core::build_envelope(
                &state.identity,
                state.device_uuid,
                conversation_uuid,
                Uuid::new_v4(),
                payload.message_type(),
                seq,
                ciphertext,
                now,
            )
        } else {
            let group = db
                .load_group(&conversation.id)
                .map_err(|e| e.to_string())?
                .ok_or("unknown group")?;
            let key = app_groups::own_epoch_key(
                &db,
                &state.identity,
                &conversation.id,
                group.current_epoch,
                &me,
            )
            .map_err(|e| e.to_string())?;
            let seq = db
                .next_sequence(&conversation.id, &state.device_uuid.to_string())
                .map_err(|e| e.to_string())? as u64;
            let payload = ChatPayload::Delete {
                from: me.clone(),
                ref_id: message_id.clone(),
                epoch: Some(group.current_epoch),
            };
            let ciphertext = chat_app_core::seal_group_payload(&key, seq, &payload)
                .map_err(|e| e.to_string())?;
            let conversation_uuid =
                Uuid::parse_str(&conversation.id).unwrap_or_else(|_| Uuid::new_v4());
            chat_app_core::build_envelope(
                &state.identity,
                state.device_uuid,
                conversation_uuid,
                Uuid::new_v4(),
                payload.message_type(),
                seq,
                ciphertext,
                now,
            )
        };
        db.tombstone_message(&message_id, now)
            .map_err(|e| e.to_string())?;
        let peers: Vec<String> = conversation
            .members
            .into_iter()
            .filter(|m| m != &me)
            .collect();
        (envelope, peers)
    };
    for peer in &peers {
        let _ = exec_outbound(&state, peer, &envelope, &message_id).await;
    }
    emit_refresh(&app);
    Ok(())
}

#[tauri::command]
fn set_presence(app: AppHandle, status: String) -> Result<String, String> {
    let state: tauri::State<AppState> = app.state();
    let parsed =
        PresenceStatus::parse(&status).ok_or_else(|| "use online, away, or dnd".to_string())?;
    {
        let mut tracker = state.presence.lock().map_err(|e| e.to_string())?;
        tracker.set_manual(parsed);
    }
    // Announce immediately instead of waiting for the next heartbeat.
    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        broadcast_presence(&app_clone).await;
    });
    emit_refresh(&app);
    Ok(parsed.label().to_string())
}

#[tauri::command]
fn get_presence(app: AppHandle) -> Result<PresenceView, String> {
    let state: tauri::State<AppState> = app.state();
    let up = transport_up(&state);
    let (mine, peers) = {
        let tracker = state.presence.lock().map_err(|e| e.to_string())?;
        let mine = tracker.effective(up);
        let peers = tracker
            .list()
            .into_iter()
            .map(|p| PeerPresenceView {
                username: p.username.clone(),
                status: format!("{:?}", p.status).to_lowercase(),
                label: p.status.label().to_string(),
                fresh: p.fresh,
            })
            .collect();
        (mine, peers)
    };
    Ok(PresenceView {
        status: format!("{mine:?}").to_lowercase(),
        label: mine.label().to_string(),
        peers,
    })
}

/// Heartbeat our presence to every friend holding keys. Fire-and-forget:
/// a missed beat just reads as stale on their side.
async fn broadcast_presence(app: &AppHandle) {
    let state: tauri::State<AppState> = app.state();
    let me = match my_username(&state) {
        Ok(me) => me,
        Err(_) => return,
    };
    let _ = me;
    let now = now_ms();
    let envelopes: Vec<(String, ProtocolEnvelope)> = {
        let (db, tracker_status) = match (state.db.lock(), state.presence.lock()) {
            (Ok(db), Ok(tracker)) => {
                let status = tracker.effective(transport_up(&state));
                (db, status)
            }
            _ => return,
        };
        if tracker_status == PresenceStatus::Offline {
            return;
        }
        db.list_contacts()
            .unwrap_or_default()
            .into_iter()
            .filter(|c| c.status == "friend" && contact_x_pub(c).is_some())
            .filter_map(|c| {
                seal_presence_envelope(&state, &db, &c.username, tracker_status, now)
                    .ok()
                    .map(|envelope| (c.username.clone(), envelope))
            })
            .collect()
    };
    for (peer, envelope) in envelopes {
        let id = envelope.message_id.to_string();
        let _ = exec_outbound(&state, &peer, &envelope, &id).await;
    }
}

#[tauri::command]
async fn send_typing(app: AppHandle, conversation_id: String, typing: bool) -> Result<(), String> {
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let works: Vec<OutboundWork> = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let me = my_username(&state).unwrap_or_default();
        if me.is_empty() {
            return Ok(());
        }
        let conversation = db
            .list_conversations()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|c| c.id == conversation_id)
            .ok_or("conversation not found")?;
        let payload = ChatPayload::Typing {
            from: me.clone(),
            typing,
        };
        let envelope = seal_control(&state, &db, &conversation_id, payload, now)
            .map_err(|e| e.to_string())?
            .ok_or("seal failed")?;
        conversation
            .members
            .into_iter()
            .filter(|m| m != &me)
            .map(|peer| OutboundWork {
                peer_username: peer,
                envelope: envelope.clone(),
            })
            .collect()
    };
    for work in works {
        let id = work.envelope.message_id.to_string();
        let _ = exec_outbound(&state, &work.peer_username, &work.envelope, &id).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Friends commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn list_friends(app: AppHandle) -> Result<FriendsView, String> {
    let state: tauri::State<AppState> = app.state();
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let seen: HashMap<String, bool> = {
        state
            .peer_addrs
            .lock()
            .map(|cache| {
                db.list_contacts()
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|c| {
                        c.endpoint_id
                            .as_deref()
                            .filter(|id| cache.contains_key(*id))
                            .map(|_| (c.username, true))
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let contacts = db
        .list_contacts()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|c| FriendView {
            username: c.username.clone(),
            display_name: if c.display_name.is_empty() {
                c.username.clone()
            } else {
                c.display_name
            },
            status: c.status,
            seen: seen.get(&c.username).copied().unwrap_or(false),
        })
        .collect();
    let mut incoming = Vec::new();
    let mut outgoing = Vec::new();
    for request in db
        .list_friend_requests(Some("pending"))
        .map_err(|e| e.to_string())?
    {
        if request.direction == "in" {
            incoming.push(request);
        } else {
            outgoing.push(request);
        }
    }
    Ok(FriendsView {
        contacts,
        incoming,
        outgoing,
    })
}

#[tauri::command]
fn my_invite(app: AppHandle) -> Result<String, String> {
    let state: tauri::State<AppState> = app.state();
    let me = my_username(&state)?;
    let display = my_display_name(&state);
    let bundle = local_bundle_of(&state);
    let endpoint_id = state
        .peer_addrs
        .lock()
        .map(|cache| {
            cache
                .get("__self__")
                .map(|a| a.id.to_string())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    app_friends::my_invite_code(&me, &display, &state.identity, &endpoint_id, &bundle)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn import_invite(app: AppHandle, code: String) -> Result<ImportResult, String> {
    let state: tauri::State<AppState> = app.state();
    let username = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let (invite, _) =
            app_friends::import_invite(&db, code.trim(), now_ms()).map_err(|e| e.to_string())?;
        invite.username.clone()
    };
    let delivered = send_friend_request_inner(&app, &username)
        .await
        .unwrap_or(false);
    // Their earlier asks/answers (arrived before we had their keys) surface now.
    let surfaced = drain_stash_for(&state, &username);
    emit_refresh(&app);
    Ok(ImportResult {
        username,
        delivered,
        surfaced,
    })
}

/// Queue a handshake envelope for background retry (survives restarts and
/// offline peers). Call after a failed direct send.
fn queue_handshake(state: &AppState, peer_username: &str, envelope: &ProtocolEnvelope) {
    let json = serde_json::to_string(envelope).unwrap_or_default();
    if json.is_empty() {
        return;
    }
    let next = now_ms() + app_sync::retry_delay_ms(0);
    if let Ok(db) = state.db.lock() {
        let _ = db.enqueue_handshake(&envelope.message_id.to_string(), peer_username, &json, next);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportResult {
    username: String,
    delivered: bool,
    surfaced: usize,
}

async fn send_friend_request_inner(app: &AppHandle, peer_username: &str) -> Result<bool, String> {
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let work = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let me = my_username(&state)?;
        let display = my_display_name(&state);
        let bundle = local_bundle_of(&state);
        app_friends::build_friend_ask(
            &db,
            &state.identity,
            state.device_uuid,
            &me,
            &display,
            &bundle,
            peer_username,
            now,
        )
        .map_err(|e| e.to_string())?
    };
    let id = work.envelope.message_id.to_string();
    let peer = work.peer_username.clone();
    // Best effort: shared queue backup for offline recipients.
    let _ = publish_ask_to_queue(&state, &peer).await;
    match exec_outbound(&state, &peer, &work.envelope, &id).await {
        Ok(_) => Ok(true),
        Err(_) => {
            // Not delivered: retry in background + shared mailbox when one is
            // configured, so it survives our own shutdown too.
            queue_handshake(&state, &peer, &work.envelope);
            if cloud_worker_url(&state).is_some() {
                let object = MailboxObject {
                    id: Uuid::new_v4().to_string(),
                    envelope_json: serde_json::to_string(&work.envelope).unwrap_or_default(),
                    created_at_ms: now_ms(),
                    expires_at_ms: now_ms() + MAILBOX_TTL_MS,
                };
                if let Ok(coord) = coordinator_for(&state) {
                    let _ = coord.mailbox_put(&peer, &object).await;
                }
            }
            Ok(false)
        }
    }
}

#[tauri::command]
async fn send_friend_request(app: AppHandle, username: String) -> Result<bool, String> {
    let delivered = send_friend_request_inner(&app, username.trim()).await?;
    emit_refresh(&app);
    Ok(delivered)
}

#[tauri::command]
async fn accept_request(app: AppHandle, request_id: String) -> Result<String, String> {
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let (conversation_id, work) = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let me = my_username(&state)?;
        let bundle = local_bundle_of(&state);
        app_friends::accept_request(
            &db,
            &state.identity,
            state.device_uuid,
            &me,
            &bundle,
            &request_id,
            now,
        )
        .map_err(|e| e.to_string())?
    };
    let id = work.envelope.message_id.to_string();
    if exec_outbound(&state, &work.peer_username, &work.envelope, &id)
        .await
        .is_err()
    {
        queue_handshake(&state, &work.peer_username, &work.envelope);
        if cloud_worker_url(&state).is_some() {
            let object = MailboxObject {
                id: Uuid::new_v4().to_string(),
                envelope_json: serde_json::to_string(&work.envelope).unwrap_or_default(),
                created_at_ms: now_ms(),
                expires_at_ms: now_ms() + MAILBOX_TTL_MS,
            };
            if let Ok(coord) = coordinator_for(&state) {
                let _ = coord.mailbox_put(&work.peer_username, &object).await;
            }
        }
    }
    emit_refresh(&app);
    Ok(conversation_id)
}

#[tauri::command]
fn reject_request(app: AppHandle, request_id: String) -> Result<(), String> {
    let state: tauri::State<AppState> = app.state();
    let db = state.db.lock().map_err(|e| e.to_string())?;
    app_friends::reject_request(&db, &request_id, now_ms()).map_err(|e| e.to_string())?;
    emit_refresh(&app);
    Ok(())
}

#[tauri::command]
fn remove_friend(app: AppHandle, username: String) -> Result<(), String> {
    let state: tauri::State<AppState> = app.state();
    let db = state.db.lock().map_err(|e| e.to_string())?;
    app_friends::remove_friend(&db, username.trim()).map_err(|e| e.to_string())?;
    emit_refresh(&app);
    Ok(())
}

#[tauri::command]
fn block_user(app: AppHandle, username: String) -> Result<(), String> {
    let state: tauri::State<AppState> = app.state();
    let db = state.db.lock().map_err(|e| e.to_string())?;
    app_friends::block_user(&db, username.trim(), now_ms()).map_err(|e| e.to_string())?;
    emit_refresh(&app);
    Ok(())
}

#[tauri::command]
fn unblock_user(app: AppHandle, username: String) -> Result<(), String> {
    let state: tauri::State<AppState> = app.state();
    let db = state.db.lock().map_err(|e| e.to_string())?;
    app_friends::unblock_user(&db, username.trim()).map_err(|e| e.to_string())?;
    emit_refresh(&app);
    Ok(())
}

// ---------------------------------------------------------------------------
// Groups commands
// ---------------------------------------------------------------------------

async fn flush_works(app: &AppHandle, works: Vec<OutboundWork>) {
    let state: tauri::State<AppState> = app.state();
    for work in works {
        let id = work.envelope.message_id.to_string();
        if exec_outbound(&state, &work.peer_username, &work.envelope, &id)
            .await
            .is_err()
        {
            note_send_failure(&state, &work.peer_username, &work.envelope, &id).await;
        }
    }
    emit_refresh(app);
}

#[tauri::command]
async fn create_group(
    app: AppHandle,
    name: String,
    members: Vec<String>,
) -> Result<String, String> {
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let (group_id, works) = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let me = my_username(&state)?;
        app_groups::create_group(
            &db,
            &state.identity,
            state.device_uuid,
            &me,
            name.trim(),
            &members,
            now,
        )
        .map_err(|e| e.to_string())?
    };
    flush_works(&app, works).await;
    Ok(group_id)
}

#[tauri::command]
async fn add_group_members(
    app: AppHandle,
    group_id: String,
    members: Vec<String>,
) -> Result<(), String> {
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let works = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let me = my_username(&state)?;
        app_groups::add_members(
            &db,
            &state.identity,
            state.device_uuid,
            &me,
            &group_id,
            &members,
            now,
        )
        .map_err(|e| e.to_string())?
    };
    flush_works(&app, works).await;
    Ok(())
}

#[tauri::command]
async fn remove_group_members(
    app: AppHandle,
    group_id: String,
    members: Vec<String>,
) -> Result<(), String> {
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let works = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let me = my_username(&state)?;
        app_groups::remove_members(
            &db,
            &state.identity,
            state.device_uuid,
            &me,
            &group_id,
            &members,
            now,
        )
        .map_err(|e| e.to_string())?
    };
    flush_works(&app, works).await;
    Ok(())
}

#[tauri::command]
async fn leave_group(app: AppHandle, group_id: String) -> Result<(), String> {
    // Honest V1 semantics: drop our own key material, tell the group, keep
    // history readable. Remaining members rotate on next membership change.
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let (envelope, peers): (ProtocolEnvelope, Vec<String>) = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let me = my_username(&state)?;
        let group = db
            .load_group(&group_id)
            .map_err(|e| e.to_string())?
            .ok_or("unknown group")?;
        let key =
            app_groups::own_epoch_key(&db, &state.identity, &group_id, group.current_epoch, &me)
                .map_err(|e| e.to_string())?;
        let seq = db
            .next_sequence(&group_id, &state.device_uuid.to_string())
            .map_err(|e| e.to_string())? as u64;
        let payload = ChatPayload::Text {
            from: me.clone(),
            body: format!("@{me} left the group"),
            reply_to: None,
            epoch: Some(group.current_epoch),
        };
        let ciphertext =
            chat_app_core::seal_group_payload(&key, seq, &payload).map_err(|e| e.to_string())?;
        let conversation_uuid = Uuid::parse_str(&group_id).unwrap_or_else(|_| Uuid::new_v4());
        let envelope = chat_app_core::build_envelope(
            &state.identity,
            state.device_uuid,
            conversation_uuid,
            Uuid::new_v4(),
            payload.message_type(),
            seq,
            ciphertext,
            now,
        );
        let peers: Vec<String> = db
            .conversation_members(&group_id)
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|m| m != &me)
            .collect();
        db.delete_wrapped_keys_for(&group_id, &me)
            .map_err(|e| e.to_string())?;
        db.remove_conversation_member(&group_id, &me)
            .map_err(|e| e.to_string())?;
        (envelope, peers)
    };
    for peer in &peers {
        let id = envelope.message_id.to_string();
        let _ = exec_outbound(&state, peer, &envelope, &id).await;
    }
    emit_refresh(&app);
    Ok(())
}

#[tauri::command]
async fn rename_group(app: AppHandle, group_id: String, name: String) -> Result<(), String> {
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let (envelope, peers): (ProtocolEnvelope, Vec<String>) = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let me = my_username(&state)?;
        app_groups::rename_group(
            &db,
            &state.identity,
            state.device_uuid,
            &me,
            &group_id,
            name.trim(),
            now,
        )
        .map_err(|e| e.to_string())?
    };
    for peer in &peers {
        let id = envelope.message_id.to_string();
        let _ = exec_outbound(&state, peer, &envelope, &id).await;
    }
    emit_refresh(&app);
    Ok(())
}

#[tauri::command]
fn delete_chat(app: AppHandle, conversation_id: String) -> Result<(), String> {
    let state: tauri::State<AppState> = app.state();
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.delete_conversation(&conversation_id)
        .map_err(|e| e.to_string())?;
    emit_refresh(&app);
    Ok(())
}

// ---------------------------------------------------------------------------
// Files commands
// ---------------------------------------------------------------------------

#[tauri::command]
async fn send_file(
    app: AppHandle,
    conversation_id: String,
    filename: String,
    mime_type: String,
    data: Vec<u8>,
) -> Result<String, String> {
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let (file_id, sealed_chunks, offer_envelope, peers): (
        String,
        Vec<Vec<u8>>,
        ProtocolEnvelope,
        Vec<String>,
    ) = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let me = my_username(&state)?;
        let conversation = db
            .list_conversations()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|c| c.id == conversation_id)
            .ok_or("conversation not found")?;
        let file_id = Uuid::new_v4().to_string();
        let (offer, sealed) =
            app_files::prepare_offer(&file_id, filename.trim(), &mime_type, &data)
                .map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&state.files_dir).map_err(|e| e.to_string())?;
        std::fs::write(state.files_dir.join(format!("{file_id}.src")), &data)
            .map_err(|e| e.to_string())?;
        let payload = ChatPayload::FileOffer {
            from: me.clone(),
            file: offer.clone(),
        };
        // NOTE: same lock covers peek-seal-stage for groups (see send_text).
        let ciphertext = if conversation.kind == "dm" {
            let peer = conversation.members.first().cloned().unwrap_or_default();
            let contact = db
                .find_contact(&peer)
                .map_err(|e| e.to_string())?
                .ok_or("unknown contact")?;
            let peer_x = contact_x_pub(&contact).ok_or("no encryption key")?;
            chat_app_core::seal_dm_payload(
                &state.identity.x_secret,
                &peer_x,
                &conversation_id,
                &payload,
            )
            .map_err(|e| e.to_string())?
        } else {
            let seq = db
                .next_sequence(&conversation_id, &state.device_uuid.to_string())
                .map_err(|e| e.to_string())? as u64;
            let group = db
                .load_group(&conversation_id)
                .map_err(|e| e.to_string())?
                .ok_or("unknown group")?;
            let key = app_groups::own_epoch_key(
                &db,
                &state.identity,
                &conversation_id,
                group.current_epoch,
                &me,
            )
            .map_err(|e| e.to_string())?;
            chat_app_core::seal_group_payload(&key, seq, &payload).map_err(|e| e.to_string())?
        };
        let preview = format!("File: {}", offer.filename);
        let (_message, envelope) = chat_app_core::stage_message(
            &db,
            &state.identity,
            state.device_uuid,
            &me,
            &conversation,
            &payload,
            &preview,
            ciphertext,
            now,
        )
        .map_err(|e| e.to_string())?;
        db.save_file(
            &FileTransfer {
                id: file_id.clone(),
                conversation_id: conversation_id.clone(),
                filename: offer.filename.clone(),
                mime_type: offer.mime_type.clone(),
                size_bytes: offer.size_bytes as i64,
                sha256_hex: offer.sha256_hex.clone(),
                state: "sending".to_string(),
                bytes_done: 0,
                local_path: Some(
                    state
                        .files_dir
                        .join(format!("{file_id}.src"))
                        .to_string_lossy()
                        .to_string(),
                ),
                created_at_ms: now,
            },
            now,
        )
        .map_err(|e| e.to_string())?;
        db.save_offer_json(
            &file_id,
            &serde_json::to_string(&offer).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let peers: Vec<String> = conversation
            .members
            .into_iter()
            .filter(|m| m != &me)
            .collect();
        (file_id, sealed, envelope, peers)
    };
    for peer in &peers {
        let id = offer_envelope.message_id.to_string();
        if exec_outbound(&state, peer, &offer_envelope, &id)
            .await
            .is_err()
        {
            note_send_failure(&state, peer, &offer_envelope, &id).await;
        }
    }
    // Stream the chunks in the background with progress events.
    let return_id = file_id.clone();
    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        let state: tauri::State<AppState> = app_clone.state();
        let me = my_username(&state).unwrap_or_default();
        let total = sealed_chunks.len();
        for (index, sealed) in sealed_chunks.into_iter().enumerate() {
            let payload = ChatPayload::FileChunk {
                from: me.clone(),
                file_id: file_id.clone(),
                index: index as u32,
                data: sealed,
            };
            // Chunk bytes are sealed with the file key (index-bound); the
            // envelope sequence is display metadata only and must stay as
            // sealed, otherwise the signature breaks.
            let envelope = {
                let db = match state.db.lock() {
                    Ok(db) => db,
                    Err(_) => break,
                };
                match seal_control(&state, &db, &conversation_id, payload, now_ms()) {
                    Ok(Some(envelope)) => envelope,
                    _ => continue,
                }
            };
            for peer in &peers {
                let id = envelope.message_id.to_string();
                let _ = exec_outbound(&state, peer, &envelope, &id).await;
            }
            let _ = app_clone.emit(
                "hearth://file-progress",
                serde_json::json!({"fileId": file_id, "sent": index + 1, "total": total}),
            );
        }
        if let Ok(db) = state.db.lock()
            && let Ok(Some(row)) = db.load_file(&file_id)
            && row.state == "sending"
        {
            let _ = db.set_conversation_preview(
                &conversation_id,
                &format!("File sent: {}", row.filename),
                now_ms(),
            );
        }
        emit_refresh(&app_clone);
    });
    Ok(return_id)
}

#[tauri::command]
async fn cancel_file(app: AppHandle, file_id: String) -> Result<(), String> {
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let works: Vec<OutboundWork> = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let me = my_username(&state)?;
        let row = db
            .load_file(&file_id)
            .map_err(|e| e.to_string())?
            .ok_or("unknown file")?;
        db.save_file(
            &FileTransfer {
                state: "cancelled".to_string(),
                ..row.clone()
            },
            now,
        )
        .map_err(|e| e.to_string())?;
        app_files::cancel_incoming(&state.files_dir, &file_id);
        let _ = std::fs::remove_file(state.files_dir.join(format!("{file_id}.src")));
        let conversation = db
            .list_conversations()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|c| c.id == row.conversation_id)
            .ok_or("conversation not found")?;
        let payload = ChatPayload::FileCancel {
            from: me.clone(),
            file_id: file_id.clone(),
        };
        match seal_control(&state, &db, &row.conversation_id, payload, now)
            .map_err(|e| e.to_string())?
        {
            Some(envelope) => conversation
                .members
                .into_iter()
                .filter(|m| m != &me)
                .map(|peer| OutboundWork {
                    peer_username: peer,
                    envelope: envelope.clone(),
                })
                .collect(),
            None => Vec::new(),
        }
    };
    for work in works {
        let id = work.envelope.message_id.to_string();
        let _ = exec_outbound(&state, &work.peer_username, &work.envelope, &id).await;
    }
    emit_refresh(&app);
    Ok(())
}

// ---------------------------------------------------------------------------
// Settings / diagnostics commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn hide_app(app: AppHandle) -> Result<(), String> {
    // Borderless window has no system minimize button; the header ‒ button
    // and tray icon are the way back.
    let window = app.get_webview_window("main").ok_or("no main window")?;
    window.hide().map_err(|e| e.to_string())
}

#[tauri::command]
fn quit_app(app: AppHandle) -> Result<(), String> {
    app.exit(0);
    Ok(())
}

#[tauri::command]
fn set_always_on_top(app: AppHandle, enabled: bool) -> Result<(), String> {
    let window = app.get_webview_window("main").ok_or("no main window")?;
    window
        .set_always_on_top(enabled)
        .map_err(|e| e.to_string())?;
    emit_refresh(&app);
    Ok(())
}

#[tauri::command]
fn set_coordinator(app: AppHandle, kind: String, worker_url: String) -> Result<(), String> {
    if kind != "local" && kind != "cloudflare" {
        return Err("unknown coordinator".to_string());
    }
    if kind == "cloudflare" {
        if worker_url.trim().is_empty() {
            return Err("worker URL is required".to_string());
        }
        CloudflareCoordinator::new(worker_url.trim()).map_err(|e| e.to_string())?;
    }
    let state: tauri::State<AppState> = app.state();
    {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        db.set_setting("coordinator", &kind)
            .map_err(|e| e.to_string())?;
        db.set_setting("worker_url", worker_url.trim())
            .map_err(|e| e.to_string())?;
    }
    {
        let app_clone = app.clone();
        tauri::async_runtime::spawn(async move {
            let _ = register_self_async(&app_clone).await;
        });
    }
    emit_refresh(&app);
    Ok(())
}

#[tauri::command]
async fn transport_diagnostics(app: AppHandle) -> Result<Vec<TransportDiagnostics>, String> {
    let state: tauri::State<AppState> = app.state();
    let guard = state.transport.lock().await;
    Ok(guard.as_ref().map(|t| t.diagnostics()).unwrap_or_default())
}

#[tauri::command]
async fn check_mailbox(app: AppHandle) -> Result<usize, String> {
    poll_mailbox(&app).await.map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Background workers
// ---------------------------------------------------------------------------

/// Fold shared-queue friend directives into local contacts + incoming rows.
/// Never clobbers a live endpoint bundle with queue metadata (which carries
/// none); bundles arrive with the sender's first direct message.
fn ingest_directives(
    state: &AppState,
    directives: Vec<chat_coordinator::FriendDirective>,
) -> usize {
    let now = now_ms();
    let mut count = 0;
    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return 0,
    };
    for directive in directives {
        if directive.status != "pending" {
            continue;
        }
        let from = directive.from_username.trim().to_ascii_lowercase();
        if from.is_empty() {
            continue;
        }
        let keep = match db.find_contact(&from) {
            Ok(Some(existing)) if existing.status == "friend" || existing.status == "blocked" => {
                false
            }
            Ok(Some(existing)) => existing.endpoint_bundle.is_none(),
            _ => true,
        };
        if keep {
            let x = chat_app_core::hex_decode_32(&directive.from_x_pubkey_hex)
                .map(|b| b.to_vec())
                .ok();
            let ed = chat_app_core::hex_decode_32(&directive.from_ed_pubkey_hex)
                .map(|b| b.to_vec())
                .ok();
            let bundle = db
                .find_contact(&from)
                .ok()
                .flatten()
                .and_then(|c| c.endpoint_bundle);
            let _ = db.upsert_contact(
                &Contact {
                    username: from.clone(),
                    display_name: directive.from_display_name.clone(),
                    x25519_pubkey: x,
                    ed_pubkey: ed,
                    endpoint_id: None,
                    endpoint_bundle: bundle,
                    status: "pending".to_string(),
                },
                now,
            );
        }
        let already = db
            .list_friend_requests(Some("pending"))
            .unwrap_or_default()
            .into_iter()
            .any(|r| r.direction == "in" && r.peer_username == from);
        if !already {
            let _ = db.save_friend_request(
                &chat_database::FriendRequest {
                    id: directive.id.clone(),
                    direction: "in".to_string(),
                    peer_username: from,
                    peer_display_name: directive.from_display_name.clone(),
                    status: "pending".to_string(),
                    created_at_ms: directive.created_at_ms,
                },
                now,
            );
            count += 1;
        }
    }
    count
}

async fn poll_mailbox(app: &AppHandle) -> anyhow::Result<usize> {
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let me = my_username(&state).unwrap_or_default();
    if me.is_empty() {
        return Ok(0);
    }
    let mut ingested = 0;
    let cloud_objects: Vec<MailboxObject> = match coordinator_for(&state) {
        Ok(coord) if coord.name() == "cloudflare" => {
            coord.mailbox_get(&me, now).await.unwrap_or_default()
        }
        _ => Vec::new(),
    };
    for object in cloud_objects {
        if ingest_mailbox_object(app, &object.envelope_json).is_ok() {
            ingested += 1;
            if let Ok(coord) = coordinator_for(&state) {
                let _ = coord.mailbox_ack(&me, &object.id).await;
            }
        }
    }
    if cloud_worker_url(&state).is_some()
        && let Ok(coord) = coordinator_for(&state)
        && let Ok(directives) = coord.fetch_friend_requests(&me).await
    {
        ingested += ingest_directives(&state, directives);
    }
    let local: Vec<(String, String)> = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("db lock"))
        .map(|db| {
            let _ = db.expire_mailbox(now);
            db.collect_mailbox(&me, now).unwrap_or_default()
        })?;
    for (id, envelope_json) in local {
        if ingest_mailbox_object(app, &envelope_json).is_ok() {
            ingested += 1;
        }
        if let Ok(db) = state.db.lock() {
            let _ = db.ack_mailbox(&id);
        }
    }
    if ingested > 0 {
        emit_refresh(app);
    }
    Ok(ingested)
}

fn ingest_mailbox_object(app: &AppHandle, envelope_json: &str) -> anyhow::Result<()> {
    let envelope: ProtocolEnvelope = serde_json::from_str(envelope_json)?;
    envelope.validate()?;
    // No live connection here; sender attribution falls back to signature
    // trial over known keys inside route_inbound.
    let inbound = InboundEnvelope {
        from: None,
        envelope,
        via_relay: true,
    };
    run_routed(app, &inbound)
}

fn run_routed(app: &AppHandle, inbound: &InboundEnvelope) -> anyhow::Result<()> {
    let state: tauri::State<AppState> = app.state();
    let outcome = route_inbound(&state, inbound)?;
    if let Some((title, body)) = outcome.notify {
        notify(app, &title, &body);
    }
    if let Some(text) = outcome.toast {
        let _ = app.emit("hearth://toast", text);
    }
    if outcome.changed {
        emit_refresh(app);
    }
    if !outcome.works.is_empty() {
        let app_clone = app.clone();
        let works = outcome.works;
        tauri::async_runtime::spawn(async move {
            let state: tauri::State<AppState> = app_clone.state();
            for work in works {
                let id = work.envelope.message_id.to_string();
                let _ = exec_outbound(&state, &work.peer_username, &work.envelope, &id).await;
            }
        });
    }
    Ok(())
}

/// Broadcast our presence heartbeat to friends every 45s. Missed beats
/// read as stale/offline on their side; nothing is persisted anywhere.
async fn presence_worker(app: AppHandle) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(45)).await;
        broadcast_presence(&app).await;
    }
}

async fn retry_worker(app: AppHandle) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        let state: tauri::State<AppState> = app.state();
        let now = now_ms();
        let due = state
            .db
            .lock()
            .ok()
            .map(|db| app_sync::due_pending(&db, now).unwrap_or_default())
            .unwrap_or_default();
        for item in due {
            let found = state.db.lock().ok().and_then(|db| {
                db.get_message(&item.message_id)
                    .ok()
                    .flatten()
                    .map(|m| (m.clone(), m.conversation_id.clone()))
            });
            let (message, conversation_id) = match found {
                Some(pair) => pair,
                None => {
                    if let Ok(db) = state.db.lock() {
                        let _ = db.dequeue_pending_for(&item.message_id, &item.peer_id);
                    }
                    continue;
                }
            };
            let conversation_uuid =
                Uuid::parse_str(&conversation_id).unwrap_or_else(|_| Uuid::new_v4());
            match app_sync::resend_envelope(
                &state.identity,
                state.device_uuid,
                conversation_uuid,
                &message,
                now,
            ) {
                Ok(envelope) => {
                    if exec_outbound(&state, &item.peer_id, &envelope, &item.message_id)
                        .await
                        .is_ok()
                    {
                        if let Ok(db) = state.db.lock() {
                            let _ = db.dequeue_pending_for(&item.message_id, &item.peer_id);
                            let still = db.list_due_pending(i64::MAX, 100).unwrap_or_default();
                            if !still.iter().any(|p| p.message_id == item.message_id) {
                                let _ = db.set_message_status(&item.message_id, "delivered");
                            }
                        }
                        emit_refresh(&app);
                    } else {
                        note_send_failure(&state, &item.peer_id, &envelope, &item.message_id).await;
                    }
                }
                Err(_) => {
                    if let Ok(db) = state.db.lock() {
                        let _ = db.dequeue_pending_for(&item.message_id, &item.peer_id);
                    }
                }
            }
        }
        // Handshake retries (friend asks/answers): envelope bytes are stored
        // with the row, no message row needed.
        let due_handshakes = state
            .db
            .lock()
            .ok()
            .map(|db| db.list_due_handshakes(now, 20).unwrap_or_default())
            .unwrap_or_default();
        for item in due_handshakes {
            let parsed: Result<ProtocolEnvelope, _> = serde_json::from_str(&item.envelope_json);
            match parsed {
                Ok(envelope) => {
                    if exec_outbound(&state, &item.peer_username, &envelope, &item.message_id)
                        .await
                        .is_ok()
                    {
                        if let Ok(db) = state.db.lock() {
                            let _ = db.dequeue_handshake(&item.message_id);
                        }
                        emit_refresh(&app);
                    } else if let Ok(db) = state.db.lock() {
                        let delay = app_sync::retry_delay_ms(item.attempt_count as u32);
                        let _ = db.backoff_handshake(&item.message_id, now + delay);
                    }
                }
                Err(_) => {
                    if let Ok(db) = state.db.lock() {
                        let _ = db.dequeue_handshake(&item.message_id);
                    }
                }
            }
        }
        nudge_stalled_files(&app).await;
    }
}

async fn nudge_stalled_files(app: &AppHandle) {
    let state: tauri::State<AppState> = app.state();
    let now = now_ms();
    let me = my_username(&state).unwrap_or_default();
    if me.is_empty() {
        return;
    }
    let pending: Vec<(String, String)> = {
        let (db, accepts) = match (state.db.lock(), state.file_accepts.lock()) {
            (Ok(db), Ok(accepts)) => (db, accepts),
            _ => return,
        };
        let _ = &accepts;
        let mut out = Vec::new();
        for conv in db.list_conversations().unwrap_or_default() {
            for file in db.list_files(&conv.id).unwrap_or_default() {
                if file.state == "incoming" && now - file.created_at_ms > 90_000 {
                    out.push((file.id.clone(), file.conversation_id.clone()));
                }
            }
        }
        out
    };
    for (file_id, conversation_id) in pending {
        let last = state
            .file_accepts
            .lock()
            .ok()
            .and_then(|m| m.get(&file_id).cloned())
            .unwrap_or(0);
        if now - last < 60_000 {
            continue;
        }
        let (offer, peers): (Option<app_files::FileOfferBody>, Vec<String>) = {
            let db = match state.db.lock() {
                Ok(db) => db,
                Err(_) => continue,
            };
            let offer = db
                .load_offer_json(&file_id)
                .unwrap_or(None)
                .and_then(|json| serde_json::from_str(&json).ok());
            let peers = db
                .conversation_members(&conversation_id)
                .unwrap_or_default()
                .into_iter()
                .filter(|m| m != &me)
                .collect();
            (offer, peers)
        };
        let offer = match offer {
            Some(offer) => offer,
            None => continue,
        };
        let total = offer.manifest.chunk_hashes.len() as u32;
        let missing = app_files::missing_chunks(&state.files_dir, &offer);
        if missing.is_empty() {
            continue;
        }
        let have: Vec<u32> = (0..total).filter(|i| !missing.contains(i)).collect();
        let payload = ChatPayload::FileAccept {
            from: me.clone(),
            file_id: file_id.clone(),
            have,
        };
        let envelope = {
            let db = match state.db.lock() {
                Ok(db) => db,
                Err(_) => continue,
            };
            match seal_control(&state, &db, &conversation_id, payload, now) {
                Ok(Some(envelope)) => envelope,
                _ => continue,
            }
        };
        for peer in &peers {
            let id = envelope.message_id.to_string();
            let _ = exec_outbound(&state, peer, &envelope, &id).await;
        }
        if let Ok(mut map) = state.file_accepts.lock() {
            map.insert(file_id, now);
        }
    }
}

async fn inbound_worker(app: AppHandle) {
    let receiver = {
        let state: tauri::State<AppState> = app.state();
        let guard = state.transport.lock().await;
        guard.as_ref().and_then(|t| t.take_inbound())
    };
    let mut receiver = match receiver {
        Some(receiver) => receiver,
        None => return,
    };
    while let Some(inbound) = receiver.recv().await {
        if let Err(e) = run_routed(&app, &inbound) {
            eprintln!("[hearth] dropping inbound envelope: {e:#}");
        }
    }
}

// ---------------------------------------------------------------------------
// Window helpers
// ---------------------------------------------------------------------------

fn show_and_focus(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        let _ = app.emit("focus-composer", ());
    }
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

fn main() {
    let shortcut_plugin = tauri_plugin_global_shortcut::Builder::new()
        .with_shortcut(SHORTCUT)
        .map(|builder| {
            builder.with_handler(|app, _shortcut, event| {
                if event.state == tauri_plugin_global_shortcut::ShortcutState::Pressed {
                    show_and_focus(app);
                }
            })
        })
        .unwrap_or_else(|_| tauri_plugin_global_shortcut::Builder::new())
        .build();

    tauri::Builder::default()
        .plugin(shortcut_plugin)
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_and_focus(app);
        }))
        .setup(|app| {
            let data_dir = app.path().app_local_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            let files_dir = data_dir.join("files");
            std::fs::create_dir_all(&files_dir)?;

            let db = Database::open(data_dir.join("hearth.sqlite3"))?;
            let has_profile = db.profile_exists().unwrap_or(false);
            let (identity, key_backend) =
                chat_identity::load_or_generate(&data_dir).expect("device identity");
            let relay_enabled = db
                .get_setting("relay_enabled")
                .ok()
                .flatten()
                .map(|v| v != "0")
                .unwrap_or(true);

            let transport = tauri::async_runtime::block_on(async {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(25),
                    Transport::bind(&identity.ed_secret, relay_enabled),
                )
                .await
                {
                    Ok(Ok(transport)) => Some(transport),
                    Ok(Err(e)) => {
                        eprintln!("[hearth] transport unavailable: {e:#}");
                        None
                    }
                    Err(_) => {
                        eprintln!("[hearth] transport bind timed out; offline mode");
                        None
                    }
                }
            });
            let (endpoint_id, bundle) = match transport.as_ref() {
                Some(t) => (
                    t.endpoint_id().to_string(),
                    t.local_bundle().unwrap_or_default(),
                ),
                None => (String::new(), String::new()),
            };

            let device_uuid = db
                .load_device()?
                .map(|d| Uuid::parse_str(&d.id).unwrap_or_else(|_| Uuid::new_v4()))
                .unwrap_or_else(Uuid::new_v4);
            let username = db
                .load_profile()?
                .map(|(username, _)| username)
                .unwrap_or_default();
            db.save_device(&DeviceRecord {
                id: device_uuid.to_string(),
                username,
                device_name: "Desktop".to_string(),
                ed25519_pubkey: identity.public().ed_pubkey.to_vec(),
                x25519_pubkey: identity.public().x_pubkey.to_vec(),
                iroh_endpoint_id: endpoint_id.clone(),
                created_at_ms: now_ms(),
                revoked_at_ms: None,
            })?;
            if !has_profile {
                let _ = db.set_setting("coordinator", "local");
                let _ = db.set_setting("relay_enabled", "1");
            }

            let mut peer_addrs = HashMap::new();
            if !endpoint_id.is_empty()
                && let Ok(addr) = chat_transport::decode_bundle(&bundle)
            {
                peer_addrs.insert("__self__".to_string(), addr);
            }

            // Global shortcuts are best-effort (some Wayland compositors
            // refuse grabs); Toujours check at runtime via app_state instead.
            let shortcut_ok = !SHORTCUT.is_empty();

            app.manage(AppState {
                db: Mutex::new(db),
                identity,
                device_uuid,
                transport: tokio::sync::Mutex::new(transport),
                typing: Mutex::new(TypingTracker::new()),
                presence: Mutex::new(PresenceTracker::new()),
                peer_addrs: Mutex::new(peer_addrs),
                file_accepts: Mutex::new(HashMap::new()),
                data_dir,
                files_dir,
                local_bundle: Mutex::new(bundle),
                key_backend,
                shortcut_ok: Mutex::new(shortcut_ok),
            });

            {
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    // Best effort: directory publishing must not block launch.
                    let _ = register_self_async(&app_handle).await;
                    // And refresh the mailbox once transport had a moment.
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    let _ = poll_mailbox(&app_handle).await;
                });
            }

            // Tray: show/hide, always-on-top toggle, mailbox check, quit.
            {
                use tauri::{
                    menu::{Menu, MenuItem},
                    tray::{MouseButton, TrayIconBuilder, TrayIconEvent},
                };
                let show = MenuItem::with_id(app, "show", "Show Hearth", true, None::<&str>)?;
                let top = MenuItem::with_id(app, "top", "Always on top", true, None::<&str>)?;
                let mailbox =
                    MenuItem::with_id(app, "mailbox", "Check mailbox", true, None::<&str>)?;
                let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
                let menu = Menu::with_items(app, &[&show, &top, &mailbox, &quit])?;
                let mut builder = TrayIconBuilder::new().menu(&menu).tooltip("Hearth");
                if let Some(icon) = app.default_window_icon() {
                    builder = builder.icon(icon.clone());
                }
                builder
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "show" => show_and_focus(app),
                        "top" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let current = window.is_always_on_top().unwrap_or(true);
                                let _ = window.set_always_on_top(!current);
                                let _ = app.emit("hearth://refresh", ());
                            }
                        }
                        "mailbox" => {
                            let app_clone = app.clone();
                            tauri::async_runtime::spawn(async move {
                                match poll_mailbox(&app_clone).await {
                                    Ok(count) => {
                                        let _ = app_clone.emit(
                                            "hearth://toast",
                                            format!("Mailbox checked: {count} new"),
                                        );
                                    }
                                    Err(e) => {
                                        let _ = app_clone.emit(
                                            "hearth://toast",
                                            format!("Mailbox check failed: {e:#}"),
                                        );
                                    }
                                }
                            });
                        }
                        "quit" => app.exit(0),
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            ..
                        } = event
                        {
                            let app = tray.app_handle();
                            if let Some(window) = app.get_webview_window("main") {
                                let visible = window.is_visible().unwrap_or(true);
                                if visible {
                                    let _ = window.hide();
                                } else {
                                    show_and_focus(app);
                                }
                            }
                        }
                    })
                    .build(app)?;
            }

            {
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(inbound_worker(app_handle));
            }
            {
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(retry_worker(app_handle));
            }
            {
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(presence_worker(app_handle));
            }
            {
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(8)).await;
                    loop {
                        let _ = poll_mailbox(&app_handle).await;
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    }
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_state,
            create_profile,
            logout,
            list_chats,
            open_chat,
            send_text,
            edit_message,
            delete_message,
            send_typing,
            set_presence,
            get_presence,
            search_messages,
            list_friends,
            my_invite,
            import_invite,
            send_friend_request,
            accept_request,
            reject_request,
            remove_friend,
            block_user,
            unblock_user,
            create_group,
            add_group_members,
            remove_group_members,
            leave_group,
            rename_group,
            delete_chat,
            send_file,
            cancel_file,
            set_always_on_top,
            hide_app,
            quit_app,
            set_coordinator,
            transport_diagnostics,
            check_mailbox,
        ])
        .run(tauri::generate_context!())
        .expect("tauri application error");
}
