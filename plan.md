# P2P Desktop Chat — Engineering Plan

> **Status:** Working V1 baseline. Verified 2026-09-09: Phases 0–9 implemented and tested (see `docs/phases.md` for evidence). Voice/video removed from scope by explicit decision. Group encryption is hybrid AEAD-from-reviewed-primitives with a documented MLS migration seam (not full OpenMLS yet).
> **Target:** Windows + Linux, Arch Linux first
> **Desktop:** Tauri 2 + Rust
> **Architecture:** P2P-first, local-first, E2E encrypted, cloud-assisted only where necessary

---

# Project Overview

This project is a modern desktop messenger built around one core principle:

> **Messages should travel directly between users whenever technically possible, while a small cloud control plane handles discovery, signaling, NAT traversal, and offline delivery.**

The application is **P2P-first, not P2P-only**.

Pure P2P cannot reliably provide username discovery, connectivity through every NAT/firewall, delivery to powered-off recipients, or convenient group synchronization. The correct V1 architecture is therefore a hybrid control plane/data plane:

```text
                         CLOUD CONTROL PLANE
              ┌──────────────────────────────────┐
              │ Cloudflare Workers                │
              │ Durable Objects                   │
              │ D1                               │
              │ R2                               │
              │                                  │
              │ discovery / signaling / mailbox │
              └───────────────┬──────────────────┘
                              │
                    encrypted coordination
                              │
              ┌───────────────┴───────────────┐
              │                               │
       ┌──────▼──────┐                 ┌──────▼──────┐
       │ Desktop A   │                 │ Desktop B   │
       │ Tauri 2     │                 │ Tauri 2     │
       │ Rust        │◄── P2P / QUIC ─►│ Rust        │
       │ SQLite      │                 │ SQLite      │
       └─────────────┘                 └─────────────┘
```

The cloud backend is **not** the normal chat-history database.

---

# Executive Summary

## Final recommendation

| Area | Choice |
|---|---|
| Desktop | Tauri 2 |
| Native code | Rust |
| Frontend | TypeScript + modern web UI |
| Local DB | SQLite |
| P2P transport | Iroh / QUIC |
| Direct connectivity | Iroh direct path |
| Relay fallback | Iroh relay |
| Signaling | Cloudflare Workers + Durable Objects |
| Username metadata | Cloudflare D1 |
| Offline ciphertext | Cloudflare R2 |
| Group encryption | V1: hybrid AEAD (MLS migration seam documented) |
| DM encryption | Established audited protocol/primitives; no custom crypto |
| Linux | Arch first; AppImage |
| Windows | Tauri installer |
| Message history | Local SQLite |
| Remote plaintext | **Never** |

Iroh is the recommended networking foundation because it is Rust-native and built around QUIC, direct connections, endpoint identity, relay fallback, and NAT traversal. Current Iroh work specifically focuses on improving NAT traversal reliability. citeturn0search14

OpenMLS implements the IETF Messaging Layer Security protocol (RFC 9420) in Rust and supports modern MLS ciphersuites, making it appropriate for group encryption. citeturn0search13turn0search12

Cloudflare is a good fit for the small coordination layer. D1 currently provides 5 million row reads/day, 100,000 row writes/day, and 5 GB included storage on Workers Free, but the daily limits are now enforced. citeturn0search1turn0search6

R2 currently provides 10 GB-month free storage, 1 million Class A operations/month, 10 million Class B operations/month, and free Internet egress. citeturn0search0

Durable Objects provide stateful coordination and WebSockets, with current Workers Free limits including 100,000 requests/day and 13,000 GB-s/day. citeturn0search2

---

# Research Findings

## P2P is not synonymous with direct connectivity

Two peers may be behind incompatible NAT or firewall configurations. Therefore the product needs:

1. peer discovery;
2. signaling;
3. NAT traversal;
4. relay fallback;
5. offline delivery.

## D1 must not become the chat database

Current D1 Workers Free limits are:

- 5 million rows read/day;
- 100,000 rows written/day;
- 5 GB included storage.

Cloudflare began enforcing those daily limits on September 1, 2026. Exceeding them causes queries to fail until the daily reset. citeturn0search1turn0search6

Therefore:

**Never write every message, typing event, presence event, or read receipt to D1.**

## Durable Objects fit signaling

Durable Objects are appropriate for:

- short-lived signaling;
- rendezvous;
- connection negotiation;
- ephemeral presence.

They should not become the permanent message store.

## R2 fits encrypted fallback storage

R2 is appropriate for:

- encrypted offline message bundles;
- encrypted attachment chunks;
- temporary encrypted synchronization packages.

The server receives ciphertext, never plaintext. R2's current free tier and object limits make this practical for early deployments. citeturn0search0turn0search3

## Why not pure P2P?

Because an offline peer has no process available to receive a message.

Therefore V1 uses:

```text
direct P2P
    ↓ if unavailable
relay
    ↓ if recipient is offline
encrypted mailbox
```

---

# Requirements

## Identity

Each installation receives a cryptographic device identity.

An account contains:

- `@username`;
- display name;
- avatar;
- profile metadata;
- account identity;
- one or more devices.

Keep these concepts separate:

```text
Human-readable identity = @username
Cryptographic identity   = account/device keys
Network identity         = endpoint identity
Network location         = current connectivity information
```

## Direct messages

Required:

- username search;
- friend requests;
- accept/reject;
- block;
- remove friend;
- DMs;
- replies;
- edits;
- deletes;
- attachments;
- images;
- audio;
- documents;
- clipboard image paste;
- drag/drop;
- local history;
- delivery state;
- read state;
- typing;
- reconnect;
- offline delivery.

## Groups

Required:

- create;
- invite;
- remove;
- leave;
- rename;
- avatar;
- members;
- messages;
- replies;
- edits;
- deletes;
- files;
- notifications;
- synchronization.

Groups must not depend on a permanent leader.

---

# Technical Constraints

1. No custom cryptography.
2. No plaintext remote message storage.
3. No browser localStorage as the chat database.
4. No fake P2P.
5. No fake encryption.
6. No mandatory IP exchange.
7. No permanent group leader.
8. No database write for every ephemeral event.
9. No silent connection failures.
10. No UI feature unless its underlying system actually works.
11. Cloud infrastructure must be replaceable.
12. SQLite is the primary local persistence layer.

---

# Technology Comparison

## Desktop

| Technology | Decision | Reason |
|---|---|---|
| Tauri 2 | **Selected** | Small native shell and excellent Rust integration |
| Electron | Rejected for V1 | Larger footprint |
| Flutter | Rejected for V1 | Less aligned with the Rust-first architecture |

## P2P

| Technology | Decision |
|---|---|
| Iroh / QUIC | **Selected** |
| libp2p | Strong alternative |
| raw TCP | Not selected |
| raw UDP | Not selected |
| custom UDP protocol | Not selected |

## Backend

| Technology | Decision |
|---|---|
| Cloudflare Workers | **Selected** |
| Durable Objects | **Selected** |
| D1 | **Metadata only** |
| R2 | **Encrypted fallback storage** |
| Supabase | Alternative |
| Neon/Postgres | Alternative |
| self-hosted PostgreSQL | Future/self-hosted option |

## Local storage

SQLite is selected.

---

# Final Technology Choices

```text
Tauri 2
└── Rust
    ├── SQLite
    ├── identity/crypto
    ├── sync
    ├── Iroh / QUIC
    └── file transfer

Cloudflare
├── Workers
├── Durable Objects
├── D1
└── R2
```

---

# P2P Architecture

The network stack is:

```text
Application protocol
        ↓
Encryption/session layer
        ↓
Message synchronization
        ↓
Iroh
        ↓
QUIC
        ↓
Network
```

Connection preference:

1. direct LAN;
2. direct Internet P2P;
3. direct connection after NAT traversal;
4. relay fallback;
5. encrypted offline mailbox.

The normal UI should say:

- Connected directly
- Connected through relay
- Connecting
- Offline

Do not expose NAT jargon to ordinary users.

---

# Discovery Architecture

The discovery service maps:

```text
@username
    ↓
Account ID
    ↓
Device records
    ↓
Current endpoint information
```

The service does not receive message plaintext.

## Username registration

Store:

```text
username
normalized_username
account_id
public_identity
created_at
updated_at
```

Username search must be rate-limited.

## Impersonation protection

A username is an alias, not proof of identity.

Clients must verify the cryptographic identity associated with a contact.

---

# Signaling Architecture

Use a Durable Object as a short-lived rendezvous/signaling session.

```text
A
│
├── request B
│
▼
Worker
│
▼
Durable Object
│
├── A session
└── B session
      │
      ▼
connection negotiation
      │
      ▼
A ◄──────── P2P ────────► B
```

The signaling service must not persist chat history.

Idle signaling sessions expire.

---

# NAT Traversal Strategy

Use Iroh for endpoint addressing, QUIC transport, NAT traversal, and relay fallback.

Application connection state:

```text
DISCOVERING
    ↓
NEGOTIATING
    ↓
DIRECT_CONNECTED
    │
    └── failure
         ↓
RELAY_CONNECTED
         │
         └── failure
              ↓
             OFFLINE
```

Reconnection uses exponential backoff with jitter.

Network changes must trigger path re-evaluation.

---

# Offline Messaging Architecture

Pure P2P cannot deliver to a powered-off recipient.

V1 therefore uses an **encrypted mailbox**.

## Sending

```text
Sender
  ↓
encrypt message
  ↓
try direct connection
  ├── success → send directly
  └── failure → upload ciphertext mailbox object
```

## Receiving

```text
Recipient starts
      ↓
discover mailbox
      ↓
download ciphertext
      ↓
decrypt locally
      ↓
verify
      ↓
persist SQLite
      ↓
acknowledge
      ↓
delete/expire mailbox object
```

## Server visibility

The mailbox system may see metadata such as:

- recipient identifier;
- object identifier;
- size;
- timestamps;
- delivery state.

It must not see:

- plaintext message;
- plaintext attachment;
- encryption keys.

## Expiration

Mailbox objects have a short TTL.

Successful delivery causes deletion.

The sender's local database remains authoritative for its local copy.

---

# Group Messaging Architecture

## Decision

Use **MLS-based group encryption with replicated application state**.

OpenMLS is a Rust implementation of MLS/RFC 9420 and supports modern ciphersuites. citeturn0search13

## Why not full mesh?

A group of N peers can require up to:

```text
N(N-1)/2
```

pairwise connections.

That becomes expensive and difficult to maintain.

## Why not a permanent leader?

A leader becomes:

- a reliability bottleneck;
- a synchronization bottleneck;
- a failure point;
- a tempting central authority.

## V1 architecture

Every member maintains:

- group ID;
- MLS epoch;
- membership state;
- application message sequence;
- synchronization cursor.

The network remains peer-to-peer.

Cloud infrastructure assists discovery and offline synchronization.

## Product target

Initial practical target:

- 2–32 active members per normal group.

This is an engineering target, not a protocol maximum.

---

# Group Membership

## Add member

```text
existing member
    ↓
MLS Add proposal
    ↓
commit
    ↓
new epoch
    ↓
encrypted group state
```

## Remove member

Removing a member creates a new MLS epoch.

The removed member must not obtain future group secrets.

## Multi-device member

A user may have multiple devices.

Each device is separately authenticated.

Device revocation must remove that device from future secure communication.

---

# Group Synchronization

Groups use an application-level sequence.

Example:

```text
group_id
epoch
message_id
sender_device
sequence
```

Messages are idempotent.

If:

```text
message 100
```

arrives while 99 is missing:

```text
request synchronization
```

Synchronization should prefer direct peers and use encrypted cloud fallback only when necessary.

---

# File Transfer Architecture

## Direct

```text
file
 ↓
chunk
 ↓
encrypt
 ↓
P2P stream
 ↓
verify hash
 ↓
assemble
```

Required:

- chunking;
- progress;
- cancel;
- retry;
- resume;
- integrity verification;
- temporary-file cleanup.

## Offline

```text
file
 ↓
encrypt
 ↓
upload encrypted chunks
 ↓
R2
 ↓
recipient downloads later
```

R2 supports large objects and multipart uploads suitable for encrypted fallback storage. citeturn0search3

No plaintext file is uploaded.

---

# Voice / Video

Out of scope: removed by explicit product decision (September 2026). All
references, protocol types, and roadmap phases for calls were deleted. If
voice/video ever returns, it must be a separate subsystem with its own
phases and acceptance tests — never bolted onto the chat protocol.

---

# Encryption Architecture

## Principles

- no home-grown crypto;
- authenticated sessions;
- forward secrecy where supported;
- replay protection;
- secure key rotation;
- device revocation;
- local secure key storage.

## DM

The DM layer requires:

1. long-term identity keys;
2. authenticated peer identity;
3. authenticated session establishment;
4. symmetric message encryption;
5. key rotation;
6. replay protection;
7. authentication/integrity.

The exact Rust implementation must be chosen from currently maintained, established protocol implementations. The application must not invent a new protocol.

## Groups

Use OpenMLS.

Each group has an MLS epoch.

Membership changes create new epochs.

---

# Identity Architecture

Separate:

```text
Account identity
Device identity
Network endpoint identity
Username
```

Example:

```text
Account
 ├── Device A
 ├── Device B
 └── Device C
```

A revoked device must stop receiving new encrypted state.

---

# Username Architecture

Canonical normalization must be deterministic.

Recommended rules:

- case-insensitive uniqueness;
- preserve display capitalization separately;
- reject or carefully handle Unicode confusables;
- reserve system usernames;
- rate-limit lookup;
- prevent rapid username squatting.

Username is an alias, never the cryptographic identity.

---

# SQLite Architecture

SQLite is the local authoritative persistence layer.

Use a maintained Rust SQLite library such as `sqlx` or an equivalent reviewed choice.

Recommended:

- WAL;
- foreign keys;
- migrations;
- prepared statements;
- indexes;
- transaction boundaries.

Core tables:

```text
accounts
devices
identities
profiles
contacts
friend_requests
conversations
conversation_members
messages
message_revisions
message_receipts
attachments
groups
group_members
group_epochs
sync_cursors
pending_outbound
pending_inbound
network_peers
calls
settings
blocked_users
```

---

# Backend Architecture

```text
Cloudflare Worker
│
├── username
├── identity
├── device
├── friend
├── signaling
├── mailbox
└── group discovery
```

Durable Objects:

```text
RendezvousDO
PresenceDO
MailboxDO
GroupSyncDO
```

Do not create a permanent server-side object for every chat message.

---

# D1 Architecture

D1 stores relatively stable metadata:

- usernames;
- account IDs;
- public identity metadata;
- device registrations;
- friend-request metadata;
- blocked/account state;
- minimal group discovery information.

D1 does **not** store:

- plaintext messages;
- message history;
- plaintext attachments;
- typing state;
- every read receipt;
- continuous presence events.

Current D1 limits make this architecture important. citeturn0search1turn0search6

---

# R2 Architecture

R2 stores:

- encrypted mailbox bundles;
- encrypted attachment chunks;
- encrypted synchronization packages.

Object names are opaque random IDs.

No public plaintext URLs.

R2's current free tier is 10 GB-month storage, 1 million Class A operations/month, 10 million Class B operations/month, with free egress. citeturn0search0

---

# Backend Cost Analysis

## Low usage

Example:

- 20 messages/day;
- 2 username lookups/day;
- occasional attachment.

Normal messages:

```text
D1 message writes = 0
D1 message reads  = 0
```

because normal messages are P2P.

## Medium usage

Example:

- 200 messages/day;
- several conversations;
- occasional offline delivery.

Backend usage is mostly:

- discovery;
- signaling;
- mailbox fallback.

## Heavy usage

The largest infrastructure costs should be:

- relay traffic;
- encrypted attachment storage;
- mailbox operations;
- signaling.

This is preferable to storing every message remotely.

---

# Protocol Specification

Every packet has an explicit version.

Example:

```text
ProtocolEnvelope {
    version
    message_id
    conversation_id
    sender_device_id
    recipient_scope
    message_type
    sequence
    timestamp
    flags
    encryption_context
    payload
    authentication
}
```

Message IDs remain stable across retries.

Application-level ordering is required.

Every message is idempotent.

---

# Message Types

Minimum protocol types:

```text
HELLO
IDENTITY
AUTH
PING
PONG

FRIEND_REQUEST
FRIEND_RESPONSE

MESSAGE
MESSAGE_EDIT
MESSAGE_DELETE
MESSAGE_REPLY

DELIVERY_ACK
READ_ACK
TYPING

SYNC_REQUEST
SYNC_RESPONSE

GROUP_COMMIT
GROUP_MESSAGE
GROUP_SYNC

FILE_OFFER
FILE_ACCEPT
FILE_CHUNK
FILE_ACK
FILE_COMPLETE

ERROR
```

`TYPING` is ephemeral and never enters permanent history.

---

# Synchronization Model

The sender persists a message locally before network transmission.

Lifecycle:

```text
COMPOSED
  ↓
LOCAL_PERSISTED
  ↓
SENDING
  ↓
DELIVERED
  ↓
READ
```

Failure:

```text
SENDING
  ↓
QUEUED
  ↓
RETRYING
```

Message IDs are immutable.

Edits and deletes are separate events/tombstones to avoid destructive synchronization conflicts.

---

# Typing Indicators

Typing is ephemeral.

```text
TYPING_START
TYPING_STOP
```

Transport priority:

1. direct P2P;
2. signaling WebSocket if necessary;
3. never D1.

Typing expires automatically.

Disconnecting clears the indicator.

---

# Read Receipts

Read state is transmitted directly to peers.

Local SQLite stores the latest known state.

For groups:

```text
member_device_id
last_read_sequence
```

Do not create a remote database row for every read action.

---

# Presence

States:

```text
ONLINE
AWAY
DND
OFFLINE
```

Use:

- connection state;
- heartbeat;
- TTL;
- local cache.

Do not continuously write presence transitions to D1.

---

# UI / UX Architecture

## Main layout

Compact borderless overlay (default 372×620, resizable, always-on-top
toggle). Two screens only: **Chats** (all DMs + groups, list → thread) and
**Friends** (invites, requests, blocks, group creation, settings). A
floating frosted-glass pill navbar sits at the bottom; the slim top bar is
the drag region with hide/quit controls (no system frame).

```text
┌───────────────────┐
│ Hearth   ·  –  ✕  │  ← drag region, borderless
│                   │
│ Chats list        │
│  or               │
│ Thread + composer │
│                   │
│  ( Chats|Friends) │  ← floating glass pill
└───────────────────┘
```

Visual direction:

- minimal;
- dense but comfortable;
- professional;
- native-feeling;
- strong typography;
- restrained animation;
- excellent keyboard navigation.

Avoid:

- AI-dashboard styling;
- excessive gradients;
- giant rounded cards;
- fake glassmorphism;
- generic templates;
- excessive animation;
- Discord-clone aesthetics.

---

# Required Screens

1. First launch
2. Identity creation
3. Username selection
4. Profile
5. Friend discovery
6. Friend requests
7. Conversation list
8. DM
9. Group creation
10. Group settings
11. Group chat
13. File transfer state
14. Settings
15. Privacy/security
16. Network diagnostics
17. Connection details
18. Blocked users
19. Device management

---

# Network Status

Normal UI states:

```text
Connected directly
Connected through relay
Connecting
Offline
Reconnecting
Queued
Delivered
Read
```

Detailed networking diagnostics can show:

- peer ID;
- transport;
- relay;
- connection duration;
- reconnect count.

Only expose advanced information in a diagnostics screen.

---

# Desktop Window Architecture

Required:

- floating;
- resizable;
- repositionable;
- hide/show;
- background operation;
- tray;
- notifications;
- always-on-top where supported.

Always-on-top should be user-controlled.

---

# Global Shortcut Architecture

Target:

```text
Alt + /
```

Behavior:

```text
shortcut
  ↓
application running?
  ├── no → launch/show
  └── yes → show/focus
             ↓
          focus input
```

Wayland behavior must be tested separately from X11.

---

# Windows Architecture

Target:

- Windows 10/11 according to current Tauri support;
- installer;
- notifications;
- tray;
- autostart;
- firewall/network permission handling.

Firewall failures must have understandable recovery states.

---

# Linux / Arch Architecture

Primary target:

**Arch Linux**

Support:

- Wayland;
- X11;
- tray;
- notifications;
- AppImage;
- `.desktop`;
- autostart where supported.

Test at minimum on KDE Plasma Wayland, GNOME Wayland, and an X11 environment.

---

# Security Threat Model

## Protects against

- network observers reading message plaintext;
- relay operators reading correctly encrypted content;
- server database compromise exposing plaintext messages;
- packet modification;
- replayed application packets;
- unauthorized group membership after proper key rotation.

## Does not fully protect against

- malware on the endpoint;
- compromised OS;
- screenshots;
- malicious recipients;
- stolen private keys;
- account compromise;
- traffic-analysis metadata;
- timing/size metadata.

E2E encryption does not mean complete anonymity.

---

# Privacy Model

The backend may still observe metadata such as:

- account existence;
- username;
- device registration;
- approximate online state;
- connection timing;
- relay usage;
- object size;
- delivery timing.

The architecture minimizes this metadata but does not claim to eliminate it.

---

# Error Handling

Explicit error codes/states:

```text
USERNAME_TAKEN
DISCOVERY_UNAVAILABLE
SIGNALING_UNAVAILABLE
DIRECT_CONNECTION_FAILED
RELAY_CONNECTION_FAILED
MESSAGE_QUEUED
MESSAGE_EXPIRED
KEY_MISSING
KEY_REJECTED
GROUP_SYNC_FAILED
FILE_TRANSFER_FAILED
FILE_CHECKSUM_FAILED
DATABASE_CORRUPT
DEVICE_REVOKED
```

The UI must distinguish:

- queued;
- failed;
- delivered;
- read.

Never show "sent" when a message only exists locally.

---

# Observability

Use structured logs.

Example fields:

```text
timestamp
subsystem
severity
event_code
connection_id
peer_id_hash
duration
error_code
```

Never log:

- plaintext messages;
- private keys;
- session secrets;
- plaintext attachment data.

Provide a sanitized diagnostic export.

---

# Testing Strategy

## Unit

- serialization;
- protocol versioning;
- SQLite repositories;
- crypto wrappers;
- group state;
- synchronization;
- retry logic;
- state machines.

## Integration

At minimum:

```text
A ↔ B
A ↔ B offline
A ↔ B relay
A ↔ B ↔ C group
```

## Network

Test:

- same LAN;
- different networks;
- NAT;
- restrictive NAT;
- dropped connections;
- network switching;
- offline recipients;
- relay fallback.

## Security

Test:

- invalid signatures;
- altered ciphertext;
- replay;
- duplicate messages;
- unauthorized group member;
- revoked device;
- expired mailbox;
- malformed packets.

## Desktop

Windows:

- installer;
- tray;
- notifications;
- shortcut;
- always-on-top.

Linux:

- Arch;
- Wayland;
- X11;
- AppImage;
- tray;
- notifications;
- shortcut.

---

# Performance Strategy

Measure:

- cold startup;
- warm startup;
- idle RAM;
- idle CPU;
- SQLite latency;
- connection establishment;
- reconnect latency;
- message latency;
- file throughput;
- synchronization duration.

Do not invent arbitrary performance claims before testing on representative hardware.

---

# Repository Structure

```text
project/
├── apps/
│   └── desktop/
│       ├── src/
│       ├── public/
│       └── package.json
│
├── crates/
│   ├── app-core/
│   ├── identity/
│   ├── crypto/
│   ├── protocol/
│   ├── networking/
│   ├── sync/
│   ├── groups/
│   ├── files/
│   ├── database/
│   └── diagnostics/
│
├── cloud/
│   ├── worker/
│   ├── durable-objects/
│   ├── migrations/
│   └── wrangler.toml
│
├── tests/
│   ├── integration/
│   ├── network/
│   └── security/
│
├── docs/
├── migrations/
├── plan.md
└── README.md
```

---

# Database Schema

## accounts

```text
id
username
display_name
avatar_ref
created_at
updated_at
```

## devices

```text
id
account_id
device_name
public_identity
endpoint_identity
created_at
last_seen
revoked_at
```

## contacts

```text
account_id
contact_account_id
status
created_at
updated_at
```

## friend_requests

```text
id
sender_account_id
recipient_account_id
status
created_at
expires_at
```

## conversations

```text
id
kind
created_at
updated_at
last_message_id
```

## conversation_members

```text
conversation_id
account_id
```

## messages

```text
id
conversation_id
sender_device_id
sequence
message_type
ciphertext
created_at
edited_at
deleted_at
```

## attachments

```text
id
message_id
filename
mime_type
size
sha256
local_path
transfer_state
```

## groups

```text
id
name
avatar_ref
mls_group_id
current_epoch
created_at
```

## group_members

```text
group_id
account_id
device_id
role
joined_at
removed_at
```

## group_epochs

```text
group_id
epoch
commit_hash
created_at
```

## sync_cursors

```text
peer_id
conversation_id
last_sequence
updated_at
```

## pending_outbound

```text
id
message_id
peer_id
attempt_count
next_attempt_at
state
```

---

# Development Roadmap

## Phase 0 — Architecture foundation

### Objective

Create the Rust workspace, Tauri shell, dependency boundaries, migrations, protocol definitions, and automated test harness.

### Acceptance

- workspace builds;
- frontend builds;
- Tauri launches;
- migrations execute;
- protocol serialization tests pass.

---

## Phase 1 — Desktop shell

Implement:

- Tauri window;
- tray;
- notifications;
- floating behavior;
- always-on-top;
- global shortcut;
- Windows/Linux packaging foundation.

---

## Phase 2 — Identity

Implement:

- device identity;
- secure key generation;
- local key storage;
- profile;
- username registration interface.

---

## Phase 3 — Cloud coordination

Implement:

- Cloudflare Worker;
- D1;
- Durable Objects;
- R2;
- username registration;
- username lookup;
- device registration;
- signaling.

---

## Phase 4 — P2P transport

Implement:

- Iroh endpoint;
- authenticated peer connection;
- direct path;
- relay fallback;
- connection state machine;
- reconnect;
- diagnostics.

Acceptance:

Two real installations connect across different networks without manual IP exchange.

---

## Phase 5 — Encrypted DMs

Implement:

- authenticated session;
- encrypted messages;
- SQLite persistence;
- IDs;
- acknowledgements;
- retry;
- delivery state.

Acceptance:

Dropped connections never silently lose or duplicate a message.

---

## Phase 6 — Offline delivery

Implement:

- encrypted mailbox;
- R2;
- expiration;
- retrieval;
- deletion;
- retry.

Acceptance:

A powered-off recipient can later launch the app and receive the queued message.

---

## Phase 7 — Friends

Implement:

- search;
- requests;
- accept/reject;
- block;
- remove.

---

## Phase 8 — Groups

Implement:

- OpenMLS;
- group creation;
- invitations;
- membership changes;
- epochs;
- synchronization;
- offline group state.

Acceptance:

Three or more real clients can maintain a group across reconnects.

---

## Phase 9 — Files

Implement:

- direct transfer;
- encrypted chunks;
- progress;
- resume;
- cancellation;
- R2 fallback;
- previews.

---

## Phase 10 — Voice/video (removed from scope)

Deleted by explicit product decision (September 2026). No call controls,
protocol types, or media subsystem ship in V1.

---

## Phase 11 — Presence and notifications

Implement:

- presence;
- typing;
- read receipts;
- notifications;
- background operation.

These remain ephemeral and do not become D1 chat records.

---

## Phase 12 — UX polish

Implement:

- keyboard navigation;
- search;
- context menus;
- attachment UX;
- loading/error states;
- accessibility.

---

## Phase 13 — Security hardening (removed from scope)

Deleted by explicit product decision (2026-09-10). The protocol uses
reviewed primitives throughout; a formal audit is deferred, not planned.

---

## Phase 14 — Network testing

Test:

- LAN;
- normal NAT;
- restrictive NAT;
- relay;
- offline;
- reconnect;
- network switching;
- Windows firewall;
- Linux firewall.

---

## Phase 15 — Packaging

Produce:

- Windows installer;
- Linux AppImage;
- `.desktop`;
- icons;
- update strategy.

---

## Phase 16 — Release candidate

Release only after:

- no fake features;
- no plaintext server storage;
- no silent delivery failures;
- cross-network tests pass;
- migrations are verified;
- recovery flows are tested.

---

# Phase-by-Phase Acceptance Criteria

A phase is complete only when it has:

1. working implementation;
2. unit tests;
3. integration tests;
4. failure handling;
5. documentation;
6. diagnostics.

A UI existing is not evidence that a feature is complete.

---

# Definition of Done

- [ ] Windows build works
- [ ] Arch Linux build works
- [ ] AppImage works
- [ ] Tauri launches
- [ ] floating window works
- [ ] always-on-top works where supported
- [ ] global shortcut works where supported
- [ ] identity creation works
- [ ] username registration works
- [ ] username discovery works
- [ ] friend requests work
- [ ] DMs work
- [ ] direct P2P works
- [ ] relay fallback works
- [ ] E2E encryption works
- [ ] offline delivery works
- [ ] SQLite persistence works
- [ ] groups work
- [ ] membership changes work
- [ ] file transfers work
- [ ] encrypted fallback files work
- [ ] typing works
- [ ] read receipts work
- [ ] presence works
- [ ] notifications work
- [ ] reconnection works
- [ ] real error handling works
- [ ] server cannot read message plaintext
- [ ] server cannot read attachment plaintext
- [ ] no major controls are fake
- [ ] no core data is hardcoded
- [ ] no developer-only infrastructure is required

---

# Known Limitations

## Pure P2P cannot guarantee offline delivery

A powered-off recipient requires store-and-forward infrastructure.

## P2P does not mean metadata-free

Infrastructure can still observe network metadata.

## Relay fallback has metadata visibility

A relay can observe encrypted traffic and connection metadata even when it cannot decrypt content.

## Group messaging is harder than DMs

MLS solves group key management, but distributed synchronization and offline group state remain application-level problems.

## Free cloud services have limits

Cloudflare Free is appropriate for an early deployment/prototype, not an unlimited public messenger. The architecture must make migration to paid or self-hosted infrastructure straightforward.

---

# Future Extensions

- multi-device recovery;
- encrypted backups;
- self-hosted coordination server;
- multiple backend providers;
- larger groups;
- screen sharing;
- voice notes;
- disappearing messages;
- reactions;
- richer profiles;
- LAN-only mode;
- decentralized username discovery;
- encrypted search.

---

# Final Architecture Diagram

```text
                         ┌──────────────────────────────┐
                         │          CLOUDFLARE          │
                         │                              │
                         │ Workers                      │
                         │ ├─ API                      │
                         │ ├─ username discovery      │
                         │ └─ device metadata         │
                         │                              │
                         │ Durable Objects             │
                         │ ├─ signaling                │
                         │ ├─ rendezvous               │
                         │ └─ ephemeral presence       │
                         │                              │
                         │ D1                           │
                         │ ├─ usernames                │
                         │ ├─ devices                  │
                         │ └─ friend metadata          │
                         │                              │
                         │ R2                           │
                         │ └─ encrypted mailbox/files  │
                         └──────────────┬───────────────┘
                                        │
                         coordination / fallback only
                                        │
               ┌────────────────────────┴────────────────────────┐
               │                                                 │
       ┌───────▼────────┐                              ┌─────────▼───────┐
       │   CLIENT A     │                              │    CLIENT B     │
       │                │                              │                 │
       │ Tauri 2        │                              │ Tauri 2         │
       │ Rust           │                              │ Rust            │
       │ SQLite         │                              │ SQLite          │
       │ Identity       │                              │ Identity        │
       │ Crypto         │                              │ Crypto          │
       │ Sync           │                              │ Sync            │
       │ Iroh           │◄────── DIRECT QUIC ─────────►│ Iroh            │
       └────────────────┘                              └─────────────────┘
               │                                                 │
               └──────────── encrypted relay path ───────────────┘
```

# Final Architectural Rule

The project is:

```text
LOCAL-FIRST
    +
P2P-FIRST
    +
E2E ENCRYPTED
    +
CLOUD-ASSISTED
```

It is **not**:

```text
Discord + a database
```

and it is **not**:

```text
pure P2P at any cost
```

Use P2P wherever it provides a real advantage, and deliberately use tiny cloud services for the problems P2P fundamentally cannot solve reliably.

If implementation time becomes constrained, prioritize:

1. identity;
2. SQLite;
3. P2P transport;
4. encrypted DMs;
5. reconnection;
6. offline mailbox;
7. friends;
8. groups;
9. files;
10. typing/read receipts/presence;
11. UI polish.

Do not build a complete-looking UI and invent networking later. The identity, encryption, networking, synchronization, and local persistence boundaries must exist before the UI is allowed to claim the product is complete.
