# Architecture baseline

## Product boundary

Hearth is **local-first + P2P-first + end-to-end encrypted + cloud-assisted**. “P2P-first” means direct QUIC is the preferred delivery path; it does not promise that offline recipients can be reached without encrypted store-and-forward.

## Trust boundaries

| Component | Responsibility | May contain plaintext? |
| --- | --- | --- |
| Desktop client | identity, encryption, local history, UI | Yes, locally |
| SQLite | authoritative local persistence | Yes, locally |
| Direct/relay transport | encrypted envelope delivery | No |
| Control plane | discovery, signaling, device metadata | No message plaintext |
| Object mailbox | short-lived encrypted bundles/files | No |

The client persists the local onboarding profile in SQLite and exposes only implemented capabilities: every chat, friend, group, and file control is backed by the real transport, encryption, and sync layers described below.

## Dependency direction

`desktop → app-core → database` and `desktop → protocol`.

The protocol crate owns versioned, transport-neutral envelopes. The database crate owns schema and SQL. The app-core crate owns user-facing state transitions. Identity, crypto, transport, coordination, groups, and files are separate crates so they cannot leak transport or storage concerns upward. (Voice/video was removed from scope; no calls crate ships.)

## Protocol rule

Every packet uses a numeric version, immutable UUID, sender device ID, conversation ID, monotonic sequence, type, timestamp, and **ciphertext**. Envelope validation rejects unsupported versions and empty ciphertext. Encryption/session implementation will be introduced only after a reviewed protocol choice is made.

## Persistence rule

SQLite uses WAL and foreign keys. Migrations create the initial `profiles`, `conversations`, `messages`, and `pending_outbound` tables. `messages.ciphertext` is the sole message payload field. Queued work is explicit in `pending_outbound`; UI must distinguish local persistence, sending, delivered, and read.

## Future integration seams

1. Identity keys and secure OS key storage (done: `chat-identity`).
2. Iroh endpoint and connection state machine — direct, relay, offline (done: `chat-transport`).
3. Authenticated DM session and outbound queue worker (done: `chat-app-core` + shell workers).
4. Cloudflare discovery/signaling plus encrypted mailbox (done: `chat-coordinator` + `cloud/worker`; local mode needs no account).
5. Friends, V1 hybrid group encryption (MLS migration seam documented), file transfer (done).

See the detailed design and non-negotiable constraints in [`../plan.md`](../plan.md).
