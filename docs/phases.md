# Delivery phases

Each phase requires implementation, automated tests, failure behavior, documentation, and diagnostics. A mock UI is never acceptance evidence.

| Phase | Outcome | Exit signal |
| --- | --- | --- |
| 0 | Workspace, desktop shell, protocol, SQLite | `cargo test --workspace`; desktop opens and identity persists |
| 1 | Desktop integration | tray, notifications, window controls, shortcut behave on target OSes |
| 2 | Identity | device keys are generated and held in secure local storage |
| 3 | Coordination | username/device registration and ephemeral signaling work without history storage |
| 4 | Transport | two installs connect via authenticated Iroh, direct then relay fallback |
| 5 | Encrypted DMs | local-first message lifecycle is durable and idempotent |
| 6 | Offline delivery | recipient retrieves and acknowledges encrypted mailbox bundles |
| 7 | Friends | discover/request/accept/block are backed by the control plane |
| 8 | Groups | membership epochs and reconnect synchronization work for three clients |
| 9 | Files | chunking, integrity, cancellation, resume, encrypted fallback |
| 10 | Calls | **removed from scope** (explicit decision, 2026-09-09) |
| 13 | Audit | **removed from scope** (explicit decision, 2026-09-10) |
| 11–16 | Presence through release | ephemeral UX, security audit, network matrix, packaging, RC |

## Verified roadmap status (2026-09-09)

| Phase | Status | Evidence / remaining work |
| --- | --- | --- |
| 0 | Complete | Workspace, migrations, profile setup, protocol validation, automated unit tests. |
| 1 | Complete | Small floating window (372×620, always-on-top toggle), tray menu (show/pin/mailbox/quit), desktop notifications, global `Alt+/` focus shortcut with Wayland fallback note, single-instance focus, Linux packaging via Tauri bundle. |
| 2 | Complete | Per-device Ed25519 identity + X25519 encryption keys; OS keyring primary with `0600` file fallback; backend reported honestly in settings (`chat-identity` tests). |
| 3 | Complete | `Coordinator` trait (cloud-replaceable) with `LocalCoordinator` (invite codes, no account) and `CloudflareCoordinator` HTTP client; deployable Worker + D1 schema + R2 mailbox + rendezvous DO in `cloud/worker`. Directory holds public keys/bundles only. |
| 4 | Complete | Iroh 1.x transport: endpoint = device key, direct + relay paths, per-peer state machine, backoff-with-jitter, diagnostics, length-prefixed acked envelope streams. Real loopback delivery test in `chat-transport`. |
| 5 | Complete | Persist-first lifecycle, `crypto_box` DMs bound to conversation, Ed25519 envelope signatures, idempotent redelivery (`INSERT OR IGNORE`), delivery/read states, retry worker. |
| 6 | Complete | Encrypted mailbox via shared coordinator (7-day TTL, ack + delete + expiry sweep) plus local spool; retry worker escalates after repeated direct failures. |
| 7 | Complete | Invite codes (TOFU with fingerprint-equivalent key display), request/accept/reject/block/remove, friend-gated messaging (unknown devices rejected). |
| 8 | Complete (V1 crypto) | Groups with per-epoch AEAD keys distributed via `crypto_box`, rotation on every membership change, epoch-hint opening with newest-first trial. **Not full MLS/OpenMLS yet** — the epoch/key-distribution boundary is the documented migration seam. |
| 11 | Complete | Presence states (online/away/DND/offline) with idle auto-away, signed heartbeats, DND notification suppression; friend-list dots, DM header status, manual selector in settings. Typing + read receipts were already in. |
| 12 | Complete | In-chat message search (SQLite, 50 latest), right-click message menu (copy/reply/edit/delete), Ctrl/Cmd+K quick chat switcher, Esc layering, loading state, toast/feed ARIA roles, labelled window controls. |
| 9 | Complete | ≤25 MB files, per-chunk file-key seals bound to index, SHA-256 manifest + whole-file verify, progress events, cancel, resume via have-lists, sender staging cleanup on confirm. |
| 10 | Removed | Voice/video deleted from scope; no call UI, protocol types, or media code ships. |

Typing indicators are ephemeral (in-memory TTL, never SQLite). Presence is
user-settable (online/away/do-not-disturb) with idle auto-away, 45s signed
heartbeats to friends, and locally derived offline — heartbeats are small
ephemeral frames, never SQLite rows or coordinator records. Do-not-disturb
suppresses desktop notifications.

## Phase 0 delivered

- Cargo workspace with explicit layering.
- Tauri 2 shell and responsive onboarding UI.
- Local SQLite database opened with WAL and foreign keys.
- First profile creation validates normalized usernames.
- Protocol envelope contains ciphertext only and validates its version.
- Unit tests cover persistence, profile validation, and protocol validation.

## Next slice

Cross-network validation (Phase 14 matrix: LAN, NAT, relay, offline,
Windows firewall) and packaging verification (AppImage, Windows installer)
on real machines with a second user, then packaging
(Phase 15) and the release gate (Phase 16).
