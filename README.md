# Hearth

Hearth is a local-first, P2P-first desktop messenger: a small floating chat
overlay designed as a Roblox-chat replacement. It is deliberately built in
vertical, verifiable phases: a control plane can assist discovery and
offline ciphertext delivery, but it never becomes the chat-history database.

## Current status

**Working V1 — phases 0–9 implemented and tested.** The app opens as a
compact borderless always-on-top overlay (`Alt+/` focuses it, even mid-game),
with one Chats screen for all DMs and groups plus a Friends screen for invites,
requests, blocking, and group creation. Messaging is end-to-end encrypted
(`crypto_box` DMs, per-epoch group keys), friend-gated, persisted first in
local SQLite, and retried idempotently; a shared coordinator (optional
Cloudflare Worker in `cloud/worker`, or zero-account local mode) provides
discovery and encrypted offline delivery. Voice/video was removed from
scope by explicit decision — no call UI or protocol types ship.

## Quick start

### Prerequisites

- Rust stable and platform build prerequisites for [Tauri 2](https://v2.tauri.app/start/prerequisites/)
- Node.js 22+ and npm

```bash
cd apps/desktop
npm install
npm run tauri dev
```

### Release builds (v1.0.0)

```bash
cd apps/desktop
npm run build   # UI + native installer + upload to a GitHub draft release
```

`npm run build` compiles the installer for your OS (AppImage on Linux x64,
setup `.exe` on Windows x64) and uploads it to a **draft** GitHub release
via the `gh` CLI (`gh auth login` first). For both installers at once, push
a tag — `git tag v1.0.0 && git push origin v1.0.0` — and CI
(`.github/workflows/release.yml`) builds Linux + Windows and attaches both
to the same draft. Review the draft, then publish it.

**Troubleshooting (Arch/CachyOS):** AppImage bundling needs `patchelf` on
PATH, and the `linuxdeploy` binary Tauri caches in `~/.cache/tauri/` must be
new enough to read modern libraries (a 2024 build fails on `.relr.dyn`
sections — replace the cached file with the [continuous
build](https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage)).
`npm run build` already strips unreadable entries from PATH, which also
crashes old linuxdeploy versions.


For non-desktop frontend work, run `npm run dev`. Run all Rust tests from the repository root with `cargo test --workspace`.

### Using it as a game overlay

- The window stays on top; toggle the pin in the header or tray.
- `Alt+/` shows and focuses Hearth from anywhere (on some Wayland
  compositors global grabs are refused — the tray icon then focuses it,
  and Settings reports shortcut status honestly).
- Local mode needs no account: share invite codes, chat P2P. For offline
  delivery and discovery without invite codes, deploy `cloud/worker` (free
  tier fits a small group — see its README) and set the worker URL in
  Friends → Settings.

## Repository map

- `apps/desktop` — Tauri 2 shell (tray, shortcut, notifications, workers) and compact TypeScript overlay UI.
- `crates/protocol` — versioned application envelopes; payloads are ciphertext only.
- `crates/database` — SQLite migrations and repositories.
- `crates/app-core` — product state transitions and validation (friends, chats, groups, files, sync, typing).
- `crates/identity` — device keys + OS keyring / `0600` file storage.
- `crates/crypto` — reviewed-primitive wrappers (`crypto_box`, ChaCha20-Poly1305, SHA-256). No custom crypto.
- `crates/transport` — Iroh/QUIC P2P with direct/relay states, backoff, diagnostics.
- `crates/coordinator` — replaceable coordination trait: local + Cloudflare clients, invite codes.
- `cloud/worker` — deployable Cloudflare Worker (D1 directory, R2 mailbox, rendezvous DO).
- `docs/` — architecture decisions, development phases, and contributor guide.
- `plan.md` — source architecture and complete roadmap.

## Guardrails

- Local SQLite is the authoritative client store.
- The server must never store message or attachment plaintext.
- No UI control may claim a network feature works before its implementation exists.
- Cryptographic protocols are selected from reviewed implementations; this repository does not invent cryptography.

Read [`docs/architecture.md`](docs/architecture.md), [`docs/phases.md`](docs/phases.md), and [`docs/contributing.md`](docs/contributing.md) before extending the project.

## Credits

Built by **Ali120B** — alibashmail2010@yahoo.com
