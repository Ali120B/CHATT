# Contributing

## Setup and checks

```bash
npm --prefix apps/desktop install
npm --prefix apps/desktop run check
npm --prefix apps/desktop run build:ui
# Full installer + GitHub draft release (needs `gh auth login`):
# npm --prefix apps/desktop run build
cargo fmt --all -- --check
cargo test --workspace
```

Use `cargo clippy --workspace --all-targets -- -D warnings` where platform dependencies are available.

## Safety rules

- Never add plaintext message or attachment fields to remote APIs, logs, or cloud storage.
- Never implement an unreviewed encryption construction.
- Treat user names as aliases, not cryptographic identity proof.
- Persist outbound messages before transport; retries must reuse message IDs.
- Keep typing, presence, and transient signaling out of durable chat history.
- Give failures an explicit, user-visible state. Do not replace failure with a fake success.

## Changes

Keep dependency direction intact. Add migrations in the database crate, protocol compatibility tests for envelope changes, and documentation for new trust boundaries. Update `docs/phases.md` only when a phase has its complete acceptance evidence.
