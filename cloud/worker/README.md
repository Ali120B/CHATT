# Hearth coordinator (Cloudflare)

Optional shared server for username discovery, friend-request metadata,
encrypted offline mailbox, and signaling rendezvous. The app works without
it (local mode: invite codes + direct P2P); point the app at a deployed
worker URL in Settings → coordinator to enable cloud backup.

## Free-tier fit (September 2026)

Cloudflare's free tier is generous for a small group and enforced daily:

- Workers: ~100k requests/day
- D1: 5M row reads/day, 100k row writes/day, 5 GB storage
- R2: 10 GB-months, 1M Class A / 10M Class B ops/month, free egress

Normal chat messages are P2P and never touch this worker, so a handful of
friends will stay far under the limits. It is **not** sized for a public
messenger with thousands of users — self-host or upgrade before that.

## Deploy

```bash
cd cloud/worker
npx wrangler d1 create hearth-directory
# apply schema.sql to the new database:
npx wrangler d1 execute hearth-directory --file schema.sql
npx wrangler r2 bucket create hearth-mailbox
cp wrangler.toml.example wrangler.toml  # then paste the D1 id
npx wrangler deploy
```

Paste the worker URL into Hearth → Friends → Settings → coordinator
→ Cloudflare worker.

## Local vs cloud — honest answers

- **Local mode, same Wi-Fi/LAN:** works, both PCs on, no account needed.
- **Local mode, different networks:** works if Iroh can punch through
  (direct or its relay); invite codes carry the address, no IPs typed.
- **Someone offline:** delivery waits. Without a shared mailbox there is
  nowhere to leave ciphertext, so messages stay queued until both are
  online. Your PC does **not** need to stay on for *receiving* later —
  but the *sender's* app must be running to retry, unless a cloud
  mailbox is configured.
- **Cloudflare configured:** offline recipients fetch ciphertext on next
  launch (7-day TTL), friend discovery works without invite codes, and
  either side can be off when the other sends.
