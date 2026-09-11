/**
 * Hearth coordination worker (Phase 3).
 *
 * What it does:
 *  - username directory (register / lookup) backed by D1 — metadata only
 *  - friend-request metadata queue backed by D1
 *  - encrypted offline mailbox: index in D1, ciphertext blobs in R2
 *  - minimal signaling rendezvous (Durable Object) for endpoint exchange
 *
 * What it NEVER sees: message plaintext, attachment plaintext, private keys.
 * Mailbox payloads are opaque `envelope_json` strings (ciphertext-only
 * ProtocolEnvelope values). The worker cannot decrypt them.
 *
 * Deploy: `wrangler d1 create hearth-directory`, `wrangler r2 bucket create
 * hearth-mailbox`, fill `wrangler.toml` from the example, `wrangler deploy`.
 */

export interface Env {
  DB: D1Database;
  MAILBOX: R2Bucket;
  SIGNALING: DurableObjectNamespace;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalize(username: string): string {
  return username.trim().toLowerCase();
}

function validUsername(username: string): boolean {
  const name = normalize(username);
  return name.length >= 3 && name.length <= 32 && /^[a-z0-9_]+$/.test(name);
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function badRequest(message: string): Response {
  return json({ error: message }, 400);
}

// Very small in-memory rate limiter (per isolate; D1-backed limits are a
// follow-up for abuse-heavy deployments).
const hits = new Map<string, { count: number; reset: number }>();
function rateLimit(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  const entry = hits.get(key);
  if (!entry || now > entry.reset) {
    hits.set(key, { count: 1, reset: now + windowMs });
    return true;
  }
  entry.count += 1;
  return entry.count <= max;
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

async function registerDirectory(request: Request, env: Env): Promise<Response> {
  const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
  if (!rateLimit(`reg:${ip}`, 10, 60_000)) {
    return json({ error: "rate limited" }, 429);
  }
  const body = (await request.json()) as Record<string, unknown>;
  const username = normalize(String(body.username ?? ""));
  if (!validUsername(username)) return badRequest("bad username");
  const displayName = String(body.display_name ?? body.displayName ?? "").slice(0, 64);
  const edHex = String(body.ed_pubkey_hex ?? "");
  const xHex = String(body.x_pubkey_hex ?? "");
  if (edHex.length !== 64 || xHex.length !== 64) return badRequest("bad keys");
  const endpointId = String(body.endpoint_id ?? "").slice(0, 128);
  const bundle = String(body.endpoint_bundle ?? "").slice(0, 8192);
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO directory (username, display_name, ed_pubkey_hex, x_pubkey_hex, endpoint_id, endpoint_bundle, updated_at_ms)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
     ON CONFLICT(username) DO UPDATE SET display_name = excluded.display_name,
       ed_pubkey_hex = excluded.ed_pubkey_hex, x_pubkey_hex = excluded.x_pubkey_hex,
       endpoint_id = excluded.endpoint_id, endpoint_bundle = excluded.endpoint_bundle,
       updated_at_ms = excluded.updated_at_ms`,
  )
    .bind(username, displayName, edHex, xHex, endpointId, bundle, now)
    .run();
  return json({ ok: true });
}

async function lookupDirectory(env: Env, username: string): Promise<Response> {
  const name = normalize(username);
  if (!validUsername(name)) return badRequest("bad username");
  const row = await env.DB.prepare(
    `SELECT username, display_name AS displayName, ed_pubkey_hex, x_pubkey_hex,
            endpoint_id AS endpointId, endpoint_bundle AS endpointBundle, updated_at_ms AS updatedAtMs
     FROM directory WHERE username = ?1`,
  )
    .bind(name)
    .first();
  if (!row) return json({ error: "not found" }, 404);
  // Shape matches the Rust DirectoryRecord (snake_case).
  return json({
    username: row.username,
    display_name: row.displayName,
    ed_pubkey_hex: row.ed_pubkey_hex,
    x_pubkey_hex: row.x_pubkey_hex,
    endpoint_id: row.endpointId,
    endpoint_bundle: row.endpointBundle,
    updated_at_ms: row.updatedAtMs,
  });
}

async function postFriendRequest(request: Request, env: Env, to: string): Promise<Response> {
  const recipient = normalize(to);
  if (!validUsername(recipient)) return badRequest("bad username");
  const body = (await request.json()) as Record<string, unknown>;
  const id = String(body.id ?? "").slice(0, 64);
  const from = normalize(String(body.from_username ?? body.from ?? ""));
  if (!id || !validUsername(from)) return badRequest("bad request");
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO friend_requests (id, to_username, from_username, from_display_name, from_ed_hex, from_x_hex, status, created_at_ms)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7)
     ON CONFLICT(id) DO NOTHING`,
  )
    .bind(
      id, recipient, from,
      String(body.from_display_name ?? "").slice(0, 64),
      String(body.from_ed_pubkey_hex ?? "").slice(0, 64),
      String(body.from_x_pubkey_hex ?? "").slice(0, 64),
      now,
    )
    .run();
  return json({ ok: true });
}

async function getFriendRequests(env: Env, username: string): Promise<Response> {
  const name = normalize(username);
  const rows = await env.DB.prepare(
    `SELECT id, from_username AS fromUsername, from_display_name AS fromDisplayName,
            from_ed_hex AS fromEdHex, from_x_hex AS fromXHex, status, created_at_ms AS createdAtMs
     FROM friend_requests WHERE to_username = ?1 AND status = 'pending' ORDER BY created_at_ms DESC LIMIT 100`,
  )
    .bind(name)
    .all();
  return json(
    (rows.results ?? []).map((row: Record<string, unknown>) => ({
      id: row.id,
      from_username: row.fromUsername,
      from_display_name: row.fromDisplayName,
      from_ed_pubkey_hex: row.fromEdHex,
      from_x_pubkey_hex: row.fromXHex,
      status: row.status,
      created_at_ms: row.createdAtMs,
    })),
  );
}

async function mailboxPut(request: Request, env: Env, to: string): Promise<Response> {
  const recipient = normalize(to);
  if (!validUsername(recipient)) return badRequest("bad username");
  const body = (await request.json()) as Record<string, unknown>;
  const id = String(body.id ?? "").slice(0, 64);
  const envelopeJson = String(body.envelope_json ?? "");
  if (!id || !envelopeJson || envelopeJson.length > 512_000) return badRequest("bad object");
  const created = Number(body.created_at_ms ?? Date.now());
  const expires = Number(body.expires_at_ms ?? Date.now() + 7 * 86400_000);
  const key = `mailbox/${recipient}/${id}.json`;
  await env.MAILBOX.put(key, envelopeJson, {
    httpMetadata: { contentType: "application/json" },
  });
  await env.DB.prepare(
    `INSERT OR IGNORE INTO mailbox_index (id, to_username, created_at_ms, expires_at_ms) VALUES (?1, ?2, ?3, ?4)`,
  )
    .bind(id, recipient, created, expires)
    .run();
  return json({ ok: true });
}

async function mailboxGet(env: Env, username: string): Promise<Response> {
  const name = normalize(username);
  const now = Date.now();
  const rows = await env.DB.prepare(
    `SELECT id FROM mailbox_index WHERE to_username = ?1 AND expires_at_ms > ?2 ORDER BY created_at_ms ASC LIMIT 100`,
  )
    .bind(name, now)
    .all();
  const out: unknown[] = [];
  for (const row of rows.results ?? []) {
    const id = String((row as Record<string, unknown>).id);
    const object = await env.MAILBOX.get(`mailbox/${name}/${id}.json`);
    if (!object) continue;
    const envelopeJson = await object.text();
    const meta = await env.DB.prepare(`SELECT created_at_ms, expires_at_ms FROM mailbox_index WHERE id = ?1`)
      .bind(id)
      .first<Record<string, unknown>>();
    out.push({
      id,
      envelope_json: envelopeJson,
      created_at_ms: meta?.created_at_ms ?? now,
      expires_at_ms: meta?.expires_at_ms ?? now,
    });
  }
  return json(out);
}

async function mailboxAck(env: Env, username: string, id: string): Promise<Response> {
  const name = normalize(username);
  await env.MAILBOX.delete(`mailbox/${name}/${id}.json`);
  await env.DB.prepare(`DELETE FROM mailbox_index WHERE id = ?1 AND to_username = ?2`).bind(id, name).run();
  return json({ ok: true });
}

async function expireSweep(env: Env): Promise<void> {
  const now = Date.now();
  const rows = await env.DB.prepare(`SELECT id, to_username FROM mailbox_index WHERE expires_at_ms <= ?1 LIMIT 200`)
    .bind(now)
    .all();
  for (const row of rows.results ?? []) {
    const record = row as Record<string, unknown>;
    await env.MAILBOX.delete(`mailbox/${String(record.to_username)}/${String(record.id)}.json`);
    await env.DB.prepare(`DELETE FROM mailbox_index WHERE id = ?1`).bind(String(record.id)).run();
  }
}

// ---------------------------------------------------------------------------
// Signaling rendezvous (Durable Object): exchange endpoint bundles when
// Iroh's default lookup cannot reach a peer. Ephemeral, small, TTL'd.
// ---------------------------------------------------------------------------

export class Rendezvous {
  state: DurableObjectState;
  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname.endsWith("/offer")) {
      const body = (await request.json()) as Record<string, unknown>;
      const peer = normalize(String(body.peer ?? ""));
      const bundle = String(body.bundle ?? "").slice(0, 8192);
      if (!validUsername(peer) || !bundle) return badRequest("bad offer");
      await this.state.storage.put(`offer:${peer}`, {
        bundle,
        at: Date.now(),
      });
      return json({ ok: true });
    }
    if (request.method === "GET") {
      const peer = normalize(url.searchParams.get("peer") ?? "");
      if (!validUsername(peer)) return badRequest("bad peer");
      const offer = await this.state.storage.get<{ bundle: string; at: number }>(`offer:${peer}`);
      if (!offer) return json({ error: "not found" }, 404);
      if (Date.now() - offer.at > 120_000) {
        await this.state.storage.delete(`offer:${peer}`);
        return json({ error: "expired" }, 404);
      }
      return json({ bundle: offer.bundle });
    }
    return json({ error: "not found" }, 404);
  }
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);

    try {
      if (parts[0] === "v1" && parts[1] === "directory" && request.method === "POST") {
        return await registerDirectory(request, env);
      }
      if (parts[0] === "v1" && parts[1] === "directory" && parts[2] && request.method === "GET") {
        return await lookupDirectory(env, parts[2]);
      }
      if (parts[0] === "v1" && parts[1] === "friends" && parts[3] === "requests" && request.method === "POST") {
        return await postFriendRequest(request, env, parts[2]);
      }
      if (parts[0] === "v1" && parts[1] === "friends" && parts[3] === "requests" && request.method === "GET") {
        return await getFriendRequests(env, parts[2]);
      }
      if (parts[0] === "v1" && parts[1] === "mailbox" && parts[2] && request.method === "POST") {
        return await mailboxPut(request, env, parts[2]);
      }
      if (parts[0] === "v1" && parts[1] === "mailbox" && parts[2] && parts.length === 3 && request.method === "GET") {
        return await mailboxGet(env, parts[2]);
      }
      if (parts[0] === "v1" && parts[1] === "mailbox" && parts[2] && parts[3] && request.method === "DELETE") {
        return await mailboxAck(env, parts[2], parts[3]);
      }
      if (parts[0] === "v1" && parts[1] === "signal") {
        const id = env.SIGNALING.idFromName("rendezvous");
        const stub = env.SIGNALING.get(id);
        return await stub.fetch(request);
      }
      if (url.pathname === "/health") return json({ ok: true });
      return json({ error: "not found" }, 404);
    } catch (error) {
      return json({ error: "internal error" }, 500);
    }
  },

  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    await expireSweep(env);
  },
};
