-- Hearth coordination schema (D1). Metadata only: usernames, device
-- records, friend-request metadata, mailbox index. No message plaintext,
-- no history, no typing/presence rows — ever.

CREATE TABLE IF NOT EXISTS directory (
  username TEXT PRIMARY KEY,
  display_name TEXT NOT NULL DEFAULT '',
  ed_pubkey_hex TEXT NOT NULL,
  x_pubkey_hex TEXT NOT NULL,
  endpoint_id TEXT NOT NULL DEFAULT '',
  endpoint_bundle TEXT NOT NULL DEFAULT '',
  updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS friend_requests (
  id TEXT PRIMARY KEY,
  to_username TEXT NOT NULL,
  from_username TEXT NOT NULL,
  from_display_name TEXT NOT NULL DEFAULT '',
  from_ed_hex TEXT NOT NULL DEFAULT '',
  from_x_hex TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_friend_requests_to ON friend_requests(to_username, status);

-- Ciphertext mailbox index. The envelope bytes live in R2 under
-- mailbox/{to_username}/{id}.json; this table only tracks delivery state.
CREATE TABLE IF NOT EXISTS mailbox_index (
  id TEXT PRIMARY KEY,
  to_username TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mailbox_to ON mailbox_index(to_username, expires_at_ms);
