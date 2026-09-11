//! Local SQLite persistence. This is the authoritative client history store.
//!
//! Plaintext message bodies live here (the local device is inside the trust
//! boundary). Anything that leaves the device — transport envelopes, mailbox
//! objects, coordinator records — carries ciphertext only.

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Contact {
    pub username: String,
    pub display_name: String,
    pub x25519_pubkey: Option<Vec<u8>>,
    pub ed_pubkey: Option<Vec<u8>>,
    pub endpoint_id: Option<String>,
    pub endpoint_bundle: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FriendRequest {
    pub id: String,
    pub direction: String,
    pub peer_username: String,
    pub peer_display_name: String,
    pub status: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conversation {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub last_message_preview: Option<String>,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub id: String,
    pub conversation_id: String,
    pub sender_device_id: String,
    pub sender_username: String,
    pub message_type: String,
    /// Local plaintext body. Never leaves the device except inside ciphertext.
    pub body: String,
    pub ciphertext: Vec<u8>,
    pub sequence: i64,
    pub status: String,
    pub reply_to: Option<String>,
    pub created_at_ms: i64,
    pub edited_at_ms: Option<i64>,
    pub deleted_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    pub id: String,
    pub username: String,
    pub device_name: String,
    pub ed25519_pubkey: Vec<u8>,
    pub x25519_pubkey: Vec<u8>,
    pub iroh_endpoint_id: String,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupInfo {
    pub group_id: String,
    pub name: String,
    pub current_epoch: i64,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileTransfer {
    pub id: String,
    pub conversation_id: String,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub sha256_hex: String,
    pub state: String,
    pub bytes_done: i64,
    pub local_path: Option<String>,
    pub created_at_ms: i64,
}

/// A stored epoch-key wrap plus the wrapper's X25519 key (if known).
pub type StoredGroupKeyWrap = (Vec<u8>, Option<Vec<u8>>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingHandshake {
    pub message_id: String,
    pub peer_username: String,
    pub envelope_json: String,
    pub attempt_count: i64,
    pub next_attempt_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StashedEnvelope {
    pub message_id: String,
    pub endpoint_id: String,
    pub envelope_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingItem {
    pub id: String,
    pub message_id: String,
    pub peer_id: String,
    pub attempt_count: i64,
    pub next_attempt_at_ms: i64,
    pub state: String,
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

pub struct Database {
    connection: Connection,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
        let db = Self { connection };
        db.migrate()?;
        Ok(db)
    }

    pub fn in_memory() -> Result<Self> {
        Self::open(":memory:")
    }

    fn migrate(&self) -> Result<()> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                username TEXT NOT NULL,
                display_name TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                device_name TEXT NOT NULL,
                ed25519_pubkey BLOB NOT NULL,
                x25519_pubkey BLOB NOT NULL,
                iroh_endpoint_id TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                revoked_at_ms INTEGER
            );
            CREATE TABLE IF NOT EXISTS contacts (
                username TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                x25519_pubkey BLOB,
                endpoint_id TEXT,
                status TEXT NOT NULL DEFAULT 'friend',
                created_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS friend_requests (
                id TEXT PRIMARY KEY,
                direction TEXT NOT NULL,
                peer_username TEXT NOT NULL,
                peer_display_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                last_message_id TEXT,
                last_message_preview TEXT
            );
            CREATE TABLE IF NOT EXISTS conversation_members (
                conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                username TEXT NOT NULL,
                added_at_ms INTEGER NOT NULL,
                PRIMARY KEY (conversation_id, username)
            );
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                sender_device_id TEXT NOT NULL,
                sender_username TEXT NOT NULL DEFAULT '',
                sequence INTEGER NOT NULL,
                message_type TEXT NOT NULL,
                body TEXT NOT NULL DEFAULT '',
                ciphertext BLOB NOT NULL,
                status TEXT NOT NULL DEFAULT 'local',
                reply_to TEXT,
                created_at_ms INTEGER NOT NULL,
                edited_at_ms INTEGER,
                deleted_at_ms INTEGER,
                UNIQUE(conversation_id, sender_device_id, sequence)
            );
            CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at_ms);
            CREATE TABLE IF NOT EXISTS pending_outbound (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL UNIQUE REFERENCES messages(id) ON DELETE CASCADE,
                peer_id TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                next_attempt_at_ms INTEGER NOT NULL,
                state TEXT NOT NULL
            );
            -- Handshake envelopes (friend asks/answers) are not message rows, so
            -- they cannot use pending_outbound's message FK. Same retry shape.
            CREATE TABLE IF NOT EXISTS pending_handshakes (
                message_id TEXT PRIMARY KEY,
                peer_username TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                next_attempt_at_ms INTEGER NOT NULL
            );
            -- Handshake envelopes from unknown devices: kept undecrypted until
            -- the matching invite is imported, then trial-opened and routed.
            CREATE TABLE IF NOT EXISTS stashed_envelopes (
                message_id TEXT PRIMARY KEY,
                endpoint_id TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                received_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sync_cursors (
                peer_id TEXT NOT NULL,
                conversation_id TEXT NOT NULL,
                last_sequence INTEGER NOT NULL DEFAULT 0,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY (peer_id, conversation_id)
            );
            CREATE TABLE IF NOT EXISTS groups (
                group_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                current_epoch INTEGER NOT NULL DEFAULT 1,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS group_keys (
                group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
                epoch INTEGER NOT NULL,
                wrapped_for TEXT NOT NULL,
                wrapped_key BLOB NOT NULL,
                PRIMARY KEY (group_id, epoch, wrapped_for)
            );
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
                size_bytes INTEGER NOT NULL,
                sha256_hex TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'offered',
                bytes_done INTEGER NOT NULL DEFAULT 0,
                local_path TEXT,
                created_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mailbox_spool (
                id TEXT PRIMARY KEY,
                recipient_username TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER NOT NULL,
                state TEXT NOT NULL DEFAULT 'pending'
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )?;
        Ok(())
    }

    // -- profiles ----------------------------------------------------------
    pub fn save_profile(&self, username: &str, display_name: &str, now_ms: i64) -> Result<()> {
        self.connection.execute("INSERT INTO profiles (id, username, display_name, created_at_ms) VALUES (1, ?1, ?2, ?3) ON CONFLICT(id) DO UPDATE SET username = excluded.username, display_name = excluded.display_name", params![username, display_name, now_ms])?;
        Ok(())
    }

    pub fn profile_exists(&self) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM profiles WHERE id = 1)",
            [],
            |row| row.get::<_, i64>(0),
        )? != 0)
    }

    pub fn load_profile(&self) -> Result<Option<(String, String)>> {
        self.connection
            .query_row(
                "SELECT username, display_name FROM profiles WHERE id = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .context("load profile")
    }

    // -- settings ----------------------------------------------------------
    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.connection.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        self.connection
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context("get setting")
    }

    // -- devices -----------------------------------------------------------
    pub fn save_device(&self, device: &DeviceRecord) -> Result<()> {
        self.connection.execute(
            "INSERT INTO devices (id, username, device_name, ed25519_pubkey, x25519_pubkey, iroh_endpoint_id, created_at_ms, revoked_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET username = excluded.username, device_name = excluded.device_name,
               iroh_endpoint_id = excluded.iroh_endpoint_id, revoked_at_ms = excluded.revoked_at_ms",
            params![device.id, device.username, device.device_name, device.ed25519_pubkey, device.x25519_pubkey, device.iroh_endpoint_id, device.created_at_ms, device.revoked_at_ms],
        )?;
        Ok(())
    }

    pub fn load_device(&self) -> Result<Option<DeviceRecord>> {
        self.connection
            .query_row(
                "SELECT id, username, device_name, ed25519_pubkey, x25519_pubkey, iroh_endpoint_id, created_at_ms, revoked_at_ms
                 FROM devices ORDER BY created_at_ms DESC LIMIT 1",
                [],
                |row| {
                    Ok(DeviceRecord {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        device_name: row.get(2)?,
                        ed25519_pubkey: row.get(3)?,
                        x25519_pubkey: row.get(4)?,
                        iroh_endpoint_id: row.get(5)?,
                        created_at_ms: row.get(6)?,
                        revoked_at_ms: row.get(7)?,
                    })
                },
            )
            .optional()
            .context("load device")
    }

    // -- contacts / friends ------------------------------------------------
    pub fn upsert_contact(&self, contact: &Contact, now_ms: i64) -> Result<()> {
        self.ensure_contact_columns()?;
        self.connection.execute(
            "INSERT INTO contacts (username, display_name, x25519_pubkey, ed_pubkey, endpoint_id, endpoint_bundle, status, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(username) DO UPDATE SET display_name = excluded.display_name, x25519_pubkey = excluded.x25519_pubkey,
               ed_pubkey = excluded.ed_pubkey, endpoint_id = excluded.endpoint_id,
               endpoint_bundle = excluded.endpoint_bundle, status = excluded.status",
            params![contact.username, contact.display_name, contact.x25519_pubkey, contact.ed_pubkey, contact.endpoint_id, contact.endpoint_bundle, contact.status, now_ms],
        )?;
        Ok(())
    }

    fn ensure_contact_columns(&self) -> Result<()> {
        let mut stmt = self.connection.prepare("PRAGMA table_info(contacts)")?;
        let mut has_ed = false;
        let mut has_bundle = false;
        for name in stmt.query_map([], |row| row.get::<_, String>(1))?.flatten() {
            if name == "ed_pubkey" {
                has_ed = true;
            }
            if name == "endpoint_bundle" {
                has_bundle = true;
            }
        }
        if !has_ed {
            self.connection
                .execute_batch("ALTER TABLE contacts ADD COLUMN ed_pubkey BLOB;")?;
        }
        if !has_bundle {
            self.connection
                .execute_batch("ALTER TABLE contacts ADD COLUMN endpoint_bundle TEXT;")?;
        }
        Ok(())
    }

    pub fn remove_contact(&self, username: &str) -> Result<bool> {
        Ok(self.connection.execute(
            "DELETE FROM contacts WHERE username = ?1",
            params![username],
        )? > 0)
    }

    pub fn set_contact_status(&self, username: &str, status: &str) -> Result<()> {
        self.connection.execute(
            "UPDATE contacts SET status = ?1 WHERE username = ?2",
            params![status, username],
        )?;
        Ok(())
    }

    pub fn list_contacts(&self) -> Result<Vec<Contact>> {
        self.ensure_contact_columns()?;
        let mut stmt = self.connection.prepare(
            "SELECT username, display_name, x25519_pubkey, ed_pubkey, endpoint_id, endpoint_bundle, status FROM contacts ORDER BY username",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Contact {
                username: row.get(0)?,
                display_name: row.get(1)?,
                x25519_pubkey: row.get(2)?,
                ed_pubkey: row.get(3)?,
                endpoint_id: row.get(4)?,
                endpoint_bundle: row.get(5)?,
                status: row.get(6)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("list contacts")
    }

    pub fn find_contact(&self, username: &str) -> Result<Option<Contact>> {
        self.ensure_contact_columns()?;
        self.connection
            .query_row(
                "SELECT username, display_name, x25519_pubkey, ed_pubkey, endpoint_id, endpoint_bundle, status FROM contacts WHERE username = ?1",
                params![username],
                |row| {
                    Ok(Contact {
                        username: row.get(0)?,
                        display_name: row.get(1)?,
                        x25519_pubkey: row.get(2)?,
                        ed_pubkey: row.get(3)?,
                        endpoint_id: row.get(4)?,
                        endpoint_bundle: row.get(5)?,
                        status: row.get(6)?,
                    })
                },
            )
            .optional()
            .context("find contact")
    }

    // -- friend requests ---------------------------------------------------
    pub fn save_friend_request(&self, request: &FriendRequest, now_ms: i64) -> Result<()> {
        self.connection.execute(
            "INSERT INTO friend_requests (id, direction, peer_username, peer_display_name, status, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET status = excluded.status, updated_at_ms = excluded.updated_at_ms",
            params![request.id, request.direction, request.peer_username, request.peer_display_name, request.status, request.created_at_ms, now_ms],
        )?;
        Ok(())
    }

    pub fn set_friend_request_status(&self, id: &str, status: &str, now_ms: i64) -> Result<()> {
        self.connection.execute(
            "UPDATE friend_requests SET status = ?1, updated_at_ms = ?2 WHERE id = ?3",
            params![status, now_ms, id],
        )?;
        Ok(())
    }

    pub fn list_friend_requests(&self, status_filter: Option<&str>) -> Result<Vec<FriendRequest>> {
        let (sql, has_filter) = match status_filter {
            Some(_) => (
                "SELECT id, direction, peer_username, peer_display_name, status, created_at_ms FROM friend_requests WHERE status = ?1 ORDER BY created_at_ms DESC",
                true,
            ),
            None => (
                "SELECT id, direction, peer_username, peer_display_name, status, created_at_ms FROM friend_requests ORDER BY created_at_ms DESC",
                false,
            ),
        };
        let mut stmt = self.connection.prepare(sql)?;
        let map = |row: &rusqlite::Row| {
            Ok(FriendRequest {
                id: row.get(0)?,
                direction: row.get(1)?,
                peer_username: row.get(2)?,
                peer_display_name: row.get(3)?,
                status: row.get(4)?,
                created_at_ms: row.get(5)?,
            })
        };
        let rows = if has_filter {
            stmt.query_map(params![status_filter.unwrap()], map)?
        } else {
            stmt.query_map([], map)?
        };
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("list friend requests")
    }

    // -- conversations -----------------------------------------------------
    pub fn create_conversation(
        &self,
        id: &str,
        kind: &str,
        name: &str,
        members: &[String],
        now_ms: i64,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO conversations (id, kind, name, created_at_ms, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, updated_at_ms = excluded.updated_at_ms",
            params![id, kind, name, now_ms, now_ms],
        )?;
        for member in members {
            self.connection.execute(
                "INSERT OR IGNORE INTO conversation_members (conversation_id, username, added_at_ms) VALUES (?1, ?2, ?3)",
                params![id, member, now_ms],
            )?;
        }
        Ok(())
    }

    pub fn rename_conversation(&self, id: &str, name: &str, now_ms: i64) -> Result<()> {
        self.connection.execute(
            "UPDATE conversations SET name = ?1, updated_at_ms = ?2 WHERE id = ?3",
            params![name, now_ms, id],
        )?;
        Ok(())
    }

    pub fn set_conversation_members(
        &self,
        conversation_id: &str,
        members: &[String],
        now_ms: i64,
    ) -> Result<()> {
        for member in members {
            self.connection.execute(
                "INSERT OR IGNORE INTO conversation_members (conversation_id, username, added_at_ms) VALUES (?1, ?2, ?3)",
                params![conversation_id, member, now_ms],
            )?;
        }
        let placeholders = members.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        // Keep the table consistent with the latest epoch membership.
        let sql = if members.is_empty() {
            "DELETE FROM conversation_members WHERE conversation_id = ?1".to_string()
        } else {
            format!(
                "DELETE FROM conversation_members WHERE conversation_id = ?1 AND username NOT IN ({placeholders})"
            )
        };
        let mut stmt = self.connection.prepare(&sql)?;
        let mut values: Vec<&dyn rusqlite::ToSql> = vec![&conversation_id];
        for member in members {
            values.push(member);
        }
        stmt.execute(values.as_slice())?;
        Ok(())
    }

    pub fn remove_conversation_member(&self, conversation_id: &str, username: &str) -> Result<()> {
        self.connection.execute(
            "DELETE FROM conversation_members WHERE conversation_id = ?1 AND username = ?2",
            params![conversation_id, username],
        )?;
        Ok(())
    }

    pub fn delete_conversation(&self, id: &str) -> Result<()> {
        self.connection
            .execute("DELETE FROM conversations WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn list_conversations(&self) -> Result<Vec<Conversation>> {
        let mut stmt = self.connection.prepare(
            "SELECT id, kind, name, created_at_ms, updated_at_ms, last_message_preview FROM conversations ORDER BY updated_at_ms DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for (id, kind, name, created, updated, preview) in
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        {
            let members = self.conversation_members(&id)?;
            out.push(Conversation {
                id,
                kind,
                name,
                created_at_ms: created,
                updated_at_ms: updated,
                last_message_preview: preview,
                members,
            });
        }
        Ok(out)
    }

    pub fn conversation_members(&self, conversation_id: &str) -> Result<Vec<String>> {
        let mut stmt = self.connection.prepare(
            "SELECT username FROM conversation_members WHERE conversation_id = ?1 ORDER BY username",
        )?;
        let rows = stmt.query_map(params![conversation_id], |row| row.get::<_, String>(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("conversation members")
    }

    pub fn find_dm_with(&self, username: &str) -> Result<Option<String>> {
        let mut stmt = self.connection.prepare(
            "SELECT c.id FROM conversations c
             JOIN conversation_members m ON m.conversation_id = c.id
             WHERE c.kind = 'dm' AND m.username = ?1
             GROUP BY c.id HAVING COUNT(*) = 1",
        )?;
        stmt.query_row(params![username], |row| row.get::<_, String>(0))
            .optional()
            .context("find dm")
    }

    // -- messages ----------------------------------------------------------
    pub fn insert_message(&self, message: &Message) -> Result<bool> {
        let changed = self.connection.execute(
            "INSERT OR IGNORE INTO messages
             (id, conversation_id, sender_device_id, sender_username, sequence, message_type, body, ciphertext, status, reply_to, created_at_ms, edited_at_ms, deleted_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![message.id, message.conversation_id, message.sender_device_id, message.sender_username, message.sequence,
                message.message_type, message.body, message.ciphertext, message.status, message.reply_to,
                message.created_at_ms, message.edited_at_ms, message.deleted_at_ms],
        )?;
        if changed > 0 {
            let preview: String = message.body.chars().take(80).collect();
            self.connection.execute(
                "UPDATE conversations SET updated_at_ms = ?1, last_message_id = ?2, last_message_preview = ?3 WHERE id = ?4",
                params![message.created_at_ms, message.id, preview, message.conversation_id],
            )?;
        }
        Ok(changed > 0)
    }

    pub fn list_messages(&self, conversation_id: &str, limit: i64) -> Result<Vec<Message>> {
        // Thread display: control rows (edits, deletes, acks, typing, chunk
        // flow, commits) applied to state elsewhere and stay out of history.
        let mut stmt = self.connection.prepare(
            "SELECT id, conversation_id, sender_device_id, sender_username, sequence, message_type, body, ciphertext, status, reply_to, created_at_ms, edited_at_ms, deleted_at_ms
             FROM messages WHERE conversation_id = ?1 AND deleted_at_ms IS NULL
               AND message_type IN ('Message', 'FileOffer', 'GroupMessage')
             ORDER BY created_at_ms ASC, sequence ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![conversation_id, limit], |row| {
            Ok(Message {
                id: row.get(0)?,
                conversation_id: row.get(1)?,
                sender_device_id: row.get(2)?,
                sender_username: row.get(3)?,
                sequence: row.get(4)?,
                message_type: row.get(5)?,
                body: row.get(6)?,
                ciphertext: row.get(7)?,
                status: row.get(8)?,
                reply_to: row.get(9)?,
                created_at_ms: row.get(10)?,
                edited_at_ms: row.get(11)?,
                deleted_at_ms: row.get(12)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("list messages")
    }

    pub fn set_message_status(&self, id: &str, status: &str) -> Result<()> {
        self.connection.execute(
            "UPDATE messages SET status = ?1 WHERE id = ?2",
            params![status, id],
        )?;
        Ok(())
    }

    pub fn edit_message(&self, id: &str, body: &str, ciphertext: &[u8], now_ms: i64) -> Result<()> {
        self.connection.execute(
            "UPDATE messages SET body = ?1, ciphertext = ?2, edited_at_ms = ?3 WHERE id = ?4",
            params![body, ciphertext, now_ms, id],
        )?;
        Ok(())
    }

    pub fn tombstone_message(&self, id: &str, now_ms: i64) -> Result<()> {
        self.connection.execute(
            "UPDATE messages SET deleted_at_ms = ?1, body = '' WHERE id = ?2",
            params![now_ms, id],
        )?;
        Ok(())
    }

    pub fn next_sequence(&self, conversation_id: &str, sender_device_id: &str) -> Result<i64> {
        let max: Option<i64> = self.connection.query_row(
            "SELECT MAX(sequence) FROM messages WHERE conversation_id = ?1 AND sender_device_id = ?2",
            params![conversation_id, sender_device_id],
            |row| row.get(0),
        )?;
        Ok(max.unwrap_or(0) + 1)
    }

    // -- pending outbound --------------------------------------------------
    pub fn enqueue_pending(
        &self,
        id: &str,
        message_id: &str,
        peer_id: &str,
        next_attempt_at_ms: i64,
        state: &str,
    ) -> Result<()> {
        self.ensure_pending_peer_scope()?;
        self.connection.execute(
            "INSERT INTO pending_outbound (id, message_id, peer_id, attempt_count, next_attempt_at_ms, state)
             VALUES (?1, ?2, ?3, 0, ?4, ?5)
             ON CONFLICT(message_id, peer_id) DO UPDATE SET next_attempt_at_ms = excluded.next_attempt_at_ms, state = excluded.state",
            params![id, message_id, peer_id, next_attempt_at_ms, state],
        )?;
        Ok(())
    }

    /// The first schema scoped uniqueness to the message only, which drops
    /// all but one recipient for group retries. Transient rows, so rebuild
    /// the table when the old shape is detected.
    fn ensure_pending_peer_scope(&self) -> Result<()> {
        let auto: Vec<String> = self
            .connection
            .prepare("PRAGMA index_list(pending_outbound)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .flatten()
            .collect();
        if auto
            .iter()
            .any(|n| n == "sqlite_autoindex_pending_outbound_1")
        {
            self.connection.execute_batch(
                "ALTER TABLE pending_outbound RENAME TO pending_outbound_legacy;
                 CREATE TABLE pending_outbound (id TEXT PRIMARY KEY, message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                   peer_id TEXT NOT NULL, attempt_count INTEGER NOT NULL DEFAULT 0, next_attempt_at_ms INTEGER NOT NULL, state TEXT NOT NULL,
                   UNIQUE(message_id, peer_id));
                 INSERT OR IGNORE INTO pending_outbound SELECT * FROM pending_outbound_legacy;
                 DROP TABLE pending_outbound_legacy;",
            )?;
        }
        Ok(())
    }

    pub fn get_pending(&self, message_id: &str, peer_id: &str) -> Result<Option<PendingItem>> {
        self.ensure_pending_peer_scope()?;
        self.connection.query_row(
            "SELECT id, message_id, peer_id, attempt_count, next_attempt_at_ms, state FROM pending_outbound WHERE message_id = ?1 AND peer_id = ?2",
            params![message_id, peer_id],
            |row| {
                Ok(PendingItem {
                    id: row.get(0)?,
                    message_id: row.get(1)?,
                    peer_id: row.get(2)?,
                    attempt_count: row.get(3)?,
                    next_attempt_at_ms: row.get(4)?,
                    state: row.get(5)?,
                })
            },
        ).optional().context("get pending")
    }

    pub fn list_due_pending(&self, now_ms: i64, limit: i64) -> Result<Vec<PendingItem>> {
        let mut stmt = self.connection.prepare(
            "SELECT id, message_id, peer_id, attempt_count, next_attempt_at_ms, state FROM pending_outbound
             WHERE next_attempt_at_ms <= ?1 ORDER BY next_attempt_at_ms ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now_ms, limit], |row| {
            Ok(PendingItem {
                id: row.get(0)?,
                message_id: row.get(1)?,
                peer_id: row.get(2)?,
                attempt_count: row.get(3)?,
                next_attempt_at_ms: row.get(4)?,
                state: row.get(5)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("due pending")
    }

    pub fn backoff_pending(&self, message_id: &str, next_attempt_at_ms: i64) -> Result<()> {
        self.connection.execute(
            "UPDATE pending_outbound SET attempt_count = attempt_count + 1, next_attempt_at_ms = ?1, state = 'retrying' WHERE message_id = ?2",
            params![next_attempt_at_ms, message_id],
        )?;
        Ok(())
    }

    pub fn dequeue_pending(&self, message_id: &str) -> Result<()> {
        self.connection.execute(
            "DELETE FROM pending_outbound WHERE message_id = ?1",
            params![message_id],
        )?;
        Ok(())
    }

    pub fn dequeue_pending_for(&self, message_id: &str, peer_id: &str) -> Result<()> {
        self.connection.execute(
            "DELETE FROM pending_outbound WHERE message_id = ?1 AND peer_id = ?2",
            params![message_id, peer_id],
        )?;
        Ok(())
    }

    // -- handshake retry queue ---------------------------------------------
    pub fn enqueue_handshake(
        &self,
        message_id: &str,
        peer_username: &str,
        envelope_json: &str,
        next_attempt_at_ms: i64,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO pending_handshakes (message_id, peer_username, envelope_json, attempt_count, next_attempt_at_ms)
             VALUES (?1, ?2, ?3, 0, ?4)
             ON CONFLICT(message_id) DO UPDATE SET next_attempt_at_ms = excluded.next_attempt_at_ms",
            params![message_id, peer_username, envelope_json, next_attempt_at_ms],
        )?;
        Ok(())
    }

    pub fn list_due_handshakes(&self, now_ms: i64, limit: i64) -> Result<Vec<PendingHandshake>> {
        let mut stmt = self.connection.prepare(
            "SELECT message_id, peer_username, envelope_json, attempt_count, next_attempt_at_ms
             FROM pending_handshakes WHERE next_attempt_at_ms <= ?1
             ORDER BY next_attempt_at_ms ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now_ms, limit], |row| {
            Ok(PendingHandshake {
                message_id: row.get(0)?,
                peer_username: row.get(1)?,
                envelope_json: row.get(2)?,
                attempt_count: row.get(3)?,
                next_attempt_at_ms: row.get(4)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("due handshakes")
    }

    pub fn backoff_handshake(&self, message_id: &str, next_attempt_at_ms: i64) -> Result<()> {
        self.connection.execute(
            "UPDATE pending_handshakes SET attempt_count = attempt_count + 1, next_attempt_at_ms = ?1 WHERE message_id = ?2",
            params![next_attempt_at_ms, message_id],
        )?;
        Ok(())
    }

    pub fn dequeue_handshake(&self, message_id: &str) -> Result<()> {
        self.connection.execute(
            "DELETE FROM pending_handshakes WHERE message_id = ?1",
            params![message_id],
        )?;
        Ok(())
    }

    // -- unknown-sender stash ----------------------------------------------
    /// Stash an undecryptable handshake envelope. Dedupes by message id so
    /// mailbox redelivery never piles up copies.
    pub fn stash_envelope(
        &self,
        message_id: &str,
        endpoint_id: &str,
        envelope_json: &str,
        now_ms: i64,
        expires_at_ms: i64,
    ) -> Result<bool> {
        let inserted = self.connection.execute(
            "INSERT OR IGNORE INTO stashed_envelopes (message_id, endpoint_id, envelope_json, received_at_ms, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![message_id, endpoint_id, envelope_json, now_ms, expires_at_ms],
        )? > 0;
        // Bounded: keep the newest 200 so a spammer cannot grow this table.
        self.connection.execute(
            "DELETE FROM stashed_envelopes WHERE message_id NOT IN
             (SELECT message_id FROM stashed_envelopes ORDER BY received_at_ms DESC LIMIT 200)",
            [],
        )?;
        Ok(inserted)
    }

    /// Non-expired stashed envelopes, oldest first. Prunes the expired.
    pub fn list_stash(&self, now_ms: i64) -> Result<Vec<StashedEnvelope>> {
        self.connection.execute(
            "DELETE FROM stashed_envelopes WHERE expires_at_ms <= ?1",
            params![now_ms],
        )?;
        let mut stmt = self.connection.prepare(
            "SELECT message_id, endpoint_id, envelope_json FROM stashed_envelopes ORDER BY received_at_ms ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StashedEnvelope {
                message_id: row.get(0)?,
                endpoint_id: row.get(1)?,
                envelope_json: row.get(2)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("list stash")
    }

    pub fn unstash(&self, message_id: &str) -> Result<()> {
        self.connection.execute(
            "DELETE FROM stashed_envelopes WHERE message_id = ?1",
            params![message_id],
        )?;
        Ok(())
    }

    // -- sync cursors ------------------------------------------------------
    pub fn update_sync_cursor(
        &self,
        peer_id: &str,
        conversation_id: &str,
        last_sequence: i64,
        now_ms: i64,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO sync_cursors (peer_id, conversation_id, last_sequence, updated_at_ms) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(peer_id, conversation_id) DO UPDATE SET last_sequence = max(last_sequence, excluded.last_sequence), updated_at_ms = excluded.updated_at_ms",
            params![peer_id, conversation_id, last_sequence, now_ms],
        )?;
        Ok(())
    }

    // -- groups ------------------------------------------------------------
    pub fn save_group(&self, group_id: &str, name: &str, epoch: i64, now_ms: i64) -> Result<()> {
        self.connection.execute(
            "INSERT INTO groups (group_id, name, current_epoch, created_at_ms, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(group_id) DO UPDATE SET name = excluded.name, current_epoch = excluded.current_epoch, updated_at_ms = excluded.updated_at_ms",
            params![group_id, name, epoch, now_ms],
        )?;
        Ok(())
    }

    pub fn load_group(&self, group_id: &str) -> Result<Option<GroupInfo>> {
        let row: Option<(String, i64)> = self
            .connection
            .query_row(
                "SELECT name, current_epoch FROM groups WHERE group_id = ?1",
                params![group_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match row {
            Some((name, epoch)) => Ok(Some(GroupInfo {
                group_id: group_id.to_string(),
                name,
                current_epoch: epoch,
                members: self.conversation_members(group_id)?,
            })),
            None => Ok(None),
        }
    }

    pub fn save_wrapped_group_key(
        &self,
        group_id: &str,
        epoch: i64,
        wrapped_for: &str,
        wrapped_key: &[u8],
    ) -> Result<()> {
        self.ensure_group_key_sender_column()?;
        self.connection.execute(
            "INSERT OR REPLACE INTO group_keys (group_id, epoch, wrapped_for, wrapped_key) VALUES (?1, ?2, ?3, ?4)",
            params![group_id, epoch, wrapped_for, wrapped_key],
        )?;
        Ok(())
    }

    /// Records which member wrapped the key so the recipient knows whose
    /// public key unwraps it. Added after the initial schema; backfilled
    /// lazily so existing installs migrate without a version table.
    pub fn save_wrapped_group_key_from(
        &self,
        group_id: &str,
        epoch: i64,
        wrapped_for: &str,
        wrapped_key: &[u8],
        wrapper_x_pub: &[u8],
    ) -> Result<()> {
        self.ensure_group_key_sender_column()?;
        self.connection.execute(
            "INSERT OR REPLACE INTO group_keys (group_id, epoch, wrapped_for, wrapped_key, wrapper_x_pub) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![group_id, epoch, wrapped_for, wrapped_key, wrapper_x_pub],
        )?;
        Ok(())
    }

    fn ensure_group_key_sender_column(&self) -> Result<()> {
        let mut stmt = self.connection.prepare("PRAGMA table_info(group_keys)")?;
        let mut has_column = false;
        let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
        for name in rows.flatten() {
            if name == "wrapper_x_pub" {
                has_column = true;
                break;
            }
        }
        if !has_column {
            self.connection
                .execute_batch("ALTER TABLE group_keys ADD COLUMN wrapper_x_pub BLOB;")?;
        }
        Ok(())
    }

    pub fn load_wrapped_group_key_with_sender(
        &self,
        group_id: &str,
        epoch: i64,
        wrapped_for: &str,
    ) -> Result<Option<StoredGroupKeyWrap>> {
        self.ensure_group_key_sender_column()?;
        let row: Option<(Vec<u8>, Option<Vec<u8>>)> = self
            .connection
            .query_row(
                "SELECT wrapped_key, wrapper_x_pub FROM group_keys WHERE group_id = ?1 AND epoch = ?2 AND wrapped_for = ?3",
                params![group_id, epoch, wrapped_for],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()?;
        Ok(row)
    }

    pub fn load_wrapped_group_key(
        &self,
        group_id: &str,
        epoch: i64,
        wrapped_for: &str,
    ) -> Result<Option<Vec<u8>>> {
        self.connection.query_row(
            "SELECT wrapped_key FROM group_keys WHERE group_id = ?1 AND epoch = ?2 AND wrapped_for = ?3",
            params![group_id, epoch, wrapped_for],
            |row| row.get::<_, Vec<u8>>(0),
        ).optional().context("load group key")
    }

    pub fn delete_wrapped_keys_for(&self, group_id: &str, username: &str) -> Result<()> {
        self.connection.execute(
            "DELETE FROM group_keys WHERE group_id = ?1 AND wrapped_for = ?2",
            params![group_id, username],
        )?;
        Ok(())
    }

    // -- files -------------------------------------------------------------
    pub fn save_file(&self, file: &FileTransfer, _now_ms: i64) -> Result<()> {
        self.connection.execute(
            "INSERT INTO files (id, conversation_id, filename, mime_type, size_bytes, sha256_hex, state, bytes_done, local_path, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET state = excluded.state, bytes_done = excluded.bytes_done, local_path = excluded.local_path",
            params![file.id, file.conversation_id, file.filename, file.mime_type, file.size_bytes, file.sha256_hex, file.state, file.bytes_done, file.local_path, file.created_at_ms],
        )?;
        Ok(())
    }

    pub fn load_file(&self, id: &str) -> Result<Option<FileTransfer>> {
        self.connection.query_row(
            "SELECT id, conversation_id, filename, mime_type, size_bytes, sha256_hex, state, bytes_done, local_path, created_at_ms FROM files WHERE id = ?1",
            params![id],
            |row| {
                Ok(FileTransfer {
                    id: row.get(0)?,
                    conversation_id: row.get(1)?,
                    filename: row.get(2)?,
                    mime_type: row.get(3)?,
                    size_bytes: row.get(4)?,
                    sha256_hex: row.get(5)?,
                    state: row.get(6)?,
                    bytes_done: row.get(7)?,
                    local_path: row.get(8)?,
                    created_at_ms: row.get(9)?,
                })
            },
        ).optional().context("load file")
    }

    pub fn list_files(&self, conversation_id: &str) -> Result<Vec<FileTransfer>> {
        let mut stmt = self.connection.prepare(
            "SELECT id, conversation_id, filename, mime_type, size_bytes, sha256_hex, state, bytes_done, local_path, created_at_ms FROM files WHERE conversation_id = ?1 ORDER BY rowid DESC",
        )?;
        let rows = stmt.query_map(params![conversation_id], |row| {
            Ok(FileTransfer {
                id: row.get(0)?,
                conversation_id: row.get(1)?,
                filename: row.get(2)?,
                mime_type: row.get(3)?,
                size_bytes: row.get(4)?,
                sha256_hex: row.get(5)?,
                state: row.get(6)?,
                bytes_done: row.get(7)?,
                local_path: row.get(8)?,
                created_at_ms: row.get(9)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("list files")
    }

    // -- local mailbox spool (used when no cloud coordinator is configured) -
    pub fn spool_mailbox(
        &self,
        id: &str,
        recipient: &str,
        envelope_json: &str,
        now_ms: i64,
        expires_at_ms: i64,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT OR IGNORE INTO mailbox_spool (id, recipient_username, envelope_json, created_at_ms, expires_at_ms, state)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending')",
            params![id, recipient, envelope_json, now_ms, expires_at_ms],
        )?;
        Ok(())
    }

    pub fn collect_mailbox(&self, recipient: &str, now_ms: i64) -> Result<Vec<(String, String)>> {
        let mut stmt = self.connection.prepare(
            "SELECT id, envelope_json FROM mailbox_spool WHERE recipient_username = ?1 AND state = 'pending' AND expires_at_ms > ?2 ORDER BY created_at_ms ASC",
        )?;
        let rows = stmt.query_map(params![recipient, now_ms], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("collect mailbox")
    }

    pub fn ack_mailbox(&self, id: &str) -> Result<()> {
        self.connection.execute(
            "UPDATE mailbox_spool SET state = 'acked' WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Case-insensitive substring search over thread-visible messages.
    pub fn search_messages(
        &self,
        conversation_id: &str,
        query: &str,
        limit: i64,
    ) -> Result<Vec<Message>> {
        let pattern = format!(
            "%{}%",
            query
                .replace(['%', '_', '\\'], "")
                .chars()
                .take(80)
                .collect::<String>()
        );
        let mut stmt = self.connection.prepare(
            "SELECT id, conversation_id, sender_device_id, sender_username, sequence, message_type, body, ciphertext, status, reply_to, created_at_ms, edited_at_ms, deleted_at_ms
             FROM messages WHERE conversation_id = ?1 AND deleted_at_ms IS NULL
               AND message_type IN ('Message', 'FileOffer', 'GroupMessage')
               AND body LIKE ?2 ESCAPE '\\'
             ORDER BY created_at_ms DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![conversation_id, pattern, limit], |row| {
            Ok(Message {
                id: row.get(0)?,
                conversation_id: row.get(1)?,
                sender_device_id: row.get(2)?,
                sender_username: row.get(3)?,
                sequence: row.get(4)?,
                message_type: row.get(5)?,
                body: row.get(6)?,
                ciphertext: row.get(7)?,
                status: row.get(8)?,
                reply_to: row.get(9)?,
                created_at_ms: row.get(10)?,
                edited_at_ms: row.get(11)?,
                deleted_at_ms: row.get(12)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("search messages")
    }

    pub fn get_message(&self, id: &str) -> Result<Option<Message>> {
        self.connection.query_row(
            "SELECT id, conversation_id, sender_device_id, sender_username, sequence, message_type, body, ciphertext, status, reply_to, created_at_ms, edited_at_ms, deleted_at_ms
             FROM messages WHERE id = ?1",
            params![id],
            |row| {
                Ok(Message {
                    id: row.get(0)?,
                    conversation_id: row.get(1)?,
                    sender_device_id: row.get(2)?,
                    sender_username: row.get(3)?,
                    sequence: row.get(4)?,
                    message_type: row.get(5)?,
                    body: row.get(6)?,
                    ciphertext: row.get(7)?,
                    status: row.get(8)?,
                    reply_to: row.get(9)?,
                    created_at_ms: row.get(10)?,
                    edited_at_ms: row.get(11)?,
                    deleted_at_ms: row.get(12)?,
                })
            },
        ).optional().context("get message")
    }

    pub fn set_conversation_preview(
        &self,
        conversation_id: &str,
        preview: &str,
        now_ms: i64,
    ) -> Result<()> {
        self.connection.execute(
            "UPDATE conversations SET last_message_preview = ?1, updated_at_ms = ?2 WHERE id = ?3",
            params![preview, now_ms, conversation_id],
        )?;
        Ok(())
    }

    pub fn unread_count(&self, conversation_id: &str, my_username: &str) -> Result<i64> {
        Ok(self.connection.query_row(
            "SELECT COUNT(*) FROM messages WHERE conversation_id = ?1 AND sender_username != ?2 AND status = 'delivered' AND deleted_at_ms IS NULL",
            params![conversation_id, my_username],
            |row| row.get::<_, i64>(0),
        )?)
    }

    fn ensure_file_offer_column(&self) -> Result<()> {
        let mut stmt = self.connection.prepare("PRAGMA table_info(files)")?;
        for name in stmt.query_map([], |row| row.get::<_, String>(1))?.flatten() {
            if name == "offer_json" {
                return Ok(());
            }
        }
        self.connection
            .execute_batch("ALTER TABLE files ADD COLUMN offer_json TEXT;")?;
        Ok(())
    }

    pub fn save_offer_json(&self, file_id: &str, offer_json: &str) -> Result<()> {
        self.ensure_file_offer_column()?;
        self.connection.execute(
            "UPDATE files SET offer_json = ?1 WHERE id = ?2",
            params![offer_json, file_id],
        )?;
        Ok(())
    }

    pub fn load_offer_json(&self, file_id: &str) -> Result<Option<String>> {
        self.ensure_file_offer_column()?;
        let row: Option<Option<String>> = self
            .connection
            .query_row(
                "SELECT offer_json FROM files WHERE id = ?1",
                params![file_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?;
        Ok(row.flatten())
    }

    /// Factory-reset identity data for logout: profile, device record,
    /// contacts, requests, conversations + history, groups + keys, pending
    /// work, cursors, files rows, mailbox spool. App `settings` (coordinator,
    /// worker URL, relay flag) are preferences and survive.
    pub fn wipe_user_data(&self) -> Result<()> {
        self.connection.execute_batch(
            "DELETE FROM mailbox_spool;
             DELETE FROM pending_outbound;
             DELETE FROM sync_cursors;
             DELETE FROM group_keys;
             DELETE FROM groups;
             DELETE FROM messages;
             DELETE FROM conversation_members;
             DELETE FROM conversations;
             DELETE FROM friend_requests;
             DELETE FROM contacts;
             DELETE FROM files;
             DELETE FROM devices;
             DELETE FROM profiles;",
        )?;
        Ok(())
    }

    pub fn expire_mailbox(&self, now_ms: i64) -> Result<u64> {
        Ok(self.connection.execute(
            "UPDATE mailbox_spool SET state = 'expired' WHERE state = 'pending' AND expires_at_ms <= ?1",
            params![now_ms],
        )? as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn migrates_and_persists_profile() {
        let db = Database::in_memory().unwrap();
        assert!(!db.profile_exists().unwrap());
        db.save_profile("ada", "Ada", 1).unwrap();
        assert!(db.profile_exists().unwrap());
        assert_eq!(
            db.load_profile().unwrap(),
            Some(("ada".to_string(), "Ada".to_string()))
        );
    }

    #[test]
    fn friends_and_dm_lifecycle() {
        let db = Database::in_memory().unwrap();
        db.upsert_contact(
            &Contact {
                username: "bob".into(),
                display_name: "Bob".into(),
                x25519_pubkey: None,
                ed_pubkey: None,
                endpoint_id: None,
                endpoint_bundle: None,
                status: "friend".into(),
            },
            1,
        )
        .unwrap();
        assert_eq!(db.list_contacts().unwrap().len(), 1);
        assert!(db.find_dm_with("bob").unwrap().is_none());
        db.create_conversation("conv-1", "dm", "", &["bob".to_string()], 2)
            .unwrap();
        assert_eq!(db.find_dm_with("bob").unwrap(), Some("conv-1".to_string()));
        assert!(db.remove_contact("bob").unwrap());
        assert!(db.list_contacts().unwrap().is_empty());
    }

    #[test]
    fn messages_are_idempotent() {
        let db = Database::in_memory().unwrap();
        db.create_conversation("conv-1", "dm", "", &["bob".to_string()], 1)
            .unwrap();
        let message = Message {
            id: "msg-1".into(),
            conversation_id: "conv-1".into(),
            sender_device_id: "dev-1".into(),
            sender_username: "ada".into(),
            message_type: "Message".into(),
            body: "hello".into(),
            ciphertext: vec![9],
            sequence: 1,
            status: "local".into(),
            reply_to: None,
            created_at_ms: 3,
            edited_at_ms: None,
            deleted_at_ms: None,
        };
        assert!(db.insert_message(&message).unwrap());
        assert!(!db.insert_message(&message).unwrap());
        assert_eq!(db.list_messages("conv-1", 50).unwrap().len(), 1);
        assert_eq!(db.next_sequence("conv-1", "dev-1").unwrap(), 2);
    }

    #[test]
    fn pending_queue_backoff_and_dequeue() {
        let db = Database::in_memory().unwrap();
        db.create_conversation("conv-1", "dm", "", &["bob".to_string()], 1)
            .unwrap();
        let message = Message {
            id: "msg-1".into(),
            conversation_id: "conv-1".into(),
            sender_device_id: "dev-1".into(),
            sender_username: "ada".into(),
            message_type: "MESSAGE".into(),
            body: "hi".into(),
            ciphertext: vec![7],
            sequence: 1,
            status: "queued".into(),
            reply_to: None,
            created_at_ms: 2,
            edited_at_ms: None,
            deleted_at_ms: None,
        };
        db.insert_message(&message).unwrap();
        db.enqueue_pending("p-1", "msg-1", "peer-bob", 10, "queued")
            .unwrap();
        assert_eq!(db.list_due_pending(11, 10).unwrap().len(), 1);
        assert!(db.list_due_pending(9, 10).unwrap().is_empty());
        db.backoff_pending("msg-1", 99).unwrap();
        assert!(db.list_due_pending(50, 10).unwrap().is_empty());
        db.dequeue_pending("msg-1").unwrap();
        assert!(db.list_due_pending(100, 10).unwrap().is_empty());
    }

    #[test]
    fn wipe_user_data_clears_identity_but_keeps_settings() {
        let db = Database::in_memory().unwrap();
        db.save_profile("ada", "Ada", 1).unwrap();
        db.set_setting("coordinator", "local").unwrap();
        db.upsert_contact(
            &crate::Contact {
                username: "bob".into(),
                display_name: "Bob".into(),
                x25519_pubkey: None,
                ed_pubkey: None,
                endpoint_id: None,
                endpoint_bundle: None,
                status: "friend".into(),
            },
            2,
        )
        .unwrap();
        db.create_conversation("conv-1", "dm", "", &["bob".to_string()], 3)
            .unwrap();
        db.wipe_user_data().unwrap();
        assert!(!db.profile_exists().unwrap());
        assert!(db.list_contacts().unwrap().is_empty());
        assert!(db.list_conversations().unwrap().is_empty());
        assert_eq!(
            db.get_setting("coordinator").unwrap(),
            Some("local".to_string())
        );
    }

    #[test]
    fn handshake_queue_roundtrip_with_backoff() {
        let db = Database::in_memory().unwrap();
        assert!(db.list_due_handshakes(100, 10).unwrap().is_empty());
        db.enqueue_handshake("m-1", "bob", "{\"a\":1}", 10).unwrap();
        // Re-enqueue keeps a single row per message.
        db.enqueue_handshake("m-1", "bob", "{\"a\":1}", 12).unwrap();
        assert!(db.list_due_handshakes(11, 10).unwrap().is_empty());
        assert_eq!(db.list_due_handshakes(12, 10).unwrap().len(), 1);
        db.backoff_handshake("m-1", 99).unwrap();
        let due = db.list_due_handshakes(99, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].attempt_count, 1);
        db.dequeue_handshake("m-1").unwrap();
        assert!(db.list_due_handshakes(100, 10).unwrap().is_empty());
    }

    #[test]
    fn stash_dedupes_and_expires() {
        let db = Database::in_memory().unwrap();
        assert!(db.stash_envelope("m-1", "node-x", "{}", 10, 100).unwrap());
        assert!(!db.stash_envelope("m-1", "node-x", "{}", 11, 100).unwrap());
        db.stash_envelope("m-old", "node-x", "{}", 10, 20).unwrap();
        let live = db.list_stash(50).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].message_id, "m-1");
        db.unstash("m-1").unwrap();
        assert!(db.list_stash(50).unwrap().is_empty());
    }

    #[test]
    fn mailbox_spool_collect_ack_expire() {
        let db = Database::in_memory().unwrap();
        db.spool_mailbox("m-1", "bob", "{\"a\":1}", 10, 100)
            .unwrap();
        db.spool_mailbox("m-2", "bob", "{\"a\":2}", 11, 12).unwrap();
        assert_eq!(db.collect_mailbox("bob", 50).unwrap().len(), 1);
        db.ack_mailbox("m-1").unwrap();
        assert!(db.collect_mailbox("bob", 50).unwrap().is_empty());
        assert_eq!(db.expire_mailbox(50).unwrap(), 1);
    }
}
