//! Ephemeral presence: typing indicators and liveness hints.
//!
//! Everything here is in-memory with short TTLs. Nothing is written to
//! SQLite, sent to the coordinator, or kept after disconnect — per the plan,
//! typing/presence must never become durable chat history.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::PresenceStatus;

pub const TYPING_TTL: Duration = Duration::from_secs(6);
/// Heartbeats older than this mean the peer is gone (or quiet): offline.
pub const PRESENCE_TTL: Duration = Duration::from_secs(90);
/// No local activity for this long → auto-away.
pub const AWAY_AFTER: Duration = Duration::from_secs(5 * 60);

#[derive(Default)]
pub struct TypingTracker {
    entries: HashMap<(String, String), Instant>,
    ttl: Option<Duration>,
}

impl TypingTracker {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            ttl: Some(TYPING_TTL),
        }
    }

    #[cfg(test)]
    fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            ttl: Some(ttl),
        }
    }

    pub fn set_typing(&mut self, conversation_id: &str, username: &str, typing: bool) {
        let key = (conversation_id.to_string(), username.to_string());
        if typing {
            self.entries.insert(key, Instant::now());
        } else {
            self.entries.remove(&key);
        }
    }

    pub fn clear_user(&mut self, username: &str) {
        self.entries.retain(|(_, user), _| user != username);
    }

    pub fn active_typists(&mut self, conversation_id: &str) -> Vec<String> {
        self.prune();
        let mut out: Vec<String> = self
            .entries
            .keys()
            .filter(|(conv, _)| conv == conversation_id)
            .map(|(_, user)| user.clone())
            .collect();
        out.sort();
        out
    }

    fn prune(&mut self) {
        let ttl = self.ttl.unwrap_or(TYPING_TTL);
        let now = Instant::now();
        self.entries.retain(|_, at| now.duration_since(*at) <= ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_appears_and_clears() {
        let mut tracker = TypingTracker::new();
        assert!(tracker.active_typists("c1").is_empty());
        tracker.set_typing("c1", "bob", true);
        assert_eq!(tracker.active_typists("c1"), vec!["bob".to_string()]);
        tracker.set_typing("c1", "bob", false);
        assert!(tracker.active_typists("c1").is_empty());
    }

    #[test]
    fn entries_expire() {
        let mut tracker = TypingTracker::with_ttl(Duration::from_millis(1));
        tracker.set_typing("c1", "bob", true);
        std::thread::sleep(Duration::from_millis(5));
        assert!(tracker.active_typists("c1").is_empty());
    }

    #[test]
    fn presence_effective_and_expiry() {
        let mut tracker = PresenceTracker::new();
        assert_eq!(tracker.effective(true), PresenceStatus::Online);
        assert_eq!(tracker.effective(false), PresenceStatus::Offline);
        assert!(!tracker.set_manual(PresenceStatus::Offline));
        assert!(tracker.set_manual(PresenceStatus::Dnd));
        assert_eq!(tracker.effective(true), PresenceStatus::Dnd);

        tracker.peer_update("bob", PresenceStatus::Online);
        let peer = tracker.peer_status("bob");
        assert!(peer.fresh);
        assert_eq!(peer.status, PresenceStatus::Online);
        // Unknown peers read as stale offline, never as online.
        let ghost = tracker.peer_status("ghost");
        assert!(!ghost.fresh);
        assert_eq!(ghost.status, PresenceStatus::Offline);
        // Wire-claimed offline is ignored.
        tracker.peer_update("mallory", PresenceStatus::Offline);
        assert!(!tracker.peer_status("mallory").fresh);
    }

    #[test]
    fn presence_labels_parse() {
        assert_eq!(PresenceStatus::parse("dnd"), Some(PresenceStatus::Dnd));
        assert_eq!(
            PresenceStatus::parse("Do Not Disturb"),
            Some(PresenceStatus::Dnd)
        );
        assert_eq!(PresenceStatus::parse("away"), Some(PresenceStatus::Away));
        assert_eq!(PresenceStatus::parse("offline"), None);
        assert_eq!(PresenceStatus::Online.label(), "online");
    }

    #[test]
    fn disconnect_clears_user_everywhere() {
        let mut tracker = TypingTracker::new();
        tracker.set_typing("c1", "bob", true);
        tracker.set_typing("c2", "bob", true);
        tracker.clear_user("bob");
        assert!(tracker.active_typists("c1").is_empty());
        assert!(tracker.active_typists("c2").is_empty());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPresence {
    pub username: String,
    pub status: PresenceStatus,
    /// False when the last heartbeat is older than [`PRESENCE_TTL`].
    pub fresh: bool,
}

/// Local presence setting plus last-seen heartbeats from friends.
///
/// Everything is in-memory and ephemeral: heartbeats are small signed frames,
/// never SQLite rows, never coordinator records.
#[derive(Debug)]
pub struct PresenceTracker {
    manual: PresenceStatus,
    last_activity: Instant,
    peers: HashMap<String, (PresenceStatus, Instant)>,
}

impl Default for PresenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl PresenceTracker {
    pub fn new() -> Self {
        Self {
            manual: PresenceStatus::Online,
            // Start "active now" so a fresh launch shows online, not away.
            last_activity: Instant::now(),
            peers: HashMap::new(),
        }
    }

    /// Manual status. `Offline` cannot be forced — it is derived.
    pub fn set_manual(&mut self, status: PresenceStatus) -> bool {
        if status == PresenceStatus::Offline {
            return false;
        }
        self.manual = status;
        self.last_activity = Instant::now();
        true
    }

    pub fn manual(&self) -> PresenceStatus {
        self.manual
    }

    /// Any local command activity resets the idle clock.
    pub fn activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// What we advertise: offline without transport, else manual choice with
    /// idle auto-away (DND sticks through idleness).
    pub fn effective(&self, transport_up: bool) -> PresenceStatus {
        if !transport_up {
            return PresenceStatus::Offline;
        }
        if self.manual == PresenceStatus::Dnd {
            return PresenceStatus::Dnd;
        }
        if self.manual == PresenceStatus::Away || self.last_activity.elapsed() > AWAY_AFTER {
            return PresenceStatus::Away;
        }
        PresenceStatus::Online
    }

    /// Record a friend's heartbeat. Offline claims from the wire are ignored;
    /// absence is what means offline.
    pub fn peer_update(&mut self, username: &str, status: PresenceStatus) {
        if status == PresenceStatus::Offline {
            return;
        }
        self.peers
            .insert(username.to_string(), (status, Instant::now()));
    }

    pub fn peer_forget(&mut self, username: &str) {
        self.peers.remove(username);
    }

    pub fn peer_status(&self, username: &str) -> PeerPresence {
        match self.peers.get(username) {
            Some((status, at)) if at.elapsed() <= PRESENCE_TTL => PeerPresence {
                username: username.to_string(),
                status: *status,
                fresh: true,
            },
            _ => PeerPresence {
                username: username.to_string(),
                status: PresenceStatus::Offline,
                fresh: false,
            },
        }
    }

    pub fn list(&self) -> Vec<PeerPresence> {
        let mut out: Vec<PeerPresence> = self
            .peers
            .keys()
            .map(|username| self.peer_status(username))
            .collect();
        out.sort_by(|a, b| a.username.cmp(&b.username));
        out
    }

    pub fn prune(&mut self) {
        self.peers
            .retain(|_, (_, at)| at.elapsed() <= PRESENCE_TTL * 2);
    }
}
