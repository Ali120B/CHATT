//! P2P transport over Iroh / QUIC (Phase 4).
//!
//! Iroh provides authenticated endpoints (the endpoint ID *is* the device's
//! Ed25519 public key), direct connections, NAT traversal, and relay
//! fallback without any manual IP exchange. This crate adds the Hearth
//! layer on top:
//!
//! * length-prefixed [`chat_protocol::ProtocolEnvelope`] frames on
//!   bidirectional streams, with a delivery ack per envelope;
//! * a [`ConnectionState`] machine per peer (`Discovering → Negotiating →
//!   DirectConnected | RelayConnected → Offline`);
//! * exponential-backoff-with-jitter reconnect delays ([`backoff_delay`]);
//! * [`TransportDiagnostics`] snapshots for the settings screen;
//! * invite-compatible endpoint bundles ([`encode_bundle`]/[`decode_bundle`]).
//!
//! UI-facing connection labels stay non-technical: "Connected directly",
//! "Connected through relay", "Connecting", "Offline".

use anyhow::{Context, Result};
use base64::Engine;
use chat_protocol::ProtocolEnvelope;
use iroh::{
    Endpoint, SecretKey,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;
use uuid::Uuid;

pub use chat_protocol::HEARTH_ALPN;
pub use iroh::{EndpointAddr, EndpointId, TransportAddr};

/// Max envelope bytes accepted on a stream (envelopes carry chat ciphertext;
/// file chunks travel on dedicated streams in the files layer).
pub const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Discovering,
    Negotiating,
    DirectConnected,
    RelayConnected,
    Offline,
}

impl ConnectionState {
    /// User-facing label. No NAT jargon.
    pub fn label(self) -> &'static str {
        match self {
            ConnectionState::Discovering | ConnectionState::Negotiating => "Connecting",
            ConnectionState::DirectConnected => "Connected directly",
            ConnectionState::RelayConnected => "Connected through relay",
            ConnectionState::Offline => "Offline",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportDiagnostics {
    pub peer_endpoint_id: String,
    pub state: ConnectionState,
    pub detail: String,
    pub reconnect_count: u32,
    pub last_error: Option<String>,
}

/// Delivery acknowledgement returned on the same stream as the envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamAck {
    pub message_id: Uuid,
    pub received_at_ms: i64,
}

/// An envelope that arrived from a peer, ready for the app layer.
#[derive(Debug, Clone)]
pub struct InboundEnvelope {
    /// Authenticated network sender. `None` for store-and-forward (mailbox)
    /// envelopes, which are attributed by signature trial instead.
    pub from: Option<EndpointId>,
    pub envelope: ProtocolEnvelope,
    pub via_relay: bool,
}

#[derive(Debug, Clone)]
struct PeerState {
    state: ConnectionState,
    reconnect_count: u32,
    last_error: Option<String>,
}

impl Default for PeerState {
    fn default() -> Self {
        Self {
            state: ConnectionState::Offline,
            reconnect_count: 0,
            last_error: None,
        }
    }
}

/// Reconnect delay: `min(5min, 1s * 2^attempt)` plus up-to-25% jitter.
pub fn backoff_delay(attempt: u32) -> Duration {
    let base = 1u64.saturating_mul(1u64 << attempt.min(8));
    let capped = base.min(300);
    let jitter = (capped as f64 * 0.25 * pseudo_random_fraction()) as u64;
    Duration::from_secs(capped + jitter)
}

fn pseudo_random_fraction() -> f64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut hasher = DefaultHasher::new();
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    (hasher.finish() % 10_000) as f64 / 10_000.0
}

// ---------------------------------------------------------------------------
// Endpoint bundles (invite codes / directory records)
// ---------------------------------------------------------------------------

pub fn encode_bundle(addr: &EndpointAddr) -> Result<String> {
    let json = serde_json::to_vec(addr)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
}

pub fn decode_bundle(bundle: &str) -> Result<EndpointAddr> {
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(bundle.trim())
        .context("bad endpoint bundle")?;
    serde_json::from_slice(&json).context("bad endpoint address")
}

pub fn addr_with_socket(id: EndpointId, socket: SocketAddr) -> EndpointAddr {
    EndpointAddr {
        id,
        addrs: BTreeSet::from([iroh::TransportAddr::Ip(socket)]),
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ChatAcceptor {
    inbound_tx: mpsc::UnboundedSender<InboundEnvelope>,
}

impl ProtocolHandler for ChatAcceptor {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let from = connection.remote_id();
        loop {
            let (mut send, mut recv) = connection.accept_bi().await?;
            let envelope = read_envelope(&mut recv).await?;
            let via_relay = path_is_relay(&connection);
            // If the app is gone there is nobody to ack to; fail the stream
            // so the sender retries instead of believing it was delivered.
            self.inbound_tx
                .send(InboundEnvelope {
                    from: Some(from),
                    envelope: envelope.clone(),
                    via_relay,
                })
                .map_err(|_| {
                    AcceptError::from_err(std::io::Error::other("app inbound queue closed"))
                })?;
            let ack = StreamAck {
                message_id: envelope.message_id,
                received_at_ms: now_ms(),
            };
            write_json_frame(&mut send, &ack).await?;
            send.finish().map_err(AcceptError::from_err)?;
        }
    }
}

pub struct Transport {
    endpoint: Endpoint,
    _router: Router,
    peers: Arc<Mutex<HashMap<EndpointId, PeerState>>>,
    inbound_rx: std::sync::Mutex<Option<mpsc::UnboundedReceiver<InboundEnvelope>>>,
}

impl Transport {
    /// Bind an endpoint for `device_secret` (the device Ed25519 key, so the
    /// network identity equals the device identity). `relay_enabled=false`
    /// keeps everything on direct paths (tests, LAN-only installs).
    pub async fn bind(device_secret: &[u8; 32], relay_enabled: bool) -> Result<Self> {
        let secret = SecretKey::from_bytes(device_secret);
        let mut builder = Endpoint::builder(presets::N0).secret_key(secret);
        if !relay_enabled {
            builder = builder.relay_mode(iroh::RelayMode::Disabled);
        }
        let endpoint = builder.bind().await.context("bind iroh endpoint")?;
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let router = Router::builder(endpoint.clone())
            .accept(HEARTH_ALPN, ChatAcceptor { inbound_tx })
            .spawn();
        Ok(Self {
            endpoint,
            _router: router,
            peers: Arc::new(Mutex::new(HashMap::new())),
            inbound_rx: std::sync::Mutex::new(Some(inbound_rx)),
        })
    }

    /// Take the inbound receiver. Only one owner (the app event loop).
    pub fn take_inbound(&self) -> Option<mpsc::UnboundedReceiver<InboundEnvelope>> {
        self.inbound_rx.lock().ok()?.take()
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn local_addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    pub fn local_bundle(&self) -> Result<String> {
        encode_bundle(&self.local_addr())
    }

    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.endpoint.bound_sockets()
    }

    pub async fn wait_online(&self) {
        self.endpoint.online().await;
    }

    pub fn peer_state(&self, peer: &EndpointId) -> ConnectionState {
        self.peers
            .lock()
            .map(|p| {
                p.get(peer)
                    .map(|s| s.state)
                    .unwrap_or(ConnectionState::Offline)
            })
            .unwrap_or(ConnectionState::Offline)
    }

    pub fn diagnostics(&self) -> Vec<TransportDiagnostics> {
        self.peers
            .lock()
            .map(|peers| {
                peers
                    .iter()
                    .map(|(id, state)| TransportDiagnostics {
                        peer_endpoint_id: id.to_string(),
                        state: state.state,
                        detail: state.state.label().to_string(),
                        reconnect_count: state.reconnect_count,
                        last_error: state.last_error.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn set_peer(&self, peer: EndpointId, f: impl FnOnce(&mut PeerState)) {
        if let Ok(mut peers) = self.peers.lock() {
            f(peers.entry(peer).or_default());
        }
    }

    /// Send one envelope and wait for the stream ack. Updates peer state and
    /// returns fresh diagnostics for the peer.
    pub async fn send_envelope(
        &self,
        addr: &EndpointAddr,
        envelope: &ProtocolEnvelope,
    ) -> Result<TransportDiagnostics> {
        envelope.validate()?;
        self.set_peer(addr.id, |p| {
            p.state = ConnectionState::Negotiating;
            p.last_error = None;
        });
        let result = self.send_once(addr, envelope).await;
        match result {
            Ok(detail) => {
                let state = if detail.via_relay {
                    ConnectionState::RelayConnected
                } else {
                    ConnectionState::DirectConnected
                };
                self.set_peer(addr.id, |p| {
                    p.state = state;
                    p.last_error = None;
                });
                Ok(self.peer_diagnostics(addr.id, state, detail.note, None))
            }
            Err(e) => {
                let message = format!("{e:#}");
                self.set_peer(addr.id, |p| {
                    p.state = ConnectionState::Offline;
                    p.reconnect_count += 1;
                    p.last_error = Some(message.clone());
                });
                Err(anyhow::anyhow!("send to {} failed: {message}", addr.id))
            }
        }
    }

    async fn send_once(
        &self,
        addr: &EndpointAddr,
        envelope: &ProtocolEnvelope,
    ) -> Result<SendDetail> {
        let connection = tokio::time::timeout(
            Duration::from_secs(20),
            self.endpoint.connect(addr.clone(), HEARTH_ALPN),
        )
        .await
        .context("connect timed out")?
        .context("connect failed")?;
        let via_relay = path_is_relay(&connection);
        let (mut send, mut recv) =
            tokio::time::timeout(Duration::from_secs(10), connection.open_bi())
                .await
                .context("open stream timed out")?
                .context("open stream failed")?;
        let frame = envelope.encode_frame()?;
        tokio::time::timeout(Duration::from_secs(30), send.write_all(&frame))
            .await
            .context("write timed out")?
            .context("write failed")?;
        send.finish().context("finish stream")?;
        let ack_bytes = tokio::time::timeout(
            Duration::from_secs(30),
            recv.read_to_end(MAX_ENVELOPE_BYTES),
        )
        .await
        .context("ack timed out")?
        .context("read ack failed")?;
        let ack: StreamAck = decode_json_frame(&ack_bytes)?;
        if ack.message_id != envelope.message_id {
            anyhow::bail!("ack referenced wrong message");
        }
        let note = if via_relay {
            "relayed path".to_string()
        } else {
            "direct path".to_string()
        };
        Ok(SendDetail { via_relay, note })
    }

    fn peer_diagnostics(
        &self,
        peer: EndpointId,
        state: ConnectionState,
        detail: String,
        last_error: Option<String>,
    ) -> TransportDiagnostics {
        let reconnect_count = self
            .peers
            .lock()
            .map(|p| p.get(&peer).map(|s| s.reconnect_count).unwrap_or(0))
            .unwrap_or(0);
        TransportDiagnostics {
            peer_endpoint_id: peer.to_string(),
            state,
            detail,
            reconnect_count,
            last_error,
        }
    }
}

struct SendDetail {
    via_relay: bool,
    note: String,
}

fn path_is_relay(connection: &Connection) -> bool {
    // The selected path decides; if no path is selected yet, assume relay so
    // the UI never overclaims "direct".
    let mut saw_any = false;
    for path in connection.paths().iter() {
        saw_any = true;
        if path.is_selected() {
            return path.is_relay();
        }
    }
    let _ = saw_any;
    true
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

async fn read_envelope(
    recv: &mut iroh::endpoint::RecvStream,
) -> Result<ProtocolEnvelope, AcceptError> {
    let mut prefix = [0u8; 4];
    recv.read_exact(&mut prefix)
        .await
        .map_err(AcceptError::from_err)?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > MAX_ENVELOPE_BYTES {
        return Err(AcceptError::from_err(std::io::Error::other(format!(
            "bad frame length {len}"
        ))));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .map_err(AcceptError::from_err)?;
    ProtocolEnvelope::decode_frame(prefix, &body)
        .map_err(|e| AcceptError::from_err(std::io::Error::other(format!("{e:#}"))))
}

async fn write_json_frame<T: Serialize>(
    send: &mut iroh::endpoint::SendStream,
    value: &T,
) -> Result<(), AcceptError> {
    let body = serde_json::to_vec(value)
        .map_err(|e| AcceptError::from_err(std::io::Error::other(format!("{e:#}"))))?;
    send.write_all(&(body.len() as u32).to_be_bytes())
        .await
        .map_err(|e| AcceptError::from_err(std::io::Error::other(format!("stream write: {e}"))))?;
    send.write_all(&body)
        .await
        .map_err(|e| AcceptError::from_err(std::io::Error::other(format!("stream write: {e}"))))?;
    Ok(())
}

fn decode_json_frame<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    if bytes.len() < 4 {
        anyhow::bail!("ack frame too short");
    }
    let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if len != bytes.len() - 4 {
        anyhow::bail!("ack length mismatch");
    }
    serde_json::from_slice(&bytes[4..]).context("bad ack payload")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat_protocol::MessageType;

    #[test]
    fn backoff_grows_and_caps() {
        assert!(backoff_delay(0) >= Duration::from_secs(1));
        assert!(backoff_delay(0) < Duration::from_secs(2));
        assert!(backoff_delay(10) <= Duration::from_secs(375));
        assert!(backoff_delay(100) <= Duration::from_secs(375));
        assert!(backoff_delay(3) >= Duration::from_secs(8));
    }

    #[test]
    fn bundle_roundtrip() {
        let secret = SecretKey::generate();
        let addr = EndpointAddr {
            id: secret.public(),
            addrs: BTreeSet::new(),
        };
        let bundle = encode_bundle(&addr).unwrap();
        let decoded = decode_bundle(&bundle).unwrap();
        assert_eq!(decoded, addr);
        assert!(decode_bundle("!!!not-a-bundle!!!").is_err());
    }

    #[test]
    fn state_labels_stay_non_technical() {
        assert_eq!(
            ConnectionState::DirectConnected.label(),
            "Connected directly"
        );
        assert_eq!(
            ConnectionState::RelayConnected.label(),
            "Connected through relay"
        );
        assert_eq!(ConnectionState::Negotiating.label(), "Connecting");
        assert_eq!(ConnectionState::Offline.label(), "Offline");
    }

    #[tokio::test]
    async fn loopback_envelope_delivery_with_ack() {
        let secret_a = chat_crypto_for_test::random_32();
        let secret_b = chat_crypto_for_test::random_32();
        let a = Transport::bind(&secret_a, false).await.expect("bind a");
        let b = Transport::bind(&secret_b, false).await.expect("bind b");
        let mut inbound_b = b.take_inbound().expect("inbound b");

        // Direct localhost dial: learn B's bound UDP socket instead of
        // waiting on relay/lookup infrastructure.
        let socket = pick_loopback(b.bound_sockets()).expect("b bound socket");
        let addr_b = addr_with_socket(b.endpoint_id(), socket);

        let envelope = ProtocolEnvelope {
            version: chat_protocol::CURRENT_PROTOCOL_VERSION,
            message_id: Uuid::new_v4(),
            conversation_id: Uuid::new_v4(),
            sender_device_id: Uuid::new_v4(),
            message_type: MessageType::Ping,
            sequence: 1,
            created_at_ms: 1,
            ciphertext: vec![1, 2, 3],
            sender_sig: vec![],
        };
        let diagnostics =
            tokio::time::timeout(Duration::from_secs(30), a.send_envelope(&addr_b, &envelope))
                .await
                .expect("send timeout")
                .expect("send failed");
        assert_eq!(diagnostics.state, ConnectionState::DirectConnected);

        let received = tokio::time::timeout(Duration::from_secs(10), inbound_b.recv())
            .await
            .expect("receive timeout")
            .expect("inbound closed");
        assert_eq!(received.envelope, envelope);
        assert_eq!(received.from, Some(a.endpoint_id()));
    }

    fn pick_loopback(sockets: Vec<SocketAddr>) -> Option<SocketAddr> {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        sockets
            .into_iter()
            .map(|s| match s.ip() {
                IpAddr::V4(v4) if v4.is_unspecified() => {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), s.port())
                }
                IpAddr::V6(v6) if v6.is_unspecified() => {
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), s.port())
                }
                ip => SocketAddr::new(ip, s.port()),
            })
            .find(|s| s.ip().is_loopback())
    }

    // Test-only keys come from the real OS RNG via chat-crypto.
    mod chat_crypto_for_test {
        pub fn random_32() -> [u8; 32] {
            chat_crypto::random_32()
        }
    }
}
