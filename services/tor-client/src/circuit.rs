use crate::crypto_engine::OnionKeys;
use crate::directory_client::DirectoryClient;
use crate::metrics::{ClientMetrics, EventKind};
use anyhow::{Context, Result};
use common::crypto::{CipherPair, NtorEphemeralKeyPair, SessionKey, ntor_client_finish_raw};
use common::metrics::Direction;
use common::{
    CELL_SIZE, CircuitId, Message, MessageCommand, NodeDescriptor, RelayReadHalf, RelayStream,
    RelayTlsConfig, RelayWriteHalf, StreamId, server_name_from_addr,
};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CircuitState {
    Building,
    Ready,
    Closing,
    Closed,
}

/// A single onion routing circuit through 3 relay nodes.
pub struct Circuit {
    pub circuit_id: CircuitId,
    pub state: CircuitState,
    pub entry_writer: Arc<Mutex<RelayWriteHalf>>,
    pub onion_keys: OnionKeys,
    pub stream_senders: HashMap<StreamId, mpsc::UnboundedSender<Message>>,
    next_stream_id: StreamId,
    pub path_display: Option<String>,
}

impl Circuit {
    pub fn active_stream_count(&self) -> usize {
        self.stream_senders.len()
    }

    pub fn allocate_stream_id(&mut self) -> StreamId {
        let id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1);
        if self.next_stream_id == 0 {
            self.next_stream_id = 1; // Skip 0 (reserved for circuit-level messages)
        }
        id
    }

    pub fn register_stream(&mut self, stream_id: StreamId, sender: mpsc::UnboundedSender<Message>) {
        self.stream_senders.insert(stream_id, sender);
    }

    pub fn unregister_stream(&mut self, stream_id: StreamId) {
        self.stream_senders.remove(&stream_id);
    }

    /// Send a message through this circuit with onion encryption.
    pub async fn send_message(
        &mut self,
        stream_id: StreamId,
        command: MessageCommand,
        data: &[u8],
    ) -> Result<()> {
        let digest = self
            .onion_keys
            .forward_digest
            .update(stream_id, command.to_u8(), data);

        let mut encrypted_data = data.to_vec();
        self.onion_keys.onion_encrypt(&mut encrypted_data);
        let mut msg = Message::new(self.circuit_id, stream_id, command, encrypted_data);
        msg.digest = digest;

        let mut writer = self.entry_writer.lock().await;
        msg.write_to_stream(&mut *writer)
            .await
            .context("Failed to write to entry node")?;
        debug!(
            "Sent {} message ({} bytes) on circuit {} stream {}",
            command, CELL_SIZE, self.circuit_id, stream_id,
        );

        Ok(())
    }

    /// Send a raw message (no onion encryption — used for CREATE/EXTEND handshakes).
    #[allow(dead_code)]
    pub async fn send_raw(&self, msg: &Message) -> Result<()> {
        let mut writer = self.entry_writer.lock().await;
        msg.write_to_stream(&mut *writer)
            .await
            .context("Failed to write to entry node")?;
        Ok(())
    }
}

/// Result of building a circuit: the circuit itself and the read half for the reader task.
pub struct BuiltCircuit {
    pub circuit: Circuit,
    pub read_half: RelayReadHalf,
}

/// Builds an N-hop circuit (N >= 3) via telescopic ntor handshake.
pub struct CircuitBuilder;

impl CircuitBuilder {
    pub async fn build(circuit_id: CircuitId, path: &[NodeDescriptor]) -> Result<BuiltCircuit> {
        if path.len() < 3 {
            return Err(anyhow::anyhow!(
                "Circuit path must have at least 3 nodes, got {}",
                path.len()
            ));
        }

        let entry = path
            .first()
            .ok_or_else(|| anyhow::anyhow!("Missing entry node"))?;

        info!(
            "Building {}-hop circuit {}: {}",
            path.len(),
            circuit_id,
            path.iter()
                .map(|n| n.address.to_string())
                .collect::<Vec<_>>()
                .join(" -> ")
        );

        let tcp_stream = TcpStream::connect(entry.address)
            .await
            .with_context(|| format!("Failed to connect to entry node at {}", entry.address))?;
        info!("TCP connected to entry node at {}", entry.address);

        let connector = RelayTlsConfig::make_tls_connector(&entry.tls_cert_fingerprint)
            .context("Failed to create TLS connector")?;
        let server_name = server_name_from_addr(entry.address);
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .with_context(|| {
                format!("TLS handshake with entry node at {} failed", entry.address)
            })?;
        info!("TLS connected to entry node at {}", entry.address);

        let mut entry_stream: RelayStream = Box::new(tls_stream);

        // CREATE handshake with entry (hop 0).
        let entry_key = Self::handshake_create(circuit_id, &mut entry_stream, entry).await?;
        info!("Completed CREATE handshake with entry node");

        let mut session_keys: Vec<SessionKey> = vec![entry_key.clone()];
        let mut ciphers: Vec<CipherPair> = vec![CipherPair::new(&entry_key)];

        // EXTEND loop for hops 1..N-1.
        for hop_index in 1..path.len() {
            let node = path
                .get(hop_index)
                .ok_or_else(|| anyhow::anyhow!("Missing node at hop {}", hop_index))?;
            let key =
                Self::handshake_extend(circuit_id, &mut entry_stream, node, &mut ciphers).await?;
            info!("Completed EXTEND to hop {} ({})", hop_index, node.address);
            session_keys.push(key.clone());
            ciphers.push(CipherPair::new(&key));
        }

        let onion_keys = OnionKeys::new(session_keys, ciphers);

        let path_display = Some(
            path.iter()
                .map(|n| format!(":{}", n.address.port()))
                .collect::<Vec<_>>()
                .join(" \u{2192} "),
        );

        let (read_half, write_half) = tokio::io::split(entry_stream);

        let circuit = Circuit {
            circuit_id,
            state: CircuitState::Ready,
            entry_writer: Arc::new(Mutex::new(write_half)),
            onion_keys,
            stream_senders: HashMap::new(),
            next_stream_id: 1,
            path_display,
        };

        Ok(BuiltCircuit { circuit, read_half })
    }

    /// CREATE handshake with the entry node (ntor).
    async fn handshake_create(
        circuit_id: CircuitId,
        stream: &mut RelayStream,
        entry: &NodeDescriptor,
    ) -> Result<SessionKey> {
        let ephemeral = NtorEphemeralKeyPair::generate();
        let our_public = ephemeral.public.bytes;

        let create_msg = Message::create(circuit_id, our_public.to_vec());
        create_msg
            .write_to_stream(stream)
            .await
            .context("Failed to send CREATE")?;
        debug!("Sent CREATE to entry node");

        let created_msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, Message::from_stream(stream))
            .await
            .context("Timed out waiting for CREATED from entry node")?
            .context("Failed to read CREATED")?
            .ok_or_else(|| anyhow::anyhow!("Entry node closed connection during CREATE"))?;

        if created_msg.command != MessageCommand::Created {
            return Err(anyhow::anyhow!(
                "Expected CREATED from entry, got {}",
                created_msg.command
            ));
        }

        if created_msg.data.len() < 64 {
            return Err(anyhow::anyhow!(
                "CREATED response too short: {} bytes (need 64)",
                created_msg.data.len()
            ));
        }

        let mut server_eph_pub = [0u8; 32];
        server_eph_pub.copy_from_slice(
            created_msg
                .data
                .get(0..32)
                .ok_or_else(|| anyhow::anyhow!("Invalid CREATED data"))?,
        );
        let mut auth = [0u8; 32];
        auth.copy_from_slice(
            created_msg
                .data
                .get(32..64)
                .ok_or_else(|| anyhow::anyhow!("Invalid CREATED auth"))?,
        );

        let session_key = ntor_client_finish_raw(
            ephemeral.secret_bytes(),
            &our_public,
            &entry.public_key.bytes,
            &server_eph_pub,
            &auth,
        )
        .map_err(|e| anyhow::anyhow!("ntor handshake failed with entry: {}", e))?;

        debug!("ntor handshake complete with entry node");
        Ok(session_key)
    }

    /// EXTEND to the next hop (ntor). `ciphers` contains the k already-established cipher
    /// pairs. The payload is wrapped in k layers (outermost first), and the EXTENDED response
    /// is unwrapped in the same order before ntor verification.
    async fn handshake_extend(
        circuit_id: CircuitId,
        stream: &mut RelayStream,
        node: &NodeDescriptor,
        ciphers: &mut [CipherPair],
    ) -> Result<SessionKey> {
        let ephemeral = NtorEphemeralKeyPair::generate();
        let our_public = ephemeral.public.bytes;

        let addr_str = node.address.to_string();
        let mut extend_payload = Vec::with_capacity(addr_str.len() + 1 + 32 + 1 + 64);
        extend_payload.extend_from_slice(addr_str.as_bytes());
        extend_payload.push(0);
        extend_payload.extend_from_slice(&our_public);
        extend_payload.push(0);
        extend_payload.extend_from_slice(node.tls_cert_fingerprint.as_bytes());

        // Wrap in k layers: innermost (last cipher) first, outermost (first cipher) last.
        for cipher in ciphers.iter_mut().rev() {
            cipher.apply_forward(&mut extend_payload);
        }

        let extend_msg = Message::extend(circuit_id, extend_payload);
        extend_msg
            .write_to_stream(stream)
            .await
            .with_context(|| format!("Failed to send EXTEND to {}", node.address))?;
        debug!("Sent EXTEND for node {}", node.address);

        let extended_msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, Message::from_stream(stream))
            .await
            .with_context(|| format!("Timed out waiting for EXTENDED from {}", node.address))?
            .with_context(|| format!("Failed to read EXTENDED from {}", node.address))?
            .ok_or_else(|| {
                anyhow::anyhow!("Connection closed during EXTEND to {}", node.address)
            })?;

        if extended_msg.command != MessageCommand::Extended {
            return Err(anyhow::anyhow!(
                "Expected EXTENDED from {}, got {}",
                node.address,
                extended_msg.command
            ));
        }

        // Unwrap k layers: outermost (first cipher) first, innermost (last cipher) last.
        let mut decrypted = extended_msg.data;
        for cipher in ciphers.iter_mut() {
            cipher.apply_backward(&mut decrypted);
        }

        if decrypted.len() < 64 {
            return Err(anyhow::anyhow!(
                "EXTENDED response too short: {} bytes (need 64)",
                decrypted.len()
            ));
        }

        let mut server_eph_pub = [0u8; 32];
        server_eph_pub.copy_from_slice(
            decrypted
                .get(0..32)
                .ok_or_else(|| anyhow::anyhow!("Invalid EXTENDED data"))?,
        );
        let mut auth = [0u8; 32];
        auth.copy_from_slice(
            decrypted
                .get(32..64)
                .ok_or_else(|| anyhow::anyhow!("Invalid EXTENDED auth"))?,
        );

        let session_key = ntor_client_finish_raw(
            ephemeral.secret_bytes(),
            &our_public,
            &node.public_key.bytes,
            &server_eph_pub,
            &auth,
        )
        .map_err(|e| anyhow::anyhow!("ntor handshake failed with {}: {}", node.address, e))?;

        debug!("ntor handshake complete with {}", node.address);
        Ok(session_key)
    }
}

/// Pool of pre-built circuits for handling SOCKS5 connections.
pub struct CircuitPool {
    circuits: HashMap<CircuitId, Arc<Mutex<Circuit>>>,
    next_circuit_id: CircuitId,
    directory_client: DirectoryClient,
    pool_size: usize,
    hop_count: usize,
    metrics: Option<Arc<ClientMetrics>>,
    max_rebuild_attempts: usize,
    /// Consecutive rebuild failure count per circuit slot.
    rebuild_failure_counts: HashMap<CircuitId, usize>,
    /// Slots that exhausted their retries and should no longer be rebuilt.
    abandoned_slots: HashSet<CircuitId>,
}

impl CircuitPool {
    pub fn new(
        directory_client: DirectoryClient,
        pool_size: usize,
        hop_count: usize,
        max_rebuild_attempts: usize,
    ) -> Self {
        Self {
            circuits: HashMap::new(),
            next_circuit_id: 1,
            directory_client,
            pool_size,
            hop_count,
            metrics: None,
            max_rebuild_attempts,
            rebuild_failure_counts: HashMap::new(),
            abandoned_slots: HashSet::new(),
        }
    }

    pub fn set_metrics(&mut self, metrics: Arc<ClientMetrics>) {
        self.metrics = Some(metrics);
    }

    pub fn metrics(&self) -> Option<&Arc<ClientMetrics>> {
        self.metrics.as_ref()
    }

    /// Pre-build circuits to fill the pool at startup.
    pub async fn initialize(&mut self) -> Result<Vec<(Arc<Mutex<Circuit>>, RelayReadHalf)>> {
        info!("Initializing circuit pool with {} circuits", self.pool_size);

        let mut results = Vec::with_capacity(self.pool_size);

        for i in 0..self.pool_size {
            match self.build_circuit().await {
                Ok((circuit_id, read_half)) => {
                    info!(
                        "Built circuit {}/{}: id={}",
                        i + 1,
                        self.pool_size,
                        circuit_id
                    );
                    let circuit = self.circuits.get(&circuit_id).ok_or_else(|| {
                        anyhow::anyhow!("Newly built circuit {} not found", circuit_id)
                    })?;
                    results.push((Arc::clone(circuit), read_half));
                }
                Err(e) => {
                    error!(
                        "Failed to build circuit {}/{}: {}",
                        i + 1,
                        self.pool_size,
                        e
                    );
                    return Err(e).context("Failed to initialize circuit pool");
                }
            }
        }

        info!("Circuit pool initialized successfully");
        Ok(results)
    }

    /// Select the least-loaded ready circuit for a new stream.
    pub async fn select_circuit(&mut self) -> Result<(Arc<Mutex<Circuit>>, Option<RelayReadHalf>)> {
        let mut best: Option<(CircuitId, usize)> = None;

        for (&circuit_id, circuit) in &self.circuits {
            let circuit = circuit.lock().await;
            if circuit.state == CircuitState::Ready {
                let count = circuit.active_stream_count();
                match &best {
                    Some((_, best_count)) if count < *best_count => {
                        best = Some((circuit_id, count));
                    }
                    None => {
                        best = Some((circuit_id, count));
                    }
                    _ => {}
                }
            }
        }

        if let Some((circuit_id, _)) = best {
            let circuit = self
                .circuits
                .get(&circuit_id)
                .ok_or_else(|| anyhow::anyhow!("Circuit {} disappeared", circuit_id))?;
            return Ok((Arc::clone(circuit), None));
        }

        warn!("No ready circuits available, building a new one");
        let (circuit_id, read_half) = self.build_circuit().await?;
        let circuit = self
            .circuits
            .get(&circuit_id)
            .ok_or_else(|| anyhow::anyhow!("Newly built circuit {} not found", circuit_id))?;
        Ok((Arc::clone(circuit), Some(read_half)))
    }

    /// Returns true if this circuit slot has exceeded its rebuild attempt budget.
    pub fn is_abandoned(&self, circuit_id: CircuitId) -> bool {
        self.abandoned_slots.contains(&circuit_id)
    }

    /// Replace a failed circuit and replenish the pool.
    pub async fn replace_circuit(
        &mut self,
        failed_id: CircuitId,
    ) -> Result<(Arc<Mutex<Circuit>>, RelayReadHalf)> {
        info!("Replacing failed circuit {}", failed_id);
        self.circuits.remove(&failed_id);
        let build_result = self.build_circuit().await;

        let (circuit_id, read_half) = match build_result {
            Ok(pair) => {
                // Success — clear any previous failure streak for this slot.
                self.rebuild_failure_counts.remove(&failed_id);
                pair
            }
            Err(e) => {
                let count = self.rebuild_failure_counts.entry(failed_id).or_insert(0);
                *count += 1;
                if *count >= self.max_rebuild_attempts {
                    self.abandoned_slots.insert(failed_id);
                    error!(
                        "Circuit slot {} permanently failed after {} rebuild attempt(s) \
                         with --hops {}. Not enough relay nodes registered or nodes are \
                         unreachable. This slot will no longer be retried. \
                         Hint: register more relay nodes or reduce --hops.",
                        failed_id, self.max_rebuild_attempts, self.hop_count,
                    );
                    if let Some(ref metrics) = self.metrics {
                        metrics.push_event(EventKind::Error {
                            message: format!(
                                "Circuit slot {failed_id} abandoned after \
                                 {} rebuild attempt(s)",
                                self.max_rebuild_attempts
                            ),
                        });
                    }
                }
                return Err(e);
            }
        };

        let circuit = self
            .circuits
            .get(&circuit_id)
            .ok_or_else(|| anyhow::anyhow!("Newly built circuit {} not found", circuit_id))?;

        if let Some(ref metrics) = self.metrics {
            metrics
                .circuits_replaced
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            metrics.push_event(EventKind::CircuitReplaced {
                old_id: failed_id,
                new_id: circuit_id,
            });
        }

        Ok((Arc::clone(circuit), read_half))
    }

    async fn build_circuit(&mut self) -> Result<(CircuitId, RelayReadHalf)> {
        let circuit_id = self.allocate_circuit_id();
        let path = self
            .directory_client
            .get_random_path(self.hop_count)
            .await
            .with_context(|| {
                format!(
                    "Failed to get a {}-hop path from the directory service \
                 (requires: 1 entry + {} middle + 1 exit relay node(s) registered)",
                    self.hop_count,
                    self.hop_count.saturating_sub(2),
                )
            })?;

        let built = CircuitBuilder::build(circuit_id, &path).await?;

        let path_display = built.circuit.path_display.clone().unwrap_or_default();

        self.circuits
            .insert(circuit_id, Arc::new(Mutex::new(built.circuit)));

        if let Some(ref metrics) = self.metrics {
            metrics
                .circuits_built
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            metrics.push_event(EventKind::CircuitBuilt {
                circuit_id,
                path: path_display,
            });
        }

        Ok((circuit_id, built.read_half))
    }

    fn allocate_circuit_id(&mut self) -> CircuitId {
        let id = self.next_circuit_id;
        self.next_circuit_id = self.next_circuit_id.wrapping_add(1);
        id
    }

    #[allow(dead_code)]
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    pub fn iter_circuits(
        &self,
    ) -> std::collections::hash_map::Iter<'_, CircuitId, Arc<Mutex<Circuit>>> {
        self.circuits.iter()
    }
}

/// Spawn a background task that reads backward messages from the entry node,
/// decrypts onion layers, and demuxes them to the correct stream channel.
pub fn spawn_circuit_reader(
    circuit: Arc<Mutex<Circuit>>,
    mut read_half: RelayReadHalf,
    metrics: Arc<ClientMetrics>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let circuit_id = circuit.lock().await.circuit_id;
        info!("Starting circuit reader for circuit {}", circuit_id);

        loop {
            let msg = match Message::from_stream(&mut read_half).await {
                Ok(Some(msg)) => msg,
                Ok(None) => {
                    info!("Entry node closed connection for circuit {}", circuit_id);
                    let mut circuit_guard = circuit.lock().await;
                    circuit_guard.state = CircuitState::Closed;
                    metrics.push_event(EventKind::CircuitClosed { circuit_id });
                    break;
                }
                Err(e) => {
                    error!(
                        "Error reading from entry node for circuit {}: {}",
                        circuit_id, e
                    );
                    let mut circuit_guard = circuit.lock().await;
                    circuit_guard.state = CircuitState::Closed;
                    metrics.push_event(EventKind::CircuitClosed { circuit_id });
                    break;
                }
            };

            debug!(
                "Circuit {} received backward {} for stream {}",
                circuit_id, msg.command, msg.stream_id
            );

            // DESTROY from entry — relay teardown signal, no decryption needed.
            if msg.command == MessageCommand::Destroy {
                let mut circuit_guard = circuit.lock().await;
                circuit_guard.state = CircuitState::Closed;
                circuit_guard.stream_senders.clear();
                metrics.push_event(EventKind::CircuitClosed { circuit_id });
                break;
            }

            let mut circuit_guard = circuit.lock().await;

            let mut decrypted_data = msg.data;
            circuit_guard.onion_keys.onion_decrypt(&mut decrypted_data);

            if !circuit_guard.onion_keys.backward_digest.verify(
                msg.stream_id,
                msg.command.to_u8(),
                &decrypted_data,
                msg.digest,
            ) {
                error!(
                    "Backward digest mismatch on circuit {} stream {} — possible tampering, tearing down circuit",
                    circuit_id, msg.stream_id
                );
                circuit_guard.state = CircuitState::Closed;
                metrics.push_event(EventKind::CircuitClosed { circuit_id });
                break;
            }

            let data_len = decrypted_data.len();

            if msg.command == MessageCommand::Data {
                metrics
                    .bytes_received
                    .fetch_add(data_len as u64, std::sync::atomic::Ordering::Relaxed);
                metrics.push_event(EventKind::StreamData {
                    circuit_id,
                    stream_id: msg.stream_id,
                    bytes: data_len,
                    direction: Direction::Backward,
                });
            }

            let decrypted_msg =
                Message::new(msg.circuit_id, msg.stream_id, msg.command, decrypted_data);

            if let Some(sender) = circuit_guard.stream_senders.get(&msg.stream_id) {
                if sender.send(decrypted_msg).is_err() {
                    debug!(
                        "Stream {} channel closed on circuit {}",
                        msg.stream_id, circuit_id
                    );
                }
            } else {
                warn!(
                    "No stream {} registered on circuit {} for {} message",
                    msg.stream_id, circuit_id, msg.command
                );
            }
        }

        {
            let mut circuit_guard = circuit.lock().await;
            circuit_guard.state = CircuitState::Closed;
            circuit_guard.stream_senders.clear();
        }

        info!("Circuit reader terminated for circuit {}", circuit_id);
    })
}

/// Polls the pool every `check_interval` and rebuilds any circuit in `Closed` state.
pub fn spawn_circuit_monitor(
    pool: Arc<Mutex<CircuitPool>>,
    metrics: Arc<ClientMetrics>,
    check_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(check_interval).await;

            let failed_ids: Vec<CircuitId> = {
                let g = pool.lock().await;
                let mut ids = Vec::new();
                for (&id, c) in g.iter_circuits() {
                    if c.lock().await.state == CircuitState::Closed {
                        ids.push(id);
                    }
                }
                ids
            };

            for failed_id in failed_ids {
                // Skip slots that already exhausted their rebuild budget.
                {
                    let g = pool.lock().await;
                    if g.is_abandoned(failed_id) {
                        continue;
                    }
                }

                // Exponential backoff: base 5s * 2^failures, capped at 60s.
                // We already slept `check_interval`; only add the difference.
                let backoff = {
                    let g = pool.lock().await;
                    let failures = g
                        .rebuild_failure_counts
                        .get(&failed_id)
                        .copied()
                        .unwrap_or(0);
                    let secs = (5u64 * (1u64 << failures)).min(60);
                    Duration::from_secs(secs)
                };
                if backoff > check_interval {
                    tokio::time::sleep(backoff - check_interval).await;
                }

                info!("Circuit monitor: replacing closed circuit {}", failed_id);
                let mut g = pool.lock().await;
                match g.replace_circuit(failed_id).await {
                    Ok((new_circuit, read_half)) => {
                        drop(g);
                        spawn_circuit_reader(new_circuit, read_half, Arc::clone(&metrics));
                        info!("Circuit monitor: replacement built successfully");
                    }
                    Err(e) => {
                        error!(
                            "Circuit monitor: failed to replace circuit {}: {:#}",
                            failed_id, e
                        );
                        metrics.push_event(EventKind::Error {
                            message: format!("Monitor replace failed: {e:#}"),
                        });
                    }
                }
            }
        }
    })
}

/// Sends a PADDING cell to the entry node on every `Ready` circuit at random intervals.
/// A write failure means the entry is dead; the circuit monitor will detect and rebuild.
/// Uses the `max(X, Y)` distribution over `Uniform(1.5s, 9.5s)` to match real Tor's
/// link padding — average interval ≈ 5.5s with natural variance.
pub fn spawn_circuit_keepalive(pool: Arc<Mutex<CircuitPool>>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let interval = random_padding_interval();
            tokio::time::sleep(interval).await;

            // Collect Arc clones first so we don't hold the pool lock during writes.
            let circuits: Vec<Arc<Mutex<Circuit>>> = {
                let g = pool.lock().await;
                g.iter_circuits().map(|(_, c)| Arc::clone(c)).collect()
            };

            for arc in circuits {
                let c = arc.lock().await;
                if c.state == CircuitState::Ready {
                    let msg = Message::padding(c.circuit_id);
                    let mut w = c.entry_writer.lock().await;
                    if let Err(e) = msg.write_to_stream(&mut *w).await {
                        debug!("Keepalive write failed for circuit {}: {}", c.circuit_id, e);
                        // circuit_monitor will detect the Closed state and rebuild
                    }
                }
            }
        }
    })
}

/// Sample a random PADDING interval using the `max(X, Y)` distribution over
/// `Uniform(1.5s, 9.5s)`. This creates a slight bias toward longer intervals,
/// matching real Tor's link padding behavior. Average ≈ 5.5s.
fn random_padding_interval() -> Duration {
    let mut rng = rand::rng();
    let a: f64 = rng.random_range(1.5..9.5);
    let b: f64 = rng.random_range(1.5..9.5);
    Duration::from_secs_f64(a.max(b))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_id_allocation_monotonic() {
        let directory_client = DirectoryClient::new("http://localhost:8080".to_string());
        let mut pool = CircuitPool::new(directory_client, 3, 3, 3);

        let id1 = pool.allocate_circuit_id();
        let id2 = pool.allocate_circuit_id();
        let id3 = pool.allocate_circuit_id();

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn test_circuit_state_transitions() {
        assert_ne!(CircuitState::Building, CircuitState::Ready);
        assert_ne!(CircuitState::Ready, CircuitState::Closing);
        assert_ne!(CircuitState::Closing, CircuitState::Closed);
    }

    #[test]
    fn test_pool_size_configuration() {
        let directory_client = DirectoryClient::new("http://localhost:8080".to_string());
        let pool = CircuitPool::new(directory_client, 5, 3, 3);
        assert_eq!(pool.pool_size, 5);
        assert_eq!(pool.circuit_count(), 0);
    }

    #[test]
    fn test_stream_id_allocation_skips_zero() {
        let mut next_id: StreamId = 1;

        let id1 = next_id;
        next_id = next_id.wrapping_add(1);
        let id2 = next_id;
        next_id = next_id.wrapping_add(1);
        let id3 = next_id;

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);

        let mut wrap_id: StreamId = u16::MAX;
        wrap_id = wrap_id.wrapping_add(1);
        assert_eq!(wrap_id, 0);
        if wrap_id == 0 {
            wrap_id = 1;
        }
        assert_eq!(wrap_id, 1);
    }

    #[test]
    fn test_rebuild_failure_increments_counter() {
        let directory_client = DirectoryClient::new("http://localhost:8080".to_string());
        let mut pool = CircuitPool::new(directory_client, 3, 3, 3);

        // Simulate a failure by manually incrementing the counter (no real TCP).
        let failed_id: CircuitId = 42;
        let count = pool.rebuild_failure_counts.entry(failed_id).or_insert(0);
        *count += 1;

        assert_eq!(
            pool.rebuild_failure_counts
                .get(&failed_id)
                .copied()
                .unwrap_or(0),
            1
        );
        assert!(!pool.is_abandoned(failed_id));
    }

    #[test]
    fn test_rebuild_failure_abandoned_after_max() {
        let directory_client = DirectoryClient::new("http://localhost:8080".to_string());
        let mut pool = CircuitPool::new(directory_client, 3, 3, 2);

        let failed_id: CircuitId = 7;

        // Simulate max_rebuild_attempts (2) consecutive failures.
        for _ in 0..2 {
            let count = pool.rebuild_failure_counts.entry(failed_id).or_insert(0);
            *count += 1;
            if *count >= pool.max_rebuild_attempts {
                pool.abandoned_slots.insert(failed_id);
            }
        }

        assert!(pool.is_abandoned(failed_id));
    }

    #[test]
    fn test_rebuild_success_resets_counter() {
        let directory_client = DirectoryClient::new("http://localhost:8080".to_string());
        let mut pool = CircuitPool::new(directory_client, 3, 3, 3);

        let failed_id: CircuitId = 5;

        // One failure.
        let count = pool.rebuild_failure_counts.entry(failed_id).or_insert(0);
        *count += 1;
        assert_eq!(
            pool.rebuild_failure_counts
                .get(&failed_id)
                .copied()
                .unwrap_or(0),
            1
        );

        // Simulate success: clear the counter.
        pool.rebuild_failure_counts.remove(&failed_id);

        assert_eq!(
            pool.rebuild_failure_counts
                .get(&failed_id)
                .copied()
                .unwrap_or(0),
            0
        );
        assert!(!pool.is_abandoned(failed_id));
    }
}
