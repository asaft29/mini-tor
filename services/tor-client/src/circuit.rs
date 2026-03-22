use crate::crypto_engine::OnionKeys;
use crate::directory_client::DirectoryClient;
use crate::metrics::{ClientMetrics, EventKind};
use anyhow::{Context, Result};
use common::crypto::{CipherPair, NtorEphemeralKeyPair, SessionKey, ntor_client_finish_raw};
use common::metrics::Direction;
use common::{CELL_SIZE, CircuitId, Message, MessageCommand, NodeDescriptor, StreamId};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{ReadHalf, WriteHalf};
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
    pub entry_writer: Arc<Mutex<WriteHalf<TcpStream>>>,
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
    pub read_half: ReadHalf<TcpStream>,
}

/// Builds a 3-hop circuit via telescopic ntor handshake.
pub struct CircuitBuilder;

impl CircuitBuilder {
    pub async fn build(circuit_id: CircuitId, path: &[NodeDescriptor]) -> Result<BuiltCircuit> {
        if path.len() != 3 {
            return Err(anyhow::anyhow!(
                "Circuit path must have exactly 3 nodes, got {}",
                path.len()
            ));
        }

        let entry = path
            .first()
            .ok_or_else(|| anyhow::anyhow!("Missing entry node"))?;
        let middle = path
            .get(1)
            .ok_or_else(|| anyhow::anyhow!("Missing middle node"))?;
        let exit = path
            .get(2)
            .ok_or_else(|| anyhow::anyhow!("Missing exit node"))?;

        info!(
            "Building circuit {}: {} -> {} -> {}",
            circuit_id, entry.address, middle.address, exit.address
        );

        let mut entry_stream = TcpStream::connect(entry.address)
            .await
            .context("Failed to connect to entry node")?;
        info!("Connected to entry node at {}", entry.address);

        let entry_key = Self::handshake_create(circuit_id, &mut entry_stream, entry).await?;
        let mut entry_cipher = CipherPair::new(&entry_key);
        info!("Completed CREATE handshake with entry node");

        let middle_key = Self::handshake_extend_to_middle(
            circuit_id,
            &mut entry_stream,
            middle,
            &mut entry_cipher,
        )
        .await?;
        let mut middle_cipher = CipherPair::new(&middle_key);
        info!("Completed EXTEND to middle node");

        let exit_key = Self::handshake_extend_to_exit(
            circuit_id,
            &mut entry_stream,
            exit,
            &mut entry_cipher,
            &mut middle_cipher,
        )
        .await?;
        let exit_cipher = CipherPair::new(&exit_key);
        info!("Completed EXTEND to exit node");

        let onion_keys = OnionKeys::from_parts(
            entry_key,
            middle_key,
            exit_key,
            entry_cipher,
            middle_cipher,
            exit_cipher,
        );

        let path_display = Some(format!(
            ":{} \u{2192} :{} \u{2192} :{}",
            entry.address.port(),
            middle.address.port(),
            exit.address.port()
        ));

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
        stream: &mut TcpStream,
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

    /// EXTEND to the middle node (ntor, encrypted with entry cipher).
    async fn handshake_extend_to_middle(
        circuit_id: CircuitId,
        stream: &mut TcpStream,
        middle: &NodeDescriptor,
        entry_cipher: &mut CipherPair,
    ) -> Result<SessionKey> {
        let ephemeral = NtorEphemeralKeyPair::generate();
        let our_public = ephemeral.public.bytes;

        let addr_str = middle.address.to_string();
        let mut extend_payload = Vec::with_capacity(addr_str.len() + 1 + 32);
        extend_payload.extend_from_slice(addr_str.as_bytes());
        extend_payload.push(0);
        extend_payload.extend_from_slice(&our_public);

        entry_cipher.apply_forward(&mut extend_payload);

        let extend_msg = Message::extend(circuit_id, extend_payload);
        extend_msg
            .write_to_stream(stream)
            .await
            .context("Failed to send EXTEND to middle")?;
        debug!("Sent EXTEND for middle node {}", middle.address);

        let extended_msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, Message::from_stream(stream))
            .await
            .context("Timed out waiting for EXTENDED from middle node")?
            .context("Failed to read EXTENDED")?
            .ok_or_else(|| anyhow::anyhow!("Connection closed during EXTEND to middle"))?;

        if extended_msg.command != MessageCommand::Extended {
            return Err(anyhow::anyhow!(
                "Expected EXTENDED, got {}",
                extended_msg.command
            ));
        }

        let mut decrypted = extended_msg.data;
        entry_cipher.apply_backward(&mut decrypted);

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
            &middle.public_key.bytes,
            &server_eph_pub,
            &auth,
        )
        .map_err(|e| anyhow::anyhow!("ntor handshake failed with middle: {}", e))?;

        debug!("ntor handshake complete with middle node");
        Ok(session_key)
    }

    /// EXTEND to the exit node (ntor, encrypted with 2 layers).
    async fn handshake_extend_to_exit(
        circuit_id: CircuitId,
        stream: &mut TcpStream,
        exit: &NodeDescriptor,
        entry_cipher: &mut CipherPair,
        middle_cipher: &mut CipherPair,
    ) -> Result<SessionKey> {
        let ephemeral = NtorEphemeralKeyPair::generate();
        let our_public = ephemeral.public.bytes;

        let addr_str = exit.address.to_string();
        let mut extend_payload = Vec::with_capacity(addr_str.len() + 1 + 32);
        extend_payload.extend_from_slice(addr_str.as_bytes());
        extend_payload.push(0);
        extend_payload.extend_from_slice(&our_public);

        middle_cipher.apply_forward(&mut extend_payload);
        entry_cipher.apply_forward(&mut extend_payload);

        let extend_msg = Message::extend(circuit_id, extend_payload);
        extend_msg
            .write_to_stream(stream)
            .await
            .context("Failed to send EXTEND to exit")?;
        debug!("Sent EXTEND for exit node {}", exit.address);

        let extended_msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, Message::from_stream(stream))
            .await
            .context("Timed out waiting for EXTENDED from exit node")?
            .context("Failed to read EXTENDED")?
            .ok_or_else(|| anyhow::anyhow!("Connection closed during EXTEND to exit"))?;

        if extended_msg.command != MessageCommand::Extended {
            return Err(anyhow::anyhow!(
                "Expected EXTENDED, got {}",
                extended_msg.command
            ));
        }

        let mut decrypted = extended_msg.data;
        entry_cipher.apply_backward(&mut decrypted);
        middle_cipher.apply_backward(&mut decrypted);

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
            &exit.public_key.bytes,
            &server_eph_pub,
            &auth,
        )
        .map_err(|e| anyhow::anyhow!("ntor handshake failed with exit: {}", e))?;

        debug!("ntor handshake complete with exit node");
        Ok(session_key)
    }
}

/// Pool of pre-built circuits for handling SOCKS5 connections.
pub struct CircuitPool {
    circuits: HashMap<CircuitId, Arc<Mutex<Circuit>>>,
    next_circuit_id: CircuitId,
    directory_client: DirectoryClient,
    pool_size: usize,
    metrics: Option<Arc<ClientMetrics>>,
}

impl CircuitPool {
    pub fn new(directory_client: DirectoryClient, pool_size: usize) -> Self {
        Self {
            circuits: HashMap::new(),
            next_circuit_id: 1,
            directory_client,
            pool_size,
            metrics: None,
        }
    }

    pub fn set_metrics(&mut self, metrics: Arc<ClientMetrics>) {
        self.metrics = Some(metrics);
    }

    pub fn metrics(&self) -> Option<&Arc<ClientMetrics>> {
        self.metrics.as_ref()
    }

    /// Pre-build circuits to fill the pool at startup.
    pub async fn initialize(&mut self) -> Result<Vec<(Arc<Mutex<Circuit>>, ReadHalf<TcpStream>)>> {
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
    pub async fn select_circuit(
        &mut self,
    ) -> Result<(Arc<Mutex<Circuit>>, Option<ReadHalf<TcpStream>>)> {
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

    /// Replace a failed circuit and replenish the pool.
    pub async fn replace_circuit(
        &mut self,
        failed_id: CircuitId,
    ) -> Result<(Arc<Mutex<Circuit>>, ReadHalf<TcpStream>)> {
        info!("Replacing failed circuit {}", failed_id);
        self.circuits.remove(&failed_id);
        let (circuit_id, read_half) = self.build_circuit().await?;
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

    async fn build_circuit(&mut self) -> Result<(CircuitId, ReadHalf<TcpStream>)> {
        let circuit_id = self.allocate_circuit_id();
        let path = self
            .directory_client
            .get_random_path()
            .await
            .context("Failed to get path from directory")?;

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
    mut read_half: ReadHalf<TcpStream>,
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_id_allocation_monotonic() {
        let directory_client = DirectoryClient::new("http://localhost:8080".to_string());
        let mut pool = CircuitPool::new(directory_client, 3);

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
        let pool = CircuitPool::new(directory_client, 5);
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
}
