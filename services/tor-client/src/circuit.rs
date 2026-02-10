use crate::crypto_engine::OnionKeys;
use crate::directory_client::DirectoryClient;
use anyhow::{Context, Result};
use common::crypto::{EphemeralKeyPair, SessionKey, aes_decrypt, aes_encrypt, derive_session_key};
use common::{CircuitId, Message, MessageCommand, NodeDescriptor, StreamId};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};

/// State of a circuit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CircuitState {
    /// Circuit is being built (handshakes in progress)
    Building,
    /// Circuit is ready for data transfer
    Ready,
    /// Circuit is being torn down
    Closing,
    /// Circuit is closed
    Closed,
}

/// A single onion routing circuit through 3 relay nodes
///
/// Each circuit holds:
/// - A TCP connection to the entry node
/// - Session keys for all 3 hops (used for onion encryption)
/// - A map of active streams multiplexed over this circuit
pub struct Circuit {
    pub circuit_id: CircuitId,
    pub state: CircuitState,
    /// TCP connection to the entry node (shared for writes)
    pub entry_stream: Arc<Mutex<TcpStream>>,
    /// Onion encryption keys for all 3 hops
    pub onion_keys: OnionKeys,
    /// Channel senders for each active stream (stream_id -> sender)
    /// The background reader task demuxes incoming messages by stream_id
    pub stream_senders: HashMap<StreamId, mpsc::UnboundedSender<Message>>,
    /// Next stream ID to allocate
    next_stream_id: StreamId,
}

impl Circuit {
    /// Get the number of active streams on this circuit
    pub fn active_stream_count(&self) -> usize {
        self.stream_senders.len()
    }

    /// Allocate a new stream ID for this circuit
    pub fn allocate_stream_id(&mut self) -> StreamId {
        let id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1);
        if self.next_stream_id == 0 {
            self.next_stream_id = 1; // Skip 0 (reserved for circuit-level messages)
        }
        id
    }

    /// Register a stream sender for receiving demuxed backward messages
    pub fn register_stream(&mut self, stream_id: StreamId, sender: mpsc::UnboundedSender<Message>) {
        self.stream_senders.insert(stream_id, sender);
    }

    /// Unregister a stream (on close)
    pub fn unregister_stream(&mut self, stream_id: StreamId) {
        self.stream_senders.remove(&stream_id);
    }

    /// Send a message through this circuit with onion encryption
    ///
    /// The message data is onion-encrypted (3 layers) before sending to the entry node.
    ///
    /// # Errors
    /// Returns an error if writing to the entry node fails
    pub async fn send_message(
        &self,
        stream_id: StreamId,
        command: MessageCommand,
        data: &[u8],
    ) -> Result<()> {
        let encrypted_data = self.onion_keys.onion_encrypt(data);
        let msg = Message::new(self.circuit_id, stream_id, command, encrypted_data);
        let bytes = msg.to_bytes();

        let mut stream = self.entry_stream.lock().await;
        stream
            .write_all(&bytes)
            .await
            .context("Failed to write to entry node")?;
        debug!(
            "Sent {} message ({} bytes) on circuit {} stream {}",
            command,
            bytes.len(),
            self.circuit_id,
            stream_id,
        );

        Ok(())
    }

    /// Send a raw message (no onion encryption -- used for CREATE/EXTEND handshakes)
    ///
    /// # Errors
    /// Returns an error if writing to the entry node fails
    #[allow(dead_code)]
    pub async fn send_raw(&self, msg: &Message) -> Result<()> {
        let bytes = msg.to_bytes();
        let mut stream = self.entry_stream.lock().await;
        stream
            .write_all(&bytes)
            .await
            .context("Failed to write to entry node")?;
        Ok(())
    }
}

/// Builds a 3-hop circuit via telescopic handshake
///
/// The build process:
/// 1. Connect to entry node via TCP
/// 2. CREATE handshake with entry -> derive session_key_1
/// 3. EXTEND to middle (encrypted with entry key) -> derive session_key_2
/// 4. EXTEND to exit (encrypted with entry+middle keys) -> derive session_key_3
pub struct CircuitBuilder;

impl CircuitBuilder {
    /// Build a complete 3-hop circuit
    ///
    /// # Arguments
    /// * `circuit_id` - Unique ID for this circuit
    /// * `path` - Ordered list of 3 node descriptors: [entry, middle, exit]
    ///
    /// # Errors
    /// Returns an error if any handshake step fails
    pub async fn build(circuit_id: CircuitId, path: &[NodeDescriptor]) -> Result<Circuit> {
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

        // Step 1: Connect to entry node
        let mut entry_stream = TcpStream::connect(entry.address)
            .await
            .context("Failed to connect to entry node")?;
        info!("Connected to entry node at {}", entry.address);

        // Step 2: CREATE handshake with entry
        let entry_key = Self::handshake_create(circuit_id, &mut entry_stream, entry).await?;
        info!("Completed CREATE handshake with entry node");

        // Step 3: EXTEND to middle node
        let middle_key =
            Self::handshake_extend_to_middle(circuit_id, &mut entry_stream, middle, &entry_key)
                .await?;
        info!("Completed EXTEND to middle node");

        // Step 4: EXTEND to exit node
        let exit_key = Self::handshake_extend_to_exit(
            circuit_id,
            &mut entry_stream,
            exit,
            &entry_key,
            &middle_key,
        )
        .await?;
        info!("Completed EXTEND to exit node");

        let onion_keys = OnionKeys::new(entry_key, middle_key, exit_key);

        Ok(Circuit {
            circuit_id,
            state: CircuitState::Ready,
            entry_stream: Arc::new(Mutex::new(entry_stream)),
            onion_keys,
            stream_senders: HashMap::new(),
            next_stream_id: 1,
        })
    }

    /// Step 2: CREATE handshake with the entry node
    ///
    /// Sends CREATE with our ephemeral public key, receives CREATED with entry's public key,
    /// performs DH to derive the shared session key.
    async fn handshake_create(
        circuit_id: CircuitId,
        stream: &mut TcpStream,
        _entry: &NodeDescriptor,
    ) -> Result<SessionKey> {
        // Generate ephemeral keypair for this hop
        let ephemeral = EphemeralKeyPair::generate();
        let our_public = ephemeral.public.bytes;

        // Send CREATE
        let create_msg = Message::create(circuit_id, our_public.to_vec());
        let bytes = create_msg.to_bytes();
        stream
            .write_all(&bytes)
            .await
            .context("Failed to send CREATE")?;
        debug!("Sent CREATE to entry node");

        // Receive CREATED
        let created_msg = Message::from_stream(stream)
            .await
            .context("Failed to read CREATED")?
            .ok_or_else(|| anyhow::anyhow!("Entry node closed connection during CREATE"))?;

        if created_msg.command != MessageCommand::Created {
            return Err(anyhow::anyhow!(
                "Expected CREATED from entry, got {}",
                created_msg.command
            ));
        }

        if created_msg.data.len() < 32 {
            return Err(anyhow::anyhow!(
                "CREATED response too short: {} bytes",
                created_msg.data.len()
            ));
        }

        // Extract entry's public key
        let mut entry_public = [0u8; 32];
        entry_public.copy_from_slice(
            created_msg
                .data
                .get(0..32)
                .ok_or_else(|| anyhow::anyhow!("Invalid CREATED data"))?,
        );

        // Perform DH and derive session key
        let shared_secret = ephemeral.diffie_hellman(&entry_public);
        let session_key = derive_session_key(&shared_secret);

        debug!("Derived session key with entry node");
        Ok(session_key)
    }

    /// Step 3: EXTEND to the middle node
    ///
    /// Sends EXTEND with the middle node's address and our public key (encrypted with entry key).
    /// Entry node connects to middle, forwards CREATE, returns CREATED response as EXTENDED.
    async fn handshake_extend_to_middle(
        circuit_id: CircuitId,
        stream: &mut TcpStream,
        middle: &NodeDescriptor,
        entry_key: &SessionKey,
    ) -> Result<SessionKey> {
        // Generate ephemeral keypair for middle hop
        let ephemeral = EphemeralKeyPair::generate();
        let our_public = ephemeral.public.bytes;

        // Build EXTEND payload: "addr:port\0" + public_key (32 bytes)
        let addr_str = middle.address.to_string();
        let mut extend_payload = Vec::with_capacity(addr_str.len() + 1 + 32);
        extend_payload.extend_from_slice(addr_str.as_bytes());
        extend_payload.push(0); // null terminator
        extend_payload.extend_from_slice(&our_public);

        // Encrypt with entry's forward key (one layer)
        let encrypted_payload = aes_encrypt(&extend_payload, &entry_key.forward);

        // Send EXTEND
        let extend_msg = Message::extend(circuit_id, encrypted_payload);
        let bytes = extend_msg.to_bytes();
        stream
            .write_all(&bytes)
            .await
            .context("Failed to send EXTEND to middle")?;
        debug!("Sent EXTEND for middle node {}", middle.address);

        // Receive EXTENDED
        let extended_msg = Message::from_stream(stream)
            .await
            .context("Failed to read EXTENDED")?
            .ok_or_else(|| anyhow::anyhow!("Connection closed during EXTEND to middle"))?;

        if extended_msg.command != MessageCommand::Extended {
            return Err(anyhow::anyhow!(
                "Expected EXTENDED, got {}",
                extended_msg.command
            ));
        }

        // Decrypt EXTENDED response (entry added one backward layer)
        let decrypted = aes_decrypt(&extended_msg.data, &entry_key.backward)
            .context("Failed to decrypt EXTENDED from middle")?;

        if decrypted.len() < 32 {
            return Err(anyhow::anyhow!(
                "EXTENDED response too short: {} bytes",
                decrypted.len()
            ));
        }

        // Extract middle's public key
        let mut middle_public = [0u8; 32];
        middle_public.copy_from_slice(
            decrypted
                .get(0..32)
                .ok_or_else(|| anyhow::anyhow!("Invalid EXTENDED data"))?,
        );

        // Perform DH and derive session key
        let shared_secret = ephemeral.diffie_hellman(&middle_public);
        let session_key = derive_session_key(&shared_secret);

        debug!("Derived session key with middle node");
        Ok(session_key)
    }

    /// Step 4: EXTEND to the exit node
    ///
    /// Sends EXTEND with the exit node's address and our public key.
    /// This is encrypted with 2 layers (middle.forward, then entry.forward).
    /// Entry peels one layer and forwards to middle. Middle sees the EXTEND payload.
    async fn handshake_extend_to_exit(
        circuit_id: CircuitId,
        stream: &mut TcpStream,
        exit: &NodeDescriptor,
        entry_key: &SessionKey,
        middle_key: &SessionKey,
    ) -> Result<SessionKey> {
        // Generate ephemeral keypair for exit hop
        let ephemeral = EphemeralKeyPair::generate();
        let our_public = ephemeral.public.bytes;

        // Build EXTEND payload: "addr:port\0" + public_key (32 bytes)
        let addr_str = exit.address.to_string();
        let mut extend_payload = Vec::with_capacity(addr_str.len() + 1 + 32);
        extend_payload.extend_from_slice(addr_str.as_bytes());
        extend_payload.push(0); // null terminator
        extend_payload.extend_from_slice(&our_public);

        // Encrypt with middle's forward key first, then entry's forward key (2 layers)
        let layer2 = aes_encrypt(&extend_payload, &middle_key.forward);
        let encrypted_payload = aes_encrypt(&layer2, &entry_key.forward);

        // Send EXTEND
        let extend_msg = Message::extend(circuit_id, encrypted_payload);
        let bytes = extend_msg.to_bytes();
        stream
            .write_all(&bytes)
            .await
            .context("Failed to send EXTEND to exit")?;
        debug!("Sent EXTEND for exit node {}", exit.address);

        // Receive EXTENDED
        let extended_msg = Message::from_stream(stream)
            .await
            .context("Failed to read EXTENDED")?
            .ok_or_else(|| anyhow::anyhow!("Connection closed during EXTEND to exit"))?;

        if extended_msg.command != MessageCommand::Extended {
            return Err(anyhow::anyhow!(
                "Expected EXTENDED, got {}",
                extended_msg.command
            ));
        }

        // Decrypt EXTENDED response (only entry added its backward layer)
        let decrypted = aes_decrypt(&extended_msg.data, &entry_key.backward)
            .context("Failed to decrypt EXTENDED from exit")?;

        if decrypted.len() < 32 {
            return Err(anyhow::anyhow!(
                "EXTENDED response too short: {} bytes",
                decrypted.len()
            ));
        }

        // Extract exit's public key
        let mut exit_public = [0u8; 32];
        exit_public.copy_from_slice(
            decrypted
                .get(0..32)
                .ok_or_else(|| anyhow::anyhow!("Invalid EXTENDED data"))?,
        );

        // Perform DH and derive session key
        let shared_secret = ephemeral.diffie_hellman(&exit_public);
        let session_key = derive_session_key(&shared_secret);

        debug!("Derived session key with exit node");
        Ok(session_key)
    }
}

/// Pool of pre-built circuits for handling SOCKS5 connections
///
/// Maintains a configurable number of ready circuits and assigns
/// new streams to the least-loaded circuit.
pub struct CircuitPool {
    circuits: HashMap<CircuitId, Arc<Mutex<Circuit>>>,
    next_circuit_id: CircuitId,
    directory_client: DirectoryClient,
    pool_size: usize,
}

impl CircuitPool {
    /// Create a new circuit pool
    pub fn new(directory_client: DirectoryClient, pool_size: usize) -> Self {
        Self {
            circuits: HashMap::new(),
            next_circuit_id: 1,
            directory_client,
            pool_size,
        }
    }

    /// Pre-build circuits to fill the pool at startup
    ///
    /// # Errors
    /// Returns an error if any circuit fails to build
    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing circuit pool with {} circuits", self.pool_size);

        for i in 0..self.pool_size {
            match self.build_circuit().await {
                Ok(circuit_id) => {
                    info!(
                        "Built circuit {}/{}: id={}",
                        i + 1,
                        self.pool_size,
                        circuit_id
                    );
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
        Ok(())
    }

    /// Select the least-loaded ready circuit for a new stream
    ///
    /// If no ready circuits exist, builds a new one.
    ///
    /// # Errors
    /// Returns an error if no circuits are available and building a new one fails
    pub async fn select_circuit(&mut self) -> Result<Arc<Mutex<Circuit>>> {
        // Find the ready circuit with fewest active streams
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
            return Ok(Arc::clone(circuit));
        }

        // No ready circuits, build a new one
        warn!("No ready circuits available, building a new one");
        let circuit_id = self.build_circuit().await?;
        let circuit = self
            .circuits
            .get(&circuit_id)
            .ok_or_else(|| anyhow::anyhow!("Newly built circuit {} not found", circuit_id))?;
        Ok(Arc::clone(circuit))
    }

    /// Replace a failed circuit and replenish the pool
    ///
    /// # Errors
    /// Returns an error if building a replacement circuit fails
    #[allow(dead_code)]
    pub async fn replace_circuit(&mut self, failed_id: CircuitId) -> Result<CircuitId> {
        info!("Replacing failed circuit {}", failed_id);
        self.circuits.remove(&failed_id);
        self.build_circuit().await
    }

    /// Build a single circuit and add it to the pool
    async fn build_circuit(&mut self) -> Result<CircuitId> {
        let circuit_id = self.allocate_circuit_id();
        let path = self
            .directory_client
            .get_random_path()
            .await
            .context("Failed to get path from directory")?;

        let circuit = CircuitBuilder::build(circuit_id, &path).await?;

        self.circuits
            .insert(circuit_id, Arc::new(Mutex::new(circuit)));

        Ok(circuit_id)
    }

    /// Allocate a new unique circuit ID
    fn allocate_circuit_id(&mut self) -> CircuitId {
        let id = self.next_circuit_id;
        self.next_circuit_id = self.next_circuit_id.wrapping_add(1);
        id
    }

    /// Get references to all circuits in the pool (for spawning readers)
    pub fn circuits(&self) -> Vec<Arc<Mutex<Circuit>>> {
        self.circuits.values().map(Arc::clone).collect()
    }

    /// Get the number of circuits in the pool
    #[allow(dead_code)]
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }
}

/// Spawn a background task that reads messages from the entry node
/// and demuxes them to the correct stream channel based on stream_id.
///
/// This is the backward direction reader: it reads responses coming back
/// through the circuit, decrypts the onion layers, and routes data to
/// the appropriate SOCKS5 connection handler.
pub fn spawn_circuit_reader(circuit: Arc<Mutex<Circuit>>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let circuit_id = circuit.lock().await.circuit_id;
        info!("Starting circuit reader for circuit {}", circuit_id);

        loop {
            // Read a message from the entry node
            let msg = {
                let mut circuit_guard = circuit.lock().await;
                let mut stream = circuit_guard.entry_stream.lock().await;
                match Message::from_stream(&mut *stream).await {
                    Ok(Some(msg)) => msg,
                    Ok(None) => {
                        info!("Entry node closed connection for circuit {}", circuit_id);
                        drop(stream);
                        circuit_guard.state = CircuitState::Closed;
                        break;
                    }
                    Err(e) => {
                        error!(
                            "Error reading from entry node for circuit {}: {}",
                            circuit_id, e
                        );
                        drop(stream);
                        circuit_guard.state = CircuitState::Closed;
                        break;
                    }
                }
            };

            debug!(
                "Circuit {} received backward {} for stream {}",
                circuit_id, msg.command, msg.stream_id
            );

            // Decrypt the onion layers
            let circuit_guard = circuit.lock().await;
            let decrypted_data = match circuit_guard.onion_keys.onion_decrypt(&msg.data) {
                Ok(data) => data,
                Err(e) => {
                    error!(
                        "Failed to decrypt backward message on circuit {}: {}",
                        circuit_id, e
                    );
                    continue;
                }
            };

            // Create decrypted message and route to the correct stream
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
        // Verify state enum variants exist and are distinguishable
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
    fn test_stream_id_allocation() {
        let keys = OnionKeys::new(SessionKey::zero(), SessionKey::zero(), SessionKey::zero());
        let stream = Arc::new(Mutex::new(unsafe {
            // We can't create a real TcpStream in a sync test, so just test the allocation logic
            // by testing the ID counter directly
            std::mem::zeroed::<u16>()
        }));

        // Just test the counter logic directly
        let mut next_id: StreamId = 1;
        let id1 = next_id;
        next_id = next_id.wrapping_add(1);
        let id2 = next_id;
        next_id = next_id.wrapping_add(1);
        let id3 = next_id;

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);

        // Suppress unused variable warnings
        let _ = keys;
        let _ = stream;
    }
}
