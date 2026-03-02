use crate::circuit::handler::{CircuitContext, CircuitState, NextHop};
use crate::keypair::KeyPair;
use crate::metrics::{EventKind, RelayMetrics};
use common::{
    crypto::{SessionKey, aes_decrypt, aes_encrypt, derive_session_key},
    protocol::{CircuitId, Message, MessageCommand},
};
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info};

/// Entry node circuit handler
/// Handles the first hop in a circuit
/// Knows the client but NOT the final destination
pub struct EntryCircuitHandler {
    context: CircuitContext,
    keypair: KeyPair,
    next_hop: Option<NextHop>,
    /// Metrics for TUI events (optional — None in tests)
    metrics: Option<Arc<RelayMetrics>>,
}

impl EntryCircuitHandler {
    /// Create a new entry circuit handler
    pub fn new(circuit_id: CircuitId, keypair: KeyPair) -> Self {
        Self {
            context: CircuitContext::new(circuit_id),
            keypair,
            next_hop: None,
            metrics: None,
        }
    }

    /// Set the metrics reference for TUI event reporting
    pub fn set_metrics(&mut self, metrics: Arc<RelayMetrics>) {
        self.metrics = Some(metrics);
    }

    /// Handle CREATE message (DH handshake initialization)
    async fn handle_create(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Entry: Handling CREATE for circuit {}",
            self.context.circuit_id
        );

        if msg.data.len() < 32 {
            return Err(anyhow::anyhow!("CREATE message too short"));
        }

        let mut client_public = [0u8; 32];
        client_public.copy_from_slice(
            msg.data
                .get(0..32)
                .ok_or(anyhow::anyhow!("Invalid CREATE data"))?,
        );

        debug!("Entry: Client public key: {:02x?}...", &client_public[0..8]);

        let shared_secret = self.keypair.diffie_hellman(&client_public);
        debug!("Entry: Shared secret derived");

        let session_key = derive_session_key(&shared_secret);

        self.context.activate(session_key.clone());

        info!("Entry: Circuit {} activated", self.context.circuit_id);

        let response = Message::created(
            self.context.circuit_id,
            self.keypair.public_key().bytes.to_vec(),
        );

        Ok(Some(response))
    }

    /// Handle EXTEND message (extend circuit to next hop)
    async fn handle_extend(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Entry: Handling EXTEND for circuit {}",
            self.context.circuit_id
        );

        let session_key = self
            .context
            .session_key
            .as_ref()
            .ok_or(anyhow::anyhow!("Circuit not yet established"))?;

        let decrypted = aes_decrypt(&msg.data, &session_key.forward)?;

        if decrypted.len() < 32 {
            return Err(anyhow::anyhow!("EXTEND payload too short"));
        }

        let addr_end = decrypted
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(decrypted.len() - 32);

        let addr_bytes = decrypted
            .get(0..addr_end)
            .ok_or(anyhow::anyhow!("Invalid address"))?;
        let addr_str = std::str::from_utf8(addr_bytes)?;

        info!("Entry: Extending to next hop: {}", addr_str);

        let mut next_hop_stream = TcpStream::connect(addr_str).await?;

        info!("Entry: Connected to next hop {}", addr_str);

        let create_payload_start = addr_end + 1;
        let create_payload = decrypted
            .get(create_payload_start..)
            .ok_or(anyhow::anyhow!("Missing CREATE payload for next hop"))?;

        let create_msg = Message::create(self.context.circuit_id, create_payload.to_vec());

        let create_bytes = create_msg.to_bytes();
        next_hop_stream.write_all(&create_bytes).await?;
        debug!("Entry: Sent CREATE to next hop");

        let created_msg = Message::from_stream(&mut next_hop_stream)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Next hop closed connection waiting for CREATED"))?;

        if created_msg.command != MessageCommand::Created {
            return Err(anyhow::anyhow!(
                "Expected CREATED from next hop, got {:?}",
                created_msg.command
            ));
        }

        info!("Entry: Received CREATED from next hop");

        self.next_hop = Some(NextHop::new(next_hop_stream));

        if let Some(m) = &self.metrics {
            m.push_event(EventKind::CircuitExtended {
                circuit_id: self.context.circuit_id,
                next_hop: addr_str.to_string(),
            });
        }

        let response = Message::extended(self.context.circuit_id, created_msg.data);

        let encrypted_data = aes_encrypt(&response.data, &session_key.backward);
        let encrypted_response = Message::extended(self.context.circuit_id, encrypted_data);

        Ok(Some(encrypted_response))
    }

    /// Handle relay cell (forward data to next hop)
    async fn handle_relay(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        debug!(
            "Entry: Handling relay cell for circuit {}",
            self.context.circuit_id
        );

        let session_key = self
            .context
            .session_key
            .as_ref()
            .ok_or(anyhow::anyhow!("Circuit not yet established"))?;

        let decrypted = aes_decrypt(&msg.data, &session_key.forward)?;

        if let Some(next_hop) = &mut self.next_hop {
            let forward_msg = Message::new(msg.circuit_id, msg.stream_id, msg.command, decrypted);

            let serialized = forward_msg.to_bytes();
            next_hop.write.write_all(&serialized).await?;

            debug!("Entry: Forwarded {} bytes to next hop", serialized.len());
        } else {
            error!(
                "Entry: No next hop configured for circuit {}",
                self.context.circuit_id
            );
        }

        Ok(None)
    }

    /// Handle backward relay cell (data coming back from middle/exit node)
    /// Encrypt one layer and return to client
    pub async fn handle_backward_relay(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        debug!(
            "Entry: Handling backward relay for circuit {}",
            self.context.circuit_id
        );

        let session_key = self
            .context
            .session_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No session key established"))?;

        let encrypted = aes_encrypt(&msg.data, &session_key.backward);

        Ok(Some(Message::new(
            msg.circuit_id,
            msg.stream_id,
            msg.command,
            encrypted,
        )))
    }

    /// Handle an incoming message on this circuit
    /// Returns optional response message to send back
    pub async fn handle_message(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        match msg.command {
            MessageCommand::Create => self.handle_create(msg).await,
            MessageCommand::Extend => {
                if self.next_hop.is_some() {
                    // Already extended once; relay this EXTEND to the next hop
                    // (e.g., middle node will handle extending to exit)
                    debug!(
                        "Entry: Relaying EXTEND to next hop for circuit {}",
                        self.context.circuit_id
                    );
                    self.handle_relay(msg).await
                } else {
                    // First EXTEND: handle locally (connect to middle node)
                    self.handle_extend(msg).await
                }
            }
            // Forward all stream-level and relay messages to next hop
            MessageCommand::Data
            | MessageCommand::Begin
            | MessageCommand::End
            | MessageCommand::Connected => self.handle_relay(msg).await,
            MessageCommand::Destroy => {
                info!("Entry: Circuit {} destroyed", self.context.circuit_id);
                self.close();
                Ok(None)
            }
            _ => {
                error!(
                    "Entry: Unexpected command {:?} for circuit {}",
                    msg.command, self.context.circuit_id
                );
                Err(anyhow::anyhow!("Unexpected command: {:?}", msg.command))
            }
        }
    }

    /// Get the circuit ID
    #[allow(dead_code)]
    pub fn circuit_id(&self) -> CircuitId {
        self.context.circuit_id
    }

    /// Get the current state
    #[allow(dead_code)]
    pub fn state(&self) -> CircuitState {
        self.context.state
    }

    /// Get the session key (if established)
    #[allow(dead_code)]
    pub fn session_key(&self) -> Option<&SessionKey> {
        self.context.session_key.as_ref()
    }

    /// Close this circuit
    pub fn close(&mut self) {
        self.context.close();
        self.next_hop = None;
    }

    /// Spawn a background task to read responses from next hop
    /// Returns the task handle
    pub fn spawn_nexthop_reader(
        &mut self,
        circuit_registry: Arc<Mutex<crate::circuit::handler::CircuitRegistry>>,
        client_write: Arc<Mutex<WriteHalf<TcpStream>>>,
        metrics: Arc<RelayMetrics>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let circuit_id = self.context.circuit_id;

        let mut read_half = self.next_hop.as_mut()?.take_read()?;

        info!(
            "Entry: Spawning background reader for circuit {}",
            circuit_id
        );

        Some(tokio::spawn(async move {
            loop {
                match Message::from_stream(&mut read_half).await {
                    Ok(Some(msg)) => {
                        debug!(
                            "Entry: Received backward message from next hop for circuit {}",
                            circuit_id
                        );

                        let backward_command = msg.command;
                        let backward_bytes = msg.data.len();

                        let response = {
                            let mut registry = circuit_registry.lock().await;
                            match registry.handle_backward_message(msg).await {
                                Ok(Some(response)) => response,
                                Ok(_) => continue,
                                Err(e) => {
                                    error!("Entry: Error handling backward message: {}", e);
                                    break;
                                }
                            }
                        };

                        let bytes = response.to_bytes();
                        let mut writer = client_write.lock().await;
                        if let Err(e) = writer.write_all(&bytes).await {
                            error!("Entry: Error sending backward message to client: {}", e);
                            break;
                        }
                        debug!("Entry: Sent backward message to client");

                        metrics
                            .bytes_received
                            .fetch_add(backward_bytes as u64, std::sync::atomic::Ordering::Relaxed);
                        metrics.push_event(EventKind::RelayBackward {
                            circuit_id,
                            command: backward_command,
                            bytes: backward_bytes,
                        });
                    }
                    Ok(_) => {
                        info!(
                            "Entry: Next hop closed connection for circuit {}",
                            circuit_id
                        );
                        break;
                    }
                    Err(e) => {
                        error!("Entry: Error reading from next hop: {}", e);
                        break;
                    }
                }
            }
            info!(
                "Entry: Background reader task terminated for circuit {}",
                circuit_id
            );
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::circuit::handler::CircuitState;
    use common::crypto::{EphemeralKeyPair, aes_decrypt, derive_session_key};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_entry_create_handshake() {
        let keypair = KeyPair::generate();
        let mut handler = EntryCircuitHandler::new(1, keypair.clone());

        // Client generates ephemeral keypair and sends CREATE
        let ephemeral = EphemeralKeyPair::generate();
        let client_public = ephemeral.public.bytes;
        let create_msg = Message::create(1, client_public.to_vec());

        let response = handler.handle_create(create_msg).await.unwrap();
        let response = response.unwrap();

        // Should return CREATED with relay's public key
        assert_eq!(response.command, MessageCommand::Created);
        assert_eq!(response.circuit_id, 1);
        assert_eq!(response.data.len(), 32);

        // Handler should be activated
        assert_eq!(handler.state(), CircuitState::Active);
        assert!(handler.session_key().is_some());

        // Both sides should derive the same session key
        let mut relay_public = [0u8; 32];
        relay_public.copy_from_slice(&response.data[0..32]);
        let client_shared = ephemeral.diffie_hellman(&relay_public);
        let client_key = derive_session_key(&client_shared);

        let relay_key = handler.session_key().unwrap();
        assert_eq!(client_key, *relay_key);
    }

    #[tokio::test]
    async fn test_entry_create_too_short() {
        let keypair = KeyPair::generate();
        let mut handler = EntryCircuitHandler::new(1, keypair);

        // Send CREATE with too-short payload (< 32 bytes)
        let create_msg = Message::create(1, vec![0u8; 16]);
        let result = handler.handle_create(create_msg).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[tokio::test]
    async fn test_entry_backward_relay_encrypts() {
        let keypair = KeyPair::generate();
        let mut handler = EntryCircuitHandler::new(1, keypair.clone());

        // First, establish the circuit via CREATE
        let ephemeral = EphemeralKeyPair::generate();
        let create_msg = Message::create(1, ephemeral.public.bytes.to_vec());
        let created = handler.handle_create(create_msg).await.unwrap().unwrap();

        // Derive session key on client side
        let mut relay_public = [0u8; 32];
        relay_public.copy_from_slice(&created.data[0..32]);
        let client_shared = ephemeral.diffie_hellman(&relay_public);
        let client_key = derive_session_key(&client_shared);

        // Simulate a backward DATA message (e.g., from middle/exit)
        let plaintext = b"Hello from exit node";
        let backward_msg = Message::data(1, 5, plaintext.to_vec());

        let response = handler
            .handle_backward_relay(backward_msg)
            .await
            .unwrap()
            .unwrap();

        // Response should be encrypted with backward key
        assert_eq!(response.command, MessageCommand::Data);
        assert_eq!(response.circuit_id, 1);
        assert_eq!(response.stream_id, 5);

        // Client can decrypt with backward key
        let decrypted = aes_decrypt(&response.data, &client_key.backward).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_entry_backward_relay_no_session_key() {
        let keypair = KeyPair::generate();
        let mut handler = EntryCircuitHandler::new(1, keypair);

        // Try backward relay without establishing circuit
        let msg = Message::data(1, 1, b"test".to_vec());
        let result = handler.handle_backward_relay(msg).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No session key"));
    }

    #[tokio::test]
    async fn test_entry_destroy_closes_circuit() {
        let keypair = KeyPair::generate();
        let mut handler = EntryCircuitHandler::new(1, keypair.clone());

        // Establish circuit
        let ephemeral = EphemeralKeyPair::generate();
        let create_msg = Message::create(1, ephemeral.public.bytes.to_vec());
        handler.handle_create(create_msg).await.unwrap();

        assert_eq!(handler.state(), CircuitState::Active);

        // Send DESTROY
        let destroy_msg = Message::destroy(1);
        let result = handler.handle_message(destroy_msg).await.unwrap();

        assert!(result.is_none());
        assert_eq!(handler.state(), CircuitState::Closed);
        assert!(handler.session_key().is_none());
    }

    #[tokio::test]
    async fn test_entry_extend_to_middle_over_tcp() {
        // Set up a fake "middle node" listener
        let middle_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let middle_addr = middle_listener.local_addr().unwrap();
        let middle_keypair = KeyPair::generate();
        let middle_public = middle_keypair.public_key().bytes;

        // Spawn fake middle node that responds to CREATE with CREATED
        let middle_kp_clone = middle_keypair.clone();
        let middle_task = tokio::spawn(async move {
            let (mut stream, _) = middle_listener.accept().await.unwrap();
            let msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
            assert_eq!(msg.command, MessageCommand::Create);

            // Respond with CREATED
            let created =
                Message::created(msg.circuit_id, middle_kp_clone.public_key().bytes.to_vec());
            stream.write_all(&created.to_bytes()).await.unwrap();
        });

        // Set up entry handler with established circuit
        let entry_keypair = KeyPair::generate();
        let mut handler = EntryCircuitHandler::new(42, entry_keypair.clone());

        let ephemeral = EphemeralKeyPair::generate();
        let client_public = ephemeral.public.bytes;
        let create_msg = Message::create(42, client_public.to_vec());
        let created_response = handler.handle_create(create_msg).await.unwrap().unwrap();

        // Derive client-side session key
        let mut relay_public = [0u8; 32];
        relay_public.copy_from_slice(&created_response.data[0..32]);
        let client_shared = ephemeral.diffie_hellman(&relay_public);
        let entry_key = derive_session_key(&client_shared);

        // Build EXTEND payload: "addr:port\0" + middle_public_key
        let addr_str = middle_addr.to_string();
        let mut extend_payload = Vec::new();
        extend_payload.extend_from_slice(addr_str.as_bytes());
        extend_payload.push(0);
        extend_payload.extend_from_slice(&middle_public);

        // Encrypt with entry forward key (client encrypts)
        let encrypted_payload = common::crypto::aes_encrypt(&extend_payload, &entry_key.forward);

        // Send EXTEND
        let extend_msg = Message::extend(42, encrypted_payload);
        let response = handler.handle_message(extend_msg).await.unwrap().unwrap();

        // Should return EXTENDED with middle's public key (encrypted with entry backward)
        assert_eq!(response.command, MessageCommand::Extended);
        assert_eq!(response.circuit_id, 42);

        // Decrypt the EXTENDED response
        let decrypted = aes_decrypt(&response.data, &entry_key.backward).unwrap();
        assert_eq!(decrypted.len(), 32);
        assert_eq!(&decrypted[..], &middle_public);

        middle_task.await.unwrap();
    }
}
