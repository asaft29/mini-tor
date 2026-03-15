use crate::circuit::handler::{CircuitContext, CircuitState, NextHop};
use crate::keypair::KeyPair;
use crate::metrics::{EventKind, RelayMetrics};
use common::{
    crypto::{SessionKey, derive_session_key},
    protocol::{CircuitId, Message, MessageCommand},
};
use std::sync::Arc;
use tokio::io::WriteHalf;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info};

/// Middle node circuit handler
/// Handles the second hop in a circuit
/// Knows neither the client nor the final destination (only previous and next hop)
pub struct MiddleCircuitHandler {
    context: CircuitContext,
    keypair: KeyPair,
    next_hop: Option<NextHop>,
    metrics: Option<Arc<RelayMetrics>>,
}

impl MiddleCircuitHandler {
    /// Create a new middle circuit handler
    pub fn new(circuit_id: CircuitId, keypair: KeyPair) -> Self {
        Self {
            context: CircuitContext::new(circuit_id),
            keypair,
            next_hop: None,
            metrics: None,
        }
    }

    /// Set optional metrics for TUI event reporting
    pub fn set_metrics(&mut self, metrics: Arc<RelayMetrics>) {
        self.metrics = Some(metrics);
    }

    /// Handle EXTENDED message (response to EXTEND from entry node)
    /// The entry node has already performed DH with us
    async fn handle_extended(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Middle: Received EXTENDED for circuit {}",
            self.context.circuit_id
        );

        if msg.data.len() < 32 {
            return Err(anyhow::anyhow!("EXTENDED message too short"));
        }

        let mut next_public = [0u8; 32];
        next_public.copy_from_slice(
            msg.data
                .get(0..32)
                .ok_or(anyhow::anyhow!("EXTENDED message too short"))?,
        );

        debug!(
            "Middle: Got next hop public key for circuit {}",
            self.context.circuit_id
        );

        Ok(Some(msg))
    }

    /// Handle EXTEND message (from entry node asking us to extend to exit node)
    ///
    /// The EXTEND payload arrives encrypted with our session key (forward direction).
    /// We decrypt it to get the address and public key, then connect to the next hop.
    /// The EXTENDED response is encrypted with our backward key before returning.
    async fn handle_extend(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Middle: Received EXTEND for circuit {}",
            self.context.circuit_id
        );

        // Decrypt the EXTEND payload with our stateful cipher (forward direction)
        let cipher_pair = self
            .context
            .cipher_pair
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No cipher pair established for EXTEND"))?;

        let mut decrypted = msg.data.clone();
        cipher_pair.apply_forward(&mut decrypted);

        let null_pos = decrypted
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| anyhow::anyhow!("No null terminator in EXTEND address"))?;

        let addr_str = std::str::from_utf8(
            decrypted
                .get(0..null_pos)
                .ok_or(anyhow::anyhow!("Invalid EXTEND data"))?,
        )?;
        let addr: std::net::SocketAddr = addr_str.parse()?;

        let key_start = null_pos + 1;
        if decrypted.len() < key_start + 32 {
            return Err(anyhow::anyhow!("EXTEND message missing public key"));
        }

        let mut client_public = [0u8; 32];
        client_public.copy_from_slice(
            decrypted
                .get(key_start..key_start + 32)
                .ok_or(anyhow::anyhow!("EXTEND message missing public key"))?,
        );

        info!(
            "Middle: Extending to next hop at {} for circuit {}",
            addr, self.context.circuit_id
        );

        let mut stream = TcpStream::connect(addr).await?;
        debug!("Middle: Connected to next hop at {}", addr);

        let create_msg = Message::create(self.context.circuit_id, client_public.to_vec());

        create_msg.write_to_stream(&mut stream).await?;
        debug!("Middle: Sent CREATE to next hop");

        let created_msg = Message::from_stream(&mut stream)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Connection closed waiting for CREATED"))?;

        if created_msg.command != MessageCommand::Created {
            return Err(anyhow::anyhow!(
                "Expected CREATED, got {:?}",
                created_msg.command
            ));
        }

        if created_msg.data.len() < 32 {
            return Err(anyhow::anyhow!("CREATED response too short"));
        }

        info!(
            "Middle: Forwarding exit node's public key back for circuit {}",
            self.context.circuit_id
        );

        self.next_hop = Some(NextHop::new(stream));

        if let Some(m) = &self.metrics {
            m.push_event(EventKind::CircuitExtended {
                circuit_id: self.context.circuit_id,
                next_hop: addr.to_string(),
            });
        }

        // Encrypt the EXTENDED response with our backward cipher
        let cipher_pair = self
            .context
            .cipher_pair
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No cipher pair established"))?;

        let mut encrypted_response = created_msg.data.clone();
        cipher_pair.apply_backward(&mut encrypted_response);

        Ok(Some(Message::extended(
            self.context.circuit_id,
            encrypted_response,
        )))
    }

    /// Handle CREATE message (from previous hop establishing circuit with us)
    async fn handle_create(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Middle: Received CREATE for circuit {}",
            self.context.circuit_id
        );

        if msg.data.len() < 32 {
            return Err(anyhow::anyhow!("CREATE message too short"));
        }

        let mut client_public = [0u8; 32];
        client_public.copy_from_slice(
            msg.data
                .get(0..32)
                .ok_or(anyhow::anyhow!("CREATE message too short"))?,
        );

        let shared_secret = self.keypair.diffie_hellman(&client_public);
        let session_key = derive_session_key(&shared_secret);
        self.context.activate(session_key.clone());

        info!(
            "Middle: Established session for circuit {}",
            self.context.circuit_id
        );

        Ok(Some(Message::created(
            self.context.circuit_id,
            self.keypair.public_key().bytes.to_vec(),
        )))
    }

    /// Handle relay cell (encrypted data)
    /// Decrypt one layer and forward to next hop (forward direction)
    /// OR encrypt one layer and forward to previous hop (backward direction)
    async fn handle_relay(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        debug!(
            "Middle: Relaying data for circuit {}",
            self.context.circuit_id
        );

        let cipher_pair = self
            .context
            .cipher_pair
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No cipher pair established"))?;

        let mut decrypted = msg.data.clone();
        cipher_pair.apply_forward(&mut decrypted);

        if let Some(next_hop) = &mut self.next_hop {
            let mut relay_msg = Message::new(msg.circuit_id, msg.stream_id, msg.command, decrypted);
            relay_msg.digest = msg.digest; // pass through intact for exit to verify

            relay_msg.write_to_stream(&mut next_hop.write).await?;
            debug!("Middle: Forwarded relay cell to next hop");
        } else {
            error!(
                "Middle: No next hop configured for circuit {}",
                self.context.circuit_id
            );
        }

        Ok(None)
    }

    /// Handle backward relay cell (data coming back from exit node)
    /// Encrypt one layer and return to previous hop
    pub async fn handle_backward_relay(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        debug!(
            "Middle: Handling backward relay for circuit {}",
            self.context.circuit_id
        );

        let cipher_pair = self
            .context
            .cipher_pair
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No cipher pair established"))?;

        let mut encrypted = msg.data.clone();
        cipher_pair.apply_backward(&mut encrypted);

        let mut response = Message::new(msg.circuit_id, msg.stream_id, msg.command, encrypted);
        response.digest = msg.digest; // pass through intact for client to verify
        Ok(Some(response))
    }

    /// Handle an incoming message on this circuit
    /// Returns optional response message to send back
    pub async fn handle_message(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        match msg.command {
            MessageCommand::Create => self.handle_create(msg).await,
            MessageCommand::Extend => self.handle_extend(msg).await,
            MessageCommand::Extended => self.handle_extended(msg).await,
            MessageCommand::Data
            | MessageCommand::Begin
            | MessageCommand::End
            | MessageCommand::Connected => self.handle_relay(msg).await,
            MessageCommand::Destroy => {
                info!("Middle: Circuit {} destroyed", self.context.circuit_id);
                self.close();
                Ok(None)
            }
            _ => {
                error!(
                    "Middle: Unexpected command {:?} for circuit {}",
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

    /// Spawn a background task to read responses from next hop (exit node)
    /// Returns the task handle
    pub fn spawn_nexthop_reader(
        &mut self,
        circuit_registry: Arc<Mutex<crate::circuit::handler::CircuitRegistry>>,
        prev_hop_write: Arc<Mutex<WriteHalf<TcpStream>>>,
        metrics: Arc<RelayMetrics>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let circuit_id = self.context.circuit_id;

        let mut read_half = self.next_hop.as_mut()?.take_read()?;

        info!(
            "Middle: Spawning background reader for circuit {}",
            circuit_id
        );

        Some(tokio::spawn(async move {
            loop {
                match Message::from_stream(&mut read_half).await {
                    Ok(Some(msg)) => {
                        debug!(
                            "Middle: Received backward message from next hop for circuit {}",
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
                                    error!("Middle: Error handling backward message: {}", e);
                                    break;
                                }
                            }
                        };

                        let mut writer = prev_hop_write.lock().await;
                        if let Err(e) = response.write_to_stream(&mut *writer).await {
                            error!(
                                "Middle: Error sending backward message to previous hop: {}",
                                e
                            );
                            break;
                        }
                        debug!("Middle: Sent backward message to previous hop");

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
                            "Middle: Next hop closed connection for circuit {}",
                            circuit_id
                        );
                        break;
                    }
                    Err(e) => {
                        error!("Middle: Error reading from next hop: {}", e);
                        break;
                    }
                }
            }
            info!(
                "Middle: Background reader task terminated for circuit {}",
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
    use common::crypto::{CipherPair, EphemeralKeyPair, derive_session_key};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_middle_create_handshake() {
        let keypair = KeyPair::generate();
        let mut handler = MiddleCircuitHandler::new(10, keypair.clone());

        // Entry node sends CREATE to middle
        let ephemeral = EphemeralKeyPair::generate();
        let create_msg = Message::create(10, ephemeral.public.bytes.to_vec());

        let response = handler.handle_create(create_msg).await.unwrap().unwrap();

        assert_eq!(response.command, MessageCommand::Created);
        assert_eq!(response.circuit_id, 10);
        assert_eq!(response.data.len(), 32);
        assert_eq!(handler.state(), CircuitState::Active);

        // Verify DH produces same key
        let mut middle_public = [0u8; 32];
        middle_public.copy_from_slice(&response.data[0..32]);
        let client_shared = ephemeral.diffie_hellman(&middle_public);
        let client_key = derive_session_key(&client_shared);
        assert_eq!(client_key, *handler.session_key().unwrap());
    }

    #[tokio::test]
    async fn test_middle_create_too_short() {
        let keypair = KeyPair::generate();
        let mut handler = MiddleCircuitHandler::new(10, keypair);

        let create_msg = Message::create(10, vec![0u8; 10]);
        let result = handler.handle_create(create_msg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_middle_backward_relay_encrypts() {
        let keypair = KeyPair::generate();
        let mut handler = MiddleCircuitHandler::new(10, keypair.clone());

        // Establish session
        let ephemeral = EphemeralKeyPair::generate();
        let create_msg = Message::create(10, ephemeral.public.bytes.to_vec());
        let created = handler.handle_create(create_msg).await.unwrap().unwrap();

        let mut middle_public = [0u8; 32];
        middle_public.copy_from_slice(&created.data[0..32]);
        let client_shared = ephemeral.diffie_hellman(&middle_public);
        let session_key = derive_session_key(&client_shared);

        // Backward DATA from exit
        let plaintext = b"response from exit";
        let backward_msg = Message::data(10, 3, plaintext.to_vec());

        let response = handler
            .handle_backward_relay(backward_msg)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(response.command, MessageCommand::Data);
        assert_eq!(response.stream_id, 3);

        // Should be decryptable with backward key using stateful CipherPair
        let mut client_cipher = CipherPair::new(&session_key);
        let mut decrypted = response.data.clone();
        client_cipher.apply_backward(&mut decrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_middle_backward_relay_no_session() {
        let keypair = KeyPair::generate();
        let mut handler = MiddleCircuitHandler::new(10, keypair);

        let msg = Message::data(10, 1, b"test".to_vec());
        let result = handler.handle_backward_relay(msg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_middle_destroy_closes_circuit() {
        let keypair = KeyPair::generate();
        let mut handler = MiddleCircuitHandler::new(10, keypair.clone());

        // Establish circuit
        let ephemeral = EphemeralKeyPair::generate();
        let create_msg = Message::create(10, ephemeral.public.bytes.to_vec());
        handler.handle_create(create_msg).await.unwrap();
        assert_eq!(handler.state(), CircuitState::Active);

        // Destroy
        let destroy_msg = Message::destroy(10);
        let result = handler.handle_message(destroy_msg).await.unwrap();
        assert!(result.is_none());
        assert_eq!(handler.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_middle_extend_to_exit_over_tcp() {
        // Set up a fake "exit node" listener
        let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let exit_addr = exit_listener.local_addr().unwrap();
        let exit_keypair = KeyPair::generate();
        let exit_public = exit_keypair.public_key().bytes;

        // Spawn fake exit node: expects CREATE, responds CREATED
        let exit_kp_clone = exit_keypair.clone();
        let exit_task = tokio::spawn(async move {
            let (mut stream, _) = exit_listener.accept().await.unwrap();
            let msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
            assert_eq!(msg.command, MessageCommand::Create);
            let created =
                Message::created(msg.circuit_id, exit_kp_clone.public_key().bytes.to_vec());
            stream.write_all(&created.to_bytes()).await.unwrap();
        });

        // Set up middle handler with session established
        let middle_keypair = KeyPair::generate();
        let mut handler = MiddleCircuitHandler::new(20, middle_keypair.clone());

        let ephemeral_mid = EphemeralKeyPair::generate();
        let create_msg = Message::create(20, ephemeral_mid.public.bytes.to_vec());
        let created = handler.handle_create(create_msg).await.unwrap().unwrap();

        let mut mid_public = [0u8; 32];
        mid_public.copy_from_slice(&created.data[0..32]);
        let mid_shared = ephemeral_mid.diffie_hellman(&mid_public);
        let middle_key = derive_session_key(&mid_shared);

        // Build EXTEND payload (for exit): "addr:port\0" + exit public key
        // Client would encrypt this; entry already decrypted one layer
        // Middle receives it encrypted with its forward key
        let ephemeral_exit = EphemeralKeyPair::generate();
        let addr_str = exit_addr.to_string();
        let mut extend_payload = Vec::new();
        extend_payload.extend_from_slice(addr_str.as_bytes());
        extend_payload.push(0);
        extend_payload.extend_from_slice(&ephemeral_exit.public.bytes);

        // Encrypt with middle's forward key using stateful CipherPair (simulating what the client did)
        let mut client_cipher = CipherPair::new(&middle_key);
        let mut encrypted = extend_payload.clone();
        client_cipher.apply_forward(&mut encrypted);

        let extend_msg = Message::extend(20, encrypted);
        let response = handler.handle_message(extend_msg).await.unwrap().unwrap();

        assert_eq!(response.command, MessageCommand::Extended);
        assert_eq!(response.circuit_id, 20);

        // Decrypt EXTENDED response with middle's backward key using stateful CipherPair
        let mut decrypted = response.data.clone();
        client_cipher.apply_backward(&mut decrypted);
        assert_eq!(decrypted.len(), 32);
        assert_eq!(&decrypted[..], &exit_public);

        exit_task.await.unwrap();
    }
}
