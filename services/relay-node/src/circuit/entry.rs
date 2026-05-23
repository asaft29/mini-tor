use crate::circuit::handler::{CircuitContext, CircuitState, NextHop};
use crate::core::keypair::KeyPair;
use crate::core::metrics::{EventKind, RelayMetrics};
use common::{
    RelayStream, RelayTlsConfig, RelayWriteHalf,
    crypto::SessionKey,
    protocol::{CircuitId, Message, MessageCommand},
    server_name_from_addr,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info};

/// How long a relay waits for CREATED from the next hop before giving up.
const RELAY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Entry node circuit handler — first hop, knows the client but NOT the destination.
pub struct EntryCircuitHandler {
    context: CircuitContext,
    keypair: KeyPair,
    next_hop: Option<NextHop>,
    metrics: Option<Arc<RelayMetrics>>,
}

impl EntryCircuitHandler {
    pub fn new(circuit_id: CircuitId, keypair: KeyPair) -> Self {
        Self {
            context: CircuitContext::new(circuit_id),
            keypair,
            next_hop: None,
            metrics: None,
        }
    }

    pub fn set_metrics(&mut self, metrics: Arc<RelayMetrics>) {
        self.metrics = Some(metrics);
    }

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

        debug!("Entry: Client public key: {:02x?}...", &client_public[..8]);

        let (server_eph_pub, auth, session_key) =
            self.keypair.ntor_server_handshake(&client_public);
        debug!("Entry: ntor handshake complete");

        self.context.activate(session_key.clone());

        info!("Entry: Circuit {} activated", self.context.circuit_id);

        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&server_eph_pub);
        payload.extend_from_slice(&auth);

        let response = Message::created(self.context.circuit_id, payload);

        Ok(Some(response))
    }

    async fn handle_extend(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Entry: Handling EXTEND for circuit {}",
            self.context.circuit_id
        );

        let cipher_pair = self
            .context
            .cipher_pair
            .as_mut()
            .ok_or(anyhow::anyhow!("Circuit not yet established"))?;

        let mut decrypted = msg.data.clone();
        cipher_pair.apply_forward(&mut decrypted);

        if decrypted.len() < 33 {
            return Err(anyhow::anyhow!("EXTEND payload too short"));
        }

        let addr_end = decrypted
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| anyhow::anyhow!("EXTEND payload missing address separator"))?;

        let addr_bytes = decrypted
            .get(0..addr_end)
            .ok_or_else(|| anyhow::anyhow!("Invalid address in EXTEND payload"))?;
        let addr_str = std::str::from_utf8(addr_bytes)?;

        let key_start = addr_end + 1;
        let key_end = key_start + 32;
        if key_end > decrypted.len() {
            return Err(anyhow::anyhow!(
                "EXTEND payload too short for ephemeral key"
            ));
        }
        let mut client_public = [0u8; 32];
        client_public.copy_from_slice(
            decrypted
                .get(key_start..key_end)
                .ok_or_else(|| anyhow::anyhow!("Invalid ephemeral key in EXTEND payload"))?,
        );

        let fp_start = decrypted
            .get(key_end)
            .ok_or_else(|| anyhow::anyhow!("EXTEND payload missing fingerprint separator"))?;
        if *fp_start != 0 {
            return Err(anyhow::anyhow!(
                "EXTEND payload missing fingerprint separator"
            ));
        }
        let fp_bytes = decrypted
            .get(key_end + 1..)
            .ok_or_else(|| anyhow::anyhow!("EXTEND payload missing TLS fingerprint"))?;
        let fingerprint = std::str::from_utf8(fp_bytes)?;

        info!(
            "Entry: Extending to next hop: {} (fingerprint: {})",
            addr_str, fingerprint
        );

        let addr: SocketAddr = addr_str.parse()?;
        let tcp_stream = TcpStream::connect(addr).await?;
        let connector = RelayTlsConfig::make_tls_connector(fingerprint)?;
        let server_name = server_name_from_addr(addr);
        let tls_stream = connector.connect(server_name, tcp_stream).await?;
        let mut next_hop_stream: RelayStream = Box::new(tls_stream);

        info!("Entry: Connected to next hop {} via TLS", addr_str);

        let create_msg = Message::create(self.context.circuit_id, client_public.to_vec());

        create_msg.write_to_stream(&mut next_hop_stream).await?;
        debug!("Entry: Sent CREATE to next hop");

        let created_msg = tokio::time::timeout(
            RELAY_HANDSHAKE_TIMEOUT,
            Message::from_stream(&mut next_hop_stream),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for CREATED from {}", addr_str))?
        .map_err(|e| anyhow::anyhow!("Error reading CREATED from {}: {}", addr_str, e))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Next hop closed connection waiting for CREATED from {}",
                addr_str
            )
        })?;

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

        let cipher_pair = self
            .context
            .cipher_pair
            .as_mut()
            .ok_or(anyhow::anyhow!("No cipher pair established"))?;

        let mut encrypted_data = response.data.clone();
        cipher_pair.apply_backward(&mut encrypted_data);
        let encrypted_response = Message::extended(self.context.circuit_id, encrypted_data);

        Ok(Some(encrypted_response))
    }

    async fn handle_relay(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        debug!(
            "Entry: Handling relay cell for circuit {}",
            self.context.circuit_id
        );

        let cipher_pair = self
            .context
            .cipher_pair
            .as_mut()
            .ok_or(anyhow::anyhow!("Circuit not yet established"))?;

        let mut decrypted = msg.data.clone();
        cipher_pair.apply_forward(&mut decrypted);

        if let Some(next_hop) = &mut self.next_hop {
            let mut forward_msg =
                Message::new(msg.circuit_id, msg.stream_id, msg.command, decrypted);
            forward_msg.digest = msg.digest;

            forward_msg.write_to_stream(&mut next_hop.write).await?;

            debug!("Entry: Forwarded cell to next hop");
        } else {
            error!(
                "Entry: No next hop configured for circuit {}",
                self.context.circuit_id
            );
        }

        Ok(None)
    }

    /// Encrypt one backward layer and return to client.
    pub async fn handle_backward_relay(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        debug!(
            "Entry: Handling backward relay for circuit {}",
            self.context.circuit_id
        );

        let cipher_pair = self
            .context
            .cipher_pair
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No session key established"))?;

        let mut encrypted = msg.data.clone();
        cipher_pair.apply_backward(&mut encrypted);

        let mut response = Message::new(msg.circuit_id, msg.stream_id, msg.command, encrypted);
        response.digest = msg.digest;
        Ok(Some(response))
    }

    pub async fn handle_message(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        match msg.command {
            MessageCommand::Create => self.handle_create(msg).await,
            MessageCommand::Extend => {
                if self.next_hop.is_some() {
                    debug!(
                        "Entry: Relaying EXTEND to next hop for circuit {}",
                        self.context.circuit_id
                    );
                    self.handle_relay(msg).await
                } else {
                    self.handle_extend(msg).await
                }
            }
            MessageCommand::Data
            | MessageCommand::Begin
            | MessageCommand::End
            | MessageCommand::Connected => self.handle_relay(msg).await,
            MessageCommand::Destroy => {
                info!("Entry: Circuit {} destroyed", self.context.circuit_id);
                self.close();
                Ok(None)
            }
            MessageCommand::Padding => Ok(None),
            _ => {
                error!(
                    "Entry: Unexpected command {:?} for circuit {}",
                    msg.command, self.context.circuit_id
                );
                Err(anyhow::anyhow!("Unexpected command: {:?}", msg.command))
            }
        }
    }

    #[allow(dead_code)]
    pub fn circuit_id(&self) -> CircuitId {
        self.context.circuit_id
    }

    #[allow(dead_code)]
    pub fn state(&self) -> CircuitState {
        self.context.state
    }

    #[allow(dead_code)]
    pub fn session_key(&self) -> Option<&SessionKey> {
        self.context.session_key.as_ref()
    }

    pub fn close(&mut self) {
        self.context.close();
        self.next_hop = None;
    }

    pub fn spawn_nexthop_reader(
        &mut self,
        circuit_registry: Arc<Mutex<crate::circuit::handler::CircuitRegistry>>,
        client_write: Arc<Mutex<RelayWriteHalf>>,
        metrics: Arc<RelayMetrics>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let circuit_id = self.context.circuit_id;

        let mut read_half = self.next_hop.as_mut()?.take_read()?;

        info!(
            "Entry: Spawning background reader for circuit {}",
            circuit_id
        );

        Some(tokio::spawn(async move {
            let mut destroy_sent = false;
            loop {
                match Message::from_stream(&mut read_half).await {
                    Ok(Some(msg)) => {
                        debug!(
                            "Entry: Received backward message from next hop for circuit {}",
                            circuit_id
                        );

                        // DESTROY from middle — propagate upstream to client and shut down.
                        if msg.command == MessageCommand::Destroy {
                            let mut writer = client_write.lock().await;
                            let _ = Message::destroy(circuit_id)
                                .write_to_stream(&mut *writer)
                                .await;
                            let _ = writer.shutdown().await;
                            destroy_sent = true;
                            break;
                        }

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

                        let mut writer = client_write.lock().await;
                        if let Err(e) = response.write_to_stream(&mut *writer).await {
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
            // Downstream (middle) closed without DESTROY — notify client and shut down.
            if !destroy_sent {
                let mut writer = client_write.lock().await;
                let _ = Message::destroy(circuit_id)
                    .write_to_stream(&mut *writer)
                    .await;
                let _ = writer.shutdown().await;
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
    use common::crypto::{CipherPair, NtorEphemeralKeyPair, ntor_client_finish_raw};
    use common::{RelayStream, RelayTlsConfig};
    use tokio::net::TcpListener;

    async fn do_ntor_create(
        handler: &mut EntryCircuitHandler,
        circuit_id: u32,
        relay_static_pub: &[u8; 32],
    ) -> (Message, SessionKey) {
        let client_eph = NtorEphemeralKeyPair::generate();
        let client_pub = client_eph.public.bytes;
        let create_msg = Message::create(circuit_id, client_pub.to_vec());
        let created = handler.handle_create(create_msg).await.unwrap().unwrap();

        assert_eq!(created.data.len(), 64);
        let mut server_eph_pub = [0u8; 32];
        server_eph_pub.copy_from_slice(&created.data[0..32]);
        let mut auth = [0u8; 32];
        auth.copy_from_slice(&created.data[32..64]);

        let client_key = ntor_client_finish_raw(
            client_eph.secret_bytes(),
            &client_pub,
            relay_static_pub,
            &server_eph_pub,
            &auth,
        )
        .unwrap();

        (created, client_key)
    }

    #[tokio::test]
    async fn test_entry_create_handshake() {
        let keypair = KeyPair::generate();
        let mut handler = EntryCircuitHandler::new(1, keypair.clone());

        let (response, client_key) =
            do_ntor_create(&mut handler, 1, &keypair.public_key().bytes).await;

        assert_eq!(response.command, MessageCommand::Created);
        assert_eq!(response.circuit_id, 1);
        assert_eq!(response.data.len(), 64);
        assert_eq!(handler.state(), CircuitState::Active);
        assert!(handler.session_key().is_some());

        let relay_key = handler.session_key().unwrap();
        assert_eq!(client_key, *relay_key);
    }

    #[tokio::test]
    async fn test_entry_create_too_short() {
        let keypair = KeyPair::generate();
        let mut handler = EntryCircuitHandler::new(1, keypair);

        let create_msg = Message::create(1, vec![0u8; 16]);
        let result = handler.handle_create(create_msg).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[tokio::test]
    async fn test_entry_backward_relay_encrypts() {
        let keypair = KeyPair::generate();
        let mut handler = EntryCircuitHandler::new(1, keypair.clone());

        let (_, client_key) = do_ntor_create(&mut handler, 1, &keypair.public_key().bytes).await;

        let plaintext = b"Hello from exit node";
        let backward_msg = Message::data(1, 5, plaintext.to_vec());

        let response = handler
            .handle_backward_relay(backward_msg)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(response.command, MessageCommand::Data);
        assert_eq!(response.circuit_id, 1);
        assert_eq!(response.stream_id, 5);

        let mut client_cipher = CipherPair::new(&client_key);
        let mut decrypted = response.data.clone();
        client_cipher.apply_backward(&mut decrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_entry_backward_relay_no_session_key() {
        let keypair = KeyPair::generate();
        let mut handler = EntryCircuitHandler::new(1, keypair);

        let msg = Message::data(1, 1, b"test".to_vec());
        let result = handler.handle_backward_relay(msg).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No session key"));
    }

    #[tokio::test]
    async fn test_entry_destroy_closes_circuit() {
        let keypair = KeyPair::generate();
        let mut handler = EntryCircuitHandler::new(1, keypair.clone());

        let client_eph = NtorEphemeralKeyPair::generate();
        let create_msg = Message::create(1, client_eph.public.bytes.to_vec());
        handler.handle_create(create_msg).await.unwrap();

        assert_eq!(handler.state(), CircuitState::Active);

        let destroy_msg = Message::destroy(1);
        let result = handler.handle_message(destroy_msg).await.unwrap();

        assert!(result.is_none());
        assert_eq!(handler.state(), CircuitState::Closed);
        assert!(handler.session_key().is_none());
    }

    #[tokio::test]
    async fn test_entry_extend_to_middle_over_tls() {
        let middle_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let middle_addr = middle_listener.local_addr().unwrap();
        let middle_keypair = KeyPair::generate();
        let middle_static_pub = middle_keypair.public_key().bytes;

        let middle_tls_config = RelayTlsConfig::generate("test-middle", middle_addr).unwrap();
        let middle_fingerprint = middle_tls_config.fingerprint.clone();
        let middle_acceptor = middle_tls_config.acceptor.clone();

        let middle_kp_clone = middle_keypair.clone();
        let middle_task = tokio::spawn(async move {
            let (tcp_stream, _) = middle_listener.accept().await.unwrap();
            let tls_stream = middle_acceptor.accept(tcp_stream).await.unwrap();
            let mut stream: RelayStream = Box::new(tls_stream);
            let msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
            assert_eq!(msg.command, MessageCommand::Create);

            let mut client_pub = [0u8; 32];
            client_pub.copy_from_slice(&msg.data[0..32]);
            let (server_eph_pub, auth, _key) = middle_kp_clone.ntor_server_handshake(&client_pub);

            let mut payload = Vec::with_capacity(64);
            payload.extend_from_slice(&server_eph_pub);
            payload.extend_from_slice(&auth);
            let created = Message::created(msg.circuit_id, payload);
            created.write_to_stream(&mut stream).await.unwrap();
        });

        let entry_keypair = KeyPair::generate();
        let mut handler = EntryCircuitHandler::new(42, entry_keypair.clone());

        let (_, entry_key) =
            do_ntor_create(&mut handler, 42, &entry_keypair.public_key().bytes).await;
        let mut client_cipher = CipherPair::new(&entry_key);

        let middle_client_eph = NtorEphemeralKeyPair::generate();
        let addr_str = middle_addr.to_string();
        let mut extend_payload = Vec::new();
        extend_payload.extend_from_slice(addr_str.as_bytes());
        extend_payload.push(0);
        extend_payload.extend_from_slice(&middle_client_eph.public.bytes);
        extend_payload.push(0);
        extend_payload.extend_from_slice(middle_fingerprint.as_bytes());

        let mut encrypted_payload = extend_payload.clone();
        client_cipher.apply_forward(&mut encrypted_payload);

        let extend_msg = Message::extend(42, encrypted_payload);
        let response = handler.handle_message(extend_msg).await.unwrap().unwrap();

        assert_eq!(response.command, MessageCommand::Extended);
        assert_eq!(response.circuit_id, 42);

        let mut decrypted = response.data.clone();
        client_cipher.apply_backward(&mut decrypted);

        assert_eq!(decrypted.len(), 64);

        let mut server_eph_pub = [0u8; 32];
        server_eph_pub.copy_from_slice(&decrypted[0..32]);
        let mut auth = [0u8; 32];
        auth.copy_from_slice(&decrypted[32..64]);

        let middle_key = ntor_client_finish_raw(
            middle_client_eph.secret_bytes(),
            &middle_client_eph.public.bytes,
            &middle_static_pub,
            &server_eph_pub,
            &auth,
        )
        .unwrap();

        assert_ne!(middle_key.forward, [0u8; 16]);

        middle_task.await.unwrap();
    }
}
