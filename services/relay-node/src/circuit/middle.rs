use crate::circuit::handler::{CircuitContext, CircuitState, NextHop};
use crate::keypair::KeyPair;
use crate::metrics::{EventKind, RelayMetrics};
use common::{
    crypto::SessionKey,
    protocol::{CircuitId, Message, MessageCommand},
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info};

/// How long a relay waits for CREATED from the next hop before giving up.
/// Must be less than the client's HANDSHAKE_TIMEOUT (30s) so the relay can
/// return a clean error rather than the client timing out with a confusing message.
const RELAY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Middle node circuit handler — second hop, knows neither client nor destination.
pub struct MiddleCircuitHandler {
    context: CircuitContext,
    keypair: KeyPair,
    next_hop: Option<NextHop>,
    metrics: Option<Arc<RelayMetrics>>,
}

impl MiddleCircuitHandler {
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

    /// Handle EXTEND: decrypt payload, connect to next hop, return EXTENDED.
    async fn handle_extend(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Middle: Received EXTEND for circuit {}",
            self.context.circuit_id
        );

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

        let created_msg =
            tokio::time::timeout(RELAY_HANDSHAKE_TIMEOUT, Message::from_stream(&mut stream))
                .await
                .map_err(|_| anyhow::anyhow!("Timed out waiting for CREATED from {}", addr))?
                .map_err(|e| anyhow::anyhow!("Error reading CREATED from {}: {}", addr, e))?
                .ok_or_else(|| {
                    anyhow::anyhow!("Connection closed waiting for CREATED from {}", addr)
                })?;

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

        let (server_eph_pub, auth, session_key) =
            self.keypair.ntor_server_handshake(&client_public);
        self.context.activate(session_key.clone());

        info!(
            "Middle: Established session for circuit {}",
            self.context.circuit_id
        );

        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&server_eph_pub);
        payload.extend_from_slice(&auth);

        Ok(Some(Message::created(self.context.circuit_id, payload)))
    }

    /// Peel one forward layer and relay to next hop.
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
            relay_msg.digest = msg.digest;

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

    /// Encrypt one backward layer and return to previous hop.
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
        response.digest = msg.digest;
        Ok(Some(response))
    }

    pub async fn handle_message(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        match msg.command {
            MessageCommand::Create => self.handle_create(msg).await,
            MessageCommand::Extend => {
                if self.next_hop.is_some() {
                    debug!(
                        "Middle: Relaying EXTEND to next hop for circuit {}",
                        self.context.circuit_id
                    );
                    self.handle_relay(msg).await
                } else {
                    self.handle_extend(msg).await
                }
            }
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
            MessageCommand::Padding => Ok(None),
            _ => {
                error!(
                    "Middle: Unexpected command {:?} for circuit {}",
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
            // Downstream (exit) closed — send DESTROY upstream toward entry then shut down.
            {
                let mut writer = prev_hop_write.lock().await;
                let _ = Message::destroy(circuit_id)
                    .write_to_stream(&mut *writer)
                    .await;
                let _ = writer.shutdown().await;
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
    use common::crypto::{CipherPair, NtorEphemeralKeyPair, ntor_client_finish_raw};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn do_ntor_create(
        handler: &mut MiddleCircuitHandler,
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
    async fn test_middle_create_handshake() {
        let keypair = KeyPair::generate();
        let mut handler = MiddleCircuitHandler::new(10, keypair.clone());

        let (response, client_key) =
            do_ntor_create(&mut handler, 10, &keypair.public_key().bytes).await;

        assert_eq!(response.command, MessageCommand::Created);
        assert_eq!(response.circuit_id, 10);
        assert_eq!(response.data.len(), 64);
        assert_eq!(handler.state(), CircuitState::Active);

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

        let (_, session_key) = do_ntor_create(&mut handler, 10, &keypair.public_key().bytes).await;

        let plaintext = b"response from exit";
        let backward_msg = Message::data(10, 3, plaintext.to_vec());

        let response = handler
            .handle_backward_relay(backward_msg)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(response.command, MessageCommand::Data);
        assert_eq!(response.stream_id, 3);

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

        let client_eph = NtorEphemeralKeyPair::generate();
        let create_msg = Message::create(10, client_eph.public.bytes.to_vec());
        handler.handle_create(create_msg).await.unwrap();
        assert_eq!(handler.state(), CircuitState::Active);

        let destroy_msg = Message::destroy(10);
        let result = handler.handle_message(destroy_msg).await.unwrap();
        assert!(result.is_none());
        assert_eq!(handler.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_middle_extend_to_exit_over_tcp() {
        let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let exit_addr = exit_listener.local_addr().unwrap();
        let exit_keypair = KeyPair::generate();

        let exit_kp_clone = exit_keypair.clone();
        let exit_task = tokio::spawn(async move {
            let (mut stream, _) = exit_listener.accept().await.unwrap();
            let msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
            assert_eq!(msg.command, MessageCommand::Create);

            let mut client_pub = [0u8; 32];
            client_pub.copy_from_slice(&msg.data[0..32]);
            let (server_eph_pub, auth, _key) = exit_kp_clone.ntor_server_handshake(&client_pub);

            let mut payload = Vec::with_capacity(64);
            payload.extend_from_slice(&server_eph_pub);
            payload.extend_from_slice(&auth);
            let created = Message::created(msg.circuit_id, payload);
            stream.write_all(&created.to_bytes()).await.unwrap();
        });

        let middle_keypair = KeyPair::generate();
        let mut handler = MiddleCircuitHandler::new(20, middle_keypair.clone());

        let (_, middle_key) =
            do_ntor_create(&mut handler, 20, &middle_keypair.public_key().bytes).await;

        let ephemeral_exit = NtorEphemeralKeyPair::generate();
        let addr_str = exit_addr.to_string();
        let mut extend_payload = Vec::new();
        extend_payload.extend_from_slice(addr_str.as_bytes());
        extend_payload.push(0);
        extend_payload.extend_from_slice(&ephemeral_exit.public.bytes);

        let mut client_cipher = CipherPair::new(&middle_key);
        let mut encrypted = extend_payload.clone();
        client_cipher.apply_forward(&mut encrypted);

        let extend_msg = Message::extend(20, encrypted);
        let response = handler.handle_message(extend_msg).await.unwrap().unwrap();

        assert_eq!(response.command, MessageCommand::Extended);
        assert_eq!(response.circuit_id, 20);

        let mut decrypted = response.data.clone();
        client_cipher.apply_backward(&mut decrypted);
        assert_eq!(decrypted.len(), 64);

        let mut exit_eph_pub = [0u8; 32];
        exit_eph_pub.copy_from_slice(&decrypted[0..32]);
        let mut auth = [0u8; 32];
        auth.copy_from_slice(&decrypted[32..64]);

        let exit_key = ntor_client_finish_raw(
            ephemeral_exit.secret_bytes(),
            &ephemeral_exit.public.bytes,
            &exit_keypair.public_key().bytes,
            &exit_eph_pub,
            &auth,
        )
        .unwrap();

        assert_ne!(exit_key.forward, [0u8; 16]);

        exit_task.await.unwrap();
    }
}
