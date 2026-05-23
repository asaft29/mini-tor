use crate::circuit::handler::{CircuitContext, CircuitState};
use crate::core::keypair::KeyPair;
use crate::core::metrics::{EventKind, RelayMetrics};
use common::{
    RelayWriteHalf,
    crypto::{CipherPair, RunningDigest, SessionKey},
    metrics::Direction,
    protocol::{CircuitId, MAX_PAYLOAD_SIZE, Message, MessageCommand, StreamId},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

type DestinationTx = tokio::sync::mpsc::UnboundedSender<Vec<u8>>;

struct ExitStream {
    destination: String,
    dest_tx: DestinationTx,
    _task_handle: tokio::task::JoinHandle<()>,
}

/// Combined crypto state for the exit node: cipher pair + running digests.
pub struct ExitCryptoState {
    pub cipher: CipherPair,
    pub forward_digest: RunningDigest,
    pub backward_digest: RunningDigest,
}

/// Exit node circuit handler — final hop, connects to the actual destination.
pub struct ExitCircuitHandler {
    context: CircuitContext,
    keypair: KeyPair,
    streams: HashMap<StreamId, ExitStream>,
    metrics: Option<Arc<RelayMetrics>>,
    shared_state: Option<Arc<Mutex<ExitCryptoState>>>,
}

impl ExitCircuitHandler {
    pub fn new(circuit_id: CircuitId, keypair: KeyPair) -> Self {
        Self {
            context: CircuitContext::new(circuit_id),
            keypair,
            streams: HashMap::new(),
            metrics: None,
            shared_state: None,
        }
    }

    pub fn set_metrics(&mut self, metrics: Arc<RelayMetrics>) {
        self.metrics = Some(metrics);
    }

    async fn handle_create(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Exit: Received CREATE for circuit {}",
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

        let cipher_pair = self
            .context
            .cipher_pair
            .take()
            .ok_or_else(|| anyhow::anyhow!("CipherPair not created during activate"))?;
        self.shared_state = Some(Arc::new(Mutex::new(ExitCryptoState {
            cipher: cipher_pair,
            forward_digest: RunningDigest::new(),
            backward_digest: RunningDigest::new(),
        })));

        info!(
            "Exit: Established session for circuit {}",
            self.context.circuit_id
        );

        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&server_eph_pub);
        payload.extend_from_slice(&auth);

        Ok(Some(Message::created(self.context.circuit_id, payload)))
    }

    async fn handle_begin(
        &mut self,
        msg: Message,
        prev_hop_write: Arc<Mutex<RelayWriteHalf>>,
    ) -> anyhow::Result<Option<Message>> {
        info!(
            "Exit: Received BEGIN for circuit {} stream {}",
            self.context.circuit_id, msg.stream_id
        );

        let shared_state = self
            .shared_state
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No crypto state established"))?
            .clone();

        let mut decrypted = msg.data.clone();
        {
            let mut state = shared_state.lock().await;
            state.cipher.apply_forward(&mut decrypted);

            if !state.forward_digest.verify(
                msg.stream_id,
                msg.command.to_u8(),
                &decrypted,
                msg.digest,
            ) {
                warn!(
                    "Exit: Digest mismatch on BEGIN for circuit {} stream {}",
                    self.context.circuit_id, msg.stream_id
                );
                return Err(anyhow::anyhow!("Digest mismatch on BEGIN"));
            }
        }

        let dest_str = std::str::from_utf8(&decrypted)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in destination: {}", e))?
            .trim_end_matches('\0');

        info!(
            "Exit: Connecting to destination {} for circuit {} stream {}",
            dest_str, self.context.circuit_id, msg.stream_id
        );

        match TcpStream::connect(dest_str).await {
            Ok(destination_stream) => {
                info!(
                    "Exit: Connected to {} for circuit {} stream {}",
                    dest_str, self.context.circuit_id, msg.stream_id
                );

                let connected_msg = Message::connected(self.context.circuit_id, msg.stream_id);
                let mut encrypted_data = connected_msg.data.clone();
                {
                    let mut state = shared_state.lock().await;
                    let digest = state.backward_digest.update(
                        msg.stream_id,
                        MessageCommand::Connected.to_u8(),
                        &encrypted_data,
                    );
                    state.cipher.apply_backward(&mut encrypted_data);
                    let mut response = Message::new(
                        self.context.circuit_id,
                        msg.stream_id,
                        MessageCommand::Connected,
                        encrypted_data,
                    );
                    response.digest = digest;

                    let mut writer = prev_hop_write.lock().await;
                    response.write_to_stream(&mut *writer).await?;
                }

                let (dest_tx, dest_rx) = tokio::sync::mpsc::unbounded_channel();

                let task_handle = self.spawn_stream_tasks(
                    msg.stream_id,
                    destination_stream,
                    shared_state.clone(),
                    prev_hop_write,
                    dest_rx,
                );

                let dest_string = dest_str.to_string();
                self.streams.insert(
                    msg.stream_id,
                    ExitStream {
                        destination: dest_string.clone(),
                        dest_tx,
                        _task_handle: task_handle,
                    },
                );

                if let Some(m) = &self.metrics {
                    m.streams_opened
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    m.push_event(EventKind::StreamOpened {
                        circuit_id: self.context.circuit_id,
                        stream_id: msg.stream_id,
                        destination: dest_string,
                    });
                }

                Ok(None)
            }
            Err(e) => {
                error!("Exit: Failed to connect to {}: {}", dest_str, e);

                let mut end_data = format!("Connection failed: {}", e).into_bytes();
                let digest;
                {
                    let mut state = shared_state.lock().await;
                    digest = state.backward_digest.update(
                        msg.stream_id,
                        MessageCommand::End.to_u8(),
                        &end_data,
                    );
                    state.cipher.apply_backward(&mut end_data);
                }
                let mut response = Message::end(self.context.circuit_id, msg.stream_id, end_data);
                response.digest = digest;
                Ok(Some(response))
            }
        }
    }

    fn spawn_stream_tasks(
        &self,
        stream_id: StreamId,
        destination_stream: TcpStream,
        shared_state: Arc<Mutex<ExitCryptoState>>,
        prev_hop_write: Arc<Mutex<RelayWriteHalf>>,
        mut dest_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> tokio::task::JoinHandle<()> {
        let circuit_id = self.context.circuit_id;
        let metrics = self.metrics.clone();

        let (mut read_half, mut write_half) = tokio::io::split(destination_stream);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];

            loop {
                tokio::select! {
                    read_result = read_half.read(&mut buf) => {
                        match read_result {
                            Ok(0) => {
                                info!("Exit: Destination closed for circuit {} stream {}", circuit_id, stream_id);

                                let mut end_payload = Vec::new();
                                let mut state = shared_state.lock().await;
                                let digest = state.backward_digest.update(
                                    stream_id,
                                    MessageCommand::End.to_u8(),
                                    &end_payload,
                                );
                                state.cipher.apply_backward(&mut end_payload);
                                let mut end_msg = Message::end(circuit_id, stream_id, end_payload);
                                end_msg.digest = digest;

                                let mut writer = prev_hop_write.lock().await;
                                let _ = end_msg.write_to_stream(&mut *writer).await;
                                drop(writer);
                                drop(state);

                                if let Some(m) = &metrics {
                                    m.push_event(EventKind::StreamClosed {
                                        circuit_id,
                                        stream_id,
                                    });
                                }
                                break;
                            }
                            Ok(n) => {
                                debug!("Exit: Read {} bytes from destination for circuit {} stream {}", n, circuit_id, stream_id);

                                let Some(data_slice) = buf.get(..n) else {
                                    error!("Exit: Buffer slice out of bounds: {} for circuit {} stream {}", n, circuit_id, stream_id);
                                    break;
                                };

                                let mut send_failed = false;
                                for chunk in data_slice.chunks(MAX_PAYLOAD_SIZE) {
                                    let mut encrypted = chunk.to_vec();
                                    let mut state = shared_state.lock().await;
                                    let digest = state.backward_digest.update(
                                        stream_id,
                                        MessageCommand::Data.to_u8(),
                                        &encrypted,
                                    );
                                    state.cipher.apply_backward(&mut encrypted);

                                    let mut data_msg = Message::data(circuit_id, stream_id, encrypted);
                                    data_msg.digest = digest;

                                    let mut writer = prev_hop_write.lock().await;
                                    if let Err(e) = data_msg.write_to_stream(&mut *writer).await {
                                        error!("Exit: Failed to send backward message for circuit {} stream {}: {}", circuit_id, stream_id, e);
                                        send_failed = true;
                                        break;
                                    }
                                    drop(writer);
                                    drop(state);
                                }
                                if send_failed {
                                    break;
                                }
                                debug!("Exit: Sent {} bytes back to middle node (chunked)", n);

                                if let Some(m) = &metrics {
                                    m.bytes_received.fetch_add(
                                        n as u64,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                                    m.push_event(EventKind::StreamData {
                                        circuit_id,
                                        stream_id,
                                        bytes: n,
                                        direction: Direction::Backward,
                                    });
                                }
                            }
                            Err(e) => {
                                error!("Exit: Error reading from destination for circuit {} stream {}: {}", circuit_id, stream_id, e);

                                let mut end_data = format!("Read error: {}", e).into_bytes();
                                let mut state = shared_state.lock().await;
                                let digest = state.backward_digest.update(
                                    stream_id,
                                    MessageCommand::End.to_u8(),
                                    &end_data,
                                );
                                state.cipher.apply_backward(&mut end_data);
                                let mut end_msg = Message::end(circuit_id, stream_id, end_data);
                                end_msg.digest = digest;

                                let mut writer = prev_hop_write.lock().await;
                                let _ = end_msg.write_to_stream(&mut *writer).await;
                                drop(writer);
                                drop(state);
                                break;
                            }
                        }
                    }

                    msg = dest_rx.recv() => {
                        match msg {
                            Some(data) => {
                                if write_half.write_all(&data).await.is_err() {
                                    break;
                                }
                            }
                            _ => {
                                debug!("Exit: Control channel closed, stopping stream task");
                                break;
                            }
                        }
                    }
                }
            }

            info!(
                "Exit: Stream task terminated for circuit {} stream {}",
                circuit_id, stream_id
            );
        })
    }

    async fn handle_data(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        debug!(
            "Exit: Received DATA for circuit {} stream {}",
            self.context.circuit_id, msg.stream_id
        );

        let shared_state = self
            .shared_state
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No crypto state established"))?
            .clone();

        let mut decrypted = msg.data.clone();
        {
            let mut state = shared_state.lock().await;
            state.cipher.apply_forward(&mut decrypted);

            if !state.forward_digest.verify(
                msg.stream_id,
                msg.command.to_u8(),
                &decrypted,
                msg.digest,
            ) {
                warn!(
                    "Exit: Digest mismatch on DATA for circuit {} stream {}",
                    self.context.circuit_id, msg.stream_id
                );
                return Err(anyhow::anyhow!("Digest mismatch on DATA"));
            }
        }

        if let Some(exit_stream) = self.streams.get(&msg.stream_id) {
            if exit_stream.dest_tx.send(decrypted.clone()).is_err() {
                error!(
                    "Exit: Destination task closed for circuit {} stream {}",
                    self.context.circuit_id, msg.stream_id
                );

                let mut end_data = b"Destination closed".to_vec();
                let digest;
                {
                    let mut state = shared_state.lock().await;
                    digest = state.backward_digest.update(
                        msg.stream_id,
                        MessageCommand::End.to_u8(),
                        &end_data,
                    );
                    state.cipher.apply_backward(&mut end_data);
                }
                let mut response = Message::end(self.context.circuit_id, msg.stream_id, end_data);
                response.digest = digest;
                return Ok(Some(response));
            }
            let data_len = decrypted.len();
            debug!(
                "Exit: Queued {} bytes to destination {}",
                data_len, exit_stream.destination
            );

            if let Some(m) = &self.metrics {
                m.bytes_forwarded
                    .fetch_add(data_len as u64, std::sync::atomic::Ordering::Relaxed);
                m.push_event(EventKind::StreamData {
                    circuit_id: self.context.circuit_id,
                    stream_id: msg.stream_id,
                    bytes: data_len,
                    direction: Direction::Forward,
                });
            }

            Ok(None)
        } else {
            error!(
                "Exit: No stream {} for circuit {}",
                msg.stream_id, self.context.circuit_id
            );

            let mut end_data = b"Stream not found".to_vec();
            let digest;
            {
                let mut state = shared_state.lock().await;
                digest = state.backward_digest.update(
                    msg.stream_id,
                    MessageCommand::End.to_u8(),
                    &end_data,
                );
                state.cipher.apply_backward(&mut end_data);
            }
            let mut response = Message::end(self.context.circuit_id, msg.stream_id, end_data);
            response.digest = digest;
            Ok(Some(response))
        }
    }

    /// Handle END message. MUST decrypt and verify forward digest even for empty
    /// payloads to keep the running digest in sync with the client.
    async fn handle_end(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Exit: Received END for circuit {} stream {}",
            self.context.circuit_id, msg.stream_id
        );

        let shared_state = self
            .shared_state
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No crypto state established"))?
            .clone();

        let mut decrypted = msg.data.clone();
        {
            let mut state = shared_state.lock().await;
            state.cipher.apply_forward(&mut decrypted);

            if !state.forward_digest.verify(
                msg.stream_id,
                msg.command.to_u8(),
                &decrypted,
                msg.digest,
            ) {
                warn!(
                    "Exit: Digest mismatch on END for circuit {} stream {}",
                    self.context.circuit_id, msg.stream_id
                );
                return Err(anyhow::anyhow!("Digest mismatch on END"));
            }
        }

        if let Some(exit_stream) = self.streams.remove(&msg.stream_id) {
            info!("Exit: Closed connection to {}", exit_stream.destination);
        } else {
            warn!(
                "Exit: No stream {} to close for circuit {}",
                msg.stream_id, self.context.circuit_id
            );
        }

        if let Some(m) = &self.metrics {
            m.push_event(EventKind::StreamClosed {
                circuit_id: self.context.circuit_id,
                stream_id: msg.stream_id,
            });
        }

        let mut encrypted_data = Vec::new();
        let digest;
        {
            let mut state = shared_state.lock().await;
            digest = state.backward_digest.update(
                msg.stream_id,
                MessageCommand::End.to_u8(),
                &encrypted_data,
            );
            state.cipher.apply_backward(&mut encrypted_data);
        }
        let mut response = Message::end(self.context.circuit_id, msg.stream_id, encrypted_data);
        response.digest = digest;
        Ok(Some(response))
    }

    pub async fn handle_message(
        &mut self,
        msg: Message,
        prev_hop_write: Option<Arc<Mutex<RelayWriteHalf>>>,
    ) -> anyhow::Result<Option<Message>> {
        match msg.command {
            MessageCommand::Create => self.handle_create(msg).await,
            MessageCommand::Begin => {
                let writer =
                    prev_hop_write.ok_or_else(|| anyhow::anyhow!("No prev_hop_write for BEGIN"))?;
                self.handle_begin(msg, writer).await
            }
            MessageCommand::Data => self.handle_data(msg).await,
            MessageCommand::End => self.handle_end(msg).await,
            MessageCommand::Destroy => {
                info!("Exit: Circuit {} destroyed", self.context.circuit_id);
                self.close();
                Ok(None)
            }
            MessageCommand::Padding => Ok(None),
            _ => {
                error!(
                    "Exit: Unexpected command {:?} for circuit {}",
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
        self.streams.clear();
        self.shared_state = None;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::circuit::handler::CircuitState;
    use common::RelayStream;
    use common::crypto::{CipherPair, NtorEphemeralKeyPair, RunningDigest, ntor_client_finish_raw};
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;

    async fn setup_exit_handler(
        handler: &mut ExitCircuitHandler,
        relay_static_pub: &[u8; 32],
    ) -> (SessionKey, CipherPair, RunningDigest) {
        let client_eph = NtorEphemeralKeyPair::generate();
        let client_pub = client_eph.public.bytes;
        let create_msg = Message::create(handler.circuit_id(), client_pub.to_vec());

        let created = handler.handle_create(create_msg).await.unwrap().unwrap();
        assert_eq!(created.data.len(), 64);

        let mut server_eph_pub = [0u8; 32];
        server_eph_pub.copy_from_slice(&created.data[0..32]);
        let mut auth = [0u8; 32];
        auth.copy_from_slice(&created.data[32..64]);

        let key = ntor_client_finish_raw(
            client_eph.secret_bytes(),
            &client_pub,
            relay_static_pub,
            &server_eph_pub,
            &auth,
        )
        .unwrap();
        let cipher = CipherPair::new(&key);
        let digest = RunningDigest::new();
        (key, cipher, digest)
    }

    #[tokio::test]
    async fn test_exit_create_handshake() {
        let keypair = KeyPair::generate();
        let mut handler = ExitCircuitHandler::new(100, keypair.clone());

        let client_eph = NtorEphemeralKeyPair::generate();
        let client_pub = client_eph.public.bytes;
        let create_msg = Message::create(100, client_pub.to_vec());
        let response = handler.handle_create(create_msg).await.unwrap().unwrap();

        assert_eq!(response.command, MessageCommand::Created);
        assert_eq!(response.circuit_id, 100);
        assert_eq!(response.data.len(), 64);
        assert_eq!(handler.state(), CircuitState::Active);

        let mut server_eph_pub = [0u8; 32];
        server_eph_pub.copy_from_slice(&response.data[0..32]);
        let mut auth = [0u8; 32];
        auth.copy_from_slice(&response.data[32..64]);

        let client_key = ntor_client_finish_raw(
            client_eph.secret_bytes(),
            &client_pub,
            &keypair.public_key().bytes,
            &server_eph_pub,
            &auth,
        )
        .unwrap();
        assert_eq!(client_key, *handler.session_key().unwrap());
    }

    #[tokio::test]
    async fn test_exit_create_too_short() {
        let keypair = KeyPair::generate();
        let mut handler = ExitCircuitHandler::new(100, keypair);

        let create_msg = Message::create(100, vec![0u8; 5]);
        let result = handler.handle_create(create_msg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_exit_data_unknown_stream_returns_end() {
        let keypair = KeyPair::generate();
        let mut handler = ExitCircuitHandler::new(100, keypair.clone());
        let (_session_key, mut client_cipher, mut client_digest) =
            setup_exit_handler(&mut handler, &keypair.public_key().bytes).await;

        let plaintext = b"hello";
        let digest = client_digest.update(99, MessageCommand::Data.to_u8(), plaintext);
        let mut encrypted_data = plaintext.to_vec();
        client_cipher.apply_forward(&mut encrypted_data);
        let mut data_msg = Message::data(100, 99, encrypted_data);
        data_msg.digest = digest;

        let response = handler
            .handle_message(data_msg, None)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(response.command, MessageCommand::End);
        assert_eq!(response.stream_id, 99);
        let mut decrypted = response.data.clone();
        client_cipher.apply_backward(&mut decrypted);
        assert!(
            String::from_utf8_lossy(&decrypted).contains("Stream not found"),
            "Expected 'Stream not found', got: {}",
            String::from_utf8_lossy(&decrypted)
        );
    }

    #[tokio::test]
    async fn test_exit_end_unknown_stream() {
        let keypair = KeyPair::generate();
        let mut handler = ExitCircuitHandler::new(100, keypair.clone());
        let (_session_key, mut client_cipher, mut client_digest) =
            setup_exit_handler(&mut handler, &keypair.public_key().bytes).await;

        let plaintext: &[u8] = &[];
        let digest = client_digest.update(55, MessageCommand::End.to_u8(), plaintext);
        let mut encrypted = plaintext.to_vec();
        client_cipher.apply_forward(&mut encrypted);
        let mut end_msg = Message::end(100, 55, encrypted);
        end_msg.digest = digest;

        let response = handler
            .handle_message(end_msg, None)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(response.command, MessageCommand::End);
        assert_eq!(response.stream_id, 55);
    }

    #[tokio::test]
    async fn test_exit_destroy_clears_streams() {
        let keypair = KeyPair::generate();
        let mut handler = ExitCircuitHandler::new(100, keypair.clone());
        let (_, _, _) = setup_exit_handler(&mut handler, &keypair.public_key().bytes).await;

        assert_eq!(handler.state(), CircuitState::Active);
        assert!(handler.shared_state.is_some());

        let destroy_msg = Message::destroy(100);
        let result = handler.handle_message(destroy_msg, None).await.unwrap();
        assert!(result.is_none());
        assert_eq!(handler.state(), CircuitState::Closed);
        assert!(handler.shared_state.is_none());
    }

    #[tokio::test]
    async fn test_exit_begin_connects_to_destination() {
        let dest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest_listener.local_addr().unwrap();

        let dest_task = tokio::spawn(async move {
            let (_stream, _) = dest_listener.accept().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let keypair = KeyPair::generate();
        let mut handler = ExitCircuitHandler::new(100, keypair.clone());
        let (_session_key, mut client_cipher, mut client_digest) =
            setup_exit_handler(&mut handler, &keypair.public_key().bytes).await;

        let prev_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let prev_addr = prev_listener.local_addr().unwrap();
        let prev_connect =
            tokio::spawn(async move { TcpStream::connect(prev_addr).await.unwrap() });
        let (prev_server, _) = prev_listener.accept().await.unwrap();
        let mut prev_client = prev_connect.await.unwrap();
        let prev_boxed: RelayStream = Box::new(prev_server);
        let (_prev_read, prev_write) = tokio::io::split(prev_boxed);
        let prev_hop_write = Arc::new(Mutex::new(prev_write));

        let dest_str = format!("{}\0", dest_addr);
        let plaintext = dest_str.as_bytes();
        let digest = client_digest.update(1, MessageCommand::Begin.to_u8(), plaintext);
        let mut encrypted_dest = plaintext.to_vec();
        client_cipher.apply_forward(&mut encrypted_dest);
        let mut begin_msg = Message::begin(100, 1, encrypted_dest);
        begin_msg.digest = digest;

        let response = handler
            .handle_message(begin_msg, Some(prev_hop_write))
            .await
            .unwrap();
        assert!(
            response.is_none(),
            "handle_begin should return None (writes CONNECTED directly)"
        );

        let connected = Message::from_stream(&mut prev_client)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(connected.command, MessageCommand::Connected);
        assert_eq!(connected.circuit_id, 100);
        assert_eq!(connected.stream_id, 1);

        let mut decrypted = connected.data.clone();
        client_cipher.apply_backward(&mut decrypted);
        assert!(decrypted.is_empty());

        dest_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_exit_begin_unreachable_destination() {
        let keypair = KeyPair::generate();
        let mut handler = ExitCircuitHandler::new(100, keypair.clone());
        let (_session_key, mut client_cipher, mut client_digest) =
            setup_exit_handler(&mut handler, &keypair.public_key().bytes).await;

        let prev_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let prev_addr = prev_listener.local_addr().unwrap();
        let prev_connect =
            tokio::spawn(async move { TcpStream::connect(prev_addr).await.unwrap() });
        let (prev_server, _) = prev_listener.accept().await.unwrap();
        let _prev_client = prev_connect.await.unwrap();
        let prev_boxed: RelayStream = Box::new(prev_server);
        let (_prev_read, prev_write) = tokio::io::split(prev_boxed);
        let prev_hop_write = Arc::new(Mutex::new(prev_write));

        let dest_str = "127.0.0.1:1\0";
        let plaintext = dest_str.as_bytes();
        let digest = client_digest.update(2, MessageCommand::Begin.to_u8(), plaintext);
        let mut encrypted_dest = plaintext.to_vec();
        client_cipher.apply_forward(&mut encrypted_dest);
        let mut begin_msg = Message::begin(100, 2, encrypted_dest);
        begin_msg.digest = digest;

        let response = handler
            .handle_message(begin_msg, Some(prev_hop_write))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(response.command, MessageCommand::End);
        assert_eq!(response.stream_id, 2);
    }
}
