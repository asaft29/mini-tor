use crate::circuit::handler::{CircuitContext, CircuitState};
use crate::keypair::KeyPair;
use common::{
    crypto::{SessionKey, aes_decrypt, aes_encrypt, derive_session_key},
    protocol::{CircuitId, Message, MessageCommand, StreamId},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Channel for sending data to destination stream
type DestinationTx = tokio::sync::mpsc::UnboundedSender<Vec<u8>>;

/// Stream state for exit node
struct ExitStream {
    destination: String,
    dest_tx: DestinationTx,
    _task_handle: tokio::task::JoinHandle<()>,
}

/// Exit node circuit handler
/// Handles the final hop in a circuit
/// Connects to the actual destination on behalf of the client
pub struct ExitCircuitHandler {
    context: CircuitContext,
    keypair: KeyPair,
    /// Map of stream IDs to stream state
    streams: HashMap<StreamId, ExitStream>,
}

impl ExitCircuitHandler {
    /// Create a new exit circuit handler
    pub fn new(circuit_id: CircuitId, keypair: KeyPair) -> Self {
        Self {
            context: CircuitContext::new(circuit_id),
            keypair,
            streams: HashMap::new(),
        }
    }

    /// Handle CREATE message (establishing circuit with middle node)
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

        let shared_secret = self.keypair.diffie_hellman(&client_public);
        let session_key = derive_session_key(&shared_secret);
        self.context.activate(session_key.clone());

        info!(
            "Exit: Established session for circuit {}",
            self.context.circuit_id
        );

        Ok(Some(Message::created(
            self.context.circuit_id,
            self.keypair.public_key().bytes.to_vec(),
        )))
    }

    /// Handle BEGIN message (client wants to connect to a destination)
    async fn handle_begin(
        &mut self,
        msg: Message,
        prev_hop_stream: Arc<Mutex<TcpStream>>,
    ) -> anyhow::Result<Option<Message>> {
        info!(
            "Exit: Received BEGIN for circuit {} stream {}",
            self.context.circuit_id, msg.stream_id
        );

        let session_key = self
            .context
            .session_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No session key established"))?;

        let decrypted = aes_decrypt(&msg.data, &session_key.forward)?;

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

                let (dest_tx, dest_rx) = tokio::sync::mpsc::unbounded_channel();

                let task_handle = self.spawn_stream_tasks(
                    msg.stream_id,
                    destination_stream,
                    session_key.backward,
                    prev_hop_stream,
                    dest_rx,
                );

                self.streams.insert(
                    msg.stream_id,
                    ExitStream {
                        destination: dest_str.to_string(),
                        dest_tx,
                        _task_handle: task_handle,
                    },
                );

                // Encrypt CONNECTED response with backward key
                let connected_msg = Message::connected(self.context.circuit_id, msg.stream_id);
                let encrypted_data = aes_encrypt(&connected_msg.data, &session_key.backward);
                Ok(Some(Message::new(
                    self.context.circuit_id,
                    msg.stream_id,
                    MessageCommand::Connected,
                    encrypted_data,
                )))
            }
            Err(e) => {
                error!("Exit: Failed to connect to {}: {}", dest_str, e);

                // Encrypt END response with backward key
                let end_data = format!("Connection failed: {}", e).into_bytes();
                let encrypted_data = aes_encrypt(&end_data, &session_key.backward);
                Ok(Some(Message::end(
                    self.context.circuit_id,
                    msg.stream_id,
                    encrypted_data,
                )))
            }
        }
    }

    /// Spawn background tasks for bidirectional stream communication
    fn spawn_stream_tasks(
        &self,
        stream_id: StreamId,
        destination_stream: TcpStream,
        backward_key: [u8; 16],
        prev_hop_stream: Arc<Mutex<TcpStream>>,
        mut dest_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> tokio::task::JoinHandle<()> {
        let circuit_id = self.context.circuit_id;

        let (mut read_half, mut write_half) = tokio::io::split(destination_stream);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];

            loop {
                tokio::select! {
                    read_result = read_half.read(&mut buf) => {
                        match read_result {
                            Ok(0) => {
                                info!("Exit: Destination closed for circuit {} stream {}", circuit_id, stream_id);

                                let encrypted_data = aes_encrypt(&[], &backward_key);
                                let end_msg = Message::end(circuit_id, stream_id, encrypted_data);

                                let bytes = end_msg.to_bytes();
                                let mut stream = prev_hop_stream.lock().await;
                                let _ = stream.write_all(&bytes).await;
                                break;
                            }
                            Ok(n) => {
                                debug!("Exit: Read {} bytes from destination for circuit {} stream {}", n, circuit_id, stream_id);

                                let Some(data_slice) = buf.get(..n) else {
                                    error!("Exit: Buffer slice out of bounds: {} for circuit {} stream {}", n, circuit_id, stream_id);
                                    break;
                                };

                                let encrypted = aes_encrypt(data_slice, &backward_key);
                                let encrypted_len = encrypted.len();

                                let data_msg = Message::data(circuit_id, stream_id, encrypted);

                                let bytes = data_msg.to_bytes();
                                let mut stream = prev_hop_stream.lock().await;
                                if let Err(e) = stream.write_all(&bytes).await {
                                    error!("Exit: Failed to send backward message for circuit {} stream {}: {}", circuit_id, stream_id, e);
                                    break;
                                }
                                debug!("Exit: Sent {} encrypted bytes back to middle node", encrypted_len);
                            }
                            Err(e) => {
                                error!("Exit: Error reading from destination for circuit {} stream {}: {}", circuit_id, stream_id, e);

                                let end_data = format!("Read error: {}", e).into_bytes();
                                let encrypted_data = aes_encrypt(&end_data, &backward_key);
                                let end_msg = Message::end(
                                    circuit_id,
                                    stream_id,
                                    encrypted_data,
                                );

                                let bytes = end_msg.to_bytes();
                                let mut stream = prev_hop_stream.lock().await;
                                let _ = stream.write_all(&bytes).await;
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

    /// Handle DATA message (relay data to destination)
    async fn handle_data(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        debug!(
            "Exit: Received DATA for circuit {} stream {}",
            self.context.circuit_id, msg.stream_id
        );

        let session_key = self
            .context
            .session_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No session key established"))?;

        let decrypted = aes_decrypt(&msg.data, &session_key.forward)?;

        if let Some(exit_stream) = self.streams.get(&msg.stream_id) {
            if exit_stream.dest_tx.send(decrypted.clone()).is_err() {
                error!(
                    "Exit: Destination task closed for circuit {} stream {}",
                    self.context.circuit_id, msg.stream_id
                );

                let encrypted_data = aes_encrypt(b"Destination closed", &session_key.backward);
                return Ok(Some(Message::end(
                    self.context.circuit_id,
                    msg.stream_id,
                    encrypted_data,
                )));
            }
            debug!(
                "Exit: Queued {} bytes to destination {}",
                decrypted.len(),
                exit_stream.destination
            );

            Ok(None)
        } else {
            error!(
                "Exit: No stream {} for circuit {}",
                msg.stream_id, self.context.circuit_id
            );

            let encrypted_data = aes_encrypt(b"Stream not found", &session_key.backward);
            Ok(Some(Message::end(
                self.context.circuit_id,
                msg.stream_id,
                encrypted_data,
            )))
        }
    }

    /// Handle END message (close a stream)
    async fn handle_end(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Exit: Received END for circuit {} stream {}",
            self.context.circuit_id, msg.stream_id
        );

        if let Some(exit_stream) = self.streams.remove(&msg.stream_id) {
            info!("Exit: Closed connection to {}", exit_stream.destination);
        } else {
            warn!(
                "Exit: No stream {} to close for circuit {}",
                msg.stream_id, self.context.circuit_id
            );
        }

        let session_key = self
            .context
            .session_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No session key established"))?;

        let encrypted_data = aes_encrypt(&[], &session_key.backward);
        Ok(Some(Message::end(
            self.context.circuit_id,
            msg.stream_id,
            encrypted_data,
        )))
    }

    /// Handle an incoming message on this circuit
    /// Returns optional response message to send back
    pub async fn handle_message(
        &mut self,
        msg: Message,
        prev_hop_stream: Option<Arc<Mutex<TcpStream>>>,
    ) -> anyhow::Result<Option<Message>> {
        match msg.command {
            MessageCommand::Create => self.handle_create(msg).await,
            MessageCommand::Begin => {
                let stream = prev_hop_stream
                    .ok_or_else(|| anyhow::anyhow!("No prev_hop_stream for BEGIN"))?;
                self.handle_begin(msg, stream).await
            }
            MessageCommand::Data => self.handle_data(msg).await,
            MessageCommand::End => self.handle_end(msg).await,
            MessageCommand::Destroy => {
                info!("Exit: Circuit {} destroyed", self.context.circuit_id);
                self.close();
                Ok(None)
            }
            _ => {
                error!(
                    "Exit: Unexpected command {:?} for circuit {}",
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

    /// Close this circuit and all streams
    pub fn close(&mut self) {
        self.context.close();
        self.streams.clear();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::circuit::handler::CircuitState;
    use common::crypto::{EphemeralKeyPair, aes_decrypt, aes_encrypt, derive_session_key};
    use tokio::net::TcpListener;

    /// Helper: establish a session between client ephemeral key and exit handler,
    /// returning the client-side session key.
    async fn setup_exit_handler(handler: &mut ExitCircuitHandler) -> (SessionKey, [u8; 32]) {
        let ephemeral = EphemeralKeyPair::generate();
        let client_public = ephemeral.public.bytes;
        let create_msg = Message::create(handler.circuit_id(), client_public.to_vec());

        let created = handler.handle_create(create_msg).await.unwrap().unwrap();
        let mut exit_public = [0u8; 32];
        exit_public.copy_from_slice(&created.data[0..32]);
        let shared = ephemeral.diffie_hellman(&exit_public);
        let key = derive_session_key(&shared);
        (key, exit_public)
    }

    #[tokio::test]
    async fn test_exit_create_handshake() {
        let keypair = KeyPair::generate();
        let mut handler = ExitCircuitHandler::new(100, keypair.clone());

        let ephemeral = EphemeralKeyPair::generate();
        let create_msg = Message::create(100, ephemeral.public.bytes.to_vec());
        let response = handler.handle_create(create_msg).await.unwrap().unwrap();

        assert_eq!(response.command, MessageCommand::Created);
        assert_eq!(response.circuit_id, 100);
        assert_eq!(response.data.len(), 32);
        assert_eq!(handler.state(), CircuitState::Active);

        // Verify DH key agreement
        let mut exit_public = [0u8; 32];
        exit_public.copy_from_slice(&response.data[0..32]);
        let client_shared = ephemeral.diffie_hellman(&exit_public);
        let client_key = derive_session_key(&client_shared);
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
        let (session_key, _) = setup_exit_handler(&mut handler).await;

        // Send DATA for a stream that doesn't exist
        let encrypted_data = aes_encrypt(b"hello", &session_key.forward);
        let data_msg = Message::data(100, 99, encrypted_data);

        let response = handler
            .handle_message(data_msg, None)
            .await
            .unwrap()
            .unwrap();

        // Should return END with "Stream not found"
        assert_eq!(response.command, MessageCommand::End);
        assert_eq!(response.stream_id, 99);
        let decrypted = aes_decrypt(&response.data, &session_key.backward).unwrap();
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
        let (_session_key, _) = setup_exit_handler(&mut handler).await;

        // Send END for unknown stream — should still succeed
        let end_msg = Message::end(100, 55, vec![]);
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
        let _ = setup_exit_handler(&mut handler).await;

        assert_eq!(handler.state(), CircuitState::Active);

        let destroy_msg = Message::destroy(100);
        let result = handler.handle_message(destroy_msg, None).await.unwrap();
        assert!(result.is_none());
        assert_eq!(handler.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_exit_begin_connects_to_destination() {
        // Set up a fake destination server
        let dest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest_listener.local_addr().unwrap();

        // Spawn destination that accepts and does nothing (just stays alive briefly)
        let dest_task = tokio::spawn(async move {
            let (_stream, _) = dest_listener.accept().await.unwrap();
            // Keep connection alive for test
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let keypair = KeyPair::generate();
        let mut handler = ExitCircuitHandler::new(100, keypair.clone());
        let (session_key, _) = setup_exit_handler(&mut handler).await;

        // We need a prev_hop_stream for BEGIN
        let prev_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let prev_addr = prev_listener.local_addr().unwrap();
        let prev_connect =
            tokio::spawn(async move { TcpStream::connect(prev_addr).await.unwrap() });
        let (prev_server, _) = prev_listener.accept().await.unwrap();
        let _prev_client = prev_connect.await.unwrap();
        let prev_hop = Arc::new(Mutex::new(prev_server));

        // Build BEGIN payload: "host:port\0" encrypted with forward key
        let dest_str = format!("{}\0", dest_addr);
        let encrypted_dest = aes_encrypt(dest_str.as_bytes(), &session_key.forward);
        let begin_msg = Message::begin(100, 1, encrypted_dest);

        let response = handler
            .handle_message(begin_msg, Some(prev_hop))
            .await
            .unwrap()
            .unwrap();

        // Should return CONNECTED
        assert_eq!(response.command, MessageCommand::Connected);
        assert_eq!(response.circuit_id, 100);
        assert_eq!(response.stream_id, 1);

        // CONNECTED data is encrypted with backward key
        let decrypted = aes_decrypt(&response.data, &session_key.backward).unwrap();
        // CONNECTED data is empty (from Message::connected)
        assert!(decrypted.is_empty());

        dest_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_exit_begin_unreachable_destination() {
        let keypair = KeyPair::generate();
        let mut handler = ExitCircuitHandler::new(100, keypair.clone());
        let (session_key, _) = setup_exit_handler(&mut handler).await;

        // prev_hop_stream
        let prev_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let prev_addr = prev_listener.local_addr().unwrap();
        let prev_connect =
            tokio::spawn(async move { TcpStream::connect(prev_addr).await.unwrap() });
        let (prev_server, _) = prev_listener.accept().await.unwrap();
        let _prev_client = prev_connect.await.unwrap();
        let prev_hop = Arc::new(Mutex::new(prev_server));

        // Try to connect to an address that should refuse connections
        let dest_str = "127.0.0.1:1\0"; // port 1 is very unlikely to be open
        let encrypted_dest = aes_encrypt(dest_str.as_bytes(), &session_key.forward);
        let begin_msg = Message::begin(100, 2, encrypted_dest);

        let response = handler
            .handle_message(begin_msg, Some(prev_hop))
            .await
            .unwrap()
            .unwrap();

        // Should return END with connection failure reason
        assert_eq!(response.command, MessageCommand::End);
        assert_eq!(response.stream_id, 2);
    }
}
