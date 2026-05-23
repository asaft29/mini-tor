//! Integration tests for the Tor circuit builder (`CircuitBuilder`).
//!
//! These tests simulate relay nodes using in-process TCP+TLS listeners that
//! perform real ntor key exchange, validating the full telescopic
//! handshake (CREATE + 2 EXTENDs) over TLS.
//!
//! The simulated relays use `CipherPair` (stateful AES-CTR with IV=0) to
//! match the real relay implementation. The cipher state is accumulated
//! across handshake messages just like in production.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::doc_lazy_continuation
)]

use common::crypto::CipherPair;
use common::{
    Message, MessageCommand, NodeDescriptor, NodeType, PublicKey, RelayStream, RelayTlsConfig,
    server_name_from_addr,
};
use rand_core::OsRng;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tor_client::core::circuit::CircuitBuilder;
use tor_client::core::transport::TcpTlsTransport;
use tor_llcrypto::pk::curve25519::{PublicKey as X25519PublicKey, StaticSecret};

/// A relay's static identity keypair (persists for the relay's lifetime).
struct RelayIdentity {
    secret_bytes: [u8; 32],
    public_bytes: [u8; 32],
}

impl RelayIdentity {
    fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self {
            secret_bytes: secret.to_bytes(),
            public_bytes: *public.as_bytes(),
        }
    }
}

/// Simulate a relay ntor handshake: given the client's 32-byte ephemeral public key
/// and the relay's static identity, perform the server side of ntor.
/// Returns (server_ephemeral_pub || auth, session_key).
fn relay_ntor(
    client_ephemeral_pub: &[u8; 32],
    identity: &RelayIdentity,
) -> ([u8; 64], common::crypto::SessionKey) {
    let (server_eph_pub, auth, session_key) = common::crypto::ntor_server(
        &identity.secret_bytes,
        &identity.public_bytes,
        client_ephemeral_pub,
    );

    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(&server_eph_pub);
    payload[32..].copy_from_slice(&auth);

    (payload, session_key)
}

/// Accept a TLS connection on the given listener, perform TLS handshake,
/// and return the TLS stream boxed as a RelayStream.
async fn accept_tls(
    listener: &TcpListener,
    tls_acceptor: &Arc<dyn common::tls::StreamAcceptor>,
) -> (RelayStream, std::net::SocketAddr) {
    let (tcp_stream, addr) = listener.accept().await.unwrap();
    let stream: RelayStream = tls_acceptor.accept(tcp_stream).await.unwrap();
    (stream, addr)
}

/// Spawn a simulated entry node that handles:
/// 1. CREATE -> CREATED  (ntor handshake)
/// 2. EXTEND -> connects to next hop via TLS, forwards CREATE, receives CREATED,
///    encrypts CREATED payload with backward cipher, sends EXTENDED back
/// 3. Second EXTEND -> decrypts one layer (forward), forwards to middle,
///    reads EXTENDED from middle, adds backward layer, sends back
///
/// Uses stateful `CipherPair` matching real relay behavior.
async fn spawn_entry_relay(
    identity: RelayIdentity,
    tls_acceptor: Arc<dyn common::tls::StreamAcceptor>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = accept_tls(&listener, &tls_acceptor).await;

        // --- Step 1: Handle CREATE ---
        let create_msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
        assert_eq!(create_msg.command, MessageCommand::Create);

        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&create_msg.data[0..32]);
        let (created_payload, session_key) = relay_ntor(&client_pub, &identity);

        // Create stateful cipher pair (matches real entry.rs behavior)
        let mut cipher = CipherPair::new(&session_key);

        let created_msg = Message::created(create_msg.circuit_id, created_payload.to_vec());
        stream.write_all(&created_msg.to_bytes()).await.unwrap();

        // --- Step 2: Handle first EXTEND (to middle) ---
        let extend_msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
        assert_eq!(extend_msg.command, MessageCommand::Extend);

        // Decrypt the EXTEND payload with forward cipher (stateful)
        let mut decrypted = extend_msg.data.clone();
        cipher.apply_forward(&mut decrypted);

        // Parse 3-field format: addr\0key\0fingerprint
        let null_pos = decrypted.iter().position(|&b| b == 0).unwrap();
        let addr_str = std::str::from_utf8(&decrypted[..null_pos]).unwrap();
        let next_hop_addr: std::net::SocketAddr = addr_str.parse().unwrap();
        // Next 32 bytes after the first null separator are the ephemeral key
        let key_start = null_pos + 1;
        let inner_payload = &decrypted[key_start..key_start + 32];

        // Connect to middle node via TLS
        let middle_fingerprint = std::str::from_utf8(&decrypted[key_start + 33..]).unwrap();
        let middle_tcp = tokio::net::TcpStream::connect(next_hop_addr).await.unwrap();
        let connector = RelayTlsConfig::make_tls_connector(middle_fingerprint).unwrap();
        let server_name = server_name_from_addr(next_hop_addr);
        let middle_tls = connector.connect(server_name, middle_tcp).await.unwrap();
        let mut next_stream: RelayStream = Box::new(middle_tls);

        let forward_create = Message::create(extend_msg.circuit_id, inner_payload.to_vec());
        forward_create
            .write_to_stream(&mut next_stream)
            .await
            .unwrap();

        // Read CREATED from middle
        let created_from_middle = Message::from_stream(&mut next_stream)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(created_from_middle.command, MessageCommand::Created);

        // Encrypt CREATED payload with backward cipher, send as EXTENDED
        let mut encrypted = created_from_middle.data.clone();
        cipher.apply_backward(&mut encrypted);
        let extended_msg = Message::extended(extend_msg.circuit_id, encrypted);
        stream.write_all(&extended_msg.to_bytes()).await.unwrap();

        // --- Step 3: Handle second EXTEND (to exit) ---
        let extend2_msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
        assert_eq!(extend2_msg.command, MessageCommand::Extend);

        // Decrypt one layer with forward cipher (still has middle's layer)
        let mut after_entry = extend2_msg.data.clone();
        cipher.apply_forward(&mut after_entry);

        // Forward to middle as EXTEND
        let fwd_extend = Message::extend(extend2_msg.circuit_id, after_entry);
        fwd_extend.write_to_stream(&mut next_stream).await.unwrap();

        // Read EXTENDED from middle
        let extended_from_middle = Message::from_stream(&mut next_stream)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(extended_from_middle.command, MessageCommand::Extended);

        // Add our backward layer
        let mut encrypted2 = extended_from_middle.data.clone();
        cipher.apply_backward(&mut encrypted2);
        let extended2_msg = Message::extended(extend2_msg.circuit_id, encrypted2);
        stream.write_all(&extended2_msg.to_bytes()).await.unwrap();
    });

    addr
}

/// Spawn a simulated middle node that handles:
/// 1. CREATE -> CREATED (ntor handshake)
/// 2. EXTEND -> connects to exit via TLS, forwards CREATE, receives CREATED,
///    encrypts with backward cipher, sends EXTENDED
///
/// Uses stateful `CipherPair` matching real relay behavior.
async fn spawn_middle_relay(
    identity: RelayIdentity,
    tls_acceptor: Arc<dyn common::tls::StreamAcceptor>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = accept_tls(&listener, &tls_acceptor).await;

        // Handle CREATE
        let create_msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
        assert_eq!(create_msg.command, MessageCommand::Create);

        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&create_msg.data[0..32]);
        let (created_payload, session_key) = relay_ntor(&client_pub, &identity);

        // Create stateful cipher pair (matches real middle.rs behavior)
        let mut cipher = CipherPair::new(&session_key);

        let created_msg = Message::created(create_msg.circuit_id, created_payload.to_vec());
        stream.write_all(&created_msg.to_bytes()).await.unwrap();

        // Handle EXTEND (to exit)
        let extend_msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
        assert_eq!(extend_msg.command, MessageCommand::Extend);

        // Decrypt with forward cipher (stateful)
        let mut decrypted = extend_msg.data.clone();
        cipher.apply_forward(&mut decrypted);

        // Parse 3-field format: addr\0key\0fingerprint
        let null_pos = decrypted.iter().position(|&b| b == 0).unwrap();
        let addr_str = std::str::from_utf8(&decrypted[..null_pos]).unwrap();
        let exit_addr: std::net::SocketAddr = addr_str.parse().unwrap();
        let key_start = null_pos + 1;
        let inner_payload = &decrypted[key_start..key_start + 32];

        // Connect to exit node via TLS
        let exit_fingerprint = std::str::from_utf8(&decrypted[key_start + 33..]).unwrap();
        let exit_tcp = tokio::net::TcpStream::connect(exit_addr).await.unwrap();
        let connector = RelayTlsConfig::make_tls_connector(exit_fingerprint).unwrap();
        let server_name = server_name_from_addr(exit_addr);
        let exit_tls = connector.connect(server_name, exit_tcp).await.unwrap();
        let mut exit_stream: RelayStream = Box::new(exit_tls);

        let forward_create = Message::create(extend_msg.circuit_id, inner_payload.to_vec());
        forward_create
            .write_to_stream(&mut exit_stream)
            .await
            .unwrap();

        // Read CREATED from exit
        let created_from_exit = Message::from_stream(&mut exit_stream)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(created_from_exit.command, MessageCommand::Created);

        // Encrypt with backward cipher, send as EXTENDED
        let mut encrypted = created_from_exit.data.clone();
        cipher.apply_backward(&mut encrypted);
        let extended_msg = Message::extended(extend_msg.circuit_id, encrypted);
        stream.write_all(&extended_msg.to_bytes()).await.unwrap();
    });

    addr
}

/// Spawn a simulated exit node that handles:
/// 1. CREATE -> CREATED (ntor handshake only)
async fn spawn_exit_relay(
    identity: RelayIdentity,
    tls_acceptor: Arc<dyn common::tls::StreamAcceptor>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = accept_tls(&listener, &tls_acceptor).await;

        // Handle CREATE
        let create_msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
        assert_eq!(create_msg.command, MessageCommand::Create);

        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&create_msg.data[0..32]);
        let (created_payload, _session_key) = relay_ntor(&client_pub, &identity);

        let created_msg = Message::created(create_msg.circuit_id, created_payload.to_vec());
        stream.write_all(&created_msg.to_bytes()).await.unwrap();
    });

    addr
}

/// Helper: create a `NodeDescriptor` pointing to the given address with a real public key.
fn node_at(
    id: &str,
    node_type: NodeType,
    addr: std::net::SocketAddr,
    public_key: PublicKey,
    tls_cert_fingerprint: String,
) -> NodeDescriptor {
    let mut desc =
        NodeDescriptor::new(id.to_string(), node_type, addr, public_key, 1_000_000, None);
    desc.tls_cert_fingerprint = tls_cert_fingerprint;
    desc
}

/// Full 3-hop telescopic handshake: CREATE + 2 EXTENDs
#[tokio::test]
async fn test_full_telescopic_handshake() {
    // Generate static identity keypairs for each relay
    let entry_id = RelayIdentity::generate();
    let middle_id = RelayIdentity::generate();
    let exit_id = RelayIdentity::generate();

    // Extract public keys before moving identities into relay tasks
    let entry_pub = PublicKey::new(entry_id.public_bytes);
    let middle_pub = PublicKey::new(middle_id.public_bytes);
    let exit_pub = PublicKey::new(exit_id.public_bytes);

    // Generate TLS configs for each relay
    let entry_tls = RelayTlsConfig::generate("test-entry", "127.0.0.1:0".parse().unwrap()).unwrap();
    let middle_tls =
        RelayTlsConfig::generate("test-middle", "127.0.0.1:0".parse().unwrap()).unwrap();
    let exit_tls = RelayTlsConfig::generate("test-exit", "127.0.0.1:0".parse().unwrap()).unwrap();

    let entry_fp = entry_tls.fingerprint.clone();
    let middle_fp = middle_tls.fingerprint.clone();
    let exit_fp = exit_tls.fingerprint.clone();

    // Spawn simulated relays (order matters: exit first so its address is known)
    let exit_addr = spawn_exit_relay(exit_id, exit_tls.acceptor.clone()).await;
    let middle_addr = spawn_middle_relay(middle_id, middle_tls.acceptor.clone()).await;
    let entry_addr = spawn_entry_relay(entry_id, entry_tls.acceptor.clone()).await;

    let path = vec![
        node_at("entry", NodeType::Entry, entry_addr, entry_pub, entry_fp),
        node_at(
            "middle",
            NodeType::Middle,
            middle_addr,
            middle_pub,
            middle_fp,
        ),
        node_at("exit", NodeType::Exit, exit_addr, exit_pub, exit_fp),
    ];

    let built = CircuitBuilder::build(
        42,
        &path,
        &TcpTlsTransport,
        &common::crypto::TorNtorHandshaker,
    )
    .await
    .unwrap();

    // Circuit should be Ready with the correct ID
    assert_eq!(built.circuit.circuit_id, 42);
    assert_eq!(
        built.circuit.state,
        tor_client::core::circuit::CircuitState::Ready
    );

    // Onion keys should be populated — 3 hops with non-zero session keys
    assert_eq!(built.circuit.onion_keys.session_keys.len(), 3);
    assert_ne!(built.circuit.onion_keys.session_keys[0].forward, [0u8; 16]);
    assert_ne!(built.circuit.onion_keys.session_keys[1].forward, [0u8; 16]);
    assert_ne!(built.circuit.onion_keys.session_keys[2].forward, [0u8; 16]);
}

/// Path with wrong number of nodes should fail
#[tokio::test]
async fn test_build_rejects_wrong_path_length() {
    let path = vec![node_at(
        "entry",
        NodeType::Entry,
        "127.0.0.1:1".parse().unwrap(),
        PublicKey::new([0u8; 32]),
        String::new(),
    )];

    let result = CircuitBuilder::build(
        1,
        &path,
        &TcpTlsTransport,
        &common::crypto::TorNtorHandshaker,
    )
    .await;
    match result {
        Err(e) => {
            let err = format!("{e}");
            assert!(
                err.contains("at least 3 nodes"),
                "Expected path length error, got: {err}",
            );
        }
        Ok(_) => panic!("Expected error for wrong path length, but build succeeded"),
    }
}

/// Connection to unreachable entry node should fail
#[tokio::test]
async fn test_build_fails_on_unreachable_entry() {
    let path = vec![
        node_at(
            "entry",
            NodeType::Entry,
            "127.0.0.1:1".parse().unwrap(),
            PublicKey::new([0u8; 32]),
            String::new(),
        ),
        node_at(
            "middle",
            NodeType::Middle,
            "127.0.0.1:2".parse().unwrap(),
            PublicKey::new([0u8; 32]),
            String::new(),
        ),
        node_at(
            "exit",
            NodeType::Exit,
            "127.0.0.1:3".parse().unwrap(),
            PublicKey::new([0u8; 32]),
            String::new(),
        ),
    ];

    let result = CircuitBuilder::build(
        1,
        &path,
        &TcpTlsTransport,
        &common::crypto::TorNtorHandshaker,
    )
    .await;
    assert!(result.is_err());
}
