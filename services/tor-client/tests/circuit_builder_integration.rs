//! Integration tests for the Tor circuit builder (`CircuitBuilder`).
//!
//! These tests simulate relay nodes using in-process TCP listeners that
//! perform real Diffie-Hellman key exchange, validating the full telescopic
//! handshake (CREATE + 2 EXTENDs) over loopback.
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

use common::crypto::{CipherPair, derive_session_key};
use common::{Message, MessageCommand, NodeDescriptor, NodeType, PublicKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tor_client::circuit::CircuitBuilder;
use tor_llcrypto::pk::curve25519::{PublicKey as X25519PublicKey, StaticSecret};

/// Simulate a relay DH handshake: given the client's 32-byte public key,
/// generate a relay keypair, compute the shared secret, and return
/// (relay_public_bytes, session_key_from_relay_perspective).
fn relay_dh(client_public: &[u8; 32]) -> ([u8; 32], common::crypto::SessionKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    let relay_public_bytes: [u8; 32] = *public.as_bytes();

    let client_x25519 = X25519PublicKey::from(*client_public);
    let shared = secret.diffie_hellman(&client_x25519);

    let mut hasher = Sha256::new();
    hasher.update(shared.as_bytes());
    let hash = hasher.finalize();
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&hash);

    let session_key = derive_session_key(&key_bytes);
    (relay_public_bytes, session_key)
}

/// Spawn a simulated entry node that handles:
/// 1. CREATE -> CREATED  (DH handshake)
/// 2. EXTEND -> connects to next hop, forwards CREATE, receives CREATED,
///    encrypts CREATED payload with backward cipher, sends EXTENDED back
/// 3. Second EXTEND -> decrypts one layer (forward), forwards to middle,
///    reads EXTENDED from middle, adds backward layer, sends back
///
/// Uses stateful `CipherPair` matching real relay behavior.
async fn spawn_entry_relay() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // --- Step 1: Handle CREATE ---
        let create_msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
        assert_eq!(create_msg.command, MessageCommand::Create);

        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&create_msg.data[0..32]);
        let (relay_pub, session_key) = relay_dh(&client_pub);

        // Create stateful cipher pair (matches real entry.rs behavior)
        let mut cipher = CipherPair::new(&session_key);

        let created_msg = Message::created(create_msg.circuit_id, relay_pub.to_vec());
        stream.write_all(&created_msg.to_bytes()).await.unwrap();

        // --- Step 2: Handle first EXTEND (to middle) ---
        let extend_msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
        assert_eq!(extend_msg.command, MessageCommand::Extend);

        // Decrypt the EXTEND payload with forward cipher (stateful)
        let mut decrypted = extend_msg.data.clone();
        cipher.apply_forward(&mut decrypted);

        // Parse "addr:port\0" + public_key
        let null_pos = decrypted.iter().position(|&b| b == 0).unwrap();
        let addr_str = std::str::from_utf8(&decrypted[..null_pos]).unwrap();
        let next_hop_addr: std::net::SocketAddr = addr_str.parse().unwrap();
        let inner_payload = &decrypted[null_pos + 1..];

        // Connect to middle node and forward CREATE
        let mut next_stream = tokio::net::TcpStream::connect(next_hop_addr).await.unwrap();
        let forward_create = Message::create(extend_msg.circuit_id, inner_payload.to_vec());
        next_stream
            .write_all(&forward_create.to_bytes())
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
        next_stream.write_all(&fwd_extend.to_bytes()).await.unwrap();

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
/// 1. CREATE -> CREATED (DH handshake)
/// 2. EXTEND -> connects to exit, forwards CREATE, receives CREATED,
///    encrypts with backward cipher, sends EXTENDED
///
/// Uses stateful `CipherPair` matching real relay behavior.
async fn spawn_middle_relay() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Handle CREATE
        let create_msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
        assert_eq!(create_msg.command, MessageCommand::Create);

        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&create_msg.data[0..32]);
        let (relay_pub, session_key) = relay_dh(&client_pub);

        // Create stateful cipher pair (matches real middle.rs behavior)
        let mut cipher = CipherPair::new(&session_key);

        let created_msg = Message::created(create_msg.circuit_id, relay_pub.to_vec());
        stream.write_all(&created_msg.to_bytes()).await.unwrap();

        // Handle EXTEND (to exit)
        let extend_msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
        assert_eq!(extend_msg.command, MessageCommand::Extend);

        // Decrypt with forward cipher (stateful)
        let mut decrypted = extend_msg.data.clone();
        cipher.apply_forward(&mut decrypted);

        // Parse "addr:port\0" + public_key
        let null_pos = decrypted.iter().position(|&b| b == 0).unwrap();
        let addr_str = std::str::from_utf8(&decrypted[..null_pos]).unwrap();
        let exit_addr: std::net::SocketAddr = addr_str.parse().unwrap();
        let inner_payload = &decrypted[null_pos + 1..];

        // Connect to exit node
        let mut exit_stream = tokio::net::TcpStream::connect(exit_addr).await.unwrap();
        let forward_create = Message::create(extend_msg.circuit_id, inner_payload.to_vec());
        exit_stream
            .write_all(&forward_create.to_bytes())
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
/// 1. CREATE -> CREATED (DH handshake only)
async fn spawn_exit_relay() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Handle CREATE
        let create_msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
        assert_eq!(create_msg.command, MessageCommand::Create);

        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&create_msg.data[0..32]);
        let (relay_pub, _session_key) = relay_dh(&client_pub);

        let created_msg = Message::created(create_msg.circuit_id, relay_pub.to_vec());
        stream.write_all(&created_msg.to_bytes()).await.unwrap();
    });

    addr
}

/// Helper: create a `NodeDescriptor` pointing to the given address.
fn node_at(id: &str, node_type: NodeType, addr: std::net::SocketAddr) -> NodeDescriptor {
    NodeDescriptor::new(
        id.to_string(),
        node_type,
        addr,
        PublicKey::new([0u8; 32]), // Public key in descriptor unused by CircuitBuilder
        1_000_000,
        None,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Full 3-hop telescopic handshake: CREATE + 2 EXTENDs
#[tokio::test]
async fn test_full_telescopic_handshake() {
    // Spawn simulated relays (order matters: exit first so its address is known)
    let exit_addr = spawn_exit_relay().await;
    let middle_addr = spawn_middle_relay().await;
    let entry_addr = spawn_entry_relay().await;

    let path = vec![
        node_at("entry", NodeType::Entry, entry_addr),
        node_at("middle", NodeType::Middle, middle_addr),
        node_at("exit", NodeType::Exit, exit_addr),
    ];

    let built = CircuitBuilder::build(42, &path).await.unwrap();

    // Circuit should be Ready with the correct ID
    assert_eq!(built.circuit.circuit_id, 42);
    assert_eq!(
        built.circuit.state,
        tor_client::circuit::CircuitState::Ready
    );

    // Onion keys should be populated (non-zero)
    // Just check that the keys exist — the DH math is verified by the fact
    // that the handshake completed without errors
    assert_ne!(built.circuit.onion_keys.entry.forward, [0u8; 16]);
    assert_ne!(built.circuit.onion_keys.middle.forward, [0u8; 16]);
    assert_ne!(built.circuit.onion_keys.exit.forward, [0u8; 16]);
}

/// Path with wrong number of nodes should fail
#[tokio::test]
async fn test_build_rejects_wrong_path_length() {
    let path = vec![node_at(
        "entry",
        NodeType::Entry,
        "127.0.0.1:1".parse().unwrap(),
    )];

    let result = CircuitBuilder::build(1, &path).await;
    match result {
        Err(e) => {
            let err = format!("{e}");
            assert!(
                err.contains("exactly 3 nodes"),
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
            "127.0.0.1:1".parse().unwrap(), // Unreachable
        ),
        node_at("middle", NodeType::Middle, "127.0.0.1:2".parse().unwrap()),
        node_at("exit", NodeType::Exit, "127.0.0.1:3".parse().unwrap()),
    ];

    let result = CircuitBuilder::build(1, &path).await;
    assert!(result.is_err());
}
