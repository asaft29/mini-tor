use aes::Aes128;
use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::anyhow;
use ctr::Ctr128BE;
use rand::Rng;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tor_llcrypto::pk::curve25519::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::PublicKey;

type Aes128Ctr = Ctr128BE<Aes128>;

/// Stateful AES-128-CTR cipher pair for a single circuit hop.
///
/// Holds persistent forward and backward stream ciphers initialized with IV=0
/// (matching real Tor). Encryption/decryption is an XOR with the keystream,
/// so the output is always the same size as the input — zero overhead per layer.
///
/// Created from a [`SessionKey`] after the DH handshake completes.
/// Must be used behind `&mut self` because each call advances the keystream.
pub struct CipherPair {
    forward: Aes128Ctr,
    backward: Aes128Ctr,
}

impl CipherPair {
    /// Create a new cipher pair from a session key.
    ///
    /// Both ciphers are initialized with IV = 0 (16 zero bytes).
    pub fn new(key: &SessionKey) -> Self {
        let zero_iv = [0u8; 16];
        Self {
            forward: Aes128Ctr::new(&key.forward.into(), &zero_iv.into()),
            backward: Aes128Ctr::new(&key.backward.into(), &zero_iv.into()),
        }
    }

    /// Apply the forward keystream in-place (encrypt or decrypt — same in CTR).
    ///
    /// Used on the **forward** path: client→destination encryption on the client side,
    /// and forward-direction decryption (layer peeling) on relay nodes.
    pub fn apply_forward(&mut self, data: &mut [u8]) {
        self.forward.apply_keystream(data);
    }

    /// Apply the backward keystream in-place (encrypt or decrypt — same in CTR).
    ///
    /// Used on the **backward** path: relay nodes encrypt responses with the backward
    /// key, and the client decrypts (peels layers) with backward keys.
    pub fn apply_backward(&mut self, data: &mut [u8]) {
        self.backward.apply_keystream(data);
    }
}

impl std::fmt::Debug for CipherPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherPair")
            .field("forward", &"<Aes128Ctr>")
            .field("backward", &"<Aes128Ctr>")
            .finish()
    }
}

/// Running SHA-256 digest for cell integrity verification.
///
/// Accumulates every relay cell's contents into a stateful SHA-256 hash.
/// The sender embeds the first 4 bytes of the current digest snapshot into
/// the cell's `digest` field. The receiver recomputes the same digest and
/// compares. A mismatch means the cell was tampered with in transit.
///
/// One `RunningDigest` is maintained per direction per circuit endpoint
/// (client forward, client backward, exit forward, exit backward).
/// Matching real Tor's "recognized" mechanism (spec section 6.1).
pub struct RunningDigest {
    state: Sha256,
}

impl RunningDigest {
    /// Create a fresh digest state (used after CREATE/CREATED handshake).
    pub fn new() -> Self {
        Self {
            state: Sha256::new(),
        }
    }

    /// Feed a cell's fields into the running digest and return the 4-byte snapshot.
    ///
    /// The caller should embed the returned bytes into the cell's `digest` field
    /// before encrypting and sending.
    pub fn update(&mut self, stream_id: u16, command: u8, data: &[u8]) -> [u8; 4] {
        self.state.update(stream_id.to_be_bytes());
        self.state.update([command]);
        self.state.update(data);

        // Take a snapshot of the current state (clone — does not reset)
        let snapshot = self.state.clone().finalize();
        let mut tag = [0u8; 4];
        tag.copy_from_slice(snapshot.get(..4).unwrap_or(&[0u8; 4]));
        tag
    }

    /// Verify a cell's digest by recomputing and comparing.
    ///
    /// Feeds the cell's fields into the running state (advancing it) and checks
    /// whether the first 4 bytes match `expected`. Returns `true` on match.
    ///
    /// **Important:** This advances the digest state regardless of whether
    /// verification succeeds — the state must stay in sync with the sender.
    pub fn verify(&mut self, stream_id: u16, command: u8, data: &[u8], expected: [u8; 4]) -> bool {
        let computed = self.update(stream_id, command, data);
        computed == expected
    }
}

impl Default for RunningDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RunningDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningDigest")
            .field("state", &"<Sha256>")
            .finish()
    }
}

/// Session key for encrypted communication between nodes
/// Contains separate keys for forward (client to server) and backward (server to client) communication
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKey {
    pub forward: [u8; 16],  // AES-128 key for forward direction
    pub backward: [u8; 16], // AES-128 key for backward direction
}

impl SessionKey {
    /// Create a new session key from forward and backward keys
    pub fn new(forward: [u8; 16], backward: [u8; 16]) -> Self {
        Self { forward, backward }
    }

    /// Create from a single shared key (derive forward and backward)
    /// This is a simplified approach - in production, use proper KDF
    pub fn from_shared(shared: &[u8; 32]) -> Self {
        let mut forward = [0u8; 16];
        let mut backward = [0u8; 16];

        forward.copy_from_slice(&shared[0..16]);
        backward.copy_from_slice(&shared[16..32]);

        Self { forward, backward }
    }

    /// Convert to 32-byte array (for storage/transmission)
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..16].copy_from_slice(&self.forward);
        bytes[16..32].copy_from_slice(&self.backward);
        bytes
    }

    /// Create from 32-byte array
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut forward = [0u8; 16];
        let mut backward = [0u8; 16];

        forward.copy_from_slice(&bytes[0..16]);
        backward.copy_from_slice(&bytes[16..32]);

        Self { forward, backward }
    }

    /// Create a zero key (for testing)
    pub fn zero() -> Self {
        Self {
            forward: [0u8; 16],
            backward: [0u8; 16],
        }
    }
}

impl Default for SessionKey {
    fn default() -> Self {
        Self::zero()
    }
}

/// Encrypt data using AES-128 in CTR mode
/// Returns encrypted data (same length as input)
pub fn aes_encrypt(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
    // 1. Generate a random 16-byte IV
    let mut iv = [0u8; 16];
    rand::rng().fill(&mut iv);

    // 2. Initialize cipher with the Key and random IV
    let mut cipher = Aes128Ctr::new(key.into(), &iv.into());

    // 3. Encrypt the data
    let mut ciphertext = data.to_vec();
    cipher.apply_keystream(&mut ciphertext);

    // 4. Prepend the IV to the output
    // Result format: [IV ... IV | Ciphertext ... Ciphertext]
    let mut output = Vec::with_capacity(16 + ciphertext.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&ciphertext);

    output
}

/// Decrypt data using AES-128 in CTR mode
/// Returns decrypted data (same length as input)
/// Note: CTR mode encryption and decryption are the same operation
///
/// # Errors
///
/// Returns an error if:
/// - The ciphertext is too short (< 16 bytes)
/// - The IV cannot be extracted from the data
pub fn aes_decrypt(data: &[u8], key: &[u8; 16]) -> anyhow::Result<Vec<u8>> {
    // 1. Validate length (must have at least the IV)
    if data.len() < 16 {
        return Err(anyhow!(
            "Invalid ciphertext: length {} is too short (min 16)",
            data.len()
        ));
    }

    // 2. Extract the IV (first 16 bytes)
    let iv_slice = data
        .get(0..16)
        .ok_or_else(|| anyhow!("Invalid ciphertext: missing IV (expected 16 bytes)"))?;
    let ciphertext = data
        .get(16..)
        .ok_or_else(|| anyhow!("Invalid ciphertext: missing encrypted data"))?;

    // 3. Initialize cipher with the Key and EXTRACTED IV
    let mut cipher = Aes128Ctr::new(key.into(), iv_slice.into());

    // 4. Decrypt (CTR decryption is the same operation as encryption)
    let mut plaintext = ciphertext.to_vec();
    cipher.apply_keystream(&mut plaintext);

    Ok(plaintext)
}

/// Derive session key from shared secret using SHA-256
/// Takes a 32-byte shared secret and produces forward/backward keys
pub fn derive_session_key(shared_secret: &[u8; 32]) -> SessionKey {
    SessionKey::from_shared(shared_secret)
}

/// Hash data using SHA-256
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Ephemeral key pair for client-side Diffie-Hellman key exchange
/// Uses X25519 via tor-llcrypto. Should be used once and discarded.
/// The client generates one ephemeral key pair per circuit hop.
pub struct EphemeralKeyPair {
    /// The public key (safe to share with relay nodes)
    pub public: PublicKey,
    secret: EphemeralSecret,
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral keypair (should be used once and discarded)
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_x25519 = X25519PublicKey::from(&secret);

        let public = PublicKey {
            bytes: *public_x25519.as_bytes(),
        };

        Self { public, secret }
    }

    /// Perform DH exchange with a relay's public key
    /// Consumes self since ephemeral keys should only be used once
    /// Returns the shared secret (SHA-256 hashed) that can be used to derive session keys
    pub fn diffie_hellman(self, their_public: &[u8; 32]) -> [u8; 32] {
        let their_public_key = X25519PublicKey::from(*their_public);
        let shared_secret = self.secret.diffie_hellman(&their_public_key);

        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        let result = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result);

        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_key_creation() {
        let forward = [1u8; 16];
        let backward = [2u8; 16];

        let key = SessionKey::new(forward, backward);

        assert_eq!(key.forward, forward);
        assert_eq!(key.backward, backward);
    }

    #[test]
    fn test_session_key_from_shared() {
        let shared = [0xAB; 32];
        let key = SessionKey::from_shared(&shared);

        assert_eq!(&key.forward, &shared[0..16]);
        assert_eq!(&key.backward, &shared[16..32]);
    }

    #[test]
    fn test_session_key_to_from_bytes() {
        let key = SessionKey::new([1u8; 16], [2u8; 16]);
        let bytes = key.to_bytes();
        let key2 = SessionKey::from_bytes(&bytes);

        assert_eq!(key, key2);
    }

    #[test]
    fn test_session_key_zero() {
        let key = SessionKey::zero();
        assert_eq!(key.forward, [0u8; 16]);
        assert_eq!(key.backward, [0u8; 16]);
    }

    #[test]
    fn test_session_key_default() {
        let key = SessionKey::default();
        assert_eq!(key, SessionKey::zero());
    }

    #[test]
    fn test_aes_encrypt_decrypt() -> anyhow::Result<()> {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let plaintext = b"Hello, World!";

        let ciphertext = aes_encrypt(plaintext, &key);
        assert_ne!(ciphertext, plaintext);

        let decrypted = aes_decrypt(&ciphertext, &key)?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_aes_ctr_symmetry() -> anyhow::Result<()> {
        let key = [42u8; 16];
        let data = b"This is a test message for AES-128 CTR mode";

        // Encrypt
        let encrypted = aes_encrypt(data, &key);

        // Decrypt (should be same as encrypt in CTR mode)
        let decrypted = aes_decrypt(&encrypted, &key)?;

        assert_eq!(&decrypted, data);
        Ok(())
    }

    #[test]
    fn test_derive_session_key() {
        let shared_secret = [0xAB; 32];
        let session_key = derive_session_key(&shared_secret);

        // Should derive consistent keys
        assert_eq!(
            session_key.forward,
            SessionKey::from_shared(&shared_secret).forward
        );
        assert_eq!(
            session_key.backward,
            SessionKey::from_shared(&shared_secret).backward
        );
    }

    #[test]
    fn test_sha256() {
        let data = b"test data";
        let hash1 = sha256(data);
        let hash2 = sha256(data);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);

        // Different input should produce different hash
        let hash3 = sha256(b"different data");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_cipher_pair_roundtrip() {
        let key = SessionKey::new([0xAA; 16], [0xBB; 16]);
        let mut encryptor = CipherPair::new(&key);
        let mut decryptor = CipherPair::new(&key);

        let plaintext = b"Hello stateful AES-CTR!";
        let mut buf = plaintext.to_vec();

        // Encrypt with forward
        encryptor.apply_forward(&mut buf);
        assert_ne!(buf, plaintext);

        // Decrypt with forward (same operation in CTR)
        decryptor.apply_forward(&mut buf);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn test_cipher_pair_stateful_continuity() {
        // Two consecutive encryptions must use different keystream positions
        let key = SessionKey::new([0x42; 16], [0x99; 16]);
        let mut cipher = CipherPair::new(&key);

        let mut buf1 = vec![0u8; 16];
        let mut buf2 = vec![0u8; 16];

        cipher.apply_forward(&mut buf1);
        cipher.apply_forward(&mut buf2);

        // Both are all-zero inputs but should produce different outputs
        // because the keystream has advanced
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_cipher_pair_zero_overhead() {
        let key = SessionKey::new([1u8; 16], [2u8; 16]);
        let mut cipher = CipherPair::new(&key);

        let data = b"exact same size";
        let mut buf = data.to_vec();
        let original_len = buf.len();

        cipher.apply_forward(&mut buf);

        // Output length must equal input length (zero overhead)
        assert_eq!(buf.len(), original_len);
    }

    #[test]
    fn test_cipher_pair_backward_direction() {
        let key = SessionKey::new([0xAA; 16], [0xBB; 16]);
        let mut encryptor = CipherPair::new(&key);
        let mut decryptor = CipherPair::new(&key);

        let plaintext = b"backward direction test";
        let mut buf = plaintext.to_vec();

        encryptor.apply_backward(&mut buf);
        assert_ne!(buf, plaintext);

        decryptor.apply_backward(&mut buf);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn test_running_digest_update_returns_4_bytes() {
        let mut digest = RunningDigest::new();
        let tag = digest.update(1, 0x12, b"hello");
        // Tag should be 4 bytes (non-zero for non-trivial input)
        assert_eq!(tag.len(), 4);
        assert_ne!(tag, [0u8; 4]);
    }

    #[test]
    fn test_running_digest_verify_matches() {
        let mut sender = RunningDigest::new();
        let mut receiver = RunningDigest::new();

        let tag = sender.update(1, 0x12, b"hello");
        assert!(receiver.verify(1, 0x12, b"hello", tag));
    }

    #[test]
    fn test_running_digest_verify_rejects_tampered() {
        let mut sender = RunningDigest::new();
        let mut receiver = RunningDigest::new();

        let tag = sender.update(1, 0x12, b"hello");
        // Tamper: different data on receiver side
        assert!(!receiver.verify(1, 0x12, b"tampered", tag));
    }

    #[test]
    fn test_running_digest_is_stateful() {
        let mut digest = RunningDigest::new();

        let tag1 = digest.update(1, 0x12, b"first");
        let tag2 = digest.update(1, 0x12, b"first");

        // Same input but different position in the running state
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_running_digest_multi_cell_sync() {
        let mut sender = RunningDigest::new();
        let mut receiver = RunningDigest::new();

        // Simulate 3 cells
        let tag1 = sender.update(1, 0x12, b"cell one");
        assert!(receiver.verify(1, 0x12, b"cell one", tag1));

        let tag2 = sender.update(1, 0x12, b"cell two");
        assert!(receiver.verify(1, 0x12, b"cell two", tag2));

        let tag3 = sender.update(2, 0x13, b"");
        assert!(receiver.verify(2, 0x13, b"", tag3));
    }

    #[test]
    fn test_running_digest_default() {
        let d1 = RunningDigest::new();
        let d2 = RunningDigest::default();
        // Both start from the same initial state
        let mut d1 = d1;
        let mut d2 = d2;
        let t1 = d1.update(1, 0x12, b"test");
        let t2 = d2.update(1, 0x12, b"test");
        assert_eq!(t1, t2);
    }
}
