use aes::Aes128;
use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::anyhow;
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use rand::Rng;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tor_llcrypto::pk::curve25519::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

use crate::PublicKey;

type Aes128Ctr = Ctr128BE<Aes128>;

/// Abstraction over a stateful stream cipher used for cell encryption/decryption.
/// Enables swapping the cipher algorithm (e.g., ChaCha20) without changing relay logic.
pub trait StatefulCipher: Send {
    fn apply_forward(&mut self, data: &mut [u8]);
    fn apply_backward(&mut self, data: &mut [u8]);
}

/// Stateful AES-128-CTR cipher pair for a single circuit hop.
pub struct CipherPair {
    forward: Aes128Ctr,
    backward: Aes128Ctr,
}

impl StatefulCipher for CipherPair {
    fn apply_forward(&mut self, data: &mut [u8]) {
        self.forward.apply_keystream(data);
    }
    fn apply_backward(&mut self, data: &mut [u8]) {
        self.backward.apply_keystream(data);
    }
}

impl CipherPair {
    /// Create a new cipher pair from a session key.
    pub fn new(key: &SessionKey) -> Self {
        let zero_iv = [0u8; 16];
        Self {
            forward: Aes128Ctr::new(&key.forward.into(), &zero_iv.into()),
            backward: Aes128Ctr::new(&key.backward.into(), &zero_iv.into()),
        }
    }

    /// Apply the forward keystream in-place.
    pub fn apply_forward(&mut self, data: &mut [u8]) {
        self.forward.apply_keystream(data);
    }

    /// Apply the backward keystream in-place.
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
pub struct RunningDigest {
    state: Sha256,
}

impl RunningDigest {
    /// Create a fresh digest state.
    pub fn new() -> Self {
        Self {
            state: Sha256::new(),
        }
    }

    /// Feed a cell's fields into the running digest and return the 4-byte snapshot.
    pub fn update(&mut self, stream_id: u16, command: u8, data: &[u8]) -> [u8; 4] {
        self.state.update(stream_id.to_be_bytes());
        self.state.update([command]);
        self.state.update(data);

        let snapshot = self.state.clone().finalize();
        let mut tag = [0u8; 4];
        tag.copy_from_slice(snapshot.get(..4).unwrap_or(&[0u8; 4]));
        tag
    }

    /// Verify a cell's digest by recomputing and comparing.
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

/// Session key with separate forward and backward AES-128 keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKey {
    pub forward: [u8; 16],
    pub backward: [u8; 16],
}

impl SessionKey {
    /// Create a new session key from forward and backward keys.
    pub fn new(forward: [u8; 16], backward: [u8; 16]) -> Self {
        Self { forward, backward }
    }

    /// Create from a single 32-byte shared secret.
    pub fn from_shared(shared: &[u8; 32]) -> Self {
        let mut forward = [0u8; 16];
        let mut backward = [0u8; 16];

        forward.copy_from_slice(&shared[0..16]);
        backward.copy_from_slice(&shared[16..32]);

        Self { forward, backward }
    }

    /// Convert to 32-byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..16].copy_from_slice(&self.forward);
        bytes[16..32].copy_from_slice(&self.backward);
        bytes
    }

    /// Create from 32-byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut forward = [0u8; 16];
        let mut backward = [0u8; 16];

        forward.copy_from_slice(&bytes[0..16]);
        backward.copy_from_slice(&bytes[16..32]);

        Self { forward, backward }
    }

    /// Create a zero key (for testing).
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

/// Encrypt data using AES-128-CTR with a random IV prepended.
pub fn aes_encrypt(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let mut iv = [0u8; 16];
    rand::rng().fill(&mut iv);

    let mut cipher = Aes128Ctr::new(key.into(), &iv.into());

    let mut ciphertext = data.to_vec();
    cipher.apply_keystream(&mut ciphertext);

    let mut output = Vec::with_capacity(16 + ciphertext.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&ciphertext);

    output
}

/// Decrypt data using AES-128-CTR (IV is the first 16 bytes).
///
/// # Errors
/// Returns an error if `data` is shorter than 16 bytes (the IV size).
pub fn aes_decrypt(data: &[u8], key: &[u8; 16]) -> anyhow::Result<Vec<u8>> {
    if data.len() < 16 {
        return Err(anyhow!(
            "Invalid ciphertext: length {} is too short (min 16)",
            data.len()
        ));
    }

    let iv_slice = data
        .get(0..16)
        .ok_or_else(|| anyhow!("Invalid ciphertext: missing IV (expected 16 bytes)"))?;
    let ciphertext = data
        .get(16..)
        .ok_or_else(|| anyhow!("Invalid ciphertext: missing encrypted data"))?;

    let mut cipher = Aes128Ctr::new(key.into(), iv_slice.into());

    let mut plaintext = ciphertext.to_vec();
    cipher.apply_keystream(&mut plaintext);

    Ok(plaintext)
}

/// Derive session key from a 32-byte shared secret.
pub fn derive_session_key(shared_secret: &[u8; 32]) -> SessionKey {
    SessionKey::from_shared(shared_secret)
}

/// Hash data using SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Client-side ephemeral key pair for Diffie-Hellman key exchange.
pub struct EphemeralKeyPair {
    pub public: PublicKey,
    secret: EphemeralSecret,
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral keypair.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_x25519 = X25519PublicKey::from(&secret);

        let public = PublicKey {
            bytes: *public_x25519.as_bytes(),
        };

        Self { public, secret }
    }

    /// Perform DH exchange and return the SHA-256 hashed shared secret.
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

const PROTOID: &[u8] = b"ntor-curve25519-sha256-1";

fn t_key() -> Vec<u8> {
    [PROTOID, b":key_extract"].concat()
}

fn t_verify() -> Vec<u8> {
    [PROTOID, b":verify"].concat()
}

fn t_mac() -> Vec<u8> {
    [PROTOID, b":mac"].concat()
}

fn m_expand() -> Vec<u8> {
    [PROTOID, b":key_expand"].concat()
}

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256(data, key).
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return [0u8; 32];
    };
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Perform raw X25519 DH (no hashing).
fn raw_dh_static(secret_bytes: &[u8; 32], their_public: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*secret_bytes);
    let their_key = X25519PublicKey::from(*their_public);
    let shared = secret.diffie_hellman(&their_key);
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.as_bytes());
    out
}

/// Build `secret_input = exp1 || exp2 || B || X || Y || PROTOID`.
fn build_secret_input(
    exp1: &[u8; 32],
    exp2: &[u8; 32],
    server_static_pub: &[u8; 32],
    client_ephemeral_pub: &[u8; 32],
    server_ephemeral_pub: &[u8; 32],
) -> Vec<u8> {
    let mut si = Vec::with_capacity(32 * 5 + PROTOID.len());
    si.extend_from_slice(exp1);
    si.extend_from_slice(exp2);
    si.extend_from_slice(server_static_pub);
    si.extend_from_slice(client_ephemeral_pub);
    si.extend_from_slice(server_ephemeral_pub);
    si.extend_from_slice(PROTOID);
    si
}

/// Derive a [`SessionKey`] from a KEY_SEED using HMAC-based key expansion.
fn expand_key_seed(key_seed: &[u8; 32]) -> SessionKey {
    let key_material = hmac_sha256(&m_expand(), key_seed);
    let mut forward = [0u8; 16];
    let mut backward = [0u8; 16];
    forward.copy_from_slice(&key_material[..16]);
    backward.copy_from_slice(&key_material[16..]);
    SessionKey::new(forward, backward)
}

/// Abstraction over the ntor key-exchange handshake.
/// Enables injecting test-only handshakes or swapping to alternative protocols.
pub trait NtorHandshaker: Send + Sync {
    fn server_handshake(
        &self,
        static_secret: &[u8; 32],
        static_public: &[u8; 32],
        client_ephemeral_pub: &[u8; 32],
    ) -> ([u8; 32], [u8; 32], SessionKey);

    fn client_handshake(
        &self,
        client_ephemeral_secret_bytes: &[u8; 32],
        client_ephemeral_pub: &[u8; 32],
        server_static_pub: &[u8; 32],
        server_ephemeral_pub: &[u8; 32],
        auth: &[u8; 32],
    ) -> Result<SessionKey, crate::TorError>;
}

pub struct TorNtorHandshaker;

impl NtorHandshaker for TorNtorHandshaker {
    fn server_handshake(
        &self,
        static_secret: &[u8; 32],
        static_public: &[u8; 32],
        client_ephemeral_pub: &[u8; 32],
    ) -> ([u8; 32], [u8; 32], SessionKey) {
        ntor_server(static_secret, static_public, client_ephemeral_pub)
    }

    fn client_handshake(
        &self,
        client_ephemeral_secret_bytes: &[u8; 32],
        client_ephemeral_pub: &[u8; 32],
        server_static_pub: &[u8; 32],
        server_ephemeral_pub: &[u8; 32],
        auth: &[u8; 32],
    ) -> Result<SessionKey, crate::TorError> {
        ntor_client_finish_raw(
            client_ephemeral_secret_bytes,
            client_ephemeral_pub,
            server_static_pub,
            server_ephemeral_pub,
            auth,
        )
    }
}

/// Server (relay) side of the ntor handshake. Returns `(server_ephemeral_public, auth, session_key)`.
pub fn ntor_server(
    static_secret: &[u8; 32],
    static_public: &[u8; 32],
    client_ephemeral_pub: &[u8; 32],
) -> ([u8; 32], [u8; 32], SessionKey) {
    let y_secret = StaticSecret::random_from_rng(OsRng);
    let y_public = X25519PublicKey::from(&y_secret);
    let y_pub_bytes: [u8; 32] = *y_public.as_bytes();
    let y_secret_bytes = y_secret.to_bytes();

    let exp1 = raw_dh_static(&y_secret_bytes, client_ephemeral_pub);
    let exp2 = raw_dh_static(static_secret, client_ephemeral_pub);

    let secret_input = build_secret_input(
        &exp1,
        &exp2,
        static_public,
        client_ephemeral_pub,
        &y_pub_bytes,
    );

    let key_seed = hmac_sha256(&t_key(), &secret_input);
    let verify = hmac_sha256(&t_verify(), &secret_input);

    let mut auth_input = Vec::with_capacity(32 * 4 + PROTOID.len() + 6);
    auth_input.extend_from_slice(&verify);
    auth_input.extend_from_slice(static_public);
    auth_input.extend_from_slice(&y_pub_bytes);
    auth_input.extend_from_slice(client_ephemeral_pub);
    auth_input.extend_from_slice(PROTOID);
    auth_input.extend_from_slice(b"Server");

    let auth = hmac_sha256(&t_mac(), &auth_input);
    let session_key = expand_key_seed(&key_seed);

    (y_pub_bytes, auth, session_key)
}

/// Client side of the ntor handshake — verify AUTH and derive the session key.
///
/// # Errors
/// Returns [`TorError::HandshakeAuthFailed`] if the relay's AUTH tag does not verify.
pub fn ntor_client_finish_raw(
    client_ephemeral_secret_bytes: &[u8; 32],
    client_ephemeral_pub: &[u8; 32],
    server_static_pub: &[u8; 32],
    server_ephemeral_pub: &[u8; 32],
    auth: &[u8; 32],
) -> Result<SessionKey, crate::TorError> {
    let exp1 = raw_dh_static(client_ephemeral_secret_bytes, server_ephemeral_pub);
    let exp2 = raw_dh_static(client_ephemeral_secret_bytes, server_static_pub);

    let secret_input = build_secret_input(
        &exp1,
        &exp2,
        server_static_pub,
        client_ephemeral_pub,
        server_ephemeral_pub,
    );

    let key_seed = hmac_sha256(&t_key(), &secret_input);
    let verify = hmac_sha256(&t_verify(), &secret_input);

    let mut auth_input = Vec::with_capacity(32 * 4 + PROTOID.len() + 6);
    auth_input.extend_from_slice(&verify);
    auth_input.extend_from_slice(server_static_pub);
    auth_input.extend_from_slice(server_ephemeral_pub);
    auth_input.extend_from_slice(client_ephemeral_pub);
    auth_input.extend_from_slice(PROTOID);
    auth_input.extend_from_slice(b"Server");

    let expected_auth = hmac_sha256(&t_mac(), &auth_input);

    if auth != &expected_auth {
        return Err(crate::TorError::HandshakeAuthFailed);
    }

    Ok(expand_key_seed(&key_seed))
}

/// Client-side ephemeral keypair for the ntor handshake.
pub struct NtorEphemeralKeyPair {
    pub public: PublicKey,
    secret_bytes: [u8; 32],
}

impl NtorEphemeralKeyPair {
    /// Generate a new ephemeral keypair for ntor.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_x25519 = X25519PublicKey::from(&secret);
        let public = PublicKey {
            bytes: *public_x25519.as_bytes(),
        };
        Self {
            public,
            secret_bytes: secret.to_bytes(),
        }
    }

    /// Get the raw secret bytes.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret_bytes
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
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

    #[test]
    fn test_ntor_server_client_roundtrip() {
        // Simulate relay's static keypair
        let relay_secret = StaticSecret::random_from_rng(OsRng);
        let relay_public = X25519PublicKey::from(&relay_secret);
        let relay_secret_bytes = relay_secret.to_bytes();
        let relay_public_bytes: [u8; 32] = *relay_public.as_bytes();

        // Client generates ephemeral keypair
        let client_eph = NtorEphemeralKeyPair::generate();
        let client_pub = client_eph.public.bytes;

        // Server side
        let (server_eph_pub, auth, server_key) =
            ntor_server(&relay_secret_bytes, &relay_public_bytes, &client_pub);

        // Client side — verify AUTH and derive key
        let client_key = ntor_client_finish_raw(
            client_eph.secret_bytes(),
            &client_pub,
            &relay_public_bytes,
            &server_eph_pub,
            &auth,
        )
        .unwrap();

        // Both must derive the same session key
        assert_eq!(server_key, client_key);
    }

    #[test]
    fn test_ntor_client_rejects_tampered_auth() {
        let relay_secret = StaticSecret::random_from_rng(OsRng);
        let relay_public = X25519PublicKey::from(&relay_secret);
        let relay_secret_bytes = relay_secret.to_bytes();
        let relay_public_bytes: [u8; 32] = *relay_public.as_bytes();

        let client_eph = NtorEphemeralKeyPair::generate();
        let client_pub = client_eph.public.bytes;

        let (server_eph_pub, mut auth, _) =
            ntor_server(&relay_secret_bytes, &relay_public_bytes, &client_pub);

        // Tamper with the AUTH tag
        auth[0] ^= 0xFF;

        let result = ntor_client_finish_raw(
            client_eph.secret_bytes(),
            &client_pub,
            &relay_public_bytes,
            &server_eph_pub,
            &auth,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_ntor_client_rejects_wrong_static_key() {
        let relay_secret = StaticSecret::random_from_rng(OsRng);
        let relay_public = X25519PublicKey::from(&relay_secret);
        let relay_secret_bytes = relay_secret.to_bytes();
        let relay_public_bytes: [u8; 32] = *relay_public.as_bytes();

        let client_eph = NtorEphemeralKeyPair::generate();
        let client_pub = client_eph.public.bytes;

        let (server_eph_pub, auth, _) =
            ntor_server(&relay_secret_bytes, &relay_public_bytes, &client_pub);

        // Client thinks it's talking to a DIFFERENT relay
        let fake_relay_secret = StaticSecret::random_from_rng(OsRng);
        let fake_relay_public = X25519PublicKey::from(&fake_relay_secret);
        let fake_relay_public_bytes: [u8; 32] = *fake_relay_public.as_bytes();

        let result = ntor_client_finish_raw(
            client_eph.secret_bytes(),
            &client_pub,
            &fake_relay_public_bytes,
            &server_eph_pub,
            &auth,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_ntor_different_sessions_different_keys() {
        let relay_secret = StaticSecret::random_from_rng(OsRng);
        let relay_public = X25519PublicKey::from(&relay_secret);
        let relay_secret_bytes = relay_secret.to_bytes();
        let relay_public_bytes: [u8; 32] = *relay_public.as_bytes();

        let client_eph1 = NtorEphemeralKeyPair::generate();
        let client_eph2 = NtorEphemeralKeyPair::generate();

        let (_, _, key1) = ntor_server(
            &relay_secret_bytes,
            &relay_public_bytes,
            &client_eph1.public.bytes,
        );
        let (_, _, key2) = ntor_server(
            &relay_secret_bytes,
            &relay_public_bytes,
            &client_eph2.public.bytes,
        );

        // Different ephemeral keys must produce different session keys
        assert_ne!(key1, key2);
    }
}
