use common::crypto::{CipherPair, RunningDigest, SessionKey};

/// Keys for a 3-hop onion circuit.
pub struct OnionKeys {
    pub entry: SessionKey,
    pub middle: SessionKey,
    pub exit: SessionKey,
    pub entry_cipher: CipherPair,
    pub middle_cipher: CipherPair,
    pub exit_cipher: CipherPair,
    pub forward_digest: RunningDigest,
    pub backward_digest: RunningDigest,
}

impl OnionKeys {
    /// Create with fresh cipher pairs (for tests).
    pub fn new(entry: SessionKey, middle: SessionKey, exit: SessionKey) -> Self {
        let entry_cipher = CipherPair::new(&entry);
        let middle_cipher = CipherPair::new(&middle);
        let exit_cipher = CipherPair::new(&exit);
        Self {
            entry,
            middle,
            exit,
            entry_cipher,
            middle_cipher,
            exit_cipher,
            forward_digest: RunningDigest::new(),
            backward_digest: RunningDigest::new(),
        }
    }

    /// Create from pre-existing cipher pairs (preserves handshake state).
    pub fn from_parts(
        entry: SessionKey,
        middle: SessionKey,
        exit: SessionKey,
        entry_cipher: CipherPair,
        middle_cipher: CipherPair,
        exit_cipher: CipherPair,
    ) -> Self {
        Self {
            entry,
            middle,
            exit,
            entry_cipher,
            middle_cipher,
            exit_cipher,
            forward_digest: RunningDigest::new(),
            backward_digest: RunningDigest::new(),
        }
    }

    /// Apply 3-layer onion encryption in-place (forward direction).
    pub fn onion_encrypt(&mut self, data: &mut [u8]) {
        self.exit_cipher.apply_forward(data);
        self.middle_cipher.apply_forward(data);
        self.entry_cipher.apply_forward(data);
    }

    /// Peel 3-layer onion encryption in-place (backward direction).
    pub fn onion_decrypt(&mut self, data: &mut [u8]) {
        self.entry_cipher.apply_backward(data);
        self.middle_cipher.apply_backward(data);
        self.exit_cipher.apply_backward(data);
    }
}

impl std::fmt::Debug for OnionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionKeys")
            .field("entry", &self.entry)
            .field("middle", &self.middle)
            .field("exit", &self.exit)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use common::crypto::CipherPair;

    fn test_keys() -> OnionKeys {
        OnionKeys::new(
            SessionKey::new([1u8; 16], [4u8; 16]),
            SessionKey::new([2u8; 16], [5u8; 16]),
            SessionKey::new([3u8; 16], [6u8; 16]),
        )
    }

    #[test]
    fn test_onion_encrypt_decrypt_roundtrip() {
        // For a true encrypt-then-decrypt roundtrip, we need to simulate what
        // the relays do. The client encrypts forward, then the relays peel layers.
        // In the backward direction, relays add layers and the client decrypts.
        //
        // With stateful CTR, we need separate client and relay cipher instances
        // initialized from the same keys.
        let entry_key = SessionKey::new([1u8; 16], [1u8; 16]);
        let middle_key = SessionKey::new([2u8; 16], [2u8; 16]);
        let exit_key = SessionKey::new([3u8; 16], [3u8; 16]);

        let mut client = OnionKeys::new(entry_key.clone(), middle_key.clone(), exit_key.clone());

        // Simulate relay cipher pairs (same keys, fresh state)
        let mut entry_relay = CipherPair::new(&entry_key);
        let mut middle_relay = CipherPair::new(&middle_key);
        let mut exit_relay = CipherPair::new(&exit_key);

        let plaintext = b"Hello, onion routing!";

        // Client encrypts forward: exit.fwd -> middle.fwd -> entry.fwd
        let mut data = plaintext.to_vec();
        client.onion_encrypt(&mut data);

        // Entry peels: apply_forward (XOR with same keystream as client's entry.fwd)
        entry_relay.apply_forward(&mut data);
        // Middle peels:
        middle_relay.apply_forward(&mut data);
        // Exit peels:
        exit_relay.apply_forward(&mut data);

        assert_eq!(data, plaintext);
    }

    #[test]
    fn test_onion_encryption_changes_data() {
        let mut keys = test_keys();
        let plaintext = b"Secret message";

        let mut data = plaintext.to_vec();
        keys.onion_encrypt(&mut data);

        // Encrypted data should be different from plaintext
        assert_ne!(data, plaintext.as_slice());
        // With stateful CTR, no overhead — same length
        assert_eq!(data.len(), plaintext.len());
    }

    #[test]
    fn test_onion_layer_order_matters() {
        let mut keys = test_keys();
        let plaintext = b"Order matters";

        let mut data = plaintext.to_vec();
        keys.onion_encrypt(&mut data);

        // Decrypting with wrong key order (exit backward first) should NOT recover plaintext
        let mut wrong_cipher = CipherPair::new(&keys.exit);
        let mut wrong_data = data.clone();
        wrong_cipher.apply_backward(&mut wrong_data);
        assert_ne!(wrong_data, plaintext.as_slice());
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let mut keys1 = test_keys();
        let mut keys2 = OnionKeys::new(
            SessionKey::new([10u8; 16], [40u8; 16]),
            SessionKey::new([20u8; 16], [50u8; 16]),
            SessionKey::new([30u8; 16], [60u8; 16]),
        );
        let plaintext = b"Same plaintext";

        let mut data1 = plaintext.to_vec();
        keys1.onion_encrypt(&mut data1);
        let mut data2 = plaintext.to_vec();
        keys2.onion_encrypt(&mut data2);

        // Different keys should produce different ciphertext
        assert_ne!(data1, data2);
    }

    #[test]
    fn test_empty_payload_encrypt_decrypt() {
        let entry_key = SessionKey::new([1u8; 16], [1u8; 16]);
        let middle_key = SessionKey::new([2u8; 16], [2u8; 16]);
        let exit_key = SessionKey::new([3u8; 16], [3u8; 16]);

        let mut client = OnionKeys::new(entry_key.clone(), middle_key.clone(), exit_key.clone());

        let mut entry_relay = CipherPair::new(&entry_key);
        let mut middle_relay = CipherPair::new(&middle_key);
        let mut exit_relay = CipherPair::new(&exit_key);

        let mut data: Vec<u8> = vec![];
        client.onion_encrypt(&mut data);

        entry_relay.apply_forward(&mut data);
        middle_relay.apply_forward(&mut data);
        exit_relay.apply_forward(&mut data);

        assert!(data.is_empty());
    }

    #[test]
    fn test_simulated_relay_backward_path() {
        // Simulate what relays do in the backward direction:
        // Exit encrypts with exit.backward, middle encrypts with middle.backward,
        // entry encrypts with entry.backward. Client onion_decrypt() peels all 3.
        let entry_key = SessionKey::new([1u8; 16], [4u8; 16]);
        let middle_key = SessionKey::new([2u8; 16], [5u8; 16]);
        let exit_key = SessionKey::new([3u8; 16], [6u8; 16]);

        let mut client = OnionKeys::new(entry_key.clone(), middle_key.clone(), exit_key.clone());

        // Relay ciphers (same keys, fresh state)
        let mut exit_relay = CipherPair::new(&exit_key);
        let mut middle_relay = CipherPair::new(&middle_key);
        let mut entry_relay = CipherPair::new(&entry_key);

        let plaintext = b"response from destination";
        let mut data = plaintext.to_vec();

        // Exit node encrypts first (backward)
        exit_relay.apply_backward(&mut data);
        // Middle node adds its layer (backward)
        middle_relay.apply_backward(&mut data);
        // Entry node adds its layer (backward)
        entry_relay.apply_backward(&mut data);

        // Client peels all 3 layers
        client.onion_decrypt(&mut data);
        assert_eq!(data, plaintext);
    }

    #[test]
    fn test_large_payload_64kb() {
        let entry_key = SessionKey::new([1u8; 16], [1u8; 16]);
        let middle_key = SessionKey::new([2u8; 16], [2u8; 16]);
        let exit_key = SessionKey::new([3u8; 16], [3u8; 16]);

        let mut client = OnionKeys::new(entry_key.clone(), middle_key.clone(), exit_key.clone());
        let mut entry_relay = CipherPair::new(&entry_key);
        let mut middle_relay = CipherPair::new(&middle_key);
        let mut exit_relay = CipherPair::new(&exit_key);

        let plaintext: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();

        let mut data = plaintext.clone();
        client.onion_encrypt(&mut data);

        entry_relay.apply_forward(&mut data);
        middle_relay.apply_forward(&mut data);
        exit_relay.apply_forward(&mut data);

        assert_eq!(data, plaintext);
    }

    #[test]
    fn test_corrupted_ciphertext() {
        let entry_key = SessionKey::new([1u8; 16], [1u8; 16]);
        let middle_key = SessionKey::new([2u8; 16], [2u8; 16]);
        let exit_key = SessionKey::new([3u8; 16], [3u8; 16]);

        let mut client = OnionKeys::new(entry_key, middle_key, exit_key);
        let plaintext = b"sensitive data here";

        let mut data = plaintext.to_vec();
        client.onion_encrypt(&mut data);

        // Corrupt a byte in the ciphertext
        let last_idx = data.len() - 1;
        data[last_idx] ^= 0xFF;

        // Just verify the data is different from original plaintext
        assert_ne!(
            data,
            plaintext.as_slice(),
            "encrypted+corrupted should differ from plaintext"
        );
    }
}
