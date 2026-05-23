use common::crypto::{RunningDigest, SessionKey, StatefulCipher};

/// Keys for an N-hop onion circuit (N >= 3).
pub struct OnionKeys {
    /// Session keys indexed [0=entry .. N-1=exit].
    pub session_keys: Vec<SessionKey>,
    /// Stateful cipher pairs indexed [0=entry .. N-1=exit].
    pub ciphers: Vec<Box<dyn StatefulCipher>>,
    pub forward_digest: RunningDigest,
    pub backward_digest: RunningDigest,
}

impl OnionKeys {
    /// Create from pre-built parallel vecs of session keys and cipher pairs.
    pub fn new(session_keys: Vec<SessionKey>, ciphers: Vec<Box<dyn StatefulCipher>>) -> Self {
        Self {
            session_keys,
            ciphers,
            forward_digest: RunningDigest::new(),
            backward_digest: RunningDigest::new(),
        }
    }

    /// Apply N-layer onion encryption in-place (forward direction, client → exit).
    /// Applies exit cipher first, then inner hops, then entry last (outermost layer).
    pub fn onion_encrypt(&mut self, data: &mut [u8]) {
        for cipher in self.ciphers.iter_mut().rev() {
            cipher.apply_forward(data);
        }
    }

    /// Peel N-layer onion encryption in-place (backward direction, exit → client).
    /// Applies entry cipher first, peeling outward to exit.
    pub fn onion_decrypt(&mut self, data: &mut [u8]) {
        for cipher in self.ciphers.iter_mut() {
            cipher.apply_backward(data);
        }
    }
}

impl std::fmt::Debug for OnionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionKeys")
            .field("hop_count", &self.session_keys.len())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use common::crypto::CipherPair;

    fn make_test_keys(keys: &[SessionKey]) -> OnionKeys {
        let ciphers: Vec<Box<dyn StatefulCipher>> = keys
            .iter()
            .map(|k| Box::new(CipherPair::new(k)) as Box<dyn StatefulCipher>)
            .collect();
        OnionKeys::new(keys.to_vec(), ciphers)
    }

    fn three_hop_keys() -> OnionKeys {
        make_test_keys(&[
            SessionKey::new([1u8; 16], [4u8; 16]),
            SessionKey::new([2u8; 16], [5u8; 16]),
            SessionKey::new([3u8; 16], [6u8; 16]),
        ])
    }

    #[test]
    fn test_onion_encrypt_decrypt_roundtrip() {
        // Simulate what the relays do in the forward direction.
        let entry_key = SessionKey::new([1u8; 16], [1u8; 16]);
        let middle_key = SessionKey::new([2u8; 16], [2u8; 16]);
        let exit_key = SessionKey::new([3u8; 16], [3u8; 16]);

        let mut client = make_test_keys(&[entry_key.clone(), middle_key.clone(), exit_key.clone()]);

        // Simulate relay cipher pairs (same keys, fresh state)
        let mut entry_relay = CipherPair::new(&entry_key);
        let mut middle_relay = CipherPair::new(&middle_key);
        let mut exit_relay = CipherPair::new(&exit_key);

        let plaintext = b"Hello, onion routing!";

        // Client encrypts forward: exit.fwd -> middle.fwd -> entry.fwd
        let mut data = plaintext.to_vec();
        client.onion_encrypt(&mut data);

        // Each relay peels its layer (apply_forward with same keystream)
        entry_relay.apply_forward(&mut data);
        middle_relay.apply_forward(&mut data);
        exit_relay.apply_forward(&mut data);

        assert_eq!(data, plaintext);
    }

    #[test]
    fn test_onion_encryption_changes_data() {
        let mut keys = three_hop_keys();
        let plaintext = b"Secret message";

        let mut data = plaintext.to_vec();
        keys.onion_encrypt(&mut data);

        assert_ne!(data, plaintext.as_slice());
        assert_eq!(data.len(), plaintext.len());
    }

    #[test]
    fn test_onion_layer_order_matters() {
        let mut keys = three_hop_keys();
        let plaintext = b"Order matters";

        let mut data = plaintext.to_vec();
        keys.onion_encrypt(&mut data);

        // Decrypting with wrong key order should NOT recover plaintext
        let mut wrong_cipher = CipherPair::new(&keys.session_keys[2]);
        let mut wrong_data = data.clone();
        wrong_cipher.apply_backward(&mut wrong_data);
        assert_ne!(wrong_data, plaintext.as_slice());
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let mut keys1 = make_test_keys(&[
            SessionKey::new([1u8; 16], [4u8; 16]),
            SessionKey::new([2u8; 16], [5u8; 16]),
            SessionKey::new([3u8; 16], [6u8; 16]),
        ]);
        let mut keys2 = make_test_keys(&[
            SessionKey::new([10u8; 16], [40u8; 16]),
            SessionKey::new([20u8; 16], [50u8; 16]),
            SessionKey::new([30u8; 16], [60u8; 16]),
        ]);
        let plaintext = b"Same plaintext";

        let mut data1 = plaintext.to_vec();
        keys1.onion_encrypt(&mut data1);
        let mut data2 = plaintext.to_vec();
        keys2.onion_encrypt(&mut data2);

        assert_ne!(data1, data2);
    }

    #[test]
    fn test_empty_payload_encrypt_decrypt() {
        let entry_key = SessionKey::new([1u8; 16], [1u8; 16]);
        let middle_key = SessionKey::new([2u8; 16], [2u8; 16]);
        let exit_key = SessionKey::new([3u8; 16], [3u8; 16]);

        let mut client = make_test_keys(&[entry_key.clone(), middle_key.clone(), exit_key.clone()]);

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
        let entry_key = SessionKey::new([1u8; 16], [4u8; 16]);
        let middle_key = SessionKey::new([2u8; 16], [5u8; 16]);
        let exit_key = SessionKey::new([3u8; 16], [6u8; 16]);

        let mut client = make_test_keys(&[entry_key.clone(), middle_key.clone(), exit_key.clone()]);

        let mut exit_relay = CipherPair::new(&exit_key);
        let mut middle_relay = CipherPair::new(&middle_key);
        let mut entry_relay = CipherPair::new(&entry_key);

        let plaintext = b"response from destination";
        let mut data = plaintext.to_vec();

        // Relays add backward layers: exit first, then middle, then entry
        exit_relay.apply_backward(&mut data);
        middle_relay.apply_backward(&mut data);
        entry_relay.apply_backward(&mut data);

        // Client peels all layers
        client.onion_decrypt(&mut data);
        assert_eq!(data, plaintext);
    }

    #[test]
    fn test_large_payload_64kb() {
        let entry_key = SessionKey::new([1u8; 16], [1u8; 16]);
        let middle_key = SessionKey::new([2u8; 16], [2u8; 16]);
        let exit_key = SessionKey::new([3u8; 16], [3u8; 16]);

        let mut client = make_test_keys(&[entry_key.clone(), middle_key.clone(), exit_key.clone()]);
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

        let mut client = make_test_keys(&[entry_key, middle_key, exit_key]);
        let plaintext = b"sensitive data here";

        let mut data = plaintext.to_vec();
        client.onion_encrypt(&mut data);

        let last_idx = data.len() - 1;
        data[last_idx] ^= 0xFF;

        assert_ne!(
            data,
            plaintext.as_slice(),
            "encrypted+corrupted should differ from plaintext"
        );
    }

    #[test]
    fn test_4_hop_encrypt_decrypt_roundtrip() {
        // 4-hop circuit: entry → middle1 → middle2 → exit
        let entry_key = SessionKey::new([1u8; 16], [1u8; 16]);
        let mid1_key = SessionKey::new([2u8; 16], [2u8; 16]);
        let mid2_key = SessionKey::new([3u8; 16], [3u8; 16]);
        let exit_key = SessionKey::new([4u8; 16], [4u8; 16]);

        let mut client = make_test_keys(&[
            entry_key.clone(),
            mid1_key.clone(),
            mid2_key.clone(),
            exit_key.clone(),
        ]);

        let mut entry_relay = CipherPair::new(&entry_key);
        let mut mid1_relay = CipherPair::new(&mid1_key);
        let mut mid2_relay = CipherPair::new(&mid2_key);
        let mut exit_relay = CipherPair::new(&exit_key);

        let plaintext = b"4-hop onion test";
        let mut data = plaintext.to_vec();

        // Client encrypts: exit.fwd → mid2.fwd → mid1.fwd → entry.fwd
        client.onion_encrypt(&mut data);

        // Relays peel layers in order
        entry_relay.apply_forward(&mut data);
        mid1_relay.apply_forward(&mut data);
        mid2_relay.apply_forward(&mut data);
        exit_relay.apply_forward(&mut data);

        assert_eq!(data, plaintext);
    }

    #[test]
    fn test_4_hop_backward_path() {
        let entry_key = SessionKey::new([1u8; 16], [4u8; 16]);
        let mid1_key = SessionKey::new([2u8; 16], [5u8; 16]);
        let mid2_key = SessionKey::new([3u8; 16], [6u8; 16]);
        let exit_key = SessionKey::new([4u8; 16], [7u8; 16]);

        let mut client = make_test_keys(&[
            entry_key.clone(),
            mid1_key.clone(),
            mid2_key.clone(),
            exit_key.clone(),
        ]);

        let mut exit_relay = CipherPair::new(&exit_key);
        let mut mid2_relay = CipherPair::new(&mid2_key);
        let mut mid1_relay = CipherPair::new(&mid1_key);
        let mut entry_relay = CipherPair::new(&entry_key);

        let plaintext = b"4-hop response";
        let mut data = plaintext.to_vec();

        // Relays add backward layers: exit first, then mid2, mid1, entry
        exit_relay.apply_backward(&mut data);
        mid2_relay.apply_backward(&mut data);
        mid1_relay.apply_backward(&mut data);
        entry_relay.apply_backward(&mut data);

        client.onion_decrypt(&mut data);
        assert_eq!(data, plaintext);
    }
}
