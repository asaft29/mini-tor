use anyhow::Result;
use common::crypto::{SessionKey, aes_decrypt, aes_encrypt};

/// Keys for a 3-hop onion circuit
///
/// Holds the session keys for each hop in the circuit:
/// - `entry`: Key shared with the entry (guard) node
/// - `middle`: Key shared with the middle node
/// - `exit`: Key shared with the exit node
#[derive(Debug, Clone)]
pub struct OnionKeys {
    pub entry: SessionKey,
    pub middle: SessionKey,
    pub exit: SessionKey,
}

impl OnionKeys {
    /// Create a new set of onion keys
    pub fn new(entry: SessionKey, middle: SessionKey, exit: SessionKey) -> Self {
        Self {
            entry,
            middle,
            exit,
        }
    }

    /// Apply 3-layer onion encryption (forward direction: client -> destination)
    ///
    /// Encryption order: exit.forward, then middle.forward, then entry.forward.
    /// Each relay peels one layer: entry first, then middle, then exit sees plaintext.
    pub fn onion_encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        // Layer 3: Encrypt with exit key (innermost layer)
        let layer3 = aes_encrypt(plaintext, &self.exit.forward);

        // Layer 2: Encrypt with middle key
        let layer2 = aes_encrypt(&layer3, &self.middle.forward);

        // Layer 1: Encrypt with entry key (outermost layer)
        aes_encrypt(&layer2, &self.entry.forward)
    }

    /// Peel 3-layer onion encryption (backward direction: destination -> client)
    ///
    /// Decryption order: entry.backward, then middle.backward, then exit.backward.
    /// Each relay added one layer: exit first, then middle, then entry.
    ///
    /// # Errors
    /// Returns an error if any decryption layer fails (e.g., corrupted data)
    pub fn onion_decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Layer 1: Decrypt entry's backward layer (outermost)
        let layer1 = aes_decrypt(ciphertext, &self.entry.backward)?;

        // Layer 2: Decrypt middle's backward layer
        let layer2 = aes_decrypt(&layer1, &self.middle.backward)?;

        // Layer 3: Decrypt exit's backward layer (innermost)
        aes_decrypt(&layer2, &self.exit.backward)
    }

    /// Encrypt data for the EXTEND payload to the middle node
    ///
    /// Only one layer needed: entry.forward (entry peels it to see the EXTEND payload)
    #[allow(dead_code)]
    pub fn encrypt_for_extend_to_middle(&self, plaintext: &[u8]) -> Vec<u8> {
        aes_encrypt(plaintext, &self.entry.forward)
    }

    /// Encrypt data for the EXTEND payload to the exit node
    ///
    /// Two layers needed: middle.forward, then entry.forward
    /// Entry peels one layer, forwards to middle. Middle sees the EXTEND payload.
    #[allow(dead_code)]
    pub fn encrypt_for_extend_to_exit(&self, plaintext: &[u8]) -> Vec<u8> {
        let layer2 = aes_encrypt(plaintext, &self.middle.forward);
        aes_encrypt(&layer2, &self.entry.forward)
    }

    /// Decrypt an EXTENDED response from the middle node
    ///
    /// One layer: entry.backward (entry added its backward layer)
    ///
    /// # Errors
    /// Returns an error if decryption fails
    #[allow(dead_code)]
    pub fn decrypt_extended_from_middle(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        aes_decrypt(ciphertext, &self.entry.backward)
    }

    /// Decrypt an EXTENDED response from the exit node
    ///
    /// Two layers: entry.backward first, then middle.backward
    /// (entry adds its backward layer, middle adds its backward layer)
    ///
    /// # Errors
    /// Returns an error if decryption fails
    #[allow(dead_code)]
    pub fn decrypt_extended_from_exit(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let after_entry = aes_decrypt(ciphertext, &self.entry.backward)?;
        aes_decrypt(&after_entry, &self.middle.backward)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn test_keys() -> OnionKeys {
        OnionKeys::new(
            SessionKey::new([1u8; 16], [4u8; 16]),
            SessionKey::new([2u8; 16], [5u8; 16]),
            SessionKey::new([3u8; 16], [6u8; 16]),
        )
    }

    #[test]
    fn test_onion_encrypt_decrypt_roundtrip() {
        // For roundtrip to work, we need keys where the backward decryption
        // undoes the forward encryption. In real Tor, the relays apply
        // backward encryption on responses, but this test simulates the full
        // loop by using symmetric keys (forward == backward).
        let keys = OnionKeys::new(
            SessionKey::new([1u8; 16], [1u8; 16]),
            SessionKey::new([2u8; 16], [2u8; 16]),
            SessionKey::new([3u8; 16], [3u8; 16]),
        );
        let plaintext = b"Hello, onion routing!";

        let encrypted = keys.onion_encrypt(plaintext);
        let decrypted = keys.onion_decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_onion_encryption_changes_data() {
        let keys = test_keys();
        let plaintext = b"Secret message";

        let encrypted = keys.onion_encrypt(plaintext);

        // Encrypted data should be different from plaintext
        assert_ne!(encrypted, plaintext);
        // Each layer adds 16 bytes (IV), so 3 layers = 48 bytes overhead
        assert_eq!(encrypted.len(), plaintext.len() + 48);
    }

    #[test]
    fn test_onion_layer_order_matters() {
        let keys = test_keys();
        let plaintext = b"Order matters";

        let encrypted = keys.onion_encrypt(plaintext);

        // Decrypting with wrong key order should NOT recover plaintext
        let wrong_order = aes_decrypt(&encrypted, &keys.exit.backward);
        if let Ok(wrong_result) = wrong_order {
            assert_ne!(wrong_result, plaintext);
        }
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let keys1 = test_keys();
        let keys2 = OnionKeys::new(
            SessionKey::new([10u8; 16], [40u8; 16]),
            SessionKey::new([20u8; 16], [50u8; 16]),
            SessionKey::new([30u8; 16], [60u8; 16]),
        );
        let plaintext = b"Same plaintext";

        let encrypted1 = keys1.onion_encrypt(plaintext);
        let encrypted2 = keys2.onion_encrypt(plaintext);

        // Different keys should produce different ciphertext
        // (with overwhelming probability due to random IVs)
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_empty_payload_encrypt_decrypt() {
        let keys = test_keys();
        let plaintext = b"";

        let encrypted = keys.onion_encrypt(plaintext);
        let decrypted = keys.onion_decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_extend_to_middle_encrypt() {
        let keys = test_keys();
        let plaintext = b"extend payload for middle";

        let encrypted = keys.encrypt_for_extend_to_middle(plaintext);

        // Should be decryptable with entry's forward key
        let decrypted = aes_decrypt(&encrypted, &keys.entry.forward).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_extend_to_exit_encrypt() {
        let keys = test_keys();
        let plaintext = b"extend payload for exit";

        let encrypted = keys.encrypt_for_extend_to_exit(plaintext);

        // Peel entry layer first
        let after_entry = aes_decrypt(&encrypted, &keys.entry.forward).unwrap();
        // Then peel middle layer
        let decrypted = aes_decrypt(&after_entry, &keys.middle.forward).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
