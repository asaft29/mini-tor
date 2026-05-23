use common::PublicKey;
use common::crypto::{NtorHandshaker, SessionKey, TorNtorHandshaker};
use rand::rngs::OsRng;
use tor_llcrypto::pk::curve25519::{PublicKey as X25519PublicKey, StaticSecret};

/// X25519 key pair for a relay node (using tor-llcrypto).
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public: PublicKey,
    secret_bytes: [u8; 32],
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_x25519 = X25519PublicKey::from(&secret);

        let public = PublicKey {
            bytes: *public_x25519.as_bytes(),
        };

        let secret_bytes = secret.to_bytes();

        Self {
            public,
            secret_bytes,
        }
    }

    #[allow(dead_code)]
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public_x25519 = X25519PublicKey::from(&secret);

        let public = PublicKey {
            bytes: *public_x25519.as_bytes(),
        };

        Self {
            public,
            secret_bytes: bytes,
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Perform the ntor server-side handshake, returning (server_ephemeral_pub, auth, session_key).
    pub fn ntor_server_handshake(
        &self,
        client_ephemeral_pub: &[u8; 32],
    ) -> ([u8; 32], [u8; 32], SessionKey) {
        TorNtorHandshaker.server_handshake(
            &self.secret_bytes,
            &self.public.bytes,
            client_ephemeral_pub,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use common::NtorEphemeralKeyPair;

    #[test]
    fn test_ntor_handshake_exchange() {
        let relay_kp = KeyPair::generate();

        let client_kp = NtorEphemeralKeyPair::generate();
        let client_pub = client_kp.public.bytes;

        let (server_eph_pub, auth, relay_key) = relay_kp.ntor_server_handshake(&client_pub);

        let client_key = TorNtorHandshaker
            .client_handshake(
                client_kp.secret_bytes(),
                &client_pub,
                &relay_kp.public.bytes,
                &server_eph_pub,
                &auth,
            )
            .unwrap();

        assert_eq!(relay_key, client_key);
    }

    #[test]
    fn test_ntor_ephemeral_keypair_generation() {
        let e1 = NtorEphemeralKeyPair::generate();
        let e2 = NtorEphemeralKeyPair::generate();

        assert_ne!(e1.public.bytes, e2.public.bytes);
    }

    #[test]
    fn test_public_key_deterministic_from_secret() {
        let secret_bytes = [99u8; 32];

        let k1 = KeyPair::from_secret_bytes(secret_bytes);
        let k2 = KeyPair::from_secret_bytes(secret_bytes);

        assert_eq!(k1.public.bytes, k2.public.bytes);
    }
}
