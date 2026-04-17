use anyhow::Result;
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn compute_cert_fingerprint(cert_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let hash = hasher.finalize();
    hex::encode(hash)
}

pub struct RelayTlsConfig {
    pub fingerprint: String,
    pub acceptor: TlsAcceptor,
}

impl RelayTlsConfig {
    pub fn generate(node_id: &str, bind_addr: SocketAddr) -> Result<Self> {
        install_crypto_provider();
        let mut params = CertificateParams::new(Vec::new())
            .map_err(|e| anyhow::anyhow!("Failed to create certificate params: {}", e))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, node_id);
        params
            .subject_alt_names
            .push(SanType::IpAddress(bind_addr.ip()));

        let key_pair = KeyPair::generate()
            .map_err(|e| anyhow::anyhow!("Failed to generate TLS key pair: {}", e))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| anyhow::anyhow!("Failed to sign TLS certificate: {}", e))?;

        let cert_der = cert.der().to_vec();
        let fingerprint = compute_cert_fingerprint(&cert_der);

        let private_key_der = key_pair.serialize_der();
        let rustls_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(private_key_der));

        let rustls_cert = CertificateDer::from(cert_der);

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![rustls_cert], rustls_key)
            .map_err(|e| anyhow::anyhow!("Failed to create TLS server config: {}", e))?;

        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        Ok(Self {
            fingerprint,
            acceptor,
        })
    }

    pub fn make_tls_connector(expected_fingerprint: &str) -> Result<TlsConnector> {
        install_crypto_provider();
        let verifier = Arc::new(FingerprintVerifier {
            expected: expected_fingerprint.to_string(),
        });

        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        Ok(TlsConnector::from(Arc::new(client_config)))
    }
}

#[derive(Debug)]
struct FingerprintVerifier {
    expected: String,
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let actual = compute_cert_fingerprint(end_entity.as_ref());
        if actual.eq_ignore_ascii_case(&self.expected) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "Certificate fingerprint mismatch: expected {}, got {}",
                self.expected, actual
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

pub fn server_name_from_addr(addr: SocketAddr) -> ServerName<'static> {
    ServerName::IpAddress(addr.ip().into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::protocol::Message;
    use std::net::SocketAddr;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn test_compute_cert_fingerprint_deterministic() {
        let data = b"hello world";
        let fp1 = compute_cert_fingerprint(data);
        let fp2 = compute_cert_fingerprint(data);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64);
    }

    #[test]
    fn test_cert_fingerprint_differs_for_diff_input() {
        let fp1 = compute_cert_fingerprint(b"hello");
        let fp2 = compute_cert_fingerprint(b"world");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_generate_tls_config() {
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let config = RelayTlsConfig::generate("test-node", addr).unwrap();
        assert!(!config.fingerprint.is_empty());
        assert_eq!(config.fingerprint.len(), 64);
    }

    #[tokio::test]
    async fn test_tls_accept_connect_roundtrip() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = RelayTlsConfig::generate("test-relay", addr).unwrap();
        let fingerprint = config.fingerprint.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bind_addr = listener.local_addr().unwrap();

        let fp_clone = fingerprint.clone();
        let server_config = config.acceptor.clone();
        let server = tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let tls_stream = server_config.accept(tcp_stream).await.unwrap();
            let mut stream: Box<dyn crate::types::RelayStreamTrait> = Box::new(tls_stream);
            let msg = Message::from_stream(&mut stream).await.unwrap().unwrap();
            msg.write_to_stream(&mut stream).await.unwrap();
        });

        let connector = RelayTlsConfig::make_tls_connector(&fp_clone).unwrap();
        let server_name = server_name_from_addr(bind_addr);
        let tcp_stream = TcpStream::connect(bind_addr).await.unwrap();
        let tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

        let mut client_stream: Box<dyn crate::types::RelayStreamTrait> = Box::new(tls_stream);
        let msg = Message::data(1, 1, b"hello".to_vec());
        msg.write_to_stream(&mut client_stream).await.unwrap();

        let response = Message::from_stream(&mut client_stream)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.data, b"hello");

        server.await.unwrap();
    }

    #[test]
    fn test_extend_payload_three_field_format() {
        let addr = "127.0.0.1:9002";
        let key = [0x42u8; 32];
        let fingerprint = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";

        let mut payload = Vec::new();
        payload.extend_from_slice(addr.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&key);
        payload.push(0);
        payload.extend_from_slice(fingerprint.as_bytes());

        let parts: Vec<&[u8]> = payload.split(|&b| b == 0).collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(std::str::from_utf8(parts[0]).unwrap(), addr);
        assert_eq!(parts[1], key);
        assert_eq!(std::str::from_utf8(parts[2]).unwrap(), fingerprint);
    }

    #[test]
    fn test_server_name_from_addr() {
        let addr: SocketAddr = "192.168.1.1:9001".parse().unwrap();
        let name = server_name_from_addr(addr);
        assert!(matches!(name, ServerName::IpAddress(_)));
    }

    #[test]
    fn test_make_tls_connector() {
        let connector = RelayTlsConfig::make_tls_connector(
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        );
        assert!(connector.is_ok());
    }
}
