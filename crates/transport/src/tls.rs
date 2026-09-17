use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::version::TLS13;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, ServerConfig,
    SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use zeroize::Zeroize;

pub const ALPN_H2: &[u8] = b"h2";
const IDENTITY_MAGIC: &[u8; 8] = b"GCTLSID\x01";

/// A stable TLS server identity consisting of one certificate and its PKCS#8 key.
pub struct TlsIdentity {
    certificate_der: Vec<u8>,
    private_key_pkcs8_der: Vec<u8>,
    service_id: [u8; 32],
}

impl TlsIdentity {
    pub fn generate() -> Result<Self, rcgen::Error> {
        let key = rcgen::KeyPair::generate()?;
        let mut params = rcgen::CertificateParams::new(vec![])?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "local");
        let cert = params.self_signed(&key)?;
        Ok(Self {
            certificate_der: cert.der().to_vec(),
            private_key_pkcs8_der: key.serialize_der(),
            service_id: Sha256::digest(key.public_key_der()).into(),
        })
    }

    pub fn from_der(
        certificate_der: Vec<u8>,
        private_key_pkcs8_der: Vec<u8>,
    ) -> Result<Self, TlsIdentityError> {
        if certificate_der.is_empty() || private_key_pkcs8_der.is_empty() {
            return Err(TlsIdentityError::InvalidEncoding);
        }
        let service_id = certificate_service_id(&certificate_der)
            .map_err(|_| TlsIdentityError::InvalidEncoding)?;
        let identity = Self {
            certificate_der,
            private_key_pkcs8_der,
            service_id,
        };
        identity
            .server_config()
            .map_err(TlsIdentityError::InvalidIdentity)?;
        Ok(identity)
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub fn private_key_pkcs8_der(&self) -> &[u8] {
        &self.private_key_pkcs8_der
    }

    /// Encodes this identity in a versioned, length-delimited binary format.
    pub fn encode(&self) -> Result<Vec<u8>, TlsIdentityError> {
        let cert_len = u32::try_from(self.certificate_der.len())
            .map_err(|_| TlsIdentityError::IdentityTooLarge)?;
        let key_len = u32::try_from(self.private_key_pkcs8_der.len())
            .map_err(|_| TlsIdentityError::IdentityTooLarge)?;
        let mut encoded = Vec::with_capacity(
            IDENTITY_MAGIC.len()
                + 8
                + self.certificate_der.len()
                + self.private_key_pkcs8_der.len(),
        );
        encoded.extend_from_slice(IDENTITY_MAGIC);
        encoded.extend_from_slice(&cert_len.to_be_bytes());
        encoded.extend_from_slice(&key_len.to_be_bytes());
        encoded.extend_from_slice(&self.certificate_der);
        encoded.extend_from_slice(&self.private_key_pkcs8_der);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, TlsIdentityError> {
        if encoded.len() < IDENTITY_MAGIC.len() + 8
            || &encoded[..IDENTITY_MAGIC.len()] != IDENTITY_MAGIC
        {
            return Err(TlsIdentityError::InvalidEncoding);
        }
        let lengths = &encoded[IDENTITY_MAGIC.len()..IDENTITY_MAGIC.len() + 8];
        let cert_len = u32::from_be_bytes(lengths[..4].try_into().unwrap()) as usize;
        let key_len = u32::from_be_bytes(lengths[4..].try_into().unwrap()) as usize;
        let cert_start = IDENTITY_MAGIC.len() + 8;
        let cert_end = cert_start
            .checked_add(cert_len)
            .ok_or(TlsIdentityError::InvalidEncoding)?;
        let key_end = cert_end
            .checked_add(key_len)
            .ok_or(TlsIdentityError::InvalidEncoding)?;
        if key_end != encoded.len() {
            return Err(TlsIdentityError::InvalidEncoding);
        }
        Self::from_der(
            encoded[cert_start..cert_end].to_vec(),
            encoded[cert_end..].to_vec(),
        )
    }

    pub fn service_id(&self) -> [u8; 32] {
        self.service_id
    }

    pub fn server_config(&self) -> Result<ServerConfig, TlsError> {
        server_config(
            CertificateDer::from(self.certificate_der.clone()),
            PrivateKeyDer::Pkcs8(self.private_key_pkcs8_der.clone().into()),
        )
    }
}

impl Drop for TlsIdentity {
    fn drop(&mut self) {
        self.private_key_pkcs8_der.zeroize();
    }
}

#[derive(Debug)]
pub enum TlsIdentityError {
    InvalidEncoding,
    IdentityTooLarge,
    InvalidIdentity(TlsError),
}

impl fmt::Display for TlsIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding => f.write_str("invalid TLS identity encoding"),
            Self::IdentityTooLarge => f.write_str("TLS identity is too large to encode"),
            Self::InvalidIdentity(error) => write!(f, "invalid TLS identity: {error}"),
        }
    }
}

impl std::error::Error for TlsIdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidIdentity(error) => Some(error),
            _ => None,
        }
    }
}

fn provider() -> rustls::crypto::CryptoProvider {
    let base = rustls::crypto::aws_lc_rs::default_provider();
    rustls::crypto::CryptoProvider {
        cipher_suites: base.cipher_suites,
        kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768],
        ..base
    }
}

pub fn generate_self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let identity = TlsIdentity::generate().expect("self-signed identity");
    (
        CertificateDer::from(identity.certificate_der.clone()),
        PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            identity.private_key_pkcs8_der.clone(),
        )),
    )
}

pub fn server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, TlsError> {
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    cfg.alpn_protocols = vec![ALPN_H2.to_vec()];
    cfg.send_tls13_tickets = 0;
    Ok(cfg)
}

/// Builds a TLS 1.3 client config accepting only a leaf with the pinned SPKI.
pub fn client_config_pinned(expected_service_id: [u8; 32]) -> Result<ClientConfig, TlsError> {
    let provider = Arc::new(provider());
    let verifier = PinnedVerifier {
        expected_service_id,
        provider: provider.clone(),
    };
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN_H2.to_vec()];
    cfg.resumption = rustls::client::Resumption::disabled();
    Ok(cfg)
}

pub fn server_name_ip(ip: std::net::IpAddr) -> ServerName<'static> {
    ServerName::IpAddress(rustls::pki_types::IpAddr::from(ip))
}

pub fn server_name_ip_or_host(host: &str) -> ServerName<'static> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        server_name_ip(ip)
    } else {
        ServerName::try_from(host.to_string()).expect("valid host name")
    }
}

#[derive(Debug)]
struct PinnedVerifier {
    expected_service_id: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedVerifier {
    fn verify_pin(&self, cert: &CertificateDer<'_>) -> Result<(), TlsError> {
        let actual = certificate_service_id(cert.as_ref()).map_err(|_| {
            TlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        })?;
        if actual != self.expected_service_id {
            return Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(())
    }
}

fn certificate_service_id(cert_der: &[u8]) -> Result<[u8; 32], ()> {
    let (remainder, certificate) = x509_parser::parse_x509_certificate(cert_der).map_err(|_| ())?;
    if !remainder.is_empty() {
        return Err(());
    }
    Ok(Sha256::digest(certificate.public_key().raw).into())
}

impl rustls::client::danger::ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, TlsError> {
        self.verify_pin(end_entity)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        self.verify_pin(cert)?;
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        self.verify_pin(cert)?;
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    fn identity_for_key(key: &rcgen::KeyPair, serial: u64) -> TlsIdentity {
        let mut params = rcgen::CertificateParams::new(vec![]).expect("certificate params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "local");
        params.serial_number = Some(serial.into());
        let certificate = params.self_signed(key).expect("certificate");
        TlsIdentity::from_der(certificate.der().to_vec(), key.serialize_der()).expect("identity")
    }

    #[test]
    fn identity_roundtrip_keeps_service_id() {
        let identity = TlsIdentity::generate().expect("identity");
        let service_id = identity.service_id();
        let decoded = TlsIdentity::decode(&identity.encode().expect("encode")).expect("decode");
        assert_eq!(decoded.service_id(), service_id);
        assert_eq!(decoded.certificate_der(), identity.certificate_der());
    }

    #[test]
    fn service_id_is_sha256_of_spki_and_survives_reissue() {
        let key = rcgen::KeyPair::generate().expect("key");
        let first = identity_for_key(&key, 1);
        let reissued = identity_for_key(&key, 2);
        let expected: [u8; 32] = Sha256::digest(key.public_key_der()).into();

        assert_ne!(first.certificate_der(), reissued.certificate_der());
        assert_eq!(first.service_id(), reissued.service_id());
        assert_eq!(first.service_id(), expected);
    }

    #[test]
    fn service_id_differs_for_different_keys() {
        let first = TlsIdentity::generate().expect("first identity");
        let second = TlsIdentity::generate().expect("second identity");
        assert_ne!(first.service_id(), second.service_id());
    }

    #[test]
    fn pinned_verifier_rejects_malformed_certificate() {
        let verifier = PinnedVerifier {
            expected_service_id: [0; 32],
            provider: Arc::new(provider()),
        };
        assert!(verifier
            .verify_pin(&CertificateDer::from(vec![0x30, 0x01, 0x00]))
            .is_err());
    }

    #[test]
    fn right_pin_config_builds() {
        let identity = TlsIdentity::generate().expect("identity");
        let config = client_config_pinned(identity.service_id()).expect("client config");
        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn configs_build() {
        let (cert, key) = generate_self_signed();
        let s = server_config(cert, key).expect("server config");
        assert_eq!(s.alpn_protocols, vec![b"h2".to_vec()]);
        assert_eq!(s.send_tls13_tickets, 0);
        let c = client_config_pinned([7; 32]).expect("client config");
        assert_eq!(c.alpn_protocols, vec![b"h2".to_vec()]);
    }

    async fn handshake(identity: &TlsIdentity, pin: [u8; 32]) -> bool {
        let server = Arc::new(identity.server_config().expect("server config"));
        let client = Arc::new(client_config_pinned(pin).expect("client config"));
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let accept = TlsAcceptor::from(server).accept(server_io);
        let connect = TlsConnector::from(client)
            .connect(server_name_ip("127.0.0.1".parse().unwrap()), client_io);
        let (client_result, server_result) = tokio::join!(connect, accept);
        client_result.is_ok() && server_result.is_ok()
    }

    #[tokio::test]
    async fn pinned_handshake_rejects_wrong_pin_and_accepts_right_pin() {
        let identity = TlsIdentity::generate().expect("identity");
        let mut wrong_pin = identity.service_id();
        wrong_pin[0] ^= 1;
        assert!(!handshake(&identity, wrong_pin).await);
        assert!(handshake(&identity, identity.service_id()).await);
    }
}
