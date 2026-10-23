//! Alternative routing (T6.3): reaching the API when `vpn-api.proton.me` is blocked, as win-app's
//! `AlternativeHostHandler` does.
//!
//! The route names are TXT records of `d<base32 of the API host>.protonpro.xyz` (prefixed with the session UID
//! when there is one), looked up over DNS over HTTPS so that a censored resolver can't hide them. Each record
//! is an alternative host: an IP address, or a name that's resolved over DoH too. Those hosts serve the API
//! with certificates that no CA vouches for; they're accepted only when their public key matches one of
//! [`PINS`] (win-app's pins for alternative routing).
//!
//! It only kicks in while the tunnel is down ([`set_tunnel_up`]) and the setting allows it
//! ([`set_enabled`]): through the VPN, API failures aren't censorship. A blocking kill switch (permanent
//! mode) lets only the API's own addresses through, so alternative routes can't work under it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

use super::doh;
use super::error::ApiError;

/// SHA-256 of the SubjectPublicKeyInfo of the alternative hosts' certificates (win-app
/// `DefaultTlsPinningConfigurationFactory`, the `ALTERNATIVE_ROUTING_HOSTNAME` entry).
pub const PINS: [&str; 4] = [
    "EU6TS9MO0L/GsDHvVc9D5fChYLNy5JdGYpJw0ccgetM=",
    "iKPIHPnDNqdkvOnTClQ8zQAIKG0XavaPkcEo0LBAABA=",
    "MSlVrBCdL0hKyczvgYVSRNm88RicyY04Q2y5qrBt0xA=",
    "C2UxW0T1Ckl9s+8cXfjXxlEqwAfPM4HiW2y3UdtBeCw=",
];
/// How long an alternative route is used before the direct API is tried again (win-app's
/// `AlternativeRoutingCheckInterval`).
pub const CHECK_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// win-app's `API_PING_TEST_PATH`.
pub const PING_PATH: &str = "tests/ping";

static ENABLED: AtomicBool = AtomicBool::new(true);
static TUNNEL_UP: AtomicBool = AtomicBool::new(false);

/// The "alternative routing" setting.
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

/// The engine reports whether the host is routed through the tunnel.
pub fn set_tunnel_up(up: bool) {
    TUNNEL_UP.store(up, Ordering::Relaxed);
}

pub fn allowed() -> bool {
    ENABLED.load(Ordering::Relaxed) && !TUNNEL_UP.load(Ordering::Relaxed)
}

/// Whether a failed request looks like the API being blocked (no answer, no name, a TLS failure, a reset)
/// rather than like an answer from it.
pub fn looks_blocked(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect()
}

/// The name whose TXT records list the alternative hosts for `api_host` (win-app's
/// `AlternativeRoutingHostGenerator`).
pub fn route_name(api_host: &str, uid: Option<&str>) -> String {
    let base = format!("d{}.protonpro.xyz", base32(api_host.as_bytes()));
    match uid.filter(|u| !u.is_empty()) {
        Some(uid) => format!("{uid}.{base}"),
        None => base,
    }
}

/// RFC 4648 base32, upper case, without padding.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// One alternative host, ready to send requests to.
#[derive(Clone)]
pub struct Route {
    /// As listed in the TXT record.
    pub host: String,
    /// `https://<host>`.
    pub base_url: String,
    pub http: reqwest::Client,
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route").field("host", &self.host).finish_non_exhaustive()
    }
}

/// The candidate routes for `api_host`, in the order the TXT records list them; a named host gets one route
/// per address.
pub async fn discover(api_host: &str, uid: Option<&str>, user_agent: &str) -> Result<Vec<Route>, ApiError> {
    let name = route_name(api_host, uid);
    let hosts = doh::txt(&name).await.map_err(|e| ApiError::AlternativeRouting(format!("{name}: {e}")))?;
    tracing::info!("alternative routing: {} host(s) listed for {name}", hosts.len());
    let mut routes = Vec::new();
    for host in hosts {
        let host = host.trim().to_owned();
        if let Ok(ip) = host.parse::<IpAddr>() {
            let base_url = match ip {
                IpAddr::V4(v4) => format!("https://{v4}"),
                IpAddr::V6(v6) => format!("https://[{v6}]"),
            };
            routes.push(Route { host, base_url, http: pinned_client(user_agent, None)? });
            continue;
        }
        match doh::a(&host).await {
            Ok(addresses) => {
                for address in addresses {
                    let http = pinned_client(user_agent, Some((&host, SocketAddr::new(address.into(), 443))))?;
                    routes.push(Route { host: host.clone(), base_url: format!("https://{host}"), http });
                }
            }
            Err(e) => tracing::warn!("alternative routing: resolving {host}: {e}"),
        }
    }
    if routes.is_empty() {
        return Err(ApiError::AlternativeRouting(format!("no usable host listed for {name}")));
    }
    Ok(routes)
}

/// A client that trusts only the [`PINS`], and sends `name` to `address` when given (SNI and Host stay the
/// name, as in win-app).
fn pinned_client(user_agent: &str, resolve: Option<(&str, SocketAddr)>) -> Result<reqwest::Client, ApiError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| ApiError::AlternativeRouting(format!("TLS setup: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { provider }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut builder = reqwest::Client::builder()
        .user_agent(user_agent)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .tls_backend_preconfigured(tls);
    if let Some((name, address)) = resolve {
        builder = builder.resolve(name, address);
    }
    builder.build().map_err(ApiError::Network)
}

/// base64 of the SHA-256 of a certificate's SubjectPublicKeyInfo (the usual "pin-sha256").
pub fn spki_pin(certificate_der: &[u8]) -> Option<String> {
    let (_, certificate) = x509_parser::parse_x509_certificate(certificate_der).ok()?;
    Some(BASE64.encode(Sha256::digest(certificate.tbs_certificate.subject_pki.raw)))
}

/// Accepts a server certificate whose key is one of [`PINS`], whatever its name, issuer or dates: the
/// alternative hosts' certificates are self-issued, so the pin is the whole check. Handshake signatures are
/// still verified, so the server must hold the pinned key.
#[derive(Debug)]
struct PinnedVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let pin = spki_pin(end_entity).ok_or(rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if PINS.contains(&pin.as_str()) {
            Ok(ServerCertVerified::assertion())
        } else {
            tracing::warn!("alternative routing: certificate key {pin} isn't pinned");
            Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_names() {
        // win-app's AlternativeRoutingHostGeneratorTest.
        assert_eq!(route_name("api.protonvpn.ch", None), "dMFYGSLTQOJXXI33OOZYG4LTDNA.protonpro.xyz");
        assert_eq!(route_name("api.protonvpn.ch", Some("")), "dMFYGSLTQOJXXI33OOZYG4LTDNA.protonpro.xyz");
        assert_eq!(route_name("api.protonvpn.ch", Some("abc123")), "abc123.dMFYGSLTQOJXXI33OOZYG4LTDNA.protonpro.xyz");
        assert_eq!(route_name("vpn-api.proton.me", None), "dOZYG4LLBOBUS44DSN52G63RONVSQ.protonpro.xyz");
        // RFC 4648 test vectors, unpadded.
        for (input, output) in [("", ""), ("f", "MY"), ("fo", "MZXQ"), ("foo", "MZXW6"), ("foobar", "MZXW6YTBOI")] {
            assert_eq!(base32(input.as_bytes()), output);
        }
    }

    #[test]
    fn pins_the_public_key() {
        let pem = include_str!("../../tests/fixtures/proton-vpn-root-ca.pem");
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = BASE64.decode(body).unwrap();
        let pin = spki_pin(&der).unwrap();
        assert_eq!(BASE64.decode(&pin).unwrap().len(), 32);
        assert!(!PINS.contains(&pin.as_str()), "the VPN root CA isn't an alternative-routing key");
        assert_eq!(spki_pin(b"not a certificate"), None);
    }

    #[test]
    fn only_while_disconnected_and_enabled() {
        assert!(allowed());
        set_tunnel_up(true);
        assert!(!allowed());
        set_tunnel_up(false);
        set_enabled(false);
        assert!(!allowed());
        set_enabled(true);
    }
}
