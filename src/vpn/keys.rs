//! Ed25519 keypair, X25519 derivation and the certificate lifecycle (T3.1).
//!
//! One Ed25519 keypair serves both ends: the API certifies its public key (`vpn/v1/certificate`), the local
//! agent authenticates with it, and its X25519 conversion is the WireGuard private key, so the server can tie
//! the tunnel to the certificate. Mirrors api-core's `session/key_mgr.py` and `session/credentials.py`.

use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::api::ApiClient;
use crate::api::vpn::CertificateRequest;
use crate::config::{self, NetShield, Paths, Settings};

/// Certificate lifetime asked for: 7 days, as api-core (`VPNPubkeyCredentials.REFRESH_INTERVAL`).
pub const CERTIFICATE_DURATION: &str = "10080 min";
/// A certificate this close to expiry is replaced even before its `RefreshTime` (api-core
/// `MINIMUM_VALIDITY_PERIOD_IN_SECS`).
pub const MINIMUM_VALIDITY_SECS: u64 = 300;

/// DER prefix of an Ed25519 SubjectPublicKeyInfo; the 32-byte key follows.
const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
/// DER prefix of an Ed25519 PKCS#8 private key; the 32-byte seed follows.
const PKCS8_PREFIX: [u8; 16] =
    [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

/// The client keypair. `Debug` never prints the secret.
pub struct VpnKeys {
    signing: SigningKey,
}

impl std::fmt::Debug for VpnKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VpnKeys").field("fingerprint", &self.fingerprint()).finish_non_exhaustive()
    }
}

/// What `keys.json` holds (api-core `VPNSecrets.to_dict`). Written `0600`.
#[derive(Serialize, Deserialize)]
struct StoredKeys {
    /// The 32-byte Ed25519 seed, base64.
    ed25519_privatekey: String,
}

impl VpnKeys {
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(seed.as_mut());
        Self { signing: SigningKey::from_bytes(&seed) }
    }

    /// From a base64 Ed25519 seed (the `ed25519_privatekey` format api-core stores).
    pub fn from_base64(seed: &str) -> Result<Self> {
        let bytes = Zeroizing::new(BASE64.decode(seed.trim()).context("decoding the Ed25519 key")?);
        let seed: &[u8; 32] = bytes.as_slice().try_into().context("Ed25519 key must be 32 bytes")?;
        Ok(Self { signing: SigningKey::from_bytes(seed) })
    }

    /// Loads the keypair from `path`, or generates and stores a new one.
    pub fn load_or_generate(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let stored: StoredKeys =
                    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
                Self::from_base64(&stored.ed25519_privatekey)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let keys = Self::generate();
                let stored = StoredKeys { ed25519_privatekey: BASE64.encode(keys.signing.to_bytes()) };
                let json = Zeroizing::new(serde_json::to_vec_pretty(&stored)?);
                config::write_atomic(path, &json, 0o600).with_context(|| format!("writing {}", path.display()))?;
                tracing::info!("generated a new client keypair ({})", keys.fingerprint());
                Ok(keys)
            }
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Ed25519 public key as SPKI PEM: the certificate request's `ClientPublicKey`.
    pub fn ed25519_public_pem(&self) -> String {
        let mut der = SPKI_PREFIX.to_vec();
        der.extend_from_slice(self.signing.verifying_key().as_bytes());
        pem("PUBLIC KEY", &der)
    }

    /// Ed25519 private key as unencrypted PKCS#8 PEM, for the local agent's TLS client auth (T3.7).
    pub fn ed25519_private_pem(&self) -> Zeroizing<String> {
        let mut der = Zeroizing::new(PKCS8_PREFIX.to_vec());
        der.extend_from_slice(self.signing.as_bytes());
        Zeroizing::new(pem("PRIVATE KEY", &der))
    }

    /// The WireGuard private key: libsodium's `crypto_sign_ed25519_sk_to_curve25519`, i.e. the first half of
    /// SHA-512(seed), clamped.
    pub fn x25519_private(&self) -> Zeroizing<[u8; 32]> {
        let hash = Zeroizing::new(Sha512::digest(self.signing.as_bytes()));
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&hash[..32]);
        key[0] &= 248;
        key[31] &= 127;
        key[31] |= 64;
        key
    }

    /// The WireGuard public key: the Ed25519 public key mapped to Montgomery form
    /// (`crypto_sign_ed25519_pk_to_curve25519`).
    pub fn x25519_public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_montgomery().to_bytes()
    }

    /// base64(SHA-512(X25519 public key)): what the API returns as `ClientKeyFingerprint` and embeds in the
    /// certificate (api-core `get_proton_fingerprint_from_x25519_pk`).
    pub fn fingerprint(&self) -> String {
        BASE64.encode(Sha512::digest(self.x25519_public()))
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    let body = BASE64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The connection features baked into a certificate. The local agent can change them live (T3.7); the
/// certificate makes them apply even when it can't.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateFeatures {
    pub netshield_level: u8,
    pub vpn_accelerator: bool,
    pub moderate_nat: bool,
    pub port_forwarding: bool,
}

impl CertificateFeatures {
    pub fn from_settings(settings: &Settings, tier: u8) -> Self {
        Self {
            netshield_level: settings.netshield_for_tier(tier).level(),
            vpn_accelerator: settings.vpn_accelerator,
            moderate_nat: settings.moderate_nat,
            port_forwarding: settings.port_forwarding,
        }
    }

    /// The request's `Features`: only values that differ from the server defaults (api-core
    /// `VPNSessionFetcher._convert_features`).
    pub fn to_request(self) -> Map<String, Value> {
        let mut features = Map::new();
        if !self.moderate_nat {
            features.insert("RandomNAT".into(), false.into());
        }
        if !self.vpn_accelerator {
            features.insert("SplitTCP".into(), false.into());
        }
        if self.port_forwarding {
            features.insert("PortForwarding".into(), true.into());
        }
        if self.netshield_level != NetShield::Off.level() {
            features.insert("NetShieldLevel".into(), self.netshield_level.into());
        }
        features
    }
}

/// What `certificate.json` holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCertificate {
    /// X.509, PEM.
    pub certificate: String,
    /// Unix seconds.
    pub expiration_time: u64,
    /// Unix seconds.
    pub refresh_time: u64,
    pub features: CertificateFeatures,
    /// [`VpnKeys::fingerprint`] of the key it certifies.
    pub fingerprint: String,
}

impl StoredCertificate {
    pub fn load(path: &Path) -> Result<Option<Self>> {
        match std::fs::read(path) {
            // An unreadable certificate is just a missing one: ask for a new one.
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        config::write_atomic(path, &serde_json::to_vec_pretty(self)?, 0o600)
            .with_context(|| format!("writing {}", path.display()))
    }

    /// Whether this certificate can be used as is for `keys` and `features` at `now`.
    /// [`Self::usable`] without the refresh time, for connecting while the API is out of reach (a blocking
    /// kill switch): the refresh then happens through the tunnel.
    pub fn usable_offline(&self, keys: &VpnKeys, features: &CertificateFeatures, now: u64) -> bool {
        self.fingerprint == keys.fingerprint()
            && &self.features == features
            && now + MINIMUM_VALIDITY_SECS < self.expiration_time
    }

    pub fn usable(&self, keys: &VpnKeys, features: &CertificateFeatures, now: u64) -> bool {
        self.fingerprint == keys.fingerprint()
            && &self.features == features
            && now < self.refresh_time
            && now + MINIMUM_VALIDITY_SECS < self.expiration_time
    }
}

/// Returns a certificate for `keys` with `features`: the stored one while it's usable, else a new one from
/// the API (stored before returning). Feature changes therefore take effect at the next connection even
/// without the local agent.
pub async fn ensure_certificate(
    api: &ApiClient,
    paths: &Paths,
    keys: &VpnKeys,
    features: CertificateFeatures,
) -> Result<StoredCertificate> {
    let path = paths.certificate_file();
    if let Some(stored) = StoredCertificate::load(&path)?
        && stored.usable(keys, &features, config::unix_now())
    {
        return Ok(stored);
    }
    let certificate = request_certificate(api, keys, features).await?;
    certificate.save(&path)?;
    Ok(certificate)
}

/// Asks the API for a new certificate and checks that it certifies `keys`.
pub async fn request_certificate(
    api: &ApiClient,
    keys: &VpnKeys,
    features: CertificateFeatures,
) -> Result<StoredCertificate> {
    let request = CertificateRequest {
        client_public_key: keys.ed25519_public_pem(),
        client_public_key_mode: "EC".into(),
        device_name: device_name(),
        duration: CERTIFICATE_DURATION.into(),
        mode: "session".into(),
        features: features.to_request(),
    };
    let response = api.request_certificate(&request).await.context("requesting a VPN certificate")?;
    let fingerprint = keys.fingerprint();
    // api-core refuses a certificate whose fingerprint doesn't match the local key (strict mode).
    if let Some(theirs) = &response.client_key_fingerprint
        && theirs != &fingerprint
    {
        bail!("the API certified a different key (fingerprint {theirs}, expected {fingerprint})");
    }
    tracing::info!(
        "new VPN certificate: refresh at {}, expires at {}, features {features:?}",
        response.refresh_time,
        response.expiration_time
    );
    Ok(StoredCertificate {
        certificate: response.certificate,
        expiration_time: response.expiration_time,
        refresh_time: response.refresh_time,
        features,
        fingerprint,
    })
}

/// `protontui-<hostname>`, shown in the account's session list.
pub fn device_name() -> String {
    let host = nix::unistd::gethostname().ok().and_then(|h| h.into_string().ok()).unwrap_or_default();
    if host.is_empty() { "protontui".into() } else { format!("protontui-{host}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    // From python-proton-vpn-api-core tests/python/session/data: a key and the API's certificate response
    // for it (`ClientKey`, `ClientKeyFingerprint`).
    const API_CORE_SEED: &str = "rNW3dL5A3dUrQX3ZKbVAFLjSFJdvDU5JzjrRrnI+cos=";
    const API_CORE_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAoqBxaQgj21lzBd9YG0iotoSoHLXQDYS2LdDtiE6Jtk=\n-----END PUBLIC KEY-----\n";
    const API_CORE_FINGERPRINT: &str =
        "a3CzIFFDKF5w4CtPDaz8mWZWzljRb+SqGTkvktCqznMhUemScDonoinYDz8ncOfQw7WI0Ek5aombSVSITnQDTw==";

    // libsodium test/default/ed25519_convert.{c,exp}.
    const SODIUM_SEED: &str = "421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee";
    const SODIUM_X25519_PUBLIC: &str = "f1814f0e8ff1043d8a44d25babff3cedcae6c22c3edaa48f857ae70de2baae50";
    const SODIUM_X25519_SECRET: &str = "8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn libsodium_conversion_vector() {
        let keys = VpnKeys::from_base64(&BASE64.encode(from_hex(SODIUM_SEED))).unwrap();
        assert_eq!(hex(keys.x25519_private().as_ref()), SODIUM_X25519_SECRET);
        assert_eq!(hex(&keys.x25519_public()), SODIUM_X25519_PUBLIC);
    }

    #[test]
    fn matches_the_api_certificate_for_a_known_key() {
        let keys = VpnKeys::from_base64(API_CORE_SEED).unwrap();
        assert_eq!(keys.ed25519_public_pem(), API_CORE_PUBLIC_PEM);
        assert_eq!(keys.fingerprint(), API_CORE_FINGERPRINT);
    }

    #[test]
    fn x25519_public_matches_the_derived_private_key() {
        let keys = VpnKeys::generate();
        let private = curve25519_dalek::Scalar::from_bytes_mod_order(*keys.x25519_private());
        let public = curve25519_dalek::MontgomeryPoint::mul_base(&private);
        assert_eq!(public.to_bytes(), keys.x25519_public());
    }

    #[test]
    fn private_pem_is_pkcs8() {
        let keys = VpnKeys::from_base64(API_CORE_SEED).unwrap();
        let pem = keys.ed25519_private_pem();
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = BASE64.decode(body).unwrap();
        assert_eq!(der[..16], PKCS8_PREFIX);
        assert_eq!(BASE64.encode(&der[16..]), API_CORE_SEED);
    }

    #[test]
    fn keys_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let first = VpnKeys::load_or_generate(&path).unwrap();
        let again = VpnKeys::load_or_generate(&path).unwrap();
        assert_eq!(first.fingerprint(), again.fingerprint());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn features_follow_api_core() {
        let defaults = CertificateFeatures::from_settings(&Settings::default(), 2);
        // Defaults: NetShield 1 for paid tiers, accelerator on, moderate NAT off, no port forwarding.
        assert_eq!(
            serde_json::Value::Object(defaults.to_request()),
            serde_json::json!({"RandomNAT": false, "NetShieldLevel": 1})
        );
        let free = CertificateFeatures::from_settings(&Settings::default(), 0);
        assert_eq!(serde_json::Value::Object(free.to_request()), serde_json::json!({"RandomNAT": false}));
        let custom = CertificateFeatures {
            netshield_level: 2,
            vpn_accelerator: false,
            moderate_nat: true,
            port_forwarding: true,
        };
        assert_eq!(
            serde_json::Value::Object(custom.to_request()),
            serde_json::json!({"SplitTCP": false, "PortForwarding": true, "NetShieldLevel": 2})
        );
    }

    #[test]
    fn certificate_reuse_rules() {
        let keys = VpnKeys::generate();
        let features = CertificateFeatures::from_settings(&Settings::default(), 2);
        let cert = StoredCertificate {
            certificate: String::new(),
            expiration_time: 10_000,
            refresh_time: 8_000,
            features,
            fingerprint: keys.fingerprint(),
        };
        assert!(cert.usable(&keys, &features, 1_000));
        assert!(!cert.usable(&keys, &features, 8_000), "past RefreshTime");
        assert!(!cert.usable(&keys, &CertificateFeatures { port_forwarding: true, ..features }, 1_000));
        assert!(!cert.usable(&VpnKeys::generate(), &features, 1_000), "other key");
        let short = StoredCertificate { refresh_time: 20_000, ..cert };
        assert!(!short.usable(&keys, &features, 9_800), "about to expire");
    }

    #[tokio::test]
    async fn requests_and_reuses_a_certificate() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let keys = VpnKeys::generate();
        let server = MockServer::start().await;
        let now = config::unix_now();
        Mock::given(method("POST"))
            .and(path("/vpn/v1/certificate"))
            .and(body_partial_json(serde_json::json!({
                "ClientPublicKey": keys.ed25519_public_pem(),
                "ClientPublicKeyMode": "EC",
                "Mode": "session",
                "Duration": "10080 min",
                "Features": {"RandomNAT": false, "NetShieldLevel": 1},
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
                "ExpirationTime": now + 7 * 86400,
                "RefreshTime": now + 5 * 86400,
                "ClientKeyFingerprint": keys.fingerprint(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        let api = ApiClient::new(&server.uri()).unwrap();
        let features = CertificateFeatures::from_settings(&Settings::default(), 2);
        let first = ensure_certificate(&api, &paths, &keys, features).await.unwrap();
        // Second call: served from disk (the mock expects exactly one request).
        let second = ensure_certificate(&api, &paths, &keys, features).await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn refuses_a_certificate_for_another_key() {
        use wiremock::matchers::path;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(path("/vpn/v1/certificate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000, "Certificate": "x", "ExpirationTime": 2, "RefreshTime": 1,
                "ClientKeyFingerprint": VpnKeys::generate().fingerprint(),
            })))
            .mount(&server)
            .await;
        let api = ApiClient::new(&server.uri()).unwrap();
        let features = CertificateFeatures::from_settings(&Settings::default(), 2);
        assert!(request_certificate(&api, &VpnKeys::generate(), features).await.is_err());
    }
}
