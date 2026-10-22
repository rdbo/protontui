//! Server signature validation (win-app `ServerValidator.cs`).
//!
//! Proton signs each physical server's entry IP and label with an Ed25519 key whose public half ships with the
//! clients. A server whose signature doesn't verify could send the tunnel somewhere else, so it's dropped.

use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, VerifyingKey};

use crate::api::servers::{LogicalServerDto, PhysicalServerDto};

/// `ServerValidationPublicKey` in win-app's `DefaultConfiguration.cs`: an Ed25519 SubjectPublicKeyInfo (DER).
pub const SERVER_VALIDATION_PUBLIC_KEY: &str = "MCowBQYDK2VwAyEANpYpt/FlSRwEuGLMoNAGOjy1BTyEJPJvKe00oln7LZk=";
/// DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw 32-byte key follows it.
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
/// Length of a base64 WireGuard public key (`SERVER_PUBLIC_KEY_LENGTH`).
const X25519_KEY_B64_LEN: usize = 44;

static VERIFYING_KEY: LazyLock<VerifyingKey> = LazyLock::new(|| {
    spki_to_key(SERVER_VALIDATION_PUBLIC_KEY).expect("the built-in server validation key is a valid Ed25519 SPKI")
});

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidServer {
    #[error("missing or malformed WireGuard public key")]
    BadPublicKey,
    #[error("missing signature")]
    MissingSignature,
    #[error("malformed signature")]
    MalformedSignature,
    #[error("signature does not match")]
    BadSignature,
}

fn spki_to_key(spki_b64: &str) -> Option<VerifyingKey> {
    let der = BASE64.decode(spki_b64).ok()?;
    let raw: [u8; 32] = der.strip_prefix(&ED25519_SPKI_PREFIX[..])?.try_into().ok()?;
    VerifyingKey::from_bytes(&raw).ok()
}

/// The signed message: `{"Server":{"EntryIP":"…","Label":"…"}}`, compact, keys in this order (the
/// Newtonsoft serialization of `ServerValidationObject`).
pub fn signed_message(entry_ip: &str, label: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "Server": { "EntryIP": entry_ip, "Label": label } }))
        .expect("serializing strings can't fail")
}

/// Checks the WireGuard key's shape and the signature, as `ServerValidator.Validate` does.
pub fn validate(server: &PhysicalServerDto) -> Result<(), InvalidServer> {
    validate_with(&VERIFYING_KEY, server)
}

fn validate_with(key: &VerifyingKey, server: &PhysicalServerDto) -> Result<(), InvalidServer> {
    let wg_key = server.x25519_public_key.as_deref().ok_or(InvalidServer::BadPublicKey)?;
    if wg_key.len() != X25519_KEY_B64_LEN || BASE64.decode(wg_key).map_or(true, |k| k.len() != 32) {
        return Err(InvalidServer::BadPublicKey);
    }
    let signature =
        server.signature.as_deref().filter(|s| !s.trim().is_empty()).ok_or(InvalidServer::MissingSignature)?;
    let signature = BASE64
        .decode(signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or(InvalidServer::MalformedSignature)?;
    key.verify_strict(&signed_message(&server.entry_ip, &server.label), &signature)
        .map_err(|_| InvalidServer::BadSignature)
}

/// Drops every physical server that fails [`validate`], then every logical server left without physical
/// servers. Returns how many physical servers were dropped. CPU bound (one Ed25519 check per server, ~19k on
/// the live list): call it from a blocking task.
pub fn retain_valid(logicals: &mut Vec<LogicalServerDto>) -> usize {
    let mut dropped = 0;
    for logical in logicals.iter_mut() {
        logical.servers.retain(|server| match validate(server) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("dropping server {} ({}): {e}", logical.name, server.domain);
                dropped += 1;
                false
            }
        });
    }
    logicals.retain(|logical| !logical.servers.is_empty());
    dropped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::servers::LogicalsResponse;

    fn fixture() -> Vec<LogicalServerDto> {
        let response: LogicalsResponse =
            serde_json::from_str(include_str!("../../tests/fixtures/logicals.json")).unwrap();
        response.logical_servers
    }

    #[test]
    fn built_in_key_parses() {
        LazyLock::force(&VERIFYING_KEY);
        assert!(spki_to_key("AAAA").is_none());
    }

    #[test]
    fn message_matches_newtonsoft_shape() {
        assert_eq!(signed_message("1.2.3.4", ""), br#"{"Server":{"EntryIP":"1.2.3.4","Label":""}}"#);
    }

    #[test]
    fn fixture_servers_verify() {
        let logicals = fixture();
        let physicals: Vec<_> = logicals.iter().flat_map(|l| &l.servers).collect();
        assert!(physicals.iter().any(|p| p.label.is_empty()) && physicals.iter().any(|p| !p.label.is_empty()));
        for server in physicals {
            assert_eq!(validate(server), Ok(()), "{}", server.domain);
        }
    }

    #[test]
    fn tampered_servers_fail() {
        let original = fixture()[0].servers[0].clone();
        let tamper = |f: &dyn Fn(&mut PhysicalServerDto)| {
            let mut server = original.clone();
            f(&mut server);
            validate(&server)
        };
        assert_eq!(tamper(&|s| s.entry_ip = "203.0.113.7".into()), Err(InvalidServer::BadSignature));
        assert_eq!(tamper(&|s| s.label.push('1')), Err(InvalidServer::BadSignature));
        assert_eq!(tamper(&|s| s.signature = None), Err(InvalidServer::MissingSignature));
        assert_eq!(tamper(&|s| s.signature = Some("not base64!".into())), Err(InvalidServer::MalformedSignature));
        assert_eq!(tamper(&|s| s.x25519_public_key = Some("short".into())), Err(InvalidServer::BadPublicKey));
        assert_eq!(tamper(&|s| s.x25519_public_key = None), Err(InvalidServer::BadPublicKey));
        // A signature from another server doesn't carry over.
        let other = fixture().into_iter().flat_map(|l| l.servers).find(|s| s.entry_ip != original.entry_ip).unwrap();
        assert_eq!(tamper(&|s| s.signature = other.signature.clone()), Err(InvalidServer::BadSignature));
        // Exit IP, domain and status are not signed.
        assert_eq!(tamper(&|s| s.exit_ip = "203.0.113.8".into()), Ok(()));
    }

    #[test]
    fn retain_valid_drops_tampered_and_empty_logicals() {
        let mut logicals = fixture();
        let total: usize = logicals.iter().map(|l| l.servers.len()).sum();
        // Tamper with one server of a multi-server logical, and with the only server of another.
        let multi = logicals.iter().position(|l| l.servers.len() > 1).unwrap();
        logicals[multi].servers[0].entry_ip = "203.0.113.9".into();
        let single = logicals.iter().position(|l| l.servers.len() == 1).unwrap();
        let single_id = logicals[single].id.clone();
        logicals[single].servers[0].signature = None;

        assert_eq!(retain_valid(&mut logicals), 2);
        assert_eq!(logicals.iter().map(|l| l.servers.len()).sum::<usize>(), total - 2);
        assert!(logicals.iter().all(|l| l.id != single_id), "a logical without servers is dropped");
        assert!(logicals.iter().flat_map(|l| &l.servers).all(|s| s.entry_ip != "203.0.113.9"));
    }
}
