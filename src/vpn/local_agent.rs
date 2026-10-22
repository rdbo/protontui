//! Local agent client: NetShield, VPN Accelerator, Moderate NAT, port forwarding (T3.7).
//!
//! Built on Proton's `local_agent_rs` crate: a TLS connection to `10.2.0.1:65432` through the tunnel,
//! authenticated with the API certificate and the Ed25519 key. The call sequence follows api-core's
//! `localagent_mixin.py`: connect, request the features (paid plans only: the agent refuses a feature request
//! from a Free session, even for the defaults), then read status messages. A `hard-jailed` status means the
//! server blocks the connection, with a reason code. Port forwarding is a NAT-PMP lease on `10.2.0.1:5351`
//! that lasts 60 s and gets renewed while the agent reports `port-forwarding`, as the crate's `Listener` does.
//!
//! [`Agent`] runs all that in a background task and reports [`AgentEvent`]s to the connection task, which
//! owns the reactions (new certificate, ending the connection). The certificate's own features (T3.1) already
//! apply without the agent, so an agent that can't be reached only costs live changes and statistics.

use std::time::Duration;

use local_agent_rs::{AgentConnection, AgentConnector, ConnectParams, Error as AgentError, State, StatusMessage};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

pub use local_agent_rs::AgentFeatures;

use crate::config::Settings;

/// Timeout for connecting and for each request, in seconds (the crate's own default).
pub const TIMEOUT_SECS: u64 = 10;
/// NAT-PMP leases last 60 s; renew well before.
const PORT_FORWARDING_RENEWAL: Duration = Duration::from_secs(45);
const PORT_FORWARDING_RETRIES: u32 = 2;
/// How often NetShield statistics are requested.
const STATISTICS_INTERVAL: Duration = Duration::from_secs(30);
/// Consecutive failed (re)connections before giving up for this tunnel.
const MAX_FAILURES: u32 = 5;
/// Longest wait for a certificate that starts in the future (the local clock is behind the API's).
const MAX_CLOCK_WAIT: Duration = Duration::from_secs(30 * 60);

/// What the agent's server-side counterpart blocked so far on this connection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetShieldStats {
    pub malware: u32,
    pub ads: u32,
    pub trackers: u32,
}

/// What the agent task reports to the connection.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentEvent {
    /// The agent confirmed the connection; `features` are the ones in effect.
    Connected {
        features: Option<AgentFeatures>,
    },
    /// The forwarded port changed (`None`: no longer forwarded).
    PortForward(Option<u16>),
    NetShieldStats(NetShieldStats),
    /// The agent refused our certificate (expired, revoked, not yet valid): get a new one, then restart it.
    CertificateRejected(String),
    /// The server blocks this connection for good (too many devices, restricted server, policy).
    Jailed {
        code: i32,
        description: String,
    },
    /// Something the user should know; the connection itself carries on.
    Warning(String),
}

/// Reason codes that a new certificate fixes (`reason_code.rs`).
const CERTIFICATE_CODES: [i32; 4] = [
    local_agent_rs::REASON_CODE_CERTIFICATE_EXPIRED,
    local_agent_rs::REASON_CODE_CERTIFICATE_REVOKED,
    local_agent_rs::REASON_CODE_BAD_CERT_SIGNATURE,
    local_agent_rs::REASON_CODE_CERT_NOT_PROVIDED,
];

/// The features to request, as api-core's `__get_agent_features`. `None` for Free (tier 0): the agent
/// rejects feature requests from Free sessions, which then get the defaults.
pub fn features_for(settings: &Settings, tier: u8, label: &str) -> Option<AgentFeatures> {
    (tier > 0).then(|| AgentFeatures {
        netshield_level: Some(settings.netshield_for_tier(tier).level()),
        randomized_nat: Some(!settings.moderate_nat),
        split_tcp: Some(settings.vpn_accelerator),
        port_forwarding: Some(settings.port_forwarding),
        bouncing: (!label.is_empty()).then(|| label.to_owned()),
        ..AgentFeatures::default()
    })
}

/// A human-readable explanation for a jail reason.
pub fn describe_jail(code: i32, description: &str) -> String {
    use local_agent_rs::*;
    let text = match code {
        REASON_CODE_MAX_SESSIONS_UNKNOWN..=REASON_CODE_MAX_SESSIONS_PRO => {
            "too many devices are connected for this plan; disconnect one and try again"
        }
        REASON_CODE_RESTRICTED_SERVER => "this server isn't available to this account",
        REASON_CODE_USER_TORRENT_NOT_ALLOWED => "file sharing isn't allowed on this server; use a P2P server",
        REASON_CODE_POLICY_VIOLATION_LOW_PLAN => "this server needs a higher plan",
        REASON_CODE_POLICY_VIOLATION_DELINQUENT => "the account has an unpaid invoice",
        REASON_CODE_2FA_UNSPECIFIED | REASON_CODE_2FA_EXPIRED | REASON_CODE_2FA_SITUATION_CHANGED => {
            "the server asks for two-factor authentication; sign out and in again"
        }
        REASON_CODE_GUEST_SESSION => "guest sessions can't use this server",
        _ => return format!("the server blocked the connection: {description} ({code})"),
    };
    format!("{text} ({code})")
}

/// What the agent needs to authenticate.
pub struct AgentParams {
    /// The physical server's `Domain`, checked against the agent's TLS certificate.
    pub domain: String,
    /// Ed25519 key, PKCS#8 PEM.
    pub key_pem: Zeroizing<String>,
    /// The API certificate, PEM.
    pub certificate_pem: String,
}

/// A running agent client. Dropping it stops the task.
pub struct Agent {
    features: watch::Sender<Option<AgentFeatures>>,
    task: JoinHandle<()>,
}

impl Agent {
    pub fn spawn(
        params: AgentParams,
        features: Option<AgentFeatures>,
        events: mpsc::UnboundedSender<AgentEvent>,
    ) -> Self {
        let (features, features_rx) = watch::channel(features);
        let task = tokio::spawn(run(params, features_rx, events));
        Self { features, task }
    }

    /// Pushes new features to the agent (live settings change). Ignored for Free (`None`).
    pub fn set_features(&self, features: Option<AgentFeatures>) {
        self.features.send_if_modified(|current| {
            let changed = *current != features;
            *current = features;
            changed
        });
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.task.abort();
    }
}

enum Outcome {
    /// Done for this tunnel (jailed, certificate rejected, or the owner went away).
    Stop,
    /// The session failed; `established` says whether it got as far as reading a status.
    Retry { established: bool, error: String },
    /// The certificate starts in the future by the local clock; `local_agent_rs` refuses it until then.
    NotYetValid { wait: Option<Duration> },
}

async fn run(
    params: AgentParams,
    mut features: watch::Receiver<Option<AgentFeatures>>,
    events: mpsc::UnboundedSender<AgentEvent>,
) {
    let mut failures = 0;
    loop {
        match session(&params, &mut features, &events).await {
            Outcome::Stop => return,
            // A new certificate wouldn't help: the API dates it by its own clock, which is ahead of ours.
            Outcome::NotYetValid { wait } => {
                let wait = wait.unwrap_or(Duration::from_secs(60));
                if wait > MAX_CLOCK_WAIT {
                    let _ = events.send(AgentEvent::Warning(format!(
                        "the system clock is {} min behind the VPN certificate; fix the clock (NTP) and reconnect \
                         for port forwarding, NetShield statistics and live feature changes",
                        wait.as_secs() / 60
                    )));
                    return;
                }
                tracing::warn!(
                    "local agent: the certificate starts in {} s by the local clock; waiting",
                    wait.as_secs()
                );
                let _ = events.send(AgentEvent::Warning(format!(
                    "the system clock is about {} s behind Proton's; the local agent (port forwarding, NetShield \
                     statistics, live feature changes) starts once the certificate becomes valid. Enable NTP to \
                     avoid this delay",
                    wait.as_secs()
                )));
                tokio::time::sleep(wait + Duration::from_secs(2)).await;
            }
            Outcome::Retry { established, error } => {
                failures = if established { 1 } else { failures + 1 };
                tracing::warn!("local agent: {error} (attempt {failures} of {MAX_FAILURES})");
                if failures >= MAX_FAILURES {
                    let _ = events.send(AgentEvent::Warning(format!(
                        "the local agent is unreachable ({error}): NetShield statistics, port forwarding and live \
                         feature changes are unavailable; the features from the certificate still apply"
                    )));
                    return;
                }
                // api-core waits a random 0–10 s before reconnecting.
                let delay = Duration::from_millis(rand::random::<u64>() % 10_000);
                tokio::time::sleep(delay).await;
            }
        }
    }
}

async fn session(
    params: &AgentParams,
    features: &mut watch::Receiver<Option<AgentFeatures>>,
    events: &mpsc::UnboundedSender<AgentEvent>,
) -> Outcome {
    let connect = ConnectParams {
        domain: params.domain.clone(),
        key: params.key_pem.to_string(),
        cert: params.certificate_pem.clone(),
        timeout_in_seconds: TIMEOUT_SECS,
    };
    let connection = match AgentConnector::connect(connect).await {
        Ok(connection) => connection,
        Err(AgentError::NotYetValidCertificate(_)) => {
            return Outcome::NotYetValid { wait: starts_in(&params.certificate_pem, std::time::SystemTime::now()) };
        }
        Err(e @ AgentError::ExpiredCertificate(_)) => {
            let _ = events.send(AgentEvent::CertificateRejected(e.to_string()));
            return Outcome::Stop;
        }
        Err(e) => return Outcome::Retry { established: false, error: format!("connecting: {e}") },
    };
    tracing::info!("local agent: connected to {}", params.domain);

    // Reading has its own task: a read cancelled halfway through a frame would desynchronize the stream.
    let (status_tx, mut statuses) = mpsc::channel(16);
    let reader = connection.clone();
    let _reader = AbortOnDrop(tokio::spawn(async move {
        loop {
            let result = reader.read().await;
            let fatal = matches!(&result, Err(e) if !matches!(e, AgentError::GetStatusError(_)));
            if status_tx.send(result).await.is_err() || fatal {
                return;
            }
        }
    }));

    let requested = features.borrow_and_update().clone();
    if let Some(requested) = requested
        && let Err(e) = connection.request_features(requested, TIMEOUT_SECS).await
    {
        return Outcome::Retry { established: false, error: format!("requesting features: {e}") };
    }
    let mut state = SessionState::default();
    let mut renewal = tokio::time::interval(PORT_FORWARDING_RENEWAL);
    let mut statistics = tokio::time::interval(STATISTICS_INTERVAL);
    let mut established = false;

    loop {
        tokio::select! {
            message = statuses.recv() => match message {
                Some(Ok(status)) => {
                    established = true;
                    if let Some(outcome) = state.handle(status, events) {
                        let _ = connection.close(TIMEOUT_SECS).await;
                        return outcome;
                    }
                    if state.port_forwarding && state.forwarded_port.is_none() {
                        renewal.reset_immediately();
                    }
                }
                Some(Err(AgentError::GetStatusError(e))) => {
                    tracing::warn!("local agent error {}: {}", e.code, e.description);
                    let _ = events.send(AgentEvent::Warning(format!("local agent: {} ({})", e.description, e.code)));
                }
                Some(Err(e)) => return Outcome::Retry { established, error: format!("reading: {e}") },
                None => return Outcome::Retry { established, error: "the connection closed".into() },
            },
            changed = features.changed() => {
                if changed.is_err() {
                    let _ = connection.close(TIMEOUT_SECS).await;
                    return Outcome::Stop;
                }
                let requested = features.borrow_and_update().clone();
                if let Some(requested) = requested {
                    tracing::info!("local agent: requesting {requested:?}");
                    if let Err(e) = connection.request_features(requested, TIMEOUT_SECS).await {
                        return Outcome::Retry { established, error: format!("requesting features: {e}") };
                    }
                }
            }
            _ = renewal.tick(), if state.port_forwarding => {
                match local_agent_rs::request_tcp_port_forwarding(TIMEOUT_SECS, PORT_FORWARDING_RETRIES).await {
                    Ok(port) => state.set_port(Some(port), events),
                    Err(e) => tracing::warn!("local agent: port forwarding lease: {e}"),
                }
            }
            _ = statistics.tick() => {
                if let Err(e) = request_statistics(&connection).await {
                    return Outcome::Retry { established, error: format!("requesting statistics: {e}") };
                }
            }
        }
    }
}

/// How long until the PEM certificate's validity starts, if it's in the future of `now`.
fn starts_in(certificate_pem: &str, now: std::time::SystemTime) -> Option<Duration> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes()).ok()?;
    let certificate = pem.parse_x509().ok()?;
    let start = certificate.validity().not_before.timestamp();
    let now = now.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
    (start > now).then(|| Duration::from_secs((start - now) as u64))
}

async fn request_statistics(connection: &AgentConnection) -> local_agent_rs::Result<()> {
    connection.request_status(TIMEOUT_SECS, Some(true)).await
}

#[derive(Default)]
struct SessionState {
    connected: bool,
    port_forwarding: bool,
    forwarded_port: Option<u16>,
    netshield: Option<NetShieldStats>,
}

impl SessionState {
    /// Reacts to one status message; `Some` ends the session.
    fn handle(&mut self, status: StatusMessage, events: &mpsc::UnboundedSender<AgentEvent>) -> Option<Outcome> {
        tracing::debug!("local agent status: {status:?}");
        match status.state {
            State::Connected => {
                if !self.connected {
                    self.connected = true;
                    tracing::info!("local agent: connection confirmed, features {:?}", status.features);
                    let _ = events.send(AgentEvent::Connected { features: status.features.clone() });
                }
                self.port_forwarding = status.features.as_ref().and_then(|f| f.port_forwarding) == Some(true);
                if !self.port_forwarding {
                    self.set_port(None, events);
                }
                if let Some(stats) = status.features_statistics.and_then(|s| s.netshield_level) {
                    let stats = NetShieldStats {
                        malware: stats.malware.unwrap_or(0),
                        ads: stats.ads.unwrap_or(0),
                        trackers: stats.tracker.unwrap_or(0),
                    };
                    if self.netshield != Some(stats) {
                        self.netshield = Some(stats);
                        let _ = events.send(AgentEvent::NetShieldStats(stats));
                    }
                }
                None
            }
            State::HardJailed => {
                let (code, description) =
                    status.reason.map(|r| (r.code, r.description)).unwrap_or((0, "no reason given".into()));
                tracing::warn!("local agent: hard-jailed, {code}: {description}");
                let event = if CERTIFICATE_CODES.contains(&code) {
                    AgentEvent::CertificateRejected(format!("{description} ({code})"))
                } else {
                    AgentEvent::Jailed { code, description }
                };
                let _ = events.send(event);
                Some(Outcome::Stop)
            }
        }
    }

    fn set_port(&mut self, port: Option<u16>, events: &mpsc::UnboundedSender<AgentEvent>) {
        if self.forwarded_port != port {
            tracing::info!("local agent: forwarded port {port:?}");
            self.forwarded_port = port;
            let _ = events.send(AgentEvent::PortForward(port));
        }
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetShield;

    #[test]
    fn certificate_start_in_the_future() {
        // Proton's public root CA: valid from 2019-10-17 08:06:41 UTC.
        let pem = include_str!("../../tests/fixtures/proton-vpn-root-ca.pem");
        let start = std::time::UNIX_EPOCH + Duration::from_secs(1_571_299_601);
        assert_eq!(starts_in(pem, start - Duration::from_secs(251)), Some(Duration::from_secs(251)));
        assert_eq!(starts_in(pem, start), None);
        assert_eq!(starts_in(pem, std::time::SystemTime::now()), None);
        assert_eq!(starts_in("not a certificate", start), None);
    }

    #[test]
    fn features_follow_settings() {
        let settings = Settings {
            netshield: Some(NetShield::AdsTrackersMalware),
            vpn_accelerator: false,
            moderate_nat: true,
            port_forwarding: true,
            ..Settings::default()
        };
        let features = features_for(&settings, 2, "3").unwrap();
        assert_eq!(features.netshield_level, Some(2));
        assert_eq!(features.split_tcp, Some(false));
        assert_eq!(features.randomized_nat, Some(false), "moderate NAT = not randomized");
        assert_eq!(features.port_forwarding, Some(true));
        assert_eq!(features.bouncing.as_deref(), Some("3"));
        assert_eq!(features.jail, None);
        let json = serde_json::to_value(&features).unwrap();
        assert_eq!(json["netshield-level"], 2);
        assert_eq!(json["randomized-nat"], false);

        // Tier default NetShield (malware) for paid plans; no label, no bouncing.
        let defaults = features_for(&Settings::default(), 1, "").unwrap();
        assert_eq!(defaults.netshield_level, Some(1));
        assert_eq!(defaults.bouncing, None);
        // Free: no feature request at all.
        assert_eq!(features_for(&settings, 0, "3"), None);
    }

    fn status(json: &str) -> StatusMessage {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn status_handling() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut state = SessionState::default();

        let connected = status(
            r#"{"state":"connected","reason":null,"features":{"netshield-level":2,"port-forwarding":true},
                "features-statistics":{"netshield-level":{"DNSBL/1b":1,"DNSBL/2a":7,"DNSBL/2b":3}}}"#,
        );
        assert!(state.handle(connected.clone(), &tx).is_none());
        assert!(matches!(rx.try_recv().unwrap(), AgentEvent::Connected { .. }));
        assert_eq!(
            rx.try_recv().unwrap(),
            AgentEvent::NetShieldStats(NetShieldStats { malware: 1, ads: 7, trackers: 3 })
        );
        assert!(state.port_forwarding);
        // The same status again changes nothing.
        assert!(state.handle(connected, &tx).is_none());
        assert!(rx.try_recv().is_err());

        state.set_port(Some(51234), &tx);
        assert_eq!(rx.try_recv().unwrap(), AgentEvent::PortForward(Some(51234)));
        // Port forwarding switched off: the port goes away.
        assert!(
            state
                .handle(status(r#"{"state":"connected","reason":null,"features":{"port-forwarding":false}}"#), &tx)
                .is_none()
        );
        assert_eq!(rx.try_recv().unwrap(), AgentEvent::PortForward(None));

        let jailed = status(
            r#"{"state":"hard-jailed","reason":{"code":86113,"final":true,"description":"max sessions"},"features":null}"#,
        );
        assert!(matches!(state.handle(jailed, &tx), Some(Outcome::Stop)));
        assert_eq!(rx.try_recv().unwrap(), AgentEvent::Jailed { code: 86113, description: "max sessions".into() });

        let expired = status(
            r#"{"state":"hard-jailed","reason":{"code":86101,"final":true,"description":"expired"},"features":null}"#,
        );
        assert!(state.handle(expired, &tx).is_some());
        assert!(matches!(rx.try_recv().unwrap(), AgentEvent::CertificateRejected(_)));
    }

    #[test]
    fn jail_descriptions() {
        assert!(describe_jail(86113, "x").starts_with("too many devices"));
        assert!(describe_jail(86104, "x").contains("isn't available"));
        assert_eq!(describe_jail(99999, "odd"), "the server blocked the connection: odd (99999)");
    }
}
