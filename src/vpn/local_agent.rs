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

//!
//! Without the `local-agent` cargo feature (default on), the crate isn't built in: [`Agent`] then only warns,
//! once per connection, and the certificate's features are all there is. `local_agent_rs` comes without a
//! license, so binaries meant for distribution can leave it out (PLAN.md §1, T6.4).

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

#[cfg(feature = "local-agent")]
mod client;

#[cfg(feature = "local-agent")]
pub use client::describe_jail;
#[cfg(feature = "local-agent")]
pub use local_agent_rs::AgentFeatures;

use crate::config::Settings;

/// What a build without the local agent tells the user when connecting.
#[cfg(not(feature = "local-agent"))]
pub const NOT_BUILT_IN: &str = "this build has no local agent: NetShield, VPN Accelerator and Moderate NAT apply \
                                from the certificate, but there's no port forwarding, NetShield statistics or live \
                                feature changes";

/// Stand-in for `local_agent_rs::AgentFeatures` in builds without the local agent.
#[cfg(not(feature = "local-agent"))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentFeatures;

/// A human-readable explanation for a jail reason (none come without the local agent).
#[cfg(not(feature = "local-agent"))]
pub fn describe_jail(code: i32, description: &str) -> String {
    format!("the server blocked the connection: {description} ({code})")
}

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

/// The features to request, as api-core's `__get_agent_features`. `None` for Free (tier 0): the agent
/// rejects feature requests from Free sessions, which then get the defaults.
#[cfg(feature = "local-agent")]
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

#[cfg(not(feature = "local-agent"))]
pub fn features_for(_settings: &Settings, _tier: u8, _label: &str) -> Option<AgentFeatures> {
    None
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
        #[cfg(feature = "local-agent")]
        let task = tokio::spawn(client::run(params, features_rx, events));
        #[cfg(not(feature = "local-agent"))]
        let task = {
            drop((params, features_rx));
            tokio::spawn(async move {
                let _ = events.send(AgentEvent::Warning(NOT_BUILT_IN.into()));
            })
        };
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

#[cfg(all(test, feature = "local-agent"))]
mod tests {
    use super::*;
    use crate::config::NetShield;
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
}
