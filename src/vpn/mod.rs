//! Everything that touches the host network: WireGuard, routing, DNS, kill switch, local agent, engine.
//!
//! Each submodule that changes the system also owns the matching `recover` step, so that the undo logic sits
//! next to the code it undoes. [`recover`] runs them all.

pub mod dns;
pub mod engine;
pub mod keys;
pub mod killswitch;
pub mod local_agent;
pub mod routing;
pub mod wireguard;

use std::path::Path;

use crate::config;

/// What a recovery run did.
#[derive(Debug, Default)]
pub struct RecoverReport {
    /// Changes made, one line each. Empty on a clean system.
    pub actions: Vec<String>,
    /// Steps that failed. Recovery carries on after a failure, so the other steps still run.
    pub errors: Vec<String>,
}

impl RecoverReport {
    fn step(&mut self, name: &str, result: anyhow::Result<Vec<String>>) {
        match result {
            Ok(actions) => self.actions.extend(actions),
            Err(e) => self.errors.push(format!("{name}: {e:#}")),
        }
    }
}

/// Undoes everything protontui may have changed on the host, without reading any state file: kill switch
/// tables, the WireGuard link, policy rules and routes, and DNS. Idempotent; on a clean system it changes
/// nothing. Needs root (or `CAP_NET_ADMIN` plus write access to `/etc/resolv.conf`).
pub async fn recover() -> RecoverReport {
    let mut report = RecoverReport::default();

    // Firewall first: with a permanent kill switch the host is offline until the table is gone.
    report.step("kill switch", killswitch::recover().await);

    match rtnetlink::new_connection() {
        Ok((connection, handle, _)) => {
            let task = tokio::spawn(connection);
            // Deleting the link also drops routes through it; routing then removes what's left.
            report.step("wireguard", wireguard::recover(&handle).await);
            report.step("routing", routing::recover(&handle).await);
            task.abort();
        }
        Err(e) => report.errors.push(format!("netlink: {e}")),
    }

    report.step("dns", dns::recover().await);

    let state = Path::new(config::RUN_DIR).join(engine::STATE_FILE_NAME);
    match std::fs::remove_file(&state) {
        Ok(()) => report.actions.push(format!("removed {}", state.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => report.errors.push(format!("state file {}: {e}", state.display())),
    }

    report
}
