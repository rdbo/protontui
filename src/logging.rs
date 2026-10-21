//! File logging through `tracing`. The TUI owns stdout, so nothing is logged to the terminal.

use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

use crate::config;

/// Log filter override, in `tracing_subscriber::EnvFilter` syntax (e.g. `debug`, `protontui=trace`).
pub const LOG_ENV: &str = "PROTONTUI_LOG";

/// Which process is logging; decides the log file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The root daemon: `/var/log/protontui.log`.
    Daemon,
    /// The TUI and CLI subcommands: `$XDG_STATE_HOME/protontui/protontui.log`.
    User,
}

pub fn log_file(role: Role) -> Result<PathBuf> {
    Ok(match role {
        Role::Daemon => PathBuf::from(config::DAEMON_LOG_FILE),
        Role::User => config::user_state_dir()?.join("protontui.log"),
    })
}

/// Installs the global subscriber. Keep the returned guard alive for the life of the process: dropping it
/// flushes the log.
pub fn init(role: Role) -> Result<WorkerGuard> {
    let path = log_file(role)?;
    let dir = path.parent().context("log path has no parent")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening log file {}", path.display()))?;

    let (writer, guard) = tracing_appender::non_blocking(file);
    let filter = EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).with_writer(writer).with_ansi(false).init();
    Ok(guard)
}
