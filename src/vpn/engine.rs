//! The connection state machine; the single entry point used by the daemon and `--standalone` (T3.5).

/// Name of the crash-recovery record under [`crate::config::RUN_DIR`]: what the engine created, so that a
/// restart after a crash can clean up (T3.2). `recover` never relies on it.
pub const STATE_FILE_NAME: &str = "state.json";
