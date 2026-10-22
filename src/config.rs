//! Filesystem locations and the user-facing settings.
//!
//! Two roles share one binary: the root daemon keeps its state in `/var/lib/protontui`, an unprivileged run
//! (the TUI, or CLI subcommands before the daemon exists) keeps it under the XDG state directory. Runtime
//! state that must not survive a reboot lives in `/run/protontui`.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Overrides the state directory, for development and tests.
pub const STATE_DIR_ENV: &str = "PROTONTUI_STATE_DIR";
/// Where the root daemon keeps sessions, keys, certificates and settings.
pub const SYSTEM_STATE_DIR: &str = "/var/lib/protontui";
/// Runtime state (crash-recovery record, DNS backup). Cleared at boot by the tmpfs.
pub const RUN_DIR: &str = "/run/protontui";
/// The daemon's log file. The TUI and CLI log under the XDG state directory instead.
pub const DAEMON_LOG_FILE: &str = "/var/log/protontui.log";

const APP_DIR: &str = "protontui";

/// Every file protontui keeps on disk, resolved for the current role.
#[derive(Debug, Clone)]
pub struct Paths {
    pub state_dir: PathBuf,
}

impl Paths {
    /// Resolves the state directory: `$PROTONTUI_STATE_DIR`, else `/var/lib/protontui` for root, else
    /// `$XDG_STATE_HOME/protontui` (`~/.local/state/protontui`).
    pub fn detect() -> Result<Self> {
        if let Some(dir) = std::env::var_os(STATE_DIR_ENV).filter(|d| !d.is_empty()) {
            return Ok(Self::at(dir));
        }
        if nix::unistd::geteuid().is_root() {
            return Ok(Self::at(SYSTEM_STATE_DIR));
        }
        Ok(Self::at(user_state_dir()?))
    }

    pub fn at(state_dir: impl Into<PathBuf>) -> Self {
        Self { state_dir: state_dir.into() }
    }

    /// Session tokens and identity (secret).
    pub fn session_file(&self) -> PathBuf {
        self.state_dir.join("session.json")
    }

    /// Cached account info (plan, tier, email).
    pub fn account_file(&self) -> PathBuf {
        self.state_dir.join("account.json")
    }

    /// Ed25519 keypair (secret, T3.1).
    pub fn keys_file(&self) -> PathBuf {
        self.state_dir.join("keys.json")
    }

    /// VPN certificate (T3.1).
    pub fn certificate_file(&self) -> PathBuf {
        self.state_dir.join("certificate.json")
    }

    /// Cached server list (public data, T2.1).
    pub fn servers_file(&self) -> PathBuf {
        self.state_dir.join("servers.json")
    }

    /// Cached `vpn/v2/clientconfig` (T2.1).
    pub fn client_config_file(&self) -> PathBuf {
        self.state_dir.join("clientconfig.json")
    }

    pub fn settings_file(&self) -> PathBuf {
        self.state_dir.join("settings.toml")
    }

    /// Everything tied to a signed-in account, removed by logout.
    pub fn account_bound_files(&self) -> [PathBuf; 4] {
        [self.session_file(), self.account_file(), self.keys_file(), self.certificate_file()]
    }
}

/// `$XDG_STATE_HOME/protontui`, falling back to `~/.local/state/protontui`.
pub fn user_state_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir).join(APP_DIR));
    }
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/state").join(APP_DIR))
}

/// Writes `contents` to `path` atomically: write a temporary file in the same directory with `mode`, fsync it,
/// then rename it over the target. Creates the parent directory (`0700`) when missing.
pub fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;

    let file_name = path.file_name().ok_or_else(|| io::Error::other("path has no file name"))?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp = dir.join(tmp_name);

    let result = (|| {
        let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        // Persist the rename itself.
        fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Overwrites a secret file with zeros before unlinking it, so its contents don't linger in freed blocks on
/// non-copy-on-write filesystems. Missing files are fine.
pub fn remove_secret_file(path: &Path) -> io::Result<()> {
    match fs::metadata(path) {
        Ok(meta) => {
            if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
                let _ = file.write_all(&vec![0u8; meta.len() as usize]).and_then(|_| file.sync_all());
            }
            fs::remove_file(path)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------------------------

/// Every user-facing option. Missing or unknown fields in the file fall back to defaults, so older and newer
/// settings files both load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub kill_switch: KillSwitchMode,
    /// Let LAN traffic (RFC 1918, link-local) bypass the kill switch.
    pub allow_lan: bool,
    /// `None` means the tier default: off for Free, malware blocking for paid plans (api-core
    /// `Features.default`). Use [`Settings::netshield_for_tier`] to resolve it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netshield: Option<NetShield>,
    pub vpn_accelerator: bool,
    pub moderate_nat: bool,
    pub port_forwarding: bool,
    pub ipv6: bool,
    pub custom_dns: CustomDns,
    pub auto_connect: AutoConnect,
    pub favourites: Vec<ConnectTarget>,
    /// Most recent first.
    pub recents: Vec<ConnectTarget>,
}

impl Default for Settings {
    /// Mirrors api-core's defaults (`core/settings/settings.py`, `features.py`).
    fn default() -> Self {
        Self {
            kill_switch: KillSwitchMode::Off,
            allow_lan: false,
            netshield: None,
            vpn_accelerator: true,
            moderate_nat: false,
            port_forwarding: false,
            ipv6: true,
            custom_dns: CustomDns::default(),
            auto_connect: AutoConnect::Off,
            favourites: Vec::new(),
            recents: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KillSwitchMode {
    #[default]
    Off,
    /// Block traffic outside the tunnel while connected or connecting.
    Standard,
    /// Block traffic outside the tunnel even while disconnected.
    Permanent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetShield {
    /// Level 0.
    Off,
    /// Level 1: block malware.
    Malware,
    /// Level 2: block malware, ads and trackers.
    AdsTrackersMalware,
}

impl NetShield {
    /// The numeric level used by the API certificate and the local agent.
    pub fn level(self) -> u8 {
        match self {
            NetShield::Off => 0,
            NetShield::Malware => 1,
            NetShield::AdsTrackersMalware => 2,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomDns {
    pub enabled: bool,
    pub servers: Vec<std::net::IpAddr>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AutoConnect {
    #[default]
    Off,
    Fastest,
    Last,
    /// A named profile (T6.2).
    Profile(String),
}

/// Something the user can connect to; used by favourites, recents and auto-connect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ConnectTarget {
    Fastest,
    Country { code: String },
    City { country: String, city: String },
    Server { name: String },
}

impl Settings {
    /// Loads settings from `path`. A missing file gives defaults. An unreadable file is moved aside to
    /// `<path>.bad` and defaults are used, so a corrupt file never blocks the app.
    pub fn load(path: &Path) -> Result<Self> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        match toml::from_str(&text) {
            Ok(settings) => Ok(settings),
            Err(e) => {
                let bad = path.with_extension("toml.bad");
                tracing::warn!("settings file {} is invalid ({e}); moved to {}", path.display(), bad.display());
                fs::rename(path, &bad).with_context(|| format!("moving aside {}", path.display()))?;
                Ok(Self::default())
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self).context("serializing settings")?;
        write_atomic(path, text.as_bytes(), 0o644).with_context(|| format!("writing {}", path.display()))
    }

    /// The NetShield level to use: the explicit setting, else the tier default.
    pub fn netshield_for_tier(&self, tier: u8) -> NetShield {
        self.netshield.unwrap_or(if tier < 1 { NetShield::Off } else { NetShield::Malware })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Settings {
        Settings {
            kill_switch: KillSwitchMode::Permanent,
            allow_lan: true,
            netshield: Some(NetShield::AdsTrackersMalware),
            vpn_accelerator: false,
            moderate_nat: true,
            port_forwarding: true,
            ipv6: false,
            custom_dns: CustomDns {
                enabled: true,
                servers: vec!["9.9.9.9".parse().unwrap(), "2620:fe::fe".parse().unwrap()],
            },
            auto_connect: AutoConnect::Profile("work".into()),
            favourites: vec![
                ConnectTarget::Country { code: "CH".into() },
                ConnectTarget::Server { name: "CH#10".into() },
            ],
            recents: vec![
                ConnectTarget::City { country: "US".into(), city: "New York".into() },
                ConnectTarget::Fastest,
            ],
        }
    }

    #[test]
    fn round_trip_through_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/settings.toml");
        let settings = sample();
        settings.save(&path).unwrap();
        assert_eq!(Settings::load(&path).unwrap(), settings);

        // Saving again replaces the file atomically and leaves no temporary files behind.
        Settings::default().save(&path).unwrap();
        assert_eq!(Settings::load(&path).unwrap(), Settings::default());
        let names: Vec<_> = fs::read_dir(path.parent().unwrap()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from("settings.toml")]);
    }

    #[test]
    fn missing_file_gives_defaults() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Settings::load(&dir.path().join("nope.toml")).unwrap(), Settings::default());
    }

    #[test]
    fn missing_and_unknown_fields_fall_back_to_defaults() {
        let old = r#"
            kill_switch = "standard"
            removed_option = 42

            [custom_dns]
            enabled = true
        "#;
        let settings: Settings = toml::from_str(old).unwrap();
        assert_eq!(
            settings,
            Settings {
                kill_switch: KillSwitchMode::Standard,
                custom_dns: CustomDns { enabled: true, servers: vec![] },
                ..Settings::default()
            }
        );
        assert_eq!(toml::from_str::<Settings>("").unwrap(), Settings::default());
    }

    #[test]
    fn invalid_file_is_moved_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.toml");
        fs::write(&path, "kill_switch = \"sometimes\"").unwrap();
        assert_eq!(Settings::load(&path).unwrap(), Settings::default());
        assert!(!path.exists());
        assert!(dir.path().join("settings.toml.bad").exists());
    }

    #[test]
    fn netshield_defaults_by_tier() {
        let settings = Settings::default();
        assert_eq!(settings.netshield_for_tier(0), NetShield::Off);
        assert_eq!(settings.netshield_for_tier(2), NetShield::Malware);
        let explicit = Settings { netshield: Some(NetShield::Off), ..Settings::default() };
        assert_eq!(explicit.netshield_for_tier(2), NetShield::Off);
    }

    #[test]
    fn atomic_write_sets_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        write_atomic(&path, b"{}", 0o600).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        remove_secret_file(&path).unwrap();
        assert!(!path.exists());
        remove_secret_file(&path).unwrap();
    }
}
