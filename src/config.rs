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

use crate::servers::select::FeatureFilter;

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

    /// Free-plan "Change server" bookkeeping (T4.2).
    pub fn change_server_file(&self) -> PathBuf {
        self.state_dir.join("change_server.json")
    }

    /// Imported WireGuard configs (T5.7; secret: they hold private keys).
    pub fn profiles_dir(&self) -> PathBuf {
        self.state_dir.join("profiles")
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

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
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
    /// Reach the API through alternative routes when it's blocked (T6.3).
    pub alternative_routing: bool,
    pub auto_connect: AutoConnect,
    pub favourites: Vec<Destination>,
    /// Most recent first.
    pub recents: Vec<Destination>,
    /// Named connections (T6.2).
    pub profiles: Vec<Profile>,
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
            alternative_routing: true,
            auto_connect: AutoConnect::Off,
            favourites: Vec::new(),
            recents: Vec::new(),
            profiles: Vec::new(),
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

/// Something the user can connect to; used by favourites, recents, profiles and auto-connect.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ConnectTarget {
    Fastest,
    Country {
        code: String,
    },
    City {
        country: String,
        city: String,
    },
    Server {
        name: String,
    },
    /// Secure Core into `exit` through `entry`; either may be left to the fastest choice.
    #[serde(rename = "secure-core")]
    SecureCore {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entry: Option<String>,
    },
    /// A [`Profile`], by name.
    Profile {
        name: String,
    },
}

/// A target plus the server feature it asked for (the P2P and Tor tabs, `--feature`): what favourites and
/// recents remember. Older settings files hold bare targets, which read as having no feature.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Destination {
    #[serde(flatten)]
    pub target: ConnectTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature: Option<FeatureFilter>,
}

impl From<ConnectTarget> for Destination {
    fn from(target: ConnectTarget) -> Self {
        Self { target, feature: None }
    }
}

/// A named connection (T6.2): where to, and the connection features that override the global settings
/// while it's connected. Unset fields follow the global settings. The protocol is always WireGuard over UDP
/// (PLAN.md §1), so what a profile can pick there is the port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    /// Never a profile itself.
    pub target: Destination,
    /// WireGuard UDP port (normally one of clientconfig's: 443, 88, 1224, 51820, 500, 4500); unset tries
    /// them in order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netshield: Option<NetShield>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_accelerator: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moderate_nat: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_forwarding: Option<bool>,
}

/// Longest profile name.
pub const MAX_PROFILE_NAME: usize = 64;

impl Profile {
    /// A profile for `target` that overrides nothing.
    pub fn new(name: impl Into<String>, target: Destination) -> Self {
        Self {
            name: name.into(),
            target,
            port: None,
            netshield: None,
            vpn_accelerator: None,
            moderate_nat: None,
            port_forwarding: None,
        }
    }

    /// Checks the name (1–64 printable characters, no surrounding spaces) and that the target isn't a profile.
    pub fn validate(&self) -> Result<()> {
        let name = &self.name;
        anyhow::ensure!(!name.trim().is_empty(), "a profile needs a name");
        anyhow::ensure!(name.trim() == name, "a profile name can't start or end with spaces");
        anyhow::ensure!(
            name.chars().count() <= MAX_PROFILE_NAME,
            "profile names are at most {MAX_PROFILE_NAME} characters"
        );
        anyhow::ensure!(!name.chars().any(char::is_control), "a profile name can't contain control characters");
        anyhow::ensure!(
            !matches!(self.target.target, ConnectTarget::Profile { .. }),
            "a profile can't point at another profile"
        );
        anyhow::ensure!(self.port != Some(0), "port 0 isn't a port");
        Ok(())
    }

    /// The settings a connection with this profile runs with: `settings` with this profile's overrides.
    pub fn apply(&self, settings: &mut Settings) {
        if let Some(level) = self.netshield {
            settings.netshield = Some(level);
        }
        if let Some(on) = self.vpn_accelerator {
            settings.vpn_accelerator = on;
        }
        if let Some(on) = self.moderate_nat {
            settings.moderate_nat = on;
        }
        if let Some(on) = self.port_forwarding {
            settings.port_forwarding = on;
        }
    }
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

    pub fn profile(&self, name: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.name == name)
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
            alternative_routing: false,
            auto_connect: AutoConnect::Profile("work".into()),
            favourites: vec![
                ConnectTarget::Country { code: "CH".into() }.into(),
                Destination { target: ConnectTarget::Country { code: "SE".into() }, feature: Some(FeatureFilter::P2P) },
                ConnectTarget::Server { name: "CH#10".into() }.into(),
            ],
            recents: vec![
                ConnectTarget::City { country: "US".into(), city: "New York".into() }.into(),
                ConnectTarget::SecureCore { exit: Some("DE".into()), entry: None }.into(),
                ConnectTarget::Profile { name: "work".into() }.into(),
                ConnectTarget::Fastest.into(),
            ],
            profiles: vec![
                Profile {
                    port: Some(443),
                    netshield: Some(NetShield::Off),
                    port_forwarding: Some(true),
                    ..Profile::new("work", ConnectTarget::Country { code: "CH".into() }.into())
                },
                Profile::new("tor", Destination { target: ConnectTarget::Fastest, feature: Some(FeatureFilter::Tor) }),
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
    fn older_favourites_and_recents_still_load() {
        let old = r#"
            [[favourites]]
            kind = "country"
            code = "CH"

            [[recents]]
            kind = "fastest"
        "#;
        let settings: Settings = toml::from_str(old).unwrap();
        assert_eq!(settings.favourites, [Destination::from(ConnectTarget::Country { code: "CH".into() })]);
        assert_eq!(settings.recents, [Destination::from(ConnectTarget::Fastest)]);
    }

    #[test]
    fn profiles_override_connection_features() {
        let profile = Profile {
            netshield: Some(NetShield::AdsTrackersMalware),
            vpn_accelerator: Some(false),
            ..Profile::new("p", ConnectTarget::Fastest.into())
        };
        let mut settings = Settings { moderate_nat: true, ..Settings::default() };
        profile.apply(&mut settings);
        assert_eq!(settings.netshield, Some(NetShield::AdsTrackersMalware));
        assert!(!settings.vpn_accelerator);
        assert!(settings.moderate_nat, "unset in the profile: the global value stays");

        assert!(profile.validate().is_ok());
        for bad in ["", " x", "x\n"] {
            assert!(Profile { name: bad.into(), ..profile.clone() }.validate().is_err(), "{bad:?}");
        }
        let nested = Profile::new("n", ConnectTarget::Profile { name: "p".into() }.into());
        assert!(nested.validate().is_err());
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
