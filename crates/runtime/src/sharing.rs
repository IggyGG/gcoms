//! Optional desktop relay contribution; personal messaging is independent.
#[cfg(feature = "gc2-carrier")]
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
#[cfg(feature = "gc2-carrier")]
use sha2::{Digest, Sha256};
#[cfg(all(feature = "gc2-carrier", target_os = "linux"))]
use std::path::Path;
#[cfg(all(
    feature = "gc2-carrier",
    any(target_os = "linux", target_os = "windows")
))]
use std::time::Duration;
#[cfg(feature = "gc2-carrier")]
use std::{io::Write, path::PathBuf, sync::Mutex};
#[cfg(feature = "gc2-carrier")]
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaySharingConfig {
    pub enabled: bool,
    pub router_mapping: bool,
    pub circuits: usize,
    pub connections: usize,
    /// Aggregate contribution budget across interactive and bulk circuits.
    pub bandwidth_bytes_per_second: usize,
}

impl Default for RelaySharingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            router_mapping: true,
            circuits: 32,
            connections: 64,
            bandwidth_bytes_per_second: 512 * 1024,
        }
    }
}

impl RelaySharingConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=4096).contains(&self.circuits)
            || self.connections < self.circuits * 2
            || self.connections > 8192
            || self.bandwidth_bytes_per_second < self.circuits * 8192 + 64 * 1024
            || self.bandwidth_bytes_per_second > 128 * 1024 * 1024
        {
            return Err("invalid relay sharing capacity or bandwidth budget".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RelaySharingStatus {
    pub enabled: bool,
    pub published: bool,
    pub state: String,
    pub circuits: usize,
    pub connections: usize,
    pub bandwidth_bytes_per_second: usize,
    pub lease_expires_at: Option<u64>,
    pub transferred_bytes: u64,
}

#[cfg(feature = "gc2-carrier")]
pub(crate) struct State {
    pub config: Mutex<RelaySharingConfig>,
    pub status: Mutex<RelaySharingStatus>,
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

#[cfg(feature = "gc2-carrier")]
impl State {
    pub fn open(
        path: PathBuf,
        seed: [u8; 32],
        default: RelaySharingConfig,
    ) -> Result<Self, String> {
        default.validate()?;
        crate::private_fs::validate_private_parent(&path, "relay sharing settings")?;
        let mut hash = Sha256::new();
        hash.update(b"gcoms.relay-sharing.settings.v1\0");
        hash.update(seed);
        let key: Zeroizing<[u8; 32]> = Zeroizing::new(hash.finalize().into());
        let config: RelaySharingConfig = if path.exists() {
            crate::private_fs::validate_private_file(&path, "relay sharing settings")?;
            let bytes = std::fs::read(&path).map_err(|_| "cannot read relay sharing settings")?;
            if !(28..=4096).contains(&bytes.len()) {
                return Err("invalid relay sharing settings size".into());
            }
            let plain = Aes256Gcm::new_from_slice(&*key)
                .map_err(|_| "invalid sharing key")?
                .decrypt(Nonce::from_slice(&bytes[..12]), &bytes[12..])
                .map_err(|_| "cannot authenticate relay sharing settings")?;
            let saved: RelaySharingConfig =
                serde_json::from_slice(&plain).map_err(|_| "invalid relay sharing settings")?;
            let mut config = default;
            config.enabled &= saved.enabled;
            config
        } else {
            default
        };
        config.validate()?;
        let status = RelaySharingStatus {
            enabled: config.enabled,
            circuits: config.circuits,
            connections: config.connections,
            bandwidth_bytes_per_second: config.bandwidth_bytes_per_second,
            state: if config.enabled {
                "Checking relay sharing eligibility"
            } else {
                "Relay sharing is off"
            }
            .into(),
            ..Default::default()
        };
        Ok(Self {
            config: Mutex::new(config),
            status: Mutex::new(status),
            path,
            key,
        })
    }

    pub fn set_enabled(&self, enabled: bool) -> Result<(), String> {
        let mut config = self
            .config
            .lock()
            .map_err(|_| "relay sharing settings busy")?;
        let mut next = config.clone();
        next.enabled = enabled;
        let nonce = rand::random::<[u8; 12]>();
        let bytes =
            serde_json::to_vec(&next).map_err(|_| "cannot encode relay sharing settings")?;
        let encrypted = Aes256Gcm::new_from_slice(&*self.key)
            .map_err(|_| "invalid sharing key")?
            .encrypt(Nonce::from_slice(&nonce), bytes.as_slice())
            .map_err(|_| "cannot encrypt relay sharing settings")?;
        crate::private_fs::validate_private_parent(&self.path, "relay sharing settings")?;
        let mut file =
            tempfile::NamedTempFile::new_in(self.path.parent().ok_or("settings parent missing")?)
                .map_err(|_| "cannot stage sharing settings")?;
        crate::private_fs::make_private(file.path(), false)?;
        file.write_all(&nonce)
            .and_then(|_| file.write_all(&encrypted))
            .and_then(|_| file.as_file().sync_all())
            .map_err(|_| "cannot save sharing settings")?;
        file.persist(&self.path)
            .map_err(|_| "cannot commit sharing settings")?;
        #[cfg(unix)]
        std::fs::File::open(self.path.parent().ok_or("settings parent missing")?)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| "cannot sync sharing settings directory")?;
        *config = next;
        Ok(())
    }
}

/// Unknown cost/power information pauses contribution. Hosts can provide a
/// native signal; failure never disables the personal outbound client.
#[cfg(feature = "gc2-carrier")]
pub(crate) async fn eligibility() -> Result<(), &'static str> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(devices) = std::fs::read_dir("/sys/class/power_supply") {
            for device in devices.flatten() {
                let path = device.path();
                if std::fs::read_to_string(path.join("type")).is_ok_and(|t| t.trim() == "Battery") {
                    let status = std::fs::read_to_string(path.join("status")).unwrap_or_default();
                    if !matches!(status.trim(), "Charging" | "Full") {
                        return Err("Paused on battery power");
                    }
                }
            }
        }
        if let Ok(pressure) = std::fs::read_to_string("/proc/pressure/memory") {
            if pressure.lines().any(|line| {
                line.starts_with("full ")
                    && line
                        .split_whitespace()
                        .find_map(|p| p.strip_prefix("avg10="))
                        .and_then(|p| p.parse::<f64>().ok())
                        .is_some_and(|p| p > 1.0)
            }) {
                return Err("Paused under memory pressure");
            }
        }
        let output = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::process::Command::new("nmcli")
                .args(["-g", "GENERAL.METERED", "device", "show"])
                .kill_on_drop(true)
                .output(),
        )
        .await;
        match output {
            Ok(Ok(output)) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
                if text.lines().any(|line| line.starts_with("yes")) {
                    return Err("Paused on a metered network");
                }
                if !text.lines().any(|line| line.starts_with("no")) {
                    return Err("Waiting for an unmetered network");
                }
            }
            _ => {
                // Headless Ethernet hosts may not run NetworkManager. Refuse
                // wireless/mobile links without a native cost classification.
                if !wired_network(Path::new("/sys/class/net")) {
                    return Err("Waiting for an unmetered network");
                }
            }
        }
        if let Ok(load) = std::fs::read_to_string("/proc/loadavg") {
            let capacity = std::thread::available_parallelism().map_or(1, usize::from) as f64;
            if load
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
                .is_some_and(|load| load > capacity)
            {
                return Err("Paused while this device is busy");
            }
        }
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        let script = "Add-Type -AssemblyName System.Windows.Forms; $p=[System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus; $n=[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile(); $o=Get-CimInstance Win32_OperatingSystem; $c=(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average; if ($p -eq 'Online' -and $n -and $n.GetConnectionCost().NetworkCostType -eq 'Unrestricted' -and $o.FreePhysicalMemory -gt $o.TotalVisibleMemorySize*0.1 -and $null -ne $c -and $c -lt 80) { 'eligible' }";
        if tokio::time::timeout(
            Duration::from_secs(5),
            tokio::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", script])
                .kill_on_drop(true)
                .output(),
        )
        .await
        .is_ok_and(|out| {
            out.is_ok_and(|out| {
                out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "eligible"
            })
        }) {
            return Ok(());
        }
        return Err("Waiting for external power, an unmetered network and available resources");
    }
    #[cfg(target_os = "macos")]
    {
        return super::sharing_macos::eligibility().await;
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    Err("Relay sharing is unavailable on this device")
}

#[cfg(all(feature = "gc2-carrier", target_os = "linux"))]
fn wired_network(root: &Path) -> bool {
    std::fs::read_dir(root).is_ok_and(|devices| {
        devices.flatten().any(|device| {
            let path = device.path();
            device.file_name() != "lo"
                && !path.join("wireless").exists()
                && std::fs::read_to_string(path.join("type")).is_ok_and(|v| v.trim() == "1")
                && std::fs::read_to_string(path.join("operstate")).is_ok_and(|v| v.trim() == "up")
        })
    })
}

#[cfg(all(test, feature = "gc2-carrier"))]
mod tests {
    use super::*;
    #[test]
    fn disable_survives_restart_and_wrong_profile_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        crate::private_fs::make_private(dir.path(), true).unwrap();
        let path = dir.path().join("sharing");
        let state = State::open(path.clone(), [7; 32], RelaySharingConfig::default()).unwrap();
        state.set_enabled(false).unwrap();
        assert!(
            !State::open(path.clone(), [7; 32], RelaySharingConfig::default())
                .unwrap()
                .config
                .lock()
                .unwrap()
                .enabled
        );
        assert!(State::open(path, [8; 32], RelaySharingConfig::default()).is_err());
    }
}
