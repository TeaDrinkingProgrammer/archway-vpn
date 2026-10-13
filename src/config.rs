//! Persistent settings. Saved to ~/.config/fortisaml-gui/config.json (mode 0600, it may hold the PSK)
//! every time a value changes.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

pub const ENCRYPTIONS: [&str; 3] = ["AES128", "AES192", "AES256"];
pub const HASHES: [&str; 4] = ["SHA1", "SHA256", "SHA384", "SHA512"];
/// DH groups the backend implements (MODP2048, ECP256/384/521).
pub const DH_SUPPORTED: [u16; 4] = [14, 19, 20, 21];
/// Groups shown by the official client but not implemented here (rendered disabled).
pub const DH_UNSUPPORTED: [u16; 8] = [1, 2, 5, 15, 16, 17, 18, 31];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Proposal {
    pub enc: String,
    pub hash: String,
}

impl Proposal {
    pub fn new(enc: &str, hash: &str) -> Self {
        Self { enc: enc.into(), hash: hash.into() }
    }
    pub fn spec(&self) -> String {
        format!("{}-{}", self.enc.to_lowercase(), self.hash.to_lowercase())
    }
}

/// User authentication when SSO is disabled.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum UserAuth {
    /// EAP (MSCHAPv2/GTC) with username + password - FortiClient's IKEv2 default
    Eap,
    /// No user authentication: the client authenticates with the pre-shared key only
    None,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum RouteMode {
    /// Use split networks / traffic selectors pushed by the FortiGate (full tunnel if it pushes 0.0.0.0/0)
    Gateway,
    /// Force everything through the VPN
    Full,
    /// Only the networks listed in `custom_routes`
    Custom,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Profile {
    pub name: String,
    pub description: String,
    pub gateway: String,
    // Single Sign On
    pub sso_enabled: bool,
    pub saml_port: u16,
    pub open_browser: bool,
    pub verify_cert: bool,
    pub saml_timeout: u32,
    // Authentication
    /// encrypted at rest (hardcoded key, see secret.rs)
    #[serde(with = "crate::secret::sealed")]
    pub psk: String,
    // user authentication when SSO is off
    pub user_auth: UserAuth,
    pub username: String,
    /// not written to disk unless `save_password`; encrypted at rest when saved
    #[serde(with = "crate::secret::sealed")]
    pub password: String,
    pub save_password: bool,
    // VPN settings
    pub ike_port: u16,
    // Phase 1
    pub ike_proposals: Vec<Proposal>,
    pub dh_groups: Vec<u16>,
    pub local_id: String,
    pub natt_keepalive: u32,
    // Phase 2
    pub esp_proposals: Vec<Proposal>,
    // Network
    pub route_mode: RouteMode,
    pub custom_routes: String,
    pub block_ipv6: bool,
    pub set_dns: bool,
    pub ifname: String,
    pub mtu: u16,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            name: "New connection".into(),
            description: String::new(),
            gateway: String::new(),
            sso_enabled: true,
            saml_port: 443,
            open_browser: true,
            verify_cert: false,
            saml_timeout: 300,
            psk: String::new(),
            user_auth: UserAuth::Eap,
            username: String::new(),
            password: String::new(),
            save_password: false,
            ike_port: 500,
            // FortiClient GUI defaults
            ike_proposals: vec![Proposal::new("AES128", "SHA1"), Proposal::new("AES256", "SHA256")],
            dh_groups: vec![20],
            local_id: String::new(),
            natt_keepalive: 20,
            esp_proposals: vec![Proposal::new("AES128", "SHA1"), Proposal::new("AES256", "SHA256")],
            route_mode: RouteMode::Gateway,
            custom_routes: String::new(),
            block_ipv6: true,
            set_dns: true,
            ifname: "fsaml0".into(),
            mtu: 1400,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub profiles: Vec<Profile>,
    pub selected: usize,
    /// FortiClient installation UID presented to the FortiGate (SAML UID + EAP identity)
    pub uid: String,
    pub verbose: bool,
    pub log_file: String,
    pub show_log: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profiles: vec![Profile::default()],
            selected: 0,
            uid: new_uid(),
            verbose: false,
            log_file: String::new(),
            show_log: true,
        }
    }
}

pub fn new_uid() -> String {
    let mut b = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    b.iter().map(|x| format!("{x:02X}")).collect()
}

pub fn config_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config"));
    base.join("fortisaml-gui").join("config.json")
}

impl Config {
    pub fn load() -> Self {
        let mut c: Config = std::fs::read_to_string(config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        if c.profiles.is_empty() {
            c.profiles.push(Profile::default());
        }
        if c.uid.len() != 32 {
            c.uid = new_uid();
        }
        c.selected = c.selected.min(c.profiles.len() - 1);
        c
    }

    /// Atomic write with 0600 permissions.
    pub fn save(&self) -> std::io::Result<()> {
        let path = config_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let tmp = path.with_extension("json.tmp");
        {
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            let mut on_disk = self.clone();
            for p in on_disk.profiles.iter_mut().filter(|p| !p.save_password) {
                p.password.clear(); // kept in memory only
            }
            f.write_all(serde_json::to_string_pretty(&on_disk).unwrap().as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(tmp, path)
    }
}
