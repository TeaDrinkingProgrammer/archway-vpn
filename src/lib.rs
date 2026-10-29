//! The parsers and protocol code as a library, only for the fuzz targets in `fuzz/` (feature `fuzzing`). Without the
//! feature this crate is empty. The app is built from `main.rs`, which declares the same modules privately; the GUI
//! modules (view, theme, form, glide, keyring) parse nothing from outside and aren't here.
#![cfg(feature = "fuzzing")]
#![doc(hidden)]

pub mod azure;
pub mod backend;
pub mod charon;
pub mod config;
pub mod diag;
pub mod entra;
pub mod net;
pub mod netlink;
pub mod openvpn3;
pub mod privdrop;
pub mod protocol;
pub mod resolved;
pub mod saml;
pub mod systemd;
pub mod tls;
pub mod tunnel;
pub mod vici;

/// Same as `main.rs`: the modules build their error messages with `crate::diag`.
pub fn diag(level: &str, headline: &str, note: &str, help: &str) -> String {
    diag::Diag::new(level, headline, note, help).to_string()
}
