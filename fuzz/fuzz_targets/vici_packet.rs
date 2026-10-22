//! One VICI packet payload (what follows the length prefix) from charon, and its body as the message shapes the
//! backend deserializes (`Status`, `list-sa`, `ike-updown`, `stats`, `control-log`).
#![no_main]

use archway_vpn::{charon, vici};
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Child {
    #[serde(rename = "remote-ts", default)]
    _remote_ts: Vec<String>,
}

#[derive(Deserialize)]
struct Ike {
    #[serde(rename = "remote-host", default)]
    _remote_host: String,
    #[serde(rename = "local-vips", default)]
    _local_vips: Vec<String>,
    #[serde(rename = "child-sas", default)]
    _child_sas: BTreeMap<String, Child>,
}

#[derive(Deserialize)]
struct Stats {
    #[serde(default)]
    _plugins: Vec<String>,
}

#[derive(Deserialize)]
struct LogLine {
    #[serde(default)]
    _msg: String,
}

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(p)) = vici::decode(data) {
        // what we can decode, we can encode back to the same packet
        let bytes = vici::encode(&p);
        assert_eq!(vici::decode(&bytes[4..]), Ok(Some(p)));
    }
    let _ = serde_vici::from_slice::<vici::Status>(data).map(|s| s.check("fuzz"));
    let _ = charon::is_down(data);
    let _ = serde_vici::from_slice::<BTreeMap<String, Ike>>(data);
    let _ = serde_vici::from_slice::<BTreeMap<String, String>>(data);
    let _ = serde_vici::from_slice::<Stats>(data);
    let _ = serde_vici::from_slice::<LogLine>(data);
});
