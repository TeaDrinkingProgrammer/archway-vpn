//! A shared profile file: the TOML parse into the checked types, and from a profile that loads, everything the app does
//! with it before pkexec: Save's sparse TOML must load back to the same profile, and the backend request built from it
//! must survive its JSON trip to the backend.
#![no_main]

use archway_vpn::backend;
use archway_vpn::config::{self, Config};
use archway_vpn::protocol::{BackendRequest, ClientAuth};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static CFG: OnceLock<Config> = OnceLock::new();

fuzz_target!(|text: &str| {
    let Ok(mut p) = config::parse_profile(text) else {
        return;
    };
    let mut again =
        config::parse_profile(&config::sparse(&p)).expect("what Save writes loads again");
    again.id = p.id.clone(); // random per parse, not in the file
    assert_eq!(again, p, "a profile survives Save and load");
    let _ = p.problems();
    let cfg = CFG.get_or_init(Config::default);
    let _ = backend::client_auth(cfg, &p, None);
    p.psk = "k".into();
    if let Ok(req) = backend::build_request(cfg, &p, ClientAuth::PskOnly) {
        let json = serde_json::to_string(&req).unwrap();
        let back: BackendRequest =
            serde_json::from_str(&json).expect("a built request is a valid request");
        assert_eq!(back, req);
    }
});
