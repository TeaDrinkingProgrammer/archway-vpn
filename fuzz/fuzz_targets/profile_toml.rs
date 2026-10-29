//! A shared profile file of any connection type: the `type` key and the TOML parse into the checked types, and from a
//! profile that loads, everything the app does with it before connecting: Save's sparse TOML must load back to the same
//! profile and name the same type (a FortiGate file never gets a `type`, an Azure file always starts with one); a
//! FortiGate one's backend request must survive its JSON trip to the backend, and an Azure one's OpenVPN config must
//! have exactly the template's lines. The `type` key alone picks the type: FortiGate keys in an Azure file and Azure
//! keys in a FortiGate file are ignored, never mixed in.
#![no_main]

use archway_vpn::config::{self, Config, Kind, Vpn};
use archway_vpn::protocol::{BackendRequest, ClientAuth};
use archway_vpn::{azure, backend};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static CFG: OnceLock<Config> = OnceLock::new();

/// The FortiGate sections and keys that must not survive into an Azure profile's file, and the Azure keys that must
/// not survive into a FortiGate one.
const FORTIGATE_ONLY: [&str; 5] = ["[sso]", "[auth]", "[ike]", "[esp]", "[network]"];
const AZURE_ONLY: [&str; 4] = ["type", "tenant", "audience", "root"];

fuzz_target!(|text: &str| {
    let parsed = config::parse_profile(text);
    // the `type` key decides, and nothing else does: what toml sees at the top level
    if let Ok(table) = toml::from_str::<toml::Table>(text) {
        match (table.get("type"), &parsed) {
            (None, Ok(p)) => assert_eq!(p.vpn.kind(), Kind::FortiGateIkev2, "{text:?}"),
            (Some(toml::Value::String(id)), Ok(p)) => assert_eq!(
                match id.as_str() {
                    "fortigate-ikev2" => Some(Kind::FortiGateIkev2),
                    "azure-openvpn" => Some(Kind::AzureOpenvpn),
                    _ => None,
                },
                Some(p.vpn.kind()),
                "{text:?}"
            ),
            (Some(_), Ok(_)) => panic!("a type that isn't a known id loaded: {text:?}"),
            (_, Err(e)) => assert!(!e.trim().is_empty(), "an empty error for {text:?}"),
        }
    } else {
        assert!(parsed.is_err(), "not TOML, yet a profile: {text:?}");
    }
    let Ok(p) = parsed else {
        return;
    };
    let file = config::sparse(&p);
    let mut again = config::parse_profile(&file).expect("what Save writes loads again");
    again.id = p.id.clone(); // random per parse, not in the file
    assert_eq!(again, p, "a profile survives Save and load");
    let _ = p.problems();
    let _ = (p.gateway_text(), p.sign_in(), p.vpn.kind());
    let cfg = CFG.get_or_init(Config::default);
    match &p.vpn {
        Vpn::FortiGate(f) => {
            let keys: Vec<&str> = file.lines().filter_map(|l| l.split_once(" = ").map(|(k, _)| k)).collect();
            for k in AZURE_ONLY {
                assert!(!keys.contains(&k), "{k} in a FortiGate file:\n{file}");
            }
            let _ = backend::client_auth(cfg, f, None);
            if let Ok(req) = backend::build_request(cfg, "k", f, ClientAuth::PskOnly) {
                let json = serde_json::to_string(&req).unwrap();
                let back: BackendRequest =
                    serde_json::from_str(&json).expect("a built request is a valid request");
                assert_eq!(back, req);
            }
        }
        Vpn::Azure(az) => {
            assert!(file.starts_with("type = \"azure-openvpn\"\n"), "{file}");
            for s in FORTIGATE_ONLY {
                assert!(!file.contains(s), "{s} in an Azure file:\n{file}");
            }
            let c = azure::ovpn(az, &"0".repeat(512), "CA").expect("a 512-hex secret makes a config");
            // the 15 fixed directives, <ca>/CA/</ca>, and the static key block inside <tls-auth>
            assert_eq!(c.expose().lines().count(), 15 + 3 + 20, "no line was injected:\n{}", c.expose());
        }
    }
});
