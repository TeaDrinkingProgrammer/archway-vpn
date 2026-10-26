//! The JSON line the root backend reads first: an arbitrary request must either be rejected or be a request that
//! serializes and parses back to itself, and whose values reach charon's config and VICI message without panicking.
#![no_main]

use archway_vpn::charon::{self, ConnParams};
use archway_vpn::protocol::BackendRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    let Ok(r) = serde_json::from_str::<BackendRequest>(text) else {
        return;
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: BackendRequest =
        serde_json::from_str(&json).expect("an accepted request round-trips");
    assert_eq!(back, r);
    let _ = r.routes.overrides();
    let dns = r.set_dns.then(|| charon::resolvconf_name(&r.ifname, None));
    let _ = charon::config(u32::from(r.natt_keepalive.get()), r.verbose, dns.as_deref());
    let params = ConnParams {
        gateway: r.gateway.clone(),
        ike_port: r.ike_port,
        ike_proposals: r.ike_proposals.clone(),
        dh_groups: r.dh_groups.clone(),
        esp_proposals: r.esp_proposals.clone(),
        local_id: r.local_id.clone(),
        auth: r.auth.clone(),
        psk: r.psk.clone(),
    };
    serde_vici::to_vec(&charon::conn_message(&params)).expect("the load-conn message encodes");
});
