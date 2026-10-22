//! The checked value types: any text either fails to parse or gives a value whose text form parses back to the same
//! value (what a profile file, a request line and the editor rely on).
#![no_main]

use archway_vpn::net::*;
use libfuzzer_sys::fuzz_target;
use std::str::FromStr;

fn round_trip<T: FromStr<Err = String> + ToString + PartialEq + std::fmt::Debug>(s: &str) {
    if let Ok(v) = s.parse::<T>() {
        assert_eq!(
            v.to_string().parse::<T>().as_ref(),
            Ok(&v),
            "{s:?} as {}",
            std::any::type_name::<T>()
        );
    }
}

fuzz_target!(|s: &str| {
    round_trip::<IfName>(s);
    round_trip::<Ipv4Net>(s);
    round_trip::<DnsName>(s);
    round_trip::<Host>(s);
    round_trip::<Port>(s);
    round_trip::<Proposal>(s);
    round_trip::<Encryption>(s);
    round_trip::<Hash>(s);
    round_trip::<ClientUid>(s);
    round_trip::<Username>(s);
    round_trip::<LocalId>(s);
    round_trip::<Description>(s);
    round_trip::<ProfileName>(s);
    let _ = Ipv4Net::parse_list(s);
    if let Ok(n) = s.parse::<ProfileName>() {
        for suffix in [" (copy)", " 2", " 1000"] {
            assert!(n.with_suffix(suffix).as_str().len() <= ProfileName::MAX);
        }
    }
    // serde goes through the same parsers, with u16 for the numeric ones
    if let Ok(n) = s.parse::<u16>() {
        let _ = Mtu::try_from(n);
        let _ = Keepalive::try_from(n);
        let _ = LoginTimeout::try_from(n);
        let _ = DhGroup::try_from(n);
    }
});
