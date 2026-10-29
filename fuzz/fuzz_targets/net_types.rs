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
    round_trip::<Guid>(s);
    round_trip::<AzureGateway>(s);
    round_trip::<Tenant>(s);
    round_trip::<CertPin>(s);
    if let Ok(g) = s.parse::<AzureGateway>() {
        // the name OpenVPN checks the certificate against: the VNet id in the same domain, a host name itself
        let cn = g.cert_name();
        assert!(cn.parse::<DnsName>().is_ok(), "{s:?}: cert name {cn:?}");
        assert!(g.to_string().ends_with(&cn[36..]), "{s:?}: {cn:?}");
        // the VNet id in the name is the one dialled, and the dialled name is never the one checked
        assert!(g.to_string().contains(&cn[..36]) && cn != g.to_string(), "{s:?}: {cn:?}");
        let Host::Name(n) = Host::from(&g) else {
            panic!("a gateway is a name")
        };
        assert_eq!(n.to_string(), g.to_string());
    }
    if let Ok(pin) = s.parse::<CertPin>() {
        let t = pin.to_string();
        assert!(t.len() == 40 && t.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_lowercase()), "{t}");
    }
    if let Ok(t) = s.parse::<Tenant>() {
        assert!(t.to_string().ends_with('/') && t.to_string().starts_with("https://"), "{t}");
        // the code and PKCE verifier are posted to this host: only Entra's sign-in hosts
        assert!(
            [
                "login.microsoftonline.com",
                "login.microsoftonline.us",
                "login.chinacloudapi.cn"
            ]
            .contains(&t.host.to_string().as_str()),
            "{s:?}"
        );
    }
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
