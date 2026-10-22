//! A stdout line from the backend as the GUI reads it (`@@{json}` status events), plus the rustc-style error text the
//! GUI parses back into a banner (`Diag::parse`).
#![no_main]

use archway_vpn::diag::Diag;
use archway_vpn::protocol::BackendEvent;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|line: &str| {
    if let Some(Ok(ev)) = BackendEvent::from_line(line) {
        assert_eq!(BackendEvent::from_line(&ev.to_line()), Some(Ok(ev)));
    }
    if let Some(d) = Diag::parse(line) {
        assert_eq!(
            Diag::parse(&d.to_string()),
            Some(d.clone()),
            "a parsed diag prints as the same diag"
        );
        let _ = d.fix();
    }
});
