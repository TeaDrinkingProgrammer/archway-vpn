//! The HTTP request the browser (or anything else on the machine) sends to the local SSO callback listener: request
//! line and query parsing, percent decoding.
#![no_main]

use archway_vpn::saml;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = saml::callback_params(data);
    let text = String::from_utf8_lossy(data);
    let _ = saml::url_decode(&text);
    let _ = saml::query_param(&text, "tokenid");
});
