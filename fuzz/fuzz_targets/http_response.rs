//! An HTTP response from the FortiGate's SSO port or an AIA server: header split, chunked decoding, and what the SAML
//! code makes of the page (the script redirect, the start page skip, the https-only check for the browser).
#![no_main]

use archway_vpn::{saml, tls};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((head, body)) = tls::split_http(data) {
        let html = String::from_utf8_lossy(&body);
        let _ = saml::idp_from_start_page(&head, &html);
        if let Some(u) = saml::js_redirect(&html) {
            let _ = saml::browser_url(&u);
        }
    }
    let _ = tls::dechunk(data);
});
