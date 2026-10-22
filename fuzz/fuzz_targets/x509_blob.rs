//! What an AIA server answers (DER, PEM or PKCS#7) and the certificate the server presents: certificate extraction
//! and the AIA "CA Issuers" URL lookup, both on x509-parser.
#![no_main]

use archway_vpn::tls;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for c in tls::certs_from_blob(data) {
        let _ = tls::aia_issuer_urls(c.as_ref());
    }
    let _ = tls::aia_issuer_urls(data);
});
