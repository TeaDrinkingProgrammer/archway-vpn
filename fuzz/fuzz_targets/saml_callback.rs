//! The HTTP request the browser (or anything else on the machine) sends to the local SSO callback listener: request
//! line and query parsing, percent decoding.
#![no_main]

use archway_vpn::saml;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Ok(query) = saml::callback_query(data) {
        // only a top-level GET of / counts, and the query is what followed its `?`
        let mut words = text.split_whitespace();
        assert_eq!(words.next(), Some("GET"), "{text:?}");
        let target = words.next().unwrap_or("");
        assert!(target == "/" || target.starts_with("/?"), "{text:?}");
        assert!(!query.contains(char::is_whitespace), "{query:?}");
        assert!(query.is_empty() || target == format!("/?{query}"), "{query:?}");
        for h in text.lines().skip(1).take_while(|l| !l.is_empty()) {
            let name = h.split_once(':').map_or("", |(n, _)| n).trim().to_ascii_lowercase();
            assert_ne!(name, "origin", "a script's request got through: {text:?}");
        }
    }
    let _ = saml::url_decode(&text);
    let _ = saml::query_param(&text, "tokenid");
});
