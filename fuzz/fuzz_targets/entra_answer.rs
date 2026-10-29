//! What comes back from the Entra sign-in: the browser's callback query (code or error, only with our `state`) and
//! the token endpoint's JSON answer (an access token whose payload names the account).
#![no_main]

use archway_vpn::entra;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // the callback: the query is the input, the state is its first 8 bytes when they're text
    let text = String::from_utf8_lossy(data);
    let state: String = text.chars().take(8).collect();
    match entra::callback(&text, &state) {
        Some(Ok(code)) => {
            assert!(!code.is_empty(), "an empty code is no code");
            assert_eq!(
                archway_vpn::saml::query_param(&text, "state").as_deref(),
                Some(state.as_str()),
                "a code counts only with our state"
            );
        }
        Some(Err(e)) => assert!(e.starts_with("error: the Microsoft sign-in failed\n"), "{e}"),
        None => {}
    }
    assert!(entra::callback(&text, "").is_none(), "an empty state never matches");
    assert!(
        entra::callback(&text, "never-sent-\u{1}").is_none(),
        "a state that wasn't in the query doesn't match"
    );

    // the token answer
    match entra::token_from(data) {
        Ok(t) => assert!(!t.username.is_empty() && !t.token.expose().is_empty()),
        Err(e) => assert!(e.starts_with("error: the Microsoft sign-in failed\n"), "{e}"),
    }
});
