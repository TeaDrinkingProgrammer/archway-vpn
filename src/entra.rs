//! Microsoft Entra ID sign-in for Azure VPN, as the Azure VPN Client does it: a public client (the profile's audience
//! is the client id), OAuth 2.0 authorization code with PKCE in the browser, a loopback redirect to
//! `http://localhost:2023`, then the code is exchanged for an access token. The gateway takes that token as the OpenVPN
//! password and the account's UPN as the username.

use crate::azure::Azure;
use crate::net::Secret;
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

/// The Azure VPN Client app's registered redirect.
const REDIRECT_PORT: u16 = 2023;
const REDIRECT: &str = "http://localhost:2023";

pub struct EntraToken {
    pub username: String,
    pub token: Secret,
}

/// Percent-encoded in a URL query or a form body: everything but the RFC 3986 unreserved characters.
const QUERY: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", percent_encoding::utf8_percent_encode(v, QUERY)))
        .collect::<Vec<_>>()
        .join("&")
}

/// `n` random bytes, base64url without padding.
fn random(n: usize) -> Result<String, String> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b)
        .map_err(|e| format!("the system random number generator failed: {e}"))?;
    Ok(data_encoding::BASE64URL_NOPAD.encode(&b))
}

/// The PKCE S256 code challenge for `verifier` (RFC 7636 §4.2).
fn challenge(verifier: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
    data_encoding::BASE64URL_NOPAD.encode(d.as_ref())
}

fn scope(az: &Azure) -> String {
    // no offline_access: a refresh token would only sit in memory unused
    format!("{}/.default openid", az.audience)
}

/// The sign-in page the browser opens.
fn authorize_url(az: &Azure, challenge: &str, state: &str) -> String {
    let client_id = az.audience.to_string();
    let scope = scope(az);
    format!(
        "https://{}/{}/oauth2/v2.0/authorize?{}",
        az.tenant.host,
        az.tenant.id,
        form(&[
            ("client_id", &client_id),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT),
            ("scope", &scope),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("state", state),
        ])
    )
}

/// The account in an access token: `upn`, else `preferred_username`, else `unique_name`. The token isn't verified
/// here; the gateway does that.
fn username(jwt: &str) -> Option<String> {
    let payload = jwt.split('.').nth(1)?;
    let json = data_encoding::BASE64URL_NOPAD
        .decode(payload.trim_end_matches('=').as_bytes())
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&json).ok()?;
    ["upn", "preferred_username", "unique_name"]
        .iter()
        .find_map(|k| claims.get(k)?.as_str().filter(|s| !s.is_empty()))
        .map(str::to_owned)
}

/// What the browser's callback says: the code, or the sign-in error. None: not our callback (another `state`, or
/// neither a code nor an error), keep waiting.
pub fn callback(query: &str, state: &str) -> Option<Result<String, String>> {
    let get = |k| crate::saml::query_param(query, k).filter(|v| !v.is_empty());
    if get("state")? != state {
        return None;
    }
    if let Some(e) = get("error") {
        let why = get("error_description").unwrap_or_default();
        return Some(Err(signin_error(&format!(
            "{e}: {}",
            why.lines().next().unwrap_or("")
        ))));
    }
    get("code").map(Ok)
}

fn signin_error(note: &str) -> String {
    crate::diag(
        "error",
        "the Microsoft sign-in failed",
        note,
        "connect again and sign in once more",
    )
}

/// Sign in in the browser and return the account and its access token. `on_url` gets the sign-in page's address.
pub fn login(
    az: &Azure,
    timeout: Duration,
    cancel: &AtomicBool,
    log: &dyn Fn(String),
    on_url: &dyn Fn(&str),
) -> Result<EntraToken, String> {
    // only IPv4: a browser that tries ::1 first for "localhost" is refused there and falls back to 127.0.0.1 (a socket
    // held on ::1 without answering would leave it waiting). A code taken on ::1 is useless without the PKCE verifier.
    let listener = TcpListener::bind(("127.0.0.1", REDIRECT_PORT)).map_err(|e| {
        crate::diag(
            "error",
            "the sign-in can't receive its answer",
            &format!("Port {REDIRECT_PORT} on this computer is in use ({e})."),
            "close the other program using it (such as another VPN client signing in) and connect again",
        )
    })?;
    let verifier = random(32)?;
    let state = random(16)?;
    let url = authorize_url(az, &challenge(&verifier), &state);
    log(format!(
        "Entra: signing in at https://{}/{}/ for the Azure VPN app {}",
        az.tenant.host, az.tenant.id, az.audience
    ));
    on_url(&url);
    crate::saml::open_browser(&url, log);
    log(format!(
        "Entra: waiting up to {}s for the browser to return to {REDIRECT}/",
        timeout.as_secs()
    ));
    let code =
        crate::saml::wait_for_callback(&listener, timeout, cancel, log, |q| callback(q, &state))?;

    let client_id = az.audience.to_string();
    let scope = scope(az);
    let body = form(&[
        ("client_id", &client_id),
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT),
        ("code_verifier", &verifier),
        ("scope", &scope),
    ]);
    let (host, path) = (
        az.tenant.host.to_string(),
        format!("/{}/oauth2/v2.0/token", az.tenant.id),
    );
    // in the background, so Cancel works while the request is slow
    let answer = crate::saml::in_background(cancel, move || {
        let quiet: Arc<dyn Fn(String) + Send + Sync> = Arc::new(|_| {});
        crate::tls::https_post(
            &host,
            443,
            &path,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            body.as_bytes(),
            true,
            quiet,
        )
    });
    let (_, answer) = match answer {
        Ok(r) => r.map_err(|e| signin_error(&format!("The token request failed: {e}")))?,
        Err(crate::saml::Waited::Cancelled) => return Err("cancelled".into()),
        Err(crate::saml::Waited::Gone) => {
            return Err(signin_error("The token request ended without an answer."));
        }
    };
    token_from(&answer)
}

/// The account and access token in the token endpoint's answer, or its error.
pub fn token_from(answer: &[u8]) -> Result<EntraToken, String> {
    let json: serde_json::Value = serde_json::from_slice(answer)
        .map_err(|_| signin_error("The token endpoint's answer isn't JSON."))?;
    let field = |k: &str| json.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let token = Secret::new(field("access_token").to_string()).map_err(|_| {
        let why = field("error_description").lines().next().unwrap_or("");
        signin_error(&format!("No access token: {} {why}", field("error")))
    })?;
    let username = username(token.expose())
        .ok_or_else(|| signin_error("The access token names no account (upn)."))?;
    Ok(EntraToken { username, token })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn az() -> Azure {
        Azure {
            gateway: "azuregateway-0000aaaa-1111-2222-3333-444455556666-0a1b2c3d4e5f.vpn.azure.com"
                .parse()
                .unwrap(),
            tenant: "https://login.microsoftonline.com/99999999-8888-7777-6666-555555555555/"
                .parse()
                .unwrap(),
            audience: "c632b3df-fb67-4d84-bdcf-b95ad541b5c8".parse().unwrap(),
            root: "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4".parse().unwrap(),
        }
    }

    #[test]
    fn pkce_challenge_matches_rfc_7636() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(random(32).unwrap().len(), 43);
    }

    #[test]
    fn the_sign_in_page_asks_for_the_vpn_audience() {
        let u = authorize_url(&az(), "CH", "ST");
        assert!(u.starts_with("https://login.microsoftonline.com/99999999-8888-7777-6666-555555555555/oauth2/v2.0/authorize?client_id=c632b3df-fb67-4d84-bdcf-b95ad541b5c8&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A2023&"), "{u}");
        assert!(
            u.contains("&scope=c632b3df-fb67-4d84-bdcf-b95ad541b5c8%2F.default%20openid&"),
            "{u}"
        );
        assert!(
            u.ends_with("&code_challenge=CH&code_challenge_method=S256&state=ST"),
            "{u}"
        );
    }

    fn jwt(claims: &str) -> String {
        format!(
            "e30.{}.sig",
            data_encoding::BASE64URL_NOPAD.encode(claims.as_bytes())
        )
    }

    #[test]
    fn the_account_comes_from_the_token() {
        assert_eq!(
            username(&jwt(
                r#"{"upn":"jane@example.com","preferred_username":"x"}"#
            ))
            .as_deref(),
            Some("jane@example.com")
        );
        assert_eq!(
            username(&jwt(r#"{"preferred_username":"jane@example.com"}"#)).as_deref(),
            Some("jane@example.com")
        );
        assert_eq!(username(&jwt("{}")), None);
        assert_eq!(username("garbage"), None);
        let t = token_from(
            format!(
                r#"{{"access_token":"{}"}}"#,
                jwt(r#"{"upn":"jane@example.com"}"#)
            )
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(t.username, "jane@example.com");
        let e = token_from(br#"{"error":"invalid_grant","error_description":"AADSTS70008: expired\r\nTrace ID: 1"}"#)
            .err()
            .unwrap();
        assert!(
            e.contains("invalid_grant AADSTS70008: expired") && !e.contains("Trace"),
            "{e}"
        );
    }

    #[test]
    fn only_a_callback_with_our_state_counts() {
        assert_eq!(callback("code=C&state=S", "S"), Some(Ok("C".into())));
        assert_eq!(callback("code=C&state=X", "S"), None);
        assert_eq!(callback("code=C", "S"), None);
        assert_eq!(callback("state=S", "S"), None);
        let e = callback(
            "error=access_denied&error_description=User+cancelled&state=S",
            "S",
        );
        assert!(
            matches!(&e, Some(Err(m)) if m.starts_with("error: the Microsoft sign-in failed\n  note: access_denied: User cancelled\n")),
            "{e:?}"
        );
    }
}
