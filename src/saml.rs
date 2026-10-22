//! SAML SSO for FortiGate IKE (external-browser flow of FortiAuth.dll `GetIpsecSamlDataExternalBrowser`):
//!
//! ```text
//!   POST https://<gw>:<ike_saml_port>/saml_login?   UID=<uid>&REDIRECT_PORT=<p>
//!   -> window.location="<IdP URL>"  -> user logs in in the browser
//!   -> FortiGate redirects the browser to http://127.0.0.1:<p>/?...tokenid=<T>&...&username=<U>
//! ```

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const DONE_PAGE: &str = "<html><head><title>Archway</title></head><body style=\"font-family:sans-serif\">\
<h3>✔ Signed in</h3><p>You can close this tab. Archway continues setting up the connection.</p></body></html>";

pub struct SamlResult {
    pub username: String,
    pub token: String,
}

pub fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                // on bytes: the two after `%` can be part of a multi-byte character, and slicing the &str there panics
                let hex = |c: u8| (c as char).to_digit(16);
                if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into()
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| url_decode(v))
    })
}

/// The `tokenid` and `username` of the browser's callback request `req` (the raw HTTP request, at least up to the end
/// of its headers), each None when the query doesn't have it. Err for a request that can't be the browser coming back
/// from the login: anything but a GET of `/`, or one a web page sent itself (a script's fetch or form, an image, a
/// frame) instead of the FortiGate's top-level redirect. The FortiGate builds the callback URL, so it can't carry a
/// nonce of ours; these checks keep other pages from slipping in a token of their own.
pub fn callback_params(req: &[u8]) -> Result<(Option<String>, Option<String>), &'static str> {
    let text = String::from_utf8_lossy(req);
    let mut lines = text.lines();
    let mut request = lines.next().unwrap_or("").split_whitespace();
    let (method, target) = (request.next().unwrap_or(""), request.next().unwrap_or(""));
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if method != "GET" || path != "/" {
        return Err("not a GET of /");
    }
    for line in lines.take_while(|l| !l.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
        // browsers send Origin with a script's request and a form post, never with a top-level GET navigation
        if name == "origin" {
            return Err("sent by a script on a web page");
        }
        // Sec-Fetch-Dest says what the request is for; the FortiGate's redirect is a "document"
        if name == "sec-fetch-dest" && !value.eq_ignore_ascii_case("document") {
            return Err("not a page navigation");
        }
    }
    Ok((
        query_param(query, "tokenid"),
        query_param(query, "username"),
    ))
}

/// The uid of the process that owns the local end `peer` of a TCP connection to `ours`, from /proc/net/tcp. Ok(None)
/// when the connection isn't in the table (already closed, or not IPv4); Err when the table can't be read (no /proc).
fn peer_uid(
    ours: std::net::SocketAddr,
    peer: std::net::SocketAddr,
) -> std::io::Result<Option<u32>> {
    let addr = |a: std::net::SocketAddr| match a {
        // as the kernel prints it: the address's bytes as one host-order u32, then the port
        std::net::SocketAddr::V4(a) => Some(format!(
            "{:08X}:{:04X}",
            u32::from_ne_bytes(a.ip().octets()),
            a.port()
        )),
        std::net::SocketAddr::V6(_) => None,
    };
    let table = std::fs::read_to_string("/proc/net/tcp")?;
    let (Some(ours), Some(peer)) = (addr(ours), addr(peer)) else {
        return Ok(None);
    };
    Ok(table.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.get(1) == Some(&peer.as_str()) && f.get(2) == Some(&ours.as_str()))
            .then(|| f.get(7)?.parse().ok())?
    }))
}

/// Whether the connection from `peer` to `ours` comes from another user's process. Checked right after accept, while
/// the connection is surely still open: a connection that's gone from the table can't be told apart from another
/// user's that sent its request and reset at once, so it counts as someone else's. Only without /proc/net/tcp is
/// there nothing to check.
fn from_another_user(ours: std::net::SocketAddr, peer: std::net::SocketAddr) -> bool {
    // SAFETY: geteuid has no preconditions and can't fail.
    let me = unsafe { libc::geteuid() };
    match peer_uid(ours, peer) {
        Ok(Some(uid)) => uid != me,
        Ok(None) => true,
        Err(_) => false,
    }
}

pub struct SamlParams {
    pub gateway: crate::net::Host,
    pub port: crate::net::Port,
    /// 32 hex digits, so it goes into the form body as is
    pub uid: crate::net::ClientUid,
    pub verify_cert: bool,
    pub open_browser: bool,
    pub timeout: Duration,
}

fn port_error(p: &SamlParams, cause: &str) -> String {
    let help = if cause.contains("invalid peer certificate") {
        "the FortiGate's certificate isn't trusted by this system: ask your IT department for a trusted certificate, or turn off \"Verify the server certificate on the SSO port\""
    } else {
        "check the SSO port (FortiGate `auth-ike-saml-port`)"
    };
    crate::diag(
        "error",
        &format!("no SSO login page at {}:{}", p.gateway, p.port),
        cause,
        help,
    )
}

/// Why waiting for a background request ended without its answer.
enum Waited {
    Cancelled,
    /// the thread ended without sending (it panicked)
    Gone,
}

/// Run `f` on another thread and wait for it, so Cancel works while the gateway is slow or silent. An abandoned request
/// ends at its own connect/read timeout.
fn in_background<T: Send + 'static>(
    cancel: &AtomicBool,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Waited> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err(Waited::Cancelled);
        }
        match rx.recv_timeout(Duration::from_millis(150)) {
            Ok(r) => return Ok(r),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err(Waited::Gone),
        }
    }
}

/// The target of the page's `window.location="…"` script redirect.
fn js_redirect(html: &str) -> Option<String> {
    html.split_once("window.location=\"")
        .and_then(|(_, r)| r.split_once('"'))
        .map(|(u, _)| u.to_string())
}

/// Given the FortiGate's SSO start page: the identity provider URL it only redirects to by script, when the browser can
/// go there directly. Not when the page sets a cookie (the FortiGate would need it back when the IdP posts the answer)
/// or the target isn't https.
fn idp_from_start_page(head: &str, body: &str) -> Option<String> {
    let ok = head
        .lines()
        .next()
        .is_some_and(|l| l.split_whitespace().nth(1) == Some("200"));
    let cookie = head
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("set-cookie:"));
    js_redirect(body).filter(|u| ok && !cookie && u.starts_with("https://"))
}

/// The start page only sends the browser on to the identity provider. Fetch it here and open the IdP directly: one
/// page fewer flashing by in the browser. None: open the start page as before.
fn skip_start_page(
    p: &SamlParams,
    start: &str,
    cancel: &AtomicBool,
    log: Arc<dyn Fn(String) + Send + Sync>,
) -> Result<Option<String>, Waited> {
    let Some(path) = start
        .strip_prefix(&format!("https://{}:{}", p.gateway, p.port))
        .map(str::to_owned)
    else {
        return Ok(None);
    };
    let (gateway, port, verify, l) = (
        p.gateway.to_string(),
        p.port.get(),
        p.verify_cert,
        log.clone(),
    );
    let page = in_background(cancel, move || {
        crate::tls::https_get(
            &gateway,
            port,
            &path,
            &[("User-Agent", "FortiClient Windows")],
            verify,
            l,
        )
    })?;
    Ok(match page {
        Ok((head, body)) => {
            let idp = idp_from_start_page(&head, &String::from_utf8_lossy(&body));
            if idp.is_none() {
                log(
                    "SAML: opening the FortiGate start page in the browser (it can't be skipped)"
                        .into(),
                );
            }
            idp
        }
        Err(e) => {
            log(format!(
                "SAML: start page not fetched ({e}); opening it in the browser"
            ));
            None
        }
    })
}

/// `url` if the browser may open it: https only, so an answer like `file:///…` never reaches xdg-open.
fn browser_url(url: &str) -> Result<String, String> {
    if url.starts_with("https://") {
        Ok(url.into())
    } else {
        Err(format!(
            "the login page address isn't https ({})",
            url.chars().take(40).collect::<String>()
        ))
    }
}

/// `on_url` is called with the IdP start URL (for display / manual opening).
pub fn login(
    p: &SamlParams,
    cancel: &AtomicBool,
    log: Arc<dyn Fn(String) + Send + Sync>,
    on_url: &dyn Fn(&str),
) -> Result<SamlResult, String> {
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|e| format!("callback listener: {e}"))?;
    listener.set_nonblocking(true).ok();
    let local = listener
        .local_addr()
        .map_err(|e| format!("callback listener: {e}"))?;
    let rport = local.port();

    log(format!(
        "SAML: POST https://{}:{}/saml_login? (UID={}, REDIRECT_PORT={rport})",
        p.gateway, p.port, p.uid
    ));
    let body = format!("UID={}&REDIRECT_PORT={rport}", p.uid);
    // in the background, so Cancel works while the gateway is slow or silent; an abandoned request ends at
    // its own connect/read timeout
    let (gateway, port, verify, l) = (
        p.gateway.to_string(),
        p.port.get(),
        p.verify_cert,
        log.clone(),
    );
    let answer = in_background(cancel, move || {
        let headers = [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("User-Agent", "FortiClient Windows"),
        ];
        crate::tls::https_post(
            &gateway,
            port,
            "/saml_login?",
            &headers,
            body.as_bytes(),
            verify,
            l,
        )
    });
    let (head, html) = match answer {
        Err(Waited::Cancelled) => return Err("cancelled".into()),
        Err(Waited::Gone) => return Err(port_error(p, "the request ended without an answer")),
        Ok(r) => r.map_err(|e| port_error(p, &e))?,
    };
    let html = String::from_utf8_lossy(&html);
    let start = js_redirect(&html).ok_or_else(|| {
        port_error(
            p,
            &format!(
                "the answer isn't a FortiGate SSO page ({})",
                head.lines().next().unwrap_or("empty response")
            ),
        )
    })?;
    let start = if start.starts_with('/') {
        format!("https://{}:{}{start}", p.gateway, p.port)
    } else {
        start
    };
    let url = match skip_start_page(p, &start, cancel, log.clone()) {
        Err(Waited::Cancelled) => return Err("cancelled".into()),
        Ok(Some(idp)) => idp,
        Ok(None) | Err(Waited::Gone) => start,
    };
    let url = browser_url(&url).map_err(|e| port_error(p, &e))?;
    log(format!("SAML: identity provider login URL: {url}"));
    on_url(&url);
    if p.open_browser {
        // ARCHWAY_BROWSER overrides the opener (e.g. a specific browser, or a test harness)
        let opener = std::env::var("ARCHWAY_BROWSER").unwrap_or_else(|_| "xdg-open".into());
        match std::process::Command::new(&opener)
            .arg(&url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(_) => {}
            Err(e) => log(format!(
                "could not run {opener} ({e}); open the URL manually"
            )),
        }
    }
    log(format!(
        "SAML: waiting up to {}s for the browser to return to http://127.0.0.1:{rport}/",
        p.timeout.as_secs()
    ));

    let deadline = Instant::now() + p.timeout;
    while Instant::now() < deadline {
        if cancel.load(Ordering::SeqCst) {
            return Err("cancelled".into());
        }
        let (mut s, peer) = match listener.accept() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(150));
                continue;
            }
            Err(e) => return Err(format!("callback listener: {e}")),
        };
        // only the browser of the user running the app may hand over the token, not another user's process;
        // checked before reading, so such a connection is dropped at once and can't stall the real callback
        if from_another_user(local, peer) {
            log(
                "SAML: ignored a connection on the callback port (from another user's process)"
                    .into(),
            );
            continue;
        }
        s.set_nonblocking(false).ok();
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut req = Vec::new();
        let mut buf = [0u8; 4096];
        while !req.windows(4).any(|w| w == b"\r\n\r\n") && req.len() < 65536 {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => req.extend_from_slice(&buf[..n]),
            }
        }
        let (token, username) = match callback_params(&req) {
            Ok(p) => p,
            Err(why) => {
                log(format!(
                    "SAML: ignored a request on the callback port ({why})"
                ));
                let _ = s.write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                continue;
            }
        };
        let resp = if token.is_some() {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{DONE_PAGE}",
                DONE_PAGE.len()
            )
        } else {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        };
        let _ = s.write_all(resp.as_bytes());
        if let Some(token) = token.filter(|t| !t.is_empty()) {
            let username = username.unwrap_or_default();
            log(format!(
                "SAML: success, username={username}, tokenid=<{} chars>",
                token.len()
            ));
            return Ok(SamlResult { username, token });
        }
    }
    Err("SSO login timed out".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_browsers_redirect_is_a_callback() {
        let ok = b"GET /?tokenid=t%2B1&username=jane HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nSec-Fetch-Dest: document\r\n\r\n";
        assert_eq!(
            callback_params(ok),
            Ok((Some("t+1".into()), Some("jane".into())))
        );
        // no Sec-Fetch headers at all (an older browser): still the redirect
        assert!(callback_params(b"GET /?tokenid=t HTTP/1.1\r\n\r\n").is_ok());
        for bad in [
            &b"POST /?tokenid=t HTTP/1.1\r\n\r\n"[..],
            b"GET /other?tokenid=t HTTP/1.1\r\n\r\n",
            b"GET /?tokenid=t HTTP/1.1\r\nOrigin: https://evil.example\r\n\r\n",
            b"GET /?tokenid=t HTTP/1.1\r\nsec-fetch-dest: image\r\n\r\n",
            b"GET /?tokenid=t HTTP/1.1\r\nSec-Fetch-Dest: iframe\r\n\r\n",
        ] {
            assert!(
                callback_params(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn the_peer_of_a_local_connection_is_this_user() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (_s, peer) = l.accept().unwrap();
        assert_eq!(peer, c.local_addr().unwrap());
        // SAFETY: geteuid has no preconditions and can't fail.
        let me = unsafe { libc::geteuid() };
        let ours = l.local_addr().unwrap();
        assert_eq!(peer_uid(ours, peer).unwrap(), Some(me));
        assert!(!from_another_user(ours, peer));
        // a connection that's no longer in the table (sent its request and reset) can't be shown to be ours
        let gone: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert_eq!(peer_uid(ours, gone).unwrap(), None);
        assert!(from_another_user(ours, gone));
    }

    #[test]
    fn percent_before_a_multibyte_character_is_kept() {
        // found by the saml_callback fuzzer: "%a" followed by "é" used to slice inside the character and panic
        assert_eq!(url_decode("%a\u{e9}"), "%a\u{e9}");
        assert_eq!(url_decode("%\u{e9}x"), "%\u{e9}x");
        assert_eq!(url_decode("a%2Fb%zz"), "a/b%zz");
    }
    #[test]
    fn decode() {
        assert_eq!(url_decode("user%40example.com"), "user@example.com");
        assert_eq!(
            query_param("tokenid=ab%2Fc&realm=&username=a%40b", "username").unwrap(),
            "a@b"
        );
        assert_eq!(
            query_param("tokenid=ab%2Fc&realm=", "tokenid").unwrap(),
            "ab/c"
        );
    }

    fn params(port: u16) -> SamlParams {
        SamlParams {
            gateway: "127.0.0.1".parse().unwrap(),
            port: crate::net::Port::new(port).unwrap(),
            uid: "0123456789ABCDEF0123456789ABCDEF".parse().unwrap(),
            verify_cert: false,
            open_browser: false,
            timeout: Duration::from_secs(5),
        }
    }

    fn quiet() -> Arc<dyn Fn(String) + Send + Sync> {
        Arc::new(|_| {})
    }

    fn assert_port_error(e: &str, port: u16) {
        assert!(
            e.starts_with(&format!(
                "error: no SSO login page at 127.0.0.1:{port}\n  note: "
            )),
            "{e}"
        );
        assert!(
            e.contains("\n  help: check the SSO port (FortiGate `auth-ike-saml-port`)"),
            "{e}"
        );
    }

    #[test]
    fn refused_port_explains_itself() {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port(); // closed again
        let e = login(&params(port), &AtomicBool::new(false), quiet(), &|_| {})
            .err()
            .unwrap();
        assert_port_error(&e, port);
    }

    #[test]
    fn non_tls_answer_explains_itself() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            }
        });
        let e = login(&params(port), &AtomicBool::new(false), quiet(), &|_| {})
            .err()
            .unwrap();
        assert_port_error(&e, port);
    }

    #[test]
    fn cancel_returns_while_gateway_hangs() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap(); // connects, but never answers the TLS handshake
        let port = l.local_addr().unwrap().port();
        let cancel = Arc::new(AtomicBool::new(false));
        let c = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            c.store(true, Ordering::SeqCst);
        });
        let t0 = Instant::now();
        let r = login(&params(port), &cancel, quiet(), &|_| {});
        assert_eq!(r.err().as_deref(), Some("cancelled"));
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "took {:?}",
            t0.elapsed()
        );
        drop(l);
    }

    #[test]
    fn script_redirects_are_found() {
        assert_eq!(
            js_redirect("<script>window.location=\"/saml?x=1\";</script>").as_deref(),
            Some("/saml?x=1")
        );
        assert_eq!(js_redirect("<html>nothing</html>"), None);
    }

    #[test]
    fn the_start_page_is_skipped_only_when_it_is_a_plain_redirect_to_https() {
        let page = "<html><script>window.location=\"https://login.example/saml2?SAMLRequest=abc%3D\";</script></html>";
        let ok = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: no-cache";
        assert_eq!(
            idp_from_start_page(ok, page).as_deref(),
            Some("https://login.example/saml2?SAMLRequest=abc%3D")
        );
        // a cookie set here would be needed again when the IdP posts back: then the browser must load this page itself
        assert_eq!(
            idp_from_start_page("HTTP/1.1 200 OK\r\nSet-Cookie: s=1; Path=/", page),
            None
        );
        assert_eq!(
            idp_from_start_page("HTTP/1.1 200 OK\r\nset-cookie: s=1", page),
            None
        );
        assert_eq!(
            idp_from_start_page("HTTP/1.1 302 Found\r\nLocation: /x", page),
            None
        );
        assert_eq!(
            idp_from_start_page(
                ok,
                "<script>window.location=\"file:///etc/passwd\"</script>"
            ),
            None
        );
        assert_eq!(idp_from_start_page(ok, "<html>no script</html>"), None);
    }

    #[test]
    fn only_https_pages_are_opened_in_the_browser() {
        assert!(browser_url("https://vpn.example.com:10443/saml?x=1").is_ok());
        for bad in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "http://vpn.example.com/saml",
            "-x",
            "",
        ] {
            assert!(browser_url(bad).is_err(), "{bad:?}");
        }
    }
}
