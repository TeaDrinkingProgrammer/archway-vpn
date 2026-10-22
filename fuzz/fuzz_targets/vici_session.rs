//! A whole VICI session against a charon that answers with arbitrary bytes: the input is everything the backend reads
//! from the socket while it checks plugins, loads the connection and secrets, initiates, lists the SA and waits for
//! events. Covers the length framing, packet decoding and every message shape, in the order the backend uses them.
#![no_main]

use archway_vpn::charon::{self, ConnParams};
use archway_vpn::net::{DhGroup, Port, Secret};
use archway_vpn::protocol::{ClientAuth, EapIdentity};
use archway_vpn::vici::{EventName, Vici};
use libfuzzer_sys::fuzz_target;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Once;
use std::time::Duration;

static INIT: Once = Once::new();

fn params() -> ConnParams {
    ConnParams {
        gateway: "vpn.example.com".parse().unwrap(),
        ike_port: Port::new(500).unwrap(),
        ike_proposals: vec1::vec1!["aes128-sha1".parse().unwrap()],
        dh_groups: vec1::vec1![DhGroup::Ecp384],
        esp_proposals: vec1::vec1!["aes128-sha1".parse().unwrap()],
        local_id: None,
        auth: ClientAuth::Eap {
            identity: EapIdentity::Uid("0123456789ABCDEF0123456789ABCDEF".parse().unwrap()),
            secret: Secret::new("token-secret".into()).unwrap(),
        },
        psk: Secret::new("psk-secret".into()).unwrap(),
    }
}

fuzz_target!(|data: &[u8]| {
    // libFuzzer's main doesn't go through Rust's runtime init, which is what normally ignores SIGPIPE
    INIT.call_once(|| unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    });
    let (client, mut charon_side) = UnixStream::pair().unwrap();
    // never block on the socket buffer: a stuck write is an error here, not a hang
    client
        .set_write_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let data = data.to_vec();
    let fake = std::thread::spawn(move || {
        let _ = charon_side.write_all(&data);
        let _ = charon_side.shutdown(std::net::Shutdown::Write); // EOF after the script: no waiting for timeouts
        // drain what the backend sends until it hangs up
        let mut sink = [0u8; 4096];
        while let Ok(n) = charon_side.read(&mut sink) {
            if n == 0 {
                break;
            }
        }
    });
    let mut v = Vici::from_stream(client);
    let p = params();
    let _ = charon::check_plugins(&mut v, true);
    let _ = charon::connect(&mut v, &p, &|_| {});
    let _ = charon::established(&mut v, &|_| {});
    let _ = v.register(EventName::IkeUpdown);
    for _ in 0..4 {
        match v.next_event(Duration::from_millis(50)) {
            Ok(Some((EventName::IkeUpdown, body))) => {
                let _ = charon::is_down(&body);
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    charon::terminate(&mut v);
    drop(v);
    let _ = fake.join();
});
