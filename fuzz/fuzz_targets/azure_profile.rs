//! What the user picks in the file dialog for an Azure VPN import: the Azure portal's zip or its `azurevpnconfig.xml`.
//! The zip reader, the XML walk and the typed fields. A profile that imports must survive Save and load (the Azure
//! settings, never the secret), and the OpenVPN config built from it must have exactly the lines the template writes:
//! nothing from the file may add a line of its own. The zip is only a wrapper: the same XML inside a zip, under any
//! of the entry names the reader accepts, must import to the same profile or be refused as well, and an entry that
//! inflates past the cap must be refused, not read (libFuzzer's memory and time limits catch a zip bomb that isn't).
#![no_main]

use archway_vpn::azure;
use archway_vpn::config::{self, Vpn};
use libfuzzer_sys::fuzz_target;
use std::io::Write;

/// Lines of `ovpn()` for a profile: the 15 fixed directives, `<ca>`/CA/`</ca>`, and the static key block (header,
/// 16 lines of 32 hex digits, footer) inside `<tls-auth>`.
const OVPN_LINES: usize = 15 + 3 + 20;

const REFUSED: &str = "error: this file can't be imported as an Azure VPN profile\n";

/// The entry names the reader must find the profile under: as the portal writes it, with forward slashes, bare,
/// deeper, in another case. All must import; `xazurevpnconfig.xml` and `azurevpnconfig.xml.bak` must not.
const NAMES: [&str; 5] = [
    "AzureVPN\\azurevpnconfig.xml",
    "AzureVPN/azurevpnconfig.xml",
    "azurevpnconfig.xml",
    "a\\b/AZUREVPNCONFIG.XML",
    "./azurevpnconfig.xml",
];

/// A zip with `Generic\VpnSettings.xml` and `name` holding `xml`, deflated or stored.
fn zipped(name: &str, xml: &[u8], deflate: bool) -> Vec<u8> {
    let method = if deflate {
        zip::CompressionMethod::Deflated
    } else {
        zip::CompressionMethod::Stored
    };
    let opts = zip::write::SimpleFileOptions::default().compression_method(method);
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file("Generic\\VpnSettings.xml", opts).unwrap();
    w.write_all(b"<VpnProfile/>").unwrap();
    w.start_file(name, opts).unwrap();
    w.write_all(xml).unwrap();
    w.finish().unwrap().into_inner()
}

/// What matters of an import's outcome, to compare the bare XML with the zipped one.
fn outcome(r: &Result<config::Profile, String>) -> Result<(String, String, Vpn), String> {
    r.as_ref()
        .map(|p| (p.name.to_string(), p.psk.clone(), p.vpn.clone()))
        .map_err(|e| e.lines().nth(1).unwrap_or("").to_string())
}

fuzz_target!(|bytes: &[u8]| {
    let imported = azure::import_file(bytes);

    // the zip is transparent: the same XML inside a zip gives the same result, under every accepted entry name
    if !bytes.starts_with(b"PK\x03\x04") {
        let direct = outcome(&imported);
        let pick = bytes.len() % NAMES.len();
        let zipped_result = azure::import_file(&zipped(NAMES[pick], bytes, pick % 2 == 0));
        match (std::str::from_utf8(bytes).is_ok(), &direct) {
            // the zip reader only takes UTF-8 text; bare bytes that aren't are refused before the XML parse
            (false, _) => assert!(zipped_result.is_err(), "{}", NAMES[pick]),
            (true, direct) => assert_eq!(&outcome(&zipped_result), direct, "zipped as {}", NAMES[pick]),
        }
        if bytes.len() % 7 == 0 {
            let e = azure::import_file(&zipped("xazurevpnconfig.xml", bytes, false)).unwrap_err();
            assert!(e.contains("no AzureVPN/azurevpnconfig.xml"), "{e}");
        }
    }

    let p = match imported {
        Ok(p) => p,
        Err(e) => {
            assert!(e.starts_with(REFUSED), "every refusal is a diag: {e}");
            return;
        }
    };
    let Vpn::Azure(az) = &p.vpn else {
        panic!("an imported profile is an Azure one")
    };
    assert!(
        p.psk.len() == 512 && p.psk.bytes().all(|b| b.is_ascii_hexdigit()),
        "the server secret was checked"
    );

    // Save writes the sparse TOML without the secret; loading it gives the same profile
    let file = config::sparse(&p);
    assert!(!file.contains(&p.psk[..16]), "the secret isn't in the file");
    assert!(file.starts_with("type = \"azure-openvpn\"\n"), "{file}");
    let mut again = config::parse_profile(&file).expect("what Save writes loads again");
    again.id = p.id.clone(); // random per parse, not in the file
    again.name = p.name.clone(); // the file's name, not in the file
    again.psk = p.psk.clone(); // the keyring's
    assert_eq!(again, p, "an imported profile survives Save and load");

    let c = azure::ovpn(az, &p.psk, "CA").expect("a checked secret makes a config");
    let c = c.expose();
    assert_eq!(c.lines().count(), OVPN_LINES, "no line was injected:\n{c}");
    let line = |prefix: &str| c.lines().find(|l| l.starts_with(prefix)).expect(prefix);
    assert_eq!(line("remote ").split(' ').count(), 3, "{c}");
    let name = line("verify-x509-name ").split(' ').nth(1).unwrap();
    assert_eq!(name, az.gateway.cert_name());
    assert!(
        name.parse::<archway_vpn::net::DnsName>().is_ok(),
        "the checked name is a host name: {name}"
    );
    assert!(!c.contains("<ca>\nCA\n</ca>\n<ca>"), "{c}");
});
