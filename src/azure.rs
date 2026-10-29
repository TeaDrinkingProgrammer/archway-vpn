//! Azure VPN Gateway, Point-to-Site with the OpenVPN tunnel type and Microsoft Entra ID sign-in. The profile the Azure
//! portal hands out (`azurevpnconfig.xml`) is imported once; connecting signs in with Entra in the browser (entra.rs)
//! and hands the token to OpenVPN 3 Linux over D-Bus (openvpn3.rs) as the OpenVPN password. All of it runs as the
//! user: openvpn3's own services set up the tun device, routes and DNS, so there is no pkexec here.

use crate::backend::Event;
use crate::config::{Profile, Vpn};
use crate::net::{AzureGateway, CertPin, Guid, Host, ProfileName, Secret, Tenant};
use crate::protocol::BackendEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// An imported Azure VPN profile. The server secret (the OpenVPN tls-auth key) is the profile's PSK, so it lives in
/// the keyring like one.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Azure {
    pub gateway: AzureGateway,
    pub tenant: Tenant,
    /// the Entra app the token is for; also the client id the browser sign-in uses (the Azure VPN Client app)
    pub audience: Guid,
    /// SHA-1 of the root certificate the gateway's chain must end in
    pub root: CertPin,
}

/// How long the browser sign-in may take.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

const IMPORT_HELP: &str = "in the Azure portal, click Download VPN client in the gateway's Point-to-site configuration and import the zip file it gives you";

/// Largest file read for an import, and largest file unpacked from a zip: the Azure portal's zip is a few kB.
pub const MAX_FILE: u64 = 1 << 20;

fn not_importable(note: &str) -> String {
    crate::diag(
        "error",
        "this file can't be imported as an Azure VPN profile",
        note,
        IMPORT_HELP,
    )
}

/// The text of every element by its path below the root, such as `clientauth/aad/tenant`.
fn elements(xml: &str) -> Result<HashMap<String, String>, String> {
    use quick_xml::events::Event as X;
    let mut r = quick_xml::Reader::from_str(xml);
    // an element's text arrives in pieces: text, CDATA, and each entity reference on its own
    let (mut path, mut text, mut out) = (Vec::<String>::new(), String::new(), HashMap::new());
    loop {
        match r.read_event().map_err(|e| e.to_string())? {
            X::Start(e) => {
                path.push(String::from_utf8_lossy(e.local_name().as_ref()).into());
                text.clear();
            }
            X::Text(t) => text.push_str(&t.decode().map_err(|e| e.to_string())?),
            X::CData(t) => text.push_str(&t.decode().map_err(|e| e.to_string())?),
            X::GeneralRef(e) => match e.resolve_char_ref().map_err(|e| e.to_string())? {
                Some(c) => text.push(c),
                None => {
                    let name = e.decode().map_err(|e| e.to_string())?;
                    let value = quick_xml::escape::resolve_predefined_entity(&name)
                        .ok_or_else(|| format!("unknown entity &{name};"))?;
                    text.push_str(value);
                }
            },
            X::End(_) => {
                let value = text.trim();
                if !value.is_empty() {
                    // the first wins: a profile with several servers lists the primary first
                    out.entry(path.get(1..).unwrap_or_default().join("/"))
                        .or_insert_with(|| value.to_string());
                }
                path.pop();
                text.clear();
            }
            X::Eof => return Ok(out),
            _ => {}
        }
    }
}

/// An Azure VPN connection from the file the user picked: the zip the Azure portal gives out (its
/// `AzureVPN\azurevpnconfig.xml`), or that XML file on its own. The zip is read in memory, nothing is unpacked to disk.
pub fn import_file(bytes: &[u8]) -> Result<Profile, String> {
    use std::io::Read;
    if !bytes.starts_with(b"PK\x03\x04") {
        let xml = std::str::from_utf8(bytes)
            .map_err(|_| not_importable("It's neither a zip file nor XML text."))?;
        return import(xml);
    }
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| not_importable(&format!("It isn't a valid zip file: {e}")))?;
    // the portal writes Windows paths: `AzureVPN\azurevpnconfig.xml`
    let name = zip
        .file_names()
        .filter_map(Result::ok)
        .find(|n| {
            let n = n.replace('\\', "/").to_ascii_lowercase();
            n == "azurevpnconfig.xml" || n.ends_with("/azurevpnconfig.xml")
        })
        .map(|n| n.into_owned())
        .ok_or_else(|| {
            not_importable("The zip has no AzureVPN/azurevpnconfig.xml: the gateway may not use the OpenVPN tunnel type with Microsoft Entra ID sign-in.")
        })?;
    let mut xml = String::new();
    zip.by_name(&name)
        .map_err(|e| e.to_string())
        .and_then(|f| {
            f.take(MAX_FILE)
                .read_to_string(&mut xml)
                .map_err(|e| e.to_string())
        })
        .map_err(|e| not_importable(&format!("Its azurevpnconfig.xml can't be read: {e}")))?;
    import(&xml)
}

/// An Azure VPN connection from `azurevpnconfig.xml`: its name, the Azure settings, and the server secret as PSK.
pub fn import(xml: &str) -> Result<Profile, String> {
    let el = elements(xml).map_err(|e| not_importable(&format!("It isn't valid XML: {e}")))?;
    let get = |path: &str, what: &str| {
        el.get(path)
            .map(String::as_str)
            .ok_or_else(|| not_importable(&format!("It has no {what}.")))
    };
    fn parse<T: std::str::FromStr<Err = String>>(text: &str, what: &str) -> Result<T, String> {
        text.parse()
            .map_err(|e| not_importable(&format!("The {what} is invalid: {e}")))
    }
    let auth = get("clientauth/type", "sign-in type")?;
    if !auth.eq_ignore_ascii_case("aad") {
        return Err(not_importable(&format!(
            "It signs in with \"{auth}\"; Archway supports Microsoft Entra ID sign-in only."
        )));
    }
    let transport = get(
        "protocolconfig/sslprotocolConfig/transportprotocol",
        "transport protocol",
    )?;
    if !transport.eq_ignore_ascii_case("tcp") {
        return Err(not_importable(&format!(
            "It uses the \"{transport}\" transport; Archway supports OpenVPN over TCP only."
        )));
    }
    let secret = get("servervalidation/serversecret", "server secret")?;
    tls_auth_key(secret).map_err(|e| not_importable(&e))?;
    let azure = Azure {
        gateway: parse(get("serverlist/ServerEntry/fqdn", "gateway")?, "gateway")?,
        tenant: parse(get("clientauth/aad/tenant", "tenant")?, "tenant")?,
        audience: parse(get("clientauth/aad/audience", "audience")?, "audience")?,
        root: parse(
            get(
                "servervalidation/Cert/hash",
                "server certificate fingerprint",
            )?,
            "server certificate fingerprint",
        )?,
    };
    Ok(Profile {
        name: el
            .get("name")
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| "Azure VPN".parse::<ProfileName>().expect("a valid name")),
        psk: secret.into(),
        ..Profile::new(Vpn::Azure(azure))
    })
}

/// The server secret as an OpenVPN static key block: 256 bytes, 512 hex digits.
fn tls_auth_key(hex: &str) -> Result<String, String> {
    let ok = hex.len() == 512 && hex.bytes().all(|b| b.is_ascii_hexdigit());
    if !ok {
        return Err("The server secret must be 512 hexadecimal digits.".into());
    }
    Ok(pem("OpenVPN Static key V1", &hex.to_ascii_lowercase(), 32))
}

/// The root certificate with SHA-1 fingerprint `pin` from the system's trusted certificates, as PEM.
fn root_ca(pin: CertPin) -> Result<String, String> {
    let sha1 = |der: &[u8]| {
        ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, der)
            .as_ref()
            .to_vec()
    };
    let store = rustls_native_certs::load_native_certs();
    let der = store
        .certs
        .into_iter()
        .find(|c| sha1(c.as_ref()) == pin.0)
        .ok_or_else(|| {
            // say why when the store couldn't be (fully) read
            let read = store
                .errors
                .first()
                .map_or_else(String::new, |e| format!(" Reading them failed: {e}."));
            crate::diag(
                "error",
                "the gateway's root certificate isn't trusted on this system",
                &format!("The profile expects a root certificate with SHA-1 fingerprint {pin}, which isn't among the system's trusted certificates.{read}"),
                "update your system's CA certificates (the ca-certificates package) and connect again",
            )
        })?;
    Ok(pem(
        "CERTIFICATE",
        &data_encoding::BASE64.encode(der.as_ref()),
        64,
    ))
}

/// `body` as a PEM-style block: BEGIN line, `body` in lines of `width`, END line.
fn pem(label: &str, body: &str, width: usize) -> String {
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(width)
        .map(|c| std::str::from_utf8(c).expect("base64 and hex are ASCII"))
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----",
        lines.join("\n")
    )
}

/// The OpenVPN config for `az`. It holds the tls-auth key, so it's a secret too. The gateway's certificate is issued
/// to `<vnet-id>.<domain>`, not to the name dialled: that's the name checked. Credentials come over D-Bus.
/// `ping-restart 0`: the gateway sends no keepalive pings, so OpenVPN 3's default (restart after 40 s without hearing
/// from it) cut every idle tunnel, and the reconnect can't sign in again. TCP still notices a dead gateway.
pub fn ovpn(az: &Azure, server_secret: &str, ca_pem: &str) -> Result<Secret, String> {
    let key = tls_auth_key(server_secret)?;
    Secret::new(format!(
        "client\n\
         dev tun\n\
         proto tcp-client\n\
         remote {gateway} 443\n\
         nobind\n\
         remote-cert-tls server\n\
         verify-x509-name {cn} name\n\
         auth SHA256\n\
         cipher AES-256-GCM\n\
         data-ciphers AES-256-GCM:AES-128-GCM\n\
         tls-version-min 1.2\n\
         key-direction 1\n\
         ping-restart 0\n\
         auth-user-pass\n\
         auth-nocache\n\
         <ca>\n{ca_pem}\n</ca>\n\
         <tls-auth>\n{key}\n</tls-auth>\n",
        gateway = az.gateway,
        cn = az.gateway.cert_name(),
    ))
}

/// One Azure VPN session: check openvpn3 is there, sign in in the browser, connect, wait until disconnected.
pub fn run(
    p: &Profile,
    az: &Azure,
    cancel: &AtomicBool,
    send: Arc<dyn Fn(Event) + Send + Sync>,
) -> Result<(), String> {
    let key = Secret::new(p.psk.clone()).map_err(|_| {
        crate::diag(
            "error",
            "can't connect without the server secret",
            "it's in the profile the Azure portal gives out, and wasn't found in your keyring",
            "import the profile again and click Save",
        )
    })?;
    let config = ovpn(az, key.expose(), &root_ca(az.root)?)?;
    let ov = crate::openvpn3::OpenVpn3::connect()?;

    send(Event::Backend(BackendEvent::SamlStart));
    let log = |m: String| send(Event::Log(m));
    let login = crate::entra::login(az, LOGIN_TIMEOUT, cancel, &log, &|url| {
        send(Event::Backend(BackendEvent::SamlUrl { url: url.into() }))
    });
    let token = match login {
        Err(e) if cancel.load(Ordering::SeqCst) => {
            log(format!("Entra: {e}"));
            return Ok(());
        }
        r => r?,
    };
    send(Event::Backend(BackendEvent::SamlOk {
        username: token.username.clone(),
    }));
    if cancel.load(Ordering::SeqCst) {
        return Ok(());
    }

    send(Event::Backend(BackendEvent::IkeStart {
        gateway: Host::from(&az.gateway),
    }));
    let session = ov.start(
        p.name.as_str(),
        &config,
        &token.username,
        &token.token,
        cancel,
        &log,
    )?;
    if cancel.load(Ordering::SeqCst) {
        return Ok(()); // dropping the session disconnects it
    }
    // only for the window: a tunnel that's up isn't torn down because its details can't be read
    match session
        .device()
        .and_then(|ifname| Ok((crate::netlink::ipv4_of(&ifname)?, ifname)))
    {
        Ok(((ip, routes), ifname)) => {
            log(format!(
                "tunnel up: {ifname} ip={} routes [{}]",
                ip.map_or_else(|| "?".into(), |i| i.to_string()),
                routes
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            let full_tunnel = routes
                .iter()
                .any(|r| *r == crate::net::Ipv4Net::ALL || crate::net::Ipv4Net::HALVES.contains(r));
            if let Some(ip) = ip {
                send(Event::Backend(BackendEvent::TunnelUp {
                    ifname,
                    ip,
                    routes,
                    full_tunnel,
                }));
            }
        }
        Err(e) => log(format!(
            "warning: the tunnel's address and routes can't be shown: {e}"
        )),
    }
    send(Event::Backend(BackendEvent::Connected));
    let reason = session.wait(cancel, &log);
    log(format!("disconnecting: {reason}"));
    send(Event::Backend(BackendEvent::Disconnecting));
    drop(session);
    log("disconnected".into());
    send(Event::Backend(BackendEvent::Disconnected));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GW: &str = "azuregateway-0000aaaa-1111-2222-3333-444455556666-0a1b2c3d4e5f.vpn.azure.com";

    fn xml(auth: &str, transport: &str, secret: &str) -> String {
        format!(
            r#"<AzVpnProfile xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.datacontract.org/2004/07/">
  <any xmlns:d2p1="http://schemas.datacontract.org/2004/07/System.Xml" i:nil="true" />
  <clientauth>
    <aad>
      <audience>c632b3df-fb67-4d84-bdcf-b95ad541b5c8</audience>
      <issuer>https://sts.windows.net/99999999-8888-7777-6666-555555555555/</issuer>
      <tenant>https://login.microsoftonline.com/99999999-8888-7777-6666-555555555555/</tenant>
    </aad>
    <cert i:nil="true" />
    <type>{auth}</type>
  </clientauth>
  <name>office-vnet</name>
  <protocolconfig><sslprotocolConfig><transportprotocol>{transport}</transportprotocol></sslprotocolConfig></protocolconfig>
  <serverlist><ServerEntry><displayname i:nil="true" /><fqdn>{GW}</fqdn></ServerEntry></serverlist>
  <servervalidation>
    <Cert><hash>DF3C24F9BFD666761B268073FE06D1CC8D4F82A4</hash><issuer i:nil="true" /></Cert>
    <serversecret>{secret}</serversecret>
    <type>cert</type>
  </servervalidation>
  <version>1</version>
</AzVpnProfile>"#
        )
    }

    fn secret() -> String {
        "0123456789ABCDEF".repeat(32)
    }

    #[test]
    fn a_profile_from_the_azure_portal_imports() {
        let p = import(&xml("aad", "tcp", &secret())).unwrap();
        let Vpn::Azure(az) = p.vpn.clone() else {
            panic!("an Azure connection")
        };
        assert_eq!(p.name.as_str(), "office-vnet");
        assert_eq!(p.psk, secret());
        assert_eq!(az.gateway.to_string(), GW);
        assert_eq!(
            az.tenant.to_string(),
            "https://login.microsoftonline.com/99999999-8888-7777-6666-555555555555/"
        );
        assert_eq!(
            az.audience.to_string(),
            "c632b3df-fb67-4d84-bdcf-b95ad541b5c8"
        );
        assert_eq!(
            az.root.to_string(),
            "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4"
        );
        // what Save writes: the Azure settings, never the server secret
        let file = crate::config::sparse(&p);
        assert!(
            file.starts_with("type = \"azure-openvpn\"\n") && !file.contains("0123456789"),
            "{file}"
        );
        let back = crate::config::parse_profile(&file).unwrap();
        assert_eq!(back.vpn, p.vpn);
    }

    /// A zip as the Azure portal writes it: Windows paths, the profile next to the generic files.
    fn portal_zip(profile: &str) -> Vec<u8> {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, text) in [
            ("Generic\\VpnSettings.xml", "<VpnProfile/>"),
            ("AzureVPN\\azurevpnconfig.xml", profile),
        ] {
            w.start_file(name, opts).unwrap();
            w.write_all(text.as_bytes()).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn the_zip_from_the_azure_portal_imports_and_so_does_its_xml() {
        let x = xml("aad", "tcp", &secret());
        let from_zip = import_file(&portal_zip(&x)).unwrap();
        let from_xml = import_file(x.as_bytes()).unwrap();
        assert_eq!(
            (from_zip.vpn.clone(), from_zip.psk.clone()),
            (from_xml.vpn, from_xml.psk)
        );
        assert_eq!(from_zip.name.as_str(), "office-vnet");
        let refused = |bytes: &[u8], why: &str| {
            let e = import_file(bytes).unwrap_err();
            assert!(
                e.starts_with("error: this file can't be imported as an Azure VPN profile\n")
                    && e.contains(why),
                "{e}"
            );
        };
        // a gateway without OpenVPN + Entra: the portal's zip has only the generic files
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        w.start_file(
            "Generic\\VpnSettings.xml",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        refused(
            &w.finish().unwrap().into_inner(),
            "no AzureVPN/azurevpnconfig.xml",
        );
        refused(b"PK\x03\x04 broken", "isn't a valid zip file");
        refused(&[0xff, 0xfe, 0x00], "neither a zip file nor XML text");
    }

    #[test]
    fn entities_and_cdata_are_read_in_full() {
        let x = xml("aad", "tcp", &secret()).replace(
            "<name>office-vnet</name>",
            "<name>R&amp;D &#38; <![CDATA[lab]]> net</name>",
        );
        assert_eq!(import(&x).unwrap().name.as_str(), "R&D & lab net");
        let x = xml("aad", "tcp", &secret())
            .replace("<name>office-vnet</name>", "<name>a&nope;</name>");
        assert!(import(&x).unwrap_err().contains("unknown entity &nope;"));
    }

    #[test]
    fn other_profiles_are_refused_saying_why() {
        let refused = |x: &str, why: &str| {
            let e = import(x).unwrap_err();
            assert!(
                e.starts_with("error: this file can't be imported as an Azure VPN profile\n")
                    && e.contains(why),
                "{e}"
            );
        };
        refused(
            &xml("cert", "tcp", &secret()),
            "Microsoft Entra ID sign-in only",
        );
        refused(&xml("aad", "udp", &secret()), "OpenVPN over TCP only");
        refused(&xml("aad", "tcp", "abc"), "512 hexadecimal digits");
        refused(
            &xml("aad", "tcp", &secret()).replace(GW, "vpn.example.com"),
            "The gateway is invalid",
        );
        refused("<html>", "It has no sign-in type.");
        refused("not xml <<", "It isn't valid XML");
    }

    #[test]
    fn the_config_checks_the_vnet_name_and_holds_no_credentials() {
        let p = import(&xml("aad", "tcp", &secret())).unwrap();
        let Vpn::Azure(az) = &p.vpn else {
            panic!("an Azure connection")
        };
        let c = ovpn(az, &p.psk, "CA").unwrap();
        let c = c.expose();
        for line in [
            &format!("remote {GW} 443"),
            "proto tcp-client",
            "verify-x509-name 0000aaaa-1111-2222-3333-444455556666.vpn.azure.com name",
            "remote-cert-tls server",
            "key-direction 1",
            "\nping-restart 0\n",
            "\nauth-user-pass\n",
            "<ca>\nCA\n</ca>",
            "-----BEGIN OpenVPN Static key V1-----\n0123456789abcdef0123456789abcdef\n",
        ] {
            assert!(c.contains(line), "{line:?} in\n{c}");
        }
        assert_eq!(c.matches("0123456789abcdef0123456789abcdef\n").count(), 16);
    }

    #[test]
    fn a_pinned_root_that_is_not_trusted_is_refused() {
        let e = root_ca("0000000000000000000000000000000000000000".parse().unwrap()).unwrap_err();
        assert!(
            e.contains("0000000000000000000000000000000000000000"),
            "{e}"
        );
    }
}
