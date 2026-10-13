//! Kernel data plane: XFRM states/policies bound to an xfrm interface (if_id), UDP-encapsulated ESP on the
//! IKE socket, routes (tagged with protocol RT_PROTO so they can always be found again) and DNS via
//! systemd-resolved. Configuration is applied with iproute2 / resolvectl.

use crate::ike::{xfrm_auth, ChildSa, Ike};
use std::os::fd::AsRawFd;
use std::process::Command;

pub const RT_PROTO: u32 = 233;
pub const IF_ID: u32 = 0x5a17;

pub struct TunnelOpts {
    pub ifname: String,
    pub mtu: u16,
    /// None = use what the gateway pushes; Some(list) = override (0.0.0.0/0 = full tunnel)
    pub routes: Option<Vec<String>>,
    pub block_ipv6: bool,
    pub set_dns: bool,
}

pub struct Tunnel {
    cleanup: Vec<String>,
    pub routes: Vec<String>,
    pub full: bool,
}

fn redact(cmd: &str) -> String {
    // never log ESP keys
    let mut out = Vec::new();
    let mut hide = false;
    for w in cmd.split(' ') {
        if hide && w.starts_with("0x") {
            out.push("0x<redacted>".to_string());
            hide = false;
            continue;
        }
        hide = w == "'cbc(aes)'" || w.starts_with("'hmac(");
        out.push(w.to_string());
    }
    out.join(" ")
}

pub fn sh(cmd: &str, log: &dyn Fn(String)) -> Result<String, String> {
    log(format!("+ {}", redact(cmd)));
    let o = Command::new("sh").arg("-c").arg(cmd).output().map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(format!("{}: {}", redact(cmd), String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into())
}

fn quiet(cmd: &str) -> bool {
    Command::new("sh").arg("-c").arg(cmd).output().map(|o| o.status.success()).unwrap_or(false)
}

fn which(bin: &str) -> bool {
    quiet(&format!("command -v {bin} >/dev/null 2>&1"))
}

pub fn set_udp_encap(ike: &Ike, on: bool) -> Result<(), String> {
    const UDP_ENCAP: libc::c_int = 100;
    const UDP_ENCAP_ESPINUDP: libc::c_int = 2;
    let v: libc::c_int = if on { UDP_ENCAP_ESPINUDP } else { 0 };
    let r = unsafe {
        libc::setsockopt(
            ike.sock.as_raw_fd(),
            libc::IPPROTO_UDP,
            UDP_ENCAP,
            &v as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(format!("setsockopt(UDP_ENCAP): {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Remove leftovers of a previous run that died without cleanup. Returns number of items removed.
pub fn purge_stale(ifname: &str) -> usize {
    let mut n = 0;
    for d in ["out", "in"] {
        n += quiet(&format!("ip xfrm policy delete dir {d} src 0.0.0.0/0 dst 0.0.0.0/0 if_id {IF_ID}")) as usize;
    }
    if let Ok(o) = Command::new("ip").args(["xfrm", "state", "list"]).output() {
        let text = String::from_utf8_lossy(&o.stdout).to_string();
        let mut blocks: Vec<String> = vec![];
        for line in text.lines() {
            if line.starts_with("src ") {
                blocks.push(String::new());
            }
            if let Some(b) = blocks.last_mut() {
                b.push_str(line);
                b.push('\n');
            }
        }
        for b in blocks {
            if !(b.contains(&format!("if_id {:#x}", IF_ID)) || b.contains(&format!("if_id {IF_ID}\n"))) {
                continue;
            }
            let w: Vec<&str> = b.split_whitespace().collect();
            let (src, dst) = (w.get(1), w.get(3));
            let spi = w.iter().position(|x| *x == "spi").and_then(|i| w.get(i + 1));
            if let (Some(s), Some(d), Some(spi)) = (src, dst, spi) {
                n += quiet(&format!("ip xfrm state delete src {s} dst {d} proto esp spi {spi}")) as usize;
            }
        }
    }
    n += quiet(&format!("ip link del {ifname}")) as usize;
    for fam in ["-4", "-6"] {
        if let Ok(o) = Command::new("ip").args([fam, "route", "show", "proto", &RT_PROTO.to_string()]).output() {
            for line in String::from_utf8_lossy(&o.stdout).lines().filter(|l| !l.trim().is_empty()) {
                let r = line.split(" proto ").next().unwrap_or(line);
                n += quiet(&format!("ip {fam} route del {r} proto {RT_PROTO}")) as usize;
            }
        }
    }
    n
}

impl Tunnel {
    pub fn up(ike: &Ike, c: &ChildSa, o: &TunnelOpts, log: &dyn Fn(String)) -> Result<Tunnel, String> {
        let mut t = Tunnel { cleanup: vec![], routes: vec![], full: false };
        match t.install(ike, c, o, log) {
            Ok(()) => Ok(t),
            Err(e) => {
                t.down(log);
                Err(e)
            }
        }
    }

    fn install(&mut self, ike: &Ike, c: &ChildSa, o: &TunnelOpts, log: &dyn Fn(String)) -> Result<(), String> {
        let (l, g, lp) = (ike.local_ip, ike.gw, ike.local_port);
        let (aalg, abits) = xfrm_auth(c.integ);
        let hx = crate::ike::hex;
        set_udp_encap(ike, true)?; // kernel now decapsulates ESP-in-UDP arriving on our IKE socket
        for (src, dst, spi, enc, auth, sp, dp) in [
            (l, g, &c.spi_out, &c.enc_i, &c.auth_i, lp, 4500),
            (g, l, &c.spi_in, &c.enc_r, &c.auth_r, 4500, lp),
        ] {
            sh(
                &format!(
                    "ip xfrm state add src {src} dst {dst} proto esp spi 0x{} reqid 1 mode tunnel \
                     enc 'cbc(aes)' 0x{} auth-trunc '{aalg}' 0x{} {abits} encap espinudp {sp} {dp} 0.0.0.0 if_id {IF_ID}",
                    hx(spi),
                    hx(enc),
                    hx(auth)
                ),
                log,
            )?;
            self.cleanup.push(format!("ip xfrm state delete src {src} dst {dst} proto esp spi 0x{}", hx(spi)));
        }
        for (d, s, t) in [("out", l, g), ("in", g, l)] {
            sh(&format!("ip xfrm policy add dir {d} src 0.0.0.0/0 dst 0.0.0.0/0 if_id {IF_ID} tmpl src {s} dst {t} proto esp reqid 1 mode tunnel"), log)?;
            self.cleanup.push(format!("ip xfrm policy delete dir {d} src 0.0.0.0/0 dst 0.0.0.0/0 if_id {IF_ID}"));
        }
        let ifn = &o.ifname;
        sh(&format!("ip link add {ifn} type xfrm if_id {IF_ID}"), log)?;
        self.cleanup.push(format!("ip link del {ifn}"));
        let vip = c.cfg.ip;
        if let Some(v) = vip {
            sh(&format!("ip addr add {v}/32 dev {ifn}"), log)?;
        }
        sh(&format!("ip link set {ifn} mtu {} up", o.mtu), log)?;

        let mut routes: Vec<String> = match &o.routes {
            Some(r) => r.clone(),
            None => {
                let mut r: Vec<String> = vec![];
                for s in &c.cfg.subnets {
                    if !r.contains(s) {
                        r.push(s.clone());
                    }
                }
                if r.is_empty() {
                    for (a, b) in &c.tsr {
                        r.extend(crate::ike::range_to_cidrs(*a, *b));
                    }
                }
                r
            }
        };
        self.full = routes.iter().any(|r| r == "0.0.0.0/0");
        if self.full {
            // keep the gateway reachable outside the tunnel, then cover 0/0 with two /1 routes
            let via = sh(&format!("ip -4 route get {g}"), log)?;
            let first = via.lines().next().unwrap_or("").replace("cache", "");
            let spec = first.split(" uid ").next().unwrap_or("").trim().to_string();
            sh(&format!("ip route replace {spec} proto {RT_PROTO}"), log)?;
            self.cleanup.insert(0, format!("ip route del {g}/32 proto {RT_PROTO}"));
            routes = vec!["0.0.0.0/1".into(), "128.0.0.0/1".into()];
            if o.block_ipv6 {
                for r6 in ["::/1", "8000::/1"] {
                    let _ = sh(&format!("ip -6 route add unreachable {r6} metric 1 proto {RT_PROTO}"), log);
                    self.cleanup.insert(0, format!("ip -6 route del unreachable {r6} metric 1 proto {RT_PROTO}"));
                }
            }
        }
        let src = vip.map(|v| format!(" src {v}")).unwrap_or_default();
        for r in &routes {
            if let Err(e) = sh(&format!("ip route add {r} dev {ifn} proto {RT_PROTO}{src}"), log) {
                log(format!("WARNING: {e}"));
            }
        }
        self.routes = routes;
        if o.set_dns && !c.cfg.dns.is_empty() {
            if which("resolvectl") {
                let dns: Vec<String> = c.cfg.dns.iter().map(|d| d.to_string()).collect();
                let _ = sh(&format!("resolvectl dns {ifn} {}", dns.join(" ")), log);
                let mut domains: Vec<String> = c.cfg.domain.iter().cloned().collect();
                if self.full {
                    domains.push("~.".into()); // all DNS through the VPN
                    let _ = sh(&format!("resolvectl default-route {ifn} yes"), log);
                }
                if !domains.is_empty() {
                    let _ = sh(&format!("resolvectl domain {ifn} {}", domains.join(" ")), log);
                }
            } else {
                log("WARNING: resolvectl not found; VPN DNS servers not configured".into());
            }
        }
        Ok(())
    }

    /// Undo everything (each step independent; resolved drops per-link DNS with the interface).
    pub fn down(&mut self, log: &dyn Fn(String)) {
        for cmd in self.cleanup.drain(..).rev() {
            if let Err(e) = sh(&cmd, log) {
                log(format!("cleanup: {e}"));
            }
        }
    }
}
