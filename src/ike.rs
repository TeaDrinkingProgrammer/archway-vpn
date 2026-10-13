//! Minimal IKEv2 initiator (RFC 7296) as used by FortiClient for dial-up IPsec with SAML:
//! Fortinet vendor IDs, EAP (identity = FortiClient UID, secret = SAML tokenid), gateway PSK auth,
//! forced NAT-T (UDP 4500) so the kernel can use ESP-in-UDP on the same socket.

use crate::crypto::{self, aes_cbc_decrypt, aes_cbc_encrypt, mschapv2, prf_plus, random, DhKey, HashAlg};
use std::net::{Ipv4Addr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::time::Duration;

pub const IKE_SA_INIT: u8 = 34;
pub const IKE_AUTH: u8 = 35;
pub const INFORMATIONAL: u8 = 37;
const PL_SA: u8 = 33;
const PL_KE: u8 = 34;
const PL_IDI: u8 = 35;
const PL_IDR: u8 = 36;
const PL_AUTH: u8 = 39;
const PL_NONCE: u8 = 40;
const PL_N: u8 = 41;
const PL_D: u8 = 42;
const PL_V: u8 = 43;
const PL_TSI: u8 = 44;
const PL_TSR: u8 = 45;
const PL_SK: u8 = 46;
const PL_CP: u8 = 47;
const PL_EAP: u8 = 48;
const F_INIT: u8 = 0x08;
const F_RESP: u8 = 0x20;
const T_ENCR: u8 = 1;
const T_PRF: u8 = 2;
const T_INTEG: u8 = 3;
const T_DH: u8 = 4;
const T_ESN: u8 = 5;
const ENCR_AES_CBC: u16 = 12;
const N_COOKIE: u16 = 16390;
const N_INVALID_KE: u16 = 17;
const N_NATD_SRC: u16 = 16388;
const N_NATD_DST: u16 = 16389;
const N_INITIAL_CONTACT: u16 = 16384;
const N_FRAG_SUPPORTED: u16 = 16430;

/// Fortinet vendor IDs (ipsec.exe table @0x1400f0610): MD5 of these strings.
const FORTI_VIDS: [&[u8]; 3] = [b"forticlient connect license", b"Fortinet Endpoint Control", b"Forticlient EAP Extension"];

fn notify_name(t: u16) -> &'static str {
    match t {
        7 => "INVALID_SYNTAX",
        14 => "NO_PROPOSAL_CHOSEN",
        17 => "INVALID_KE_PAYLOAD",
        24 => "AUTHENTICATION_FAILED",
        35 => "NO_ADDITIONAL_SAS",
        36 => "INTERNAL_ADDRESS_FAILURE",
        37 => "FAILED_CP_REQUIRED",
        38 => "TS_UNACCEPTABLE",
        16001 => "FORTINET_EMS_SN_CHECK_FAILED",
        _ => "",
    }
}

/// (AES key bits, IKEv2 integrity transform id)
pub type Prop = (u16, u16);

pub fn parse_proposals(spec: &str) -> Result<Vec<Prop>, String> {
    let mut v = Vec::new();
    for item in spec.split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()) {
        let (e, h) = item.split_once('-').ok_or(format!("bad proposal {item}"))?;
        let bits = match e {
            "aes128" => 128,
            "aes192" => 192,
            "aes256" => 256,
            _ => return Err(format!("bad encryption in {item}")),
        };
        let integ = match h {
            "sha1" => 2,
            "sha256" => 12,
            "sha384" => 13,
            "sha512" => 14,
            _ => return Err(format!("bad hash in {item}")),
        };
        v.push((bits, integ));
    }
    if v.is_empty() {
        return Err("empty proposal list".into());
    }
    Ok(v)
}

/// integrity id -> (hash, key length, ICV length)
fn integ_alg(id: u16) -> Result<(HashAlg, usize, usize), String> {
    Ok(match id {
        2 => (HashAlg::Sha1, 20, 12),
        12 => (HashAlg::Sha256, 32, 16),
        13 => (HashAlg::Sha384, 48, 24),
        14 => (HashAlg::Sha512, 64, 32),
        x => return Err(format!("unsupported integrity transform {x}")),
    })
}
fn prf_for_integ(id: u16) -> u16 {
    match id {
        2 => 2,
        12 => 5,
        13 => 6,
        _ => 7,
    }
}
fn prf_alg(id: u16) -> Result<HashAlg, String> {
    Ok(match id {
        2 => HashAlg::Sha1,
        5 => HashAlg::Sha256,
        6 => HashAlg::Sha384,
        7 => HashAlg::Sha512,
        x => return Err(format!("unsupported PRF {x}")),
    })
}
/// kernel names for `ip xfrm`: (auth algo, truncation bits)
pub fn xfrm_auth(id: u16) -> (&'static str, u32) {
    match id {
        2 => ("hmac(sha1)", 96),
        12 => ("hmac(sha256)", 128),
        13 => ("hmac(sha384)", 192),
        _ => ("hmac(sha512)", 256),
    }
}

// ───────────────────────────── encoding helpers ─────────────────────────────
type Payloads = Vec<(u8, Vec<u8>)>;

fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}
fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}
fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn encode_chain(p: &[(u8, Vec<u8>)]) -> (u8, Vec<u8>) {
    let mut out = Vec::new();
    for (i, (_, body)) in p.iter().enumerate() {
        let nxt = p.get(i + 1).map_or(0, |x| x.0);
        out.push(nxt);
        out.push(0);
        out.extend(be16((4 + body.len()) as u16));
        out.extend(body);
    }
    (p.first().map_or(0, |x| x.0), out)
}

fn parse_chain(first: u8, data: &[u8]) -> Result<(Payloads, u8), String> {
    let (mut res, mut t, mut off) = (Vec::new(), first, 0usize);
    while t != 0 && off + 4 <= data.len() {
        let nxt = data[off];
        let ln = rd16(data, off + 2) as usize;
        if ln < 4 || off + ln > data.len() {
            return Err("malformed payload length".into());
        }
        res.push((t, data[off + 4..off + ln].to_vec()));
        if t == PL_SK {
            return Ok((res, nxt)); // SK's "next payload" = first inner payload
        }
        t = nxt;
        off += ln;
    }
    Ok((res, 0))
}

fn transform(ttype: u8, id: u16, keylen: Option<u16>, last: bool) -> Vec<u8> {
    let attrs: Vec<u8> = keylen.map_or(vec![], |k| [be16(0x800e), be16(k)].concat());
    let mut v = vec![if last { 0 } else { 3 }, 0];
    v.extend(be16(8 + attrs.len() as u16));
    v.extend([ttype, 0]);
    v.extend(be16(id));
    v.extend(attrs);
    v
}

fn proposal(num: u8, proto: u8, spi: &[u8], trs: &[(u8, u16, Option<u16>)], last: bool) -> Vec<u8> {
    let body: Vec<u8> = trs.iter().enumerate().flat_map(|(i, t)| transform(t.0, t.1, t.2, i == trs.len() - 1)).collect();
    let mut v = vec![if last { 0 } else { 2 }, 0];
    v.extend(be16((8 + spi.len() + body.len()) as u16));
    v.extend([num, proto, spi.len() as u8, trs.len() as u8]);
    v.extend(spi);
    v.extend(body);
    v
}

/// One proposal per enc/integ pair (FortiClient style); IKE proposals carry the matching PRF and all DH groups.
fn sa_payload(proto: u8, spi: &[u8], pairs: &[Prop], groups: &[u16]) -> Vec<u8> {
    let mut body = Vec::new();
    for (i, (bits, integ)) in pairs.iter().enumerate() {
        let mut trs = vec![(T_ENCR, ENCR_AES_CBC, Some(*bits))];
        if proto == 1 {
            trs.push((T_PRF, prf_for_integ(*integ), None));
        }
        trs.push((T_INTEG, *integ, None));
        if proto == 1 {
            trs.extend(groups.iter().map(|g| (T_DH, *g, None)));
        } else {
            trs.push((T_ESN, 0, None));
        }
        body.extend(proposal(i as u8 + 1, proto, spi, &trs, i == pairs.len() - 1));
    }
    body
}

struct ChosenProp {
    spi: Vec<u8>,
    encr_bits: u16,
    prf: Option<u16>,
    integ: u16,
}

fn parse_sa(body: &[u8]) -> Result<ChosenProp, String> {
    if body.len() < 8 {
        return Err("short SA payload".into());
    }
    let (spisz, ntr) = (body[6] as usize, body[7] as usize);
    let spi = body[8..8 + spisz].to_vec();
    let mut off = 8 + spisz;
    let (mut encr, mut prf, mut integ) = (None, None, None);
    for _ in 0..ntr {
        let tlen = rd16(body, off + 2) as usize;
        let (ttype, tid) = (body[off + 4], rd16(body, off + 6));
        let mut keylen = None;
        let mut a = off + 8;
        while a + 4 <= off + tlen {
            let (at, av) = (rd16(body, a), rd16(body, a + 2));
            if at & 0x7fff == 14 {
                keylen = Some(av);
            }
            a += if at & 0x8000 != 0 { 4 } else { 4 + av as usize };
        }
        match ttype {
            T_ENCR => encr = encr.or(keylen),
            T_PRF => prf = prf.or(Some(tid)),
            T_INTEG => integ = integ.or(Some(tid)),
            _ => {}
        }
        off += tlen;
    }
    Ok(ChosenProp {
        spi,
        encr_bits: encr.ok_or("no ENCR key length in chosen proposal")?,
        prf,
        integ: integ.ok_or("no INTEG in chosen proposal")?,
    })
}

fn ts_any() -> Vec<u8> {
    let mut v = vec![1, 0, 0, 0, 7, 0];
    v.extend(be16(16));
    v.extend(be16(0));
    v.extend(be16(65535));
    v.extend([0, 0, 0, 0, 255, 255, 255, 255]);
    v
}

pub type Ts = (Ipv4Addr, Ipv4Addr);
fn parse_ts(body: &[u8]) -> Vec<Ts> {
    let mut out = vec![];
    let (n, mut off) = (body.first().copied().unwrap_or(0), 4usize);
    for _ in 0..n {
        if off + 16 > body.len() {
            break;
        }
        let ln = rd16(body, off + 2) as usize;
        if body[off] == 7 {
            let a = Ipv4Addr::new(body[off + 8], body[off + 9], body[off + 10], body[off + 11]);
            let b = Ipv4Addr::new(body[off + 12], body[off + 13], body[off + 14], body[off + 15]);
            out.push((a, b));
        }
        off += ln.max(8);
    }
    out
}

fn cp_request(uid: &str) -> Vec<u8> {
    let mut attrs: Vec<(u16, Vec<u8>)> = vec![(7, format!("FCT800{uid}").into_bytes())]; // APPLICATION_VERSION
    for t in [1u16, 2, 3, 4, 0x7004, 13, 25, 0x7001, 0x540a, 0x540b, 0x7000, 0x7006] {
        attrs.push((t, vec![]));
    }
    let mut v = vec![1, 0, 0, 0]; // CFG_REQUEST
    for (t, val) in attrs {
        v.extend(be16(t));
        v.extend(be16(val.len() as u16));
        v.extend(val);
    }
    v
}

fn ip4(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

pub fn mask_to_prefix(m: Ipv4Addr) -> u32 {
    u32::from(m).leading_ones()
}

/// Smallest CIDR list covering [a, b].
pub fn range_to_cidrs(a: Ipv4Addr, b: Ipv4Addr) -> Vec<String> {
    let (mut s, e) = (u32::from(a) as u64, u32::from(b) as u64);
    let mut out = vec![];
    while s <= e {
        let mut size = if s == 0 { 32 } else { (s.trailing_zeros()).min(32) };
        while size > 0 && s + (1u64 << size) - 1 > e {
            size -= 1;
        }
        out.push(format!("{}/{}", Ipv4Addr::from(s as u32), 32 - size));
        s += 1u64 << size;
    }
    out
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct NetCfg {
    pub ip: Option<Ipv4Addr>,
    pub mask: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub subnets: Vec<String>,
    pub domain: Option<String>,
    pub banner: Option<String>,
}

fn parse_cp(body: &[u8]) -> NetCfg {
    let mut c = NetCfg::default();
    let mut off = 4;
    while off + 4 <= body.len() {
        let (t, ln) = (rd16(body, off) & 0x7fff, rd16(body, off + 2) as usize);
        let v = &body[off + 4..(off + 4 + ln).min(body.len())];
        match t {
            1 if v.len() >= 4 => c.ip = Some(ip4(v)),
            2 if v.len() == 4 => c.mask = Some(ip4(v)),
            3 if v.len() == 4 => c.dns.push(ip4(v)),
            13 if v.len() == 8 => c.subnets.push(format!("{}/{}", ip4(v), mask_to_prefix(ip4(&v[4..])))),
            0x7004 => {
                for o in (0..v.len().saturating_sub(13)).step_by(14) {
                    c.subnets.push(format!("{}/{}", ip4(&v[o..]), mask_to_prefix(ip4(&v[o + 4..]))));
                }
            }
            25 | 0x7002 if !v.is_empty() => c.domain = Some(String::from_utf8_lossy(v).into()),
            0x7000 if !v.is_empty() => c.banner = Some(String::from_utf8_lossy(v).into()),
            _ => {}
        }
        off += 4 + ln;
    }
    c
}

pub struct ChildSa {
    pub spi_out: Vec<u8>,
    pub spi_in: Vec<u8>,
    pub enc_i: Vec<u8>,
    pub auth_i: Vec<u8>,
    pub enc_r: Vec<u8>,
    pub auth_r: Vec<u8>,
    pub integ: u16,
    #[allow(dead_code)]
    pub tsi: Vec<Ts>,
    pub tsr: Vec<Ts>,
    pub cfg: NetCfg,
}

// ───────────────────────────── the IKE SA ─────────────────────────────
pub struct IkeParams {
    pub gateway: String,
    pub port: u16,
    pub psk: Option<String>,
    /// FortiClient UID (sent in the CP APPLICATION_VERSION attribute)
    pub uid: String,
    /// EAP identity: the UID for SAML SSO, the username for username/password login.
    /// None = no EAP: the client authenticates with the PSK directly (AUTH in the first IKE_AUTH).
    pub eap_identity: Option<String>,
    /// EAP secret: SAML tokenid or the user's password
    pub token: String,
    pub local_id: Option<String>,
    pub groups: Vec<u16>,
    pub ike_props: Vec<Prop>,
    pub esp_props: Vec<Prop>,
    pub fake_nat: bool,
}

pub struct Ike {
    p: IkeParams,
    pub gw: Ipv4Addr,
    pub sock: UdpSocket,
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub spi_i: [u8; 8],
    spi_r: [u8; 8],
    msgid: u32,
    natt: bool,
    child_spi_i: Vec<u8>,
    msk: Option<Vec<u8>>,
    ni: Vec<u8>,
    nr: Vec<u8>,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    idr: Vec<u8>,
    prf: HashAlg,
    integ: (HashAlg, usize, usize),
    sk_d: Vec<u8>,
    sk_ai: Vec<u8>,
    sk_ar: Vec<u8>,
    sk_ei: Vec<u8>,
    sk_er: Vec<u8>,
    sk_pi: Vec<u8>,
    sk_pr: Vec<u8>,
    ms: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>, // (auth challenge, peer challenge, NT-response)
    log: Box<dyn Fn(String) + Send>,
    dbg: Box<dyn Fn(String) + Send>,
}

impl Ike {
    pub fn new(p: IkeParams, log: Box<dyn Fn(String) + Send>, dbg: Box<dyn Fn(String) + Send>) -> Result<Ike, String> {
        let gw = (p.gateway.as_str(), p.port)
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve {}: {e}", p.gateway))?
            .find_map(|a| match a {
                std::net::SocketAddr::V4(v) => Some(*v.ip()),
                _ => None,
            })
            .ok_or(format!("{} has no IPv4 address", p.gateway))?;
        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        sock.connect(SocketAddrV4::new(gw, p.port)).map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let (local_ip, local_port) = match sock.local_addr().map_err(|e| e.to_string())? {
            std::net::SocketAddr::V4(a) => (*a.ip(), a.port()),
            _ => return Err("unexpected IPv6 local address".into()),
        };
        let mut spi_i = [0u8; 8];
        spi_i.copy_from_slice(&random(8));
        Ok(Ike {
            p,
            gw,
            sock,
            local_ip,
            local_port,
            spi_i,
            spi_r: [0; 8],
            msgid: 0,
            natt: false,
            child_spi_i: random(4),
            msk: None,
            ni: vec![],
            nr: vec![],
            msg1: vec![],
            msg2: vec![],
            idr: vec![],
            prf: HashAlg::Sha256,
            integ: (HashAlg::Sha256, 32, 16),
            sk_d: vec![],
            sk_ai: vec![],
            sk_ar: vec![],
            sk_ei: vec![],
            sk_er: vec![],
            sk_pi: vec![],
            sk_pr: vec![],
            ms: None,
            log,
            dbg,
        })
    }

    // ---------------- transport ----------------
    fn send_raw(&self, data: &[u8]) -> Result<(), String> {
        let r = if self.natt { self.sock.send(&[&[0u8; 4][..], data].concat()) } else { self.sock.send(data) };
        r.map(|_| ()).map_err(|e| format!("send: {e}"))
    }

    /// Next IKE message for our SA (strips the non-ESP marker). Err on timeout.
    pub fn recv_msg(&self) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        loop {
            let n = self.sock.recv(&mut buf)?;
            let mut d = &buf[..n];
            if self.natt {
                if d == [0xff] || d.len() < 4 || d[..4] != [0, 0, 0, 0] {
                    continue; // keepalive / ESP (ESP is consumed by the kernel once UDP_ENCAP is set)
                }
                d = &d[4..];
            }
            if d.len() >= 28 && d[..8] == self.spi_i {
                return Ok(d.to_vec());
            }
        }
    }

    fn exchange(&mut self, xtype: u8, pls: &[(u8, Vec<u8>)], encrypt: bool) -> Result<(Vec<u8>, Payloads), String> {
        let mid = self.msgid;
        let pkt = self.build(xtype, pls, mid, F_INIT, encrypt);
        for attempt in 0..4 {
            self.send_raw(&pkt)?;
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                match self.recv_msg() {
                    Ok(resp) => {
                        let (flags, rmid) = (resp[19], rd32(&resp, 20));
                        if flags & F_RESP != 0 && rmid == mid {
                            self.msgid += 1;
                            let parsed = self.parse(&resp)?;
                            return Ok((resp, parsed));
                        }
                        if flags & F_RESP == 0 && encrypt {
                            let _ = self.handle_peer_request(&resp);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => break,
                    Err(e) => return Err(format!("recv: {e}")),
                }
            }
            (self.dbg)(format!("retransmit msgid {mid} (attempt {})", attempt + 1));
        }
        Err(format!("no response from gateway to exchange {xtype} (msgid {mid})"))
    }

    fn build(&self, xtype: u8, pls: &[(u8, Vec<u8>)], mid: u32, flags: u8, encrypt: bool) -> Vec<u8> {
        let hdr = |np: u8, total: usize| {
            let mut h = Vec::with_capacity(28);
            h.extend(self.spi_i);
            h.extend(self.spi_r);
            h.extend([np, 0x20, xtype, flags]);
            h.extend(mid.to_be_bytes());
            h.extend((total as u32).to_be_bytes());
            h
        };
        let (first, inner) = encode_chain(pls);
        if !encrypt {
            let mut m = hdr(first, 28 + inner.len());
            m.extend(inner);
            return m;
        }
        let padlen = (16 - (inner.len() + 1) % 16) % 16;
        let mut plain = inner;
        plain.extend(vec![0u8; padlen]);
        plain.push(padlen as u8);
        let iv = random(16);
        let ct = [iv.clone(), aes_cbc_encrypt(&self.sk_ei, &iv, &plain)].concat();
        let icv = self.integ.2;
        let sk_len = 4 + ct.len() + icv;
        let mut m = hdr(PL_SK, 28 + sk_len);
        m.extend([first, 0]);
        m.extend(be16(sk_len as u16));
        m.extend(ct);
        let mac = self.integ.0.hmac(&self.sk_ai, &m);
        m.extend(&mac[..icv]);
        m
    }

    fn parse(&self, msg: &[u8]) -> Result<Payloads, String> {
        let len = (rd32(msg, 24) as usize).min(msg.len());
        let (mut pls, sk_next) = parse_chain(msg[16], &msg[28..len])?;
        if let Some((PL_SK, body)) = pls.last().cloned() {
            let icv = self.integ.2;
            if body.len() < 16 + icv {
                return Err("short SK payload".into());
            }
            let mac = self.integ.0.hmac(&self.sk_ar, &msg[..len - icv]);
            if mac[..icv] != msg[len - icv..len] {
                return Err("integrity check failed on received message".into());
            }
            let (iv, ct) = (&body[..16], &body[16..body.len() - icv]);
            let mut plain = aes_cbc_decrypt(&self.sk_er, iv, ct)?;
            let pad = *plain.last().ok_or("empty SK")? as usize + 1;
            plain.truncate(plain.len().saturating_sub(pad));
            let (inner, _) = parse_chain(sk_next, &plain)?;
            pls.pop();
            pls.extend(inner);
        }
        Ok(pls)
    }

    fn notifies(pls: &Payloads) -> Vec<(u16, Vec<u8>)> {
        pls.iter()
            .filter(|(t, b)| *t == PL_N && b.len() >= 4)
            .map(|(_, b)| (rd16(b, 2), b[4 + b[1] as usize..].to_vec()))
            .collect()
    }

    fn check_errors(pls: &Payloads, where_: &str) -> Result<(), String> {
        for (t, d) in Self::notifies(pls) {
            if t < 16384 {
                return Err(format!("{where_}: gateway sent error notify {t} {} {}", notify_name(t), hex(&d)));
            }
        }
        Ok(())
    }

    /// Answer a peer-initiated INFORMATIONAL (DPD / delete). Returns true if the peer deleted the SA.
    pub fn handle_peer_request(&self, msg: &[u8]) -> Result<bool, String> {
        let pls = self.parse(msg)?;
        let (xtype, mid) = (msg[18], rd32(msg, 20));
        let deleted = pls.iter().any(|(t, _)| *t == PL_D);
        if xtype == INFORMATIONAL {
            self.send_raw(&self.build(INFORMATIONAL, &[], mid, F_RESP, true))?;
            (self.dbg)(format!("answered gateway INFORMATIONAL {mid}{}", if deleted { " (delete)" } else { " (DPD)" }));
        }
        Ok(deleted)
    }

    // ---------------- IKE_SA_INIT ----------------
    fn nat_hash(&self, ip: Ipv4Addr, port: u16, fake: bool) -> Vec<u8> {
        let addr = if fake { random(4) } else { ip.octets().to_vec() };
        crypto::sha1(&[&self.spi_i[..], &self.spi_r, &addr, &be16(port)].concat())
    }

    pub fn sa_init(&mut self) -> Result<(), String> {
        let mut cookie: Option<Vec<u8>> = None;
        let (raw, rpls, dh, pls) = loop {
            let dh = DhKey::new(self.p.groups[0])?;
            self.ni = random(32);
            let mut pls: Payloads = vec![];
            let notify = |t: u16, d: &[u8]| (PL_N, [&[0u8, 0][..], &be16(t), d].concat());
            if let Some(c) = &cookie {
                pls.push(notify(N_COOKIE, c));
            }
            pls.push((PL_SA, sa_payload(1, &[], &self.p.ike_props, &self.p.groups)));
            pls.push((PL_KE, [&be16(dh.group())[..], &[0, 0], &dh.public()].concat()));
            pls.push((PL_NONCE, self.ni.clone()));
            for v in FORTI_VIDS {
                pls.push((PL_V, crypto::md5(v)));
            }
            pls.push(notify(N_NATD_SRC, &self.nat_hash(self.local_ip, self.local_port, self.p.fake_nat)));
            pls.push(notify(N_NATD_DST, &self.nat_hash(self.gw, self.p.port, false)));
            pls.push(notify(N_FRAG_SUPPORTED, &[]));
            self.msgid = 0;
            let (raw, rpls) = self.exchange(IKE_SA_INIT, &pls, false)?;
            let nots = Self::notifies(&rpls);
            if let Some((_, c)) = nots.iter().find(|(t, _)| *t == N_COOKIE) {
                (self.log)("IKE_SA_INIT: gateway sent COOKIE, retrying".into());
                cookie = Some(c.clone());
                continue;
            }
            if let Some((_, d)) = nots.iter().find(|(t, _)| *t == N_INVALID_KE) {
                let g = rd16(d, 0);
                (self.log)(format!("IKE_SA_INIT: gateway wants DH group {g}"));
                if !self.p.groups.contains(&g) {
                    return Err(format!("gateway requires DH group {g}, which is not enabled"));
                }
                self.p.groups.retain(|x| *x != g);
                self.p.groups.insert(0, g);
                continue;
            }
            Self::check_errors(&rpls, "IKE_SA_INIT")?;
            break (raw, rpls, dh, pls);
        };
        self.msg1 = self.build(IKE_SA_INIT, &pls, 0, F_INIT, false);
        self.msg2 = raw.clone();
        self.spi_r.copy_from_slice(&raw[8..16]);
        let get = |t: u8| rpls.iter().find(|(x, _)| *x == t).map(|(_, b)| b.clone()).ok_or(format!("IKE_SA_INIT response lacks payload {t}"));
        let prop = parse_sa(&get(PL_SA)?)?;
        let ke = get(PL_KE)?;
        self.nr = get(PL_NONCE)?;
        self.prf = prf_alg(prop.prf.ok_or("no PRF chosen")?)?;
        self.integ = integ_alg(prop.integ)?;
        let shared = dh.shared(&ke[4..])?;
        (self.log)(format!(
            "IKE_SA_INIT ok: AES-CBC-{} {:?} DH {} SPIr={}",
            prop.encr_bits,
            self.integ.0,
            rd16(&ke, 0),
            hex(&self.spi_r)
        ));
        let skeyseed = self.prf.hmac(&[&self.ni[..], &self.nr].concat(), &shared);
        let (hl, il, el) = (self.prf.len(), self.integ.1, prop.encr_bits as usize / 8);
        let seed = [&self.ni[..], &self.nr, &self.spi_i, &self.spi_r].concat();
        let km = prf_plus(self.prf, &skeyseed, &seed, 3 * hl + 2 * il + 2 * el);
        let mut o = 0;
        let mut take = |n: usize| {
            let v = km[o..o + n].to_vec();
            o += n;
            v
        };
        self.sk_d = take(hl);
        self.sk_ai = take(il);
        self.sk_ar = take(il);
        self.sk_ei = take(el);
        self.sk_er = take(el);
        self.sk_pi = take(hl);
        self.sk_pr = take(hl);
        // float to NAT-T port 4500 (local port unchanged; NAT was faked so the gateway uses UDP encapsulation)
        self.natt = true;
        self.sock.connect(SocketAddrV4::new(self.gw, 4500)).map_err(|e| e.to_string())?;
        Ok(())
    }

    // ---------------- IKE_AUTH + EAP ----------------
    fn idi_body(&self) -> Vec<u8> {
        match self.p.local_id.as_deref().filter(|s| !s.is_empty()) {
            Some(id) => match id.parse::<Ipv4Addr>() {
                Ok(ip) => [&[1u8, 0, 0, 0][..], &ip.octets()].concat(),
                Err(_) => [&[2u8, 0, 0, 0][..], id.as_bytes()].concat(), // ID_FQDN
            },
            None => [&[1u8, 0, 0, 0][..], &self.local_ip.octets()].concat(), // FortiClient default: own IP
        }
    }

    fn peer_auth_octets(&self, key: &[u8]) -> Vec<u8> {
        let k = self.prf.hmac(key, b"Key Pad for IKEv2");
        self.prf.hmac(&k, &[&self.msg2[..], &self.ni, &self.prf.hmac(&self.sk_pr, &self.idr)].concat())
    }

    /// Returns Some(response) to send, or None on EAP-Success.
    fn eap_response(&mut self, req: &[u8]) -> Result<Option<Vec<u8>>, String> {
        if req.len() < 4 {
            return Err("short EAP packet".into());
        }
        let (code, ident) = (req[0], req[1]);
        let ln = (rd16(req, 2) as usize).min(req.len());
        match code {
            3 => return Ok(None),
            4 => return Err("EAP failure: credentials rejected (wrong password, or SSO token expired/used/UID mismatch)".into()),
            1 => {}
            c => return Err(format!("unexpected EAP code {c}")),
        }
        let etype = req.get(4).copied().unwrap_or(0);
        let data = &req[5.min(ln)..ln];
        let mk = |t: u8, d: &[u8]| [&[2u8, ident][..], &be16(5 + d.len() as u16), &[t], d].concat();
        let (uid, token) = (self.p.eap_identity.clone().unwrap_or_default(), self.p.token.clone());
        Ok(Some(match etype {
            1 => {
                (self.log)(format!("EAP identity -> {uid}"));
                mk(1, uid.as_bytes())
            }
            6 => {
                (self.log)("EAP-GTC -> secret".into());
                mk(6, token.as_bytes())
            }
            4 => {
                let vs = data[0] as usize;
                (self.log)("EAP-MD5 -> secret".into());
                let r = crypto::md5(&[&[ident][..], token.as_bytes(), &data[1..1 + vs]].concat());
                mk(4, &[&[16u8][..], &r].concat())
            }
            26 => match data.first() {
                Some(1) => {
                    let (ms_id, vs) = (data[1], data[4] as usize);
                    let auth = data[5..5 + vs].to_vec();
                    let peer = random(16);
                    let nt = mschapv2::nt_response(&auth, &peer, &uid, &token);
                    let val = [&peer[..], &[0u8; 8], &nt, &[0u8]].concat();
                    let body = [&[2u8, ms_id][..], &be16((5 + val.len() + uid.len()) as u16), &[49u8], &val, uid.as_bytes()].concat();
                    self.ms = Some((auth, peer, nt));
                    (self.log)("EAP-MSCHAPv2 challenge -> response".into());
                    mk(26, &body)
                }
                Some(3) => {
                    let (auth, peer, nt) = self.ms.clone().ok_or("MSCHAPv2 success without challenge")?;
                    let msg = String::from_utf8_lossy(&data[4..]);
                    let exp = mschapv2::authenticator_response(&token, &nt, &peer, &auth, &uid);
                    if !msg.contains(&exp) {
                        return Err("MSCHAPv2: invalid authenticator response from gateway".into());
                    }
                    self.msk = Some(mschapv2::msk(&token, &nt));
                    (self.log)("EAP-MSCHAPv2 success, MSK derived".into());
                    mk(26, &[3])
                }
                Some(4) => return Err(format!("MSCHAPv2 failure: {}", String::from_utf8_lossy(&data[4..]))),
                _ => return Err("malformed MSCHAPv2 packet".into()),
            },
            2 => {
                (self.log)(format!("EAP notification: {}", String::from_utf8_lossy(data)));
                mk(2, &[])
            }
            t => {
                (self.log)(format!("EAP type {t} not supported -> NAK (offer GTC, MSCHAPv2, MD5)"));
                mk(3, &[6, 26, 4])
            }
        }))
    }

    fn own_auth(&self, idi: &[u8], key: &[u8]) -> Vec<u8> {
        let k = self.prf.hmac(key, b"Key Pad for IKEv2");
        let a = self.prf.hmac(&k, &[&self.msg1[..], &self.nr, &self.prf.hmac(&self.sk_pi, idi)].concat());
        [&[2u8, 0, 0, 0][..], &a].concat() // method 2: shared key MIC
    }

    pub fn auth(&mut self) -> Result<ChildSa, String> {
        let idi = self.idi_body();
        let use_eap = self.p.eap_identity.is_some();
        let mut pls: Payloads = vec![(PL_IDI, idi.clone())];
        if !use_eap {
            let psk = self.p.psk.clone().ok_or("no pre-shared key")?;
            pls.push((PL_AUTH, self.own_auth(&idi, psk.as_bytes())));
        }
        pls.extend([
            (PL_N, [&[0u8, 0][..], &be16(N_INITIAL_CONTACT)].concat()),
            (PL_CP, cp_request(&self.p.uid)),
            (PL_SA, sa_payload(3, &self.child_spi_i, &self.p.esp_props, &[])),
            (PL_TSI, ts_any()),
            (PL_TSR, ts_any()),
        ]);
        let (_, rpls) = self.exchange(IKE_AUTH, &pls, true)?;
        Self::check_errors(&rpls, "IKE_AUTH")?;
        // gateway authentication (PSK) in the first IKE_AUTH response
        let find = |p: &Payloads, t: u8| p.iter().find(|(x, _)| *x == t).map(|(_, b)| b.clone());
        if let (Some(idr), Some(a)) = (find(&rpls, PL_IDR), find(&rpls, PL_AUTH)) {
            self.idr = idr;
            match (a[0], &self.p.psk) {
                (2, Some(psk)) => {
                    if self.peer_auth_octets(psk.as_bytes()) != a[4..] {
                        return Err("gateway PSK authentication FAILED (wrong pre-shared key?)".into());
                    }
                    (self.log)("gateway authenticated with PSK (verified)".into());
                }
                (m, _) => (self.log)(format!("WARNING: gateway AUTH method {m} not verified by this client")),
            }
        } else {
            (self.log)("WARNING: gateway sent no AUTH in the first IKE_AUTH response".into());
        }
        let rpls = if use_eap { self.eap_and_final_auth(&idi, &rpls)? } else { rpls };
        self.child_sa(&rpls)
    }

    fn eap_and_final_auth(&mut self, idi: &[u8], rpls: &Payloads) -> Result<Payloads, String> {
        let find = |p: &Payloads, t: u8| p.iter().find(|(x, _)| *x == t).map(|(_, b)| b.clone());
        let mut req = find(rpls, PL_EAP).ok_or("gateway did not start EAP (is EAP/SAML enabled on the phase1?)")?;
        while let Some(resp) = self.eap_response(&req)? {
            let (_, r) = self.exchange(IKE_AUTH, &[(PL_EAP, resp)], true)?;
            Self::check_errors(&r, "IKE_AUTH/EAP")?;
            req = find(&r, PL_EAP).ok_or("EAP ended without EAP-Success")?;
        }
        if req.len() >= 6 && req[4] == 6 {
            (self.dbg)(format!("Fortinet EAP-Success extension flags {}", hex(&req[5..])));
        }
        let key = self.msk.clone().unwrap_or_else(|| self.sk_pi.clone());
        let auth = self.own_auth(idi, &key);
        let (_, rpls) = self.exchange(IKE_AUTH, &[(PL_AUTH, auth)], true)?;
        Self::check_errors(&rpls, "IKE_AUTH/final")?;
        if let (Some(a), Some(msk)) = (find(&rpls, PL_AUTH), &self.msk) {
            if self.peer_auth_octets(msk) == a[4..] {
                (self.log)("gateway final AUTH (MSK) verified".into());
            } else {
                return Err("gateway final AUTH (MSK) did not verify".into());
            }
        }
        Ok(rpls)
    }

    fn child_sa(&self, rpls: &Payloads) -> Result<ChildSa, String> {
        let find = |p: &Payloads, t: u8| p.iter().find(|(x, _)| *x == t).map(|(_, b)| b.clone());
        // child SA
        let sa = find(&rpls, PL_SA).ok_or("no child SA in final IKE_AUTH (NO_PROPOSAL_CHOSEN / TS_UNACCEPTABLE?)")?;
        let prop = parse_sa(&sa)?;
        let (ek, ik) = (prop.encr_bits as usize / 8, integ_alg(prop.integ)?.1);
        let km = prf_plus(self.prf, &self.sk_d, &[&self.ni[..], &self.nr].concat(), 2 * (ek + ik));
        Ok(ChildSa {
            spi_out: prop.spi,
            spi_in: self.child_spi_i.clone(),
            enc_i: km[..ek].to_vec(),
            auth_i: km[ek..ek + ik].to_vec(),
            enc_r: km[ek + ik..2 * ek + ik].to_vec(),
            auth_r: km[2 * ek + ik..].to_vec(),
            integ: prop.integ,
            tsi: find(&rpls, PL_TSI).map(|b| parse_ts(&b)).unwrap_or_default(),
            tsr: find(&rpls, PL_TSR).map(|b| parse_ts(&b)).unwrap_or_default(),
            cfg: find(&rpls, PL_CP).map(|b| parse_cp(&b)).unwrap_or_default(),
        })
    }

    pub fn send_keepalive(&self) {
        let _ = self.sock.send(&[0xff]);
    }

    pub fn delete(&mut self) {
        self.sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let _ = self.exchange(INFORMATIONAL, &[(PL_D, vec![1, 0, 0, 0])], true);
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cidrs() {
        assert_eq!(range_to_cidrs("0.0.0.0".parse().unwrap(), "255.255.255.255".parse().unwrap()), vec!["0.0.0.0/0"]);
        assert_eq!(range_to_cidrs("10.0.0.0".parse().unwrap(), "10.0.255.255".parse().unwrap()), vec!["10.0.0.0/16"]);
    }
    #[test]
    fn proposals() {
        assert_eq!(parse_proposals("aes128-sha1, AES256-SHA256").unwrap(), vec![(128, 2), (256, 12)]);
        assert!(parse_proposals("des-md5").is_err());
    }
}
