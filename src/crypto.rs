//! Crypto primitives for the IKEv2 initiator (RustCrypto, pure Rust).

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use md4::Md4;
use md5::Md5;
use num_bigint::BigUint;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

pub fn random(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::fill(&mut v).expect("getrandom");
    v
}

// ───────────────────────────── hashes / PRF ─────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

macro_rules! hmac_with {
    ($d:ty, $k:expr, $parts:expr) => {{
        let mut m = <Hmac<$d> as KeyInit>::new_from_slice($k).expect("hmac key");
        for p in $parts {
            m.update(p);
        }
        m.finalize().into_bytes().to_vec()
    }};
}

impl HashAlg {
    pub fn len(self) -> usize {
        match self {
            HashAlg::Sha1 => 20,
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }
    pub fn hmac_parts(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        match self {
            HashAlg::Sha1 => hmac_with!(Sha1, key, parts),
            HashAlg::Sha256 => hmac_with!(Sha256, key, parts),
            HashAlg::Sha384 => hmac_with!(Sha384, key, parts),
            HashAlg::Sha512 => hmac_with!(Sha512, key, parts),
        }
    }
    pub fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        self.hmac_parts(key, &[data])
    }
}

/// IKEv2 prf+ (RFC 7296 2.13)
pub fn prf_plus(h: HashAlg, key: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + h.len());
    let mut t: Vec<u8> = Vec::new();
    let mut i = 1u8;
    while out.len() < len {
        t = h.hmac_parts(key, &[&t, seed, &[i]]);
        out.extend_from_slice(&t);
        i = i.wrapping_add(1);
    }
    out.truncate(len);
    out
}

pub fn sha1(data: &[u8]) -> Vec<u8> {
    Sha1::digest(data).to_vec()
}
pub fn md5(data: &[u8]) -> Vec<u8> {
    Md5::digest(data).to_vec()
}
pub fn md4(data: &[u8]) -> Vec<u8> {
    Md4::digest(data).to_vec()
}

// ───────────────────────────── AES-CBC ─────────────────────────────
enum Aes {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl Aes {
    fn new(key: &[u8]) -> Aes {
        match key.len() {
            16 => Aes::A128(aes::Aes128::new_from_slice(key).unwrap()),
            24 => Aes::A192(aes::Aes192::new_from_slice(key).unwrap()),
            32 => Aes::A256(aes::Aes256::new_from_slice(key).unwrap()),
            n => panic!("bad AES key length {n}"),
        }
    }
    fn enc(&self, b: &mut [u8]) {
        let blk = b.try_into().unwrap();
        match self {
            Aes::A128(c) => c.encrypt_block(blk),
            Aes::A192(c) => c.encrypt_block(blk),
            Aes::A256(c) => c.encrypt_block(blk),
        }
    }
    fn dec(&self, b: &mut [u8]) {
        let blk = b.try_into().unwrap();
        match self {
            Aes::A128(c) => c.decrypt_block(blk),
            Aes::A192(c) => c.decrypt_block(blk),
            Aes::A256(c) => c.decrypt_block(blk),
        }
    }
}

/// AES-CBC without padding (caller pads to 16 bytes, IKEv2 style).
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    assert!(data.len() % 16 == 0);
    let c = Aes::new(key);
    let mut prev = iv.to_vec();
    let mut out = data.to_vec();
    for chunk in out.chunks_mut(16) {
        for (a, b) in chunk.iter_mut().zip(&prev) {
            *a ^= b;
        }
        c.enc(chunk);
        prev.copy_from_slice(chunk);
    }
    out
}

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() % 16 != 0 {
        return Err("ciphertext not a multiple of the block size".into());
    }
    let c = Aes::new(key);
    let mut prev = iv.to_vec();
    let mut out = data.to_vec();
    for chunk in out.chunks_mut(16) {
        let ct = chunk.to_vec();
        c.dec(chunk);
        for (a, b) in chunk.iter_mut().zip(&prev) {
            *a ^= b;
        }
        prev = ct;
    }
    Ok(out)
}

// ───────────────────────────── Diffie-Hellman ─────────────────────────────
const MODP2048_P: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
15728E5A8AACAA68FFFFFFFFFFFFFFFF";

pub enum DhKey {
    Modp2048(BigUint),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
}

/// Random EC private scalar (retry until it is a valid non-zero scalar < n).
macro_rules! ec_key {
    ($c:ident, $len:expr) => {{
        loop {
            let mut b = random($len);
            if $len == 66 {
                b[0] &= 0x01; // P-521 scalars are 521 bits
            }
            if let Ok(k) = $c::SecretKey::from_slice(&b) {
                break k;
            }
        }
    }};
}

fn ec_pub_xy(sec1: &[u8]) -> Vec<u8> {
    sec1[1..].to_vec() // strip 0x04 (uncompressed point) -> RFC 5903 x|y
}

impl DhKey {
    pub fn new(group: u16) -> Result<DhKey, String> {
        Ok(match group {
            14 => {
                let mut x = random(256);
                x[0] &= 0x7f;
                DhKey::Modp2048(BigUint::from_bytes_be(&x))
            }
            19 => DhKey::P256(ec_key!(p256, 32)),
            20 => DhKey::P384(ec_key!(p384, 48)),
            21 => DhKey::P521(ec_key!(p521, 66)),
            g => return Err(format!("DH group {g} not supported")),
        })
    }

    pub fn group(&self) -> u16 {
        match self {
            DhKey::Modp2048(_) => 14,
            DhKey::P256(_) => 19,
            DhKey::P384(_) => 20,
            DhKey::P521(_) => 21,
        }
    }

    pub fn public(&self) -> Vec<u8> {
        match self {
            DhKey::Modp2048(x) => {
                let p = BigUint::parse_bytes(MODP2048_P.as_bytes(), 16).unwrap();
                let y = BigUint::from(2u32).modpow(x, &p).to_bytes_be();
                let mut out = vec![0u8; 256 - y.len()];
                out.extend(y);
                out
            }
            DhKey::P256(k) => ec_pub_xy(&k.public_key().to_sec1_bytes()),
            DhKey::P384(k) => ec_pub_xy(&k.public_key().to_sec1_bytes()),
            DhKey::P521(k) => ec_pub_xy(&k.public_key().to_sec1_bytes()),
        }
    }

    pub fn shared(&self, peer: &[u8]) -> Result<Vec<u8>, String> {
        let pt = |b: &[u8]| {
            let mut v = vec![4u8];
            v.extend_from_slice(b);
            v
        };
        Ok(match self {
            DhKey::Modp2048(x) => {
                let p = BigUint::parse_bytes(MODP2048_P.as_bytes(), 16).unwrap();
                let y = BigUint::from_bytes_be(peer);
                let one = BigUint::from(1u32);
                if y <= one || y >= &p - &one {
                    return Err("invalid MODP public value".into());
                }
                let z = y.modpow(x, &p).to_bytes_be();
                let mut out = vec![0u8; 256 - z.len()];
                out.extend(z);
                out
            }
            DhKey::P256(k) => {
                let pk = p256::PublicKey::from_sec1_bytes(&pt(peer)).map_err(|_| "invalid P-256 point")?;
                k.diffie_hellman(&pk).raw_secret_bytes().to_vec()
            }
            DhKey::P384(k) => {
                let pk = p384::PublicKey::from_sec1_bytes(&pt(peer)).map_err(|_| "invalid P-384 point")?;
                k.diffie_hellman(&pk).raw_secret_bytes().to_vec()
            }
            DhKey::P521(k) => {
                let pk = p521::PublicKey::from_sec1_bytes(&pt(peer)).map_err(|_| "invalid P-521 point")?;
                k.diffie_hellman(&pk).raw_secret_bytes().to_vec()
            }
        })
    }
}

// ───────────────────────────── MSCHAPv2 (RFC 2759 / 3079) ─────────────────────────────
fn des_key(k7: &[u8]) -> [u8; 8] {
    let mut k = [0u8; 8];
    let v = k7.iter().fold(0u64, |a, b| (a << 8) | *b as u64);
    for (i, out) in k.iter_mut().enumerate() {
        *out = (((v >> (49 - 7 * i)) & 0x7f) << 1) as u8;
    }
    k
}

fn des_encrypt(k7: &[u8], data: &[u8]) -> Vec<u8> {
    let c = des::Des::new_from_slice(&des_key(k7)).unwrap();
    let mut b = [0u8; 8];
    b.copy_from_slice(data);
    c.encrypt_block((&mut b).into());
    b.to_vec()
}

pub mod mschapv2 {
    use super::*;
    const M1: &[u8] = b"This is the MPPE Master Key";
    const M2: &[u8] = b"On the client side, this is the send key; on the server side, it is the receive key.";
    const M3: &[u8] = b"On the client side, this is the receive key; on the server side, it is the send key.";

    pub fn nt_hash(pw: &str) -> Vec<u8> {
        let u: Vec<u8> = pw.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        md4(&u)
    }
    fn challenge_hash(peer: &[u8], auth: &[u8], user: &str) -> Vec<u8> {
        sha1(&[peer, auth, user.as_bytes()].concat())[..8].to_vec()
    }
    pub fn nt_response(auth: &[u8], peer: &[u8], user: &str, pw: &str) -> Vec<u8> {
        let ch = challenge_hash(peer, auth, user);
        let mut h = nt_hash(pw);
        h.extend([0u8; 5]);
        [des_encrypt(&h[0..7], &ch), des_encrypt(&h[7..14], &ch), des_encrypt(&h[14..21], &ch)].concat()
    }
    pub fn authenticator_response(pw: &str, nt: &[u8], peer: &[u8], auth: &[u8], user: &str) -> String {
        let hh = md4(&nt_hash(pw));
        let d = sha1(&[&hh[..], nt, b"Magic server to client signing constant"].concat());
        let ch = challenge_hash(peer, auth, user);
        let r = sha1(&[&d[..], &ch, b"Pad to make it do more than one iteration"].concat());
        format!("S={}", r.iter().map(|b| format!("{b:02X}")).collect::<String>())
    }
    /// Peer MSK layout (wpa_supplicant / strongSwan): peer Send-Key | peer Recv-Key | 32 zero bytes.
    pub fn msk(pw: &str, nt: &[u8]) -> Vec<u8> {
        let hh = md4(&nt_hash(pw));
        let mk = sha1(&[&hh[..], nt, M1].concat())[..16].to_vec();
        let ask = |m: &[u8]| sha1(&[&mk[..], &[0u8; 40], m, &[0xf2u8; 40]].concat())[..16].to_vec();
        [ask(M2), ask(M3), vec![0u8; 32]].concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02X}")).collect()
    }
    fn un(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    #[test]
    fn md4_rfc1320() {
        assert_eq!(hx(&md4(b"abc")), "A448017AAF21D8525FC10AE87AA6729D");
        assert_eq!(hx(&md4(b"")), "31D6CFE0D16AE931B73C59D7E0C089C0");
    }
    #[test]
    fn mschapv2_rfc2759_3079() {
        let (user, pw) = ("User", "clientPass");
        let auth = un("5B5D7C7D7B3F2F3E3C2C602132262628");
        let peer = un("21402324255E262A28295F2B3A337C7E");
        assert_eq!(hx(&mschapv2::nt_hash(pw)), "44EBBA8D5312B8D611474411F56989AE");
        let nt = mschapv2::nt_response(&auth, &peer, user, pw);
        assert_eq!(hx(&nt), "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF");
        assert_eq!(mschapv2::authenticator_response(pw, &nt, &peer, &auth, user), "S=407A5589115FD0D6209F510FE9C04566932CDA56");
        assert_eq!(hx(&mschapv2::msk(pw, &nt)[16..32]), "8B7CDC149B993A1BA118CB153F56DCCB");
    }
    #[test]
    fn aes_cbc_nist_sp800_38a() {
        // F.2.1 CBC-AES128.Encrypt, block 1
        let k = un("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = un("000102030405060708090a0b0c0d0e0f");
        let pt = un("6bc1bee22e409f96e93d7e117393172a");
        let ct = aes_cbc_encrypt(&k, &iv, &pt);
        assert_eq!(hx(&ct), "7649ABAC8119B246CEE98E9B12E9197D");
        assert_eq!(aes_cbc_decrypt(&k, &iv, &ct).unwrap(), pt);
    }
    #[test]
    fn hmac_rfc4231_case2() {
        let h = HashAlg::Sha256.hmac(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(hx(&h), "5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843");
    }
    #[test]
    fn dh_agreement() {
        for g in [14u16, 19, 20, 21] {
            let (a, b) = (DhKey::new(g).unwrap(), DhKey::new(g).unwrap());
            assert_eq!(a.shared(&b.public()).unwrap(), b.shared(&a.public()).unwrap(), "group {g}");
        }
    }
}
