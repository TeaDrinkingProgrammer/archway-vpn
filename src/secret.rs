//! At-rest obfuscation of secrets in config.json with a key compiled into the binary.
//!
//! NOTE: this is obfuscation, not real protection - anyone with the config file AND this binary (or its source)
//! can decrypt. It keeps the PSK out of plain sight (casual viewing, grep, scanners). The file itself is 0600.
//!
//! Format: "enc:v1:" + hex( IV(16) | AES-256-CBC(PKCS#7) | HMAC-SHA256(tag over "v1"|IV|CT) )

use crate::crypto::{aes_cbc_decrypt, aes_cbc_encrypt, random, HashAlg};

const PREFIX: &str = "enc:v1:";
/// Hardcoded master key material; encryption and MAC keys are derived from it.
const MASTER: &[u8; 32] = b"fortisaml-gui/psk-at-rest/v1\x5a\x17\xc3\x9e";

fn keys() -> (Vec<u8>, Vec<u8>) {
    (HashAlg::Sha256.hmac(MASTER, b"enc"), HashAlg::Sha256.hmac(MASTER, b"mac"))
}

pub fn seal(plain: &str) -> String {
    if plain.is_empty() {
        return String::new();
    }
    let (ek, mk) = keys();
    let iv = random(16);
    let mut data = plain.as_bytes().to_vec();
    let pad = 16 - data.len() % 16;
    data.extend(std::iter::repeat_n(pad as u8, pad));
    let ct = aes_cbc_encrypt(&ek, &iv, &data);
    let tag = HashAlg::Sha256.hmac_parts(&mk, &[b"v1", &iv, &ct]);
    let blob = [iv, ct, tag].concat();
    format!("{PREFIX}{}", blob.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Decrypt a sealed value ("" stays "").
pub fn open(stored: &str) -> Result<String, String> {
    if stored.is_empty() {
        return Ok(String::new());
    }
    let hex = stored.strip_prefix(PREFIX).ok_or("encrypted secret: missing enc:v1: prefix")?;
    let blob: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16))
        .collect::<Result<_, _>>()
        .map_err(|_| "encrypted secret: bad hex")?;
    if blob.len() < 16 + 16 + 32 || (blob.len() - 48) % 16 != 0 {
        return Err("encrypted secret: bad length".into());
    }
    let (iv, rest) = blob.split_at(16);
    let (ct, tag) = rest.split_at(rest.len() - 32);
    let (ek, mk) = keys();
    let exp = HashAlg::Sha256.hmac_parts(&mk, &[b"v1", iv, ct]);
    // constant-time compare
    if exp.iter().zip(tag).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0 {
        return Err("encrypted secret: integrity check failed (corrupted or different key)".into());
    }
    let mut p = aes_cbc_decrypt(&ek, iv, ct)?;
    let pad = *p.last().ok_or("encrypted secret: empty")? as usize;
    if pad == 0 || pad > 16 || pad > p.len() {
        return Err("encrypted secret: bad padding".into());
    }
    p.truncate(p.len() - pad);
    String::from_utf8(p).map_err(|_| "encrypted secret: not UTF-8".into())
}

/// serde adapter: `#[serde(with = "crate::secret::sealed")]` - plaintext in memory, sealed on disk.
pub mod sealed {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &str, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::seal(v))
    }
    /// Lenient: an undecryptable value becomes empty (re-enter it) instead of failing the whole config load,
    /// which would otherwise reset all profiles to defaults.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
        let s = String::deserialize(d)?;
        Ok(super::open(&s).unwrap_or_else(|e| {
            eprintln!("config: {e}; the field was cleared");
            String::new()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_tamper() {
        for pw in ["x", "exactly16bytes!!", "a much longer pre-shared key with ünïcödé"] {
            let s = seal(pw);
            assert!(s.starts_with(PREFIX) && !s.contains(pw));
            assert_eq!(open(&s).unwrap(), pw);
            assert_ne!(seal(pw), s, "random IV");
        }
        assert!(open("plain-text").is_err());
        assert_eq!(open("").unwrap(), "");
        assert_eq!(seal(""), "");
        let mut t = seal("secret").into_bytes();
        let n = t.len() - 70;
        t[n] = if t[n] == b'0' { b'1' } else { b'0' };
        assert!(open(&String::from_utf8(t).unwrap()).is_err());
    }
}
