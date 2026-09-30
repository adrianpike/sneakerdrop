//! Identities, addresses, and the hash/signature conventions of spec §3–§4.

use std::fmt;

use curve25519_dalek::edwards::CompressedEdwardsY;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

use crate::codec::hex;

pub const CTX_ID: &str = "sneakerdrop v1 record id";
pub const CTX_SEAL: &str = "sneakerdrop v1 seal key";
pub const CTX_BURN: &str = "sneakerdrop v1 burn";
pub const CTX_ADDR: &str = "sneakerdrop v1 address checksum";
pub const CTX_BUNDLE: &str = "sneakerdrop v1 bundle checksum";
pub const CTX_SUMMARY: &str = "sneakerdrop v1 summary";

pub const TAG_BROADCAST: &[u8] = b"sneakerdrop v1 broadcast";
pub const TAG_SEALED: &[u8] = b"sneakerdrop v1 sealed";

pub const ADDRESS_PREFIX: &str = "sd1";

/// `H(ctx, m)`: BLAKE3 in key-derivation mode, over the concatenation of `parts`.
pub fn derive(ctx: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(ctx);
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// `H64(ctx, m)`: the first 64 bytes of the extendable output of `H`.
pub fn derive64(ctx: &str, parts: &[&[u8]]) -> [u8; 64] {
    let mut h = blake3::Hasher::new_derive_key(ctx);
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 64];
    h.finalize_xof().fill(&mut out);
    out
}

/// `burn_hash = H(CTX_BURN, burn_secret)`.
pub fn burn_hash(secret: &[u8; 32]) -> [u8; 32] {
    derive(CTX_BURN, &[secret])
}

/// Returns true if `bytes` is the canonical encoding of an Edwards point that
/// is not of small order (spec §3.1).
fn is_canonical_strong_point(bytes: &[u8; 32]) -> bool {
    match CompressedEdwardsY(*bytes).decompress() {
        Some(p) => p.compress().to_bytes() == *bytes && !p.is_small_order(),
        None => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KeyError {
    #[error("not a canonical, prime-order Ed25519 public key")]
    InvalidPoint,
    #[error("address must start with \"{ADDRESS_PREFIX}\"")]
    BadPrefix,
    #[error("address is not valid base32")]
    BadEncoding,
    #[error("address has the wrong length")]
    BadLength,
    #[error("address checksum mismatch")]
    BadChecksum,
}

/// An identity public key (spec §4). Always a valid, canonical, prime-order point.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, KeyError> {
        if is_canonical_strong_point(&bytes) {
            Ok(Self(bytes))
        } else {
            Err(KeyError::InvalidPoint)
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.0).expect("validated at construction")
    }

    /// The X25519 (Montgomery `u`) form of this key.
    pub fn to_x25519(&self) -> [u8; 32] {
        self.verifying_key().to_montgomery().to_bytes()
    }

    /// Strict Ed25519 verification of `sig` over `tag ‖ 0x00 ‖ parts…` (spec §3.1).
    pub fn verify(&self, tag: &[u8], parts: &[&[u8]], sig: &[u8; 64]) -> bool {
        let r: [u8; 32] = sig[..32].try_into().expect("64-byte signature");
        if !is_canonical_strong_point(&r) {
            return false;
        }
        let msg = signed_message(tag, parts);
        self.verifying_key()
            .verify_strict(&msg, &Signature::from_bytes(sig))
            .is_ok()
    }

    pub fn to_address(&self) -> String {
        let check = derive(CTX_ADDR, &[&self.0]);
        let mut raw = self.0.to_vec();
        raw.extend_from_slice(&check[..3]);
        format!(
            "{ADDRESS_PREFIX}{}",
            BASE32_NOPAD.encode(&raw).to_lowercase()
        )
    }

    pub fn from_address(addr: &str) -> Result<Self, KeyError> {
        let addr = addr.trim();
        if addr.len() < ADDRESS_PREFIX.len()
            || !addr[..ADDRESS_PREFIX.len()].eq_ignore_ascii_case(ADDRESS_PREFIX)
        {
            return Err(KeyError::BadPrefix);
        }
        let body = addr[ADDRESS_PREFIX.len()..].to_ascii_uppercase();
        let raw = BASE32_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| KeyError::BadEncoding)?;
        if raw.len() != 35 {
            return Err(KeyError::BadLength);
        }
        let pk: [u8; 32] = raw[..32].try_into().expect("length checked");
        if derive(CTX_ADDR, &[&pk])[..3] != raw[32..] {
            return Err(KeyError::BadChecksum);
        }
        Self::from_bytes(pk)
    }

    /// First 8 hex digits, for compact display.
    pub fn short(&self) -> String {
        hex(&self.0[..4])
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.short())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_address())
    }
}

fn signed_message(tag: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let len = tag.len() + 1 + parts.iter().map(|p| p.len()).sum::<usize>();
    let mut msg = Vec::with_capacity(len);
    msg.extend_from_slice(tag);
    msg.push(0);
    for p in parts {
        msg.extend_from_slice(p);
    }
    msg
}

/// An identity key pair (spec §4).
#[derive(Clone)]
pub struct Identity {
    signing: SigningKey,
    public: PublicKey,
}

impl Identity {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        // Ed25519 public keys derived from a seed are always canonical and prime-order.
        let public = PublicKey::from_bytes(signing.verifying_key().to_bytes())
            .expect("derived public keys are valid");
        Self { signing, public }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public(&self) -> PublicKey {
        self.public
    }

    pub(crate) fn sign(&self, tag: &[u8], parts: &[&[u8]]) -> [u8; 64] {
        self.signing.sign(&signed_message(tag, parts)).to_bytes()
    }

    /// The X25519 private scalar, as described in spec §4.
    pub(crate) fn x25519_secret(&self) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from(self.signing.to_scalar_bytes())
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({})", self.public.short())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_roundtrip() {
        let id = Identity::from_seed([7; 32]);
        let addr = id.public().to_address();
        assert_eq!(addr.len(), 59);
        assert!(addr.starts_with("sd1"));
        assert_eq!(PublicKey::from_address(&addr), Ok(id.public()));
        assert_eq!(
            PublicKey::from_address(&addr.to_uppercase()),
            Ok(id.public())
        );
    }

    #[test]
    fn address_detects_typos() {
        let addr = Identity::from_seed([7; 32]).public().to_address();
        let mut chars: Vec<char> = addr.chars().collect();
        chars[10] = if chars[10] == 'a' { 'b' } else { 'a' };
        let typo: String = chars.into_iter().collect();
        assert!(PublicKey::from_address(&typo).is_err());
    }

    #[test]
    fn rejects_small_order_and_non_canonical_keys() {
        // The identity point (y = 1) has small order.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(PublicKey::from_bytes(identity), Err(KeyError::InvalidPoint));
        // y = p + 1 (non-canonical encoding of the identity point).
        let mut non_canonical = [0xffu8; 32];
        non_canonical[0] = 0xee;
        non_canonical[31] = 0x7f;
        assert_eq!(
            PublicKey::from_bytes(non_canonical),
            Err(KeyError::InvalidPoint)
        );
    }

    #[test]
    fn signatures_are_domain_separated() {
        let id = Identity::from_seed([9; 32]);
        let sig = id.sign(TAG_BROADCAST, &[b"hello"]);
        assert!(id.public().verify(TAG_BROADCAST, &[b"hel", b"lo"], &sig));
        assert!(!id.public().verify(TAG_SEALED, &[b"hello"], &sig));
        assert!(!id.public().verify(TAG_BROADCAST, &[b"hellO"], &sig));
    }

    #[test]
    fn x25519_matches_birational_map() {
        let id = Identity::from_seed([3; 32]);
        let derived = x25519_dalek::PublicKey::from(&id.x25519_secret());
        assert_eq!(derived.to_bytes(), id.public().to_x25519());
    }
}
