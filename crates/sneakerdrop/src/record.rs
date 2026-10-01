//! Record formats (spec §5): parsing, construction, sealing, and opening.

use std::fmt;
use std::sync::Arc;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

use crate::codec::{DecodeError, Reader, hex, put_varint, varint_len};
use crate::consts::*;
use crate::crypto::{
    CTX_ID, CTX_SEAL, Identity, KeyError, PublicKey, TAG_BROADCAST, TAG_SEALED, burn_hash, derive,
    derive64,
};

pub const VERSION: u8 = 0x01;
pub const KIND_BROADCAST: u8 = 0x01;
pub const KIND_SEALED: u8 = 0x02;
pub const KIND_BURN: u8 = 0x03;
pub const HEADER_LEN: usize = 18;

/// Content types of sealed plaintext (spec §5.4.3).
pub const CTYPE_TEXT: u8 = 0x00;

const SEALED_PREFIX_LEN: usize = HEADER_LEN + 64;
const TAG_LEN: usize = 16;
const MIN_INNER_LEN: usize = 128;
const BURN_RECORD_LEN: usize = HEADER_LEN + 64;

/// A content-derived record identifier (spec §5.2).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordId(pub [u8; 32]);

impl RecordId {
    pub fn of(bytes: &[u8]) -> Self {
        Self(derive(CTX_ID, &[bytes]))
    }

    /// Leading zero bits: the proof-of-work of the record (spec §7.3).
    pub fn work(&self) -> u32 {
        let mut bits = 0;
        for b in self.0 {
            if b == 0 {
                bits += 8;
            } else {
                return bits + b.leading_zeros();
            }
        }
        bits
    }

    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    pub fn short(&self) -> String {
        hex(&self.0[..6])
    }
}

impl fmt::Debug for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecordId({})", self.short())
    }
}

impl fmt::Display for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecordError {
    #[error("record exceeds {MAX_RECORD_SIZE} bytes")]
    TooLarge,
    #[error("record shorter than its header")]
    TooShort,
    #[error("unsupported record version {0}")]
    BadVersion(u8),
    #[error("record kind 0 is invalid")]
    BadKind,
    #[error("malformed record: {0}")]
    Malformed(#[from] DecodeError),
    #[error("invalid author key: {0}")]
    BadAuthor(KeyError),
    #[error("signature does not verify")]
    BadSignature,
    #[error("timestamps violate created < expires <= created + MAX_TTL")]
    BadTimes,
    #[error("sealed ciphertext has an invalid length")]
    BadSealedLength,
    #[error("burn record must be exactly {BURN_RECORD_LEN} bytes")]
    BadBurnLength,
    #[error("content too large for a single record")]
    ContentTooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Broadcast {
    pub author: PublicKey,
    pub created: u64,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub burn_hash: [u8; 32],
    pub eph: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Burn {
    pub target: RecordId,
    pub secret: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Broadcast(Broadcast),
    Sealed(Sealed),
    Burn(Burn),
    /// A reserved kind (spec §5.6), carried opaquely.
    Unknown(u8),
}

/// A structurally valid version 1 record. Constructing one via [`Record::parse`]
/// performs every deterministic check in spec §7.1, including broadcast
/// signature verification.
#[derive(Clone)]
pub struct Record {
    bytes: Arc<[u8]>,
    id: RecordId,
    kind: u8,
    expires: u64,
    stamp: u64,
    body: Body,
}

impl PartialEq for Record {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
impl Eq for Record {}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match &self.body {
            Body::Broadcast(_) => "broadcast".to_string(),
            Body::Sealed(_) => "sealed".to_string(),
            Body::Burn(b) => format!("burn->{}", b.target.short()),
            Body::Unknown(k) => format!("kind{k}"),
        };
        write!(f, "Record({} {kind} exp={})", self.id.short(), self.expires)
    }
}

impl Record {
    pub fn parse(bytes: impl Into<Arc<[u8]>>) -> Result<Self, RecordError> {
        let bytes: Arc<[u8]> = bytes.into();
        if bytes.len() > MAX_RECORD_SIZE {
            return Err(RecordError::TooLarge);
        }
        if bytes.len() < HEADER_LEN {
            return Err(RecordError::TooShort);
        }
        let mut r = Reader::new(&bytes);
        let version = r.u8()?;
        if version != VERSION {
            return Err(RecordError::BadVersion(version));
        }
        let kind = r.u8()?;
        let expires = r.u64()?;
        let stamp = r.u64()?;
        let body = match kind {
            0 => return Err(RecordError::BadKind),
            KIND_BROADCAST => Body::Broadcast(parse_broadcast(&bytes, &mut r, expires)?),
            KIND_SEALED => Body::Sealed(parse_sealed(&mut r)?),
            KIND_BURN => Body::Burn(parse_burn(&bytes, &mut r)?),
            other => Body::Unknown(other),
        };
        Ok(Self {
            id: RecordId::of(&bytes),
            bytes,
            kind,
            expires,
            stamp,
            body,
        })
    }

    pub fn id(&self) -> RecordId {
        self.id
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn shared_bytes(&self) -> Arc<[u8]> {
        self.bytes.clone()
    }
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        false
    }
    pub fn kind(&self) -> u8 {
        self.kind
    }
    pub fn expires(&self) -> u64 {
        self.expires
    }
    pub fn stamp(&self) -> u64 {
        self.stamp
    }
    pub fn body(&self) -> &Body {
        &self.body
    }
    pub fn work(&self) -> u32 {
        self.id.work()
    }

    pub fn as_broadcast(&self) -> Option<&Broadcast> {
        match &self.body {
            Body::Broadcast(b) => Some(b),
            _ => None,
        }
    }
    pub fn as_sealed(&self) -> Option<&Sealed> {
        match &self.body {
            Body::Sealed(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_burn(&self) -> Option<&Burn> {
        match &self.body {
            Body::Burn(b) => Some(b),
            _ => None,
        }
    }

    /// Whether `self` is a burn valid for `target` (spec §5.5).
    pub fn burns(&self, target: &Record) -> bool {
        match (&self.body, &target.body) {
            (Body::Burn(b), Body::Sealed(s)) => {
                b.target == target.id
                    && self.expires == target.expires
                    && blake3::Hash::from(burn_hash(&b.secret)) == blake3::Hash::from(s.burn_hash)
            }
            _ => false,
        }
    }

    /// Creates a signed broadcast (spec §5.3).
    pub fn new_broadcast(
        author: &Identity,
        created: u64,
        expires: u64,
        stamp: u64,
        content: &[u8],
    ) -> Result<Self, RecordError> {
        let mut out = header(KIND_BROADCAST, expires, stamp);
        out.extend_from_slice(author.public().as_bytes());
        out.extend_from_slice(&created.to_be_bytes());
        put_varint(&mut out, content.len() as u64);
        out.extend_from_slice(content);
        if out.len() + 64 > MAX_RECORD_SIZE {
            return Err(RecordError::ContentTooLarge);
        }
        let sig = author.sign(TAG_BROADCAST, &[&out]);
        out.extend_from_slice(&sig);
        Self::parse(out)
    }

    /// Seals `content` to `recipient` (spec §5.4.1), drawing the ephemeral key from `rng`.
    pub fn new_sealed<R: RngCore + CryptoRng>(
        sender: &Identity,
        recipient: &PublicKey,
        opts: &SealOptions,
        content: &[u8],
        rng: &mut R,
    ) -> Result<SealedMessage, RecordError> {
        loop {
            let mut e = [0u8; 32];
            rng.fill_bytes(&mut e);
            // An all-zero shared secret is only possible for a malicious
            // recipient key, which `PublicKey` already excludes; retry anyway.
            if let Some(sealed) =
                Self::new_sealed_with_ephemeral(sender, recipient, opts, content, e)?
            {
                return Ok(sealed);
            }
        }
    }

    /// Deterministic sealing with a caller-supplied ephemeral scalar. Returns
    /// `None` if the shared secret is all zeroes. Exposed for test vectors;
    /// `e` MUST NOT be reused.
    pub fn new_sealed_with_ephemeral(
        sender: &Identity,
        recipient: &PublicKey,
        opts: &SealOptions,
        content: &[u8],
        e: [u8; 32],
    ) -> Result<Option<SealedMessage>, RecordError> {
        let e = x25519_dalek::StaticSecret::from(e);
        let eph = x25519_dalek::PublicKey::from(&e).to_bytes();
        let r_u = recipient.to_x25519();
        let ss = e.diffie_hellman(&x25519_dalek::PublicKey::from(r_u));
        if !ss.was_contributory() {
            return Ok(None);
        }
        let okm = derive64(CTX_SEAL, &[ss.as_bytes(), &eph, &r_u]);
        let key: [u8; 32] = okm[..32].try_into().expect("64-byte okm");
        let burn_secret: [u8; 32] = okm[32..].try_into().expect("64-byte okm");

        let mut ad = header(KIND_SEALED, opts.expires, opts.stamp);
        ad.extend_from_slice(&burn_hash(&burn_secret));
        ad.extend_from_slice(&eph);

        let mut inner = Vec::new();
        inner.extend_from_slice(sender.public().as_bytes());
        inner.extend_from_slice(&opts.created.to_be_bytes());
        inner.push(opts.ctype);
        put_varint(&mut inner, content.len() as u64);
        inner.extend_from_slice(content);
        let sig = sender.sign(TAG_SEALED, &[recipient.as_bytes(), &ad, &inner]);
        inner.extend_from_slice(&sig);
        let padded = inner
            .len()
            .next_multiple_of(PAD_BLOCK)
            .max(MIN_INNER_LEN)
            .max(opts.min_padded_len.next_multiple_of(PAD_BLOCK));
        inner.resize(padded, 0);

        if ad.len() + inner.len() + TAG_LEN > MAX_RECORD_SIZE {
            return Err(RecordError::ContentTooLarge);
        }
        let ct = cipher(&key)
            .encrypt(
                Nonce::from_slice(&[0; 12]),
                Payload {
                    msg: &inner,
                    aad: &ad,
                },
            )
            .expect("ChaCha20-Poly1305 encryption is infallible for in-range lengths");
        let mut out = ad;
        out.extend_from_slice(&ct);
        Ok(Some(SealedMessage {
            record: Self::parse(out)?,
            burn_secret,
        }))
    }

    /// Creates a burn record (spec §5.5).
    pub fn new_burn(target: RecordId, expires: u64, secret: [u8; 32], stamp: u64) -> Self {
        let mut out = header(KIND_BURN, expires, stamp);
        out.extend_from_slice(&target.0);
        out.extend_from_slice(&secret);
        Self::parse(out).expect("burn records are always well-formed")
    }
}

/// Parameters for sealing that are visible on the outside of the record.
#[derive(Debug, Clone)]
pub struct SealOptions {
    pub created: u64,
    pub expires: u64,
    pub stamp: u64,
    /// Content type of the plaintext (spec §5.4.3). Hidden inside the ciphertext.
    pub ctype: u8,
    /// Pad the plaintext to at least this many bytes, to hide the content length.
    pub min_padded_len: usize,
}

impl SealOptions {
    pub fn new(created: u64, expires: u64) -> Self {
        Self {
            created,
            expires,
            stamp: 0,
            ctype: CTYPE_TEXT,
            min_padded_len: 0,
        }
    }
}

/// The output of sealing: the record, plus the burn secret so the sender can
/// later retract the message.
#[derive(Debug, Clone)]
pub struct SealedMessage {
    pub record: Record,
    pub burn_secret: [u8; 32],
}

/// The result of trial-decrypting a record (spec §5.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    NotSealed,
    NotForUs,
    Forged,
    Message(Message),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: RecordId,
    pub sender: PublicKey,
    pub created: u64,
    pub expires: u64,
    pub ctype: u8,
    pub content: Vec<u8>,
    pub burn_secret: [u8; 32],
}

impl Message {
    pub fn burn(&self, stamp: u64) -> Record {
        Record::new_burn(self.id, self.expires, self.burn_secret, stamp)
    }
}

impl Identity {
    /// Trial-decrypts `record` (spec §5.4.2).
    pub fn open(&self, record: &Record) -> Opened {
        let Some(sealed) = record.as_sealed() else {
            return Opened::NotSealed;
        };
        let ss = self
            .x25519_secret()
            .diffie_hellman(&x25519_dalek::PublicKey::from(sealed.eph));
        if !ss.was_contributory() {
            return Opened::NotForUs;
        }
        let r_u = self.public().to_x25519();
        let okm = derive64(CTX_SEAL, &[ss.as_bytes(), &sealed.eph, &r_u]);
        let key: [u8; 32] = okm[..32].try_into().expect("64-byte okm");
        let burn_secret: [u8; 32] = okm[32..].try_into().expect("64-byte okm");
        if blake3::Hash::from(burn_hash(&burn_secret)) != blake3::Hash::from(sealed.burn_hash) {
            return Opened::NotForUs;
        }
        let (ad, ct) = record.bytes().split_at(SEALED_PREFIX_LEN);
        let Ok(inner) =
            cipher(&key).decrypt(Nonce::from_slice(&[0; 12]), Payload { msg: ct, aad: ad })
        else {
            return Opened::NotForUs;
        };
        match parse_inner(&inner, ad, &self.public(), record.expires) {
            Some(Inner {
                sender,
                created,
                ctype,
                content,
            }) => Opened::Message(Message {
                id: record.id,
                sender,
                created,
                expires: record.expires,
                ctype,
                content,
                burn_secret,
            }),
            None => Opened::Forged,
        }
    }
}

struct Inner {
    sender: PublicKey,
    created: u64,
    ctype: u8,
    content: Vec<u8>,
}

fn parse_inner(inner: &[u8], ad: &[u8], recipient: &PublicKey, expires: u64) -> Option<Inner> {
    let mut r = Reader::new(inner);
    let sender = PublicKey::from_bytes(r.array().ok()?).ok()?;
    let created = r.u64().ok()?;
    let ctype = r.u8().ok()?;
    let content = r.len_prefixed().ok()?;
    let signed_len = r.position();
    let sig: [u8; 64] = r.array().ok()?;
    if r.rest().iter().any(|&b| b != 0) {
        return None;
    }
    if !valid_times(created, expires) {
        return None;
    }
    if !sender.verify(
        TAG_SEALED,
        &[recipient.as_bytes(), ad, &inner[..signed_len]],
        &sig,
    ) {
        return None;
    }
    Some(Inner {
        sender,
        created,
        ctype,
        content: content.to_vec(),
    })
}

fn cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(Key::from_slice(key))
}

fn header(kind: u8, expires: u64, stamp: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.push(VERSION);
    out.push(kind);
    out.extend_from_slice(&expires.to_be_bytes());
    out.extend_from_slice(&stamp.to_be_bytes());
    out
}

fn valid_times(created: u64, expires: u64) -> bool {
    created < expires && expires - created <= MAX_TTL
}

fn parse_broadcast(
    bytes: &[u8],
    r: &mut Reader<'_>,
    expires: u64,
) -> Result<Broadcast, RecordError> {
    let author = PublicKey::from_bytes(r.array()?).map_err(RecordError::BadAuthor)?;
    let created = r.u64()?;
    let content = r.len_prefixed()?.to_vec();
    let signed_len = r.position();
    let sig: [u8; 64] = r.array()?;
    r.finish()?;
    if !valid_times(created, expires) {
        return Err(RecordError::BadTimes);
    }
    if !author.verify(TAG_BROADCAST, &[&bytes[..signed_len]], &sig) {
        return Err(RecordError::BadSignature);
    }
    Ok(Broadcast {
        author,
        created,
        content,
    })
}

fn parse_sealed(r: &mut Reader<'_>) -> Result<Sealed, RecordError> {
    let burn_hash = r.array()?;
    let eph = r.array()?;
    let ct_len = r.rest().len();
    if ct_len < TAG_LEN + MIN_INNER_LEN || !(ct_len - TAG_LEN).is_multiple_of(PAD_BLOCK) {
        return Err(RecordError::BadSealedLength);
    }
    Ok(Sealed { burn_hash, eph })
}

fn parse_burn(bytes: &[u8], r: &mut Reader<'_>) -> Result<Burn, RecordError> {
    if bytes.len() != BURN_RECORD_LEN {
        return Err(RecordError::BadBurnLength);
    }
    Ok(Burn {
        target: RecordId(r.array()?),
        secret: r.array()?,
    })
}

/// Largest broadcast content that fits in one record.
pub const MAX_BROADCAST_CONTENT: usize = {
    // header + author + created + varint(len) + content + sig <= MAX_RECORD_SIZE
    MAX_RECORD_SIZE - HEADER_LEN - 32 - 8 - 3 - 64
};

/// Size of the sealed record for `content_len` bytes of content with default padding.
pub fn sealed_record_len(content_len: usize) -> usize {
    let inner = 32 + 8 + 1 + varint_len(content_len as u64) + content_len + 64;
    SEALED_PREFIX_LEN + inner.next_multiple_of(PAD_BLOCK).max(MIN_INNER_LEN) + TAG_LEN
}

/// Grinds `stamp` until `build` produces a record with at least `min_work`
/// bits of work (spec §7.3).
pub fn grind<E>(
    min_work: u32,
    mut build: impl FnMut(u64) -> Result<Record, E>,
) -> Result<Record, E> {
    let mut stamp = 0u64;
    loop {
        let rec = build(stamp)?;
        if rec.work() >= min_work {
            return Ok(rec);
        }
        stamp = stamp.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const T0: u64 = 1_800_000_000;

    fn alice() -> Identity {
        Identity::from_seed([1; 32])
    }
    fn bob() -> Identity {
        Identity::from_seed([2; 32])
    }
    fn carol() -> Identity {
        Identity::from_seed([3; 32])
    }
    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([42; 32])
    }

    #[test]
    fn broadcast_roundtrip() {
        let rec = Record::new_broadcast(&alice(), T0, T0 + 3600, 9, b"hello world").unwrap();
        let parsed = Record::parse(rec.bytes().to_vec()).unwrap();
        assert_eq!(parsed.id(), rec.id());
        assert_eq!(parsed.stamp(), 9);
        let b = parsed.as_broadcast().unwrap();
        assert_eq!(b.author, alice().public());
        assert_eq!(b.content, b"hello world");
    }

    #[test]
    fn broadcast_rejects_any_single_bit_flip() {
        let rec = Record::new_broadcast(&alice(), T0, T0 + 3600, 0, b"integrity").unwrap();
        for i in 0..rec.len() * 8 {
            let mut bytes = rec.bytes().to_vec();
            bytes[i / 8] ^= 1 << (i % 8);
            // Flipping a `kind` bit can yield a reserved kind, which relays
            // must carry opaquely (spec §5.6); it can never yield a broadcast.
            match Record::parse(bytes) {
                Err(_) => {}
                Ok(r) => assert!(
                    matches!(r.body(), Body::Unknown(_)) && i / 8 == 1,
                    "bit {i} flip accepted as {r:?}"
                ),
            }
        }
    }

    #[test]
    fn broadcast_ttl_is_enforced() {
        assert_eq!(
            Record::new_broadcast(&alice(), T0, T0 + MAX_TTL + 1, 0, b"x").unwrap_err(),
            RecordError::BadTimes
        );
        assert_eq!(
            Record::new_broadcast(&alice(), T0, T0, 0, b"x").unwrap_err(),
            RecordError::BadTimes
        );
        assert!(Record::new_broadcast(&alice(), T0, T0 + MAX_TTL, 0, b"x").is_ok());
    }

    #[test]
    fn sealed_roundtrip_and_privacy() {
        let opts = SealOptions::new(T0, T0 + 86400);
        let sealed =
            Record::new_sealed(&alice(), &bob().public(), &opts, b"psst", &mut rng()).unwrap();
        let rec = &sealed.record;
        assert_eq!(rec.len(), sealed_record_len(4));

        match bob().open(rec) {
            Opened::Message(m) => {
                assert_eq!(m.sender, alice().public());
                assert_eq!(m.content, b"psst");
                assert_eq!(m.ctype, CTYPE_TEXT);
                assert_eq!(m.created, T0);
                assert_eq!(m.burn_secret, sealed.burn_secret);
            }
            other => panic!("bob could not open: {other:?}"),
        }
        assert_eq!(carol().open(rec), Opened::NotForUs);
        assert_eq!(alice().open(rec), Opened::NotForUs);

        // Neither party's key appears anywhere in the record.
        for pk in [alice().public(), bob().public()] {
            assert!(!rec.bytes().windows(32).any(|w| w == pk.as_bytes()));
            assert!(!rec.bytes().windows(32).any(|w| w == pk.to_x25519()));
        }
    }

    #[test]
    fn ctype_is_carried_and_authenticated() {
        let opts = SealOptions {
            ctype: 0x81,
            ..SealOptions::new(T0, T0 + 86400)
        };
        let sealed =
            Record::new_sealed(&alice(), &bob().public(), &opts, b"{}", &mut rng()).unwrap();
        match bob().open(&sealed.record) {
            Opened::Message(m) => assert_eq!((m.ctype, &m.content[..]), (0x81, &b"{}"[..])),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn sealed_padding_hides_length() {
        let opts = SealOptions::new(T0, T0 + 86400);
        let a = Record::new_sealed(&alice(), &bob().public(), &opts, b"a", &mut rng()).unwrap();
        let b = Record::new_sealed(&alice(), &bob().public(), &opts, &[7; 20], &mut rng()).unwrap();
        assert_eq!(a.record.len(), b.record.len());
        let padded = SealOptions {
            min_padded_len: 1000,
            ..opts
        };
        let c = Record::new_sealed(&alice(), &bob().public(), &padded, b"a", &mut rng()).unwrap();
        assert_eq!(c.record.len(), SEALED_PREFIX_LEN + 1024 + TAG_LEN);
        assert!(matches!(bob().open(&c.record), Opened::Message(_)));
    }

    #[test]
    fn sealed_header_tampering_breaks_opening() {
        let opts = SealOptions::new(T0, T0 + 86400);
        let rec = Record::new_sealed(&alice(), &bob().public(), &opts, b"psst", &mut rng())
            .unwrap()
            .record;
        for i in 0..rec.len() {
            let mut bytes = rec.bytes().to_vec();
            bytes[i] ^= 0x01;
            // Relays may or may not accept the mutated record, but bob never
            // accepts it as authentic.
            if let Ok(mutated) = Record::parse(bytes) {
                assert!(
                    !matches!(bob().open(&mutated), Opened::Message(_)),
                    "byte {i}"
                );
            }
        }
    }

    #[test]
    fn forged_inner_signature_is_detected() {
        // Mallory seals a message to bob claiming to be alice by signing with
        // her own key but writing alice's public key into the plaintext.
        let mallory = Identity::from_seed([66; 32]);
        let opts = SealOptions::new(T0, T0 + 86400);
        let e = [5u8; 32];
        let honest = Record::new_sealed_with_ephemeral(&mallory, &bob().public(), &opts, b"hi", e)
            .unwrap()
            .unwrap();
        // Re-encrypt the same plaintext with alice's key swapped in.
        let secret = x25519_dalek::StaticSecret::from(e);
        let ss = secret.diffie_hellman(&x25519_dalek::PublicKey::from(bob().public().to_x25519()));
        let eph = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let okm = derive64(
            CTX_SEAL,
            &[ss.as_bytes(), &eph, &bob().public().to_x25519()],
        );
        let key: [u8; 32] = okm[..32].try_into().unwrap();
        let (ad, ct) = honest.record.bytes().split_at(SEALED_PREFIX_LEN);
        let mut inner = cipher(&key)
            .decrypt(Nonce::from_slice(&[0; 12]), Payload { msg: ct, aad: ad })
            .unwrap();
        inner[..32].copy_from_slice(alice().public().as_bytes());
        let ct = cipher(&key)
            .encrypt(
                Nonce::from_slice(&[0; 12]),
                Payload {
                    msg: &inner,
                    aad: ad,
                },
            )
            .unwrap();
        let mut forged = ad.to_vec();
        forged.extend_from_slice(&ct);
        let forged = Record::parse(forged).unwrap();
        assert_eq!(bob().open(&forged), Opened::Forged);
    }

    #[test]
    fn surreptitious_forwarding_is_detected() {
        // Bob receives a message from alice and tries to re-seal the same
        // signed plaintext to carol so it looks like alice wrote to carol.
        let opts = SealOptions::new(T0, T0 + 86400);
        let sealed =
            Record::new_sealed(&alice(), &bob().public(), &opts, b"for bob", &mut rng()).unwrap();
        let e = [8u8; 32];
        let secret = x25519_dalek::StaticSecret::from(e);
        let eph = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let c_u = carol().public().to_x25519();
        let ss = secret.diffie_hellman(&x25519_dalek::PublicKey::from(c_u));
        let okm = derive64(CTX_SEAL, &[ss.as_bytes(), &eph, &c_u]);
        let key: [u8; 32] = okm[..32].try_into().unwrap();
        let burn_secret: [u8; 32] = okm[32..].try_into().unwrap();

        // Bob recovers alice's signed plaintext.
        let bob_ss = bob()
            .x25519_secret()
            .diffie_hellman(&x25519_dalek::PublicKey::from(
                sealed.record.as_sealed().unwrap().eph,
            ));
        let bob_okm = derive64(
            CTX_SEAL,
            &[
                bob_ss.as_bytes(),
                &sealed.record.as_sealed().unwrap().eph,
                &bob().public().to_x25519(),
            ],
        );
        let (ad0, ct0) = sealed.record.bytes().split_at(SEALED_PREFIX_LEN);
        let inner = cipher(&bob_okm[..32].try_into().unwrap())
            .decrypt(Nonce::from_slice(&[0; 12]), Payload { msg: ct0, aad: ad0 })
            .unwrap();

        let mut ad = header(KIND_SEALED, opts.expires, 0);
        ad.extend_from_slice(&burn_hash(&burn_secret));
        ad.extend_from_slice(&eph);
        let ct = cipher(&key)
            .encrypt(
                Nonce::from_slice(&[0; 12]),
                Payload {
                    msg: &inner,
                    aad: &ad,
                },
            )
            .unwrap();
        ad.extend_from_slice(&ct);
        let forwarded = Record::parse(ad).unwrap();
        assert_eq!(carol().open(&forwarded), Opened::Forged);
    }

    #[test]
    fn burn_validity() {
        let opts = SealOptions::new(T0, T0 + 86400);
        let sealed =
            Record::new_sealed(&alice(), &bob().public(), &opts, b"burn me", &mut rng()).unwrap();
        let Opened::Message(msg) = bob().open(&sealed.record) else {
            panic!()
        };

        let good = msg.burn(0);
        assert!(good.burns(&sealed.record));
        assert_eq!(good.len(), BURN_RECORD_LEN);

        // The sender can retract with the secret returned at sealing time.
        let retract = Record::new_burn(sealed.record.id(), opts.expires, sealed.burn_secret, 1);
        assert!(retract.burns(&sealed.record));

        let wrong_secret = Record::new_burn(sealed.record.id(), opts.expires, [9; 32], 0);
        assert!(!wrong_secret.burns(&sealed.record));
        let wrong_expiry =
            Record::new_burn(sealed.record.id(), opts.expires + 1, msg.burn_secret, 0);
        assert!(!wrong_expiry.burns(&sealed.record));
        let wrong_target = Record::new_burn(RecordId([0; 32]), opts.expires, msg.burn_secret, 0);
        assert!(!wrong_target.burns(&sealed.record));

        let broadcast = Record::new_broadcast(&alice(), T0, T0 + 10, 0, b"x").unwrap();
        let at_broadcast = Record::new_burn(broadcast.id(), broadcast.expires(), [0; 32], 0);
        assert!(!at_broadcast.burns(&broadcast));
    }

    #[test]
    fn unknown_kinds_are_carried() {
        let mut bytes = header(0x42, T0, 0);
        bytes.extend_from_slice(b"future stuff");
        let rec = Record::parse(bytes).unwrap();
        assert_eq!(rec.body(), &Body::Unknown(0x42));
        assert_eq!(
            Record::parse(header(0, T0, 0)).unwrap_err(),
            RecordError::BadKind
        );
        let mut v2 = header(1, T0, 0);
        v2[0] = 2;
        assert_eq!(Record::parse(v2).unwrap_err(), RecordError::BadVersion(2));
    }

    #[test]
    fn grinding_reaches_target_work() {
        let rec = grind(10, |stamp| {
            Record::new_broadcast(&alice(), T0, T0 + 60, stamp, b"work")
        })
        .unwrap();
        assert!(rec.work() >= 10);
    }

    #[test]
    fn size_limits() {
        let big = vec![b'x'; MAX_BROADCAST_CONTENT];
        let rec = Record::new_broadcast(&alice(), T0, T0 + 60, 0, &big).unwrap();
        assert!(rec.len() <= MAX_RECORD_SIZE);
        let too_big = vec![b'x'; MAX_BROADCAST_CONTENT + 64];
        assert_eq!(
            Record::new_broadcast(&alice(), T0, T0 + 60, 0, &too_big).unwrap_err(),
            RecordError::ContentTooLarge
        );
    }

    proptest! {
        #[test]
        fn parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = Record::parse(bytes);
        }

        #[test]
        fn parse_never_panics_with_valid_header(kind in 0u8..5, tail in proptest::collection::vec(any::<u8>(), 0..400)) {
            let mut bytes = header(kind, T0, 0);
            bytes.extend(tail);
            let _ = Record::parse(bytes);
        }

        #[test]
        fn sealed_roundtrip_any_content(content in proptest::collection::vec(any::<u8>(), 0..600), seed: [u8; 32]) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let opts = SealOptions::new(T0, T0 + 1000);
            let sealed = Record::new_sealed(&alice(), &bob().public(), &opts, &content, &mut rng).unwrap();
            prop_assert_eq!(sealed.record.len(), sealed_record_len(content.len()));
            match bob().open(&sealed.record) {
                Opened::Message(m) => prop_assert_eq!(m.content, content),
                other => prop_assert!(false, "unexpected {:?}", other),
            }
        }
    }
}
