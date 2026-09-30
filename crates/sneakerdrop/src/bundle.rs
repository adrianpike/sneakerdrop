//! Ledger files (spec §9.1) and bundles (spec §9.2).

use thiserror::Error;

use crate::codec::{DecodeError, Reader, put_varint};
use crate::consts::{CHECKSUM_LEN, SALT_LEN, SUMMARY_PREFIX};
use crate::crypto::{CTX_BUNDLE, CTX_SUMMARY, derive};
use crate::record::{Record, RecordId};

pub const LEDGER_MAGIC: &[u8; 8] = b"SNKLEDG\x01";
pub const BUNDLE_MAGIC: &[u8; 4] = b"SDB\x01";

const ITEM_RECORD: u8 = 0x01;
const ITEM_SUMMARY: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FormatError {
    #[error("missing or wrong magic bytes")]
    BadMagic,
    #[error("checksum mismatch")]
    BadChecksum,
    #[error("unknown bundle item type {0:#04x}")]
    UnknownItem(u8),
    #[error(transparent)]
    Decode(#[from] DecodeError),
}

// ---------------------------------------------------------------------------
// Ledger files

/// Encodes records as a ledger file.
pub fn encode_ledger_file<'a>(records: impl IntoIterator<Item = &'a Record>) -> Vec<u8> {
    let mut out = LEDGER_MAGIC.to_vec();
    for r in records {
        put_varint(&mut out, r.len() as u64);
        out.extend_from_slice(r.bytes());
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerFile {
    pub entries: Vec<Vec<u8>>,
    /// The file ended part-way through an entry, which was ignored.
    pub truncated: bool,
}

/// Decodes a ledger file, tolerating a truncated final entry.
pub fn decode_ledger_file(bytes: &[u8]) -> Result<LedgerFile, FormatError> {
    let body = bytes
        .strip_prefix(LEDGER_MAGIC)
        .ok_or(FormatError::BadMagic)?;
    let mut r = Reader::new(body);
    let mut entries = Vec::new();
    while !r.is_empty() {
        match r.len_prefixed() {
            Ok(entry) => entries.push(entry.to_vec()),
            Err(DecodeError::Truncated) => {
                return Ok(LedgerFile {
                    entries,
                    truncated: true,
                });
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(LedgerFile {
        entries,
        truncated: false,
    })
}

// ---------------------------------------------------------------------------
// Summaries

/// A salted set of truncated record IDs (spec §10.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    salt: [u8; SALT_LEN],
    /// Sorted, for binary search and a canonical encoding.
    prefixes: Vec<[u8; SUMMARY_PREFIX]>,
}

impl Summary {
    pub fn new<'a>(salt: [u8; SALT_LEN], ids: impl IntoIterator<Item = &'a RecordId>) -> Self {
        let key = derive(CTX_SUMMARY, &[&salt]);
        let prefixes = ids
            .into_iter()
            .map(|id| prefix_with_key(&key, id))
            .collect();
        Self::from_parts(salt, prefixes)
    }

    fn from_parts(salt: [u8; SALT_LEN], mut prefixes: Vec<[u8; SUMMARY_PREFIX]>) -> Self {
        prefixes.sort_unstable();
        prefixes.dedup();
        Self { salt, prefixes }
    }

    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    pub fn len(&self) -> usize {
        self.prefixes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }

    /// Returns a membership test for IDs against this summary.
    pub fn matcher(&self) -> impl Fn(&RecordId) -> bool + '_ {
        let key = derive(CTX_SUMMARY, &[&self.salt]);
        move |id| {
            self.prefixes
                .binary_search(&prefix_with_key(&key, id))
                .is_ok()
        }
    }
}

fn prefix_with_key(key: &[u8; 32], id: &RecordId) -> [u8; SUMMARY_PREFIX] {
    blake3::keyed_hash(key, &id.0).as_bytes()[..SUMMARY_PREFIX]
        .try_into()
        .expect("hash is 32 bytes")
}

// ---------------------------------------------------------------------------
// Bundles

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Record(Vec<u8>),
    Summary(Summary),
}

pub fn encode_bundle(items: &[Item]) -> Vec<u8> {
    let mut out = BUNDLE_MAGIC.to_vec();
    for item in items {
        match item {
            Item::Record(bytes) => {
                out.push(ITEM_RECORD);
                put_varint(&mut out, bytes.len() as u64);
                out.extend_from_slice(bytes);
            }
            Item::Summary(s) => {
                out.push(ITEM_SUMMARY);
                out.extend_from_slice(&s.salt);
                put_varint(&mut out, s.prefixes.len() as u64);
                for p in &s.prefixes {
                    out.extend_from_slice(p);
                }
            }
        }
    }
    let checksum = derive(CTX_BUNDLE, &[&out]);
    out.extend_from_slice(&checksum[..CHECKSUM_LEN]);
    out
}

/// Convenience: a bundle of records.
pub fn encode_records<'a>(records: impl IntoIterator<Item = &'a Record>) -> Vec<u8> {
    let items: Vec<Item> = records
        .into_iter()
        .map(|r| Item::Record(r.bytes().to_vec()))
        .collect();
    encode_bundle(&items)
}

pub fn decode_bundle(bytes: &[u8]) -> Result<Vec<Item>, FormatError> {
    if !bytes.starts_with(BUNDLE_MAGIC) || bytes.len() < BUNDLE_MAGIC.len() + CHECKSUM_LEN {
        return Err(FormatError::BadMagic);
    }
    let (content, checksum) = bytes.split_at(bytes.len() - CHECKSUM_LEN);
    if derive(CTX_BUNDLE, &[content])[..CHECKSUM_LEN] != *checksum {
        return Err(FormatError::BadChecksum);
    }
    let mut r = Reader::new(&content[BUNDLE_MAGIC.len()..]);
    let mut items = Vec::new();
    while !r.is_empty() {
        match r.u8()? {
            ITEM_RECORD => items.push(Item::Record(r.len_prefixed()?.to_vec())),
            ITEM_SUMMARY => {
                let salt = r.array()?;
                let count = r.varint()?;
                if count > (r.remaining() / SUMMARY_PREFIX) as u64 {
                    return Err(DecodeError::Truncated.into());
                }
                let prefixes = (0..count).map(|_| r.array()).collect::<Result<_, _>>()?;
                items.push(Item::Summary(Summary::from_parts(salt, prefixes)));
            }
            other => return Err(FormatError::UnknownItem(other)),
        }
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn ledger_file_tolerates_truncation() {
        let mut bytes = LEDGER_MAGIC.to_vec();
        put_varint(&mut bytes, 3);
        bytes.extend_from_slice(b"abc");
        put_varint(&mut bytes, 10);
        bytes.extend_from_slice(b"defg");
        let f = decode_ledger_file(&bytes).unwrap();
        assert_eq!(f.entries, vec![b"abc".to_vec()]);
        assert!(f.truncated);
        assert_eq!(decode_ledger_file(b"nope"), Err(FormatError::BadMagic));
    }

    #[test]
    fn bundle_checksum_detects_corruption() {
        let bundle = encode_bundle(&[Item::Record(b"hello".to_vec())]);
        for i in 0..bundle.len() {
            let mut b = bundle.clone();
            b[i] ^= 0x10;
            assert!(decode_bundle(&b).is_err(), "byte {i}");
        }
    }

    #[test]
    fn summary_membership() {
        let ids: Vec<RecordId> = (0..100u8).map(|i| RecordId([i; 32])).collect();
        let s = Summary::new([1; SALT_LEN], &ids[..50]);
        let has = s.matcher();
        assert!(ids[..50].iter().all(&has));
        assert!(!ids[50..].iter().any(&has));
        // Prefixes depend on the salt.
        let s2 = Summary::new([2; SALT_LEN], &ids[..50]);
        assert_ne!(s.prefixes, s2.prefixes);
    }

    #[test]
    fn summary_count_cannot_overallocate() {
        let mut b = BUNDLE_MAGIC.to_vec();
        b.push(ITEM_SUMMARY);
        b.extend_from_slice(&[0; SALT_LEN]);
        put_varint(&mut b, u64::MAX >> 4);
        let checksum = derive(CTX_BUNDLE, &[&b]);
        b.extend_from_slice(&checksum[..CHECKSUM_LEN]);
        assert!(decode_bundle(&b).is_err());
    }

    fn item_strategy() -> impl Strategy<Value = Item> {
        prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..300).prop_map(Item::Record),
            (
                any::<[u8; SALT_LEN]>(),
                proptest::collection::vec(any::<[u8; 32]>(), 0..20)
            )
                .prop_map(|(salt, ids)| {
                    let ids: Vec<RecordId> = ids.into_iter().map(RecordId).collect();
                    Item::Summary(Summary::new(salt, &ids))
                }),
        ]
    }

    proptest! {
        #[test]
        fn bundle_roundtrip(items in proptest::collection::vec(item_strategy(), 0..8)) {
            let bytes = encode_bundle(&items);
            prop_assert_eq!(decode_bundle(&bytes).unwrap(), items);
        }

        #[test]
        fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = decode_bundle(&bytes);
            let _ = decode_ledger_file(&bytes);
            let mut with_magic = LEDGER_MAGIC.to_vec();
            with_magic.extend_from_slice(&bytes);
            let _ = decode_ledger_file(&with_magic);
        }
    }
}
