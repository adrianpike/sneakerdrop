//! Synchronization helpers (spec §10) and input auto-detection.

use rand_core::{CryptoRng, RngCore};

use crate::armor::dearmor;
use crate::bundle::{BUNDLE_MAGIC, Item, LEDGER_MAGIC, Summary, decode_bundle, decode_ledger_file};
use crate::consts::SALT_LEN;
use crate::ledger::Ledger;
use crate::record::Record;

/// A summary of every record in `ledger`, under a fresh salt.
pub fn summarize<R: RngCore + CryptoRng>(ledger: &Ledger, rng: &mut R) -> Summary {
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    Summary::new(
        salt,
        ledger.iter().map(|r| r.id()).collect::<Vec<_>>().iter(),
    )
}

/// Records in `ledger` that the peer described by `summary` lacks.
pub fn missing<'a>(ledger: &'a Ledger, summary: &Summary) -> Vec<&'a Record> {
    let has = summary.matcher();
    ledger.iter().filter(|r| !has(&r.id())).collect()
}

/// Everything extracted from an input of unknown format.
#[derive(Debug, Clone, Default)]
pub struct Incoming {
    pub records: Vec<Vec<u8>>,
    pub summaries: Vec<Summary>,
    /// Blocks or bundles that could not be decoded.
    pub failed: usize,
    /// A ledger file ended in a partial entry.
    pub truncated: bool,
}

impl Incoming {
    fn push_items(&mut self, items: Vec<Item>) {
        for item in items {
            match item {
                Item::Record(r) => self.records.push(r),
                Item::Summary(s) => self.summaries.push(s),
            }
        }
    }
}

/// Decodes a ledger file, a binary bundle, or armored text.
pub fn read_any(input: &[u8]) -> Incoming {
    let mut incoming = Incoming::default();
    if input.starts_with(LEDGER_MAGIC) {
        match decode_ledger_file(input) {
            Ok(f) => {
                incoming.records = f.entries;
                incoming.truncated = f.truncated;
            }
            Err(_) => incoming.failed += 1,
        }
    } else if input.starts_with(BUNDLE_MAGIC) {
        match decode_bundle(input) {
            Ok(items) => incoming.push_items(items),
            Err(_) => incoming.failed += 1,
        }
    } else {
        let text = String::from_utf8_lossy(input);
        let d = dearmor(&text);
        incoming.failed += d.failed;
        for block in d.blocks {
            match decode_bundle(&block) {
                Ok(items) => incoming.push_items(items),
                Err(_) => incoming.failed += 1,
            }
        }
    }
    incoming
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::armor::{Encoding, armor};
    use crate::bundle::{encode_bundle, encode_ledger_file, encode_records};
    use crate::crypto::Identity;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const T0: u64 = 1_800_000_000;

    fn ledger_with(author: u8, n: u64) -> Ledger {
        let id = Identity::from_seed([author; 32]);
        let mut l = Ledger::default();
        for i in 0..n {
            let r =
                Record::new_broadcast(&id, T0, T0 + 1000, i, format!("{author}/{i}").as_bytes())
                    .unwrap();
            l.insert(r, T0).unwrap();
        }
        l
    }

    #[test]
    fn three_message_reconciliation() {
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let mut a = ledger_with(1, 30);
        let mut b = ledger_with(2, 20);
        let shared = ledger_with(3, 10);
        a.merge(shared.iter(), T0);
        b.merge(shared.iter(), T0);

        // 1. A -> B: summary
        let s_a = summarize(&a, &mut rng);
        // 2. B -> A: what A lacks, plus B's summary
        let to_a: Vec<Record> = missing(&b, &s_a).into_iter().cloned().collect();
        assert_eq!(to_a.len(), 20);
        let s_b = summarize(&b, &mut rng);
        a.merge(&to_a, T0);
        // 3. A -> B: what B lacks
        let to_b: Vec<Record> = missing(&a, &s_b).into_iter().cloned().collect();
        assert_eq!(to_b.len(), 30);
        b.merge(&to_b, T0);

        assert_eq!(a.ids(), b.ids());
        assert_eq!(a.len(), 60);
    }

    #[test]
    fn read_any_detects_formats() {
        let l = ledger_with(1, 3);
        let expected: Vec<Vec<u8>> = l.iter().map(|r| r.bytes().to_vec()).collect();

        assert_eq!(read_any(&encode_ledger_file(l.iter())).records, expected);
        assert_eq!(read_any(&encode_records(l.iter())).records, expected);

        let text = format!(
            "noise\n{}{}",
            armor(&encode_records(l.iter().take(2)), Encoding::Base64),
            armor(
                &encode_bundle(&[Item::Record(expected[2].clone())]),
                Encoding::Base32
            )
        );
        let got = read_any(text.as_bytes());
        assert_eq!(got.records, expected);
        assert_eq!(got.failed, 0);
    }
}
