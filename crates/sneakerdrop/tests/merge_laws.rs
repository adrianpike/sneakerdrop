//! Property tests for the ledger merge semantics of spec §8.
//!
//! The optimized `Ledger` is checked against `model_visible`, a literal
//! transcription of the definitions in §8.1.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sneakerdrop::record::Body;
use sneakerdrop::{Identity, Ledger, Opened, Record, RecordId, SealOptions};

const T0: u64 = 1_800_000_000;

/// A pool of records with deliberately tangled burn relationships.
fn pool() -> &'static Vec<Record> {
    static POOL: OnceLock<Vec<Record>> = OnceLock::new();
    POOL.get_or_init(|| {
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let people: Vec<Identity> = (1..=3).map(|i| Identity::from_seed([i; 32])).collect();
        let mut out = Vec::new();
        for i in 0..6u64 {
            let (s, r) = (&people[i as usize % 3], &people[(i as usize + 1) % 3]);
            let expires = T0 + 100 + 50 * i;
            let sealed = Record::new_sealed(
                s,
                &r.public(),
                &SealOptions::new(T0, expires),
                b"m",
                &mut rng,
            )
            .unwrap();
            let Opened::Message(msg) = r.open(&sealed.record) else {
                panic!()
            };
            out.push(sealed.record.clone());
            // Valid burns: one from the recipient, a duplicate with another stamp,
            // and a retraction by the sender (same secret).
            out.push(msg.burn(0));
            if i % 2 == 0 {
                out.push(msg.burn(1));
                out.push(Record::new_burn(msg.id, expires, sealed.burn_secret, 2));
            }
            // Invalid burns: wrong secret, wrong expiry (possibly outliving the target).
            out.push(Record::new_burn(msg.id, expires, [i as u8; 32], 0));
            out.push(Record::new_burn(msg.id, expires + 200, msg.burn_secret, 0));
            out.push(Record::new_broadcast(s, T0, expires + 25, i, b"b").unwrap());
        }
        // A burn aimed at a broadcast, and an unknown-kind record.
        let b = out
            .iter()
            .find(|r| r.as_broadcast().is_some())
            .unwrap()
            .clone();
        out.push(Record::new_burn(b.id(), b.expires(), [0; 32], 0));
        let mut unknown = vec![1u8, 0x42];
        unknown.extend_from_slice(&(T0 + 333).to_be_bytes());
        unknown.extend_from_slice(&[0; 8]);
        out.push(Record::parse(unknown).unwrap());
        out
    })
}

/// Spec §8.1, transcribed literally.
fn model_visible(admitted: &[&Record], t: u64) -> BTreeSet<RecordId> {
    let live: Vec<&Record> = admitted
        .iter()
        .copied()
        .filter(|r| r.expires() > t)
        .collect();
    let burned: BTreeSet<RecordId> = live
        .iter()
        .filter(|target| live.iter().any(|b| b.burns(target)))
        .map(|r| r.id())
        .collect();
    live.iter()
        .map(|r| r.id())
        .filter(|id| !burned.contains(id))
        .collect()
}

/// A random schedule: which pool records arrive, in which order, and when.
fn schedule() -> impl Strategy<Value = Vec<(usize, u64)>> {
    let n = pool().len();
    proptest::collection::vec((0..n, 0u64..400), 0..60).prop_map(|mut v| {
        v.sort_by_key(|&(_, dt)| dt); // time is monotonic per node
        v
    })
}

fn replay(steps: &[(usize, u64)]) -> (Ledger, Vec<&'static Record>) {
    let mut ledger = Ledger::default();
    let mut admitted = Vec::new();
    for &(i, dt) in steps {
        let r = &pool()[i];
        if ledger.insert(r.clone(), T0 + dt).is_ok() {
            admitted.push(r);
        }
    }
    (ledger, admitted)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// The stored ledger always equals visible(R, t).
    #[test]
    fn ledger_matches_model(steps in schedule(), extra in 0u64..400) {
        let (mut ledger, admitted) = replay(&steps);
        let t = steps.last().map_or(T0, |s| T0 + s.1) + extra;
        ledger.expire(t);
        prop_assert_eq!(ledger.ids(), model_visible(&admitted, t));
    }

    /// Arrival order does not matter (Theorem, §8.3).
    #[test]
    fn order_independent(idx in proptest::collection::vec(0..pool().len(), 0..40), seed: u64, t in 0u64..300) {
        let mut shuffled = idx.clone();
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        for i in (1..shuffled.len()).rev() {
            let j = (rand_core::RngCore::next_u64(&mut rng) % (i as u64 + 1)) as usize;
            shuffled.swap(i, j);
        }
        let a: Vec<_> = idx.iter().map(|&i| (i, t)).collect();
        let b: Vec<_> = shuffled.iter().map(|&i| (i, t)).collect();
        prop_assert_eq!(replay(&a).0.ids(), replay(&b).0.ids());
    }

    /// visible(visible(X, t1) ∪ Y, t2) = visible(X ∪ Y, t2) for t1 <= t2 (Lemma, §8.3).
    #[test]
    fn merge_lemma(x in schedule(), y in proptest::collection::vec(0..pool().len(), 0..30), dt in 0u64..200) {
        let (mut left, admitted_x) = replay(&x);
        let t1 = x.last().map_or(T0, |s| T0 + s.1);
        let t2 = t1 + dt;
        let y_records: Vec<&Record> = y.iter().map(|&i| &pool()[i]).collect();
        left.merge(y_records.iter().copied(), t2);
        left.expire(t2);

        let mut union: Vec<&Record> = admitted_x.clone();
        union.extend(y_records.iter().copied().filter(|r| r.expires() > t2));
        prop_assert_eq!(left.ids(), model_visible(&union, t2));
    }

    /// Two nodes that sync in both directions end up identical, whichever syncs first.
    #[test]
    fn pairwise_sync_converges(a in schedule(), b in schedule(), a_first: bool) {
        let (mut la, _) = replay(&a);
        let (mut lb, _) = replay(&b);
        let t = T0 + 400;
        let (snap_a, snap_b): (Vec<Record>, Vec<Record>) = (la.iter().cloned().collect(), lb.iter().cloned().collect());
        if a_first {
            la.merge(&snap_b, t);
            lb.merge(la.iter().cloned().collect::<Vec<_>>().iter(), t);
        } else {
            lb.merge(&snap_a, t);
            la.merge(lb.iter().cloned().collect::<Vec<_>>().iter(), t);
        }
        prop_assert_eq!(la.ids(), lb.ids());
    }
}

#[test]
fn pool_is_interesting() {
    // Guard against the pool degenerating: it must contain burned targets,
    // valid and invalid burns, and records with distinct expiries.
    let p = pool();
    let sealed = p.iter().filter(|r| r.as_sealed().is_some()).count();
    let valid_burns = p.iter().filter(|b| p.iter().any(|t| b.burns(t))).count();
    let burns = p
        .iter()
        .filter(|r| matches!(r.body(), Body::Burn(_)))
        .count();
    assert_eq!(sealed, 6);
    assert!(valid_burns >= 12);
    assert!(burns - valid_burns >= 12);
}
