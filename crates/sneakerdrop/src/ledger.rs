//! Admission (spec §7) and ledger state / merge (spec §8).
//!
//! A [`Ledger`] always stores exactly `visible(R, t)`, where `R` is every
//! record it has admitted and `t` the time of the latest operation. Burns are
//! kept until they expire and act as tombstones for their targets.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use thiserror::Error;

use crate::consts::MAX_HORIZON;
use crate::record::{Body, KIND_BROADCAST, KIND_BURN, KIND_SEALED, Record, RecordError, RecordId};

/// Configurable admission policy (spec §7.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Policy {
    pub min_work_broadcast: u32,
    pub min_work_sealed: u32,
    pub min_work_burn: u32,
    pub min_work_other: u32,
}

impl Policy {
    pub fn uniform(bits: u32) -> Self {
        Self {
            min_work_broadcast: bits,
            min_work_sealed: bits,
            min_work_burn: bits,
            min_work_other: bits,
        }
    }

    pub fn required_work(&self, kind: u8) -> u32 {
        match kind {
            KIND_BROADCAST => self.min_work_broadcast,
            KIND_SEALED => self.min_work_sealed,
            KIND_BURN => self.min_work_burn,
            _ => self.min_work_other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Reject {
    #[error(transparent)]
    Malformed(#[from] RecordError),
    #[error("record has expired")]
    Expired,
    #[error("record expires beyond the acceptance horizon")]
    BeyondHorizon,
    #[error("insufficient work: have {have} bits, need {need}")]
    InsufficientWork { have: u32, need: u32 },
}

/// The clock- and policy-dependent admission rules (spec §7.2, §7.3). The
/// deterministic rules of §7.1 are enforced by [`Record::parse`].
pub fn check_admission(record: &Record, now: u64, policy: &Policy) -> Result<(), Reject> {
    if record.expires() <= now {
        return Err(Reject::Expired);
    }
    if record.expires() > now.saturating_add(MAX_HORIZON) {
        return Err(Reject::BeyondHorizon);
    }
    let need = policy.required_work(record.kind());
    let have = record.work();
    if have < need {
        return Err(Reject::InsufficientWork { have, need });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    /// Stored.
    New,
    /// Already stored.
    Duplicate,
    /// Admitted, but it's a sealed record already burned by a stored burn,
    /// so it is not stored.
    Burned,
}

#[derive(Debug, Clone)]
struct Entry {
    record: Record,
    seq: u64,
}

#[derive(Debug, Clone, Default)]
pub struct MergeStats {
    pub new: usize,
    pub duplicate: usize,
    pub burned: usize,
    pub rejected: usize,
}

impl MergeStats {
    fn count(&mut self, result: &Result<Admitted, Reject>) {
        match result {
            Ok(Admitted::New) => self.new += 1,
            Ok(Admitted::Duplicate) => self.duplicate += 1,
            Ok(Admitted::Burned) => self.burned += 1,
            Err(_) => self.rejected += 1,
        }
    }
}

/// A node's set of records.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    policy: Policy,
    entries: HashMap<RecordId, Entry>,
    /// Local arrival order, for incremental push (spec §10.2).
    by_seq: BTreeMap<u64, RecordId>,
    by_expiry: BTreeSet<(u64, RecordId)>,
    /// Stored burns, indexed by target.
    burns_by_target: HashMap<RecordId, BTreeSet<RecordId>>,
    next_seq: u64,
}

impl Ledger {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, id: &RecordId) -> bool {
        self.entries.contains_key(id)
    }

    pub fn get(&self, id: &RecordId) -> Option<&Record> {
        self.entries.get(id).map(|e| &e.record)
    }

    /// Records in local arrival order.
    pub fn iter(&self) -> impl Iterator<Item = &Record> {
        self.by_seq.values().map(|id| &self.entries[id].record)
    }

    /// Records that arrived after `cursor`, with their sequence numbers.
    pub fn since(&self, cursor: u64) -> impl Iterator<Item = (u64, &Record)> {
        self.by_seq
            .range(cursor.saturating_add(1)..)
            .map(|(seq, id)| (*seq, &self.entries[id].record))
    }

    /// The sequence number of the most recent arrival, or 0 if empty.
    pub fn last_seq(&self) -> u64 {
        self.by_seq.keys().next_back().copied().unwrap_or(0)
    }

    pub fn ids(&self) -> BTreeSet<RecordId> {
        self.entries.keys().copied().collect()
    }

    /// Drops expired records (spec §8.1). Returns how many were removed.
    pub fn expire(&mut self, now: u64) -> usize {
        let mut removed = 0;
        while let Some(&(expires, id)) = self.by_expiry.first() {
            if expires > now {
                break;
            }
            self.remove(&id);
            removed += 1;
        }
        removed
    }

    /// Parses and admits raw record bytes.
    pub fn insert_bytes(&mut self, bytes: &[u8], now: u64) -> Result<Admitted, Reject> {
        self.expire(now);
        // Skip parsing (and signature verification) for records we already hold.
        if self.entries.contains_key(&RecordId::of(bytes)) {
            return Ok(Admitted::Duplicate);
        }
        self.insert(Record::parse(bytes.to_vec())?, now)
    }

    /// Admits a parsed record at time `now` (spec §8.2).
    pub fn insert(&mut self, record: Record, now: u64) -> Result<Admitted, Reject> {
        self.expire(now);
        check_admission(&record, now, &self.policy)?;
        let id = record.id();
        if self.entries.contains_key(&id) {
            return Ok(Admitted::Duplicate);
        }
        match record.body() {
            Body::Sealed(_) => {
                if self.is_burned(&record) {
                    return Ok(Admitted::Burned);
                }
            }
            Body::Burn(burn) => {
                let target = burn.target;
                self.burns_by_target.entry(target).or_default().insert(id);
                if self.get(&target).is_some_and(|t| record.burns(t)) {
                    self.remove(&target);
                }
            }
            Body::Broadcast(_) | Body::Unknown(_) => {}
        }
        let seq = self.next_seq + 1;
        self.next_seq = seq;
        self.by_seq.insert(seq, id);
        self.by_expiry.insert((record.expires(), id));
        self.entries.insert(id, Entry { record, seq });
        Ok(Admitted::New)
    }

    /// Advances to `now` and admits every record of `records`, returning
    /// counts by outcome.
    pub fn merge<'a>(
        &mut self,
        records: impl IntoIterator<Item = &'a Record>,
        now: u64,
    ) -> MergeStats {
        self.expire(now);
        let mut stats = MergeStats::default();
        for r in records {
            let result = self.insert(r.clone(), now);
            stats.count(&result);
        }
        stats
    }

    /// Like [`Ledger::merge`], for unparsed records.
    pub fn merge_bytes<'a>(
        &mut self,
        records: impl IntoIterator<Item = &'a [u8]>,
        now: u64,
    ) -> MergeStats {
        self.expire(now);
        let mut stats = MergeStats::default();
        for r in records {
            let result = self.insert_bytes(r, now);
            stats.count(&result);
        }
        stats
    }

    /// Whether some stored burn is valid for `sealed`.
    pub fn is_burned(&self, sealed: &Record) -> bool {
        self.burns_by_target
            .get(&sealed.id())
            .is_some_and(|burns| burns.iter().any(|b| self.entries[b].record.burns(sealed)))
    }

    fn remove(&mut self, id: &RecordId) {
        let Some(entry) = self.entries.remove(id) else {
            return;
        };
        self.by_seq.remove(&entry.seq);
        self.by_expiry.remove(&(entry.record.expires(), *id));
        if let Some(burn) = entry.record.as_burn()
            && let Some(set) = self.burns_by_target.get_mut(&burn.target)
        {
            set.remove(id);
            if set.is_empty() {
                self.burns_by_target.remove(&burn.target);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::MAX_TTL;
    use crate::crypto::Identity;
    use crate::record::{Opened, SealOptions};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const T0: u64 = 1_800_000_000;

    struct Fixture {
        sealed: Record,
        burn: Record,
        broadcast: Record,
    }

    fn fixture() -> Fixture {
        let alice = Identity::from_seed([1; 32]);
        let bob = Identity::from_seed([2; 32]);
        let mut rng = ChaCha20Rng::from_seed([0; 32]);
        let sealed = Record::new_sealed(
            &alice,
            &bob.public(),
            &SealOptions::new(T0, T0 + 1000),
            b"m",
            &mut rng,
        )
        .unwrap()
        .record;
        let Opened::Message(msg) = bob.open(&sealed) else {
            panic!()
        };
        Fixture {
            burn: msg.burn(0),
            sealed,
            broadcast: Record::new_broadcast(&alice, T0, T0 + 2000, 0, b"b").unwrap(),
        }
    }

    #[test]
    fn burn_before_or_after_target_converges() {
        let f = fixture();
        let mut a = Ledger::default();
        assert_eq!(a.insert(f.sealed.clone(), T0), Ok(Admitted::New));
        assert_eq!(a.insert(f.burn.clone(), T0), Ok(Admitted::New));

        let mut b = Ledger::default();
        assert_eq!(b.insert(f.burn.clone(), T0), Ok(Admitted::New));
        assert_eq!(b.insert(f.sealed.clone(), T0), Ok(Admitted::Burned));

        assert_eq!(a.ids(), b.ids());
        assert_eq!(a.ids(), [f.burn.id()].into());
    }

    #[test]
    fn records_expire() {
        let f = fixture();
        let mut l = Ledger::default();
        l.merge([&f.sealed, &f.broadcast], T0);
        assert_eq!(l.len(), 2);
        assert_eq!(l.expire(T0 + 1000), 1);
        assert!(l.contains(&f.broadcast.id()));
        assert_eq!(l.insert(f.sealed.clone(), T0 + 1000), Err(Reject::Expired));
    }

    #[test]
    fn horizon_is_enforced() {
        let alice = Identity::from_seed([1; 32]);
        let rec = Record::new_broadcast(&alice, T0, T0 + MAX_TTL, 0, b"x").unwrap();
        let mut l = Ledger::default();
        // A relay whose clock lags the creator by more than 7 days rejects it.
        let lagging = T0 + MAX_TTL - MAX_HORIZON - 1;
        assert_eq!(l.insert(rec.clone(), lagging), Err(Reject::BeyondHorizon));
        assert_eq!(l.insert(rec, lagging + 1), Ok(Admitted::New));
    }

    #[test]
    fn policy_is_enforced() {
        let f = fixture();
        let mut l = Ledger::new(Policy::uniform(30));
        assert!(matches!(
            l.insert(f.broadcast.clone(), T0),
            Err(Reject::InsufficientWork { need: 30, .. })
        ));
    }

    #[test]
    fn since_cursor_tracks_arrivals() {
        let f = fixture();
        let mut l = Ledger::default();
        l.insert(f.broadcast.clone(), T0).unwrap();
        let cursor = l.last_seq();
        l.insert(f.sealed.clone(), T0).unwrap();
        let later: Vec<_> = l.since(cursor).map(|(_, r)| r.id()).collect();
        assert_eq!(later, vec![f.sealed.id()]);
        // Burning the sealed record removes it from the push queue, but the
        // burn itself is new.
        l.insert(f.burn.clone(), T0).unwrap();
        let later: Vec<_> = l.since(cursor).map(|(_, r)| r.id()).collect();
        assert_eq!(later, vec![f.burn.id()]);
    }

    #[test]
    fn duplicate_bytes_skip_parsing() {
        let f = fixture();
        let mut l = Ledger::default();
        assert_eq!(l.insert_bytes(f.broadcast.bytes(), T0), Ok(Admitted::New));
        assert_eq!(
            l.insert_bytes(f.broadcast.bytes(), T0),
            Ok(Admitted::Duplicate)
        );
        assert!(matches!(
            l.insert_bytes(&[1, 2, 3], T0),
            Err(Reject::Malformed(_))
        ));
    }
}
