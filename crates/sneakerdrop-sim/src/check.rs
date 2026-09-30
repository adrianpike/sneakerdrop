//! Invariants. Each is a property the spec promises; a violation is a bug in
//! the spec or the implementation.

use std::collections::{BTreeSet, HashMap};

use sneakerdrop::consts::MAX_HORIZON;
use sneakerdrop::record::Body;
use sneakerdrop::{Ledger, Record, RecordId};

use crate::report::Violation;
use crate::world::World;

/// `visible(R, t)` from spec §8.1, computed from scratch.
pub fn model_visible<'a>(admitted: impl Iterator<Item = &'a Record>, t: u64) -> BTreeSet<RecordId> {
    let live: Vec<&Record> = admitted.filter(|r| r.expires() > t).collect();
    let mut burns: HashMap<RecordId, Vec<&Record>> = HashMap::new();
    for r in &live {
        if let Body::Burn(b) = r.body() {
            burns.entry(b.target).or_default().push(r);
        }
    }
    live.iter()
        .filter(|r| {
            !burns
                .get(&r.id())
                .is_some_and(|bs| bs.iter().any(|b| b.burns(r)))
        })
        .map(|r| r.id())
        .collect()
}

/// Invariants checked continuously at every honest node.
pub fn node_invariants(w: &mut World, n: usize) -> Result<(), Violation> {
    let now = w.nodes[n].now(w.global);
    w.nodes[n].admitted.retain(|_, r| r.expires() > now);
    w.nodes[n].ledger.expire(now);
    let node = &w.nodes[n];

    // I1. The ledger equals visible(R, t) (spec §8.1).
    let expected = model_visible(node.admitted.values(), now);
    let actual = node.ledger.ids();
    if expected != actual {
        let extra: Vec<_> = actual.difference(&expected).map(|i| i.short()).collect();
        let lacking: Vec<_> = expected.difference(&actual).map(|i| i.short()).collect();
        return w.violation(
            "model",
            format!("node {n}: extra {extra:?}, lacking {lacking:?}"),
        );
    }

    for rec in node.ledger.iter() {
        // I2. Nothing expired, nothing beyond the horizon.
        if rec.expires() <= now || rec.expires() > now + MAX_HORIZON {
            return w.violation("expiry", format!("node {n} holds {rec:?} at t={now}"));
        }
        // I3. Every broadcast under an honest author's key was written by them.
        if let Some(b) = rec.as_broadcast()
            && let Some(&author) = w.pk_to_node.get(&b.author)
            && w.nodes[author].honest()
            && w.broadcasts.get(&rec.id()) != Some(&author)
        {
            return w.violation(
                "authenticity",
                format!("node {n} holds forged broadcast {rec:?}"),
            );
        }
    }

    // I4. An honest sealed message disappears before expiry only if an
    //     authorized party published a burn, and a valid burn is held.
    for (id, msg) in &w.sealed {
        if msg.expires <= now || !node.admitted.contains_key(id) || node.ledger.contains(id) {
            continue;
        }
        if !w.legit_burns.contains_key(id) {
            return w.violation(
                "burn-safety",
                format!("node {n} lost {} with no legitimate burn", id.short()),
            );
        }
        if !node.ledger.is_burned(&node.admitted[id]) {
            return w.violation(
                "burn-safety",
                format!("node {n} dropped {} without holding its burn", id.short()),
            );
        }
    }
    Ok(())
}

/// Invariants checked after the network has been flushed.
pub fn final_invariants(w: &mut World, good: &[usize]) -> Result<(), Violation> {
    // Records whose admission or expiry could legitimately differ between
    // nodes because of clock skew are excluded (spec §7.2).
    let skew = w.cfg.max_skew;
    let lo = w.global + skew;
    let hi = w.global + MAX_HORIZON - skew;
    let stable = |l: &Ledger| -> BTreeSet<RecordId> {
        l.iter()
            .filter(|r| r.expires() > lo && r.expires() <= hi)
            .map(|r| r.id())
            .collect()
    };

    // F1. Convergence.
    if let Some(&first) = good.first() {
        let reference = stable(&w.nodes[first].ledger);
        for &n in &good[1..] {
            let other = stable(&w.nodes[n].ledger);
            if other != reference {
                let d1 = reference.difference(&other).count();
                let d2 = other.difference(&reference).count();
                return w.violation(
                    "convergence",
                    format!("node {first} and node {n} differ by {d1}/{d2} records"),
                );
            }
        }
    }

    // F2. Delivery: every live, unburned message between good nodes arrived.
    let good_set: BTreeSet<usize> = good.iter().copied().collect();
    for (id, msg) in &w.sealed {
        let relevant = good_set.contains(&msg.sender) && good_set.contains(&msg.recipient);
        if relevant
            && msg.expires > lo
            && !w.legit_burns.contains_key(id)
            && msg.delivered_step.is_none()
        {
            return w.violation(
                "delivery",
                format!(
                    "{} from {} to {} never arrived",
                    id.short(),
                    msg.sender,
                    msg.recipient
                ),
            );
        }
    }

    // F3. Burns win: no good node holds a message burned by a good node.
    //     A burn published only by an excluded node may not have spread, and
    //     near expiry a burn can expire at fast clocks before reaching slow
    //     ones (spec §12.7), so the skew window is excluded.
    for (target, publishers) in &w.burn_publishers {
        let expires = w.sealed.get(target).map_or(0, |m| m.expires);
        if expires <= lo || !publishers.iter().any(|p| good_set.contains(p)) {
            continue;
        }
        for &n in good {
            if w.nodes[n].ledger.contains(target) {
                return w.violation(
                    "burn-propagation",
                    format!("node {n} still holds burned {}", target.short()),
                );
            }
        }
    }

    // F4. Persistence: every ledger survives a round trip through its file format.
    for &n in good {
        let node = &w.nodes[n];
        let now = node.now(w.global);
        let file = sneakerdrop::encode_ledger_file(node.ledger.iter());
        let decoded = sneakerdrop::bundle::decode_ledger_file(&file).expect("own file decodes");
        let mut reloaded = Ledger::new(*node.ledger.policy());
        reloaded.merge_bytes(decoded.entries.iter().map(Vec::as_slice), now);
        if reloaded.ids() != node.ledger.ids() {
            return w.violation(
                "persistence",
                format!("node {n}'s ledger changed across save/load"),
            );
        }
    }
    Ok(())
}
