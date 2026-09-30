//! Adversarial behaviours. Adversaries speak the wire format directly and
//! build malicious records by hand, independently of the library's builders.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sneakerdrop::consts::{MAX_HORIZON, PAD_BLOCK};
use sneakerdrop::crypto::{CTX_SEAL, burn_hash, derive64};
use sneakerdrop::record::{HEADER_LEN, KIND_BROADCAST, KIND_BURN, KIND_SEALED, VERSION};
use sneakerdrop::{Identity, Record, RecordId, SealOptions};

use crate::config::Adversary;
use crate::world::{Bytes, World};

fn header(kind: u8, expires: u64, stamp: u64) -> Vec<u8> {
    let mut out = vec![VERSION, kind];
    out.extend_from_slice(&expires.to_be_bytes());
    out.extend_from_slice(&stamp.to_be_bytes());
    out
}

/// Most new records an adversary injects per transfer. Without proof of work
/// (spec §7.3), an unbounded flooder simply grows every ledger without limit;
/// the simulation models a bounded attacker instead.
const MAX_INJECT: usize = 4;

/// Transforms what an adversary sends during a transfer.
pub fn meddle(w: &mut World, n: usize, role: Adversary, candidates: Vec<Bytes>) -> Vec<Bytes> {
    let mut out: Vec<Bytes> = Vec::with_capacity(candidates.len());
    match role {
        Adversary::Tamperer => {
            let mut mutated = 0;
            for r in candidates {
                if w.rng.chance(0.2) {
                    continue; // censor
                }
                if mutated < MAX_INJECT && w.rng.chance(0.4) {
                    mutated += 1;
                    let mut b = r.to_vec();
                    let bit = w.rng.index(b.len() * 8);
                    b[bit / 8] ^= 1 << (bit % 8);
                    w.metrics.adversarial_injected += 1;
                    out.push(b.into());
                } else {
                    out.push(r);
                }
            }
        }
        Adversary::Forger => {
            out = candidates;
            let forged = forge(w, n);
            w.metrics.adversarial_injected += forged.len() as u64;
            out.extend(forged);
        }
        Adversary::BurnForger => {
            let mut forged = Vec::new();
            for r in &candidates {
                if forged.len() >= MAX_INJECT {
                    break;
                }
                let Ok(rec) = Record::parse(r.clone()) else {
                    continue;
                };
                if rec.as_sealed().is_some() && w.rng.chance(0.5) {
                    // Guess a secret; or use the right expiry but a guessed secret;
                    // or an expiry that outlives the target.
                    let secret = w.rng.array();
                    forged.push(Record::new_burn(rec.id(), rec.expires(), secret, 0));
                    forged.push(Record::new_burn(
                        rec.id(),
                        rec.expires() + 86_400,
                        secret,
                        1,
                    ));
                }
                if let Some(b) = rec.as_burn() {
                    // Re-stamp a real burn: a valid duplicate with a new ID.
                    forged.push(Record::new_burn(
                        b.target,
                        rec.expires(),
                        b.secret,
                        w.rng.range(2, u64::MAX),
                    ));
                }
            }
            w.metrics.adversarial_injected += forged.len() as u64;
            out = candidates;
            out.extend(forged.into_iter().map(|r| r.shared_bytes()));
        }
        Adversary::Replayer => {
            let mut hoard: Vec<(RecordId, Bytes)> = w.nodes[n]
                .hoard
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            hoard.sort_by_key(|(k, _)| *k);
            w.metrics.adversarial_injected += hoard.len() as u64;
            out = candidates;
            out.extend(hoard.into_iter().map(|(_, v)| v));
        }
        Adversary::Flooder => {
            out = candidates;
            let junk = junk(w, n);
            w.metrics.adversarial_injected += junk.len() as u64;
            out.extend(junk);
        }
        Adversary::Liar => out = candidates,
    }
    out
}

/// Well-formed junk that relays cannot distinguish from real traffic.
pub fn junk(w: &mut World, n: usize) -> Vec<Bytes> {
    let now = w.nodes[n].now(w.global);
    let mut out: Vec<Vec<u8>> = Vec::new();

    // A sealed-shaped record of random bytes.
    let mut sealed = header(
        KIND_SEALED,
        now + w.rng.range(3600, 5 * 86_400),
        w.rng.next(),
    );
    let blocks = 2 + w.rng.index(4);
    sealed.extend(w.rng.bytes(64 + 16 + PAD_BLOCK * blocks));
    out.push(sealed);

    // A reserved kind with a random body.
    let kind = w.rng.range(4, 256) as u8;
    let mut unknown = header(kind, now + w.rng.range(3600, 3 * 86_400), w.rng.next());
    let len = w.rng.index(100);
    unknown.extend(w.rng.bytes(len));
    out.push(unknown);

    // A burn aimed at nothing.
    let mut burn = header(KIND_BURN, now + w.rng.range(3600, 86_400), 0);
    burn.extend(w.rng.bytes(64));
    out.push(burn);

    // Occasionally, a record right at the acceptance horizon, to probe
    // clock-skew divergence (spec §7.2).
    if w.rng.chance(0.05) {
        let edge = now + MAX_HORIZON - w.rng.range(0, 2 * w.cfg.max_skew + 1);
        let mut rec = header(0x7f, edge, w.rng.next());
        rec.extend_from_slice(b"horizon probe");
        out.push(rec);
    }

    // Garbage that shouldn't parse at all.
    let len = w.rng.index(HEADER_LEN * 2);
    out.push(w.rng.bytes(len));

    out.into_iter().map(Bytes::from).collect()
}

/// Forgeries against honest identities.
fn forge(w: &mut World, n: usize) -> Vec<Bytes> {
    let honest = w.honest_nodes();
    let (Some(&victim), Some(&target)) = (w.rng.pick(&honest), w.rng.pick(&honest)) else {
        return vec![];
    };
    if victim == target {
        return vec![];
    }
    let now = w.nodes[n].now(w.global);
    let expires = now + 86_400;
    let victim_pk = w.nodes[victim].identity.public();
    let mut out = Vec::new();

    // 1. A broadcast claiming the victim as author, with a garbage signature.
    let mut b = header(KIND_BROADCAST, expires, 0);
    b.extend_from_slice(victim_pk.as_bytes());
    b.extend_from_slice(&now.to_be_bytes());
    let content = b"send all your bitcoin to mallory";
    b.push(content.len() as u8);
    b.extend_from_slice(content);
    b.extend(w.rng.bytes(64));
    out.push(Bytes::from(b));

    // 2. A sealed message to `target` whose plaintext claims the victim as
    //    sender, signed with the forger's own key.
    let forger: &Identity = &w.nodes[n].identity;
    let e: [u8; 32] = w.rng.array();
    let recipient = w.nodes[target].identity.public();
    let honest_shape = Record::new_sealed_with_ephemeral(
        forger,
        &recipient,
        &SealOptions::new(now, expires),
        b"it's me, your friend",
        e,
    );
    if let Ok(Some(sealed)) = honest_shape {
        let secret = x25519_dalek::StaticSecret::from(e);
        let r_u = recipient.to_x25519();
        let ss = secret.diffie_hellman(&x25519_dalek::PublicKey::from(r_u));
        let eph = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let okm = derive64(CTX_SEAL, &[ss.as_bytes(), &eph, &r_u]);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&okm[..32]));
        let split = HEADER_LEN + 64;
        let (ad, ct) = sealed.record.bytes().split_at(split);
        debug_assert_eq!(
            &ad[HEADER_LEN..HEADER_LEN + 32],
            &burn_hash(okm[32..].try_into().unwrap())
        );
        let nonce = Nonce::from_slice(&[0; 12]);
        if let Ok(mut inner) = cipher.decrypt(nonce, Payload { msg: ct, aad: ad }) {
            inner[..32].copy_from_slice(victim_pk.as_bytes());
            let ct = cipher
                .encrypt(
                    nonce,
                    Payload {
                        msg: &inner,
                        aad: ad,
                    },
                )
                .expect("encrypt");
            let mut forged = ad.to_vec();
            forged.extend_from_slice(&ct);
            out.push(Bytes::from(forged));
        }
    }
    out
}

trait Next {
    fn next(&mut self) -> u64;
}

impl Next for crate::rng::Rng {
    fn next(&mut self) -> u64 {
        rand_core::RngCore::next_u64(self)
    }
}
