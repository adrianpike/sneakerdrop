//! Transports. Every transfer goes through the real wire encodings (ledger
//! files, bundles, armor) so that codec bugs surface as invariant violations.

use sneakerdrop::bundle::{LEDGER_MAGIC, encode_bundle};
use sneakerdrop::codec::put_varint;
use sneakerdrop::sync::{missing, read_any, summarize};
use sneakerdrop::{Encoding, Item, armor};

use crate::config::{Adversary, Radio};
use crate::report::Violation;
use crate::world::{Bytes, Channel, World};

/// Records `from` is willing to send, after any adversarial meddling.
fn outgoing(w: &mut World, from: usize, candidates: Vec<Bytes>) -> Vec<Bytes> {
    match w.nodes[from].role {
        None => candidates,
        Some(role) => crate::adversary::meddle(w, from, role, candidates),
    }
}

fn ledger_file(records: &[Bytes]) -> Vec<u8> {
    let mut out = LEDGER_MAGIC.to_vec();
    for r in records {
        put_varint(&mut out, r.len() as u64);
        out.extend_from_slice(r);
    }
    out
}

fn bundle(records: &[Bytes], extra: Option<Item>) -> Vec<u8> {
    let mut items: Vec<Item> = records.iter().map(|r| Item::Record(r.to_vec())).collect();
    items.extend(extra);
    encode_bundle(&items)
}

fn to_shared(records: Vec<Vec<u8>>) -> Vec<Bytes> {
    records.into_iter().map(Bytes::from).collect()
}

/// Physical damage to a file in transit.
fn damage_file(w: &mut World, mut file: Vec<u8>) -> Vec<u8> {
    if w.rng.chance(w.cfg.faults.usb_truncate) {
        let at = w.rng.index(file.len() + 1);
        file.truncate(at);
    }
    if !file.is_empty() && w.rng.chance(w.cfg.faults.usb_bitrot) {
        let at = w.rng.index(file.len());
        file[at] ^= 1 << w.rng.index(8);
    }
    file
}

/// Both parties copy their whole ledger file to the other (spec §10.1).
pub fn usb_swap(w: &mut World, a: usize, b: usize) {
    w.metrics.meetings_usb += 1;
    w.trace(|| format!("usb {a} <-> {b}"));
    for (from, to) in [(a, b), (b, a)] {
        let records: Vec<Bytes> = w.nodes[from]
            .ledger
            .iter()
            .map(|r| r.shared_bytes())
            .collect();
        let records = outgoing(w, from, records);
        let file = damage_file(w, ledger_file(&records));
        w.metrics.bytes_usb += file.len() as u64;
        let incoming = read_any(&file);
        w.deliver(to, &to_shared(incoming.records), Channel::Usb);
    }
}

/// The three-message reconciliation of spec §10.3, with `a` initiating.
pub fn reconcile(w: &mut World, a: usize, b: usize) {
    w.metrics.meetings_reconcile += 1;
    w.trace(|| format!("reconcile {a} -> {b}"));
    let loss = w.cfg.faults.reconcile_loss;

    // 1. A -> B: summary.
    let s_a = summarize(&w.nodes[a].ledger, &mut w.rng);
    let msg1 = encode_bundle(&[Item::Summary(s_a)]);
    w.metrics.bytes_reconcile += msg1.len() as u64;
    if w.rng.chance(loss) {
        return;
    }
    let Some(s_a) = read_any(&msg1).summaries.pop() else {
        return;
    };

    // 2. B -> A: what A lacks, and B's summary.
    let to_a: Vec<Bytes> = missing(&w.nodes[b].ledger, &s_a)
        .into_iter()
        .map(|r| r.shared_bytes())
        .collect();
    let to_a = outgoing(w, b, to_a);
    let s_b = if w.nodes[b].role == Some(Adversary::Liar) {
        // Echo A's own summary back, claiming to hold everything A holds.
        s_a
    } else {
        summarize(&w.nodes[b].ledger, &mut w.rng)
    };
    let msg2 = bundle(&to_a, Some(Item::Summary(s_b)));
    w.metrics.bytes_reconcile += msg2.len() as u64;
    if w.rng.chance(loss) {
        return;
    }
    let mut incoming = read_any(&msg2);
    w.deliver(a, &to_shared(incoming.records), Channel::Reconcile);
    let Some(s_b) = incoming.summaries.pop() else {
        return;
    };

    // 3. A -> B: what B lacks.
    let to_b: Vec<Bytes> = missing(&w.nodes[a].ledger, &s_b)
        .into_iter()
        .map(|r| r.shared_bytes())
        .collect();
    let to_b = outgoing(w, a, to_b);
    let msg3 = bundle(&to_b, None);
    w.metrics.bytes_reconcile += msg3.len() as u64;
    if w.rng.chance(loss) {
        return;
    }
    w.deliver(b, &to_shared(read_any(&msg3).records), Channel::Reconcile);
}

/// Fault-free full exchange, used to flush the network before final checks.
pub fn clean_sync(w: &mut World, a: usize, b: usize) {
    for (from, to) in [(a, b), (b, a)] {
        let records: Vec<Bytes> = w.nodes[from]
            .ledger
            .iter()
            .map(|r| r.shared_bytes())
            .collect();
        let file = ledger_file(&records);
        w.deliver(to, &to_shared(read_any(&file).records), Channel::Usb);
    }
}

/// One-way push over a noisy text channel (spec §10.2), one record per
/// bundle so that corruption loses as little as possible.
///
/// Checks that every block the channel happened not to corrupt is received:
/// noise may lose records, but the codec must never lose them on its own.
pub fn radio_transmit(
    w: &mut World,
    sender: usize,
    listeners: &[usize],
    radio: &Radio,
) -> Result<(), Violation> {
    w.metrics.radio_transmissions += 1;
    let node = &w.nodes[sender];
    let mut records: Vec<Bytes> = node
        .ledger
        .since(node.radio_cursor)
        .map(|(_, r)| r.shared_bytes())
        .collect();
    // `iter()` is in arrival order, so everything before the new tail is old.
    let older: Vec<Bytes> = node
        .ledger
        .iter()
        .take(node.ledger.len() - records.len())
        .map(|r| r.shared_bytes())
        .collect();
    w.nodes[sender].radio_cursor = w.nodes[sender].ledger.last_seq();
    for _ in 0..radio.repeats {
        if let Some(r) = w.rng.pick(&older) {
            records.push(r.clone());
        }
    }
    let records = outgoing(w, sender, records);
    if records.is_empty() {
        return Ok(());
    }
    let encoding = if radio.morse {
        Encoding::Base32
    } else {
        Encoding::Base64
    };
    let blocks: Vec<String> = records
        .iter()
        .map(|r| armor(&bundle(std::slice::from_ref(r), None), encoding))
        .collect();
    w.trace(|| format!("radio {sender} -> {listeners:?}: {} records", records.len()));
    for &to in listeners {
        let mut text = String::from("CQ CQ CQ de sneakerdrop\n");
        let mut clean = Vec::new();
        for (block, record) in blocks.iter().zip(&records) {
            let (received, corrupted) = noisy(w, block, radio);
            if !corrupted {
                clean.push(record);
            }
            text.push_str(&received);
            text.push_str("QSL?\n");
        }
        // Morse has no case: each listener's decoder picks one.
        if radio.morse {
            text = if w.rng.chance(0.5) {
                text.to_ascii_uppercase()
            } else {
                text.to_ascii_lowercase()
            };
        }
        w.metrics.bytes_radio += text.len() as u64;
        let incoming = read_any(text.as_bytes());
        w.metrics.radio_blocks_lost += records.len().saturating_sub(incoming.records.len()) as u64;
        for r in clean {
            if !incoming
                .records
                .iter()
                .any(|got| got.as_slice() == r.as_ref())
            {
                return w.violation(
                    "codec",
                    format!("radio {sender} -> {to}: uncorrupted block was not decoded"),
                );
            }
        }
        w.deliver(to, &to_shared(incoming.records), Channel::Radio);
    }
    Ok(())
}

/// A lossy text channel: dropped lines and corrupted characters. Returns the
/// received text and whether anything was damaged.
fn noisy(w: &mut World, text: &str, radio: &Radio) -> (String, bool) {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= ";
    let mut out = String::with_capacity(text.len());
    let mut corrupted = false;
    for line in text.lines() {
        if w.rng.chance(radio.line_loss) {
            corrupted = true;
            continue;
        }
        for c in line.chars() {
            if w.rng.chance(radio.char_error) {
                let r = ALPHABET[w.rng.index(ALPHABET.len())] as char;
                corrupted |= r != c;
                out.push(r);
            } else {
                out.push(c);
            }
        }
        out.push('\n');
    }
    (out, corrupted)
}
