//! Test vectors (spec Appendix A).
//!
//! Regenerate with `SNEAKERDROP_REGEN_VECTORS=1 cargo test -p sneakerdrop --test vectors`.

use std::path::PathBuf;

use serde_json::{Value, json};
use sneakerdrop::bundle::Summary;
use sneakerdrop::crypto::burn_hash;
use sneakerdrop::{
    Encoding, Identity, Item, Opened, PublicKey, Record, RecordId, SealOptions, armor,
    encode_bundle,
};

const CREATED: u64 = 1_800_000_000;
const EXPIRES: u64 = CREATED + 7 * 86_400;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn generate() -> Value {
    let alice = Identity::from_seed([0x11; 32]);
    let bob = Identity::from_seed([0x22; 32]);
    let identity = |id: &Identity| {
        json!({
            "seed": hex(&id.seed()),
            "public_key": hex(id.public().as_bytes()),
            "x25519_public": hex(&id.public().to_x25519()),
            "address": id.public().to_address(),
        })
    };

    let broadcast =
        Record::new_broadcast(&alice, CREATED, EXPIRES, 7, b"Hello from the dead drop.").unwrap();

    let ephemeral = [0x33; 32];
    let opts = SealOptions {
        stamp: 3,
        ..SealOptions::new(CREATED, EXPIRES)
    };
    let sealed = Record::new_sealed_with_ephemeral(
        &alice,
        &bob.public(),
        &opts,
        b"Meet at the usual place.",
        ephemeral,
    )
    .unwrap()
    .unwrap();
    let burn = Record::new_burn(sealed.record.id(), EXPIRES, sealed.burn_secret, 0);

    let salt = [0x44; 16];
    let ids = [broadcast.id(), sealed.record.id()];
    let summary = Summary::new(salt, &ids);
    let bundle = encode_bundle(&[
        Item::Record(broadcast.bytes().to_vec()),
        Item::Record(burn.bytes().to_vec()),
        Item::Summary(summary),
    ]);

    let record =
        |r: &Record| json!({ "hex": hex(r.bytes()), "id": r.id().to_hex(), "work": r.work() });
    json!({
        "description": "Sneakerdrop v1 test vectors. See docs/SPEC.md Appendix A.",
        "identities": { "alice": identity(&alice), "bob": identity(&bob) },
        "broadcast": {
            "author": "alice", "created": CREATED, "expires": EXPIRES, "stamp": 7,
            "content_utf8": "Hello from the dead drop.",
            "record": record(&broadcast),
        },
        "sealed": {
            "sender": "alice", "recipient": "bob", "created": CREATED, "expires": EXPIRES, "stamp": 3,
            "content_utf8": "Meet at the usual place.",
            "ephemeral_secret": hex(&ephemeral),
            "burn_secret": hex(&sealed.burn_secret),
            "burn_hash": hex(&burn_hash(&sealed.burn_secret)),
            "record": record(&sealed.record),
        },
        "burn": { "target": "sealed", "record": record(&burn) },
        "bundle": {
            "items": ["broadcast", "burn", "summary(salt, [broadcast.id, sealed.id])"],
            "summary_salt": hex(&salt),
            "hex": hex(&bundle),
            "armor_b64": armor(&bundle, Encoding::Base64),
            "armor_b32": armor(&bundle, Encoding::Base32),
        },
    })
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/v1.json")
}

#[test]
fn vectors_match() {
    let generated = generate();
    if std::env::var_os("SNEAKERDROP_REGEN_VECTORS").is_some() {
        std::fs::write(
            path(),
            serde_json::to_string_pretty(&generated).unwrap() + "\n",
        )
        .unwrap();
    }
    let stored: Value =
        serde_json::from_str(&std::fs::read_to_string(path()).expect("testvectors/v1.json"))
            .unwrap();
    assert_eq!(
        generated, stored,
        "implementation output differs from testvectors/v1.json"
    );
}

/// Checks the stored vectors by parsing, not by regenerating, the way an
/// independent implementation would.
#[test]
fn vectors_verify_independently() {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path()).unwrap()).unwrap();
    let s = |p: &str| v.pointer(p).unwrap().as_str().unwrap().to_string();

    let bob = Identity::from_seed(unhex(&s("/identities/bob/seed")).try_into().unwrap());
    let alice_pk = PublicKey::from_address(&s("/identities/alice/address")).unwrap();

    let broadcast = Record::parse(unhex(&s("/broadcast/record/hex"))).unwrap();
    assert_eq!(broadcast.id().to_hex(), s("/broadcast/record/id"));
    assert_eq!(broadcast.as_broadcast().unwrap().author, alice_pk);

    let sealed = Record::parse(unhex(&s("/sealed/record/hex"))).unwrap();
    assert_eq!(sealed.id().to_hex(), s("/sealed/record/id"));
    let Opened::Message(msg) = bob.open(&sealed) else {
        panic!("bob cannot open vector")
    };
    assert_eq!(msg.sender, alice_pk);
    assert_eq!(msg.content, s("/sealed/content_utf8").as_bytes());
    assert_eq!(hex(&msg.burn_secret), s("/sealed/burn_secret"));

    let burn = Record::parse(unhex(&s("/burn/record/hex"))).unwrap();
    assert!(burn.burns(&sealed));

    let incoming = sneakerdrop::sync::read_any(s("/bundle/armor_b32").as_bytes());
    assert_eq!(
        incoming.records,
        vec![broadcast.bytes().to_vec(), burn.bytes().to_vec()]
    );
    let has = incoming.summaries[0].matcher();
    assert!(has(&broadcast.id()) && has(&sealed.id()) && !has(&RecordId([0; 32])));
}

/// A v1 reader skips v0 ledgers (spec §9.3) without error.
#[test]
fn v0_ledger_is_skipped() {
    let v0 = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/v0/example.snk"),
    )
    .unwrap();
    let d = sneakerdrop::dearmor(&v0);
    assert_eq!(d.other_versions, 5);
    assert_eq!((d.blocks.len(), d.failed), (0, 0));
    let incoming = sneakerdrop::sync::read_any(v0.as_bytes());
    assert!(incoming.records.is_empty() && incoming.failed == 0);
}
