# Sneakerdrop Protocol, Version 1

Status: Draft
Supersedes: the unversioned Ruby implementation ("v0", 2016)

## 1. Introduction

Sneakerdrop is a store-and-forward messaging protocol for links that are slow,
intermittent, one-way, or entirely offline: USB sticks carried between people,
packet radio, printed paper, a flashlight blinking Morse code. Every node keeps
a **ledger**, a set of self-contained **records**. Nodes exchange records by
whatever means they have, and ledgers merge.

This document defines:

- the record formats and their cryptography (§5, §6),
- how a node decides which records to accept and keep (§7),
- the merge semantics, and why they converge (§8),
- the on-disk ledger format, binary bundles, and text armor (§9),
- the synchronization procedures (§10).

### 1.1 Goals

1. **Convergence.** Two nodes that have seen the same records hold the same
   ledger, regardless of the order or path by which the records arrived.
2. **Integrity.** No party can alter, suppress, or impersonate another party's
   record, including by choosing a colliding identifier.
3. **Confidentiality and unlinkability of direct messages.** A sealed message
   reveals neither its sender nor its recipient to anyone except the recipient.
4. **Transport agnosticism.** Records are small, self-validating, and can be
   carried over binary or text channels, including lossy and case-insensitive
   ones, with no round-trips required.
5. **Bounded lifetime.** Every record expires, at most about one year after
   creation.

### 1.2 Non-goals

- Real-time delivery, delivery guarantees, or delivery ordering.
- Hiding *that* a node participates, or traffic analysis resistance beyond
  length padding. See §12.
- Forward secrecy and deniability. Version 1 has neither. See §12.
- Group (one-to-many private) messaging.

## 2. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted
as described in RFC 2119.

| Notation        | Meaning                                                            |
|-----------------|--------------------------------------------------------------------|
| `u8`            | one unsigned byte                                                  |
| `u64`           | unsigned 64-bit integer, big-endian, 8 bytes                       |
| `varint`        | unsigned LEB128, at most 10 bytes, **minimal encoding required**   |
| `bytes[n]`      | exactly `n` bytes                                                  |
| `a ‖ b`         | byte concatenation                                                 |
| `"text"`        | the ASCII bytes of `text`, no terminator                           |
| `now`           | the node's local clock, in whole seconds since the Unix epoch      |

A varint is non-minimal if it has trailing `0x80`/`0x00` continuation groups
that contribute no value bits (e.g. `0x80 0x00` for zero). Decoders MUST reject
non-minimal varints, and varints encoding values greater than `2^64 − 1`.

All parsing is **strict**: a record that has trailing bytes, truncated fields,
or non-minimal encodings is malformed. Strictness means that every record has
exactly one encoding, which matters because record identity is a hash of the
encoding (§5.2).

## 3. Cryptographic primitives

| Purpose              | Primitive                                                    |
|----------------------|--------------------------------------------------------------|
| Signatures           | Ed25519 (RFC 8032), strict verification (§3.1)               |
| Key agreement        | X25519 (RFC 7748) over the Montgomery form of Ed25519 keys   |
| Authenticated cipher | ChaCha20-Poly1305 (RFC 8439)                                 |
| Hash / KDF / MAC     | BLAKE3, in `derive_key` and `keyed_hash` modes               |

### 3.1 Ed25519 verification

Verifiers MUST reject a signature `(R, S)` over public key `A` if any of the
following hold:

- `A` or `R` is not the canonical encoding of a curve point (i.e. the encoding
  does not round-trip through decompression and compression),
- `A` or `R` is a point of small order,
- `S ≥ L`, where `L` is the order of the prime-order subgroup,
- the cofactorless equation `[S]B = R + [k]A` does not hold, where
  `k = SHA-512(R ‖ A ‖ M) mod L`.

This is the behaviour of `verify_strict` in `ed25519-dalek` 2.x, plus the
canonical-`A` check.

### 3.2 Hash contexts

`H(ctx, m)` denotes BLAKE3 `derive_key(ctx, m)`, which outputs 32 bytes.
`H64(ctx, m)` denotes the first 64 bytes of the extendable output of the same
construction. The context strings are:

| Name            | Context string                          |
|-----------------|-----------------------------------------|
| `CTX_ID`        | `sneakerdrop v1 record id`              |
| `CTX_SEAL`      | `sneakerdrop v1 seal key`               |
| `CTX_BURN`      | `sneakerdrop v1 burn`                   |
| `CTX_ADDR`      | `sneakerdrop v1 address checksum`       |
| `CTX_BUNDLE`    | `sneakerdrop v1 bundle checksum`        |
| `CTX_SUMMARY`   | `sneakerdrop v1 summary`                |

Signatures use these domain tags, which are prepended to the signed message
followed by a single `0x00` byte:

| Name            | Tag                           |
|-----------------|-------------------------------|
| `TAG_BROADCAST` | `sneakerdrop v1 broadcast`    |
| `TAG_SEALED`    | `sneakerdrop v1 sealed`       |

## 4. Identities

An identity is an Ed25519 key pair. The 32-byte public key `pk` is the
identity. Nothing else (names, emails) is bound to it by the protocol.

To receive sealed messages, the same key is used for X25519:

- The X25519 public key is the birational map of `pk` to Montgomery form,
  `u = (1 + y) / (1 − y)`, which is `crypto_sign_ed25519_pk_to_curve25519` in
  libsodium.
- The X25519 private scalar is the clamped lower 32 bytes of
  `SHA-512(seed)`, i.e. the same scalar Ed25519 signs with.

Using one key for both Ed25519 and X25519 is a deliberate trade-off. It gives
32-byte identities and lets anyone who has seen a broadcast reply privately to
its author. The joint security of this reuse is analysed in Thormarker,
*On using the same key pair for Ed25519 and an X25519 based KEM* (2021).

### 4.1 Addresses

An **address** is the text form of an identity, used for exchanging identities
out of band:

```
address = "sd1" ‖ base32lower(pk ‖ H(CTX_ADDR, pk)[0..3])
```

`base32lower` is the RFC 4648 alphabet, lower-cased, without padding. The
35-byte input encodes to exactly 56 characters, so an address is 59
characters. Decoders MUST accept upper case, MUST verify the checksum, and MUST
reject a `pk` that is not a valid, non-small-order, canonically encoded point.

## 5. Records

### 5.1 Common header

Every record begins with an 18-byte header:

```
record  = version:u8 ‖ kind:u8 ‖ expires:u64 ‖ stamp:u64 ‖ body
```

| Field     | Meaning                                                                 |
|-----------|-------------------------------------------------------------------------|
| `version` | `0x01`. Records with any other value are not version 1 records (§7.1).  |
| `kind`    | Record type: `0x01` broadcast, `0x02` sealed, `0x03` burn. `0x00` is invalid; `0x04`–`0xFF` are reserved for future kinds (§5.6). |
| `expires` | Absolute expiry time, in Unix seconds.                                  |
| `stamp`   | Arbitrary value chosen by the creator, used to grind proof of work (§7.3). |

The header layout is fixed for every kind so that a node can apply expiry and
admission rules to records it cannot otherwise parse.

The total record length MUST NOT exceed `MAX_RECORD_SIZE` (65 536) bytes. A
record's length is always supplied by its container (§9). Records are not
self-delimiting.

### 5.2 Record identity

```
id(record) = H(CTX_ID, record)
```

The ID is a 32-byte content hash of the complete encoded record. Two records
are the same record if and only if they have the same bytes. Because IDs are
derived rather than chosen, an attacker can't create a record with another
record's ID without finding a BLAKE3 collision (compare v0, where a
sender-chosen UUID let the first arrival shadow any later record with the same
UUID).

### 5.3 Broadcast (`kind = 0x01`)

A signed, public message.

```
body = author:bytes[32] ‖ created:u64 ‖ len:varint ‖ content:bytes[len] ‖ sig:bytes[64]
```

- `author` is the author's identity public key.
- `created` is the creation time in Unix seconds.
- `content` is opaque bytes. Clients SHOULD treat it as UTF-8 text.
- `sig` is an Ed25519 signature by `author` over
  `TAG_BROADCAST ‖ 0x00 ‖ P`, where `P` is every byte of the record before
  `sig`, header included.

A broadcast is **well-formed** if it parses strictly, `sig` verifies (§3.1),
and

```
created < expires ≤ created + MAX_TTL
```

Since the signature covers the header, only the author can produce a different
encoding (e.g. a re-ground `stamp`) of the same broadcast.

### 5.4 Sealed (`kind = 0x02`)

An encrypted message to one recipient. Neither the sender nor the recipient is
visible outside the ciphertext.

```
body = burn_hash:bytes[32] ‖ eph:bytes[32] ‖ ct:bytes[*]
```

`ct` runs to the end of the record. Let `AD` be every byte of the record before
`ct`, i.e. the header, `burn_hash`, and `eph`.

A sealed record is **well-formed** if `len(ct) ≥ 16 + 128` and
`(len(ct) − 16) mod 64 = 0`. Relays can check this and nothing more.

#### 5.4.1 Sealing

To seal `content` from sender `(sk_s, pk_s)` to recipient `pk_r`, valid until
`expires`:

1. Generate a fresh ephemeral X25519 key pair `(e, eph)`.
2. `r_u` = Montgomery form of `pk_r` (§4).
3. `ss = X25519(e, r_u)`. If `ss` is all zeroes, abort.
4. `okm = H64(CTX_SEAL, ss ‖ eph ‖ r_u)`. Let `key = okm[0..32]` and
   `burn_secret = okm[32..64]`.
5. `burn_hash = H(CTX_BURN, burn_secret)`.
6. Choose `stamp` and form `AD = 0x01 ‖ 0x02 ‖ expires ‖ stamp ‖ burn_hash ‖ eph`.
7. Form the plaintext:

   ```
   inner = sender:bytes[32] ‖ created:u64 ‖ len:varint ‖ content:bytes[len] ‖ sig:bytes[64] ‖ pad
   ```

   with `sender = pk_s` and
   `sig = Ed25519-Sign(sk_s, TAG_SEALED ‖ 0x00 ‖ pk_r ‖ AD ‖ Q)`, where `Q` is
   `inner` up to but not including `sig`. `pad` is zero bytes: at least enough
   to make `len(inner)` a multiple of `PAD_BLOCK` (64) and at least 128 bytes
   in total. Senders MAY add further multiples of 64 bytes of padding to hide
   the message length.
8. `ct = ChaCha20-Poly1305-Encrypt(key, nonce = 0^12, aad = AD, inner)`.

A zero nonce is safe because `key` is derived from a fresh ephemeral key, so it
encrypts exactly one message. Senders MUST NOT reuse `e`.

Binding `pk_r` into the inner signature prevents *surreptitious forwarding*: a
recipient can't re-seal a signed message to a third party so that it appears
to have been addressed to them.

#### 5.4.2 Opening

A node holding identity `(sk_r, pk_r)` attempts to open every sealed record
("trial decryption"):

1. `ss = X25519(scalar(sk_r), eph)`. If all zeroes, the record is *not for us*.
2. Derive `key` and `burn_secret` as in §5.4.1. If
   `H(CTX_BURN, burn_secret) ≠ burn_hash`, the record is *not for us*.
3. Decrypt `ct` with `AD`. If authentication fails, the record is *not for us*.
4. Parse `inner` strictly. `pad` MUST be all zeroes. Verify `sig` as in step 7
   of §5.4.1, with `pk_r` being our own key. Check
   `created < expires ≤ created + MAX_TTL`.
   If any check fails, the record is *forged*.

The outcomes are therefore *not for us*, *forged*, or an authenticated message
`(sender, created, content)`. Forged records remain in the ledger (relays
cannot tell them apart) but MUST NOT be displayed as authentic.

After opening a message, the recipient holds `burn_secret` and may later burn
it (§5.5).

### 5.5 Burn (`kind = 0x03`)

A burn destroys a sealed record everywhere it propagates. It is the v1 form of
v0's "read receipt".

```
body = target:bytes[32] ‖ secret:bytes[32]
```

A burn is well-formed if its body is exactly 64 bytes, giving a burn record of
exactly 82 bytes.

A burn `B` is **valid for** a record `T` if and only if:

- `T.kind = 0x02` (sealed),
- `B.target = id(T)`,
- `H(CTX_BURN, B.secret) = T.burn_hash`, and
- `B.expires = T.expires`.

Validity is a relation between two records, not a property of a burn alone. A
burn whose target is absent is simply held until it expires.

Only the sender and the recipient can compute `burn_secret`, so only they can
burn a sealed message, and anyone holding the target can check a burn without
learning who sent it. Requiring equal expiry makes a burn live exactly as long
as its target could, so it can serve as the target's tombstone (§8).

Once published, `secret` is public, and anyone can produce other burns for the
same target by varying `stamp`. These are valid, harmless duplicates, bounded
by admission policy (§7.3).

Broadcasts cannot be burned. A burn whose target is a broadcast is never valid
and has no effect.

### 5.6 Unknown kinds

A version 1 record with a reserved `kind` (`0x04`–`0xFF`) is well-formed if it
satisfies the common header rules. Nodes MUST store and relay such records like
any other. This lets new record kinds be deployed without every relay upgrading
first.

A consequence is that anyone can change the `kind` byte of any record to a
reserved value and get a well-formed, opaque record with a new ID. This is no
more powerful than injecting arbitrary junk (§12.6). The relabelled copy can
never be mistaken for the original, and the original is unaffected.

## 6. Constants

| Name              | Value                        |
|-------------------|------------------------------|
| `MAX_RECORD_SIZE` | 65 536 bytes                 |
| `MAX_TTL`         | 31 536 000 s (365 days)      |
| `MAX_HORIZON`     | 32 140 800 s (372 days)      |
| `PAD_BLOCK`       | 64 bytes                     |
| `SUMMARY_PREFIX`  | 8 bytes                      |
| `SALT_LEN`        | 16 bytes                     |
| `CHECKSUM_LEN`    | 4 bytes                      |

`MAX_HORIZON − MAX_TTL` (7 days) is the clock-skew tolerance between a creator
and a relay (§7.2).

## 7. Admission

Admission decides whether a node accepts an incoming record into its ledger.

### 7.1 Structural rules (deterministic)

A node MUST reject a record that:

- is longer than `MAX_RECORD_SIZE` or shorter than the 18-byte header,
- has `version ≠ 0x01` or `kind = 0x00`,
- is a broadcast, sealed, or burn record that is not well-formed (§5.3–§5.5).

These rules depend only on the record's bytes, so every conforming node
reaches the same verdict.

### 7.2 Time rules (clock-dependent)

A node MUST reject a record with `expires ≤ now` or `expires > now + MAX_HORIZON`.

These rules depend on the local clock. Creators MUST set
`expires ≤ now + MAX_TTL`. As long as the clocks of the creator and a relay
differ by less than `MAX_HORIZON − MAX_TTL`, the relay accepts every honestly
created record. A node whose clock is off by more than that may reject records
its peers accept. This is the only source of divergence among correctly
configured honest nodes, and implementations SHOULD warn when they see many
records rejected for exceeding the horizon.

Divergence at the horizon is transient. A lagging node that rejects a record
will accept the same record if it sees it again once its clock has advanced
far enough. When comparing ledgers, records that expire within the skew window
of either end (`now ± skew` and `now + MAX_HORIZON ± skew`) should be ignored.

### 7.3 Policy rules (configurable)

The **work** of a record is the number of leading zero bits in its ID. A node
MAY require a minimum work for each kind before it admits a record, to raise the
cost of flooding. Creators grind `stamp` to reach a target work.

A node MAY also impose storage quotas.

Policy rules sacrifice convergence. A node with a stricter policy than its
peers will hold a strict subset of their records. Networks SHOULD agree on a
common policy. The default policy is no minimum work and no quota.

## 8. Ledger state and merge

### 8.1 Definitions

Let `L` be a set of admitted records and `t` a time.

- `live(L, t) = { r ∈ L : r.expires > t }`
- `burned(L) = { T ∈ L : ∃ B ∈ L such that B is valid for T }`
- `visible(L, t) = live(L, t) \ burned(live(L, t))`

A node's stored ledger at time `t` MUST be equal to `visible(R, t)`, where
`R` is the set of every record the node has admitted. In other words, a node
discards expired records and burned sealed records, and keeps everything else,
including every burn, whether valid, duplicate, or targeting nothing it has
seen, until that burn expires.

### 8.2 Merge

To merge a set of incoming records `I` into stored ledger `S` at time `t`:

```
S' = visible(S ∪ admit(I, t), t)
```

### 8.3 Convergence

**Lemma.** For any sets `X`, `Y` and times `t₁ ≤ t₂`:

```
visible(visible(X, t₁) ∪ Y, t₂) = visible(X ∪ Y, t₂)
```

*Proof sketch.* A record `r ∈ X` is missing from `visible(X, t₁)` for one of two
reasons. Either it expired by `t₁`, in which case it has also expired by `t₂`,
or it is a sealed record burned by some live `B ∈ X`. Burns are never removed
except by expiry, and `B.expires = r.expires`, so `B ∈ visible(X, t₁)`
whenever `r` would otherwise be live, and `B` burns `r` again on the right-hand
side. No record can be missing from the left-hand side for any other reason,
and removing records never makes a burn valid for a record where it was not
valid before. ∎

**Theorem (convergence).** If two nodes have admitted sets `R₁` and `R₂` with
`R₁ = R₂`, their ledgers are identical at any common time `t`, no matter in
what order or in which batches the records arrived.

*Proof.* By induction over merges using the lemma: every sequence of merges
yields `visible(R, t)`. ∎

**Corollary.** After nodes A and B perform a complete sync (§10), both hold
`visible(R_A ∪ R_B, t)`, provided they agree on admission (§7.2, §7.3).

The simulator in this repository (`sneakerdrop-sim`) checks these properties
under randomized topologies, schedules, faults, and adversaries.

## 9. Encodings

### 9.1 Ledger file

A ledger file is how a node stores its ledger, and how two nodes sync by
copying a file. For example, "sync the USB stick" means merging the ledger file
on the stick.

```
file = "SNKLEDG" ‖ 0x01 ‖ entry*
entry = len:varint ‖ record:bytes[len]
```

- Entry order is not significant. Implementations SHOULD append new records in
  arrival order and rewrite the file on compaction.
- A reader that encounters a truncated final entry (e.g. after a crash
  mid-append) MUST ignore it and SHOULD truncate it on next write.
- A reader MUST apply admission (§7) to every entry. A ledger file is
  untrusted input, like any other.
- Writers SHOULD rewrite files atomically (write to a temporary file, flush,
  rename).

### 9.2 Bundle

A bundle is the unit of transfer over a stream or message channel.

```
bundle = "SDB" ‖ 0x01 ‖ item* ‖ checksum:bytes[4]
item   = 0x01 ‖ len:varint ‖ record:bytes[len]                                   ; RECORD
       | 0x02 ‖ salt:bytes[16] ‖ count:varint ‖ prefix:bytes[8] × count          ; SUMMARY
checksum = H(CTX_BUNDLE, everything before checksum)[0..4]
```

A receiver MUST discard the whole bundle if the checksum does not match or any
item fails to parse. An unknown item type is a parse failure.

The checksum only detects accidental corruption. Integrity against attackers
comes from record-level signatures and content addressing.

On lossy links, senders SHOULD keep bundles small (a single record per bundle
is valid), so that one corrupted byte loses as little as possible.

### 9.3 Text armor

Armor carries a bundle over text-only channels: terminals, pipes, email, paper,
voice, radio modes like PSK31 and RTTY, and Morse.

```
== SNEAKERDROP 1 <ENC> ==
<body lines>
== PORDREKAENS ==
```

- `<ENC>` is `B64` (RFC 4648 base64, standard alphabet) or `B32` (RFC 4648
  base32). `B32` is for case-insensitive channels such as Morse, and SHOULD be
  emitted in lower case, which is cheaper in PSK varicode.
- Writers SHOULD wrap body lines at 64 characters and SHOULD omit `=` padding.
- Readers MUST ignore all text outside the markers, allowing arbitrary noise,
  chatter, and headers between and around blocks.
- Readers MUST match markers case-insensitively and treat runs of whitespace
  inside a marker line as a single space.
- Readers MUST ignore whitespace in the body, MUST accept either case for `B32`,
  and MUST accept bodies with or without `=` padding.
- If a begin marker appears before the previous block's end marker, the reader
  MUST abandon the previous block and start a new one.
- A block that fails to decode or whose bundle fails its checksum is skipped,
  and the reader continues scanning.

The end marker is v0's, and v0's begin marker is `== SNEAKERDROP 0 ==`, so a
v1 reader will skip v0 blocks as blocks of an unknown version.

## 10. Synchronization

Records are self-contained, so *any* delivery of records to a node is a valid
sync. The procedures below describe how to decide which records to send.

### 10.1 Full transfer

The sender sends every record in its ledger, as a ledger file or as a bundle.
This is the right choice for high-bandwidth, low-coordination media such as USB
sticks. Both directions of a USB swap are full transfers.

### 10.2 Push (one-way, incremental)

For one-way links such as broadcast radio, the sender keeps a local cursor per
channel and sends only records admitted since the last transmission.
Retransmitting a record is harmless (it's idempotent), so senders MAY
periodically repeat records to cover losses. Cursors are local state and are
not part of the protocol.

### 10.3 Reconciliation (interactive)

For two-way links with limited bandwidth:

1. A → B: `SUMMARY(salt_A, prefixes of A's IDs)`.
2. B → A: a `RECORD` for every record in B's ledger whose prefix is not in
   A's summary, then `SUMMARY(salt_B, prefixes of B's IDs)`.
3. A merges, then A → B: a `RECORD` for every record in A's ledger whose
   prefix is not in B's summary.

The prefix of an ID under a salt is:

```
prefix(salt, id) = keyed_hash(H(CTX_SUMMARY, salt), id)[0..8]
```

A summary only affects what is sent *to its author*. A dishonest summary, such
as one that echoes the peer's own summary back, can only deprive its author of
records.

The salt MUST be fresh and random for each summary. Otherwise an attacker
could grind a junk record whose prefix collides with a victim record, so that
the victim record is always reported as "already held" and never transferred.
With fresh salts, an accidental collision between a node's own `n` records
suppresses a transfer with probability about `n² / 2⁶⁵` per round.

After step 3, both nodes hold `visible(R_A ∪ R_B, t)`, apart from any
prefix-collision misses.

## 11. Client behaviour (informative)

- **Displaying broadcasts:** show `author` as an address or a locally assigned
  petname. Sort by `created`, but remember that `created` is a claim by the
  author.
- **Displaying sealed messages:** show only those that open successfully,
  and mark *forged* ones as such or hide them.
- **Burning:** after reading a message, the recipient MAY publish a burn. A
  sender MAY burn a message to retract it. Clients SHOULD delay and batch burns
  (§12.3).
- **Replies:** the sender's `pk` inside an opened message is enough to reply.

## 12. Security considerations

### 12.1 What an observer learns

An observer who holds a ledger learns:

- every broadcast in full, including its author and claimed creation time,
- for each sealed record: its expiry, its padded length, and when and where it
  was first seen, *but not* its sender or recipient,
- which sealed records have been burned, and when each burn first appeared.

An observer of a *link* also learns who synced with whom, and when. Sneakerdrop
does not hide that.

### 12.2 Traffic analysis

The node where a sealed record or burn first appears is probably its sender
or recipient. Users who need to hide this SHOULD relay a record through
intermediate nodes before it appears anywhere they can be linked to, and MAY
publish decoy sealed records to themselves. Padding hides message lengths only
to within `PAD_BLOCK`, unless senders pad further.

### 12.3 Burns

A burn tells the whole network that a specific sealed message was read or
retracted. Its first appearance tends to identify the recipient's node. Clients
SHOULD delay burns by a random interval and publish them in batches.

### 12.4 Key compromise

There is no forward secrecy. Anyone who obtains a recipient's secret key can
open every sealed message to that recipient that they have stored, including
messages that honest nodes have since burned or expired. Anyone who obtains a
sender's key can forge messages from them but cannot read what they sent.

### 12.5 Non-repudiation

Inner signatures are transferable. A recipient can prove to a third party that
the sender wrote a message to them by revealing the record and its decrypted
plaintext, because the signature covers the recipient's key and the record
header. Version 1 does not offer deniable authentication.

### 12.6 Flooding

Anyone can create sealed records and burns without identifying themselves.
Proof of work (§7.3) and storage quotas are the only defences, and both reduce
convergence when nodes disagree on them.

### 12.7 Clock attacks

A node whose clock is set in the future discards records early and rejects
nothing.

Because a burn expires together with its target, a node whose clock runs slow
may receive a sealed record but never its burn. Once faster-clocked nodes have
expired the burn, they no longer relay it. The slow node then keeps the burned
ciphertext until the record expires by its own clock, up to its skew later than
everyone else. The target is never kept past its own expiry by the holder's
clock. A node whose clock is set in the past keeps records longer and may
reject records near the horizon. Neither lets an attacker forge, alter, or
resurrect records, because expiry times are signed or authenticated inside
every record that carries meaning.

### 12.8 Implementation hazards

- Ed25519 verification MUST be strict (§3.1). Otherwise signature malleability
  would let third parties create distinct encodings of a broadcast, and
  therefore distinct IDs.
- Implementations MUST compare MACs and checksums in constant time where secret
  data is involved (step 2 of §5.4.2).
- Implementations MUST bound memory when reading bundles and armor from
  untrusted input.

## 13. Changes from v0

| v0 (Ruby, 2016)                                        | v1                                                   |
|--------------------------------------------------------|------------------------------------------------------|
| JSON between `== SNEAKERDROP 0 ==` / `== PORDREKAENS ==` | Canonical binary records, optional text armor       |
| OpenPGP via GnuPG                                      | Ed25519 / X25519 / ChaCha20-Poly1305 / BLAKE3       |
| ~1.7 KB armored public key in every record             | 32-byte public key                                  |
| Sender-chosen UUID as ID (spoofable)                   | Content-addressed ID                                |
| Direct messages expose sender key, signature not verified | Sender, recipient, and signature inside ciphertext |
| Read receipts (unimplemented)                          | Burns, verifiable by anyone, no identity exposed    |
| Expiry (unimplemented)                                 | Mandatory `expires`, max 365 days                   |
| Merge = union keyed by UUID, first arrival wins        | Specified merge with a convergence proof            |

v1 does not read v0 ledgers.

## 14. Future work

- Set reconciliation with sketches (IBLT / minisketch) for large ledgers over
  radio.
- Forward secrecy via published one-time prekeys.
- Deniable authentication for sealed messages.
- Author retraction of broadcasts.
- Forward error correction and chunking for very lossy links.
- Group messages.

## Appendix A. Test vectors

`testvectors/v1.json` contains deterministic identities, records, IDs,
bundles, and armor produced by the reference implementation. The test suite
checks the reference implementation against it.

`testvectors/v0/example.snk` is a v0 ledger. A v1 reader must skip all five of
its blocks as blocks of another version (§9.3).

## Appendix B. Conformance properties

The reference simulator (`crates/sneakerdrop-sim`, described in
`docs/SIMULATION.md`) checks the following properties for honest nodes, under
random topologies, message loss and corruption, clock skew, and adversaries.
Other implementations are encouraged to check the same properties.

| ID | Property | Spec |
|----|----------|------|
| I1 | A node's ledger equals `visible(R, t)` computed from scratch | §8.1 |
| I2 | No stored record is expired or beyond the horizon | §7.2 |
| I3 | Every stored broadcast under an honest key was written by that key's owner | §5.3 |
| I4 | A sealed record disappears before expiry only if its sender or recipient published a burn, and a valid burn is held | §5.5, §8 |
| O1 | A sealed record opens as a message only for its true recipient, with its true sender and content. Forgeries open as *forged* or *not for us* | §5.4 |
| P1 | No sealed record contains any identity key, in Ed25519 or X25519 form | §5.4 |
| C1 | An armored block that was not corrupted in transit is always decoded, whatever its case | §9.3 |
| F1 | After a full sync, all honest nodes hold identical ledgers, outside the skew window | §8.3 |
| F2 | After a full sync, every unexpired, unburned sealed message has reached its recipient | §10 |
| F3 | After a full sync, no honest node holds a record burned by an honest node | §5.5 |
| F4 | A ledger is unchanged by writing and re-reading its ledger file | §9.1 |
