sneakerdrop
===========

A sneakernet meets a dead drop. Use it for anonymous communication over low
bandwidth radio links, USB keys, morse code flashlights, or any other
non-realtime, potentially offline communication strategy.

---

Sneakerdrop supports both one-to-one private messaging and one-to-many public
broadcasting, even when individuals are separated by many hops.

Imagine Alice and Bob need to pass messages, but don't want to reveal their
presence directly to each other or to anyone monitoring them. Alice sends a
message to her sneakerdrop, which adds it to a local `ledger`. She `syncs` the
`ledger` to a USB drive, and passes the drive over to Carol. Meanwhile, Bob
has done the same `sync`ing and passing of his own USB stick with his friend
Dan.

Dan and Carol have coffee and `sync` their sneakerdrop `ledger`s, which has the
effect of both Alice and Bob's messages to each other living on both USB sticks.

Carol brings her stick back to Alice, Alice syncs, and now Alice has received
Bob's messages.

Dan, however, has a problem - he cannot travel to Bob anymore to sync his USB
stick. Luckily, they both have FM radio equipment, so Dan broadcasts just the
ledger updates to Bob over PSK500. It takes a little while longer, but it works.

These are the kind of complicated communications topologies that sneakerdrop is
built to provide.

Sneakerdrop is decentralized and provides no communication of its own, and so
requires users to devise their own strategy for passing messages. It's simply a
tool for making the crypto signing, verifying, and database synchronization
tasks much much easier.

Sneakerdrop supports three kinds of record:

 - **Broadcasts**: signed public messages, visible to anyone with a ledger.
 - **Sealed messages**: one-to-one messages. Nobody but the recipient can tell
   who sent them or who they're for.
 - **Burns**: once you've read a sealed message (or regret sending one), a burn
   deletes it from every ledger it reaches.

Gotchas
=======

Due to the nature of this software, it's only fair to start with the gotchas:

- Your broadcasts are signed by your key, and anyone can see them. If you need
  anonymity (and you should), generate a fresh identity for it.
- Sealed messages hide who is talking to whom, but not *where a record first
  appeared*. Whoever watches the ledgers can guess that a message was written
  near where it first showed up. See spec §12.2.
- There is no forward secrecy. If your secret key leaks, every message to you
  that someone kept a copy of can be read.
- It would be fairly trivial to observe traffic patterns of messaging, but the
  content is secure. If you're looking to remain invisible, you'll want to find
  some way of adding cryptographically secure noise to hide real traffic within.
- sneakerdrop is alpha software, and has not yet had a security audit.

Quickstart
==========

You'll need a Rust toolchain.

```bash
$ cargo install --path crates/sneakerdrop-cli
$ sneakerdrop init
Created identity. Your address is:
sd1q7rki7zsfglns7ef3jxaoqtz7wbavconctqabgghfsq2vbxvrts25aca
```

Give your address to the people you want to hear from. Now let's broadcast a
message to the ledger!

```bash
$ echo "Hey world! This is my first Sneakerdrop message." | sneakerdrop broadcast
Broadcast baa2ae2d3789 stored.
== SNEAKERDROP 1 B64 ==
U0RCAQGsAQEBAAAAAGrlBs4AAAAAAAAAAIfipH8yKZbZfIXabgdCef2CConNFOAA
mMcsoaqG9YzlAAAAAGq9ec4xSGV5IHdvcmxkISBUaGlzIGlzIG15IGZpcnN0IFNu
ZWFrZXJkcm9wIG1lc3NhZ2UuCmBD3Da5xiL6UGYvdXGD6nIz/5FFjIba96nLr8DW
n5ts23izKqmEwPsru2teN+5xM8ss8Df8ZmYFlQRhHnhIuAdaZ/qO
== PORDREKAENS ==
```

The message is now in your ledger (`~/.sneakerdrop/ledger.snk`), and the armored
block on stdout can be pasted, printed, piped into a modem, or read aloud. Just
like the original, stdout carries only protocol data and everything else goes
to stderr, so you can pipe it to and from packet radio interfaces, network
pipes, and other fun.

```bash
# Send a private message
$ echo "Meet at the usual place." | sneakerdrop send sd13xem7mqcf5zun5g2...

# Read everything you can
$ sneakerdrop show

# Merge with a USB stick (both directions)
$ sneakerdrop sync /media/usb/ledger.snk

# Take in anything: armored text with noise around it, bundles, ledger files
$ sneakerdrop import < overheard-on-the-radio.txt

# Send only what's new since last time, in base32 for Morse or other caseless channels
$ sneakerdrop export --new --b32 | your-modem

# Destroy a message you've read, everywhere the burn reaches
$ sneakerdrop burn 1291cb

# Reconcile over a slow two-way link (3 messages, only sends what's missing)
alice$ sneakerdrop reconcile start                       > to-bob
bob$   sneakerdrop reconcile respond --with-summary      < to-bob   > to-alice
alice$ sneakerdrop reconcile respond                     < to-alice > to-bob
bob$   sneakerdrop import                                < to-bob
```

Use `--home DIR` or `SNEAKERDROP_HOME` to keep several identities apart.

How it works
============

The full protocol is in **[docs/SPEC.md](docs/SPEC.md)**. In brief:

- Identities are Ed25519 keys; addresses are 59-character `sd1…` strings.
- Records are compact binary. A record's ID is the hash of its bytes, so
  nobody can shadow someone else's record by reusing its ID.
- Sealed messages use X25519, ChaCha20-Poly1305 and BLAKE3. The sender's
  identity and signature are inside the ciphertext, and lengths are padded.
- Every record expires, after at most a year.
- Burns are proved by revealing a secret that only the sender and recipient
  can compute. Anyone can check a burn, and it says nothing about who sent it.
- Merging is specified precisely enough to prove that ledgers converge,
  whatever order records arrive in.

Repository layout
=================

| Path | What |
|------|------|
| `docs/SPEC.md` | Protocol specification (v1) |
| `docs/SIMULATION.md` | How the protocol is tested |
| `crates/sneakerdrop` | Reference library. No I/O, no clock, no global RNG |
| `crates/sneakerdrop-cli` | The `sneakerdrop` command |
| `crates/sneakerdrop-sim` | Deterministic network simulator with fault injection and adversaries |
| `testvectors/` | Wire-format test vectors for v1, and a v0 ledger for posterity |

```bash
cargo test --workspace                                  # unit, property, vector and scenario tests
cargo run --release -p sneakerdrop-sim -- sweep --seeds 100
```

History
=======

Sneakerdrop v0 (2016) was a Ruby tool built on GnuPG with a JSON ledger. v1 is a
clean break: a new wire format, new cryptography, and a written spec. v0 ledgers
are not readable by v1 (they're skipped as an unknown version). The Ruby
implementation lives in git history.

Roadmap
=======

- ~~Make a real spec.~~ [docs/SPEC.md](docs/SPEC.md)
- ~~Rewrite the ledger format to be more compact, extensible, and introspectable.~~
- ~~Build non-Ruby reference implementations.~~ Rust.
- Set reconciliation with sketches, for big ledgers over radio.
- Forward secrecy via one-time prekeys.
- Forward error correction for very lossy channels.
- A real interface, and petnames for addresses.
- A security audit.
