sneakerdrop
===========

A sneakernet meets a dead drop. Use it for anonymous communication over low
bandwidth radio links, USB keys, morse code flashlights, or any other
non-realtime, potentially offline communication strategy.

---

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

sneakerdrop supports two methods of cryptographically secure communication.

 - Signed broadcasts, visible to anyone with access to a sneakerdrop ledger.
 - Individual one-to-one messages.

Gotchas
=======

Due to the nature of this software, it's only fair to start with the gotchas;

- Your public keys _will_ get exposed to the ledger. If you need true anonymity,
  (and you should), generate new keys.
- sneakerdrop currently relies entirely on gpg. A zero-day in GPG is a zero-day
  in sneakerdrop.
- sneakerdrop is alpha software, and has not yet had a security audit.

Quickstart
==========

First things first, you'll need a working GPG installation.

Implementation Details
======================

The core component of a Sneakerdrop consists of the Ledger. The Ledger contains
all the message contents, separated by a preamble and a postamble.

Sneakerdrop ledgers are simultaneously a database of messages and a transaction
history.

Messages can only be added to a ledger. The content of a message does get removed
when a signed read receipt shows up, or a message expires. A read receipt does not
get removed until its companion message is expired, so that a read receipt eventually
gets replicated out to the entire sneakernet.

One-to-one messages must have a maximum expiration of 1 year.

Roadmap
=======

- Move to Binary instead of ASCII armored. Maybe Base64?
- Make a real spec
- Build non-Ruby reference implementations
- Configuration and setup tool
- Build real interface, including MessageDecorator

