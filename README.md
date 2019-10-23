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
- It would be fairly trivial to observe traffic patterns of messaging, but the 
  content is secure. If you're looking to remain invisible, you'll want to find
  some way of adding cryptographically secure noise to hide real traffic within.
- sneakerdrop is alpha software, and has not yet had a security audit.

Quickstart
==========

First things first, you'll need a working GPG installation. By default,
we'll default to your signing key with GPG, but you can override this
with the `SNEAKERDROP_SENDER` environment variable. Set this to the email
or name of the private key you want to send.

Now let's broadcast a message to the ledger!

```bash
$ bin/sneakerdrop broadcast
(sea1)➜  sneakerdrop git:(master) ✗ bin/sneakerdrop broadcast
=== Sneakerdrop ===
Broadcasting from adrian@adrianpike.com to ledger.snk (and STDOUT).
Type your message, and ^d to finish...
Hey world! This is my first Sneakerdrop message. It's pretty cool - and it's going to save it in the ledger, signed by my key.

^d
Saving f5dd6aec-9518-42fa-b1b1-43b97d1f6b92...
(sea1)➜  sneakerdrop git:(master) ✗
```

Neat! Now the file called `ledger.snk` has the contents of that message. You can
share it with someone else at will. Also - STDIN and STDOUT are kept clean of
unimportant stuff, so you can pipe it to/from packet radio interfaces, network
pipes, and other fun.

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

- Make a real spec.
- Rewrite the ledger format to be more compact, extensible, and introspectable.
- Build non-Ruby reference implementations
- Configuration and setup tooling.
- Build real interface, including MessageDecorator

