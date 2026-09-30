# Simulation and testing

Sneakerdrop is meant for networks you can't observe: people carrying USB sticks,
radios that only transmit, clocks nobody has set. Its correctness can't be
checked by running a few nodes on a laptop, so it is checked in three layers.

| Layer | Where | What it establishes |
|-------|-------|---------------------|
| Unit and property tests | `crates/sneakerdrop/src/*`, `tests/merge_laws.rs` | Codecs round-trip and reject non-canonical input. Parsers never panic. The ledger satisfies the merge laws of spec §8. |
| Test vectors | `testvectors/v1.json`, `tests/vectors.rs` | The wire format is pinned. Other implementations can check against it. |
| Deterministic simulation | `crates/sneakerdrop-sim` | The protocol keeps its promises across whole networks, under faults and attack. |

## Running

```bash
cargo test --workspace                               # everything, ~30 s
cargo run --release -p sneakerdrop-sim -- list       # scenarios
cargo run --release -p sneakerdrop-sim -- run --scenario chaos --seed 7
cargo run --release -p sneakerdrop-sim -- sweep --seeds 100
cargo run --release -p sneakerdrop-sim -- sweep --scenarios hostile,morse --from 1000 --seeds 500
```

A run is a pure function of its scenario and seed. To reproduce a failing run,
re-run it with `--trace`, which prints every seal, read, burn, meeting and
radio transmission, followed by the violation:

```
$ sneakerdrop-sim run --scenario badclock --seed 6 --trace 2>&1 | grep 9255814177a1
[  409] node 3 seals 9255814177a1 to node 0
[  458] node 0 reads 9255814177a1 after 49h
[  476] node 0 burns 9255814177a1
```

## The simulated world

Time advances in one-hour steps from a fixed epoch.

- **Villages.** Residents meet at random. At each meeting they either swap USB
  ledger files (spec §10.1) or run the three-message reconciliation (§10.3).
- **Couriers** wander between villages and meet whoever is there.
- **Radio links** push records one way (§10.2) from a sender to every listener
  in another village. Records go out as armored text, one bundle per record,
  with a few older records repeated to cover losses.
- **Partitions** can cut a village off for a period.
- **Users** compose broadcasts and sealed messages to random honest nodes, with
  random lengths and TTLs (some at the 365-day maximum). Recipients read by trial
  decryption, and may burn what they read after a random delay. Senders
  occasionally retract.

Every transfer goes through the real encodings: ledger files, bundles, and
armor. The same bytes a real node would emit are damaged, decoded, and admitted.

### Faults

| Fault | Model |
|-------|-------|
| USB truncation | A copied ledger file is cut at a random byte (crash mid-write, yanked stick) |
| USB bit rot | One random bit of a copied file flips |
| Reconciliation loss | Any of the three messages is lost |
| Radio noise | Per-character substitution and per-line loss, plus chatter around blocks |
| Morse | Base32 armor. Each listener's decoder reports all upper or all lower case |
| Clock skew | Honest clocks are skewed within ±3 days (inside the 7-day tolerance of §6) |
| Bad clock | One node lags by 10 days (outside tolerance) |

### Adversaries

Adversaries are full participants. They hold ledgers, meet people, and relay.
They build malicious records by hand from the wire format, not with the
library's builders.

| Adversary | Behaviour |
|-----------|-----------|
| Tamperer | Censors 20% of what it relays and flips a random bit in some of the rest |
| Forger | Broadcasts under honest authors' keys, and sends sealed messages whose plaintext claims an honest sender |
| BurnForger | Burns with guessed secrets, burns with outliving expiries, and re-stamped copies of real burns |
| Replayer | Hoards everything it sees and replays the hoard forever, including records that have since expired |
| Flooder | Well-formed junk: random sealed records, reserved kinds, burns aimed at nothing, records exactly at the acceptance horizon, and garbage |
| Liar | Answers reconciliation with the initiator's own summary |

Each adversary injects at most a few new records per transfer. Without proof of
work, an unbounded flooder grows every ledger without limit; the `pow`
scenario shows admission policy rejecting unground junk.

## Invariants

These are checked for every honest node every few simulated hours (the `I`
checks), whenever a message is opened (`O`), created (`P`), or received over
radio (`C`), and after a final fault-free flush in which all well-clocked
honest nodes sync until nothing changes (`F`). They are the properties listed
in spec Appendix B.

| ID | Property |
|----|----------|
| I1 | Ledger = `visible(R, t)` recomputed from scratch from every record the node admitted (spec §8.1) |
| I2 | No stored record is expired or beyond the horizon |
| I3 | Every broadcast under an honest key was written by that key's owner |
| I4 | A sealed message vanishes before expiry only if its sender or recipient published a burn, and the node holds a valid burn |
| O1 | Messages open only for their true recipient, with true sender and content. Honest messages never open as forged |
| P1 | Sealed records contain no identity key, in either form |
| C1 | A radio block the channel didn't corrupt is always decoded |
| F1 | All well-clocked honest nodes converge (outside the skew window of §7.2) |
| F2 | Every unexpired, unburned message between them was delivered |
| F3 | No burn by one of them failed to win everywhere |
| F4 | Every ledger survives its own file format |

## Scenarios

| Scenario | Network | Faults | Adversaries |
|----------|---------|--------|-------------|
| `baseline` | 3 villages × 4, 2 couriers | none | none |
| `radio` | villages linked only by radio | noisy base64 | none |
| `morse` | villages linked only by radio | noisier, base32, no case | none |
| `hostile` | baseline | none | one of each |
| `chaos` | baseline plus radio | all, ±3-day skew, a 7-day partition | one of each |
| `badclock` | baseline, long TTLs | one node 10 days slow | none |
| `pow` | baseline, 6-bit minimum work | none | Flooder, BurnForger |
| `soak` | 6 villages × 6, 4 couriers, 60 days | as chaos | one of each |

## Does the harness catch bugs?

A harness that never fails proves nothing, so the simulator was mutation-tested
by planting bugs in the protocol library and running `hostile`, `chaos`, and
`morse` over three seeds:

| Planted bug | Caught by |
|-------------|-----------|
| Broadcast signatures not verified | I3 at step 6 |
| Sealed inner signature not verified | O1 at step 16 |
| Burns dropped when their target is absent | I1 at step 6 |
| Burn doesn't remove a present target | I1 at step 60 |
| Sealed record admitted despite a stored burn | I1 at step 102 |
| Expiry off by one second | I1 at step 42 |
| Horizon not enforced | I2 at step 42 (a Tamperer bit flip pushed an expiry out to year 4.4 million) |
| Burns valid without the secret | I4 at step 132 |
| Base32 armor decoded case-sensitively | C1 at step 12 |
| Sealed header not bound as AEAD associated data | not caught: equivalent mutant (see below) |

The survivor is a genuine redundancy in the design. The inner signature
already covers the header (spec §5.4.1 step 7), so a tampered header is caught
as *forged* even without AEAD binding. The base32 bug initially survived too,
because the Morse channel only ever upper-cased text. That gap led to the C1
invariant and per-listener case.

## What the simulator found

- **Merge needed to advance time even with no input.** Merging an empty set at a
  later time left expired records in place. Found by the `pairwise_sync_converges`
  property. `Ledger::merge` now always expires first.
- **Flipping a `kind` bit yields a valid record.** A single bit flip can turn any
  record into a reserved kind, which relays must carry (§5.6). This is harmless
  and now documented in the spec, but it explains why `hostile` ledgers are
  dominated by junk (about 300 records per node, against about 60 honest ones).
- **Horizon divergence is transient.** The `badclock` node rejects long-lived
  records, as §7.2 predicts, while everyone else converges. The spec now says the
  divergence is transient and how to compare ledgers around it.
- **A burn can lose a race with expiry.** A burn and its target expire
  together, so near expiry, fast-clocked nodes drop the burn before it reaches
  slow-clocked nodes that already hold the target (`chaos` seeds 125 and 140).
  Those nodes keep the burned ciphertext until it expires by their own clock.
  This is harmless and now documented in spec §12.7, and F3 excludes the skew
  window as F1 and F2 already did.
- **Burns from unreachable nodes don't spread.** An early version of F3 demanded
  otherwise (`badclock` seed 6). That was a harness bug, not a protocol one: a
  burn can't propagate from a node nobody meets.
