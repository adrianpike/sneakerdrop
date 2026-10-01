# Proposal: Private groups with a preshared key

Status: Proposal
Targets: Sneakerdrop v1 (docs/SPEC.md), as an extension
Depends on: content types (spec §5.4.3)

## 1. Summary

A group is a random 256-bit key `K` shared among its members. A group post is
a sealed record (kind `0x02`) encrypted under a key derived from `K` and
signed inside the ciphertext by the poster. Relays cannot tell group posts from
direct messages, or one group from another, and need no changes.

There is no owner and there are no membership operations. A member is anyone
who holds `K`. To remove someone, the remaining members **fork**: one of them
creates a new group and invites the others, linking it to the old one.

## 2. Goals and non-goals

Goals:

- Groups of 3–4 people, up to about 20.
- One record per post, whatever the group size.
- Group posts are indistinguishable from direct messages to everyone outside
  the group.
- New members can read the group's history, meaning every post still in the
  ledgers.
- Every post is authenticated as coming from a specific identity.
- No changes for relays, and no new record kinds.

Non-goals:

- Enforced membership. Anyone holding `K` can read and post, and can give `K`
  to anyone else.
- Anonymous posting within a group.
- Forward secrecy. A leaked `K` exposes every post made under it that is still
  in any ledger.
- Consensus on membership. Each member keeps their own roster.

## 3. Design rationale

Three alternatives were considered (see the discussion leading to this
proposal):

- **Fan-out** (sealing a copy of each post to every member) costs O(N) records
  per post: about 4.6 KB for 20 members, which is 75 s at PSK500.
- **An owner who signs membership operations** gives one shared roster, but
  freezes the group if the owner disappears. Recovering from that needs a
  recovery key or a multi-admin operation DAG. A DAG suffers from backdating:
  without trusted time, a removed admin can sign operations that appear
  concurrent with their own removal.
- **A preshared key** has no membership protocol at all, so there is nothing to
  order or resolve. Its weaknesses (no enforced membership, and removal needs a
  new key) are acceptable for small groups whose members trust each other and
  often meet in person.

If larger or less trusting groups need it later, owner-signed membership can be
added as an optional layer using the same post format.

## 4. Group keys

### 4.1 The key

`K` is 32 bytes from a cryptographically secure random number generator.
Clients MUST NOT derive `K` from a passphrase or any other human-chosen
secret. Group posts are public, and trial decryption is cheap, so anyone
holding a ledger could test passphrase guesses offline, without limit, against
every post.

### 4.2 Text form

For exchange in person, as a QR code, on paper, or by voice:

```
group_key_text = "sdg1" ‖ base32lower(K ‖ H(CTX_GROUP_CHECK, K)[0..3])
```

That is 60 characters, encoded like addresses (spec §4.1). Decoders MUST accept
upper case and MUST verify the checksum. A group key is a secret, unlike an
address.

### 4.3 Derived values

| Value          | Definition                          | Visible to                    |
|----------------|-------------------------------------|-------------------------------|
| `group_id`     | `H(CTX_GROUP_ID, K)`                | Members only. Never in clear. |
| post key       | `H(CTX_GROUP_SEAL, K ‖ eph)`        | Members only                  |

New contexts and tags (added to spec §3.2):

| Name               | String                               |
|--------------------|--------------------------------------|
| `CTX_GROUP_ID`     | `sneakerdrop v1 group id`            |
| `CTX_GROUP_SEAL`   | `sneakerdrop v1 group seal key`      |
| `CTX_GROUP_BURN`   | `sneakerdrop v1 group burn`          |
| `CTX_GROUP_CHECK`  | `sneakerdrop v1 group key checksum`  |
| `TAG_GROUP`        | `sneakerdrop v1 group`               |

## 5. Group posts

### 5.1 Format

A group post is an ordinary sealed record (spec §5.4):

```
record = 0x01 ‖ 0x02 ‖ expires:u64 ‖ stamp:u64 ‖ burn_hash:bytes[32] ‖ eph:bytes[32] ‖ ct
```

### 5.2 Posting

To post `content` of type `ctype` to the group with key `K`, from identity
`(sk_s, pk_s)`:

1. Generate a fresh X25519 key pair `(e, eph)` and discard `e`. `eph` MUST be a
   genuine X25519 public key, not random bytes. Real public keys always have
   the top bit clear and are not uniformly distributed, so random bytes would
   make group posts distinguishable from direct messages.
2. `group_id = H(CTX_GROUP_ID, K)`.
3. `key = H(CTX_GROUP_SEAL, K ‖ eph)`.
4. `burn_secret = H(CTX_GROUP_BURN, seed_s ‖ group_id ‖ eph)`, where `seed_s` is
   the sender's 32-byte Ed25519 seed. Only the sender can compute this, and they
   can recompute it from the record alone, so retraction needs no stored state.
5. `burn_hash = H(CTX_BURN, burn_secret)`.
6. `AD = 0x01 ‖ 0x02 ‖ expires ‖ stamp ‖ burn_hash ‖ eph`.
7. `inner` is exactly as in spec §5.4.1 step 7 (sender, created, ctype, content,
   signature, padding), except that the signature is
   `Ed25519-Sign(sk_s, TAG_GROUP ‖ 0x00 ‖ group_id ‖ AD ‖ Q)`.
8. `ct = ChaCha20-Poly1305-Encrypt(key, nonce = 0^12, aad = AD, inner)`.

Senders MUST pad group posts by the same policy they use for direct messages.

Binding `group_id` into the signature stops *cross-group replay*. Without it, a
member of two groups could re-encrypt Alice's post from one group into the
other, making it appear that she posted there.

### 5.3 Opening

Spec §5.4.2 is extended. A node holding identity `(sk_r, pk_r)` and group keys
`K_1 … K_n` opens a sealed record as follows:

1. Try the direct-message procedure of §5.4.2. If the result is a message or
   *forged*, stop.
2. For each `K_i`: derive `key` from `K_i` and `eph`, and decrypt `ct` with
   `AD`. If authentication fails, try the next key.
3. If decryption succeeds, parse `inner` strictly (zero padding, valid times),
   and verify `sig` with `TAG_GROUP` and `group_id_i`. If any check fails, the
   record is *forged (group i)*. Otherwise it is a group message
   `(group_i, sender, created, ctype, content)`.
4. If no key opens it, the record is *not for us*.

The order of steps 1 and 2 doesn't matter: a record cannot open under both
paths except with negligible probability.

**Cost.** One X25519 operation per sealed record (unchanged), plus one BLAKE3
call and one Poly1305 check over `ct` per group key held. For 20 groups this
is a few tens of microseconds per record.

### 5.4 Burns

Burn records and their validity rule (spec §5.5) are unchanged.

- Only the sender can burn a group post. Members cannot compute `burn_secret`.
- Group posts have no read receipts. A reader burning a post would delete it
  for every other member.
- To retract, the sender opens their own post (they hold `K`), recomputes
  `burn_secret` from their seed, and publishes a burn.

## 6. Content types

These are registered in spec §5.4.3:

| `ctype` | Name   | Carried in      | Content                     |
|---------|--------|-----------------|-----------------------------|
| `0x00`  | text   | DM or group post | UTF-8 text                 |
| `0x01`  | invite | DM only         | Invite (§6.1)               |
| `0x02`  | join   | Group post only | Optional UTF-8 display name |

A `0x01` invite received in a group post, or a `0x02` join received in a DM,
MUST be ignored.

### 6.1 Invite

An invite is sent as a direct message to each invitee:

```
invite      = 0x01 ‖ K:bytes[32] ‖ name_len:varint ‖ name:bytes[name_len]
            ‖ roster_count:varint ‖ member:bytes[32] × roster_count
            ‖ history_count:varint ‖ K_prev:bytes[32] × history_count
```

- The leading `0x01` is the invite format version.
- `name` is a UTF-8 display name, at most 64 bytes. It is advisory: members can
  rename groups locally.
- `roster` is the identity keys the inviter considers members. It is advisory.
- `history` is the keys of predecessor groups, most recent first (§7). The
  first one identifies the direct predecessor. A new group has none.

Decoders MUST parse invites strictly and MUST discard the invite if any
key in `roster` is not a valid identity key.

Invites MUST only travel inside sealed DMs. A group key in a broadcast is
public.

### 6.2 Join notice

After accepting an invite, a member SHOULD post a `0x02` join notice to the
group. This lets other members see who has joined: it adds the poster to their
rosters (§8). A member who never posts is invisible to the rest of the group.
That is inherent to this design.

## 7. Forks: removal and rotation

Forking is the only way to remove a member, and also the response to a
suspected key leak:

1. A member mints a new key `K'`.
2. They send each member who should remain an invite with
   `history = [K, …K's history]`.
3. Each recipient's client shows the fork as a proposal: who proposed it, the
   new group's name, and how the new roster differs from the old one. The
   difference is advisory and computed locally.
4. A member who accepts it marks the old group as *superseded by* the new one.
   They keep `K` so they can still read history, and post only in the new
   group from then on.

Two members may fork at the same time. Their clients then show two successor
groups, and the people involved choose. The protocol doesn't resolve this.

Clients MUST post to the newest successor group the user has accepted, and
SHOULD warn before posting to a superseded group.

**The switch-over window cannot be avoided.** A member who hasn't yet received
the fork keeps posting under `K`, and the removed member can read those posts.
Members who need a removal to take effect should confirm the fork reached
everyone (for example, by seeing join notices in the new group) before posting
sensitive content.

## 8. Rosters

Each client keeps a roster per group: the set of identity keys it believes are
members. It is built from:

- the roster in the invite it accepted,
- join notices,
- explicit user actions (accepting or removing someone locally).

Posts from signers not in the local roster MUST be visibly marked as from an
*unknown member*. This is the main way to spot a leaked key: an outsider who
has `K` can read without being seen, but cannot post as an existing member.

Rosters are local and may differ between members. Nothing in the protocol
synchronizes them.

## 9. Security considerations

- **A leaked `K` exposes everything posted under it.** Every post still in any
  ledger (up to a year) and every future post can be read until the group
  forks. Signatures stop the holder from impersonating members, but not from
  reading.
- **Membership is not enforced.** Any member can share `K`, and nothing
  detects it until the new holder posts.
- **Removed members keep history.** They still hold `K` and everything under
  it. Forking protects future posts only, and only after the switch-over
  window.
- **Groups are not hidden from their members.** Invites list rosters, and join
  notices identify new members.
- **Traffic analysis.** A fork sends one invite per member from one place at
  one time, which reveals the group's approximate size to an observer who can
  connect those DMs. Senders MAY stagger invites or add decoy DMs. Where a post
  first appears still suggests where its author is, as with DMs (spec §12.2).
- **Non-repudiation.** Signatures are transferable. Any member can prove to
  outsiders who posted what, by revealing a post together with `K`.
- **Flooding.** A member can flood the group. Clients SHOULD allow muting a
  signer. Admission policy (spec §7.3) applies as usual.
- **Cross-group replay** is prevented by binding `group_id` into signatures
  (§5.2).
- **Indistinguishability** depends on group posts and DMs having the same
  structure, `eph` distribution, and padding policy. Any divergence, such as a
  client that pads group posts differently, would leak which records are group
  traffic.

## 10. Changes to SPEC.md

- §3.2: the new contexts and tag from §4.3 of this proposal.
- §5.4.2: generalized opening (§5.3 of this proposal).
- New §5.7: group keys, posting, burns, invites, join notices.
- §5.4.3: register `ctype` `0x01` (invite) and `0x02` (join).
- §11: client behaviour for rosters, forks, and unknown members.
- §12: the security considerations above.
- Appendix A: group test vectors.
- Appendix B: the new conformance properties (§11 of this proposal).

## 11. Simulator additions

**Workload.**
- Honest nodes form groups of 3–20 and exchange invites by DM.
- Members post, occasionally retract, and occasionally fork to remove someone.
- Members join late, through invites that carry history.

**New adversaries.**
- *Leaker*: an outsider who obtains `K` from a compromised member, reads, and
  posts under their own identity.
- *Cross-group replayer*: a member of two groups who re-encrypts posts from one
  into the other.
- *Removed member*: keeps posting under the old key after a fork.
- *Burn forger*: tries to burn other members' posts.

**New invariants.**

| ID | Property |
|----|----------|
| G1 | No node without `K` opens a post made under `K`. The simulator tries every node's keys. |
| G2 | Group posts open with their true sender, group, and content. Cross-group replays open as *forged*. |
| G3 | After the final flush, every holder of `K` has opened every live post made under `K`, including posts from before it joined (history). |
| G4 | No post the removed member made under the old key after a fork is attributed to the new group. Posts under the new key are never opened by the removed member. |
| G5 | Group posts and DMs are indistinguishable: same length distribution, top bit of `eph` always clear, same structural validity. |
| G6 | Only the sender's burn removes a group post. Burns by other members are never valid. |
| G7 | Every post by a signer outside the reader's roster is flagged as from an *unknown member*. |

**Mutation targets** (bugs the harness should catch):
- `group_id` not bound in the signature (caught by G2),
- random bytes used as `eph` (G5),
- burn secret derived from `K` instead of the sender's seed (G6),
- history keys ignored when joining (G3).

## 12. Implementation plan

1. **Library** (`crates/sneakerdrop`):
   - a `group` module with `GroupKey` (generate, text form, `id`),
     `Record::new_group_post`, and invite encoding and decoding;
   - opening that takes the group keys held and returns
     `Opened::GroupMessage` / `Opened::GroupForged`;
   - sender-side burn secret recovery for one's own posts;
   - unit tests and property tests.
2. **Test vectors**: a group key, a post, an invite, and a burn of the post.
3. **Spec**: fold in this proposal as described in §10.
4. **CLI**:
   - `group create NAME`, `group invite GROUP ADDRESS…` and `group accept ID`;
   - `group post GROUP`, `group fork GROUP --without ADDRESS…` and
     `group list`;
   - `show` displays group posts with roster flags;
   - keys are stored with mode 0600, like the identity.
5. **Simulator**: the workload, adversaries, and invariants from §11, plus a
   `groups` scenario and a mutation run.

## 13. Open questions

1. **Roster in invites.** Including it tells the invitee every member's
   identity, which they'd learn from join notices anyway, and costs 32 bytes
   per member (about 640 B at 20). Should it be optional?
2. **Display names.** Should join notices carry a display name, or should
   clients rely on local petnames only?
3. **History depth.** Should a fork carry the predecessor's full history chain,
   or only the most recent key?
4. **Invite acknowledgement.** Should the join notice reference the invite it
   answers, so the inviter can tell which invitees have joined? This would add
   a 32-byte invite ID.
