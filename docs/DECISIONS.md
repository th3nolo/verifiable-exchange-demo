# Decisions

Every significant design decision on this project, with what it was chosen
over, what it costs, and how it behaves at scale.

The decisions are the work. The code is what came out of them. This file exists
so the reasoning survives outside a conversation. It is also what lets a reader
who is new to the project judge it on its arguments.

Terms come from [GLOSSARY.md](GLOSSARY.md). One word for each thing.
[ENGINE.md](ENGINE.md) is the specification. [PLAN.md](PLAN.md) is the
schedule. [`services/ROADMAP.md`](../services/ROADMAP.md) is the design story.
This file is the argument behind all three.

## The decisions

1. [The log is a Merkle tree per RFC 9162, not a hash chain](#the-log-is-a-merkle-tree-per-rfc-9162-not-a-hash-chain)
2. [Follow RFC 9162 rather than invent a tree](#follow-rfc-9162-rather-than-invent-a-tree)
3. [Verify over the bytes that were received, not over re-serialised structs](#verify-over-the-bytes-that-were-received-not-over-re-serialised-structs)
4. [The inclusion deadline on the separate service](#the-inclusion-deadline-on-the-separate-service)
5. [Cancel newest for self-trade prevention](#cancel-newest-for-self-trade-prevention)
6. [The rules live in the log, not in the binary](#the-rules-live-in-the-log-not-in-the-binary)
7. [The tree lives on disk, not on the heap](#the-tree-lives-on-disk-not-on-the-heap), which supersedes [The tree lived on the heap](#the-tree-lived-on-the-heap-superseded)
8. [One binary, seven processes, one container](#one-binary-seven-processes-one-container)
9. [SQLite](#sqlite)
10. [No zero-knowledge proof of execution](#no-zero-knowledge-proof-of-execution)
11. [The used-nonce set never expires](#the-used-nonce-set-never-expires)
12. [Restart monthly with a fresh database, rather than segment the log](#restart-monthly-with-a-fresh-database-rather-than-segment-the-log)
13. [Keys are pinned on first use](#keys-are-pinned-on-first-use)
14. [Every matching rule is written twice](#every-matching-rule-is-written-twice)
15. [A session names a signed history, not a database file](#a-session-names-a-signed-history-not-a-database-file)
16. [Signatures cover a named statement, and are verified strictly](#signatures-cover-a-named-statement-and-are-verified-strictly)
17. [Anchor every five minutes, to a contract the operator writes](#anchor-every-five-minutes-to-a-contract-the-operator-writes)
18. [The checkpoint commits to the tree, not only the chain](#the-checkpoint-commits-to-the-tree-not-only-the-chain)
19. [Serve the stored Merkle nodes, so a stranger can check them](#serve-the-stored-merkle-nodes-so-a-stranger-can-check-them)
20. [Real balances, a second key for orders, and a withdrawal that waits](#real-balances-a-second-key-for-orders-and-a-withdrawal-that-waits)
21. [The pairs are MERKLE-USDC, ETH-USDC and BTC-USDC](#the-pairs-are-merkle-usdc-eth-usdc-and-btc-usdc)

Decision 4 is the one with open work in it. Decision 20 is the longest, and it
is the only one that describes work nobody has started: it is chosen, and no
code in this repository implements any part of it. Decision 7 is kept in two
entries, the one in force and the one it replaced, because the arithmetic that
was wrong is the point of the entry.

---

## How to read this file

**Measured or estimated.** Every number says which it is. A measured number
names where it came from. An estimated number shows its arithmetic.

**The scale tables use one assumption.** One user sends one message every 200
seconds. That gives:

| users | messages a second |
|---|---|
| 1,000 | 5 |
| 100,000 | 500 |
| 1,000,000 | 5,000 |

This is an assumption, not a measurement. The measured configuration runs at a
mean of 69 messages a second with 40 simulated accounts. It is a mean because
the generator switches between three
activity states, 24, 69 and 114 messages a second, each holding a third of the
time. A scale table below that reads "at the deployed rate" was written when
that rate was 2, and the tables written after it read 24.

**The constants every table uses.**

| What | Value | Where it came from |
|---|---|---|
| a message on the wire | 122 bytes | `/messages.ndjson` served 121,895 bytes for 1,000 messages, 2026-08-17 |
| a message in `feed.db` | 331 to 334 bytes | the live file over its message count, taken twice on 2026-08-17 |
| the message text alone | 121.0 bytes | `SUM(LENGTH(json))` over 106,554 messages is 12,896,470, 2026-08-15 |
| the chain hash column | 32.0 bytes | `SUM(LENGTH(chain))` over the same table is 3,409,728 |
| a node in the tree | 1.994 nodes a message, 64 bytes of hash | `GET /tree/nodes` served 1,994 nodes for 1,000 leaves, 2026-08-17 |
| a message in the serving window | about 600 bytes | [`feed.rs:66`](../services/src/feed.rs) |
| a used nonce | 3.1 bytes | [`ROADMAP.md`](../services/ROADMAP.md), "What the history costs" |
| the measured container memory cap | 512 MB | deployment measurement |
| measured steady state across seven processes | about 200 MB | deployment measurement |

---

## The log is a Merkle tree per RFC 9162, not a hash chain

**Chosen.** An RFC 9162 Merkle tree over the stored bytes of every message. The
sequencer signs a tree head. It serves inclusion proofs and consistency proofs.

**Over.**

- A SHA-256 hash chain, `chain_i = SHA-256(chain_{i-1} || bytes_i)`. This ran in
  production, and it still runs beside the tree today.
- No proof at all. A reader downloads the whole log and hashes it again.

**Why.** A chain answers one question. Was this history changed? It cannot
answer "is my message inside" without every message after it. A tree answers
both. The second answer costs `ceil(log2(n))` hashes instead of `n` messages.

**Costs now.**

The two ways to answer "is my trade in the log", both measured in the browser
on a 183,823-message log (commit `6439ae3`):

| | proof | hashing the whole window again |
|---|---|---|
| bytes | 480 | 21,322,304 |
| requests | 3 | 184 |
| time | 41 ms | 3,038 ms |
| hashes | 15 | 182,900 messages hashed |

That is 44,400 times fewer bytes and 74 times faster.

Measured against the live exchange on 2026-08-15, at tree size 106,879:

- An inclusion proof for leaf 0 is 1,237 bytes on the wire, and carries 17
  hashes. A proof for a recent message is shorter, because it sits near the
  incomplete right side of the tree. That is the 15 hashes above.
- A consistency proof from 100,000 to 106,000 is 819 bytes and 11 hashes. The
  signed tree head is 377 bytes.
- `/messages.ndjson` returns 1,000 messages a page, verified live at 123,201
  bytes.
- The first anchor stood at message 13,774
  ([`feed.rs:4152`](../services/src/feed.rs)), and 13,774 messages at 124.2
  bytes is 1.71 MB. That is the 1.7 MB [ENGINE.md](ENGINE.md) section 8 cites.
- Memory: 95 bytes a message. At 106,879 messages that is 10.2 MB.
- CPU: 0.16 microseconds a message. Startup over 44,000 messages measured 36 ms
  with the tree and 29 ms without it
  ([`feed.rs:543`](../services/src/feed.rs)).
- Disk: none. The tree is rebuilt at every start. See the tree-on-the-heap
  decision below.

**Both checks are kept, and that is a second decision.** The proof says this
message is in the tree the sequencer signed. Hashing the window again says the
messages the sequencer served produce the value written on Base. The second is
stronger, and the page says so. Replacing it with the proof would lose the only
check that does not end at the operator's own signature.

**At scale.** Proof size grows as `log2`. Chain cost grows as `n`. The right
column is what the reader pays after one year at that rate.

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing in the proof. 158M messages a year needs 28 hashes, 896 bytes. The chain needs 19.6 GB for the same answer. |
| 100,000 | 500 | Nothing in the proof. 15.8 billion messages a year needs 34 hashes, 1,088 bytes. The chain needs 1.96 TB. |
| 1,000,000 | 5,000 | Nothing in the proof. 158 billion messages a year needs 38 hashes, 1,216 bytes. The chain needs 19.6 TB. |

Proofs for a past tree size are served `public, max-age=31536000, immutable`
with an ETag, verified live. A cache holds them forever, so the origin serves
each one once.

**When to revisit.** Never, for the proof. It is `log2`. Revisit where the tree
is stored, which is a separate decision below.

---

## Follow RFC 9162 rather than invent a tree

**Chosen.** RFC 9162 sections 2.1.1 to 2.1.5, transcribed step for step,
including the RFC's step numbers as comments. The RFC's own seven-entry worked
example is a test.

**Over.**

- A tree of our own design. The same shape, no prefix bytes, and no
  specification to check an implementation against.
- RFC 6962, Certificate Transparency 1.0. The same tree, an older document.

**Why.** The `0x00` and `0x01` prefixes make leaf hashing and node hashing
different functions. Without them the 64 bytes `left || right` of any internal
node hash to that node. An attacker presents those 64 bytes as a message
nobody submitted. The attacker then produces an inclusion proof that lands on
the real root. RFC 9162 calls the prefixes "required to give second preimage
resistance" ([`merkle.rs:52`](../services/src/merkle.rs)).

The second reason is agreement. An auditor who implements the RFC from the text
gets the same accept or reject decision on every input, including malformed
input ([`merkle.rs:17`](../services/src/merkle.rs)).

**This was proved by getting it wrong.** The verifier published in
[API.md](API.md) accepted a forged proof. RFC 9162 section 2.1.3.2 step 4 says
to **fail** when `sn` reaches 0 with proof elements left. The published script
stopped instead, then tested `sn == 0`, which is true at that point. So a
correct proof with 32 junk bytes appended was accepted. Step 1, which refuses a
leaf index at or past the tree size, was missing as well. Both were reproduced,
fixed, and tested against five cases (commit `6439ae3`).

The lesson is the decision. "Recompute the root some other way and compare" is
not the same as the RFC's steps, and the difference is a forged proof.

**Costs now.**

- Memory, disk, network: nothing. One extra byte per hash input.
- CPU: nothing. SHA-256 pads a 64-byte input to two blocks, and a 65-byte input
  is also two blocks.
- Development: 14 tests in [`merkle.rs`](../services/src/merkle.rs), including
  the RFC's known answers and an attack test named
  `an_internal_node_cannot_be_passed_off_as_a_leaf`.

**At scale.**

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing. The cost is fixed. |
| 100,000 | 500 | Nothing. The cost is fixed. |
| 1,000,000 | 5,000 | Nothing. The value grows instead: one forged proof is one fabricated trade against any account. |

**When to revisit.** When RFC 9162 is superseded, or when SHA-256 is broken.
Not before.

---

## Verify over the bytes that were received, not over re-serialised structs

**Chosen.** Every consumer hashes the bytes it was served from
`/messages.ndjson`. Parsing is a separate step, and it exists only for
interpretation.

**Over.**

- Parse each message into `OrderMessage`, serialise it again, and hash the
  result. This is what ran before.
- Freeze the message format, so the producer and every consumer always agree.

**Why.** Serde writes what the build declares. A field or a message kind added
after a consumer was built comes back out missing. The bytes differ, the chain
hash differs, and the consumer reports that the sequencer rewrote its history.
The sequencer is correct. The consumer is only old. On a validator that verdict
stays set until an operator clears it by hand
([`ROADMAP.md`](../services/ROADMAP.md), "Failure: an honest sequencer reported
as a liar").

**What it bought.** `validator.rs` no longer names `OrderMessage` in production
code at all. A validator attests to the order of messages, not to their
meaning. **A deployed validator needs no rebuild when a message kind is added.**
That is the property the whole change was for.

**The proof, run with real processes.** A newer binary published 31,800
messages, and 4,681 of them were a kind the old binary had never heard of. The
old binary computed the same chain hash and attested with `disputed: false`.
One message was then edited by hand, and the same old binary reported FAILED
and exited 1 ([`ROADMAP.md`](../services/ROADMAP.md), "The proof, run with real
processes").

**The newest payoff.** The separate service's confirmation now carries the
message's stored bytes plus an RFC 9162 inclusion proof, instead of a
re-serialised message (commit `8ab3a1b`). That check is hashing over bytes and
nothing else, so it works for a message kind neither service can read. The
deadline decision below is where that matters.

**Costs now.**

- One extra endpoint, `/messages.ndjson`, so the bytes can be served verbatim.
- Three exit states instead of two: pass 0, fail 1, cannot interpret 3. A
  failed check outranks cannot-interpret ([ENGINE.md](ENGINE.md) section 6).
- A program that must act on a message it cannot read stops. It never skips.
- The sequencer serialises once and serves the stored bytes, so it cannot
  report its own history as tampered with after a rollback.

**At scale.**

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing. The cost is one endpoint. |
| 100,000 | 500 | Nothing. The rule is per message and costs no work. |
| 1,000,000 | 5,000 | Nothing. Without it, a deploy needs the sequencer and every reader rebuilt in one moment, forever. |

**When to revisit.** Never. Every other decision here rests on it.

---

## The inclusion deadline on the separate service

**Chosen today.** 5,000 ms, one deadline for every submission
([`inbox.rs:128`](../services/src/inbox.rs)). Past that, `GET /status` lists
the entry as late, and that is the censorship alarm.

**Over.**

- No deadline. Report only that an entry is pending.
- A deadline the submitter picks.
- A different deadline for an order that would trade at once and for an order
  that would rest.
- A window measured in hours, which is what every production system chose. See
  the table below.

### What the deadline is for

It is not a latency target. It is the point where the separate service
publishes an accusation against the operator. So the two errors do not cost the
same:

- **Too short.** The separate service accuses an honest sequencer. Both
  [ENGINE.md](ENGINE.md) section 7 and [PLAN.md](PLAN.md) say this is worse
  than no alarm, because nobody believes the alarm when it is right.
- **Too long.** A censoring operator gets a longer start. The order is not
  lost. It stays in the separate service's database, signed by the submitter,
  and the record stays checkable.

A false accusation destroys the alarm permanently. A slow alarm costs one
trader some time. The errors are not equal, so the number should not sit close
to the honest path.

### What the honest path costs today

Measured: an entry was sequenced 0.4 s after the separate service accepted it
([API.md](API.md), the Trade panel). The sequencer drains the separate service
on every 100 ms tick, and it drains it before its own generated traffic
([`generate.rs:49`](../services/src/feed/generate.rs)). So 5 s is a 12.5 times
margin over the observed path.

That margin sounds large. Three measured facts say it is not.

**1. A restart already costs more than 5 s.** The sequencer reloads its whole
history at startup and builds the tree again. Measured at 36 ms over 44,000
messages, which is 0.82 microseconds a message
([`feed.rs:543`](../services/src/feed.rs)). This deployment targets a monthly
restart at 5.2M messages ([`ROADMAP.md`](../services/ROADMAP.md)).

```
5.2 x 10^6 x 0.82 microseconds = 4.25 s
```

Estimated, and it is a floor. That measurement had the page cache warm on a
7.5 MB database. The monthly database is 850 MB. And all seven processes
restart together, so the sequencer's startup is only one part of the
container's.

Every entry pending at that moment is reported late. **A normal restart
produces a false censorship alarm.**

**2. The mark budget caps the clearing rate at 640 entries a second.** An entry
leaves the pending set only when the sequencer's mark lands. `feed_id IS NULL`
is the pending test ([`inbox.rs`](../services/src/inbox.rs), `list_pending`).
The sequencer sends at most 64 marks a tick
([`drain.rs:39`](../services/src/feed/drain.rs)), and it ticks 10 times a
second.

Above 640 submissions a second the pending set grows, and entries pass 5 s
while their orders are already live in the market.
[`drain.rs:202`](../services/src/feed/drain.rs) says exactly that: "The orders
behind those newer entries are already live in the market. Only the evidence
that names them is waiting."

**3. Two more paths produce a late entry with no censorship.** A mark refused
eight times makes the sequencer give up, and the entry stays pending forever
([`drain.rs:34`](../services/src/feed/drain.rs)). And a message published by a
newer build, met by a rolled-back sequencer, cannot be judged, so the entry
stays pending. The code names that one itself: "a censorship alarm for
something that is not censorship"
([`drain.rs`](../services/src/feed/drain.rs), `sequence_drained`).

### What production systems chose for the same job

Every system that guarantees inclusion against a censoring sequencer chose
**hours**. All of these are the guaranteed path, not the normal path.

| system | normal path | guaranteed inclusion | ratio |
|---|---|---|---|
| Arbitrum One | 250 ms soft confirmation | 24 hours | 345,600 |
| OP Stack (OP Mainnet) | 2 s block time | 12 hours | 21,600 |
| this project | 0.4 s, measured | 5 s | 12.5 |

**Arbitrum One keeps a 24-hour delay.** `maxTimeVariation()` on the
`SequencerInbox` at `0x1c479675ad559DC151F6Ec7ed3FbF8ceE79582B6` returns
`delayBlocks` 7200 and `delaySeconds` 86400, read from the contract. The term
is force inclusion, through `SequencerInbox.forceInclusion` on the delayed
inbox. A 2023 proposal to cut it to 4 hours was rejected. The reason given by
Offchain Labs is the interesting part:

> If the sequencer has still been offering soft confirmations for the length of
> the inclusion window, there would likely be a reorg of everything since the
> last batch was posted leading to large scale MEV extraction.

They offered 12 hours instead, and it was never implemented.
[Proposal thread](https://forum.arbitrum.foundation/t/proposal-decrease-censorship-delay-from-24-hours-to-4-hours/13047) ·
[Sequencer docs](https://docs.arbitrum.io/how-arbitrum-works/deep-dives/sequencer)

**And 24 hours is not what a censored user actually waits.** The same contract
has a Censorship Timeout buffer, read live: `bufferBlocks` 14400, `max` 14400,
`threshold` 150, `replenishRateInBasis` 500. The effective delay is the smaller
of `delayBlocks` and the current buffer. Under sustained censorship the buffer
drains toward 150 L1 blocks, which is **30 minutes**, and it refills at 5%.

So Arbitrum's number under attack is half an hour, and its 24 hours is the
quiet-day value. This matters for the recommendation below.

**OP Stack uses a 12-hour sequencing window.** That is 3,600 L1 blocks. The
specification says the value constrains "the sequencer's ability to re-order transactions",
and that "higher values would pose a risk to user protections". The docs give
the sizing reason: "a balance between operational reliability and minimizing
potential L2 reorganizations".
[Configurability spec](https://specs.optimism.io/protocol/configurability.html) ·
[Forced transaction docs](https://docs.optimism.io/stack/transactions/forced-transaction)

**Certificate Transparency states the general rule, and it settles this.**
RFC 6962 calls the bound the Maximum Merge Delay. It is not a latency target:

> the maximum period of time during which a misissued certificate can be used
> without being available for audit is the MMD
> ([RFC 6962 section 7.1](https://www.rfc-editor.org/rfc/rfc6962.html))

RFC 9162 section 4.1 deliberately specifies **no value**, "to allow for
experimentation", and requires the log to fix and publish it before it starts.
Ordinary logs run 24 hours. Chrome's current policy caps the new tiled-log
architecture at **1 minute**.

So the same guarantee is 60 seconds under one implementation and 24 hours under
another. **The number tracks what the implementation can deliver, not what the
security argument requires.** That is the rule this project should apply to
itself, and the three measured facts above say what this implementation can
deliver.

One thing this project already does right: `GET /status` publishes
`deadline_ms` beside the verdict, which is the CT rule that the parameter must
be a published commitment.

**Price bands are sized the same way, from a window and not from an instant.**
Limit Up-Limit Down uses a reference price. It is the mean of trades over the
past 5 minutes. The bands are 5%, 10% or 20% by tier. A Limit State lasts 15
seconds before a 5-minute pause
([Nasdaq LULD FAQ](https://www.nasdaqtrader.com/content/MarketRegulation/LULD_FAQ.pdf)).
Binance spot measures its price cap against a 5-minute average price as well,
confirmed live on `PERCENT_PRICE_BY_SIDE` for BTCUSDT. This is the same
argument [ENGINE.md](ENGINE.md) section 4.2 already makes for the collar's
reference price: measure over a window, because one trade moves the last price.

### Can one deadline be right for a market order and a resting limit order?

The question is fair: an order may rest in the book for minutes, so why does
five seconds matter?

**The deadline is not about the order's lifetime.** A resting order waits
because its owner chose to wait. The deadline is about the window in which the
operator holds a signed order the market cannot see. That window is the same
whether the order will rest or trade.

**What the operator can do with that window does differ.**

- An order that would cross the book on arrival tells the operator that a trade
  is about to happen. The operator can read the price and trade ahead of it. The
  harm grows with every millisecond.
- An order that would rest tells the operator less. Delaying it costs the
  submitter queue position at that price level. The harm grows with every
  competing order that arrives in the gap, not with time.

**The force-inclusion systems do not split it.** Arbitrum's `forceInclusion`
and OP Stack's `depositTransaction` apply one delay to every delayed message.
Neither specification has any concept of order intent or urgency.

**Trading venues do split it, and four of them do it explicitly.**

- **Nasdaq**, under LULD: an aggressively priced order is re-priced to the band
  on entry, both IOC and longer time-in-force. In a Limit State, market orders
  in options are rejected before acceptance, while stop orders are accepted.
- **CME Globex.** Its rule says "a GTC or GTD order may be entered in most
  products ... on
  CME Globex outside of the daily limit", and it rests until the price comes
  back inside. An aggressive order at the same price is rejected by price
  banding. One venue, opposite treatment, keyed on intent.
- **dYdX v4** is the clearest case, and it is a protocol design rather than an
  exchange rule. Short-Term orders are "mainly intended for use by market
  makers with high throughput or for market orders". Their maximum life is 20
  blocks, about 30 seconds, and they are held in validator memory and never
  committed on-chain unless filled. Stateful orders have a maximum of 95 days
  and are committed to the chain.
  [dYdX order docs](https://docs.dydx.xyz/concepts/trading/orders)
- **Binance** publishes separate market and limit price cap ratios.

**Read dYdX carefully, because it answers the objection.** The obvious problem
with a per-order deadline is that the submitter declares it, and a declaration
is not evidence. A submitter who wants a louder alarm declares every order
urgent.

dYdX does not give the short-term order a tighter alarm. It gives it a shorter
**life**. A Short-Term order that is not filled in 30 seconds expires, and
nothing is accused of anything. Declaring "urgent" buys a weaker guarantee, not
a stronger one, so the declaration is self-enforcing.

**This architecture still cannot classify an order by itself**, and that part
stands. The separate service does not hold the book, so it cannot know whether
a buy at 10.07 would cross. Reading `/market` to find out would be asking the
operator how fast the operator must act. And the order kind sits in `body`,
which [ENGINE.md](ENGINE.md) section 2 forbids a program from depending on for
correctness.

So the split is real and buildable, and it is not a split between two
deadlines. It is a split between a deadline and a lifetime.

### The recommendation

**Two numbers, and they do different jobs.**

The mistake is not the value 5,000. The mistake is that one number does two
jobs: a latency report for the visitor on screen, and an accusation for a third
party. Every system above separates those two jobs.

**1. A lifetime the submitter declares, and 30 seconds by default.** An entry
that is not sequenced within its life expires. It is reported as expired, and
nothing is accused. This is dYdX's Short-Term order, and it is what a market
order actually wants: a stale market order is worse than no order. The
declaration is safe because it buys a weaker guarantee.

**2. One inclusion deadline, 15 minutes, and it is the only alarm.** This
number comes from this system. The anchor sender writes every 5 minutes, so 15
minutes is three anchor intervals. An entry still missing after three anchors is
missing from a history that is already hard to revise.

15 minutes covers every measured false alarm above. It is 212 times the 4.25 s
restart floor and 2,250 times the measured 0.4 s honest path. That ratio sits
between this project's current 12.5 and OP Stack's 21,600.

It also lands beside the only production number measured under actual
censorship: Arbitrum's buffer drains to 30 minutes when a sequencer really is
censoring. 15 minutes is half of that, on a system whose alarm forces nothing.

**Why not hours, like Arbitrum.** Because Arbitrum's 24 hours is not the cost
of proving censorship. It is the cost of the **remedy**. Force inclusion
reorders the sequencer's own feed, which reorganises soft confirmations and
creates the MEV their own rejection quotes. This project's separate service
forces nothing into the log. It publishes a fact. An alarm that destroys
nothing does not need to allow time for a remedy that does. So this project can
be shorter than Arbitrum, and for a real reason.

**The stronger form, and what it costs.** Define the alarm against the anchor
rather than against a clock: an entry is censored when it is not in the log at
a tree size that has been anchored on Base. That removes the clock from the
argument entirely, which is what RFC 9162 declines to fix a number for. It
costs the separate service a dependency it does not have today. It would have
to read the anchor contract, and it reads nothing but the sequencer now.

**Two fixes that cost nothing and remove real false alarms.**

- Separate "sequenced but not marked" from "not sequenced". The order is
  already live in the market in the first case, and `drain.rs` already knows
  which it is.
- Let the submitter deliver the mark. The submitter holds the entry, the
  sequencer's signed tree head and its own inclusion proof, so it can prove the
  pairing without the sequencer's cooperation. Today only the sequencer can
  clear an entry, which means the party the alarm accuses is the only party who
  can silence it.

**Costs now.**

- Memory, disk: one timestamp per entry.
- CPU: one comparison per entry on `GET /status`, bounded in SQL to 200 rows a
  page ([`inbox.rs:136`](../services/src/inbox.rs)).
- Network, per mark: the stored bytes, one signed tree head, and about 17
  hashes. One head is signed per drain pass, and reused across every mark in it
  ([`drain.rs`](../services/src/feed/drain.rs), `sequence_drained`). The Ed25519
  cost is therefore per tick, not per mark.
- The submission rate limit is 120 in 10 seconds per caller, and the sequencer's
  own `POST /order` uses the same two numbers
  ([`inbox.rs:190`](../services/src/inbox.rs)). That is deliberate. A front door
  more generous than the separate service would push callers back onto the path
  the sequencer controls. That is the path this service exists to avoid.

**At scale.**

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing, until a restart. Then every pending entry is reported late, and each one is a false accusation. |
| 100,000 | 500 | The mark budget, at 78% of its 640 a second ceiling. Any burst above it produces false alarms. |
| 1,000,000 | 5,000 | The separate service stops accepting. Above 640 a second the pending set reaches the 5,000 cap in about 1.1 s, and `POST /submit` then returns 503. It refuses submissions exactly when it is needed. |

**When to revisit.** Now. The deadline is the one number in this system that
was chosen by feel, and three measured paths already trip it with an honest
sequencer. Revisit it again whenever the restart cost changes, because that is
the floor the number tracks. Moving the tree to disk removes most of that cost
and lets the deadline come down.

---

## Cancel newest for self-trade prevention

**Chosen.** Cancel newest. The arriving order is refused, and it is told why.
The resting order stays.

**Over.**

- Cancel oldest. Remove the resting order, and let the arriving order trade on.
- Cancel both. Remove the resting order and refuse the arriving one.
- Decrement. Reduce both by the smaller quantity, and match the remainder.

**Why.** Cancel newest keeps time priority. Cancel oldest lets an account clear
its own quote to reach the liquidity behind it. Cancel newest needs no quantity
arithmetic, so the checker reproduces it exactly ([ENGINE.md](ENGINE.md)
section 4.1).

The rule is also held by a type. Step 4 takes `book: &Book`, not `&mut Book`,
so the step cannot take the resting order off the book even if somebody wants
to ([`step4_self_trade_check.rs:50`](../services/src/matcher/step4_self_trade_check.rs)).
Cancel oldest is a compile error, not a review comment.

**Costs now.**

- Step 4 walks the crossing levels, and step 5 then walks the same levels to
  fill them. That is the price of "a step never calls another step". Two pieces
  of code must agree on which levels cross ([ENGINE.md](ENGINE.md) section 4.0).
- A participant quoting both sides gets its own arriving order refused. Under
  decrement it would get a fill for the part that does not self-trade.
- The rule is data, so it needs an `EngineRule` message naming rule set 2 in
  the log before it does anything. Nothing in this repository publishes one
  yet, so the rule is built and unreachable in production until something can.
- A schema bump. The rule set is in the state root, so it has to be in the
  state database too or a resume rebuilds a state its own last claim
  contradicts and the run ends.

**How much traffic it touches, and one number this repository cannot settle.**
The first log held **1,008 self-trades in 28,104**, and the unit is genuinely
uncertain. Commit `309b38c` wrote "28,104 messages". Commit `3c793f4` restated
it as "28,104 trades" without measuring again, and both wordings are still in
the repository. That log was session `349d462ced25bb2b`, and it is gone, so
nobody can settle it now. This entry is the one place that says so; every other
mention links here.

Either reading carries the argument. 1,008 self-trades is far too many to turn
the rule on in a binary, because every one of them would replay differently and
every signed claim and anchor over them would stop verifying.

The live log is the third one. It opens at rule set 2 and refuses self-trades
from message 1, so it executes none: `GET /market` reported
`orders_ignored_by_reason` as `{"self_trade": 18, "unlisted_symbol": 1}` over
295,627 messages on 17 August 2026.

**At scale.**

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing. The book is small and the double walk is free. |
| 100,000 | 500 | The refusal rate. 3.6% of messages refused becomes a support question, and each refusal needs its own reason on `/market`. |
| 1,000,000 | 5,000 | The double walk. Two passes over the crossing levels, 5,000 times a second, on a book with many levels. |

**When to revisit.** When a participant quotes both sides in size, and a
refused arriving order costs them a hedge. Decrement is the answer then, and it
needs quantity arithmetic the checker must reproduce exactly.

---

## The rules live in the log, not in the binary

**Chosen.** The log opens by stating its own rules. Message 1 is `EngineRule`.
Messages 2 to 4 are `ListSymbol`. The test for whether something belongs in the
log: if changing it makes the same messages produce a different result, it is
data, not configuration.

**Over.**

- The symbol list and the matching rules as constants in the binary. This is
  what runs today.
- A configuration file read at startup.

**Why.** The symbol list was consulted inside the execution path. Delisting a
pair would change how every past message replayed, and it would break every
anchor written so far. Self-trade prevention would do the same: the first log
held 1,008 self-trades, so adding the rule as plain code would make every past
claim fail. See "Cancel newest for self-trade prevention" above for that
measurement and what is uncertain about it.

**What it prevents.** An operator changing a constant, then re-signing a
history that now means something different. Replay then gives the same answer
to everyone.

**What it costs.**

- Four extra messages at the head of every log.
- One restart. `SYMBOLS` is a constant in
  [`domain.rs`](../services/src/domain.rs) today, so moving it into the log
  needs a clean genesis ([PLAN.md](PLAN.md) step 5).
- `DelistSymbol` must cancel every resting order in that book, and there is no
  pipeline step for that ([ENGINE.md](ENGINE.md) section 4.0).
- Metrics, caching and rate limits stay out of the log. They change no result.

**At scale.**

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing. Four messages, once. |
| 100,000 | 500 | The registry replay. 500 listed symbols is 500 messages read at every start, plus every rule change after them. |
| 1,000,000 | 5,000 | The deploy order. A rule change is a message, so every reader must be upgraded before the sequencer publishes it ([ENGINE.md](ENGINE.md) section 6.1). |

**As built, for the symbol list.** The registry is a map on `MatcherState`,
filled by `ListSymbol` and emptied by `DelistSymbol`, persisted in the state
database's `listings` table (schema 8) and covered by the state root. It
starts **empty**
and there is no fall back to `SYMBOLS`: a log that lists nothing trades
nothing, which is the same answer every build gives. A fallback would have kept
the binary in the answer for exactly the history where the bug was measured.

Two consequences follow from that and neither is hidden:

- **This cannot be deployed onto the running session.** No log in existence
  carries a `ListSymbol`, so an engine upgraded before the genesis emits them
  refuses every order. It ships with the restart, like the envelope and the
  pair rename. The state root moved to `exchange-state-v3` as well, so an
  existing run refuses to resume rather than quietly stopping.
- **Intake and execution now ask the same question, and it is about the
  message alone.** `inbox::validate_submission` no longer reads `SYMBOLS`. It
  checks the symbol name rule of ENGINE.md section 4.0, and nothing else about
  the symbol. That rule is 1 to 32 characters, `A`-`Z`, `0`-`9` and `-`. Every
  check it makes is now a pure function of the message: the nonce, the two grid
  checks and the name rule. The sequencer reruns that function over every entry
  drained from the separate service. By then, the entry has an inclusion
  deadline. A rule change between intake and sequencing would falsely report an
  honest sequencer as late. ENGINE.md section 7 removes that false alarm.
  Whether a symbol is listed is a fact about the growing log, so intake cannot
  ask it.
  The separate service does not replay the log, and asking the sequencer would
  put the distrusted party back in the admission path.

  The cost is a typo. A symbol that is spelled correctly but not listed costs
  the submitter one message that does nothing, plus a receipt for it, instead
  of a refusal at the door. The order enters the log, its inclusion proof
  verifies, and `/market` counts it under `unlisted_symbol`. That is the same
  outcome a delisted symbol already produced, and it is harmless for the same
  reason: everyone replaying the log agrees the exchange ignores it. The
  protection against a typo moves to the client, where the command line and the
  page read the listed symbols from `GET /market`. In exchange, a market can be
  opened while the exchange runs, without redeploying every intake binary
  first, the acceptance test in [PLAN.md](PLAN.md) step 4.

**When to revisit.** Never. The alternative breaks anchors that are already on
Base.

---

## The tree lives on disk, not on the heap

**Decided 15 August 2026.** The heap version shipped first and is being
replaced. What follows records why, because the numbers moved twice and the
second move changed the answer.

**Chosen.** The nodes go in a SQLite table beside the messages. About `log2(n)`
row writes on append, about `log2(n)` row reads to serve a proof, and memory
that does not grow with the history.

**Over.**
- *Nodes on the heap.* What shipped. Simple, and it has a date on it.
- *Store nothing, recompute each proof.* Every sibling in a proof is the root of
  a subtree holding up to half the log, so one proof reads about 13 MB of
  messages. That moves the 21 MB cost from the visitor to the server rather
  than removing it.
- *The RFC 9162 section 2.1.2 compact hash stack.* `O(log n)` memory, cheap
  appends, cheap root. It cannot produce a proof for an arbitrary historical
  leaf, which is the whole feature.
- *Put the tree on chain.* About 20,000 gas per 32-byte slot and roughly one
  node per message: 110,000 messages is 2.2 billion gas. Not expensive,
  impossible. It is also unnecessary. The root is already on chain, and
  anyone can recompute a proof from the data without trusted storage.
- *Compress the nodes.* They are SHA-256 output. Hashes do not compress; that
  is what makes them hashes.

**Why.** The memory was never the real danger. The tree is rebuilt from the
database at every start, so a `feed.db` past the limit **cannot be opened at
all.** The process dies during startup, restarts, and dies again. The data
remains intact, but no service can reach it. On disk there is nothing to rebuild.

**Costs, estimated.** About 32 bytes a message. **Measured.** The tree adds 64
bytes of node hash a message, and `feed.db` holds 331 to 334 bytes a message in
total, taken twice on the live deployment on 2026-08-17. The estimate was low
because it guessed a row cost from the hash width and left out the row. At 24
messages a second one month is 62.2M messages and 20.6 to 20.8 GB. The
deployment keeps capacity beyond one full window, so the decision stands on the
corrected number.

**The number that decided it, and it was wrong once.** The first calculation
used the host instead of the container limit and dismissed the risk. Measured
against the container's actual `mem_limit: 512m` with 200 MB steady state, the
limit was **19 days**. That is inside the wipe window, so it would have happened.

**When to revisit.** If a proof's row reads ever show up in
`feed_db_page_seconds_max`. Not before.

## The tree lived on the heap (superseded)

**Chosen.** Hold the whole tree in memory. Rebuild it from `feed.db` at every
start.

**Over.**

- The tree on disk, with one row per perfect subtree hash.
- No tree in memory. Recompute a proof from the stored messages on each
  request.

**Why, and this is the owner's position.** This is a demonstration. It is wiped
every few months, so 220 days is not a real risk at this scale. A proper
on-disk solution should still be built, and it is described below.

**Costs now.**

- Memory: 95 bytes a message. The tree held 87,992 hashes in 4.19 MB over
  44,000 messages ([`feed.rs:549`](../services/src/feed.rs)).
- CPU: 7 ms over 44,000 messages at startup, which is 0.16 microseconds a
  message.
- Disk and network: none.

**The number that matters, and a correction.** The first calculation used host
memory. That is the wrong limit for the container the exchange actually runs
in.

Estimated from two deployment measurements. The container cap was 512 MB and
steady state across the seven processes was about 200 MB. Headroom was
therefore about 312 MB.

```
312 x 10^6 / 95        = 3.28 x 10^6 messages
3.28 x 10^6 / 2 per s  = 1.64 x 10^6 s = 19 days
```

**19 days, not 220.**

The failure is not a slow leak. The tree is rebuilt at every start, so a
`feed.db` past that size cannot be opened at all. The kernel kills the process,
the entrypoint exits, and Docker restarts the container into the same failure.
[`feed.rs:534`](../services/src/feed.rs) records the same failure from the
message list before it was streamed: "the process died on the read every time,
with a perfectly intact database on disk and no way in to it."

**At scale.** Estimated, using 3.28M messages of headroom.

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | The container is killed after 7.6 days. It then cannot restart. |
| 100,000 | 500 | The container is killed after 1.8 hours. |
| 1,000,000 | 5,000 | The container is killed after 11 minutes. |

**The on-disk solution, and what it costs.** Store one row per perfect subtree
hash, keyed by level and index, in `feed.db`. An append writes one leaf hash
plus the number of trailing 1 bits in the new leaf's index. That is under one
node hash per append on average, and nothing already stored is rewritten
([`merkle.rs:31`](../services/src/merkle.rs)). A proof reads `ceil(log2(n))`
rows.

Costs, estimated:

- Disk: 64 bytes of hash a message plus SQLite row overhead. Call it 100 bytes
  a message. That is 59% on top of the 169.4 bytes a message `feed.db` already
  costs, measured.
- Memory: bounded. Only the incomplete right side of the tree is held, which is
  `log2(n)` hashes. At 100 million messages that is 27 hashes, 864 bytes.
- CPU: one row write per append, inside the transaction the message already
  writes. No extra fsync, because one tick is already one transaction
  ([`generate.rs:37`](../services/src/feed/generate.rs)).
- A proof becomes 17 to 30 row reads instead of a memory lookup.
- Startup stops hashing the whole history again. The 7 ms over 44,000 messages
  goes away, and so does the linear growth behind it.

**When to revisit.** Now, if uptime past two weeks matters. [PLAN.md](PLAN.md)
ranks this fourth of six, because a bug in production ranks higher.

---

## One binary, seven processes, one container

**Chosen.** One Rust binary with subcommands. Seven processes started by
[`docker/entrypoint.sh`](../docker/entrypoint.sh): the separate service, the
sequencer, three validators, the exchange, and the bot. One container, one
lifetime. If any one process exits, the script kills the rest and exits
non-zero, so Docker restarts the whole container.

**Over.**

- Seven binaries, one per program.
- Seven containers, or Kubernetes.
- One process with seven threads.

**Why.** They are one demonstration with one lifetime. A container whose
sequencer has died but whose UI still answers is worse than one that is down.
It still answers requests. It serves a market that no longer changes. Nothing
tells a visitor the difference
([`docker/entrypoint.sh`](../docker/entrypoint.sh)).

One binary also means the exchange and the checker ship from one build, so
version skew between them cannot happen on this deployment.

**Costs now.**

- Memory: about 200 MB across the seven processes, measured. The cap is 512 MB.
- Disk: one binary, 13,818,936 bytes.
- CPU: seven event loops. The sequencer ticks every 100 ms, the exchange polls
  every 200 ms, three validators poll, and the bot polls.
- Network: loopback inside the container. Traefik reaches the exchange on 3001.
- A crash of any one process restarts all seven. The sequencer then reloads the
  whole history and builds the tree again.

**The anchor key is the one thing the container does not hold, and that is its
own decision.** It arrives as a mounted file, never as an environment
variable. An
environment variable is readable through `docker inspect`, through
`/proc/<pid>/environ` for anything running as the same user, and through the
deployment interface that set it. Setting `ANCHOR_KEY` makes the sender refuse
to start ([`anchor/README.md`](../anchor/README.md)).

The anchor sender shares the container's lifetime like everything else, so the
entrypoint checks the key file itself before starting it. An unreadable key
would otherwise make the sender exit, and one exit stops all seven processes.
The exchange is the thing being served, and the anchor is evidence about it, so
not anchoring is the better failure. The UI shows the age of the last anchor,
which makes it visible ([`docker/entrypoint.sh`](../docker/entrypoint.sh)).

**The weakness, stated plainly.** The three validators are three copies of one
binary, on one machine, started by the operator.
[`ROADMAP.md`](../services/ROADMAP.md) already says a vote taken among them is
not a second opinion. The container makes it concrete: one memory cap, one
kernel, one restart.

**At scale.**

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing. 200 MB against a 512 MB cap. |
| 100,000 | 500 | The single volume. 500 messages a second writes 7.3 GB of `feed.db` a day to one disk, and every restart reloads it. |
| 1,000,000 | 5,000 | The model itself. Validators must run on other machines, owned by other parties, or they add nothing. |

**When to revisit.** When a validator is run by somebody who is not the
operator. That is the first thing that cannot share the operator's container.
Splitting the processes would then make the runtime match the trust boundary.

---

## SQLite

**Chosen.** SQLite, one file per program, with `journal_mode = WAL`,
`synchronous = FULL` and `busy_timeout = 5000`. It is bundled into the binary,
so the runtime image needs no database package.

**Over.**

- PostgreSQL. A server, a connection pool, and a second thing to run.
- Append-only files with an index built by hand.
- No database. Hold the history in memory only.

**Why.** Each file has exactly one writer. The sequencer is the only writer of
`feed.db`, and the exchange the only writer of `state.db`. So SQLite's
single-writer limit costs nothing. `synchronous = FULL` means a committed
message survives power loss, not only a process exit
([`feed/db.rs:17`](../services/src/feed/db.rs)). One tick is one transaction
and one fsync, however high the rate.

**Costs now.** Measured on `run/feed.db`, 106,554 messages.

- Disk: 169.4 bytes a message. Of that, 121.0 bytes is the message text and
  32.0 bytes is the chain hash. The remaining 16.4 bytes is page and index
  overhead.
- The WAL file was 4,140,632 bytes beside an 18,046,976 byte database.
- Memory: bounded. The startup pass reads rows one at a time
  ([`feed.rs:529`](../services/src/feed.rs)).
- CPU: at most 10 fsyncs a second from the sequencer, because the generator
  ticks every 100 ms and each publishing tick is one transaction.

**Where it breaks, and it is not the sequencer.** The separate service writes
one row per `POST /submit`, and every write goes through an fsync
([`inbox.rs:1201`](../services/src/inbox.rs)). That is one fsync per
submission, not one per tick. Estimated: a consumer NVMe fsync costs 0.1 to
1 ms. So the ceiling is 1,000 to 10,000 submissions a second. One writer lock
serialises them, so more disks do not help.

**At scale.**

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing. 73 MB a day, 27 GB a year. |
| 100,000 | 500 | Disk. 7.3 GB a day, 2.7 TB a year, on one volume. |
| 1,000,000 | 5,000 | The separate service. 5,000 fsyncs a second through one writer lock is past any single disk. `POST /submit` then returns 503 at 5,000 pending entries ([`inbox.rs:162`](../services/src/inbox.rs)). |

**When to revisit.** When the separate service takes more than about 500
submissions a second, or when `feed.db` passes what one disk holds. The
sequencer's own writes are not the problem at any rate in this table.

---

## No zero-knowledge proof of execution

**Chosen.** Signed execution claims, published over HTTP, checked by
re-executing the history.

**Over.** A zkVM, specifically RISC Zero, so an auditor checks a receipt
instead of re-executing.

**Why.** This was measured, not skipped. Proving this system's message rate on
one consumer GPU costs 1.5 to 7 minutes per 1,000 messages. Re-executing the
same batch natively costs about 2 ms
([`ROADMAP.md`](../services/ROADMAP.md), "Why there is no zkVM here"). The
prover would run four to five orders of magnitude behind the exchange it is
meant to be proving.

It also solves the wrong problem. The gap was that execution claims were
unsigned rows in a private SQLite file. A third party could not obtain them,
and the operator could edit them. Neither is fixed by making the check cheaper.

**Costs now.**

- The audit is linear in history, and every auditor pays it again.
- Measured, release build, local: 1,840 messages re-execute in 0.02 s, which is
  92,000 messages a second (README).
- The claim boundary rehashes the whole state. The live exchange holds 1,503
  resting orders, so one state root is 1,503 order hashes plus every position.

**At scale.** Estimated, at 92,000 messages a second, for one year of history.

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing serious. 158M messages re-execute in 29 minutes. |
| 100,000 | 500 | The time to audit. 15.8 billion messages take 48 hours. |
| 1,000,000 | 5,000 | Nobody audits. 158 billion messages take 20 days. |

**The prerequisite, and it is breaking.** `state_root` hashes the whole state
at every boundary. A prover needs a sparse Merkle tree over orders and
positions, so a batch's proof is logarithmic in state size. That changes the
on-disk commitment format and every root ever published
([`ROADMAP.md`](../services/ROADMAP.md)).

**When to revisit.** When proving 1,000 messages costs less than re-executing
them. Not before.

---

## The used-nonce set never expires

**Chosen.** The sequencer keeps every `(account, nonce)` pair it has ever
accepted. Nothing expires.

**Over.** A bounded seen-set with a time limit.

**Why.** A bounded set puts a clock in the path of `sequence_drained`. A
sequencer that was down long enough would then refuse a pending entry that was
never a replay. It would report a censorship alarm for its own outage
([`feed.rs:411`](../services/src/feed.rs)).

The set has no table of its own and needs none. Every nonce is inside the
message it authorised, so the set is one pass over the reloaded history. It is
exactly as written to disk, and exactly as tamper-evident, as the history
itself.

**Costs now.** 3.1 bytes a message, measured
([`ROADMAP.md`](../services/ROADMAP.md)). Only real signed submissions add to
it, so the demonstration's generated traffic costs nothing.

**At scale.** At scale every message is a real submission, so every message
costs 3.1 bytes. Estimated, for one year:

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | 158M messages is 490 MB in memory. Past the container cap on its own. |
| 100,000 | 500 | 49 GB a year. |
| 1,000,000 | 5,000 | 490 GB a year. |

**When to revisit.** In the same change as the tree. Both are unbounded
per-message structures on the heap, and both are rebuilt at every start. The
tree is 30 times larger per message, so it fails first.

---

## Restart monthly with a fresh database, rather than segment the log

**Chosen.** Restart monthly with a fresh database. The rate was 2 messages a
second when this was decided, and it is 24 now.

**Over.** Segment the log. Each period is its own append-only segment, and the
first message of segment N commits to the final signed root of segment N-1.

**Why.** `--verify` reads the run's whole trade record into memory, at about
259 bytes a message. That is the number that decides how long a deployment can
run before its own audit tool stops fitting on it. A monthly restart keeps
`--verify` usable on a small host, and keeps `feed.db` under a gigabyte.

**What it cost when this was decided.** Measured, from
[`ROADMAP.md`](../services/ROADMAP.md), at 164 bytes a message on disk:

| rate | messages a month | `feed.db` | `--verify` peak |
|---|---|---|---|
| 2/s | 5.2M | 850 MB | 1.3 GB |
| 5/s | 13M | 2.1 GB | 3.4 GB |
| 25/s | 65M | 10.6 GB | 17 GB |

**What it costs, plainly.** The verification horizon is one month. A signed
receipt from before a restart names a message in a history that no longer
exists. The new run announces a new session, so nothing links the two. For a
system whose whole claim is that you can check it yourself, that is a real
limitation.

**At scale.**

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | `--verify` needs 3.4 GB a month and exceeds the deployment budget. `--audit-url` still works, because it streams. |
| 100,000 | 500 | `--verify` is unusable. Only `--audit-url` remains, and it has no ceiling. |
| 1,000,000 | 5,000 | The restart throws away 13 billion messages a month. Segments become the only answer. |

**Revised on 2026-08-17.** The old reason is gone, and the decision stands.
`--verify` no longer reads the run's whole trade record into memory. It reads
the record in two sequential scans and keeps no row,
[`verify/trades.rs`](../services/src/verify/trades.rs). Measured on two
databases on 2026-08-17. At 319,705 messages, peak memory fell from 108.3 MB to
26.2 MB. At 2,572,509 messages, it fell from 707.7 MB to 28.1 MB.
Eight times the history added 279 bytes a message before and 0.87 bytes a
message after. Both binaries printed the same 25 checks with the same counts on
both databases. So the numbers in the two tables above are what `--verify`
cost, and not what it costs. The row `1,000 users` no longer breaks: 3.4 GB a
month of peak memory was the old shape, and the new shape does not follow the
length of the history.

The monthly restart stays, for the other cost in the same tables: `feed.db` on
disk. That cost has doubled since the tables above because the Merkle tree moved
from memory into `merkle_nodes` rows in the same file. Two measurements on the
live deployment on 2026-08-17 found 331 to 334 bytes per message. At 24
messages a second one month is 62.2M messages and 20.6 to 20.8 GB. The restart
is now a choice about how much history to keep, and not a memory limit the
process imposes.

**When to revisit.** When a receipt has to survive a restart. That is a product
decision, not a storage one. The anchor half of segmentation already exists in
[`anchor/`](../anchor); the seam does not.

---

## Keys are pinned on first use

**Chosen.** Trust on first use. The separate service pins each account's public
key on that account's first accepted submission. It pins the sequencer's key
from `GET /head` on first contact.

**Over.**

- An operator-held registry of account keys.
- A certificate authority.

**Why.** An operator-held list gives the operator a way to censor before an
order exists. Refuse to register an account, and that account cannot submit.
That is the exact power the separate service exists to take away
([`inbox.rs:53`](../services/src/inbox.rs)).

**Costs now.**

- First contact is not authenticated. Whoever submits first as account N owns
  account N.
- An account whose key reached the sequencer and the separate service in a
  different order is refused. The entry then stays pending and is reported
  late, with no explanation ([`inbox.rs:80`](../services/src/inbox.rs)). That
  is a false censorship alarm, caused by the pinning rule.
- Storage: one row per account.

**Account ids collide.** The browser derives the id from SHA-512 of the public
key, into the range 1,000,000 to 2^32-1. That leaves 4,293,967,296 ids
([API.md](API.md)). Estimated collisions, from the birthday bound
`n^2 / 2N`:

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing. About 1 chance in 8,600 that any two collide. |
| 100,000 | 500 | Collisions. About 1.2 pairs expected, and a 69% chance of at least one. Each one gives a visitor `403` forever. |
| 1,000,000 | 5,000 | Collisions. About 116 pairs expected. The id space is too small. |

**When to revisit.** At 100,000 accounts, on the collision arithmetic alone.
The fix is an id from somewhere with its own history, such as a wallet address
on the chain this exchange already anchors to.

---

## Every matching rule is written twice

**Chosen.** The exchange implements each matching rule, and the checker
implements it again with separate code. `verify.rs` imports `feed`, `logchain`
and `wire`. It never imports `matcher`. The pipeline step modules are private,
and every item in them is `pub(super)`.

**Over.**

- One shared pipeline module, called by both.
- One implementation, and more tests around it.

**Why.** Two implementations that share no matching code can catch each other's
bugs. If both call the same module, a bug in that module is invisible to both
([ENGINE.md](ENGINE.md) section 5). The private modules make reusing a step a
compile error rather than a review comment.

**Costs now.**

- Every feature is built twice. The exchange is 9,864 lines across `matcher.rs`
  and `matcher/`, and the checker is 4,073 across `verify.rs` and `verify/`.
  Both numbers were last written down when each program was one file, and both
  were wrong by more than half.
- Two sites in `verify.rs` decide what the checker does with a message kind it
  cannot replay. Those are behaviour decisions, not mechanical edits
  ([PLAN.md](PLAN.md), "A change that cannot run in parallel").
- The two can drift apart. Only the audit makes them disagree out loud.

**At scale.**

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing. The cost is per rule, not per message. |
| 100,000 | 500 | Nothing. Same. |
| 1,000,000 | 5,000 | Nothing. Same. The cost is one extra implementation for each new rule, forever. |

**When to revisit.** Never, while the project's claim is that you can check it
yourself. Making any step `pub(crate)` is how the checker stops being
independent ([ENGINE.md](ENGINE.md) section 4).

---

## A session names a signed history, not a database file

**Chosen.** Mint a new session whenever the database holds no signed
checkpoint. Applied in commit `2d04a98`
([`feed.rs:835`](../services/src/feed.rs)).

**Over.** Mint the session on the first open of the database file. That is what
ran before, and it is what the attack below defeated.

**Why.** An adversarial review found an attack, and it was reproduced by hand.

```
running sequencer:  session 84e864467850cf24  last_id 290

sqlite3 f.db "DELETE FROM feed_messages;
              DELETE FROM feed_meta WHERE key='checkpoint';"

restart:            session 84e864467850cf24  last_id 190
```

The same session and the same key now sign a different history. Nothing
refuses. Nothing warns. Replay protection fails with it. The used-nonce set is
rebuilt from the rows, so an empty table means an empty set. The account table
survives in its own table. So an order refused as a duplicate before the wipe
is accepted after it.

**The cause.** The session was minted on first open, before anything was
published. So a fresh database and an emptied one were the same thing: session
present, no checkpoint, no rows.

Every other tampering path was already closed, and all four were tested: edit a
message, edit a chain value, delete a row from the middle, truncate the tail.
Deleting everything skipped all three checks, because the evidence that
anything existed is the row the attacker deletes.

**What the fix costs.**

- Runtime: one comparison at startup. Nothing measurable.
- A wiped database gets a new name, and the name is the alarm. The anchor
  contract reverts a session change with `SessionChanged()`. Validators reset
  their cursor and carry the new name in their attestation. The exchange opens
  a new run.
- The ordinary restart of a checkpointed database is untouched. Same name, same
  ids, and nothing downstream resets. That is the common case, and it has to
  stay quiet.
- The session is now written to disk in the same transaction as the checkpoint
  and nowhere else, so the two cannot be caught apart.

**The second half, still open, and now sharper.** A wipe changes the name, so
it no longer lands in the blind spot. Restoring an older copy of `feed.db`
still does. Every startup check passes, because an old copy of a history is a
valid prefix of that history and keeps its name by design. The sequencer then
serves a head standing behind every validator's cursor, inside the session they
pinned. Each validator files it as `HeadDoesNotCover` and waits. `validator.rs`
needs `head.last_id < state.cursor` to be a dispute, and there is nowhere else
it can be caught.

**At scale.**

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing. One comparison at startup. |
| 100,000 | 500 | Nothing. The cost does not scale. |
| 1,000,000 | 5,000 | Nothing technical. The value of the alarm grows with the number of people relying on it. |

**When to revisit.** The first half is closed. The second half is open, and it
is the sharper one. A restored file is the remaining path.

---

## Signatures cover a named statement, and are verified strictly

**Chosen.** Every signature covers a newline-separated statement whose first
line names the statement and its version. Verification uses `verify_strict`,
not plain verification.

```
exchange-feed-sth-v1\n<session>\n<timestamp_ms>\n<tree_size>\n<root_hash_hex>
exchange-feed-head-v1\n<session>\n<last_id>\n<chain_hex>
exchange-feed-checkpoint-v1\n<session>\n<last_id>\n<chain_hex>\n<root_hex>
```

The third one is not served to anyone. It is the checkpoint row inside
`feed.db`, and it is in this list because it is signed by the same key as the
other two and has to be unreadable as either of them.

**Over.**

- Sign the raw bytes of the value, with no statement name and no version.
- Plain Ed25519 verification, which is the default in most libraries.

**Why the statement.** A signature over bare bytes can be reused in another
context. The first line makes a tree head signature useless as a chain head
signature. The version makes a v1 signature useless under v2.

**Why strict.** `verify_strict` refuses the malleable edge cases that plain
verification accepts. A verifier that is more lenient than the signer accepts
signatures the sequencer itself would reject. In JavaScript with
noble-ed25519 that means `zip215: false`, which is not the default
([ENGINE.md](ENGINE.md) section 1.5).

**Costs now.**

- CPU: nothing measurable. The statement is under 200 bytes.
- Network: nothing. The verifier rebuilds the statement and never receives it.
- Every verifier must be told the exact bytes. This was documented nowhere
  until [ENGINE.md](ENGINE.md) section 1.5 was written, so an outsider had to
  read `logchain.rs` to check one signature.
- The signature must be checked before anything else is fetched. A root that is
  not checked against a signature is a number the operator chose, and a proof
  against such a root always verifies.

**At scale.**

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing. One signature per tree head. |
| 100,000 | 500 | Nothing. A head that nothing changed is served again, not signed again. |
| 1,000,000 | 5,000 | Nothing. A verifier does one signature check and `log2(n)` hashes, at any size. |

**When to revisit.** When a statement changes. The version in the first line
goes up, and signatures made under the old statement stay checkable.

---

## Anchor every five minutes, to a contract the operator writes

**Chosen.** A separate Go program reads only public endpoints, and writes one
tuple to a contract on Base Sepolia every five minutes.

**Over.**

- Anchor every message. One transaction per message.
- Anchor once an hour, or once a day.
- No anchor. The signed head and the claims are the whole record.

**Why.** The interval bounds how much recent history a rewind could reach. At
five minutes an operator could rewrite at most the last five minutes without
contradicting an anchor. It is not a cost decision, and the runway below is why.

**Costs now.** Measured over the first nine anchors on Base Sepolia
([`anchor/README.md`](../anchor/README.md)):

| | gas | total |
|---|---|---|
| first write, cold storage | 93,190 | 0.000000567 ETH |
| every write after | 41,799 | 0.000000259 ETH |

- The L1 data fee is 3.1% of the cost. The calldata is 132 bytes.
- On 1.054 ETH that is 4,074,804 anchors, or 38.7 years at five minutes.
- Network: about 2,900 JSON-RPC calls a day, about 0.03 a second.
- Verified live on 2026-08-15: `latest()` on
  `0x2A4A287EC1F01b5bCb5568D2Ed0765Faf860a62b` returns count 147, at message
  106,003.

**Two contracts, not one slot.** `ExchangeRootAnchor` commits the RFC 9162 root
instead of the chain hash. The live one is
`0x4162B3218b97663dEBC1f59060910221bb95672d`. A contract pins its session on
its first write, so each reset of the log needs a new one, and there are four.
See [`anchor/README.md`](../anchor/README.md) for the table. A
root is 32 bytes and so is a chain hash, so a root would fit the old contract's
slot and every transaction would succeed. Nothing on chain would then say which
anchors were chains and which were roots. The event signatures differ, so one
`eth_getLogs` filter returns one kind and cannot return the other
([`anchor.rs:27`](../services/src/anchor.rs)).

**At scale.**

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing. The cost is per anchor, not per message. |
| 100,000 | 500 | The anchor sender. It hashes every message between anchors again: 150,000 messages a tick, 18.6 MB. |
| 1,000,000 | 5,000 | The same, badly. 1.5M messages a tick is 186 MB every five minutes. Only the proof path scales. |

The root anchor removes that. Checking an anchored root against the current
tree head costs about 17 hashes and one request, against one pass over the
history ([`anchor.rs:1541`](../services/src/anchor.rs)).

**When to revisit.** Never for the interval. It has 38.7 years of runway. Now
for the sender hashing the whole window again, and the root anchor is that
change.

---

## The checkpoint commits to the tree, not only the chain

**Chosen.** The checkpoint row in `feed.db` carries the Merkle root beside the
chain, under a second signature over
`exchange-feed-checkpoint-v1\n<session>\n<last_id>\n<chain_hex>\n<root_hex>`.
A start computes `MTH` over the stored nodes, one node per set bit of the
message count, and refuses if it is not the root that was signed. A checkpoint
with no root buys the tree beside it no trust at all: that start builds the tree
again from the messages.

**Over.**

- Leave the tree unchecked, which is what it was when it moved out of memory
  into `merkle_nodes`: count the rows, read the highest leaf index, read no
  hash.
- A root column beside the nodes, or a table of its own. An unsigned number
  proves nothing: whoever rewrote the nodes rewrites it in the same statement.
- Put the root inside the existing `exchange-feed-head-v1` statement. Every
  receipt, every `/orders` page header and every checkpoint already on disk is
  signed under that statement, and none has a root. A binary reading a database
  written by a newer version would report its intact history as signed by the
  wrong key.
- Rehash the whole tree at a start. That is the pass over the history that
  putting the tree on disk removed, and it would put it back.

**Why.** The startup check on `merkle_nodes` read two numbers, and the comment
above it said a node that had been meddled with produces a proof that does not
verify. That is backwards. The root the feed signs is computed *from* those
rows. Rewriting a node therefore moves the root, and every proof over the
rewritten tree verifies against the new root. Written as
a test: the tree over the same eight messages with one leaf replaced, the same
row count, the same highest leaf index, `feed_messages` and the chain column and
the checkpoint untouched. The feed started, signed `/sth` over
`52fc004c09ae…` where the honest root is `c180a0f44f55…`, and served an
inclusion proof for bytes that were in no message which verified against it.
Anyone who could write to `feed.db`, the threat every other startup check is
there for, made the operator's key sign a commitment to messages that were
never published, with no binary patch and no key.

**Refuse, not rebuild.** A tree that disagrees with the signed root is equivalent
to an edited chain link inside an intact history. The messages are still the
ones published by this feed, so stopping loses nothing. Signed data and derived
storage disagree only if something else wrote to the file.

Rebuilding would silently repair the evidence and leave no trace. The feed
would sign the same root after either path. That behavior caused the earlier
chain-link problem described in the README.

A structurally broken table is different. Missing or extra rows, or a leaf past
the message count, can come from a build without `merkle_nodes` or an operator's
`DELETE`. Those rows are rebuilt from the messages.

**Costs now.** Measured on 100,000 messages, release build, on the development
host:

| | |
|---|---|
| restart, tree read and checked against the signed root | 62 ms |
| first start on a checkpoint with no root, tree built again | 284 ms |

- Publishing: one more Ed25519 signature per burst, about 25 µs, inside the
  transaction that already pays an fsync. The root it signs is read back out of
  the rows the same transaction just wrote: 17 rows at 100,000 messages.
- Starting: the same 17 rows and 17 hashes, at the 0.05 ms an index seek costs
  on that table.
- The migration is paid on every start until the feed publishes one message,
  because publishing is what writes a checkpoint carrying a root. A feed that is
  publishing pays it once.

**At scale.**

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | Nothing. One signature a burst, 17 reads a start. |
| 100,000 | 500 | Nothing. Both costs are `log2(n)`. |
| 1,000,000 | 5,000 | Nothing steady-state. The one-off rebuild for a checkpoint with no root is `O(n)`: a year at that rate is 63M messages, so that upgrade start is minutes, not milliseconds. Publish one message and the start after it is `log2(n)` again. |

**Where it stops.** Reading the root reads one node per set bit of the size, so
a node underneath one of those is not read at a start and a rewrite of it is not
refused. Such a rewrite cannot forge anything. The root does not move, and the
feed keeps signing the root made by its messages. A proof that reads the changed
node fails against that signed root. Making
bytes verify needs the root to move with them.

**When to revisit.** When the signed tree head's timestamp has to survive a
restart. That is the other tree fact with nowhere else to live, and this row is
where it belongs. Also if the rebuild for a checkpoint with no root ever needs
to happen once instead of at every start before the first publish. The place
for that is a checkpoint written by the start that rebuilt, which would make
that start the second thing in the program that signs one.

---

## Serve the stored Merkle nodes, so a stranger can check them

**Chosen.** `GET /tree/nodes?from=N&count=M` serves the nodes the sequencer
stored for the appends of leaves `N..N+M`, and the checker and the audit fold
the messages they were served into the same tree and compare every one of them.
A node that does not match is a failed check and exit 1.

**The hole this closes.** `merkle_nodes` was the one record this exchange writes
that nothing outside the operator ever checked. Every other record is signed or
derived from signed data. Messages fold to the chain carried by the head. The
chain and root carry Ed25519 signatures, and the root goes to a public chain
every five minutes. The nodes between the leaves and the root are none of
those. `services/tests/crash_restart.rs` did compare them against the messages,
with the database file open, inside this repository's own test suite. A
stranger has HTTP.

**What a wrong node actually does, measured.** Less than the obvious guess, and
the measurement is why this entry exists at all. `services/tests/adversarial.rs`
overwrites the node at level 0, index 40 in a 358-message log. The root does not
change. `mth` returns the stored hash of a perfect subtree without descending
into it. Over 358 leaves, the root reads the node at level 8, index 0. It never
reads leaf 40. `/sth` is unchanged, every signature still verifies, and
every anchored root still reproduces. Exactly one thing changes, and a probe
over the repository's own `merkle` module says which: the inclusion proof for
leaf 41, the only proof that reads leaf 40.

So a wrong node forges no inclusion and hides no message. It denies proof
service for specific messages: the messages under that node can no longer be
shown to be in the log. It is detected by the one person who most cares,
whoever asks for that proof, because a wrong proof fails against the signed
root. That is a smaller and more precise claim than "missed by every tool", and
the row in `adversarial.rs` says so.

**Over.**

- **Leave it.** The argument for leaving it is the paragraph above: it forges
  nothing. The argument against is that `merkle_nodes` is unsigned derived
  storage that nothing rederives, like `feed_accounts`. A project based on
  outside verification should not keep a table that only the operator can
  check. It was cheap to close.
- **A root check alone.** It does not find this. The report shows both lines in
  the same run: `the signed tree head is over these messages` passes while
  `every stored node is the one the messages make` fails.
- **Inclusion proofs instead of an endpoint.** Each inclusion proof exposes
  exactly one level-0 node, the sibling of the leaf asked for, so catching a
  single wrong leaf hash needs one request per message: 380 in the test,
  63 million on a year-old log. The endpoint reads the same nodes in pages.
- **Page by node range rather than by leaf window.** A reader makes its nodes in
  append order, one page of messages at a time, and holds only the tree's right
  edge. Serving nodes ordered by `(level, index)` would force one side to hold
  the whole tree to line the two up. A leaf window is the order both sides
  already work in, and `(level, index)` is the primary key, so each node is a
  point lookup.
- **Sign the nodes.** A signature would prove the sequencer said them, which is
  the thing the reader is testing. The reader checks them against its own fold
  of the messages instead.

**What it costs.** One leaf makes just under two nodes, so a full read of the
nodes beside a full read of the messages is about half as many bytes again.
Measured on the live exchange on 2026-08-17: `GET /tree/nodes` served 1,994
nodes for 1,000 leaves, which is 64 bytes of hash a message, against 122 bytes
a message on the wire from `/messages.ndjson`. Neither tool's memory moves: the
checker and the audit hold one page of nodes and the tree's right edge, both
under a few thousand hashes, and neither grows with the length of the history.

On the sequencer, a page is at most 2,000 point lookups on a `WITHOUT ROWID`
primary key, and a page below the head is cacheable: a perfect subtree never
changes once complete.

**What is written once.** `merkle::appended_at` says which nodes one append
makes. `append_nodes` walks the list to fill in hashes. The endpoint walks it to
select rows, and the reader walks it to identify required nodes.
`merkle::compare_nodes` performs the comparison. It is called by
`crash_restart.rs` with the file open and by both tools over HTTP. One rule sets
the comparison boundary: a node covering an unread leaf cannot be checked.

**When to revisit.** If a reader ever needs to check the nodes without reading
the messages. It cannot today, and that is correct: a level-0 node is the leaf
hash of a message, so checking it means having the message.

---

## Real balances, a second key for orders, and a withdrawal that waits

**Nothing in this entry is built.** No code in this repository holds a balance,
reads a token contract, or moves money. `grep -rn "withdraw\|deposit"
services/src` returns three lines, and all three are comments about an order
being taken off the book ([`verify.rs:1583`](../services/src/verify.rs),
[`bot.rs:536`](../services/src/bot.rs),
[`matcher.rs:2142`](../services/src/matcher.rs)). `vault`, `faucet`, `erc20`
and `multisig` return nothing at all. Read this entry as the argument for work
that is decided and not started. "No zero-knowledge proof of execution" above
is also about something that does not exist, but that one records a rejection.
This one records a plan, so the difference has to be said once and plainly:
**the code described below does not run anywhere.**

**Chosen.** Three linked decisions.

- **A.** Two keys for each account. A main key is the identity and is the only
  key that may move money. A trading key may only place and cancel orders. The
  authorisation is a message in the log, signed by the main key, naming the
  trading key, what it may do and when it expires. Revoking it is another
  message. The expiry is 24 hours.
- **B.** Balances come from real deposits. An ERC-20 token and a vault contract
  on Base Sepolia. A deposit becomes a log message carrying its transaction
  hash. Balances go into the state root. A faucet gives a visitor test tokens,
  with the gas paid for them.
- **C.** A withdrawal is a message. It waits for a challenge window to end. A
  multisig pays it if nobody disputes it. During the window anyone running the
  checker may dispute.

**Over.**

- One key that does everything. That is what runs today:
  [`app.js`](../services/static/app.js) derives the account number
  from SHA-512 of the single browser key, so the key that signs an order is the
  key that is the account.
- A session token the server holds.
- An authorisation kept in a database row beside the message. The separate
  service already stores a submitter's key and signature that way
  ([`inbox.rs:286`](../services/src/inbox.rs)).
- Invented balances, which is today. The exchange matches orders against
  balances no one paid in.
- A faucet that credits a balance directly, with no chain involved. Simpler,
  and it proves nothing.
- Instant payout on the exchange's word.
- A zero-knowledge proof of the state root instead of a challenge window. "No
  zero-knowledge proof of execution" above rules that out, and its measurement
  still holds.

### The layering, and no layer imports upward

| layer | what it holds | what it may not know |
|---|---|---|
| settlement | the token, the vault, the multisig | nothing about orders |
| bridge | watches Base, submits withdrawals | the chain and the log, not matching |
| log | deposits and withdrawals as messages | the message shape only |
| execution | balances in the engine | the log, never the chain |
| identity | main key, trading key, authorisation | signatures only |

This is the discipline the repository already uses. `verify.rs` imports `feed`,
`logchain` and `wire`, and never imports `matcher` ("Every matching rule is
written twice" above). The pipeline steps are private to their modules
([`pipeline.rs`](../services/src/matcher/pipeline.rs)). The same rule applied
here makes one error a compile error instead of a review comment: the engine
cannot call the chain, because the engine cannot see the chain.

### A. A trading key is authorised by a message, and revoked by one

**Why the authorisation is a message.** A replayer has to be able to check who
asked. Today it cannot. `OrderMessage::New` and `OrderMessage::Cancel` carry an
account number and a nonce, and no key and no signature
([`domain.rs:279`](../services/src/domain.rs),
[`domain.rs:310`](../services/src/domain.rs)). The submitter's key and
signature sit in the separate service's own database
([`inbox.rs:286`](../services/src/inbox.rs)), where the comment says why they
are kept: "so the record proves who asked". That record is not in the log.
Someone replaying `/messages.ndjson` reads account 1,000,042 and has to take
the operator's word that account 1,000,042 asked.

The three operator kinds already do it the other way. `EngineRule`,
`ListSymbol` and `DelistSymbol` each carry `public_key` and `signature` as
plain fields, and `operator::verify` checks the signature over the message's
own bytes ([`domain.rs:324`](../services/src/domain.rs),
[`operator.rs:175`](../services/src/operator.rs)). An authorisation follows
that shape. A signature in a database is invisible to anyone replaying the log;
a signature on the message is not.

**You cannot un-publish a log message.** With a JSON web token, revoking means
deleting a row, and the next request fails. Here the grant is permanent, so
revocation must be its own message. That is not a workaround. It is better: a
reader sees the exact message where a key was allowed and the exact message
where it stopped being allowed, and needs no cooperation from the operator to
see either.

**The scoping bounds the damage.** A leaked trading key costs bad fills. It
never costs the balance, because moving money needs the main key every time,
with a prompt the person sees.

**The number that decides the expiry is log cost, not security.** Every
re-authorisation is a permanent message. It is hashed into the tree, covered by
a signed head, and anchored. So the expiry is a storage decision.

Estimated, from the file's assumption of one message a user every 200 seconds
and the 169.4 bytes a message at the top of this file. One user produces
`1/200` trading messages a second and `1/3600` authorisation messages a second
at a 1-hour expiry:

```
1-hour expiry:   (1/3600) / (1/200)  = 0.05556   +5.556% of trading messages
24-hour expiry:  (1/86400) / (1/200) = 0.002315  +0.2315% of trading messages
```

Both sides scale with users, so the share is the same at every scale. As a
share of the resulting log it is 5.263% and 0.2310%, because the authorisation
messages are inside the total as well.

| users | trading msg/s | 1-hour: auth msg/s | 24-hour: auth msg/s | 1-hour: bytes a day | 24-hour: bytes a day |
|---|---|---|---|---|---|
| 1,000 | 5 | 0.278 | 0.0116 | 4.07 MB | 169 kB |
| 100,000 | 500 | 27.8 | 1.16 | 407 MB | 16.9 MB |
| 1,000,000 | 5,000 | 278 | 11.6 | 4.07 GB | 169 MB |

Arithmetic for the last row: `1,000,000 x 24 x 169.4 = 4.066 x 10^9` bytes a
day, and `1,000,000 x 1 x 169.4 = 1.694 x 10^8` bytes a day. Trading traffic at
that scale is `5,000 x 86,400 x 169.4 = 7.32 x 10^10`, which is 73.2 GB a day.

**Those bytes are understated, and by three times.** 169.4 bytes is the average
message in the log today, and that log is nearly all generated orders with no
key and no signature on them. An authorisation message carries a 64-character
public key, a 128-character signature, a 64-character trading key, an expiry
and a scope. Estimated from the shapes that exist: `New` serialises to 117
bytes and `EngineRule` to 305 bytes, both measured on the test vectors in
[`domain.rs:675`](../services/src/domain.rs). Adding the trading key, the scope
and the expiry to the `EngineRule` shape gives 462 bytes of message text. In
`feed.db` that is `462 + 32.0 + 16.4 = 510.4` bytes, using the measured chain
column and page overhead at the top of this file. That is 3.01 times the
average message. So the byte columns above become 12.25 GB a day and 510 MB a
day at a million users. The log adds 16.7% to trading traffic with a 1-hour
expiry, compared with 0.70% at 24 hours.

**Chosen: 24 hours, revocation available at any moment, and silent
re-authorisation while the person is active.** A long expiry is only dangerous
when you cannot cancel early. Revocation is one message, and it is the same
cost whether the grant had one hour or one day left.

**What this breaks, and it is real.** The separate service pins one key for
each account on first use, and from then on accepts a submission naming that
account only under the pinned key ([`inbox.rs:74`](../services/src/inbox.rs)).
Two keys for one account contradicts that rule directly. Every ownership check
downstream rests on it. The cancel-ownership check in `matcher.rs` and
`cancel_takes_effect` in `verify.rs` compare account numbers. Those numbers mean
"the holder of account N's key asked for this" only because of the pin. And the
account number is derived from the key that signs
([`app.js`](../services/static/app.js)), so the derivation has to
move to the main key while a different key signs the order. Neither is hard.
Both are changes to the rule that every ownership statement in this system
currently stands on, so neither is a small edit.

### B. Balances come from real deposits

**Why.** Today the exchange proves it matched orders correctly against balances
it invented. The claim is true and narrow. The checker already reconciles cash:
`cash matches the prices the feed published` builds two ledgers, one from the
trade rows and one from the feed's own published prices, and compares them
([`verify.rs:1544`](../services/src/verify.rs)). It has no opening balance to
start from and never asks whether an account had the money. Nothing can ask,
because nobody ever paid anything in.

With real deposits the claim becomes: **the sum of every account balance equals
what the vault holds.** That is solvency. Anyone checks it with two numbers,
the state root and the contract's balance. It is the property a centralised
exchange asks you to take on faith.

**The transaction hash is the field that removes the trusted party.** Without
it, an observer has to trust whoever watched the chain. With it, a replayer
queries Base and checks for themselves. Estimated size of a deposit message:
188 bytes of text, built the same way as the authorisation message above. The
66-character transaction hash costs 79 bytes with its field name and its comma,
which is 42% of the message. That 42% is what an observer would otherwise have
to trust a person for.

**The rule must not bend.** The engine never calls the chain. If a replay
depends on network state it stops being deterministic, and every verification
claim in this file goes with it. The bridge observes, the log records, the
engine replays what the log says. The repository already keeps that separation:
`matcher.rs` uses `reqwest` only to poll the sequencer, and `/anchor-config`
serves the contract address to the browser so the **browser** reads Base, not
the exchange ([`matcher.rs:4763`](../services/src/matcher.rs)). The anchor
sender is a separate program that reads only public endpoints ("Anchor every
five minutes, to a contract the operator writes" above).

Base Sepolia is already in use for the anchors, at
`0x4162B3218b97663dEBC1f59060910221bb95672d` and the two closed contracts
before it, so the chain, the key handling and the sender are not new work.

### C. A withdrawal waits, and anyone may dispute it

**Why only withdrawals.** A wrong deposit costs the operator and not the user.
An operator who understates a deposit is caught by the transaction hash in the
message; one who overstates it gives away money. **A withdrawal is the only
direction where money leaves on the exchange's word.** The checker is already a
second implementation of every matching rule, and it has never had anywhere to
send a verdict: `grep -n dispute services/src/verify.rs` returns nothing. It
prints PASS or FAIL and exits. The validators have a `disputed` field
([`validator.rs:106`](../services/src/validator.rs)), but that is about the
order of messages, not about execution. The challenge window is the first place
a checker's verdict can go.

**The window has to be longer than a full check takes. Measured, on this host,
release build, on 2026-08-15.**

| what was checked | messages | claim boundaries | wall clock | user CPU |
|---|---|---|---|---|
| a local log over loopback | 232,204 | 1,136 | 6.25 s | 6.67 s |
| the live exchange over the internet | 193,224 | 169,939 | 94.02 s | 7.23 s |
| a local log, small | 6,498 | 2,355 | 0.14 s | 0.14 s |

Two facts come out of that, and they do not agree about what the window costs.

**Re-execution is not the cost.** 232,204 messages re-execute in 6.67 s of CPU,
which is 34,813 messages a second. The live exchange holds 193,943 messages
(measured on `/head`), so re-executing all of it costs about 6 s.

**Fetching is the cost.** The same audit against the live exchange took 94.02 s
of wall clock for 7.23 s of CPU. 87 s of that is waiting on the network. Both
`/messages.ndjson` and `/claims` page at 1,000 rows
([`matcher.rs:3799`](../services/src/matcher.rs)), so 193,224 messages and
169,939 claims need `194 + 170 = 364` requests. `94.02 / 364 = 258 ms` a
request, estimated from the measured total.

**One caution on the second row.** That audit reported FAILED because of version
skew, not an exchange fault. The binary came from `agent/operator` and builds
its symbol registry from `ListSymbol` messages. The live log has none, so
re-execution ignored every order and produced 0 trades. All 193,224 messages
were still fetched, and all 169,939 claim boundaries were still hashed. The
wall clock therefore stands. Only the matching work
is missing from the CPU figure, and the loopback row above shows that work
costs about 6 s at this size.

**What window that justifies.** Estimated, using the measured 258 ms a request
and the measured claim rate of `169,939 / 79,417 s = 2.14` claims a second.

- At 193,943 messages: **94 s** for a from-zero audit, measured.
- At the end of a month: the mean rate is 69 messages a second, so
  `69 x 2,592,000 = 178.8 x 10^6` messages, which is 178,848 page requests at
  258 ms, or **12.8 hours** for the messages alone. Claims add an unknown amount.
  The measured 2.14 claims a second came from a message rate of 2.433 a second.
  A claim covers a batch, so its rate does not scale directly with messages.

So the window grows with the log, and it grows on request latency and not on
compute. **The 6-hour window below was sized when the deployment ran at 2.433
messages a second, and it no longer has the margin that justified it.** At the
flat 24 a second that followed, the message side alone was 4.5 hours of a
6-hour window. At the mean of 69 a second the deployment runs now, it is 12.8
hours, so the from-zero audit no longer fits inside the window at all. The
window is still under the 24 hours Arbitrum uses for a
mechanism that has to allow time for a remedy ("The inclusion deadline on the
separate service" above). This entry does not fix the number, because the
number tracks the log length, and the log length is set by the restart
decision.

**The window must be measured against a checker that is already following.** A
from-zero audit is the wrong bound to design to, because it grows without limit
while the window cannot. A checker that already holds state at message N
re-executes only the messages after N, which arrive at a mean of 69 a second
today and never faster than 114. That is the check the window has to cover. The
from-zero number above answers a different question. It measures how long a
newcomer needs before they can dispute anything.

**The multisig is a demonstration.** On Base Sepolia it holds test tokens and
shows that the mechanism works. Holding real value is a different project with
different key management, and this entry does not claim otherwise. The anchor
key already gets careful handling: a mounted file, never an environment
variable, and the sender refuses to start if `ANCHOR_KEY` is set
([`anchor/README.md`](../anchor/README.md)). A multisig holding real money
needs more than that, on hardware this project does not have.

### What was measured for this entry

Measured on 2026-08-15, on the development host, release build at commit
`94e145d`. The deployment has since moved from 2.433 messages a second to 24,
so the arithmetic above uses 24 and this table records the inputs it was first
built on:

| what | value | how |
|---|---|---|
| the live exchange's message rate | 2.433 messages a second | `/head` sampled 30 s apart, 193,870 to 193,943 |
| the live exchange's log | 193,943 messages | `/head` |
| resting orders on the live exchange | 1,998 across three symbols | `/market`, summing `open_bid_orders` and `open_ask_orders` |
| a message on the wire | 123.2 bytes | 1,000 messages from the live `/messages.ndjson` were 123,201 bytes |
| `feed.db`, whole file | 255.3 bytes a message | a 283,004-message local log was 72,241,152 bytes |
| `feed.db`, `feed_messages` only | 164.7 bytes a message | `dbstat` on the same file |
| `feed.db`, `merkle_nodes` only | 90.4 bytes a message | `dbstat` on the same file, 565,999 rows |
| re-execution rate | 34,813 messages a second | 232,204 messages in 6.67 s of CPU |
| a page request to the live exchange | 258 ms | 364 requests in 94.02 s |

The split matters when sizing a disk: `feed_messages` is 164.7 bytes a message
and `merkle_nodes` 90.4, so the tree is 35.4% of the file. The whole-file figure
at the top of this document, 331 to 334 bytes a message, is the later
measurement on the live deployment and is the one to use.

**Costs now.** Nothing. No code exists. What it will cost when it does:

- Every account needs two keys, and the browser has to hold both. The main key
  must be usable from a wallet, because it is the key that signs a withdrawal.
- The key pin in [`inbox.rs:74`](../services/src/inbox.rs) becomes a pin plus a
  replay of the authorisation messages. Intake would then need information from
  the log that it does not use today. The rule above says why intake cannot ask
  the log: a rule change between intake and sequencing would falsely report an
  honest sequencer as late. An authorisation that expires between intake and
  sequencing is exactly that failure. The safe form is that intake checks the
  signature only and the engine checks the expiry, so a stale authorisation
  costs one ignored message and no false alarm.
- Four new message kinds, so the checker implements each one a second time.
- The state root grows by one balance for every account with money in it.
- Two contracts, a bridge process and a faucet, none of which exists.
- The audit gains a step it cannot do offline: checking a deposit's transaction
  hash needs a Base node. The audit already accepts `--anchor-address` and
  reads the chain, so that path exists.

**At scale.**

| users | messages/s | what breaks first |
|---|---|---|
| 1,000 | 5 | The from-zero audit. A year is 158M messages and 158M claims, so 316,000 page requests at 258 ms, or 22.6 hours. A challenge window that covers it is longer than Arbitrum's. The multisig is still workable: 1% of users withdrawing a day is 10 human-signed transactions a day. Authorisation traffic is 0.0116 messages a second at a 24-hour expiry, which is nothing. |
| 100,000 | 500 | The multisig. 1% a day is 1,000 withdrawals a day, one every 86 seconds, and no human multisig signs at that rate. The challenge window still works, but only for a checker that follows the log continuously and re-executes 500 messages a second. A from-zero audit of a year of history is 15.8 billion messages, which is 47 days. |
| 1,000,000 | 5,000 | The dispute right itself. A year is 158 billion messages, which is 158 million page requests at 258 ms, or 472 days. Nobody can start from zero and become able to dispute. Only a checker that has followed the log from the start can use the window, and that is a small group that chooses itself. |

**When to revisit.** Decision A before the others, because the two-key change
touches the pin in [`inbox.rs:74`](../services/src/inbox.rs) that every
ownership check in this system rests on, and it is cheap to do before any money
depends on it. **Decision C's window now**, before the restart decision changes.
The rate rose from 2.433 messages a second to 24. A month's from-zero audit
therefore rose from 51 minutes to about 4.5 hours against a 6-hour window.
Decision B not at all while the
vault holds test tokens; the moment it holds anything real, the multisig is a
different project and this entry stops covering it.

---

## The pairs are MERKLE-USDC, ETH-USDC and BTC-USDC

**Chosen.** Three markets, each with its own starting mid price and price step
([`domain.rs`](../services/src/domain.rs), `SYMBOLS`):

| Symbol | Starting mid | Price step |
|---|---|---|
| MERKLE-USDC | 10.0 | 0.01 |
| ETH-USDC | 100.0 | 0.10 |
| BTC-USDC | 1000.0 | 1.00 |

Three mids a hundred times apart, so the demonstration shows three different
decimal behaviours. Each market needs its own step. A step of 0.01 made the
generator's price band 10 prices wide on MERKLE-USDC and 1,000 wide on
BTC-USDC. Orders 1,000 prices apart never met, so the BTC-USDC book became
one-sided. [`PLAN.md`](PLAN.md) step 5 has that
measurement.

**Over.**

- `NEX-USDC`. `NEX` names the take-home this project grew out of, and it is a
  search term that leads somebody sitting that exercise straight to this
  answer. Renamed in commit `331e2dc`.
- `ALFA-USD`, `BRAVO-USD`, `CHARLIE-USD`. NATO words carry nothing about the
  project.
- `ROOT` and `PROOF` as base words, which are the two best project words.
  Both fail the real-asset test: Root Inc trades on NASDAQ, and a `prove` token
  exists. A name someone can mistake for a tradeable asset is the one mistake a
  demonstration venue must not make.
- `MERKLE-PAPER`, `WITNESS-PAPER`, `CLAIM-PAPER`. This was the pick of the
  naming review. The `PAPER` quote would state that the venue simulates trading
  and settles no real money. `MERKLE` was taken and the rest was not. **Why the quote
  stayed `USDC` is not recorded anywhere, and the objection stands: USDC is
  Circle's real stablecoin, and quoting in it implies real settlement in a real
  asset.**

`MERKLE`, `WITNESS`, `CLAIM` and `PAPER` each pass the real-asset test, checked
word by word against an autocomplete price query. `MERKLE` returns nothing and
corrects to `markel stock`. `ETH` and `BTC` stay because a demonstration venue
pricing fake bitcoin is the ordinary convention and confuses nobody.

**What the names cannot do.** Renaming a pair is not an SEO mechanism. The HTML
shell contains no configured market symbol because the page reads the symbol
list from the API after it loads. Counted on 2026-08-26 across the 332,024 bytes
of `services/static/index.html` and `services/static/app.js`: `USDC` appears 10
times, `BTC-USDC` 5, `MERKLE` 2 and `ETH-USDC` 3. The remaining names are in
examples and comments. The documents and screenshot carry the project terms.

**Costs now.** A rename is 194 occurrences,
[`API.md`](API.md) 33, [`matcher.rs`](../services/src/matcher.rs) 120,
[`bot.rs`](../services/src/bot.rs) 18 and
[`inbox.rs`](../services/src/inbox.rs) 23, mostly in tests. It must land alone,
in one commit, while nothing else is running. Intake needs no edit. It applies
the symbol name rule through `operator::valid_symbol` but does not ask whether a
symbol is listed. Listing is a fact about the log, and a market can open while
the exchange runs.

**When to revisit.** When the quote unit is settled one way or the other. That
is the only open question here.
