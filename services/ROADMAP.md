# Roadmap: from a local simulation to a verifiable exchange

This document lists the steps in order. Each step builds on the one before it.
Each step keeps the same core idea: the exchange state is a function of an
ordered message list plus a position in that list.

## The two layers

- **Sequencing layer** (the sequencer): decides the order of messages. It must
  never lose the list and never change it.
- **Execution layer** (the exchange): applies the list, in order. The same list
  always gives the same result. The exchange must always be able to return to
  its last position.

## V1: one machine per layer, with its state on disk  [DONE]

What it is:

- The exchange saves its results and its cursor in `state.db`. Every batch is
  one SQLite transaction. A crash or a stop loses nothing. Restart with the
  same `--state-db` and the exchange continues.
- The sequencer writes every message to `feed.db` before it publishes the
  message. A restart reloads the full history and continues the same ids.
- The sequencer sends a session id (`x-feed-session` header) with every
  response. The session names a signed history and not a file. The session
  changes when the sequencer starts on a database that holds no signed
  checkpoint, which is a new file or one whose log was emptied. The exchange
  stores the session next to its cursor. A different session on the wire means
  one thing: this cursor points into a history that no longer exists. The
  exchange then starts a new run instead of mixing two histories.

What V1 gives: full recovery when the exchange dies, when the sequencer dies,
or when both die. What V1 does not give: protection against a *dishonest*
operator. V1 answers the machine that stops. It does not answer the operator
that lies.

## V2: signed, public log  [DONE]

What it is:

- Every message extends a hash chain: `chain_i = SHA-256(chain_{i-1} ||
  message_i)`. The chain value at message N commits to the entire history
  1..N. Change one old message and every later chain value changes.
- The sequencer has an Ed25519 key (`feed.key`, created once, kept next to
  `feed.db`). It signs `(session, last_id, chain)`, the head of the log, on
  every `/orders` response (`x-feed-*` headers) and on `GET /head`.
- `POST /order` returns a receipt: the signed head that contains the order. A
  signed history without that order cannot reproduce the receipt's chain.
- The exchange pins the sequencer's public key on first contact, and stores the
  key in `state.db`. On every poll the exchange verifies the signature. It
  computes the chain again from the messages it consumed, and compares. The
  chain commits in the same transaction as the cursor.
- A bad signature or a wrong key: the batch is not applied and
  `feed_integrity_failures` counts it. A chain that disagrees:
  `feed_chain_mismatches` counts it, and the log says which two chains
  disagreed. `chain_verified_at` in `/market` shows the verification keeping
  up.
- `--verify` computes the chain again over the sequencer's full history and
  checks the head signature. It does this without the exchange.
- The sequencer keeps a signed checkpoint of its own head in `feed.db`. It
  checks the stored messages against that checkpoint on every start, and
  refuses to run if they disagree. Without the checkpoint, editing
  `feed_messages` between two runs was enough. The sequencer reloaded the
  edited history, computed the chain over it, and signed that. The operator's
  edit became the signed record.
- That checkpoint states the Merkle root as well as the chain, and the start
  checks the stored tree against it. When the tree moved from memory into
  `merkle_nodes` it became the one thing in the file no signature reached, and
  the same edit worked again one table over. Rewriting a node moves the root
  the sequencer signs. It breaks no proof, because the root is computed from
  those same rows. So `/sth` carried the operator's signature over messages
  that were never published. See decision 18 in
  [DECISIONS.md](../docs/DECISIONS.md).

What V2 gives: tampering with sequenced history is detected, and the
sequencer's own signature is the evidence. What V2 does not give: the sequencer
can still refuse a message before sequencing it. That is V3.

## V3: separate service  [DONE, local form]

What it is:

- The separate service takes order submissions and the sequencer does not
  control it. It has its own database. Users submit there when the sequencer
  refuses them or cannot be reached. The ports, the flags and the routes are in
  [`docs/API.md`](../docs/API.md#the-separate-services-http-api).
- The sequencer reads the separate service on every tick and sequences the
  pending entries ahead of its own generated traffic. The pairing "entry N is
  message M" commits in the same transaction as the message. So a crash can
  never sequence an entry twice, and only the mark is ever repeated.
- Every entry carries the time the separate service accepted it. An entry that
  is still pending past the deadline (default 5s) is reported late. Late, plus
  the sequencer's signed head that provably does not contain the entry, is
  evidence of censorship a third party can check.
- The service confirms an entry with an RFC 9162 inclusion proof, and not by
  comparing the message field by field. Three outcomes, not two: confirmed,
  confirmed with the content unchecked, and late. Only late is an alarm. Field
  comparison called an honest sequencer late whenever the service could not read
  the message kind. False alarms make the result hard to trust.
- The alarm is on screen, and not only in a JSON endpoint. The separate service
  answers submissions from a browser. The Trade panel shows an entry as pending
  first. It then shows the sequencing time beside the deadline, or marks the
  entry late if the sequencer omits it. That last state is the one this layer
  exists to produce.

What is still only local: the separate service is one process on the operator's
own machine. An operator who wants the alarm silent can stop the separate
service rather than censor through it. A visitor then sees `separate service
unreachable` on the verification strip. That is honest, but it is not evidence
anybody can take elsewhere. That is the same gap the closing note below
describes, and closing it needs a base chain, not more code here.

What V3 does not give: a way to tell a censored entry apart from one the
sequencer justifiably would not sequence. The sequencer does refuse entries it
cannot sign for: a nonce already used for a different submission, or an
account key that reached the sequencer and the separate service in a different
order. That reason reaches the sequencer's own log and nowhere else. Both cases
look identical on `GET /status`: pending, then late. Nothing stops a dishonest
sequencer from having an excuse for an entry it refused. So the alarm stays up
either way, and whoever reads it has to find out which case it is.

What a base chain would add that this cannot: the separate service here is a
neutral local process, and the penalty for censorship is an alarm. On a chain,
the separate service is a contract whose record nobody can dispute, and the
penalty is enforced by the chain itself: it takes away a deposit, or it forces
the message in. The mechanism is the same: intake nobody controls, a deadline
for inclusion, and a violation anyone can prove.

## V4: the validators agree on the order  [DONE, safety half]

What it is:

- Validators (`--start-validator`, ports 3010 and up, `validatorN.db` and their
  own key) follow the sequencer on their own. Each one computes the hash chain
  from the messages themselves, checks the sequencer's signed head against it,
  and serves a signed attestation (`GET /attest`) of the position it vouches
  for. A validator that catches the sequencer signing a different history stops
  attesting and marks itself disputed.
- The exchange (`--validators url,url,...`) counts the attestations whose
  chains match its own history. `quorum_verified_at` on `/market` is the
  highest position two thirds of the validators vouch for. With 3 validators, 2
  must agree. History at or below that mark cannot be rewritten by the
  sequencer alone. A second version would need a second set of validators, and
  a validator that signs two chains for one position has signed the proof of
  its own dishonesty.
- Matching never waits for the validators. Trading runs at the sequencer's
  speed, and the mark the validators vouch for follows a moment behind. Losing
  the validators stops that mark moving while trading continues, and the
  growing gap is visible on `/market`.

What this deliberately is not: full Byzantine fault tolerant consensus. This is
the safety half: an order the validators agree on, where a validator that
signs two answers can be named for it. The liveness half is replacing a stalled
or censoring sequencer with another one. That needs view-change machinery and a
deposit to take away, and it belongs to a real chain. If the sequencer stops,
this market stops. V4 only guarantees that what the sequencer already published
and the validators saw can never be rewritten.

## V5: accountable execution  [DONE, deliberately without a zk proof]

What it is:

- The state gets a commitment: `state_root` is a SHA-256 hash over every
  resting order and every position, in one fixed order, plus the cursor. Two
  engines with equal roots will match all future messages identically. It is
  served live on `/market`.
- Every committed batch also commits a **claim**, in the same transaction: "in
  history `session`, root S1 plus messages a..b gives root S2, with T trades so
  far". The `claims` table holds them. The `root_before` of one claim is the
  `root_after` of the one before it, so a single claim at message N commits to
  everything that came before it too.
- Each claim is **signed** with the exchange's own Ed25519 key (`state.key`,
  next to `state.db`, created on first run, and the run records which key it
  is). The statement is `exchange-claim-v1`, domain-separated and versioned
  like every other signature in this system. The signature is written in the
  same `INSERT`, inside the same transaction, as the claim itself, and the
  store refuses a claim without one. Two signed claims for the same history and
  the same message range with different roots are the exchange's own signature
  on its own contradiction. V2 gives that property to the sequencer's ordering;
  this gives it to execution.
- On resume, the restored state must hash back to the last claim's root, or the
  engine refuses to start. A database whose rows were edited passes the logical
  checks. It does not pass this one. A key file that has changed under a run
  with claims already in it also stops the engine, rather than leaving one run
  signed by two keys with nothing saying so.
- The claims and the trade record are **published.** `GET /claims?since=` and
  `GET /trade-log?since=`. They are paged the way `feed.rs` pages `/orders`,
  with the bound applied by SQLite inside the query and not by the handler
  afterwards. The exchange's public key is served beside them, the way the
  sequencer's key is served on `/head`.
- `--audit [STATE_DB]` lets anybody be the prover against a local file.
  `--audit-url <MATCHER_URL>` is the same audit against a **live exchange over
  HTTP**, with no database in hand. It fetches the signed claims and the trade
  log from the endpoints above, checks every claim's signature, and re-executes
  the sequencer's signed history against them in bounded pages. Both modes
  drive one re-execution, through the same `apply_message` and `state_root` the
  live exchange runs. There is one definition of what a claim means, not two.
  An invented fill, an edited price, a skipped message, an edited root: each
  fails a named claim, in either mode.
- The history is **anchored on a public chain**, which is the one piece of this
  that does not live on the operator's machine. Every five minutes a separate
  program (`anchor/`, Go, reading nothing but the public endpoints) writes
  `(lastId, treeSize, session, rootHash, stateRoot)` to an `ExchangeRootAnchor`
  contract on Base Sepolia. All five values are at one position of one history.
  The state root is taken from the exchange's own signed claim at exactly that
  message. The Merkle root is checked against the tree head the sequencer
  signed. `--audit-url --root-anchor-contract <ADDRESS>` then re-executes
  today's history and reproduces every anchor the contract ever wrote, or names
  the one that fails. Live at
  [`0x4162B3218b97663dEBC1f59060910221bb95672d`](https://sepolia.basescan.org/address/0x4162B3218b97663dEBC1f59060910221bb95672d),
  holding 44 anchors to message 262,110 on 17 August 2026, at 0.000000259 ETH
  an anchor measured. Three closed contracts still hold the anchors of the logs
  before this one, because a contract pins its session; see
  [`anchor/README.md`](../anchor/README.md).

What the anchor closes, precisely. Everything else in V5 proves that what the
exchange serves agrees with itself. Take an operator who stops, deletes both
databases, replays a *different* history, signs every head and every claim over
it again, and restarts. That operator passes every one of those checks. The
result is a completely coherent exchange. Only somebody who happened to keep an
earlier signed head could say otherwise. The anchor is that saved head. It is
written by a process outside the exchange, to a place the operator cannot
revise, at a rate that bounds how much recent history a rewind could reach:
five minutes.

Every anchor is checked, and not only the newest one, because an operator who
rewinds and re-anchors leaves a newest entry that today's history reproduces
exactly. So the auditor reads the whole `Anchored` log, and an incomplete read
is itself a failure. [`anchor/README.md`](../anchor/README.md) works the case
through.

What the anchor does **not** prove:

- **Nothing about honesty at the time it was written.** An operator who is
  dishonest from the start anchors their dishonest history quite happily, and
  every check passes. What the anchor removes is the ability to change the
  answer afterwards.
- **Nothing about who wrote it.** This contract's writer is the operator's own
  key, so its anchors are the operator's own commitment. The operator cannot
  deny them, but they are not independent. The sender reads only public
  endpoints, precisely so that anyone can run one against their own contract
  and publish the address. `--anchor-contract` takes any address, and a third
  party's anchor is the stronger evidence.
- **Nothing about gaps between anchors.** Messages published after the newest
  anchor are covered by the signed head and the claims, and by nothing else.
  That is what the five-minute interval buys down.
- **Nothing that survives the sequencer being wiped.** A replaced sequencer
  announces a new session, the contract refuses to record it, and every audit
  against the old contract fails loudly and says the history was replaced. That
  is the correct answer and not a bug: the anchored history really is gone.
- **Nothing about *which* contract is this exchange's.** The contract stops an
  operator rewriting what that contract recorded. It does not stop them
  deploying a second contract and publishing that address instead. Nothing on
  the chain binds an address to an exchange. The address must therefore appear
  in records with independent histories. Those records are
  `anchor/README.md`, `anchor/root-deployment.json`, this repository's public
  git history, and the site the exchange is served
  from. Changing it is then itself a visible, dated event. That is a name-binding
  problem, no contract can fix it, and it is stated here rather than implied
  away.

What V5 gives, said plainly: **accountability after the fact, and not a proof
and not prevention.** A signed claim is evidence. Two claims for one history and
one message range with different roots are the exchange's own signature on the
proof that it published two answers, whether or not anybody was watching at the
time. Checking them needs nothing from the operator beyond the endpoints they
already serve: `--audit-url` re-executes the history, and either every claim
holds or a named one fails.

What V5 deliberately does not give you:

- **A short proof.** Checking an exchange still costs re-executing its history.
  The audit is fast. A 15,000-message run re-executes end to end in about 18
  seconds in a debug build, some thirty times faster than the sequencer
  produced it. But the cost rises with the length of the history, and every
  auditor pays it again.
- **Protection against an exchange that stops making claims.** An auditor can
  prove that what was claimed is correct. It cannot prove that everything
  executed was claimed. What it can do is notice claims stopping short of the
  cursor the exchange itself reports, which is what the coverage check is.
- **Anything that stops wrong execution in the moment.** The audit runs after
  the fact. Wrong execution is provable once somebody runs the audit. Nothing
  refuses that execution while it is being written. The validators (V4) attest
  to the *order* of the messages and to nothing else. They do not vote on what
  those messages do, and a vote taken among three copies of one binary, on one
  machine, started by the operator would not have been a second opinion about
  it.
- **One agreed place to get the keys from.** `--audit-url` pins the exchange's
  key on first contact, unless `--matcher-key` names one. A key checked against
  itself shows that the claims agree with each other, and not who made them.

### Why there is no zkVM here

This was evaluated and rejected on numbers, and not on effort. Proving this
system's actual message rate, on the hardware it deploys on, one consumer
GPU, costs on the order of **1.5 to 7 minutes per 1,000 messages**. Running
the same batch natively costs about **2 milliseconds**. A prover would run four
to five orders of magnitude behind the exchange it is meant to be proving. So
the "verify in milliseconds" saving is real for the verifier and unreachable
for the prover.

And it would have solved the wrong problem. The gap V5 actually had was not
that checking execution was slow. It was that execution claims were **unsigned
rows in a private SQLite file**. A third party could not obtain them, and the
operator could edit them. Making the check cheaper fixes neither. Signing the
claims and serving them over HTTP is what closed that gap, and it reuses
infrastructure this system already had.

The zkVM path stays a real, considered option for whoever picks it up later:

- **Toolchain.** RISC Zero compiles Rust to RISC-V. `apply_message` plus
  `state_root` is already the shape a guest program needs: a function from
  (state, message) to state that uses integers only, gives the same answer
  every time, and does no input or output.
- **Breaking prerequisite.** `state_root` hashes the whole
  state again at every boundary. A prover needs an in-place commitment, such as
  a sparse Merkle tree over orders and positions. Its batch-proof cost would
  rise with the logarithm of the state size. That changes the on-disk commitment
  format and every root ever published, so it is a version of its own, not a
  patch.
- **What it would provide.** The claims table stores a receipt beside each claim,
  and the cost of verification stops rising with the length of the history.
  `--audit` becomes a signature check.
- **What it would not provide.** It says nothing about non-repudiation, censorship,
  ordering, or liveness. Those are V2, V3 and V4, and a proof does not touch
  them.

## What the history costs, and what production would do instead

A log that is only ever added to, and never pruned, grows forever. That is the
point of it. Every guarantee above rests on the history still being there. So
the question is not how to avoid the growth. The question is where to put it,
and what to give up when it gets large.

**What is bounded.** The always-on services are. The sequencer holds its most
recent 10,000 messages and the exchange its most recent 10,000 trades. Both sit
at roughly 23 MB no matter how long they have been running. Their startup cost
does not rise with the history either, because the checkpoint check streams the
stored history one row at a time rather than loading it. After startup, the
sequencer grows by 3.1 bytes per message. That growth is the replay-nonce map,
which only real signed submissions extend. The exchange grows by 4.4 bytes per
message for resting orders. Those orders are live state, not history.

`--verify` is bounded now too. It was not, and it was the constraint.

**What is not bounded.** Disk, at 331 to 334 bytes a message, measured twice on
the live deployment on 2026-08-17. That is the only cost in this system that
still rises with the length of the history.

**The deployment constraint.** The public service uses a small fixed memory
budget. Provider, host, network, and capacity details stay in the private
deployment record. The measurements below show why verification must not grow
with the length of the log.

**What `--verify` used to cost.** 259 bytes of peak memory for every message
the sequencer had published, measured. It read the run's whole trade record
into one vector and built four indexes over it. At 24 messages a second:

| log age | messages | `--verify` peak |
|---------|----------|-----------------|
| 1 day   | 2.1M     | 537 MB          |
| 4 days  | 8.3M     | 2,148 MB        |
| 7 days  | 14.5M    | 3,759 MB        |
| 30 days | 62.2M    | 16,112 MB       |

So the tool that carries this project's central claim could not remain usable
as the history grew.

**What `--verify` costs now.** The trade record is read in two sequential scans
and no row is kept. `verify/trades.rs` states how. The checker holds only live or
unfinished state: resting orders, orders awaiting a trade-record outcome, one
running hash chain, the Merkle tree's right edge, and one cash total per
account. None of those follows the length of the history.

Measured with `/usr/bin/time -v` on 2026-08-17, on two databases, each read by
both binaries against the same frozen sequencer:

| messages  | trades    | peak before | peak after | time before | time after |
|-----------|-----------|-------------|------------|-------------|------------|
| 319,705   | 254,054   | 108.3 MB    | 26.2 MB    | 4.8 s       | 5.3 s      |
| 2,572,509 | 2,045,829 | 707.7 MB    | 28.1 MB    | 46.3 s      | 58.7 s     |

Eight times the history. Peak memory before rose by 599.4 MB, which is 279
bytes for every message added. Peak memory after rose by 1.9 MB, which is 0.87
bytes a message. That is the number this change was for: the peak is flat, and
what is left of it is the book, the orders the trade record has not finished
with, and the accounts.

Both binaries printed the same report on each database, line for line: the same
25 checks with the same counts, `All checks passed`, and the same failure
lines. Two counters differ only on the larger run. `the feed's signed chain
matches its history` and `every stored node is the one the messages make` read
2,572,509 messages in the first run and 2,572,513 in the second. The sequencer
published four messages during the 46 seconds between runs.
Every check that reads the trade record is identical. A memory fix that changed
what is checked would be a bug, so the two reports are compared and not only
the two peaks.

The change is 27% slower on the larger database, and it writes. The scan that
orders rows by message has no index to walk, so SQLite sorts them. On the larger
run, the sort wrote 187 MB to a temporary file. That is 46 bytes for each of
the 4.09M rows. `/usr/bin/time -v` counted 365,480 file system output
blocks against 72 before. That trade is the right way round for a deployment
whose storage budget is much larger than its memory budget.

`--audit-url` measured 20.7 MB of peak memory over 97,095 messages against the
live exchange on 2026-08-16. The HTTP client, TLS library and SQLite create that
floor before the checker holds any state. `--verify` is now within 8 MB of it
at 2.5M messages.

**What this deployment does.** It runs at a mean of 69 messages a second and
restarts monthly with a fresh database. The rate is a mean because the generator
switches between three activity states: 24, 69 and 114 messages a second, each
holding a third of the time. 24 is the floor, and it is the rate that puts a
trade in 98% to 100% of five-second candles in every market, so the charts show
a market instead of a flat line. Five seconds is the finest interval the chart
offers. Measured over 134 seconds on 2026-08-17, at the flat 24 this deployment
ran then: 24.20 a second. See the comment above `INTERVALS` in
`services/static/app.js` and section 4.6 of
`docs/GENERATOR-RFC.md`.

One month at a mean of 69 is 178.8M messages and 59.2 GB of `feed.db`, at the
331 bytes a message measured on 2026-08-17. The deployment keeps capacity for
two full windows. At the flat 24 the same month was 62.2M messages and 20.6 to
20.8 GB. The old `--verify` needed 16.1 GB of memory for that smaller month,
which exceeded the deployment budget. The peak measured above does not follow
the length of the history, so the month is no longer a memory question. At 0.87
bytes per message above a 28 MB floor, 178.8M messages would use 184 MB of peak
memory.

What it is instead is a time question, and that one is not measured at 65M
messages. The walk reads every message twice over HTTP. The trade record is
read three times on disk. One read has no index, so SQLite sorts it and writes
the part that does not fit in 2 MB to a temporary file. Both costs rise with the
length of the history. The two runs above give
the shape at the sizes they ran at, and nothing beyond them.

`--audit-url` never had that ceiling. It streams the history in bounded pages,
re-executes the pages as they arrive, and needs nothing on local disk, only a
URL. A third party can use it without local state. `--verify` is the operator's
tool. The two tools also test different faults. `prove.rs` re-executes with
`matcher::MatcherState`, the engine used by the exchange. It catches a rewritten
history but cannot catch a matching-rule bug. `verify.rs` writes every matching
rule again and imports no matching code. `services/tests/checker_imports.rs`
enforces that boundary.

**What that costs, plainly.** The verification horizon is now disk, and it was
memory. One month is 20.6 GB of `feed.db`, inside the multi-window storage
budget. The restart is still monthly. A signed receipt from
before a restart names a message in a history that no longer exists, and the
new run announces a new session, so nothing links the two. For a system whose
entire claim is that you can check it yourself, that is a real limitation and
not a footnote. Segments, below, are the change that removes it.

**What production would do instead: cut the log into segments rather than reset
it.** Each period is its own append-only segment, checkable on its own, and the
first message of segment N commits to the final signed root of segment N-1. A
restart then joins two segments instead of losing everything before it. The
chain crosses the join, a receipt stays checkable against the segment that
contains it, and old segments can be moved to object storage or dropped
entirely without breaking the ones that remain. Anchoring each join publicly is
what removes the operator from that argument. Without it, the claim that
segment N really follows segment N-1 rests on the operator's own signature over
both.

The anchor half of that now exists (`anchor/`). The segment half does not. What
is deployed anchors positions *inside* one session, and the contract
deliberately refuses an anchor for a different session. So a restart with a
fresh `feed.db` still ends the verification horizon. It now ends it loudly
instead of silently. Segments would be the change that makes a join checkable.
The anchor would then be what makes it checkable by someone who was not
watching.

- **What it would provide.** Uptime is unbounded while working state stays
  bounded, and receipts survive a restart.
- **What it would not provide.** It says nothing about ordering, censorship, or
  execution correctness. Those are V2 through V5, and segments do not touch
  them. It is a storage decision, not a trust one, except for the join. That
  part needs the anchor.

## The gap found after V5: verification depended on understanding

This is not a version. It is one mistake that ran through V2, V4 and V5 at the
same time. It is written out here because the result on its own is a small diff
that hides the reasoning behind it.

Names in this section come from [`docs/GLOSSARY.md`](../docs/GLOSSARY.md). The
sequencer is `feed.rs`, the exchange is `matcher.rs`, the separate service is
`inbox.rs`. The sections above already use those names.

### What the chain hash actually covers

Every message extends the chain hash:

```text
chain_i = SHA-256(chain_{i-1} || bytes(message_i))
```

That covers the exact bytes the message was written as. It does not cover the
fields inside the message, and it does not cover the struct behind them.

Now look at how every consumer checked it. The exchange, the validators, the
checker and the audit all parsed a message into an `OrderMessage`, wrote it out
again to rebuild those bytes, and hashed the result. That is correct only while
every program is compiled from the same definition of a message.

### Failure: an honest sequencer reported as a liar

Take one message a consumer does not fully know. The sequencer publishes a
field, or a whole kind, added after that consumer was built. serde writes what
the build declares, so the unknown part comes back out missing. The bytes
differ, the chain hash differs, and the chain the consumer computes is not the
chain the sequencer signed.

The consumer then reports that the sequencer rewrote its history. The sequencer
is correct. The consumer is only old. On a validator that verdict stays set
until an operator clears it by hand.

So the message format could not grow. The sequencer and its four consumers had
to be rebuilt at the same moment, every time. A program that was not rebuilt
would accuse an honest sequencer of tampering. Five programs, one deploy,
forever. Nothing in the design said that. It came out of how the check was
written.

### First suspect: the float formatting

The first form this took was narrow and looked like a browser problem. Rust
writes a price of 100.0 as `100.0`. JavaScript's `JSON.stringify` writes `100`,
so a page that wrote the message out again could never reproduce the bytes.

That is why `/messages.ndjson` exists: it serves the exact bytes that were
hashed, one message per line. It fixed the browser, and it hid the general
problem for a day, because the four Rust consumers shared one struct and so
always agreed with each other.

### Ruled out along the way

- **The hash rule.** `chain_i = SHA-256(chain_{i-1} || bytes)` is right, and
  the problem was never in what it commits to.
- **The signature scheme.** Ed25519 over a domain-separated statement, with
  every field inside the signature. Nothing wrong there either.
- **The storage format.** The sequencer stores each message's JSON, which is
  the right thing to store. What it then did with those rows was the problem.
- **The chain itself.** No history had been rewritten and no key was wrong.
  Every difference the alarms found was a real difference in bytes.

### The actual cause: hashing was asking what the bytes meant

Verification depended on understanding. Hashing is a byte operation, and it
must not require knowing what the bytes mean. A consumer that has to understand
a message before it can hash it is a consumer that must be rebuilt at the same
time as the producer.

### The fix: hash what arrived, parse separately

Consumers hash the bytes they received, from `/messages.ndjson`. Parsing became
a separate step that exists only to work out what a message means.
`services/src/wire.rs` holds the one shared helper, so there are not four
copies of the framing.

Two outcomes that used to be one:

| What happened | What it means | Exit |
|---|---|---|
| chain mismatch | the history was rewritten | 1 |
| cannot interpret | the chain verified; this build is too old to read message N | 3 |

A failing check outranks too-old. Without that order, an old binary would be a
way to turn a failing audit into a status nobody acts on.

### The proof, run with real processes

A newer binary published 31,800 messages, and 4,681 of them were a kind the old
binary had never heard of. Then the old binary ran against that log:

```text
the checkpoint the newer build signed:  chain 71016d13...c1b96f29  last_id 31800
the head the old binary computed:       chain 71016d13...c1b96f29  last_id 31800
```

An old validator attested with `disputed: false`, and it was never rebuilt.
`--audit-url` exited 3, named message 4, and said this was not tampering.

Then one message was edited by hand in the database. The same old binary
reported FAILED and exited 1, and the sequencer refused to restart and exited
2. So hashing without parsing did not weaken tampering detection.

### The second half: the sequencer did it to itself

The sequencer stored each message's JSON. Then it parsed and wrote out that
JSON again at startup, and on every page it served from disk. So a sequencer
older than its own database would report its own history as tampered. It now
writes each message out once, and serves the stored bytes.

### What it cost, and what it bought

`validator.rs` no longer names `OrderMessage` in production code at all. A
validator attests to the order of messages, and not to their meaning, so it
needs neither. A deployed validator does not need rebuilding when a message
kind is added. That is the property the whole change was for.

### The same mistake in two other places

Once the cause was clear it turned up twice more, both outside the hashing
path.

The symbol list was read inside the execution path. Closing a market would have
changed how every past message replayed, and broken every anchor written so
far.

Self-trade prevention would have done the same. It rejects an order that would
trade against its own account in the book. The first log holds executed
self-trades, so adding that rule as plain code would have made every past claim
fail. [DECISIONS.md](../docs/DECISIONS.md), "Cancel newest for self-trade
prevention", holds that measurement.

Both are the same mistake in a different place. Something that changes
execution was living outside the log.

### The rule that came out of it

> If changing a value makes the same messages produce a different result, it is
> data and belongs in the log. It is not configuration.

Metrics, caching and rate limits pass that test. The symbol list and the
matching rules do not. The rule now sits in
[`docs/ENGINE.md`](../docs/ENGINE.md) section 3, together with the design where
the log opens by stating its own rules.

### What came next, and what is still not done

The log became a Merkle tree built to RFC 9162. A chain proves the whole
history is intact, but it is poor at proving one item is inside it: showing
that message 33,754 is in a chain needs every message after it. A tree proves
it with the hashes on one path. Measured against the live sequencer on 17
August 2026 at tree size 245,223: **18 hashes, 576 bytes.**

The tree is live and its nodes are rows in `feed.db`. The sequencer signs a
tree head, serves both proofs, and the anchor sender commits the root to Base.
The six-step matching pipeline, the order types, self-trade prevention and
listings as messages all shipped, so an order type is now a field on the
message and a step in the pipeline.

Two things are still not built. The message envelope cannot ship over a running
log, because one `OrderMessage` cannot parse both the old shape and the new
one, so it waits for a clean genesis. And the hash chain still runs beside the
tree, because every consumer has to read the tree before the chain can go.
[`docs/PLAN.md`](../docs/PLAN.md) tracks both, step by step, and says which
parts are deployed.

## Optional at any step: fair ordering

- Users encrypt their orders. The sequencer assigns positions without seeing
  the contents. Decryption happens after ordering.
- This stops the sequencer trading ahead of an order it has only now seen. It can
  be added from V2 onward.

## Summary table

| Step | Removes this risk | Cost |
|------|-------------------|------|
| V1   | Machine death, power loss | One SQLite file per service |
| V2   | Hidden censorship | Signatures |
| V3   | Censorship itself | A base chain and a bridge |
| V4   | Trusting one sequencer | A small group of agreeing nodes |
| V5   | Trusting the operator's execution, after the fact | Re-execution, by whoever checks |
| V6?  | Paying for a re-execution to check it | A zkVM, and a state commitment that updates in place |
