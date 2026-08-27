# Plan

The goal, the five steps, and how each one is judged finished.

[ENGINE.md](ENGINE.md) is the specification. This file is the schedule.

---

## The goal

A spot exchange where:

1. the history is a Merkle log built to RFC 9162, so anyone can prove one trade
   is inside it without reading the rest;
2. the rules live in the log, and not in a binary, so replay gives the same
   answer to everyone;
3. matching is a pipeline of independent steps, so a new rule is a new step and
   not an edit to an old one.

The test of whether this worked is not that the code looks tidy. It is that
**adding an order type needs no validator rebuild and no restart.**

---

## The five steps

### Step 1: `domain.rs`, layer split  **[done]**

Move `OrderMessage`, `Side`, `AccountId`, `OrderId` and the symbol list out of
`feed.rs` into a module that depends on nothing. Then split `feed.rs`,
`matcher.rs` and `inbox.rs` into layers: domain, then service, then transport.

Before the split, 11 of 13 modules imported from `feed.rs`, and two import
cycles ran through `feed.rs`. The domain model lived inside a service, so
anything that needed the shape of a message had to depend on the sequencer.

**Finished when.** Both import cycles are gone, sequencing can be tested
without starting an HTTP server, and no logic changed. The test count is
unchanged.

**The rule that decides where a thing goes.**

> The domain holds the shape of a message, and functions that look at **one**
> message. The sequencer holds state **across** messages, and the rules that
> use that state.

The nonce is the worked example, because it is three pieces of code and they do
not share a home. `nonce()` reads a field and `nonce_key()` is a pure function
of one message, so both are domain. The `HashMap` of every nonce ever used is
state across messages, so it is the sequencer, along with the rule that refuses
a duplicate. The check that settles it: the checker needs `nonce()` and must
never see the `HashMap`.

Put the ledger in the domain and the domain then holds changing state. The
domain has become a service with a different name. Put `nonce()` in the
sequencer and every program that reads a nonce must import the sequencer, which
is the coupling this step removes.

`feed.rs` was 7,122 lines and did ten jobs. It was split in nine units, one
commit each, leaves first and the sequencer core last: `domain.rs`,
`feed/limit.rs`, `feed/metrics.rs`, `feed/cache.rs`, `feed/db.rs`,
`feed/generate.rs`, `feed/drain.rs`, `feed/http.rs`, and what remained was the
sequencer. The acceptance test was the same every time: the test count does not
change. A pure move cannot change behaviour, so a test that needs more than an
import path fixed means the move was not pure.

**The split did not hold, and the reason is worth keeping.** `feed.rs` reached
4,716 lines and then grew back, because 92 of 99 tests stayed behind in the
file the code left. It is **8,436 lines** at this commit. Tests move with the
code, or a split does not hold.

### Step 2: Merkle log per RFC 9162  **[five of seven stages done]**

Split into stages, because it is seven pieces of work with different risks and
not one action. Each stage leaves every commit green, which is why the tree
runs beside the chain for a while rather than replacing it in one change.

| Stage | Work | State |
|---|---|---|
| 2a | The RFC 9162 primitives: tree, both proofs, conformance tests | **done** |
| 2b | The tree in the sequencer, the STH signed, both proofs served | **done, live** |
| 2c | The separate service verifies an inclusion proof | **done**, 8ab3a1b |
| 2d | The message envelope | not started. It waits for step 5 |
| 2e | The tree on disk, and the STH timestamp persisted | **done**, fe03468 |
| 2f | Consumers verify by the tree; the chain is deleted | **not started** |
| 2g | The anchor commits the root; the browser verifies with a proof | **done, live** |

**2c was a live bug, and it is closed.** The separate service confirmed an
entry by writing the message out again and comparing fields. A message kind it
could not read produced no confirmation, the deadline expired, and the service
publicly reported an honest sequencer as late. A censorship alarm that fires
when nothing is wrong is worse than no alarm, because nobody believes it when
it is right. The confirmation now carries an inclusion proof, so the service
has three outcomes instead of two: confirmed, confirmed with the content
unchecked, and late. Only the third is an alarm.

**2e was a memory leak, and it is closed.** The tree was 95 bytes a message on
the heap and nothing bounded it. The nodes are rows in `feed.db` now,
`services/src/feed/tree.rs`, commit fe03468. The start checks them against the
signed checkpoint.

**2g is what the project is for, and it is live.** A visitor proves their own
trade is inside a commitment on Base with **18 hashes, 576 bytes**, measured
against the live sequencer on 17 August 2026 at tree size 245,223.
`ceil(log2(245,223))` is 18, so the path is the shortest the tree allows.
Before this, the browser hashed 1.7 MB of history to answer the same question.

**2d and 2f are the two stages left.** 2d waits for a clean genesis. As ENGINE.md
section 2 explains, one `OrderMessage` cannot parse both the old shape and the
new one. The envelope therefore cannot ship over a log that already holds
messages. 2f is blocked on nothing but order. The chain still runs beside
the tree, and deleting it needs every consumer to verify by the tree first. The
consumers are the exchange, the validators, the checker, and the audit.

**Finished when.** The chain is gone, and not kept beside the tree, and a trade
can be proved against an anchored root from a browser.

### Step 3: Six-step pipeline skeleton  **[done]**

Six named steps, each in its own module, behaviour unchanged.

```
1 resolve symbol   2 validate order type   3 bound the price
4 self-trade       5 match                 6 remainder policy
```

**Finished when.** Tests are green, each step is its own module, and a step
never calls another step.

### Step 4: Four features in parallel, one worktree each  **[the three features are done]**

**The goal, stated as a test.** A market can be opened and closed while the
exchange runs, and everyone who replays the log gets the same answer.

`DelistSymbol` is correct when all three hold:

1. New orders for that symbol are refused after it.
2. Every order before it still executes identically.
3. The state root over the whole history is the same for anyone, whatever
   binary they run.

**Delisting means stop accepting new orders. It does not mean erase the
history.** The old trades happened. They stay in the log, they stay in the
tree, and their proofs keep verifying.

**The change this needed was one question, asked differently.** The engine
checked the symbol list while *executing* a message that was accepted long ago:

| | asks | replay depends on |
|---|---|---|
| before | is this symbol in `SYMBOLS`? | **the binary** |
| after | was this symbol listed at this point in the log? | **the log only** |

Both refuse a symbol nobody listed, which is why the check exists. A sequencer
must not be able to invent symbols and put strings of its choosing into the
state root. Only the second question gives everyone the same answer. The engine
asks the second one now, and builds the symbol registry from the log, commit
d1c08b8.

Measured before that change, to show it was not theoretical. Removing
`ETH-USDC` from the constant and replaying the same 2,480-message log:

    with ETH-USDC     state root ebc7c0f463d5895c…
    without           state root 3a5907ceed262e9e…
    613 orders ignored, silently

Adding a symbol was survivable even then. No earlier message names it, so
nothing is ignored. Removing one was not.

**A sequencer per market would make this simpler, and it was rejected.**
Closing a market would be stopping its sequencer: its log stops growing, its
last anchor stands, and its proofs verify forever. One log for each market lost
on a different question. Nothing orders two logs against each other, so a
position held in two markets at once cannot be checked from the logs. Sharding
here means the engine only, over one log.


| Agent | Owns | Pipeline step | Where it landed |
|---|---|---|---|
| Listings | symbol registry, `ListSymbol`, `DelistSymbol` | 1 | `matcher/step1_resolve_symbol.rs`, `verify/listings.rs` |
| Order types | market, IOC, FOK, post-only, the collar | 2, 3, 6 | `matcher/step2_validate_order_type.rs`, `step3_bound_the_price.rs`, `step6_remainder_policy.rs`, `verify/order_terms.rs` |
| Self-trade | cancel newest | 4 | `matcher/step4_self_trade_check.rs`, `verify/self_trade.rs` |
| Cleanup | remove all 25 `unwrap` and `expect` | none | not tracked here |

Nobody edits step 5, the match itself.

Every feature is written a second time in `verify.rs`, independently. See
ENGINE.md section 5. That duplication is the point, and
`services/tests/checker_imports.rs` enforces it.

**Finished when.** Four agents finish without editing each other's files. That
result is the proof the decoupling worked. The three feature agents did, and
each one's rule sits in its own step module beside its own second copy in
`verify/`.

### Step 5: Clean genesis

The pairs become `MERKLE-USDC`, `ETH-USDC`, `BTC-USDC`. `NEX` goes because it
names the take-home this project grew out of, and it is a search term that
leads someone sitting that exercise to this answer. `MERKLE` is this system's
own word and names no real asset. The other two stay: a demonstration venue
pricing fake BTC is the ordinary convention and confuses nobody.

**The rename is deployed.** It could not ship on its own: the live log held
about 130,000 messages naming the old symbol, and an engine that does not know
that symbol ignores every one of them. So the rename went out in the same
deploy that wiped the volume, on 16 August 2026. `GET /market` serves
`MERKLE-USDC`, `ETH-USDC` and `BTC-USDC` today. That was a sequencing
constraint on one deploy, and not a design problem.

**What genesis is now.** A new deployment opens its own log, and nobody types a
command to make it happen. `docker/entrypoint.sh` starts the sequencer with
`--operator-key`, so the sequencer publishes nothing of its own while its log
is empty. After the exchange answers, the entrypoint runs
`docker/open-the-log.sh`. That script publishes the rule set as message 1, then
one `ListSymbol` for each market. It names neither. The rule set number comes
from the exchange's `/market`, and the markets and their price steps come from
the sequencer's `/symbols`, which is `domain::SYMBOLS`. `./demo.sh` runs the
same file, so a local run and a deployment open a log the same way.

It publishes only when the head's `last_id` is 0. A restart on a log that
already holds messages publishes nothing, which matters because a container
restarts on every deploy. `services/tests/genesis.rs` covers both halves.

The operator key follows the anchor key, with one difference. A missing anchor
key means "do not anchor", because the anchor is evidence about the exchange,
and an exchange that is not anchored still trades. A missing operator key
cannot mean "do not open the market", because the market is the product. So the
entrypoint makes a key on the data volume, and reports that anybody who can
read that volume can open and close markets. A production deployment mounts the
secret and never reaches that branch.

**The live log recorded the old race.**
`GET /messages.ndjson?since=0&limit=5` on the deployment returns:

```
1  EngineRule   rule set 2
2  ListSymbol   MERKLE-USDC  price step 0.01
3  New          account 30, BTC-USDC, Sell 1001.0 x 1.9
4  ListSymbol   ETH-USDC     price step 0.1
5  ListSymbol   BTC-USDC     price step 1.0
```

Message 3 names a market that message 5 opens. `GET /market` on 17 August 2026
reports `orders_ignored_by_reason` as `{"self_trade": 18, "unlisted_symbol": 1}`
over 295,627 messages. That one is message 3. Message 1 is still the
operator's.

The original opening relied on timing. The generator started after message 1,
while the script still had three listing requests to send. One live run placed
an order at message 3 before BTC-USDC was listed at message 5. The engine
correctly refused that order as `unlisted_symbol`, but the log no longer had a
deterministic opening.

The sequencer now reserves messages 1 to 4 for the operator whenever an
operator key is configured. Direct user submissions, inbox entries and
generated traffic wait until the fourth message exists. A partial opening stays
closed and can be completed with the same operator commands. No new protocol
message is needed because this binary already knows the number of compiled
markets that `open-the-log.sh` lists.

**Two things the next change here has to know.**

The price step is named in one place: `domain::SYMBOLS`. That constant is
`[(&str, f64, f64); 3]`: a symbol, a starting mid price, and the price step
that market opens on. The mid price is the price halfway between the best bid
and the best ask. `GET /symbols` serves the name and the step together, and
`docker/open-the-log.sh` reads the step off that endpoint the way it already
reads the rule set and the symbol list. Whoever removes the constant has to
move the step somewhere the sequencer can still serve it.

The step is per market because one step for all three broke the books. The
markets start at mids of 10, 100 and 1000, and the generator prices within
±0.5% of the mid. One step of 0.01 made that band 10 prices wide on MERKLE-USDC
and 1000 wide on BTC-USDC. Orders 1000 prices apart never meet. Measured on the
live exchange, MERKLE-USDC held 60 bids and 330 asks, while ETH-USDC and
BTC-USDC both sat at 1000 and 1000, which is `MAX_BOOK_DEPTH`. The steps are
now 0.01, 0.10 and 1.00, which puts about 10 prices in every band.
`feed::generate::tests::the_generator_leaves_every_book_two_sided_and_the_same_size`
is that stated as a test.

The quantity step is still named twice: `docker/open-the-log.sh` holds `0.1`
and `services/src/inbox.rs` holds `QUANTITY_SCALE`. It is one number for every
market, because a quantity of 1.5 means the same amount of work whatever the
price is, so it did not move into `domain::SYMBOLS`. It is an environment
variable in the script, so a deployment overrides it without an edit.

**Finished when.** Replaying from message 1 teaches a stranger the rules and
the symbols, with nothing read from a binary or a configuration file. A log
opened by `docker/open-the-log.sh` does that, and the deployed log is one. The
message envelope, stage 2d, is the part of this step still to come.

---

## What to do next, and why that order

The five steps are not done in order. The order is decided by what is broken
and what is blocked, and it is written down here so the reason survives.

1. **2d. The message envelope.** It cannot ship over a running log: one
   `OrderMessage` expecting `{"v":1,…,"body":{…}}` fails to parse every message
   already published, and every consumer stops at message 1. So it lands with a
   clean genesis, over an empty log, and it lands alone. See ENGINE.md section
   2.
2. **2f. Delete the chain.** Only after every consumer reads the tree.
3. **The nine findings below**, and the ones in `docs/DECISIONS.md`. Blocked on
   nothing.

Step 3 was done before step 2 finished. That was a choice. It unblocked four
agents working in parallel, at the cost of leaving step 2 half done. It is
worth recording, because the same choice will come up again and the answer is
not always the same. It was right then, because what was left in step 2
included a bug in production and what was left in step 4 did not.

---

## What runs at the same time

Steps run together only when they touch different files. This is checked before
starting, and not hoped for.

Step 1 and the first half of step 2 do not collide: the Merkle primitives are
one new file that imports nothing from this repository. Everything after that
is sequential until step 4.

Step 4 is the parallel one, and each agent gets its own git worktree, so a
broken build in one cannot stop the others.

**Two branches touching one file is where the silent merges happen.** Git
conflicted two `refused` declarations and auto-merged their three usage sites.
A merge that compiles is not a merge that is right. Read the diff of any file
two branches both changed.

---

## The attack that worked, and the half of it that is still open

An adversarial review defeated the first claim the project makes: a wiped log
kept its name, so the same session and the same key signed a different history
and nothing warned. That is closed. The session is minted whenever there is no
checkpoint, in commit `2d04a98`. The reproduction, the cause, the fix and what
the fix costs are all in
[`DECISIONS.md`](DECISIONS.md#a-session-names-a-signed-history-not-a-database-file),
decision 15. They are not repeated here.

**What is on this schedule is the half that is still open.** A wipe now changes
the name, so a wipe no longer lands in the gap. Restoring an older copy of
`feed.db` still does. Every startup check passes, because an old copy of a
history is a valid prefix of that history and keeps its name by design. The
sequencer then serves a head standing behind every validator's cursor, inside
the session they pinned. Each validator files that as `HeadDoesNotCover` and
waits, the same bucket an unplugged cable produces, and never disputes.
There is no check anywhere for a head that moved backwards.
`validator.rs:742` is where `HeadDoesNotCover` is filed, and
`head.last_id < state.cursor` has to become a dispute there. There is nowhere
else it can be caught.

## A change that cannot run in parallel

Adding a field to `OrderMessage::New` breaks every construction of it.
Measured: 30 sites, 27 struct literals and 3 exhaustive matches, spread over 12
files. That is Rust's type system. There is no shape that adds a term to that
enum and leaves its constructors compiling.

So the message shape is a change that **must land alone**. It cannot share a
window with any other work, because it touches almost every file whether or not
it has anything to do with them.

This was found by trying. The plan said to fix the shapes first so three
feature agents would not collide in one file. That was correct. But it did not
say the shapes commit itself collides with everything. It has to land alone,
between other work, and not beside it.

**It landed alone, on 15 August 2026, as 4b9e3b8.** `order_type`,
`time_in_force` and `post_only` are on the message and no published byte moved.
The two sites that were not mechanical were the ones that decide what the
checker does with a message kind it cannot replay. An empty arm would make the
checker report on a history it only half understood, which is what ENGINE.md
section 6 forbids, so both answer cannot-interpret.

Stage 2d, the envelope, is the next change of this shape. Read this section
again before starting it.

## Found and not yet fixed

Each was found while doing something else, is real, and is not urgent. Line
numbers are at commit 656b069.

| Where | What |
|---|---|
| `fetch.rs:93` | The `chunk()` error inside `read_bounded` prints `e` and does not walk `Error::source()`, so it names no cause. `reason()` is right there in the same file. This was two call sites in `prove.rs` and `verify.rs`; sharing the HTTP plumbing in `fetch.rs` made it one. |
| `verify.rs:458` | `cannot reach {}/head` prints `e`, same shape. It sits in front of a line already fixed, on the same command. |
| `anchor.rs:866`, `:874`, `:894`, `:1199`, `:1809`, `:1814` | Six anchor RPC and feed calls, same shape. `anchor.rs:1785` in the same file already calls `reason()`, so the fix is one word in six places. |
| `feed/generate.rs:515` | The rate is clamped to 1000 a second on the line that computes the burst. That clamp, and not the tick, is the floor of the crash tests' runtime. Raising it means changing `start_feed`'s signature. |
| `feed/db.rs:64-74` | The migration refusal has no test, and `feed/db.rs` has no `mod tests` at all. Eleven lines that decide whether a database is safe to open. |
| `feed.rs:1410`, `:2173` | `pin_or_check_account` and `with_state` return `(StatusCode, String)`. That is the last transport type inside the sequencer, and the only reason it links axum. |
| `matcher.rs:2087`, `:2107`, `:2152`, `:2159`, `:2174`, `:2219` | `listings_ignored` has six increment sites for six different reasons and reports no breakdown. Same shape as the `orders_ignored` bug that `orders_ignored_by_reason` fixed. |
| four publish sites | The engine and the checker disagree about the mid window when a query is backdated. Reaching it needs a message whose timestamp is behind its predecessor's, and nothing enforces rising timestamps. All four sites take `clock.now_ms()` raw: `feed/drain.rs`, `feed/generate.rs`, and two in `feed/http.rs`. |
| `--audit` | It waits on the network and not on the processor: 87 of 94 seconds were spent waiting, because a page holds 1,000 rows. Measured 16 August 2026. |

**`reason()` is one definition, at `fetch.rs:55`.** An earlier version of this
list said to move it to `wire.rs`. That advice was wrong. `wire.rs` imports
nothing but `std`, `serde` and `crate::domain`, and it must stay that way:
`reason()` walks the `source()` chain of a `reqwest::Error`, so it belongs with
the HTTP client.

## Resetting a deployment

A reset changes three public facts together: the image, the append-only log,
and the Base Sepolia contract that anchors that log. Treat it as one release:

1. Build and publish the finished image before changing runtime state.
2. Deploy a new testnet anchor contract for the new log.
3. Select a new empty volume through private deployment configuration.
4. Update the contract and volume together, then deploy the published image.
5. Keep the previous volume and contract intact so their history still verifies.

Push-triggered deployment stays disabled. The CI deployment starts only after
the image job has published the image for that commit. Keep the real volume
name, key paths, proxy range, network name, and deployment API URL out of the
repository.

---

## Status

Updated 17 August 2026, at commit 656b069.

### Done and deployed

| | |
|---|---|
| Verification over received bytes | an old binary verifies a history it cannot read |
| The sequencer serves its stored bytes | it no longer writes its own database out again |
| Step 1, all nine units | the layers split. `feed.rs` reached 4,716 lines and is 8,436 again, because the tests stayed behind |
| Step 2a, 2b: the Merkle tree, STH, both proofs | live, verified from outside with an independent RFC 9162 verifier |
| Step 2c: the separate service verifies an inclusion proof | the false censorship alarm is gone |
| Step 2e: the tree on disk | `feed/tree.rs`. Memory no longer grows with history |
| Step 2g: the anchor commits the root | `0x4162B3218b97663dEBC1f59060910221bb95672d` on Base Sepolia. A trade is proved with 18 hashes, 576 bytes |
| Step 3: the six-step pipeline | state root identical over 60,000 messages |
| Step 4: listings, order types, self-trade prevention | each rule in its own step module, and written a second time in `verify/` |
| Step 5: the pair rename and a log that opens itself | deployed 16 August 2026. `docker/open-the-log.sh` publishes messages 1 to 4 |
| The message shape | `order_type`, `time_in_force` and `post_only`, with no published byte moved |
| The crash loop | `services/tests/crash_restart.rs`, 6 tests, SIGKILL at every message count from 0 to 12 |
| The session fix | a wiped log gets a new name |
| `main.rs` panics | a mistyped argument prints one line and exits 2 |
| `--verify` peak memory | flat in the length of the history: 0.87 bytes a message, against 279 before |
| Documentation | glossary, writing rules, engine contract, decisions, naming, API, roadmap, plan, bot, generator RFC |

The live deployment runs at a mean of 69 messages a second across 40 generated
accounts. The rate is a mean because the generator switches between three
activity states, 24, 69 and 114 messages a second, each holding a third of the
time (`docs/GENERATOR-RFC.md` section 4.6). Measured 17 August 2026 over 134
seconds, at the flat 24 it ran then: 24.20 a second.

### Implementation complete; deployment verification pending

The next release contains two security changes:

- The browser code and style are same-origin files, and the HTTP layer adds a
  strict CSP, HSTS, frame denial, MIME sniffing protection, a referrer policy,
  a permissions policy, and `no-store` where a route has no explicit cache
  rule. Port 80 redirects to HTTPS. A first visit keeps its demo key in tab
  memory unless the visitor explicitly stores the unencrypted seed.
- Account and account-plus-symbol trade indexes replace the unbounded account
  filter. `GET /pnl` requires one account, returns immediately for an unused
  account, and caps its sampled series at 2,001 points.

These entries move to **Done and deployed** only after a release build,
deployment, and live header and latency checks pass.

### Left

| | What it is | Blocked by |
|---|---|---|
| 2d | The message envelope: version, id, account and nonce readable without parsing | a clean genesis. It cannot parse a log that already holds messages, and it must land alone |
| 2f | Consumers verify by the tree, and the chain is deleted | every consumer reading the tree first |
| - | The nine findings above, and the ones in `docs/DECISIONS.md` | nothing |

### The order

2d edits `OrderMessage`, which breaks every construction of it across 12 files.
It must land alone, with nothing else running, over an empty log. One
`OrderMessage` cannot parse both the old shape and the new one. 2f can go before
it or after it. Nothing else waits on either.

### Designed, not built

Not on the five steps. Each is a decision already taken, with nothing written.

- **Sharding by engine, over one log.** One log for each market was rejected
  above, in step 4.
- **The speed bump as a rule anyone can verify.** Hold every `New` at the door
  and put `held_ms` on the message, so a replayer sees the delay instead of
  trusting that it happened. `held_ms` is in no file today.
- **Deposits, withdrawals and solvency.** `docs/DECISIONS.md` decision 20. It
  is chosen, and no code implements any part of it.
- **Account key rotation and recovery.** The current protocol pins the first
  key forever. A rotation message would change account authorization, replay,
  state restoration, and every independent checker. No such message exists in
  this tree.
- **`matcher.rs` split** into `api.rs`, `poller.rs` and `boot.rs`. The file is
  10,574 lines. It waits for a quiet moment in it, and for the tests to move
  with the code. See step 1.
