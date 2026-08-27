# Engine contract

This file is the agreement. Every program in this repository obeys it. Change
this file first, then the code.

It exists because four features are built at the same time by different people.
Without one written interface, four readers of the same prose produce four
different designs.

Terms come from [GLOSSARY.md](GLOSSARY.md). One word for each thing.

---

## 1. The log is a Merkle tree, per RFC 9162

The log was a hash chain. A chain proves the whole history is intact. A chain
is poor at proving one item is inside it: to show that message 33,754 is in a
chain, a reader needs every message after it.

RFC 9162 (Certificate Transparency 2.0) solves the same problem for a different
kind of log. This repository follows RFC 9162 rather than inventing a tree,
because the parts that are easy to get wrong are specified there.

### 1.1 The hash

```
MTH({})     = HASH()
MTH({d0})   = HASH(0x00 || d0)
MTH(D[n])   = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
```

`k` is the largest power of two smaller than `n`. `HASH` is SHA-256.

**The `0x00` and `0x01` prefixes are not decoration.** RFC 9162 says they are
"required to give second preimage resistance". Without them a node inside the
tree can be presented as a leaf, and a proof can be produced for data nobody
submitted. Do not remove them. Do not reorder them.

### 1.2 What a leaf is

A leaf is the stored bytes of one message, exactly as the sequencer wrote them
and exactly as `/messages.ndjson` serves them.

```
leaf_hash(n) = SHA-256(0x00 || stored_bytes(n))
```

Nothing is parsed to compute a leaf. This is the same rule as the chain hash it
replaces. Hashing is a byte operation. It must not depend on understanding the
bytes.

### 1.3 Signed tree head

The sequencer signs an STH, not a chain head. Fields follow RFC 9162
`TreeHeadDataV2`:

| Field | Meaning |
|---|---|
| `timestamp` | milliseconds since the Unix epoch |
| `tree_size` | how many messages are in the tree |
| `root_hash` | `MTH` over all of them |
| signature | Ed25519 over the above, behind a fixed name |

The fixed name is `exchange-feed-sth-v1`, and section 1.5 gives the whole
signed statement. The name is there so that a signature over one kind of
statement cannot be presented as a signature over another kind.

Each STH timestamp MUST be later than the one before it. RFC 9162 requires
this, and it stops an operator serving an old tree as if it were current.

### 1.4 The two proofs

**Inclusion.** Answers: is this message inside the tree with this root? The
proof is the shortest list of node hashes needed to recompute the root from the
leaf. Verification is RFC 9162 section 2.1.3.2 and is implemented exactly as
written there.

**Consistency.** Answers: is the tree at size `m` a prefix of the tree at size
`n`? This is what replaces the chain. It proves entries were only added, and
never changed, removed or reordered.

### 1.5 Endpoints

```
GET /sth                       the signed tree head
GET /proof/inclusion?leaf=N&tree_size=M
GET /proof/consistency?first=M&second=N
GET /tree/nodes?from=N&count=M the stored nodes for leaves N..N+M
```

`/tree/nodes` serves the nodes the sequencer stored, so a reader can check them
against the messages it was served. It is the only one of the four that carries
no signature, and it needs none. The reader hashes the messages into a tree of
its own and compares. A signature over the nodes would prove only that the
sequencer said them.

Without `/tree/nodes`, the nodes between the leaves and the root were the one
record nothing outside the operator ever checked. A wrong node there forges
nothing. The root over the whole subtree above it is stored separately and does
not change, so `/sth` and the anchors still hold. But every inclusion proof
that reads that node lands on a root the sequencer did not sign. The messages
under it can then no longer be proven to be in the log.

`count` is clamped to 1000 leaves, which is about 2,000 nodes.

`GET /head` is the **chain** head and is a different thing. It survives until
stage 2f deletes the chain. It does not serve what section 1.3 defines.

**The statement an STH signature covers**, which a verifier needs:

```
exchange-feed-sth-v1\n<session>\n<timestamp_ms>\n<tree_size>\n<root_hash_hex>
```

Newline separated, no trailing newline. Verified with Ed25519 **strict**
verification: the sequencer uses `verify_strict`. Some Ed25519 signatures can
be changed into a second, different signature that still verifies over the same
bytes. `verify_strict` refuses those. Plain verification accepts them. So a
verifier that is more lenient accepts signatures the sequencer would reject. In
JavaScript with noble-ed25519 that means `zip215: false`, which is not the
default.

The chain head's statement, for the same reason, is:

```
exchange-feed-head-v1\n<session>\n<last_id>\n<chain_hex>
```

### 1.6 Conformance tests: required, not optional

RFC 9162 section 2.1.5 gives a worked example over seven entries `d0..d6`.
It is a known-answer test and every one of these MUST pass:

```
            hash
           /    \
          k      l
         / \    / \
        g   h  i   j
       /|  /|  /|  |
      a b c d e f  d6
      | | | | | |
     d0 d1 d2 d3 d4 d5
```

Inclusion proofs:

| leaf | proof |
|---|---|
| `d0` | `[b, h, l]` |
| `d3` | `[c, g, l]` |
| `d4` | `[f, j, k]` |
| `d6` | `[i, k]` |

Consistency proofs:

| from | to | proof |
|---|---|---|
| 3 | 7 | `[c, d, g, l]` |
| 4 | 7 | `[l]` |
| 6 | 7 | `[i, j, k]` |

On top of the known answers, these properties MUST hold for trees of every
size from 0 to at least 1,024:

- every leaf produces an inclusion proof that verifies against the root;
- every pair `m <= n` produces a consistency proof that verifies;
- changing any byte of any leaf breaks its inclusion proof;
- a proof from one tree does not verify against a different tree;
- an empty tree and a one-entry tree are handled, not special-cased into a
  panic.

---

## 2. The message envelope

Every message has a fixed outer part and a changing inner part.

```json
{
  "v": 1,
  "id": 33754,
  "timestamp": 1786767726360,
  "account": 2687840600,
  "nonce": "1416f0cbe1c9cf4e32dcd9aff282e8b2",
  "body": { "New": { "symbol": "MERKLE-USDC", "side": "Buy", "price": 11.75, "quantity": 40.0 } }
}
```

**This section describes the shape at genesis, and not the shape today.** The
envelope cannot ship while the current session runs, and the reason is worth
keeping.

Serving is not what blocks it: the sequencer serves stored bytes and never
writes a message out again. `Deserialize` is what blocks it. There is one
`OrderMessage`. If it expects `{"v":1,…,"body":{…}}` then parsing fails on
every message already in the log. The engine, the checker, the bot and the
separate service all stop at message 1 with cannot-interpret. Accepting both
shapes is worse. An old message then has two spellings, `Serialize` must pick
one, and a message read and written back stops being its own bytes.

The count is whatever the live log holds, and it only grows: on 17 August 2026
the sequencer answered `GET /sth` with tree size 270,365 for session
`ea117dd79090025a`. The count does not change the argument. One message the
reader cannot parse stops it at message 1, and every message in the log is that
message.

So the envelope lands with the clean genesis in PLAN step 5, over an empty log.

**What the envelope was for has already landed**, because none of it moves a
byte. `wire::envelope` is the one function that returns the kind, the id, the
account and the nonce from raw bytes. The three copies that guessed at field
positions are deleted.

**The outer fields never change.** Any reader gets the version, the message
number, the account and the nonce without understanding `body`.

**`body` is where new kinds go.** A reader that does not know a `body` kind can
still hash the message, order it, and read its nonce.

This exists because the sequencer previously read the nonce by guessing where
it sat inside an unknown message. That works until a kind puts it elsewhere.

**Rule.** No program may read a field out of `body` that it needs for
correctness. If a program needs a field to stay correct, that field belongs in
the envelope.

---

## 3. The self-describing log

The log opens by stating its own rules. Nothing that changes execution lives in
a binary or a configuration file.

```
message 1   EngineRule    rule set 2
message 2   ListSymbol    MERKLE-USDC  price step 0.01  quantity step 0.1
message 3   ListSymbol    ETH-USDC     price step 0.10  quantity step 0.1
message 4   ListSymbol    BTC-USDC     price step 1.00  quantity step 0.1
message 5   New           the first order
```

That is the live opening, and it is not an example. `docker/open-the-log.sh`
publishes those four messages on every start of a log that is still empty. It
takes the rule set from `newest_rule_set` on the exchange's `GET /market`, and
it takes the markets and their price steps from the sequencer's `GET /symbols`,
which reports `domain::SYMBOLS` (`services/src/domain.rs:77-81`). The quantity
step is 0.1 in every market, because 0.1 is the finest quantity grid the engine
holds (`docker/open-the-log.sh:43`). The price step is per market, because a
whole cent means one thing at a mid of 10 and another at a mid of 1000.

**The test for whether something belongs in the log.** If changing it makes the
same messages produce a different result, it is data, not configuration.

The symbol list failed this test. The self-trade rule failed it. Metrics,
caching and rate limits pass it: they change no result.

`DelistSymbol` cancels every resting order in that book. A resting order that
can never fill is worse than no order.

### 3.1 The log names its operator

`EngineRule`, `ListSymbol` and `DelistSymbol` change what every later message
does. Each one carries a `public_key` and a `signature`. The sequencer checks
both before it publishes. Nothing checked them afterwards, so the exchange ran
any operator message it found in the log, and the sequencer is the party that
writes the log.

**The log names its operator once, and every later operator message must be
signed by the key the log already named.**

- The first operator message in a log sets the operator key. There is nothing
  before it to check against, so it is trusted by position: it is a message in
  the log, covered by the tree, and anchored. A reader sees which key opened
  the log, and when.
- That first message must still verify under the key it names. Trusted by
  position decides *which* key the log runs under. It does not excuse the
  signature.
- Every operator message after it must name that same key and verify under it.
- An operator message that does not verify is **ignored**. It is counted, and
  it says so once. That is the same answer, for the same reason, as a
  `ListSymbol` naming a step no book can hold. The exchange does not stop: an
  exchange that halts on a message is an exchange that is down.
- An ignored message names no operator either. It changed nothing. So a log
  whose first operator message was ignored has still named nobody, and the next
  operator message is then the first.
- An operator message with no nonce is ignored for the same reason. The nonce
  is one line of the signed statement, so a message without one has no
  statement to check. That is a refusal about the message, and not an internal
  error.

**Any program that re-executes a log needs the session.** The statement covers
the session, which is the second line, and the message does not carry it. The
session arrives on the sequencer's `x-feed-session` response header, and a run
records it in its state database. A replayer that does not know the session
checks every operator statement against the empty string. It then refuses every
`ListSymbol` the operator published, opens no market, and refuses every order
after that as an unlisted symbol. That is an honest exchange reported as a
catastrophe. So a replayer takes two inputs and not one: the messages, and the
name of the log they came from. In this repository that is
`MatcherState::replaying`, and the audit, the bot's replica and the tests over
a real history all use it.

**The key does not rotate, and that is deliberate.** No message changes it. The
signed statement covers the prefix, the session, the symbol, the steps and the
nonce. It does not cover the `public_key` field. Suppose a rule let a signature
by the key in force hand the role to the key the message names. The sequencer
could then copy an old signature onto a message naming its own key, and take
the log with no new signature at all. A lost or stolen operator key is answered
by a new log: a new session, and a new first operator message. Rotation inside
one log needs the key inside the signed statement first.

The operator key is in the state root. Two engines holding the same books under
different operator keys do not accept the same future operator messages, and
equal roots are supposed to mean two engines run the same. The key is in the
state database too, so a resume comes back under the key it was running under.

**A stolen operator key is not answered here.** Whoever holds it can open junk
markets, close real ones, which cancels every resting order in them, and move
the rule set. An `EngineRule` naming rule set 9999 leaves the exchange matching
under the rules it has, while every checker stops with cannot-interpret. That
is loud, and it is a real denial of verification. The only answer inside the
log is a new log.

**The two programs that implement this rule are the exchange and the checker,
and neither may read the other's code** (section 5). The exchange holds it in
`matcher.rs` over `operator::verify`. The checker holds its own copy in
`verify/operator_key.rs`. Write each one from the text above.

---

## 4. Matching is six steps

Each step is its own module. **A step never calls another step.** The order is
fixed.

```
submit
  │
  ├─►  1  resolve symbol        listed? price step, quantity step
  ├─►  2  validate order type    limit / market / post-only / fill-or-kill
  ├─►  3  bound the price        protection collar
  ├─►  4  self-trade check       cancel newest
  ├─►  5  match against book     price-time priority
  └─►  6  remainder policy       rest it, or cancel it
```

Three words the steps use:

- An arriving order **crosses** a resting order when a buy price is at or above
  the resting sell price, or a sell price is at or below the resting buy price.
- **Price-time priority** is the order in which step 5 fills. The best price
  goes first. At one price, the order that arrived first goes first.
- The **collar** is a limit on how far from a reference price an order may be
  filled. Section 4.2.2 gives it exactly.

| Step | Owner | May read | May change |
|---|---|---|---|
| 1 | Listings | symbol registry | nothing |
| 2 | Order types | the order, the book | nothing |
| 3 | Order types | the book, the reference price | the order's limit price |
| 4 | Self-trade | the book, the order's account | rejects the taker |
| 5 | nobody | the book | the book, trades |
| 6 | Order types | the remainder | **its answer only** |

Step 5 is not owned by any feature. Nobody edits it.

The step modules are private, and every item in them is `pub(super)`. That is
deliberate. `verify.rs` re-executes the same messages with separate code so the
two can disagree. A private module makes reusing a step a compile error rather
than a review comment. **Making any step `pub(crate)` is how the checker stops
being independent.** See section 5.

### 4.0 What the six steps do not cover

Found by building them. Each of these is real, and an agent that assumes
otherwise will write the wrong thing.

**Fill-or-kill is not step 6.** A fill-or-kill order must fill in whole or not
at all. By the time step 6 is asked, step 5 has booked the fills, moved both
positions and written the trade rows. There is nothing left to kill.
Fill-or-kill must be decided **before** step 5: ask the book whether the whole
quantity is available, and refuse in step 2. Only good-till-cancel and
immediate-or-cancel belong in step 6.

**Step 6 changes the book through its answer, and not by hand.** It returns
rest or cancel, and the caller acts. If step 6 rested the order itself, today's
behaviour would be its body and the step would not be empty.

**The collar's reference price has no step.** Section 4.2 requires a
time-weighted mid price. That is state across messages, updated whenever the
book moves. Step 3 may only read it. Step 5 is what moves the book, and nobody
may edit step 5. So the window lives on the exchange's state beside the steps.
Do not use the last trade price instead. Section 4.2 rules it out for a
reason.

**Three messages move a book, and each of them must sample the mid.** A `New`
that fills or rests, a `Cancel` that takes an order out, and a `DelistSymbol`
that empties a whole book. A message that moves the book and records no sample
leaves the mid it used to show weighing into the average for the rest of the
window. For a delist, that is a closed market pricing the collar of the market
that replaces it. Anything added later that edits the book by itself is a
fourth, and belongs on the same list.

**The symbol registry is not in the model either.** It is state across
messages, built from `ListSymbol` and `DelistSymbol` and from nothing else. So
it lives on the exchange's state and step 1 only reads it. It starts empty: a
log that has listed nothing trades nothing, which is the same answer for every
build. There is no fall back to a compile-time list, because that is the thing
that made replay depend on the binary.

A `ListSymbol` naming a step no book can represent lists nothing, and says so
once. A symbol that is listed and can never take an order would refuse every
order one at a time, naming the order instead of the listing. A second listing
of an open symbol is refused too. Changing the steps under resting orders is a
state no message asked for, and the log can say the same thing without
confusion by a delist followed by a list.

**The symbol name has a rule.** A symbol holds 1 to 32 characters. Every
character is `A` to `Z`, `0` to `9`, or `-`. Nothing else is allowed: no lower
case, no space, no dot, no underscore, no character outside ASCII. Upper case
only, because a log that took `eth-usdc` and `ETH-USDC` would hold two markets
that read as one name. An empty symbol is refused because it names no market.

A `ListSymbol` whose symbol breaks this rule lists nothing. It is counted with
the other refused listings, and it says so once: the same answer, for the same
reason, as a step no book can hold. An order that names that symbol later finds
no market, and step 1 refuses it.

The rule bounds a cost the log cannot take back. `state_root` writes the length
of a symbol in front of the symbol before it hashes it, so two different
symbols never hash alike. Nothing there bounds that length. A symbol enters the
registry, goes to the `listings` table, and is hashed into every state root
after it. Nobody can edit the log, so a symbol of a megabyte of text stays in
every later state root for the life of the log. The only place to stop it is on
arrival.

**The two programs that implement this rule are the exchange and the checker,
and neither may read the other's code** (sections 4.2.1 and 5). The exchange
holds it in `operator::valid_symbol`. The checker holds its own copy in
`verify/listings.rs`. Write each one from the two paragraphs above, and never
from the other one: a disagreement between them is the evidence, and a copy
cannot disagree.

The separate service (`inbox.rs`) is not a third implementation and must not
become one. It checks the same names as the exchange, so it calls
`operator::valid_symbol` too. Three callers of that function is the correct
count.

**Cancelling an order is not in the model.** `apply_cancel` checks ownership,
updates counters and edits the book. `DelistSymbol` must cancel every resting
order in a book, and the model has no step for that. The Listings agent works
outside the six steps for that part.

**A rejection after step 1 must prune the book.** `state_root` asserts that no
empty book is in the map. Steps 3 and 4 can reject after the book entry exists,
so the caller prunes on both paths. A rejection that forgets leaves an empty
book, and a restored engine then hashes differently from a live one.

**One counter is not enough.** Every rejection from steps 1 to 4 became
`orders_ignored` and one log line. A submitter reading `/market` could not tell
an unlisted symbol from a self-trade refusal, and section 4.1 requires the
rejected taker be told why. Splitting the counter changes what an endpoint
reports, so it was a deliberate change and not a side effect of a feature.

`orders_ignored` is still the total. `/market` now also serves
`orders_ignored_by_reason`, the same total split by one machine-readable word
per refusal: `unlisted_symbol`, `off_grid`, `off_price_step`,
`off_quantity_step`, `self_trade`, `position_overflow`.
Each step names its own words in its own module, so there is no shared list
four agents have to edit. A word appears once that refusal has happened, and
the split always sums to the total.

The split is stored beside the total, in the same commit, so it still sums to
the total after a restart. The first implementation counted the split only in
memory. After a restart, the engine reported 620 ignored orders but its reasons
added up to 320. The total covered every process lifetime, while the split
covered only the latest one. Schema version 10 stores the split. A
run recorded before that version comes back with its whole total under the word
`not_recorded`, which is what such a run knows about its own refusals: it
counted them and wrote down no reason.

`/market` reports the whole exchange. A submitter still cannot ask what
happened to their own order, because there is no route that reports the status
of one order. So "the rejected taker MUST be told why" is half met, and the
other half belongs where a submission is tracked, and not here.

**Step 4 walks the book twice.** It has to walk the crossing levels to see
whether the order would meet its own resting order. Step 5 then walks the same
levels to fill them. That is the price of "a step never calls another step",
and it is worth paying once. Two pieces of code must agree on which levels
cross.

They cannot be merged into one. Step 5 is owned by nobody, so a shared helper
would still leave step 5 with its own copy. What holds them together is that
step 4 asks a strictly smaller question, and a test that runs both. Step 4 asks
which levels cross, and not which fills happen. In that test a stranger sweeps
with a quantity large enough to clear everything it crosses, and the emptied
levels are recorded. Then an order of the arriving account is put at each level
in turn, and the refusals are recorded. The two lists must be equal at every
limit price, and the one sitting exactly on a level is included. Change `<=` to
`<` in step 5, or `..=` to `..` in step 4, and the test fails.

### 4.1 Self-trade policy

Cancel newest. The arriving order is rejected; the resting order stays.

It keeps time priority. A trader cannot use it to clear their own resting order
and reach the orders behind it, which cancel-oldest allows. It needs no
quantity arithmetic, so a second implementation can reproduce it exactly.

The rejected taker MUST be told why. A silent failure looks like a dropped
order.

**The rule arrives as a message, and not as code.** The first log ran under
rule set 1 and refused no self-trade, so it holds executed self-trades. See
[DECISIONS.md](DECISIONS.md), "Cancel newest for self-trade prevention", for
that measurement. Turning the rule on in a binary would have made those
messages replay differently. Every signed claim and every anchor over them
would then stop verifying. That is section 3's test: the rule is data, and not
configuration. So `EngineRule` names rule set 2. Replay before it self-trades
and replay after it does not, and everyone gets the same answer.

The live log opens at rule set 2, so it executes no self-trade. It refuses them
instead: on 17 August 2026 the exchange answered `GET /market` with
`orders_ignored_by_reason` naming `self_trade` 18, over 273,303 messages and
102,600 trades. That count is low because the generator's quoting accounts
never cross and its taking accounts never rest, so it asks for almost no
self-trade to refuse in the measured 40-account configuration.

Rule sets are cumulative and numbered. They are not independent flags: ten
flags is 1,024 combinations of replay behaviour, and two implementations must
agree on every one of them. A build knows rule sets 1 to N.

The two implementations respond differently to an unknown rule set. The engine
counts it in `kinds_not_acted_on` and keeps matching under the rules it knows.
Halting on one message would take the exchange down. `verify.rs` instead stops
with cannot-interpret. A report replayed under the wrong rules is worse than no
report.

The rule set is in the state root. Two engines holding the same books under
different rule sets do not match the same future messages the same way, and
equal roots are supposed to mean they do. The rule set goes in only when it is
not rule set 1, so every root already committed over a history that names no
rule set is the byte string it always was. It is also in the state database. A
resume that forgot it would rebuild a state hashing to a root its own last
claim contradicts, and the run would end.

**Quantity does not come into the check.** An order of the account at a crossed
price refuses the arrival, whether or not the arrival would have reached it
after the queue in front of it. That is what "no quantity arithmetic" means,
and it is what lets the two implementations agree on a range instead of on an
outcome. A partial self-trade refuses the whole arriving order. Reducing the
quantity is the alternative, and it needs the arithmetic in both places.

### 4.2 Market orders

The engine has one order type that rests: a limit order. A market order is a
limit order priced to cross. It may fill partly and never rests. A
fill-or-kill market order requires the whole quantity or changes nothing.

**The client chooses and signs the bound. The server may only tighten it.**

The web UI reads the displayed midpoint, lets the visitor choose 0.01% to
1.50% max slippage, and derives the worst price from those two values. A buy
rounds the result up to the symbol's price step. A sell rounds it down. The
browser shows that price before it signs. The command-line client takes the
worst price directly. In both cases, the signed order carries the bound, so the
server cannot fill at a worse price without breaking the signature.

The server then applies its own two-percent collar. That collar only tightens
the signed bound. It never widens it.

**The reference price for the collar is a time-weighted mid price**, and not
the last trade. One trade can move the last trade price. An attacker would have
to hold the mid wrong for the whole window, which costs money.

### 4.2.1 The reference price, exactly

Two programs compute this from this text and never from each other's code, so
the text has to be exact.

A **sample** is taken every time a symbol's book changes: after a match, after
a remainder rests, after a cancel takes an order out. It is the pair
`(timestamp, mid)`, where `timestamp` is the millisecond on the message that
moved the book and

```
mid = (best_bid_cents + best_ask_cents) / 2      integer division, both sides present
mid = none                                       either side empty
```

A sample holds from its own timestamp until the next sample's timestamp. The
reference price at time `t` is the average of the mid over the last
`WINDOW_MS = 30000` milliseconds, each sample weighted by how long it held
inside that window:

```
w(i)  = overlap of [t(i), t(i+1)) with [t - 30000, t]      last sample: t(i+1) = t
ref   = sum(mid(i) * w(i)) / sum(w(i))                     over samples whose mid is not none
```

Integer arithmetic throughout, dividing last, truncating toward zero.
`sum(w(i)) == 0` means **there is no reference price**. A sample that has held
for zero milliseconds carries no weight, and neither does a window with no mid
in it. That is the rule the collar rests on. Placing a quote and taking against
it in the same millisecond moves the mid for zero milliseconds, and therefore
moves the reference by nothing at all.

A timestamp that does not advance is read as the last one that did. A message
cannot move the window backwards.

### 4.2.2 The collar, exactly

```
band  = ref * 200 / 10000, at least 1            2 percent of the reference
buy   : limit_cents = min(signed_limit, ref + band)
sell  : limit_cents = max(signed_limit, ref - band), at least 1
```

It only ever tightens. A market order with no reference price is **refused**,
and not filled. The operator choosing the price is the one outcome section 4.2
exists to prevent, and refusing costs the sender nothing.

**The collar applies to market orders only.** A limit order's price is the
number its sender signed, and moving it would change where orders already in
the log came to rest.

---

## 4.3 Two nonces, and they are not related

There are two counters in this system and they answer different questions.

| | Who makes it | What it stops |
|---|---|---|
| the user's nonce | the user, inside their signature | replaying the user's signed order |
| the message number | the sequencer, when it logs | inserting an order into the log |

**A nonce is unique within one user, and not across all users.** The unique
index is on `(account, nonce)`. Nonces are public on `GET /pending`, so two
accounts can hold entries under the same nonce. Any check that compares a nonce
must compare the account with it.

This is not a detail. It was briefed as "the nonce alone identifies an entry".
Building on that would have let the sequencer close one account's entry with
another account's message: a proof that verifies, a nonce that matches, and an
entry closed that was never sequenced.

**The rule underneath.** Identity comes from what the user signed, and never
from what the sequencer assigned. The sequencer is the untrusted party. What
the sequencer hands you is a claim. What you signed is a fact.

The message number is the sequencer's assignment and is useful. It orders the
log and it names a leaf. It is not an identity, and a check that trusts it as
one is trusting the party it exists to check.

## 4.4 The order terms, exactly

`order_type`, `time_in_force` and `post_only` are three fields on `New`.
`order_type` is limit or market. `time_in_force` is good-till-cancel,
immediate-or-cancel or fill-or-kill. `post_only` is true or false. That is
twelve combinations, and every one of them has an answer here.

**Step 2 refuses, before the book is touched at all.**

| # | When | Why |
|---|---|---|
| 1 | market and post-only | a market order is priced to cross. The two terms ask for opposite things |
| 2 | post-only and not good-till-cancel | post-only asks the order to rest; the other two ask it not to. It could never do anything |
| 3 | post-only and anything is resting at or better than its limit | it would take liquidity, which is what post-only refuses |
| 4 | fill-or-kill and less than the whole quantity is available at its limit | ENGINE.md 4.0: refuse before step 5 books anything |

Step 2 reads the book without creating one. A symbol with nothing resting has
no book, and a refusal here must not leave an empty one behind, section 4.0.

Rule 4 counts every resting order at a crossing price, including the sender's
own. Step 4 then refuses the order for that same resting quantity, because step
4 refuses self-trades. So a fill-or-kill order that reached its whole quantity
only by counting its own resting orders is refused by step 4, and it is never
partly filled. Under rule set 1 step 4 refuses nothing, and the same order
fills.

**Step 3 refuses a fill-or-kill order whose price the collar moved.** The
promise that the whole quantity is available was made against the price the
sender signed. A tighter price is a different question, and the answer to it
belongs to step 2, which has already run.

**Step 6 answers rest or cancel.**

| Order | Answer |
|---|---|
| market, any time in force | cancel. The engine has one resting type and it is the limit order |
| limit, good-till-cancel | rest |
| limit, immediate-or-cancel | cancel |
| limit, fill-or-kill | cancel. Unreachable: step 2 refused it, or it filled whole and step 6 is not asked |

**Where the window lives.** On the exchange's state, beside the six steps, in
`matcher/reference_price.rs`. Step 3 is handed the reference price as a number
and cannot write it. It is **not** in the state root and **not** in the state
database. So an engine resumed from a snapshot starts with no reference price,
and refuses market orders until it has watched a book for the whole 30-second
window. That is a refusal, and never a wrong fill. It is still a real
difference between a resumed engine and an audit, which replays the same
history from message 1 and does have the window
(`services/src/matcher/reference_price.rs:69-76`).

**Market orders are on, and that difference is open under them.**
`--order-terms market` and `--order-terms market-fok` run
(`services/src/main.rs:347-348`), and the page offers `Market` and `Market,
fill or kill` to a visitor (`services/static/app.js`). It is a
known difference on a running exchange, and it costs a refusal and never a fill
at the wrong price.

Putting the window in the state root is the obvious fix, and it is refused. The
root's encoding would change, and every run has already signed claims under the
encoding it has.

---

## 5. The independent checker stays independent

`verify.rs` and the files under `verify/` import `domain`, `logchain`, `wire`,
`reporting`, `operator`, `fetch` and `anchor`. Test builds also import
`feed`. It does **not** import `matcher`, and it must not start.

`services/tests/checker_imports.rs` reads those files and fails on any other
module. This section is the prose; that test is the enforcement. The list of
allowed names is one `const` in the test. Change both together.

It exists to disagree with the engine. Two implementations that share no
matching code can catch each other's bugs. If both call the same pipeline
module, a bug in that module is invisible to both.

**Every matching rule is written twice.** Once in the pipeline, and once
independently in `verify.rs`. This is deliberate duplication. Do not remove it.
Do not "share the logic" to save work.

`verify.rs` may import `crate::operator`, on the same footing as `logchain`. It
supplies the bytes one operator signature covers, and the Ed25519 check over
them. It never supplies a rule. Which key is in force, and what an unverified
message does, stay the checker's own code.

**`verify.rs` may not import `crate::merkle`.** `merkle` is not in `ALLOWED`
in `services/tests/checker_imports.rs:55`, and that test fails on any file
under `verify/` that names it. The list at the top of this section is that
`const`, name for name.

The reason `merkle` is off the list is not that its contents are dangerous.
`merkle` supplies the RFC 9162 leaf hash, node hash and root calculation. It
also compares stored nodes with the nodes produced by the same entries. It
never supplies a matching rule. A second copy of that arithmetic would catch
nothing. Its root would disagree with the sequencer's on every honest history,
and the report would name the wrong fault. The checker keeps one rule to itself:
how to handle a root mismatch. It reports a failed check and exits with status
1.

The checker still reaches the tree comparison, through a module that is on the
list. `reporting.rs` imports `merkle` (`services/src/reporting.rs:31`), and the
checker calls `check_tree` in `reporting` (`services/src/reporting.rs:293`). So
the comparison happens, no file under `verify/` names `merkle`, and the test
passes. Do not look for an import that is not there.

`verify.rs` may import `crate::anchor`, on the same footing as `fetch`. It
supplies how to reach the anchor contract and how to read `/sth`: an address,
a topic, a selector, and a signed head. It never supplies a rule about what a
root means. A second implementation of an RPC call catches nothing. `verify.rs`
uses two things from it: `RootAnchorSource`, which names the RPC endpoint and
the contract address, and `fetch_tree_head`, which reads the head the
sequencer signed.

`verify.rs` may import `crate::feed` in test builds. It uses one constant,
`feed::PAGE_LIMIT`, so a held history hands the checker pages of the size the
sequencer serves. A second copy of the number would let the test walk pages
the real feed never sends.

`verify.rs` may import `crate::fetch`, on the same footing again. It supplies
how to read a bounded body over HTTP: the connect and request timeouts, the
client, the size cap a body is read against, and the sentence an HTTP error
turns into. It never supplies a rule about what the body means. Splitting the
transport in two catches nothing. A body `fetch` truncated hashes to a chain
that does not match the signed head, so the checker and the audit both fail
loudly on it instead of agreeing on a wrong answer.

### 5.1 What is shared, and what is written twice

A reader must be able to tell one from the other without comparing two files.
This table is the list. Nothing outside it is shared.

| What | Where | Shared or written twice |
|---|---|---|
| what a message is: `OrderMessage`, `Side`, `OrderType`, `TimeInForce`, the id aliases | `domain.rs` | shared |
| what a price and a quantity are: `to_grid` and `MAX_GRID_UNITS` | `domain.rs` | shared |
| the bytes one operator signature covers, and the Ed25519 check over them | `operator.rs` | shared |
| how to read a bounded body over HTTP: the timeouts, the client, the size cap, the reason an error gives | `fetch.rs` | shared |
| the RFC 9162 tree: the leaf hash, the node hash, the root, and the comparison of stored nodes against the entries | `merkle.rs`, reached only through `reporting.rs`; the checker may not name `merkle` itself | shared |
| how to reach the anchor contract and how to read `/sth`: the address, the topic, the selector, and the signed head | `anchor.rs` | shared |
| how many messages one page of history holds: `PAGE_LIMIT` | `feed.rs`, test builds only | shared |
| the symbol name rule | `operator::valid_symbol` and `verify/listings.rs` | written twice |
| the listing rule | `matcher`'s `SymbolRegistry` and `verify/listings.rs` | written twice |
| the order terms, the reference price and the collar | pipeline steps 2, 3 and 6, and `verify/order_terms.rs` | written twice |
| the self-trade rule | pipeline step 4 and `verify/self_trade.rs` | written twice |
| price-time priority, and the price a fill takes | pipeline step 5 and the replayed book in `verify.rs` | written twice |

The line between the two groups: **both sides must agree on what a message is,
and must be able to disagree on what the exchange may do with it.**

`to_grid` is on the shared side because it reads a number and applies no rule.
It reads a price onto whole cents and a quantity onto whole tenths, and refuses
a value that is not a whole number of either. It was written three times
before, in `matcher.rs`, in `verify.rs` and in `inbox.rs`. The three were the
same bytes, comment included. Three copies of one function cannot disagree,
so the checker's copy proved nothing. A checker that did round a price
differently would report an honest exchange as wrong the first time a price
landed between the two roundings, and the report would name the wrong fault.

A fourth copy of it is in `services/static/app.js`, in JavaScript, because
the page builds and signs a statement in the browser. That one cannot be
deleted. `inbox.rs`'s `the_browser_rounds_on_the_same_grid_as_the_engine` reads
that file as text and fails on any edit to it.

---

## 6. An old reader that meets a new message

Three states, never two:

| State | Meaning | Exit |
|---|---|---|
| pass | everything checked and held | 0 |
| fail | a check failed. The history was rewritten. | 1 |
| cannot interpret | the tree verified; this build cannot read message N | 3 |

A failed check outranks cannot-interpret. Otherwise an old binary becomes a way
to turn a failing audit into a status nobody acts on.

**A program that must act on a message it cannot read stops.** It never skips.
Skipping means running on a wrong picture while reporting nothing wrong.

Validators are the exception, and that is the point of the design. A validator
attests to the order of messages, and not to their meaning, so it never needs
upgrading when a kind is added.

### 6.1 Deploy order

Readers first, writer last.

1. Upgrade the exchange, the checker, the bot, the separate service.
2. Upgrade the sequencer last, because it is what starts producing new kinds.

Backwards, and every reader halts until it is upgraded.

---

## 7. The separate service and its confirmation

The separate service records an order the sequencer does not control, and holds
a deadline. If the sequencer does not put the order in the log in time, the
service publishes that fact.

Today the sequencer confirms by sending the message back, and the service
compares it field by field against what was signed. That check is real: it
catches a sequencer that logs a different price under your nonce.

It breaks on a message kind the sequencer cannot read. The sequencer cannot
write that message out again, so it sends nothing, and the deadline expires.
The service then publicly accuses an honest sequencer. That is worse than
noise. It makes the censorship alarm worthless.

**The fix.** The confirmation carries an **inclusion proof** against the
current STH, plus the message's stored bytes.

The service then:

1. verifies the inclusion proof: pure hashing, no parsing, works for every
   kind, forever;
2. reads the nonce from the **envelope** and confirms the entry is its own;
3. compares the fields, when it understands the kind.

Three outcomes, not two:

| Outcome | Meaning |
|---|---|
| confirmed | proof verified, nonce matches, every field matches |
| confirmed, content not checked | proof verified, nonce matches, this build cannot read the kind |
| late | nothing arrived in time. **This is the censorship alarm.** |

The middle state never fires the alarm.

---

## 8. The anchor commits the root

The anchor contract commits `root_hash`, and not a chain hash.

A visitor can prove that their trade is inside the commitment written to Base.
The browser checks **18 hashes, or 576 bytes**. This figure was measured on 17
August 2026. The live sequencer answered
`GET /proof/inclusion?leaf=122363&tree_size=245223` with an `inclusion_path` of
18 hashes. At 32 bytes per hash, the path is 576 bytes. `ceil(log2(245,223))`
is 18, so the path is the shortest the tree allows.
Against a chain the same check needs every message in the window, which
measured 1.7 MB for the first anchor.

---

## 9. What is not built

Spot venue only. No margin, no liquidation, no funding rates, no insurance
fund. Those four belong to a venue that trades perpetual futures, and a spot
venue that carries them is pretending to be something it is not.
