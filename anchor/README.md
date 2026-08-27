# The on-chain anchor

The exchange signs its history and its execution, and `--audit-url` lets a
stranger re-execute all of it. What none of that gives is a record **outside
the operator's machine**. An operator can stop the exchange, delete `feed.db`
and `state.db`, publish a different history, re-sign every head and every claim
over it, and restart. Someone auditing afterwards re-executes a perfectly
coherent exchange and every check passes. Only somebody who happened to save an
earlier signed head could tell, and nobody is obliged to.

This directory is that outside record: two small Solidity contracts on Base
Sepolia and a Go program that writes to one of them every five minutes.

## Two contract shapes, four deployments

There are two Solidity sources. `ExchangeAnchor` commits `chainHash`, the
SHA-256 fold over messages 1..`lastId`. `ExchangeRootAnchor` commits
`rootHash`, the RFC 9162 Merkle root the sequencer signs. Both are on Base
Sepolia (chain 84532) and both are written by
`0x6192D3FD82917eAb2864F46cb63b69bC8C6E09CE`.

A contract pins its session on its first write, so every reset of the log needs
a new contract. Three resets have happened, so there are four deployments. The
counts below were read from the chain on 17 August 2026 with `eth_call`:

| Address | Shape | Session it pinned | Anchors held | State |
|---|---|---|---|---|
| [`0x2A4A287E…a62b`](https://sepolia.basescan.org/address/0x2A4A287EC1F01b5bCb5568D2Ed0765Faf860a62b) | chain hash | `349d462ced25bb2b` | 152, to message 109,185 | closed |
| [`0xCE85983c…995e`](https://sepolia.basescan.org/address/0xCE85983ce00Cc964753410410c7EF3D24d1d995e) | root | `349d462ced25bb2b` | 178, to message 218,741 | closed |
| [`0x18486b8A…eE4b`](https://sepolia.basescan.org/address/0x18486b8A7a5174A295Efc4b5fE358e062670eE4b) | root | `61e4629e2f7a57be` | 285, to message 479,887 | closed |
| [`0x4162B321…672d`](https://sepolia.basescan.org/address/0x4162B3218b97663dEBC1f59060910221bb95672d) | root | `ea117dd79090025a` | 44, to message 262,110 | **live** |

Blocks and transactions: 45495043 for the first, 45515433 for the second,
45542601 for the third, and 45583892 for the live one, tx
[`0x7c3264f3…8190`](https://sepolia.basescan.org/tx/0x7c3264f3cc7ba24f9d7dff9de87d998b7bcf2a40e881172564d317c223c38190).
Event topic `0x846b388d…8385` for the chain-hash shape and
`0xf17e0641…191f` for the root shape.

**Only two of the four records survive in this repository.**
[`deployment.json`](deployment.json) holds the chain-hash contract and
[`root-deployment.json`](root-deployment.json) holds the live one. Each reset
overwrote `root-deployment.json`, so the two closed root contracts are recorded
only in this table and in the git history of that file: commit `960000d` for
`0xCE85983c…` and `a6bd186` for `0x18486b8A…`. That is a real gap: an address
that only git history remembers is harder to check than one a file names.

**The live deployment writes root anchors**, from the sender in this directory.
At runtime, `ANCHOR_CONTRACT` may override the baked address. The `Dockerfile`
bakes `root-deployment.json` in, and the exchange serves the selected address at
`/anchor-config`.

A closed contract is not a retired one. All three closed contracts still hold
real anchors over the histories they recorded, and `--audit-url` with the right
contract flag still checks them. What a closed contract cannot do is take
another write: it refuses an anchor for a session that is not the one it
pinned, which is what makes a wipe visible instead of silent.

## Why a root, and why that needed a second contract

A visitor who wants to prove their own trade is inside the commitment written
to Base needs **every message in the window** when checking a chain hash. The
first anchor required 1.7 MB. Against a Merkle root the same question takes
18 node hashes, 576 bytes, checked in their browser. That is measured against
the live sequencer on 17 August 2026 at tree size 245,223, where
`ceil(log2(245,223))` is 18. It is [`docs/ENGINE.md`](../docs/ENGINE.md)
section 8, and it is the reason this change was worth making.

A root is 32 bytes and so is a chain hash, so a root would have fitted in the
old contract's `chainHash` slot and every transaction would have succeeded. Two
things make that wrong, and only the second cannot be fixed by documentation:

- the field would be named `chainHash` forever, in the ABI, in the event, and
  in every block explorer that decodes it. A contract is what a stranger reads
  when they do not believe the documentation.
- **nothing on chain would say which anchors were which.** Both values are 32
  bytes of hash. A verifier reading the log would need a rule from outside the
  log, such as "entries after the 143rd are roots". That rule would live in a
  binary or configuration file, which `docs/ENGINE.md` section 3 forbids. A
  verifier that guessed wrong would report a tamper where there was
  none, and an alarm that fires when nothing is wrong is worse than no alarm.

The event signature settles it instead. `Anchored(...)` and `AnchoredRoot(...)`
hash to different topics, so one `eth_getLogs` filter returns chain anchors and
the other returns root anchors, and neither can return the other kind. That is
a fact about Ethereum, not a convention this repository maintains.

The old contract's own rules point the same way. The session is fixed by the
first anchor, and `lastId` only moves forward, both so that the record cannot
be revised. A tuple whose third value means something else is a revision of
what every earlier entry said, and refusing it is the same rule.

The cost of the second contract is 0.0000021 ETH to deploy and one more
address to publish. The 140-odd chain anchors keep their meaning, are still
read by `--audit-url`, and are checked by exactly the code that checked them
before.

## Why the sender is a separate program

It reads **only public endpoints.** They are `/config` and `/claims` on the
matcher, plus `/sth` and `/proof/consistency` on the feed. Nothing it does requires the
operator's cooperation or the operator's files.

That is the design, not an accident of packaging. **Anyone can run one**, and a
third party's anchor is *stronger* evidence than the operator's own: an anchor
written by the operator's process is still the operator. Point this program at
`https://exchange.th3nolo.com`, deploy your own copy of the contract with your
own key, and publish the address. The auditor's `--anchor-contract` flag takes
any address, so a reader can check the exchange against your record instead of
against ours, or against both.

The contract accepts writes from its deployer only. Without that guard,
`latest()` would mean "whatever the last stranger said", which is both a way to
fail an honest exchange's audit and a way to bury a real anchor under noise.
With it, every entry is one party's own commitment, which is exactly the thing
they cannot take back later. One contract, one writer, one history. Anybody
who wants a second opinion deploys a second contract.

## What one root anchor commits to

```
treeSize   how many messages were in the Merkle tree, from the feed's own
           signed tree head. The tree holds messages 1..treeSize, and message
           n is leaf n-1.
lastId     the matcher's durable cursor: the last feed message it has
           committed to its state database.
session    the feed history both numbers belong to. Sizes and ids restart when
           a history is replaced, so either without a session names nothing.
rootHash   the RFC 9162 root over messages 1..treeSize, copied out of the
           signed tree head.
stateRoot  the root_after of the matcher's own signed claim whose to_msg is
           exactly lastId.
```

### Two positions, not one

The chain anchor forced all four values to one position. The feed signs the
chain only at its own head, so the sender had to rederive the chain at the
matcher's cursor. Every tick folded the full `/messages.ndjson` history. The
session had reached 100,000 messages and 14 MB.

A tree head cannot be re-derived at an earlier size either. So this anchor
stops pretending, and carries both positions. Each value stands at a number a
signature covers:

- `rootHash` stands at `treeSize`, under the feed's tree-head signature;
- `stateRoot` stands at `lastId`, under the matcher's claim signature.

The contract enforces `lastId <= treeSize`, so the messages the execution
claims to have applied are always inside the tree that was anchored. A reader
of the contract alone knows that much without asking anyone.

This also fixes a smaller thing. Under the old contract, a matcher that had
stopped advancing its cursor stopped the anchor entirely. `lastId` had to
move forward or the transaction reverted. A stalled engine therefore stopped
the record of the feed's history. Here `treeSize` moves forward on its own,
while `lastId` may stay where it is.

## What one tick does

1. `latest()` on the contract: one `eth_call`, free.
2. `GET /claims?since=0` for the session, the cursor C, and the keys.
3. `GET /claims?since=C-1000` for the claim ending exactly at C; its Ed25519
   signature is verified against the matcher's published key.
4. `GET /sth`, the signed tree head. **Its Ed25519 signature is verified before
   anything else happens, and a tree head that does not verify stops the tick.**
5. `GET /proof/consistency?first=<anchored size>&second=<signed size>`, and the
   RFC 9162 check that the tree already on chain is a prefix of the tree the
   feed has just signed.
6. Skip if the signed tree is no larger than the one on chain. Otherwise send
   `anchor(treeSize, lastId, session, rootHash, stateRoot)` and wait for the
   receipt.

A failed tick is logged and retried on the next one; nothing here exits on a
transaction that did not land.

### What it refuses to write, and why

The old sender's rule was that it would not anchor a chain value it could not
reproduce from the messages the feed served. The equivalent here is stronger,
because the value being anchored is one the feed put its own signature on
rather than one this program worked out alone. Every one of these stops the
write and says which two values disagree:

| Refusal | What it means |
|---|---|
| the tree head's signature does not verify | the root is a number nobody has committed to |
| the tree head names a different session | the matcher and the feed are on two histories |
| the tree head is signed by an unpinned key | the feed key changed inside one run |
| `tree_size` is below the matcher's cursor | the state root would stand outside the anchored tree |
| the session on chain is not this one | the history this contract records has been replaced |
| the signed tree is smaller than the anchored one | the log has lost entries it was committed to |
| a different root at the size already anchored | the entries under that root have been rewritten |
| the consistency proof does not verify | the feed's tree is a fork of what this contract holds |
| the cursor is behind the anchored one | the execution has been rewound past what was anchored |

The last four compare the feed against a value on chain that nobody, including
the operator, can edit. None of them is a reason to try again in five minutes.

There is no resume file any more. The old sender kept `chain-cache.json` so
each tick could fold forward from the last anchored message instead of from
message 1. There is no fold left to resume, and what that file used to hold,
where this sender last stood in this history, is on chain, where it cannot be
edited. `-cache` and `ANCHOR_CACHE` are gone.

The first anchor to a fresh contract has nothing to extend, so no consistency
proof is asked for and the tree head's signature is the whole check. Every
anchor after it is checked against what the one before it wrote.

## Running it

```sh
go build -o anchor-sender .        # Go 1.23+; produces one static binary
./anchor-sender -once              # write one anchor and exit
./anchor-sender -interval 5m       # the real thing
```

Configuration is flags, each with an environment variable behind it, so the
container needs no command line:

| Flag | Environment | Default |
|---|---|---|
| `-rpc` | `ANCHOR_RPC` | read from `root-deployment.json` |
| `-contract` | `ANCHOR_CONTRACT` | read from `root-deployment.json` |
| `-key` | `ANCHOR_KEY_FILE` | `/run/secrets/anchor_key` |
| `-exchange-url` | `ANCHOR_EXCHANGE_URL` | `https://exchange.th3nolo.com` |
| `-feed-url` | `ANCHOR_FEED_URL` | asked for on `GET /config` |
| `-interval` | `ANCHOR_INTERVAL` | `5m` |
| `-deployment` | `ANCHOR_DEPLOYMENT` | `root-deployment.json` |

### More than one endpoint

`-rpc` takes a comma separated list, most preferred first, and each call goes to
the first endpoint that answers. When it is unset the list comes from the
deployment record, which names a primary in `rpc` and the rest in
`rpc_fallbacks`:

```json
"rpc": "https://sepolia.base.org",
"rpc_fallbacks": [
  "https://base-sepolia-rpc.publicnode.com",
  "https://base-sepolia.drpc.org"
]
```

This exists because a public testnet endpoint stops answering. On 18 August 2026
`https://sepolia.base.org` answered 503 to ten requests out of ten while both
fallbacks answered all ten. The sender knew about only the failing endpoint.
Every tick asked `latest()`, received a 503, logged `FAILED`, and waited five
minutes before trying again. No anchor was written during the outage.

Two things it deliberately does not do. It does not move to the next endpoint
when one answers with a refusal. A revert, a used nonce and an underpriced
transaction all arrive as HTTP 200 with a JSON-RPC error. Repeating the same
doomed call against each endpoint would only add delay. It
moves on 408, 429 and 5xx, which are the codes that mean the endpoint itself
could not answer. After moving, it stays on the working endpoint. Starting from
the front again would pay the dead endpoint's 20-second timeout on every call
during the outage. A restart
returns to the front.

Retrying a send is safe for the same reason rebroadcasting is: the transaction
is already signed and carries a nonce, so a second endpoint either accepts the
identical transaction or rejects one it already knows. Neither writes two
anchors.

The same list reaches the browser. The matcher serves it at `/anchor-config`
from the same record, so a visitor reading the anchor from the chain fails over
across the same endpoints.

The interval is a tuning decision, not a protocol one. It bounds how much
recent history a rewind could reach without contradicting an anchor: at five
minutes an operator could rewrite at most the last five minutes undetected. It
is not a cost decision. See the runway below.

### Pointed at the wrong contract

Both contracts declare `latest()`, so both answer the same four selector bytes:
a selector covers a function's name and its arguments and says nothing about
what comes back. The chain-hash contract answers with six 32-byte words and the
root anchor with seven, and that width is the only thing that tells them apart
over the wire.

So this sender checks it at startup and exits non-zero rather than sending a
transaction that reverts:

```
$ ./anchor-sender -once -contract 0x2A4A287EC1F01b5bCb5568D2Ed0765Faf860a62b
anchor-sender: 0x2A4A287EC1F01b5bCb5568D2Ed0765Faf860a62b answered latest() with
192 bytes, not the 224 an ExchangeRootAnchor returns. The closed chain-hash
ExchangeAnchor answers the same selector with 192 bytes; this sender writes
Merkle roots and cannot write to it. Point -contract, ANCHOR_CONTRACT or the
deployment record at the root anchor
$ echo $?
1
```

### The key

**A path, never a value.** `ANCHOR_KEY_FILE` names a file; there is no variable
that holds key material, and setting `ANCHOR_KEY` makes the program refuse to
start. An environment variable is readable through `docker inspect`, through
`/proc/<pid>/environ` for anything running as the same user, and through the
deployment UI that set it. In the container the file is a Docker secret mounted
read-only at `/run/secrets/anchor_key`.

Every way the path can be wrong is checked at startup, before a single
transaction is built, and each one names the path and exits non-zero:

```
$ ./anchor-sender -once -key /run/secrets/anchor_key
anchor-sender: the anchor key path /run/secrets/anchor_key is a directory, not a
file. Docker creates a directory there when it is told to bind-mount a file that
does not exist on the host, so the secret almost certainly never reached this
container
$ echo $?
1
```

That case is the one worth having. Without it the sender starts happily, fails
somewhere near signing, and the operator is left believing anchoring is running
when nothing has been written for a week.

The key is never logged, never copied, never written anywhere, and never
appears in an error. The derived **address** is logged once at startup, which is
how you confirm the right key reached the container.

## Why the verifier reads the whole log

`latest()` alone does not catch the attack this exists for. An operator who
rewinds the feed to message 500, publishes different messages from there, runs
on to 1500 and anchors the new root leaves a contract whose newest entry
today's history reproduces exactly. The rewind is invisible to anyone reading
one value.

The anchor at message **1000** exposes the rewrite. It commits to a root over
the old messages, while today's first 1000 messages produce a different root.
The block also records when the operator committed to the old version. The Rust
auditor therefore reads and checks every event the contract emitted. It still
reads `latest()` for the age of the newest anchor. The returned `count` tells
the log scan when it has every event.

## How an anchored root is checked, both ways

`services/src/anchor.rs` checks each root anchor two ways, because the two say
different things and both are cheap.

**By folding.** The audit builds one RFC 9162 tree over the messages the feed
serves today, in the same single pass that folds the chain and replays the
engine, and compares `root_at(treeSize)` against each anchored root. Getting a
root at an earlier size costs about 17 node hashes, so a hundred anchors is a
hundred cheap lookups rather than a hundred passes over the history. Nothing is
parsed: a leaf is the stored bytes, so this check holds over a history
containing a message kind the auditing binary has never heard of.

**By consistency proof.** The audit reads `GET /sth`, verifies its Ed25519
signature, and asks for the consistency proof between each anchored size and
the size the feed is signing now. A proof that verifies says the head this feed
signs *this second* is an extension of the root that was anchored, under the
feed's own key, over a document the auditor did not choose. An operator serving
one `/messages.ndjson` to the auditor and a different history to everybody else
still has one signing key and one current head.

Neither replaces the other. Folding works against a saved copy of the history
with the exchange switched off. The consistency proof needs a live feed. An
unavailable feed has not, by that fact alone, rewritten anything. A proof that
cannot be fetched is therefore reported as **not checked**, not as a failure. A
proof that *fails to verify* is a failure, and it is the loudest one in the
report.

Old chain-hash anchors are checked exactly as they were: fold the messages to
the anchored `lastId` and compare. That code was not touched.

## The contracts

`ExchangeAnchor.sol` is 135 lines and `ExchangeRootAnchor.sol` is 195,
including comments. `ExchangeRootAnchor` has four
rules, all of them there to stop it being used to undo what it recorded:

- **The session is fixed by the first anchor.** A new feed history means the
  sizes restart at 0 and the root restarts from the empty tree, so an anchor for
  a different history is not a later entry in this record. It is a different
  record. Wiping the feed and starting again is the exact event this contract
  exists to expose, so it is refused here. The operator has to deploy a third
  contract and publish that address, in public and permanently, while an auditor
  pointed at this one still sees the anchor for the history that was thrown
  away.
- **`treeSize` only moves forward.** A rewound feed cannot overwrite the state
  slot with a smaller tree.
- **`lastId` only moves forward**, for the same reason applied to execution.
- **`lastId <= treeSize`.** A cursor past the tree would be an execution claim
  about messages this anchor does not commit to.

State *and* an event. The event is the full history, readable by anyone from
the logs, and it is what the auditor actually checks. The state buys a single
`eth_call` for the newest anchor, which is what makes "last anchored 3 minutes
ago" one request instead of a log scan.

Rebuild and redeploy:

```sh
python3 compile.py                       # solc 0.8.26 via py-solc-x
python3 deploy.py --rpc https://sepolia.base.org --key ../.anchor/anchor.key
```

`compile.py` takes a source file and defaults to `ExchangeRootAnchor.sol`;
`deploy.py` defaults to that artefact and writes `root-deployment.json`.
Deploying the chain-hash contract again takes both `--artefact` and `--out`, on
purpose: `deployment.json` is a record of what was deployed and nothing should
overwrite it by accident.

Those two are Python because they need `solc`, which the Go toolchain does not
carry. They run once; the sender is the thing that runs forever.

## Checking an anchor yourself

```sh
cd ../services
cargo run -- --audit-url https://exchange.th3nolo.com \
  --root-anchor-rpc https://sepolia.base.org \
  --root-anchor-contract 0x4162B3218b97663dEBC1f59060910221bb95672d \
  --root-anchor-from-block 45583892
```

A passing report has this shape. The counts are whatever the contract holds
when you run it; the table at the top of this page has today's.

```
  anchors  0x2a4a287ec1f01b5bcb5568d2ed0765faf860a62b on chain 84532
           15 of 15 read, back to block 45495043
           newest: message 22283 of session 349d462ced25bb2b, written 2 minutes ago

  PASS  every anchor this contract holds was read    15 checked
  PASS  the newest anchor and the contract agree     1 checked
  PASS  every on-chain anchor names this history     15 checked
  PASS  every on-chain anchor matches the feed       15 checked
  PASS  every on-chain anchor matches this execution 15 checked
```

Or read the newest anchor with nothing but `curl`. The selector is the same on
both contracts; what comes back is not:

```sh
curl -s https://sepolia.base.org -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"eth_call","params":[
    {"to":"0x4162B3218b97663dEBC1f59060910221bb95672d","data":"0x52bfe789"},"latest"]}'
```

The answer is seven 32-byte words: `treeSize`, `lastId`, `session`
(left-aligned `bytes8`), `rootHash`, `stateRoot`, `anchoredAt`, `count`. The
chain-hash contract answers the same call with six: `lastId`, `session`,
`chainHash`, `stateRoot`, `anchoredAt`, `count`.

### Auditing a differently compiled contract

The auditor reads each contract with two values: the event topic it filters the
log on, and the `latest()` selector. All four are configurable, and all four
have the same order as everything else here. That order is flag, then
environment variable, then the built-in default:

| Flag | Environment | Default |
|---|---|---|
| `--anchored-topic` | `ANCHORED_TOPIC` | `0x846b388d9a84109263340756e41099d4945f475c34c4f401faf0850b7c6d8385` |
| `--latest-selector` | `LATEST_SELECTOR` | `0x52bfe789` |
| `--anchored-root-topic` | `ROOT_ANCHORED_TOPIC` | `0xf17e064140470b4f4b89eb3a9324a477206c096df6cbc3dfed400e9b4a2c191f` |
| `--root-latest-selector` | `ROOT_LATEST_SELECTOR` | `0x52bfe789` |

**The defaults are correct for the deployed contracts.** Nobody auditing this
exchange needs to set any of them. They exist for a contract compiled from a
different event or a different function name: your own build of either `.sol`
file, changed.

The shape is checked before any request is made: `0x` and exactly 64 or 8
**lowercase** hex characters. Uppercase is refused rather than lowered, because
`eth_getLogs` matches a topic byte for byte and a value that looks right and
matches nothing is the exact failure this checking exists for. A well-formed
value can still be the wrong value. Overriding a value therefore prints a
warning on stderr. An unmatched topic returns an empty log list, which looks
like "no anchors" instead of an error.

`anchor/anchor_test.go` derives all four defaults with a real Keccak from the
signatures the two contracts were compiled from and checks them against the
constants in `services/src/anchor.rs`, so the two sides cannot drift. It also
runs this program's RFC 9162 hashing against two references. One is the worked
example in RFC 9162 section 2.1.5. The other is the set of digests that
`services/src/merkle.rs` pins for the same seven entries. These checks prevent
the Go and Rust transcriptions of the consistency check from drifting.

## What it costs, measured

Measured on Base Sepolia. The steady-state figure is what matters; the first
write is dearer because it fills cold storage slots.

| | gas | L2 | L1 data | total |
|---|---|---|---|---|
| deploy `ExchangeRootAnchor` | 355,384 | 0.00000213 ETH | 0.0000000060 ETH | **0.00000214 ETH** |
| first anchor (cold storage) | 116,006 | 0.000000696 ETH | 0.0000000077 ETH | **0.000000704 ETH** |
| every anchor after | 44,724 | 0.000000268 ETH | 0.0000000058 ETH | **0.000000274 ETH** |

A root anchor costs about 6% more than a chain anchor did (44,724 gas against
41,799). The extra is one storage slot, and one more 32-byte word of calldata,
164 bytes against 132. The tuple is five values where it was four, and the four
8-byte numbers still share one slot but `session` no longer fits beside them.
The L1 data fee is **2.1%** of the cost, not the dominant term, because Base
compresses the calldata.

On the funded 1.054 ETH that is

- **3,845,000 anchors**
- **36.6 years** at a 5-minute interval (288 a day)
- 219 years at 30 minutes

so the interval is not a budget question at any setting worth considering. The
5-minute figure was chosen because it bounds a rewind to five minutes.

The JSON-RPC side is unchanged: about nine calls a tick, 2,600 a day, in short
bursts. What changed is what the sender asks the *exchange* for. It is now four
requests a tick, always, whatever the history is: two claims pages, one tree
head, one consistency proof. The old sender read a page of
`/messages.ndjson` for every 1,000 messages published since the last anchor,
and re-read the whole history whenever its resume file was missing. The file
was absent after every container restart. At the current session size, the
reread was about 100 pages and 14 MB.

## Switching the live sender: done, with one item left

The switch happened. This list is kept because the same steps run again at
every reset, and two of them are easy to forget.

1. **Ship the new sender.** `Dockerfile` builds `anchor/` into
   `/usr/local/bin/anchor-sender`. It must go out together with step 2, or the
   sender exits at startup saying the contract is the wrong shape, which is
   the right failure, but it is still no anchoring. **Done.**
2. **`Dockerfile` line 77.** Copy `anchor/root-deployment.json` to
   `/etc/exchange/anchor-deployment.json` instead of `anchor/deployment.json`.
   That one line moves both the sender's default contract and the address the
   exchange serves on `/anchor-config`. **Done.**
3. **`docker/entrypoint.sh` line 210.** Drop the `ANCHOR_CACHE` line. The flag no
   longer exists; an unknown environment variable is ignored, so this is
   tidying rather than a break. The old `$DATA/anchor-cache.json` can be
   deleted. **Not done. It is the only item on this list still open.**
4. **Confirm the first tick.** `docker logs` should show
   `anchoring session <session> over N messages` and a block number within a
   few seconds. A tick that logs `FAILED` names which check refused. **Done.**
5. **Point the browser at the new ABI.** The page reads both shapes now:
   `ExchangeAnchor` answers `latest()` with six words and `ExchangeRootAnchor`
   with seven, and the page parses the `AnchoredRoot` event. **Done**, in
   `services/static/app.js`.
6. **Wire the root check into the audit.** `--root-anchor-contract`,
   `--root-anchor-rpc`, `--root-anchor-from-block` and `--root-latest-selector`
   all exist, and `services/tests/anchor_flags.rs` covers them. **Done.**
7. **Leave a closed contract alone.** It is closed, not retired. Its anchors
   are still read by `--audit-url --anchor-contract 0x2A4A…a62b`, and both
   closed addresses stay in this README and in the git history. An address that
   quietly stops being mentioned is the thing an auditor should be suspicious
   of.

## What the anchor does not prove

It says nothing about whether the exchange was honest at the moment an anchor
was written. An operator who is dishonest from the start anchors their dishonest
history quite happily, and every check still passes. What it removes is the
ability to change the answer **afterwards**.

It also does not prove the anchor was written by anyone other than the operator,
not from these contracts, whose writer is the operator's own key. That is what
makes a third party running their own sender worth more than this one, and why
the whole program is 1,300 lines of Go that anybody can point at any exchange.

And it stops an operator rewriting what **a given contract** recorded. It does
not stop them publishing a *different contract address*. Nothing on chain says
which contract belongs to this exchange. An operator could deploy a fresh one,
start anchoring to it, and change the address in their documentation. A reader
who saw only the new address would find a short and internally consistent
history.

Two published addresses do not make that worse, because both are checked and
neither replaces the other. What would make it worse is one address quietly
becoming another. The defence is that the canonical addresses have to be
published somewhere with their **own** independent history, so that changing one
is itself a visible event:

- this README and the two deployment records, under version control, where each
  address arrived in a commit with a date on it;
- the git history of this repository, which is public;
- the website the exchange is served from.

An address that appears in all three, unchanged, across a long commit history is
what makes the record hard to move. An address that changed last week, in one
place, is the thing to look at. That is a weaker guarantee than everything above
it on this page, and it is weaker in a way no contract can fix. It is a
name-binding problem, not a state problem. Stating it is the honest option;
implying the contract solves it is not.

The canonical addresses for this exchange are the four in the table at the top
of this page: `0x2A4A287E…a62b`, `0xCE85983c…995e`, `0x18486b8A…eE4b` and the
live `0x4162B321…672d`. Any other address is not this record. A reset adds an
address to that table and never removes one, because the anchors a closed
contract holds stay true about the history it recorded.
