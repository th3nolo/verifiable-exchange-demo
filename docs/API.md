# API and CLI reference

This file holds what an operator or an integrator needs. It covers the command
line, the HTTP endpoints, and the statement a submission is signed under.

[`ROADMAP.md`](../services/ROADMAP.md) says what each layer of the design
gives you, and what it does not give you. This file says what a service writes
to disk only where an endpoint does not make sense without it.

## CLI reference

One invocation starts one service, or runs one command against a running
service. `cargo run -- --help` lists everything, including the few flags this
file does not.

### Starting the sequencer

- `--start-feed`: Starts the sequencer. The process runs continuously. It
  publishes new messages and answers API requests on `http://127.0.0.1:3000`
  by default. `--bind` and `--feed-port` change the address.

- `--num-accounts <NUMBER>`: How many simulated accounts place orders. Use it
  with `--start-feed`. The default is 10.

- `--rate <NUMBER>`: The **mean** number of messages the sequencer publishes
  per second. Use it with `--start-feed`. The default is 2.

  It is a mean because the generator switches between three activity states.
  Above 24 a second the states are `24`, this number, and `2 x this - 24`, each
  holding a third of the time, so the mean is this number and the quietest state
  is always 24. At 24 a second and below there is one state and the rate is
  fixed. The measured switching configuration uses 69, so it runs at 24, 69
  and 114.
  See section 4.6 of [`GENERATOR-RFC.md`](GENERATOR-RFC.md).

- `--feed-port <PORT>`: The port the sequencer listens on, default 3000. It
  has the same shape as `--matcher-port`, `--inbox-port` and
  `--validator-port`. A second sequencer runs beside the first on another
  port. So a fast sequencer for testing does not have to displace a slow one
  that holds real history. Consumers follow it with `--feed-url`.

- `--feed-db <FILE>`: The SQLite file the sequencer writes every message to
  before it publishes the message, default `feed.db`. On start the sequencer
  reloads its history. It keeps the same message numbers and the same session,
  so consumers cannot tell that it restarted. A file it has never published
  into holds no history to continue, so it gets a new session instead. Such a
  file is a new one, or one whose messages and signed checkpoint have been
  removed.

- `--no-feed-db`: Runs the sequencer with its history in memory only. A
  restart then loses every published message. The sequencer answers
  `410 Gone` for a request for messages that have left memory. See
  [**Get the messages**](#get-the-messages).

- `--inbox-url <URL>`: The separate service this sequencer drains, used with
  `--start-feed`. The sequencer puts pending entries in the log ahead of its
  own generated traffic, exactly once. Omit the flag to run the sequencer
  without a separate service.

- `--operator-key <HEX>`: The operator public key this sequencer publishes
  operator messages for, 64 lowercase hex characters. Use it with
  `--start-feed`. `services --operator-public-key` prints the value for a key
  file. Without this flag the sequencer serves no `/operator` route at all, and
  it generates traffic from its first tick. With it, user submissions, inbox
  entries and generated traffic wait for the engine rule and every compiled
  market listing. See
  [**Publish an operator message**](#publish-an-operator-message).

- `--ui-origin <ORIGIN,...>`: The web origins whose browsers may submit to this
  sequencer, comma separated. It defaults to
  `http://127.0.0.1:3001,http://localhost:3001`. Those are both spellings of
  the exchange's own address, and a browser treats them as two different
  origins. See [**Trading from the web UI**](#trading-from-the-web-ui).

- `--trusted-proxy <ADDR[/PREFIX],...>`: The addresses whose `X-Forwarded-For`
  header a service may believe, comma separated. Use it with `--start-feed`
  and `--start-inbox`, the two services that rate limit submissions per
  caller. It is empty by default. Empty means the service never reads the
  header, so a deployment that forgets the flag is never accidentally
  permissive. See [**Trading from the web UI**](#trading-from-the-web-ui).

- `--bind <ADDR>`: The address the service this invocation starts listens on,
  default `127.0.0.1`. It applies to whichever of `--start-feed`,
  `--start-matcher`, `--start-inbox` or `--start-validator` you gave, because
  one invocation starts one service. See
  [**Which address a service listens on**](#which-address-a-service-listens-on).

### Starting the exchange

- `--start-matcher`: Starts the exchange. It reads the sequencer's messages.
  It matches crossing orders by price, then by time. It serves the trading UI
  and the market state on `http://127.0.0.1:3001` by default. It commits a
  signed claim for every batch it applies.

- `--matcher-port <PORT>`: The port the exchange listens on, default 3001.

- `--poll-ms <MS>`: How often the exchange asks the sequencer for new messages,
  default 200. A validator started with `--start-validator` reads the same
  flag.

- `--feed-url <URL>`: The base URL of the sequencer, `http://127.0.0.1:3000`
  when you do not give it. Everything that reads the sequencer uses this
  address: the exchange, the validator, the bot, `--verify`, `--audit`,
  `--submit`, `--cancel` and `--orders`. `--audit-url` is the exception. Left
  unset, it asks the exchange it audits where the sequencer is. Set, it wins.
  See [**Checking the Exchange**](#checking-the-exchange).

- `--public-feed-url <URL>`: The sequencer address the UI tells a browser to
  submit to. It defaults to `--feed-url`. That default is right when the
  browser reaches the sequencer at the same address the exchange does. Behind
  a reverse proxy it does not. See
  [**Trading from the web UI**](#trading-from-the-web-ui).

- `--public-inbox-url <URL>`: The separate service address the UI tells a browser
  to submit to when the visitor picks that route. It defaults to
  `--inbox-url`. With neither flag set, `GET /config` answers
  `"inbox_url": null` and the page offers no separate service route. That is right
  when no separate service runs. A route to a port that holds nothing tells a
  visitor that the separate service is down. See
  [**The separate service from the UI**](#the-separate-service-from-the-ui).

- `--state-db <FILE>`: The SQLite file the exchange keeps its books, trades,
  read position and claims in, default `state.db`. Every poll batch commits in
  one transaction. So the exchange resumes exactly where it stopped after a
  crash, a power loss, or a clean stop.

- `--no-state-db`: Runs the exchange with no state file. The books are empty
  on start, and the exchange runs the whole log again after every restart.
  `GET /claims` and `GET /trade-log` then answer 503, because no claim history
  is written to disk.

- `--reset-state`: Abandons the run stored in the state database and starts a
  new one. The old run's trades and books stay in the file.

- `--validators <URL,...>`: The validator `/attest` URLs the exchange reads,
  comma separated. `quorum_verified_at` on `/market` is the highest position
  that two thirds of those validators agree on.

- `--stdio-engine`: Runs the exchange behind the market-harness stdio protocol.
  It reads that harness's commands on standard input and writes that harness's
  events on standard output. There is no server, no sequencer and no database.
  So a harness this repository did not write can score this exchange.

- `--stdio-messages-per-second <NUMBER>`: How many messages a second that
  protocol counts, default 6.0. It turns a command number into a millisecond.
  The harness has no clock, and the collar's reference price is an average over
  the last 30 seconds.

### Starting the separate service

- `--start-inbox`: Starts the separate service. It is a submission service the
  sequencer does not control. It listens on `http://127.0.0.1:3002` by default
  and records submissions in `inbox.db`. See
  [**Submit through the separate service**](#submit-through-the-separate-service).

- `--inbox-port <PORT>`: The port the separate service listens on, default 3002.

- `--inbox-db <FILE>`: The SQLite file the separate service records submissions
  in, default `inbox.db`.

- `--inbox-deadline-ms <MS>`: How long the sequencer may leave an entry
  pending before `GET /status` reports it late, default 5000. A late entry is
  the censorship alarm.

- `--feed-key <HEX>`: The sequencer public key whose marks the separate service
  accepts. Omit the flag, and the separate service pins the key that
  `--feed-url`'s `GET /head` serves on first contact. See
  [**Mark an Entry Sequenced**](#mark-an-entry-sequenced).

- `--ui-origin <ORIGIN,...>`: The web origins whose browsers may submit to this
  separate service, comma separated. It has the same default and the same rules as
  the sequencer's flag. The separate service needs its own flag because a browser
  opens the separate service from the trading UI. The person V3 exists for is
  remote. An separate service that only the operator's own loopback can open is one
  that only the operator can open. Only `POST /submit` is preflightable.
  `POST /mark` is not, because it is the sequencer's call, and it is the call
  that can make censorship evidence disappear. See
  [**The separate service from the UI**](#the-separate-service-from-the-ui).

### Starting the validators

- `--start-validator`: Starts one validator. It follows the sequencer
  independently. It computes the chain hash again from the messages
  themselves. It checks the sequencer's signed head against that result. It
  serves a signed attestation of the position it vouches for on `GET /attest`.

- `--validator-port <PORT>`: The port the validator serves `/attest` on,
  default 3010.

- `--validator-db <FILE>`: The SQLite file the validator keeps its followed
  position in, default `validator.db`. Its signing key sits beside that file
  (`.key`). So three validators on one machine need three of each file. Use
  `--validator-db validator1.db`, and so on.

### Starting the bot

- `--start-bot` runs the trading bot against a live sequencer.
  `--backtest-bot` runs it against a generated history, with no servers.
  [`BOT.md`](BOT.md) has its flags, the edge it measures, and the weakness it
  exposed in the exchange.

- `--bot-poll-ms <MS>`: How often the bot asks the sequencer for new messages,
  default 50. Both `--start-bot` and `--backtest-bot` read it.

### Sending commands to the sequencer

Open a second terminal to use the running sequencer. These commands use
`--feed-url`. So they reach a sequencer on another port or another host, not
only the local default.

- `--submit <ACCOUNT_ID> <SYMBOL> <SIDE> <PRICE> <QUANTITY>`: Submits a new limit order to the sequencer, signed with the account key.
    - `<ACCOUNT_ID>`: The account ID placing the order.
    - `<SYMBOL>`: The trading pair. Can be `MERKLE-USDC`, `ETH-USDC`, or `BTC-USDC`.
    - `<SIDE>`: `Buy` (bid) or `Sell` (ask).
    - `<PRICE>`: The limit price (e.g., `100.25`).
    - `<QUANTITY>`: The order quantity (e.g., `5.0`).

- `--cancel <ACCOUNT_ID> <ORDER_ID>`: Submits a cancel for a previously placed order, signed the same way.
    - `<ACCOUNT_ID>`: The account ID cancelling the order.
    - `<ORDER_ID>`: The `id` of the order to cancel.

- `--account-key <FILE>`: The Ed25519 key `--submit` and `--cancel` sign with,
  created on first use (default `account.key`). An account belongs to the key
  that first submitted for it. So you use the same file for the same account
  id every time. See [**Signing a submission**](#signing-a-submission).

- `--sign-only`: Prints the signed request body for `--submit` or `--cancel`
  and sends nothing. You can pipe it into curl or into any other client.

- `--via-inbox`: Sends `--submit` through the separate service instead of the
  sequencer's own `/order` endpoint. This shows that the separate service works
  from end to end. The separate service it reaches is `127.0.0.1` on
  `--inbox-port`, not `--feed-url`.

- `--orders [NUMBER]`: Fetches and displays the most recent messages.
    - `[NUMBER]` (optional): The number of recent messages to fetch. If omitted, it defaults to 10.

**Examples.**

Submit a bid for 5 ETH-USDC at 100.25 from account 1000:
```bash
cargo run -- --submit 1000 ETH-USDC Buy 100.25 5
```

Cancel order 42 from account 1000 (only account 1000's own key can):
```bash
cargo run -- --cancel 1000 42
```

Print the signed body instead of sending it:
```bash
cargo run -q -- --submit 1000 ETH-USDC Buy 100.25 5 --sign-only
```

Get the last 5 messages:
```bash
cargo run -- --orders 5
```

Get the last 10 messages (default):
```bash
cargo run -- --orders
```

Submit to a sequencer that is not the local default:
```bash
cargo run -- --feed-url http://192.0.2.7:3100 --submit 1000 ETH-USDC Buy 100.25 5
```

### Operator commands

Only the operator opens a market, closes one, or names the rule set. The
operator holds one Ed25519 key. The exchange trusts that one key and no other
key. Four commands use it:

- `--engine-rule <VERSION>`: Publishes the rule set that the messages after it
  run under. It takes one whole number. The sequencer does not judge which rule
  sets exist.
- `--list-symbol <SYMBOL> <PRICE_STEP> <QUANTITY_STEP>`: Opens a market. It
  takes three values, in that order.
- `--delist-symbol <SYMBOL>`: Closes a market. Every resting order in that
  market is cancelled where the log runs again.
- `--operator-public-key`: Prints the public key of the key file. It publishes
  nothing and it creates no key. That value is what a sequencer takes as
  `--operator-key`.

The first three sign a statement and publish it to `POST /operator` on the
sequencer at `--feed-url`. `--sign-only` prints the signed body and sends
nothing, as it does for `--submit`. See
[**Publish an operator message**](#publish-an-operator-message) for the
statements, the bodies and every refusal.

Three flags control them:

- `--operator-key-file <FILE>`: The key file the first three commands sign
  with, default `operator.key`. The program reads this file and never creates
  it. A mistyped path is an error and not a new key, because this is the one
  key the exchange trusts.
- `--operator-key <HEX>`: Tells a sequencer which public key to accept. Use it
  with `--start-feed`. Without it the sequencer serves no `/operator` route.
  See [**Starting the sequencer**](#starting-the-sequencer).
- `--matcher-url <URL>`: The exchange the three publishing commands ask before
  they publish. Left unset, the question goes to `127.0.0.1` on
  `--matcher-port`, which is `http://127.0.0.1:3001` while that port holds its
  default. Each command reads `GET /market` there. `--list-symbol` and
  `--delist-symbol` warn when the symbol already trades, or does not trade yet.
  `--engine-rule` warns when the version is past `newest_rule_set`. Every
  answer is a warning. The message is published either way, and an exchange the
  command cannot reach refuses nothing.

**A sequencer with an operator key waits.** Started with `--operator-key`, it
reserves the opening for one engine rule and one listing per compiled market.
User submissions, inbox entries and generated traffic wait until every opening
message exists. A deployment nobody has opened serves an empty log and
generates no traffic. It is waiting for the operator, not dead.

**`docker/open-the-log.sh` is what opens it.** Both `./demo.sh` and
`docker/entrypoint.sh` run that file on every start, so a local run and a
deployment open their logs the same way. The script asks `GET /head` first. A
`last_id` of 0 means the log holds nothing, so the script opens it. Any other
value means the log was opened already, so the script publishes nothing and
exits 0. A `last_id` it cannot read is an error and exit 1.

The script types no number of its own. It reads the rule set from the
exchange's `GET /market`, and the markets and their price steps from the
sequencer's `GET /symbols`. It publishes one `EngineRule` message and one
`ListSymbol` message for each market that `GET /symbols` serves: four messages
today, because that endpoint serves three markets. It signs every message first
with `--sign-only`, and then publishes them back to back. A signing failure
therefore publishes none of the opening. If a POST fails after publishing only
part of it, the sequencer keeps every non-operator writer held until the
operator finishes the remaining messages.

**Where the key comes from.** `./demo.sh` makes an operator key in
`run/operator.key` on each start. It deletes and remakes `run/` first, so that
key lasts one run. A deployment mounts the key as a secret at
`/run/secrets/operator_key`, which is the default `OPERATOR_KEY_FILE` in
`docker/entrypoint.sh`. With no readable key at that path the container makes
one on the data volume and says so on stderr. Anybody who can read that volume
can then open and close markets.

### Checking the exchange

- `--verify [STATE_DB]` (default `state.db`): Runs the checker. The checker
  compares the latest run's trades against the log. It checks three other
  records. The signed head must match the sequencer's history. The signed tree
  head at `GET /sth` must match the root produced by those messages. Every
  stored node must match the node produced by the same messages. The checker is
  a second implementation. It shares no matching code with the exchange, so it
  can disagree with the exchange.

- `--audit [STATE_DB]` (default `state.db`): Runs the messages of one run
  again from the sequencer's history, and checks every claim. It checks every
  boundary root, every signature, the claimed trade counts, and the full trades
  table. First it checks that the history it is about to run is the right one.
  It checks the sequencer's signed head against the sequencer's own messages.
  It checks the signature against the key the run pinned. It checks the run's
  stored chain hash against the messages themselves. Claims that stop before
  the run's read position fail the audit. They do not count as "nothing to
  check". A state database keeps every run it ever had. The audit takes the
  newest run and lists the others. This flag and `--verify` read the sequencer
  at `--feed-url`. Both already need the operator's own file, so there is no
  exchange to ask.

- `--audit-run <RUN_ID>`: Audits that run of the state database instead of the
  newest one. Without this flag you could only ever check the newest run.

- `--audit-url [MATCHER_URL]` (default `http://127.0.0.1:3001`): Runs the same
  audit against a **live exchange over HTTP**, with no database file. It
  fetches the signed claims from `GET /claims`. It fetches the trade record
  from `GET /trade-log`. It checks each claim's signature against the key the
  exchange publishes. Then it runs the sequencer's signed history against the
  claims, one page at a time. It needs no help from the operator beyond the
  endpoints the operator already serves.

  This flag takes a URL and nothing else. The history it runs again is on the
  sequencer, which is a separate service at a separate address. So the audit
  reads that address from the exchange's own
  [`GET /config`](#get-the-uis-configuration). That is the public address the
  exchange gives a browser, not the loopback address its services use between
  themselves. An exchange may answer no `/config`, or its `/config` may name no
  sequencer. The audit then stops, says so, and names `--feed-url`. It never
  assumes an address.

  `--feed-url <URL>` overrides that address and skips the question. So it also
  works against an exchange that serves no `/config`. Use it when you reach the
  sequencer somewhere other than the address the exchange publishes: through a
  tunnel, a mirror, or another route. The audit checks nothing against what the
  exchange says, because the exchange cannot know about any of those routes.

- `--matcher-key <HEX>`: Pins the key that `--audit-url` requires on the
  claims. Without it the audit takes the key on first contact. That shows the
  claims agree with each other, but not who made them.

- `--anchor-contract <0xADDRESS>` and `--anchor-rpc <URL>`: Check the exchange
  against an [`ExchangeAnchor`](../anchor/README.md) contract. Both flags are
  required together and both apply to `--audit` as well as `--audit-url`.

  Every other check above shows that the exchange agrees with **itself**. An
  operator who deleted their databases and published a different history passes
  all of them. This check is the one they do not pass. The contract holds
  `(lastId, session, chainHash, stateRoot)` tuples. The anchor sender writes
  them at intervals, and it runs outside the exchange. The audit hashes today's
  history again up to each of those positions. It either reproduces the
  anchored values, or it fails. A failure names both values, the message, the
  block and the block's timestamp.

  The audit checks every anchor the contract ever wrote, not only the newest,
  and an incomplete read is itself a failure. A rewind can leave the newest
  anchor reproducible while an older one is not.
  [`anchor/README.md`](../anchor/README.md) works that through.

  The address comes from you, never from the exchange. An operator who chooses
  which contract their own audit runs against can choose an empty one. Anyone
  may run their own anchor sender against their own contract and publish the
  address. A third party's anchor is the stronger evidence.

  No contract can settle which address to use. An anchor contract stops an
  operator rewriting what **it** recorded. It does not stop the operator
  deploying a second contract and publishing that address instead. Nothing on
  chain says which contract belongs to this exchange. Take the address from a
  place with its own independent history. Use `anchor/deployment.json` under
  version control, this repository's public git history, or the site itself.
  Look closely at an address that changed recently in one of those places.

  **`0x2A4A287EC1F01b5bCb5568D2Ed0765Faf860a62b` is closed.** It takes no more
  writes. It holds the chain-hash anchors of the deployment's first log, and
  those anchors still verify, so it is the example of auditing a closed
  contract:

  ```sh
  cargo run -- --audit-url https://exchange.th3nolo.com \
    --anchor-rpc https://sepolia.base.org \
    --anchor-contract 0x2A4A287EC1F01b5bCb5568D2Ed0765Faf860a62b \
    --anchor-from-block 45495043
  ```

  This is the run that command made against the first log, when the contract
  held 15 anchors:

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

  `349d462ced25bb2b` is that first log's session. The deployment is on its
  third log, session `ea117dd79090025a`. Measured on 17 August 2026 with an
  `eth_call` to `latest()`, the closed contract holds 152 anchors, and its
  newest one stands at message 109,185 of `349d462ced25bb2b`. The audit above
  reads all 152 and stops there, because the contract records nothing after
  that message.

  **The live contract is the root anchor.** This is the command an auditor runs
  against the deployment today:

  ```sh
  cargo run -- --audit-url https://exchange.th3nolo.com \
    --root-anchor-rpc https://sepolia.base.org \
    --root-anchor-contract 0x4162B3218b97663dEBC1f59060910221bb95672d \
    --root-anchor-from-block 45583892
  ```

  On 17 August 2026 that contract held 46 anchors, the newest at message
  276,226 of session `ea117dd79090025a`. The count grows, because the anchor
  sender writes one about every five minutes.

  Leave both flags unset, and the audit behaves as it does without an anchor.
  No extra check appears and it makes no request. Set them to a contract it
  cannot read, and the audit **fails**. An anchor it cannot read is an
  unchecked claim, not a satisfied one. A pass there would state the one
  property the rest of the audit cannot establish.

- `--root-anchor-contract <0xADDRESS>` and `--root-anchor-rpc <URL>`: Check the
  Merkle root against an
  [`ExchangeRootAnchor`](../anchor/README.md) contract. Both flags are required
  together, and they apply to `--verify` as well as to `--audit` and
  `--audit-url`.

  The live contract is `0x4162B3218b97663dEBC1f59060910221bb95672d` on Base
  Sepolia, chain 84532, from deployment block 45583892. Two public records name
  it: [`anchor/root-deployment.json`](../anchor/root-deployment.json) under
  version control and `GET /anchor-config` on the exchange itself. A private
  deployment may also set `ANCHOR_CONTRACT` at runtime. Read the address from a
  place with its own history, and not only from the exchange.

  The other contract holds a chain hash. Proving one trade sits inside one of
  those needs every message in the window: 1.7 MB, measured. This one holds
  `(treeSize, lastId, session, rootHash, stateRoot)`, and the root it holds is
  the root the sequencer signs in its tree head and the root every inclusion
  proof lands on. So proving one trade sits inside it is about 17 node hashes.

  Both tools fold the messages they were served into the RFC 9162 tree as they
  read them, and take the root at each size an anchor names. That costs one pass
  and no second read of the history.

  ```
    PASS  the signed tree head is over these messages  1 checked
    PASS  every root anchor on the contract was read   12 checked
    PASS  the newest root anchor and the contract agree 1 checked
    PASS  every anchored root is over these messages   12 checked
  ```

  A root that does not match is a **failure** and exit 1, not "cannot
  interpret". The tool read the messages and it read the root, and they
  disagree; that is a definite answer.

  Leave both flags unset, and the tools say so and go on:

  ```
    the anchored roots were not checked: no root anchor contract was named.
    Pass --root-anchor-contract and --root-anchor-rpc to check them
  ```

  A deployment with no anchor key is a valid deployment, so this is not a
  failure. It is not a pass either, and it is printed rather than left out, so
  nobody reads a page of `PASS` lines and takes the anchored roots to have been
  checked. A contract that holds no anchor yet says the same thing and names the
  contract.

  `--root-anchor-from-block`, `--anchored-root-topic` and
  `--root-latest-selector` are the same three flags as below, for this
  contract. Their environment variables are `ROOT_ANCHORED_TOPIC` and
  `ROOT_LATEST_SELECTOR`. `--root-anchor-from-block` stops the scan at the root
  contract's own deployment block, 45583892, which
  [`anchor/root-deployment.json`](../anchor/root-deployment.json) publishes
  with the address, the chain id and the writer.

  **Two spellings exist for the topic flag, and one of them works.**
  `--anchored-root-topic` is the flag, because that is what the field name
  produces in `services/src/main.rs`. `services/src/anchor.rs` prints
  `--root-anchored-topic` in its error text, and no such flag exists. Pass
  `--anchored-root-topic`, or set `ROOT_ANCHORED_TOPIC`.

- `--anchor-from-block <BLOCK>`: Where to stop scanning the contract's event
  log. Public RPC endpoints cap one `eth_getLogs` at a range of blocks. Base's
  endpoint answers `eth_getLogs is limited to a 10,000 range`. So the audit
  reads the log backwards in chunks. Without this flag the scan stops when it
  has found as many anchors as the contract says exist. That is exact, but it
  reads more chunks than it has to. With the flag, the scan stops at the
  deployment block. [`anchor/deployment.json`](../anchor/deployment.json)
  publishes that block, the address, the chain id and the writer for the
  chain-hash contract: block 45495043, address
  `0x2A4A287EC1F01b5bCb5568D2Ed0765Faf860a62b`. The root contract has its own
  record in [`anchor/root-deployment.json`](../anchor/root-deployment.json),
  block 45583892, and `--root-anchor-from-block` takes that one. One file per
  contract, because the two contracts were deployed in different blocks.

- `--anchored-topic <0xTOPIC>` and `--latest-selector <0xSELECTOR>`: Which
  event the audit filters the contract's log on, and which function it reads
  the newest anchor with. Both flags also read an environment variable,
  `ANCHORED_TOPIC` and `LATEST_SELECTOR`. The order is the flag, then the
  environment variable, then the built-in default.

  **The defaults are correct for the deployed contract.** An audit that sets
  neither flag is a correct audit, and `--audit-url <URL>` on its own needs
  nothing here. Set them only against a contract compiled from a different
  event or function signature. One example is your own `ExchangeAnchor` with a
  changed `Anchored` event.

  | | Default | Shape |
  |---|---|---|
  | `--anchored-topic` / `ANCHORED_TOPIC` | `0x846b388d9a84109263340756e41099d4945f475c34c4f401faf0850b7c6d8385` | `0x` and 64 lowercase hex characters |
  | `--latest-selector` / `LATEST_SELECTOR` | `0x52bfe789` | `0x` and 8 lowercase hex characters |

  The first default is the `keccak256` of
  `Anchored(uint64,bytes8,bytes32,bytes32,uint64,uint64)`. The second is the
  first four bytes of the `keccak256` of `latest()`. `anchor/anchor_test.go`
  derives both with a real Keccak. It checks them against the defaults in
  `services/src/anchor.rs`.

  A value of the wrong shape ends the run before any request. The error names
  the flag, what you passed and what the flag expects. An uppercase value is
  refused, not lowered, because an RPC endpoint matches these byte for byte:

  ```
  $ cargo run -- --audit-url https://exchange.th3nolo.com \
      --anchor-rpc https://sepolia.base.org \
      --anchor-contract 0x2A4A287EC1F01b5bCb5568D2Ed0765Faf860a62b \
      --anchored-topic 0x846B388D9A84109263340756E41099D4945F475C34C4F401FAF0850B7C6D8385
  cannot use that anchor: --anchored-topic was given '0x846B388D…D8385', and it
  contains uppercase hex characters, which are not the same bytes to an RPC
  endpoint as the lowercase ones: the Anchored event topic has to be 0x followed
  by exactly 64 lowercase hex characters. This value is matched byte for byte by
  the RPC endpoint, so one that is nearly right finds nothing at all rather than
  failing.
  ```

  A value of the right shape that is the wrong value passes that check, and it
  is the dangerous one. A topic that matches nothing returns an empty log list.
  An empty list looks like a contract that holds no anchors, not like an error.
  So the audit prints any override on stderr before it runs. An audit that
  overrides nothing prints nothing:

  ```
  warning: the Anchored topic was overridden to 0x1111…1111, and this audit will
  only find events matching it. An event topic that does not match the deployed
  contract produces an empty log list, which reads as 'no anchors' rather than
  as an error. The built-in default 0x846b388d…c6d8385 is the topic the deployed
  contract emits.
  ```

## Signing a submission

Every submission carries the account's Ed25519 public key and a signature over
what it asks. This holds for `POST /order`, `POST /cancel`, and the separate
service's `POST /submit`. A service pins an account's key on the account's first
submission. Only that key may submit for the account afterwards. Without this
rule the `account` field is only a number the caller types, and anyone can
cancel another account's resting order.

**The statement the account signs** is plain ASCII, newline separated, with a
versioned prefix. It has the same shape as the sequencer's head statement and
the separate service's mark statement. For an order:

```
exchange-account-order-v3
<session>
<account>
<symbol>
<Buy|Sell>
<price in whole cents>
<quantity in whole tenths>
<Limit|Market>
<GoodTillCancel|ImmediateOrCancel|FillOrKill>
<true|false>
<nonce>
```

and for a cancel:

```
exchange-account-cancel-v3
<session>
<account>
<target_id>
<nonce>
```

There is no trailing newline. Price and quantity appear as whole price steps
and whole quantity steps (100.25 is `10025`, 5.0 is `50`), not as decimals. So
a signer in any language produces the same bytes. It does not depend on how
that language prints a float. A plain limit order for 5 ETH-USDC at 100.25 from
account 1000 signs exactly these 129 bytes:

```
exchange-account-order-v3\n349d462ced25bb2b\n1000\nETH-USDC\nBuy\n10025\n50\nLimit\nGoodTillCancel\nfalse\n9f2b1c04d7e58a36bb0147fe29c3d580
```

`349d462ced25bb2b` is an example session. A signer reads the live one from
`GET /head`. The same signed bytes verify in no other log.

**The session** names the log. `GET /head` serves it, and every read of
`/messages.ndjson` carries it in the `x-feed-session` header. Read it before
you sign, and sign for the session the sequencer reports now. A sequencer
refuses a submission for another session with `400`, and the answer names both
sessions. This is what stops a captured submission from becoming a message
after the sequencer's database is emptied and starts a new log.

The separate service does **not** check the session. It cannot: it would have to
ask the sequencer which log is current, and the sequencer is the party it exists
to distrust. A sequencer that wanted to censor could then serve an old head, the
separate service would refuse every current submission at intake, and there
would be no entry, no deadline and no overdue report. So the check is where the
knowledge is, and it costs one entry in the case an operator deletes `feed.db`
and keeps `inbox.db`.

**The three order terms** are `order_type`, `time_in_force` and `post_only`.
They are always in the statement, in that order, even when they hold their
defaults: `Limit`, `GoodTillCancel` and `false`. The wire form of a published
message omits a term that holds its default. This preserves the bytes already
hashed by the sequencer. A signed statement always includes every term. Two
possible statements for one order would be ambiguous, and an unsigned term
could be changed by the sequencer. The request body may omit these terms. An
omitted term has the same default printed in the statement.

The exchange refuses two combinations on sight: `post_only` with
`order_type: "Market"`, and `post_only` on an order whose `time_in_force` is not
`GoodTillCancel`. The six that are left are the ones the trading UI and
`--order-terms` offer: `limit`, `post-only`, `ioc`, `fok`, `market` and
`market-fok`.

**The nonce** is 32 lowercase hex characters. You generate those 128 bits for
each submission, from your operating system's random source. The nonce stops a
replay. The sequencer publishes at most one message per `(account, nonce)` over
its whole history. So a captured submission that is sent again cannot produce a
second order. Send a fresh nonce for each *submission*. Do not reuse one nonce
for an account, and do not reuse one across several submissions. Two orders for
the same thing are two submissions, and they need two nonces. The sequencer
refuses anything but 32 lowercase hex characters with `400`.

The services do not accept `v1` or `v2`. Every signature made under an older
statement stops verifying. That is the point. A `v2` statement covers neither
the session nor the three order terms. If accepted, a sequencer could reuse a
`v2` signature for a market order and publish it in another log.

**In the request body**, `nonce`, `public_key` (64 hex characters) and
`signature` (128 hex characters) sit beside the fields they cover. `GET /head`
and `POST /mark` carry theirs the same way.

**Send the same signed body twice** and you get `409`. The answer names the
message your submission already became. The sequencer publishes nothing twice,
and it loses nothing. That message is your order. You get the same answer when
your client times out and sends again. Before nonces, that gave you a second,
duplicate order.

**There is no expiry.** A signed submission stays valid until it is used. The
sequencer checks uniqueness over the published history, and it never prunes
that history. This is deliberate. The sequencer would apply any time limit when
it drains the separate service. A sequencer that stayed down long enough could then
refuse an entry that was never a replay. It would report a censorship alarm for
its own outage. A clock that is wrong, fast or slow, changes nothing here.

**How to produce one.** The curl command cannot do raw Ed25519. Use the CLI as
the signer and pipe its output into curl:

```bash
# prints the signed request body and sends nothing. It still reads GET /head
# from the sequencer, because the statement names the log it is signing for.
cargo run -q -- --submit 1000 ETH-USDC Buy 100.25 5 --sign-only

curl -X POST http://127.0.0.1:3000/order \
  -H "Content-Type: application/json" \
  -d "$(cargo run -q -- --submit 1000 ETH-USDC Buy 100.25 5 --sign-only)"
```

`--order-terms` picks the kind of order. It takes `limit` (the default),
`post-only`, `ioc`, `fok`, `market` or `market-fok`:

```bash
cargo run -q -- --submit 1000 ETH-USDC Buy 100.25 5 --order-terms post-only
```

You can also sign in your own script. The key file is 32 bytes of hex, the
same format `feed.key` uses. The CLI creates it on first use (`--account-key`,
default `account.key`). This is a complete signer, tested against a running
sequencer:

```python
#!/usr/bin/env python3
"""Signs one order. Needs PyNaCl (pip install pynacl)."""
import json, os, sys, urllib.request
from nacl.signing import SigningKey

# The six kinds of order the exchange runs, as the three fields each one sets.
# The combinations that are not here are the ones the exchange refuses on
# sight: post-only on a market order, and post-only on an order that may not
# rest.
KINDS = {
    "limit":      ("Limit",  "GoodTillCancel",    False),
    "post-only":  ("Limit",  "GoodTillCancel",    True),
    "ioc":        ("Limit",  "ImmediateOrCancel", False),
    "fok":        ("Limit",  "FillOrKill",        False),
    "market":     ("Market", "GoodTillCancel",    False),
    "market-fok": ("Market", "FillOrKill",        False),
}

feed, key_file, account, symbol, side, price, quantity = sys.argv[1:8]
kind = sys.argv[8] if len(sys.argv) > 8 else "limit"
order_type, time_in_force, post_only = KINDS[kind]
key = SigningKey(bytes.fromhex(open(key_file).read().strip()))

# The log this order is for. Read now, not remembered: a sequencer whose
# database was emptied is on a new log, and a submission signed for the old one
# is refused with 400.
with urllib.request.urlopen(feed + "/head") as answer:
    session = json.load(answer)["session"]

# A fresh nonce for this submission. os.urandom, not random.random: this is
# the field that makes the submission distinguishable from a replay of it.
nonce = os.urandom(16).hex()

price_cents = round(float(price) * 100)
quantity_tenths = round(float(quantity) * 10)
# All three terms are in the statement, whatever they hold. A term the
# signature does not cover is a term the sequencer can change.
statement = "\n".join([
    "exchange-account-order-v3", session, account, symbol, side,
    str(price_cents), str(quantity_tenths),
    order_type, time_in_force, "true" if post_only else "false", nonce,
]).encode()

print(json.dumps({
    "account": int(account),
    "symbol": symbol,
    "side": side,
    "price": price_cents / 100,
    "quantity": quantity_tenths / 10,
    "nonce": nonce,
    "session": session,
    "order_type": order_type,
    "time_in_force": time_in_force,
    "post_only": post_only,
    "public_key": key.verify_key.encode().hex(),
    "signature": key.sign(statement).signature.hex(),
}))
```

Run it twice and you get two orders, because each run draws its own nonce.
Send one run's output twice and the second send gets `409` naming the message
the first one became.

```bash
FEED=http://127.0.0.1:3000
curl -X POST $FEED/order -H "Content-Type: application/json" \
  -d "$(python3 sign_order.py $FEED account.key 1000 ETH-USDC Buy 100.25 5)"

# a post-only order, which the exchange refuses rather than let it take
curl -X POST $FEED/order -H "Content-Type: application/json" \
  -d "$(python3 sign_order.py $FEED account.key 1000 ETH-USDC Buy 100.25 5 post-only)"
```

A market order carries the worst price it may fill at, and that is the `price`
argument. It is a ceiling for a buy and a floor for a sell, not a requested
execution price. Each fill uses the price of the resting order it takes. The
exchange holds the bound within two percent of its own reference price, and
refuses it outright in a symbol that has no reference price.

**Keep the key file.** The account belongs to the key that first submitted for
it. There is no recovery path. There is no way to move an account to a new key,
because either one is a second key that can speak for the account. If you lose
`account.key`, that account id is gone. Pick another one. An account id that
nobody has used goes to whoever submits for it first. So claim yours early, and
back up the file.

## Trading from the web UI

The trading UI on `http://127.0.0.1:3001` signs its own submissions. So a
visitor places and cancels orders with nothing installed. It uses the same
protocol as everything above: the same statement, the same nonce rule, the same
`POST /order` and `POST /cancel`. No server rule is relaxed for it.

**The Order control** is one dropdown of six named orders, between Side and
Price: Limit; Limit, post only; Limit, immediate or cancel; Limit, fill or
kill; Market, partial fill; Market, fill or kill. They are the same six
`--order-terms`
takes. One control and not three, because three controls let a visitor build
one of the two combinations the exchange refuses on sight. A control that can
only produce a refusal is not useful. The two market kinds are
switched off in a symbol whose book has only one side, because a market order
there is refused every time with `no_reference_price`. A market order adds a
max-slippage field from 0.01% to 1.50% of the displayed midpoint. The price
field then shows the signed max price for a buy or min price for a sell. A
partial-fill market order trades what is available inside that bound and
cancels the rest. Market, fill or kill requires the whole quantity or refuses
the order. The exchange's separate 2% collar may tighten either bound.

For all six kinds, a buy price is the most the buyer accepts and a sell price
is the least the seller accepts. Fills use prices already resting in the book.
For example, a sell limit of 2.00 may fill at bids above 2.00; it does not force
the market to trade at 2.00. Post-only is the exception that must not take: if
it crosses a resting order, the exchange refuses it and no candle changes.

**Last order** says what the exchange did. The receipt confirms that the order
is in the log. The next line says whether the order is resting, what it traded,
or which refusal the exchange counted. For a fill, the page walks the paged
`GET /trade-log` interval that began before submission. It totals quantities
and the volume-weighted average in the same whole cents and whole tenths the
matcher used, so an order that takes more than 60 resting orders is not cut off.
It reports the requested, filled and canceled quantities and the lowest and
highest execution prices. The matching server candle is outlined in gold once
that candle contains the fill range. A matcher running with `--no-state-db`
cannot serve the audit log; the page then uses at most 1,000 recent account
trades and labels the result incomplete when that window does not prove the
whole fill.

**The key.** On the first visit the page draws 32 bytes from
`crypto.getRandomValues` and keeps them in tab memory. A reload loses that
account. The page writes the raw seed as unencrypted hex to `localStorage` only
after the visitor chooses **remember key**. That hex is the same format
`account.key` holds. A person or same-origin script that can read the browser
profile can copy a remembered key. The page can remove the saved copy, but the
protocol cannot move an account to a new key or recover a lost one.

**The page derives the account id from the public key. Nobody picks it.** If
two visitors picked the same number, the second one would get `403` forever,
after doing nothing wrong. Instead the page takes SHA-512 of the public key. It
reads the first 8 bytes as a big-endian integer. It reduces that integer into
`1_000_000 ..= 2^32 - 1`:

```
account = 1_000_000 + (first 8 bytes of SHA-512(public key)) mod (2^32 - 1_000_000)
```

This project keeps every id below 1,000,000. The sequencer generates traffic
for accounts `0..--num-accounts`. The bot trades as 999. The examples above use
1000. That leaves 4,293,967,296 ids. Collisions are possible, so here is the
arithmetic. With 10,000 visitors holding ids, the next visitor has a 2.3e-6
chance of taking a used id. The chance that any two of those 10,000 collide is
about 1.2%. When that happens the page shows the `403` and offers a new key.
The new key derives a new id.

**The signer** is [@noble/ed25519](https://github.com/paulmillr/noble-ed25519)
2.3.0 (MIT). It is vendored unmodified at `services/static/ed25519.js`. The
exchange serves it from the same binary as the page. There is no CDN. This page
tells you that you need not trust the operator. So it must not fetch the code
that holds the visitor's key from a fourth party. Check the copy:

```bash
npm pack @noble/ed25519@2.3.0 && tar xzf noble-ed25519-2.3.0.tgz
diff package/index.js services/static/ed25519.js
```

The page uses Web Crypto only for SHA-512 (`crypto.subtle.digest`). Every
browser has had that for a decade. Web Crypto support for Ed25519 is much
newer: Chrome 137, Firefox 130, Safari 17. So the page vendors the curve
instead of depending on the browser. `crypto.subtle` needs a secure context. So
the page signs over `https`, or on `localhost`. Served over plain HTTP from any
other host, the page says so instead of failing at the first click.

**Cross-origin.** The exchange serves the UI, and submissions go to the
sequencer or to the separate service. Neither one is ever the same origin. They use
separate ports locally, and separate hostnames or paths behind a reverse proxy.
A browser sends that request only after the receiving service names the origin
it may come from. That flag is `--ui-origin`, on both services, because a
browser posts to both. The page reads where to submit from the exchange's
`GET /config`, which serves `--public-feed-url` and `--public-inbox-url`. The
two settings have to agree, in both directions:

```bash
# feed and inbox: which UI may submit here
services --start-feed  --ui-origin https://exchange.example.com
services --start-inbox --ui-origin https://exchange.example.com

# matcher: where the browser should send it, by either route
services --start-matcher --feed-url http://127.0.0.1:3000 \
  --public-feed-url https://exchange.example.com/feed \
  --public-inbox-url https://exchange.example.com/inbox
```

A service grants only `POST`, only the `content-type` header, and only the
paths that take submissions. Those are `/order` and `/cancel` on the sequencer,
and `/submit` on the separate service. `POST /mark` is not preflightable. It is the
sequencer's call, and it is the one call that can make censorship evidence
disappear. There is no wildcard and no reflection. A service refuses an origin
that is not on its list. The refusal names the origin, the flag, and which of
the two services refused, because a browser shows the caller only "CORS
error":

```
$ curl -s -X OPTIONS http://127.0.0.1:3002/submit \
    -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: POST'
origin https://evil.example may not submit to this inbox. The operator lists
the origins the UI is served from with --ui-origin; this inbox allows:
http://127.0.0.1:3001, http://localhost:3001
```

There is no `Access-Control-Allow-Credentials`. So a browser never attaches
cookies to a submission, and the signature stays the only thing that speaks for
an account. A request with no `Origin` header is untouched. That covers the
CLI, the bot, the sequencer's own drain, and curl. Nothing about the drain or
the CLI changes.

Both services share one implementation of these rules
(`services/src/cors.rs`). A browser has to reach the separate service at least as
easily as it reaches the sequencer's own endpoint. Two copies of an allowlist
parser are two things that can drift apart.

**Which caller a submission is rate limited on.** The sequencer's `POST /order`
and `POST /cancel` and the separate service's `POST /submit` allow 120 submissions
per caller per 10 seconds. The caller is the address the socket reports. Behind
a reverse proxy that address is the proxy, for every request. Every visitor and
the bot would then share one limit of 120, and they would block each other.
`--trusted-proxy` tells a service which addresses to take the original client
from:

```bash
# both services rate limit, so both take the flag
services --start-feed  --trusted-proxy 172.17.0.0/16
services --start-inbox --trusted-proxy 172.17.0.0/16
```

The flag takes an address (`172.17.0.3`) or a network in prefix form
(`172.17.0.0/16`), comma separated. A Traefik container needs the network form.
Its address comes from a Docker bridge network, and it changes when the
container restarts. With an exact address, that deployment silently goes back
to one shared limit after a `docker compose up`. A value that is not an address
or a network stops the service before it binds the port. A network with bits
set below its prefix stops the service too. An operator writes `172.17.0.5/16`
when they mean the one host they observed, but it names 65,536 hosts:

```
$ services --start-inbox --trusted-proxy 172.17.0.5/16
--trusted-proxy 172.17.0.5/16 has bits set below the /16, so it does not name
the host 172.17.0.5: it names every address in 172.17.0.0/16. Write
172.17.0.0/16 if that is what you meant, or 172.17.0.5 on its own to trust that
one host
```

**The flag defaults to empty, and empty means the service never reads the
header.** The socket address is the caller, exactly as it was before the flag
existed. Anyone can write `X-Forwarded-For`. Take a service that believed the
header from an address the operator did not name. Every caller could then
invent as many rate limits as they liked. That is worse than the shared limit
the flag fixes. A deployment that forgets the flag stays where it was. It is never
accidentally permissive.

When the socket peer *is* a trusted proxy, the service reads the header **right
to left**. A client can send `X-Forwarded-For: 1.2.3.4`, and the proxy appends
what it really saw. The header then holds `1.2.3.4, 203.0.113.9`. The leftmost
entry is whatever the client chose. The rightmost entry is what a machine
observed. The service skips entries that are themselves trusted proxies, so a
path through two proxies resolves to the client and not to the inner proxy. The
first entry that is not a trusted proxy is the caller. A header that is absent,
empty, or not an address falls back to the socket address. Everyone behind that
proxy then shares one limit, which is stricter than the truth and never looser.

Each service says which addresses it believes, on startup:

```
INFO services::inbox: X-Forwarded-For is believed from 172.17.0.0/16, and ignored from every other address
INFO services::inbox: no --trusted-proxy: callers are rate limited on the address the socket reports, and X-Forwarded-For is ignored. Behind a reverse proxy that is one bucket for everybody
```

### The separate service from the UI

The Trade panel has a **Route** row with two choices, `Feed` and `Inbox`. The
order is the same on either route: the same statement, the same nonce, the same
signature. Only the request body differs, and that is what V3 is for. The
sequencer's `POST /order` takes the submission's fields flat, with the proof
beside them. The separate service's `POST /submit` takes the submission as an
object, with the proof beside it.

The second choice puts the order into a service the sequencer does not control.
The panel then shows what happens to the order:

```
inbox #12  Buy 1.5 BTC-USDC at 10.07
pending in the inbox for 0.3s of the 5.0s deadline. The feed has not sequenced it yet
```

```
inbox #12  Buy 1.5 BTC-USDC at 10.07
sequenced by the feed as message #1843 after 0.4s, within the 5.0s deadline
```

and, when the sequencer does not sequence it at all:

```
inbox #12  Buy 1.5 BTC-USDC at 10.07
overdue: past the 5.0s deadline and the feed has still not sequenced it. The
inbox says so on its own GET /status, and that is the evidence this layer
produces.
```

The separate service decides that an entry is late, never the page. The page finds
its entry in the `overdue` list that `GET /status` serves. It does not compare
a browser clock against timestamps from another machine. The elapsed time on a
sequenced entry is `sequenced_at - received_at`. The separate service's own clock
stamps both times.

The page reads two endpoints while it watches an entry, and both already
existed. It reads `GET /status` for the verdict and the deadline. It reads
`GET /entries?ids=` for its own entries. See
[**Read the separate service's entries**](#read-the-separate-services-entries). With no
entry to watch, the page asks `/status` every four seconds. That answer gives
the `separate service N pending · N overdue` reading on the verification strip.
That reading is the only number on that strip that does not come from the
operator's own service.

Before this, the Rust CLI was the only client that could open the separate service
(`--submit ... --via-inbox`). So a deployed demo's separate service was reachable
only by a person who could build the binary. It was not reachable by the person
it exists for, who is remote and is being refused.

## The sequencer's HTTP API

The sequencer serves a REST API. You read the messages and submit orders
through it. It is on `http://127.0.0.1:3000` by default. `--bind` and
`--feed-port` change the address. These are the endpoints:

### Get the messages

**Endpoint.** `GET /orders`
**Query parameters.**
- `since` (optional): Return only messages with an `id` strictly greater than this value. Message numbers always increase and start at 1. So you read the whole log by polling with the highest `id` you have seen (start with `since=0`).
- `n` (optional): Return only the last `n` messages instead.

**Response.** A JSON array of messages, in the order the sequencer gave them.

Every response holds at most 1000 messages. So a consumer that is far behind
catches up over several polls. It does not pull the whole history into one
response. The signed head in the `x-feed-*` headers always stands at the **last
message in the body**, never past it. Hash the messages again across successive
`?since=` responses. Each response ends at the chain hash the sequencer signed
for what you just received. That is what `matcher.rs` and `validator.rs` do.

`?n=` is the exception, and it cannot work any other way. It returns the *end*
of the history. The chain hash covers every message from message 1, and the end
of the history does not hold those messages. The head on an `?n=` response is
still true, because it stands at the last message in the body. You cannot
compute it again from that body. Use `?n=` to look at recent traffic, and
`?since=` to check the history.

The sequencer keeps the newest 10,000 messages in memory. It reads anything
older out of `feed.db`. So `?since=0` on a long history is a page of rows from
disk, not a copy of everything ever published. The answer is the same either
way, chain hash and signature included. A sequencer started with `--no-feed-db`
is the one case where it is not. That sequencer has nowhere to read from. It
answers `410 Gone` and names the message it no longer has. It does not answer a
page that starts somewhere else. Every consumer would hash such a page into a
chain that disagrees with the head, and read that as a rewritten history.

**Message types.**

1. **New Order**, a new limit order entering the market:
```json
{
  "New": {
    "id": 42,
    "timestamp": 1753000000000,
    "account": 3,
    "symbol": "ETH-USDC",
    "side": "Buy",
    "price": 100.25,
    "quantity": 5.0
  }
}
```

2. **Cancel**, a request to cancel a previously placed order (`target_id` refers to the `id` of the order to cancel):
```json
{
  "Cancel": {
    "id": 57,
    "timestamp": 1753000004000,
    "account": 3,
    "target_id": 42
  }
}
```

Both message types carry one more field, `nonce`, when the message comes from a
signed submission. That is the submitter's replay nonce. The sequencer
publishes it as part of the message, so the chain hash covers it. Simulated
traffic from the generator has no nonce, and the message leaves the field out.
So those messages are byte for byte what they always were, and an existing
`feed.db` still opens. A consumer that computes the chain hash again must
serialize the field it received. If it drops the field, it computes a different
chain hash than the one the sequencer signed.

**Example with curl.**

Poll for all messages after id 42:
```bash
curl "http://127.0.0.1:3000/orders?since=42"
```

Get the last 5 messages:
```bash
curl "http://127.0.0.1:3000/orders?n=5"
```

### Submit order

**Endpoint.** `POST /order`
**Content-Type.** `application/json`

Submit a new limit order to the sequencer. The sequencer gives the order an `id` and publishes it to all consumers, like any other message.

```json
{
  "account": 1000,
  "symbol": "ETH-USDC",
  "side": "Buy",
  "price": 100.25,
  "quantity": 5.0,
  "nonce": "9f2b1c04d7e58a36bb0147fe29c3d580",
  "public_key": "f5d04e5e9f890afe6ad210c2201fb8ba9ad56cc0869c0a291834efad7d93e740",
  "signature": "0be66502f6c08cbe26707c5f7876ecc17710887e2099f9942aa651b15eca4189…"
}
```

The published message carries the `nonce` too. The nonce is not only part of
the signing format. That makes the record of used nonces as tamper-evident as
the history itself. Deleting a nonce to reopen a replay changes the chain hash,
and the sequencer then refuses to start. It refuses in the same way for any
other edit to `feed.db`.

The price must be a whole price step, and the quantity must be a whole quantity
step. That means whole cents, whole tenths, and at most 1,000,000,000 units of
either. The symbol must be one of the three. Anything else gets `400` with the
reason. The exchange drops an order that is off the price step, and it leaves
no trace. So a service that accepted one here would return a signed receipt for
an order that never exists. The sequencer checks `POST /cancel` the same way
(`target_id` 0 names no message that can exist). The separate service's
`POST /submit` applies the same checks, from the same function.

The refusals stay apart, because they mean different things to the person who
holds the key:

- `400`: the body is not a signed submission. A caller that still sends the old
  unsigned shape gets this, with the shape it needs. You also get `400` when
  `public_key` or `signature` is not readable hex. You get it when the `nonce`
  is missing, or is not 32 lowercase hex characters. You get it when the terms
  are off the price step or the quantity step.
- `401`: the signature does not verify for these terms. The answer prints the
  statement the signature had to cover. So you can compare a wrong signer
  against it field by field. A signer that still produces the `v1` statement
  gets this answer.
- `403`: the signature is good, but the key is not the one this account is
  pinned to. The answer names both keys. This is the impersonation case. It is
  deliberately not the same status as a broken signature, because the caller
  holds a working key. It is just not this account's key.
- `409`: this account already submitted this nonce. The answer names the
  message that submission became. The sequencer published nothing twice. A
  replay of captured bytes gets this answer. So does a client that sends again
  after a timeout, which used to get a duplicate order.
- `429`: more than 120 submissions from one caller in 10 seconds. The caller is
  the socket address. It is the client the trusted proxy reported when the
  service started with `--trusted-proxy` (see
  [**Trading from the web UI**](#trading-from-the-web-ui)).
- `503`: the sequencer could not write the message to `feed.db`, so it did not
  publish the message. The sequencer publishes nothing it could not write to
  disk. A message given to consumers and lost on restart makes every consumer's
  chain hash disagree with the sequencer's. Consumers read that as proof that
  the sequencer is lying.

An account with no key on file yet is not an error. That submission is the pin,
and the service logs it (`pinned account 1000 to public key …`).

**Response.** The `id` the sequencer gives the order, and the signed head that
contains it. That is the submitter's receipt.

```json
{ "id": 123, "receipt": { "session": "...", "last_id": 123, "chain": "...", "public_key": "...", "signature": "..." } }
```

**Example with curl.**

```bash
curl -X POST http://127.0.0.1:3000/order \
  -H "Content-Type: application/json" \
  -d "$(cargo run -q -- --submit 1000 ETH-USDC Buy 100.25 5 --sign-only)"
```

### Submit cancel

**Endpoint.** `POST /cancel`
**Content-Type.** `application/json`

Submit a cancel to the sequencer. The sequencer does not check whether the
target order is still open. Each consumer decides what a cancel means for its
own state. The sequencer does check that the named account signed the cancel.
The exchange's ownership rule needs that check. `apply_cancel` refuses a cancel
whose account is not the resting order's owner. That comparison is only worth
making because a stranger cannot type the account field.

```json
{
  "account": 1000,
  "target_id": 42,
  "nonce": "1d47a90fe3b25c8871face0426b9d013",
  "public_key": "f5d04e5e9f890afe6ad210c2201fb8ba9ad56cc0869c0a291834efad7d93e740",
  "signature": "c71a22d27f9526e7ca93184203ea84815809dcbf511e5f84cd07ff628e609e92…"
}
```

Use a fresh nonce for each cancel, not one for each order you cancel. Sending
a cancel again until it takes effect is normal. [The bot in this
repository](BOT.md) does that on every poll. Each of those cancels is its own
signed submission with its own nonce. The sequencer sequences each one as it
always did.

Same refusals as `POST /order`.

**Example with curl.**

```bash
curl -X POST http://127.0.0.1:3000/cancel \
  -H "Content-Type: application/json" \
  -d "$(cargo run -q -- --cancel 1000 42 --sign-only)"
```

### Publish an operator message

**Endpoint.** `POST /operator`
**Content-Type.** `application/json`

Publishes one message the operator signed. The three kinds are `ListSymbol`,
`DelistSymbol` and `EngineRule`. No trader may publish any of them. The
sequencer publishes them under one account that names nobody, and it pins no
key to that account.

**The route exists only where a key is configured.** A sequencer started
without `--operator-key` does not serve this route, and answers `404`. See
[**Starting the sequencer**](#starting-the-sequencer).

**A browser cannot reach it.** The route is deliberately not in the
sequencer's `SUBMISSION_PATHS`, so the cross-origin guard refuses the preflight.
`POST /order` and `POST /cancel` are the two paths a page may call. This route
is for a command line that holds the key file. This operator key can publish
every administrative message. Allowing a page to send bodies to this route
would create another way to use the key by mistake.

One body per kind. The `kind` field picks the shape:

```json
{
  "kind": "ListSymbol",
  "symbol": "DEMO-USDC",
  "price_step": 0.01,
  "quantity_step": 0.1,
  "nonce": "0123456789abcdef0123456789abcdef",
  "public_key": "f5d04e5e9f890afe6ad210c2201fb8ba9ad56cc0869c0a291834efad7d93e740",
  "signature": "0be66502f6c08cbe26707c5f7876ecc17710887e2099f9942aa651b15eca4189…"
}
```

```json
{
  "kind": "DelistSymbol",
  "symbol": "DEMO-USDC",
  "nonce": "1d47a90fe3b25c8871face0426b9d013",
  "public_key": "f5d04e5e9f890afe6ad210c2201fb8ba9ad56cc0869c0a291834efad7d93e740",
  "signature": "c71a22d27f9526e7ca93184203ea84815809dcbf511e5f84cd07ff628e609e92…"
}
```

```json
{
  "kind": "EngineRule",
  "version": 1,
  "nonce": "9f2b1c04d7e58a36bb0147fe29c3d580",
  "public_key": "f5d04e5e9f890afe6ad210c2201fb8ba9ad56cc0869c0a291834efad7d93e740",
  "signature": "3f4a9d1e0c7b58a26bb0147fe29c3d5809dcbf511e5f84cd07ff628e609e9210…"
}
```

A symbol holds 1 to 32 characters, and only `A`-`Z`, `0`-`9` and `-`. The steps
must be whole cents and whole tenths. `version` is a whole number, and the
sequencer does not judge which rule sets exist. The exchange reports the newest
rule set it can run on `GET /market`.

**The statement the operator signs** is plain ASCII, newline separated, with a
versioned prefix. It has the same shape as the account statements above. There
is no trailing newline. The three kinds are:

```
exchange-operator-list-v1
<session>
<symbol>
<price step in whole cents>
<quantity step in whole tenths>
<nonce>
```

```
exchange-operator-delist-v1
<session>
<symbol>
<nonce>
```

```
exchange-operator-rule-v1
<session>
<version>
<nonce>
```

Each kind has its own prefix. So a signature over a listing can never be read
as a signature over a delisting of the same symbol.

`<session>` is the `session` field of `GET /head`. It names one log. The same
signed bytes therefore verify in no other log, and in no new log after this one
was emptied. Read the session for every message. Do not type it once by hand.

The steps are whole price steps and whole quantity steps (0.01 is `1`, 0.1 is
`1`), not decimals. So a signer in any language produces the same bytes. The id
and the timestamp are not in the statement. The sequencer assigns both, and the
operator cannot know either one when signing.

A listing of `DEMO-USDC` with step 0.01 and step 0.1, in session
`349d462ced25bb2b`, signs exactly these bytes:

```
exchange-operator-list-v1\n349d462ced25bb2b\nDEMO-USDC\n1\n1\n0123456789abcdef0123456789abcdef
```

A delisting of the same symbol in the same session signs these:

```
exchange-operator-delist-v1\n349d462ced25bb2b\nDEMO-USDC\n0123456789abcdef0123456789abcdef
```

And rule set 1 in the same session signs these:

```
exchange-operator-rule-v1\n349d462ced25bb2b\n1\n0123456789abcdef0123456789abcdef
```

`349d462ced25bb2b` is an example session. A signer reads the live one from
`GET /head`. The same signed bytes verify in no other log.

**The nonce** is 32 lowercase hex characters, generated for each message from
your operating system's random source. It works as it does for a submission:
the sequencer publishes at most one operator message per nonce over the whole
history.

The refusals stay apart, because they mean different things to the person who
holds the key:

- `400`: the body is not an operator message. You get this when the `kind` is
  not one of the three, when a field is missing, and when `public_key` or
  `signature` is not readable hex. You get it when the `nonce` is not 32
  lowercase hex characters. You get it when the symbol breaks the name rule, or
  a step is not a whole number of cents or tenths. A message the rules refuse
  has no statement, so the answer is about the message and not about who signed
  it.
- `401`: the signature does not verify. The answer prints the exact statement
  the signature had to cover, with the lines separated by ` | `. A signature
  made for another log gets this answer, and so does one made for this log
  before it was emptied and took a new session.
- `403`: the signature is good, but the key is not the one this sequencer
  publishes for. The answer names both keys. The caller holds a working key. It
  is just not the operator's key.
- `404`: this sequencer names no operator, so it serves no `/operator` route at
  all. Start it with `--operator-key <HEX>`, where `<HEX>` is what
  `services --operator-public-key` prints for the key file.
- `409`: the operator already published this nonce. The answer names the
  message that signed statement became. A replay of captured bytes gets this
  answer, and so does a client that sends again after a timeout.
- `429`: more than 120 submissions from one caller in 10 seconds. The caller is
  the socket address, or the client the trusted proxy reported when the service
  started with `--trusted-proxy`.
- `503`: the sequencer could not write the message to `feed.db`, so it did not
  publish it. The sequencer publishes nothing it could not write to disk.

**Response.** The `id` the sequencer gives the message, and the signed head that
contains it. The same receipt `POST /order` returns.

```json
{ "id": 1, "receipt": { "session": "...", "last_id": 1, "chain": "...", "public_key": "...", "signature": "..." } }
```

**Example with curl.** The curl command cannot do raw Ed25519. The CLI signs,
then curl sends:

```bash
# prints the signed body and sends nothing
cargo run -q -- --list-symbol DEMO-USDC 0.01 0.1 --sign-only

curl -X POST http://127.0.0.1:3000/operator \
  -H "Content-Type: application/json" \
  -d "$(cargo run -q -- --list-symbol DEMO-USDC 0.01 0.1 --sign-only)"
```

The CLI sends it for you without `--sign-only`. See
[**Operator commands**](#operator-commands) for the four commands and their
flags.

### Get symbols

**Endpoint.** `GET /symbols`

**Response.** JSON array of the trading pairs this sequencer generates traffic
for, each with the price step its market opens on.

```json
[
  {"symbol": "MERKLE-USDC", "price_step": 0.01},
  {"symbol": "ETH-USDC", "price_step": 0.1},
  {"symbol": "BTC-USDC", "price_step": 1.0}
]
```

The order is the order `docker/open-the-log.sh` lists the markets in, which is
the order `GET /market` on the exchange serves them in.

The step is here because the exchange refuses a price that is not a whole number
of steps, `off_price_step`, and because the step differs per market. The three
mids are about 10, 100 and 1000, so one step for all three would be a hundred
times coarser on one market than on another.

**Available symbols.**
- `MERKLE-USDC`, price step `0.01`
- `ETH-USDC`, price step `0.1`
- `BTC-USDC`, price step `1.0`

### Get the messages as raw bytes

**Endpoint.** `GET /messages.ndjson`
**Query parameters.**
- `since` (optional): the same meaning as on `GET /orders`. Return only
  messages with an `id` strictly greater than this value.
- `limit` (optional): how many messages to return, capped at 1000.

The two endpoints take a different second parameter. `GET /orders` takes `n`,
which returns the *end* of the history. This endpoint takes `limit`, which caps
the page that starts after `since`. There is no `limit` on `GET /orders` and no
`n` here.

**Response.** One message on each line. Each line is exactly the bytes the
sequencer hashed into the log. The content type is `application/x-ndjson`.

**Use this endpoint, not `/orders`, whenever you check the log.**

`GET /orders` returns a JSON array. To find where each message ends you have to
count braces, and a brace can appear inside a symbol or a nonce. So you need to
know when you are inside a string, which means tracking quotes and escapes. Every
branch of that is a place to be wrong, and a wrong split gives a wrong hash. Every
consumer reads a wrong hash as tampering.

A newline cannot appear inside a message. JSON requires control characters to be
escaped inside a string. A newline in a symbol is written `\n`, which is a
backslash and the letter `n`. So the only raw newline in the body is the
separator, and this endpoint needs no knowledge of JSON at all.

**Do not parse a line and write it again.** Hash the bytes that arrived. Rust
writes a price of `100.0` as `100.0` and JavaScript writes it as `100`. Both are
the same number and they are different bytes, so they give different hashes.

This is also what lets you check a log holding a message kind your program does
not understand. Hashing is a byte operation. It does not need to know what the
bytes mean.

The `x-feed-*` headers carry the signed head, exactly as on `GET /orders`.

### Get the signed head

**Endpoint.** `GET /head`

The sequencer keeps a SHA-256 chain hash over its message history. It signs the
head of that chain with an Ed25519 key (`feed.key`, created on the first run
next to `feed.db`). The signed head covers the whole history up to `last_id`.

```json
{
  "session": "74058007e28bb3fd",
  "last_id": 245,
  "chain": "9f3a…",
  "public_key": "b1c2…",
  "signature": "84d0…"
}
```

Every `/orders` response sends the same five values as headers
(`x-feed-session`, `x-feed-last-id`, `x-feed-chain`, `x-feed-pubkey`,
`x-feed-signature`). `POST /order` and `POST /cancel` return them as a
`receipt`. The receipt proves that the signed history holds the submitted
message.

`session` names the signed history, not the file. It changes when the sequencer
starts on a database that holds no signed checkpoint: a new file, or one whose
log has been emptied. It does not change across a restart of a database that has
published anything, because that is the same history.

So a read position held against one session cannot move to another session. A
consumer that sees the session change is looking at a history its position does
not refer to. That consumer rebuilds instead of continuing.

A session change is therefore the signal for a log that was emptied. The
evidence that anything existed is what the delete removes. So deleting every row
and the checkpoint is the one edit to `feed.db` a startup check cannot refuse,
and it comes back under a new name for exactly that reason. An edit to a
message, chain link, session, checkpoint, or committed Merkle node instead stops
the sequencer at startup ([`ROADMAP.md`](../services/ROADMAP.md), V1 and V2).

A node deeper in the tree than that is the one edit that neither stops the
sequencer nor achieves anything. The edit does not change the root, so the
sequencer keeps signing the root produced by its messages. Any proof that reads
the edited node fails against that signed root.

### Get the signed tree head

**Endpoint.** `GET /sth`

The sequencer also builds a Merkle tree over the messages, as RFC 9162
specifies. It signs the head of that tree with the same key as `/head`.

```json
{
  "session": "cd18428a30de1944",
  "timestamp": 1786767726360,
  "tree_size": 44000,
  "root_hash": "89ab4e53…",
  "public_key": "<64 hex>",
  "signature": "<128 hex>"
}
```

`timestamp` is milliseconds since the Unix epoch. `tree_size` is how many
messages the tree holds. `root_hash` covers all of them.

`timestamp`, `tree_size` and `root_hash` are RFC 9162 `TreeHeadDataV2`. See
[`ENGINE.md`](ENGINE.md) section 1.3.

The response is `Cache-Control: no-store`, the same as `/head`. A caller reads
this endpoint to learn where the sequencer stands now.

Keep the STH you read. Both proofs below are checked against the `root_hash` in
an STH you already hold.

### Get an inclusion proof

**Endpoint.** `GET /proof/inclusion?leaf=N&tree_size=M`
**Query parameters.**
- `leaf` (required): the leaf to prove, counted from 0.
- `tree_size` (required): the tree to prove it against.

**Response.**

```json
{
  "session": "cd18428a30de1944",
  "leaf_index": 33753,
  "message_id": 33754,
  "tree_size": 44000,
  "inclusion_path": ["<64 hex>", "…"]
}
```

**`leaf_index` and `message_id` differ by one.** RFC 9162 counts leaves from 0,
and this sequencer numbers messages from 1. So message `n` is leaf `n - 1`. A
verifier uses `leaf_index`. A reader of `/messages.ndjson` has `message_id`.
The answer carries both numbers, so you do not have to convert.

`tree_size` is required, and it is not always the newest tree. You verify
against the tree your STH names. An STH from an hour ago names an older size,
and the sequencer still serves that size.

The proof carries no root and no signature. That is deliberate. The root must
come from an STH you already hold. An unsigned root beside a proof invites a
check against a root the sequencer never signed. Such a check always succeeds
and proves nothing.

A proof for a size below the current one never changes. The sequencer serves it
`public, max-age=31536000, immutable` with an `ETag`, and answers `304` to a
matching `If-None-Match`. A proof at the current size is `no-store`.

**Errors.** `400` when the tree cannot produce the proof. The answer names how
many messages the tree holds and which session it is. The likeliest cause is an
STH from a history this database replaced. Tree sizes restart at 0 with a new
database.

### Get a consistency proof

**Endpoint.** `GET /proof/consistency?first=M&second=N`
**Query parameters.**
- `first` (required): the older tree size.
- `second` (required): the newer tree size.

**Response.**

```json
{
  "session": "cd18428a30de1944",
  "first": 13774,
  "second": 44000,
  "consistency_path": ["<64 hex>", "…"]
}
```

This proof says the tree of size `first` is a prefix of the tree of size
`second`. It proves that messages were only added, never changed, removed or
reordered.

Both sizes are yours to choose. The pair that matters is two STHs you kept from
two moments. Neither has to be the newest.

This proof carries no root and no signature either, for the reason above. You
hold both roots, in the two STHs.

Same caching and same errors as `GET /proof/inclusion`.

### Get the stored Merkle nodes

**Endpoint.** `GET /tree/nodes?from=N&count=M`
**Query parameters.**
- `from` (default 0): the first leaf. Message `n` is leaf `n - 1`.
- `count` (default 1000): how many leaves' worth of nodes. Clamped to 1000.

**Response.**

```json
{
  "session": "cd18428a30de1944",
  "tree_size": 44000,
  "from": 0,
  "count": 3,
  "nodes": [
    { "level": 0, "index": 0, "hash": "<64 hex>" },
    { "level": 0, "index": 1, "hash": "<64 hex>" },
    { "level": 1, "index": 0, "hash": "<64 hex>" },
    { "level": 0, "index": 2, "hash": "<64 hex>" }
  ]
}
```

The nodes the sequencer stored for the appends of leaves `from` to
`from + count`. `hash` at `(level, index)` is the root of the perfect subtree
over leaves `index * 2^level` to `(index+1) * 2^level - 1`. Level 0 is the leaf
hashes. Nodes on the tree's ragged right edge are not stored by anyone and are
not served; they are computed from the perfect nodes below them.

The window is a range of leaves, not nodes. A reader first reads and folds a
page of messages. It then requests the nodes made by that page and compares
them. Neither side holds a whole tree.

`--verify` and `--audit` do exactly that, page for page, and print
`every stored node is the one the messages make`. What it catches is a stored
node the messages do not produce:

```
FAIL  every stored node is the one the messages make 1 of 711 bad
        the node at level 0 index 40 is 144248a4…, and the log's own messages
        make 3c27810f… there. Every inclusion proof that reads that node lands
        on a root the log did not sign
```

Nothing here is signed and nothing needs to be. You check these against your own
fold of the messages, so a sequencer that serves made-up nodes fails that
comparison. A signature over them would prove only that the sequencer said them,
which is the thing you are testing.

A node the sequencer does not hold is left out of the answer rather than being an
error, so a reader, which knows which nodes it asked about, can say which one
is missing.

**Cost.** One leaf makes just under two nodes. Three numbers, all measured on
the live deployment on 17 August 2026, and they answer three different
questions:

| What | Measured | How |
|---|---|---|
| a node, per message | 1.994 nodes, so 64 bytes of hash | `GET /tree/nodes?from=0&count=1000` served 1994 nodes for 1000 leaves |
| a message on the wire | 122 bytes | `GET /messages.ndjson?since=270000&limit=1000` served 121,895 bytes for 1000 messages, lines ranging 116 to 170 |
| a message in `feed.db` | 331 to 334 bytes | the file size over its message count, taken twice |

They do not contradict each other, and the third is the one an operator sizing
a disk needs. `feed.db` holds the message text, the 32-byte chain column beside
it, the two tree nodes, and SQLite's row and index overhead on all three
tables. 122 plus 32 plus 64 is 218, and the remaining 113 to 116 bytes is that
overhead. The tree's own share is 64 bytes against a 331-byte row, which is
19%.

### Check a message with no code from this repository

This script reads an STH, reads message 1, reads its inclusion proof, and
computes the root again. It prints `verifies` against a running sequencer.

```python
import json, hashlib, urllib.request

def get(path):
    return json.load(urllib.request.urlopen("http://127.0.0.1:3000" + path))

sth = get("/sth")
size, root = sth["tree_size"], bytes.fromhex(sth["root_hash"])

# The message the sequencer served, as raw bytes.
line = urllib.request.urlopen(
    "http://127.0.0.1:3000/messages.ndjson?since=0&limit=1").read().split(b"\n")[0]

proof = get(f"/proof/inclusion?leaf=0&tree_size={size}")
path = [bytes.fromhex(h) for h in proof["inclusion_path"]]

# RFC 9162 section 2.1.3.2, followed to the letter.
leaf_index, tree_size = proof["leaf_index"], proof["tree_size"]

if leaf_index >= tree_size:                            # step 1
    raise SystemExit("does not verify: that leaf is not in this tree")

r = hashlib.sha256(b"\x00" + line).digest()            # a leaf is prefixed 0x00
fn, sn = leaf_index, tree_size - 1
for p in path:
    if sn == 0:                                        # step 4: FAIL, do not stop
        raise SystemExit("does not verify: the proof is longer than the tree")
    if fn % 2 == 1 or fn == sn:
        r = hashlib.sha256(b"\x01" + p + r).digest()   # a node is prefixed 0x01
        while fn != 0 and fn % 2 == 0:
            fn //= 2; sn //= 2
    else:
        r = hashlib.sha256(b"\x01" + r + p).digest()
    fn //= 2; sn //= 2

print("verifies" if sn == 0 and r == root else "does not verify")
```

It proves that message 1 is in the tree the sequencer signed. The proof in that
run was 10 node hashes, about 320 bytes. The script uses no code from this
repository.

It does not prove that the STH is the sequencer's. The script does not check
the signature. A full check verifies the Ed25519 `signature` against
`public_key` too. Without that step the root could be anything.

## The separate service's HTTP API

The separate service listens on `http://127.0.0.1:3002` by default
(`--start-inbox`, `--inbox-port`, `--bind`).

### Submit through the separate service

**Endpoint.** `POST /submit` on the separate service (port 3002, `--start-inbox`)
**Content-Type.** `application/json`

This is the submission route the sequencer does not control. It uses the same
signature, the same statement, and the same pinning rule as the sequencer's own
endpoints. The wrapper is explicit here, because the body is a `Submission` and
not flat fields:

```json
{
  "submission": {
    "Order": {
      "account": 1000,
      "symbol": "BTC-USDC",
      "side": "Sell",
      "price": 1001.0,
      "quantity": 2.0,
      "nonce": "9f2b1c04d7e58a36bb0147fe29c3d580"
    }
  },
  "public_key": "f5d04e5e9f890afe6ad210c2201fb8ba9ad56cc0869c0a291834efad7d93e740",
  "signature": "0f695c81557b9b15d7ab2f9149d8300d1ed314dbe26b5fa3adc412ad2bf26d5a…"
}
```

A cancel is
`{"submission": {"Cancel": {"account": 1000, "target_id": 42, "nonce": "…"}}, …}`.

The separate service keeps the key and the signature with the entry. It serves them
on `GET /pending` and `GET /entries`. So the record proves who asked, not only
what they asked. A mark carries the message it claims for the same reason. The
sequencer checks that proof again against its own pins before it sequences the
entry. It leaves an entry it cannot check pending. The separate service then
reports that entry as late, and the sequencer's log holds the reason.

The separate service and the sequencer pin keys independently, in their own
databases. Neither one can ask the other. Asking would put the service it
distrusts back into its own admission path.

`POST /submit` applies the exchange's own rules: a listed symbol, whole cents,
whole tenths, at most 1e9 units. So the exchange cannot silently drop anything
the separate service accepts. An entry id is a promise that the order can execute.

**Replay, here.** The separate service refuses a second entry for the same
`(account, nonce)` with `409`. The answer names the entry that pair already
made. This check is not the correctness boundary. The sequencer's check is, and
the sequencer must not ask the separate service, for the same reason it keeps its
own account pins. This check is about availability. Without it, one captured
signature sent 5,000 times fills the pending cap. Everybody else then gets
`503` from the separate service. That is censorship by flooding the service that
reports censorship.

**The same bytes on both routes.** `GET /pending` serves signatures. So a
person who never had separate service access can read a submission off it and post
it to the sequencer's `POST /order`. The sequencer publishes it once. Later the
sequencer drains the original entry. It finds that nonce already published. It
marks the entry against that message instead of sequencing a second one. The
entry closes normally and nothing goes late. There is one order, no duplicate,
and no false censorship alarm. A user who sends the same signed bytes on both
routes gets the same result.

**Refusals.** The separate service has the same rate limit as the sequencer's
endpoints: 120 submissions per caller per 10 seconds, and `429` past that. The
pending set also has a cap (`pending_cap` in `GET /status`). Past that cap the
separate service refuses a submission with `503`. Otherwise `inbox.db` would grow
without limit, and that would slow every status check and every drain.

**Example with curl.**

```bash
curl -X POST http://127.0.0.1:3002/submit \
  -H "Content-Type: application/json" \
  -d "$(cargo run -q -- --submit 1000 BTC-USDC Sell 1001.00 2 --via-inbox --sign-only)"
```

**From a browser.** The trading UI posts exactly this body when the visitor
picks the separate service route. The page signs it as it does for the sequencer.
This needs the separate service's `--ui-origin` to name the origin that serves the
UI. See [**The separate service from the UI**](#the-separate-service-from-the-ui).

### Read the separate service's entries

**Endpoint.** `GET /entries` on the separate service
**Query parameters.**
- `n` (optional): how many of the most recent entries to return, default 30,
  capped at 200. Oldest first.
- `ids` (optional): entry ids, comma separated, at most 200 of them. Returns
  those entries, oldest first, and takes precedence over `n`.

`?n=` is the read for an audit. It says what this separate service was asked for
lately, and what happened to each entry. `?ids=` is the read for a submitter.
It says what happened to the entry whose id the submitter holds. `?n=` cannot
answer that once other submissions push the entry out of the window. That
difference matters here. An entry the caller cannot find looks exactly like an
entry the sequencer never sequenced. So a windowed read can produce a
censorship alarm that is not real. A read by id has no window.

An id that holds nothing is absent from the answer. The caller asked whether
those entries exist, and that is the answer. The separate service refuses an id
that is not a number with `400`. It refuses more than 200 ids the same way,
instead of skipping them or cutting the list. A caller that asked about 300
entries and silently got 200 would read the missing 100 as gone.

```bash
curl "http://127.0.0.1:3002/entries?ids=12,13"
```

```json
[{
  "inbox_id": 12,
  "received_at": 1755203071244,
  "submission": { "Order": { "account": 1000, "symbol": "BTC-USDC", "side": "Sell",
                             "price": 1001.0, "quantity": 2.0,
                             "nonce": "9f2b1c04d7e58a36bb0147fe29c3d580" } },
  "public_key": "f5d04e5e…",
  "signature": "0f695c81…",
  "feed_id": 1843,
  "sequenced_at": 1755203071601
}]
```

`feed_id` is `null` while the entry is still pending. Both timestamps come from
the separate service's own clock. So their difference is a real interval. That is
how the UI says an entry was sequenced 0.4s into a 5s deadline.

### Mark an entry sequenced

**Endpoint.** `POST /mark` on the separate service
**Content-Type.** `application/json`

This call ends an entry's pending state, and it belongs to the sequencer alone.
The sequencer signs each mark with its `feed.key`. It attaches the message the
entry became. The separate service checks the signature. It checks that the
message's id is the claimed one. It checks that the message is the submission
the user made. Without those checks, anyone could mark an entry against a
message that does not exist, and the alarm would report nothing wrong.

The separate service trusts one key. That key is `--feed-key <HEX>`, or the key
that `--feed-url`'s `GET /head` serves on first contact. It checks that key
against the head's signature and then pins it in `inbox.db`. With no key and no
reachable sequencer it refuses every mark. Entries then stay pending and go
late instead of disappearing quietly.

Some marks the sequencer *did* sign are still refused. One example is a second
sequencing of one entry. Another is a message that is not the submission. The
separate service records those refusals and serves them in `GET /status` as
`mark_rejections`.

## The exchange's UI (port 3001)

`GET /` serves the trading UI. `GET /ed25519.js` serves the signer that page
imports. Both are compiled into the binary. The exchange serves fourteen routes
in all. Three of them answer the page's own questions:

### Get the UI's configuration

**Endpoint.** `GET /config`

This says where a browser sends submissions, on either route. The page cannot
guess the addresses. The sequencer and the separate service are a different origin
in every deployment, and only the operator knows which one. Set them with
`--public-feed-url` (default `--feed-url`) and `--public-inbox-url` (default
`--inbox-url`).

```json
{ "feed_url": "http://127.0.0.1:3000", "inbox_url": "http://127.0.0.1:3002" }
```

`inbox_url` is `null` when the operator runs no separate service. The page then
offers no separate service route, instead of a route that reaches nothing. The
field is null and not missing. So a page that reads it can tell "the operator
runs no separate service" from "this exchange is older than the flag".

[`--audit-url`](#checking-the-exchange) also reads `feed_url`, to find the
history it runs again. It reads that field for the same reason a browser reads
it. The sequencer is a separate service, and only the operator knows its
address. An exchange can stop serving this endpoint, or serve it without a
`feed_url`. You can still audit that exchange. The auditor passes `--feed-url`
instead.

### Get an account's open orders

**Endpoint.** `GET /open-orders`
**Query parameters.**
- `account` (required): the account whose resting orders to return.

This returns what the account still has resting, oldest first. Each order shows
the quantity that is left. A half-filled order rests for the remainder. A
cancel can still reach these orders, so the UI offers a cancel button for each
one. An account with nothing resting gets `[]`.

```json
[{ "id": 1326, "symbol": "MERKLE-USDC", "side": "Buy", "price": 1.23, "quantity": 4.5 }]
```

### Get the candles

**Endpoint.** `GET /candles`
**Query parameters.**
- `symbol` (required): the symbol to bucket.
- `interval` (optional): the width of one bucket in seconds. The default is 15.
  The accepted values are 15, 300, 900, 3600 and 14400: the 15-second, 5-minute,
  15-minute, 1-hour and 4-hour buttons in the page. Any other value gets 400.
  The fixed set is a resource bound. The exchange maintains those five views as
  trades arrive, so a chart read does not scan the durable trade record.
- `n` (optional): how many of the newest buckets to return. The default is 150.
  The most is 1000. A larger value is cut to 1000, not refused.

This returns the newest `n` buckets, oldest first. `start` is milliseconds.
Prices are USDC, the same floats `/trades` serves. `volume` is the quantity
traded in the bucket, and `trades` is how many fills it holds.

```json
[
  { "start": 1786682460000, "open": 983.33, "high": 1002.50, "low": 980.10,
    "close": 1000.00, "volume": 441.8, "trades": 89 },
  { "start": 1786682475000, "open": 1000.00, "high": 1000.00, "low": 1000.00,
    "close": 1000.00, "volume": 0.0, "trades": 0 }
]
```

**`n` counts buckets, not buckets that hold a trade.** A bucket with no trade in
it is in the answer, with `trades` 0, `volume` 0, and `open`, `high`, `low` and
`close` all set to the close of the bucket before it. That is the price the
market stood at while nobody traded. So the answer is one run of buckets with no
hole in it, and `n` buckets are `n * interval` seconds of wall time. A chart can
draw the answer straight onto a time axis.

`start` is the bucket's first millisecond, and it is always a whole multiple of
`interval * 1000`. Each `start` is exactly one bucket width past the one before
it.

The answer is shorter than `n` only when the run's first trade falls inside the
range. Then it starts at that trade's own bucket. A reader can use that: an
answer shorter than `n` means there is nothing older to ask for.

**This changed on 16 August 2026, and it breaks a client written before then.**
`n` used to count only the buckets that held a trade, so one request could cover
any amount of wall time: the old
`?symbol=BTC-USDC&interval=1&n=400` route returned 400 buckets spanning 3716
seconds, with 3316 empty ones missing. A reader could not tell "no trades here"
from "you asked for too few". Now `n` counts buckets, the answer holds rows with
`trades` 0, and the same `n` reaches less far back on a market that trades in
bursts. One-second candles are no longer served; use one of the five intervals
listed above, or a larger `n`, up to 1000.

## Auditing a live exchange (port 3001)

### Get the market state

**Endpoint.** `GET /market`

This returns the exchange's counters, its state root, and a summary per
symbol. Three of its fields describe the software rather than the state:

```json
{ "build_commit": "656b069c0df2…", "rule_set": 2, "newest_rule_set": 2, "…": "…" }
```

`build_commit` is the commit the running binary was built from. The CI
workflow passes it into the image build and tags the published image with the
same value, so the field and the image tag can be compared directly. That is
how you check which source a deployment serves, instead of assuming it.

A build that was not given a commit reports `unknown`. A local `cargo build`
does that. The field is never empty, so `unknown` reads as an answer and not
as a broken field.

`rule_set` is the rule set the exchange is matching under, as the last
`EngineRule` message in the log named it. Rule set 1 is the first set of rules.
The live exchange reports 2, because message 1 of its log named 2:
`docker/open-the-log.sh` reads `newest_rule_set` off `GET /market` and
publishes that number as message 1.

`newest_rule_set` is the newest rule set the running binary can execute. Read
this value before publishing an `EngineRule` message. The exchange can act on
versions up to this number. No current build understands a higher version.
`services --engine-rule` reads the same field and warns only
when the version is past it.

The two rule set fields differ for the whole of an upgrade. The exchange stays
in the rule set the log put it in until the new `EngineRule` message arrives.
So a build that runs rule sets up to 3 reports `rule_set: 2` and
`newest_rule_set: 3` right up to the moment the message lands. The live
exchange reports 2 and 2, because 2 is the newest rule set any build here runs:
`RuleSet::NEWEST` is `RuleSet(2)` in `services/src/matcher/pipeline.rs`.

All three are response values only. They describe the binary, not the log. None
is part of the state root or a signed claim. Two exchanges built from different
commits must still reach the same state root after the same messages, even if
their newest supported rule sets differ.

### Get the signed execution claims

**Endpoint.** `GET /claims`
**Query parameters.**
- `since` (optional): return only claims whose `from_msg` is strictly greater
  than this value. Start at 0 and poll with the last `from_msg` you saw.

One response holds at most 1000 claims, and the SQL query applies that limit. A
shorter page is the end of the run's claims.

```json
{
  "run_id": 1,
  "session": "c189c37442ea735d",
  "cursor": 617,
  "matcher_public_key": "f947509b…",
  "feed_public_key": "c26330b6…",
  "claims": [
    {
      "from_msg": 1,
      "to_msg": 77,
      "root_before": "7d261c6b…",
      "root_after": "f4626950…",
      "trades_total": 38,
      "signature": "3480f050…"
    }
  ]
}
```

The signature covers, byte for byte:

```
exchange-claim-v1\n<session>\n<from_msg>\n<to_msg>\n<root_before>\n<root_after>\n<trades_total>
```

The two roots are 64 lowercase hex characters. `session`, `cursor` and the two
keys travel with the page. So one response carries everything you need to check
the claims in it. Three requests would be three chances to receive a matching
set from three different moments.

### Get the trade record

**Endpoint.** `GET /trade-log`
**Query parameters.**
- `since` (optional): return only trades with a `trade_id` strictly greater
  than this value.

The same limit applies. Prices are whole cents and quantities are whole tenths.
Those are the price step and the quantity step the exchange matched on, not the
floats `/trades` serves a browser. An auditor compares the messages it ran
again against these values.

```json
{
  "run_id": 1,
  "trades": [
    {
      "trade_id": 1, "timestamp": 1786682488951, "symbol": "BTC-USDC",
      "price_cents": 100134, "qty_tenths": 72,
      "maker_order": 5, "maker_account": 0,
      "taker_order": 8, "taker_account": 4, "taker_side": "Sell"
    }
  ]
}
```

`trade_id` counts the run's fills, not the fills in memory. The exchange keeps
the newest 10,000 fills in memory. It reads the `trades` table in `state.db`
for anything older. So a restart rebuilds the run's positions from every row
without holding any of them. `/trades` and `/pnl` read past the window when the
question needs it. `/candles` reads a bounded projection rebuilt during that
same startup pass and updated with each new fill. The trade table also has a
`trades_readable` view, with prices in USDC, for your own SQL analysis.

Both endpoints answer 503 when the exchange runs with `--no-state-db`. No claim
history is written to disk, so there is nothing to serve. An empty list would
say "this exchange has claimed nothing".

## Routes with no section of their own

The sections above describe the routes an integrator or an auditor needs. This
table holds the rest, one line each. The sections and this table together name
every route the four services serve.

| Service | Route | Query parameters | What it answers |
|---|---|---|---|
| the sequencer | `GET /metrics` | none | The request, byte and page counters, one counter a line, in the Prometheus text format a scraper reads. `feed_head_id` is the newest message number, and `feed_window_messages` is how many messages are still in memory. |
| the exchange | `GET /` | none | The trading UI page. |
| the exchange | `GET /app.css`, `GET /app.js` | none | The same-origin style and code used by the trading page. Keeping them outside the HTML lets the page reject inline code with CSP. |
| the exchange | `GET /ed25519.js` | none | The signing library that page imports. |
| the exchange | `GET /favicon.ico`, `GET /icon.png`, `GET /apple-icon.png` | none | The site icons used by browsers and home-screen shortcuts. |
| the exchange | `GET /book` | `symbol` (required), `depth` (default 10, most 1000) | Both sides of one market's book, one row per price level. |
| the exchange | `GET /trades` | `symbol`, `account`, `n` (default 20) | The newest trades, oldest first. |
| the exchange | `GET /positions` | `account`, `since`, `n` (default 50, most 1000) | One page of accounts and what each one holds. |
| the exchange | `GET /pnl` | `account` (required), `points` (default 200, maximum 2000) | What one account made or lost, as an exact sampled series over time. |
| the exchange | `GET /messages` | `symbol`, `n` (default 30) | The newest messages the exchange ran. |
| the exchange | `GET /anchor-config` | none | The anchor contract this deployment writes to: address, chain id, deployment block and writer. It answers 404 when the deployment anchors nothing. |
| the separate service | `GET /pending` | none | Every entry it accepted that the sequencer has not put in the log yet. |
| the separate service | `GET /status` | none | The censorship evidence: how many entries wait, which ones are late, and every mark it refused. |
| a validator | `GET /attest` | none | The signed statement of the position that validator vouches for. |

**`GET /messages` on the exchange is not `GET /messages.ndjson` on the
sequencer.** They are two services, two bodies and two sets of parameters. The
exchange serves a JSON array of the messages it ran, newest last, and it takes
`symbol` and `n`. The sequencer serves the exact bytes it hashed, one message a
line, and it takes `since` and `limit`. Check a log against
[`GET /messages.ndjson`](#get-the-messages-as-raw-bytes), never against the
exchange's route.

**`GET /attest` is not published on the live deployment.** It answers 404 on
`exchange.th3nolo.com`, on `feed.exchange.th3nolo.com` and on
`inbox.exchange.th3nolo.com`, measured on 17 August 2026. The three validators
run inside the container, and only the exchange reads them. So `GET /market`
reports `validators_responding: 3` for validators no reader outside the
container can reach. Run your own validator with `--start-validator` to get an
attestation you can read. See
[**Starting the validators**](#starting-the-validators).

## Which address a service listens on

Every service binds `127.0.0.1` by default. That is this machine only, which is
what the demo, the tests and every local run need. `--bind` changes it. It
applies to whichever service the invocation starts. There is one flag and not
four, because one invocation starts one service, and each service already has
its own port flag:

```bash
services --start-feed      --bind 0.0.0.0 --feed-port 3000
services --start-matcher   --bind 0.0.0.0 --matcher-port 3001
services --start-inbox     --bind 0.0.0.0 --inbox-port 3002
services --start-validator --bind 0.0.0.0 --validator-port 3010
```

**A container needs this flag.** A reverse proxy in another network namespace
cannot reach a process bound to `127.0.0.1` inside a container. The proxy gets
a connection refused, and the service looks down, however correct the routing
rules are. The other option is `network_mode: host`. That option makes the
proxy's peer address `127.0.0.1`. `--trusted-proxy 127.0.0.1` then believes the
`X-Forwarded-For` of every other process on the host. So change the bind
address, not the proxy list.

**A service names a non-loopback bind once, at startup.** It does not refuse
the setting, because that setting is correct inside a container. The same flag
on a host is a different deployment with the same spelling:

```
WARN services::feed: listening on 0.0.0.0:3000, which is not only this machine: anything that can route to this address reaches an unauthenticated order-submission endpoint. That is the point inside a container behind a reverse proxy. Directly on a host it is published to whatever network that host is on
```

The exchange and the validator warn in the same shape. Each one names what it
publishes. The exchange names the trading UI and the market state. The
validator names the signed attestation.

A value that is not an address stops the service before it binds the port.
`--ui-origin` and `--trusted-proxy` behave the same way:

```
$ services --start-feed --bind localhost
--bind localhost is not an IP address. It takes an address to listen on, not a
hostname, and not a port: 127.0.0.1 for this machine only, which is the
default, or 0.0.0.0 for every address on this machine, which is what a
container behind a reverse proxy needs
```
