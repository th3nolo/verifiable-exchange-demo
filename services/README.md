# Exchange services

One binary starts one service per invocation. The sequencer uses port 3000. The
exchange uses port 3001 and serves the trading UI. The separate service uses
port 3002, and validators use ports 3010 and above. The same binary also starts
the trading bot and audit tools.

The sequencer orders every message, records it in an RFC 9162 Merkle log, and
signs the result. Its HTTP API accepts orders, streams messages, and returns any
range of history.

`src/feed/tree.rs` keeps the Merkle nodes in `feed.db`, and `src/feed/http.rs`
serves them. `/sth` returns the signed tree head. `/proof/inclusion` proves that
one message belongs to the log. `/proof/consistency` proves that one log is a
prefix of another. `/tree/nodes` returns the stored nodes.

The [`API reference`](../docs/API.md#the-sequencers-http-api) gives a worked
example for each endpoint.

The sequencer also publishes synthetic traffic. `src/feed/generate.rs` sends
resting limit orders and immediate-or-cancel orders that cross one side. It
also sends a cancel for every order it placed. The log carries the operator's
messages too:
`EngineRule` names the rule set the messages after it run under, and
`ListSymbol` and `DelistSymbol` open and close a market. You can start the
sequencer, watch the stream, submit your own orders, and read any range of
history back.

The sequencer only *publishes* orders: it does not match them, and it holds no
book. What happens when a buy and a sell cross is entirely up to the consumers
of the log. The exchange in this repo is one such consumer; nothing about the
sequencer assumes it is the only one.

## Getting started

`./demo.sh` in the repository root builds everything and starts every service at
once. [The root README](../README.md#run-it) says what it starts and where to
look. The rest of this file is for running one service on its own.

### One service at a time

[Install Rust](https://rust-lang.org/tools/install/) if you haven't yet.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Build in the `services` directory.

```bash
cd services
cargo build
```

Run the sequencer in the background or in its own terminal.

```bash
cargo run -- --start-feed --num-accounts 20
```

Learn more about available commands.

```bash
cargo run -- --help
```

## Two things to know before you consume the stream

- **A cancel may arrive for an order that, in your view of the market, has
  already traded.** Handling that is up to you.
- **The sequencer reports no matches.** It does not track balances or
  positions, and it never says whether an order traded. There are no trade or
  execution messages.

[`../docs/GENERATOR-RFC.md`](../docs/GENERATOR-RFC.md) specifies the generated
traffic. It explains why markets used to stop and defines the checks for each
run. Section 4.5 measures 50,000 messages from 40 accounts. In every fixed
activity state and in the switching run, 66.6% of limit orders end in a cancel
rather than a trade.

## Where everything else is

[The root README](../README.md) lists every document. The two that matter most
here: [`../docs/API.md`](../docs/API.md) is every command, flag and HTTP
endpoint, and [`ROADMAP.md`](ROADMAP.md) is the design story in order.
