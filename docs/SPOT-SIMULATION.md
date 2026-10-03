# Funded spot simulation

The matcher has two explicit accounting modes. `funded-simulation` trades only
assets supplied by a deterministic genesis configuration. `synthetic-legacy`
keeps the original per-symbol position/PnL demonstration and does not validate
spendable balances. Both are simulations; neither provides custody, deposits,
withdrawals, blockchain settlement or access to real funds.

Start the funded simulation with the sequencer already running:

```sh
cd services
cargo run -- --start-matcher --ledger-mode funded-simulation \
  --funding funding.example.json --state-db state.db
```

SQLite commits the complete ledger and execution policy with the book, cursor,
reference-price window and signed claim. Recovery validates reserves against
open orders and checks the restored root against the authenticated claim before
serving the state. Restart requires the same explicit mode and funding JSON;
it restores balances and reservations without issuing funding again. Root v5
commits to this state; consumed historical v4 runs cannot resume equivalently
because they omitted the reference window, though their claims remain auditable.

`--no-state-db` explicitly selects volatile execution and replays retained history
from genesis after restart. Reading `/balances`, rejecting an order or cancelling
it never grants funds. `/claims` supplies the original funding and resource policy
as `execution_genesis` so local and remote audits replay the same semantics.

For the original generated traffic and PnL demonstration:

```sh
cargo run -- --start-matcher --ledger-mode synthetic-legacy
```

The matcher requires `--ledger-mode` on the CLI. A synthetic run cannot accept a
funding file. The stdio market harness and the older Rust `start_matcher` helper
retain synthetic semantics; the funded Rust constructor is
`MatcherState::funded_simulation(config)`.

The JSON contains `markets`, `funding` and `fee_units`. Each market maps a
symbol to explicit `base_asset` and `quote_asset` identifiers; symbols are not
balance identifiers. Each funding row names an account, an asset and a
positive integer `units` amount. An omitted account/asset starts at zero.
Duplicate funding or market rows are refused. There is no funding on demand.
Version 1 requires `fee_units: 0` and charges zero fees.

All assets use **1,000 integer units per asset**. In the example, 10,000,000
USDC units fund account 1 with 10,000 USDC, and 10,000 ETH units fund account 2
with 10 ETH. The execution input continues to use price cents and quantity
tenths. A sale of 0.1 ETH reserves 100 ETH units; buying 0.1 ETH at a maximum
price of 10 USDC reserves 1,000 USDC units. The same USDC balance finances
orders in every configured market that uses USDC.

Before matching, a buy reserves its full quantity at its effective worst price
(after any Market collar); a sell reserves its full base quantity. Reservations
reduce `available` and increase `reserved`. Fills consume both counterparties'
reserves, credit the acquired assets, and immediately return price improvement
to the buyer's available balance. A resting remainder keeps its own obligation.
Owner cancellation, IOC/Market remainder and delisting release that obligation
once. Insufficient funds and invalid complete plans reject before execution.
A funded command with a later accounting overflow rejects its entire plan.

`GET /market` reports `ledger_mode` and `asset_scale`. `GET /balances` returns the
versioned ledger snapshot: explicit mode/config/funding, applied sequence,
available/reserved balances and active order reservations. Values are integer
asset units. Existing `/positions` and `/pnl` report per-symbol PnL, which is
independent of the assets a funded account can spend. Snapshot restoration
checks asset conservation and exact backing of active obligations.

The root/store owner must commit the canonical ledger snapshot with books,
cursor and reference-price windows. Ledger snapshot roundtrip tests are not a
SQLite crash/restart or power-loss test. The integration contract is in
[LEDGER-INTEGRATION.md](LEDGER-INTEGRATION.md).
