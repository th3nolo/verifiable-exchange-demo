# Integrated execution contract

The integrated branch combines the component staging contracts. Their standalone
validation reports remain historical records; this document describes the
combined runtime.

`MatcherState::execution_state()` constructs `ledger-v1` from the current typed
ledger and `resource-limits-v1` from the current policy at every root and pending
commit boundary. Both travel in `Change::ExecutionState` inside the same SQLite
transaction as book/trade changes, counters and the signed claim. Cancellation,
rejection, IOC/FOK completion and delisting cannot leave a cached ledger payload
behind the execution cursor.

Recovery validates supported extension names and versions, restores the resource
policy before loading entities, restores ledger balances and reservations after
book reconstruction, and checks resource capacity and exact open-order obligations
before comparing the authenticated root. Missing execution payloads in consumed
v5 states fail closed. An empty legacy run can initialize explicit genesis.
Startup persists genesis even before consuming a message and refuses a different
requested mode or funding configuration on restart.

`ExecutionGenesis` contains mode, original funding configuration and resource
limits. It carries no current balances or reservations. The claims envelope and
local audit reader supply this policy to replay before message one. Changed
funding or admission policy changes the replayed roots and cannot verify existing
signed claims. Historical v4 auditing keeps its original root encoding.

FOK stages the full immutable fill plan and cumulative position transitions.
`funded::stage_fok_ledger` reserves and settles precisely those fills on a private
ledger before execution consumes the plan. FOK does not settle twice. Non-FOK
preflights funded effects and settles each actual fill before book/position/trade
mutation. Resource admission checks precede either path's reservation or fills.

The durable poller applies a batch to a private candidate. A successful Store
commit publishes that candidate and its tick; a failure keeps the preceding
published state and pauses execution. No-state-db remains explicitly volatile.
A new feed session starts a separate run with the same genesis funding and
resource policy; it does not replace the old run's history.

All amounts remain integer minor units in authoritative accounting. Every asset
uses thousandths: 0.1 base asset is 100 ledger units, while the matcher quantity
is one tenth. Fees remain explicitly zero. This is simulated accounting with
no custody or real-money execution.

Candidate cloning still costs O(current state) per batch. Process/SQLite failures
do not establish power-loss durability; throughput and peak-memory benchmarks
remain separate from functional validation.
