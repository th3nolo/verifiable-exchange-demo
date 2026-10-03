# C integration contract (in progress)

H9/H10 code is implemented. Final bounded library run: 587 passed, 0 failed,
15 ignored, 2 long-test filters. A real process regression emits 10001 Trade
lines in order and events_end. Rust 1.91.1, locked/offline, own .audit-target-c.

`MatcherState::apply_message_with_trades(&OrderMessage) -> Result<Vec<TradeRow>, ApplyError>`
returns every integer fill in order, including 10001 fills. It captures Change::Traded
from one call. Existing durable pending changes remain queued; volatile calls release
their temporary changes before returning. B must publish authoritative projections
only AFTER the commit; obtaining this batch alone is not publication authorization.
A/D must continue emitting Change::Traded only for applied fills. No step5 change
is needed for this API. stdio purges mappings only after translating the complete
batch, forbids overwriting active IDs, and permits reuse after close/cancel/reject.

Implementation now adds optional `matcher::ResourceLimits` (u64 counts for active
orders, account-symbol positions and all historical listing identities), configured
at genesis. Admission preflights capacity before any fill or ledger reserve. It
does not delete positions, delisted symbols or nonce history. Defaults for bounded
stdio: 100000 active orders, 100000 positions, 4096 symbols; limits configurable on
init. Legacy constructors preserve their historical policy pending B/D integration.

B: include Option<ResourceLimits> with the execution-state snapshot/config and
versioned root. No change to the existing state_root encoding or root-version tag
is delivered by C. B/integrator must connect this policy before publishing a
bounded durable/replay execution. Canonical bytes are three u64 LE fields, in the above order. Resume
must restore the exact policy, never silently apply defaults to a historical run.
C will expose policy getters and canonical bytes; no Store schema edits here.
`RESOURCE_LIMITS_EXTENSION = "resource-limits-v1"`.
`resource_limits_snapshot() -> Option<Vec<u8>>`: 28 bytes = u32 LE version 1 +
three u64 LE capacities. `ResourceLimits::from_snapshot_bytes` rejects length,
unknown version and zero capacities. `restore_resource_limits(Option<&[u8]>)`
applies the policy at genesis BEFORE loading counters/orders/trades, including
on a recording engine. `validate_resource_capacity()` runs AFTER reconstruction
and BEFORE root comparison/admission; it never truncates historical state.
Construct execution-state extensions from this runtime getter at root/commit
time; retaining a copy of bytes alone does not restore execution semantics.
The bounded constructor is initially restricted to volatile genesis so that a
configured policy cannot be silently lost in an existing snapshot schema.

D: admission check belongs after effective terms/bounds and self-trade checking,
before reserve/match. Position capacity is checked over all reachable candidate
fills, accounting once for repeated accounts and self-match. Do not admit one
fill and then reject a later fill for position cardinality. Ledger balances and
funding require a corresponding cardinality policy in D's configuration if their
account map can grow independently of actual positions.

Feed has separate `RetentionLimits` operational intake budgets: nonce and account
key indexes never expire; inbox pairings retain exact-once semantics; a RAM-only
Merkle history stops accepting messages at its configured cardinality. DB rows
remain intact. Checks happen before ids/allocation/generation; restore refuses
an over-capacity history instead of loading a partial index. CLI option
`--feed-retention-limits path.json` supplies limits. These settings decide intake
of FUTURE submissions, never execution of already sequenced commands.
Retry records are also bounded; exhaustion keeps new inbox entries pending and
preserves existing backoff/give-up decisions. No expired nonce replay path.

The active-order cap is conservative: at the cap, a new order is refused before
matching, including one that would immediately reduce the book. Cancels still
work and release active capacity. The rejection consumes a core message/counters;
it leaves execution effects unchanged. With B's new root those legitimate counter
and cursor changes may change the complete root.

## Validation and integration gates

- Library command: cargo test --manifest-path services/Cargo.toml --locked --offline --lib -- --skip the_generated_traffic_keeps_every_market_trading --skip every_pair_of_sizes_has_a_consistency_proof_that_verifies --quiet.
- Integration passes: anchor_flags 8, checker_imports 2, crash_restart 6,
  engine_rule_warning 3, order_types 10, public_release 13, stdio_retention 2.
- genesis was executed and FAILED before its shell workflow: its original
  Windows path is passed to /bin/bash and loses backslashes, so open-the-log.sh
  is not found. This is an environment/path limitation, not a passing result.
- Root/snapshot commitment of ResourceLimits is intentionally left for B's v5
  ExecutionState.extensions. Do not publish bounded durable executions with
  just a retained byte blob or a legacy root; restore semantic policy first.
- A's final commit_fill retains confirmed Change::Traded deltas; the batch API
  is compatible. D's reservation must occur AFTER C capacity admission. No
  changes to A's step5, Store schema or Ledger were made in C.
- No throughput/peak-RAM/allocation benchmarks, on-chain calls, Unix fault
  injection, live services, Docker or Go/Solidity checks were executed here.
- Evidence logs: .audit-target-c/final-unit-results.txt,
  final-integration-results.txt (includes genesis failure),
  remaining-integration-results.txt and final-stdio-unit-results.txt.
- Automatic approval review rejected a retention variant that rolled back ids
  and pruned generator references; the accepted implementation preflights BEFORE
  ids/generation and performs no retention-rejection rollback. It also rejected
  changing the bounded root outside B's ownership. No root-version change is
  included; serialization/restore APIs are delivered instead.
