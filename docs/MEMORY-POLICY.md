# Memory and admission policy

Recent reads are bounded independently of execution: the matcher retains 10000
recent trades, 200 recent messages and 4096 recent chain checkpoints. A command
can produce more than 10000 fills. `apply_message_with_trades` returns its complete
integer `TradeRow` batch in execution order and leaves durable changes queued.
Callers publish an authoritative batch only after its durable commit.

The stdio bridge retains ID mappings only for active orders. It translates a
complete command batch before removing completed makers and the incoming order.
Rejected, cancelled, fully filled and non-resting orders leave no mapping history.
An active harness ID cannot be overwritten; after closure it can be reused. Cancel
on the wrong market is refused. The harness's existing refusal vocabulary is
preserved: capacity and duplicate-ID refusals use `BadQty`; duplicate identity
details are written to stderr, and core capacity reasons remain in refusal counters.
Historical cancellations with no live mapping return `UnknownOrder`, account 0.
No historical-owner tombstone retention is promised by this protocol.

Stdio uses the synthetic matching/position semantics for external harness
comparison. It does not demonstrate funded account solvency. Its init accepts an
optional execution policy; defaults are shown here:

```json
{"type":"init","markets":[{"name":"M1","tick_size":0.01}],"stp":"reject_incoming","limits":{"max_active_orders":100000,"max_positions":100000,"max_symbols":4096}}
```

All limits are positive integer counts. At active-order capacity, every new
order is refused before execution, including an order that would immediately
cross and reduce the book. Cancels remain available and free active capacity.
Position capacity is checked over the whole reachable match before any fill.
Repeated maker accounts and self-match count once per account-symbol. Filled
positions retain cash, basis and realized PnL even when quantity returns to zero;
they are never erased to recover capacity. Delisted symbol identities also count
toward symbol capacity. Relisting the same identity needs no new slot.

Core legacy constructors retain their original execution policy. Bounded durable
executions must include `resource-limits-v1` in the versioned execution snapshot
and root. C supplies the implementation and serialization boundary; the durable
snapshot/root wiring belongs to the integrated recovery change. A payload is 28
bytes: u32 LE version 1, then u64 LE active-order, position and symbol capacities.
Restore applies it before loading state, validates loaded entity counts before
admission, and rejects unknown versions, malformed payloads or over-capacity state.
Missing payload identifies historical unbounded execution and is never replaced
silently with new defaults.

`--stdio-max-line-bytes` bounds one input line including its newline, default
1048576 bytes. An oversized line stops the adapter explicitly before parsing or
executing that command. Output is not truncated: every event and its `events_end`
terminator are written. Output and temporary changes grow with one command's
bounded active-maker count, not with all historical fills.

The feed has independent intake budgets, configurable with
`--feed-retention-limits path.json`. The default file content is:

```json
{"max_nonces":1000000,"max_accounts":100000,"max_inbox_records":1000000,"max_memory_messages":1000000,"max_batch_messages":100000,"max_retry_records":4096}
```

These are deployment admission settings: they decide whether a future submission
can become a message, and do not change execution of a message already published.
HTTP and inbox intake check headroom before taking IDs; the generator checks before
building a burst. Exhaustion returns an explicit refusal (HTTP 503), without a
receipt, cursor increment or partial batch publication. Account keys, spent nonces
and inbox-to-message pairings never expire or get evicted. A RAM-only feed also
stops at its proof-history capacity rather than forgetting published Merkle leaves.
Retry bookkeeping retains its prior backoff and give-up decisions; at capacity,
new inbox entries stay pending until capacity becomes available or the inbox epoch
changes. Existing entries may still retry and clear their tracking after success.

Restoring a feed with more required index entries than its configured budget fails
with a diagnostic. Operators can increase the budget and reopen the same history;
no reset or deletion is needed. Disk messages/trades remain semantic history and
are not pruned by these RAM policies. Recovered nonce indices stop growing at the
configured budget while streaming rows, rather than loading a partial index and
opening a replay path.

These are cardinality bounds and regression properties. They are not measurements
of allocator bytes, peak RAM, throughput or latency. The bridge preallocates its
event vector from the known command fill count; no performance claim follows from
that local allocation change.
