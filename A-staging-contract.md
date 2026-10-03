# A: FOK staging contract (2026-10-03)

Contract implemented. No ledger implementation in A. Book/positions/trades/pending settlement deltas stay intact on stage rejection; cursor and rejection counters may advance.

- `matcher::PlannedFill` is a crate-visible record: `maker_order: OrderId`, `maker_account: AccountId`, `price_cents: i64`, `qty_tenths: i64`.
- `step5_match_against_book::plan_fills(&IncomingOrder, &Book) -> Vec<PlannedFill>` walks actual matching price/FIFO priority (including dishonest build priority when enabled). It stops at the order quantity. No mutations.
- `step5_match_against_book::stage_fok(&IncomingOrder, &Book, &positions, trades_total) -> Result<FokPlan, Rejected>` produces the fill plan, validates full quantity, trade-ID capacity and cumulative position changes for every affected account. Sparse staging O(fills + affected accounts), no clone of books/history/global state.
- `FokPlan::fills(&self) -> &[PlannedFill]` is the ledger validation boundary. Ledger must stage its own cumulative effects/reservations against exactly this ordered slice before `execute_fok(order, plan, into)` consumes it. Any ledger rejection must happen BEFORE execute_fok; dropping the plan has zero execution effects. Do not validate fills independently against original balances.
- `execute_fok` commits exactly the staged fills/positions without a second matching walk or fallible position arithmetic. The synchronous caller must not change book/positions between staging and commit.
- Non-FOK keeps its existing per-fill checked semantics, with checked trade IDs. The plan is only allocated for FOK.
- FOK stage failures: insufficient reachable quantity -> unavailable; position/trade-ID overflow -> Rejected (position_overflow), with no execution effects. Incoming order never rests.

D/integrator: insert ledger reservation after bounds/self-trade checks; validate staged ledger against `plan.fills()` before execute_fok. On all failures release any incoming reservation. Non-FOK ledger must prevalidate both legs per fill before book/position mutation. A does not add funding, balances, reservations, schema or root format.

Non-FOK performs a read-only next-fill lookup then uses the same commit_fill bookkeeping as FOK. This avoids duplicated settlement/projection code; lookup cost is O(fills * log price levels). FOK staging is O(visited fills + affected accounts), and commit addresses planned maker levels directly. No throughput claim or speculative optimization.

Final implementation: PlannedFill is defined directly in matcher.rs (crate-visible); FokPlan remains step5-local with fills() accessible to the synchronous matcher caller. stage_fok returns Result<FokPlan, Rejected>. execute_fok addresses makers directly by planned price/id; it does not re-run next-fill selection. Both paths use commit_fill to keep records consistent.

Integration locations:
- FOK: in matcher.rs immediately after stage_fok succeeds and before constructing BookAndTrades / calling execute_fok. Stage ledger against plan.fills(); on failure return without execution.
- Non-FOK: in step5 execute(), after positions and trade ID validate and BEFORE commit_fill. Validate both ledger legs cumulatively (self-match uses one staged account).
- commit_fill emits Change::Traded/OrderClosed/OrderReduced only for confirmed fills. C can derive complete command batches from these deltas.

Arithmetic scope: the i64::MIN Position and >i64 liquidity fixtures test internal boundaries. No accepted real-world order history reaching that position/book total was reproduced; they are hardening, not additional audit loss findings. Unit/grid policy and wire representation are unchanged.