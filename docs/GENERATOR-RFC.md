# Synthetic order-flow generator and market-health tests: specification and root-cause RFC

| Field | Value |
|---|---|
| Status | Proposed |
| Date | 2026-08-17 |
| Audience | Engineers fixing the synthetic order generator and building the market-health test harness |

**Abstract.** The demo exchange sometimes stopped trading for hours. The order
generator caused these episodes. The matching engine and tick regime did not.
This RFC specifies the replacement generator and the health checks that gate
load and performance tests.

**Key words.** **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**
have the meanings defined by RFC 2119 and clarified by RFC 8174. They appear
only in sections 4, 5, and 7. Section 5 tests each MUST. Reviewers can check
each SHOULD in the generator configuration or through section 5.

Evidence uses four grades.

| Grade | Meaning |
|---|---|
| [ESTABLISHED] | A textbook result or a result replicated across venues and decades. |
| [SINGLE-PAPER] | One study or calibration. |
| [INDUSTRY-PRACTICE] | A venue, regulator, or simulator convention. |
| [ENGINEERING-CHOICE] | A value this investigation chose because no published value exists. |

The RFC keeps disagreements between sources separate. It does not average
them into one answer.

---

## 1. Problem statement

The demo runs three synthetic spot markets with mids near 10, 100, and 1,000.
All three use a 0.01 price step. Forty accounts send about six messages per
second. They place GTC limit orders within 0.5% of an unanchored random-walk
mid. The exchange refuses self-trades.

Table 1. Measured facts.

| # | Fact | Value | Basis |
|---|---|---|---|
| 1 | Dead-market episodes | ~2 h with zero trades, then trading resumes spontaneously | observed |
| 2 | Resting depth | 1000+ orders/side, display cap reached | observed |
| 3 | Trade rate when alive | ~1 trade per 10 messages (0.1 trades/msg) | observed |
| 4 | Message rate | 6 msg/s (43,200 msgs per 2 h) | observed |
| 5 | Accounts | 40 | observed |
| 6 | Relative tick (10⁴·tick/price) | 10 / 1 / 0.1 bps for mids 10/100/1000 | computed from context; identical profile to the US flat-penny regime |
| 7 | Placement band width, ±0.5% in ticks | 10 / 100 / 1,000 ticks across the three markets | computed, a 100× dispersion scaling from one parameter |
| 8 | Placement rule | buys ≤ mid ≤ sells, uniform in band, GTC, never re-quoted; mid unanchored | observed |
| 9 | Self-trade prevention | engine rejects same-account matches | observed |

**Failure shape.** Trading stops for hours, then resumes without a regime
change. No fixed duration explains the pattern. Rate changes alter how often
it happens, not how it starts or ends. Meanwhile, each book grows to the
display cap. The screen shows more than 1,000 orders per side while no order
trades.

**Why correctness testing could not catch it.** Every engine invariant held
during the incident. The book never crossed. Price-time priority held.
Quantities balanced, no self-trades executed, and replay produced identical
bytes. Section 6 lists these checks.

The defect sits in the generated traffic. A correct engine cannot produce a
trade when the supplied orders cannot cross. Published venue suites test
participant systems. Regulatory rules test correctness, conformance, capacity,
and controlled stops. None requires a market to keep trading. Sections 5 and 8
give the sources.

The same defect invalidates a performance test. One published replay benchmark
reports a 0.07% match rate with a synthetic price band [^39^]. That test mostly
measured order insertion, not matching.

---

## 2. Terminology

- **Tick.** The smallest price change a market allows.
- **Relative tick.** The tick divided by price, in basis points. One basis point
  is 10⁻⁴.
- **Placement distance.** The signed distance between a limit price and its
  reference, measured in ticks. Unless stated otherwise, the reference is the
  best quote on the same side.
- **Mid.** The best bid plus the best ask, divided by two.
- **Reference price.** The fundamental, mid, or last trade around which the
  generator places new orders.
- **Crossing range.** The prices at which a new order executes against resting
  orders on the other side.
- **Correctness.** The per-event engine properties in section 6: priority,
  conservation, price, and determinism.
- **Liveness.** The market properties measured over time in section 5. Both
  sides stay populated, trades recur, and spread and depth remain in range.
  Correctness does not imply or test liveness.

---

## 3. Root-cause analysis

### 3.1 Attribution

Table 2. Failure attribution. The research tracks supply the citations, and H1
to H6 test the result.

| Item | Role | Mechanism | Confidence | Tracks |
|---|---|---|---|---|
| Unanchored random-walk mid + passive-clamped placement + static GTC book | **Primary cause** | The generator clamps buys at or below the mid and sells at or above it. The mid then walks away from the resting GTC orders. Trades occur only when the walk sweeps across old orders or lands on the same tick. Once the band and book separate, crossing probability approaches zero. Trading resumes when the walk returns. The cited stable models all tie flow to book state: CST [^5^], Kelly and Yudovina [^8^], Mike-Farmer [^4^], Maslov [^9^], and Preis [^11^]. This generator does not. | HIGH (H1, H2, H4) | T1, T3, T4 |
| Flat 0.01 tick across price levels | **Amplifier, not a cause** | The 0.5% band spans 10, 100, or 1,000 ticks, depending on the market. This makes the miss distance 100 times wider in tick terms. A fine tick alone cannot stop clearing. Binance clears with about 12 million ticks in the price [^28^]. The NYSE, US decimalization, and TSE all reduced ticks without stopping trade. | HIGH (H3) | T2 |
| Self-trade refusal with only 40 accounts | **Sharpener** | In the 10-tick-wide band, a fresh order frequently meets the same account's resting order; rejections thin exactly the crossing-eligible flow. | MEDIUM-HIGH | T1 |
| Cancellation ≪ arrival | **Contributor** | Depth reaches the display cap of more than 1,000 orders per side. Old orders dominate the book, so a trade depends on overlap with the placement band. Removal below inflow violates the direction proved by Abergel and Jedidi [^7^] and the measured per-queue balance [^6^]. | HIGH | T1 |
| Engine correctness | **Ruled out** | The two implementations and full-log replay agree. Section 6 records that evidence. The venue suites reviewed here do not test market liveness. | HIGH (H4 to H6) | T5, T6 |
| Tick fineness as standalone cause | **Ruled out** | See amplifier row. | HIGH (H3) | T2 |

### 3.2 Why trading resumes after a long gap

For a symmetric one-dimensional random walk, the chance of no return after
`n` steps is `S(n) = C(2n,n)/2^{2n} ~ 1/√(πn)` [^20^]. First-passage and
excursion lengths have heavy tails and no finite mean. Lévy's arcsine law also
makes extreme occupation times more likely than middle values [^21^].

The incident produced 43,200 messages in two hours. Let `σ` be the mid-price
step per message, measured in ticks.

Table 3. Random-walk excursion statistics for `σ = 1` tick per message.

The formulas are established [^20^][^21^]. This investigation estimated the
probabilities with 2,000 Monte Carlo paths of 43,200 steps, so confidence is
MEDIUM. All times scale with `(band/σ)²`. The incident's `σ` is unknown.

| Market (mid) | Band width (ticks) | P(escape band within 2 h) | Median time to escape band | P(longest outage > 1 h within 2 h) |
|---|---|---|---|---|
| 10 | 10 (half-band h=5) | ≈ 0.98 | ~55 msgs ≈ 9 s | **≈ 0.61** |
| 100 | 100 (h=50) | ≈ 0.81 | ~5,500 msgs ≈ 15 min | ≈ 0.39 |
| 1000 | 1,000 (h=500) | ≈ 0.016 | ~5.5×10⁵ msgs ≈ 25 h | ≈ 0.002 |

In the low-priced market, an outage longer than one hour is more likely than
not within a two-hour window. The walk's expected two-hour range is about
`331.7σ` ticks.

The incident had no trades for about two hours at six messages per second.
That implies a crossing probability at or below 10⁻⁴ to 10⁻⁵ per message. A
1% probability would have produced about two trades per minute. The observed
rate therefore agrees with almost no overlap between the band and the book.

### 3.3 Load-bearing caveat

Reference-price drift alone does **not** stop fresh orders from crossing. For
example, a buy at mid + 0.3% crosses a sell at mid − 0.2%.

A total stop needs passive clamping or self-trade blocking that removes every
crossing pair. Passive clamping means an order never crosses the current best
price on the other side. The incident stopped completely, so its generator
must have behaved that way. The healthy rate of one trade per ten messages is
consistent with band sweeps and exact mid ticks as the only trade paths.

Section 4 must therefore fix both parts. Re-centering the walk is not enough.
Placement must also follow the book.

The literature does not name the complete failure sequence. It starts with
drift, a static GTC book, and passive clamping. Trading then stops for hours and
resumes when the walk returns. The literature does cover its parts. Unbounded
zero-intelligence books either diverge or empty [^9^][^17^][^19^]. Static
replay books also stop representing a live market. Research tracks 1 and 3
record this gap. The section 5 reproduction documents the combined failure.

---
## 4. Normative specification of the fixed generator

This section is normative. Every quantity uses ticks, not a percentage of
price. A 0.5% band is 10 ticks at price 10 and 1,000 ticks at price 1,000.
Section 3 shows how that unit error amplified the incident.

### 4.1 Tick regime

- Each market MUST be assigned its own price-scaled tick. A single tick shared
  across markets whose prices differ by orders of magnitude MUST NOT be used.
- For demo-liquid markets, the relative tick MUST stay within `[0.5, 2]`
  basis points. This is an [ENGINEERING-CHOICE] based on the published range
  for liquid instruments. ESMA RTS 11 implies 1 to 2 basis points at prices
  10, 100, and 1,000 [^23^]. TSE tables are near one basis point at the top of
  each band [^24^]. Liquid CME contracts range from 0.1 to 1.5 basis points
  [^29^].
- The tick SHOULD be drawn from a 1-2-5 sequence.

Table 4. Tick assignment.

| Market | Mid | Tick | Relative tick |
|---|---|---|---|
| 1 | 10 | 0.001 | 1 bp |
| 2 | 100 | 0.01 | 1 bp |
| 3 | 1000 | 0.1 | 1 bp |

The tick must be fine enough to avoid forcing a wide spread. It must also be
coarse enough for orders to collect at the same prices. AMF reports a spread
of 1.5 to 2 ticks for liquid stocks and up to 5 for less liquid stocks
[^25^][^26^]. XTX reports 2 to 4 ticks for futures [^25^]. The flat tick
amplified the incident. It did not cause it.

### 4.2 Reference price and anchoring

- The generator MUST anchor the fundamental with an Ornstein-Uhlenbeck process.
  Its half-life MUST be measured in minutes. No published intraday calibration
  exists, so this is an [ENGINEERING-CHOICE]. ABIDES uses
  `κ = 1.67×10⁻¹⁶/ns`, which gives a half-life near 48 days [^22^]. That is an
  unanchored walk at intraday timescales. A half-life of minutes prevents the
  long excursions in section 3.2 while preserving short random-looking moves.
- Every placement MUST follow the book. Measure distance in ticks from the
  best quote on the same side, or from the last trade. The generator MUST NOT
  use an outside price that can drift away from the book. CST [^5^], Kelly and
  Yudovina [^8^], Mike-Farmer [^4^], Maslov [^9^], Farmer, Patelli, and Zovko
  [^10^], and Preis [^11^] all tie placement to book state.
- A market maker MUST cancel and replace quotes around the current mid every
  1 to 2 seconds. It MUST quote about ten price levels on each side. This
  [ENGINEERING-CHOICE] scales ABIDES from a ten-second wake-up at ten levels
  to the demo's six messages per second [^22^]. The reservation-price formula
  is `r = s − qγσ²(T−t)` [^16^].
- Value agents SHOULD trade when the mid moves away from the fundamental. Their
  orders pull the mid back.

### 4.3 Placement distribution

- Placement distance MUST follow a power law in ticks from the best quote on
  the same side. Use exponent `μ = 1`. Published measurements range from 0.6
  in Paris [^1^], through 1.0 on Nasdaq [^3^], to 1.5 on the LSE [^2^]. No
  value has cross-venue agreement. The chosen exponent is therefore an
  [ENGINEERING-CHOICE], and the configuration MUST record it.
- A simpler generator MAY use an exponential distribution with a mean from
  three to five ticks. Preis uses this form around the current quote [^11^].
  The chosen mean is an [ENGINEERING-CHOICE] consistent with the published
  spread of 1.5 to 5 ticks [^25^][^26^].
- About half of limit-order flow SHOULD land at or inside the spread. These
  orders have `Δ ∈ {−1, 0, +1}` ticks [^1^].
- The generator MAY draw placement depths from a Student-t distribution. This
  produces a heavy right tail and matches the measured return tail index near
  3 [^4^][^30^].

### 4.4 Order-type mix and flow balance

- Crossing or marketable events MUST make up one-sixth to one-quarter of all
  events. This is the zero-intelligence simulator default [^1^].
- For each queue, limit-order inflow MUST remain within a few percent of
  removal. In symbols, `λ_LO ≈ λ_MO + θ_cancel`. Measured gaps are about 2% to
  6% for liquid large-tick stocks [^6^]. Citigroup measured 2,204 against
  2,331 batches per second, GE 317 against 325, and GM 102 against 104. The
  generator MUST publish both sides so section 5 can check the balance.

### 4.5 Cancellation

- Every resting order MUST have an independent exponential cancellation clock.
  This makes cancellation at a price level proportional to its queue size,
  `θ(i)·x` [^5^]. A common simulator default is `Γ ≈ 10⁻³` per order per unit
  time [^1^].
- The clock MUST make 62% to 93% of limit orders end in cancellation. The
  measured values are 62.3% in Stockholm [^14^] and about 93% on Island and
  INET [^15^]. Paris in 2001 is a 10% outlier. The configuration MUST record
  its chosen rate.
- In steady state, executions plus cancellations MUST exceed limit-order
  inflow after the refill correction. In symbols, `λ^M + λ^C > λ^L`. Abergel
  and Jedidi prove this stability direction [^7^]. It keeps the book below the
  display cap.
- Cancellation probability MAY rise with an order's current distance from the
  opposite best quote. Reference [^4^] defines the distance-dependent form.

### 4.6 Activity/volatility state

- A changing activity state MUST control event intensity. Use a two-state or
  three-state switch, or a self-exciting Hawkes intensity with
  `n ∈ [0.5, 0.8]`. The message rate MUST have a nonzero floor. The floor is an
  [ENGINEERING-CHOICE] that keeps H2 and H3 passing in the quiet state. The
  range for `n` is also an [ENGINEERING-CHOICE]. Published estimates are near
  0.9 [^12^][^13^], but `n ≥ 1` makes the process unstable.
- The same state variable MUST scale both the message rate and placement
  dispersion. This makes volume and volatility move together.
- A zero-intelligence model does not produce volatility clustering on its own.
  Neither does the basic Mike-Farmer model. Gu and Zhou found that volatility
  needs memory in order aggressiveness, not only order signs [^18^]. A constant
  Poisson rate produces the four visible failures measured here: no clustering,
  multi-hour gaps, flat volume, and no correlation between volume and
  volatility. The changing state controls each of them.

### 4.7 Backstops

- After every event, each side of each book MUST hold at least 2 resting orders
  [^17^][^19^]. If a side empties, the generator MUST re-initialize the book
  around the current reference price.
- Total resting depth per side MUST remain strictly below the display cap of
  1,000 orders. Reaching the cap is an H5 health failure, not a normal operating
  point.

### 4.8 Summary parameter table

Table 5. Fixed-generator parameters.

| Parameter | Value | Source | Grade |
|---|---|---|---|
| Tick per market | 0.001 / 0.01 / 0.1 for mids 10/100/1000; relative tick ∈ [0.5, 2] bps | RTS 11 LB6 [^23^]; TSE [^24^]; CME [^29^] | [ESTABLISHED] band; [ENGINEERING-CHOICE] edges |
| Spread target | median 2 to 4 ticks; hard bounds 1 to 5 | AMF 1.5 to 2 [^25^][^26^]; XTX 2 to 4 [^25^] | [SINGLE-PAPER] ×2, consistent |
| Fundamental | OU, half-life of minutes | none published; ABIDES HL ≈ 48 d ≈ free [^22^] | [ENGINEERING-CHOICE] |
| Placement reference | ticks from same-side best quote / last trade | [^5^][^4^][^8^][^9^][^11^] | [ESTABLISHED] |
| Placement distribution | power law μ = 1, from [0.6, 1.5]; alt. exponential mean 3 to 5 ticks | [^1^][^2^][^3^]; [^11^] | [ESTABLISHED] family; exponent [ENGINEERING-CHOICE] from disputed range |
| Flow at/inside spread | ~50% of limit flow | BMP [^1^] | [ESTABLISHED] pattern |
| Crossing/market share | 1/6 to 1/4 of events | BMP [^1^] | [ESTABLISHED] simulator convention |
| Flow balance | λ_LO ≈ λ_MO + θ within ~2 to 6% per queue | Cont and de Larrard [^6^] | [ESTABLISHED] |
| Cancellation | per-order exponential clock; 62 to 93% die cancelled; removal > inflow | [^5^][^1^]; [^14^][^15^]; [^7^] | [ESTABLISHED] |
| Market-maker agent | re-quote around mid every 1 to 2 s, ~10 levels | ABIDES 10 s/10 levels [^22^]; Avellaneda-Stoikov [^16^] | [INDUSTRY-PRACTICE], scaled [ENGINEERING-CHOICE] |
| Activity state | regime/Hawkes, n ∈ [0.5, 0.8], non-zero floor; drives rate and dispersion | empirical n ≈ 0.9 [^12^][^13^]; Gu and Zhou [^18^] | [ENGINEERING-CHOICE] below [ESTABLISHED] level |
| Backstops | ≥ 2 orders/side after each event; re-init on empty side; depth < cap | Gu et al. 2021 [^17^]; McGroarty [^19^] | [ESTABLISHED] model-family norm |
| Optional heavy-tailed depth | Student-t placement depths | Mike-Farmer [^4^]; tail index ≈ 3 [^30^] | [ESTABLISHED] |

---

## 5. Market-health test suite (normative)

This section is normative. Run all six assertions for every market. One failed
assertion fails the run. The report MUST name the assertion, market, and time
window. Deutsche Börse measures market-maker performance after every add,
change, deletion, or execution [^35^]. These checks use the same cadence.

Table 6. Health assertions.

| ID | Assertion | Threshold | Cadence |
|---|---|---|---|
| H1 | TwoSidedBook | ≥ 99% of sampled instants; FAIL < 95% | sampled after every book event |
| H2 | MaxNoTradeGap | ≤ 60 s | continuous, per trade |
| H3 | TradeRateFloor | ≥ 0.02 trades/msg per 5-min sliding window | per message |
| H4 | SpreadWithinRange | median ∈ [1, 5] ticks; p95 ≤ 10 ticks | per event, 5-min sliding window |
| H5 | DepthAtTicks(10) | ≥ 10 orders/side AND total depth < display cap | per event |
| H6 | ResilienceAfterTrade | ≤ 100 msgs to return within H4/H5 bands | per trade |

### H1. `TwoSidedBook`

H1 samples the book after every event. It records whether both a best bid and a
best ask exist. At least 99% of samples MUST be two-sided. A result below 95%
is a hard failure. The 95% to 99% band prevents repeated pass/fail changes near
one boundary. This band is an [ENGINEERING-CHOICE].

Euronext's strictest SLP tier requires more than 95% presence [^33^]. Xetra
requires 90% for equities and 80% for ETPs [^32^]. The EU legal floor is 50%
of the day [^31^]. NYSE Rule 104 requires one-sided presence at the NBBO for
10% to 25% of the day [^34^]. This RFC uses the strictest source and then asks
for 99%. A synthetic venue with automatic quoting should beat the minimum set
for human market makers.

### H2. `MaxNoTradeGap`

H2 measures the longest wall-clock gap between trades. It runs continuously.
No gap MAY exceed 60 seconds.

The deployment cycles through 24, 69, and 114 messages per second, with a mean
of 69. At those rates, 60 seconds contains 1,440 messages in the quiet state
and 6,840 in the busy state. The check uses time because a message count no
longer represents a fixed duration.

No published threshold exists. The 60-second limit is an
[ENGINEERING-CHOICE]. The failure lasted two hours, or 43,200 messages at six
per second. Healthy trading took about ten messages between trades, or 1.7
seconds at that rate. The limit is about 35 times the healthy gap and 120 times
shorter than the failure. Section 9 measures the deployed quiet state at the
same 1.7 seconds.

### H3. `TradeRateFloor`

H3 divides trades by messages over a sliding five-minute window. Recompute it
after each message. The ratio MUST stay at or above 0.02. That means 144 trades
per quiet-state window and 414 at the deployed mean rate. Because this is a
ratio, the activity state does not move the threshold.

The limit is five times below the healthy rate of 0.1 trades per message. This
margin is an [ENGINEERING-CHOICE]. Production order-to-trade rules monitor the
same failure shape: messages greatly outnumber executions [^36^].

### H4. `SpreadWithinRange`

H4 measures best ask minus best bid in ticks. Recompute its distribution after
each event over a sliding five-minute window. The median MUST remain between
one and five ticks. The 95th percentile MUST NOT exceed ten ticks.

AMF reports an optimum of 1.5 to 2 ticks for liquid stocks and accepts up to
five [^25^][^26^]. XTX reports 2 to 4 ticks for futures [^25^]. SEC DERA finds
that fewer than 2 or more than 15 ticks sits outside the useful range [^27^].
The 95th-percentile limit of ten is an [ENGINEERING-CHOICE] inside that gap.

### H5. `DepthAtTicks(10)`

After every event, H5 counts resting orders within ten ticks of the best quote
on each side. Each side MUST hold at least ten such orders. Total depth MUST
remain below the display cap.

Published stable-book models keep at least two orders per side after every
event [^17^][^19^]. This RFC raises that floor to ten to form a usable ladder.
The higher floor is an [ENGINEERING-CHOICE]. Reaching the display cap repeats
the stability failure described by Abergel and Jedidi [^7^].

### H6. `ResilienceAfterTrade`

After each trade, H6 counts messages until H4 and H5 both pass again. Recovery
MUST take at most 100 messages. That is about four seconds in the quiet state
and 1.4 seconds at the deployed mean. A message count is appropriate here
because the check measures recovery work, not elapsed market time.

No published standard sets this limit. The [ENGINEERING-CHOICE] is about ten
times the healthy refill interval. Section 4.4 produces one crossing event per
roughly ten messages.

### Benchmark gate

Every load or performance test MUST run the health assertions at the same
time. Discard every measurement collected while an assertion fails. A dead
market measures order insertion, not matching. One published Binance replay
reported a 0.07% match rate with a synthetic band [^39^]. Other measurements
move throughput by about 3 times with operation mix [^47^] and 11 times with
cancel load [^38^]. A throughput or latency claim is invalid unless the market
stays healthy during the test.

---
## 6. Engine correctness invariants (informative)

This layer did not fail. The test harness still checks it. Published
property-based and model-based engine tests use the following invariants.

1. The book never remains crossed or locked after an event, except during an
   explicit auction.
2. Price-time priority always holds within each price level [^40^][^41^].
3. Submitted quantity equals fills plus remaining and cancelled quantity.
   Remaining quantity never becomes negative [^40^].
4. A trade uses the resting order's price, so the arriving order receives any
   price improvement.
5. The configured self-trade policy prevents self-trades [^41^].
6. A cancelled order never fills later [^41^].
7. The same input produces an identical byte stream [^38^][^41^].
8. A small reference model and the fast implementation agree
   [^38^][^42^][^43^].

This project already uses two independent implementations and full-log replay.
Industrial property tests compare implementations with reference models [^42^].
Formal venue work [^43^] and byte-level engine audits [^38^] use the same kind
of comparison.

A 2026 audit reports that only 47 of about 246 open-source engines passed its
comparison [^38^]. That number is [SINGLE-PAPER], self-reported, and changes
between paper versions. It gives context, not a reliable industry rate.

---

## 7. Relationship to existing practice

The project already uses the following three practices. This RFC does not
propose replacing or specifying them again.

- **Two implementations of every matching rule.** Industrial property tests
  commonly compare a fast implementation with a separate model [^42^]. Formal
  venue checks [^43^] and engine audits [^38^] use the same approach.
- **Full-log replay.** This matches byte-level replay checks [^38^][^41^]. The
  SEC Consolidated Audit Trail also records each order event so investigators
  can rebuild books later [^44^].
- **Twenty-eight injected failures.** Published finance examples cover server
  loss, latency, and failover. They do not publish numeric market-health limits
  [^45^]. Add market-health failures only after section 5 is in place.

This RFC adds the missing work: the generator in section 4 and the market-health
checks in section 5. Six literature searches found no published PASS/FAIL test
for market liveness. Venues do publish numeric obligations for market makers.
The checks adapt those obligations to generated traffic. Section 8 states the
research gap without claiming more than the searches found.

---

## 8. Open gaps and future work

1. **A proof for each match.** Work on verifiable exchanges covers solvency and
   fairness for batches or sequencing. SPEEDEX clears more than 200,000
   transactions per second under a batch rule that anyone can re-execute
   [^46^]. The searches found no real-time cryptographic proof that a central
   limit-order book used price-time priority for every match.
2. **Injected market-health failures.** The searches found no documented fault
   test that kills a market maker and asserts market recovery [^45^]. This can
   enter CI after section 5 does.
3. **A binary simulator gate.** Published work scores simulators against market
   facts. It does not use one pass/fail boundary. Vyetrenko et al. report gaps
   even in the strongest simulators they tested [^37^]. This RFC deliberately
   turns venue obligations into a binary gate.
4. **An intraday OU calibration.** No published calibration sets an intraday
   mean-reversion rate for simulated reference prices. ABIDES uses a half-life
   near 48 days, which acts like a free intraday walk [^22^]. Section 4.2 uses
   minutes as an [ENGINEERING-CHOICE]. A calibration study could replace it.
5. **A cross-venue order ratio.** The one-sixth to one-quarter range comes from
   one simulator's sensitivity study [^1^]. The measured flow balance in [^6^]
   supports it indirectly, but no ratio has cross-venue agreement.
6. **A possible research claim.** Six searches across test tools, regulation,
   and venue documents found no executable PASS/FAIL property for market
   liveness. Section 5 may be the first such test suite. The market-maker rules
   cited there are prior work and must stay attached to any publication claim.

---

## 9. What this repository's generator measures

This section is informative. It compares `services/src/feed/generate.rs` with
sections 4 and 5. The test
`the_generated_traffic_keeps_every_market_trading` sends 50,000 generated
messages from 40 accounts into a real `MatcherState`.

The test runs five cases. Three hold one activity state for the full run. One
switches between the three states. The last holds the old rate of six
messages per second.

Run these ignored tests to reproduce the tables:

- `cargo test --release --lib where_the_resting_orders_sit -- --ignored --nocapture`
  prints the detailed tables.
- `cargo test --release --lib what_this_configuration_measures -- --ignored --nocapture`
  prints one line per activity state.
- `cargo test --release --lib how_the_volume_varies -- --ignored --nocapture`
  prints the before-and-after volume measurements for three seeds.

Every normative subsection of section 4 and every assertion of section 5 has a
row, including requirements with no measurement. **Every row is measured three
times.** Each activity state gets its own run because every state must remain
healthy. One displayed number means all three runs agree to the shown digits.

| Section | Asks for | Measured at 24 / 69 / 114 msg/s | Held |
|---|---|---|---|
| 4.1 | each market gets its own price-scaled tick | 0.01 / 0.10 / 1.00 for mids 10 / 100 / 1000 | yes |
| 4.1 | the tick is drawn from a 1-2-5 sequence (SHOULD) | 0.01, 0.10 and 1.00 are all 1 × 10ⁿ | yes |
| 4.1 | relative tick in [0.5, 2] bps | 10 bps in each of the three markets | **no** |
| 4.2 | placement referenced to the book, never to a free-floating outside price | every order is priced from the book | yes |
| 4.2 | the fundamental anchored by an OU process, half-life of minutes | no OU process; a lean on the choice of side instead | **no** |
| 4.2 | a market-maker agent re-quotes around the mid every 1 to 2 s over ~10 levels a side | no such agent | **no** |
| 4.2 | value agents trade the mid against the fundamental (SHOULD) | no such agent | **no** |
| 4.3 | ~50% of limit flow at Δ ∈ {−1, 0, +1} ticks | 29.4% / 25.4% / 22.8% | close |
| 4.4 | 1/6 to 1/4 of events cross | 16.7% / 16.7% / 16.7% | yes |
| 4.4 | limit inflow matches removal within a few percent | +0.3% / +0.3% / +0.3% | yes |
| 4.5 | 62% to 93% of limit orders end cancelled | 66.6% / 66.6% / 66.6% | yes |
| 4.6 | a time-varying activity state drives rate and dispersion | three states, 24 / 69 / 114 msg/s, a third of the time each, each with its own placement width | yes, see below |
| 4.7 | ≥ 2 resting orders a side after every event | 22 / 110 / 204 at worst; 1 at 6 msg/s | at 24 msg/s and above |
| 4.7 | depth below the 1,000-a-side display cap | 56.1 / 165.5 / 274.4 mean; 85 / 229 / 343 worst | yes |
| H1 | two-sided book ≥ 99% of samples | 100.0% / 100.0% / 100.0% | yes |
| H2 | ≤ 60 s between trades | 1.5 s / 0.5 s / 0.3 s | yes |
| H3 | ≥ 0.02 trades a message | 0.056 / 0.056 / 0.056 | yes |
| H4 | spread median 1 to 5 ticks, p95 ≤ 10 | 1 and 3 / 2 and 3 / 2 and 4 | yes |
| H5 | ≥ 10 orders a side within 10 ticks | 24.8 / 13.5 / 11.1 | yes |
| H6 | ≤ 100 messages back inside the H4 and H5 bands after a trade | 28 / 30 / 30 messages at worst | yes |

The switching case's 600-minute run measures:

- 24.7% of orders at or inside the spread;
- 16.7% crossing events;
- 0.0% net inflow over removal;
- 66.7% of limit orders ending in cancellation;
- 22 orders on the thinnest side;
- mean depth of 193.3 orders per side and a maximum of 353;
- H1 at 100.0%;
- H2 at 1.5 seconds;
- H3 at 0.056;
- H4 at median 2 and 95th percentile 3;
- H5 at 14.2; and
- H6 at 35 messages.

Every assertion holds. The switching result does not hide a bad fixed state.
Each of the three fixed-state columns above runs for 150 minutes.

**Every assertion above can hold while the market looks dead.** A market that
trades each second at one price draws a flat line. Commit `af9968b` passed every
row in the table, but its price stopped moving.

A 25-minute deployment sample used 15-second candles. After that commit:

- the price band fell from 2.84% to 3.58% down to 0.83% to 1.00%;
- the candle body fell from 0.214% to 0.247% down to 0.113% to 0.153%; and
- volume per candle fell from 277 to 286 down to 118 to 123.

Section 5 checks none of those values. `what_this_configuration_measures`
reports them beside the assertions for each activity state.

| Read off 15-second candles | 24 msg/s | 69 msg/s | 114 msg/s | the states switching |
|---|---|---|---|---|
| price band over 25 minutes | 3.13% | 4.39% | 5.08% | 4.25% |
| candle body | 0.259% | 0.464% | 0.591% | 0.406% |
| volume in one candle | 276 | 793 | 1,311 | 698 |
| variation of volume in a 15-minute bucket | 0.018 | 0.009 | 0.007 | 0.328 |
| volume against volatility, over those buckets | −0.20 | −0.35 | +0.28 | +0.87 |
| trades a second, variance over mean | 0.18 | 0.08 | 0.07 | 1.48 |

The last three rows only mean something in the switching column. A fixed state
has one message rate. Its bucket volume changes only with sampled order size,
so a correlation over nine buckets is noise.

The first three columns each cover 150 minutes. The switching column covers 600
minutes, or 45 whole buckets. Its mean rate was 60.9 messages per second, not
69. A 600-minute window holds about 120 states, and the mean over that many
draws has a standard deviation of 3.9. **The value 69 is a long-run mean. It is
not a promise about one hour.**

**Section 4.1 passes per market but fails in basis points.** Each market has its
own price step. `MERKLE-USDC` uses 0.01 at a mid of 10. `ETH-USDC` uses 0.10 at
100. `BTC-USDC` uses 1.00 at 1,000. The definitions are in
`services/src/domain.rs:77-81`.

Each step is one-thousandth of its mid. The relative tick is therefore **10
basis points in all three markets.** Section 4.1 requires 0.5 to 2 basis points,
and Table 4 assigns one. Every market is five times above the upper bound.

The requirement does not move to match the code. Section 3 classifies the flat
tick as an amplifier, not a cause. This gap does not restore the dead-market
failure, so the table records it without blocking the current generator.

The gap changes the unit behind every spread and placement limit. A tick five
times too coarse makes a given spread five times smaller in ticks. H4 is
therefore easier to pass than section 4.1 intended. Its measured median is one
tick, the smallest possible spread.

Closing the gap requires dividing all three steps by ten. That takes more than
one constant edit. Existing `ListSymbol` messages record each step in the log.
A change needs a delist and new listing, or a new log. ENGINE.md sections 3 and
4.0 define that rule.

**Section 4.2 passes for placement but not for its two agents.** Every generated
order gets its price from the book. No outside number sets the price. This is
the section 4.2 rule that fixes the primary cause from section 3.

The other requirements are absent. There is no OU fundamental.
`ANCHOR_STRENGTH` keeps the mid near its listed price by changing the order
**side**, not its price. A market 5% above its listed price receives sells and
buys in a 60/40 split. At 20% away, the split reaches 90/10.

Over 50,000 messages, the mid stays 0.57% from the listed price on average and
1.95% away at worst. `services/src/feed/generate.rs:625-656` holds that
measurement. There is no market-maker agent and no value agent.

**Two bounds in section 4 fix a third number the section does not name.** A
crossing order in this generator used to remove every order at the price it
named. Write `N` for the orders it removes. The generator sends one crossing
order every `k` messages that are not cancels. The other `k − 1` messages are
quotes. A steady book receives as many quotes as the number of orders that
leave. The cancel count is therefore `k − 1 − N`.

```text
crossing share of all messages    T = 1 / (2k − N − 1)
share of limit orders cancelled   f = (k − 1 − N) / (k − 1)
```

Section 4.4 requires `T ≥ 1/6`. For any `N ≥ 1`, that requires `k ≤ 4`.
Section 4.5 requires `f ≥ 0.62`. At `k = 4`, that requires `N ≤ 1.14`.

**A crossing order that takes a whole level needs about one order at that
level.** This generator takes the quantity of the first order filled at that
price. `the_best_level` supplies the quantity, so `N` is 1.00 by construction.
`TAKE_EVERY` rotates crossing orders through the three markets and sets `k` to
4. The measured values are `N = 1.00`, `T = 16.8%`, and `f = 66.2%`.

The generator used to hold `N` near one by taking the thinner best level. That
rule consumed the choice of side. Side is the generator's only control over
price direction, so the price stopped moving. `a_level_to_take` holds the
measurement.

**Section 4.6 uses a three-state switch.** The states send 24, 69, and 114
messages per second. Each state occupies one-third of a long run. A sampled
state lasts five minutes on average and no more than 30 minutes. The next state
is one of the other two, chosen with equal probability.

`Activity` in `services/src/feed/generate.rs` implements the switch. It reads
only the sequencer's clock. The sequencer still holds no book and reads nothing
from the exchange.

**Section 4.6 sets the floor at 24.** The deployment used that rate before the
switch. H2 measures a 1.5-second gap there against its 60-second limit. H3
measures 0.056 against its 0.02 floor.

The floor is a generator constant. The `--rate` value sets the **mean** of the
three states. The generator computes them as
`24, RATE, 2 * RATE - 24`. Changing `RATE` moves the mean and peak but leaves
the measured floor at 24.

With `RATE: "24"`, all three states collapse to one. The result differs from the
old generator by fewer than two messages in 50,000. Lower test rates therefore
keep their old behavior. `docker/entrypoint.sh` defaults to 2, while CI uses 5.
`genesis.rs` uses 1 and `fault_injection.rs` uses 10. `crash_restart.rs` uses
1,000, which exceeds the ceiling and produces a fixed rate.

**The same state scales placement dispersion. That part moves the price.** The
state multiplies the section 4.3 placement band and the walk used when a sampled
price is occupied. The factors are 1, 2, and 3.

Scaling only the rate makes a busier market less volatile. The same 14-step
walk then faces a book that is 4.75 times deeper at the same prices. The table
changes one factor at a time over 150 minutes in each state.

| what the state scales | band at 24 | at 69 | at 114 |
|---|---|---|---|
| the rate only | 3.17% | 2.80% | 2.51% |
| the rate and the §4.3 band | 3.17% | 2.93% | 2.70% |
| the rate, the band and the walk (shipped) | 3.13% | 4.39% | 5.08% |

Volume in one 15-second candle rises from 276 to 793 to 1,311 across the three
states. In the first row, volume rises 4.75 times while volatility falls 21%.
The third row gives section 4.6 the direction it requires.

The first two rows predate `CANCELS_IN_A_ROW`. That cap changes a fixed-state
measurement by less than 2%. The third row measured 3.17, 4.37, and 5.03 before
the cap.

The third row has two costs. At the peak rate, H5 falls to 11.1 orders within
ten ticks. Its limit is ten, so this is the generator's smallest margin.

Factors of 1, 2, and 2 would keep H5 at 16.8. That choice was rejected because
the peak price band falls to 4.21%, below the mean state's 4.37%. Volume and
volatility would then move in opposite directions across the two busy states.

Section 4.3 also asks for about half of limit flow at
`Δ ∈ {−1, 0, +1}` ticks. A wider band moves that share from 29.4% in the quiet
state to 22.8% in the busy state. The table already marks 29.4% as **close**,
not passing. The busy state is another 6.6 percentage points away.

**A Hawkes intensity was considered and rejected.** Section 4.6 permits either
design. A Hawkes process has no maximum. Its mean is `mu / (1 - n)`. With the
floor of 24 as `mu`, the allowed `n ∈ [0.5, 0.8]` gives 48 to 120 messages per
second. The upper half exceeds the deployment's storage budget. A hard cap
would remove the heavy tail, which is the only benefit over a switch here.

**What the four visible failures measure now.** The table compares two
600-minute runs in 15-minute buckets. The first holds the old rate of 24. The
second switches states.

| tell | before, a flat 24 | with the states switching |
|---|---|---|
| no clustering, trades a second, variance over mean | 0.18 | 1.48 |
| multi-hour holes, longest gap with no trade | 1.5 s | 1.5 s |
| flat volume histogram, variation of volume in a bucket | 0.014 | 0.328 |
| zero volume-to-volatility correlation, over buckets | −0.02 | +0.87 |

The owner measured the third row from the live chart on 17 August 2026. Ten
buckets had mean volume of 7,307 units and a standard deviation of 135. The
variation was 0.019. This test measures 0.014 on the same flat shape.

`how_the_volume_varies` runs the same 600 minutes on three seeds, before and
after:

| seed | variation before → after | correlation before → after | the run's own mean rate |
|---|---|---|---|
| 20260816 | 0.014 → 0.328 | −0.02 → +0.87 | 60.9 |
| 20260817 | 0.014 → 0.264 | +0.12 → +0.82 | 70.8 |
| 20260818 | 0.013 → 0.330 | +0.06 → +0.88 | 65.5 |

The last column explains why the measurement uses three seeds. A 600-minute
window holds about 120 states. The mean over those draws has a standard
deviation of 3.9 messages per second, so one window rarely averages 69.

**The target for the third row is 0.3 to 0.4.** The five-minute dwell sets it.
For three states with equal mean dwell, variation over window `T` is
`sqrt(1800 t / T) / 69`. Here, `t` is mean dwell in seconds. The result is 0.16
at one minute, 0.35 at five minutes, and 0.50 at ten.

A real 24-hour crypto market often measures 0.5 to 1.0 over a day. Much of that
comes from traffic moving through Asia, Europe, and the United States. This
synthetic market has no trading day. Matching the larger value would require
inventing one.

Cost sets another upper bound. A wider rate range increases monthly disk use at
the same mean. A longer dwell also makes the quiet stretch resemble the dead
market in section 3.

**What it costs.** A mean of 69 messages per second produces 178.8 million
messages before the monthly restart. At the measured 331 bytes per message,
`feed.db` reaches 59.2 GB. The measurement is from 17 August 2026. The
deployment reserves space for two full windows and resets the volume monthly.

The shape of `--verify` does not change. It uses a 28 MB floor plus 0.87 bytes
per message, or about 184 MB for a 30-day log.

**The switch introduced one defect.** After a busy state, the book still holds
orders created at the busy rate. At 114 messages per second, the six book sides
hold 1,646 orders. Their mean life of 42 seconds makes 39 expire each second.
The quiet state can send only 24 messages in that time.

The generator initially spent every quiet-state message on cancellation. It
stopped quoting and crossing, so all three markets went 680 messages without a
trade. That gap lasted 28.3 seconds.

**`CANCELS_IN_A_ROW` fixes the defect.** It permits at most two consecutive
cancels and postpones the rest. The book drains more slowly while trading
continues. The worst gap falls to 35 messages, or 1.5 seconds. That matches a
fixed-rate state. Postponed cancels are not lost, so 66.6% of limit orders still
end in cancellation with or without the cap.

**The chart does not offer one-second candles.** It offers 5 seconds, 15
seconds, 15 minutes, 1 hour, and 4 hours. `services/static/app.js` defines those
buttons. A candle with no trade leaves a hole, and a reader cannot distinguish
that hole from a broken page.

The test still checks one-second candles. It drives the generator into a real
`MatcherState` with no other sender. The thinnest market fills 99.2% of its
candles in the quiet state, 100.0% in the other fixed states, and 97.5% while
switching.

Trade-count variance divided by mean is 0.18 in the quiet state, 0.08 and 0.07
in the other fixed states, and 1.48 while switching. Independent arrivals would
measure 1.0.

Fill follows message rate because each market receives a crossing order every
18 messages. At 2 messages per second, 11% of candles fill. The result rises to
33% at 6, 67% at 12, and 99% at 24. That is why 24 is the floor.

The switching column is the point of section 4.6. A fixed rate gives 0.18,
which clusters less than independent arrivals. Switching raises it to 1.48.

The test bound moved from 2.0 to 2.5. A healthy switch can reach 1.76 when a run
splits its time evenly between 24 and 114. The fault under test removes a whole
price level and measures 3.76 under the same mix. `MOST_CLUSTERING` records the
calculation.

That fill requires each crossing order to take about one resting order. An
order that empties the best price puts all its trades inside one second and
leaves later seconds empty. A higher message rate then makes each burst taller
without shortening the gaps. `./demo.sh` fills 99% to 100% of candles with the
generator alone.

**A second sender breaks the fill, and section 4 has no answer for it.**
`demo.sh` starts a bot beside the generator. The bot sends crossing limit
orders and takes the generator's resting orders. The sequencer holds no book
and executes nothing, so the generator cannot learn which orders disappeared.
Its next crossing order may name an empty price and trade nothing.

A 17 August 2026 run measured 300 one-second candles per market at 24 messages
per second. The generator alone filled 99% to 100% of them, and one cancel found
no order. With the bot, candle fill fell to 86% to 92%, and 466 cancels found no
order.

Another two-minute run used the mean rate of 69. The exchange ignored 118
generator cancels among 5,738 messages. The 2.1% rate is the same gap measured
another way.

This remains a gap. Section 4 specifies one generator as the only source of
flow. Section 5 also measures one sender. A generator that cannot observe
executions cannot maintain those limits against arbitrary outside orders.

---

## 10. References

[^1^]: Bouchaud, J.-P., Mézard, M. & Potters, M., "Statistical Properties of Stock Order Books: Empirical Results and Models", *Quantitative Finance* 2(4):251 to 256, 2002, https://www.marcmezard.fr/wp-content/uploads/2019/01/02_BMP_QF.pdf
[^2^]: Zovko, I. & Farmer, J. D., "The Power of Patience: A Behavioural Regularity in Limit-Order Placement", *Quantitative Finance* 2(5):387 to 392, 2002, https://doi.org/10.1088/1469-7688/2/5/309
[^3^]: Potters, M. & Bouchaud, J.-P., "More Statistical Properties of Order Books and Price Impact", *Physica A* 324(1 to 2):133 to 140, 2003, https://doi.org/10.1016/S0378-4371(02)01896-4
[^4^]: Mike, S. & Farmer, J. D., "An Empirical Behavioral Model of Liquidity and Volatility", *Journal of Economic Dynamics and Control* 32(1):200 to 234, 2008, https://arxiv.org/abs/0709.0159
[^5^]: Cont, R., Stoikov, S. & Talreja, R., "A Stochastic Model for Order Book Dynamics", *Operations Research* 58(3):549 to 563, 2010, https://doi.org/10.1287/opre.1090.0780
[^6^]: Cont, R. & de Larrard, A., "Price Dynamics in a Markovian Limit Order Market", *SIAM Journal on Financial Mathematics* 4(1):1 to 25, 2013, https://arxiv.org/abs/1104.4596
[^7^]: Abergel, F. & Jedidi, A., "A Mathematical Approach to Order Book Modeling", *International Journal of Theoretical and Applied Finance* 16(5):1350025, 2013, https://arxiv.org/abs/1010.5136
[^8^]: Kelly, F. & Yudovina, E., "A Markov Model of a Limit Order Book: Thresholds, Recurrence, and Trading Strategies", *Mathematics of Operations Research* 43(1):181 to 203, 2018, https://arxiv.org/abs/1504.00579
[^9^]: Maslov, S., "Simple model of a limit order-driven market", *Physica A* 278(3 to 4):571 to 578, 2000, https://arxiv.org/abs/cond-mat/9910502
[^10^]: Farmer, J. D., Patelli, P. & Zovko, I. I., "The Predictive Power of Zero Intelligence in Financial Markets", *PNAS* 102(6):2254 to 2259, 2005, https://pmc.ncbi.nlm.nih.gov/articles/PMC548562/
[^11^]: Preis, T., Golke, S., Paul, W. & Schneider, J. J., "Multi-agent-based Order Book Model of Financial Markets", *Europhysics Letters* 75(3):510 to 516, 2006, https://doi.org/10.1209/epl/i2006-10139-0
[^12^]: Hardiman, S. J. & Bouchaud, J.-P., "Branching-Ratio Approximation for the Self-Exciting Hawkes Process", *Physical Review E* 90(6):062807, 2014, https://doi.org/10.1103/PhysRevE.90.062807
[^13^]: Filimonov, V. & Sornette, D., "Quantifying Reflexivity in Financial Markets: Toward a Prediction of Flash Crashes", *Physical Review E* 85(5):056108, 2012, https://doi.org/10.1103/PhysRevE.85.056108
[^14^]: Hollifield, B., Miller, R. A. & Sandås, P., "Empirical Analysis of Limit Order Markets", *Review of Economic Studies* 71(4):1027 to 1063, 2004, https://doi.org/10.1111/0034-6527.00313
[^15^]: Hasbrouck, J. & Saar, G., "Limit Orders and Volatility in a Hybrid Market: The Island ECN", NYU Stern working paper, 2002, http://pages.stern.nyu.edu/~jhasbrou/Research/
[^16^]: Avellaneda, M. & Stoikov, S., "High-Frequency Trading in a Limit Order Book", *Quantitative Finance* 8(3):217 to 224, 2008, https://doi.org/10.1080/14697680701381228
[^17^]: Gu, G.-F., Zhou, W.-X. et al., "An Empirical Behavioral Order-Driven Model with Price Limit Rules", *Financial Innovation*, 2021-11-01, https://link.springer.com/article/10.1186/s40854-021-00288-4
[^18^]: Gu, G.-F. & Zhou, W.-X., "Emergence of Long Memory in Stock Volatility from a Modified Mike-Farmer Model", *EPL*, 2009, https://arxiv.org/abs/0807.4639
[^19^]: McGroarty, F., Booth, A., Gerding, E. & Chinthalapati, V. L. R., "High Frequency Trading Strategies, Market Fragility and Price Spikes: An Agent Based Model Perspective", *Annals of Operations Research* 282:217 to 244, 2019, https://link.springer.com/article/10.1007/s10479-018-3019-4
[^20^]: Redner, S., *A Guide to First-Passage Processes*, Cambridge University Press, 2001, https://doi.org/10.1017/CBO9780511606014; and Sparre Andersen, E., "On the Fluctuations of Sums of Random Variables", *Math. Scand.* 1:263 to 285, 1953, https://www.mscand.dk/article/view/10555.
[^21^]: Feller, W., *An Introduction to Probability Theory and Its Applications*, Vol. I, 3rd ed., Wiley, 1968; Lévy's 1940 arcsine law as restated in Fang, Gan, Holmes, Huang, Pekoz, Rollin, Tang, "Arcsine Laws for Random Walks Generated from Random Permutations", arXiv:2001.08857, 2020, https://arxiv.org/pdf/2001.08857
[^22^]: ABIDES, `config/rmsc03.py` (RMSC-3 reference configuration: oracle κ = 1.67×10⁻¹⁶/ns ⇒ half-life ≈ 48 d; market maker wakes every 10 s, quotes 10 levels around the current mid), abides-sim/abides, GitHub, retrieved 2026-08-16, https://github.com/abides-sim/abides/blob/master/config/rmsc03.py
[^23^]: European Commission, Commission Delegated Regulation (EU) 2017/588 (RTS 11, MiFID II tick-size regime; liquidity band LB6 ⇒ 1 to 2 bps at prices 10/100/1000), adopted 2016-07-14, in force 2018, https://ec.europa.eu/finance/securities/docs/isd/mifid/rts/160714-rts-11_en.pdf
[^24^]: Japan Exchange Group, "Tick Size: Trading Rules of Domestic Stocks" (TOPIX 500: ~1 bp relative tick at band tops), JPX/TSE, accessed 2026-08, https://www.jpx.co.jp/english/equities/trading/domestic/07.html
[^25^]: Mackintosh, P., "The Tick Spreads That Help Stocks Trade Best" (AMF 500-stock study: optimal spread 1.5 to 2 ticks liquid, up to 5 less liquid; XTX: 2 to 4 ticks), Nasdaq, 2023-03-02, https://www.nasdaq.com/articles/the-tick-spreads-that-help-stocks-trade-best
[^26^]: NYSE Euronext/AMF, "Tick Size Regimes in the European Union" (comment letter; optimal tick ⇒ average spread between 1.4 and 2 ticks), submission to SEC, File 4-657, 2013-02-05, https://www.sec.gov/comments/4-657/4657-8.pdf
[^27^]: SEC DERA, "Tick Sizes and Market Quality: Revisiting the Tick Size Pilot" (<2 ticks intra-spread favors finer tick; >15 favors coarser), SEC working paper, 2022-11-28, https://www.sec.gov/files/dera_wp_ticksize-pilot-revisit.pdf
[^28^]: Binance, Spot API exchangeInfo, BTCUSDT PRICE_FILTER tickSize 0.01 at ~$120,000 (≈ 0.0008 bp, ~12M ticks in the price; recorded via CCXT issue #16441), 2023-01-11, https://github.com/ccxt/ccxt/issues/16441
[^29^]: CME Group contract specifications (ES 0.25 @ ~6,500 ≈ 0.38 bp; NQ ≈ 0.11 bp; ZN ≈ 1.4 bps; CL ≈ 1.4 bps; GC ≈ 0.3 bp), via Schwab explainer, 2026-03-16, https://www.schwab.com/learn/story/stock-index-futures-tick-values, and QuantVPS compilation, 2025-07-15, https://www.quantvps.com/blog/futures-tick-values
[^30^]: Gopikrishnan, P., Plerou, V., Amaral, L. A. N., Meyer, M. & Stanley, H. E., "Scaling of the Distribution of Fluctuations of Financial Market Indices" (tail index α ≈ 3), *Physical Review E* 60(5):5305, 1999, https://finance.martinsewell.com/stylized-facts/distribution/Gopikrishnan-etal1999.pdf
[^31^]: European Commission, Commission Delegated Regulation (EU) 2017/578 (RTS 8: two-way quotes of comparable size, divergence ≤ 50%, at competitive prices ≥ 50% of daily trading hours; venues must continuously monitor compliance), 2016-06-13, in force 2018-01-03, https://eur-lex.europa.eu/eli/reg_del/2017/578/oj/eng
[^32^]: Deutsche Börse Xetra, "Regulated Market Maker / Designated Sponsors" (DS presence 90% equities, 80% ETFs/ETPs), page current 2026, https://www.eurexgroup.com/xetra-en/trading/trading-models/liquidity-through-designated-sponsors/regulated-market-maker
[^33^]: Euronext, "Market Maker & Liquidity Provider Trading Fee Guide: Cash Markets" (SLP qualifying order > €5,000, lifetime > 30 ms; > 95% presence tier), effective 2024-07-01, https://www.euronext.com/sites/default/files/2024-06/market_maker_liquidity_provider_trading_fee_guide_euronext_cash_markets_effective_01jul2024.pdf
[^34^]: SEC, SR-NYSE-2023-36 (Release 34-98869; NYSE Rule 104 DMM floors: bid or offer at NBBO ≥ 15%/10% of the day by ADV; ETPs ≥ 25%), 2023-11-06, https://www.sec.gov/files/rules/sro/nyse/2023/34-98869.pdf
[^35^]: Deutsche Börse, "Handbook for Regulated Market Makers" (spread/size/presence formulas; measurement on every add/modify/delete/execution event), version 2025-11-10, https://www.cashmarket.deutsche-boerse.com/resource/blob/4902620/320e78a8a6ae44d6822d4928d72f0ac8/data/Regulated%20Market%20Maker%20Handbook_DB_de_en.pdf
[^36^]: Eurex, "Order to Trade Ratio" (quote-performance metric: covered time ÷ available time; OTR regime policing message-vs-trade traffic shape), concept paper, ~2015, https://www.eurex.com/resource/blob/249842/768a6bd24efc1fe684ac14beb730d382/data/concept_otr_15.pdf
[^37^]: Vyetrenko, S., Byrd, D., Petosa, N., Mahfouz, M., Dervovic, D., Veloso, M. & Balch, T., "Get Real: Realism Metrics for Robust Limit Order Book Market Simulations", ACM ICAIF 2020, https://arxiv.org/abs/1912.04941
[^38^]: flash1-dev, "The World's Fastest Matching Engine Algorithm" (byte-identical SHA-256 stream oracle from three independent engines; ~47 of ~246 engines correct as shipped; cancel-path throughput effect ~11×), arXiv:2606.01183, v1 2026-05-31 through v6, https://arxiv.org/html/2606.01183v3, [SINGLE-PAPER], numbers unstable across versions
[^39^]: shrey0303, "Lmax-disruptor-crypto-exchange" (Binance-replay benchmark; 0.07% match rate from synthetic price distribution; 67% risk-rejection under stress), GitHub, 2025-08-07, https://github.com/shrey0303/Lmax-disruptor-crypto-exchange
[^40^]: Jkrish1011, "order-match-engine-rs" (proptest invariants: quantity conservation, monotonic FIFO within price levels, never-negative remaining; deterministic replay), GitHub, 2025-10-13, https://github.com/Jkrish1011/order-match-engine-rs
[^41^]: Capataina, "Nyquestro" (property tests: price-time priority never violated, no self-match, partial fills sum correctly, cancelled orders never fill; byte-for-byte golden determinism; Nasdaq ITCH replay), GitHub, 2025-06-30, https://github.com/Capataina/Nyquestro
[^42^]: Goldstein, H., Cutler, C., Dickstein, C. & Pierce, B. C., "Property-Based Testing in Practice" (30-interview industry study incl. Jane Street; differential/model-based properties overrepresented), ICSE 2024, https://harrisongoldste.in/papers/icse24-pbt-in-practice.pdf
[^43^]: Ignatovich, D. & Passmore, G., "Transparent Order Priority and Pricing" (Imandra verification goals over the SIX Swiss Exchange trading-guide venue model; fill price independent of client ID), Aesthetic Integration, ~2016, https://www.imandra.ai/download/AI-Transparent-Order-Priority-and-Pricing.pdf
[^44^]: Exegy, "Navigating the Consolidated Audit Trail" (SEC Rule 613 CAT: full order-lifecycle reporting for ex-post book reconstruction), 2022-04-05, https://www.exegy.com/navigating-consolidated-audit-trail/
[^45^]: Chaos Engineering Stories, curated industry record of chaos/fault-injection programs (LSEG, J.P. Morgan, Goldman Sachs, Fidelity, Capital One, Bloomberg, DTCC; infrastructure resilience only, no market-quality SLOs), accessed 2026-08, https://chaosengineeringstories.com/
[^46^]: Ramseyer, G., Goel, A. & Mazières, D., "SPEEDEX: A Scalable, Parallelizable, and Economically Efficient Decentralized EXchange" (>200k tx/s; verifiable batch clearing), USENIX NSDI 2023, https://arxiv.org/abs/2111.02719
[^47^]: raja611, "Order-Matching-Engine (C++20)" (measured engine throughput swings ~3× with the operation mix), GitHub, 2026-03-14, https://github.com/raja611/Order-Matching-Engine

---

## Appendix A. Evidence by research track

### Track 1. Order-flow models

Every stable limit-order-book model reviewed here ties flow to book state. CST
prove stability when arrivals use distance from the opposite best and
cancellation grows with queue size [^5^]. Kelly and Yudovina use distance from
the quotes [^8^]. Abergel and Jedidi require removal to exceed inflow [^7^].

The useful measurements are these:

- Market orders make up one-sixth to one-quarter of events in the BMP
  simulation.
- About half of Paris orders land at or inside the spread.
- Measured placement exponents are 0.6 in Paris, 1.0 on Nasdaq, and 1.5 on the
  LSE. The sources do not agree on one value.
- Cancellations end 62.3% of Stockholm orders and about 93% of Island orders.
- Per-queue inflow and removal differ by about 2% to 6% in the measured stocks.

An unanchored reference produces trade gaps with first-passage survival near
`1/√(πn)`. Long stops followed by a return are expected under that model.

### Track 2. Tick size

The demo's flat 0.01 tick equals 10, 1, and 0.1 basis points in its three
markets. Its 0.5% placement band spans 10, 100, and 1,000 ticks.

Real venues scale ticks with price. ESMA targets 1 to 2 basis points for its
most liquid band. TSE is near one basis point, and liquid CME contracts range
from 0.1 to 1.5. AMF reports good spreads at 1.5 to 2 ticks. XTX reports 2 to 4.
DERA finds breakpoints below 2 and above 15 ticks inside the spread.

No recorded tick reduction stopped clearing. Binance clears with about 12
million ticks in the price. TSE's 2014 change reduced effective half-spreads
from 5.55 to 1.79 basis points. A fine tick widens this generator's placement
in tick units, but it cannot block a match. The incident's zero-trade stretch
implies a crossing probability at or below 10⁻⁴ to 10⁻⁵ per message.

### Track 3. Reference price

The reviewed models use four designs: placement around current quotes, an
outside fundamental with value traders, reservation-price quoting, or book
state with resets. ABIDES uses `κ = 1.67×10⁻¹⁶/ns`, a half-life near 48 days,
and refreshes ten quote levels every ten seconds. No source gives an intraday
OU calibration.

For `σ = 1` tick per message over 43,200 messages, the expected range is
`331.7σ` ticks. Escape probability is 0.98, 0.81, and 0.016 for bands of 10,
100, and 1,000 ticks. Median escape time is 9 seconds, 15 minutes, and 25 hours.
The chance of an outage longer than one hour is 0.61, 0.39, and 0.002 in the
2,000-path simulation.

Drift alone does not stop fresh orders from crossing. A total stop also needs
passive clamping. The literature does not name that combined failure.

### Track 4. Visual realism

Zero-intelligence and basic Mike-Farmer flow do not produce volatility
clustering. Gu and Zhou found that the model needs memory in order
aggressiveness, not only order signs [^18^]. Published Hawkes estimates put the
branching ratio near 0.9, although sources disagree on its trend. This RFC uses
0.5 to 0.8 for stability. Other targets include a return-tail index near 3 and
five-minute FX excess kurtosis of 21.5. The two-hour trade gap matches an
unanchored walk with a constant Poisson arrival rate.

### Track 5. Engine tests

CME AutoCert+, Nasdaq INET, LSE MIT501, and Deutsche Börse T7 certify systems
used by participants. The searches found no public test plan for a venue's own
engine. Section 6 instead draws from open-source property tests, Imandra's
formal venue work, and the 2026 comparison of independent engines.

Operation mix moves measured throughput by about 3 times. Cancel-heavy tests
show an 11-times gap on that path. Coordinated omission has understated tail
latency by 200 to 2,600 times. One synthetic price band reduced a replay test's
match rate to 0.07%.

### Track 6. Market health as a test property

The searches found no published pass/fail liveness assertion. They did find
numeric duties for participants. RTS 8 requires two-sided quotes for at least
50% of the day. Xetra requires 90% or 80% presence, depending on the product.
Euronext has a tier above 95%. NYSE Rule 104 uses 10% to 25%. Deutsche Börse
measures after each book event.

Market-wide circuit breakers bound prices, not liveness. Published fault tests
in finance cover infrastructure. Simulator studies grade results instead of
setting a binary gate. SPEEDEX proves batch fairness, not price-time priority
for each match.

---

## Appendix B. Quick-reference card

### B.1 Fixed generator

This table can stand alone.

| Parameter | Value | Basis (ref §10) |
|---|---|---|
| Tick (mids 10/100/1000) | 0.001 / 0.01 / 0.1; relative tick ∈ [0.5, 2] bps | [^23^][^24^][^29^] + [ENGINEERING-CHOICE] edges |
| Fundamental | OU around market anchor, half-life of minutes | [ENGINEERING-CHOICE]; no published intraday κ [^22^] |
| Placement reference | ticks from same-side best quote, never an external free-floating price | [^5^][^4^][^8^] |
| Placement distribution | power law μ = 1 (range [0.6, 1.5]) or exponential mean 3 to 5 ticks; ~50% of flow at/inside spread; optional Student-t | [^1^][^2^][^3^][^11^][^4^] |
| Crossing/market share | 1/6 to 1/4 of events; λ_LO ≈ λ_MO + θ within ~2 to 6% per queue | [^1^][^6^] |
| Cancellation | per-order exponential clock; 62 to 93% of limits die cancelled; removal > inflow | [^5^][^14^][^15^][^7^] |
| Market maker | cancel/re-quote around current mid every 1 to 2 s, ~10 levels/side | [^22^][^16^], scaled [ENGINEERING-CHOICE] |
| Activity state | regime switch or Hawkes n ∈ [0.5, 0.8], non-zero floor; scales message rate and dispersion | [^12^][^13^][^18^] |
| Backstops | ≥ 2 orders/side after every event; re-init on empty side; depth < 1000/side cap | [^17^][^19^] |

### B.2 Health thresholds

This table can stand alone. Apply every row to every market. Any breach fails
the run.

| Assertion | Threshold | Basis (ref §10) |
|---|---|---|
| TwoSidedBook | ≥ 99% of post-event samples; FAIL < 95% | Euronext SLP > 95% [^33^]; Xetra 90% [^32^]; RTS 8 ≥ 50% [^31^] |
| MaxNoTradeGap | ≤ 60 s, measured on the clock (1,440 msgs in the quiet state at 24 msg/s, 6,840 in the busy one at 114) | [ENGINEERING-CHOICE], ~35× above healthy (~1.7 s), 120× below observed failure (2 h) |
| TradeRateFloor | ≥ 0.02 trades/msg per 5-min window | [ENGINEERING-CHOICE], 5× below healthy 0.1; OTR-regime analogy [^36^] |
| SpreadWithinRange | median ∈ [1, 5] ticks; p95 ≤ 10 | AMF 1.5 to 2 / ≤5 [^25^][^26^]; XTX 2 to 4 [^25^]; DERA <2/>15 [^27^] |
| DepthAtTicks(10) | ≥ 10 orders/side AND total < display cap | min-depth norm ≥ 2 [^17^][^19^]; Abergel and Jedidi [^7^]; ≥10 is [ENGINEERING-CHOICE] |
| ResilienceAfterTrade | ≤ 100 msgs (~4 s in the quiet state at 24 msg/s, ~1.4 s at the deployed mean of 69) | [ENGINEERING-CHOICE], ~10× healthy refill time; no published standard |
| Gate | per the §5 meta-requirement, the health assertions run concurrently with any load/performance test; failing run invalidates the benchmark | 0.07% match-rate replay benchmark [^39^]; mix effects ~3× [^47^] / ~11× [^38^] |

*End of document.*
