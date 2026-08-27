# The trading bot

`--start-bot` runs the bot. The bot reads the sequencer's messages and rebuilds
the book from them. It then estimates a fair value for each symbol. Fair value
is the bot's own estimate of what one unit is worth right now. The bot buys
resting orders priced below that estimate, and sells resting orders priced
above it.

```bash
# against a running sequencer and exchange
cargo run --release -- --start-bot

# against generated messages, no servers needed, repeatable
cargo run --release -- --backtest-bot 120000 --backtest-seed 1
```

The bot signs every order and every cancel it sends, [like any other
caller](API.md#signing-a-submission). Its key is `--bot-key`, and the file
defaults to `bot.key`. The bot makes the key on the first run and then keeps
it. A new key on every restart would be refused, because the account is already
pinned to the old key. Its account is `--bot-account`, and the id defaults to
999. The first run under a given account id pins the pair of account and key.
After that only that key can trade as that account. The backtest signs nothing,
because it never uses HTTP.

## Where the profit comes from

Not from predicting the random number generator. The generator in
`services/src/feed/generate.rs` uses `StdRng::from_entropy()`, seeded by the
operating system. Its output is not predictable, and the bot does not try to
predict it. A test or a measurement calls `seeded_rng` instead, so that run
repeats. The profit comes from the *shape* of the distribution the generator
draws from. That shape is fixed and public.

**Every profit number in this document was measured with `--backtest-bot`, and
the backtest draws from its own copy of the generator.** `SimFeed` in `bot.rs`
says it matches `feed::generate_message` exactly. It does not. That function
moved to `services/src/feed/generate.rs:584`, and what it does was replaced on
16 and 17 August 2026. `SimFeed` was not rewritten with it, and still draws a
cancel with `gen_bool(0.15)`, walks the mid with `U(-0.002, 0.002)`, and picks
a side with `gen_bool(0.5)`. So each claim below is stated twice: what
the backtest does, which is what the profit numbers measure, and what the
sequencer publishes now.

Two words are used below. The mid is the price halfway between the best bid and
the best ask. One bp is one hundredth of one percent, so 100 bps is 1 percent.

- **In the backtest the side of an order is drawn on its own, and not from its
  price.** `SimFeed::next` takes `side` from its own `gen_bool(0.5)`. So a
  resting order carries no information about where the price is going. Nobody in
  that market knows more than the bot does. On a real venue somebody does, and
  buying below the mid is then a way to trade with somebody who already knows
  the price is falling. That risk does not exist in the backtest.

  **The sequencer leans the side.** `pick_side` measures how far the book's mid
  sits from the price the market was listed at. It multiplies that share by
  `ANCHOR_STRENGTH` (2.0), holds the result inside `ANCHOR_LIMIT` (0.4), and
  shifts the coin by it. A market above its listed price gets more sells. A
  market below it gets more buys. At 5% away the split is 60/40, and at 20% away
  and beyond it is 90/10. An order therefore does say something about where the
  price is going: it says the market is above or below its listed price. That
  reading costs the bot nothing, because the listed price is in `SYMBOLS` and
  the book mid is in the messages the bot already reads. Nobody holds that
  reading alone, so the argument above survives.
- **In the backtest the mid has no direction.** `*mid *= 1.0 + U(-0.002, 0.002)`
  has expectation `mid`, so the next mid is expected to equal the current one. A
  position entered below fair value is therefore expected to stay profitable,
  rather than to move back.

  **The sequencer keeps no such mid.** It prices every order from the book. A
  quote sits 1 to 10 price steps behind the other side's best price, and a
  crossing order names the exact price of the level it takes. One price is kept
  outside the books: the price the market was last seen at. `remember_the_price`
  writes it, and a quote reads it only when the side it quotes against is empty.
  The direction now comes from `pick_side`, and it points at the listed price. A
  position held while the market is above its listed price therefore faces a mid
  that is pulled down, and not a mid that is expected to stay.
- **A resting order keeps the price it was placed at, and the mid keeps
  moving.** The standard deviation is 11.55 basis points per later order in
  that symbol.
  The generated traffic only clears a stale order when one of its own random
  arrivals happens to cross it. Measured against the true mid in the backtest,
  the best ask sits *below* the mid between 35% and 53% of the time. The mid
  falls outside the bid-ask spread between 85% and 92% of the time. Those three
  numbers were measured against the generator that
  `services/src/feed/generate.rs` replaced. `SimFeed` still reproduces them.

  **The sequencer's books are tight now.** A 50,000-message run used 40 accounts
  at 24 messages a second. In that run, 93.2% of resting orders sat within 1%
  of the mid. The spread was 1 price step at the median and 3 at the 95th
  percentile. Each side held a mean of 59.1 orders. Every generated order also
  gets a life, so 66.0% of limit orders end in a cancel and not in a trade. A
  stale order far from the mid is what this bot takes. The sequencer now leaves
  far fewer of those orders than the three numbers above were measured on.

The bot estimates fair value with a scalar Kalman filter over log prices
(process variance `0.002²/3`, observation variance `0.005²/3`). That filter
measures 16.4 bps RMS error against the backtest's true mid. The filter is the
whole profit. The same strategy with a different source of fair value:

| fair value from | profit over 120k messages |
|---|---|
| random | −$37,388 |
| last traded price | −$17,304 |
| last printed price | −$6,849 |
| Kalman filter | **+$33,827** |

The bot still needs a threshold before it takes an order (`--bot-take-bps`,
default 6). The reason is the bot's own selection, and not another trader who
knows more. The bot fires when its estimate says a price is cheap. An estimate
that is too high says that more often. So the orders the bot picks are the ones
its own error is largest on. With no threshold the measured profit is negative.

## Measured results

Eight backtest seeds, 120,000 messages each, and roughly 20,000 orders sent by
the bot. `--rate` defaults to 2 messages a second, and 120,000 messages is about
16 hours at that rate. The measured switching configuration uses 69 as the
mean of three activity states, and 120,000 messages is 29 minutes at that rate.

```
seed 1  $33,827   seed 3  $36,775   seed 5  $37,209   seed 7  $34,867
seed 2  $38,682   seed 4  $36,460   seed 6  $37,251   seed 8  $42,853
```

## Why BTC-USDC earns most of it

All three symbols make a profit. Over 6 seeds none of them was negative on any
symbol. They are not equally worth the capital. The last column is the profit
for each dollar of the cap the bot may hold in that market:

| symbol | mean profit | worst seed | negative seeds | profit per $1 of cap |
|---|---|---|---|---|
| BTC-USDC | $28,164 | $24,032 | 0/6 | **1.41** |
| ETH-USDC | $7,344 | $4,992 | 0/6 | 0.73 |
| MERKLE-USDC | $1,193 | $700 | 0/6 | 0.24 |

The cause is the price step, and not the symbol. Every market ran on a one-cent
price step when this was measured, and what one cent was worth changed
completely with the price level:

| symbol | price | one cent | price steps inside the ±0.5% band |
|---|---|---|---|
| MERKLE-USDC | ~9 | 11.2 bps | ~9 |
| ETH-USDC | ~100 | 1.0 bps | ~100 |
| BTC-USDC | ~965 | 0.10 bps | ~965 |

The bot profits from resting orders left far from the mid. On BTC-USDC, orders
scatter over roughly a thousand different price levels, so some orders are
always left behind. On MERKLE-USDC the whole band is nine levels. The book is
dense there, and few orders are left behind.

Since 16 August 2026 `SYMBOLS` in `services/src/domain.rs` gives each market its
own price step: MERKLE-USDC 0.01 at a listed price of 10, ETH-USDC 0.10 at 100,
and BTC-USDC 1.00 at 1000. Each step is one thousandth of the listed price, so
one step is 10 bps in all three markets, and the ±0.5% band is 10 steps wide in
all three. So the profit split above measures the one-cent regime, and it is not
a statement about the three markets today. `SimFeed` reads each market's step
from `SYMBOLS`, so the same command run today measures a different market.
Nobody has run it again.

The threshold moves with the step. Rounding a limit price to a whole step moves
it up to one step away from fair value, so the real threshold is about 10 bps in
all three markets whatever `--bot-take-bps` says.

Capital is allocated with `--bot-caps`:

```bash
cargo run --release -- --start-bot --bot-caps "BTC-USDC=23000,ETH-USDC=12000"
```

A symbol left out is not traded. Total capital was held fixed at $35,000, and
MERKLE-USDC's share was moved to the other two. That measured $38,270 against
the default's $36,221 over 12 seeds. The gain is smaller than one standard
deviation ($3,569), so it is a reasonable preference and not a proven
improvement. Two results are clear at that sample size. Splitting capital
evenly across the three is worse ($28,819). Putting all of it in BTC-USDC
raises the standard deviation by about two thirds and returns no more. The
defaults stay spread over the three markets for that reason.

**The bot needs many messages before the profit shows.** At 1,000 messages the
same strategy ranges from −$326 to +$953 across ten seeds. By 5,000 messages
every seed is positive. `--rate` defaults to 2 messages a second, so a two-minute
live run against a sequencer left on that default sees only about 240 messages,
and its result is mostly noise. Raise `--rate` to see the profit in a short run.
Two minutes at the measured mean of 69 a second is about 8,280 messages.

## Why the bot rests no quotes

Market making means resting orders on both sides of the book and earning the
difference between them. It is the obvious next step, and it was built,
measured and turned off. Resting a quote on the side that closes the position
lets the bot get back to flat sooner and re-use its capital. It loses money,
and the loss grows with the size quoted:

| passive quote size | profit over 6 seeds |
|---|---|
| off | **$36,701** |
| 0.1 units | $36,605 |
| 1 unit | $35,741 |
| 5 units | $31,551 |
| 10 units | $24,996 |

The offset changes almost nothing: 25, 35, 45, 60, 80 and 120 bps all landed
within $120 of each other. That flat result names the cause. The quote is not
priced wrong. Quoting at all is what costs the money.

The reason is that **a resting quote is a stale order, and stale orders in
other people's books are the exact thing this bot profits from**. An arriving
order picks its own moment, and trades only when a price is past fair value by
more than the threshold. A resting quote gives that choice to whoever crosses
it. The mid drifts, and the quote is crossed once the drift has removed the
profit. The bot's one advantage is knowing where fair value is, and resting an
order gives that advantage away.

`--bot-quote-bps` (default 0) and `--bot-quote-units` are kept so this result
can be reproduced rather than found again.

## Tuning

`--bot-take-bps` sits on a flat best point, measured over 12 seeds with quoting
off:

| take_bps | 2 | 4 | **6** | 8 | 10 | 14 | 20 |
|---|---|---|---|---|---|---|---|
| profit | 34,685 | 35,854 | **36,221** | 36,057 | 35,373 | 33,481 | 30,499 |
| orders sent | 27,318 | 23,616 | 20,364 | 17,648 | 15,367 | 11,861 | 8,507 |

Below 4 the bot trades on price differences smaller than its own estimate
error. Above 10 it skips too many orders. Anything from 4 to 8 is within noise
of the default.

No setting makes this profitable in every condition. Position size only scales
the result. Caps of 50, 100 and 200 produced mean-to-standard-deviation ratios
of 6.1, 6.0 and 6.2. The ratio is stable at these three sizes. What is
left is a position exposed to a price the bot does not predict. That position
earns nothing for being held, and there is no other instrument on this venue to
hold against it. **The one setting with no cost is `--rate`.** The profit arises
per message, because the price only moves when a message is generated. So every
figure here is per 120,000 messages, whatever time that takes on the clock.

## Risk controls

- **A cap on the value held in each market** (BTC-USDC $20,000, ETH-USDC
  $10,000, MERKLE-USDC $5,000). A held position returns nothing on average and
  only adds variation. In the backtest the mid has no direction. Against the
  sequencer the mid is pulled toward the listed price by `pick_side`, and that
  pull can run against the position.
- **The bot counts resting and in-flight quantity, and not only the position it
  holds.** The bot sends good-till-cancel limit orders, and it sends nothing
  else. So an order that crosses and does not fill the whole quantity does not
  disappear. The remainder rests in the book. A bot that ignored those
  remainders reads itself as flat, sends the order again on every poll, and ends
  up many times over the position it intended. Measured cost of getting this
  wrong, under 4 messages of submission latency: −$140,000.

  The venue does have an immediate-or-cancel order type
  (`TimeInForce::ImmediateOrCancel`, sent by `--order-terms ioc`), and one would
  throw the remainder away and remove the need for this count. The bot does not
  send one. Nobody has measured that change, so the count stays.
- **The bot cancels a quote once it is no longer past fair value**, so a
  remainder is not left to be filled at a loss.
- **Prices and quantities are built as integers** and converted once. The
  exchange refuses an order that is not a whole number of price steps, rather
  than rounding it. A refused order would otherwise look like quantity the bot
  believes it holds.
- **The bot skips its own resting orders** when it measures what it can trade
  against, because the exchange refuses an order that would trade against them.
  `matcher/step4_self_trade_check.rs` refuses the whole arriving order, and not
  only the part that would have met the bot's own order. A bot that counted its
  own resting orders as something to trade against would send orders the
  exchange throws away.
- **A changed `x-feed-session` makes the bot drop its book and read the
  messages again**, because a book rebuilt from a different history describes a
  market that no longer exists.

## An engine weakness this work exposed

The bot does not use this weakness. It is worth fixing.

**A position that is still open is valued at the last traded price**
(`Position::unrealized_mills`). Any trade sets that price. So a person who can
choose a trade's price can choose what every open position is reported to be
worth. A trade of 0.1 units revalues a large position.

**One account can no longer match itself.** Since 15 August 2026
`matcher/step4_self_trade_check.rs` refuses that at rule set 2, and the live log
opens at rule set 2. Messages published before that `EngineRule` message still
replay under rule set 1, where an account does match itself, so the rule closes
that route forward and not backward.

**The concern stays, by a route that is still open.** The rule compares account
ids. Two accounts are two ids, whoever holds the keys. One person who holds two
accounts trades one against the other, and the exchange accepts it. The
protection collar does not stop the price: `matcher/step3_bound_the_price.rs`
bounds a market order only, and leaves a limit order's price exactly as its
sender signed it. So two accounts under one operator can still print any price
they like and revalue every open position at it.

The last traded price is also a poor measure of value on its own. It sits
between 66 and 74 bps (1σ) away from the true mid because trades happen at
resting prices. Those prices are often stale. That range was measured in the
backtest against the generator that `services/src/feed/generate.rs` replaced.
The sequencer now holds
the spread at 1 price step at the middle value and 3 at the 95th, so the gap is
smaller today. Nobody has measured it again.

Valuing an open position at a price taken from the book, such as the mid, would
fix both problems.
