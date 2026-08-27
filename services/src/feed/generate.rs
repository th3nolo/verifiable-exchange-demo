//! The simulated traffic this sequencer publishes when nobody is sending
//! orders.
//!
//! # What this generator does
//!
//! The generator runs a small market. Two kinds of account send messages:
//!
//! - a **quoting account** puts limit orders in the book, a few price steps
//!   behind the best price on the other side. Such an order never crosses
//!   anything, so it always rests. It can never trade with an order of its own
//!   account. How far behind the best price the order sits is the account's
//!   patience band. A band is one of 1, 2, 3, 5 and 10 price steps. See
//!   `PATIENCE_BANDS`.
//! - a **taking account** sends one order that buys every sell order at the
//!   lowest sell price, or sells every buy order at the highest buy price. The
//!   order is immediate-or-cancel: the exchange trades what it can and throws
//!   the rest away. Such an order never rests, so a taking account holds
//!   nothing in any book. It can never trade with itself either.
//!
//! A taking account sends on a cadence and not on a coin toss. Every fourth
//! message that is not a cancel crosses, and the three markets take turns at
//! it. At 24 messages a second each market therefore gets a crossing order
//! every 0.73 seconds, so every one-second candle holds a trade. See
//! `TAKE_EVERY`.
//!
//! The market is in one of three activity states at any moment: 24, 69 or 114
//! messages a second. Each state holds a third of the time, and one state lasts
//! five minutes on average. The state sets two things at once: how many
//! messages a second the generator sends, and how far from the best price it
//! puts a quote. So a busy market both trades more and moves more. See
//! `Activity`, `QUIET_RATE` and `PLACEMENT_WIDTH`.
//!
//! Every order the generator places is cancelled after a random life. The life
//! is drawn from an exponential distribution. Each resting order therefore has
//! the same chance of being cancelled in the next second, whatever its age.
//! That fixed rate is what holds the book at a steady depth. The rate is faster
//! for a quote near the best price than for a patient one. See
//! `BAND_LIFETIMES_MS`. A cancel wins over a quote and over a crossing order,
//! but never more than twice in a row. See `CANCELS_IN_A_ROW`.
//!
//! The front of each book holds one order a price. A quote that draws a price
//! the generator already holds an order at steps up to three prices further
//! behind. That is what keeps one crossing order to about one trade, which is
//! what the flow numbers in `docs/GENERATOR-RFC.md` need. See
//! `MOST_AT_A_LEVEL`.
//!
//! # Why it is built this way
//!
//! The old generator priced every order around a mid price of its own. A mid
//! price is the middle of the best buy price and the best sell price. The old
//! generator moved that number at random, and no order book held it. It could
//! also only cancel one of the newest 50 orders it had sent. Two faults
//! followed.
//!
//! **The books only grew.** After 50 messages an order could never be cancelled
//! again. At six messages a second that is under ten seconds. The standing
//! result for an order book is that its depth settles at the limit order rate
//! divided by the cancel rate per resting order (Smith, Farmer, Gillemot and
//! Krishnamurthy, 2003). A cancel rate of zero gives no steady depth at all.
//! The live exchange reached the 1,000-order display cap on both sides of every
//! book.
//!
//! **The markets then stopped trading.** An arriving order can trade against
//! orders at several price levels. The exchange refuses the whole arriving
//! order if any of those orders belongs to the same account:
//! `matcher/step4_self_trade_check.rs`. With `N` accounts and `K` resting
//! orders in the range the arriving order crosses, the chance the exchange
//! accepts it is `(1 - 1/N)^K`. At 40 accounts and 85 crossed orders that is
//! 12%. At 400 crossed orders it is 0.004%. `K` grew without bound because the
//! books grew without bound, so trading stopped. The live exchange refused
//! 116,618 of 320,896 messages, and one market went two hours with no trade.
//!
//! Three changes answer the three parts of that. Every order now has a life, so
//! a book stays bounded. Orders are priced from the book's own best price, as
//! every standard order book model prices them (Smith et al. 2003; Cont,
//! Stoikov and Talreja 2010; Mike and Farmer 2008), so there is no mid price
//! outside the book that can move away from it. The account roles make `K` zero
//! for a quoting account, and make a taking account hold nothing. The
//! self-trade rule therefore cannot refuse a generated order at all.
//!
//! The measurement ran 50,000 messages at 40 accounts and 24 messages a second,
//! which is the measured quiet-state configuration, into a real `MatcherState`
//! opened at rule set 2:
//!
//! ```text
//!                        trades/1,000   worst gap   depth a side   refused
//! this generator            56.0-56.3          42           57.1         0
//! the old cancel window    96.3-100.3         116        1,213.9     9,077
//! no order ever expires    96.3-100.7          20          656.5         0
//! ```
//!
//! `the_generated_traffic_keeps_every_market_trading` measures the first row on
//! every test run, at 24 messages a second and at 6. The two rows below it are
//! the same measurement with one part of the fix taken out.
//!
//! # The price has to move as well
//!
//! A market that trades every second and always at the same price is as dead as
//! a market with no trades. The chart draws a flat line either way. Three
//! numbers say whether the price moves, all read off 15-second candles: the
//! price band is the highest price less the lowest over 25 minutes, as a share
//! of the lowest; the candle body is the first price to the last price of one
//! candle; the volume is the quantity that traded in one candle. Measured on the
//! deployment and by `what_this_configuration_measures`:
//!
//! ```text
//!                                   price band   candle body   volume
//! deployment, before commit af9968b   2.84-3.58%  0.214-0.247%  277-286
//! deployment, at commit af9968b       0.83-1.00%  0.113-0.153%  118-123
//! this generator, measured            2.63-3.97%  0.248-0.282%  275-277
//! this generator, on ./demo.sh        2.32-3.24%  0.249-0.283%  262-267
//! ```
//!
//! The last row is 25 minutes of `./demo.sh` with the bot stopped, read off
//! `GET /candles?symbol=X&interval=15&n=120` on 17 August 2026. That run matches
//! the generator-only deployment measurement. The same run fills 98.0% to
//! 99.0% of its one-second
//! candles at a variance of 0.17 to 0.19 times the mean, and no cancel found
//! nothing. Every row above is a flat 24 messages a second.
//!
//! The activity state raises all three numbers, because a busy state both
//! trades more and moves more. Measured over 150 minutes of market time in each
//! state, as a mean over the three markets:
//!
//! ```text
//!                          price band   candle body   volume
//! the floor, 24 a second        3.13%        0.259%      276
//! the mean, 69                  4.39%        0.464%      793
//! the peak, 114                 5.08%        0.591%    1,311
//! the states switching          4.25%        0.406%      698
//! ```
//!
//! The last row is 600 minutes, not 150, because the numbers the activity state
//! exists to move are read over 15-minute buckets and 150 minutes holds 9 of
//! them. See `how_the_volume_varies`.
//!
//! Commit af9968b met every assertion in `docs/GENERATOR-RFC.md` and stopped the
//! price moving, because it spent the choice of side on holding the trades
//! apart. `a_level_to_take`, `MOST_STEPS_FROM_THE_TOUCH` and
//! `SMALLEST_QUOTE_TENTHS` hold the three numbers above, and each doc comment
//! carries its own measurement.
//!
//! The self-trade rule itself does not change. The rule is a matching rule. It
//! arrives in the log as rule set 2, and changing it needs a second copy of the
//! rule in the checker. This file changes what the generator sends. It changes
//! nothing about what the exchange does with those messages.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{error, info, warn};

use super::drain::{COMPLAIN_EVERY, Drain, drain_inbox};
use super::{FeedState, with_state};
use crate::domain::{AccountId, MAX_GRID_UNITS, OrderId, OrderMessage, SYMBOLS, Side, TimeInForce};
use crate::inbox::PRICE_SCALE;

/// One order the generator sent and has not yet cancelled.
///
/// The sequencer holds no book and reads none. This list is therefore
/// everything the generator knows about the books: the orders it sent, at the
/// prices it sent them at. The list is exact while the generator is the only
/// sender, because a quoting order always rests in full and a taking order
/// always fills the one level it names. An order somebody else sent through the
/// separate service can make the list wrong. Such an order is rare. The
/// generator cancels every entry here when its life ends, whether the exchange
/// still holds the order or not, so a wrong entry costs one ignored cancel and
/// nothing more.
pub(super) struct OpenOrder {
    pub(super) id: OrderId,
    pub(super) account: AccountId,
    /// The index of this order's market in `SYMBOLS`.
    pub(super) market: usize,
    pub(super) side: Side,
    pub(super) price_cents: i64,
    pub(super) qty_tenths: i64,
    /// The millisecond the generator cancels this order at. See
    /// `BAND_LIFETIMES_MS`.
    pub(super) expires_at_ms: u64,
}

/// How patient each kind of quoting account is. The band is the most price
/// steps from the other side's best price that the account puts an order at.
///
/// An account keeps one band for the whole run. `account % 5` picks the band,
/// so the five bands hold about the same number of accounts whatever the
/// account count is.
///
/// Bands do two things. They give a book the shape a real book has: many orders
/// at the best price, and a few steps behind it. They also keep two accounts
/// apart. An account that quotes 1 step out and an account that quotes up to 10
/// steps out rarely have orders at the same price at the same time.
///
/// **These are price steps. They are not a share of the price.** The five
/// numbers were `[0.01, 0.02, 0.03, 0.05, 0.10]`, read as shares of the price.
/// They are the same five numbers here, read as steps. The unit was the fault.
///
/// A share of the price is a different number of steps in every market.
/// `docs/GENERATOR-RFC.md` section 4 names this unit error. A band is the
/// furthest a quote may sit, and `steps_behind_the_touch` draws 1 step up to
/// that many. A 10% band at MERKLE-USDC is 100 steps and at BTC-USDC is 1,000,
/// so the draw put most quotes a long way out. The patient bands also live
/// longest, and a book holds an order for as long as it lives, so those far
/// quotes held most of the depth.
///
/// Measured over 50,000 messages: 22.8% of resting orders sat within 1% of the
/// mid, the spread was 5 steps at the middle value and 28 steps at the 95th,
/// and one five-minute candle ran 9.35% of its own opening price from high to
/// low. That is the long wick the chart drew. The same run in steps sits at
/// 93.6% within 1% of the mid, a spread of 1 step, and a candle of 1.12%.
///
/// A step is the same share of the price in all three markets, because
/// `SYMBOLS` gives each market its own step. A step of 0.01 at a price of 10,
/// 0.10 at 100 and 1.00 at 1000 are all one thousandth of the listed price. So
/// one table of steps gives all three markets the same book. That is what the
/// per-market step is for, and the shares undid it.
///
/// The widest band is 10 steps because the depth arithmetic says so. Assertion
/// H5 of the RFC wants 10 resting orders a side within 10 steps of the best
/// price. Every quote must land inside 10 steps, or close behind it: a wider
/// band spends depth where H5 cannot count it. `MOST_STEPS_FROM_THE_TOUCH` lets
/// a quote walk further when the price it drew is taken, and it pays for those
/// steps out of the depth the side already holds. The run measures 24.4 orders
/// a side within 10 steps at 24 messages a second and 13.1 at 6.
///
/// **The bands were swept wider and it did not help.** The bands are what
/// decides how many orders one crossing order removes, and section 4.5 of the
/// RFC needs that number at 1.14 or under. Wider bands spread the quotes over
/// more prices, so each price holds fewer. Measured over 50,000 messages at 40
/// accounts and 24 messages a second, before `MOST_AT_A_LEVEL` existed:
///
/// ```text
/// bands                  orders a crossing order removes   cancelled   H5 depth
/// [1, 2, 3, 5, 10]                                  1.81       39.2%       43.8
/// [2, 4, 6, 10, 20]                                 1.61       45.8%       41.4
/// [3, 6, 10, 20, 40]                                1.47       50.6%       35.7
/// [5, 10, 20, 40, 80]                               1.37       53.9%       27.9
/// [10, 20, 40, 80, 160]                             1.26       57.4%       20.4
/// ```
///
/// The count falls and never reaches 1.14, and H5 falls with it. A quote is
/// priced from the other side's best price, and a power law with an exponent of
/// 1 puts most quotes at the first step whatever the band is, so widening the
/// band moves the far quotes and not the near ones. `MOST_AT_A_LEVEL` acts on
/// the near ones instead, and these five bands stay as they were.
///
/// **These are the quiet state's bands.** The activity state multiplies them:
/// 1, 2 or 3, so the busy state draws over 3, 6, 9, 15 and 30 price steps. That
/// is the placement dispersion section 4.6 of `docs/GENERATOR-RFC.md` asks the
/// state to scale, beside the message rate. See `PLACEMENT_WIDTH`. The sweep
/// above is a sweep of the whole table at one rate, and it is what says a wider
/// table costs depth assertion H5 counts; the state pays that cost only where
/// the rate has already bought the depth back.
const PATIENCE_BANDS: [i64; 5] = [1, 2, 3, 5, 10];

/// The mean life of a resting order, in milliseconds, one life for each band.
///
/// These five numbers set how deep the books get. A book fills at the rate
/// orders arrive and empties at the rate orders leave, so its depth settles at
/// `d = a / r`: the limit order rate `a` over the cancel rate `r` per resting
/// order. An exponential life gives a constant cancel rate of `1 / life` per
/// second. The five lives here are 0.100, 0.050, 0.033, 0.020 and 0.010 cancels
/// a second.
///
/// **A quote near the best price is cancelled fast, and a patient quote sits.**
/// Cont, Stoikov and Talreja (2010) measured 0.71 cancels a second one step
/// from the best price, 0.47 at five steps, and a rate near zero far out. The
/// shape here is the same, and the scale is slower: 7.1 times slower at one
/// step, and 23.5 times at five. A demo at 6 messages a second cannot pay for a
/// 1.4-second life: every message would be a cancel, and nothing would be left
/// to trade with. `a_near_quote_is_replaced_and_a_patient_one_sits` holds both
/// numbers.
///
/// Measured over 50,000 messages at 40 accounts and 24 messages a second. The
/// generator sends 12.1 quoting orders a second, which is 2.02 a second into
/// each of the six market sides. The mean life over the five bands is 42
/// seconds, so a side settles near `2.02 * 42 = 85` orders, less the orders
/// that trade. The run measures 55.1 a side.
///
/// **These five numbers were halved and put back.** Halving them holds the
/// books at 29.0 orders a side at 24 messages a second, which is tidier. It
/// also holds them at 7.3 a side at 6 messages a second, and assertion H5 of
/// `docs/GENERATOR-RFC.md` wants 10 orders a side within 10 price steps. The
/// deployment runs at 24 and `the_generated_traffic_keeps_every_market_trading`
/// checks 6 as well, so the lives have to serve both. At these five numbers the
/// books hold 13.2 orders a side at 6 messages a second.
///
/// **A shorter life was asked for, measured, and refused.** A shorter life
/// corrects a wrong entry in the generator's list sooner. `TAKE_EVERY` names
/// the entries: the bot takes a resting order, the sequencer holds no book, and
/// the generator goes on believing that order rests. The request was five lives
/// on a logarithmic scale from 1 second to 10 seconds. Measured over 150,000
/// messages at 40 accounts, with `bot.rs` running beside the generator,
/// `what_this_configuration_measures_with_the_bot`:
///
/// ```text
/// lives         depth at 24   depth at 6   H5 at 6   1-second fill   cancels that
///                                                         with bot   found nothing
/// 1s to 10s             5.4          1.8       2.1           96.2%           2,972
/// 3s to 30s            16.5          4.1       4.1               -               -
/// 5s to 50s            28.4          6.7       6.6           91.0%           4,600
/// 7s to 70s            40.5          9.5       9.4           89.1%           6,322
/// 8s to 80s            46.5         10.9      10.8           89.2%           6,943
/// 10s to 100s          58.7         13.7      13.5           88.9%           7,572
/// these five           57.1         13.4      13.2           88.6%           7,468
/// ```
///
/// The request works and it cannot ship. 1 second to 10 seconds raises the
/// one-second fill with the bot from 88.6% to 96.2% and cuts the cancels that
/// find nothing by 60%. It also holds the books at 5.4 orders a side at 24
/// messages a second and 1.8 at 6, so assertion H5 fails at both rates, one
/// side of a book is empty at 397 of the 1,620 readings at 6 messages a second,
/// and assertion H1 fails with it.
///
/// **6 messages a second is what binds.** A book holds a quarter as many orders
/// there as at 24, and H5 wants 10 of them within 10 price steps. The whole
/// table above passes H5 at 24 messages a second down to 3 seconds to 30
/// seconds, and only 1 second to 10 seconds fails there, at 5.3 orders within
/// 10 steps. At 6 messages a second every scale below 8 seconds to 80 seconds
/// fails: 9.4 orders at 7 seconds to 70 seconds, 6.6 at 5 to 50. The
/// deployment runs at 24 and
/// `the_generated_traffic_keeps_every_market_trading` checks 6 as well, so the
/// lives have to serve both.
///
/// **The shortest logarithmic scale that keeps every assertion is 8 seconds to
/// 80 seconds**, at 10.8 orders within 10 price steps at 6 messages a second
/// against the 10 H5 asks for. It buys 0.6 points of one-second fill and 7%
/// fewer cancels that find nothing, and it spends the H5 margin at 6 messages a
/// second, from 13.2 down to 10.8. That is not a trade worth making, so these
/// five numbers stay.
///
/// **Why the fill moves at all, which is not the reason it was asked for.** The
/// argument for a shorter life was that the generator's list is corrected
/// sooner. The measurement shows a second and larger effect: a shallower book
/// gives the bot less to take. `bot.rs` sizes an order by the quantity resting
/// through its own limit price, so the orders it removed fell from 51,105 to
/// 14,112 over the same run. Fewer orders taken means fewer wrong entries made
/// in the first place. The share of taken orders that ends in a cancel finding
/// nothing goes the other way, from 14.6% to 21.1%, exactly as correcting the
/// list sooner predicts.
///
/// The five numbers here are already close to a logarithmic scale from 10
/// seconds to 100 seconds. The true logarithmic scale over the same two ends,
/// `[10_000, 17_800, 31_600, 56_200, 100_000]`, measures 58.7 orders a side
/// against 57.1 and the same fill inside a tenth of a point. Neither shape is
/// better than the other, so the five numbers are left as they were written.
const BAND_LIFETIMES_MS: [f64; 5] = [10_000.0, 20_000.0, 30_000.0, 50_000.0, 100_000.0];

/// The longest life any order gets. An exponential draw has no upper end. A
/// draw of a thousand years would be an order the generator never cancels. One
/// order in 22,000 draws a life longer than ten times the mean.
const LONGEST_LIFE_IN_MEANS: f64 = 10.0;

/// How many messages in a row the generator may spend on cancels.
///
/// A cancel wins over a quote and over a crossing order, because an order's
/// life is a wall-clock deadline and the generator cannot hold it back. This
/// number is how far it may be held back after all.
///
/// **The activity state is why this exists.** A market that has just been busy
/// holds a book built for the busy rate, and every order in that book still has
/// to be cancelled. At 114 messages a second a side holds 274 orders, so the
/// six sides hold 1,646, and the mean life of 42 seconds makes 39 of them come
/// due every second. The quiet state sends 24 messages a second. 39 cancels due
/// against 24 messages is every message spent on a cancel, so the generator
/// stopped quoting and stopped crossing, and every market stopped trading until
/// the book had drained. Measured over 50,000 messages at 40 accounts on seed
/// 777, with the states switching: all three markets went 677 to 680 messages
/// with no trade, which is 28.3 seconds. Assertion H2 of
/// `docs/GENERATOR-RFC.md` allows 60. The arithmetic says the worst case is
/// about 43 seconds, and a 28-second hole in the chart is the failure section
/// 4.6 exists to remove, in miniature.
///
/// **Two is the number.** At most two messages in a row are cancels, so at
/// least a third of the messages stay for quotes and crossing orders. The
/// cancels that lose are not dropped: they are still due on the next message,
/// so the long-run cancel rate is the expiry rate whatever this number is. What
/// changes is that a book built for a busier state drains more slowly and the
/// market keeps trading while it drains. Measured over 50,000 messages with the
/// states switching, on the same seed: the worst gap falls from 680 messages
/// and 28.3 seconds to 35 messages and 1.5 seconds, which is what every state
/// held at one rate already measures.
///
/// In steady state the cap almost never binds. At 24 messages a second, 8
/// orders come due a second against 24 messages, so a cancel is due on a third
/// of the messages and three in a row is uncommon. Measured at a flat 24 over
/// 50,000 messages: 66.6% of limit orders end cancelled both with the cap and
/// without it.
///
/// The bound on how many orders the generator holds open is a different thing
/// and it still wins: at `MAX_OPEN_ORDERS` the generator cancels whatever this
/// number says, because an order it forgets can never be cancelled again.
const CANCELS_IN_A_ROW: u32 = 2;

/// The share of the accounts that quote. The other accounts send the crossing
/// orders. At 40 accounts that is 34 quoting and 6 taking.
///
/// **This number no longer sets the share of messages that cross.**
/// `TAKE_EVERY` does, on a cadence. This number now only splits the accounts
/// into the two pools, and the pools are what keep the exchange from refusing a
/// generated order for a self trade: a quoting account never crosses anything,
/// and a taking account never leaves an order behind.
///
/// It used to set both. The generator drew an account for every message and
/// read the role off the number it drew, so 15% of the accounts taking made
/// about 15% of the messages cross. Measured over 50,000 messages at 20
/// accounts and 6 messages a second: 59% of the messages were quotes, 31% were
/// cancels and 10% were crossing orders. The sweep that picked 0.85 is
/// therefore no longer the sweep that matters, and it is kept because it still
/// says what the account split costs:
///
/// ```text
/// quoting share   trades/1,000   depth a side   worst gap   H5 depth in 10 steps
///          0.70          132.4            7.4         159                    6.5
///          0.75          120.7            9.3         159                    8.3
///          0.80          108.0           10.5         202                    9.7
///          0.85           93.2           12.0         324                   11.5
/// ```
///
/// 0.85 stays for two reasons. A book needs quoting accounts to fill it, and
/// the five patience bands need enough accounts to spread over: `band_of` is
/// `account % 5`, so 34 quoting accounts give about 7 accounts a band. And a
/// higher share leaves fewer taking accounts, which does not change how often a
/// crossing order is sent but does put more of the crossing orders on the same
/// account number.
const QUOTING_SHARE: f64 = 0.85;

/// How many messages the generator sends between crossing orders. Cancels are
/// not counted, because a cancel is due on a clock and the generator cannot
/// hold it back.
///
/// **Why a cadence and not a coin.** The generator used to decide the role from
/// the account it drew: 15% of the accounts take, so about 15% of the messages
/// crossed. Which market a message went to was a second draw. Two random draws
/// made the crossing orders of one market a Bernoulli process, and a Bernoulli
/// process leaves long holes. Measured on the deployment at 24 messages a
/// second, ETH-USDC over 300 one-second candles: 2.40 trades a second on
/// average, variance 13.53, and only 49% of the seconds held a trade. A market
/// with no clustering at 2.40 trades a second fills 91% of them.
///
/// The cadence removes both draws. Every fourth message that is not a cancel
/// crosses, and the three markets take turns, so each market gets a crossing
/// order every 12 such messages. At 24 messages a second that is one every 0.73
/// seconds, so every one-second candle holds one or two. At the mean of 69 it
/// is one every 0.25 seconds and at the peak of 114 one every 0.15.
///
/// **The cadence counts messages that are not cancels, so it needs some.**
/// `CANCELS_IN_A_ROW` is what guarantees that: at most two messages in a row
/// are cancels, so at least a third of the messages reach this counter. Without
/// it a book built for the busy state took every message as a cancel while it
/// drained, and all three markets went 680 messages with no trade.
///
/// **Why four.** The number sets three measured quantities at once. Write `N`
/// for the resting orders one crossing order removes. Of every `k` messages
/// that are not cancels, one crosses and `k - 1` are quotes. A book is steady
/// when the quotes that arrive match the orders that leave, so the cancels are
/// `k - 1 - N` of those messages. That gives the two numbers the RFC asks for:
///
/// ```text
/// crossing share of all messages    T = 1 / (2k - N - 1)
/// share of limit orders cancelled   f = (k - 1 - N) / (k - 1)
/// ```
///
/// `docs/GENERATOR-RFC.md` section 4.4 wants `T` between a sixth and a quarter,
/// and section 4.5 wants `f` between 62% and 93%. At `k = 4` and `N = 1`, `T`
/// is a sixth exactly and `f` is 67%. `k = 5` puts `T` at 1/8, under the sixth
/// section 4.4 asks for. `k = 3` puts `f` at 50%, under the 62% section 4.5
/// asks for. Four is the only whole number that meets both.
///
/// The same arithmetic bounds `N`: `f >= 0.62` needs `N <= 1.14`. That is what
/// `MOST_AT_A_LEVEL` delivers, and `the_best_level` reports what it measures.
///
/// **What the cadence does not cover.** The generator is not the only sender.
/// `demo.sh` also starts the bot, and the bot sends limit orders priced to
/// cross. Such an order takes the generator's resting orders, and the sequencer
/// holds no book and executes nothing, so the generator cannot learn which of
/// its orders went. It then sends its next crossing order at a price that has
/// already gone, and that order trades nothing. Measured on `./demo.sh` over
/// 300 one-second candles in each of the three markets, on 17 August 2026:
///
/// ```text
/// what is running              candles that hold a trade   cancels that found nothing
/// the generator only                        99% to 100%                            1
/// the generator and the bot                  86% to 92%                          466
/// ```
///
/// `what_this_configuration_measures_with_the_bot` drives the real `bot.rs`
/// beside the generator and measures the same shape: 98.8% of the one-second
/// candles hold a trade with the generator alone and 88.6% with the bot, and
/// 71.7 cancels a minute find nothing.
///
/// Nothing in this file can close that gap. Reading the fills back needs the
/// exchange, and the exchange reads the sequencer. `the_best_level` carries the
/// same argument for the crossing order's own quantity. `BAND_LIFETIMES_MS`
/// carries the one thing that does move the number, and what it costs.
const TAKE_EVERY: u32 = 4;

/// How many of the generator's orders may rest at one price, on one side of one
/// market. A quote that draws a price already holding this many orders steps
/// one further behind. See `a_free_step`.
///
/// One is the number the price needs. A crossing order removes the one order
/// the exchange fills first at the best price, `the_best_level`, so the best
/// price moves one step when that level held one order, and does not move at
/// all when it held two. Measured over 150,000 messages at 40 accounts and 24
/// messages a second, with everything else the same:
///
/// ```text
/// orders a level   price band   candle body   H5 depth
///              1        3.07%        0.272%       24.8
///              2        1.57%        0.128%       53.0
/// ```
///
/// **It used to be the number the flow arithmetic needed, and that reason has
/// gone.** A crossing order removed every order at the level it named, so the
/// level had to hold about one order for section 4.5 of
/// `docs/GENERATOR-RFC.md` to hold. `TAKE_EVERY` gives that arithmetic: a
/// crossing order had to remove 1.14 resting orders or fewer. Measured over
/// 50,000 messages at 40 accounts and 24 messages a second, when a crossing
/// order took the whole level:
///
/// ```text
/// orders a level   orders a crossing order removes   cancelled   H5 depth
///              1                              1.00       66.0%       56.0
///              2                              1.40       52.8%       49.3
///              3                              1.55       47.6%       47.5
/// ```
///
/// Two at a level already missed the 62% section 4.5 asks for, and it missed it
/// by 9 points. A crossing order now names one order whatever the level holds,
/// so that column reads 1.00 on every row. The price column above is what
/// decides the number instead.
const MOST_AT_A_LEVEL: usize = 1;

/// How far behind the other side's best price a quote may walk while it looks
/// for a price that holds none of the generator's orders yet.
///
/// The books are 57 orders a side and the widest band is 10 price steps, so the
/// orders do not fit one to a level inside the bands. Something has to give.
/// These two numbers choose what: a quote walks back until it finds a free
/// price, and it stops at 14 steps from the other side's best price, or sooner
/// when the side it is walking on is too thin to spend the steps.
///
/// **This is what makes the price move.** One crossing order removes the one
/// order the exchange fills first at the best price, `the_best_level`. The
/// best price therefore moves one step when that level held one order, and does
/// not move at all when it held two. The walk decides which: a quote that finds
/// a free price leaves the level it passed holding one order. A longer walk
/// therefore makes more of the front of the book one order a price, and the
/// price moves on more of the crossing orders.
///
/// The price band is the highest price less the lowest over 25 minutes of
/// 15-second candles, as a share of the lowest. The candle body is the first
/// price to the last price of one 15-second candle. `print_movement` reports
/// both, and `what_this_configuration_measures` prints the whole row. Measured
/// over 150,000 messages at 40 accounts and 24 messages a second, with the walk
/// held to a fixed number of steps:
///
/// ```text
/// steps   price band   candle body   H5 depth   H5 depth at 6 a second
///     3        1.58%        0.171%       52.1                     12.7
///     6        2.32%        0.235%       42.0                     11.5
///     8        2.80%        0.258%       33.9                     10.7
///    10        3.15%        0.273%       25.7                      9.8  H5 fails
/// ```
///
/// **One fixed number cannot serve both message rates.** The books hold 57
/// orders a side at 24 messages a second and 13.4 at 6, and assertion H5 of
/// `docs/GENERATOR-RFC.md` wants 10 orders a side within 10 price steps. A side
/// holding 13 orders spread over 14 levels has one order at each and nothing
/// left for H5 to count. `ORDERS_A_FREE_STEP_COSTS` therefore pays for the walk
/// out of the depth the side already holds: one step for every 4 orders. That
/// is 14 steps at 24 messages a second and 3 at 6. Measured:
///
/// ```text
///                            price band   H5 depth   band at 6   H5 at 6
/// 3 steps, fixed                  1.58%       52.1       2.18%      12.7
/// 14 steps, fixed                 3.43%       21.0       2.93%       9.2  fails
/// 14 steps, 1 per 4 orders        3.07%       24.8       1.23%      13.1
/// ```
///
/// **What the old walk of three steps cost.** It was chosen to hold the resting
/// orders near the mid, and it did that. Measured over 50,000 messages at 40
/// accounts and 24 messages a second, when the walk was a fixed step count and
/// a crossing order took a whole level:
///
/// ```text
/// steps back   orders within 1% of the mid   H5 depth   5-minute candle
///          3                        93.2%       56.0              0.42%
///          4                        88.4%       53.9              0.56%
///          8                        51.2%       35.4              1.16%
///         16                        19.5%       12.9              2.05%
///         64                        16.9%       10.6              2.37%
/// ```
///
/// Every row measures 1.00 orders a crossing order and 66% of limit orders
/// ending cancelled, so the choice cost nothing there. It is the shape of the
/// book that moves. Three steps holds 93.2% of the resting orders within 1% of
/// the mid; that number was 22.8% before the bands became price steps and 93.6%
/// after.
///
/// **Three steps is half of what stopped the price moving.** `a_level_to_take`
/// is the other half, and it carries the deployment numbers. Measured over
/// 150,000 messages at 40 accounts and 24 messages a second, one change at a
/// time from commit af9968b:
///
/// ```text
/// what is in place                             price band   candle body
/// commit af9968b                                    0.69%        0.103%
/// a crossing order takes one order                  1.58%        0.171%
/// and the walk is 14 steps, 1 per 4 orders          3.07%        0.272%
/// ```
///
/// A fixed walk of three steps makes the front of a 57-order side three levels
/// deep whatever the book holds, and a crossing order that removes one order
/// cannot move a price past a level that still holds another.
///
/// **What the longer walk costs.** The book spreads out. Measured over 50,000
/// messages at 40 accounts and 24 messages a second, at 3 steps and at these
/// two numbers:
///
/// ```text
///                       within 1% of the mid   H5 depth   5-minute candle
/// 3 steps, fixed                       93.2%       56.0             0.42%
/// 14 steps, 1 per 4 orders             37.7%       25.4             1.84%
/// ```
///
/// The first column is what the old walk was chosen for, and it falls by 55
/// points. The last column is the same fall read the other way: the price now
/// moves inside a five-minute candle, and that is what the chart was missing.
/// H5 wants 10 orders a side within 10 price steps and measures 25.4, so the
/// spread is paid for out of margin the run had and not out of the assertion.
///
/// **This is the quiet state's walk.** The activity state multiplies it by 1, 2
/// or 3, so the busy state may walk 42 steps. See `PLACEMENT_WIDTH`. The walk
/// and the band are the two numbers the state widens, and widening both is what
/// makes the price move further in a busy market rather than only more often.
const MOST_STEPS_FROM_THE_TOUCH: i64 = 14;

/// How many orders one side must hold before the walk may spend one more price
/// step on it. See `MOST_STEPS_FROM_THE_TOUCH`.
const ORDERS_A_FREE_STEP_COSTS: i64 = 4;

/// How fast a quote becomes less likely the further it sits from the other
/// side's best price. The chance of `i` steps is proportional to `i^-1`.
///
/// `docs/GENERATOR-RFC.md` section 4.3 sets this exponent, and asks for the
/// value to be written down where the generator reads it. The measured range is
/// 0.6 on the Paris exchange, 1.0 on Nasdaq and 1.5 on the London Stock
/// Exchange. No study agrees with another. 1.0 is the middle value, and it is
/// the one the RFC picks.
///
/// The number was 0.52, from Cont, Stoikov and Talreja (2010), Table 2. That is
/// below every value in the measured range. A smaller exponent puts quotes
/// further from the best price. 1.0 puts more of them at the best price, which
/// is what assertion H4 needs.
const QUOTE_DEPTH_EXPONENT: f64 = 1.0;

/// The smallest and largest quantity one quote carries, in tenths of a unit.
/// A quote is 2.5 to 25.0 units.
///
/// This pair sets the volume the chart draws, and nothing else. The trades a
/// second do not move with it, and no assertion in `docs/GENERATOR-RFC.md`
/// does either.
///
/// The pair was 1.0 to 10.0 units. Volume in one 15-second candle was 277 to
/// 286 on the deployment, and it fell to 118 to 123 when commit af9968b landed.
/// One crossing order stopped removing 4.12 resting orders and started removing
/// 1.00, so it printed a quarter of the quantity it used to. Section 4.5 of the RFC is what holds that count at one, see
/// `TAKE_EVERY`, so the quantity of one order is the only number left that can
/// carry the volume back. Measured over 150,000 messages at 40 accounts and 24
/// messages a second:
///
/// ```text
/// one quote        volume a 15-second candle   price band   cancelled
/// 1.0 to 10.0                            110        3.07%       66.5%
/// 2.5 to 25.0                            275        2.97%       66.5%
/// 1.0 to 50.0                            512        3.08%       66.5%
/// ```
///
/// **What this costs when the bot runs.** `bot.rs` sends at most 10 units in
/// one order, so a bot order can now fill part of a generator quote where it
/// used to fill all of it. The exchange keeps the rest of that quote resting
/// under the same order id, so the generator's cancel still finds it. What the
/// generator gets wrong is the quantity, and it names that quantity on its own
/// crossing orders. Such an order is immediate-or-cancel, so the exchange fills
/// what is there and throws the rest away. The generator-only measurement has
/// no bot, while `demo.sh` does.
const SMALLEST_QUOTE_TENTHS: i64 = 25;
const LARGEST_QUOTE_TENTHS: i64 = 250;

/// How many orders each side of a book must hold. The generator checks this
/// before it sends a take, and it checks again what the take would leave
/// behind.
///
/// A take empties the whole best level. A side that holds one order would go
/// empty. A market with an empty side trades nothing until a quote fills that
/// side again.
///
/// Two orders a side after every event is the backstop
/// `docs/GENERATOR-RFC.md` section 4.7 asks for, from Gu and others (2021) and
/// McGroarty and others (2019). `the_best_level` applies it to both sides.
const TAKE_NEEDS_A_SIDE_OF: usize = 2;

/// How far the generator leans its choice of side, to hold a market near the
/// price the market was listed at.
///
/// The generator prices every order from the book and never from a number
/// outside the book. Nothing therefore stops the price of a market moving far
/// away over a long run. `ANCHOR_STRENGTH` leans the choice of side instead of
/// the choice of price. A market above its listed price gets more sells, and a
/// market below it gets more buys. At 5% away from the listed price the split
/// is 60/40. At 20% away and beyond it is 90/10.
///
/// This lean is the only anchor, and it is enough. A quote is priced behind the
/// best price on the other side, so a wide spread used to move the mid a long
/// way in one message: a buy placed 1 step under a sell price 28 steps above
/// the best buy price raised the mid by half that gap. Narrow bands remove the
/// wide spread, and the move goes with it. Measured over 50,000 messages, the
/// mid sat 2.04% from the listed price on average and 8.95% away at worst when
/// the bands were shares of the price, against 0.80% and 2.65% once they became
/// price steps. It now sits 0.21% away on average and 0.75% at worst, because
/// `MOST_AT_A_LEVEL` keeps the front of each book one order a price, so a
/// crossing order moves the best price by one step and not by a whole queue. A
/// second anchor was tried and rejected: holding a buy at or below the mid of
/// the book. `docs/GENERATOR-RFC.md` section 3.3 names that clamp as part of
/// the failure it describes, and the measurement shows there is nothing left
/// for it to fix.
///
/// `a_level_to_take` used to overrule this lean on every crossing order, by
/// taking whichever side of the book was thinner. The price then stopped moving
/// on the deployment: the band over 25 minutes fell from 2.84%-3.58% to
/// 0.83%-1.00%. That doc comment holds the measurement. The lean now picks the
/// side of every message, quote and crossing order alike, and the drift numbers
/// above are from before the override was removed. The run now measures 0.57%
/// from the listed price on average and 1.95% at worst. The lean on its own
/// holds a market inside 2% of the price it was listed at, over 50,000 messages
/// at 40 accounts and 24 messages a second.
const ANCHOR_STRENGTH: f64 = 2.0;

/// The furthest from an even split the lean may push the choice of side.
const ANCHOR_LIMIT: f64 = 0.4;

/// How many orders the generator holds open at once, at most.
///
/// This is a memory bound and not the depth control. `BAND_LIFETIMES_MS` sets
/// the depth, and the depth follows the message rate. Measured over 50,000
/// messages at 40 accounts, orders open at the end of the run:
///
/// ```text
/// a flat 6 a second     76
/// the floor, 24        326
/// the mean, 69         968
/// the peak, 114      1,616
/// the states switching, while a book built for the peak drains   1,526
/// ```
///
/// 1,616 against 4,000 is a margin of 2.5 times. The busy state's steady book
/// is the largest a run reaches, because `CANCELS_IN_A_ROW` slows the drain but
/// nothing makes the book grow past the state that filled it. Raising `--rate`
/// raises this: the busy state is `2 * RATE - 24` and the
/// book is about 14 orders for every message a second, so a `RATE` above about
/// 155 reaches the bound.
///
/// The generator drops nothing from the list to make room. An order the
/// generator forgot could never be cancelled again, and that is the fault this
/// file exists to remove. At the bound the generator therefore cancels an order
/// instead of placing one, and it cancels whatever `CANCELS_IN_A_ROW` says.
///
/// Only a history a different build wrote reaches this bound. `with_db`
/// rebuilds the list from the log, and a log the old generator wrote holds
/// thousands of orders that were never cancelled.
pub(super) const MAX_OPEN_ORDERS: usize = 4_000;

/// The price range every generated price is held inside. It is the same range
/// the matching engine can represent, so a generated price is always a price
/// the engine accepts.
///
/// No price reaches these two bounds in a realistic run. The bounds exist
/// because a restart reads the reference price of a market from *the last
/// published price of that market* (see the mid reload in `with_db`). An
/// unbounded value there used to reach `f64::INFINITY`. serde writes
/// `f64::INFINITY` as JSON `null`, and nothing can read `null` back as a price.
/// The generator's arithmetic must have no path to a value it cannot write as
/// JSON.
const MIN_PRICE: f64 = 1.0 / PRICE_SCALE;
const MAX_PRICE: f64 = MAX_GRID_UNITS as f64 / PRICE_SCALE;

/// How often the generator wakes up to publish the messages the rate has
/// accrued. One tick is one database transaction, which is one fsync, whatever
/// the rate is. A higher rate therefore makes each burst bigger. It does not
/// make the writes to disk more frequent.
const GENERATOR_TICK: Duration = Duration::from_millis(100);

/// The message rate of the quiet state, and the floor no state goes below.
///
/// This is the deployment rate used before the activity state existed. Every
/// assertion in `docs/GENERATOR-RFC.md` section 5 passes at it
/// with margin: the worst gap between two trades is 35 messages, which is 1.5
/// seconds against the 60 seconds assertion H2 allows, and the thinnest market
/// trades 0.056 times a message against the 0.02 assertion H3 wants. Section
/// 4.6 asks for a floor "sized so section 5 H2/H3 cannot trip in the quiet
/// regime". A rate that already passes H2 by 40 times and H3 by 2.8 times is
/// that size, measured on this generator rather than chosen.
///
/// **The floor does not move when `RATE` moves.** The `--rate` argument is the
/// mean of the three states. The generator
/// builds the states as `24`, `RATE` and `2 * RATE - 24`, so the mean of the
/// three is `RATE` and the quiet state is this constant whatever `RATE` says.
/// At `RATE: "69"` the states are 24, 69 and 114 messages a second. At
/// `RATE: "40"` they are 24, 40 and 56. Editing `RATE` moves the mean and the
/// peak and leaves the floor here.
///
/// A `RATE` at or below 24 asks for a deployment quieter than the floor, so
/// there is no floor left to hold: the generator then runs flat at `RATE` and
/// switches nothing. It draws no random number for the state either, so the
/// history is the one this file published before the activity state existed,
/// give or take `CANCELS_IN_A_ROW`. Measured over 50,000 messages at 40
/// accounts on seed 20260816, this branch against the commit before it:
///
/// ```text
/// a flat rate of   quotes   takes   cancels   depth a side   worst gap
///  6, before        25,043   8,342    16,615           13.0          37
///  6, now           25,042   8,341    16,617           13.1          35
/// 24, before        25,167   8,384    16,449           55.1          37
/// 24, now           25,168   8,385    16,447           55.4          35
/// ```
///
/// The rows differ by one or two messages in fifty thousand. Two things make
/// that difference and neither is the activity state: `CANCELS_IN_A_ROW` holds
/// a cancel back when a third one falls due in a row, and the measurement's own
/// clock now adds up the milliseconds between messages instead of working them
/// out from the message number, which lands on a different millisecond about
/// once a run.
///
/// That is what keeps the low-rate runs unchanged: `docker/entrypoint.sh`
/// defaults to 2, CI runs 5, `services/tests/genesis.rs` runs 1 and
/// `services/tests/fault_injection.rs` runs 10.
pub(super) const QUIET_RATE: f64 = 24.0;

/// The fastest the generator ever runs, in messages a second.
///
/// `produce_orders` clamps the rate it accrues to this, so a state above it
/// would not be the rate it says it is, and the mean of the three states would
/// not be `RATE`. A mean above 512 puts the busy state past this ceiling, so
/// the generator runs flat there instead of running three states that do not
/// average to what they claim. `services/tests/crash_restart.rs` runs at 1000
/// for one reason: 100 messages accrue in one 100 ms tick, so one database
/// transaction carries a hundred inserts. That run stays flat.
const FASTEST_RATE: f64 = 1000.0;

/// How long one activity state lasts, in milliseconds, on average.
///
/// The draw is exponential, so a state has the same chance of ending in the
/// next second whatever its age. Five minutes is chosen from the chart, which
/// offers 15s, 5m, 15m, 1h and 4h candles
/// (`services/static/app.js`, `INTERVALS`). A state that lasts about one
/// 5-minute candle puts the busy stretches and the quiet stretches where a
/// reader looks, and a 15-minute bar then holds about three states, so its
/// volume varies rather than repeating.
///
/// The number sets one measured quantity directly: the coefficient of
/// variation of the volume in a 15-minute bucket, which is the flat volume
/// histogram `docs/GENERATOR-RFC.md` section 4.6 names as the third visual
/// tell. For a three-state Markov switch with equal dwell means, the variation
/// of the time-average over a window `T` is `sqrt(1800 * t / T) / 69`, where
/// `t` is this mean in seconds. At `T` = 900 seconds that gives 0.16 at a
/// 1-minute mean, 0.27 at 3 minutes, 0.35 at 5 minutes and 0.50 at 10 minutes.
/// Measured at 5 minutes over 600 minutes of market time: 0.328.
/// `print_movement` reports it beside the price band, and
/// `how_the_volume_varies` reads it on three seeds.
///
/// **0.3 to 0.4 is the value this file aims at, and here is why that band and
/// not a larger one.** The deployment measures 0.019 today, which is a row of
/// bars the same height. A real 24-hour crypto market runs at roughly 0.5 to
/// 1.0 over a day, and most of that is the trading day itself: Asia, then
/// Europe, then the United States. This market has no trading day, so copying
/// that number would mean inventing one. Two things also bound it from above.
/// The peak state sets the monthly disk bill, so a wider spread of rates at the
/// same mean costs disk. And a longer state makes the quiet stretch long
/// enough to look like the dead market section 3 of `docs/GENERATOR-RFC.md`
/// describes. 0.328 is 23 times the flat rate and under the real number.
const STATE_MEAN_MS: f64 = 300_000.0;

/// The longest one activity state may last, in means. An exponential draw has
/// no upper end, and a draw of a day would be a chart that shows one state and
/// nothing else. Six means is 30 minutes, which is two of the 15-minute bars
/// the chart draws. One state in 403 draws longer than that.
const LONGEST_STATE_IN_MEANS: f64 = 6.0;

/// How much wider a quote sits from the touch in each of the three states.
///
/// Section 4.6 of `docs/GENERATOR-RFC.md` says the same state variable MUST
/// scale the message rate **and** the placement dispersion, "so volume and
/// volatility co-move". This array is the second half. It multiplies two
/// numbers: `PATIENCE_BANDS`, which is the furthest a quote may be drawn from
/// the other side's best price, and `MOST_STEPS_FROM_THE_TOUCH`, which is the
/// furthest the walk may push a quote that drew a price already taken. So the
/// busy state draws over 3, 6, 9, 15 and 30 price steps where the quiet state
/// draws over 1, 2, 3, 5 and 10, and its walk reaches 42 steps where the quiet
/// walk reaches 14.
///
/// **The rate on its own makes a busy market LESS volatile, not more.** That is
/// the measurement this array exists for. Measured over 150 minutes of market
/// time in each state, at 40 accounts, one thing scaled at a time:
///
/// ```text
/// what the state scales              a second   band     body     h5   depth
/// the rate only                            24  3.17%   0.259%   24.9    56.1
///                                          69  2.80%   0.374%   53.8   164.3
///                                         114  2.51%   0.413%   88.2   274.0
/// the rate and the band                    24  3.17%   0.259%   24.9    56.1
///                                          69  2.93%   0.381%   53.9   163.1
///                                         114  2.70%   0.437%   84.1   269.6
/// the rate, the band and the walk, 1/2/2   24  3.17%   0.259%   24.9    56.1
///                                          69  4.37%   0.462%   13.5   165.6
///                                         114  4.21%   0.549%   16.8   275.7
/// the rate, the band and the walk, 1/2/3   24  3.17%   0.259%   24.9    56.1
///                                          69  4.37%   0.462%   13.5   165.6
///                                         114  5.03%   0.595%   11.1   274.4
/// ```
///
/// Read the first block. The volume in a 15-second candle goes from 276 at 24
/// messages a second to 1,308 at 114, and the price band goes the other way,
/// from 3.17% down to 2.51%. Volume up and volatility down is a worse market
/// than the flat one section 4.6 is trying to fix, and it is what the rate does
/// on its own.
///
/// **Why.** A crossing order removes the one order the exchange fills first at
/// the best price (`the_best_level`), so the best price moves one step and the
/// touch walks. The walk stops when the touch reaches the price where the
/// quotes that found no free step have piled up, because `MOST_AT_A_LEVEL`
/// keeps one order at a price only as far out as the walk reaches. At 24
/// messages a second that pile sits 14 steps out and holds about 42 orders. At
/// 114 it sits at the same 14 steps and holds about 260, so the touch meets a
/// wall 6 times thicker, 4.75 times more often. Widening the walk moves the
/// wall out to 42 steps and thins it, and the touch travels further before it
/// is stopped.
///
/// **The band alone is not enough.** Block two scales `PATIENCE_BANDS` and
/// leaves the walk at 14 steps: the peak band moves from 2.51% to 2.70%, which
/// is still below the 3.17% of the quiet state. The band is what section 4.3
/// names as the placement distribution, so it is scaled; the walk is what makes
/// the scaling bite.
///
/// **1/2/2 was measured and rejected.** It holds 16.8 orders inside the 10
/// price steps assertion H5 counts, against 11.1 at 1/2/3, and H5 wants 10. It
/// costs the co-movement: the peak's band is 4.21% and the mean's is 4.37%, so
/// the market gets busier and stops getting more volatile between the two busy
/// states. Section 4.6 wants volume and volatility to co-move, and 1/2/3 is the
/// shortest table where the band rises at every step: 3.17%, 4.37%, 5.03%.
///
/// **What 1/2/3 costs.** 11.1 orders within 10 price steps at the peak, against
/// the 10 assertion H5 asks for. That is the tightest margin in this file. It
/// is measured at 12.8 over the 50,000 messages
/// `the_generated_traffic_keeps_every_market_trading` drives, on two seeds. A
/// wider table would spend the rest of it.
///
/// The quiet state is 1, which is the placement this deployment already runs.
/// The floor of the activity state is today's deployed market in both numbers,
/// not only in the rate.
///
/// The four blocks above are one build each, so they compare with each other.
/// The last block was measured again after `CANCELS_IN_A_ROW` landed and reads
/// 3.13%, 4.39% and 5.08%, so the cap moves a state held at one rate by under
/// 2%. Those are the numbers `docs/GENERATOR-RFC.md` section 9 carries.
const PLACEMENT_WIDTH: [i64; 3] = [1, 2, 3];

/// Which of the three activity states the generator is in: how many messages a
/// second it sends, and how far from the touch it places a quote.
///
/// Section 4.6 of `docs/GENERATOR-RFC.md` allows two shapes, "a 2-3-state
/// regime switch or a Hawkes self-exciting intensity with branching ratio
/// n in [0.5, 0.8]". This is the regime switch. **The Hawkes intensity was
/// read and rejected, on disk cost.** A Hawkes process sets no maximum. Its
/// mean intensity is `mu / (1 - n)`, so with the floor of 24 messages a second
/// as `mu`, the band the RFC allows spans a mean of 48 messages a second at
/// n = 0.5 and 120 at n = 0.8. A message costs 331 bytes on disk, so that band
/// is 41 GB to 103 GB over a monthly restart. The upper half exceeds the
/// deployment's storage budget. Clipping the intensity to bound it removes the
/// heavy tail, which is the only reason to run a Hawkes process rather than a
/// switch.
/// A three-state switch has a maximum by construction: the busy state is a
/// number in this file, and the monthly disk cost is that number times 331
/// bytes.
///
/// **The three states are 24, 69 and 114 messages a second, and each holds a
/// third of the time.** 24 is the floor, `QUIET_RATE`. 69 is the configured
/// mean. 114 follows from the
/// other two, because `(24 + 69 + 114) / 3 = 69`.
///
/// The state moves on the sequencer's own clock and on nothing else. The
/// sequencer holds no book and reads nothing from the exchange, and this state
/// does not change that.
pub(super) struct Activity {
    /// The messages a second of each state, quietest first.
    rates: [f64; 3],
    /// The placement width of each state. See `PLACEMENT_WIDTH`.
    widths: [i64; 3],
    /// Which of the three states is running.
    at: usize,
    /// The millisecond this state ends at. `None` before the first message,
    /// which is what makes the first message start a state rather than switch
    /// one.
    until_ms: Option<u64>,
}

impl Activity {
    /// The three states a mean message rate gives.
    ///
    /// A mean at or below the floor, or a busy state past the ceiling, leaves
    /// no room for three states. The generator then runs flat at the mean. See
    /// `QUIET_RATE` and `FASTEST_RATE`.
    pub(super) fn of(mean: f64) -> Activity {
        let peak = 2.0 * mean - QUIET_RATE;
        if mean <= QUIET_RATE || peak > FASTEST_RATE {
            return Activity::flat(mean);
        }
        Activity {
            rates: [QUIET_RATE, mean, peak],
            widths: PLACEMENT_WIDTH,
            // The middle state, so a sequencer starts at the mean rate and not
            // at an end of the range. A restart reads its open orders back out
            // of the log, and that book may have been built at the busy rate.
            // Starting in the quiet state would put a book of 1,600 orders
            // behind 24 messages a second, which is the case `CANCELS_IN_A_ROW`
            // exists for. Starting at the mean means a restart never meets it.
            at: 1,
            until_ms: None,
        }
    }

    /// One rate for the whole run, and the placement this file ran before the
    /// activity state existed.
    fn flat(rate: f64) -> Activity {
        Activity {
            rates: [rate; 3],
            widths: [1; 3],
            at: 1,
            until_ms: None,
        }
    }

    /// The messages a second this state sends. `produce_orders` accrues at this
    /// rate, and a measurement advances its clock by `1000 / this` for one
    /// message.
    pub(super) fn messages_a_second(&self) -> f64 {
        self.rates[self.at]
    }

    /// How much wider than the quiet state this state places a quote. See
    /// `PLACEMENT_WIDTH`.
    fn placement_width(&self) -> i64 {
        self.widths[self.at]
    }

    /// Whether this activity has more than one state. A flat activity draws no
    /// random number and switches nothing, so a run at 6 messages a second
    /// publishes the same history it published before this type existed.
    fn switches(&self) -> bool {
        self.rates[0] < self.rates[2]
    }

    /// Moves to the next state when this one has run out, and draws how long
    /// the new one lasts.
    ///
    /// The next state is one of the other two, each with the same chance. That
    /// is what gives each of the three states a third of the time. A switch
    /// that could also pick the state already running would leave the quiet
    /// state and the busy state next to each other less often, and the point of
    /// the state is that the market changes.
    fn switch_when_due(&mut self, now_ms: u64, rng: &mut StdRng) {
        if !self.switches() {
            return;
        }
        match self.until_ms {
            Some(until) if now_ms < until => return,
            Some(_) => self.at = (self.at + 1 + rng.gen_range(0..2)) % self.rates.len(),
            None => {}
        }
        let draw: f64 = rng.gen_range(0.0..1.0);
        let held = -STATE_MEAN_MS * (1.0 - draw).ln();
        self.until_ms =
            Some(now_ms.saturating_add(held.min(STATE_MEAN_MS * LONGEST_STATE_IN_MEANS) as u64));
    }

    /// The same three states, held at one of them for the whole run.
    ///
    /// Section 4.6 asks for the assertions of section 5 to hold in every state,
    /// and a run that switches measures the mixture and not the state. So every
    /// measurement runs three times, once held at each state. For measurement
    /// only.
    #[cfg(test)]
    fn held_at(mean: f64, at: usize) -> Activity {
        let mut activity = Activity::of(mean);
        activity.at = at;
        activity.until_ms = Some(u64::MAX);
        activity
    }
}

/// The random numbers the generator draws from. The operating system supplies
/// the seed, so two sequencers do not publish the same history.
pub(super) fn new_rng() -> StdRng {
    StdRng::from_entropy()
}

/// The same random numbers on every run. Tests and measurements use this. See
/// `FeedState::seed_the_generator`.
pub(super) fn seeded_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// A loop that publishes random messages at a target rate. On every tick the
/// loop first reads the entries the separate service holds.
///
/// The rate accrues in fractions across ticks. At 2 messages a second and a
/// 100 ms tick, each tick accrues 0.2 messages, so the loop publishes one
/// message every fifth tick. At 100 a second each tick publishes ten messages
/// in one burst. Both rates spend one transaction on a tick that publishes.
///
/// `rate` is the mean of the three activity states, not one fixed rate. See
/// `Activity`. The loop reads the rate of the state that is running back out of
/// the sequencer state on every tick that publishes, so the accrual follows the
/// state. The read is one tick behind, because the rate lives behind the lock
/// and the accrual decides whether the tick takes the lock at all. One tick is
/// 100 ms and a state lasts five minutes on average, so a switch is at most
/// 0.03% late.
///
/// The entries from the separate service are sequenced first, before the tick's
/// generated messages. Those entries exist for users whose own `POST /order` on
/// the sequencer did not work, so they must not also wait behind the
/// simulator's own traffic.
///
/// A sequencer that names an operator drains and generates nothing until the
/// operator has published the complete opening. See `FeedState::log_is_open`.
/// The generator drops the messages a held tick would have made. When the log
/// opens, traffic starts without a burst owed from an earlier tick.
pub(super) async fn produce_orders(
    state: Arc<Mutex<FeedState>>,
    rate: f64,
    inbox_url: Option<String>,
) {
    let mut drain = match Drain::new() {
        Ok(drain) => drain,
        Err(e) => {
            error!("cannot build the inbox client: {}", e);
            std::process::exit(2);
        }
    };
    // The three activity states are built from the rate here, in the one place
    // that holds the rate. See `Activity`.
    let mean = rate.clamp(0.1, FASTEST_RATE);
    let _ = with_state(&state, move |state| {
        state.activity = Activity::of(mean);
    })
    .await;
    let mut accrued = 0.0;
    let mut last_complaint: Option<Instant> = None;
    loop {
        sleep(GENERATOR_TICK).await;

        // Ask before draining the inbox. Inbox messages and direct user
        // submissions obey the same gate as generated traffic, so none can
        // occupy a position reserved for the opening.
        let opening = with_state(&state, |state| {
            (state.log_is_open(), state.activity.messages_a_second())
        })
        .await;
        let (open, current_rate) = match opening {
            Ok(opening) => opening,
            Err(_) => continue,
        };
        if !open {
            accrued = 0.0;
            complain_about_the_closed_log(&mut last_complaint);
            continue;
        }

        if let Some(inbox) = &inbox_url {
            drain_inbox(&mut drain, inbox, &state).await;
        }

        accrued += current_rate * GENERATOR_TICK.as_secs_f64();
        let count = accrued as usize;
        accrued -= count as f64;
        if count == 0 {
            continue;
        }
        // `sequence` has already logged a failed write, and a failed write
        // publishes nothing. The next tick hands out the same ids again.
        let _ = with_state(&state, move |state| {
            let burst: Vec<OrderMessage> = (0..count)
                .map(|_| {
                    let msg = generate_message(state);
                    info!("Publishing message: {:?}", msg);
                    msg
                })
                .collect();
            let _ = state.publish_batch(burst);
        })
        .await;
    }
}

/// Warns once that the operator has not completed the opening, then warns
/// again at most every `COMPLAIN_EVERY`.
///
/// This is the same shape as `Drain::complain`, and the reason to wait between
/// warnings is the same. The generator runs ten times a second, so one line per
/// tick would hide every other line the sequencer prints. Printing the warning
/// only once is worse than repeating it: a sequencer waiting for its opening
/// looks exactly like a dead sequencer after the startup line scrolls away.
fn complain_about_the_closed_log(last_complaint: &mut Option<Instant>) {
    let now = Instant::now();
    let due = last_complaint.is_none_or(|last| now.duration_since(last) >= COMPLAIN_EVERY);
    if due {
        *last_complaint = Some(now);
        warn!(
            "this sequencer names an operator and its opening is incomplete, so it is \
             publishing nothing except messages sent through POST /operator"
        );
    }
}

/// Generates the next random message, with the time from the sequencer's clock.
pub(super) fn generate_message(state: &mut FeedState) -> OrderMessage {
    let timestamp = state.clock.now_ms();
    generate_message_at(state, timestamp)
}

/// Generates the next random message at a given millisecond.
///
/// The time is a parameter because the generator's cancels are timed. The
/// generator cancels an order when the order's life ends, and a life is a
/// number of milliseconds. A test that drove 50,000 messages through the real
/// clock would run for two hours and cancel nothing. A test therefore supplies
/// the time that the live run reads off `state.clock`.
///
/// One message does one of three things, in this order:
///
/// 1. it cancels an order whose life has ended;
/// 2. it takes the whole best level on one side of one market, when a crossing
///    order is due, see `TAKE_EVERY`;
/// 3. it places a limit order behind the best price on the other side.
///
/// A cancel wins because an order's life is a wall-clock deadline and the
/// generator cannot hold it back. That is also why `TAKE_EVERY` counts only the
/// messages that are not cancels.
pub(super) fn generate_message_at(state: &mut FeedState, timestamp: u64) -> OrderMessage {
    // 0. The activity state, which is a function of the clock and of nothing
    //    else. A cancel advances it too, because time passed for a cancel as
    //    much as for a quote. See `Activity`.
    state.activity.switch_when_due(timestamp, &mut state.rng);
    let wider = state.activity.placement_width();

    let id = state.next_id;
    state.next_id += 1;

    // 1. An order whose life has ended, or one order too many. In both cases
    //    the generator cancels an order instead of forgetting it. An order the
    //    generator forgot could never be cancelled again, and the book would
    //    only grow.
    //
    //    A cancel wins, but not more than `CANCELS_IN_A_ROW` times in a row. A
    //    book built for a busier activity state has more cancels due than the
    //    quiet state has messages, and the market stopped trading while it
    //    drained.
    let at_the_bound = state.open_orders.len() >= MAX_OPEN_ORDERS;
    let may_cancel = at_the_bound || state.cancels_in_a_row < CANCELS_IN_A_ROW;
    if may_cancel
        && let Some(index) = order_to_take_back(&state.open_orders, timestamp, at_the_bound)
    {
        state.cancels_in_a_row = state.cancels_in_a_row.saturating_add(1);
        let done = state.open_orders.swap_remove(index);
        return cancel(id, timestamp, done.account, done.id);
    }
    state.cancels_in_a_row = 0;

    // 2. The market. A crossing order is due every `TAKE_EVERY` messages that
    //    are not cancels, and the three markets take turns at it. Every other
    //    message picks a market at random.
    let due = state.since_crossing + 1 >= TAKE_EVERY
        && quoting_accounts(state.num_accounts) < state.num_accounts;
    let market = if due {
        (state.crossings % SYMBOLS.len() as u64) as usize
    } else {
        state.rng.gen_range(0..SYMBOLS.len())
    };
    let (symbol, listed_price, price_step) = SYMBOLS[market];
    let step_cents = steps_in_cents(price_step);
    let mut side = pick_side(state, market, listed_price);
    remember_the_price(state, market, symbol);

    // 3. The crossing order. It buys every sell order at the lowest sell price,
    //    or sells every buy order at the highest buy price. The order is
    //    immediate-or-cancel, so no part of it rests:
    //    `step6_remainder_policy`. It comes from a taking account, which
    //    therefore holds nothing in any book and can never meet an order of its
    //    own.
    let take = if due {
        let (taking, level) = a_level_to_take(&state.open_orders, market, side);
        side = taking;
        level
    } else {
        None
    };
    // A market whose sides are still filling has no level to take. The
    // generator quotes into that market instead, and the quote comes from a
    // quoting account. A taking account must never leave an order behind: the
    // self-trade rule cannot refuse an account that has nothing resting.
    let account = match take {
        Some(_) => a_taking_account(state),
        None => a_quoting_account(state),
    };
    if take.is_some() {
        state.crossings += 1;
        state.since_crossing = 0;
    } else {
        // Saturating, because a market whose books never fill never takes, and
        // the counter would otherwise run past the end of a u32 after 4 billion
        // messages. It stays above `TAKE_EVERY`, which is what makes the next
        // message try again.
        state.since_crossing = state.since_crossing.saturating_add(1);
    }
    if let Some(taken) = take {
        state
            .open_orders
            .retain(|open| !taken.orders.contains(&open.id));
        return OrderMessage::New {
            id,
            timestamp,
            account,
            symbol: symbol.to_string(),
            side,
            // The exact price of the level this order takes, so the order
            // crosses that one price and no other price.
            price: in_price(taken.price_cents),
            quantity: in_quantity(taken.qty_tenths),
            nonce: None,
            // A limit order priced to cross, and not a market order. The reason
            // is measured. ENGINE.md 4.2: "a market order is a limit order
            // priced to cross". ENGINE.md 4.2.2 puts a collar on a market order
            // at 2% of the reference price, and the reference price is a mid
            // averaged over the last 30 seconds. The sequencer holds no book,
            // so it cannot know that reference price, and ENGINE.md section 5
            // says the sequencer must not write a second copy of the rule to
            // work it out. Measured over 50,000 messages with market orders:
            // the collar cut 189 of the 8,113 market orders. Each cut order
            // left a level in the book that the generator believed had gone.
            // Those forgotten orders then made the exchange refuse 23 later
            // orders as self-trades, and nothing could cancel them. With a
            // limit order the sender names the price and the exchange does not
            // move it, so the level the order names is the level it takes.
            order_type: Default::default(),
            time_in_force: TimeInForce::ImmediateOrCancel,
            post_only: false,
        };
    }

    // 4. A quote, priced behind the other side's best price, inside this
    //    account's patience band. A market with an empty side needs quotes
    //    before anything can trade, so this step also fills a book at the start
    //    of a run.
    //    The band and the walk are both multiplied by the activity state's
    //    placement width, so a busy state places its quotes further out. See
    //    `PLACEMENT_WIDTH`.
    let band = PATIENCE_BANDS[band_of(account)] * wider;
    let most_steps = MOST_STEPS_FROM_THE_TOUCH * wider;
    let touch = best_cents(&state.open_orders, market, other(side))
        // An empty side has no best price. This is the only case that reads the
        // price the market was last seen at instead of reading the book.
        .unwrap_or_else(|| remembered_cents(state, symbol));
    let most = steps_in_the_band(step_cents, band);
    let steps = steps_behind_the_touch(&mut state.rng, most);
    let price_cents = a_free_step(
        &state.open_orders,
        market,
        side,
        on_the_step(behind(side, touch, steps * step_cents), step_cents),
        step_cents,
        on_the_step(
            behind(
                side,
                touch,
                steps_to_spend(&state.open_orders, market, side, most_steps) * step_cents,
            ),
            step_cents,
        ),
        most_steps,
    );

    // A quote can cross in one case: the price reached the floor of the grid,
    // so the generator could not put the quote behind the other side. The check
    // costs nothing, and it makes "a quoting account never trades with itself"
    // true and not almost true.
    // `the_generated_traffic_keeps_every_market_trading` counts how often the
    // check fires over 50,000 messages, and the answer is never.
    if let Some(index) =
        own_order_in_the_way(&state.open_orders, account, market, side, price_cents)
    {
        let target = state.open_orders.swap_remove(index);
        return cancel(id, timestamp, target.account, target.id);
    }

    let qty_tenths = state
        .rng
        .gen_range(SMALLEST_QUOTE_TENTHS..=LARGEST_QUOTE_TENTHS);
    state.open_orders.push(OpenOrder {
        id,
        account,
        market,
        side,
        price_cents,
        qty_tenths,
        expires_at_ms: timestamp.saturating_add(a_life(&mut state.rng, band_of(account))),
    });

    OrderMessage::New {
        id,
        timestamp,
        account,
        symbol: symbol.to_string(),
        side,
        price: in_price(price_cents),
        quantity: in_quantity(qty_tenths),
        nonce: None,
        // A quote is a limit order. It is good-till-cancel and not post-only,
        // as every generated order has been since the sequencer existed. These
        // three fields take the default values, so the message writes no bytes
        // for them.
        order_type: Default::default(),
        time_in_force: Default::default(),
        post_only: false,
    }
}

/// Replays one stored message into the list of orders the generator holds open,
/// so a restart continues with the books the sequencer left.
///
/// The three cases are the three kinds of message this file sends, read back.
/// An order that did not rest took the whole level it named. A good-till-cancel
/// limit order rests. A cancel takes one order out. This function matches
/// nothing: it does the same bookkeeping `generate_message_at` does, on a
/// message read off the disk instead of a new message.
///
/// Every order comes back with no life. `with_db` gives the whole list fresh
/// lives once the clock is built, so the depth control starts again from the
/// restart. A log an older build wrote holds orders that were never cancelled.
/// Those orders come back here too, and `MAX_OPEN_ORDERS` bounds them.
pub(super) fn replay_into_the_open_orders(open: &mut Vec<OpenOrder>, message: &OrderMessage) {
    match message {
        OrderMessage::New {
            id,
            account,
            symbol,
            side,
            price,
            quantity,
            order_type,
            time_in_force,
            ..
        } => {
            let Some(market) = SYMBOLS.iter().position(|(listed, _, _)| listed == symbol) else {
                return;
            };
            let price_cents = in_cents(*price);
            // A market order and an immediate-or-cancel order both trade at
            // once and leave nothing behind. Neither one rests:
            // `step6_remainder_policy`.
            //
            // The exchange fills one price oldest first, so the replay takes
            // the orders off in id order until the quantity this order named is
            // used up. That is the arithmetic `the_best_level` does when it
            // builds the order, run backwards. A log an older build wrote holds
            // crossing orders that named a whole level, and the same loop reads
            // those back too, because it follows the quantity and not a count.
            if !order_type.is_limit() || *time_in_force != TimeInForce::GoodTillCancel {
                let mut level: Vec<(OrderId, i64)> = open
                    .iter()
                    .filter(|held| at_the_level(held, market, other(*side), price_cents))
                    .map(|held| (held.id, held.qty_tenths))
                    .collect();
                level.sort_unstable_by_key(|(id, _)| *id);
                let mut wanted = (*quantity * 10.0).round() as i64;
                let mut taken: Vec<OrderId> = Vec::new();
                for (id, qty_tenths) in level {
                    if wanted <= 0 {
                        break;
                    }
                    wanted -= qty_tenths;
                    taken.push(id);
                }
                open.retain(|held| !taken.contains(&held.id));
                return;
            }
            if open.len() >= MAX_OPEN_ORDERS {
                return;
            }
            open.push(OpenOrder {
                id: *id,
                account: *account,
                market,
                side: *side,
                price_cents,
                qty_tenths: (quantity * 10.0).round().clamp(1.0, MAX_GRID_UNITS as f64) as i64,
                expires_at_ms: 0,
            });
        }
        OrderMessage::Cancel { target_id, .. } => open.retain(|held| held.id != *target_id),
        _ => {}
    }
}

/// The cancel message the generator sends for one of its own orders.
fn cancel(id: OrderId, timestamp: u64, account: AccountId, target_id: OrderId) -> OrderMessage {
    OrderMessage::Cancel {
        id,
        timestamp,
        account,
        target_id,
        // Simulated traffic. Nobody signed this message, so there is no
        // submission to replay and nothing for a nonce to protect. `None` also
        // keeps a generated message writing the same bytes it always wrote.
        nonce: None,
    }
}

/// The order the generator cancels on this message, if there is one.
///
/// It is the order whose life ended first, so orders leave the books in the
/// order their lives ended. `at_the_bound` makes the oldest deadline due
/// whether that deadline has arrived or not. That is how the generator holds
/// `MAX_OPEN_ORDERS` without dropping an order from the list.
fn order_to_take_back(open: &[OpenOrder], now_ms: u64, at_the_bound: bool) -> Option<usize> {
    let mut found: Option<(usize, u64)> = None;
    for (index, order) in open.iter().enumerate() {
        if !at_the_bound && order.expires_at_ms > now_ms {
            continue;
        }
        if found.is_none_or(|(_, due)| order.expires_at_ms < due) {
            found = Some((index, order.expires_at_ms));
        }
    }
    found.map(|(index, _)| index)
}

/// How long one order rests before the generator cancels it.
///
/// The life is exponential, so every resting order has the same chance of being
/// cancelled in the next second, whatever its age. That constant rate is what
/// gives a book a steady depth. The rate differs by band. See
/// `BAND_LIFETIMES_MS`.
pub(super) fn a_life(rng: &mut StdRng, band: usize) -> u64 {
    let mean = BAND_LIFETIMES_MS[band.min(BAND_LIFETIMES_MS.len() - 1)];
    let draw: f64 = rng.gen_range(0.0..1.0);
    let life = -mean * (1.0 - draw).ln();
    life.min(mean * LONGEST_LIFE_IN_MEANS) as u64
}

/// Which patience band this account quotes in. See `PATIENCE_BANDS`.
pub(super) fn band_of(account: AccountId) -> usize {
    account as usize % PATIENCE_BANDS.len()
}

/// One of the accounts that quote. They are the accounts numbered below
/// `quoting_accounts`. See `QUOTING_SHARE`.
fn a_quoting_account(state: &mut FeedState) -> AccountId {
    let quoting = quoting_accounts(state.num_accounts);
    state.rng.gen_range(0..quoting)
}

/// One of the accounts that take. They are the accounts numbered from
/// `quoting_accounts` up.
///
/// A sequencer with one account has no taking account, so it makes no trades.
/// Under rule set 2 one account cannot trade with itself, whatever this file
/// does. `generate_message_at` step 2 checks for that case before it asks for a
/// taking account, so this function is never called with an empty range.
fn a_taking_account(state: &mut FeedState) -> AccountId {
    let quoting = quoting_accounts(state.num_accounts);
    state
        .rng
        .gen_range(quoting..state.num_accounts.max(quoting + 1))
}

/// How many of the accounts quote.
pub(super) fn quoting_accounts(num_accounts: u32) -> u32 {
    let quoting = (num_accounts as f64 * QUOTING_SHARE).round() as u32;
    // At least one of each, when there is more than one account to split.
    quoting.clamp(1, num_accounts.saturating_sub(1).max(1))
}

/// Which side this message trades on: buy or sell.
///
/// The split is even, and then leaned toward the side that moves the market
/// back to the price it was listed at. See `ANCHOR_STRENGTH`. The lean works
/// the same way for both roles. A buy quote holds the price up, and a buy take
/// pushes it up, so the generator makes both rarer when the market is already
/// high.
fn pick_side(state: &mut FeedState, market: usize, listed_price: f64) -> Side {
    let listed_cents = in_cents(listed_price);
    let away = match book_mid_cents(&state.open_orders, market) {
        Some(mid) => (mid - listed_cents) as f64 / listed_cents.max(1) as f64,
        None => 0.0,
    };
    let lean = (ANCHOR_STRENGTH * away).clamp(-ANCHOR_LIMIT, ANCHOR_LIMIT);
    if state.rng.gen_bool(0.5 - lean) {
        Side::Buy
    } else {
        Side::Sell
    }
}

/// How many price steps wide an account's band is.
///
/// The band is already a number of steps, so this only holds it inside the
/// grid. It is at least one step, because a quote must sit behind the other
/// side's best price and not on it.
///
/// This used to turn a share of the price into a number of steps. That multiply
/// is what made one band mean 10 steps at MERKLE-USDC and 1,000 at BTC-USDC.
/// See `PATIENCE_BANDS`.
fn steps_in_the_band(step_cents: i64, band: i64) -> i64 {
    band.clamp(1, MAX_GRID_UNITS / step_cents)
}

/// How many price steps behind the other side's best price a quote sits.
///
/// The draw runs over 1 to `most` steps, with the chance of `i` steps
/// proportional to `i^-1`. See `QUOTE_DEPTH_EXPONENT`.
///
/// The code inverts that power law instead of walking a table of weights, so it
/// costs one `powf` on every message whatever `most` is.
///
/// At an exponent of exactly 1 the chance of `i` steps is `1/i`, and the
/// inverse is `(most + 1)` raised to the drawn number. The general form divides
/// by `1 - exponent`, which is zero at an exponent of 1, so the two forms are
/// written apart.
fn steps_behind_the_touch(rng: &mut StdRng, most: i64) -> i64 {
    let drawn: f64 = rng.gen_range(0.0..1.0);
    let top = (most + 1) as f64;
    // Both forms draw over `[1, most + 1)`. The draw is then cut down to a
    // whole number of steps, so the last step gets the same share of the draw
    // as every other step.
    let steps = if QUOTE_DEPTH_EXPONENT == 1.0 {
        top.powf(drawn)
    } else {
        let power = 1.0 - QUOTE_DEPTH_EXPONENT;
        (1.0 - drawn + drawn * top.powf(power)).powf(1.0 / power)
    };
    (steps as i64).clamp(1, most)
}

/// The price `distance` cents behind `touch`, for an order on `side`. The price
/// is below `touch` when the order buys, and above `touch` when the order
/// sells.
fn behind(side: Side, touch: i64, distance: i64) -> i64 {
    match side {
        Side::Buy => touch - distance,
        Side::Sell => touch + distance,
    }
}

/// The best price on one side of one market, as the generator believes the book
/// stands. That is the highest buy price, or the lowest sell price.
fn best_cents(open: &[OpenOrder], market: usize, side: Side) -> Option<i64> {
    open.iter()
        .filter(|order| order.market == market && order.side == side)
        .map(|order| order.price_cents)
        .reduce(|a, b| match side {
            Side::Buy => a.max(b),
            Side::Sell => a.min(b),
        })
}

/// The middle of the two best prices, when the market has an order on each
/// side.
fn book_mid_cents(open: &[OpenOrder], market: usize) -> Option<i64> {
    let bid = best_cents(open, market, Side::Buy)?;
    let ask = best_cents(open, market, Side::Sell)?;
    Some((bid + ask) / 2)
}

/// The side a crossing order takes, and the level it takes. `None` means this
/// market has no level to take yet.
///
/// It is the side the anchor picked: `pick_side` and `ANCHOR_STRENGTH`. A buy
/// take removes the lowest sell price, so the sell price steps up and the market
/// moves up. A sell take moves it down. The side choice is therefore the only
/// thing in this file that decides which way the price goes. A rule that gives
/// the side choice another job stops the price moving, and the measurement below
/// is one such rule.
///
/// **The rejected alternative: take the side whose best level is thinner.**
/// That rule shipped in commit af9968b. One crossing order removed every order
/// at the level it named, so a rule was needed to hold that count near one, and
/// picking the thinner of the two fronts did hold it. Measured over 50,000
/// messages at 40 accounts and 24 messages a second, with everything else the
/// same:
///
/// ```text
///                         orders a crossing order removes   cancelled   var/mean
/// the thinner side                                   1.00       66.0%       0.20
/// the side the anchor picked                         1.52       48.9%       2.24
/// ```
///
/// The last column is the trades in a one-second candle: the variance over the
/// mean, which is 1.0 when trades arrive with no clustering. A thick level
/// prints every one of its orders in the same millisecond, so taking the thick
/// side puts the clustering back.
///
/// That table left out the price. A run of buy takes walks the sell side up
/// into the prices where quotes have stacked, so the best sell level gets
/// thicker. The rule then reads that level as the thick one and switches to a
/// sell take, which moves the price back down. It reverses the direction the
/// price is moving, within a few price steps, on every crossing order. That is a
/// far stronger pull to the middle than `ANCHOR_STRENGTH` is, and it is not
/// aimed at the price the market was listed at. Measured on the deployment over
/// 25 minutes of 15-second candles, before that commit and after it: the price
/// band fell from 2.84%-3.58% to 0.83%-1.00% and the candle body from
/// 0.214%-0.247% to 0.113%-0.153%. The chart drew a nearly flat line.
///
/// `the_best_level` removes the reason for the rule. One crossing order now
/// removes one resting order whatever the level holds, so the count is 1.00 on
/// either side and the side choice is free to do its own job. Measured over
/// 150,000 messages at 40 accounts and 24 messages a second:
///
/// ```text
/// side picked by     one crossing order takes   price band   cancelled   var/mean
/// the thinner side            the whole level        0.69%       66.4%       0.19
/// the anchor                  the whole level        3.78%       49.6%       2.12
/// the thinner side            one order              1.58%       66.5%       0.18
/// the anchor                  one order              1.58%       66.5%       0.18
/// ```
///
/// Row 2 is the price movement the chart needs. It misses section 4.5 by 12
/// points and the clustering bound by 0.12. Rows 3 and 4 are the same run: a crossing order
/// that takes one order leaves both fronts holding one order for the comparison
/// to read, so the thinner-side rule has nothing left to choose between and the
/// anchor decides anyway. Those rows read 1.58% and not 2.97% because the walk
/// was still three steps; `MOST_STEPS_FROM_THE_TOUCH` is the other half of the
/// price.
fn a_level_to_take(open: &[OpenOrder], market: usize, leaning: Side) -> (Side, Option<Taken>) {
    let here = the_best_level(open, market, leaning);
    if here.is_some() {
        return (leaning, here);
    }
    // The side the anchor picked cannot be taken. `the_best_level` refuses a
    // level that would leave its side under `TAKE_NEEDS_A_SIDE_OF`, and it
    // answers for one side at a time. Taking the other side keeps the cadence
    // rather than skipping this market for a message.
    let there = the_best_level(open, market, other(leaning));
    if there.is_some() {
        return (other(leaning), there);
    }
    (leaning, None)
}

/// The level one crossing order takes, and what that costs the generator's
/// list.
struct Taken {
    price_cents: i64,
    /// The quantity the crossing order names. It is the whole quantity of the
    /// orders in `orders`, so the order fills and leaves nothing over.
    qty_tenths: i64,
    /// The orders the take removes, oldest first. The generator takes these
    /// off its own list, because the exchange takes them out of the book.
    orders: Vec<OrderId>,
}

/// The price of the best level on the other side, the quantity one crossing
/// order names there, and the order that quantity belongs to. That is what one
/// crossing order buys or sells.
///
/// The price is the best price exactly, so the order crosses that one level and
/// no other level. The quantity is the quantity of the one order the exchange
/// fills first at that price, so that order goes in full and no part of the
/// crossing order is left over.
///
/// **How the generator knows which order fills first.** Step 5 fills one price
/// oldest first: `matcher/step5_match_against_book.rs`. The generator hands out
/// ids in the order it sends messages, so the oldest order at a price is the
/// lowest id at that price. The generator reads that off its own list. It reads
/// no book and asks the exchange nothing.
///
/// The generator takes no orders out of a market that is still filling its
/// books: `TAKE_NEEDS_A_SIDE_OF`.
///
/// **What taking a whole level costs.** One crossing order removes every order
/// at the best price, so the orders at that price are the trades it prints. The
/// count was 2.82 orders at 20 accounts and 6 messages a second, and 4.12 at
/// the 40 accounts and 24 messages a second the deployment runs, because a
/// faster rate builds a deeper book and the quotes sat together at the best
/// price. Two numbers in `docs/GENERATOR-RFC.md` follow from it, and neither
/// was met. Section 4.4 asks for a sixth to a quarter of events to cross, and
/// crossing orders were 11.9% of the messages, because each one did the work of
/// four. Section 4.5 asks for 62% to 93% of limit orders to end in a cancel
/// rather than a trade, and 28.4% did.
///
/// The same count is what left the one-second candles with holes. Every order a
/// crossing order removes prints in the same millisecond, so the trades arrived
/// in bursts. Measured on the deployment, ETH-USDC over 300 one-second candles:
/// 2.40 trades a second on average and a variance of 13.53, which is 5.6 times
/// the mean. Only 49% of the seconds held a trade, against the 91% a market
/// with no clustering fills at that rate.
///
/// Three changes brought the count to 1.00 and met both sections. `TAKE_EVERY`
/// sends crossing orders on a cadence, `MOST_AT_A_LEVEL` keeps the front of a
/// book one order a price, and `a_level_to_take` took the thinner of the two
/// fronts. The third one stopped the price moving, and this function is what
/// replaces it: naming one order holds the count at 1.00 by construction, on
/// whichever side the anchor picks.
///
/// **The alternative that was rejected, and why it is what this function now
/// does.** The earlier note here said a crossing order for a bounded quantity
/// would also bring the count to one, and rejected it: the generator would have
/// to read partial fills back to know what still rests, it holds no book, and
/// any order it loses track of can never be cancelled again. That argument
/// holds for a quantity picked out of the air. It does not hold for this
/// quantity. The order names exactly what one resting order holds, and price
/// and time decide which resting order that is, so the fill is that whole order
/// and nothing else. There is no partial fill to read back. The generator still
/// knows what rests, and it still reads nothing from the exchange.
///
/// What it does depend on is that the generator's order is the oldest at that
/// price. Another sender can rest an order at the same price with a lower id,
/// and then the crossing order fills that order instead. `demo.sh` runs
/// `bot.rs`; the generator-only measurement has no other sender. The cost of
/// being wrong is one
/// order the generator believes has gone, which its next crossing order to that
/// price clears, or its cancel clears when the life ends. That is the same cost
/// `OpenOrder` already names for every order another sender takes.
fn the_best_level(open: &[OpenOrder], market: usize, side: Side) -> Option<Taken> {
    if orders_on(open, market, Side::Buy) < TAKE_NEEDS_A_SIDE_OF
        || orders_on(open, market, Side::Sell) < TAKE_NEEDS_A_SIDE_OF
    {
        return None;
    }
    let price_cents = best_cents(open, market, other(side))?;
    let mut level: Vec<&OpenOrder> = open
        .iter()
        .filter(|order| at_the_level(order, market, other(side), price_cents))
        .collect();
    // Oldest first, which is the order the exchange fills in. Step 5 fills one
    // price oldest first, and the generator hands out ids in the order it sends
    // messages, so the lowest id at a price is the order that fills first.
    level.sort_unstable_by_key(|order| order.id);
    level.truncate(1);
    let at_the_best = level.len();
    let qty_tenths: i64 = level.iter().map(|order| order.qty_tenths).sum();
    let orders: Vec<OrderId> = level.iter().map(|order| order.id).collect();
    // The whole level goes, so the side must still hold two orders once it
    // has gone. Counting the side before the take is not enough: the quotes
    // cluster at the best price now that the bands are counted in price
    // steps, so one level is often every order on that side. Before that
    // change the orders were spread over 10 to 100 steps and one level was
    // rarely the whole side, so the count before the take was almost always
    // right. It emptied a side at 2 readings in 600 once the quotes moved in.
    // `MOST_AT_A_LEVEL` has since made a level hold about one order, so this
    // check now fires only when a side is down to two or three orders.
    if orders_on(open, market, other(side)) - at_the_best < TAKE_NEEDS_A_SIDE_OF {
        return None;
    }
    (qty_tenths > 0 && qty_tenths <= MAX_GRID_UNITS).then_some(Taken {
        price_cents,
        qty_tenths,
        orders,
    })
}

/// The first price at or behind `wanted` that holds fewer than
/// `MOST_AT_A_LEVEL` of the generator's orders. `furthest_cents` is where the
/// walk stops: see `MOST_STEPS_FROM_THE_TOUCH`.
///
/// A quote that joins a level makes that level thicker. A thicker best level is
/// a best price that a crossing order cannot move, because a crossing order
/// removes one order and the level still holds another. That is what stops the
/// price moving, and `MOST_STEPS_FROM_THE_TOUCH` holds the measurement.
///
/// It also used to decide how many orders one crossing order removed, because a
/// crossing order took the whole level. `TAKE_EVERY` says what that cost:
/// section 4.5 of `docs/GENERATOR-RFC.md` wants 62% to 93% of limit orders to
/// end in a cancel, and the arithmetic there needs a crossing order to remove
/// 1.14 orders or fewer. `the_best_level` now names one order, so a thick level
/// no longer costs anything there.
///
/// The quote steps away from the other side's best price, never toward it, so
/// this can only make a quote less likely to cross. It cannot break "a quoting
/// account never crosses anything".
fn a_free_step(
    open: &[OpenOrder],
    market: usize,
    side: Side,
    wanted: i64,
    step_cents: i64,
    furthest_cents: i64,
    most_steps: i64,
) -> i64 {
    let mut price_cents = wanted;
    // The walk can never take more steps than `most_steps`, because `past`
    // stops it there. The count is the loop's own bound, so a price that stops
    // moving cannot spin.
    for _ in 0..most_steps {
        if orders_at(open, market, side, price_cents) < MOST_AT_A_LEVEL {
            return price_cents;
        }
        let next = on_the_step(behind(side, price_cents, step_cents), step_cents);
        // The grid has a floor and a ceiling, and `on_the_step` holds the price
        // inside them. A price that did not move has reached one of the two, so
        // there is no free step behind it.
        if next == price_cents {
            return price_cents;
        }
        // The walk stops at `most_steps`. A quote past that point is depth
        // assertion H5 cannot count.
        if past(side, next, furthest_cents) {
            return price_cents;
        }
        price_cents = next;
    }
    price_cents
}

/// How many price steps the walk may spend on one side of one market.
///
/// One step for every `ORDERS_A_FREE_STEP_COSTS` orders the side already holds,
/// and never more than `most_steps`. A thin side spends nothing, so its orders
/// stay inside the 10 price steps assertion H5 counts. See
/// `MOST_STEPS_FROM_THE_TOUCH` for the measurement.
///
/// `most_steps` is `MOST_STEPS_FROM_THE_TOUCH` multiplied by the activity
/// state's placement width, so the busy state may walk three times as far. See
/// `PLACEMENT_WIDTH`.
fn steps_to_spend(open: &[OpenOrder], market: usize, side: Side, most_steps: i64) -> i64 {
    let held = orders_on(open, market, side) as i64;
    (held / ORDERS_A_FREE_STEP_COSTS).clamp(1, most_steps)
}

/// Whether `price_cents` sits further behind the other side's best price than
/// `furthest_cents` does. A buy is further behind when its price is lower, and
/// a sell when its price is higher.
fn past(side: Side, price_cents: i64, furthest_cents: i64) -> bool {
    match side {
        Side::Buy => price_cents < furthest_cents,
        Side::Sell => price_cents > furthest_cents,
    }
}

/// How many of the generator's orders rest at one price of one side of one
/// market.
fn orders_at(open: &[OpenOrder], market: usize, side: Side, price_cents: i64) -> usize {
    open.iter()
        .filter(|order| at_the_level(order, market, side, price_cents))
        .count()
}

/// How many orders the generator holds on one side of one market.
fn orders_on(open: &[OpenOrder], market: usize, side: Side) -> usize {
    open.iter()
        .filter(|order| order.market == market && order.side == side)
        .count()
}

/// Whether this open order is one of the orders at a named level.
fn at_the_level(order: &OpenOrder, market: usize, side: Side, price_cents: i64) -> bool {
    order.market == market && order.side == side && order.price_cents == price_cents
}

/// The account's own open order that a quote at this price would trade with, if
/// there is one.
///
/// In that case the exchange refuses the whole arriving order and keeps the
/// resting order: `step4_self_trade_check`, cancel newest. The generator
/// therefore cancels the resting order instead, and sends no order the exchange
/// would refuse.
fn own_order_in_the_way(
    open: &[OpenOrder],
    account: AccountId,
    market: usize,
    side: Side,
    price_cents: i64,
) -> Option<usize> {
    open.iter().position(|order| {
        order.account == account
            && order.market == market
            && order.side != side
            && crosses(side, price_cents, order.price_cents)
    })
}

/// Whether an order arriving on `side` at `price_cents` trades with an order
/// resting at `resting_cents`.
fn crosses(side: Side, price_cents: i64, resting_cents: i64) -> bool {
    match side {
        Side::Buy => price_cents >= resting_cents,
        Side::Sell => price_cents <= resting_cents,
    }
}

/// The other side.
fn other(side: Side) -> Side {
    match side {
        Side::Buy => Side::Sell,
        Side::Sell => Side::Buy,
    }
}

/// Writes down the price a market trades at now, so an empty side has a price
/// to quote around.
///
/// This is the only price the generator keeps outside the books, and it is read
/// only when a side of a book is empty. The price lives in the sequencer's
/// state because `with_db` reads it from the last published price of that
/// market on a restart.
fn remember_the_price(state: &mut FeedState, market: usize, symbol: &str) {
    if let Some(mid) = book_mid_cents(&state.open_orders, market)
        && let Some(known) = state.mids.get_mut(symbol)
    {
        *known = in_price(mid);
    }
}

/// The price a market was last seen at, in cents.
fn remembered_cents(state: &FeedState, symbol: &str) -> i64 {
    in_cents(state.mids.get(symbol).copied().unwrap_or(MIN_PRICE))
}

/// A market's price step, in cents.
fn steps_in_cents(price_step: f64) -> i64 {
    in_cents(price_step).max(1)
}

/// Puts a price on the step the market is listed on, and inside the range the
/// engine can represent.
///
/// The engine refuses a price that is off the listed step, see
/// `matcher/step1_resolve_symbol.rs`. This function is what keeps a generated
/// order acceptable. One step is the smallest price a step names, so one step
/// is the floor.
fn on_the_step(price_cents: i64, step_cents: i64) -> i64 {
    let highest = MAX_GRID_UNITS / step_cents * step_cents;
    // The price is held inside the range before the multiply, so no arithmetic
    // here can overflow i64. The engine does not accept a price outside that
    // range anyway.
    let held = price_cents.clamp(0, highest);
    let steps = (held as f64 / step_cents as f64).round() as i64;
    (steps * step_cents).clamp(step_cents, highest)
}

/// Reads a price in cents back as the number a message carries.
fn in_price(price_cents: i64) -> f64 {
    round2(price_cents.clamp(1, MAX_GRID_UNITS) as f64 / PRICE_SCALE)
}

/// Reads a quantity in tenths back as the number a message carries.
fn in_quantity(qty_tenths: i64) -> f64 {
    round1(qty_tenths.clamp(1, MAX_GRID_UNITS) as f64 / 10.0)
}

/// Reads a price as whole cents, held inside the range the engine can
/// represent. See `MIN_PRICE` and `MAX_PRICE`.
fn in_cents(price: f64) -> i64 {
    // `clamp` returns the right bound for both infinities and panics on
    // neither. NaN is the one value `clamp` passes through, and NaN is not a
    // price.
    let held = if price.is_nan() {
        MIN_PRICE
    } else {
        price.clamp(MIN_PRICE, MAX_PRICE)
    };
    (held * PRICE_SCALE).round() as i64
}

/// Rounds a value to two decimal places (used for prices).
pub(super) fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// Rounds a value to one decimal place (used for quantities).
fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bot::{Action, Bot, BotConfig};
    use crate::domain::{OPERATOR_ACCOUNT, to_grid};
    use crate::matcher::MatcherState;
    use ed25519_dalek::SigningKey;

    /// The mean message rate used by the measured switching configuration. A
    /// measurement here runs at the deployment's measured rate, so the two
    /// report the same market. The order lives in `BAND_LIFETIMES_MS` are
    /// counted in seconds, so the rate is what turns them into a number of
    /// messages.
    ///
    /// It is a mean and not a fixed rate. `Activity::of(69.0)` gives the three
    /// states 24, 69 and 114 messages a second. `EVERY_STATE` runs a
    /// measurement held at each of them, because section 4.6 of
    /// `docs/GENERATOR-RFC.md` asks for section 5 to hold in every state and a
    /// run that switches measures the mixture.
    const RATE: f64 = 69.0;

    /// One message in milliseconds, at the quiet state's rate. Tests that only
    /// drive the generator use this to advance a clock, and they build a
    /// `FeedState` that `produce_orders` never gave a rate to, so its activity
    /// is flat at `QUIET_RATE`.
    const MS_PER_MESSAGE: u64 = (1000.0 / QUIET_RATE) as u64;

    /// The run length. 50,000 messages is 2 hours 19 minutes of live traffic.
    const MESSAGES: usize = 50_000;

    /// The default account count used by `demo.sh` and the measurements.
    const ACCOUNTS: u32 = 40;

    /// One seed, so a reader can check every number below by running the test.
    const SEED: u64 = 20_260_816;

    /// The seed one run uses. `GENERATOR_SEED` overrides it, so a number in
    /// this file can be checked on another random history without editing the
    /// file. `services/tests/market_health.rs` reads `MARKET_HEALTH_SEED` the
    /// same way and for the same reason.
    fn seed() -> u64 {
        if let Some(seed) = ON_THIS_SEED.with(|held| held.get()) {
            return seed;
        }
        std::env::var("GENERATOR_SEED")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(SEED)
    }

    thread_local! {
        /// The seed one measurement drives, when that measurement drives more
        /// than one. It is a thread-local and not an environment variable
        /// because tests run beside each other on their own threads, and one
        /// test must not change the seed another test is reading.
        static ON_THIS_SEED: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    }

    /// How often the books are counted. 250 messages is 42 seconds of live
    /// traffic, which is shorter than the one minute each bar of the chart
    /// covers.
    const SAMPLE_EVERY: usize = 250;

    /// What one book held at one moment.
    #[derive(Clone, Copy, Default)]
    struct Sample {
        at_message: usize,
        bids: usize,
        asks: usize,
    }

    /// The edges of the distance table, as a share of the mid price. The live
    /// exchange was read with these same edges, so a run here compares with it
    /// line for line.
    const DISTANCE_EDGES: [f64; 6] = [0.005, 0.01, 0.02, 0.03, 0.05, 0.10];

    /// The name of each distance bucket, for the table `print_distance` writes.
    const DISTANCE_NAMES: [&str; 7] = [
        "  0.0% -  0.5%",
        "  0.5% -  1.0%",
        "  1.0% -  2.0%",
        "  2.0% -  3.0%",
        "  3.0% -  5.0%",
        "  5.0% - 10.0%",
        " 10.0% +      ",
    ];

    /// `pass` or `FAIL`, for the health table.
    fn pass(held: bool) -> &'static str {
        if held { "pass" } else { "FAIL" }
    }

    /// The most messages assertion H6 allows a market to take before its
    /// spread and its depth are back inside the H4 and H5 bands.
    const RESILIENCE_MESSAGES: usize = 100;

    /// The widest spread assertion H4 allows, in price steps. H4 reads the
    /// median over a window; assertion H6 reads one instant, so it uses the
    /// same upper bound the median has to sit under.
    const WIDEST_SPREAD_STEPS: i64 = 5;

    /// The fewest orders assertion H5 wants within 10 price steps of the best
    /// price on a side.
    const H5_DEPTH: usize = 10;

    /// Whether one market's book is inside the H4 and H5 bands at this moment:
    /// a spread of `WIDEST_SPREAD_STEPS` or less, and `H5_DEPTH` orders or more
    /// within 10 price steps of the best price on each side.
    ///
    /// A market that holds only one side is outside the bands. It has no
    /// spread, and a market with one side cannot trade.
    fn inside_the_bands(book: &[(Side, i64)], market: usize) -> bool {
        let step = steps_in_cents(SYMBOLS[market].2);
        let bid = book
            .iter()
            .filter(|(side, _)| *side == Side::Buy)
            .map(|(_, price)| *price)
            .max();
        let ask = book
            .iter()
            .filter(|(side, _)| *side == Side::Sell)
            .map(|(_, price)| *price)
            .min();
        let (Some(bid), Some(ask)) = (bid, ask) else {
            return false;
        };
        if (ask - bid) / step > WIDEST_SPREAD_STEPS {
            return false;
        }
        [(Side::Buy, bid), (Side::Sell, ask)]
            .iter()
            .all(|(side, best)| {
                book.iter()
                    .filter(|(s, price)| s == side && (price - best).abs() <= 10 * step)
                    .count()
                    >= H5_DEPTH
            })
    }

    /// Which distance bucket one resting price falls in, measured from the mid
    /// of its own book.
    fn distance_bucket(price_cents: i64, mid_cents: i64) -> usize {
        let away = (price_cents - mid_cents).abs() as f64 / mid_cents.max(1) as f64;
        DISTANCE_EDGES
            .iter()
            .position(|edge| away < *edge)
            .unwrap_or(DISTANCE_EDGES.len())
    }

    /// How long one candle is. The chart draws five-minute candles, and the
    /// high-to-low range of one candle is the wick this measurement reports.
    const CANDLE_MS: u64 = 5 * 60 * 1000;

    /// How long one candle of the price-movement table is.
    ///
    /// The owner reads the regression off 15-second candles, so the numbers
    /// here are read off the same candle length. See `print_movement`.
    const SHORT_CANDLE_MS: u64 = 15_000;

    /// How many 15-second candles one price band covers. 100 candles is 25
    /// minutes, which is the window the price band was measured over on the
    /// deployment.
    const BAND_CANDLES: usize = 100;

    /// One candle: the first price, the highest, the lowest, the last, and the
    /// quantity that traded inside it.
    #[derive(Clone, Copy)]
    struct Candle {
        open: i64,
        high: i64,
        low: i64,
        close: i64,
        volume_tenths: i64,
    }

    /// One trade, as the millisecond it printed at, the price in cents and the
    /// quantity in tenths.
    #[derive(Clone, Copy)]
    struct Print {
        at_ms: u64,
        price_cents: i64,
        qty_tenths: i64,
    }

    /// How long one volume bucket is. The owner reads the volume histogram off
    /// the live chart in 15-minute bars, so the measurement uses the same bar.
    const BUCKET_MS: u64 = 15 * 60 * 1000;

    /// One 15-minute bucket of one market: what traded in it, and how far the
    /// price moved inside it.
    #[derive(Clone, Copy, Default)]
    struct Bucket {
        volume_tenths: i64,
        /// The squared moves of the 15-second candles in this bucket, added up.
        /// Its square root is the realized volatility of the bucket.
        squares: f64,
    }

    /// The standard deviation of a list over its mean. Statistics calls this
    /// the coefficient of variation. It is a share, so two markets at different
    /// prices compare.
    fn spread_of(values: &[f64]) -> f64 {
        if values.len() < 2 {
            return 0.0;
        }
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let variance =
            values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (values.len() - 1) as f64;
        variance.sqrt() / mean.abs().max(1e-9)
    }

    /// How closely two lists move together, from -1 to 1. This is the Pearson
    /// correlation. 0 means one says nothing about the other, which is the
    /// fourth visual tell section 4.6 of `docs/GENERATOR-RFC.md` names.
    fn correlation(left: &[f64], right: &[f64]) -> f64 {
        if left.len() < 3 || left.len() != right.len() {
            return 0.0;
        }
        let n = left.len() as f64;
        let mean_left = left.iter().sum::<f64>() / n;
        let mean_right = right.iter().sum::<f64>() / n;
        let mut together = 0.0;
        let mut square_left = 0.0;
        let mut square_right = 0.0;
        for (a, b) in left.iter().zip(right) {
            together += (a - mean_left) * (b - mean_right);
            square_left += (a - mean_left).powi(2);
            square_right += (b - mean_right).powi(2);
        }
        let apart = (square_left * square_right).sqrt();
        if apart <= 0.0 {
            return 0.0;
        }
        together / apart
    }

    /// What one run of the generator into a real exchange made.
    #[derive(Default)]
    struct Health {
        messages: usize,
        accounts: u32,
        /// The messages a second this run drove. See `RATE`.
        rate: f64,
        /// Per market, in `SYMBOLS` order.
        trades: [u64; 3],
        trades_first_tenth: [u64; 3],
        trades_last_tenth: [u64; 3],
        longest_gap: [usize; 3],
        /// The longest a market went with no trade, in milliseconds. This is
        /// assertion H2, which is 60 seconds. A run whose rate changes cannot
        /// turn a number of messages into a number of seconds, so both are
        /// counted.
        longest_gap_ms: [u64; 3],
        /// How long the whole run covers, in milliseconds. `messages` divided
        /// by this is the rate the run actually ran at.
        elapsed_ms: u64,
        samples: [Vec<Sample>; 3],
        quotes: u64,
        takes: u64,
        cancels: u64,
        cancels_that_found_nothing: u64,
        refused: u64,
        /// How often the check against quoting through the account's own order
        /// fired. It must never fire. See `generate_message_at` step 4.
        own_order_in_the_way: u64,
        /// The most messages between an order and the cancel for that order.
        oldest_order_cancelled: OrderId,
        open_at_end: usize,
        /// Why the exchange refused what it refused, read off the exchange
        /// itself: `MatcherState::orders_ignored_by_kind`. This test works out
        /// none of it.
        refused_by_kind: std::collections::BTreeMap<String, u64>,
        /// Takes that traded less than the whole level they named. Each one
        /// leaves an order in a book that the generator believes has gone, and
        /// nothing can cancel an order the generator has forgotten.
        takes_that_fell_short: u64,
        /// Resting orders counted by how far they sit from the mid of their
        /// own book, summed over every reading and every market. Row 0 is
        /// bids and row 1 is asks. See `DISTANCE_NAMES`.
        distance: [[u64; 7]; 2],
        /// How many readings the distance table sums over. One reading is one
        /// market at one moment, and only a market holding both a bid and an
        /// ask has a mid to measure from.
        distance_readings: u64,
        /// Every trade, per market and in time order. The candles are built
        /// from this.
        trade_prints: [Vec<Print>; 3],
        /// The best ask price less the best bid price, counted in price
        /// steps, at every reading of every market that had both. This is
        /// assertion H4 of `docs/GENERATOR-RFC.md`: the median must be 1 to 5
        /// steps and the 95th value must be 10 steps or less.
        spread_steps: Vec<i64>,
        /// Resting orders within 10 price steps of the best price on their
        /// own side, per reading and per side. Assertion H5 wants 10 or more.
        depth_within_ten: Vec<usize>,
        /// How far the mid of a book sits from the price its market was
        /// listed at, as a share of the listed price, at every reading. This
        /// is what says whether the price walks away over a long run.
        drift: Vec<f64>,
        /// Quotes placed at or inside the spread: 1 step better than the best
        /// price on their own side, level with it, or 1 step behind it.
        /// Section 4.3 of the RFC wants about half of all quotes here.
        at_or_inside_the_spread: u64,
        /// Quotes placed into a market that already had a best price on the
        /// account's own side, so the distance above is defined.
        quotes_measured: u64,
        /// How many resting orders every take removed, added up. This divided
        /// by `takes` is the orders one crossing order removes.
        orders_taken: u64,
        /// The fewest orders any one side of any book held, at any message.
        /// Section 4.7 of `docs/GENERATOR-RFC.md` wants 2 or more after every
        /// event.
        thinnest_side: usize,
        /// How many messages each market needed to come back inside the H4 and
        /// H5 bands after a trade. Assertion H6 wants 100 or fewer.
        resilience: Vec<usize>,
        /// How many of those waits reached `RESILIENCE_MESSAGES` without the
        /// book coming back.
        slow_to_recover: usize,
        /// Crossing orders that traded nothing at all. Each one named a price
        /// the generator believed held an order and the exchange no longer
        /// did, so the order crossed nothing and the second it was sent in
        /// holds no trade.
        takes_that_traded_nothing: u64,
        /// How many messages the bot sent. Zero unless the run drives the bot.
        bot_messages: u64,
        /// Resting orders the bot took off a book. Each one is an order the
        /// generator still believes is resting.
        bot_took: u64,
    }

    /// What the trades of one market look like when they are counted in
    /// one-second buckets. That is the one-second candle a reader sees on the
    /// chart.
    struct Buckets {
        /// How many one-second buckets the run covers, first trade to last.
        buckets: usize,
        /// How many of those buckets hold at least one trade.
        filled: usize,
        mean: f64,
        variance: f64,
        /// Runs of buckets with no trade at all: how many runs, the longest,
        /// and the middle length.
        empty_runs: usize,
        longest_empty: usize,
        median_empty: usize,
        /// How many buckets held 0 trades, 1 trade, 2 trades, and so on. The
        /// last entry holds every count at or above `COUNTS - 1`.
        counts: [usize; Self::COUNTS],
    }

    impl Buckets {
        const COUNTS: usize = 12;

        /// Counts the trades of one market into one-second buckets.
        fn of(prints: &[Print]) -> Buckets {
            let mut zero = Buckets {
                buckets: 0,
                filled: 0,
                mean: 0.0,
                variance: 0.0,
                empty_runs: 0,
                longest_empty: 0,
                median_empty: 0,
                counts: [0; Self::COUNTS],
            };
            let (Some(first), Some(last)) = (prints.first(), prints.last()) else {
                return zero;
            };
            let (first, last) = (first.at_ms, last.at_ms);
            let buckets = (last / 1000 - first / 1000) as usize + 1;
            let mut per_bucket = vec![0usize; buckets];
            for print in prints {
                per_bucket[(print.at_ms / 1000 - first / 1000) as usize] += 1;
            }
            let mean = prints.len() as f64 / buckets as f64;
            let variance = per_bucket
                .iter()
                .map(|held| (*held as f64 - mean).powi(2))
                .sum::<f64>()
                / buckets as f64;
            let mut runs: Vec<usize> = Vec::new();
            let mut run = 0usize;
            for held in &per_bucket {
                if *held == 0 {
                    run += 1;
                } else if run > 0 {
                    runs.push(run);
                    run = 0;
                }
                zero.counts[(*held).min(Self::COUNTS - 1)] += 1;
            }
            if run > 0 {
                runs.push(run);
            }
            runs.sort_unstable();
            Buckets {
                buckets,
                filled: per_bucket.iter().filter(|held| **held > 0).count(),
                mean,
                variance,
                empty_runs: runs.len(),
                longest_empty: runs.last().copied().unwrap_or(0),
                median_empty: runs.get(runs.len() / 2).copied().unwrap_or(0),
                counts: zero.counts,
            }
        }

        /// The share of one-second buckets that hold a trade.
        fn fill(&self) -> f64 {
            self.filled as f64 / self.buckets.max(1) as f64
        }

        /// The share of buckets a Poisson arrival at the same mean would fill.
        /// A Poisson arrival is what a market with no clustering makes.
        fn poisson_fill(&self) -> f64 {
            1.0 - (-self.mean).exp()
        }

        /// Variance over mean. A Poisson arrival gives 1.0. A larger number
        /// says the trades arrive in bursts, so some seconds hold many trades
        /// and more seconds hold none.
        fn spread(&self) -> f64 {
            self.variance / self.mean.max(1e-9)
        }
    }

    impl Health {
        /// Trades for every 1,000 messages, in one market.
        fn trades_per_1000(&self, market: usize) -> f64 {
            self.trades[market] as f64 * 1000.0 / self.messages as f64
        }

        fn at(&self, market: usize, fraction: f64) -> Sample {
            let samples = &self.samples[market];
            samples[((samples.len() as f64 - 1.0) * fraction).round() as usize]
        }

        /// The most orders any one side of any book held, after the first tenth
        /// of the run. This number grows without bound when the generator
        /// cannot cancel orders.
        fn deepest_side(&self) -> usize {
            let mut deepest = 0;
            for market in 0..3 {
                let from = self.samples[market].len() / 10;
                for sample in self.samples[market].iter().skip(from) {
                    deepest = deepest.max(sample.bids).max(sample.asks);
                }
            }
            deepest
        }

        /// The mean number of orders a side, over the last nine tenths of the
        /// run.
        fn mean_side_depth(&self) -> f64 {
            let mut total = 0.0;
            let mut counted: f64 = 0.0;
            for market in 0..3 {
                let from = self.samples[market].len() / 10;
                for sample in self.samples[market].iter().skip(from) {
                    total += (sample.bids + sample.asks) as f64;
                    counted += 2.0;
                }
            }
            total / counted.max(1.0)
        }

        /// How many readings found one side of a book with nothing in it,
        /// after the first tenth of the run.
        fn readings_with_an_empty_side(&self) -> usize {
            let mut empty = 0;
            for market in 0..3 {
                let from = self.samples[market].len() / 10;
                for sample in self.samples[market].iter().skip(from) {
                    if sample.bids == 0 || sample.asks == 0 {
                        empty += 1;
                    }
                }
            }
            empty
        }

        /// The open, the high and the low of every five-minute candle that
        /// holds a trade, in one market, in cents.
        ///
        /// A candle with no trade is left out. The chart draws it as a flat
        /// line at the last price, and a flat line has no wick to measure.
        fn candles(&self, market: usize) -> Vec<Candle> {
            self.candles_of(market, CANDLE_MS)
        }

        /// The candles of one market at a chosen candle length, in time order.
        ///
        /// A candle with no trade is left out. The chart draws it as a flat
        /// line at the last price, and a flat line has no range and no body.
        fn candles_of(&self, market: usize, candle_ms: u64) -> Vec<Candle> {
            let mut candles: Vec<Candle> = Vec::new();
            let mut window = u64::MAX;
            for print in &self.trade_prints[market] {
                let held = print.at_ms / candle_ms;
                match candles.last_mut() {
                    Some(candle) if held == window => {
                        candle.high = candle.high.max(print.price_cents);
                        candle.low = candle.low.min(print.price_cents);
                        candle.close = print.price_cents;
                        candle.volume_tenths += print.qty_tenths;
                    }
                    _ => {
                        window = held;
                        candles.push(Candle {
                            open: print.price_cents,
                            high: print.price_cents,
                            low: print.price_cents,
                            close: print.price_cents,
                            volume_tenths: print.qty_tenths,
                        });
                    }
                }
            }
            candles
        }

        /// How far the price of one market travels, as a share of its own
        /// lowest price, over each block of `BAND_CANDLES` 15-second candles.
        /// The answer is the mean over the blocks.
        ///
        /// This is the number the owner reads off the chart. A market whose
        /// price does not move draws a flat line, and a flat line is the same
        /// dead market a market with no trades is. Measured on the deployment
        /// over 25 minutes: 2.84% to 3.58% before commit af9968b and 0.83% to
        /// 1.00% after it.
        fn price_band(&self, market: usize) -> f64 {
            let candles = self.candles_of(market, SHORT_CANDLE_MS);
            let mut total = 0.0;
            let mut blocks: f64 = 0.0;
            for block in candles.chunks(BAND_CANDLES) {
                // A part block at the end of the run covers less time than the
                // blocks before it, so it would report a smaller band for a
                // reason that has nothing to do with the generator.
                if block.len() < BAND_CANDLES {
                    continue;
                }
                let high = block.iter().map(|c| c.high).max().unwrap_or(0);
                let low = block.iter().map(|c| c.low).min().unwrap_or(1);
                total += (high - low) as f64 / low.max(1) as f64;
                blocks += 1.0;
            }
            total / blocks.max(1.0)
        }

        /// The mean body of a 15-second candle: the first price to the last
        /// price, as a share of the first price. The body is the filled part of
        /// the candle a reader sees, and the sign is dropped.
        ///
        /// Measured on the deployment: 0.214% to 0.247% before commit af9968b
        /// and 0.113% to 0.153% after it.
        fn body_mean(&self, market: usize) -> f64 {
            let candles = self.candles_of(market, SHORT_CANDLE_MS);
            let total: f64 = candles
                .iter()
                .map(|c| (c.close - c.open).abs() as f64 / c.open.max(1) as f64)
                .sum();
            total / candles.len().max(1) as f64
        }

        /// The mean quantity that trades inside one 15-second candle, in units.
        ///
        /// Measured on the deployment: 277 to 286 before commit af9968b and 118
        /// to 123 after it.
        fn volume_a_candle(&self, market: usize) -> f64 {
            let candles = self.candles_of(market, SHORT_CANDLE_MS);
            let total: i64 = candles.iter().map(|c| c.volume_tenths).sum();
            total as f64 / 10.0 / candles.len().max(1) as f64
        }

        /// Every 15-minute bucket of one market, oldest first, with the part
        /// bucket at the end of the run left out.
        ///
        /// The bucket is 15 minutes because that is the bucket the owner read
        /// off the live chart: 10 buckets, mean volume 7,307, standard
        /// deviation 135. The buckets are counted from the market's first
        /// trade, so the first one is a whole bucket and not the tail of one.
        fn buckets(&self, market: usize) -> Vec<Bucket> {
            let prints = &self.trade_prints[market];
            let Some(first) = prints.first().map(|print| print.at_ms) else {
                return Vec::new();
            };
            let mut buckets: Vec<Bucket> = Vec::new();
            // The 15-second candle being filled: which one it is, its first
            // price, and its last price.
            let mut candle: Option<(u64, i64, i64)> = None;
            let close_the_candle = |buckets: &mut Vec<Bucket>, candle: Option<(u64, i64, i64)>| {
                if let Some((held, open, close)) = candle {
                    let at = (held * SHORT_CANDLE_MS / BUCKET_MS) as usize;
                    if let Some(bucket) = buckets.get_mut(at) {
                        let moved = (close - open) as f64 / open.max(1) as f64;
                        bucket.squares += moved * moved;
                    }
                }
            };
            for print in prints {
                let since = print.at_ms - first;
                let at_bucket = (since / BUCKET_MS) as usize;
                while buckets.len() <= at_bucket {
                    buckets.push(Bucket::default());
                }
                buckets[at_bucket].volume_tenths += print.qty_tenths;
                let at_candle = since / SHORT_CANDLE_MS;
                match candle {
                    Some((held, open, _)) if held == at_candle => {
                        candle = Some((held, open, print.price_cents))
                    }
                    _ => {
                        close_the_candle(&mut buckets, candle);
                        candle = Some((at_candle, print.price_cents, print.price_cents));
                    }
                }
            }
            close_the_candle(&mut buckets, candle);
            // The run stops in the middle of a bucket, and a part bucket holds
            // less volume for a reason that has nothing to do with the
            // generator.
            buckets.pop();
            buckets
        }

        /// How much the volume of a 15-minute bucket varies: the standard
        /// deviation over the mean.
        ///
        /// **This is the number section 4.6 of `docs/GENERATOR-RFC.md` exists
        /// to move.** The third of the four visual tells it names is a flat
        /// volume histogram. The owner read 0.019 off the live chart on 17
        /// August 2026: mean 7,307 units a bucket, standard deviation 135, over
        /// 10 buckets. Every bar was the same height.
        fn volume_variation(&self, market: usize) -> f64 {
            let volumes: Vec<f64> = self
                .buckets(market)
                .iter()
                .map(|bucket| bucket.volume_tenths as f64 / 10.0)
                .collect();
            spread_of(&volumes)
        }

        /// How closely the volume of a 15-minute bucket follows how far the
        /// price moved inside it: the correlation over the buckets.
        ///
        /// The fourth visual tell section 4.6 names is zero volume-to-
        /// volatility correlation. A market that trades more when it moves more
        /// has a positive number here. The volatility of one bucket is the
        /// square root of the sum of the squared moves of its 15-second
        /// candles, each move being the candle's first price to its last price
        /// as a share of the first price. That is the standard realized
        /// volatility, built out of the candles a reader already sees.
        fn volume_against_volatility(&self, market: usize) -> f64 {
            let buckets = self.buckets(market);
            let volumes: Vec<f64> = buckets
                .iter()
                .map(|bucket| bucket.volume_tenths as f64)
                .collect();
            let moves: Vec<f64> = buckets.iter().map(|bucket| bucket.squares.sqrt()).collect();
            correlation(&volumes, &moves)
        }

        /// The three price-movement numbers, per market, beside the flow
        /// numbers. Every configuration reports this table, because a
        /// configuration that fixes the flow and stops the price moving trades
        /// one dead market for another.
        fn print_movement(&self) {
            println!(
                "{:<12} {:>10} {:>10} {:>10} {:>8} {:>8} {:>8}   (15-second candles; \
                 the last three over 15-minute buckets)",
                "symbol", "price band", "body", "volume", "buckets", "vol cv", "vol/vlty"
            );
            for (market, (symbol, _, _)) in SYMBOLS.iter().enumerate() {
                println!(
                    "{:<12} {:>9.2}% {:>9.3}% {:>10.0} {:>8} {:>8.3} {:>8.2}",
                    symbol,
                    self.price_band(market) * 100.0,
                    self.body_mean(market) * 100.0,
                    self.volume_a_candle(market),
                    self.buckets(market).len(),
                    self.volume_variation(market),
                    self.volume_against_volatility(market),
                );
            }
        }

        /// The candle high-to-low range as a share of the candle open, at five
        /// minutes, averaged over every candle that holds a trade.
        ///
        /// This is the wick the chart draws. A book that only trades far from
        /// the mid prints a wide range inside one candle, and that is the long
        /// wick this change exists to shorten.
        fn wick(&self) -> f64 {
            let mut total = 0.0;
            let mut counted: f64 = 0.0;
            for market in 0..3 {
                for candle in self.candles(market) {
                    total += (candle.high - candle.low) as f64 / candle.open.max(1) as f64;
                    counted += 1.0;
                }
            }
            total / counted.max(1.0)
        }

        /// The widest single candle in any market, as a share of its open.
        fn worst_wick(&self) -> f64 {
            let mut worst: f64 = 0.0;
            for market in 0..3 {
                for candle in self.candles(market) {
                    worst =
                        worst.max((candle.high - candle.low) as f64 / candle.open.max(1) as f64);
                }
            }
            worst
        }

        /// One value out of a sorted list, by share. `at(0.5)` is the median.
        fn quantile(sorted: &[i64], share: f64) -> i64 {
            if sorted.is_empty() {
                return 0;
            }
            sorted[(((sorted.len() - 1) as f64) * share).round() as usize]
        }

        /// The longest a market went with no trade, in milliseconds. Assertion
        /// H2 allows 60,000.
        fn worst_gap_ms(&self) -> u64 {
            *self.longest_gap_ms.iter().max().unwrap_or(&0)
        }

        /// The messages a second the run actually ran at, over the whole run. A
        /// run held at one state reports that state's rate; a run that switches
        /// reports the mean of the three states it drew.
        fn measured_rate(&self) -> f64 {
            self.messages as f64 / (self.elapsed_ms.max(1) as f64 / 1000.0)
        }

        /// The six health assertions of `docs/GENERATOR-RFC.md` section 5,
        /// each with the number this run measured.
        ///
        /// H2 is 60 seconds, read off the clock. It used to be counted in
        /// messages, as 60 times the rate. The activity state changes the rate
        /// inside one run, so a number of messages is no longer a number of
        /// seconds and the assertion is measured in the unit it is written in.
        fn print_health(&self) {
            let mut spreads = self.spread_steps.clone();
            spreads.sort_unstable();
            let median = Self::quantile(&spreads, 0.5);
            let p95 = Self::quantile(&spreads, 0.95);
            let thinnest = self.depth_within_ten.iter().min().copied().unwrap_or(0);
            let mean_within_ten = self.depth_within_ten.iter().sum::<usize>() as f64
                / self.depth_within_ten.len().max(1) as f64;
            let worst_rate = (0..3)
                .map(|market| self.trades_per_1000(market))
                .fold(f64::MAX, f64::min);
            println!("     RFC section 5 health assertions");
            println!(
                "     H1 two-sided book   {:>8.1}%   want 99%+     {}",
                self.two_sided_share() * 100.0,
                pass(self.two_sided_share() >= 0.99)
            );
            println!(
                "     H2 worst trade gap  {:>8.1} s    want <= 60    {}",
                self.worst_gap_ms() as f64 / 1000.0,
                pass(self.worst_gap_ms() <= LONGEST_GAP_MS)
            );
            println!(
                "     H3 trades a message {:>8.3}    want >= 0.02  {}",
                worst_rate / 1000.0,
                pass(worst_rate / 1000.0 >= 0.02)
            );
            println!(
                "     H4 spread in steps  {:>8} median, {} at p95; want 1-5 and <= 10  {}",
                median,
                p95,
                pass((1..=5).contains(&median) && p95 <= 10)
            );
            println!(
                "     H5 depth in 10 steps{:>8.1} mean, {} thinnest; want >= 10  {}",
                mean_within_ten,
                thinnest,
                pass(mean_within_ten >= 10.0)
            );
            println!(
                "     H6 back after a trade{:>7} msgs worst, {} waits reached {}; want <= {}  {}",
                self.resilience.iter().max().copied().unwrap_or(0),
                self.slow_to_recover,
                RESILIENCE_MESSAGES,
                RESILIENCE_MESSAGES,
                pass(self.slow_to_recover == 0)
            );
        }

        /// The share of all messages that cross. Section 4.4 of
        /// `docs/GENERATOR-RFC.md` wants a sixth to a quarter.
        fn crossing_share(&self) -> f64 {
            self.takes as f64 / self.messages.max(1) as f64
        }

        /// The share of limit orders that end in a cancel rather than a trade.
        /// Section 4.5 wants 62% to 93%.
        fn cancelled_share(&self) -> f64 {
            let left = self.trades.iter().sum::<u64>() + self.cancels;
            self.cancels as f64 / left.max(1) as f64
        }

        /// The worst variance over mean of the trades in a one-second candle,
        /// over the three markets.
        fn worst_clustering(&self) -> f64 {
            (0..3)
                .map(|market| Buckets::of(&self.trade_prints[market]).spread())
                .fold(0.0, f64::max)
        }

        /// The smallest share of one-second candles any market filled.
        fn worst_fill(&self) -> f64 {
            (0..3)
                .map(|market| Buckets::of(&self.trade_prints[market]).fill())
                .fold(f64::MAX, f64::min)
        }

        /// Every number one configuration of the generator is judged on, as one
        /// line. The sweep scripts read this line.
        ///
        /// The first three numbers are the price movement, and they come first
        /// because a configuration that fixes the flow and stops the price
        /// moving trades one dead market for another. Commit af9968b shipped
        /// for that reason: it reported the flow numbers and not these three.
        fn print_one_line(&self, name: &str) {
            let mut spreads = self.spread_steps.clone();
            spreads.sort_unstable();
            let mean_within_ten = self.depth_within_ten.iter().sum::<usize>() as f64
                / self.depth_within_ten.len().max(1) as f64;
            let worst_rate = (0..3)
                .map(|market| self.trades_per_1000(market))
                .fold(f64::MAX, f64::min);
            let band = (0..3).map(|m| self.price_band(m)).sum::<f64>() / 3.0;
            let body = (0..3).map(|m| self.body_mean(m)).sum::<f64>() / 3.0;
            let volume = (0..3).map(|m| self.volume_a_candle(m)).sum::<f64>() / 3.0;
            let variation = (0..3).map(|m| self.volume_variation(m)).sum::<f64>() / 3.0;
            let together = (0..3)
                .map(|m| self.volume_against_volatility(m))
                .sum::<f64>()
                / 3.0;
            let left = self.trades.iter().sum::<u64>() + self.cancels;
            let imbalance = (self.quotes as f64 - left as f64) / left.max(1) as f64;
            println!(
                "ROW {:<30} rate={:<5.1} band={:.2}% body={:.3}% volume={:.0} \
                 volcv={:.3} volvlty={:+.2} buckets={} \
                 N={:.2} atspread={:.1}% crossing={:.1}% flow={:+.1}% cancelled={:.1}% \
                 varmean={:.2} fill={:.1}% \
                 depth={:.1} deepest={} open={} h5={:.1} thinnest={} empty={} refused={} \
                 H1={:.1}%/{} H2={:.1}s/{} H3={:.3}/{} H4={}+{}/{} H5={:.1}/{} H6={}msgs/{}",
                name,
                self.measured_rate(),
                band * 100.0,
                body * 100.0,
                volume,
                variation,
                together,
                self.buckets(0).len(),
                self.orders_taken as f64 / self.takes.max(1) as f64,
                self.at_or_inside_the_spread as f64 / self.quotes_measured.max(1) as f64 * 100.0,
                self.crossing_share() * 100.0,
                imbalance * 100.0,
                self.cancelled_share() * 100.0,
                self.worst_clustering(),
                self.worst_fill() * 100.0,
                self.mean_side_depth(),
                self.deepest_side(),
                self.open_at_end,
                mean_within_ten,
                self.thinnest_side,
                self.readings_with_an_empty_side(),
                self.refused,
                self.two_sided_share() * 100.0,
                pass(self.two_sided_share() >= 0.99),
                self.worst_gap_ms() as f64 / 1000.0,
                pass(self.worst_gap_ms() <= LONGEST_GAP_MS),
                worst_rate / 1000.0,
                pass(worst_rate / 1000.0 >= 0.02),
                Self::quantile(&spreads, 0.5),
                Self::quantile(&spreads, 0.95),
                pass(
                    (1..=5).contains(&Self::quantile(&spreads, 0.5))
                        && Self::quantile(&spreads, 0.95) <= 10
                ),
                mean_within_ten,
                pass(mean_within_ten >= 10.0),
                self.resilience.iter().max().copied().unwrap_or(0),
                pass(self.slow_to_recover == 0),
            );
        }

        /// The share of readings where a market held both a bid and an ask.
        /// Assertion H1.
        fn two_sided_share(&self) -> f64 {
            let readings: usize = (0..3).map(|market| self.samples[market].len()).sum();
            self.distance_readings as f64 / readings.max(1) as f64
        }

        /// The ledger of section 4.4: orders that arrive against orders that
        /// leave. The two must balance within a few percent, or the books
        /// grow without bound.
        fn print_flow(&self) {
            let arrived = self.quotes;
            let executed: u64 = self.trades.iter().sum();
            let left = executed + self.cancels;
            let imbalance = (arrived as f64 - left as f64) / left.max(1) as f64;
            let died_cancelled = self.cancels as f64 / left.max(1) as f64;
            println!(
                "     flow ledger: {} limit orders in, {} out ({} traded, {} cancelled)",
                arrived, left, executed, self.cancels
            );
            println!(
                "     inflow over removal off by {:+.1}% (RFC 4.4 wants a few percent); \
                 {:.1}% of limit orders died cancelled (RFC 4.5 wants 62-93%)",
                imbalance * 100.0,
                died_cancelled * 100.0
            );
            println!(
                "     {:.1}% of quotes landed at or inside the spread \
                 (RFC 4.3 wants about 50%)",
                self.at_or_inside_the_spread as f64 / self.quotes_measured.max(1) as f64 * 100.0
            );
            let worst_drift = self.drift.iter().fold(0.0_f64, |a, b| a.max(b.abs()));
            let mean_drift =
                self.drift.iter().map(|d| d.abs()).sum::<f64>() / self.drift.len().max(1) as f64;
            println!(
                "     the mid sat {:.2}% from the listed price on average, {:.2}% at worst",
                mean_drift * 100.0,
                worst_drift * 100.0
            );
        }

        /// The one-second candle table, per market. This is the number the
        /// deployment is judged on: a one-second candle with no trade is a gap
        /// on the chart.
        fn print_buckets(&self) {
            println!(
                "{:<12} {:>7} {:>9} {:>9} {:>7} {:>9} {:>7} {:>7} {:>7}",
                "symbol",
                "fill",
                "trades/s",
                "variance",
                "var/mean",
                "poisson",
                "runs",
                "worst",
                "median"
            );
            for (market, (symbol, _, _)) in SYMBOLS.iter().enumerate() {
                let seconds = Buckets::of(&self.trade_prints[market]);
                println!(
                    "{:<12} {:>6.1}% {:>9.2} {:>9.2} {:>7.2} {:>8.0}% {:>7} {:>6}s {:>6}s",
                    symbol,
                    seconds.fill() * 100.0,
                    seconds.mean,
                    seconds.variance,
                    seconds.spread(),
                    seconds.poisson_fill() * 100.0,
                    seconds.empty_runs,
                    seconds.longest_empty,
                    seconds.median_empty,
                );
            }
            let seconds = Buckets::of(&self.trade_prints[1]);
            println!(
                "     {} trades in a second, at {}: {:?}",
                SYMBOLS[1].0, "0,1,2,...", seconds.counts
            );
            println!(
                "     one take removes {:.2} resting orders",
                self.orders_taken as f64 / self.takes.max(1) as f64
            );
        }

        /// The share of resting orders that sit within one hundredth of the
        /// mid. Nothing rested there on the live exchange.
        fn share_within_one_percent(&self) -> f64 {
            let near: u64 = self.distance[0][..2].iter().sum::<u64>()
                + self.distance[1][..2].iter().sum::<u64>();
            let all: u64 =
                self.distance[0].iter().sum::<u64>() + self.distance[1].iter().sum::<u64>();
            near as f64 / all.max(1) as f64
        }

        /// The table the live exchange was read with: resting orders by how
        /// far they sit from the mid. The counts are a mean over every
        /// reading, so they read as the shape of one book at one moment.
        fn print_distance(&self) {
            println!(
                "{:<16} {:>8} {:>8}      (mean over {} readings)",
                "distance from mid", "bids", "asks", self.distance_readings
            );
            let readings = self.distance_readings.max(1) as f64;
            for (bucket, name) in DISTANCE_NAMES.iter().enumerate() {
                println!(
                    "{:<16} {:>8.1} {:>8.1}",
                    name,
                    self.distance[0][bucket] as f64 / readings,
                    self.distance[1][bucket] as f64 / readings,
                );
            }
            println!(
                "     {:.1}% of resting orders sit within 1% of the mid",
                self.share_within_one_percent() * 100.0
            );
            println!(
                "     candle range over open, at 5 minutes: {:.2}% mean, {:.2}% worst",
                self.wick() * 100.0,
                self.worst_wick() * 100.0
            );
        }

        fn print(&self, name: &str) {
            println!(
                "\n=== {} ===  {} messages, {} accounts, {} a second, seed {}",
                name,
                self.messages,
                self.accounts,
                self.rate,
                seed()
            );
            println!(
                "     {} quotes, {} takes, {} cancels ({} found nothing), {} orders refused",
                self.quotes,
                self.takes,
                self.cancels,
                self.cancels_that_found_nothing,
                self.refused
            );
            println!(
                "     the oldest order any cancel reached was {} messages back; \
                 {} orders open at the end",
                self.oldest_order_cancelled, self.open_at_end
            );
            if self.takes_that_fell_short > 0 {
                println!(
                    "     {} takes traded less than the level they named",
                    self.takes_that_fell_short
                );
            }
            if !self.refused_by_kind.is_empty() {
                println!("     refused by kind: {:?}", self.refused_by_kind);
            }
            println!(
                "{:<12} {:>7} {:>8} {:>8} {:>8} {:>9}",
                "symbol", "trades", "t/1000", "1st 10%", "last 10%", "worst gap"
            );
            let tenth = self.messages / 10;
            for (market, (symbol, _, _)) in SYMBOLS.iter().enumerate() {
                println!(
                    "{:<12} {:>7} {:>8.1} {:>8.1} {:>8.1} {:>9}",
                    symbol,
                    self.trades[market],
                    self.trades_per_1000(market),
                    self.trades_first_tenth[market] as f64 * 1000.0 / tenth as f64,
                    self.trades_last_tenth[market] as f64 * 1000.0 / tenth as f64,
                    self.longest_gap[market],
                );
            }
            println!(
                "{:<12} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}",
                "book", "bids@10%", "asks@10%", "bids@50%", "asks@50%", "bids@end", "asks@end"
            );
            for (market, (symbol, _, _)) in SYMBOLS.iter().enumerate() {
                let (start, middle, end) = (
                    self.at(market, 0.1),
                    self.at(market, 0.5),
                    self.at(market, 1.0),
                );
                println!(
                    "{:<12} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}",
                    symbol, start.bids, start.asks, middle.bids, middle.asks, end.bids, end.asks
                );
            }
            println!(
                "     mean depth a side {:.1}, deepest side {}, readings with an empty side {}",
                self.mean_side_depth(),
                self.deepest_side(),
                self.readings_with_an_empty_side()
            );
        }
    }

    /// What a test makes the generator do wrong, so the test can show that the
    /// measurement below fails when one part of the fix is taken out.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Sabotage {
        /// Nothing. The generator behaves as this file writes it.
        None,
        /// The defect this file replaces. `CANCEL_CANDIDATE_WINDOW` was 50, so
        /// the generator forgot every order except the newest 50, and it could
        /// never cancel an older one.
        ForgetAllButFifty,
        /// No order ever reaches the end of its life. The generator therefore
        /// cancels nothing, and only a trade takes an order off a book.
        NeverExpire,
    }

    /// Opens a log the way `docker/open-the-log.sh` opens it: rule set 2, then
    /// one message that lists a market. Then it drives `messages` generated
    /// messages into a real exchange.
    ///
    /// The exchange is the real one. `MatcherState` is the type `matcher.rs`
    /// runs. This test calls `apply_message` in the order the sequencer
    /// publishes, exactly as the poller calls it. This file copies no matching
    /// rule.
    fn drive(accounts: u32, messages: usize, sabotage: Sabotage) -> Health {
        drive_at(accounts, messages, sabotage, QUIET_RATE)
    }

    /// The same run at one fixed message rate, in messages a second. That rate
    /// is what turns the order lives in `BAND_LIFETIMES_MS` into a number of
    /// messages.
    ///
    /// The rate is fixed and the placement width is the quiet state's, so this
    /// is the market this file ran before the activity state existed. Every
    /// older number in this file was measured this way.
    fn drive_at(accounts: u32, messages: usize, sabotage: Sabotage, rate: f64) -> Health {
        drive_with(accounts, messages, sabotage, Activity::flat(rate), false)
    }

    /// The same run held at one of the three activity states of a mean rate.
    /// State 0 is the floor at 24 messages a second, 1 the mean at 69, 2 the
    /// peak at 114. See `Activity` and `PLACEMENT_WIDTH`.
    fn drive_in(accounts: u32, messages: usize, mean: f64, at: usize) -> Health {
        drive_with(
            accounts,
            messages,
            Sabotage::None,
            Activity::held_at(mean, at),
            false,
        )
    }

    /// The same run with the activity state switching, which is what the
    /// deployment runs. The coefficient of variation of the volume in a bucket
    /// and the volume-to-volatility correlation only exist in this run: a run
    /// held at one state has one rate, so its volume varies by nothing but the
    /// draw of one quote's quantity.
    fn drive_mixed(accounts: u32, messages: usize, mean: f64) -> Health {
        drive_with(
            accounts,
            messages,
            Sabotage::None,
            Activity::of(mean),
            false,
        )
    }

    /// The same run with the demo bot sending orders beside the generator.
    ///
    /// `demo.sh` starts `bot.rs`; the generator-only measurement does not. The
    /// bot is
    /// the only sender that takes the generator's resting orders, and the
    /// sequencer holds no book and executes nothing, so the generator cannot
    /// learn which of its orders went. Its list is then wrong, and this is the
    /// run that measures by how much.
    ///
    /// The bot here is the real one. `Bot::observe` and `Bot::decide` are the
    /// functions `start_bot` calls, driven by the same messages the exchange
    /// runs. The only part left out is the network: live the bot polls every 50
    /// ms and the sequencer publishes every 100 ms, and here the bot decides
    /// after every sequenced message. At 24 messages a second one message is 42
    /// ms, so the two cadences are close, and a bot that decides sooner takes
    /// more of the generator's orders rather than fewer.
    fn drive_with(
        accounts: u32,
        messages: usize,
        sabotage: Sabotage,
        activity: Activity,
        with_bot: bool,
    ) -> Health {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut state = FeedState::new(accounts, 1_786_752_000_000);
        state.seed_the_generator(seed());
        // The rate the run reports. A run held at one state reports that
        // state's rate. A run that switches reports the mean, which is the
        // state it starts in.
        let rate = activity.messages_a_second();
        state.activity = activity;
        let mut engine = MatcherState::new();
        let mut timestamp = state.clock.now_ms();

        // The bot replays the same history the exchange runs, so it reads the
        // rule set and the listings before it reads any order.
        let mut bot = with_bot.then(|| Bot::new(BotConfig::default()));
        let open_the_log = |state: &mut FeedState, engine: &mut MatcherState, message| {
            let signed = crate::operator::signed_as(&key, "", message);
            engine
                .apply_message(&signed)
                .expect("the operator opens the log");
            state.next_id += 1;
            signed
        };
        let signed = open_the_log(
            &mut state,
            &mut engine,
            OrderMessage::EngineRule {
                id: 1,
                timestamp,
                account: OPERATOR_ACCOUNT,
                version: 2,
                nonce: Some(format!("{:032x}", 1)),
                public_key: String::new(),
                signature: String::new(),
            },
        );
        if let Some(bot) = &mut bot {
            bot.observe(&signed);
        }
        for (index, (symbol, _, price_step)) in SYMBOLS.iter().enumerate() {
            let id = 2 + index as OrderId;
            let signed = open_the_log(
                &mut state,
                &mut engine,
                OrderMessage::ListSymbol {
                    id,
                    timestamp,
                    account: OPERATOR_ACCOUNT,
                    symbol: symbol.to_string(),
                    price_step: *price_step,
                    quantity_step: 0.1,
                    nonce: Some(format!("{:032x}", id)),
                    public_key: String::new(),
                    signature: String::new(),
                },
            );
            if let Some(bot) = &mut bot {
                bot.observe(&signed);
            }
        }
        assert_eq!(
            engine.listed_symbols().len(),
            3,
            "the three markets are open before the run starts"
        );
        // Every refusal from here on is a message the generator made.
        assert_eq!(engine.orders_ignored(), 0);

        let mut health = Health {
            messages,
            accounts,
            rate,
            thinnest_side: usize::MAX,
            ..Default::default()
        };
        // The message a market last traded at, per market, while that market is
        // still outside the H4 and H5 bands. See assertion H6.
        let mut recovering: [Option<usize>; 3] = [None; 3];
        // The clock advances by one message at the rate of the activity state
        // that message was made in. The count is kept in fractions of a
        // millisecond and cut to a whole number only when the clock is read. At
        // 24 a second a message is 41.67 ms, and adding 41 every time would run
        // the clock 1.6% slow over the run.
        let first_ms = timestamp;
        let mut elapsed_ms = 0.0f64;
        let tenth = messages / 10;
        let mut last_trade_at = [0usize; 3];
        let mut last_trade_ms = [timestamp; 3];
        // The ids the exchange still holds. Every reading drops the ids the
        // exchange no longer holds.
        let mut resting: Vec<OrderId> = Vec::new();

        for step in 0..messages {
            let refused_before = engine.orders_ignored();
            let trades_before = engine.trades_total();
            // Worked out before the message is made. A cancel the generator
            // sends when no order was due to be cancelled is the check in step
            // 4 of `generate_message_at` firing.
            let at_the_bound = state.open_orders.len() >= MAX_OPEN_ORDERS;
            // The same two questions step 1 of `generate_message_at` asks: is
            // an order due, and may this message be a cancel at all. See
            // `CANCELS_IN_A_ROW`.
            let was_due = (at_the_bound || state.cancels_in_a_row < CANCELS_IN_A_ROW)
                && order_to_take_back(&state.open_orders, timestamp, at_the_bound).is_some();
            let before_open: Vec<(usize, Side, i64)> = state
                .open_orders
                .iter()
                .map(|open| (open.market, open.side, open.price_cents))
                .collect();
            let mut expected_fills = 0usize;

            let sent_at_ms = timestamp;
            let message = generate_message_at(&mut state, timestamp);
            // Read after the message, because that message may have switched
            // the activity state, and the gap to the next message belongs to
            // the state that is running now.
            elapsed_ms += 1000.0 / state.activity.messages_a_second();
            timestamp = first_ms + elapsed_ms as u64;

            match &message {
                OrderMessage::New {
                    id,
                    time_in_force,
                    symbol,
                    side,
                    price,
                    ..
                } => {
                    if *time_in_force != TimeInForce::GoodTillCancel {
                        health.takes += 1;
                        expected_fills = state_before_take(
                            &before_open,
                            market_of(symbol),
                            *side,
                            in_cents(*price),
                        );
                        health.orders_taken += expected_fills as u64;
                    } else {
                        health.quotes += 1;
                        // Section 4.3 measures the distance from the best
                        // price on the order's *own* side. The generator
                        // prices from the other side, so this is where the
                        // two are compared. A negative distance is a quote
                        // that improved its own side's best price.
                        let market = market_of(symbol);
                        let step = steps_in_cents(SYMBOLS[market].2);
                        let own_best = before_open
                            .iter()
                            .filter(|(m, s, _)| *m == market && s == side)
                            .map(|(_, _, price)| *price)
                            .reduce(|a, b| match side {
                                Side::Buy => a.max(b),
                                Side::Sell => a.min(b),
                            });
                        if let Some(own_best) = own_best {
                            health.quotes_measured += 1;
                            let behind = match side {
                                Side::Buy => own_best - in_cents(*price),
                                Side::Sell => in_cents(*price) - own_best,
                            } / step;
                            if (-1..=1).contains(&behind) {
                                health.at_or_inside_the_spread += 1;
                            }
                        }
                    }
                    resting.push(*id);
                }
                OrderMessage::Cancel { id, target_id, .. } => {
                    health.cancels += 1;
                    health.oldest_order_cancelled =
                        health.oldest_order_cancelled.max(*id - *target_id);
                    if engine.open_order(*target_id).is_none() {
                        health.cancels_that_found_nothing += 1;
                    }
                    if !was_due {
                        health.own_order_in_the_way += 1;
                    }
                }
                _ => panic!("the generator sends orders and cancels and nothing else"),
            }

            engine.apply_message(&message).expect("in feed order");
            health.refused += engine.orders_ignored() - refused_before;
            let booked = (engine.trades_total() - trades_before) as usize;
            if expected_fills > 0 && booked < expected_fills {
                health.takes_that_fell_short += 1;
            }
            if expected_fills > 0 && booked == 0 {
                health.takes_that_traded_nothing += 1;
            }

            // The bot reads the message the sequencer just published, decides,
            // and the sequencer publishes what it decided. Every one of the
            // bot's own messages is sequenced too, so the bot's copy of the book
            // and the exchange stay the same book.
            //
            // `timestamp` already holds the next message's time by here, which
            // is when the sequencer would publish what the bot sent back.
            if let Some(bot) = &mut bot {
                bot.observe(&message);
                for action in bot.decide() {
                    let id = state.next_id;
                    state.next_id += 1;
                    let sent = match action {
                        Action::Submit {
                            symbol,
                            side,
                            price,
                            quantity,
                        } => {
                            bot.note_sent(id, &symbol, side, quantity);
                            OrderMessage::New {
                                id,
                                timestamp,
                                account: bot.cfg.account,
                                symbol,
                                side,
                                price,
                                quantity,
                                nonce: Some(format!("{:032x}", id)),
                                // The three terms the bot sends. It places
                                // plain limit orders and needs them to rest.
                                order_type: Default::default(),
                                time_in_force: Default::default(),
                                post_only: false,
                            }
                        }
                        Action::Cancel { target_id } => OrderMessage::Cancel {
                            id,
                            timestamp,
                            account: bot.cfg.account,
                            target_id,
                            nonce: Some(format!("{:032x}", id)),
                        },
                    };
                    engine.apply_message(&sent).expect("in feed order");
                    bot.observe(&sent);
                    health.bot_messages += 1;
                }
            }

            let mut traded = [false; 3];
            for trade_id in (trades_before + 1)..=engine.trades_total() {
                let trade = engine.trade(trade_id).expect("a trade just booked");
                let market = market_of(&trade.symbol);
                traded[market] = true;
                if trade.taker_account == BotConfig::default().account {
                    health.bot_took += 1;
                }
                health.trades[market] += 1;
                health.trade_prints[market].push(Print {
                    at_ms: trade.timestamp,
                    price_cents: in_cents(trade.price),
                    qty_tenths: (trade.quantity * 10.0).round() as i64,
                });
                if step < tenth {
                    health.trades_first_tenth[market] += 1;
                }
                if step >= messages - tenth {
                    health.trades_last_tenth[market] += 1;
                }
            }
            for market in 0..3 {
                if traded[market] {
                    last_trade_at[market] = step;
                    last_trade_ms[market] = sent_at_ms;
                }
                health.longest_gap[market] =
                    health.longest_gap[market].max(step - last_trade_at[market]);
                // Assertion H2 is 60 seconds and not a number of messages, so
                // the gap is measured in milliseconds as well. A run whose rate
                // changes cannot turn one into the other.
                health.longest_gap_ms[market] = health.longest_gap_ms[market]
                    .max(sent_at_ms.saturating_sub(last_trade_ms[market]));
            }

            match sabotage {
                Sabotage::None => {}
                Sabotage::ForgetAllButFifty => {
                    while state.open_orders.len() > 50 {
                        state.open_orders.remove(0);
                    }
                }
                Sabotage::NeverExpire => {
                    for open in &mut state.open_orders {
                        open.expires_at_ms = u64::MAX;
                    }
                }
            }

            // Pruned on every message and not only on a sample, because
            // assertion H6 is measured per message: it asks how many messages
            // a market needs to come back inside the H4 and H5 bands after a
            // trade. Read off the exchange and not off the generator's list,
            // so every table measures the book a person sees on the chart.
            resting.retain(|id| engine.open_order(*id).is_some());
            let mut counted = [Sample::default(); 3];
            let mut book: [Vec<(Side, i64)>; 3] = Default::default();
            for id in &resting {
                let (symbol, side, price_cents, _) = engine
                    .open_order(*id)
                    .expect("just pruned to the open ones");
                let market = market_of(symbol);
                let sample = &mut counted[market];
                match side {
                    Side::Buy => sample.bids += 1,
                    Side::Sell => sample.asks += 1,
                }
                book[market].push((side, price_cents));
            }
            for market in 0..3 {
                // After the first tenth of the run, so the count measures a
                // book that has filled and not a book that is still filling.
                // `readings_with_an_empty_side` skips the same first tenth.
                if step >= messages / 10 {
                    health.thinnest_side = health
                        .thinnest_side
                        .min(counted[market].bids.min(counted[market].asks));
                }
                // H6: how long the book takes to come back after a trade. The
                // clock restarts on every trade, so a market that trades again
                // before it has recovered is measured from the newer trade.
                if traded[market] {
                    recovering[market] = Some(step);
                }
                let Some(from) = recovering[market] else {
                    continue;
                };
                let waited = step - from;
                if inside_the_bands(&book[market], market) {
                    health.resilience.push(waited);
                    recovering[market] = None;
                } else if waited >= RESILIENCE_MESSAGES {
                    health.resilience.push(waited);
                    health.slow_to_recover += 1;
                    recovering[market] = None;
                }
            }

            if step % SAMPLE_EVERY == SAMPLE_EVERY - 1 || step == messages - 1 {
                for market in 0..3 {
                    counted[market].at_message = step + 1;
                    health.samples[market].push(counted[market]);
                    // Only a market holding both a bid and an ask has a mid.
                    let bid = book[market]
                        .iter()
                        .filter(|(side, _)| *side == Side::Buy)
                        .map(|(_, price)| *price)
                        .max();
                    let ask = book[market]
                        .iter()
                        .filter(|(side, _)| *side == Side::Sell)
                        .map(|(_, price)| *price)
                        .min();
                    let (Some(bid), Some(ask)) = (bid, ask) else {
                        continue;
                    };
                    let mid = (bid + ask) / 2;
                    health.distance_readings += 1;
                    for (side, price) in &book[market] {
                        let row = match side {
                            Side::Buy => 0,
                            Side::Sell => 1,
                        };
                        health.distance[row][distance_bucket(*price, mid)] += 1;
                    }
                    let step = steps_in_cents(SYMBOLS[market].2);
                    health.spread_steps.push((ask - bid) / step);
                    let listed = in_cents(SYMBOLS[market].1);
                    health.drift.push((mid - listed) as f64 / listed as f64);
                    // Assertion H5 counts each side on its own.
                    for (side, best) in [(Side::Buy, bid), (Side::Sell, ask)] {
                        health.depth_within_ten.push(
                            book[market]
                                .iter()
                                .filter(|(s, price)| {
                                    *s == side && (price - best).abs() <= 10 * step
                                })
                                .count(),
                        );
                    }
                }
            }
        }

        resting.retain(|id| engine.open_order(*id).is_some());
        health.open_at_end = resting.len();
        health.elapsed_ms = timestamp.saturating_sub(first_ms);
        health.refused_by_kind = engine.orders_ignored_by_kind().clone();
        health
    }

    /// How many orders stood at the level a market order named, before the
    /// exchange ran that order.
    fn state_before_take(
        before: &[(usize, Side, i64)],
        market: usize,
        side: Side,
        price_cents: i64,
    ) -> usize {
        before
            .iter()
            .filter(|(m, s, p)| *m == market && *s == other(side) && *p == price_cents)
            .count()
            // One crossing order names one resting order, whatever the level
            // holds. See `the_best_level`.
            .min(1)
    }

    fn market_of(symbol: &str) -> usize {
        SYMBOLS
            .iter()
            .position(|(listed, _, _)| *listed == symbol)
            .expect("the generator names only listed markets")
    }

    // -----------------------------------------------------------------------
    // The one long run, and every property measured from that run.
    // -----------------------------------------------------------------------

    // The numbers this run measures, at 20 accounts, 50,000 messages and 6
    // messages a second, on seed 20260816. Every threshold below is a loose
    // multiple of one of these numbers. `--nocapture` prints the table the
    // numbers come from.
    //
    //   quotes 25,167   crossing orders 8,384   cancels 16,449 (0 found nothing)
    //   orders refused 0
    //   oldest order a cancel reached: 14,945 messages back
    //   orders open at the end: 334
    //
    //   symbol        trades   t/1000   1st 10%   last 10%   worst gap
    //   MERKLE-USDC    2,795     55.9      59.0       55.8          37
    //   ETH-USDC       2,795     55.9      58.8       55.8          42
    //   BTC-USDC       2,794     55.9      58.8       55.6          40
    //
    //   mean depth a side 55.1, deepest side 84, readings with an empty side 0
    //
    //   one-second candles that hold a trade: 98.8% to 99.0% a market
    //   trades a second: mean 1.34, variance 0.25, variance over mean 0.19
    //   price band 2.63% to 3.97%, candle body 0.248% to 0.282%, volume 275-277
    //
    // At 6 messages a second the same run measures 55.6 trades per 1,000, worst
    // gaps of 34 to 37, and 13.0 orders a side.
    //
    // For comparison: `services/tests/market_health.rs` measures the same
    // exchange under the old generator at 40 accounts. It measures 11 to 23
    // trades per 1,000 messages, worst gaps of 17,655 to 37,525 messages, and
    // books of 5,380 to 5,677 resting orders still growing at message 50,000.

    /// The least a market may trade, per 1,000 messages. The run measures 55.9
    /// at 24 messages a second and 55.6 at 6. This bound is a little under half
    /// of the lower of those numbers. The old generator measures 11 to 23.
    ///
    /// The number used to be 93.2 to 95.1, because one crossing order removed
    /// 2.82 resting orders and printed 2.82 trades. It now removes 1.00 and
    /// prints 1.00. There are more crossing orders and fewer trades in each of
    /// them. `TAKE_EVERY` says why: section 4.5 of `docs/GENERATOR-RFC.md`
    /// wants most limit orders to end in a cancel, and every order a crossing
    /// order removes is an order that traded instead.
    const LEAST_TRADES_PER_1000: f64 = 25.0;

    /// The longest run of messages a market may go with no trade. The run
    /// measures 34 to 40 at 24 messages a second, so this bound is twenty-five
    /// times the highest of them.
    /// At 24 messages a second the bound is 42 seconds. That is one empty bar
    /// on the one-minute chart. The old generator measures 17,655 to 37,525,
    /// which is 49 to 104 minutes.
    ///
    /// A gap in messages grows with the rate, because the cadence sends a
    /// crossing order to one market every 18 messages whatever the rate is. The
    /// gap in seconds is what assertion H2 asks about, and `LONGEST_GAP_MS`
    /// holds it.
    const LONGEST_GAP: usize = 1_000;

    /// Assertion H2 of `docs/GENERATOR-RFC.md`, in milliseconds: the longest a
    /// market may go with no trade. The assertion is 60 seconds and this is
    /// that number, not a multiple of it.
    ///
    /// It is measured on the clock and not in messages. The activity state
    /// changes the message rate inside one run, so a number of messages is no
    /// longer a number of seconds.
    const LONGEST_GAP_MS: u64 = 60_000;

    /// The most orders one side of one book may hold, after the books have
    /// filled.
    ///
    /// Depth follows the message rate, because an order's life is a number of
    /// seconds and not a number of messages. See `SHALLOWEST_MEAN_SIDE` for the
    /// arithmetic and the measured numbers at all three activity states. The
    /// bound here is twice the worst single side the busy state reaches.
    ///
    /// Section 4.7 of `docs/GENERATOR-RFC.md` puts the hard limit at the
    /// 1,000-a-side display cap, and reaching that cap is assertion H5 failing.
    /// This bound sits well under it, so the check here fires long before the
    /// RFC's does. With the old cancel window of 50 the same run reaches 723 at
    /// 24 messages a second, and the books are still growing at the end.
    const DEEPEST_SIDE: usize = 600;

    /// The book depth the generator is built for, per side.
    ///
    /// `d = a / r`: the quoting rate `a` over the cancel rate `r` per resting
    /// order. At 24 messages a second the generator sends 12.1 quoting orders a
    /// second, which is 2.02 a second into each of the six market sides. The
    /// mean life over the five bands is 42 seconds, so a side settles near
    /// `2.02 * 42 = 85` orders, less the orders that trade. Measured: 55.1.
    ///
    /// The depth follows the message rate, because a life is a number of
    /// seconds and not a number of messages. A real market behaves the same
    /// way: a busier market has a deeper book. Measured: 4.4 orders a side at 2
    /// messages a second, 13.0 at 6, 29.0 at 12 and 55.1 at 24.
    ///
    /// **The activity state is what set the upper bound here.** The three
    /// states are 24, 69 and 114 messages a second, so a side is 4.75 times
    /// deeper in the busy state than in the quiet one. Measured over 150
    /// minutes of market time in each state, at 40 accounts:
    ///
    /// ```text
    /// state                  messages a second   orders a side   deepest side
    /// the floor                             24            56.1             85
    /// the mean                              69           165.5            229
    /// the peak                             114           274.4            343
    /// the states switching, over 600 min    61           193.3            353
    /// ```
    ///
    /// 274.4 is 4.89 times the 56.1 of the floor, against a rate ratio of 4.75.
    /// The upper bound is 400, which is 46% above the deepest state's mean and
    /// leaves the run room to be unlucky. It is not the RFC's limit: section 4.7
    /// of `docs/GENERATOR-RFC.md` puts that at the 1,000-a-side display cap, and
    /// 400 is 40% of it. `DEEPEST_SIDE` holds the worst single side, and the
    /// worst of the four rows above is 353 against that bound of 600.
    ///
    /// **The alternative was measured and refused: shorten the lives as the
    /// rate rises, so depth stays flat.** Multiplying every mean life by
    /// `24 / rate` holds a side at 56 orders in all three states. Measured over
    /// 150 minutes of market time in each state, with nothing else changed:
    ///
    /// ```text
    ///                  lives fixed                    lives follow the rate
    /// state        depth  h5   band    body        depth  h5   band    body
    /// the floor     56.1 24.9  3.17%  0.259%        56.1 24.9  3.17%  0.259%
    /// the mean     165.6 13.5  4.37%  0.462%        55.9 23.0  4.10%  0.435%
    /// the peak     274.4 11.1  5.03%  0.595%        55.6 22.2  4.50%  0.510%
    /// ```
    ///
    /// Flat depth works. It holds every assertion, it holds a side at 56 orders
    /// in all three states, and it needs neither of the two bounds here to
    /// move. It costs the price movement the busy states exist to produce: the
    /// band at the peak falls 11%, from 5.03% to 4.50%, and the candle body
    /// falls 14%, from 0.595% to 0.510%. It buys 11 orders of assertion H5
    /// margin, from 11.1 to 22.2 against the 10 H5 asks for.
    ///
    /// The lives stay fixed, for two reasons. A real market is deeper when it
    /// is busier, and this generator's whole design is to copy what published
    /// order-book models do rather than to invent a shape. And section 4.6 of
    /// `docs/GENERATOR-RFC.md` names two things the activity state must scale,
    /// the message rate and the placement dispersion; the order lifetime is a
    /// third thing, and adding it would put a number in the state that no
    /// section asks for. The H5 margin is bought instead by the placement
    /// width, which `PLACEMENT_WIDTH` measures.
    ///
    /// `BAND_LIFETIMES_MS` holds the other sweep of the same five numbers: what
    /// a shorter life does at a fixed message rate, and why the lives are not
    /// shorter there either.
    ///
    /// The books are deeper than the 12.0 a side of the run before this one,
    /// and the whole of that comes from `TAKE_EVERY`. A crossing order used to
    /// remove 2.82 resting orders; it now removes 1.00. The orders that no
    /// longer trade have to leave some other way, so the generator cancels
    /// 32.8% of its messages where it cancelled 30.8%, and a book holds what a
    /// cancel has not reached yet.
    const SHALLOWEST_MEAN_SIDE: f64 = 10.0;
    const DEEPEST_MEAN_SIDE: f64 = 400.0;

    /// The least share of one-second candles a market must fill, once it trades
    /// at least once a second on average.
    ///
    /// This is the number the deployment is judged on. A one-second candle with
    /// no trade is a hole on the chart. Measured at 24 messages a second: 98.9%
    /// to 99.4%. The deployment measured 49% before `TAKE_EVERY` existed.
    const LEAST_ONE_SECOND_FILL: f64 = 0.90;

    /// The most the trades in a one-second candle may cluster: the variance of
    /// the count over its mean.
    ///
    /// Trades that arrive with no clustering give 1.0. Measured in each
    /// activity state: 0.18 at 24 messages a second, 0.08 at 69, 0.07 at 114.
    /// The deployment measured 5.6 before `TAKE_EVERY` existed, because one
    /// crossing order removed a whole queue and printed every order in it in
    /// the same millisecond.
    ///
    /// **The activity state raised this bound from 2.0 to 2.5, and the
    /// arithmetic says by how much it had to.** Clustering is what section 4.6
    /// of `docs/GENERATOR-RFC.md` asks the state to produce, so some of this
    /// number is now the feature and not the fault. A market trades 1.34 times
    /// a second in the quiet state, 3.86 at the mean and 6.37 at the peak. For
    /// a mixture the variance is the mean of the within-state variances plus
    /// the variance of the state means:
    ///
    /// ```text
    /// var/mean = (within-state var/mean) + var(state means) / mean
    /// ```
    ///
    /// The worst mixture is half the time at 24 and half at 114, which gives a
    /// mean of 3.86 and a variance of the means of 6.35, so `0.12 + 6.35/3.86
    /// = 1.76`. That is the most the state alone can make. Measured with the
    /// states switching: 0.99 to 1.48 over four runs.
    ///
    /// The fault the bound catches is unchanged and still lands well above it.
    /// A crossing order that removes a whole price level measured 2.12 at a
    /// flat 24 (`a_level_to_take`), and the same fault under the mixture
    /// measures `2.12 + 6.35/3.86 = 3.76`. So 2.5 sits 69% above the worst
    /// legitimate run and 33% below the fault.
    const MOST_CLUSTERING: f64 = 2.5;

    /// The most resting orders one crossing order may remove.
    ///
    /// `TAKE_EVERY` gives the arithmetic: the share of limit orders that end in
    /// a cancel is `(TAKE_EVERY - 1 - this) / (TAKE_EVERY - 1)`, and section
    /// 4.5 of `docs/GENERATOR-RFC.md` wants that share at 62% or more.
    /// `TAKE_EVERY` is 4, so this number is 1.14. Measured: 1.00.
    const MOST_ORDERS_A_CROSSING_ORDER: f64 = 1.14;

    /// The three activity states of the deployed mean, named for the tables.
    /// See `Activity`.
    const EVERY_STATE: [(&str, usize); 3] = [
        ("the floor, 24 a second", 0),
        ("the mean, 69 a second", 1),
        ("the peak, 114 a second", 2),
    ];

    /// The fixed message rates the health check runs at as well as the three
    /// activity states. 6 a second was the deployment rate before 24,
    /// and it is under the floor, so the generator runs flat there and every
    /// number this file measured at 6 still means what it meant.
    const FLAT_RATES: [f64; 1] = [6.0];

    /// The generated traffic keeps all three markets trading, and the books the
    /// generator builds stop growing.
    ///
    /// One run, every property. This is one test and not six because the run is
    /// the expensive part. A failure also names every property that failed, and
    /// not only the first one.
    ///
    /// The run repeats five times: once held at each of the three activity
    /// states, once with the state switching, and once at the flat 6 messages a
    /// second the deployment ran before. Section 4.6 of
    /// `docs/GENERATOR-RFC.md` puts the market in three states, and section 5
    /// has to hold in each of them. A run that only measures the mixture hides
    /// a state that fails.
    #[test]
    fn the_generated_traffic_keeps_every_market_trading() {
        let mut runs: Vec<(String, Health)> = Vec::new();
        for (name, at) in EVERY_STATE {
            runs.push((name.to_string(), drive_in(ACCOUNTS, MESSAGES, RATE, at)));
        }
        runs.push((
            "the states switching".to_string(),
            drive_mixed(ACCOUNTS, MESSAGES, RATE),
        ));
        for rate in FLAT_RATES {
            runs.push((
                format!("a flat {} a second", rate),
                drive_at(ACCOUNTS, MESSAGES, Sabotage::None, rate),
            ));
        }
        for (name, health) in &runs {
            health.print(name);
            health.print_one_line(name);
            let failures = what_is_unhealthy(health);
            assert!(
                failures.is_empty(),
                "at {} the generated traffic does not keep the markets trading:\n  {}",
                name,
                failures.join("\n  ")
            );
        }
    }

    /// Every check the run above makes, as sentences. The function returns the
    /// failures instead of asserting them, so one run reports all of them, and
    /// so the sabotage tests below can name the checks the sabotage broke.
    fn what_is_unhealthy(health: &Health) -> Vec<String> {
        let mut failures = Vec::new();
        for (market, (symbol, _, _)) in SYMBOLS.iter().enumerate() {
            let rate = health.trades_per_1000(market);
            if rate < LEAST_TRADES_PER_1000 {
                failures.push(format!(
                    "{} traded {:.1} times per 1,000 messages, and the least is {:.0}",
                    symbol, rate, LEAST_TRADES_PER_1000
                ));
            }
            if health.longest_gap[market] > LONGEST_GAP {
                failures.push(format!(
                    "{} went {} messages with no trade, and the most is {}: {} minutes of flat \
                     chart at 6 messages a second",
                    symbol,
                    health.longest_gap[market],
                    LONGEST_GAP,
                    health.longest_gap[market] / 360
                ));
            }
            // Assertion H2 of docs/GENERATOR-RFC.md, in the unit it is written
            // in.
            if health.longest_gap_ms[market] > LONGEST_GAP_MS {
                failures.push(format!(
                    "{} went {:.1} seconds with no trade, and assertion H2 allows {}",
                    symbol,
                    health.longest_gap_ms[market] as f64 / 1000.0,
                    LONGEST_GAP_MS / 1000
                ));
            }
            // The first tenth against the last tenth. A generator that slows
            // down as its books fill trades well early and badly late. That is
            // the shape the charts showed.
            let tenth = health.messages / 10;
            let first = health.trades_first_tenth[market] as f64 * 1000.0 / tenth as f64;
            let last = health.trades_last_tenth[market] as f64 * 1000.0 / tenth as f64;
            if last * 2.0 < first {
                failures.push(format!(
                    "{} traded {:.1} times per 1,000 messages in the first tenth of the run and \
                     {:.1} in the last, so it is slowing down",
                    symbol, first, last
                ));
            }
            let end = health.at(market, 1.0);
            if end.bids == 0 || end.asks == 0 {
                failures.push(format!(
                    "{} ended with {} bids and {} asks, and a market with one side cannot trade",
                    symbol, end.bids, end.asks
                ));
            }
        }
        for (market, (symbol, _, _)) in SYMBOLS.iter().enumerate() {
            let seconds = Buckets::of(&health.trade_prints[market]);
            // The chart draws one-second candles. A candle with no trade is a
            // hole in the chart. The cadence sends a crossing order to this
            // market every `3 * TAKE_EVERY` messages that are not cancels, so a
            // market only fills every candle when that is faster than a second.
            // At 6 messages a second it is one crossing order every 3 seconds,
            // and two candles in three are empty whatever the generator does.
            if seconds.mean >= 1.0 && seconds.fill() < LEAST_ONE_SECOND_FILL {
                failures.push(format!(
                    "{} filled {:.0}% of its one-second candles at {:.1} trades a second, and the \
                     least is {:.0}%. It went {} seconds with no trade at worst",
                    symbol,
                    seconds.fill() * 100.0,
                    seconds.mean,
                    LEAST_ONE_SECOND_FILL * 100.0,
                    seconds.longest_empty,
                ));
            }
            if seconds.spread() > MOST_CLUSTERING {
                failures.push(format!(
                    "{} trades a second have a variance of {:.2} over a mean of {:.2}, which is \
                     {:.2}, and the most is {:.1}. Trades that arrive with no clustering give \
                     1.0, and a crossing order that removes a whole queue prints every order in \
                     it in the same millisecond",
                    symbol,
                    seconds.variance,
                    seconds.mean,
                    seconds.spread(),
                    MOST_CLUSTERING,
                ));
            }
        }
        if health.readings_with_an_empty_side() > 0 {
            failures.push(format!(
                "a side of a book was empty at {} readings, and a market with one side cannot \
                 trade",
                health.readings_with_an_empty_side()
            ));
        }
        let per_crossing = health.orders_taken as f64 / health.takes.max(1) as f64;
        if per_crossing > MOST_ORDERS_A_CROSSING_ORDER {
            failures.push(format!(
                "one crossing order removed {:.2} resting orders and the most is {:.2}. Section \
                 4.5 of docs/GENERATOR-RFC.md wants 62% to 93% of limit orders to end in a \
                 cancel, and the share is (TAKE_EVERY - 1 - this number) / (TAKE_EVERY - 1)",
                per_crossing, MOST_ORDERS_A_CROSSING_ORDER
            ));
        }
        if health.deepest_side() > DEEPEST_SIDE {
            failures.push(format!(
                "one side of a book held {} orders, and the most is {}. The books grew from {} \
                 orders at a tenth of the run to {} at half and {} at the end",
                health.deepest_side(),
                DEEPEST_SIDE,
                health.at(0, 0.1).bids + health.at(0, 0.1).asks,
                health.at(0, 0.5).bids + health.at(0, 0.5).asks,
                health.at(0, 1.0).bids + health.at(0, 1.0).asks,
            ));
        }
        let mean = health.mean_side_depth();
        if !(SHALLOWEST_MEAN_SIDE..=DEEPEST_MEAN_SIDE).contains(&mean) {
            failures.push(format!(
                "the books held {:.1} orders a side and the generator is built for {:.0} to {:.0}",
                mean, SHALLOWEST_MEAN_SIDE, DEEPEST_MEAN_SIDE
            ));
        }
        if health.refused > 0 {
            failures.push(format!(
                "the exchange refused {} of the {} orders the generator sent, and it must refuse \
                 none: a quoting account never crosses anything and a taking account holds \
                 nothing to cross. The exchange gives the reasons as {:?}",
                health.refused,
                health.quotes + health.takes,
                health.refused_by_kind
            ));
        }
        if health.own_order_in_the_way > 0 {
            failures.push(format!(
                "the generator met one of its own orders in the way {} times, and the pricing is \
                 built so that it never can",
                health.own_order_in_the_way
            ));
        }
        if health.takes_that_fell_short > 0 {
            failures.push(format!(
                "{} takes traded less than the level they named, so the generator believes {} \
                 levels have gone that are still in the books, and nothing can cancel them",
                health.takes_that_fell_short, health.takes_that_fell_short
            ));
        }
        if health.cancels_that_found_nothing > 0 {
            failures.push(format!(
                "{} of the {} cancels named an order the exchange no longer held, and the \
                 generator only cancels orders it believes are resting",
                health.cancels_that_found_nothing, health.cancels
            ));
        }
        failures
    }

    /// Prints where the resting orders sit, how long the wick is, and the six
    /// health assertions of `docs/GENERATOR-RFC.md` section 5.
    ///
    /// The live exchange was read with the same distance buckets. At
    /// MERKLE-USDC, mid 10.34, nothing at all rested within 1% of the mid, so
    /// every trade printed at least 1% away. That is the long wick on the
    /// chart, and it is the number a change to the bands has to move. Run this
    /// before and after such a change.
    ///
    /// The wick is the high-to-low range of a five-minute candle, as a share of
    /// that candle's opening price. It measured 9.35% when the bands were
    /// shares of the price, 1.12% once they became price steps, 1.97% at 24
    /// messages a second, and 0.42% at commit af9968b. It measures 1.84% now,
    /// and that rise is the price movement commit af9968b took away.
    /// `MOST_STEPS_FROM_THE_TOUCH` holds the measurement.
    ///
    /// This run is a flat 24 messages a second, which is the quiet activity
    /// state, so it compares with every number above. The deployment runs a
    /// mean of 69 over three states, and `what_this_configuration_measures`
    /// prints one line for each of them.
    ///
    /// `print_buckets` is the last table, and it is the one the deployment is
    /// judged on: the share of one-second candles that hold a trade, per
    /// market, with the variance of the count over its mean beside it.
    ///
    /// Run it with `--ignored --nocapture`.
    #[test]
    #[ignore = "a measurement, not a check: run it with --ignored --nocapture"]
    fn where_the_resting_orders_sit() {
        let health = drive(ACCOUNTS, MESSAGES, Sabotage::None);
        health.print("where the resting orders sit");
        health.print_distance();
        health.print_flow();
        health.print_health();
        health.print_buckets();
        health.print_movement();
    }

    /// How long one measurement covers, in minutes of market time.
    ///
    /// 150 minutes is 10 of the 15-minute buckets the volume histogram is read
    /// in, which is the window the owner read 0.019 off the live chart in. It
    /// is also 6 blocks of the 25 minutes `price_band` averages over, so the
    /// band is a mean of 6 readings and not one.
    ///
    /// The run is a number of minutes and not a number of messages, because the
    /// activity state changes the messages a second. 150 minutes is 216,000
    /// messages at the floor and 1,026,000 at the peak. One fixed message count
    /// would cover 6 times as much market time at the floor as at the peak, and
    /// the price band and the bucket count would move with the run length
    /// rather than with the generator.
    const MOVEMENT_MINUTES: f64 = 150.0;

    /// How long the run with the states switching covers.
    ///
    /// Longer than `MOVEMENT_MINUTES`, because this is the only run whose
    /// coefficient of variation and correlation mean anything, and 150 minutes
    /// is 9 whole buckets. A correlation over 9 readings has a standard error
    /// near 0.35, which is wider than the number it reports. 600 minutes is 39
    /// buckets and a standard error near 0.16. The three markets share one
    /// activity state, so measuring three markets does not buy three times the
    /// readings.
    const MIXED_MINUTES: f64 = 600.0;

    /// How long the run with the bot covers. Shorter than `MOVEMENT_MINUTES`,
    /// because the bot decides after every sequenced message and the run at the
    /// peak rate is 340,000 messages even at 50 minutes.
    const BOT_MINUTES: f64 = 50.0;

    /// How many messages a number of minutes holds at a rate.
    fn messages_over(minutes: f64, rate: f64) -> usize {
        (minutes * 60.0 * rate) as usize
    }

    /// One line for each activity state, holding every number one configuration
    /// of the generator is judged on.
    ///
    /// The first row is the generator this file ran before the activity state:
    /// a flat 24 messages a second with the quiet state's placement. It is the
    /// before to every after below it, and it is where the two numbers section
    /// 4.6 of `docs/GENERATOR-RFC.md` exists to move are read: `volcv` is the
    /// coefficient of variation of the volume in a 15-minute bucket, and
    /// `volvlty` is the correlation between that volume and how far the price
    /// moved in the same bucket.
    ///
    /// The sweep scripts change a constant, rebuild, and run this again. That
    /// is how the tables in `a_level_to_take` and `the_best_level` were
    /// measured.
    ///
    /// Run it with `--ignored --nocapture`. It drives about 3 million messages
    /// and takes a few minutes.
    #[test]
    #[ignore = "a measurement, not a check: run it with --ignored --nocapture"]
    fn what_this_configuration_measures() {
        for rate in FLAT_RATES {
            let health = drive_at(
                ACCOUNTS,
                messages_over(MOVEMENT_MINUTES, rate),
                Sabotage::None,
                rate,
            );
            health.print_one_line(&format!("before, a flat {}", rate));
        }
        // The before to the after, over the same 600 minutes the run with the
        // states switching covers, so the two coefficients of variation and the
        // two correlations are read off the same number of buckets.
        let health = drive_at(
            ACCOUNTS,
            messages_over(MIXED_MINUTES, QUIET_RATE),
            Sabotage::None,
            QUIET_RATE,
        );
        health.print_one_line("before, a flat 24");
        for (name, at) in EVERY_STATE {
            let rate = Activity::held_at(RATE, at).messages_a_second();
            let health = drive_in(ACCOUNTS, messages_over(MOVEMENT_MINUTES, rate), RATE, at);
            health.print_one_line(name);
        }
        let health = drive_mixed(ACCOUNTS, messages_over(MIXED_MINUTES, RATE), RATE);
        health.print_one_line("the states switching");
    }

    /// The two numbers section 4.6 of `docs/GENERATOR-RFC.md` exists to move,
    /// measured before and after over the same 600 minutes of market time.
    ///
    /// - `volcv` is the coefficient of variation of the volume in a 15-minute
    ///   bucket. The third of the four visual tells section 4.6 names is a flat
    ///   volume histogram. The owner read 0.019 off the live chart on 17 August
    ///   2026, over 10 buckets.
    /// - `volvlty` is the correlation between that volume and how far the price
    ///   moved inside the same bucket. The fourth tell is that this number is
    ///   zero.
    ///
    /// Both need many buckets, and both are read off one activity state after
    /// another, so this measurement runs on three seeds. Set `GENERATOR_SEED`
    /// to read a fourth.
    ///
    /// Run it with `--ignored --nocapture`.
    #[test]
    #[ignore = "a measurement, not a check: run it with --ignored --nocapture"]
    fn how_the_volume_varies() {
        for seed in [SEED, SEED + 1, SEED + 2] {
            ON_THIS_SEED.with(|held| held.set(Some(seed)));
            let before = drive_at(
                ACCOUNTS,
                messages_over(MIXED_MINUTES, QUIET_RATE),
                Sabotage::None,
                QUIET_RATE,
            );
            before.print_one_line(&format!("before, a flat 24, seed {}", seed));
            let after = drive_mixed(ACCOUNTS, messages_over(MIXED_MINUTES, RATE), RATE);
            after.print_one_line(&format!("the states switching, seed {}", seed));
        }
    }

    /// The same measurement with the demo bot running beside the generator.
    ///
    /// `demo.sh` starts the bot and the generator-only run does not, so this run
    /// is what `./demo.sh` looks like and the run above is what the deployment
    /// looks like. The two numbers to read are `nothing` and `blank`:
    ///
    /// - `nothing` is the cancels that named an order the exchange no longer
    ///   held. The bot took the order, the sequencer holds no book, so the
    ///   generator never learnt it had gone.
    /// - `blank` is the crossing orders that traded nothing, because they named
    ///   a price that had already gone. Each one is a second with no trade.
    ///
    /// Run it with `--ignored --nocapture`.
    #[test]
    #[ignore = "a measurement, not a check: run it with --ignored --nocapture"]
    fn what_this_configuration_measures_with_the_bot() {
        let runs = [
            ("before, a flat 24".to_string(), Activity::flat(QUIET_RATE)),
            ("the states switching".to_string(), Activity::of(RATE)),
        ];
        for (name, activity) in runs {
            let rate = activity.messages_a_second();
            let health = drive_with(
                ACCOUNTS,
                messages_over(BOT_MINUTES, rate),
                Sabotage::None,
                activity,
                true,
            );
            health.print_one_line(&format!("{} with the bot", name));
            println!(
                "BOT {:<24} rate={:<5.1} nothing={} blank={} bot_messages={} bot_took={} \
                 nothing_a_minute={:.1}",
                name,
                health.measured_rate(),
                health.cancels_that_found_nothing,
                health.takes_that_traded_nothing,
                health.bot_messages,
                health.bot_took,
                health.cancels_that_found_nothing as f64
                    / (health.elapsed_ms.max(1) as f64 / 60_000.0),
            );
        }
    }

    /// The account count and the message rate, swept, so a number answers the
    /// two open questions and not an opinion.
    ///
    /// **The account count does not matter any more.** It used to be the
    /// largest term. The exchange refuses an order that crosses any order of
    /// the same account, so the chance the exchange accepted an order was
    /// `(1 - 1/N)^K`. Raising `N` was the only control anybody had. The account
    /// roles remove `K` instead. Measured at 24 messages a second, with the
    /// share of one-second candles that hold a trade in the last column:
    ///
    /// ```text
    /// accounts   trades/1,000   worst gap   depth a side   refused   fill
    ///       20           55.9          39           55.1         0     99%
    ///       40           55.9          42           55.1         0     99%
    ///      100           55.9          39           58.7         0     99%
    ///      400           55.9          41           58.8         0     99%
    ///      600           55.9          38           59.7         0     99%
    /// ```
    ///
    /// **The message rate sets the depth, and it also sets the fill.** An
    /// order's life is a number of seconds. Twice the messages a second is
    /// therefore twice the quotes a second into a book that empties at the same
    /// rate per resting order, so `d = a / r` doubles. Measured: 4.4 orders a
    /// side at 2 messages a second, 13.0 at 6, 26.8 at 12 and 55.1 at 24.
    ///
    /// The fill follows the rate for a different reason. `TAKE_EVERY` sends one
    /// crossing order to one market every 12 messages that are not cancels, so
    /// a market trades once every 18 messages. That is 0.73 seconds at 24
    /// messages a second and 2.9 seconds at 6. Measured: 10% of the one-second
    /// candles at 2 messages a second, 33% at 6, 67% at 12 and 99% at 24. **The
    /// rate has to be near 24 for a one-second candle to hold a trade.** At 2 a
    /// second a side of a book is empty at 2 readings of 540. At 6 and above no
    /// side is ever empty.
    ///
    /// Run this test with `--ignored --nocapture`. It drives nine histories of
    /// 50,000 messages and takes about a minute.
    #[test]
    #[ignore = "a sweep, not a check: run it with --ignored --nocapture"]
    fn the_account_count_and_the_message_rate_swept() {
        println!(
            "\n{:<10} {:>6} {:>9} {:>9} {:>9} {:>9} {:>10}",
            "accounts", "ms/msg", "trades", "t/1000", "worst gap", "depth", "refused"
        );
        for accounts in [20, 40, 100, 400, 600] {
            let health = drive_at(accounts, MESSAGES, Sabotage::None, RATE);
            print_row(&health);
        }
        for rate in [2.0, 6.0, 12.0, 24.0] {
            let health = drive_at(ACCOUNTS, MESSAGES, Sabotage::None, rate);
            print_row(&health);
        }
    }

    fn print_row(health: &Health) {
        let worst_fill = (0..3)
            .map(|market| Buckets::of(&health.trade_prints[market]).fill())
            .fold(f64::MAX, f64::min);
        println!(
            "{:<10} {:>6} {:>9} {:>9.1} {:>9} {:>9.1} {:>10.0}% {:>10} {:?}",
            health.accounts,
            health.rate,
            health.trades.iter().sum::<u64>(),
            (0..3).map(|m| health.trades_per_1000(m)).sum::<f64>() / 3.0,
            health.longest_gap.iter().max().copied().unwrap_or(0),
            health.mean_side_depth(),
            worst_fill * 100.0,
            health.refused,
            health.refused_by_kind,
        );
        println!(
            "{:<10} {:>6} {:>9} {:>9} {:>9} {:>9} {:>10}",
            "",
            "",
            "",
            "",
            "empty sides",
            health.readings_with_an_empty_side(),
            ""
        );
    }

    // -----------------------------------------------------------------------
    // The same measurement with the fix taken out.
    // -----------------------------------------------------------------------

    /// The defect this file replaces, measured. The generator forgets every
    /// order except the newest 50. Nothing can cancel an order that falls out
    /// of that window, so only a trade takes such an order off a book.
    ///
    /// Measured on the same seed and the same 50,000 messages at 40 accounts
    /// and 24 messages a second: the books hold 1,213.9 orders a side against
    /// 55.1, one side reaches 2,668 against 84, and the run breaks 8 of the
    /// checks above. The self-trade refusals come back with the depth, 9,077
    /// against none. That is the mechanism: the exchange reads every order at
    /// every level an arriving order crosses, so a deeper book refuses more
    /// orders. 5,087 crossing orders also traded less than the level they
    /// named, because the generator no longer knew what rested.
    /// Ignored, and this is the reason. It drives 50,000 messages to measure a
    /// design this file replaced, which is 700 seconds of a suite that was
    /// 1,351. What it proves is proven again in seconds by
    /// `the_health_check_still_fails_a_generator_that_forgets` below, which is
    /// not ignored: this one is the number, that one is the check.
    #[test]
    #[ignore = "a counterfactual, not a check on this code: 700s, run it with --ignored"]
    fn forgetting_every_order_but_the_newest_fifty_makes_the_books_grow() {
        let health = drive(ACCOUNTS, MESSAGES, Sabotage::ForgetAllButFifty);
        health.print("the old cancel window of 50");
        let failures = what_is_unhealthy(&health);
        assert!(
            !failures.is_empty(),
            "the measurement passed a generator that can only cancel its newest 50 orders, so it \
             does not measure the defect it was written for"
        );
        println!("the checks it broke:\n  {}", failures.join("\n  "));
        assert!(
            health.deepest_side() > DEEPEST_SIDE,
            "one side of a book reached {} orders, which is inside the bound of {}",
            health.deepest_side(),
            DEEPEST_SIDE
        );
    }

    /// The health check still fails a generator that forgets what it placed.
    ///
    /// This is the part of the test above that is a check, at a size that can
    /// run on every commit. The test above drives 50,000 messages because it
    /// reports what the old design did, in numbers a reader can compare with
    /// the RFC. This one asks the only question CI needs answered: is
    /// `what_is_unhealthy` still able to see that defect at all?
    ///
    /// Without it, the two `#[ignore]`s above would take that question out of
    /// CI with them. A threshold in `what_is_unhealthy` loosened far enough to
    /// pass a book 22 times too deep would then ship, and
    /// `the_generated_traffic_keeps_every_market_trading` would not catch it,
    /// because that test drives the healthy generator and would still pass.
    ///
    /// 4,000 messages and not 50,000. The defect is not subtle: measured at
    /// this size the sabotaged run still breaks the checks, and it costs a few
    /// seconds instead of 700.
    #[test]
    fn the_health_check_still_fails_a_generator_that_forgets() {
        // The control. A short run of the generator this file ships has to look
        // healthy at this size, or the assertion below would hold for the
        // wrong reason: a check that fails everything catches nothing.
        let healthy = what_is_unhealthy(&drive(ACCOUNTS, 4_000, Sabotage::None));
        assert!(
            healthy.is_empty(),
            "4,000 messages is too few for the shipped generator to measure as healthy, so \
             this test cannot tell a broken check from a short run: {}",
            healthy.join(", ")
        );

        let health = drive(ACCOUNTS, 4_000, Sabotage::ForgetAllButFifty);
        let failures = what_is_unhealthy(&health);
        assert!(
            !failures.is_empty(),
            "`what_is_unhealthy` passed a generator that can only cancel its newest 50 \
             orders. It no longer measures the defect it was written for, and the two \
             measurements of that defect are `#[ignore]`d, so nothing else will say so."
        );
    }

    /// No order ever reaches the end of its life. That is a cancel rate of zero
    /// per resting order. Smith, Farmer, Gillemot and Krishnamurthy (2003): a
    /// book fills at `a`, empties at `r` per resting order, and settles at
    /// `a / r`. At `r = 0` there is no settling depth.
    ///
    /// Measured on the same seed: the books hold 656.5 orders a side against
    /// 55.1, and one side reaches 1,106 against 84. The generator sends the
    /// cancels the `MAX_OPEN_ORDERS` bound forces and no others, and 3,998
    /// orders are open at the end. The exchange refuses nothing, because the
    /// account roles are still in place. That is what separates the two halves
    /// of the fix.
    /// Ignored for the same reason as
    /// `forgetting_every_order_but_the_newest_fifty_makes_the_books_grow`: it
    /// drives 50,000 messages to measure a design that is not this one, and it
    /// is 300 seconds.
    #[test]
    #[ignore = "a counterfactual, not a check on this code: 300s, run it with --ignored"]
    fn an_order_that_never_expires_makes_the_books_grow() {
        let health = drive(ACCOUNTS, MESSAGES, Sabotage::NeverExpire);
        health.print("no order ever expires");
        assert!(
            health.deepest_side() > DEEPEST_SIDE,
            "one side of a book reached {} orders, which is inside the bound of {}",
            health.deepest_side(),
            DEEPEST_SIDE
        );
    }

    // -----------------------------------------------------------------------
    // The properties that hold by construction.
    // -----------------------------------------------------------------------

    /// A quoting account never sends an order that crosses one of its own
    /// orders, and a taking account never has an order to cross.
    ///
    /// This is what stops the self-trade rule refusing generated orders. The
    /// test asks the question of the messages themselves, so the answer holds
    /// whatever the exchange does with those messages.
    #[test]
    fn no_generated_order_can_be_refused_as_a_self_trade() {
        let mut state = FeedState::new(ACCOUNTS, 1_786_752_000_000);
        state.seed_the_generator(SEED);
        let mut timestamp = state.clock.now_ms();
        for _ in 0..MESSAGES {
            // The books as they stood when the message was made. The exchange
            // asks its question against these books, and not against the books
            // after the message.
            let before: Vec<(AccountId, usize, Side, i64)> = state
                .open_orders
                .iter()
                .map(|open| (open.account, open.market, open.side, open.price_cents))
                .collect();
            let message = generate_message_at(&mut state, timestamp);
            timestamp += MS_PER_MESSAGE;
            let OrderMessage::New {
                account,
                symbol,
                side,
                price,
                ..
            } = &message
            else {
                continue;
            };
            let market = market_of(symbol);
            let price_cents = in_cents(*price);
            for (open_account, open_market, open_side, open_cents) in &before {
                if open_account != account || *open_market != market || open_side == side {
                    continue;
                }
                assert!(
                    !crosses(*side, price_cents, *open_cents),
                    "account {} sent a {:?} at {} against its own order at {}",
                    account,
                    side,
                    price_cents,
                    open_cents
                );
            }
        }
    }

    /// A taking account holds nothing in any book. That is the other half of
    /// the self-trade answer. The exchange reads the levels an arriving order
    /// crosses, and finds no order of that account at any of them.
    #[test]
    fn a_taking_account_holds_nothing_in_any_book() {
        let mut state = FeedState::new(ACCOUNTS, 1_786_752_000_000);
        state.seed_the_generator(SEED);
        let mut timestamp = state.clock.now_ms();
        for _ in 0..10_000 {
            generate_message_at(&mut state, timestamp);
            timestamp += MS_PER_MESSAGE;
        }
        let quoting = quoting_accounts(ACCOUNTS);
        assert_eq!(quoting, 34, "34 of the 40 accounts quote and 6 take");
        for open in &state.open_orders {
            assert!(
                open.account < quoting,
                "account {} takes and yet holds order {} in a book",
                open.account,
                open.id
            );
        }
    }

    /// The generator's list of open orders holds the same orders as the
    /// exchange's book, order for order, and with nothing extra on either side.
    ///
    /// The pricing rests on this. The generator prices an order from the best
    /// price on the other side, and it reads that price off its own list. A
    /// list that no longer matched would price orders against a book that is
    /// not there. The list is exact because a quoting order never crosses, so
    /// it always rests in full, and because a taking order names one whole
    /// level, so it always empties that level.
    #[test]
    fn the_generator_knows_exactly_which_orders_rest() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut state = FeedState::new(ACCOUNTS, 1_786_752_000_000);
        state.seed_the_generator(SEED);
        let mut engine = MatcherState::new();
        let timestamp = state.clock.now_ms();
        // Rule set 2 first, exactly as the live log opens. Without rule set 2
        // `step4_self_trade_check` returns early, and the test would measure a
        // case where an order can trade with itself. The live log does not run
        // that case.
        engine
            .apply_message(&crate::operator::signed_as(
                &key,
                "",
                OrderMessage::EngineRule {
                    id: 1,
                    timestamp,
                    account: OPERATOR_ACCOUNT,
                    version: 2,
                    nonce: Some(format!("{:032x}", 1)),
                    public_key: String::new(),
                    signature: String::new(),
                },
            ))
            .expect("the operator opens the log");
        state.next_id += 1;
        for (index, (symbol, _, price_step)) in SYMBOLS.iter().enumerate() {
            let id = 2 + index as OrderId;
            engine
                .apply_message(&crate::operator::signed_as(
                    &key,
                    "",
                    OrderMessage::ListSymbol {
                        id,
                        timestamp,
                        account: OPERATOR_ACCOUNT,
                        symbol: symbol.to_string(),
                        price_step: *price_step,
                        quantity_step: 0.1,
                        nonce: Some(format!("{:032x}", id)),
                        public_key: String::new(),
                        signature: String::new(),
                    },
                ))
                .expect("the operator opens the market");
            state.next_id += 1;
        }

        let mut timestamp = timestamp;
        let mut sent: Vec<OrderId> = Vec::new();
        for _ in 0..20_000 {
            let message = generate_message_at(&mut state, timestamp);
            timestamp += MS_PER_MESSAGE;
            if let OrderMessage::New { id, .. } = &message {
                sent.push(*id);
            }
            engine.apply_message(&message).expect("in feed order");
        }

        for open in &state.open_orders {
            let held = engine.open_order(open.id);
            let Some((symbol, side, price_cents, qty_tenths)) = held else {
                panic!(
                    "the generator believes order {} rests and the exchange does not hold it",
                    open.id
                );
            };
            assert_eq!(market_of(symbol), open.market);
            assert_eq!(side, open.side);
            assert_eq!(price_cents, open.price_cents);
            assert_eq!(qty_tenths, open.qty_tenths);
        }
        let held = sent
            .iter()
            .filter(|id| engine.open_order(**id).is_some())
            .count();
        assert_eq!(
            held,
            state.open_orders.len(),
            "the exchange holds {} of the generator's orders and the generator believes it holds \
             {}",
            held,
            state.open_orders.len()
        );
    }

    /// The generator can cancel an order at any age. The old generator reached
    /// back 50 messages. This generator reaches back thousands, because it
    /// forgets nothing.
    ///
    /// Measured over 50,000 messages on seed 20260816: the oldest order a
    /// cancel reached was 16,689 messages back, which is 12 minutes of live
    /// traffic at 24 messages a second. The bound below is well under that.
    #[test]
    fn an_order_is_still_cancellable_long_after_the_newest_fifty() {
        let mut state = FeedState::new(ACCOUNTS, 1_786_752_000_000);
        state.seed_the_generator(SEED);
        let mut timestamp = state.clock.now_ms();
        let mut oldest = 0;
        for _ in 0..MESSAGES {
            let message = generate_message_at(&mut state, timestamp);
            timestamp += MS_PER_MESSAGE;
            if let OrderMessage::Cancel { id, target_id, .. } = message {
                oldest = oldest.max(id - target_id);
            }
        }
        assert!(
            oldest > 600,
            "the oldest order any cancel reached was {} messages back, and the old window of 50 \
             is what this replaces",
            oldest
        );
    }

    // -----------------------------------------------------------------------
    // The numbers the generator makes.
    // -----------------------------------------------------------------------

    /// Every price the generator can make sits on its market's price step, on
    /// the cent grid, and inside the range the engine holds. The engine refuses
    /// a price that is off the listed step: `matcher/step1_resolve_symbol.rs`.
    /// The exchange would ignore a generated order that failed this check, and
    /// the market would trade nothing.
    #[test]
    fn every_generated_price_sits_on_the_listed_step() {
        let mut state = FeedState::new(ACCOUNTS, 1_786_752_000_000);
        state.seed_the_generator(SEED);
        let mut timestamp = state.clock.now_ms();
        let steps: Vec<i64> = SYMBOLS
            .iter()
            .map(|(_, _, step)| steps_in_cents(*step))
            .collect();
        for _ in 0..20_000 {
            let message = generate_message_at(&mut state, timestamp);
            timestamp += MS_PER_MESSAGE;
            let OrderMessage::New {
                symbol,
                price,
                quantity,
                ..
            } = &message
            else {
                continue;
            };
            let cents = to_grid(*price, PRICE_SCALE)
                .unwrap_or_else(|| panic!("{} priced {} off the cent grid", symbol, price));
            assert_eq!(
                cents % steps[market_of(symbol)],
                0,
                "{} priced {} off its step",
                symbol,
                price
            );
            assert!(
                to_grid(*quantity, 10.0).is_some(),
                "{} sized {} off the tenth grid",
                symbol,
                quantity
            );
        }
    }

    /// A price stays inside the range the engine can represent, whatever number
    /// it was read from. A restart reads the reference price of a market from
    /// the last published price. A value outside the grid there used to reach
    /// `f64::INFINITY`. serde writes `f64::INFINITY` as JSON `null`, and
    /// nothing can read `null` back as a price.
    #[test]
    fn prices_stay_inside_the_grid() {
        assert_eq!(in_cents(100.25), 10_025);
        assert_eq!(in_cents(f64::INFINITY), MAX_GRID_UNITS);
        assert_eq!(in_cents(f64::NAN), 1);
        assert_eq!(in_cents(-1.0), 1);
        assert_eq!(in_cents(1e307), MAX_GRID_UNITS);
        assert!(to_grid(in_price(MAX_GRID_UNITS), PRICE_SCALE).is_some());
        assert_eq!(on_the_step(10_037, 100), 10_000);
        assert_eq!(on_the_step(-500, 10), 10);
        assert_eq!(on_the_step(i64::MAX, 100), MAX_GRID_UNITS / 100 * 100);
    }

    /// A quote near the best price is cancelled fast, and a patient quote sits.
    /// The mean life of each band is one divided by that band's cancel rate,
    /// and the cancel rate is the depth control: a book settles at the order
    /// rate divided by the cancel rate.
    ///
    /// Cont, Stoikov and Talreja (2010) measured 0.71 cancels a second one step
    /// from the best price, and 0.47 at five steps, falling toward zero far
    /// out. The rates here fall the same way, and slower.
    ///
    /// The bands are counted in steps now, so the two can be read against each
    /// other directly. Band 0 is 1 step and is cancelled 0.100 times a second,
    /// which is 7.1 times slower than the 0.71 measured at one step. Band 3 is
    /// 5 steps at 0.020 a second, which is 23.5 times slower than the 0.47
    /// measured at five steps. So the fall with distance here is steeper than
    /// the measured one.
    ///
    /// The lives are kept as they are, because they are the depth control.
    /// These five hold the books at 55.1 orders a side at 24 messages a second
    /// and 13.0 at 6. A fall as shallow as the measured one needs a slower near
    /// band, that makes the books deeper, and every measured number in this
    /// file would move.
    #[test]
    fn a_near_quote_is_replaced_and_a_patient_one_sits() {
        let mut rng = seeded_rng(SEED);
        let draws = 100_000;
        let mut rates = Vec::new();
        for band in 0..PATIENCE_BANDS.len() {
            let total: u64 = (0..draws).map(|_| a_life(&mut rng, band)).sum();
            let mean = total as f64 / draws as f64;
            let built = BAND_LIFETIMES_MS[band];
            assert!(
                (mean - built).abs() < built * 0.1,
                "band {} ({} steps) measured a mean life of {:.0} ms and is built for {:.0}",
                band,
                PATIENCE_BANDS[band],
                mean,
                built
            );
            rates.push(1000.0 / mean);
        }
        for pair in rates.windows(2) {
            assert!(
                pair[0] > pair[1],
                "a wider band must be cancelled more slowly, and the rates are {:?}",
                rates
            );
        }
        assert!(
            (rates[0] - 0.1).abs() < 0.01,
            "the 1-step band is cancelled {:.3} times a second and is built for 0.100",
            rates[0]
        );
        assert!(
            (rates[4] - 0.01).abs() < 0.002,
            "the 10-step band is cancelled {:.3} times a second and is built for 0.010",
            rates[4]
        );
    }

    /// A quote sits near the best price on the other side, whatever band its
    /// account is in. The chance of `i` steps away falls as `i^-1`, so most
    /// orders land within a few steps of that price. That is what makes a book
    /// trade. See `QUOTE_DEPTH_EXPONENT`.
    ///
    /// The widest band is 10 steps, so 5 steps is half of the widest band and
    /// the whole of the other four.
    #[test]
    fn most_quotes_land_within_a_few_steps_of_the_best_price() {
        let mut rng = seeded_rng(SEED);
        let draws = 100_000;
        for most in PATIENCE_BANDS {
            let mut within_five = 0;
            let mut furthest = 0;
            for _ in 0..draws {
                let steps = steps_behind_the_touch(&mut rng, most);
                assert!(
                    (1..=most).contains(&steps),
                    "a quote {} steps out of a band {} steps wide",
                    steps,
                    most
                );
                furthest = furthest.max(steps);
                if steps <= 5 {
                    within_five += 1;
                }
            }
            let share = within_five as f64 / draws as f64;
            assert!(
                share > 0.70,
                "only {:.0}% of quotes in a band {} steps wide landed within 5 steps of the best \
                 price",
                share * 100.0,
                most
            );
            assert_eq!(
                furthest, most,
                "the widest quote reaches the end of the band"
            );
        }
    }

    /// A band is the same number of price steps in every market, and that is
    /// also the same share of the price in every market.
    ///
    /// This is what the per-market step in `SYMBOLS` is for. A step of 0.01 at
    /// a price of 10, 0.10 at 100 and 1.00 at 1000 are all one thousandth of
    /// the listed price. So one table of bands counted in steps gives all three
    /// markets the same book. Counted as a share of the price, one band meant
    /// 10 steps at MERKLE-USDC and 1,000 at BTC-USDC, and the per-market step
    /// did no work at all.
    #[test]
    fn a_band_is_the_same_number_of_steps_in_every_market() {
        for (symbol, price, step) in SYMBOLS {
            let step_cents = steps_in_cents(step);
            let listed = in_cents(price);
            let share_of_price = step_cents as f64 / listed as f64;
            assert!(
                (share_of_price - 0.001).abs() < 1e-9,
                "one step at {} is {:.5} of its listed price, and all three must match",
                symbol,
                share_of_price
            );
            for (band, width) in PATIENCE_BANDS.iter().enumerate() {
                assert_eq!(
                    steps_in_the_band(step_cents, *width),
                    *width,
                    "{} band {} is not the {} steps the table names",
                    symbol,
                    band,
                    width
                );
            }
        }
        // The floor. A band is never zero steps wide. A band of zero steps
        // would put a quote on the other side's best price, and the quote would
        // cross it.
        assert_eq!(steps_in_the_band(1, 0), 1);
    }

    /// The choice of side leans toward the price the market was listed at. A
    /// market priced only from its own book therefore cannot move far away over
    /// a long run.
    #[test]
    fn the_side_choice_leans_a_market_back_to_its_listed_price() {
        let mut state = FeedState::new(ACCOUNTS, 1_786_752_000_000);
        state.seed_the_generator(SEED);
        let mut timestamp = state.clock.now_ms();
        for _ in 0..MESSAGES {
            generate_message_at(&mut state, timestamp);
            timestamp += MS_PER_MESSAGE;
        }
        for (market, (symbol, listed, _)) in SYMBOLS.iter().enumerate() {
            let Some(mid) = book_mid_cents(&state.open_orders, market) else {
                panic!("{} has no two-sided book at the end of the run", symbol);
            };
            let away = (mid as f64 / PRICE_SCALE - listed) / listed;
            assert!(
                away.abs() < 0.25,
                "{} ended {:.0}% from the price it was listed at",
                symbol,
                away * 100.0
            );
        }
    }

    /// Most of the accounts quote, whatever the account count is. There is
    /// always at least one account of each kind when there is more than one
    /// account. See `QUOTING_SHARE`.
    #[test]
    fn the_accounts_split_into_quoting_and_taking() {
        assert_eq!(
            quoting_accounts(1),
            1,
            "one account cannot take from itself"
        );
        assert_eq!(quoting_accounts(2), 1);
        assert_eq!(quoting_accounts(4), 3);
        assert_eq!(quoting_accounts(20), 17);
        assert_eq!(quoting_accounts(40), 34);
        assert_eq!(quoting_accounts(400), 340);
        // The two pools never overlap, whatever the account count is. That is
        // what keeps a taking account holding nothing and a quoting account
        // crossing nothing.
        let mut state = FeedState::new(20, 1_786_752_000_000);
        state.seed_the_generator(SEED);
        for _ in 0..1_000 {
            assert!(a_quoting_account(&mut state) < 17);
            assert!(a_taking_account(&mut state) >= 17);
            assert!(a_taking_account(&mut state) < 20);
        }
    }

    /// Replaying the log rebuilds the orders the generator can still cancel. A
    /// restart that forgot those orders would leave every order it had placed
    /// in the books forever, and that is the defect this file removes.
    #[test]
    fn a_replayed_log_rebuilds_the_orders_the_generator_holds_open() {
        let mut state = FeedState::new(ACCOUNTS, 1_786_752_000_000);
        state.seed_the_generator(SEED);
        let mut timestamp = state.clock.now_ms();
        let mut log = Vec::new();
        for _ in 0..5_000 {
            let message = generate_message_at(&mut state, timestamp);
            timestamp += MS_PER_MESSAGE;
            log.push(message);
        }

        let mut replayed: Vec<OpenOrder> = Vec::new();
        for message in &log {
            replay_into_the_open_orders(&mut replayed, message);
        }
        assert!(
            !replayed.is_empty(),
            "5,000 messages leave orders open, so a replay of them must rebuild some"
        );
        // Sorted by id, because the live generator takes an order out of the
        // middle of its list with `swap_remove` and the replay does not.
        replayed.sort_by_key(|open| open.id);
        let mut held = state.open_orders.iter().collect::<Vec<_>>();
        held.sort_by_key(|open| open.id);
        assert_eq!(
            replayed.len(),
            held.len(),
            "the replay rebuilt {} open orders and the generator holds {}",
            replayed.len(),
            held.len()
        );
        for (rebuilt, open) in replayed.iter().zip(held) {
            assert_eq!(rebuilt.id, open.id);
            assert_eq!(rebuilt.market, open.market);
            assert_eq!(rebuilt.side, open.side);
            assert_eq!(rebuilt.price_cents, open.price_cents);
            assert_eq!(rebuilt.qty_tenths, open.qty_tenths);
        }
    }
}
