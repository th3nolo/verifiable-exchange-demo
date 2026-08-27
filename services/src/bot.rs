//! A trading bot that reads the sequencer's messages and profits from resting
//! orders that are now priced wrong.
//!
//! # Why there is anything to take
//!
//! The generator in `feed.rs` picks an order's side without looking at its
//! price. `side` comes from its own `gen_bool(0.5)` and never from the price.
//! So a resting order says nothing about where the price is going, and nobody
//! on this venue knows more about the price than the bot does. The mid, the
//! price halfway between the best bid and the best ask, moves as
//! `mid *= 1.0 + U(-0.002, 0.002)`, and the average of that is the mid it
//! started at. So on average, buying below the mid and selling above it makes
//! money. The only hard part is knowing where the mid is.
//!
//! A resting order keeps the price it was placed at, while its symbol's mid
//! keeps moving. The mid moves by 11.55 basis points of standard deviation for
//! every later order in that symbol. One basis point is one hundredth of a
//! percent. The other traders remove an order that is priced wrong only when
//! one of their own random arrivals happens to cross it. This bot re-checks on
//! every poll, so it sees prices that have fallen past fair value long before
//! the other traders clear them.
//!
//! # Why this does not predict the random numbers
//!
//! The sequencer uses `rand::thread_rng()`, seeded by the operating system.
//! Nothing here predicts it and nothing here could. What the bot uses is the
//! *shape* of the distribution the generator draws from, which is fixed and
//! public. It never uses the particular numbers the generator draws.
//!
//! # What the bot is made of
//!
//! - A Kalman filter per symbol over the logarithm of the price. That filter
//!   is the whole advantage. Put the last observed price in as fair value
//!   instead, and the same strategy loses money.
//! - A `MatcherState` used as an exact copy of the book. The bot replays the
//!   sequencer's messages through the real engine instead of writing matching
//!   a second time, so its view cannot drift away from the venue's.
//! - A count of what the bot has at risk, which adds up resting quantity and
//!   quantity still in flight, and not only the position. This venue has no
//!   immediate-or-cancel order type, so an order that arrives and does not
//!   fill does not disappear. It rests. A bot that ignored those remainders
//!   re-sends on every poll and ends up holding many times the position it
//!   meant to hold.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde::Deserialize;
use serde_json::json;
use tokio::time::sleep;
use tracing::{Level, error, info, warn};

use crate::domain::{AccountId, OPERATOR_ACCOUNT, OrderId, OrderMessage, SYMBOLS, Side, to_grid};
use crate::inbox::{self, SignedSubmission, Submission};
use crate::logchain;
use crate::matcher::MatcherState;
use crate::wire::{self, RawMessage, SESSION_HEADER, TooOld};

/// Variance of one drift step, `U(-0.002, 0.002)` in log space.
const PROCESS_VAR: f64 = (0.002 * 0.002) / 3.0;

/// Variance of one price observation around the mid, `U(-0.005, 0.005)`.
const OBSERVATION_VAR: f64 = (0.005 * 0.005) / 3.0;

/// How many prices of a symbol the bot sees before it will trade that symbol.
/// The filter settles on its steady gain within a few prices. Twenty is well
/// past that, and replaying the log from the start supplies twenty at once.
const WARMUP_OBSERVATIONS: u32 = 20;

/// How often a stopped bot repeats why it is not trading. See the report in
/// the poll loop for why it is neither once nor every poll.
const STOP_REPORT_EVERY: Duration = Duration::from_secs(60);

/// Fair value per symbol, estimated with a scalar Kalman filter over the
/// logarithm of the price. The filter keeps two numbers per symbol: the
/// estimate of the mid, and how uncertain that estimate is. Every price it
/// reads moves both.
///
/// Logarithms are the right place for this. The mid moves by multiplication
/// (`mid *= 1 + u`), and so does the noise on one price
/// (`price = mid * (1 + u)`). Taking logarithms turns both into additions with
/// a constant variance, which is exactly the model a Kalman filter is best
/// for.
///
/// The measured error against the true mid is 16.4 basis points RMS. That
/// number matters more than it looks. Trading against the book is only
/// profitable when the estimate is better than roughly 25 basis points, so the
/// filter is what puts the strategy on the profitable side of that line.
#[derive(Default)]
pub struct FairValue {
    /// The estimate of the logarithm of the mid, per symbol.
    log_mid: HashMap<String, f64>,
    /// How uncertain that estimate is, per symbol.
    variance: HashMap<String, f64>,
    /// How many prices the bot has read per symbol, so it can wait for the
    /// filter to settle.
    seen: HashMap<String, u32>,
}

impl FairValue {
    /// Adds one published price to the estimate for its symbol.
    ///
    /// The generator moves the mid of only the symbol it drew, so only that
    /// symbol's estimate takes a drift step here. A symbol that has not traded
    /// for a while has not become less well known.
    pub fn observe(&mut self, symbol: &str, price: f64) {
        if price <= 0.0 {
            return;
        }
        let observed = price.ln();
        *self.seen.entry(symbol.to_string()).or_insert(0) += 1;
        match self.log_mid.get_mut(symbol) {
            None => {
                self.log_mid.insert(symbol.to_string(), observed);
                self.variance.insert(symbol.to_string(), OBSERVATION_VAR);
            }
            Some(x) => {
                let p = self
                    .variance
                    .get_mut(symbol)
                    .expect("variance is written with log_mid");
                *p += PROCESS_VAR;
                let gain = *p / (*p + OBSERVATION_VAR);
                *x += gain * (observed - *x);
                *p *= 1.0 - gain;
            }
        }
    }

    /// The current fair value for a symbol, once enough prices have been seen.
    pub fn get(&self, symbol: &str) -> Option<f64> {
        if self.seen.get(symbol).copied().unwrap_or(0) < WARMUP_OBSERVATIONS {
            return None;
        }
        self.log_mid.get(symbol).map(|x| x.exp())
    }
}

/// How the bot is configured for one run.
#[derive(Clone, Debug)]
pub struct BotConfig {
    /// The account the bot trades as. Any id works, because the sequencer does
    /// not own account ids.
    pub account: AccountId,
    pub feed_url: String,
    pub poll_ms: u64,
    /// How far through fair value a resting price must be before the bot takes
    /// it, in basis points.
    ///
    /// This threshold exists because of how the bot picks its own trades, and
    /// not because the people it trades with know more than it does. The bot
    /// fires when its estimate says a price is cheap, and the moments its
    /// estimate says that are also the moments the estimate is most likely to
    /// be too high. With no threshold at all, the measured profit is negative.
    /// The profit is flat between roughly 3 and 12 basis points, and it falls
    /// away above that, as the bot skips chances it should have taken.
    pub take_bps: f64,
    /// The largest position the bot will hold in each symbol, counted as money
    /// in the quote token. The cap is per symbol, because the same number of
    /// units is very different money at a mid of 10 and at a mid of 1000.
    pub caps: HashMap<String, f64>,
    /// Largest single order, in units. Incoming quantities are `U(1, 10)`, so
    /// nothing above 10 is ever usable against one arrival.
    pub max_order_units: f64,
    /// How far past fair value the bot rests its own orders, in basis points.
    /// Zero is the default. It turns resting off, and leaves the bot trading
    /// only against orders that are already in the book.
    ///
    /// Resting was measured, and it loses money on this venue. The loss grows
    /// with the size rested: over 6 seeds, $36,701 with resting off, against
    /// $31,551 resting 5 units and $24,996 resting 10. The offset barely
    /// changes the result, and that is what shows the problem is resting
    /// itself, and not a badly priced resting order.
    ///
    /// The reason is that the bot's own resting order becomes an order priced
    /// wrong, which is the exact thing this bot exists to profit from in other
    /// people's orders. Trading against the book lets the bot pick its moment,
    /// and trade only when a price is measurably past fair value. A resting
    /// order hands that choice to whoever crosses it, and on a moving mid it
    /// is crossed once the mid has moved past the profit. The advantage here
    /// is knowing where fair value is, and resting an order gives that
    /// advantage away.
    ///
    /// It is kept as a setting because the measurement is worth reproducing.
    pub quote_bps: f64,
    /// The size of one resting order the bot places, in units.
    pub quote_units: f64,
}

impl Default for BotConfig {
    fn default() -> Self {
        let mut caps = HashMap::new();
        caps.insert("BTC-USDC".to_string(), 20_000.0);
        caps.insert("ETH-USDC".to_string(), 10_000.0);
        caps.insert("MERKLE-USDC".to_string(), 5_000.0);
        BotConfig {
            account: 999,
            feed_url: "http://127.0.0.1:3000".to_string(),
            poll_ms: 50,
            take_bps: 6.0,
            caps,
            max_order_units: 10.0,
            // Off by default. It was measured: resting orders lose money here,
            // and the loss grows with the size rested. See `quote_bps`.
            quote_bps: 0.0,
            quote_units: 5.0,
        }
    }
}

/// Something the bot wants the sequencer to publish.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Submit {
        symbol: String,
        side: Side,
        price: f64,
        quantity: f64,
    },
    Cancel {
        target_id: OrderId,
    },
}

/// The bot's whole state: a copy of the book, a fair value per symbol, and the
/// orders the bot is responsible for.
pub struct Bot {
    pub cfg: BotConfig,
    /// The real engine, replaying the same messages the exchange runs.
    pub book: MatcherState,
    pub fair: FairValue,
    /// Orders the bot has sent and seen arrive, which may still be resting.
    mine: HashSet<OrderId>,
    /// Orders sent but not yet seen back in the log, as (symbol, side,
    /// tenths). Until one lands, the bot must still count that quantity as
    /// committed.
    inflight: HashMap<OrderId, (String, Side, i64)>,
    /// The history this copy of the book belongs to.
    session: Option<String>,
    /// The highest message number the bot has read.
    pub cursor: OrderId,
    /// The first message this build cannot read, once it has met one.
    ///
    /// A value here means the bot has stopped. It reads nothing past this
    /// message and decides nothing. See `consume` for why stopping is the
    /// answer, and what stopping costs.
    blocked: Option<TooOld>,
}

/// Rounds down to a whole cent. `to_grid` refuses a price that is not a whole
/// number of cents rather than rounding it, so the bot works in whole numbers
/// and converts once. That way it never sends a price the engine cannot hold.
fn floor_cents(price: f64) -> i64 {
    (price * 100.0).floor() as i64
}

fn ceil_cents(price: f64) -> i64 {
    (price * 100.0).ceil() as i64
}

/// The price step `symbol` is listed on, in cents.
///
/// The bot takes the step from `domain::SYMBOLS`, the same constant it takes
/// its symbol list from. Its copy of the book holds the real listings from the
/// log, but a bot that read the step off that copy would have no step for a
/// market whose `ListSymbol` it has not read yet, and it starts placing orders
/// from its first page. A market listed on a step this constant does not name
/// is a market the bot prices too coarsely on. That costs it profit and breaks
/// nothing.
fn step_cents(symbol: &str) -> i64 {
    SYMBOLS
        .iter()
        .find(|(name, _, _)| *name == symbol)
        .and_then(|(_, _, step)| to_grid(*step, 100.0))
        .unwrap_or(1)
}

/// Rounds `cents` down to the market's step. It is used for a buy, because a
/// lower price costs the bot nothing when the order does not fill.
fn floor_to_step(cents: i64, step_cents: i64) -> i64 {
    cents - cents.rem_euclid(step_cents)
}

/// Rounds `cents` up to the market's step. It is used for a sell, for the same
/// reason the other way round.
fn ceil_to_step(cents: i64, step_cents: i64) -> i64 {
    floor_to_step(cents + step_cents - 1, step_cents)
}

impl Bot {
    pub fn new(cfg: BotConfig) -> Self {
        Bot {
            cfg,
            book: MatcherState::new(),
            fair: FairValue::default(),
            mine: HashSet::new(),
            inflight: HashMap::new(),
            session: None,
            cursor: 0,
            blocked: None,
        }
    }

    /// Applies one page of the sequencer's bytes to the bot's copy of the
    /// book, and stops at the first message this build cannot read.
    ///
    /// # What happens on a kind this build does not know, and why
    ///
    /// The bot stops. It reads nothing past that message, it decides nothing,
    /// and it sends nothing, until either this binary is upgraded or the
    /// sequencer starts a new history.
    ///
    /// The alternative was to skip the message and carry on. That is worse
    /// here, and the reason is what this bot is. `self.book` is the real
    /// matching engine replaying the same history the exchange runs, and every
    /// price the bot sends comes off that book. A skipped message is a message
    /// the exchange applied and this copy did not, so the two books stop being
    /// the same book. Nothing later puts them back, because the difference
    /// grows through every fill and cancel that follows. The bot would go on
    /// sending orders against quantity that is not there, at prices worked out
    /// from a fair value fed by a history with a hole in it. Skipping also
    /// does not work in practice: the engine refuses a message that jumps a
    /// gap (`ApplyError::OutOfOrder`), so the message after the skipped one is
    /// refused anyway.
    ///
    /// **The risk of stopping**: the bot goes idle with its orders still
    /// resting on the venue. Those orders keep filling, and nothing cancels or
    /// reprices them, so the position it ends up with is not the one it chose.
    /// That is a real cost, and it has a limit. The resting quantity is
    /// whatever the bot had already committed, and it cannot grow, because a
    /// stopped bot sends nothing. A copy of the book that has gone wrong has
    /// no such limit. It keeps sending orders, and every one of them is priced
    /// off a book that is wrong.
    ///
    /// This says nothing against the sequencer. The bot hashes no chain, so it
    /// has nothing to say about whether the history is honest. All it knows is
    /// that the sequencer publishes a kind this binary was compiled before.
    /// That is a deploy, and `start_bot` reports it as one.
    ///
    /// The messages before the unreadable one are applied. They are readable
    /// and in order, so the copy of the book is exactly correct up to that
    /// point, and the cursor stops on the message that stopped the bot rather
    /// than somewhere less exact.
    pub fn consume(&mut self, page: &[RawMessage]) -> Result<(), TooOld> {
        for raw in page {
            match raw.parse() {
                Ok(msg) => self.observe(&msg),
                Err(too_old) => {
                    self.blocked = Some(too_old.clone());
                    return Err(too_old);
                }
            }
        }
        self.blocked = None;
        Ok(())
    }

    /// The message this build cannot read, if the bot has stopped on one.
    pub fn blocked(&self) -> Option<&TooOld> {
        self.blocked.as_ref()
    }

    /// What an operator has to read when the bot has stopped trading.
    ///
    /// A stopped bot looks exactly like a bot with nothing to do, so this
    /// report has to say all four things: that the bot has stopped, why, that
    /// nothing is wrong with the sequencer, and what is still at risk while
    /// the bot is stopped. The last one is the part an operator acts on. The
    /// orders the bot left resting are still live, and nobody is managing
    /// them.
    fn stopped_report(&self, too_old: &TooOld) -> String {
        format!(
            "this bot has stopped trading. {}\n  It sends no orders and no cancels until this \
             binary can read message {}. Its replica of the book is correct up to message {}, \
             and it will not trade on a replica that has skipped anything.\n  {} of its own \
             orders may still be resting on the venue and will keep filling unmanaged.\n  \
             Upgrade this binary to resume.",
            too_old.notice(
                "The bot folds no chain, so this says nothing about whether the feed's history \
                 is honest, only that this build is older than the message format the feed \
                 publishes."
            ),
            too_old.id,
            self.cursor,
            self.mine.len() + self.inflight.len(),
        )
    }

    /// Reads one message: applies it to the bot's copy of the book, and, when
    /// the message carries a price, updates that symbol's fair value.
    ///
    /// The copy of the book applies one history in order. A message the engine
    /// refuses, a repeat or one that jumps a gap, is not read at all.
    /// Acting on a book that skipped messages would size orders against
    /// quantity that may not be there. The cursor stays where it is, so the
    /// next poll asks for the same range again.
    pub fn observe(&mut self, msg: &OrderMessage) {
        if let Err(e) = self.book.apply_message(msg) {
            warn!("bot replica refused feed message {}: {}", msg.id(), e);
            return;
        }
        self.cursor = self.cursor.max(msg.id());
        if let OrderMessage::New { symbol, price, .. } = msg {
            self.fair.observe(symbol, *price);
        }
        // One of the bot's own messages arriving is the moment its quantity
        // stops being in flight and becomes either a position or a resting
        // order. The copy of the book counts both of those.
        let id = msg.id();
        if self.inflight.remove(&id).is_some() {
            self.mine.insert(id);
        }
    }

    /// Quantity of the bot's own orders resting on one side of one symbol.
    fn resting_tenths(&self, symbol: &str, side: Side) -> i64 {
        self.mine
            .iter()
            .filter_map(|id| self.book.open_order(*id))
            .filter(|(sym, s, _, _)| *sym == symbol && *s == side)
            .map(|(_, _, _, qty)| qty)
            .sum()
    }

    /// Quantity sent but not yet seen back, on one side of one symbol.
    fn inflight_tenths(&self, symbol: &str, side: Side) -> i64 {
        self.inflight
            .values()
            .filter(|(sym, s, _)| sym == symbol && *s == side)
            .map(|(_, _, qty)| qty)
            .sum()
    }

    /// Everything the bot has committed in one direction, in tenths. That is
    /// the position it holds, plus everything that could still fill without
    /// the bot doing anything more.
    ///
    /// Counting resting quantity and quantity in flight is what keeps the bot
    /// inside its cap. Without that count, an order that rests instead of
    /// filling leaves the position unchanged, the bot reads itself as holding
    /// nothing, and it sends the same order again on the next poll.
    fn exposure(&self, symbol: &str, side: Side) -> i64 {
        let (position, _, _) = self.book.position_of(self.cfg.account, symbol);
        let signed = match side {
            Side::Buy => position,
            Side::Sell => -position,
        };
        signed + self.resting_tenths(symbol, side) + self.inflight_tenths(symbol, side)
    }

    /// What the bot wants to do right now.
    pub fn decide(&mut self) -> Vec<Action> {
        self.mine.retain(|id| self.book.open_order(*id).is_some());
        let mut actions = Vec::new();

        for (symbol, _, _) in SYMBOLS {
            let Some(fair) = self.fair.get(symbol) else {
                continue;
            };
            let Some(cap_notional) = self.cfg.caps.get(symbol).copied() else {
                continue;
            };
            let cap_tenths = ((cap_notional / fair) * 10.0).round() as i64;
            if cap_tenths <= 0 {
                continue;
            }
            let (position, _, _) = self.book.position_of(self.cfg.account, symbol);
            let ratio = position as f64 / cap_tenths as f64;

            // Ask for more profit before making a position bigger, and ask for
            // none at all before cutting one that is already near the cap. The
            // mid is as likely to go up as down, so holding a position earns
            // nothing and only adds risk.
            let base = self.cfg.take_bps / 10_000.0;
            let buy_thr = if ratio < -0.7 {
                0.0
            } else {
                base * (1.0 + 3.0 * ratio.max(0.0))
            };
            let sell_thr = if ratio > 0.7 {
                0.0
            } else {
                base * (1.0 + 3.0 * (-ratio).max(0.0))
            };
            // On the market's own price step, and not on the cent. The engine
            // refuses a price that is not a whole number of steps,
            // `off_price_step` in step 1. So a bot that priced BTC-USDC to the
            // cent against a step of 1.00 would have every order it sent
            // ignored.
            let step = step_cents(symbol);
            let buy_limit = floor_to_step(floor_cents(fair * (1.0 - buy_thr)), step);
            let sell_limit = ceil_to_step(ceil_cents(fair * (1.0 + sell_thr)), step);

            // Cancel the bot's own resting orders that are no longer past fair
            // value. They were sent to trade at once against the book. A
            // remainder that stayed behind is a resting order, and a resting
            // order the market has caught up to is one that will fill at a
            // loss.
            for id in self.mine.iter().copied() {
                let Some((sym, side, cents, _)) = self.book.open_order(id) else {
                    continue;
                };
                if sym != symbol {
                    continue;
                }
                let still_good = match side {
                    Side::Buy => cents <= buy_limit,
                    Side::Sell => cents >= sell_limit,
                };
                if !still_good {
                    actions.push(Action::Cancel { target_id: id });
                }
            }

            let max_order_tenths = (self.cfg.max_order_units * 10.0).round() as i64;

            // The room left is counted here, in a local, through the rest of
            // this symbol. The orders decided below are not in the book yet:
            // `decide` returns them and the caller sends them. Reading the
            // exposure again would not see them, and a resting order would
            // then be sized against room an order in the same batch has
            // already claimed.
            let mut long_room = cap_tenths - self.exposure(symbol, Side::Buy);
            let mut short_room = cap_tenths - self.exposure(symbol, Side::Sell);

            if long_room > 0
                && self
                    .book
                    .best_ask_cents(symbol)
                    .is_some_and(|ask| ask <= buy_limit)
            {
                let available = self.book.qty_through_cents(
                    symbol,
                    Side::Sell,
                    buy_limit,
                    Some(self.cfg.account),
                );
                let want = available.min(long_room).min(max_order_tenths);
                if want > 0 {
                    actions.push(Action::Submit {
                        symbol: symbol.to_string(),
                        side: Side::Buy,
                        price: buy_limit as f64 / 100.0,
                        quantity: want as f64 / 10.0,
                    });
                    long_room -= want;
                }
            }

            if short_room > 0
                && self
                    .book
                    .best_bid_cents(symbol)
                    .is_some_and(|bid| bid >= sell_limit)
            {
                let available = self.book.qty_through_cents(
                    symbol,
                    Side::Buy,
                    sell_limit,
                    Some(self.cfg.account),
                );
                let want = available.min(short_room).min(max_order_tenths);
                if want > 0 {
                    actions.push(Action::Submit {
                        symbol: symbol.to_string(),
                        side: Side::Sell,
                        price: sell_limit as f64 / 100.0,
                        quantity: want as f64 / 10.0,
                    });
                    short_room -= want;
                }
            }

            // The bot's own resting orders.
            //
            // Trading against the book alone leaves the bot waiting for the
            // other side to become cheap before it can get back to no
            // position. Everything it holds in the meantime is exposed to a
            // mid that pays nothing for being held. A resting order on the
            // side that shrinks the position closes the round trip on the
            // market's own schedule instead. That takes the profit and frees
            // the cap to earn it again.
            //
            // While a position is on one side, only the side that shrinks it
            // gets a resting order. Near no position at all, both sides get
            // one, and then a fill either way is a round trip and not a new
            // position.
            //
            // These need no records of their own. A resting order sits at
            // `quote_bps` past fair value, and the cancel loop above already
            // cancels anything of the bot's that fair value has caught up to.
            // So a resting order is repriced by being withdrawn and replaced
            // here on the next poll.
            if self.cfg.quote_bps > 0.0 {
                let offset = self.cfg.quote_bps / 10_000.0;
                let quote_tenths = (self.cfg.quote_units * 10.0).round() as i64;
                for side in [Side::Buy, Side::Sell] {
                    // Only the side that shrinks the position, and never one
                    // that grows it. Trading against the book and resting an
                    // order both draw on the same cap, and trading against the
                    // book is worth several times more per unit of cap. So a
                    // resting order that builds a position takes cap away from
                    // the better use of it. Measured: resting on both sides
                    // near no position at all costs about 14% of total profit.
                    let reduces = match side {
                        Side::Buy => position < 0,
                        Side::Sell => position > 0,
                    };
                    let room = match side {
                        Side::Buy => long_room,
                        Side::Sell => short_room,
                    };
                    // One resting order per side at a time. An order that
                    // filled only in part already left a resting order at a
                    // better price than this one would be, so that remainder
                    // counts as the resting order for that side.
                    let already =
                        self.resting_tenths(symbol, side) + self.inflight_tenths(symbol, side) > 0;
                    if !reduces || room < quote_tenths || already {
                        continue;
                    }
                    // On the market's price step, for the same reason the
                    // limits above are. A resting order off the step is
                    // refused, and the bot then rests nothing at all.
                    let target = match side {
                        Side::Buy => floor_to_step(floor_cents(fair * (1.0 - offset)), step),
                        Side::Sell => ceil_to_step(ceil_cents(fair * (1.0 + offset)), step),
                    };
                    // An order priced past the other side of the book does not
                    // rest. It would trade at once, at a price the bot chose
                    // for resting and not for trading.
                    let crosses = match side {
                        Side::Buy => self
                            .book
                            .best_ask_cents(symbol)
                            .is_some_and(|ask| target >= ask),
                        Side::Sell => self
                            .book
                            .best_bid_cents(symbol)
                            .is_some_and(|bid| target <= bid),
                    };
                    if crosses || target <= 0 {
                        continue;
                    }
                    actions.push(Action::Submit {
                        symbol: symbol.to_string(),
                        side,
                        price: target as f64 / 100.0,
                        quantity: quote_tenths as f64 / 10.0,
                    });
                    match side {
                        Side::Buy => long_room -= quote_tenths,
                        Side::Sell => short_room -= quote_tenths,
                    }
                }
            }
        }
        actions
    }

    /// Records an order the bot has sent, before it comes back in the log.
    pub fn note_sent(&mut self, id: OrderId, symbol: &str, side: Side, quantity: f64) {
        let tenths = (quantity * 10.0).round() as i64;
        self.inflight.insert(id, (symbol.to_string(), side, tenths));
    }

    /// Realized and unrealized profit in the quote token, as `GET /positions`
    /// would report it.
    pub fn pnl(&self) -> (f64, f64) {
        let (realized, unrealized) = self.book.account_pnl_mills(self.cfg.account);
        (realized as f64 / 1000.0, unrealized as f64 / 1000.0)
    }

    /// Net position per symbol, in units.
    pub fn positions(&self) -> Vec<(String, f64)> {
        SYMBOLS
            .iter()
            .map(|(symbol, _, _)| {
                let (tenths, _, _) = self.book.position_of(self.cfg.account, symbol);
                (symbol.to_string(), tenths as f64 / 10.0)
            })
            .collect()
    }

    /// Drops the bot's copy of the book when the sequencer names a history
    /// that book does not belong to. A book built from a different session
    /// describes a market that no longer exists, and trading on it would be
    /// trading on nothing.
    ///
    /// This is also where the copy learns which log it is on. The book is
    /// built with the session, because an operator message is signed over a
    /// statement naming the log. A copy that did not know the session would
    /// refuse every `ListSymbol` the sequencer published, which would leave
    /// this bot working from a book that holds no market at all. See
    /// `MatcherState::replaying`.
    fn check_session(&mut self, session: &str) -> bool {
        match &self.session {
            Some(known) if known == session => false,
            Some(_) => {
                warn!("feed session changed: discarding the book and replaying from the start");
                self.start_over(session);
                true
            }
            // First contact. This runs before the page it arrived with is
            // applied, so an ordinary bot learns its log before it reads a
            // single message, and it starts.
            //
            // A copy of the book that had already read messages is the other
            // case. It built its books without knowing which log they were, so
            // it checked every operator message against the wrong session. It
            // replays from the first message, which is the same answer the
            // exchange gives to a run that reached a cursor without a session.
            None => {
                self.session = Some(session.to_string());
                if self.cursor > 0 {
                    warn!(
                        "the feed named its session {} only after {} messages: replaying the \
                         book from the start, because the messages already consumed were \
                         checked against no session at all",
                        session, self.cursor
                    );
                    self.start_over(session);
                    return true;
                }
                self.book = MatcherState::replaying(session);
                false
            }
        }
    }

    /// Throws the copy of the book away and starts again on the log `session`
    /// names.
    ///
    /// Everything that came from the old history goes: the book, the fair
    /// values, the ids of this bot's own orders, and the ids in flight. The
    /// cursor goes back to zero, so the next poll reads the new history from
    /// its first message.
    fn start_over(&mut self, session: &str) {
        self.book = MatcherState::replaying(session);
        self.fair = FairValue::default();
        self.mine.clear();
        self.inflight.clear();
        // A new history is a new set of messages. The one this build could not
        // read belonged to the history being discarded, so it is no longer a
        // reason to stay stopped.
        self.blocked = None;
        self.cursor = 0;
        self.session = Some(session.to_string());
    }
}

#[derive(Deserialize)]
struct SubmitResponse {
    id: OrderId,
}

/// The body `POST /order` and `POST /cancel` want. It is the submission's own
/// fields at the top level, with the account's key and its signature over them
/// beside.
///
/// It is built from the signed submission and not assembled by hand, so the
/// bytes that were signed and the bytes that are sent cannot drift apart.
fn submission_body(signed: &SignedSubmission) -> serde_json::Value {
    let mut body = match &signed.submission {
        Submission::Order {
            account,
            symbol,
            side,
            price,
            quantity,
            order_type,
            time_in_force,
            post_only,
            ..
        } => json!({
            "account": account,
            "symbol": symbol,
            "side": side,
            "price": price,
            "quantity": quantity,
            // Always written, even when they hold their defaults. The
            // signature covers all three whatever they hold, so a body that
            // left one out for being a default would be a body the sequencer
            // rebuilds a different statement from. The bot only ever sends the
            // defaults; writing them anyway is what keeps that true if it ever
            // sends anything else.
            "order_type": order_type,
            "time_in_force": time_in_force,
            "post_only": post_only,
        }),
        Submission::Cancel {
            account, target_id, ..
        } => json!({
            "account": account,
            "target_id": target_id,
        }),
    };
    let fields = body.as_object_mut().expect("a JSON object was just built");
    // The nonce goes on the wire beside the fields it was signed with. Without
    // it the sequencer cannot rebuild the statement, and every submission gets
    // a 401.
    fields.insert(
        "nonce".to_string(),
        json!(inbox::nonce_of(&signed.submission)),
    );
    // The session travels for the same reason as the nonce: it is a line of
    // the statement, so the sequencer cannot rebuild the statement without it.
    fields.insert(
        "session".to_string(),
        json!(inbox::session_of(&signed.submission)),
    );
    fields.insert("public_key".to_string(), json!(signed.public_key));
    fields.insert("signature".to_string(), json!(signed.signature));
    body
}

/// Runs the bot against a running sequencer.
///
/// The bot holds its own account key and signs every order and cancel it
/// sends, like any other caller. The sequencer pins that key to the bot's
/// account on the first submission, and refuses any other key for that account
/// afterwards. The key is loaded from a file (`--bot-key`, default `bot.key`)
/// and not made fresh on each run, because a new key on every restart would be
/// refused for an account already pinned to the old one.
pub async fn start_bot(cfg: BotConfig, key: SigningKey) {
    // Without this line every `info!` below goes nowhere, and nobody could
    // check a bot's fills against the exchange. `try_init` and not `expect`,
    // because a caller may already have set a subscriber up.
    let _ = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .try_init();

    let client = reqwest::Client::new();
    let mut bot = Bot::new(cfg);
    let poll = Duration::from_millis(bot.cfg.poll_ms);
    let mut reported = Instant::now();
    // When the "this bot has stopped" report was last written, so it is
    // repeated rather than said once and lost.
    let mut stop_reported: Option<Instant> = None;

    info!(
        "bot trading as account {} against {} (take {} bps), signing with public key {}",
        bot.cfg.account,
        bot.cfg.feed_url,
        bot.cfg.take_bps,
        logchain::to_hex(key.verifying_key().as_bytes())
    );

    loop {
        // The raw-bytes endpoint, and not `/orders`. The bot reads one message
        // at a time out of it, so a kind it does not know stops it at that
        // message instead of failing the whole response. Parsing the page as
        // one `Vec<OrderMessage>` did fail the whole response, and it left the
        // bot dropping every message in the page, including the ones it could
        // read, on every poll forever. The raw endpoint also gives the
        // message's id and kind for the log without the bot having to
        // understand the message. See `wire::RawMessage`.
        let url = wire::messages_url(&bot.cfg.feed_url, bot.cursor);
        let response = match client.get(&url).send().await {
            Ok(response) => response,
            Err(e) => {
                warn!("feed poll failed: {}", e);
                sleep(poll).await;
                continue;
            }
        };
        let session = response
            .headers()
            .get(SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        // The status is read before the body. A refusal has a body too: "410
        // Gone, that message has left this log's memory", or "429, the read
        // budget is spent". Reading such a body as a page of messages would
        // report the sequencer as answering with something that is not a page
        // of messages, and that sends an operator after the wrong thing.
        let status = response.status();
        let body = match response.bytes().await {
            Ok(body) if status.is_success() => body,
            Ok(body) => {
                warn!(
                    "{} answered {}: {}",
                    url,
                    status,
                    String::from_utf8_lossy(&body[..body.len().min(200)])
                );
                sleep(poll).await;
                continue;
            }
            Err(e) => {
                warn!("feed response unreadable: {}", e);
                sleep(poll).await;
                continue;
            }
        };
        let page = match wire::split_ndjson(&body) {
            Ok(page) => page,
            Err(e) => {
                warn!("the feed answered {} with something else: {}", url, e);
                sleep(poll).await;
                continue;
            }
        };
        if let Some(session) = session
            && bot.check_session(&session)
        {
            stop_reported = None;
            continue;
        }
        if let Err(too_old) = bot.consume(&page) {
            // Written at warning level, and repeated. A bot that stops trading
            // looks exactly like a bot with nothing worth trading on, so
            // saying nothing here reads the same as a quiet market. Once a
            // minute, and not once per poll: at the default 50 ms poll that
            // would be twenty lines a second, which buries the rest of the log
            // and tells an operator nothing either.
            if stop_reported.is_none_or(|at| at.elapsed() >= STOP_REPORT_EVERY) {
                error!("{}", bot.stopped_report(&too_old));
                stop_reported = Some(Instant::now());
            }
            // No `decide`, and nothing sent. The copy of the book is behind
            // the venue from here on, and every price below would come off
            // that copy.
            sleep(poll).await;
            continue;
        }
        if stop_reported.take().is_some() {
            info!(
                "the bot is reading the feed again and has resumed trading from message {}",
                bot.cursor
            );
        }

        // Every submission is signed for one log, and the bot signs for the log
        // it is reading. The session arrives on the `x-feed-session` header of
        // the same poll the messages came on, so by here the bot has one unless
        // the sequencer has never named it. Nothing is signed without it: the
        // statement has no session line to fill, and the sequencer would refuse
        // the submission anyway.
        let Some(session) = bot.session.clone() else {
            warn!("the sequencer has not named its session, so there is nothing to sign for yet");
            sleep(poll).await;
            continue;
        };
        for action in bot.decide() {
            // A new nonce for each action, and not one per run or one per
            // account. The bot re-sends the same cancel on every poll until
            // its copy of the exchange shows the order closed. Each of those
            // re-sends has to be its own submission, or the sequencer would
            // refuse everything after the first one as a replay. One nonce per
            // action makes them separate cancels for the same target, which is
            // what the sequencer has always published them as.
            let nonce = Some(inbox::new_nonce());
            let session = Some(session.clone());
            let submission = match &action {
                Action::Submit {
                    symbol,
                    side,
                    price,
                    quantity,
                } => Submission::Order {
                    account: bot.cfg.account,
                    symbol: symbol.clone(),
                    side: *side,
                    price: *price,
                    quantity: *quantity,
                    nonce,
                    session,
                    // The bot places plain limit orders that wait to be
                    // traded with. It quotes both sides and needs its quotes
                    // to rest, so none of the three terms is anything but its
                    // default.
                    order_type: Default::default(),
                    time_in_force: Default::default(),
                    post_only: false,
                },
                Action::Cancel { target_id } => Submission::Cancel {
                    account: bot.cfg.account,
                    target_id: *target_id,
                    nonce,
                    session,
                },
            };
            // `None` means the bot built a price or a quantity the engine
            // cannot hold, and the sequencer would refuse it anyway. Dropping
            // it here says so once, instead of sending it to be refused.
            let Some(signed) = inbox::sign_submission(&key, &submission) else {
                error!(
                    "not sending {:?}: it is not on the engine's price and quantity grid, so \
                     there is nothing to sign",
                    submission
                );
                continue;
            };
            let body = submission_body(&signed);
            match action {
                Action::Submit {
                    symbol,
                    side,
                    price,
                    quantity,
                } => {
                    match client
                        .post(format!("{}/order", bot.cfg.feed_url))
                        .json(&body)
                        .send()
                        .await
                    {
                        Ok(response) if response.status().is_success() => {
                            if let Ok(sr) = response.json::<SubmitResponse>().await {
                                info!(
                                    "sent {:?} {} {} @ {}  (id {})",
                                    side, quantity, symbol, price, sr.id
                                );
                                bot.note_sent(sr.id, &symbol, side, quantity);
                            }
                        }
                        // The status alone used to be the whole report. It is
                        // not enough. A 403 here means this sequencer has
                        // another key pinned for the bot's account. No amount
                        // of retrying fixes that, and the operator has to be
                        // told in words.
                        Ok(response) => {
                            let status = response.status();
                            let detail = response.text().await.unwrap_or_default();
                            warn!("order rejected: {} {}", status, detail);
                        }
                        Err(e) => warn!("order not sent: {}", e),
                    }
                }
                Action::Cancel { target_id } => {
                    match client
                        .post(format!("{}/cancel", bot.cfg.feed_url))
                        .json(&body)
                        .send()
                        .await
                    {
                        Ok(response) if response.status().is_success() => {}
                        Ok(response) => {
                            let status = response.status();
                            let detail = response.text().await.unwrap_or_default();
                            warn!("cancel of {} rejected: {} {}", target_id, status, detail);
                        }
                        Err(e) => warn!("cancel not sent: {}", e),
                    }
                }
            }
        }

        if reported.elapsed() >= Duration::from_secs(5) {
            let (realized, unrealized) = bot.pnl();
            let held: Vec<String> = bot
                .positions()
                .into_iter()
                .filter(|(_, qty)| *qty != 0.0)
                .map(|(symbol, qty)| format!("{} {:+.1}", symbol, qty))
                .collect();
            info!(
                "pnl realized {:.2} unrealized {:.2} total {:.2} | held: {}",
                realized,
                unrealized,
                realized + unrealized,
                if held.is_empty() {
                    "flat".to_string()
                } else {
                    held.join(", ")
                }
            );
            reported = std::time::Instant::now();
        }

        sleep(poll).await;
    }
}

/// A seeded copy of the sequencer's generator, for backtesting.
///
/// It matches `feed::generate_message` exactly, including the chance of a
/// cancel, the window of cancel candidates and its `swap_remove`. So a
/// backtest runs against the same distribution the live sequencer publishes.
/// The seed is only there to make runs reproducible. The live sequencer's own
/// randomness is not predictable, and nothing here assumes it is.
struct SimFeed {
    rng: StdRng,
    mids: HashMap<String, f64>,
    candidates: Vec<(OrderId, AccountId)>,
    next_id: OrderId,
    num_accounts: u32,
    /// The messages this history opens with, oldest first, before any order.
    ///
    /// ENGINE.md section 3: a log states its own rules, and which symbols it
    /// trades is one of them. The bot's copy of the book is a real
    /// `MatcherState`, and its registry is built from `ListSymbol` messages
    /// and from nothing else. So a simulated history with no listings in it is
    /// a history in which every order is refused. The backtest would run to
    /// the end and report zero profit against an empty book, which is a wrong
    /// answer and not an error message.
    opening: VecDeque<OrderMessage>,
}

impl SimFeed {
    fn new(seed: u64, num_accounts: u32) -> Self {
        let mut sim = SimFeed {
            rng: StdRng::seed_from_u64(seed),
            mids: SYMBOLS
                .iter()
                .map(|(s, m, _)| (s.to_string(), *m))
                .collect(),
            candidates: Vec::new(),
            next_id: 1,
            num_accounts: num_accounts.max(1),
            opening: VecDeque::new(),
        };
        for (symbol, _, price_step) in SYMBOLS {
            let id = sim.take_id();
            // The backtest invents its own history and never publishes it, and
            // it still signs the listing. The engine it drives ignores an
            // operator message it cannot check, ENGINE.md section 3.1, so an
            // unsigned listing would open no market and the bot would trade
            // nothing. The session is empty, which is what an engine that has
            // never spoken to a sequencer reads.
            sim.opening.push_back(crate::operator::signed_as(
                &ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]),
                "",
                OrderMessage::ListSymbol {
                    id,
                    timestamp: 0,
                    account: OPERATOR_ACCOUNT,
                    symbol: symbol.to_string(),
                    // The steps this market is listed on live, so the
                    // backtest refuses the same prices the exchange does.
                    price_step,
                    quantity_step: 0.1,
                    nonce: Some(format!("{:032x}", id)),
                    public_key: String::new(),
                    signature: String::new(),
                },
            ));
        }
        sim
    }

    fn take_id(&mut self) -> OrderId {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn next(&mut self) -> OrderMessage {
        if let Some(opening) = self.opening.pop_front() {
            return opening;
        }
        let id = self.take_id();
        if !self.candidates.is_empty() && self.rng.gen_bool(0.15) {
            let idx = self.rng.gen_range(0..self.candidates.len());
            let (target_id, account) = self.candidates.swap_remove(idx);
            return OrderMessage::Cancel {
                id,
                timestamp: 0,
                account,
                target_id,
                nonce: None,
            };
        }
        let (symbol, _, price_step) = SYMBOLS[self.rng.gen_range(0..SYMBOLS.len())];
        let mid = self.mids.get_mut(symbol).expect("every symbol has a mid");
        *mid *= 1.0 + self.rng.gen_range(-0.002..0.002);
        // On the market's price step, the same way `feed/generate.rs` prices
        // the real traffic. The engine this simulation drives refuses a price
        // off the step, so an order priced to the cent here would be ignored,
        // and the backtest would measure a bot that traded nothing.
        let drifted = *mid * (1.0 + self.rng.gen_range(-0.005..0.005));
        let price = ((drifted / price_step).round() * price_step * 100.0).round() / 100.0;
        let quantity = (self.rng.gen_range(1.0..10.0f64) * 10.0).round() / 10.0;
        let side = if self.rng.gen_bool(0.5) {
            Side::Buy
        } else {
            Side::Sell
        };
        let account = self.rng.gen_range(0..self.num_accounts);
        self.candidates.push((id, account));
        if self.candidates.len() > 50 {
            self.candidates.remove(0);
        }
        OrderMessage::New {
            id,
            timestamp: 0,
            account,
            symbol: symbol.to_string(),
            side,
            price,
            quantity,
            nonce: None,
            order_type: Default::default(),
            time_in_force: Default::default(),
            post_only: false,
        }
    }
}

/// What one symbol contributed to a backtest run.
#[derive(Debug)]
pub struct SymbolResult {
    pub symbol: String,
    /// Cash from this symbol's fills, plus any open quantity valued at the
    /// true mid. It is everything the symbol contributed, however that total
    /// is split up.
    pub total: f64,
    pub realized: f64,
    pub end_units: f64,
    /// Open quantity valued at the true mid. It measures how much risk the bot
    /// is carrying.
    pub end_notional: f64,
}

/// What one backtest run produced.
#[derive(Debug)]
pub struct BacktestResult {
    pub per_symbol: Vec<SymbolResult>,
    pub realized: f64,
    /// Profit with open quantity valued at each symbol's true mid. The
    /// simulation knows that mid, and the live bot never can.
    pub total_at_true_mid: f64,
    /// Profit as `GET /positions` would report it. It values open quantity at
    /// the last traded price, which one trade can move.
    pub total_at_last_trade: f64,
    pub orders_sent: usize,
    pub feed_messages: usize,
    pub end_position_notional: f64,
    /// Orders the copy of the engine refused. Either the price or the quantity
    /// was one the engine cannot hold, or the symbol was one the simulated
    /// history had not listed. A count above zero means the run's books are
    /// not the books this history describes, and every number above it is
    /// measured against the wrong market.
    pub orders_ignored: u64,
}

/// Replays an invented history through the bot and reports what it made.
///
/// The bot acts between messages, which is what happens live. At the default
/// rate the sequencer publishes every 500 ms, and the bot polls every 50 ms.
pub fn backtest(seed: u64, messages: usize, cfg: BotConfig) -> BacktestResult {
    let account = cfg.account;
    let mut sim = SimFeed::new(seed, 10);
    let mut bot = Bot::new(cfg);
    let mut sent = 0usize;

    for _ in 0..messages {
        let msg = sim.next();
        bot.observe(&msg);
        for action in bot.decide() {
            let id = sim.take_id();
            let msg = match action {
                Action::Submit {
                    symbol,
                    side,
                    price,
                    quantity,
                } => {
                    bot.note_sent(id, &symbol, side, quantity);
                    OrderMessage::New {
                        id,
                        timestamp: 0,
                        account,
                        symbol,
                        side,
                        price,
                        quantity,
                        // A backtest never signs or sends anything, so there
                        // is nothing for a nonce to cover. Leaving the nonce
                        // out keeps the simulated history the same bytes the
                        // generator's history is, and leaving the three order
                        // terms at their defaults does the same. This bot
                        // places limit orders and nothing else.
                        nonce: None,
                        order_type: Default::default(),
                        time_in_force: Default::default(),
                        post_only: false,
                    }
                }
                Action::Cancel { target_id } => OrderMessage::Cancel {
                    id,
                    timestamp: 0,
                    account,
                    target_id,
                    nonce: None,
                },
            };
            sent += 1;
            bot.observe(&msg);
        }
    }

    let (realized_mills, unrealized_mills) = bot.book.account_pnl_mills(account);
    let realized = realized_mills as f64 / 1000.0;

    // Total profit is cash plus the open quantity valued at some price. The
    // engine's own test proves that equals realized plus unrealized. Valuing
    // at the true mid is the honest number. The last traded price is one trade
    // old, and it carries 66 basis points of noise around the mid, so anybody
    // who can place one trade can move the profit this run reports.
    let mut cash = 0.0;
    let mut open_at_true_mid = 0.0;
    let mut notional = 0.0;
    let mut per_symbol = Vec::new();
    for (symbol, _, _) in SYMBOLS {
        let (tenths, realized_mills, cash_mills) = bot.book.position_of(account, symbol);
        let symbol_cash = cash_mills as f64 / 1000.0;
        let units = tenths as f64 / 10.0;
        let mid = sim.mids[symbol];
        cash += symbol_cash;
        open_at_true_mid += units * mid;
        notional += units.abs() * mid;
        per_symbol.push(SymbolResult {
            symbol: symbol.to_string(),
            total: symbol_cash + units * mid,
            realized: realized_mills as f64 / 1000.0,
            end_units: units,
            end_notional: units.abs() * mid,
        });
    }

    BacktestResult {
        per_symbol,
        realized,
        total_at_true_mid: cash + open_at_true_mid,
        total_at_last_trade: realized + unrealized_mills as f64 / 1000.0,
        orders_sent: sent,
        feed_messages: messages,
        end_position_notional: notional,
        orders_ignored: bot.book.orders_ignored(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The session the submissions below are signed for. Sixteen lowercase hex
    /// characters, the shape the sequencer prints.
    const TEST_SESSION: &str = "349d462ced25bb2b";

    /// A kind of message the sequencer publishes, and that this build was
    /// compiled before. It is written out as bytes, because no struct in this
    /// binary can build one.
    const MARKET_ORDER: &str = r#"{"Market":{"id":2,"timestamp":2000,"account":7,"symbol":"ETH-USDC","side":"Buy","quantity":3.0,"max_slippage_bps":50}}"#;

    fn new_order(id: OrderId, price: f64) -> OrderMessage {
        OrderMessage::New {
            id,
            timestamp: id * 1000,
            account: 7,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            price,
            quantity: 5.0,
            nonce: None,
            order_type: Default::default(),
            time_in_force: Default::default(),
            post_only: false,
        }
    }

    /// One `/messages.ndjson` page, built the way the sequencer writes one and
    /// split back out the way the bot reads one.
    fn page(lines: &[String]) -> Vec<RawMessage> {
        let mut body = Vec::new();
        for line in lines {
            body.extend_from_slice(line.as_bytes());
            body.push(b'\n');
        }
        wire::split_ndjson(&body).expect("the feed serves one message per line")
    }

    /// The decision this file had to make, and what it costs.
    ///
    /// The bot stops at a message it cannot read, and does not skip it. The
    /// bot's copy of the book is the real matching engine replaying the
    /// venue's history, so a skipped message makes that copy stop being the
    /// venue's book, and every price after it comes off the wrong book. The
    /// bot keeps everything before the unreadable message, because that part
    /// is correct.
    ///
    /// The whole page used to be parsed as one `Vec<OrderMessage>`, so this
    /// same page gave the bot nothing at all, not even message 1. The bot then
    /// went quiet, with a one-line warning that blamed the sequencer's
    /// response.
    #[test]
    fn an_unknown_kind_stops_the_bot_at_that_message_and_not_before_it() {
        let mut bot = Bot::new(BotConfig::default());
        assert!(
            serde_json::from_str::<OrderMessage>(MARKET_ORDER).is_err(),
            "this build must genuinely not know this kind, or the test proves nothing"
        );

        let served = page(&[
            serde_json::to_string(&new_order(1, 100.25)).unwrap(),
            MARKET_ORDER.to_string(),
            serde_json::to_string(&new_order(3, 100.26)).unwrap(),
        ]);
        let stopped = bot.consume(&served).expect_err("message 2 cannot be read");

        assert_eq!(stopped.id, 2);
        assert_eq!(stopped.kind, "Market");
        assert_eq!(
            bot.cursor, 1,
            "message 1 was applied and nothing past the one it stopped on was"
        );
        assert!(bot.blocked().is_some(), "and the bot stays stopped");

        // The next poll asks for the same range and stops in the same place,
        // rather than drifting forward a message at a time.
        assert!(bot.consume(&served[1..]).is_err());
        assert_eq!(bot.cursor, 1);
    }

    /// The replica opens the markets the log opened, which needs it to know
    /// which log it is on.
    ///
    /// The listing below is signed for one session, the way the sequencer
    /// publishes one. A replica that had not been told the session would check
    /// it against the empty string, refuse it, hold no market, and then refuse
    /// every order after it, so this bot would price its quotes off a book
    /// that is empty for a reason that has nothing to do with the market.
    #[test]
    fn the_replica_opens_the_market_the_log_opened() {
        const LIVE: &str = "9c41e0b7a25d3f68";
        let listing = crate::operator::signed_as(
            &ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]),
            LIVE,
            OrderMessage::ListSymbol {
                id: 1,
                timestamp: 1000,
                account: crate::domain::OPERATOR_ACCOUNT,
                symbol: "ETH-USDC".to_string(),
                price_step: 0.01,
                quantity_step: 0.1,
                nonce: Some(format!("{:032x}", 1)),
                public_key: String::new(),
                signature: String::new(),
            },
        );
        let served = page(&[
            serde_json::to_string(&listing).unwrap(),
            serde_json::to_string(&new_order(2, 100.25)).unwrap(),
        ]);

        let mut told = Bot::new(BotConfig::default());
        assert!(!told.check_session(LIVE), "first contact starts the bot");
        told.consume(&served).expect("this build reads both");
        assert!(
            told.book.is_listed("ETH-USDC"),
            "the replica did not open the market the log opened"
        );
        assert!(
            told.book.open_order(2).is_some(),
            "and the order after the listing has nowhere to rest"
        );

        // The same page, into a replica that was never told which log it is
        // on. This is the state the bug left it in, written down so the fix
        // cannot be undone quietly.
        let mut untold = Bot::new(BotConfig::default());
        untold.consume(&served).expect("this build reads both");
        assert!(!untold.book.is_listed("ETH-USDC"));
        assert!(untold.book.open_order(2).is_none());
    }

    /// A stopped bot has to be easy to see. It looks exactly like a bot with
    /// nothing worth trading on. So the report has to say that the bot
    /// stopped, why it stopped, that nothing is being said against the
    /// sequencer, and what of the bot's is still live on the venue while it is
    /// stopped.
    #[test]
    fn a_stopped_bot_says_so_in_words_an_operator_can_act_on() {
        let mut bot = Bot::new(BotConfig::default());
        let served = page(&[
            serde_json::to_string(&new_order(1, 100.25)).unwrap(),
            MARKET_ORDER.to_string(),
        ]);
        let stopped = bot.consume(&served).expect_err("message 2 cannot be read");
        let report = bot.stopped_report(&stopped);

        assert!(report.contains("stopped trading"), "{}", report);
        assert!(report.contains("message 2"), "{}", report);
        assert!(report.contains("'Market'"), "{}", report);
        assert!(
            report.contains("not tampering"),
            "it must not read as an accusation about the feed: {}",
            report
        );
        assert!(
            report.contains("resting on the venue"),
            "it has to name the risk of staying stopped: {}",
            report
        );
        assert!(report.contains("Upgrade this binary"), "{}", report);
    }

    /// A history this build can read is consumed as it always was, and a bot
    /// that was stopped on an old history starts again on a new one, which is
    /// the one recovery available without a redeploy.
    #[test]
    fn a_readable_page_is_consumed_and_a_new_session_clears_the_stop() {
        let mut bot = Bot::new(BotConfig::default());
        bot.check_session("first");
        assert!(
            bot.consume(&page(&[MARKET_ORDER.replace("\"id\":2", "\"id\":1")]))
                .is_err()
        );
        assert!(bot.blocked().is_some());

        assert!(
            bot.check_session("second"),
            "a new history discards the replica"
        );
        assert!(
            bot.blocked().is_none(),
            "the message it stopped on belonged to the history that was discarded"
        );

        let readable = page(&[
            serde_json::to_string(&new_order(1, 100.25)).unwrap(),
            serde_json::to_string(&new_order(2, 100.26)).unwrap(),
        ]);
        bot.consume(&readable).expect("this build reads both");
        assert_eq!(bot.cursor, 2);
        assert!(bot.blocked().is_none());
    }

    /// The bot's own submissions have to survive replay protection.
    ///
    /// Two things carry the whole weight here. The nonce has to reach the
    /// wire. Without it the sequencer cannot rebuild the statement the bot
    /// signed, and every order and cancel comes back 401, with nothing in the
    /// log to say why. And the nonce has to be new for each *action*. The bot
    /// re-sends the same cancel on every poll until its copy of the book shows
    /// the order closed, so a nonce fixed per account or per run would make
    /// the sequencer refuse every re-send after the first one as a replay. The
    /// bot's cancels would then stop working on its first cancel of every run.
    #[test]
    fn every_bot_submission_carries_its_own_nonce_on_the_wire() {
        let key = logchain::ephemeral_key();
        let cancel_of = |target_id: OrderId| Submission::Cancel {
            account: 999,
            target_id,
            nonce: Some(inbox::new_nonce()),
            session: Some(TEST_SESSION.to_string()),
        };

        // The same cancel, re-sent the way the bot re-sends it.
        let resends: Vec<SignedSubmission> = (0..5)
            .map(|_| inbox::sign_submission(&key, &cancel_of(42)).expect("a cancel signs"))
            .collect();
        let nonces: HashSet<String> = resends
            .iter()
            .map(|s| {
                inbox::nonce_of(&s.submission)
                    .expect("every submission has one")
                    .to_string()
            })
            .collect();
        assert_eq!(nonces.len(), 5, "each resend is its own signed submission");

        for signed in &resends {
            let body = submission_body(signed);
            let sent = body["nonce"].as_str().expect("the nonce is on the wire");
            assert_eq!(
                Some(sent),
                inbox::nonce_of(&signed.submission),
                "the nonce sent must be the nonce signed, or the feed answers 401"
            );
            assert!(
                inbox::canonical_nonce(sent).is_some(),
                "and it has to be the spelling the feed accepts: {}",
                sent
            );
            // The body is exactly what `POST /cancel` deserializes.
            assert_eq!(body["account"], 999);
            assert_eq!(body["target_id"], 42);
            assert!(body["public_key"].is_string());
            assert!(body["signature"].is_string());
        }

        // An order body carries it in the same place.
        let order = Submission::Order {
            account: 999,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            price: 100.25,
            quantity: 5.0,
            nonce: Some(inbox::new_nonce()),
            session: Some(TEST_SESSION.to_string()),
            order_type: crate::domain::OrderType::Limit,
            time_in_force: crate::domain::TimeInForce::GoodTillCancel,
            post_only: false,
        };
        let signed = inbox::sign_submission(&key, &order).expect("an order signs");
        let body = submission_body(&signed);
        assert_eq!(body["nonce"].as_str(), inbox::nonce_of(&signed.submission));
        // The session travels with the nonce, for the same reason: it is a
        // line of the statement the sequencer rebuilds from this body.
        assert_eq!(
            body["session"].as_str(),
            inbox::session_of(&signed.submission)
        );
        // And the three order terms travel too, even though the bot only ever
        // sends the defaults. A body that dropped a default term would be a
        // body the sequencer rebuilds a different statement from.
        assert_eq!(body["order_type"], "Limit");
        assert_eq!(body["time_in_force"], "GoodTillCancel");
        assert_eq!(body["post_only"], false);
    }

    #[test]
    fn fair_value_converges_on_a_static_mid() {
        let mut fair = FairValue::default();
        for _ in 0..60 {
            fair.observe("ETH-USDC", 100.0);
        }
        let estimate = fair.get("ETH-USDC").expect("warmed up");
        assert!((estimate - 100.0).abs() < 0.01, "estimate was {}", estimate);
    }

    #[test]
    fn fair_value_waits_for_warmup() {
        let mut fair = FairValue::default();
        fair.observe("ETH-USDC", 100.0);
        assert!(fair.get("ETH-USDC").is_none());
    }

    #[test]
    fn every_submitted_price_and_quantity_is_on_the_engine_grid() {
        // The exchange drops an order whose price or quantity it cannot hold,
        // and counts it in orders_ignored. That would leave the bot believing
        // it holds a position it never got. Replaying correctly matters here,
        // because the prices the bot sends depend on the positions it has
        // already taken.
        let cfg = BotConfig::default();
        let mut sim = SimFeed::new(7, 10);
        let mut bot = Bot::new(cfg.clone());
        let mut checked = 0;
        for _ in 0..20_000 {
            let msg = sim.next();
            bot.observe(&msg);
            for action in bot.decide() {
                let id = sim.take_id();
                let msg = match action {
                    Action::Submit {
                        symbol,
                        side,
                        price,
                        quantity,
                    } => {
                        let cents = price * 100.0;
                        let tenths = quantity * 10.0;
                        assert!(
                            (cents - cents.round()).abs() < 1e-6,
                            "price {} is off the cent grid",
                            price
                        );
                        assert!(
                            (tenths - tenths.round()).abs() < 1e-6,
                            "quantity {} is off the tenth grid",
                            quantity
                        );
                        checked += 1;
                        bot.note_sent(id, &symbol, side, quantity);
                        OrderMessage::New {
                            id,
                            timestamp: 0,
                            account: cfg.account,
                            symbol,
                            side,
                            price,
                            quantity,
                            nonce: None,
                            order_type: Default::default(),
                            time_in_force: Default::default(),
                            post_only: false,
                        }
                    }
                    Action::Cancel { target_id } => OrderMessage::Cancel {
                        id,
                        timestamp: 0,
                        account: cfg.account,
                        target_id,
                        nonce: None,
                    },
                };
                bot.observe(&msg);
            }
        }
        assert!(checked > 0, "the bot never sent an order");
        assert_eq!(
            bot.book.orders_ignored(),
            0,
            "the engine dropped an order the bot sent"
        );
    }

    /// The bot ends a simulated session with more than it started with.
    ///
    /// `backtest` is the `--backtest` command's own path, driven end to end.
    /// `SimFeed` opens its history with a `ListSymbol` for every symbol it
    /// trades, so the bot's replica, a real `MatcherState` whose registry is
    /// built from the log alone, has books to quote against. Without those
    /// messages every order is refused, the books stay empty, and this test
    /// reports a loss of exactly zero rather than an error.
    #[test]
    fn the_bot_makes_money_on_a_simulated_feed() {
        let result = backtest(1, 60_000, BotConfig::default());
        assert_eq!(
            result.orders_ignored, 0,
            "the replica refused an order the simulated history produced"
        );
        assert!(
            result.total_at_true_mid > 0.0,
            "bot lost money: {:?}",
            result
        );
    }

    #[test]
    fn exposure_keeps_the_position_inside_its_cap() {
        let cfg = BotConfig::default();
        let cap = cfg.caps["BTC-USDC"];
        let mut sim = SimFeed::new(3, 10);
        let mut bot = Bot::new(cfg.clone());
        let mut worst = 0.0f64;
        for _ in 0..40_000 {
            let msg = sim.next();
            bot.observe(&msg);
            for action in bot.decide() {
                let id = sim.take_id();
                let msg = match action {
                    Action::Submit {
                        symbol,
                        side,
                        price,
                        quantity,
                    } => {
                        bot.note_sent(id, &symbol, side, quantity);
                        OrderMessage::New {
                            id,
                            timestamp: 0,
                            account: cfg.account,
                            symbol,
                            side,
                            price,
                            quantity,
                            nonce: None,
                            order_type: Default::default(),
                            time_in_force: Default::default(),
                            post_only: false,
                        }
                    }
                    Action::Cancel { target_id } => OrderMessage::Cancel {
                        id,
                        timestamp: 0,
                        account: cfg.account,
                        target_id,
                        nonce: None,
                    },
                };
                bot.observe(&msg);
            }
            let (tenths, _, _) = bot.book.position_of(cfg.account, "BTC-USDC");
            let held = (tenths as f64 / 10.0).abs() * sim.mids["BTC-USDC"];
            worst = worst.max(held);
        }
        // A single fill can cross the line, so allow one maximum order on top.
        let slack = cfg.max_order_units * sim.mids["BTC-USDC"];
        assert!(
            worst <= cap + slack,
            "held {} against a cap of {}",
            worst,
            cap
        );
    }
}
