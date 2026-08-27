//! Step 5: match against the book.
//!
//! Price-time priority. The best-priced level fills first, and inside a level
//! the order that arrived first fills first. The trade happens at the resting
//! order's price. So when the arriving order was ready to pay more than that
//! price, the difference stays with the arriving order.
//!
//! | | |
//! |---|---|
//! | Owner | **nobody** |
//! | May read | the book |
//! | May change | the book, and the record of what trading it produced |
//!
//! # This file is the fixed part
//!
//! No feature owns this file and no feature agent edits it. ENGINE.md section
//! 4 says so, and PLAN.md step 4 repeats it. Four features are built in
//! parallel, and this is the one file none of them touch. A new rule is a new
//! step, not an edit to this loop.
//!
//! That is not tidiness. This loop is the only code that moves quantity
//! between two accounts. `verify.rs` runs the same messages again with its own
//! separate copy of these rules, so the two can disagree and catch each other.
//! A bug added here is a bug in one of the two implementations, and the other
//! implementation is what finds it. A bug four agents add here at once is a
//! bug nobody is looking for.
//!
//! # What it will not do
//!
//! This step does not check the symbol, the order type, the price bound, or
//! who owns the resting orders. Steps 1 to 4 do that, and they have already
//! run. This step does not decide what happens to the remainder either. It
//! returns how much is left, and step 6 decides.

use std::collections::{HashMap, VecDeque};
use tracing::info;

use super::pipeline::IncomingOrder;
use super::{
    Book, CandleCache, MatcherState, OrderRef, Position, SymbolAgg, Trade, cents_to_f64,
    tenths_to_f64,
};
use crate::domain::{AccountId, OrderId, Side};
use crate::store::{Change, TradeRow};

/// The parts of the exchange one match writes to.
///
/// This type is the "may change" column of the table above, written as a type.
/// It holds the book of the one symbol being matched, and the four records a
/// fill moves: the index that finds a resting order by id, the positions of
/// the two accounts, the symbol's running totals, the trade log, and the
/// bounded candle projection derived from that log.
///
/// They arrive as separate references and not as `&mut MatcherState`. That is
/// the difference between "this step may change the book and the trades" and
/// "this step may change anything the exchange holds". The cursor, the
/// counters, the chain and the recent-message window are not here, so a match
/// cannot reach them.
pub(super) struct BookAndTrades<'a> {
    /// The book of the symbol being matched. Its levels are keyed by price in
    /// cents; each level is a queue, oldest first.
    pub(super) book: &'a mut Book,
    /// Where an open order lives, so a cancel can find it without scanning the
    /// book. A resting order that fills completely comes out of this map.
    pub(super) open_orders: &'a mut HashMap<OrderId, OrderRef>,
    /// What each account holds in each symbol. Both sides of every fill land
    /// here.
    pub(super) positions: &'a mut HashMap<(AccountId, String), Position>,
    /// Last trade price, traded volume and trade count, per symbol.
    pub(super) aggregates: &'a mut HashMap<String, SymbolAgg>,
    /// The window of newest trades the API serves.
    pub(super) trades: &'a mut VecDeque<Trade>,
    /// How many trades this run has executed. `trade_id` counts up from this
    /// number.
    pub(super) trades_total: &'a mut u64,
    /// The browser's bounded OHLCV view. It is updated beside the recent trade
    /// window so one order that makes more than 10,000 fills cannot lose rows
    /// from the chart.
    pub(super) candle_cache: &'a mut CandleCache,
    /// Changes on their way to the state database, in the order they happened.
    pub(super) pending: &'a mut Option<Vec<Change>>,
}

/// How the match ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Matched {
    /// The order crossed every level it could reach at its limit price.
    /// `remaining_tenths` is what is left for step 6 to decide about, and zero
    /// means the order filled completely.
    Crossed { remaining_tenths: i64 },
    /// The match stopped early. The next fill could not be booked, because one
    /// of the two accounts' running totals would no longer fit in a 64-bit
    /// whole number. The fills already made stand, because they really
    /// happened. The order does not rest, and step 6 is not asked.
    Overflowed { remaining_tenths: i64 },
}

/// Fills `order` against the opposite side of `into.book`, best price first
/// and oldest order first inside a price level, while the levels cross the
/// order's limit price.
pub(super) fn execute(order: &IncomingOrder, into: &mut BookAndTrades<'_>) -> Matched {
    let id = order.id;
    let timestamp = order.timestamp;
    let account = order.account;
    let symbol = order.symbol.as_str();
    let side = order.side;
    let limit_cents = order.limit_cents;
    let mut remaining = order.qty_tenths;

    // Set when a fill cannot be booked, because the fill would overflow a
    // position. The order stops matching at that point. It never rests, and
    // the fills it already made stand, because they really happened.
    let mut overflowed = false;

    while remaining > 0 {
        // The best level on the other side: the lowest ask for a buy, the
        // highest bid for a sell.
        let best = match side {
            Side::Buy => into.book.asks.keys().next().copied(),
            Side::Sell => into.book.bids.keys().next_back().copied(),
        };
        let Some(level_price) = best else { break };
        let crosses = match side {
            Side::Buy => level_price <= limit_cents,
            Side::Sell => level_price >= limit_cents,
        };
        // The dishonest build fills past the taker's limit here.
        #[cfg(feature = "dishonest")]
        let crosses = crosses || crate::dishonest::telling(crate::dishonest::Lie::OverLimit);
        if !crosses {
            break;
        }

        let level = match side {
            Side::Buy => into.book.asks.get_mut(&level_price),
            Side::Sell => into.book.bids.get_mut(&level_price),
        }
        .expect("best level key was just read from this map");

        while remaining > 0 {
            // The dishonest build takes the newest order at this level
            // rather than the oldest, so the fill skips the queue.
            #[cfg(feature = "dishonest")]
            let newest_first = crate::dishonest::telling(crate::dishonest::Lie::Priority);
            #[cfg(not(feature = "dishonest"))]
            let newest_first = false;
            let maker = if newest_first {
                level.back_mut()
            } else {
                level.front_mut()
            };
            let Some(maker) = maker else {
                break;
            };
            let fill = remaining.min(maker.qty_tenths);
            let maker_id = maker.id;
            let maker_account = maker.account;

            // Both sides of the fill are booked at the trade price. The maker
            // takes the side opposite the arriving order.
            let maker_side = match side {
                Side::Buy => Side::Sell,
                Side::Sell => Side::Buy,
            };
            // Work out both positions before anything moves. A fill that one
            // of the two positions cannot hold is refused whole. Booking the
            // trade and then failing to book the position would leave the two
            // records of one fill disagreeing forever.
            let maker_key = (maker_account, symbol.to_string());
            let taker_key = (account, symbol.to_string());
            let self_match = maker_account == account;
            let maker_before = into.positions.get(&maker_key).copied().unwrap_or_default();
            let taker_next = maker_before
                .after_fill(maker_side, fill, level_price)
                .and_then(|maker_next| {
                    // An account matching itself takes both sides onto one
                    // position. The maker's side is added first.
                    let taker_before = if self_match {
                        maker_next
                    } else {
                        into.positions.get(&taker_key).copied().unwrap_or_default()
                    };
                    taker_before
                        .after_fill(side, fill, level_price)
                        .map(|taker_next| (maker_next, taker_next))
                });
            let Some((maker_next, taker_next)) = taker_next else {
                overflowed = true;
                break;
            };

            maker.qty_tenths -= fill;
            remaining -= fill;
            let maker_done = maker.qty_tenths == 0;
            let maker_left = maker.qty_tenths;

            let trade_id = *into.trades_total + 1;
            let trade = Trade {
                trade_id,
                symbol: symbol.to_string(),
                price: cents_to_f64(level_price),
                quantity: tenths_to_f64(fill),
                maker_order: maker_id,
                maker_account,
                taker_order: id,
                taker_account: account,
                taker_side: side,
                timestamp,
            };
            info!("Trade: {:?}", trade);
            // The record written to disk carries the whole numbers the match
            // was computed from, and not the `f64` the trade shows the API.
            MatcherState::record(
                into.pending,
                Change::Traded(TradeRow {
                    trade_id,
                    timestamp,
                    symbol: symbol.to_string(),
                    price_cents: level_price,
                    qty_tenths: fill,
                    maker_order: maker_id,
                    maker_account,
                    taker_order: id,
                    taker_account: account,
                    taker_side: side,
                }),
            );
            MatcherState::record(
                into.pending,
                if maker_done {
                    Change::OrderClosed { order_id: maker_id }
                } else {
                    Change::OrderReduced {
                        order_id: maker_id,
                        qty_tenths: maker_left,
                    }
                },
            );

            if !self_match {
                into.positions.insert(maker_key, maker_next);
            }
            into.positions.insert(taker_key, taker_next);
            let agg = into.aggregates.entry(symbol.to_string()).or_default();
            agg.last_trade_cents = level_price;
            agg.volume_tenths = agg.volume_tenths.saturating_add(fill);
            agg.trade_count = agg.trade_count.saturating_add(1);
            MatcherState::push_trade(
                into.trades,
                into.trades_total,
                into.candle_cache,
                trade,
                level_price,
                fill,
            );

            if maker_done {
                if newest_first {
                    level.pop_back();
                } else {
                    level.pop_front();
                }
                into.open_orders.remove(&maker_id);
            }
        }

        if level.is_empty() {
            match side {
                Side::Buy => into.book.asks.remove(&level_price),
                Side::Sell => into.book.bids.remove(&level_price),
            };
        }
        if overflowed {
            break;
        }
    }

    if overflowed {
        Matched::Overflowed {
            remaining_tenths: remaining,
        }
    } else {
        Matched::Crossed {
            remaining_tenths: remaining,
        }
    }
}
