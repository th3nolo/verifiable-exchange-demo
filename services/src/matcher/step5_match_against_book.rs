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
//! # Atomic fill-or-kill execution
//!
//! FOK stages the complete price-time fill plan and every affected position
//! before this step changes anything. Staging copies only touched accounts,
//! not the exchange state. Other settlement rules can validate the same fill
//! slice before committing it. The checker keeps its own matching rules.
//!
//! # What it will not do
//!
//! This step does not check the symbol, the order type, the price bound, or
//! who owns the resting orders. Steps 1 to 4 do that, and they have already
//! run. This step does not decide what happens to the remainder either. It
//! returns how much is left, and step 6 decides.

use std::collections::{HashMap, VecDeque};
use tracing::info;

use super::pipeline::{IncomingOrder, Rejected};
use super::{
    Book, CandleCache, MatcherState, OrderRef, PlannedFill, Position, SymbolAgg, Trade,
    cents_to_f64, tenths_to_f64,
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
    pub(super) ledger: &'a mut crate::ledger::Ledger,
    /// The complete FOK ledger plan is already committed. Do not settle twice
    /// or introduce fallible monetary arithmetic while applying that plan.
    pub(super) ledger_plan_committed: bool,
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

/// A fully validated FOK. Construction has no execution effects. Positions
/// after each fill are retained so commit does no fallible accounting work.
/// Memory is O(fills + affected accounts) during staging; no whole-state clone.
pub(super) struct FokPlan {
    fills: Vec<PlannedFill>,
    positions_after: Vec<(Position, Position)>,
}

impl FokPlan {
    /// The settlement validation boundary. Validate cumulative ledger effects
    /// on these fills before consuming the plan with `execute_fok`.
    #[allow(dead_code)] // Used by the spot-ledger integration.
    pub(super) fn fills(&self) -> &[PlannedFill] {
        &self.fills
    }
}

fn newest_first() -> bool {
    #[cfg(feature = "dishonest")]
    {
        crate::dishonest::telling(crate::dishonest::Lie::Priority)
    }
    #[cfg(not(feature = "dishonest"))]
    {
        false
    }
}

fn crosses(side: Side, price_cents: i64, limit_cents: i64) -> bool {
    let crosses = match side {
        Side::Buy => price_cents <= limit_cents,
        Side::Sell => price_cents >= limit_cents,
    };
    #[cfg(feature = "dishonest")]
    let crosses = crosses || crate::dishonest::telling(crate::dishonest::Lie::OverLimit);
    crosses
}

/// Plans the same price-time walk as execution, stopping at the requested
/// quantity. This reads the book without changing orders or any accounting.
pub(super) fn plan_fills(order: &IncomingOrder, book: &Book) -> Vec<PlannedFill> {
    let levels = match order.side {
        Side::Buy => &book.asks,
        Side::Sell => &book.bids,
    };
    let mut fills = Vec::new();
    let mut remaining = order.qty_tenths;
    let mut add_level = |price, level: &VecDeque<super::RestingOrder>| {
        if !crosses(order.side, price, order.limit_cents) || remaining == 0 {
            return false;
        }
        let mut add_maker = |maker: &super::RestingOrder| {
            if remaining == 0 {
                return false;
            }
            let qty_tenths = remaining.min(maker.qty_tenths);
            fills.push(PlannedFill {
                maker_order: maker.id,
                maker_account: maker.account,
                price_cents: price,
                qty_tenths,
            });
            remaining -= qty_tenths;
            remaining > 0
        };
        if newest_first() {
            for maker in level.iter().rev() {
                if !add_maker(maker) {
                    break;
                }
            }
        } else {
            for maker in level {
                if !add_maker(maker) {
                    break;
                }
            }
        }
        remaining > 0
    };
    match order.side {
        Side::Buy => {
            for (&price, level) in levels {
                if !add_level(price, level) {
                    break;
                }
            }
        }
        Side::Sell => {
            for (&price, level) in levels.iter().rev() {
                if !add_level(price, level) {
                    break;
                }
            }
        }
    }
    fills
}

/// Validates every cumulative position transition before any execution effect.
/// The synchronous caller must keep book and positions unchanged until commit.
pub(super) fn stage_fok(
    order: &IncomingOrder,
    book: &Book,
    positions: &HashMap<(AccountId, String), Position>,
    trades_total: u64,
) -> Result<FokPlan, Rejected> {
    let fills = plan_fills(order, book);
    // This sum is bounded by the validated incoming order's quantity.
    let filled: i64 = fills.iter().map(|fill| fill.qty_tenths).sum();
    if filled != order.qty_tenths {
        return Err(Rejected::because(
            super::step2_validate_order_type::FILL_OR_KILL_UNAVAILABLE,
            "the effective price cannot fill the entire fill-or-kill order",
        ));
    }
    let overflow = || {
        Rejected::because(
            super::POSITION_OVERFLOW,
            "the complete fill-or-kill plan would overflow accounting or trade IDs",
        )
    };
    trades_total
        .checked_add(u64::try_from(fills.len()).map_err(|_| overflow())?)
        .ok_or_else(overflow)?;
    let mut staged = HashMap::<AccountId, Position>::new();
    let mut positions_after = Vec::with_capacity(fills.len());
    let maker_side = match order.side {
        Side::Buy => Side::Sell,
        Side::Sell => Side::Buy,
    };
    for fill in &fills {
        let before = |account| {
            staged.get(&account).copied().unwrap_or_else(|| {
                positions
                    .get(&(account, order.symbol.clone()))
                    .copied()
                    .unwrap_or_default()
            })
        };
        let maker_next = before(fill.maker_account)
            .after_fill(maker_side, fill.qty_tenths, fill.price_cents)
            .ok_or_else(overflow)?;
        // Maker first, then taker, just as execution and restoration book a
        // self-match. Repeated accounts read the result of preceding fills.
        let taker_before = if fill.maker_account == order.account {
            maker_next
        } else {
            before(order.account)
        };
        let taker_next = taker_before
            .after_fill(order.side, fill.qty_tenths, fill.price_cents)
            .ok_or_else(overflow)?;
        staged.insert(fill.maker_account, maker_next);
        staged.insert(order.account, taker_next);
        positions_after.push((maker_next, taker_next));
    }
    Ok(FokPlan {
        fills,
        positions_after,
    })
}

/// Consumes the exact validated fills; no second matching walk. The caller
/// must leave book/positions unchanged and stage settlement before this call.
pub(super) fn execute_fok(
    order: &IncomingOrder,
    plan: FokPlan,
    into: &mut BookAndTrades<'_>,
) -> Matched {
    for (fill, (maker_next, taker_next)) in plan.fills.into_iter().zip(plan.positions_after) {
        // stage_fok proved capacity for every ID, before the first effect.
        let trade_id = into
            .trades_total
            .checked_add(1)
            .expect("staged trade ID fits");
        commit_fill(order, fill, maker_next, taker_next, trade_id, into);
    }
    Matched::Crossed {
        remaining_tenths: 0,
    }
}

/// How the match ended for a non-FOK order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Matched {
    Crossed {
        remaining_tenths: i64,
    },
    /// Earlier fills stand. Only non-FOK orders can stop during execution;
    /// FOK arithmetic is checked completely before execute_fok is called.
    Overflowed {
        remaining_tenths: i64,
    },
}

/// Reads the next fill without changing the book. This is used only by the
/// streaming non-FOK path; FOK commit addresses its already planned makers.
fn next_fill(order: &IncomingOrder, book: &Book, remaining: i64) -> Option<PlannedFill> {
    let (price, level) = match order.side {
        Side::Buy => book.asks.first_key_value(),
        Side::Sell => book.bids.last_key_value(),
    }?;
    if !crosses(order.side, *price, order.limit_cents) {
        return None;
    }
    let maker = if newest_first() {
        level.back()
    } else {
        level.front()
    }?;
    Some(PlannedFill {
        maker_order: maker.id,
        maker_account: maker.account,
        price_cents: *price,
        qty_tenths: remaining.min(maker.qty_tenths),
    })
}

/// Non-FOK still validates both positions and trade-ID capacity per fill.
/// It allocates no fill plan. Book lookup per fill costs O(log price levels).
pub(super) fn execute(order: &IncomingOrder, into: &mut BookAndTrades<'_>) -> Matched {
    let mut remaining = order.qty_tenths;
    let maker_side = match order.side {
        Side::Buy => Side::Sell,
        Side::Sell => Side::Buy,
    };
    while remaining > 0 {
        let Some(fill) = next_fill(order, into.book, remaining) else {
            break;
        };
        let maker_key = (fill.maker_account, order.symbol.clone());
        let taker_key = (order.account, order.symbol.clone());
        let maker_before = into.positions.get(&maker_key).copied().unwrap_or_default();
        let positions = maker_before
            .after_fill(maker_side, fill.qty_tenths, fill.price_cents)
            .and_then(|maker_next| {
                let taker_before = if fill.maker_account == order.account {
                    maker_next
                } else {
                    into.positions.get(&taker_key).copied().unwrap_or_default()
                };
                taker_before
                    .after_fill(order.side, fill.qty_tenths, fill.price_cents)
                    .map(|taker_next| (maker_next, taker_next))
            });
        let Some(((maker_next, taker_next), trade_id)) =
            positions.zip(into.trades_total.checked_add(1))
        else {
            return Matched::Overflowed {
                remaining_tenths: remaining,
            };
        };
        into.ledger
            .settle_fill(
                fill.maker_order,
                order.id,
                fill.price_cents,
                fill.qty_tenths,
            )
            .expect("complete funded command preflight accepted each actual fill");
        commit_fill(order, fill, maker_next, taker_next, trade_id, into);
        remaining -= fill.qty_tenths;
    }
    Matched::Crossed {
        remaining_tenths: remaining,
    }
}

/// Commits a fill whose arithmetic has already passed validation. Both
/// execution paths share this bookkeeping, so all projections/durable deltas
/// describe the same confirmed fills. No settlement validation belongs here.
fn commit_fill(
    order: &IncomingOrder,
    fill: PlannedFill,
    maker_next: Position,
    taker_next: Position,
    trade_id: u64,
    into: &mut BookAndTrades<'_>,
) {
    debug_assert!(
        order.time_in_force != crate::domain::TimeInForce::FillOrKill || into.ledger_plan_committed,
        "FOK settlement must be staged before the first execution effect"
    );
    let levels = match order.side {
        Side::Buy => &mut into.book.asks,
        Side::Sell => &mut into.book.bids,
    };
    let level = levels
        .get_mut(&fill.price_cents)
        .expect("validated maker level exists");
    let newest_first = newest_first();
    let maker = if newest_first {
        level.back_mut()
    } else {
        level.front_mut()
    }
    .expect("validated maker exists");
    assert_eq!(
        (maker.id, maker.account),
        (fill.maker_order, fill.maker_account),
        "the book must remain unchanged between staging and commit"
    );
    let maker_left = maker
        .qty_tenths
        .checked_sub(fill.qty_tenths)
        .filter(|left| *left >= 0)
        .expect("validated fill fits the maker");
    maker.qty_tenths = maker_left;
    let maker_done = maker_left == 0;
    if maker_done {
        if newest_first {
            level.pop_back();
        } else {
            level.pop_front();
        }
        into.open_orders.remove(&fill.maker_order);
    }
    if level.is_empty() {
        levels.remove(&fill.price_cents);
    }

    let trade = Trade {
        trade_id,
        symbol: order.symbol.clone(),
        price: cents_to_f64(fill.price_cents),
        quantity: tenths_to_f64(fill.qty_tenths),
        maker_order: fill.maker_order,
        maker_account: fill.maker_account,
        taker_order: order.id,
        taker_account: order.account,
        taker_side: order.side,
        timestamp: order.timestamp,
    };
    info!("Trade: {:?}", trade);
    MatcherState::record(
        into.pending,
        Change::Traded(TradeRow {
            trade_id,
            timestamp: order.timestamp,
            symbol: order.symbol.clone(),
            price_cents: fill.price_cents,
            qty_tenths: fill.qty_tenths,
            maker_order: fill.maker_order,
            maker_account: fill.maker_account,
            taker_order: order.id,
            taker_account: order.account,
            taker_side: order.side,
        }),
    );
    MatcherState::record(
        into.pending,
        if maker_done {
            Change::OrderClosed {
                order_id: fill.maker_order,
            }
        } else {
            Change::OrderReduced {
                order_id: fill.maker_order,
                qty_tenths: maker_left,
            }
        },
    );

    if fill.maker_account != order.account {
        into.positions
            .insert((fill.maker_account, order.symbol.clone()), maker_next);
    }
    into.positions
        .insert((order.account, order.symbol.clone()), taker_next);
    let agg = into.aggregates.entry(order.symbol.clone()).or_default();
    agg.last_trade_cents = fill.price_cents;
    // These bounded display totals are not settlement amounts.
    agg.volume_tenths = agg.volume_tenths.saturating_add(fill.qty_tenths);
    agg.trade_count = agg.trade_count.saturating_add(1);
    MatcherState::push_trade(
        into.trades,
        into.trades_total,
        into.candle_cache,
        trade,
        fill.price_cents,
        fill.qty_tenths,
    );
}
