//! The order terms, worked out again from the sequencer's own messages.
//!
//! ENGINE.md section 5: this module must be able to disagree with the engine.
//! So it shares no matching code with the engine, and it states every rule it
//! checks in its own words. The two numbers below are the engine's numbers,
//! written out here and not imported. A checker that imported them would agree
//! with the engine about a number the engine had got wrong.
//!
//! ENGINE.md 4.2.1 and 4.2.2 are the text those numbers come from.
//!
//! # Why two checks and not one
//!
//! `refused` reports an order the rules allowed no fill at all. There are
//! three: a post-only order that would trade at once, a fill-or-kill order the
//! book cannot fill whole, and a market order with no reference price.
//! `collared` reports a market order that filled outside the bound the
//! exchange applies for itself. The first check says the fill should not
//! exist. The second says the fill exists at the wrong price.

use std::collections::HashMap;

use crate::domain::{OrderId, OrderType, Side, TimeInForce};

use super::{FeedOrder, LoggedTrade, ReplayBook};
use crate::reporting::Check;

/// How far back the reference price is averaged, in milliseconds.
const REFERENCE_WINDOW_MS: u64 = 30_000;

/// How far past the reference price a market order may fill, in basis points.
/// One basis point is one hundredth of a percent, so 200 is two percent.
const COLLAR_BASIS_POINTS: i64 = 200;

/// What the exchange's own rules say happens to one published order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum OrderFate {
    /// No fill and nothing resting. A trade naming this order as its taker is
    /// a fill the exchange's rules forbid.
    Refused(String),
    /// The order may trade, at no worse than `limit_cents`. For a market order
    /// that number is the collar, and not the bound its sender signed. What
    /// does not fill either rests or is dropped.
    Allowed { limit_cents: i64, rests: bool },
}

/// What the exchange's rules do with one order, given the book it arrived at
/// and the reference price standing at that moment.
///
/// Written from ENGINE.md 4.4's table, in the order that table gives, so the
/// reason this function reports is the reason the engine would print.
fn fate(order: &FeedOrder, book: &ReplayBook, reference_cents: Option<i64>) -> OrderFate {
    let market = matches!(order.order_type, OrderType::Market);
    if order.post_only {
        if market {
            return OrderFate::Refused("a market order cannot be post-only".to_string());
        }
        if !matches!(order.time_in_force, TimeInForce::GoodTillCancel) {
            return OrderFate::Refused("post-only cannot also refuse to rest".to_string());
        }
    }

    let reachable = book.crossing_tenths(&order.symbol, order.side, order.price_cents);
    if order.post_only && reachable > 0 {
        return OrderFate::Refused(format!(
            "post-only, with {} tenths resting at or better than {}",
            reachable, order.price_cents
        ));
    }
    let all_or_nothing = matches!(order.time_in_force, TimeInForce::FillOrKill);
    if all_or_nothing && reachable < order.qty_tenths {
        return OrderFate::Refused(format!(
            "fill-or-kill, with only {} of {} tenths available at {}",
            reachable, order.qty_tenths, order.price_cents
        ));
    }

    if !market {
        return OrderFate::Allowed {
            limit_cents: order.price_cents,
            // Only a good-till-cancel limit order rests. A post-only order
            // reaches here only when it crossed nothing, so it rests like any
            // other one.
            rests: matches!(order.time_in_force, TimeInForce::GoodTillCancel),
        };
    }

    let Some(reference) = reference_cents else {
        return OrderFate::Refused(
            "a market order with no reference price to bound it".to_string(),
        );
    };
    let collared = collar(order.side, order.price_cents, reference);
    if all_or_nothing && collared != order.price_cents {
        return OrderFate::Refused(format!(
            "fill-or-kill, with the collar moving its price from {} to {}",
            order.price_cents, collared
        ));
    }
    OrderFate::Allowed {
        limit_cents: collared,
        // ENGINE.md 4.2: the engine has one order type that rests, and it is
        // the limit order. A market order's price is a bound the server worked
        // out, and not a price its sender offered.
        rests: false,
    }
}

/// The collar of ENGINE.md 4.2.2. It only ever tightens a bound.
fn collar(side: Side, signed_limit_cents: i64, reference_cents: i64) -> i64 {
    let band = std::cmp::max(1, reference_cents * COLLAR_BASIS_POINTS / 10_000);
    match side {
        Side::Buy => std::cmp::min(signed_limit_cents, reference_cents + band),
        Side::Sell => std::cmp::max(signed_limit_cents, std::cmp::max(1, reference_cents - band)),
    }
}

/// The mid price each replayed book showed, and when it showed it.
///
/// ENGINE.md 4.2.1 defines the reference price as an average of the mid over
/// the last 30 seconds, weighted by how long each mid held. This map keeps
/// what that average needs and nothing else: one entry per millisecond of the
/// window, per symbol. So it does not grow with the length of the history,
/// which is the same rule the rest of this file walks the sequencer under.
///
/// This map walks every sample on every question, and it stays that way. The
/// exchange keeps running sums instead, because it answers this question on
/// every new order, and a walk costs more as the sequencer runs faster. This
/// module answers the question once per replayed order, off a log that is
/// already on disk, so the walk costs it nothing worth saving. Two readings of
/// one rule that share no code can disagree with each other, and that is the
/// whole job here.
#[derive(Default)]
pub(crate) struct MidHistory {
    held: HashMap<String, std::collections::VecDeque<(u64, Option<i64>)>>,
}

impl MidHistory {
    /// Records the mid a book showed after a message finished with it. `None`
    /// is a book with a side missing. That book shows no mid at all, and it
    /// ends the price before it.
    pub(crate) fn showed(&mut self, symbol: &str, at_ms: u64, mid_cents: Option<i64>) {
        let held = self.held.entry(symbol.to_string()).or_default();
        // A timestamp that does not go up is read as the last one that did. A
        // message cannot wind this history back.
        let at = std::cmp::max(at_ms, held.back().map_or(at_ms, |(when, _)| *when));
        match held.back_mut() {
            Some((when, mid)) if *when == at => *mid = mid_cents,
            _ => held.push_back((at, mid_cents)),
        }
        while held.len() > 1 && held[1].0 <= at.saturating_sub(REFERENCE_WINDOW_MS) {
            held.pop_front();
        }
    }

    /// The reference price at `at_ms`, or `None` when the window holds no mid
    /// that has held for any time at all. ENGINE.md 4.2.1: `None` is not zero
    /// and not a guess. It is the answer that refuses a market order.
    pub(crate) fn reference_cents(&self, symbol: &str, at_ms: u64) -> Option<i64> {
        let held = self.held.get(symbol)?;
        let opened = at_ms.saturating_sub(REFERENCE_WINDOW_MS);
        let mut total: i128 = 0;
        let mut milliseconds: i128 = 0;
        for (index, (when, mid)) in held.iter().enumerate() {
            let ends = held.get(index + 1).map_or(at_ms, |(next, _)| *next);
            let (from, to) = (std::cmp::max(*when, opened), std::cmp::min(ends, at_ms));
            match mid {
                Some(mid) if to > from => {
                    total += *mid as i128 * (to - from) as i128;
                    milliseconds += (to - from) as i128;
                }
                _ => {}
            }
        }
        if milliseconds == 0 {
            return None;
        }
        Some((total / milliseconds) as i64)
    }
}

impl ReplayBook {
    /// How much is resting at prices an order on `side` limited at
    /// `limit_cents` would reach. `side` is the arriving order's side. A buy
    /// reaches the offers at or below its limit, and a sell reaches the bids at
    /// or above its limit.
    ///
    /// Post-only and fill-or-kill both ask about this number. Post-only refuses
    /// any of it. Fill-or-kill refuses anything less than all of it. The total
    /// counts the sender's own resting orders, because ENGINE.md 4.4 says the
    /// engine counts them: an account can still match itself.
    fn crossing_tenths(&self, symbol: &str, side: Side, limit_cents: i64) -> i64 {
        let Some(levels) = self.levels(
            symbol,
            match side {
                Side::Buy => Side::Sell,
                Side::Sell => Side::Buy,
            },
        ) else {
            return 0;
        };
        levels
            .iter()
            .filter(|(price, _)| match side {
                Side::Buy => **price <= limit_cents,
                Side::Sell => **price >= limit_cents,
            })
            .flat_map(|(_, level)| level.values())
            .sum()
    }

    /// The mid price this book shows. It is halfway between the best bid and
    /// the best offer, rounded down. It is `None` whenever either side is
    /// empty.
    pub(super) fn mid_cents(&self, symbol: &str) -> Option<i64> {
        let best_bid = *self.levels(symbol, Side::Buy)?.keys().next_back()?;
        let best_ask = *self.levels(symbol, Side::Sell)?.keys().next()?;
        Some((best_bid + best_ask) / 2)
    }
}

/// What this rule counts during the replay.
pub(super) struct Checks {
    /// The refusal that comes from the order's own terms, and not from whose
    /// order it crosses. There are three: post-only, fill-or-kill, and the
    /// market order with no reference price.
    pub(super) refused: Check,
    /// The collar a market order had to fill inside.
    pub(super) collared: Check,
}

impl Checks {
    pub(super) fn new() -> Self {
        Checks {
            refused: Check::new("no fill for an order the rules refuse"),
            collared: Check::new("every market order filled inside its collar"),
        }
    }
}

/// Reads one published order against the terms it carries, and reports what
/// the rules do with it.
///
/// The answer goes back to the caller, because two more places need it:
/// whether the order rests, and the price a market order's fills are held to.
///
/// `fills` is the rows the trade record gives this one arriving order. Only
/// how many there are is read here.
pub(super) fn observe(
    checks: &mut Checks,
    id: OrderId,
    taker: &FeedOrder,
    book: &ReplayBook,
    reference_cents: Option<i64>,
    fills: &[LoggedTrade],
) -> OrderFate {
    let answer = fate(taker, book, reference_cents);
    if let OrderFate::Refused(why) = &answer {
        checks.refused.checked += 1;
        if !fills.is_empty() {
            checks.refused.fail(format!(
                "order {} is {}, and the trade log gives it {} fill(s)",
                id,
                why,
                fills.len()
            ));
        }
    }
    answer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AccountId, OrderMessage};
    use crate::verify::LoggedTrade;
    use crate::verify::testkit::*;

    // Every expectation below is a number written by hand from ENGINE.md 4.2
    // and 4.4. Nothing here asks the engine what it did.

    const REFUSED: &str = "no fill for an order the rules refuse";
    const COLLAR: &str = "every market order filled inside its collar";

    fn plain_at(
        id: OrderId,
        at_ms: u64,
        account: AccountId,
        side: Side,
        price: f64,
        quantity: f64,
    ) -> OrderMessage {
        termed(
            id,
            at_ms,
            account,
            side,
            price,
            quantity,
            OrderType::Limit,
            TimeInForce::GoodTillCancel,
            false,
        )
    }

    fn cancel_at(id: OrderId, at_ms: u64, account: AccountId, target_id: OrderId) -> OrderMessage {
        OrderMessage::Cancel {
            id,
            timestamp: at_ms,
            account,
            target_id,
            nonce: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn traded(
        trade_id: u64,
        maker: OrderId,
        maker_account: AccountId,
        taker: OrderId,
        taker_account: AccountId,
        taker_side: Side,
        price_cents: i64,
        qty_tenths: i64,
    ) -> LoggedTrade {
        LoggedTrade {
            trade_id,
            symbol: "ETH-USDC".to_string(),
            price_cents,
            qty_tenths,
            maker_order: maker,
            maker_account,
            taker_order: taker,
            taker_account,
            taker_side,
        }
    }

    /// A post-only order that would have traded at once may not fill. So a
    /// trade log that says it did is the engine breaking its own rule.
    #[tokio::test]
    async fn a_fill_for_a_post_only_order_that_would_have_taken_is_reported() {
        let messages = vec![
            list_eth(1),
            plain_at(2, 1_000, 5, Side::Sell, 100.0, 5.0),
            termed(
                3,
                2_000,
                7,
                Side::Buy,
                100.0,
                5.0,
                OrderType::Limit,
                TimeInForce::GoodTillCancel,
                true,
            ),
        ];
        let trades = vec![traded(1, 2, 5, 3, 7, Side::Buy, 10_000, 50)];
        let check = replay_check(&messages, &trades, REFUSED).await;
        assert_eq!(check.checked, 1, "one order was refused and looked at");
        assert_eq!(check.failures.len(), 1, "{:?}", check.failures);
        assert!(
            check.failures[0].contains("post-only, with 50 tenths resting"),
            "{}",
            check.failures[0]
        );
    }

    /// The same order, priced where it trades with nothing, rests instead. The
    /// fill that later takes it out of the book is an ordinary fill against an
    /// ordinary maker.
    #[tokio::test]
    async fn a_post_only_order_that_took_nothing_rests_and_is_filled_normally() {
        let messages = vec![
            list_eth(1),
            plain_at(2, 1_000, 5, Side::Sell, 100.0, 5.0),
            termed(
                3,
                2_000,
                7,
                Side::Buy,
                99.0,
                5.0,
                OrderType::Limit,
                TimeInForce::GoodTillCancel,
                true,
            ),
            plain_at(4, 3_000, 11, Side::Sell, 99.0, 5.0),
        ];
        let trades = vec![traded(1, 3, 7, 4, 11, Side::Sell, 9_900, 50)];
        for check in replay(&messages, &trades).await.checks() {
            assert!(
                check.failures.is_empty(),
                "{} failed: {:?}",
                check.name,
                check.failures
            );
        }
    }

    /// A fill-or-kill order the book could not fill whole must produce no fill
    /// at all, and not the part fill this log claims. ENGINE.md 4.0: the reason
    /// the question is decided before the match is that a part fill cannot be
    /// undone.
    #[tokio::test]
    async fn a_partial_fill_of_a_fill_or_kill_order_is_reported() {
        let messages = vec![
            list_eth(1),
            plain_at(2, 1_000, 5, Side::Sell, 100.0, 2.0),
            termed(
                3,
                2_000,
                7,
                Side::Buy,
                100.0,
                5.0,
                OrderType::Limit,
                TimeInForce::FillOrKill,
                false,
            ),
        ];
        let trades = vec![traded(1, 2, 5, 3, 7, Side::Buy, 10_000, 20)];
        let check = replay_check(&messages, &trades, REFUSED).await;
        assert_eq!(check.failures.len(), 1, "{:?}", check.failures);
        assert!(
            check.failures[0].contains("only 20 of 50 tenths available"),
            "{}",
            check.failures[0]
        );
    }

    /// A fill-or-kill order the book can fill whole is an ordinary order, and
    /// nothing here says anything about it.
    #[tokio::test]
    async fn a_fill_or_kill_order_the_book_could_fill_whole_passes() {
        let messages = vec![
            list_eth(1),
            plain_at(2, 1_000, 5, Side::Sell, 100.0, 5.0),
            termed(
                3,
                2_000,
                7,
                Side::Buy,
                100.0,
                5.0,
                OrderType::Limit,
                TimeInForce::FillOrKill,
                false,
            ),
        ];
        let trades = vec![traded(1, 2, 5, 3, 7, Side::Buy, 10_000, 50)];
        for check in replay(&messages, &trades).await.checks() {
            assert!(
                check.failures.is_empty(),
                "{} failed: {:?}",
                check.name,
                check.failures
            );
        }
    }

    /// An immediate-or-cancel order rests nothing. So a later fill against what
    /// would have been its remainder is a fill against an order that was not in
    /// the book. This is the check that catches an engine which rested a
    /// remainder it was told to drop.
    #[tokio::test]
    async fn a_fill_against_an_immediate_or_cancel_remainder_is_reported() {
        let messages = vec![
            list_eth(1),
            plain_at(2, 1_000, 5, Side::Sell, 100.0, 2.0),
            termed(
                3,
                2_000,
                7,
                Side::Buy,
                100.0,
                5.0,
                OrderType::Limit,
                TimeInForce::ImmediateOrCancel,
                false,
            ),
            plain_at(4, 3_000, 11, Side::Sell, 100.0, 3.0),
        ];
        let trades = vec![
            traded(1, 2, 5, 3, 7, Side::Buy, 10_000, 20),
            traded(2, 3, 7, 4, 11, Side::Sell, 10_000, 30),
        ];
        let check = priority(&messages, &trades).await;
        assert_eq!(check.failures.len(), 1, "{:?}", check.failures);
        assert!(
            check.failures[0].contains("order 3 was not resting"),
            "{}",
            check.failures[0]
        );
    }

    /// A market order filled outside its collar, where the collar is worked out
    /// from the mid prices this replay watched the book show.
    ///
    /// The book showed a mid of 10,000 for eighteen seconds. Everything after
    /// that happens in one millisecond, so the offer at 150.00 has moved the
    /// mid for no time at all and the reference price is still 10,000. Two
    /// percent of 10,000 is 200, so nothing worse than 10,200 was allowed.
    #[tokio::test]
    async fn a_market_order_filled_outside_its_collar_is_reported() {
        let messages = vec![
            list_eth(1),
            plain_at(2, 1_000, 5, Side::Sell, 105.0, 5.0),
            plain_at(3, 2_000, 7, Side::Buy, 95.0, 5.0),
            cancel_at(4, 20_000, 5, 2),
            plain_at(5, 20_000, 5, Side::Sell, 150.0, 5.0),
            termed(
                6,
                20_000,
                7,
                Side::Buy,
                200.0,
                5.0,
                OrderType::Market,
                TimeInForce::GoodTillCancel,
                false,
            ),
        ];
        let trades = vec![traded(1, 5, 5, 6, 7, Side::Buy, 15_000, 50)];
        let check = replay_check(&messages, &trades, COLLAR).await;
        assert_eq!(check.checked, 1);
        assert_eq!(check.failures.len(), 1, "{:?}", check.failures);
        assert!(
            check.failures[0].contains("reference price of 10000 allowed no worse than 10200"),
            "{}",
            check.failures[0]
        );
    }

    /// The same history with the offer inside the collar. The order carries the
    /// same wide signed bound of 200.00, so the check that compares a fill with
    /// what its sender signed says nothing here. The collar check is the only
    /// check that would have caught the fill above.
    #[tokio::test]
    async fn a_market_order_filled_inside_its_collar_passes() {
        let messages = vec![
            list_eth(1),
            plain_at(2, 1_000, 5, Side::Sell, 105.0, 5.0),
            plain_at(3, 2_000, 7, Side::Buy, 95.0, 5.0),
            cancel_at(4, 20_000, 5, 2),
            plain_at(5, 20_000, 5, Side::Sell, 102.0, 5.0),
            termed(
                6,
                20_000,
                7,
                Side::Buy,
                200.0,
                5.0,
                OrderType::Market,
                TimeInForce::GoodTillCancel,
                false,
            ),
        ];
        let trades = vec![traded(1, 5, 5, 6, 7, Side::Buy, 10_200, 50)];
        for check in replay(&messages, &trades).await.checks() {
            assert!(
                check.failures.is_empty(),
                "{} failed: {:?}",
                check.name,
                check.failures
            );
        }
    }

    /// A market order on a book whose mid has held for no time at all has no
    /// reference price, and an order with no reference price may not fill.
    #[tokio::test]
    async fn a_fill_for_a_market_order_with_no_reference_price_is_reported() {
        let messages = vec![
            plain_at(1, 1_000, 5, Side::Sell, 100.0, 5.0),
            plain_at(2, 1_000, 7, Side::Buy, 95.0, 5.0),
            termed(
                3,
                1_000,
                7,
                Side::Buy,
                200.0,
                5.0,
                OrderType::Market,
                TimeInForce::GoodTillCancel,
                false,
            ),
        ];
        let trades = vec![traded(1, 1, 5, 3, 7, Side::Buy, 10_000, 50)];
        let check = replay_check(&messages, &trades, REFUSED).await;
        assert_eq!(check.failures.len(), 1, "{:?}", check.failures);
        assert!(
            check.failures[0].contains("no reference price"),
            "{}",
            check.failures[0]
        );
    }

    /// The reference price this checker computes, on its own numbers.
    ///
    /// ENGINE.md 4.2.1 is what these expectations come from, worked out by
    /// hand. A mid that held for no time carries no weight. A mid that held for
    /// part of the window carries that part of the average.
    #[test]
    fn the_reference_price_weighs_a_mid_by_how_long_it_held() {
        let mut mids = MidHistory::default();
        mids.showed("ETH-USDC", 0, Some(10_000));
        assert_eq!(
            mids.reference_cents("ETH-USDC", 0),
            None,
            "nothing has held for any time yet"
        );
        assert_eq!(mids.reference_cents("ETH-USDC", 1_000), Some(10_000));

        // A mid nine times higher, and the order that would be priced against
        // it in the same millisecond.
        mids.showed("ETH-USDC", 20_000, Some(90_000));
        assert_eq!(
            mids.reference_cents("ETH-USDC", 20_000),
            Some(10_000),
            "the 90,000 has held for nothing"
        );
        // Ten seconds later it has held for a third of the window.
        assert_eq!(
            mids.reference_cents("ETH-USDC", 30_000),
            Some((10_000 * 20_000 + 90_000 * 10_000) / 30_000)
        );
        // A book with a side missing shows no mid. What the book showed before
        // stops counting at that moment, instead of staying in the average.
        mids.showed("ETH-USDC", 30_000, None);
        assert_eq!(
            mids.reference_cents("ETH-USDC", 40_000),
            Some((10_000 * 10_000 + 90_000 * 10_000) / 20_000),
            "the window has moved on and nothing has been showing since 30,000"
        );
        assert_eq!(
            mids.reference_cents("MERKLE-USDC", 40_000),
            None,
            "another symbol's book is not this one's reference price"
        );
    }

    /// The collar of ENGINE.md 4.2.2, on its own numbers. It tightens a bound
    /// and never widens one, on both sides.
    #[test]
    fn the_collar_only_ever_tightens_a_signed_bound() {
        assert_eq!(collar(Side::Buy, 20_000, 10_000), 10_200);
        assert_eq!(collar(Side::Buy, 10_100, 10_000), 10_100);
        assert_eq!(collar(Side::Sell, 1, 10_000), 9_800);
        assert_eq!(collar(Side::Sell, 9_900, 10_000), 9_900);
        // A price of zero is not a price this engine holds, whatever the
        // reference is.
        assert_eq!(collar(Side::Sell, 1, 1), 1);
        // And the band is never zero, so a cheap symbol still has room to fill.
        assert_eq!(collar(Side::Buy, 999, 1), 2);
    }
}
