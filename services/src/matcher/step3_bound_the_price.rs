//! Step 3: bound the price.
//!
//! The protection collar. The collar lowers the price a buy will pay, or
//! raises the price a sell will accept, so an order cannot fill far away from
//! where the market is.
//!
//! | | |
//! |---|---|
//! | Owner | the Order types feature |
//! | May read | the book, the reference price, the order |
//! | May change | the order's limit price, and nothing else |
//!
//! This step returns the bounded price and does not write it. `apply_new`
//! assigns it. That is why the order arrives here as `&IncomingOrder`. The one
//! field this step may change is the one field it returns, so the signature
//! states what the step may do and the compiler holds it to that.
//!
//! # What it bounds, and what it leaves alone
//!
//! Market orders only. ENGINE.md section 4.2: a market order is a limit order
//! priced so that it trades at once, and the price it carries is a bound the
//! *server* worked out and the client signed. The collar is a second bound,
//! the one the exchange applies for itself. It stops a signed bound that is
//! far too wide from filling somebody 90% away from the market. A bound gets
//! that wide in two ways: a browser that asked to accept a price up to 90%
//! worse, and a page somebody tampered with.
//!
//! A limit order's price is not touched. That price is the number its sender
//! named and signed. Tightening it would change where orders come to rest, so
//! the same messages would produce a different state root from the one every
//! run in the log has already committed to.
//!
//! # Where the reference price comes from
//!
//! `reference_cents` is the time-weighted mid of ENGINE.md 4.2.1. The mid is
//! the price halfway between the best bid and the best ask, and time-weighted
//! means each value counts for as long as the book held it.
//! `matcher/reference_price.rs` computes the number and hands it in. This step
//! cannot write it, and that is the point. The window is state that lives
//! across messages, and no step owns state across messages. Step 5 is what
//! moves the book the mid is read from, and step 5 is owned by nobody and
//! edited by nobody.
//!
//! `None` means the exchange has no reference price for this symbol. It has
//! not seen a bid and an ask at the same time for any measurable time. A
//! market order is then **refused**. Letting it through with no bound is the
//! one outcome section 4.2 exists to prevent: the operator, and not the
//! sender, choosing the price. A refusal costs the sender nothing at all.
//!
//! # Why `book` is here and unused
//!
//! The table says this step may read the book, and this step does not. That is
//! deliberate, and it is the whole security argument. An attacker can move the
//! book with one order, so a collar measured from the book would move with the
//! attacker's order. The collar is measured from a price nobody can move
//! without holding it against the market for a measurable part of the window.
//!
//! Do not call another step from here.

use super::Book;
use super::pipeline::{IncomingOrder, Rejected};
use crate::domain::{Side, TimeInForce};

/// How far from the reference price a market order may fill, in basis points.
/// One basis point is one hundredth of a percent, so 200 is two percent.
/// ENGINE.md 4.2.2.
///
/// Two percent is wide compared with the book. The sequencer's generator
/// quotes within half a percent of its mid and moves that mid by up to 0.2%
/// per message, so a market order fills against the book it can really see.
/// Two percent is narrow compared with the mistakes the collar exists to
/// catch: a signed bound with one digit too many, and a book with a hole in
/// it.
const COLLAR_BASIS_POINTS: i64 = 200;

/// What `/market` counts a market order with no reference price to bound it
/// under.
pub(super) const NO_REFERENCE_PRICE: &str = "no_reference_price";

/// What `/market` counts a fill-or-kill order whose price the collar moved
/// under.
pub(super) const FILL_OR_KILL_COLLARED: &str = "fill_or_kill_collared";

/// Returns the price the order may fill at, in cents: the price it arrived
/// with, or a tighter one.
///
/// `reference_cents` is the price the collar is measured from, when the
/// exchange has one.
pub(super) fn bound(
    order: &IncomingOrder,
    book: &Book,
    reference_cents: Option<i64>,
) -> Result<i64, Rejected> {
    let _ = book;
    if !order.is_market() {
        return Ok(order.limit_cents);
    }
    let Some(reference) = reference_cents else {
        return Err(Rejected::because(
            NO_REFERENCE_PRICE,
            format!(
                "it is a market order and {} has no reference price to bound it against",
                order.symbol
            ),
        ));
    };

    let bounded = collar(order.side, order.limit_cents, reference);

    // Step 2 decided fill-or-kill against the price the order arrived with.
    // The collar has moved that price, so fewer levels cross it and the whole
    // quantity may no longer be there. Step 5 runs next, and after step 5 a
    // fill-or-kill order can no longer be refused. Asking step 2's question
    // again here would put step 2's rule in two places. So the order is
    // refused instead, and that costs its sender nothing: a refusal is exactly
    // what a fill-or-kill order asks for when it cannot have everything.
    if matches!(order.time_in_force, TimeInForce::FillOrKill) && bounded != order.limit_cents {
        return Err(Rejected::because(
            FILL_OR_KILL_COLLARED,
            format!(
                "the collar moved a fill-or-kill order's price from {} to {} cents, and the whole \
                 quantity was only promised at {}",
                order.limit_cents, bounded, order.limit_cents
            ),
        ));
    }
    Ok(bounded)
}

/// The collar of ENGINE.md 4.2.2. It is the reference price plus or minus two
/// percent of the reference price, and it is never wider than the price the
/// order carries.
///
/// The band is at least one cent, so a symbol trading at a few cents still has
/// a collar an order can fill inside. The lowest a sell can be pushed is one
/// cent, because a price of zero is not a price this engine holds.
fn collar(side: Side, limit_cents: i64, reference_cents: i64) -> i64 {
    let band = (reference_cents * COLLAR_BASIS_POINTS / 10_000).max(1);
    match side {
        Side::Buy => limit_cents.min(reference_cents + band),
        Side::Sell => limit_cents.max((reference_cents - band).max(1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::OrderType;

    fn order(
        side: Side,
        limit_cents: i64,
        order_type: OrderType,
        time_in_force: TimeInForce,
    ) -> IncomingOrder {
        IncomingOrder {
            id: 42,
            timestamp: 42_000,
            account: 9,
            symbol: "ETH-USDC".to_string(),
            side,
            limit_cents,
            qty_tenths: 20,
            order_type,
            time_in_force,
            post_only: false,
        }
    }

    fn market(side: Side, limit_cents: i64) -> IncomingOrder {
        order(
            side,
            limit_cents,
            OrderType::Market,
            TimeInForce::GoodTillCancel,
        )
    }

    fn limit(side: Side, limit_cents: i64) -> IncomingOrder {
        order(
            side,
            limit_cents,
            OrderType::Limit,
            TimeInForce::GoodTillCancel,
        )
    }

    /// A limit order keeps the price its sender signed, whatever the reference
    /// price says. That is what leaves the state root over the log so far
    /// unchanged, because every message published up to now is a limit order.
    #[test]
    fn a_limit_order_keeps_the_price_its_sender_named() {
        let book = Book::default();
        for reference in [None, Some(10_000), Some(1)] {
            assert_eq!(
                bound(&limit(Side::Buy, 99_999), &book, reference).expect("never refused"),
                99_999
            );
            assert_eq!(
                bound(&limit(Side::Sell, 1), &book, reference).expect("never refused"),
                1
            );
        }
    }

    /// A market order is capped at two percent past the reference, on both
    /// sides, and a bound already inside the collar is left where it is.
    #[test]
    fn a_market_order_is_capped_two_percent_from_the_reference() {
        let book = Book::default();
        // 10,000 cents, so the band is 200 cents.
        assert_eq!(
            bound(&market(Side::Buy, 99_999), &book, Some(10_000)).expect("bounded"),
            10_200
        );
        assert_eq!(
            bound(&market(Side::Sell, 1), &book, Some(10_000)).expect("bounded"),
            9_800
        );
        assert_eq!(
            bound(&market(Side::Buy, 10_100), &book, Some(10_000)).expect("bounded"),
            10_100,
            "a bound already inside the collar is the sender's, and it stands"
        );
        assert_eq!(
            bound(&market(Side::Sell, 9_900), &book, Some(10_000)).expect("bounded"),
            9_900
        );
    }

    /// The collar only ever tightens. It never widens a bound the sender
    /// signed into a bound the sender did not sign.
    #[test]
    fn the_collar_never_loosens_a_signed_bound() {
        let book = Book::default();
        for reference in [1, 100, 10_000, 1_000_000] {
            let buy = bound(&market(Side::Buy, 5_000), &book, Some(reference)).expect("bounded");
            assert!(buy <= 5_000, "a buy at {} became {}", reference, buy);
            let sell = bound(&market(Side::Sell, 5_000), &book, Some(reference)).expect("bounded");
            assert!(sell >= 5_000, "a sell at {} became {}", reference, sell);
        }
    }

    /// Prices this engine can hold are whole cents above zero, and a collar on
    /// a symbol trading at a few cents must not produce anything else.
    #[test]
    fn the_collar_stays_on_prices_this_engine_can_hold() {
        let book = Book::default();
        assert_eq!(
            bound(&market(Side::Sell, 1), &book, Some(1)).expect("bounded"),
            1,
            "a one-cent reference cannot floor a sell below a cent"
        );
        assert_eq!(
            bound(&market(Side::Buy, 999), &book, Some(1)).expect("bounded"),
            2,
            "the band is at least one cent, so a buy may still reach the offer"
        );
    }

    /// No reference price is a refusal, and not a fill with no bound on it.
    /// The message names the symbol, because the symbol is what the sender has
    /// to wait on.
    #[test]
    fn a_market_order_with_no_reference_price_is_refused() {
        let book = Book::default();
        let refused =
            bound(&market(Side::Buy, 10_000), &book, None).expect_err("nothing to bound against");
        assert_eq!(
            refused.to_string(),
            "it is a market order and ETH-USDC has no reference price to bound it against"
        );
    }

    /// A fill-or-kill market order whose price the collar moved is refused:
    /// step 2 promised the whole quantity at the price the order carried, and
    /// this is no longer that price.
    #[test]
    fn a_fill_or_kill_market_order_the_collar_moves_is_refused() {
        let book = Book::default();
        let moved = order(
            Side::Buy,
            99_999,
            OrderType::Market,
            TimeInForce::FillOrKill,
        );
        let refused = bound(&moved, &book, Some(10_000)).expect_err("the promise was at 99,999");
        assert_eq!(
            refused.to_string(),
            "the collar moved a fill-or-kill order's price from 99999 to 10200 cents, and the \
             whole quantity was only promised at 99999"
        );

        // A fill-or-kill market order the collar leaves alone is not refused:
        // the price step 2 measured is still the price step 5 will match at.
        let untouched = order(
            Side::Buy,
            10_100,
            OrderType::Market,
            TimeInForce::FillOrKill,
        );
        assert_eq!(
            bound(&untouched, &book, Some(10_000)).expect("inside the collar"),
            10_100
        );
    }
}
