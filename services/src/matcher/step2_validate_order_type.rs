//! Step 2: validate the order type.
//!
//! Limit, market, post-only or fill-or-kill: is this a kind of order the
//! exchange runs, and can it do what its terms ask?
//!
//! | | |
//! |---|---|
//! | Owner | the Order types feature |
//! | May read | the order, the book |
//! | May change | nothing |
//!
//! # Why this step reads the book
//!
//! ENGINE.md section 4.0: **fill-or-kill is not step 6.** By the time step 6
//! is asked, step 5 has booked the fills, moved both positions and written the
//! trade rows. Nothing is left to kill. So the question "is the whole quantity
//! available" has to be asked before step 5 runs, and that means here.
//! Answering it means reading the book. Post-only asks a question of the same
//! shape, "would this order trade at once against something already resting?",
//! and one walk of the book answers both.
//!
//! The book arrives as `Option<&Book>` and not `&Book`. That is the whole
//! reason a refusal here is safe. `apply_new` creates a symbol's book entry
//! before step 3, because steps 3, 4 and 5 all need one. A symbol with nothing
//! resting has no entry at all, and `state_root` asserts that no empty book is
//! in the map. A step that could only take a real book would force `apply_new`
//! to create the entry first and delete it again on every refusal. `None`
//! means "no book", so this step refuses before any entry exists.
//!
//! # What it refuses
//!
//! The four rules of ENGINE.md 4.4, in this order. The order matters. Rule 1
//! names the term that is wrong on a market order, instead of blaming the
//! book.
//!
//! 1. a market order that is also post-only: the two ask for opposite things;
//! 2. a post-only order that is not good-till-cancel: it may not trade at
//!    once and it is not allowed to rest, so it could never do anything;
//! 3. a post-only order with something already resting at a price it would
//!    trade at: its limit price, or below it for a buy, or above it for a
//!    sell;
//! 4. a fill-or-kill order the book cannot fill whole.
//!
//! Nothing here refuses an order type this build does not know. Such an order
//! never reaches this step. `OrderType` and `TimeInForce` are enums, so a term
//! written after this build was compiled fails to deserialize in `domain.rs`
//! and is reported as cannot-interpret, ENGINE.md section 6. `domain.rs`'s
//! `an_unknown_order_term_is_not_read_as_the_default` is the test for that.
//!
//! Do not call another step from here. A check that needs an answer only
//! another step holds belongs in that step, or the answer belongs in this
//! step's parameters.

use super::Book;
use super::pipeline::{IncomingOrder, Rejected};
use crate::domain::{Side, TimeInForce};

/// What `/market` counts a market order that also asked to be post-only under.
pub(super) const POST_ONLY_MARKET: &str = "post_only_market";

/// What `/market` counts a post-only order that also refused to rest under.
pub(super) const POST_ONLY_NOT_RESTING: &str = "post_only_not_resting";

/// What `/market` counts a post-only order that would have traded at once
/// under.
pub(super) const POST_ONLY_WOULD_TAKE: &str = "post_only_would_take";

/// What `/market` counts a fill-or-kill order the book cannot fill whole under.
pub(super) const FILL_OR_KILL_UNAVAILABLE: &str = "fill_or_kill_unavailable";

/// Checks that the exchange runs this kind of order, and that the book can do
/// what the order's terms demand of it.
///
/// `book` is `None` for a symbol with nothing resting in it. An empty book
/// would give the same answer, and `apply_new` deliberately never builds one.
pub(super) fn validate(order: &IncomingOrder, book: Option<&Book>) -> Result<(), Rejected> {
    if order.post_only && order.is_market() {
        return Err(Rejected::because(
            POST_ONLY_MARKET,
            "a market order is priced to cross and cannot be post-only",
        ));
    }
    if order.post_only && !matches!(order.time_in_force, TimeInForce::GoodTillCancel) {
        return Err(Rejected::because(
            POST_ONLY_NOT_RESTING,
            format!(
                "post-only asks it to rest and {} asks it not to, so it could never do anything",
                named(order.time_in_force)
            ),
        ));
    }

    // One walk answers both remaining rules. Post-only refuses any crossing
    // quantity at all. Fill-or-kill refuses anything short of the whole order.
    let available = crossing_tenths(book, order.side, order.limit_cents);
    if order.post_only && available > 0 {
        return Err(Rejected::because(
            POST_ONLY_WOULD_TAKE,
            format!(
                "it is post-only and {} tenths are resting at or better than {} cents",
                available, order.limit_cents
            ),
        ));
    }
    if matches!(order.time_in_force, TimeInForce::FillOrKill) && available < order.qty_tenths {
        return Err(Rejected::because(
            FILL_OR_KILL_UNAVAILABLE,
            format!(
                "it is fill-or-kill and only {} of {} tenths are available at {} cents",
                available, order.qty_tenths, order.limit_cents
            ),
        ));
    }
    Ok(())
}

/// How the term reads in a refusal. These are GLOSSARY.md's words and not the
/// enum variant names, because the refusal ends up on an operator's terminal.
fn named(time_in_force: TimeInForce) -> &'static str {
    match time_in_force {
        TimeInForce::GoodTillCancel => "good-till-cancel",
        TimeInForce::ImmediateOrCancel => "immediate-or-cancel",
        TimeInForce::FillOrKill => "fill-or-kill",
    }
}

/// Total quantity, in tenths, resting at prices an order on `side` limited at
/// `limit_cents` would cross. `side` is the arriving order's side: a buy reads
/// the asks at or below the limit, a sell reads the bids at or above it.
///
/// The walk counts the sender's own resting orders. ENGINE.md 4.4 says so, and
/// the reason is that step 4 refuses nothing yet. An account can match itself
/// today, so its own quantity really is quantity this order would fill. When
/// step 4 starts refusing self-trades, a fill-or-kill order that counted its
/// own resting orders is refused by step 4 rather than partly filled. The
/// answer changes; the direction of the mistake does not.
///
/// `MatcherState::qty_through_cents` walks the same two maps for a bot sizing
/// an order. **It is not this function and must not replace it.** Its `side`
/// names the resting side, not the arriving side, so
/// `qty_through_cents(symbol, Buy, p, _)` reads the bids where
/// `crossing_tenths(book, Buy, p)` reads the asks. It also takes `exclude`,
/// which drops one account's own resting orders from the total, the opposite
/// of what the paragraph above requires here.
///
/// The walk is written out again for a second reason. `qty_through_cents` is a
/// method on `MatcherState`, and this step is handed a book. A step that
/// reached for the engine could read the cursor, the counters and the chain,
/// and the table above says it may read the order and the book.
fn crossing_tenths(book: Option<&Book>, side: Side, limit_cents: i64) -> i64 {
    let Some(book) = book else {
        return 0;
    };
    let levels = match side {
        Side::Buy => book.asks.range(..=limit_cents),
        Side::Sell => book.bids.range(limit_cents..),
    };
    levels
        .flat_map(|(_, level)| level.iter())
        .map(|resting| resting.qty_tenths)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::super::RestingOrder;
    use super::*;
    use crate::domain::{OrderType, Side};

    /// A book with one price level on one side. That is all any rule here
    /// needs, because the rules count quantity at crossing prices and nothing
    /// else.
    fn book_with(side: Side, price_cents: i64, qty_tenths: i64) -> Book {
        let mut book = Book::default();
        let levels = match side {
            Side::Buy => &mut book.bids,
            Side::Sell => &mut book.asks,
        };
        levels
            .entry(price_cents)
            .or_default()
            .push_back(RestingOrder {
                id: 1,
                account: 7,
                qty_tenths,
            });
        book
    }

    fn order(
        side: Side,
        limit_cents: i64,
        qty_tenths: i64,
        order_type: OrderType,
        time_in_force: TimeInForce,
        post_only: bool,
    ) -> IncomingOrder {
        IncomingOrder {
            id: 42,
            timestamp: 42_000,
            account: 9,
            symbol: "ETH-USDC".to_string(),
            side,
            limit_cents,
            qty_tenths,
            order_type,
            time_in_force,
            post_only,
        }
    }

    fn plain(side: Side, limit_cents: i64, qty_tenths: i64) -> IncomingOrder {
        order(
            side,
            limit_cents,
            qty_tenths,
            OrderType::Limit,
            TimeInForce::GoodTillCancel,
            false,
        )
    }

    /// The order every message in the log so far is: nothing about it is
    /// refused, with a book, without one, and whether or not it crosses.
    #[test]
    fn a_plain_limit_order_is_never_refused_here() {
        let crossing = book_with(Side::Sell, 9_900, 50);
        assert!(validate(&plain(Side::Buy, 10_000, 20), None).is_ok());
        assert!(validate(&plain(Side::Buy, 10_000, 20), Some(&crossing)).is_ok());
        assert!(validate(&plain(Side::Buy, 9_800, 20), Some(&crossing)).is_ok());
        assert!(validate(&plain(Side::Sell, 10_000, 20), Some(&crossing)).is_ok());
    }

    /// Post-only is refused when the order would trade at once, and passes
    /// when it would not. The book is the same book every time. Only the limit
    /// price moves.
    #[test]
    fn post_only_is_refused_only_when_it_would_take() {
        let asks = book_with(Side::Sell, 10_050, 50);
        let post_only = |limit| {
            order(
                Side::Buy,
                limit,
                20,
                OrderType::Limit,
                TimeInForce::GoodTillCancel,
                true,
            )
        };
        let refused = validate(&post_only(10_060), Some(&asks))
            .expect_err("10,060 crosses an ask resting at 10,050");
        assert_eq!(
            refused.to_string(),
            "it is post-only and 50 tenths are resting at or better than 10060 cents"
        );
        assert!(
            validate(&post_only(10_050), Some(&asks)).is_err(),
            "a buy at the ask's own price trades with it"
        );
        assert!(
            validate(&post_only(10_040), Some(&asks)).is_ok(),
            "a cent below the ask takes nothing and rests"
        );
        assert!(
            validate(&post_only(10_060), None).is_ok(),
            "there is nothing to take on a symbol with no book"
        );
    }

    /// The sell side too, because a sell crosses the bids, and the range that
    /// finds the bids is the other half of the walk.
    #[test]
    fn post_only_reads_the_side_it_would_take_from() {
        let bids = book_with(Side::Buy, 10_000, 30);
        let selling = |limit| {
            order(
                Side::Sell,
                limit,
                20,
                OrderType::Limit,
                TimeInForce::GoodTillCancel,
                true,
            )
        };
        assert!(validate(&selling(9_990), Some(&bids)).is_err());
        assert!(validate(&selling(10_000), Some(&bids)).is_err());
        assert!(validate(&selling(10_010), Some(&bids)).is_ok());
    }

    /// Fill-or-kill measures the whole quantity, not any quantity: one tenth
    /// short is a refusal.
    #[test]
    fn fill_or_kill_needs_the_whole_quantity() {
        let asks = book_with(Side::Sell, 10_000, 19);
        let fok = |qty| {
            order(
                Side::Buy,
                10_000,
                qty,
                OrderType::Limit,
                TimeInForce::FillOrKill,
                false,
            )
        };
        let refused = validate(&fok(20), Some(&asks)).expect_err("19 tenths is not 20");
        assert_eq!(
            refused.to_string(),
            "it is fill-or-kill and only 19 of 20 tenths are available at 10000 cents"
        );
        assert!(validate(&fok(19), Some(&asks)).is_ok(), "exactly enough");
        assert!(validate(&fok(1), Some(&asks)).is_ok());
        assert!(
            validate(&fok(1), None).is_err(),
            "an empty book fills nothing at all"
        );
    }

    /// Only the levels the order would really cross count toward the total.
    /// Quantity resting at a price the order will not pay is not quantity the
    /// order can have.
    #[test]
    fn fill_or_kill_counts_only_the_levels_it_would_cross() {
        let mut asks = book_with(Side::Sell, 10_000, 10);
        asks.asks
            .entry(10_100)
            .or_default()
            .push_back(RestingOrder {
                id: 2,
                account: 7,
                qty_tenths: 40,
            });
        let fok = |limit| {
            order(
                Side::Buy,
                limit,
                20,
                OrderType::Limit,
                TimeInForce::FillOrKill,
                false,
            )
        };
        assert!(
            validate(&fok(10_000), Some(&asks)).is_err(),
            "the 40 tenths at 10,100 are not for sale at 10,000"
        );
        assert!(
            validate(&fok(10_100), Some(&asks)).is_ok(),
            "10 and 40 is 50"
        );
    }

    /// A market order cannot be post-only, and it is told which of its two
    /// terms is the problem rather than being blamed on the book.
    #[test]
    fn a_market_order_cannot_be_post_only() {
        for tif in [
            TimeInForce::GoodTillCancel,
            TimeInForce::ImmediateOrCancel,
            TimeInForce::FillOrKill,
        ] {
            let refused = validate(
                &order(Side::Buy, 10_000, 20, OrderType::Market, tif, true),
                None,
            )
            .expect_err("a market order takes liquidity by definition");
            assert_eq!(
                refused.to_string(),
                "a market order is priced to cross and cannot be post-only"
            );
        }
    }

    /// Post-only with either of the two terms that refuse to rest is an order
    /// that could never do anything, whatever the book holds. The exchange
    /// refuses it rather than accepting it and dropping it without a word. A
    /// sender who gets no fill, no resting order and no reason cannot tell
    /// that from a lost message.
    #[test]
    fn post_only_that_may_not_rest_is_refused_whatever_the_book_holds() {
        let asks = book_with(Side::Sell, 10_050, 50);
        for (tif, words) in [
            (TimeInForce::ImmediateOrCancel, "immediate-or-cancel"),
            (TimeInForce::FillOrKill, "fill-or-kill"),
        ] {
            for book in [None, Some(&asks)] {
                let refused = validate(
                    &order(Side::Buy, 10_000, 20, OrderType::Limit, tif, true),
                    book,
                )
                .expect_err("post-only and not resting are opposite instructions");
                assert_eq!(
                    refused.to_string(),
                    format!(
                        "post-only asks it to rest and {} asks it not to, so it could never \
                         do anything",
                        words
                    )
                );
            }
        }
    }

    /// A market order that is not post-only gets exactly the fill-or-kill rule
    /// here and nothing else. Its price bound is step 3's work.
    #[test]
    fn a_market_order_is_checked_for_nothing_but_its_time_in_force() {
        let asks = book_with(Side::Sell, 10_000, 10);
        let market = |tif| order(Side::Buy, 999_999, 20, OrderType::Market, tif, false);
        assert!(validate(&market(TimeInForce::GoodTillCancel), Some(&asks)).is_ok());
        assert!(validate(&market(TimeInForce::ImmediateOrCancel), Some(&asks)).is_ok());
        assert!(
            validate(&market(TimeInForce::FillOrKill), Some(&asks)).is_err(),
            "10 tenths is not the 20 it asked for"
        );
    }
}
