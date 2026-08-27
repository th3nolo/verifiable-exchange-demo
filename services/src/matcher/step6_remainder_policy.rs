//! Step 6: remainder policy.
//!
//! The order has crossed everything it could. What happens to what is left?
//!
//! | | |
//! |---|---|
//! | Owner | the Order types feature |
//! | May read | the remainder, the order |
//! | May change | the book, through the answer it returns |
//!
//! # Why it returns an answer instead of resting the order itself
//!
//! ENGINE.md's table says this step may change the book. It does, but through
//! `apply_new`. `apply_new` puts the remainder in the book when the answer is
//! `Rest`. Keeping the resting code in the caller is what let this step stay
//! empty until now. Adding a rule here means adding a branch, and never
//! editing the code that puts an order in a book.
//!
//! # The two terms that do not decide anything here
//!
//! **Fill-or-kill** was settled in step 2. By the time this step is asked,
//! step 5 has booked the fills, moved both positions and written the trade
//! rows. Nothing is left to kill, ENGINE.md section 4.0. A fill-or-kill order
//! that reaches this step with something left over should be impossible: step
//! 2 refused it unless the whole quantity was available at its limit, step 3
//! refused it if the collar moved that limit, and nothing between step 2 and
//! step 5 can take quantity off the book. `Cancel` is the answer anyway,
//! because `Cancel` is the answer that cannot leave a fill-or-kill order
//! resting if that reasoning is ever wrong. An assertion was rejected here:
//! `debug_assert` is compiled out of the release binary, so an assertion would
//! hold in the tests and do nothing in the run that matters.
//!
//! **Post-only** was settled in step 2 as well. A post-only order that reaches
//! step 5 crossed nothing. Its remainder is therefore the whole order, and it
//! rests like any other good-till-cancel limit order.

use super::pipeline::IncomingOrder;
use crate::domain::TimeInForce;

/// What to do with the part of the order that did not fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Remainder {
    /// Put the remainder in the book as a resting order, where it waits for
    /// the other side to cross it. That is what a good-till-cancel limit order
    /// asks for, and every message published so far is one.
    Rest,
    /// Drop the remainder. Nothing rests, and the sender keeps only what
    /// already filled.
    Cancel,
}

/// Decides what happens to `remaining_tenths`. That number is always above
/// zero, because `apply_new` does not ask when the order filled completely.
pub(super) fn decide(order: &IncomingOrder, remaining_tenths: i64) -> Remainder {
    let _ = remaining_tenths;
    // The dishonest build drops an order the rules say should rest.
    #[cfg(feature = "dishonest")]
    if crate::dishonest::telling(crate::dishonest::Lie::DropResting) {
        return Remainder::Cancel;
    }
    // A market order never rests. ENGINE.md section 4.2: the engine has one
    // order type that rests, and it is the limit order. The price a market
    // order carries is a bound the server worked out so the order would trade
    // at once. It is not a price the sender offers to stand behind. Resting
    // the order would put that bound in the book as though the sender had
    // named it.
    if order.is_market() {
        return Remainder::Cancel;
    }
    match order.time_in_force {
        TimeInForce::GoodTillCancel => Remainder::Rest,
        TimeInForce::ImmediateOrCancel => Remainder::Cancel,
        TimeInForce::FillOrKill => Remainder::Cancel,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{OrderType, Side};

    fn order(order_type: OrderType, time_in_force: TimeInForce, post_only: bool) -> IncomingOrder {
        IncomingOrder {
            id: 42,
            timestamp: 42_000,
            account: 9,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            limit_cents: 10_000,
            qty_tenths: 20,
            order_type,
            time_in_force,
            post_only,
        }
    }

    /// All twelve combinations of the three terms an order can carry, counted
    /// and not sampled, with the answer each one gets. The table is written
    /// out here and not generated from the rule above, because a table
    /// generated from the rule agrees with a wrong rule.
    #[test]
    fn all_twelve_shapes_of_the_three_terms_get_the_answer_they_ask_for() {
        let shapes = [
            (
                OrderType::Limit,
                TimeInForce::GoodTillCancel,
                false,
                Remainder::Rest,
            ),
            (
                OrderType::Limit,
                TimeInForce::GoodTillCancel,
                true,
                Remainder::Rest,
            ),
            (
                OrderType::Limit,
                TimeInForce::ImmediateOrCancel,
                false,
                Remainder::Cancel,
            ),
            (
                OrderType::Limit,
                TimeInForce::ImmediateOrCancel,
                true,
                Remainder::Cancel,
            ),
            (
                OrderType::Limit,
                TimeInForce::FillOrKill,
                false,
                Remainder::Cancel,
            ),
            (
                OrderType::Limit,
                TimeInForce::FillOrKill,
                true,
                Remainder::Cancel,
            ),
            (
                OrderType::Market,
                TimeInForce::GoodTillCancel,
                false,
                Remainder::Cancel,
            ),
            (
                OrderType::Market,
                TimeInForce::GoodTillCancel,
                true,
                Remainder::Cancel,
            ),
            (
                OrderType::Market,
                TimeInForce::ImmediateOrCancel,
                false,
                Remainder::Cancel,
            ),
            (
                OrderType::Market,
                TimeInForce::ImmediateOrCancel,
                true,
                Remainder::Cancel,
            ),
            (
                OrderType::Market,
                TimeInForce::FillOrKill,
                false,
                Remainder::Cancel,
            ),
            (
                OrderType::Market,
                TimeInForce::FillOrKill,
                true,
                Remainder::Cancel,
            ),
        ];
        assert_eq!(
            shapes.len(),
            12,
            "two order types, three times in force, two post-only"
        );
        for (shape, (order_type, time_in_force, post_only, expected)) in
            shapes.into_iter().enumerate()
        {
            assert_eq!(
                decide(&order(order_type, time_in_force, post_only), 7),
                expected,
                "shape {} ({:?}, {:?}, post_only {}) got the wrong answer",
                shape,
                order_type,
                time_in_force,
                post_only
            );
        }
    }

    /// Two of the twelve rest, and both are the same order: a good-till-cancel
    /// limit order, post-only or not. That is the order every message in the
    /// log so far is. The count is asserted here so that a rule which started
    /// resting something else could not pass by agreeing with a table above
    /// that somebody had changed to match it.
    #[test]
    fn only_the_plain_good_till_cancel_limit_order_rests() {
        let mut rested = 0;
        for order_type in [OrderType::Limit, OrderType::Market] {
            for time_in_force in [
                TimeInForce::GoodTillCancel,
                TimeInForce::ImmediateOrCancel,
                TimeInForce::FillOrKill,
            ] {
                for post_only in [false, true] {
                    if decide(&order(order_type, time_in_force, post_only), 7) == Remainder::Rest {
                        rested += 1;
                        assert_eq!(order_type, OrderType::Limit);
                        assert_eq!(time_in_force, TimeInForce::GoodTillCancel);
                    }
                }
            }
        }
        assert_eq!(rested, 2, "good-till-cancel limit, post-only or not");
    }

    /// How much is left over changes nothing. What happens to a remainder is a
    /// question about the order's terms. A step that answered differently for
    /// one tenth than for a hundred tenths would be a step nobody could
    /// predict.
    #[test]
    fn the_size_of_the_remainder_does_not_change_the_answer() {
        let resting = order(OrderType::Limit, TimeInForce::GoodTillCancel, false);
        let cancelling = order(OrderType::Limit, TimeInForce::ImmediateOrCancel, false);
        for remaining in [1, 7, 1_000, i64::MAX] {
            assert_eq!(decide(&resting, remaining), Remainder::Rest);
            assert_eq!(decide(&cancelling, remaining), Remainder::Cancel);
        }
    }
}
