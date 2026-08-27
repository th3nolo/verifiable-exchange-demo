//! Step 4: self-trade check.
//!
//! Would this order trade against an order the same account already has
//! resting? ENGINE.md section 4.1 says cancel newest. The arriving order is
//! refused, and the resting order stays where it is.
//!
//! | | |
//! |---|---|
//! | Owner | the Self-trade feature |
//! | May read | the book, the order, the rule set |
//! | May change | nothing. It refuses the arriving order, and that is all |
//!
//! # Why cancel newest and not cancel oldest
//!
//! Cancel newest keeps time priority, which is the rule the whole book runs
//! on: the order that arrived first stays in front. Cancel oldest would take
//! the resting order off the book instead, and that hands an account a way to
//! remove its own resting order and reach the next account's order behind it.
//! The account sends an order that crosses its own best offer. Its own offer
//! comes off the book. The next account's offer is now the one the arriving
//! order fills against.
//!
//! Cancel newest also needs no quantity arithmetic. The answer is "there is
//! one" or "there is not", so `verify.rs` reproduces the answer exactly rather
//! than approximately.
//!
//! `book` is `&Book`, not `&mut Book`, so this step cannot take the resting
//! order off the book even if somebody wants it to. Cancel oldest is a compile
//! error here, not a review comment.
//!
//! # The rule is in the log, not in this binary
//!
//! The live log holds 1,008 self-trades in 28,104 trades. Turning this rule on
//! as plain code would make those messages replay differently. Every signed
//! claim and every anchor over them would then stop verifying. ENGINE.md
//! section 3: if changing a value makes the same messages produce a different
//! result, the value is data and not configuration. So the rule arrives as an
//! `EngineRule` message naming rule set 2, and a replay of the messages before
//! that message still self-trades.
//!
//! # Which levels this walks, and why they are step 5's levels
//!
//! A buy crosses the asks priced at or below its limit. A sell crosses the
//! bids priced at or above its limit. That is the same set of levels
//! `step5_match_against_book` fills. The walk is written out a second time
//! because a step never calls another step, ENGINE.md section 4.0.
//!
//! **Quantity does not come into it.** An order of the account's own at a
//! crossed price refuses the arriving order, whether or not the arriving order
//! would have reached that resting order after the queue in front of it. That
//! is deliberate, and it is what makes the two walks agree. This step does not
//! predict step 5's fills. It only asks which levels cross. So the two pieces
//! of code have to agree on a range of prices, and not on an outcome.
//!
//! The other decision this step owns: a self-trade on part of the quantity
//! refuses the whole arriving order, not only the part that would have
//! self-traded. The alternative was to reduce the arriving order by that part,
//! and reducing it needs quantity arithmetic in two implementations.

use std::collections::VecDeque;

use super::pipeline::{IncomingOrder, Rejected, RuleSet};
use super::{Book, RestingOrder};
use crate::domain::{OrderId, Side};

/// The rule set that turned this rule on. Rule sets are cumulative, so rule
/// set 2 and every rule set after it refuses a self-trade.
const FROM_RULE_SET: u32 = 2;

/// What `/market` counts a self-trade refusal under.
pub(super) const SELF_TRADE: &str = "self_trade";

/// Refuses the order if filling it would trade the account against itself.
pub(super) fn check(order: &IncomingOrder, book: &Book, rules: RuleSet) -> Result<(), Rejected> {
    if !rules.at_least(FROM_RULE_SET) {
        // Rule set 1: an account may match itself. That is what every message
        // published before the `EngineRule` message did.
        return Ok(());
    }
    // The dishonest build lets one account trade with itself.
    #[cfg(feature = "dishonest")]
    if crate::dishonest::telling(crate::dishonest::Lie::SelfTrade) {
        return Ok(());
    }
    let Some(resting) = own_order_in_the_way(order, book) else {
        return Ok(());
    };
    Err(Rejected::because(
        SELF_TRADE,
        format!(
            "it would trade against account {}'s own resting order {}",
            order.account, resting
        ),
    ))
}

/// The first resting order of this account that the arriving order would
/// reach. Best price first, and oldest first inside a price level, which is
/// the order step 5 fills in.
///
/// `None` means no level the arriving order crosses holds an order of this
/// account's own.
fn own_order_in_the_way(order: &IncomingOrder, book: &Book) -> Option<OrderId> {
    let crossing: Box<dyn Iterator<Item = &VecDeque<RestingOrder>>> = match order.side {
        // A buy crosses the asks priced at or below its limit, cheapest ask
        // first.
        Side::Buy => Box::new(
            book.asks
                .range(..=order.limit_cents)
                .map(|(_, level)| level),
        ),
        // A sell crosses the bids priced at or above its limit, dearest bid
        // first.
        Side::Sell => Box::new(
            book.bids
                .range(order.limit_cents..)
                .rev()
                .map(|(_, level)| level),
        ),
    };
    crossing
        .flat_map(|level| level.iter())
        .find(|resting| resting.account == order.account)
        .map(|resting| resting.id)
}
