//! Self-trade prevention, worked out again from the sequencer's own messages.
//!
//! ENGINE.md section 4.1, cancel newest. An arriving order that would trade
//! against an order the same account already has resting is refused whole. The
//! resting order keeps its place in line.
//!
//! `matcher.rs` states the same rule in `step4_self_trade_check`. This module
//! shares no line of code with that one. ENGINE.md section 5 says every
//! matching rule is written twice, so the two copies can disagree and catch
//! each other.
//!
//! The rule arrives in the log and not in this binary. A history that has not
//! yet named a rule set is running under rule set 1, and rule set 1 lets an
//! account match itself.
//!
//! # Why two checks and not one
//!
//! `paired` reads the trade row's own two account fields and needs no book at
//! all. `refused` needs the replayed book. It catches the arriving order that
//! crossed both a stranger's order and one of its own. That trade joins two
//! different accounts, and the rule still forbids it. Keeping the two checks
//! apart means `paired` still reports when the book replay is wrong.

use crate::domain::Side;

use super::{FeedOrder, LoggedTrade, ReplayBook, Rules};
use crate::reporting::Check;

/// The rule set the log must have reached before the checker looks for a
/// self-trade at all. Below rule set 2, a self-trade is a legal fill. Rule set
/// numbers only go up, so every later rule set refuses one too.
const FROM_RULE_SET: u32 = 2;

impl Rules {
    /// ENGINE.md section 4.1, cancel newest. The arriving order is refused
    /// whole when the same account already has an order resting that the
    /// arriving order would trade with. The resting order stays. True from
    /// rule set 2 on.
    fn refuses_self_trades(self) -> bool {
        self.version >= FROM_RULE_SET
    }
}

impl ReplayBook {
    /// Whether an arriving order would trade against an order the same account
    /// already has resting.
    ///
    /// The rule as ENGINE.md section 4.1 states it, and not as the engine
    /// writes it. An arriving order is refused when the book holds an order of
    /// the same account at a price the arriving order crosses. A buy crosses
    /// an ask priced at or below its limit. A sell crosses a bid priced at or
    /// above its limit. Quantity does not come into it, and neither does the
    /// queue. An order of the account's own at a crossed price refuses the
    /// arriving order, whether or not the arriving order would have got that
    /// far.
    ///
    /// This function walks the account's own resting orders and compares each
    /// price against the limit. The engine goes the other way round. It walks
    /// the book's crossing levels, with `BTreeMap::range` bounds, and compares
    /// each order's account. Two different walks, and "crosses" written two
    /// ways. A `..` where a `..=` belonged is a mistake one of them can make
    /// without the other making it. ENGINE.md section 5 is why they are not
    /// the same code.
    pub(super) fn would_self_trade(&self, arriving: &FeedOrder) -> bool {
        self.resting.values().any(|resting| {
            resting.account == arriving.account
                && resting.symbol == arriving.symbol
                && resting.side != arriving.side
                && match arriving.side {
                    Side::Buy => resting.price_cents <= arriving.price_cents,
                    Side::Sell => resting.price_cents >= arriving.price_cents,
                }
        })
    }
}

/// What this rule counts during the replay.
pub(super) struct Checks {
    /// Once the log has turned self-trade prevention on, every trade must join
    /// two different accounts. This check reads that straight off the trade
    /// row.
    pub(super) paired: Check,
    /// No trade may name an arriving order the self-trade rule refused. This
    /// check needs the replayed book.
    pub(super) refused: Check,
}

impl Checks {
    pub(super) fn new() -> Self {
        Checks {
            paired: Check::new("no trade joins an account to itself"),
            refused: Check::new("no fill against the taker's own resting order"),
        }
    }
}

/// Reads one published order and the fills the trade log gives it.
///
/// `true` means the rule refused the order. The caller then stops with that
/// order. A refused order makes no trade and does not rest, so every fill the
/// log claims for it is a fill the rules forbid. The book must not go on
/// holding the order either: an order left resting here would make the honest
/// fills that follow look wrong.
///
/// The engine asks this question fourth, after the order's own terms and the
/// collar. The checker asks it first. That is one more place the two differ on
/// purpose, ENGINE.md section 5. The answers still agree, because both
/// refusals produce the same book: no fill, and nothing resting. Only the
/// reason printed for an order that breaks both rules can differ, and that
/// order is reported either way.
///
/// `fills` is the rows the trade record gives this one arriving order, and
/// nothing else. The whole trade record used to be passed in beside a list of
/// positions into it, which needed the whole record in memory.
pub(super) fn observe(
    checks: &mut Checks,
    taker: &FeedOrder,
    book: &ReplayBook,
    rules: Rules,
    fills: &[LoggedTrade],
) -> bool {
    if rules.refuses_self_trades() && book.would_self_trade(taker) {
        for trade in fills {
            checks.refused.checked += 1;
            checks.refused.fail(format!(
                "trade {}: order {} crossed account {}'s own resting order, which \
                 rule set {} refuses whole, so it could not have filled order {}",
                trade.trade_id, trade.taker_order, taker.account, rules.version, trade.maker_order
            ));
        }
        return true;
    }
    if rules.refuses_self_trades() {
        checks.refused.checked += 1;
        // The trade row's own two accounts. No book, no orders index, and
        // nothing this walk rebuilt. If the log turned the rule on and a row
        // still joins an account to itself, that row is wrong whatever the
        // rest of this file worked out.
        for trade in fills {
            checks.paired.checked += 1;
            if trade.maker_account == trade.taker_account {
                checks.paired.fail(format!(
                    "trade {} joins account {} to itself, and rule set {} refuses \
                     the arriving order instead",
                    trade.trade_id, trade.taker_account, rules.version
                ));
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::domain::Side;
    use crate::verify::testkit::*;

    /// The check that needs no book. Once the log has turned the rule on, a
    /// trade row joining an account to itself is wrong, however the rest of
    /// this file replays the history.
    #[tokio::test]
    async fn a_trade_that_joins_an_account_to_itself_is_reported() {
        let messages = vec![
            list_eth(1),
            engine_rule(2, 2),
            new_order(3, 7, Side::Sell, 100.0, 5.0),
            new_order(4, 7, Side::Buy, 100.0, 5.0),
        ];
        let trades = vec![fill_between(1, (3, 7), (4, 7), 10_000, 50, Side::Buy)];
        let replayed = replay(&messages, &trades).await;
        assert_eq!(
            replayed.self_trade.paired.checked, 0,
            "the order never reached a fill"
        );
        assert_eq!(
            replayed.self_trade.refused.failures.len(),
            1,
            "{:?}",
            replayed.self_trade.refused.failures
        );
        assert!(
            replayed.self_trade.refused.failures[0].contains("rule set 2 refuses"),
            "{}",
            replayed.self_trade.refused.failures[0]
        );

        // The same history without the rule message holds an honest
        // self-trade, and nothing here reports it. That is what makes the rule
        // replayable. The answer depends on the log and not on this binary.
        let before = vec![
            list_eth(1),
            new_order(2, 7, Side::Sell, 100.0, 5.0),
            new_order(3, 7, Side::Buy, 100.0, 5.0),
        ];
        let trades = vec![fill_between(1, (2, 7), (3, 7), 10_000, 50, Side::Buy)];
        let replayed = replay(&before, &trades).await;
        assert!(replayed.self_trade.paired.failures.is_empty());
        assert!(replayed.self_trade.refused.failures.is_empty());
        assert_eq!(
            replayed.self_trade.paired.checked, 0,
            "rule set 1 has nothing to check here"
        );
    }

    /// Cancel newest refuses the whole arriving order, and not only the part
    /// that would have self-traded. So an order that crosses a stranger's
    /// order *and* one of its own may not fill against the stranger either.
    /// That trade joins two different accounts, so only the book replay can
    /// catch it.
    ///
    /// This is the case the trade-row check above cannot see, and it is why
    /// there are two checks and not one.
    #[tokio::test]
    async fn a_fill_against_a_stranger_by_an_order_that_also_self_traded_is_reported() {
        let messages = vec![
            list_eth(1),
            engine_rule(2, 2),
            // Account 5 offers at 100, and account 7 offers at 101.
            new_order(3, 5, Side::Sell, 100.0, 5.0),
            new_order(4, 7, Side::Sell, 101.0, 5.0),
            // Account 7 buys at 101. That crosses both offers, so the whole
            // order is refused.
            new_order(5, 7, Side::Buy, 101.0, 5.0),
        ];
        let trades = vec![fill_between(1, (3, 5), (5, 7), 10_000, 50, Side::Buy)];
        let replayed = replay(&messages, &trades).await;
        assert!(
            replayed.self_trade.paired.failures.is_empty(),
            "the two accounts really are different, so this check says nothing"
        );
        assert_eq!(
            replayed.self_trade.refused.failures.len(),
            1,
            "{:?}",
            replayed.self_trade.refused.failures
        );
        assert!(
            replayed.self_trade.refused.failures[0].contains("order 5"),
            "{}",
            replayed.self_trade.refused.failures[0]
        );
    }

    /// A refused order does not rest, so the fills after it are checked
    /// against a book that never held it. A replay that let the refused order
    /// rest would report the honest fill that follows as a fill out of turn.
    #[tokio::test]
    async fn an_order_the_rule_refused_is_not_left_resting_in_the_replayed_book() {
        let messages = vec![
            list_eth(1),
            engine_rule(2, 2),
            // Account 7's bid at 100.
            new_order(3, 7, Side::Buy, 100.0, 5.0),
            // Account 7 sells into its own bid and is refused. A replay that
            // let this order rest would put it at the front of the asks at
            // 100.
            new_order(4, 7, Side::Sell, 100.0, 5.0),
            // A stranger offers at 100, behind nothing.
            new_order(5, 5, Side::Sell, 100.0, 5.0),
            // And a stranger buys. Order 5 is next in line only if order 4
            // never rested.
            new_order(6, 8, Side::Buy, 100.0, 5.0),
        ];
        let trades = vec![fill_between(1, (5, 5), (6, 8), 10_000, 50, Side::Buy)];
        let replayed = replay(&messages, &trades).await;
        assert!(
            replayed.priority.failures.is_empty(),
            "the refused order was left in the book: {:?}",
            replayed.priority.failures
        );
        assert!(replayed.self_trade.refused.failures.is_empty());
        assert!(replayed.self_trade.paired.failures.is_empty());
    }

    /// The rule applies from the message that names it and not before, in one
    /// history walked once. Same accounts, same prices, two answers.
    #[tokio::test]
    async fn the_rule_starts_where_the_message_is_and_not_before() {
        let messages = vec![
            list_eth(1),
            // Before: account 7 crosses itself and the fill is honest.
            new_order(2, 7, Side::Buy, 100.0, 5.0),
            new_order(3, 7, Side::Sell, 100.0, 5.0),
            engine_rule(4, 2),
            // After: the same pair of orders again, and now the fill is not
            // honest.
            new_order(5, 7, Side::Buy, 100.0, 5.0),
            new_order(6, 7, Side::Sell, 100.0, 5.0),
        ];
        let trades = vec![
            fill_between(1, (2, 7), (3, 7), 10_000, 50, Side::Sell),
            fill_between(2, (5, 7), (6, 7), 10_000, 50, Side::Sell),
        ];
        let replayed = replay(&messages, &trades).await;
        assert_eq!(
            replayed.self_trade.refused.failures.len(),
            1,
            "one of the two self-trades is forbidden and the other is not: {:?}",
            replayed.self_trade.refused.failures
        );
        assert!(
            replayed.self_trade.refused.failures[0].contains("trade 2"),
            "the second one is the forbidden one: {}",
            replayed.self_trade.refused.failures[0]
        );
    }

    /// The other direction of disagreement. The engine refuses a self-trade,
    /// and this file replays the same refusal. An order the engine really did
    /// refuse leaves both books the same, and the fills after it check out.
    /// Without this test, a checker that reported everything would pass the
    /// tests above.
    #[tokio::test]
    async fn a_history_the_engine_matched_under_the_rule_reconciles_clean() {
        let messages = vec![
            list_eth(1),
            engine_rule(2, 2),
            new_order(3, 7, Side::Buy, 100.0, 5.0),
            new_order(4, 9, Side::Buy, 100.0, 3.0),
            // Refused: account 7 into its own bid. No trade row for it.
            new_order(5, 7, Side::Sell, 100.0, 4.0),
            // A stranger sells 4.0 and takes order 3's front of the queue.
            new_order(6, 8, Side::Sell, 100.0, 4.0),
        ];
        let trades = vec![fill_between(1, (3, 7), (6, 8), 10_000, 40, Side::Sell)];
        let replayed = replay(&messages, &trades).await;
        assert!(
            replayed.priority.failures.is_empty(),
            "{:?}",
            replayed.priority.failures
        );
        assert!(
            replayed.self_trade.paired.failures.is_empty(),
            "{:?}",
            replayed.self_trade.paired.failures
        );
        assert!(
            replayed.self_trade.refused.failures.is_empty(),
            "{:?}",
            replayed.self_trade.refused.failures
        );
        assert_eq!(replayed.priority.checked, 1);
    }

    /// An order of the account's own at a price the arriving order does not
    /// cross is not a self-trade. A checker stricter than the engine reports
    /// honest fills, and that is as much a failure as a checker that is
    /// looser.
    #[tokio::test]
    async fn an_own_order_the_arrival_does_not_cross_is_not_reported() {
        let messages = vec![
            list_eth(1),
            engine_rule(2, 2),
            // Account 7 offers at 101, out of reach of a bid of 100.
            new_order(3, 7, Side::Sell, 101.0, 5.0),
            // A stranger offers at 100.
            new_order(4, 5, Side::Sell, 100.0, 5.0),
            // Account 7 buys at 100. That crosses the stranger's offer and not
            // its own.
            new_order(5, 7, Side::Buy, 100.0, 5.0),
        ];
        let trades = vec![fill_between(1, (4, 5), (5, 7), 10_000, 50, Side::Buy)];
        let replayed = replay(&messages, &trades).await;
        assert!(
            replayed.self_trade.refused.failures.is_empty(),
            "101 is not crossed by a bid of 100: {:?}",
            replayed.self_trade.refused.failures
        );
        assert!(replayed.priority.failures.is_empty());
    }

    /// The row-only check earning its place. Here the trade log claims a
    /// self-trade the sequencer's own orders do not support. The row says
    /// order 3 and order 4 both belong to account 7, and the sequencer
    /// published order 3 under account 5. The book replay sees nothing of
    /// account 7 resting, so it passes the order through. The two account
    /// fields on the row are what catch the claim.
    #[tokio::test]
    async fn a_row_claiming_a_self_trade_the_feed_does_not_support_is_reported() {
        let messages = vec![
            list_eth(1),
            engine_rule(2, 2),
            new_order(3, 5, Side::Sell, 100.0, 5.0),
            new_order(4, 7, Side::Buy, 100.0, 5.0),
        ];
        let trades = vec![fill_between(1, (3, 7), (4, 7), 10_000, 50, Side::Buy)];
        let replayed = replay(&messages, &trades).await;
        assert_eq!(
            replayed.self_trade.paired.checked, 1,
            "the row reached the check rather than being refused before it"
        );
        assert_eq!(
            replayed.self_trade.paired.failures.len(),
            1,
            "{:?}",
            replayed.self_trade.paired.failures
        );
        assert!(
            replayed.self_trade.paired.failures[0].contains("account 7 to itself"),
            "{}",
            replayed.self_trade.paired.failures[0]
        );
        assert!(
            replayed.self_trade.refused.failures.is_empty(),
            "the book has nothing of account 7 resting, so it says nothing"
        );
    }
}
