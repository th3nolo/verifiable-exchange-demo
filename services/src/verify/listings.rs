//! The listing rule, worked out again from the sequencer's own messages.
//!
//! ENGINE.md section 3: a log states which symbols it trades. An order naming
//! a symbol the log has not opened never entered a book. So no trade may name
//! that order, and nothing may be filled against it.
//!
//! Nothing here shares a line of code with `matcher.rs`. The engine answers
//! "was this symbol listed here" from a registry it keeps on its state. This
//! file answers the same question from a map it fills as the history streams
//! past, and empties on a delist. Both are written from ENGINE.md section 3.
//!
//! The second walk is the walk that reads these messages. It holds a book, so
//! a delist empties the book it closed. It also records which delist closed
//! each order the trade record still names, so the check `no fill against an
//! already cancelled order` can say a delist closed the order and not its own
//! account. The first walk read these messages too, until the trade record
//! stopped being held in memory: it kept the delist against every order the
//! trade record named, and that index was as large as the trade record.

use std::collections::HashMap;

use crate::domain::{OrderMessage, to_grid};

use super::order_terms::MidHistory;
use super::{NamedOrders, ReplayBook};

/// The most characters a symbol may hold. It is written out here and not
/// imported. This module checks the exchange, so it states the rules it checks
/// against in its own words. `to_grid` above does come from `domain.rs`, and
/// both sides share `domain.rs` on purpose: it says what a price is, and not
/// what the exchange may do with one, see `verify.rs`.
const MAX_SYMBOL_CHARACTERS: usize = 32;

/// Whether the log can open a market under this name.
///
/// ENGINE.md section 4.0 gives the rule. A name is 1 to 32 characters, and
/// every character is `A` to `Z`, `0` to `9` or `-`. A name that breaks the
/// rule opens nothing, so an order under that name never rested and no trade
/// may name it.
///
/// This function is read from that text and from nothing the exchange runs.
/// The exchange writes the same rule as its own code, and the two are meant to
/// be able to disagree, so this file imports neither `matcher` nor `operator`.
fn names_a_market(symbol: &str) -> bool {
    let characters = symbol.chars().count();
    if characters == 0 || characters > MAX_SYMBOL_CHARACTERS {
        return false;
    }
    symbol
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
}

/// The steps one `ListSymbol` message opened a symbol on, in whole cents and
/// whole tenths.
#[derive(Debug, Clone, Copy)]
struct Steps {
    price_cents: i64,
    quantity_tenths: i64,
}

/// The symbols the log has opened and not closed, at the point a walk has
/// reached.
///
/// **A missing entry is the whole answer.** A symbol with no entry here is one
/// the log either never listed or has since delisted. An order naming that
/// symbol never entered a book, so no trade may name the order and nothing may
/// be filled against it. This map is written from the rule and not from
/// `matcher.rs`. The engine keeps a row for a delisted symbol with a flag
/// turned off, because its read endpoints still answer about what that symbol
/// traded. This file answers no such questions, so the entry goes, and an
/// engine that forgot to turn its flag off would disagree with this file and
/// be caught.
///
/// The arithmetic is the same arithmetic on purpose, and that is not laziness.
/// A second implementation that rounded differently would report an honest
/// exchange the first time a price landed between the two roundings, and a
/// checker whose reports are sometimes wrong is a checker nobody acts on. What
/// is not shared is the code. This file imports nothing from `matcher`, so a
/// mistake in one of them is not a mistake in the other.
#[derive(Debug, Default)]
pub(super) struct Listings(HashMap<String, Steps>);

impl Listings {
    /// Reads one `ListSymbol`.
    ///
    /// Three kinds of message open nothing.
    ///
    /// A name the log cannot open a market under opens none. A symbol already
    /// open stays on the steps it was opened with: the log has to close the
    /// symbol before it can be opened on different steps, or an order would
    /// already be resting at a price the new steps forbid. And a step that is
    /// not a whole number of the units the books are kept in, cents and
    /// tenths, opens nothing at all, because no book could hold a price on
    /// that step.
    fn list(&mut self, symbol: &str, price_step: f64, quantity_step: f64) {
        if !names_a_market(symbol) {
            return;
        }
        if self.0.contains_key(symbol) {
            return;
        }
        let (Some(price_cents), Some(quantity_tenths)) =
            (to_grid(price_step, 100.0), to_grid(quantity_step, 10.0))
        else {
            return;
        };
        self.0.insert(
            symbol.to_string(),
            Steps {
                price_cents,
                quantity_tenths,
            },
        );
    }

    /// Reads one `DelistSymbol`. True when a symbol really was open, which is
    /// the only case where anything can have been resting to close.
    fn delist(&mut self, symbol: &str) -> bool {
        self.0.remove(symbol).is_some()
    }

    /// Whether an order for `symbol` at this price in cents and this quantity
    /// in tenths could have entered a book here. Three things must hold: the
    /// symbol is open, the price is a whole number of its price step, and the
    /// quantity is a whole number of its quantity step.
    pub(super) fn admits(&self, symbol: &str, price_cents: i64, qty_tenths: i64) -> bool {
        match self.0.get(symbol) {
            Some(steps) => {
                price_cents % steps.price_cents == 0 && qty_tenths % steps.quantity_tenths == 0
            }
            None => false,
        }
    }
}

impl ReplayBook {
    /// Empties a whole market, which is what a `DelistSymbol` does.
    ///
    /// Both sides go, and every order that was resting in either of them stops
    /// resting. The levels are already keyed by symbol, so each of the two
    /// sides goes in one call. The index of resting orders is not keyed by
    /// symbol, so it is walked for the orders that named this symbol.
    fn close_symbol(&mut self, symbol: &str) {
        self.bids.remove(symbol);
        self.asks.remove(symbol);
        self.resting.retain(|_, order| order.symbol != symbol);
    }
}

/// What the replay walk does with a listing message. This walk holds a book,
/// so a delist empties one.
pub(super) fn replayed(
    listings: &mut Listings,
    book: &mut ReplayBook,
    mids: &mut MidHistory,
    named: &mut NamedOrders,
    message: &OrderMessage,
) {
    match message {
        OrderMessage::ListSymbol {
            symbol,
            price_step,
            quantity_step,
            ..
        } => {
            listings.list(symbol, *price_step, *quantity_step);
        }
        OrderMessage::DelistSymbol {
            id,
            timestamp,
            symbol,
            ..
        } => {
            // The market closes, and its book goes with it. Walking past this
            // message would leave the replay comparing later fills against
            // orders that stopped resting here, and reporting an honest engine
            // as wrong for not filling them.
            if listings.delist(symbol) {
                // A delist closes a market, and nothing resting in it is
                // resting any more. From this message on, a fill against any
                // of those orders is a fill against something that had left
                // the book. A cancel leads to the same conclusion from a
                // different message. The check `no fill against an already
                // cancelled order` reads this and names the delist.
                //
                // Only orders already published are closed. An order under one
                // of these ids that the sequencer publishes later is a
                // different question. That order names a symbol the log has
                // closed, so it never entered a book at all, and `tradable`
                // says so.
                named.delisted_on(symbol, *id);
                book.close_symbol(symbol);
                // A delist moves a book more than anything else does: it
                // empties one. So it ends the mid that book was showing, for
                // the same reason a cancel does. Without this line, the next
                // market order on the symbol after a relisting would be
                // collared against a book that no longer exists.
                mids.showed(symbol, *timestamp, book.mid_cents(symbol));
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{OrderId, OrderType, Side, TimeInForce};
    use crate::verify::FeedOrder;
    use crate::verify::testkit::*;

    /// The check that reports a fill against an order a message had already
    /// taken out of the book. A delist is one of the two messages that does
    /// that, so this file's tests name it.
    const CLOSED: &str = "no fill against an already cancelled order";

    /// An order for a symbol the log never listed never rested. So no trade
    /// can name that order, and the replayed book holds nothing at its price.
    ///
    /// The old rule read `domain::SYMBOLS`, and this is the one thing about it
    /// that had to survive the change. A sequencer must not be able to invent
    /// a symbol, put a string of its choosing into the state, and have a
    /// checker agree that orders traded on it.
    #[tokio::test]
    async fn an_order_for_a_symbol_the_log_never_listed_never_rests() {
        let messages = vec![
            new_order(1, 5, Side::Sell, 100.0, 5.0),
            new_order(2, 7, Side::Buy, 100.0, 5.0),
        ];
        let trades = vec![fill(1, 2, 10_000, 50)];

        let maker = published_order(&messages, &trades, 1).await;
        assert!(maker.on_grid, "its price and quantity are ordinary");
        assert!(
            !maker.tradable,
            "nothing listed ETH-USDC, so no book could hold it"
        );

        // And the book replay says the maker was never in the book to fill.
        let check = priority(&messages, &trades).await;
        assert_eq!(check.checked, 1);
        assert_eq!(check.failures.len(), 1, "{:?}", check.failures);
        assert!(
            check.failures[0].contains("was not resting"),
            "{}",
            check.failures[0]
        );
    }

    /// A delist empties that symbol's book and no other symbol's.
    #[tokio::test]
    async fn a_delist_empties_that_book_and_leaves_every_other_one_alone() {
        let mut book = ReplayBook::default();
        for (id, symbol, side, price) in [
            (1u64, "ETH-USDC", Side::Sell, 10_000i64),
            (2, "ETH-USDC", Side::Buy, 9_900),
            (3, "BTC-USDC", Side::Sell, 100_000),
        ] {
            book.rest(
                id,
                FeedOrder {
                    account: 5,
                    symbol: symbol.to_string(),
                    side,
                    price_cents: price,
                    qty_tenths: 50,
                    on_grid: true,
                    tradable: true,
                    order_type: OrderType::Limit,
                    time_in_force: TimeInForce::GoodTillCancel,
                    post_only: false,
                },
                50,
            );
        }
        // Account 5 is about to buy BTC-USDC at 1000, which crosses its own
        // offer there. That must still be a self-trade after the delist, and
        // the same arriving order on the closed symbol must not be one.
        let arriving = |symbol: &str, price_cents: i64| FeedOrder {
            account: 5,
            symbol: symbol.to_string(),
            side: Side::Buy,
            price_cents,
            qty_tenths: 10,
            on_grid: true,
            tradable: true,
            order_type: OrderType::Limit,
            time_in_force: TimeInForce::GoodTillCancel,
            post_only: false,
        };
        assert!(book.would_self_trade(&arriving("ETH-USDC", 10_000)));

        book.close_symbol("ETH-USDC");
        assert_eq!(book.remaining(1), None, "the sell went");
        assert_eq!(book.remaining(2), None, "and the buy on the same symbol");
        assert_eq!(book.remaining(3), Some(50), "BTC-USDC is untouched");
        assert!(book.order(1).is_none(), "and the index goes with them");
        assert!(book.order(3).is_some());

        // The index of resting orders is a second index, and it has to go with
        // the levels. An order left behind in it would make `would_self_trade`
        // refuse an arriving order that crosses nothing. That is this checker
        // reporting an honest fill as one the engine should have refused.
        assert!(
            !book.would_self_trade(&arriving("ETH-USDC", 10_000)),
            "a delisted symbol's orders are still in the resting index"
        );
        assert!(
            book.would_self_trade(&arriving("BTC-USDC", 100_000)),
            "and the symbol that stayed open still refuses a self-trade"
        );
    }

    /// A fill against an order the log had already delisted out of the book.
    /// The order was real and it rested, and then the whole market closed. So
    /// a trade naming that order afterwards is a trade against nothing.
    #[tokio::test]
    async fn a_fill_after_a_delist_is_reported() {
        let messages = vec![
            list_eth(1),
            new_order(2, 5, Side::Sell, 100.0, 5.0),
            delist(3, "ETH-USDC"),
            new_order(4, 7, Side::Buy, 100.0, 5.0),
        ];
        let trades = vec![fill(2, 4, 10_000, 50)];

        // The walk records which message closed the order, and names a
        // delist and not a cancel. Nobody cancelled anything here, so the
        // reason printed has to be the delist.
        let closed = replay_check(&messages, &trades, CLOSED).await;
        assert_eq!(closed.failed, 1, "{:?}", closed.failures);
        assert!(
            closed.failures[0].contains("message 3 had closed with the whole ETH-USDC market"),
            "{}",
            closed.failures[0]
        );

        let check = priority(&messages, &trades).await;
        assert_eq!(check.failures.len(), 1, "{:?}", check.failures);
        assert!(
            check.failures[0].contains("was not resting"),
            "{}",
            check.failures[0]
        );
    }

    /// Relisting works, and the orders in between stay ignored.
    ///
    /// Three orders on one symbol at one price: before the delist, between the
    /// delist and the listing that follows it, and after that listing. Only
    /// the first and the last could ever have rested.
    #[tokio::test]
    async fn a_relisted_symbol_trades_again_and_the_orders_in_between_do_not() {
        let messages = vec![
            list_eth(1),
            new_order(2, 5, Side::Sell, 100.0, 5.0),
            delist(3, "ETH-USDC"),
            new_order(4, 5, Side::Sell, 100.0, 5.0),
            list_eth(5),
            new_order(6, 5, Side::Sell, 100.0, 5.0),
        ];
        let trades = vec![
            fill(2, 9, 10_000, 50),
            fill(4, 9, 10_000, 50),
            fill(6, 9, 10_000, 50),
        ];
        let replayed = replayed_history(&messages, &trades).await;
        let tradable = |id: OrderId| replayed.published.get(&id).expect("published").tradable;
        assert!(tradable(2), "listed when it was published");
        assert!(!tradable(4), "delisted when it was published");
        assert!(tradable(6), "listed again when it was published");
    }

    /// A `ListSymbol` naming a step no book can hold opens nothing.
    ///
    /// The books hold whole cents and whole tenths. A price step of 0.001
    /// names prices no book can hold, so an order on that step could never
    /// have entered a book. A symbol that is listed and can never take an
    /// order is worse than one that is not listed, because every refusal
    /// afterwards names the order instead of the listing.
    #[tokio::test]
    async fn a_listing_on_a_step_no_book_can_hold_opens_nothing() {
        let messages = vec![
            list_on(1, "ETH-USDC", 0.001, 0.1),
            new_order(2, 5, Side::Sell, 100.0, 5.0),
        ];
        let trades = vec![fill(2, 9, 10_000, 50)];
        assert!(
            !published_order(&messages, &trades, 2).await.tradable,
            "the listing opened nothing, so the order rested nowhere"
        );
    }

    /// A `ListSymbol` whose symbol breaks the name rule opens nothing, so an
    /// order under that symbol never rested.
    ///
    /// ENGINE.md section 4.0 gives the rule. The checker reads it from that
    /// text. An exchange that listed `eth-usdc` anyway would disagree with
    /// this file, which is the point of the file.
    #[tokio::test]
    async fn a_listing_whose_name_breaks_the_rule_opens_nothing() {
        let messages = vec![
            list_on(1, "eth-usdc", 0.01, 0.1),
            new_order_on(2, 5, "eth-usdc", Side::Sell, 100.0, 5.0),
        ];
        let trades = vec![fill(2, 9, 10_000, 50)];
        let order = published_order(&messages, &trades, 2).await;
        assert!(order.on_grid, "its price and quantity are ordinary");
        assert!(
            !order.tradable,
            "the listing opened no market, so the order rested nowhere"
        );
    }

    /// The edges of the name rule, in the checker.
    ///
    /// 32 characters is a name. 33 is not. Nor is an empty name, lower case, a
    /// space or a dot. The strings here are the checker's own, and not the
    /// ones the exchange's test uses.
    #[test]
    fn the_name_rule_takes_32_characters_and_only_a_z_0_9_and_a_dash() {
        let longest = "ETH-USDC-PERPETUAL-Q4-2026-00001";
        assert_eq!(longest.chars().count(), 32, "the test data is the boundary");
        let too_long = format!("{longest}7");
        assert_eq!(too_long.chars().count(), 33);

        let mut listings = Listings::default();
        for symbol in [longest, "ETH-USDC", "X9", "7"] {
            listings.list(symbol, 0.01, 0.1);
            assert!(listings.admits(symbol, 10_000, 50), "{symbol} is a name");
        }
        for symbol in [&too_long[..], "", "eth-usdc", "ETH USDC", "ETH.USDC"] {
            listings.list(symbol, 0.01, 0.1);
            assert!(
                !listings.admits(symbol, 10_000, 50),
                "{symbol:?} is not a name"
            );
        }
    }

    /// An order off the symbol's own step never rests, even when its price is
    /// a whole number of cents.
    ///
    /// A symbol listed on a price step of 0.05 takes 100.00 and refuses
    /// 100.03, and both prices are whole numbers of cents. That is the
    /// symbol's own step doing work whole cents alone do not do.
    #[tokio::test]
    async fn an_order_off_the_symbol_s_own_step_never_rests() {
        let messages = vec![
            list_on(1, "ETH-USDC", 0.05, 0.5),
            new_order(2, 5, Side::Sell, 100.0, 5.0),
            new_order(3, 5, Side::Sell, 100.03, 5.0),
            new_order(4, 5, Side::Sell, 100.0, 5.2),
        ];
        let trades = vec![
            fill(2, 9, 10_000, 50),
            fill(3, 9, 10_003, 50),
            fill(4, 9, 10_000, 52),
        ];
        let replayed = replayed_history(&messages, &trades).await;
        let order = |id: OrderId| replayed.published.get(&id).expect("published").clone();
        assert!(order(2).tradable, "100.00 is four steps of 0.05");
        assert!(order(3).on_grid, "100.03 is a whole number of cents");
        assert!(!order(3).tradable, "and it is not a whole number of 0.05");
        assert!(order(4).on_grid, "5.2 is a whole number of tenths");
        assert!(!order(4).tradable, "and it is not a whole number of 0.5");
    }
}
