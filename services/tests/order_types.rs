//! The order terms, end to end through all six matching steps.
//!
//! These drive `MatcherState` the way the poller does, one message at a time,
//! in feed order, and read the result off the same public views the API
//! handlers and the bot read. Nothing here reaches inside the engine, so a
//! rule that moved between steps would not change a line of this file.
//!
//! ENGINE.md sections 4.2 and 4.4 are what it checks.

use ed25519_dalek::SigningKey;
use services::domain::{OPERATOR_ACCOUNT, OrderMessage, OrderType, Side, TimeInForce};
use services::matcher::MatcherState;
use services::{logchain, operator};

/// The symbol every case here trades. Its mid on the feed is 10.00, so a cent
/// is a thousandth of the price and the two-percent collar is 20 cents wide.
const SYMBOL: &str = "MERKLE-USDC";

fn order(
    id: u64,
    timestamp: u64,
    account: u32,
    side: Side,
    price: f64,
    quantity: f64,
    order_type: OrderType,
    time_in_force: TimeInForce,
    post_only: bool,
) -> OrderMessage {
    OrderMessage::New {
        id,
        timestamp,
        account,
        symbol: SYMBOL.to_string(),
        side,
        price,
        quantity,
        nonce: None,
        order_type,
        time_in_force,
        post_only,
    }
}

/// A plain limit order with all three terms at the value an absent field
/// means: the only shape any message published so far has.
fn plain(
    id: u64,
    timestamp: u64,
    account: u32,
    side: Side,
    price: f64,
    quantity: f64,
) -> OrderMessage {
    order(
        id,
        timestamp,
        account,
        side,
        price,
        quantity,
        OrderType::Limit,
        TimeInForce::GoodTillCancel,
        false,
    )
}

/// Lists a symbol on the steps every case here uses: prices in whole cents,
/// quantities in whole tenths. A fresh engine has an empty registry, so every
/// history has to name its symbols before it can trade them.
///
/// It is signed, and it has to be: the engine ignores an operator message that
/// does not verify under the key the log named, ENGINE.md section 3.1, so an
/// unsigned listing would open no market and every case below would be refused
/// for the one reason none of them is about. The session is empty because an
/// engine built here has never spoken to a feed, so it announces no session
/// and reads the statement's session line as empty.
fn list(id: u64, timestamp: u64, symbol: &str) -> OrderMessage {
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let mut message = OrderMessage::ListSymbol {
        id,
        timestamp,
        account: OPERATOR_ACCOUNT,
        symbol: symbol.to_string(),
        price_step: 0.01,
        quantity_step: 0.1,
        nonce: Some(format!("{:032x}", id)),
        public_key: logchain::to_hex(key.verifying_key().as_bytes()),
        signature: String::new(),
    };
    let (kind, fields) = operator::kind_and_fields(&message).expect("a listing has a statement");
    if let OrderMessage::ListSymbol { signature, .. } = &mut message {
        *signature = operator::sign(&key, kind, "", &fields);
    }
    message
}

fn cancel(id: u64, timestamp: u64, account: u32, target_id: u64) -> OrderMessage {
    OrderMessage::Cancel {
        id,
        timestamp,
        account,
        target_id,
        nonce: None,
    }
}

/// What one order did, in the units the engine matches in.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    /// True when a step refused the order: `orders_ignored` moved and nothing
    /// else did.
    refused: bool,
    /// Tenths filled by this order, across every trade it took part in.
    filled_tenths: i64,
    /// Tenths of it left resting in the book afterwards.
    rested_tenths: i64,
    /// The prices it filled at, in cents, oldest fill first.
    fill_prices: Vec<i64>,
}

impl Outcome {
    fn refused() -> Self {
        Outcome {
            refused: true,
            filled_tenths: 0,
            rested_tenths: 0,
            fill_prices: Vec::new(),
        }
    }

    fn did_nothing() -> Self {
        Outcome {
            refused: false,
            filled_tenths: 0,
            rested_tenths: 0,
            fill_prices: Vec::new(),
        }
    }

    fn rested(tenths: i64) -> Self {
        Outcome {
            refused: false,
            filled_tenths: 0,
            rested_tenths: tenths,
            fill_prices: Vec::new(),
        }
    }

    fn filled(tenths: i64, at_cents: i64) -> Self {
        Outcome {
            refused: false,
            filled_tenths: tenths,
            rested_tenths: 0,
            fill_prices: vec![at_cents],
        }
    }

    fn filled_and_rested(filled: i64, at_cents: i64, rested: i64) -> Self {
        Outcome {
            refused: false,
            filled_tenths: filled,
            rested_tenths: rested,
            fill_prices: vec![at_cents],
        }
    }
}

/// Applies one order to an engine and reports everything it did.
fn apply(engine: &mut MatcherState, message: &OrderMessage) -> Outcome {
    let id = match message {
        OrderMessage::New { id, .. } => *id,
        other => panic!("this helper submits orders, not {:?}", other),
    };
    let ignored_before = engine.orders_ignored();
    let trades_before = engine.trades_total();
    engine.apply_message(message).expect("in feed order");

    let fills: Vec<(i64, i64)> = engine
        .trades()
        .filter(|trade| trade.taker_order == id)
        .map(|trade| {
            (
                (trade.quantity * 10.0).round() as i64,
                (trade.price * 100.0).round() as i64,
            )
        })
        .collect();
    Outcome {
        refused: engine.orders_ignored() > ignored_before,
        filled_tenths: fills.iter().map(|(qty, _)| qty).sum(),
        rested_tenths: engine.open_order(id).map_or(0, |(_, _, _, tenths)| tenths),
        fill_prices: fills.iter().map(|(_, price)| *price).collect(),
    }
    .also_check(engine, trades_before, id)
}

impl Outcome {
    /// A refused order must not have traded, and an order that traded must not
    /// be reported as refused. Checked on every one of the 36 cases rather
    /// than trusted, because `orders_ignored` is the only signal a submitter
    /// gets and a wrong one is worse than none.
    fn also_check(self, engine: &MatcherState, trades_before: u64, id: u64) -> Self {
        if self.refused {
            assert_eq!(
                engine.trades_total(),
                trades_before,
                "order {} was refused and still traded",
                id
            );
            assert_eq!(self.rested_tenths, 0, "order {} was refused and rested", id);
        }
        self
    }
}

/// The engine, wound forward to where a two-sided book has been standing long
/// enough to have a reference price of exactly 1000 cents.
///
/// Message 1 lists the symbol, which puts nothing in the book. Message 2 puts
/// a bid at 995 and message 3 an ask at 1005, one second apart. From message 3
/// on, the mid is 1000. Every case then submits at t = 20,000, so the mid has
/// held for 18 seconds inside a 30-second window and the reference is 1000
/// cents to the cent, which puts the collar at 1020.
fn engine_with_a_reference_price() -> MatcherState {
    let mut engine = MatcherState::new();
    engine
        .apply_message(&list(1, 0, SYMBOL))
        .expect("in feed order");
    engine
        .apply_message(&plain(2, 1_000, 1, Side::Buy, 9.95, 10.0))
        .expect("in feed order");
    engine
        .apply_message(&plain(3, 2_000, 1, Side::Sell, 10.05, 3.0))
        .expect("in feed order");
    engine
}

/// What the taking side of the book holds when the order under test arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Book {
    /// Nothing to take. The ask that built the reference price is cancelled.
    Empty,
    /// Ten tenths at 1005, against an order that wants twenty.
    Partial,
    /// Thirty tenths at 1005, which is more than the order wants.
    Full,
}

/// An engine holding a reference price of 1000 cents and the asks this case
/// needs, with the id the next message must carry.
///
/// `apply_message` refuses anything but the successor of its cursor, so the id
/// travels with the engine rather than being guessed at the call site.
fn engine_with(book: Book) -> (MatcherState, u64) {
    let mut engine = engine_with_a_reference_price();
    let next = match book {
        Book::Full => 4,
        Book::Empty => {
            engine
                .apply_message(&cancel(4, 3_000, 1, 3))
                .expect("in feed order");
            5
        }
        Book::Partial => {
            engine
                .apply_message(&cancel(4, 3_000, 1, 3))
                .expect("in feed order");
            engine
                .apply_message(&plain(5, 4_000, 1, Side::Sell, 10.05, 1.0))
                .expect("in feed order");
            6
        }
    };
    (engine, next)
}

/// The state root the same engine would have if the message it is about to be
/// given had done nothing at all.
///
/// `state_root` covers the cursor as well as the books and the positions, so an
/// engine that refused a message does not hash to what it hashed before the
/// message: it has consumed one more. The thing to compare a refusal against is
/// a message of the same id that really changed nothing, and a cancel naming an
/// order that does not exist is exactly that: `apply_cancel` counts it and
/// returns without touching a book.
fn root_if_nothing_had_happened(mut engine: MatcherState, id: u64) -> [u8; 32] {
    engine
        .apply_message(&cancel(id, 20_000, 4_242, 4_242))
        .expect("in feed order");
    engine.state_root()
}

/// Every combination of the three terms against every state of the book:
/// 2 order types × 3 times in force × 2 post-only values × 3 books = 36.
///
/// The expected column is written out by hand. Nothing in it is derived from
/// the rules the engine runs, because a table derived that way agrees with a
/// wrong rule.
#[test]
fn all_thirty_six_combinations_of_terms_and_book() {
    // The order under test every time: a buy of 2.0 at 10.10, which is inside
    // the collar (1020) and crosses the ask at 1005 whenever there is one.
    const AT: f64 = 10.10;
    const QTY: f64 = 2.0;

    let cases: Vec<(OrderType, TimeInForce, bool, Book, Outcome)> = vec![
        // A plain limit order. This row is what the whole log so far is, and
        // it is the row that must not change.
        (
            OrderType::Limit,
            TimeInForce::GoodTillCancel,
            false,
            Book::Empty,
            Outcome::rested(20),
        ),
        (
            OrderType::Limit,
            TimeInForce::GoodTillCancel,
            false,
            Book::Partial,
            Outcome::filled_and_rested(10, 1005, 10),
        ),
        (
            OrderType::Limit,
            TimeInForce::GoodTillCancel,
            false,
            Book::Full,
            Outcome::filled(20, 1005),
        ),
        // Post-only: rests when it would not take, refused when it would.
        (
            OrderType::Limit,
            TimeInForce::GoodTillCancel,
            true,
            Book::Empty,
            Outcome::rested(20),
        ),
        (
            OrderType::Limit,
            TimeInForce::GoodTillCancel,
            true,
            Book::Partial,
            Outcome::refused(),
        ),
        (
            OrderType::Limit,
            TimeInForce::GoodTillCancel,
            true,
            Book::Full,
            Outcome::refused(),
        ),
        // Immediate-or-cancel takes what it can and rests nothing.
        (
            OrderType::Limit,
            TimeInForce::ImmediateOrCancel,
            false,
            Book::Empty,
            Outcome::did_nothing(),
        ),
        (
            OrderType::Limit,
            TimeInForce::ImmediateOrCancel,
            false,
            Book::Partial,
            Outcome::filled(10, 1005),
        ),
        (
            OrderType::Limit,
            TimeInForce::ImmediateOrCancel,
            false,
            Book::Full,
            Outcome::filled(20, 1005),
        ),
        // Post-only and immediate-or-cancel ask for opposite things: it may
        // not take and it is not allowed to rest.
        (
            OrderType::Limit,
            TimeInForce::ImmediateOrCancel,
            true,
            Book::Empty,
            Outcome::refused(),
        ),
        (
            OrderType::Limit,
            TimeInForce::ImmediateOrCancel,
            true,
            Book::Partial,
            Outcome::refused(),
        ),
        (
            OrderType::Limit,
            TimeInForce::ImmediateOrCancel,
            true,
            Book::Full,
            Outcome::refused(),
        ),
        // Fill-or-kill: the whole quantity or nothing at all.
        (
            OrderType::Limit,
            TimeInForce::FillOrKill,
            false,
            Book::Empty,
            Outcome::refused(),
        ),
        (
            OrderType::Limit,
            TimeInForce::FillOrKill,
            false,
            Book::Partial,
            Outcome::refused(),
        ),
        (
            OrderType::Limit,
            TimeInForce::FillOrKill,
            false,
            Book::Full,
            Outcome::filled(20, 1005),
        ),
        // And the same contradiction as immediate-or-cancel.
        (
            OrderType::Limit,
            TimeInForce::FillOrKill,
            true,
            Book::Empty,
            Outcome::refused(),
        ),
        (
            OrderType::Limit,
            TimeInForce::FillOrKill,
            true,
            Book::Partial,
            Outcome::refused(),
        ),
        (
            OrderType::Limit,
            TimeInForce::FillOrKill,
            true,
            Book::Full,
            Outcome::refused(),
        ),
        // A market order never rests, whatever its time in force says. Its
        // bound of 10.10 is inside the collar, so it fills at the ask.
        (
            OrderType::Market,
            TimeInForce::GoodTillCancel,
            false,
            Book::Empty,
            Outcome::did_nothing(),
        ),
        (
            OrderType::Market,
            TimeInForce::GoodTillCancel,
            false,
            Book::Partial,
            Outcome::filled(10, 1005),
        ),
        (
            OrderType::Market,
            TimeInForce::GoodTillCancel,
            false,
            Book::Full,
            Outcome::filled(20, 1005),
        ),
        // A market order is priced to cross. Post-only asks it not to.
        (
            OrderType::Market,
            TimeInForce::GoodTillCancel,
            true,
            Book::Empty,
            Outcome::refused(),
        ),
        (
            OrderType::Market,
            TimeInForce::GoodTillCancel,
            true,
            Book::Partial,
            Outcome::refused(),
        ),
        (
            OrderType::Market,
            TimeInForce::GoodTillCancel,
            true,
            Book::Full,
            Outcome::refused(),
        ),
        (
            OrderType::Market,
            TimeInForce::ImmediateOrCancel,
            false,
            Book::Empty,
            Outcome::did_nothing(),
        ),
        (
            OrderType::Market,
            TimeInForce::ImmediateOrCancel,
            false,
            Book::Partial,
            Outcome::filled(10, 1005),
        ),
        (
            OrderType::Market,
            TimeInForce::ImmediateOrCancel,
            false,
            Book::Full,
            Outcome::filled(20, 1005),
        ),
        (
            OrderType::Market,
            TimeInForce::ImmediateOrCancel,
            true,
            Book::Empty,
            Outcome::refused(),
        ),
        (
            OrderType::Market,
            TimeInForce::ImmediateOrCancel,
            true,
            Book::Partial,
            Outcome::refused(),
        ),
        (
            OrderType::Market,
            TimeInForce::ImmediateOrCancel,
            true,
            Book::Full,
            Outcome::refused(),
        ),
        (
            OrderType::Market,
            TimeInForce::FillOrKill,
            false,
            Book::Empty,
            Outcome::refused(),
        ),
        (
            OrderType::Market,
            TimeInForce::FillOrKill,
            false,
            Book::Partial,
            Outcome::refused(),
        ),
        (
            OrderType::Market,
            TimeInForce::FillOrKill,
            false,
            Book::Full,
            Outcome::filled(20, 1005),
        ),
        (
            OrderType::Market,
            TimeInForce::FillOrKill,
            true,
            Book::Empty,
            Outcome::refused(),
        ),
        (
            OrderType::Market,
            TimeInForce::FillOrKill,
            true,
            Book::Partial,
            Outcome::refused(),
        ),
        (
            OrderType::Market,
            TimeInForce::FillOrKill,
            true,
            Book::Full,
            Outcome::refused(),
        ),
    ];

    assert_eq!(
        cases.len(),
        36,
        "2 order types x 3 times in force x 2 post-only x 3 books"
    );
    // Counted, not sampled: every one of the twelve shapes appears against
    // every one of the three books, exactly once.
    for order_type in [OrderType::Limit, OrderType::Market] {
        for time_in_force in [
            TimeInForce::GoodTillCancel,
            TimeInForce::ImmediateOrCancel,
            TimeInForce::FillOrKill,
        ] {
            for post_only in [false, true] {
                for book in [Book::Empty, Book::Partial, Book::Full] {
                    let found = cases
                        .iter()
                        .filter(|(t, f, p, b, _)| {
                            (*t, *f, *p, *b) == (order_type, time_in_force, post_only, book)
                        })
                        .count();
                    assert_eq!(
                        found, 1,
                        "{:?}/{:?}/post_only {}/{:?} appears {} times",
                        order_type, time_in_force, post_only, book, found
                    );
                }
            }
        }
    }

    for (case, (order_type, time_in_force, post_only, book, expected)) in
        cases.into_iter().enumerate()
    {
        let (mut engine, id) = engine_with(book);
        let under_test = order(
            id,
            20_000,
            9,
            Side::Buy,
            AT,
            QTY,
            order_type,
            time_in_force,
            post_only,
        );
        let outcome = apply(&mut engine, &under_test);
        assert_eq!(
            outcome, expected,
            "case {}: {:?} {:?} post_only {} against a {:?} book",
            case, order_type, time_in_force, post_only, book
        );
    }
}

/// A fill-or-kill order that cannot fill entirely leaves the book exactly as it
/// found it: no partial fills, no empty book, and the same state root.
#[test]
fn a_fill_or_kill_that_cannot_fill_changes_nothing_at_all() {
    for book in [Book::Empty, Book::Partial] {
        let (mut engine, id) = engine_with(book);
        let untouched = root_if_nothing_had_happened(engine_with(book).0, id);
        let trades_before = engine.trades_total();
        let bid_before = engine.best_bid_cents(SYMBOL);
        let ask_before = engine.best_ask_cents(SYMBOL);

        let outcome = apply(
            &mut engine,
            &order(
                id,
                20_000,
                9,
                Side::Buy,
                10.10,
                2.0,
                OrderType::Limit,
                TimeInForce::FillOrKill,
                false,
            ),
        );
        assert!(outcome.refused, "{:?}: it cannot fill whole", book);
        assert_eq!(
            engine.state_root(),
            untouched,
            "{:?}: a refused fill-or-kill order moved the state root",
            book
        );
        assert_eq!(engine.trades_total(), trades_before, "{:?}", book);
        assert_eq!(engine.best_bid_cents(SYMBOL), bid_before, "{:?}", book);
        assert_eq!(engine.best_ask_cents(SYMBOL), ask_before, "{:?}", book);
        assert_eq!(engine.orders_ignored(), 1, "{:?}: counted once", book);
    }
}

/// A refusal on a symbol that has never been traded leaves no empty book
/// behind, on both of the paths that can leave one.
///
/// `state_root` asserts that no empty book is in the map, and that assertion is
/// a `debug_assert`, compiled out of the release binary, so it is not what is
/// being relied on here. The root itself is: an engine holding a book with
/// nothing in it hashes differently from one holding no book, and the run that
/// resumed from it would end permanently.
///
/// The comparison is against an engine that consumed a message of the same id
/// which changed nothing, a cancel of an order that does not exist. `last_seen`
/// is in the root, so a fresh engine is not the right thing to compare with.
#[test]
fn a_refusal_leaves_no_empty_book_behind() {
    let mut untouched = MatcherState::new();
    untouched
        .apply_message(&list(1, 1_000, SYMBOL))
        .expect("in feed order");
    untouched
        .apply_message(&cancel(2, 1_000, 9, 4_242))
        .expect("in feed order");
    let nothing_happened = untouched.state_root();

    // Step 2 refuses before a book entry exists at all.
    for (order_type, time_in_force, post_only) in [
        (OrderType::Limit, TimeInForce::FillOrKill, false),
        (OrderType::Limit, TimeInForce::ImmediateOrCancel, true),
        (OrderType::Limit, TimeInForce::FillOrKill, true),
        (OrderType::Market, TimeInForce::GoodTillCancel, true),
        // And step 3, which refuses after `apply_new` has created one: a market
        // order on a symbol the engine has no reference price for.
        (OrderType::Market, TimeInForce::GoodTillCancel, false),
        (OrderType::Market, TimeInForce::FillOrKill, false),
    ] {
        let mut engine = MatcherState::new();
        engine
            .apply_message(&list(1, 1_000, SYMBOL))
            .expect("in feed order");
        let outcome = apply(
            &mut engine,
            &order(
                2,
                1_000,
                9,
                Side::Buy,
                10.10,
                2.0,
                order_type,
                time_in_force,
                post_only,
            ),
        );
        assert!(
            outcome.refused,
            "{:?}/{:?}/post_only {} was expected to be refused",
            order_type, time_in_force, post_only
        );
        assert_eq!(
            engine.state_root(),
            nothing_happened,
            "{:?}/{:?}/post_only {} left something behind",
            order_type,
            time_in_force,
            post_only
        );
    }
}

/// Immediate-or-cancel fills what it can and rests nothing, however much is
/// left over.
#[test]
fn immediate_or_cancel_fills_what_it_can_and_rests_nothing() {
    let (mut engine, id) = engine_with(Book::Partial);
    let outcome = apply(
        &mut engine,
        &order(
            id,
            20_000,
            9,
            Side::Buy,
            10.10,
            2.0,
            OrderType::Limit,
            TimeInForce::ImmediateOrCancel,
            false,
        ),
    );
    assert_eq!(outcome.filled_tenths, 10, "one of the two units was there");
    assert_eq!(outcome.rested_tenths, 0);
    assert!(!outcome.refused, "a partial fill is not a refusal");
    assert_eq!(
        engine.best_bid_cents(SYMBOL),
        Some(995),
        "the remainder did not become the best bid"
    );
    assert_eq!(engine.best_ask_cents(SYMBOL), None, "it took the whole ask");
}

/// Post-only is refused when it would take liquidity and rests when it would
/// not, with the ask standing still in both cases.
#[test]
fn post_only_is_refused_when_it_would_take_and_rests_when_it_would_not() {
    // One cent below the ask: it takes nothing, so it rests and becomes the
    // best bid.
    let (mut engine, id) = engine_with(Book::Full);
    let resting = apply(
        &mut engine,
        &order(
            id,
            20_000,
            9,
            Side::Buy,
            10.04,
            2.0,
            OrderType::Limit,
            TimeInForce::GoodTillCancel,
            true,
        ),
    );
    assert_eq!(resting, Outcome::rested(20));
    assert_eq!(engine.best_bid_cents(SYMBOL), Some(1004));

    // At the ask's own price it would trade, so it is refused and the book is
    // untouched.
    let (mut engine, id) = engine_with(Book::Full);
    let untouched = root_if_nothing_had_happened(engine_with(Book::Full).0, id);
    let refused = apply(
        &mut engine,
        &order(
            id,
            20_000,
            9,
            Side::Buy,
            10.05,
            2.0,
            OrderType::Limit,
            TimeInForce::GoodTillCancel,
            true,
        ),
    );
    assert_eq!(refused, Outcome::refused());
    assert_eq!(engine.state_root(), untouched);
    assert_eq!(engine.best_ask_cents(SYMBOL), Some(1005));
}

/// A market order cannot fill outside the collar, on a thin book or an empty
/// one.
///
/// The thin book here holds one offer at 15.00, which is 50% above the
/// reference price of 10.00. The order carries a signed bound of 20.00, so
/// without a collar it would fill at 1500 and pay half again what the market
/// was showing a moment earlier.
///
/// The far offer arrives in the same millisecond as the order it is meant to
/// fill, so the mid it produces carries no weight and the reference is still
/// the 1000 the book held for the eighteen seconds before it.
#[test]
fn a_market_order_never_fills_outside_the_collar() {
    let mut engine = engine_with_a_reference_price();
    engine
        .apply_message(&cancel(4, 20_000, 1, 3))
        .expect("in feed order");
    engine
        .apply_message(&plain(5, 20_000, 1, Side::Sell, 15.00, 5.0))
        .expect("in feed order");

    let outcome = apply(
        &mut engine,
        &order(
            6,
            20_000,
            9,
            Side::Buy,
            20.00,
            2.0,
            OrderType::Market,
            TimeInForce::GoodTillCancel,
            false,
        ),
    );
    assert_eq!(
        outcome,
        Outcome::did_nothing(),
        "1500 is past the collar at 1020, and a market order does not rest"
    );
    assert_eq!(
        engine.best_ask_cents(SYMBOL),
        Some(1500),
        "the far offer is still there, untouched"
    );

    // The same order against a book with nothing in it: no fill, and nothing
    // left resting at a bound of 20.00 either.
    let (mut engine, id) = engine_with(Book::Empty);
    let outcome = apply(
        &mut engine,
        &order(
            id,
            20_000,
            9,
            Side::Buy,
            20.00,
            2.0,
            OrderType::Market,
            TimeInForce::GoodTillCancel,
            false,
        ),
    );
    assert_eq!(outcome, Outcome::did_nothing());
    assert_eq!(
        engine.best_bid_cents(SYMBOL),
        Some(995),
        "the bound did not become a quote"
    );

    // And an offer at the collar itself does fill, so the collar bounds a
    // market order rather than blocking every one there is.
    let mut engine = engine_with_a_reference_price();
    engine
        .apply_message(&cancel(4, 20_000, 1, 3))
        .expect("in feed order");
    engine
        .apply_message(&plain(5, 20_000, 1, Side::Sell, 10.20, 5.0))
        .expect("in feed order");
    let outcome = apply(
        &mut engine,
        &order(
            6,
            20_000,
            9,
            Side::Buy,
            20.00,
            2.0,
            OrderType::Market,
            TimeInForce::GoodTillCancel,
            false,
        ),
    );
    assert_eq!(
        outcome,
        Outcome::filled(20, 1020),
        "1020 is the collar itself"
    );
}

/// The collar's reference price cannot be moved by one trade.
///
/// A trade prints at 5.00, half the market, and the last trade price follows
/// it, because moving that takes one trade and nothing else. The reference does
/// not follow: it is a mid price weighted by how long the book showed it, and
/// this book showed 5.00 for no time at all.
#[test]
fn one_trade_moves_the_last_price_and_not_the_reference() {
    let mut engine = engine_with_a_reference_price();
    // Everything from here on happens in one millisecond, at t = 20,000.
    // The standing bid comes off, so that a bid far below the market is the
    // best one and a sell into it prints there.
    engine
        .apply_message(&cancel(4, 20_000, 1, 2))
        .expect("in feed order");
    engine
        .apply_message(&plain(5, 20_000, 4, Side::Buy, 5.00, 2.0))
        .expect("in feed order");
    engine
        .apply_message(&plain(6, 20_000, 5, Side::Sell, 5.00, 2.0))
        .expect("in feed order");

    assert_eq!(
        engine.last_trade_cents(SYMBOL),
        Some(500),
        "one trade moved the last trade price to half the market"
    );

    // A market buy with a wide signed bound. If the collar followed the last
    // trade it would sit near 510 and this order would not reach the offer at
    // 1005 at all.
    let outcome = apply(
        &mut engine,
        &order(
            7,
            20_000,
            9,
            Side::Buy,
            20.00,
            2.0,
            OrderType::Market,
            TimeInForce::GoodTillCancel,
            false,
        ),
    );
    assert_eq!(
        outcome,
        Outcome::filled(20, 1005),
        "the collar is still measured from 1000, so it reaches the offer at 1005"
    );
}

/// The reference price is a mid the book really held, so moving it means
/// standing a quote against the market for a measurable part of the window,
/// and then it does move, by the fraction of the window that quote was up.
#[test]
fn holding_the_mid_wrong_does_move_the_reference_and_costs_the_window() {
    // Fifteen seconds of a mid at 1000, then fifteen at 2000. The average sits
    // halfway, at 1500, and the collar two percent past that is 1530.
    let mut engine = MatcherState::new();
    engine
        .apply_message(&list(1, 0, SYMBOL))
        .expect("in feed order");
    engine
        .apply_message(&plain(2, 0, 1, Side::Buy, 9.95, 10.0))
        .expect("in feed order");
    engine
        .apply_message(&plain(3, 0, 1, Side::Sell, 10.05, 10.0))
        .expect("in feed order");
    // At 15 seconds the offer is withdrawn and replaced far above the market,
    // which is what it takes to move a mid: the bid at 995 is still standing,
    // so an offer at 30.05 puts the mid at 2000.
    engine
        .apply_message(&cancel(4, 15_000, 1, 3))
        .expect("in feed order");
    engine
        .apply_message(&plain(5, 15_000, 1, Side::Sell, 30.05, 10.0))
        .expect("in feed order");
    // At 30 seconds an offer arrives at 15.30, inside a collar measured from
    // 1500, and far outside one measured from 1000.
    engine
        .apply_message(&plain(6, 30_000, 5, Side::Sell, 15.30, 2.0))
        .expect("in feed order");

    let outcome = apply(
        &mut engine,
        &order(
            7,
            30_000,
            9,
            Side::Buy,
            20.00,
            2.0,
            OrderType::Market,
            TimeInForce::GoodTillCancel,
            false,
        ),
    );
    assert_eq!(
        outcome,
        Outcome::filled(20, 1530),
        "half a window at 2000 carried the reference to 1500, and 1530 is its collar"
    );
}

/// A market order on a symbol the engine has no reference price for is
/// refused. That is the whole of ENGINE.md 4.2 in one case: the operator
/// choosing the price is the outcome it exists to prevent, and refusing costs
/// the sender nothing.
#[test]
fn a_market_order_with_no_reference_price_is_refused_not_filled() {
    let mut engine = MatcherState::new();
    // A book with liquidity on it, but no time behind its mid: both orders
    // arrive at the same millisecond as the market order that follows.
    engine
        .apply_message(&list(1, 1_000, SYMBOL))
        .expect("in feed order");
    engine
        .apply_message(&plain(2, 1_000, 1, Side::Buy, 9.95, 10.0))
        .expect("in feed order");
    engine
        .apply_message(&plain(3, 1_000, 1, Side::Sell, 10.05, 10.0))
        .expect("in feed order");

    let outcome = apply(
        &mut engine,
        &order(
            4,
            1_000,
            9,
            Side::Buy,
            10.10,
            2.0,
            OrderType::Market,
            TimeInForce::GoodTillCancel,
            false,
        ),
    );
    assert_eq!(outcome, Outcome::refused());
    assert_eq!(
        engine.best_ask_cents(SYMBOL),
        Some(1005),
        "the offer it could not be priced against is untouched"
    );

    // A second later the same book has held its mid for a measurable time, and
    // the same order fills.
    let outcome = apply(
        &mut engine,
        &order(
            5,
            2_000,
            9,
            Side::Buy,
            10.10,
            2.0,
            OrderType::Market,
            TimeInForce::GoodTillCancel,
            false,
        ),
    );
    assert_eq!(outcome, Outcome::filled(20, 1005));
}

/// A history of plain limit orders reaches the state it always did.
///
/// The root below is this build's, and it had to be: the state root now covers
/// the symbol registry, and it says `exchange-state-v4`. Two engines with the
/// same books over different registries trade differently and must not share a
/// root. The root moved again when the tag reached v4, for two
/// reasons that hold together: the tag itself, and the operator key the three
/// listings below named, which the root now carries. What the ten orders
/// below *do* has not changed, and
/// that half is pinned where it can still be compared against the old
/// encoding: `replaying_the_live_page_reaches_the_state_root_it_always_did`
/// and `a_history_with_no_engine_rule_message_hashes_to_the_root_it_always_did`
/// in `matcher.rs` both check `state_root_v2`, the previous build's encoding of
/// the books and the positions, against values measured before any of this
/// existed.
///
/// What this one still catches is a rule that starts applying itself to plain
/// limit orders tomorrow: three symbols, resting orders on both sides, a
/// partial fill, a full fill, a self-crossing account and two cancels.
#[test]
fn a_history_with_no_new_order_types_hashes_to_the_root_it_always_did() {
    let mut engine = MatcherState::new();
    let history = vec![
        list(1, 0, SYMBOL),
        list(2, 0, "ETH-USDC"),
        list(3, 0, "BTC-USDC"),
        eth(4, 7, Side::Buy, 100.25, 5.0),
        eth(5, 9, Side::Sell, 100.50, 4.0),
        eth(6, 11, Side::Sell, 100.25, 3.0),
        btc(7, 7, Side::Buy, 997.16, 2.0),
        btc(8, 9, Side::Sell, 997.16, 5.0),
        // `eth` and `btc` take their timestamp from the id, as `id * 1000`.
        // The four messages that name their own carry the same offset, so the
        // history stays in time order: a feed's timestamps advance with its
        // ids, and a fixture whose do not would be exercising the
        // reference-price tracker's clamp instead of its ordinary path.
        cancel(9, 9_000, 9, 5),
        plain(10, 10_000, 13, Side::Sell, 10.05, 8.0),
        plain(11, 11_000, 7, Side::Buy, 10.05, 8.0),
        eth(12, 11, Side::Buy, 100.30, 6.0),
        cancel(13, 13_000, 7, 4),
    ];
    for message in &history {
        engine.apply_message(message).expect("in feed order");
    }
    let root: String = engine
        .state_root()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect();
    assert_eq!(
        root, "058e26bcc1c7c6f21ea7dcbaf1d26e01a32caf38709619307fcb43a869977c4f",
        "a history of plain limit orders no longer produces the state it used to"
    );
    assert_eq!(engine.trades_total(), 3);
    assert_eq!(engine.orders_ignored(), 0);
}

fn eth(id: u64, account: u32, side: Side, price: f64, quantity: f64) -> OrderMessage {
    on("ETH-USDC", id, account, side, price, quantity)
}

fn btc(id: u64, account: u32, side: Side, price: f64, quantity: f64) -> OrderMessage {
    on("BTC-USDC", id, account, side, price, quantity)
}

fn on(symbol: &str, id: u64, account: u32, side: Side, price: f64, quantity: f64) -> OrderMessage {
    OrderMessage::New {
        id,
        timestamp: id * 1000,
        account,
        symbol: symbol.to_string(),
        side,
        price,
        quantity,
        nonce: None,
        order_type: OrderType::Limit,
        time_in_force: TimeInForce::GoodTillCancel,
        post_only: false,
    }
}
