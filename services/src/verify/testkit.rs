//! The builders the tests of `verify.rs` and of its feature modules share.
//!
//! Each feature has its own `mod tests`, and one feature's tests are not
//! inside another feature's. So a builder that more than one of them needs
//! lives here, one level above all of them, instead of being written out again
//! in each one.
//!
//! Nothing here is compiled into a release build.
//!
//! The three kinds of operator message are signed, and they have to be. This
//! checker ignores an operator message the log's operator did not write,
//! ENGINE.md section 3.1. So an unsigned listing would open no market, and
//! every test built on one would read a history in which nothing happened.
//!
//! One key signs them all, because a log has one operator.
//! `operator::signed_as` is what puts the signature on. Writing a history is
//! not the same job as checking one, and the bytes a signature covers are
//! stated in one place for every program.

use ed25519_dalek::SigningKey;

use super::*;
use crate::domain::OPERATOR_ACCOUNT;

/// The operator of every history these tests build.
fn operator() -> SigningKey {
    SigningKey::from_bytes(&[5u8; 32])
}

/// Signs one operator message for the log the held histories announce.
fn by_operator(message: OrderMessage) -> OrderMessage {
    crate::operator::signed_as(&operator(), HELD_SESSION, message)
}

/// The 32 hex characters of a nonce, one per message. The nonce is a line of
/// the signed statement, so an operator message without one cannot be checked
/// by anybody.
fn nonce(id: OrderId) -> Option<String> {
    Some(format!("{:032x}", id))
}

/// The key the histories here are opened under, as a message carries it.
pub(super) fn operator_public_key() -> String {
    crate::logchain::to_hex(operator().verifying_key().as_bytes())
}

/// A second key, for the tests about a message the log's operator did not
/// write.
pub(super) fn stranger() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

pub(super) fn new_order(
    id: OrderId,
    account: AccountId,
    side: Side,
    price: f64,
    quantity: f64,
) -> OrderMessage {
    OrderMessage::New {
        id,
        timestamp: id * 1000,
        account,
        symbol: "ETH-USDC".to_string(),
        side,
        price,
        quantity,
        nonce: None,
        order_type: Default::default(),
        time_in_force: Default::default(),
        post_only: false,
    }
}

/// Like `new_order`, but naming its own symbol, for the tests that care which
/// symbol an order names.
pub(super) fn new_order_on(
    id: OrderId,
    account: AccountId,
    symbol: &str,
    side: Side,
    price: f64,
    quantity: f64,
) -> OrderMessage {
    OrderMessage::New {
        id,
        timestamp: id * 1000,
        account,
        symbol: symbol.to_string(),
        side,
        price,
        quantity,
        nonce: None,
        order_type: Default::default(),
        time_in_force: Default::default(),
        post_only: false,
    }
}

/// An order carrying terms, at a millisecond of the test's choosing. The
/// timestamp matters here in a way it does not for the plain builder above.
/// The reference price is an average over time, so when a message arrives is
/// part of what the message means.
#[allow(clippy::too_many_arguments)]
pub(super) fn termed(
    id: OrderId,
    at_ms: u64,
    account: AccountId,
    side: Side,
    price: f64,
    quantity: f64,
    order_type: OrderType,
    time_in_force: TimeInForce,
    post_only: bool,
) -> OrderMessage {
    OrderMessage::New {
        id,
        timestamp: at_ms,
        account,
        symbol: "ETH-USDC".to_string(),
        side,
        price,
        quantity,
        nonce: None,
        order_type,
        time_in_force,
        post_only,
    }
}

/// The message every history below opens with.
///
/// ENGINE.md section 3: a log states its own rules, and which symbols it
/// trades is one of them. Nothing rests in a book for a symbol the log has not
/// opened. So a history of orders with no `ListSymbol` in front of them is a
/// history in which nothing happened, which is what
/// `an_order_for_a_symbol_the_log_never_listed_never_rests` checks.
pub(super) fn list_eth(id: OrderId) -> OrderMessage {
    list_on(id, "ETH-USDC", 0.01, 0.1)
}

pub(super) fn list_on(
    id: OrderId,
    symbol: &str,
    price_step: f64,
    quantity_step: f64,
) -> OrderMessage {
    by_operator(OrderMessage::ListSymbol {
        id,
        timestamp: id * 1000,
        account: OPERATOR_ACCOUNT,
        symbol: symbol.to_string(),
        price_step,
        quantity_step,
        nonce: nonce(id),
        public_key: String::new(),
        signature: String::new(),
    })
}

pub(super) fn delist(id: OrderId, symbol: &str) -> OrderMessage {
    by_operator(OrderMessage::DelistSymbol {
        id,
        timestamp: id * 1000,
        account: OPERATOR_ACCOUNT,
        symbol: symbol.to_string(),
        nonce: nonce(id),
        public_key: String::new(),
        signature: String::new(),
    })
}

pub(super) fn engine_rule(id: OrderId, version: u32) -> OrderMessage {
    by_operator(OrderMessage::EngineRule {
        id,
        timestamp: id * 1000,
        account: OPERATOR_ACCOUNT,
        version,
        nonce: nonce(id),
        public_key: String::new(),
        signature: String::new(),
    })
}

/// The same three kinds of message, signed by somebody else. The message names
/// the key that signed it, and the signature under that key is good. That is
/// the case worth having a builder for, because it is what a sequencer writing
/// its own operator messages would publish.
pub(super) fn by_stranger(message: OrderMessage) -> OrderMessage {
    crate::operator::signed_as(&stranger(), HELD_SESSION, message)
}

/// A `ListSymbol` for `ETH-USDC` on the ordinary steps, unsigned, for a caller
/// that signs it itself.
pub(super) fn unsigned_list_eth(id: OrderId) -> OrderMessage {
    OrderMessage::ListSymbol {
        id,
        timestamp: id * 1000,
        account: OPERATOR_ACCOUNT,
        symbol: "ETH-USDC".to_string(),
        price_step: 0.01,
        quantity_step: 0.1,
        nonce: nonce(id),
        public_key: String::new(),
        signature: String::new(),
    }
}

/// One trade row between two named accounts, at the price and quantity the
/// engine would have logged.
pub(super) fn fill(
    maker: OrderId,
    taker: OrderId,
    price_cents: i64,
    qty_tenths: i64,
) -> LoggedTrade {
    LoggedTrade {
        trade_id: 1,
        symbol: "ETH-USDC".to_string(),
        price_cents,
        qty_tenths,
        maker_order: maker,
        maker_account: 5,
        taker_order: taker,
        taker_account: 7,
        taker_side: Side::Buy,
    }
}

/// The same row with both accounts named, so a self-trade can be written down
/// as the engine would have logged it.
pub(super) fn fill_between(
    trade_id: u64,
    maker: (OrderId, AccountId),
    taker: (OrderId, AccountId),
    price_cents: i64,
    qty_tenths: i64,
    taker_side: Side,
) -> LoggedTrade {
    LoggedTrade {
        trade_id,
        symbol: "ETH-USDC".to_string(),
        price_cents,
        qty_tenths,
        maker_order: maker.0,
        maker_account: maker.1,
        taker_order: taker.0,
        taker_account: taker.1,
        taker_side,
    }
}

/// A history as it arrives. It is the bytes the sequencer published, split out
/// of one `/messages.ndjson` body the way the real walk splits them.
pub(super) fn served(messages: &[OrderMessage]) -> Vec<RawMessage> {
    let mut body = Vec::new();
    for msg in messages {
        body.extend_from_slice(&crate::logchain::canonical_bytes(msg));
        body.push(b'\n');
    }
    wire::split_ndjson(&body).expect("the feed serves one message per line")
}

/// Walks a history the way `--verify` walks the sequencer's: in pages, through
/// the same loop, and keeping no more of it than the real run keeps. A test
/// that read the messages directly would not be testing what runs.
pub(super) async fn survey(messages: &[OrderMessage]) -> Survey {
    survey_raw(&served(messages)).await
}

pub(super) async fn survey_raw(messages: &[RawMessage]) -> Survey {
    let head = Err("this test serves no head".to_string());
    let mut session = None;
    // No tree head and no anchor here, so no size has a root taken. These
    // tests drive the chain, the operator signatures and the order count a
    // walk finds. The tree check has its own tests.
    survey_history(
        &History::Held(messages),
        &mut session,
        &head,
        &mut TreeWalk::new(&[]),
    )
    .await
    .expect("a held history is walked to its end")
}

/// The second walk over a held history, against a trade record the test wrote.
/// Those are the two walks the real run makes. Every check the walk makes is on
/// the struct it returns, by name and as a list.
///
/// This one makes no claim about whether this build could read every message.
/// `replay` is the one that claims that.
pub(super) async fn replayed_history(
    messages: &[OrderMessage],
    trades: &[LoggedTrade],
) -> Replayed {
    let received = served(messages);
    let surveyed = survey_raw(&received).await;
    let mut session = None;
    replay_the_history(
        &History::Held(&received),
        &mut session,
        &Record::Held(trades),
        surveyed.last_id,
    )
    .await
    .expect("a held history is replayed to its end")
}

pub(super) async fn replay(messages: &[OrderMessage], trades: &[LoggedTrade]) -> Replayed {
    let replayed = replayed_history(messages, trades).await;
    assert!(
        replayed.too_old.is_none(),
        "this build reads every message here"
    );
    replayed
}

/// What the second walk made of the order the sequencer published under `id`:
/// the price and quantity it read, whether the book could hold them, and
/// whether the log had the symbol open at that message.
pub(super) async fn published_order(
    messages: &[OrderMessage],
    trades: &[LoggedTrade],
    id: OrderId,
) -> FeedOrder {
    replayed_history(messages, trades)
        .await
        .published
        .get(&id)
        .cloned()
        .unwrap_or_else(|| panic!("the feed published no order {}", id))
}

/// Only the priority check, for the tests that were written before the replay
/// reported more than one thing.
pub(super) async fn priority(messages: &[OrderMessage], trades: &[LoggedTrade]) -> Check {
    replay(messages, trades).await.priority
}

/// One of the replay's checks by name, so a test names the check it means and
/// not a position in a list that will grow.
pub(super) async fn replay_check(
    messages: &[OrderMessage],
    trades: &[LoggedTrade],
    name: &str,
) -> Check {
    replay(messages, trades)
        .await
        .checks()
        .into_iter()
        .find(|check| check.name == name)
        .unwrap_or_else(|| panic!("the replay makes no check called {:?}", name))
}
