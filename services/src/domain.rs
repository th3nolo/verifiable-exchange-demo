//! What a message is, with no program attached to it.
//!
//! Sequencing a message, matching it, storing it and checking it are four
//! different programs. Every one of them needs the same description of the
//! thing it works on: `OrderMessage`, `Side`, the two id aliases, the list of
//! symbols, and the whole numbers a price and a quantity are read onto.
//!
//! **This module imports nothing from this repository.** That is the line
//! between what a message *is* and what a program *does* with it. This file
//! holds only the first half. Anybody can check the rule with one grep, and
//! nobody has to read the code to trust it.
//!
//! These types used to live in `feed.rs`, next to the HTTP server, the SQLite
//! writer, the rate limiter and the traffic generator. A module that needed
//! only the shape of a message then had to depend on the program that
//! sequences messages. Two import cycles ran through exactly that dependency:
//!
//! ```text
//! feed -> logchain -> feed   the chain hashes serialized messages in turn
//! feed -> inbox -> matcher -> feed
//! ```
//!
//! The rule also decides what does *not* belong here. Anything that needs
//! another module is not part of this description:
//!
//! - the replay-nonce index (`feed.rs`'s `nonce_key`) needs `inbox` to decode
//!   a nonce, and it answers a sequencer's own question: which slot in *my*
//!   used-nonce table does this message occupy;
//! - the generator's price clamp (`feed.rs`'s `clamp_price`) reads
//!   `MAX_GRID_UNITS` below and `PRICE_SCALE` in `inbox.rs`, but it is a
//!   service's own policy and not part of a message. It keeps a random walk
//!   inside the range the exchange can hold;
//! - the signed-head header names are the sequencer's HTTP contract, and they
//!   live in `wire.rs` with the rest of what a reader takes off the sequencer.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// The trading pairs the sequencer publishes, with the mid price each one
/// starts at and the price step each one opens on. A price is counted in the
/// second token of the pair, so an `ETH-USDC` price is USDC per ETH.
///
/// # Why the step is here and not one number shared by every market
///
/// The step used to be `0.01` for all three. The mids differ by a hundred
/// times, so the same step meant three different markets. The generator prices
/// within ±0.5% of the mid. That band held 10 steps at a mid of 10, and 1000
/// steps at a mid of 1000. At 10 steps the orders land on a few prices and
/// cross each other. At 1000 they spread out and never meet, so BTC-USDC and
/// ETH-USDC both grew to `MAX_BOOK_DEPTH` resting orders while MERKLE-USDC
/// held 60 bids and 330 asks.
///
/// The steps below put about 10 steps in every generator band and about 1000
/// steps in every price, so all three books behave the same way.
///
/// **Nothing that decides how a message executes reads this any more.** The
/// engine asks its symbol registry, built from the log's `ListSymbol` and
/// `DelistSymbol` messages, so a replay gives every build the same answer.
/// See `matcher::SymbolRegistry`.
///
/// What still reads this constant is configuration and service policy. None of
/// it changes what a message already in the log does:
///
/// - `feed.rs` and `feed/generate.rs` start the invented traffic from it:
///   which orders to invent, at what starting mid, and on what step;
/// - `feed/http.rs` serves it on `/symbols`, and `inbox.rs` refuses a
///   submission that names anything else. That is a filter on the way in, and
///   not the rule. See `inbox::validate_submission` for why the way in must
///   not read a registry that can change between intake and sequencing.
///   `docker/open-the-log.sh` reads the step off that endpoint, so the step is
///   named here and nowhere else;
/// - `bot.rs` picks the markets it quotes from it, and `main.rs` checks
///   `--bot-caps` against it.
///
/// This constant can go once the generator is told its symbols another way,
/// and the way in gets the listed set from something other than a constant.
pub const SYMBOLS: [(&str, f64, f64); 3] = [
    ("MERKLE-USDC", 10.0, 0.01),
    ("ETH-USDC", 100.0, 0.10),
    ("BTC-USDC", 1000.0, 1.00),
];

/// The largest value `to_grid` accepts, for a price and for a quantity. A
/// price of 10 million USDC, or a quantity of 100 million units, is far beyond
/// anything this sequencer produces.
///
/// This limit bounds one fill. At the limit, quantity times price is 1e18
/// mills, inside i64's 9.2e18. It does not bound the running totals a position
/// keeps. `cash_mills`, `cost_basis_mills` and `net_qty_tenths` grow with every
/// fill, and two fills at the limit are already past i64. Those totals are
/// therefore carried with checked arithmetic, see `Position::after_fill` in
/// `matcher.rs`, and a fill that would leave the range is refused rather than
/// wrapped round.
pub const MAX_GRID_UNITS: i64 = 1_000_000_000;

/// Turns a value into the whole number a book is kept in, or `None` when the
/// value is not one of those whole numbers. `scale` is 100 for a price (whole
/// cents) and 10 for a quantity (whole tenths).
///
/// # Why the exchange and the checker share this one function
///
/// They write every matching rule twice, so that a disagreement between them
/// is the evidence, ENGINE.md section 5. This function is not one of those
/// rules. It is part of what a price *is*: one reading of one number, before
/// any rule runs on it. A checker that rounded a price differently from the
/// exchange would report an honest exchange the first time a price landed
/// between the two roundings, and the report would name the wrong fault.
///
/// # Why a value this function refuses is not rounded to fit
///
/// The sequencer's generator only produces values this function accepts, but
/// `POST /order` takes any positive `f64`. So a price of 100.253 or a quantity
/// of 0.04 can arrive. Rounding those to fit would change or erase somebody's
/// order without saying so, so they are refused instead. An order the exchange
/// cannot hold exactly must not enter a book.
pub fn to_grid(value: f64, scale: f64) -> Option<i64> {
    let scaled = value * scale;
    if !scaled.is_finite() || (scaled - scaled.round()).abs() > 1e-6 {
        return None;
    }
    // An `f64` too large for `i64` becomes `i64::MAX` on the cast, so the
    // range is checked after the cast and not before it.
    let units = scaled.round() as i64;
    (units > 0 && units <= MAX_GRID_UNITS).then_some(units)
}

/// Whether the order names the price it will trade at, or takes whatever the
/// book is showing.
///
/// # Why the default variant is not written on the wire
///
/// Every message published so far is a limit order, and none of them carries
/// this field. `Limit` is therefore what an absent field means, and
/// `skip_serializing_if` on the field that holds it makes a limit order write
/// no bytes at all. The two directions agree: absent means `Limit`, and
/// `Limit` writes nothing.
///
/// A value this build does not know, an order type added after this build was
/// compiled, fails to deserialize. `wire.rs` reports that as `TooOld`, and
/// ENGINE.md section 6 calls it "cannot interpret". That is the answer this
/// design wants. The value is never read as `Limit` without saying so.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
pub enum OrderType {
    /// The order names the worst price it will accept and rests at it.
    #[default]
    Limit,
    /// The order takes what the book offers. ENGINE.md section 4.2: the server
    /// works out the bound and the client signs it, so what arrives here is a
    /// limit order carrying that bound and priced to trade at once.
    Market,
}

impl OrderType {
    /// True for the reading of an absent field. Named in `skip_serializing_if`
    /// on `OrderMessage::New::order_type`, which is why it takes `&self`.
    pub fn is_limit(&self) -> bool {
        matches!(self, OrderType::Limit)
    }
}

/// How long the order stays alive once it has crossed everything it can.
///
/// The same absent-means-default rule as `OrderType`: every message published
/// so far rests its remainder, so `GoodTillCancel` writes no bytes.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeInForce {
    /// The remainder rests in the book until it fills or somebody cancels it.
    /// That is what every order the sequencer published has done since the log
    /// began.
    #[default]
    GoodTillCancel,
    /// The remainder is dropped. The sender keeps only what already filled.
    ImmediateOrCancel,
    /// The whole quantity fills, or none of it does. ENGINE.md section 4.0:
    /// the question is decided *before* the book is touched and not after,
    /// because once step 5 has booked the fills there is nothing left to kill.
    FillOrKill,
}

impl TimeInForce {
    /// True for the reading of an absent field. Named in
    /// `skip_serializing_if` on `OrderMessage::New::time_in_force`.
    pub fn is_good_till_cancel(&self) -> bool {
        matches!(self, TimeInForce::GoodTillCancel)
    }
}

/// True when `post_only` is off, which is the reading of an absent field.
///
/// A free function rather than a method because `bool` is not this crate's
/// type. It is named in `skip_serializing_if` on
/// `OrderMessage::New::post_only`, so a message that is not post-only writes
/// no bytes for it.
///
/// `inbox::Submission::Order` names it too, and for the same reason. A
/// submission that asks for no term writes exactly the bytes it wrote before
/// the terms existed, so a row already in an `inbox.db` reads back unchanged.
pub(crate) fn not_post_only(post_only: &bool) -> bool {
    !*post_only
}

/// Which way an order goes: a buy or a sell.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Buy,
    Sell,
}

/// Reads a `Side` out of a string. Upper case and lower case both work, and
/// one letter is enough: `B` is a buy and `S` is a sell.
impl FromStr for Side {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "BUY" | "BID" | "B" => Ok(Side::Buy),
            "SELL" | "ASK" | "S" => Ok(Side::Sell),
            _ => Err(format!("'{}' is not a valid side", s)),
        }
    }
}

/// The number that names one account.
pub type AccountId = u32;

/// The number that names one message, and the order that message carries. The
/// numbers only go up across the whole log, and they start at 1.
pub type OrderId = u64;

/// The account written on `EngineRule`, `ListSymbol` and `DelistSymbol`.
///
/// The owner of the exchange publishes these three kinds, and no trader does.
/// They hold no position and nobody can cancel them, so the account on them
/// names nobody. The field is still there because `wire::envelope` reads an
/// account out of every message, and a message with no account key at all
/// would make that reader answer `None` for a kind that is otherwise complete.
///
/// One fixed value keeps the sequencer's `(account, nonce)` map working for
/// operator messages. Every operator message lands in the same row of that
/// map, so one signed statement becomes one message in one log. `u32::MAX` is
/// outside the range the traffic generator and the separate service hand out,
/// so it can never be a trader's account.
pub const OPERATOR_ACCOUNT: AccountId = u32::MAX;

/// The kinds of message the sequencer publishes.
///
/// # The nonce field
///
/// `nonce` is the submitter's replay nonce. It is carried on the published
/// message and not kept in a table beside it. That has two results, and both
/// are deliberate.
///
/// The nonce is inside the hash chain. So the record of which nonces have been
/// used gets the same protection the history already has. An operator who
/// deletes or edits a nonce to reopen a replay is caught by the same
/// checkpoint check as any other edit to `feed_messages`. See
/// `FeedState::with_db`. A separate table would have needed protection of its
/// own, and deleting that table would have left no trace.
///
/// The field is an `Option` with `skip_serializing_if`. So a message that
/// never had a nonce writes exactly the bytes it wrote before. That covers
/// every message the generator publishes, and everything published before this
/// field existed. That is not tidiness; the whole log rests on it. The chain
/// is built by hashing `serde_json::to_vec(message)` for each message in turn,
/// so a message whose JSON gained a `"nonce": null` would produce a different
/// chain from the one the sequencer signed. Every deployed `feed.db` would
/// then fail its checkpoint check and refuse to start.
///
/// # Why this is not the envelope of ENGINE.md section 2
///
/// Section 2 asks for `{"v":1,"id":…,"account":…,"nonce":…,"body":{"New":{…}}}`,
/// so that a reader gets the version, the id, the account and the nonce
/// without understanding `body`. This type is not that shape, and it cannot
/// become that shape while the current session is running. The reason is one
/// message:
///
/// ```text
/// {"New":{"id":1,"timestamp":1786752446786,"account":6,"symbol":"BTC-USDC","side":"Buy","price":997.16,"quantity":2.0}}
/// ```
///
/// Those 115 bytes are message 1 of session `349d462ced25bb2b`. Their leaf
/// hash is `SHA-256(0x00 || those bytes)`, and it is under the root the
/// sequencer signs and the anchor contract holds on Base. The envelope shape
/// of the same message is a different byte string, so a different leaf, so a
/// different root.
///
/// Serving is not the problem. The sequencer serves its stored bytes and never
/// writes them again. `Deserialize` is the problem. There is one
/// `OrderMessage`, and if it expects the envelope then
/// `raw.parse::<OrderMessage>()` fails on every one of the 126,989 messages
/// already in the log. The engine, the checker, the bot and the separate
/// service would all stop at message 1 and report cannot-interpret. Accepting
/// both shapes instead would give every message two spellings, and
/// `Serialize` has to pick one of them. An old message read and written back
/// would then no longer be its own bytes, and the log would hold both
/// spellings forever.
///
/// So the envelope lands at the clean genesis of PLAN.md step 5, where there
/// is no history to keep. What lands now is everything the envelope was for
/// that does not change a byte: the id, the account and the nonce are read out
/// of a message's bytes by one function, `wire::envelope`, which `feed.rs` and
/// `inbox.rs` both call instead of each guessing at the layout themselves.
///
/// # The three order-terms fields on `New`
///
/// `order_type`, `time_in_force` and `post_only` follow the same rule as
/// `nonce`, and for the same reason. Each has a default, and that default is
/// what every message published before the field existed meant. Each is
/// skipped when it holds that default. A `New` that names none of them writes
/// exactly the bytes it wrote before they existed. That is the byte string the
/// sequencer already hashed into its chain, into the Merkle tree, and into the
/// anchor on Base.
///
/// They are three fields and not one `Option<OrderTerms>` object. Both shapes
/// cost nothing for a message that names none of them, so the common case is a
/// tie, and the two uncommon cases decide it:
///
/// ```text
/// three fields   {"id":1,...,"order_type":"Market","time_in_force":"ImmediateOrCancel"}
/// one object     {"id":1,...,"terms":{"order_type":"Market","time_in_force":"ImmediateOrCancel"}}
/// ```
///
/// The object pays ten bytes for the wrapper on every order that names
/// anything, and it adds a way of writing an order that means nothing new. An
/// empty `"terms":{}` is the same order as no `terms` at all. Three fields,
/// each holding a value and not an `Option`, give each term exactly one
/// spelling per meaning. This build cannot also write a limit order as
/// `"order_type":"Limit"`, because `skip_serializing_if` drops that field.
///
/// # The kinds after `Cancel`
///
/// `EngineRule`, `ListSymbol` and `DelistSymbol` are new variants. Adding a
/// variant to an externally tagged enum changes nothing about how the variants
/// beside it write themselves. `New` still writes `{"New":{...}}`, byte for
/// byte. That is what lets this format grow at all. The tests at the bottom of
/// this file check it instead of trusting it.
///
/// All three carry `public_key` and `signature`, and both are a plain `String`
/// and not an `Option<String>`. Only the owner of the exchange may open a
/// market, close one, or change the rule set, so a message of these kinds with
/// no signature means nothing. Neither field has ever been absent, because no
/// message of these kinds has ever been published; nothing in this repository
/// could publish one before. `operator.rs` builds the bytes the signature
/// covers, and `operator::verify` checks it.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OrderMessage {
    /// A new order entering the market.
    New {
        id: OrderId,
        timestamp: u64,
        account: AccountId,
        symbol: String,
        side: Side,
        price: f64,
        quantity: f64,
        /// The submitter's replay nonce. `None` is generated traffic, which
        /// nobody signed and nobody can replay into anything.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
        /// Limit or market. Absent means `Limit`, which is what every message
        /// published before this field existed was. Read by matching steps 2,
        /// 3 and 6.
        #[serde(default, skip_serializing_if = "OrderType::is_limit")]
        order_type: OrderType,
        /// What happens to the part that does not fill. Absent means
        /// `GoodTillCancel`, which is what the exchange has always done. Read
        /// by matching steps 2 and 6.
        #[serde(default, skip_serializing_if = "TimeInForce::is_good_till_cancel")]
        time_in_force: TimeInForce,
        /// Refuse the order rather than let it trade at once against something
        /// already resting. Absent means `false`. It is a plain `bool` and not
        /// an `Option<bool>` on purpose. `Some(false)` and `None` would be the
        /// same order written two ways, and one of the two would sit in the
        /// log forever.
        #[serde(default, skip_serializing_if = "not_post_only")]
        post_only: bool,
    },
    /// A request to cancel an order placed earlier. `target_id` is the `id` of
    /// the order to cancel.
    Cancel {
        id: OrderId,
        timestamp: u64,
        account: AccountId,
        target_id: OrderId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
    },
    /// The rule set the messages after this one run under.
    ///
    /// ENGINE.md section 3: the log opens by stating its own rules, so that
    /// nothing which changes a result lives in a binary or a configuration
    /// file. `version` names the rule set. What each version means is written
    /// where the rule is implemented, and not here.
    EngineRule {
        id: OrderId,
        timestamp: u64,
        /// Always `OPERATOR_ACCOUNT`. The owner publishes this kind, so the
        /// account names nobody. The field is here because `wire::envelope`
        /// reads an account out of every message.
        account: AccountId,
        /// The rule set number. Version 1 is the rules the log has run under
        /// since message 1.
        version: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
        /// The operator's Ed25519 public key, 64 hex characters.
        public_key: String,
        /// The signature over `operator::operator_statement`, 128 hex
        /// characters.
        signature: String,
    },
    /// A symbol becomes tradable, with the steps its prices and quantities
    /// must be whole numbers of.
    ///
    /// This message is what replaces the `SYMBOLS` constant above. A registry
    /// built from these messages is state a replay reproduces. A constant is
    /// not.
    ListSymbol {
        id: OrderId,
        timestamp: u64,
        /// Always `OPERATOR_ACCOUNT`. The owner publishes this kind, so the
        /// account names nobody. The field is here because `wire::envelope`
        /// reads an account out of every message.
        account: AccountId,
        symbol: String,
        /// The smallest price difference, in the quote token: `0.01` means
        /// prices are whole cents. Matching step 1 turns a price into a whole
        /// number of these.
        price_step: f64,
        /// The smallest quantity difference, in the base token: `0.1` means
        /// quantities are whole tenths.
        quantity_step: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
        /// The operator's Ed25519 public key, 64 hex characters.
        public_key: String,
        /// The signature over `operator::operator_statement`, 128 hex
        /// characters.
        signature: String,
    },
    /// A symbol stops being tradable.
    ///
    /// ENGINE.md section 3: this message cancels every resting order in that
    /// book, because a resting order that can never fill is worse than no
    /// order. That cancelling is not one of the six matching steps. See
    /// section 4.0.
    DelistSymbol {
        id: OrderId,
        timestamp: u64,
        /// Always `OPERATOR_ACCOUNT`. The owner publishes this kind, so the
        /// account names nobody. The field is here because `wire::envelope`
        /// reads an account out of every message.
        account: AccountId,
        symbol: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
        /// The operator's Ed25519 public key, 64 hex characters.
        public_key: String,
        /// The signature over `operator::operator_statement`, 128 hex
        /// characters.
        signature: String,
    },
}

impl OrderMessage {
    /// The message's own position in the log.
    pub fn id(&self) -> OrderId {
        match self {
            OrderMessage::New { id, .. }
            | OrderMessage::Cancel { id, .. }
            | OrderMessage::EngineRule { id, .. }
            | OrderMessage::ListSymbol { id, .. }
            | OrderMessage::DelistSymbol { id, .. } => *id,
        }
    }

    /// The account this message is under.
    pub fn account(&self) -> AccountId {
        match self {
            OrderMessage::New { account, .. }
            | OrderMessage::Cancel { account, .. }
            | OrderMessage::EngineRule { account, .. }
            | OrderMessage::ListSymbol { account, .. }
            | OrderMessage::DelistSymbol { account, .. } => *account,
        }
    }

    /// The submitter's replay nonce, if this message came from a signed
    /// submission.
    pub fn nonce(&self) -> Option<&str> {
        match self {
            OrderMessage::New { nonce, .. }
            | OrderMessage::Cancel { nonce, .. }
            | OrderMessage::EngineRule { nonce, .. }
            | OrderMessage::ListSymbol { nonce, .. }
            | OrderMessage::DelistSymbol { nonce, .. } => nonce.as_deref(),
        }
    }
}

/// What `wire::read_ndjson` reads out of a message it has just parsed, instead
/// of parsing the same bytes a second time to find it.
///
/// serde writes this enum as an object with one key, and that key is the
/// variant name. So the five strings below are the five map keys on the wire.
/// `wire::envelope` reads the same key as the kind, and the two readings must
/// agree. A message that reported `New` before it was parsed and something
/// else after would put two kinds on one id.
/// `the_kind_is_the_key_in_the_bytes` checks every variant.
impl crate::wire::Interpreted for OrderMessage {
    fn id(&self) -> OrderId {
        OrderMessage::id(self)
    }

    fn kind(&self) -> &'static str {
        match self {
            OrderMessage::New { .. } => "New",
            OrderMessage::Cancel { .. } => "Cancel",
            OrderMessage::EngineRule { .. } => "EngineRule",
            OrderMessage::ListSymbol { .. } => "ListSymbol",
            OrderMessage::DelistSymbol { .. } => "DelistSymbol",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Three messages copied out of the running feed, byte for byte:
    //
    //     curl -s 'https://feed.exchange.th3nolo.com/messages.ndjson?since=0&limit=500'
    //
    // Their bytes are leaves of the Merkle tree the sequencer signs, and they
    // are inside the root written to Base. If this build writes any of them
    // differently, every published inclusion proof over them stops verifying,
    // and every deployed `feed.db` fails its checkpoint check on start. The
    // whole 500-message page is checked in `logchain.rs`. These three are here
    // because this is the file that decides their bytes.
    const LIVE_FIRST_ORDER: &str = r#"{"New":{"id":1,"timestamp":1786752446786,"account":6,"symbol":"BTC-USDC","side":"Buy","price":997.16,"quantity":2.0}}"#;
    const LIVE_CANCEL: &str =
        r#"{"Cancel":{"id":43,"timestamp":1786752468881,"account":19,"target_id":42}}"#;
    const LIVE_SIGNED_ORDER: &str = r#"{"New":{"id":53,"timestamp":1786752473591,"account":999,"symbol":"MERKLE-USDC","side":"Buy","price":9.99,"quantity":7.4,"nonce":"46fead7bf58190d5db8ff23c0d22e4ca"}}"#;

    // The two operator fields, as shapes and not as a real key pair. This file
    // decides where the fields sit in the bytes, and `operator.rs` decides
    // what a good signature is. 64 hex characters and 128 hex characters.
    const OPERATOR_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OPERATOR_SIGNATURE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// The most important test in this file. Every message already in the log
    /// still writes the bytes it was written with.
    #[test]
    fn a_published_message_serializes_to_the_bytes_the_feed_published() {
        for published in [LIVE_FIRST_ORDER, LIVE_CANCEL, LIVE_SIGNED_ORDER] {
            let message: OrderMessage =
                serde_json::from_str(published).expect("this build reads what the feed published");
            assert_eq!(
                serde_json::to_string(&message).expect("it serializes"),
                published,
                "the three order-terms fields changed how an existing message serializes"
            );
        }
    }

    /// The writing side of the same claim. A `New` this build makes without
    /// naming any of the three terms is the byte string the sequencer wrote
    /// before the three terms existed.
    #[test]
    fn an_order_that_names_no_term_is_written_as_it_was_before_the_terms_existed() {
        let order = OrderMessage::New {
            id: 1,
            timestamp: 1786752446786,
            account: 6,
            symbol: "BTC-USDC".to_string(),
            side: Side::Buy,
            price: 997.16,
            quantity: 2.0,
            nonce: None,
            order_type: OrderType::Limit,
            time_in_force: TimeInForce::GoodTillCancel,
            post_only: false,
        };
        assert_eq!(
            serde_json::to_string(&order).expect("it serializes"),
            LIVE_FIRST_ORDER
        );
    }

    /// Every shape the three new terms can take, counted and not sampled.
    ///
    /// Two order types, times three times in force, times two post-only
    /// values, is twelve orders. All twelve are here in order, with the exact
    /// bytes each one writes. Nothing here is generated from the same rule the
    /// code uses, because a table generated that way agrees with a wrong rule.
    ///
    /// The first row is the one the anchors depend on. An order at all three
    /// defaults writes no field for any of them, and that is why it is the
    /// byte string the sequencer has been publishing since message 1.
    #[test]
    fn all_twelve_shapes_of_the_three_terms_write_and_read_back_exactly() {
        let shapes = [
            (OrderType::Limit, TimeInForce::GoodTillCancel, false, ""),
            (
                OrderType::Limit,
                TimeInForce::GoodTillCancel,
                true,
                r#","post_only":true"#,
            ),
            (
                OrderType::Limit,
                TimeInForce::ImmediateOrCancel,
                false,
                r#","time_in_force":"ImmediateOrCancel""#,
            ),
            (
                OrderType::Limit,
                TimeInForce::ImmediateOrCancel,
                true,
                r#","time_in_force":"ImmediateOrCancel","post_only":true"#,
            ),
            (
                OrderType::Limit,
                TimeInForce::FillOrKill,
                false,
                r#","time_in_force":"FillOrKill""#,
            ),
            (
                OrderType::Limit,
                TimeInForce::FillOrKill,
                true,
                r#","time_in_force":"FillOrKill","post_only":true"#,
            ),
            (
                OrderType::Market,
                TimeInForce::GoodTillCancel,
                false,
                r#","order_type":"Market""#,
            ),
            (
                OrderType::Market,
                TimeInForce::GoodTillCancel,
                true,
                r#","order_type":"Market","post_only":true"#,
            ),
            (
                OrderType::Market,
                TimeInForce::ImmediateOrCancel,
                false,
                r#","order_type":"Market","time_in_force":"ImmediateOrCancel""#,
            ),
            (
                OrderType::Market,
                TimeInForce::ImmediateOrCancel,
                true,
                r#","order_type":"Market","time_in_force":"ImmediateOrCancel","post_only":true"#,
            ),
            (
                OrderType::Market,
                TimeInForce::FillOrKill,
                false,
                r#","order_type":"Market","time_in_force":"FillOrKill""#,
            ),
            (
                OrderType::Market,
                TimeInForce::FillOrKill,
                true,
                r#","order_type":"Market","time_in_force":"FillOrKill","post_only":true"#,
            ),
        ];
        assert_eq!(
            shapes.len(),
            12,
            "two order types, three tif, two post-only"
        );

        for (shape, (order_type, time_in_force, post_only, terms)) in shapes.into_iter().enumerate()
        {
            let order = OrderMessage::New {
                id: 1,
                timestamp: 1786752446786,
                account: 6,
                symbol: "BTC-USDC".to_string(),
                side: Side::Buy,
                price: 997.16,
                quantity: 2.0,
                nonce: None,
                order_type,
                time_in_force,
                post_only,
            };
            let expected = format!(
                r#"{{"New":{{"id":1,"timestamp":1786752446786,"account":6,"symbol":"BTC-USDC","side":"Buy","price":997.16,"quantity":2.0{}}}}}"#,
                terms
            );
            let written = serde_json::to_string(&order).expect("it serializes");
            assert_eq!(written, expected, "shape {} writes the wrong bytes", shape);

            // And back: reading those bytes and writing them again is the same
            // byte string, so no shape has two spellings.
            let read: OrderMessage = serde_json::from_str(&written).expect("it reads back");
            assert_eq!(
                serde_json::to_string(&read).expect("it serializes"),
                expected,
                "shape {} does not round-trip",
                shape
            );
            let OrderMessage::New {
                order_type: read_type,
                time_in_force: read_tif,
                post_only: read_post_only,
                ..
            } = read
            else {
                panic!("shape {} came back as a different kind", shape);
            };
            assert_eq!(
                (read_type, read_tif, read_post_only),
                (order_type, time_in_force, post_only),
                "shape {} came back meaning something else",
                shape
            );
        }
    }

    /// Each of the five kinds writes its own one-key object, and reading one
    /// back gives the same bytes. Counted, not sampled: every kind this build
    /// knows is in this list.
    ///
    /// The `New` and the `Cancel` rows hold the two byte strings the sequencer
    /// published, so the two operator fields added to the three kinds below
    /// them cannot have moved a byte of a message already in the log.
    #[test]
    fn every_kind_writes_its_own_object_and_reads_back_byte_for_byte() {
        let kinds = [
            (
                OrderMessage::New {
                    id: 1,
                    timestamp: 1786752446786,
                    account: 6,
                    symbol: "BTC-USDC".to_string(),
                    side: Side::Buy,
                    price: 997.16,
                    quantity: 2.0,
                    nonce: None,
                    order_type: OrderType::Limit,
                    time_in_force: TimeInForce::GoodTillCancel,
                    post_only: false,
                },
                LIVE_FIRST_ORDER,
            ),
            (
                OrderMessage::Cancel {
                    id: 43,
                    timestamp: 1786752468881,
                    account: 19,
                    target_id: 42,
                    nonce: None,
                },
                LIVE_CANCEL,
            ),
            (
                OrderMessage::EngineRule {
                    id: 1,
                    timestamp: 1786752446786,
                    account: OPERATOR_ACCOUNT,
                    version: 1,
                    nonce: None,
                    public_key: OPERATOR_KEY.to_string(),
                    signature: OPERATOR_SIGNATURE.to_string(),
                },
                r#"{"EngineRule":{"id":1,"timestamp":1786752446786,"account":4294967295,"version":1,"public_key":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","signature":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}"#,
            ),
            (
                OrderMessage::ListSymbol {
                    id: 2,
                    timestamp: 1786752446786,
                    account: OPERATOR_ACCOUNT,
                    symbol: "ALFA-USD".to_string(),
                    price_step: 0.01,
                    quantity_step: 0.1,
                    nonce: None,
                    public_key: OPERATOR_KEY.to_string(),
                    signature: OPERATOR_SIGNATURE.to_string(),
                },
                r#"{"ListSymbol":{"id":2,"timestamp":1786752446786,"account":4294967295,"symbol":"ALFA-USD","price_step":0.01,"quantity_step":0.1,"public_key":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","signature":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}"#,
            ),
            (
                OrderMessage::DelistSymbol {
                    id: 3,
                    timestamp: 1786752446786,
                    account: OPERATOR_ACCOUNT,
                    symbol: "ALFA-USD".to_string(),
                    nonce: Some("46fead7bf58190d5db8ff23c0d22e4ca".to_string()),
                    public_key: OPERATOR_KEY.to_string(),
                    signature: OPERATOR_SIGNATURE.to_string(),
                },
                r#"{"DelistSymbol":{"id":3,"timestamp":1786752446786,"account":4294967295,"symbol":"ALFA-USD","nonce":"46fead7bf58190d5db8ff23c0d22e4ca","public_key":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","signature":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}"#,
            ),
        ];
        assert_eq!(
            kinds.len(),
            5,
            "every kind this build knows is checked here"
        );

        for (kind, (message, expected)) in kinds.into_iter().enumerate() {
            let written = serde_json::to_string(&message).expect("it serializes");
            assert_eq!(written, expected, "kind {} writes the wrong bytes", kind);
            let read: OrderMessage = serde_json::from_str(&written).expect("it reads back");
            assert_eq!(
                serde_json::to_string(&read).expect("it serializes"),
                expected,
                "kind {} does not round-trip",
                kind
            );
        }
    }

    /// Every kind carries a nonce, and every kind answers the three questions
    /// the envelope of ENGINE.md section 2 exists to answer, without the
    /// caller knowing which kind it is holding.
    ///
    /// Account 11 is a probe value, not what an operator message carries. The
    /// three operator kinds are published under `OPERATOR_ACCOUNT`; this test
    /// checks that the accessor returns whatever is on the message, so it uses
    /// one value for all five kinds.
    #[test]
    fn every_kind_answers_the_three_envelope_questions() {
        let nonce = "46fead7bf58190d5db8ff23c0d22e4ca";
        let kinds = every_kind();
        assert_eq!(kinds.len(), 5);
        for (kind, message) in kinds.into_iter().enumerate() {
            assert_eq!(message.id(), 7, "kind {} lost its id", kind);
            assert_eq!(message.account(), 11, "kind {} lost its account", kind);
            assert_eq!(message.nonce(), Some(nonce), "kind {} lost its nonce", kind);
        }
    }

    /// One message of every kind this build knows, all with the same id, the
    /// same account and the same nonce.
    fn every_kind() -> [OrderMessage; 5] {
        let nonce = "46fead7bf58190d5db8ff23c0d22e4ca";
        [
            OrderMessage::New {
                id: 7,
                timestamp: 1,
                account: 11,
                symbol: "ALFA-USD".to_string(),
                side: Side::Buy,
                price: 1.0,
                quantity: 1.0,
                nonce: Some(nonce.to_string()),
                order_type: OrderType::Limit,
                time_in_force: TimeInForce::GoodTillCancel,
                post_only: false,
            },
            OrderMessage::Cancel {
                id: 7,
                timestamp: 1,
                account: 11,
                target_id: 6,
                nonce: Some(nonce.to_string()),
            },
            OrderMessage::EngineRule {
                id: 7,
                timestamp: 1,
                account: 11,
                version: 1,
                nonce: Some(nonce.to_string()),
                public_key: OPERATOR_KEY.to_string(),
                signature: OPERATOR_SIGNATURE.to_string(),
            },
            OrderMessage::ListSymbol {
                id: 7,
                timestamp: 1,
                account: 11,
                symbol: "ALFA-USD".to_string(),
                price_step: 0.01,
                quantity_step: 0.1,
                nonce: Some(nonce.to_string()),
                public_key: OPERATOR_KEY.to_string(),
                signature: OPERATOR_SIGNATURE.to_string(),
            },
            OrderMessage::DelistSymbol {
                id: 7,
                timestamp: 1,
                account: 11,
                symbol: "ALFA-USD".to_string(),
                nonce: Some(nonce.to_string()),
                public_key: OPERATOR_KEY.to_string(),
                signature: OPERATOR_SIGNATURE.to_string(),
            },
        ]
    }

    /// `Interpreted::kind` names the key the bytes carry.
    ///
    /// `wire::read_ndjson` takes the kind from the parsed message and
    /// `wire::envelope` takes it from the map key. A kind read one way and not
    /// the other would put two names on one message. An operator would then
    /// read "cannot interpret message 7, which the feed published as a 'New'
    /// message" for a `Cancel`. This test walks every kind and compares the
    /// two readings.
    #[test]
    fn the_kind_is_the_key_in_the_bytes() {
        use crate::wire::{self, Interpreted};
        for message in every_kind() {
            let bytes = crate::logchain::canonical_bytes(&message);
            let read = wire::envelope(&bytes).expect("this build wrote it");
            assert_eq!(
                read.kind,
                Interpreted::kind(&message),
                "the two readings of {} disagree",
                String::from_utf8_lossy(&bytes)
            );
            assert_eq!(read.id, Interpreted::id(&message));
        }
    }

    /// A term this build was compiled before is not read as the default. It
    /// fails to parse, which `wire.rs` reports as `TooOld` and ENGINE.md
    /// section 6 calls "cannot interpret", the answer that stops a program
    /// acting on a message it does not understand.
    #[test]
    fn an_unknown_order_term_is_not_read_as_the_default() {
        let newer = r#"{"New":{"id":1,"timestamp":1786752446786,"account":6,"symbol":"BTC-USDC","side":"Buy","price":997.16,"quantity":2.0,"time_in_force":"GoodTillDate"}}"#;
        assert!(serde_json::from_str::<OrderMessage>(newer).is_err());
        let newer = r#"{"New":{"id":1,"timestamp":1786752446786,"account":6,"symbol":"BTC-USDC","side":"Buy","price":997.16,"quantity":2.0,"order_type":"Iceberg"}}"#;
        assert!(serde_json::from_str::<OrderMessage>(newer).is_err());
    }

    /// A field this build was compiled before is skipped. That is what lets a
    /// reader keep hashing a history it cannot fully act on. It is the same
    /// rule as `wire.rs`'s envelope, checked here on the typed reading.
    #[test]
    fn a_field_this_build_does_not_know_is_ignored() {
        let newer = r#"{"New":{"id":1,"timestamp":1786752446786,"account":6,"symbol":"BTC-USDC","side":"Buy","price":997.16,"quantity":2.0,"display_qty":0.5}}"#;
        let message: OrderMessage = serde_json::from_str(newer).expect("this build still reads it");
        assert_eq!(
            serde_json::to_string(&message).expect("it serializes"),
            LIVE_FIRST_ORDER
        );
    }

    /// The edges of the grid. The exchange, the separate service and the
    /// checker all read a price through this one function, so the cases are
    /// stated here once instead of three times.
    #[test]
    fn a_value_on_the_grid_is_accepted_and_a_value_off_it_is_not() {
        assert_eq!(to_grid(100.25, 100.0), Some(10025));
        assert_eq!(to_grid(0.1, 10.0), Some(1)); // smallest legal quantity
        assert_eq!(to_grid(0.01, 100.0), Some(1)); // smallest legal price
        assert_eq!(to_grid(100.253, 100.0), None); // finer than one cent
        assert_eq!(to_grid(0.04, 10.0), None); // finer than one tenth
        assert_eq!(to_grid(0.0, 10.0), None); // zero is not a quantity
        assert_eq!(to_grid(-5.0, 10.0), None); // nor is a negative one
        assert_eq!(to_grid(f64::INFINITY, 10.0), None);
        assert_eq!(to_grid(f64::NAN, 100.0), None);
    }

    /// The limit itself is accepted and one unit past it is not. None of the
    /// three copies this function replaced checked either side of it.
    #[test]
    fn the_largest_value_the_grid_takes_is_max_grid_units() {
        let largest_price = MAX_GRID_UNITS as f64 / 100.0;
        assert_eq!(to_grid(largest_price, 100.0), Some(MAX_GRID_UNITS));
        assert_eq!(to_grid(largest_price + 0.01, 100.0), None);

        let largest_quantity = MAX_GRID_UNITS as f64 / 10.0;
        assert_eq!(to_grid(largest_quantity, 10.0), Some(MAX_GRID_UNITS));
        assert_eq!(to_grid(largest_quantity + 0.1, 10.0), None);
    }

    /// The saturating cast the body's comment names. A float above i64's range
    /// is finite and is a whole number, so it passes both earlier checks and
    /// reaches the cast. The cast pins it to `i64::MAX`, and the range check
    /// after the cast is what refuses it. A range check before the cast would
    /// read a wrapped value instead.
    #[test]
    fn a_value_too_large_for_i64_is_refused_after_the_cast() {
        assert_eq!(1e32_f64 as i64, i64::MAX);
        assert_eq!(to_grid(1e30, 100.0), None);
        assert_eq!(-1e32_f64 as i64, i64::MIN);
        assert_eq!(to_grid(-1e30, 100.0), None);
    }
}
