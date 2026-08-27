//! The checker. The checker runs the sequencer's messages again with its own
//! code, and compares the result with the trades the exchange recorded.
//!
//! The checker shares no matching rule with `matcher`. The checker reads the
//! trades from the state database with its own SQL. The checker reads the
//! messages from the sequencer's own history. From those two records alone,
//! the checker works out every claim again. A checker built on the exchange's
//! code would agree with the exchange about anything the exchange got wrong.
//! This checker can disagree.
//!
//! Four words come back all through this file. The book is the set of orders
//! that wait to trade. A resting order is an order that waits in the book. A
//! trade has two orders: the maker was already waiting in the book, and the
//! taker arrived and traded against the book. A fill is the part of an order
//! that traded.
//!
//! # What is shared, and what is written twice
//!
//! One reading is shared: `domain::to_grid`, with the limit
//! `domain::MAX_GRID_UNITS` beside it. `to_grid` turns a price or a quantity
//! into the whole cents and whole tenths the book holds. That is what a price
//! is. That is not a rule about what to do with a price. So both sides must
//! read a number the same way. A checker that rounded a price differently
//! would accuse an honest exchange. It would do so the first time a price
//! landed between the two roundings.
//!
//! `operator` is shared for the same reason, and so is `fetch`. `fetch`
//! supplies how to read a body of bounded size over HTTP: the timeouts, the
//! client, the size cap, and the sentence an error turns into. `fetch` never
//! supplies what the body means. A body that `fetch` cut short hashes to a
//! chain that does not match the signed head. The checker then fails and says
//! so, instead of agreeing with a wrong answer.
//!
//! `merkle` is shared for the same reason again. `merkle` supplies the
//! RFC 9162 arithmetic that turns message bytes into one root hash. `merkle`
//! never supplies a rule about what a message means. A second copy of that
//! arithmetic would catch nothing. The root the second copy produced would
//! disagree with the sequencer's root on every honest history, and the report
//! would name the wrong fault. `merkle` is used by `check_tree` in
//! `reporting.rs`. `check_tree` compares the root these messages make against
//! the root the sequencer signs at `/sth`, and against every root an anchor
//! sender wrote to a public chain.
//!
//! Every rule built on top of that shared reading is written twice. Once in
//! the exchange, and once here. The two copies are meant to be able to
//! disagree:
//!
//! - whether the log had the symbol open on these steps: `verify/listings.rs`
//!   against `matcher`'s `SymbolRegistry`;
//! - what the order terms allow: `verify/order_terms.rs` against steps 2, 3
//!   and 6 of the pipeline;
//! - the rule that stops one account trading with itself:
//!   `verify/self_trade.rs` against step 4;
//! - which resting order trades first, and at which price: the replayed book
//!   in this file against step 5. The exchange takes the best price first.
//!   Among equal prices it takes the order that arrived first.
//!
//! ENGINE.md section 5 says the same.
//!
//! Every check asks about a mistake an exchange must never make. Did the
//! exchange invent an order that nobody sent? Did the exchange trade an order
//! at a price the account never agreed to? Did the exchange trade one order
//! twice? Did money appear from nowhere?
//!
//! The checker walks the sequencer's history in pages of bounded size, and
//! keeps no page. The checker used to work another way. It collected every
//! message the sequencer had ever published into one vector. It indexed every
//! order and every cancel in that vector. Only then did it check anything.
//! That cost 272 bytes a message, measured. A year at the default rate is 63
//! million messages, so a year needed 17 GB, well beyond the deployment's
//! memory budget. The checker now keeps only what the checks ask about: the
//! orders the trade record has not finished with, the orders still resting in
//! the rebuilt book, a running hash chain, the right edge of the Merkle tree, a
//! count of
//! duplicates, and the cancels that name one of those orders. None of those
//! grows with the length of the history. That change alone was measured at 0.8
//! bytes a message across a 15x range of history lengths. `prove.rs` reads the
//! same endpoint the same way.
//!
//! The trade record used to be read the other way. `read_trades_from_db` read
//! one run's trades into one vector, and four indexes were built over that
//! vector. Together they cost 259 bytes for every message the sequencer had
//! published, measured. Seven days at 24 messages a second needed 3.7 GB, so
//! the checker exceeded the deployment budget before it printed anything.
//! `verify/trades.rs` now reads the same rows in two sequential scans and holds
//! none of them. `services/ROADMAP.md` has the before and after numbers.
//!
//! The checker walks the history twice. The first walk hashes it: the chain
//! the sequencer signs, the log's own tree nodes, and the operator signature
//! over every operator message. It also counts the orders the sequencer
//! published, and the ids it published twice. The second walk rebuilds the
//! book from the same messages, and checks every trade row against the book at
//! the message the row's taker arrived at. The second walk stops at the
//! message the first walk ended on, so both walks cover exactly the same
//! history even though the sequencer keeps publishing.
//!
//! The first walk used to do more. It collected every order the trade record
//! names, with the terms the sequencer published them under, so the second
//! walk could ask about an order it had already gone past. That index was as
//! large as the trade record. The trade record now hands each row to the
//! second walk twice: once at the message that published the row's maker, and
//! once at the message that published the row's taker. The second walk checks
//! the row at whichever of the two comes second, so both orders are in hand
//! and no index of published orders is kept. `verify/trades.rs` states that
//! rule and why.
//!
//! Two walks still buy one thing. A sequencer is free to serve different bytes
//! the second time. The second walk reports that and stops, instead of
//! replaying a book the chain check never covered.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::anchor::RootAnchorSource;
use crate::domain::{AccountId, OrderId, OrderMessage, OrderType, Side, TimeInForce, to_grid};
use crate::fetch::{self, MAX_PAGE_BYTES, read_bounded, reason};
use crate::logchain::Chain;
use crate::wire::{self, RawMessage, TooOld, Verdict};

mod listings;
mod operator_key;
// The checker's copy of the reference price is reachable from the rest of the
// crate. One test needs to run it beside the exchange's copy and compare the
// two prices. Nothing outside a test may call it. The checker is the second
// reading of a rule. A second reading that shares code with the exchange
// cannot disagree with the exchange.
pub(crate) mod order_terms;
mod self_trade;
#[cfg(test)]
mod testkit;
mod trades;

use crate::reporting::{
    Check, FAILURES_SHOWN, FeedHead, FoldedChain, TreeWalk, check_feed_head, check_tree,
    read_root_anchors, root_sizes,
};
use listings::Listings;
use operator_key::Operator;
use order_terms::{MidHistory, OrderFate};
use trades::{Record, Run, Sides, TradeSide};

/// One trade as the exchange recorded it, read back from the state database.
///
/// The trade record hands every row over twice, once at each of the row's two
/// orders, so `Clone` is what the second hand-over costs. One row is 88 bytes
/// and a symbol. The checker holds the rows of one arriving order at a time
/// and no more.
#[derive(Debug, Clone)]
struct LoggedTrade {
    trade_id: u64,
    symbol: String,
    price_cents: i64,
    qty_tenths: i64,
    maker_order: OrderId,
    maker_account: AccountId,
    taker_order: OrderId,
    taker_account: AccountId,
    taker_side: Side,
}

/// A new order as the sequencer published it. Every trade that names this
/// order is checked against this record.
#[derive(Debug, Clone)]
struct FeedOrder {
    account: AccountId,
    symbol: String,
    side: Side,
    price_cents: i64,
    qty_tenths: i64,
    /// Whether the book can hold this price and this quantity at all. A price
    /// off the price step, or a quantity off the quantity step, is ignored on
    /// arrival.
    on_grid: bool,
    /// Whether the exchange could have traded this order at all. Two things
    /// must hold. The price and the quantity are on the steps. The log had the
    /// symbol open on these steps when the order was published. An order with
    /// `tradable == false` never rested and never traded, whatever the trade
    /// record says about it.
    tradable: bool,
    /// The three terms the order carries. `fate` writes out what each term
    /// allows the exchange to do with the order. `fate` was written from
    /// ENGINE.md sections 4.2 and 4.4, and from no code the exchange runs.
    order_type: OrderType,
    time_in_force: TimeInForce,
    post_only: bool,
}

impl FeedOrder {
    /// The order one New message publishes, or `None` for a message that
    /// publishes no order.
    ///
    /// One function reads a message's terms. The copy kept for trades to be
    /// checked against, and the copy put into the replayed book, are then the
    /// same reading of the same bytes. `listings` is the state of the log at
    /// the point this message sits. That is why the checker reads the order as
    /// the history streams past, and not afterwards. The same order published
    /// before a delist and after a delist gives two different answers.
    fn published(message: &OrderMessage, listings: &Listings) -> Option<FeedOrder> {
        let OrderMessage::New {
            account,
            symbol,
            side,
            price,
            quantity,
            order_type,
            time_in_force,
            post_only,
            ..
        } = message
        else {
            return None;
        };
        let price_cents = to_grid(*price, 100.0);
        let qty_tenths = to_grid(*quantity, 10.0);
        let on_grid = price_cents.is_some() && qty_tenths.is_some();
        Some(FeedOrder {
            account: *account,
            symbol: symbol.clone(),
            side: *side,
            // A value off the steps is still recorded, rounded, so a report
            // about it can name what the sequencer published.
            price_cents: price_cents.unwrap_or_else(|| (price * 100.0).round() as i64),
            qty_tenths: qty_tenths.unwrap_or_else(|| (quantity * 10.0).round() as i64),
            on_grid,
            tradable: match (price_cents, qty_tenths) {
                (Some(cents), Some(tenths)) => listings.admits(symbol, cents, tenths),
                _ => false,
            },
            order_type: *order_type,
            time_in_force: *time_in_force,
            post_only: *post_only,
        })
    }
}

/// One page of the sequencer's history, with the session the sequencer
/// announced beside it.
///
/// The checker reads the session from the response header. The exchange reads
/// it from the same header. Both sides then mean the same thing by "the
/// session of this response", and a run's recorded session can be compared
/// with it.
struct FeedPage {
    /// The messages as bytes. Turning the bytes into messages is a separate
    /// step. The chain does not need that step at all: see `wire`.
    messages: Vec<RawMessage>,
    session: Option<String>,
}

/// The session a held history announces. Test builds only. The tests sign
/// their operator messages for this log and no other.
#[cfg(test)]
const HELD_SESSION: &str = "4b1f0d7a9c2e6851";

/// Where the history to compare against comes from, one page at a time.
///
/// The walk below never sees which variant it has. Both variants hand over
/// pages of the same size. The loop that runs against a live sequencer is the
/// same loop the tests run against a history they built themselves.
enum History<'a> {
    /// Pages fetched from a live sequencer with `?since=`. Every reader in
    /// this repository reads the history that way.
    Feed {
        client: &'a reqwest::Client,
        url: &'a str,
    },
    /// A history already in hand, handed over in pages of the same size.
    #[cfg(test)]
    Held(&'a [RawMessage]),
}

impl History<'_> {
    /// The nodes the log stored when it appended leaves `from .. from+count`,
    /// or `None` when there is no log to ask.
    ///
    /// A held history has no stored tree beside it. There is then nothing to
    /// compare, and the walk says so. A live sequencer that refuses is a
    /// different case, and reaches the caller as an error.
    async fn tree_nodes(&self, from: u64, count: u64) -> Result<Option<wire::TreeNodes>, String> {
        match self {
            History::Feed { client, url } => {
                let page = wire::tree_nodes_url(url, from, count);
                let response = client
                    .get(&page)
                    .send()
                    .await
                    .map_err(|e| format!("cannot reach {}: {}", page, reason(&e)))?;
                let status = response.status();
                let body = read_bounded(response, "a page of stored nodes", MAX_PAGE_BYTES).await?;
                if !status.is_success() {
                    let detail = String::from_utf8_lossy(&body).trim().to_string();
                    return Err(if detail.is_empty() {
                        format!("{} answered {}", page, status)
                    } else {
                        format!("{} answered {}: {}", page, status, detail)
                    });
                }
                serde_json::from_slice(&body)
                    .map(Some)
                    .map_err(|e| format!("cannot read the nodes {} served: {}", page, e))
            }
            #[cfg(test)]
            History::Held(_) => Ok(None),
        }
    }

    async fn page(&self, since: OrderId) -> Result<FeedPage, String> {
        match self {
            History::Feed { client, url } => {
                // The raw-bytes endpoint. The checker builds the chain by
                // hashing the bytes the sequencer hashed. So the checker asks
                // for those bytes, and not for a JSON array it would have to
                // take the bytes back out of. See `wire::MESSAGES_PATH`.
                let page = wire::messages_url(url, since);
                let response = client
                    .get(&page)
                    .send()
                    .await
                    .map_err(|e| format!("cannot reach feed at {}: {}", url, reason(&e)))?;
                let session = response
                    .headers()
                    .get(crate::wire::SESSION_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .map(String::from);
                let status = response.status();
                let body = read_bounded(response, "a page of feed history", MAX_PAGE_BYTES).await?;
                if !status.is_success() {
                    // The body of a refusal carries the reason. A sequencer
                    // with no database names the message it can no longer
                    // serve. Without that body the caller sees only a bare
                    // 410.
                    let detail = String::from_utf8_lossy(&body).trim().to_string();
                    return Err(if detail.is_empty() {
                        format!("{} answered {}", page, status)
                    } else {
                        format!("{} answered {}: {}", page, status, detail)
                    });
                }
                let messages = wire::split_ndjson(&body)
                    .map_err(|e| format!("{} did not serve a page of messages: {}", page, e))?;
                Ok(FeedPage { messages, session })
            }
            #[cfg(test)]
            History::Held(all) => {
                let start = all.partition_point(|m| m.id <= since);
                let end = (start + crate::feed::PAGE_LIMIT).min(all.len());
                Ok(FeedPage {
                    messages: all[start..end].to_vec(),
                    // A held history announces a session, because an operator
                    // signature covers a session. A history whose operator
                    // messages were signed for no named log is not the history
                    // a real sequencer serves.
                    session: Some(HELD_SESSION.to_string()),
                })
            }
        }
    }
}

/// Walks the sequencer's history one bounded page at a time. Hands every
/// message to `each` and keeps none of them. Returns the id of the last
/// message the walk covered.
///
/// `session` carries the session the sequencer announced into the walk and out
/// of it. A session that changes ends the read. The change can come between
/// two pages of one walk, or between the two walks the checker makes. Two
/// histories cannot be compared as one.
///
/// `stop_at` is what makes the second walk cover the same history as the
/// first. The sequencer goes on publishing while the checker runs. A walk that
/// read to the end would replay messages the first walk never saw.
///
/// `each` is handed the session with every message, because an operator
/// signature covers the session. The second line of an operator statement is
/// the name of the log the message was written for. A sequencer that announces
/// no session leaves the session empty. A statement built over an empty
/// session is one no operator signed for a named log.
async fn walk_history(
    history: &History<'_>,
    session: &mut Option<String>,
    stop_at: Option<OrderId>,
    mut tree: Option<&mut TreeWalk>,
    mut each: impl FnMut(&RawMessage, &str),
) -> Result<OrderId, String> {
    let mut at: OrderId = 0;
    loop {
        let asked = at;
        let page = history.page(asked).await?;
        match (&session, &page.session) {
            (None, _) => *session = page.session.clone(),
            (Some(first), Some(now)) if first != now => {
                return Err(format!(
                    "the feed changed session from {} to {} while its history was being read: \
                     these are two different histories and cannot be reconciled as one",
                    first, now
                ));
            }
            _ => {}
        }
        if page.messages.is_empty() {
            return Ok(at);
        }
        let announced = session.as_deref().unwrap_or_default().to_string();
        // Where this page's leaves start. Message n is leaf n-1, and the walk
        // covers the ids with no gap. So the page that begins after message
        // `asked` begins at leaf `asked`.
        let leaves_from = at;
        let mut leaves = 0u64;
        for message in &page.messages {
            if stop_at.is_some_and(|stop| message.id > stop) {
                return Ok(at);
            }
            if let Some(tree) = tree.as_deref_mut() {
                tree.feed(&message.bytes);
                leaves += 1;
            }
            each(message, &announced);
            at = message.id;
        }
        // The log's own nodes for the leaves this page just hashed. The
        // checker asks page by page, so neither side ever holds a whole tree.
        if let Some(tree) = tree.as_deref_mut()
            && tree.wants_nodes()
            && leaves > 0
        {
            match history.tree_nodes(leaves_from, leaves).await {
                Ok(Some(served)) => tree.page(&served),
                Ok(None) => tree.no_source(),
                Err(reason) => tree.unreadable(reason),
            }
        }
        // The cursor is the last id of the page. A page that does not carry
        // the history forward is a page this walk would ask for again for
        // ever. That used to end in out of memory instead of a message. Every
        // re-read of the same page was appended to the vector this walk no
        // longer keeps.
        if at <= asked {
            return Err(format!(
                "the feed answered ?since={} with a page ending at message {}, so its history \
                 cannot be read forward from there",
                asked, at
            ));
        }
    }
}

/// Fetches the sequencer's signed head, or the reason there is none to check.
///
/// A head the checker cannot fetch is not a missing feature to pass over. The
/// signature over the head is the only evidence that the history compared
/// against is the history the sequencer stands behind. Without the signature
/// there is nothing to check, and a check that could not run has not passed.
async fn read_feed_head(client: &reqwest::Client, feed_url: &str) -> Result<FeedHead, String> {
    let response = client
        .get(format!("{}/head", feed_url))
        .send()
        .await
        .map_err(|e| format!("cannot reach {}/head: {}", feed_url, e))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("{}/head answered {}", feed_url, status));
    }
    let body = read_bounded(response, "the feed's head", MAX_PAGE_BYTES).await?;
    serde_json::from_slice(&body)
        .map_err(|e| format!("cannot read the head {} served: {}", feed_url, e))
}

/// One order the trade record names, kept for as long as the trade record
/// still names it.
struct NamedOrder {
    /// The order the sequencer published under this id, or `None` when the
    /// message under that id published no order.
    ///
    /// `None` is an answer, and the check `both sides of every trade exist on
    /// the feed` reports it. It must not be read as "not kept".
    ///
    /// The first order that carries an id is the one kept. A later message
    /// that reuses the id is not a second order. Ids are the sequencer's
    /// sequence numbers. A trade that names that id cannot be said to mean
    /// either copy. This used to overwrite the first order with the second and
    /// say nothing. A trade against the second copy then read as ordinary, and
    /// the report never mentioned the reused id anywhere.
    order: Option<FeedOrder>,
    /// How many rows of the trade record still name this id, on either side.
    /// The entry goes when this reaches zero.
    owed: u32,
    /// How many tenths the trade rows filled this order.
    filled: i64,
    /// Whether any row filled it. A row counts here only after both of its
    /// orders were found on the feed, which is the rule the check
    /// `no order filled beyond the quantity it offered` was written under.
    any_fill: bool,
    /// The id of the first cancel that could have taken effect on this order.
    /// From that cancel on, the order is out of the book. That holds whether
    /// the cancel removed the order, or the order had already traded in full.
    /// Nothing may trade against the order after that point. A cancel that
    /// could not take effect is not recorded at all. Two kinds cannot take
    /// effect: a cancel from another account, and a cancel for an order not
    /// yet published. The order they name went on resting.
    cancelled_by: Option<OrderId>,
    /// The id of the message that closed the whole market this order was
    /// published for. The meaning is the same as `cancelled_by`. It is a
    /// separate field so the report can say which of the two happened. The
    /// order's own account asks for a cancel. A delist closes the market, and
    /// the order with it.
    delisted_by: Option<OrderId>,
    /// Whether the self-trade rule refused this order when it arrived. A
    /// refused order makes no trade, so the check `every fill went to the
    /// order next in line` counted none of the rows that name it as taker.
    /// A row whose maker the sequencer published later than its taker is
    /// reported at that maker's message, and this says whether there is a
    /// counted row to report against. Without it that report could print more
    /// failures than the check read rows.
    refused: bool,
}

/// The orders the trade record has not finished with.
///
/// This map used to hold one entry for every order the trade record names,
/// from the start of the run to the end of it. That is the trade record in
/// another shape, and it grows with the length of the history.
///
/// An entry now opens at the message that published the order, and closes when
/// the last row that names the order has been checked. On an honest record
/// that is the time the order rests in the book: an order is a maker only
/// while it rests, and it is a taker only at its own message. So the size of
/// this map follows the book, and not the history. `verify/trades.rs` says how
/// the trade record is read to make that true.
///
/// A record that is not honest can hold an order open longer, by naming an
/// order that stopped resting long before. Every such row fails the check
/// `every fill went to the order next in line`, which is the fault being
/// reported. That case cost the whole trade record before this change, so it
/// is no worse now.
#[derive(Default)]
struct NamedOrders(HashMap<OrderId, NamedOrder>);

impl NamedOrders {
    /// Notes that one more row of the trade record names this id. Called at
    /// the message that published the order, before the message is read.
    fn wanted(&mut self, id: OrderId) {
        let entry = self.0.entry(id).or_insert(NamedOrder {
            order: None,
            owed: 0,
            filled: 0,
            any_fill: false,
            cancelled_by: None,
            delisted_by: None,
            refused: false,
        });
        // Saturating, and not wrapping. A count that wrapped round to zero
        // would close an entry that rows still name, and the checks after it
        // would read "the feed never published that order" about an order the
        // feed did publish. It takes four billion rows naming one order to
        // reach that, and a record that large is one this checker should still
        // report on rather than misread.
        entry.owed = entry.owed.saturating_add(1);
    }

    /// Records what the sequencer published as `id`, if a check can ask about
    /// it.
    fn published(&mut self, id: OrderId, message: &OrderMessage, listings: &Listings) {
        if let Some(entry) = self.0.get_mut(&id)
            && entry.order.is_none()
        {
            entry.order = FeedOrder::published(message, listings);
        }
    }

    /// The order the sequencer published as `id`, or `None` when this walk has
    /// no order under that id.
    fn get(&self, id: OrderId) -> Option<&FeedOrder> {
        self.0.get(&id).and_then(|entry| entry.order.as_ref())
    }

    /// Whether this walk has reached the message that published `id`.
    ///
    /// An id the walk has not reached is a different answer from an id the
    /// sequencer published no order under. A trade whose maker comes later in
    /// the history than its own taker is the first case, and the checks that
    /// report it wait until the walk gets there.
    fn reached(&self, id: OrderId) -> bool {
        self.0.contains_key(&id)
    }

    /// Records the first cancel that could have taken effect on `target_id`.
    ///
    /// A cancel that could not take effect is not recorded. Two kinds cannot:
    /// a cancel from another account, and a cancel for an order the sequencer
    /// has not published. The order they name went on resting, and a trade
    /// against it after that cancel is an ordinary trade.
    fn cancelled(&mut self, target_id: OrderId, cancel_id: OrderId, account: AccountId) {
        let Some(entry) = self.0.get_mut(&target_id) else {
            return;
        };
        let owner = entry.order.as_ref().map(|order| order.account);
        if cancel_takes_effect(owner, cancel_id, account, target_id) {
            entry.cancelled_by.get_or_insert(cancel_id);
        }
    }

    /// Records that the self-trade rule refused this order when it arrived.
    fn refused(&mut self, id: OrderId) {
        if let Some(entry) = self.0.get_mut(&id) {
            entry.refused = true;
        }
    }

    /// Whether the replay put the rows that name this order as taker through
    /// the book. It did that at the order's own message, unless the sequencer
    /// published no order there or the self-trade rule refused the order.
    fn took_the_book(&self, id: OrderId) -> bool {
        self.0
            .get(&id)
            .is_some_and(|entry| entry.order.is_some() && !entry.refused)
    }

    /// The two messages that could have taken an order out of the book before
    /// a trade named it: the first cancel, and the delist that closed its
    /// market.
    fn closed(&self, id: OrderId) -> (Option<OrderId>, Option<OrderId>) {
        match self.0.get(&id) {
            Some(entry) => (entry.cancelled_by, entry.delisted_by),
            None => (None, None),
        }
    }

    /// Adds one row's quantity to an order's filled total.
    fn filled(&mut self, id: OrderId, qty_tenths: i64) {
        if let Some(entry) = self.0.get_mut(&id) {
            entry.filled = entry.filled.saturating_add(qty_tenths);
            entry.any_fill = true;
        }
    }

    /// Records that a `DelistSymbol` closed every order this map holds for
    /// `symbol`.
    ///
    /// The size of this map follows the book, so this walk is bounded by the
    /// orders that are open and traded, and not by the number of trades. It
    /// used to walk every order the trade record had ever named, on every
    /// delist.
    fn delisted_on(&mut self, symbol: &str, by: OrderId) {
        for entry in self.0.values_mut() {
            if entry.order.as_ref().is_some_and(|o| o.symbol == symbol) {
                entry.delisted_by.get_or_insert(by);
            }
        }
    }

    /// Takes one row off an order's count, and closes the entry once no row
    /// names the order any more.
    ///
    /// `overfill` is checked as the entry closes, because that is the moment
    /// every fill of the order is in. The check used to run over one map of
    /// totals after the whole trade record had been read.
    fn done_with(&mut self, id: OrderId, overfill: &mut Check) {
        let Some(entry) = self.0.get_mut(&id) else {
            return;
        };
        entry.owed = entry.owed.saturating_sub(1);
        if entry.owed == 0 {
            let entry = self.0.remove(&id).expect("the entry was read a line above");
            close(id, &entry, overfill);
        }
    }

    /// Closes every entry still open. A row the walk never reached leaves its
    /// two orders open, so those fills are counted here instead.
    fn finish(self, overfill: &mut Check) {
        let mut left: Vec<(OrderId, NamedOrder)> = self.0.into_iter().collect();
        // In id order, so a report over the same input reads the same twice.
        left.sort_by_key(|(id, _)| *id);
        for (id, entry) in left {
            close(id, &entry, overfill);
        }
    }
}

/// The one check an order answers as its entry closes: no order was filled
/// beyond the quantity it offered.
fn close(id: OrderId, entry: &NamedOrder, overfill: &mut Check) {
    if !entry.any_fill {
        return;
    }
    overfill.checked += 1;
    let Some(order) = entry.order.as_ref() else {
        return;
    };
    if entry.filled > order.qty_tenths {
        overfill.fail(format!(
            "order {} offered {} tenths but was filled {}",
            id, order.qty_tenths, entry.filled
        ));
    }
}

/// Whether a Cancel message could have removed an order placed by `owner`.
///
/// Two conditions must hold, and the checker works out both from the
/// sequencer's messages alone. First, the cancel must come after the order it
/// names. A cancel for an order that does not exist yet has nothing to remove.
/// Second, the cancel must come from the account that placed the order. An
/// order belongs to the account that published it. The exchange refuses a
/// cancel from any other account, and the order goes on resting and can still
/// trade. If the checker counted another account's cancel, it would report a
/// good trade as a trade against a cancelled order.
///
/// `owner` is `None` for an order the sequencer never published. No cancel can
/// remove that order either.
fn cancel_takes_effect(
    owner: Option<AccountId>,
    id: OrderId,
    account: AccountId,
    target_id: OrderId,
) -> bool {
    id > target_id && owner == Some(account)
}

/// The rule sets the checker can replay, and what each one means here.
///
/// Written out from ENGINE.md, and not read from the exchange's code. Section
/// 3 says the log opens by stating its own rules. Section 5 says every
/// matching rule is written twice: once in the pipeline, and once here on its
/// own. The two copies can then disagree and catch each other. A checker that
/// imported the exchange's rule set could not disagree with it about anything.
///
/// Rule sets add up, in order. Rule set 2 is rule set 1 plus one more rule. So
/// the test is `version >= 2`, and not `version == 2`.
///
/// | version | what it adds |
/// |---|---|
/// | 1 | the rules the log has run under since message 1 |
/// | 2 | self-trade prevention, cancel newest (section 4.1) |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rules {
    version: u32,
}

impl Rules {
    /// What a history runs under before it names a rule set: rule set 1.
    const GENESIS: Rules = Rules { version: 1 };

    /// The newest rule set this build can replay.
    const NEWEST: u32 = 2;

    /// The rule set this version names, or `None` when this build cannot
    /// replay it.
    fn known(version: u32) -> Option<Rules> {
        (Rules::GENESIS.version..=Rules::NEWEST)
            .contains(&version)
            .then_some(Rules { version })
    }
}

/// The verdict for a message that names a rule set this build cannot replay.
///
/// The checker makes the opposite choice from the exchange, for the opposite
/// reason. The exchange counts the message and goes on serving books, because
/// an exchange that stops on one message is an exchange that is down. The
/// checker exists to say whether the history holds. So replaying the history
/// under the wrong rules and reporting a pass is the one thing the checker
/// must never do. See ENGINE.md section 6, exit 3.
fn unknown_rule_set(raw: &RawMessage, version: u32) -> TooOld {
    TooOld {
        id: raw.id,
        kind: raw.kind.clone(),
        reason: format!(
            "it names rule set {}, and this build replays rule sets {} to {}, so a report past \
             it would cover a history matched under rules this checker cannot apply",
            version,
            Rules::GENESIS.version,
            Rules::NEWEST
        ),
    }
}

/// Hashes the sequencer's chain over the messages as they stream past, as far
/// as the id the sequencer's signed head stands at.
///
/// The checker fetches the head before the history. The history then always
/// reaches the signed id, even though the sequencer keeps publishing between
/// the two requests. A head the checker could not fetch hashes nothing. There
/// is then no value to compare a chain against, and the check reports that
/// instead.
///
/// `HeadChain` hashes the bytes each message arrived as. So this check still
/// holds over a history that contains messages this build cannot read. It is
/// the one check that still means something when the rest of the checker has
/// to stop.
struct HeadChain {
    chain: Chain,
    stands_at: Option<OrderId>,
    counted: usize,
}

impl HeadChain {
    fn new(head: &Result<FeedHead, String>) -> Self {
        HeadChain {
            chain: crate::logchain::EMPTY_CHAIN,
            stands_at: head.as_ref().ok().map(|head| head.last_id),
            counted: 0,
        }
    }

    fn feed(&mut self, message: &RawMessage) {
        if self.stands_at.is_none_or(|at| message.id > at) {
            return;
        }
        self.chain = crate::logchain::extend_bytes(&self.chain, &message.bytes);
        self.counted += 1;
    }
}

/// What one walk of the sequencer's history leaves behind. It holds everything
/// the checks need from the history, and not the history itself.
///
/// Every field here is a counter, a running hash, or an index whose size the
/// trade record fixes. No field grows with the number of messages the
/// sequencer has published.
struct Survey {
    /// Who the log's operator is, and which operator messages the operator
    /// really wrote. An operator message the operator did not write opens
    /// nothing and closes nothing. So this walk asks who wrote a message
    /// before it reads anything out of the message.
    operator: Operator,
    /// How many different ids the sequencer published orders under.
    published: usize,
    /// How many New messages reused an id, and the first few of those ids.
    /// The report prints no more ids than it can show.
    duplicates: usize,
    duplicate_ids: Vec<OrderId>,
    /// The highest id an order has been published under so far. The
    /// sequencer's ids are its sequence numbers, and `?since=` serves them in
    /// rising order. So an id that does not rise is an id already published.
    /// That is how the checker answers "published twice" without keeping every
    /// id it ever saw. Keeping every id is the history again.
    highest_order_id: Option<OrderId>,
    chain: HeadChain,
    /// The last message this walk covered. The second walk stops there, so
    /// both walks cover the same history.
    last_id: OrderId,
    /// The first message this build could not read, if there was one.
    ///
    /// Every field below the chain in this struct answers a question about
    /// orders, cancels and ids. All of those answers need the message read,
    /// not only hashed. So the walk goes on hashing, because the head check is
    /// still worth making and still holds. The run then ends with this message
    /// instead of a report whose counts skipped a message and said nothing.
    too_old: Option<TooOld>,
}

impl Survey {
    fn new(head: &Result<FeedHead, String>) -> Self {
        Survey {
            operator: Operator::new(),
            published: 0,
            duplicates: 0,
            duplicate_ids: Vec::new(),
            highest_order_id: None,
            chain: HeadChain::new(head),
            last_id: 0,
            too_old: None,
        }
    }

    fn feed(&mut self, raw: &RawMessage, session: &str) {
        // Hash the bytes first, with no opinion about what the bytes say.
        // Reading the bytes is the next line and a separate job. That job can
        // fail without saying anything about the sequencer.
        self.chain.feed(raw);
        let message = match raw.parse() {
            Ok(message) => message,
            Err(too_old) => {
                self.too_old.get_or_insert(too_old);
                return;
            }
        };
        // Who wrote the message, before anything is read out of it. An
        // operator message the log's operator did not write opens no market,
        // closes no market, and moves no rule set. So this walk stops here for
        // that message. The exchange reaches the same answer, and this file
        // reaches it with its own code.
        if !self.operator.accepts(raw.id, &message, session) {
            return;
        }
        match &message {
            OrderMessage::New { id, .. } => {
                if self.highest_order_id.is_some_and(|highest| *id <= highest) {
                    self.duplicates += 1;
                    if self.duplicate_ids.len() < FAILURES_SHOWN {
                        self.duplicate_ids.push(*id);
                    }
                    return;
                }
                self.highest_order_id = Some(*id);
                self.published += 1;
            }
            // Nothing this walk counts. A cancel, a listing and a delist all
            // move the book, and the book is the second walk's business. This
            // walk used to keep an index of the cancels and the delists that
            // named an order the trade record names. That index was as large
            // as the trade record. The second walk now records both against
            // the order they name, for as long as the trade record still names
            // that order.
            OrderMessage::Cancel { .. }
            | OrderMessage::ListSymbol { .. }
            | OrderMessage::DelistSymbol { .. } => {}
            // The rule set that the messages after this one run under. This
            // walk keeps no book, so it has nothing to replay differently. A
            // version this build cannot replay still ends the run, because the
            // second walk would replay the history under the wrong rules.
            //
            // ENGINE.md section 6 gives three states. "cannot interpret" is
            // the state for a history this build checked and could not read in
            // full. Whether the message parses is not the test. A message that
            // moves the books and is walked past leaves this file reporting on
            // a history it replayed only in part. A pass over that history is
            // worse than no pass, because somebody acts on it.
            OrderMessage::EngineRule { version, .. } => {
                if Rules::known(*version).is_none() {
                    self.too_old
                        .get_or_insert_with(|| unknown_rule_set(raw, *version));
                }
            }
        }
    }
}

/// Walks the sequencer's history once and returns what the checks need.
async fn survey_history(
    history: &History<'_>,
    session: &mut Option<String>,
    head: &Result<FeedHead, String>,
    tree: &mut TreeWalk,
) -> Result<Survey, String> {
    let mut survey = Survey::new(head);
    let last_id = walk_history(history, session, None, Some(tree), |message, session| {
        survey.feed(message, session)
    })
    .await?;
    survey.last_id = last_id;
    Ok(survey)
}

/// Hands the shared head check the two values this walk produced.
fn folded_chain(folded: &HeadChain) -> FoldedChain {
    FoldedChain {
        chain: folded.chain,
        counted: folded.counted,
    }
}

/// The book of resting orders, rebuilt from the sequencer's own messages.
///
/// Prices sit in a `BTreeMap`, so the best price is the first key or the last
/// key and not a search. Each price level is a `BTreeMap` keyed by order id,
/// so the oldest order at that price is the first key of the level. The
/// sequencer's ids rise as it publishes, so rising id is the same order as
/// arrival.
#[derive(Default)]
struct ReplayBook {
    bids: HashMap<String, BTreeMap<i64, BTreeMap<OrderId, i64>>>,
    asks: HashMap<String, BTreeMap<i64, BTreeMap<OrderId, i64>>>,
    /// The order behind every id resting above. The replay is handed one
    /// message at a time and keeps no history. So a resting order's own terms
    /// are kept here. The size of this map follows the orders that are still
    /// open, not the orders that ever existed. This map is also what lets the
    /// book be addressed by id alone. An order's level is found from the
    /// order's own symbol, side and price, so no caller has to remember where
    /// the order sits.
    resting: HashMap<OrderId, FeedOrder>,
}

impl ReplayBook {
    fn levels(&self, symbol: &str, side: Side) -> Option<&BTreeMap<i64, BTreeMap<OrderId, i64>>> {
        match side {
            Side::Buy => self.bids.get(symbol),
            Side::Sell => self.asks.get(symbol),
        }
    }

    fn levels_mut(
        &mut self,
        symbol: &str,
        side: Side,
    ) -> &mut BTreeMap<i64, BTreeMap<OrderId, i64>> {
        let books = match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        };
        books.entry(symbol.to_string()).or_default()
    }

    /// Puts what is left of an order into its level.
    fn rest(&mut self, order_id: OrderId, order: FeedOrder, qty_tenths: i64) {
        self.levels_mut(&order.symbol, order.side)
            .entry(order.price_cents)
            .or_default()
            .insert(order_id, qty_tenths);
        self.resting.insert(order_id, order);
    }

    /// The order resting under an id, as the sequencer published it.
    fn order(&self, order_id: OrderId) -> Option<&FeedOrder> {
        self.resting.get(&order_id)
    }

    /// How much of one order is still resting, or `None` when the order is not
    /// in the book at all. It traded in full, it was cancelled, or it never
    /// rested.
    fn remaining(&self, order_id: OrderId) -> Option<i64> {
        let order = self.resting.get(&order_id)?;
        self.levels(&order.symbol, order.side)?
            .get(&order.price_cents)?
            .get(&order_id)
            .copied()
    }

    /// The order that had to trade next on this side of this symbol. That is
    /// the best price, and the oldest order resting at that price.
    fn next_in_line(&self, symbol: &str, side: Side) -> Option<(i64, OrderId)> {
        let levels = self.levels(symbol, side)?;
        let (price, level) = match side {
            // The best order to buy from is the cheapest one. The best order
            // to sell to is the dearest one.
            Side::Sell => levels.iter().next()?,
            Side::Buy => levels.iter().next_back()?,
        };
        level.keys().next().map(|id| (*price, *id))
    }

    /// Takes a traded quantity off a resting order, and drops the order once
    /// nothing is left. A quantity larger than the order is not for this
    /// function to judge. The overfill check reports that. So the subtraction
    /// stops at zero instead of wrapping round.
    fn take(&mut self, order_id: OrderId, qty_tenths: i64) {
        let Some(order) = self.resting.get(&order_id) else {
            return;
        };
        let price = order.price_cents;
        let books = match order.side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        };
        let mut emptied = false;
        if let Some(levels) = books.get_mut(&order.symbol)
            && let Some(level) = levels.get_mut(&price)
        {
            if let Some(left) = level.get_mut(&order_id) {
                *left = left.saturating_sub(qty_tenths);
                if *left <= 0 {
                    level.remove(&order_id);
                    emptied = true;
                }
            }
            if level.is_empty() {
                levels.remove(&price);
            }
        }
        if emptied {
            self.resting.remove(&order_id);
        }
    }

    /// Removes a cancelled order, if it is still there to remove.
    fn remove(&mut self, order_id: OrderId) {
        let Some(order) = self.resting.remove(&order_id) else {
            return;
        };
        let levels = self.levels_mut(&order.symbol, order.side);
        let Some(level) = levels.get_mut(&order.price_cents) else {
            return;
        };
        level.remove(&order_id);
        if level.is_empty() {
            levels.remove(&order.price_cents);
        }
    }
}

/// The checks one row of the trade record makes against the two orders the
/// sequencer published under the ids the row names.
///
/// Every one of these used to run in a loop over the whole trade record, after
/// both walks had finished. That loop needed every order the trade record
/// names to be in memory at once. They run inside the second walk now, at the
/// message where the row's second order arrives, so no order is kept past the
/// last row that names it.
struct Rows {
    ids: Check,
    known: Check,
    opposed: Check,
    resting: Check,
    symbols: Check,
    accounts: Check,
    maker_price: Check,
    taker_price: Check,
    positive: Check,
    overfill: Check,
    cancelled: Check,
    cash: Check,
    /// Two ledgers, built from two sources. `logged_cash` is what the trade
    /// rows say each account paid and received. `feed_cash` is the same trades
    /// priced from the sequencer's own record. A trade against a maker takes
    /// the maker's published limit price, and the accounts come from the two
    /// orders the sequencer published. The two ledgers share nothing but the
    /// traded quantity. So they agree only when the trade rows describe what
    /// the sequencer published. One entry per account: 41 accounts on the
    /// deployment, and no growth with the length of the history.
    logged_cash: HashMap<AccountId, i64>,
    feed_cash: HashMap<AccountId, i64>,
    /// Set to false when a row's arithmetic does not fit in the ledger. The
    /// compare at the end then means nothing, and it is not printed as if it
    /// did.
    cash_usable: bool,
}

impl Rows {
    fn new() -> Self {
        Rows {
            ids: Check::new("trade ids are 1..n with no gaps"),
            known: Check::new("both sides of every trade exist on the feed"),
            opposed: Check::new("maker and taker are on opposite sides"),
            resting: Check::new("maker order was published before the taker"),
            symbols: Check::new("trade symbol matches both orders"),
            accounts: Check::new("trade accounts match the orders' accounts"),
            maker_price: Check::new("trade executed at the maker's limit price"),
            taker_price: Check::new("price honours the taker's limit"),
            positive: Check::new("every fill has positive quantity"),
            overfill: Check::new("no order filled beyond the quantity it offered"),
            cancelled: Check::new("no fill against an already cancelled order"),
            cash: Check::new("cash matches the prices the feed published"),
            logged_cash: HashMap::new(),
            feed_cash: HashMap::new(),
            cash_usable: true,
        }
    }

    /// Checks one row against the orders the sequencer published.
    ///
    /// Called once for every row, at whichever of the row's two orders the
    /// walk reaches second. Both orders are in `named` by then, and neither
    /// was kept past this row.
    fn check(&mut self, trade: &LoggedTrade, named: &mut NamedOrders) {
        // A trade against an order the sequencer had already cancelled. The
        // cancel's own message id is where the cancel took effect. The taker's
        // id is where the trade happened. So a cancel with the lower id came
        // first. This code used to ignore Cancel messages. A trade against an
        // order that had been withdrawn before it then passed every other
        // check here. Only the cancels that could take effect are recorded, so
        // a refused cancel from another account does not accuse a correct
        // trade that followed it.
        self.cancelled.checked += 1;
        let (cancelled_by, delisted_by) = named.closed(trade.maker_order);
        if let Some(cancel_id) = cancelled_by
            && cancel_id < trade.taker_order
        {
            self.cancelled.fail(format!(
                "trade {} filled order {}, which message {} had cancelled before order {} arrived",
                trade.trade_id, trade.maker_order, cancel_id, trade.taker_order
            ));
        }
        // The same answer from a different message. A delist closes the market
        // and every order resting in it stops resting. So a trade against one
        // of those orders after that message is a trade against nothing.
        if let Some(delist_id) = delisted_by
            && delist_id < trade.taker_order
        {
            self.cancelled.fail(format!(
                "trade {} filled order {}, which message {} had closed with the whole {} market \
                 before order {} arrived",
                trade.trade_id, trade.maker_order, delist_id, trade.symbol, trade.taker_order
            ));
        }

        self.known.checked += 1;
        let filled = self.against(trade, named);
        // The addition stops at the maximum, and does not wrap round. A
        // crafted quantity must not turn a row that overfills an order into a
        // row that looks like it underfills the order. The totals sit on the
        // order's own record, and the check runs as that record closes.
        if filled {
            named.filled(trade.maker_order, trade.qty_tenths);
            named.filled(trade.taker_order, trade.qty_tenths);
        }
    }

    /// Every compare that needs both of the row's orders. Returns whether the
    /// row counts towards the two orders' filled totals, which it does only
    /// when the sequencer published both of them.
    fn against(&mut self, trade: &LoggedTrade, named: &NamedOrders) -> bool {
        let (Some(maker), Some(taker)) =
            (named.get(trade.maker_order), named.get(trade.taker_order))
        else {
            self.known.fail(format!(
                "trade {} references order {} or {}, which the feed never published",
                trade.trade_id, trade.maker_order, trade.taker_order
            ));
            return false;
        };
        if !maker.on_grid || !taker.on_grid {
            self.known.fail(format!(
                "trade {} joins order {} and {}, at least one of which the feed published off \
                 the price and quantity grid; the engine drops those on arrival, so neither \
                 could have traded",
                trade.trade_id, trade.maker_order, trade.taker_order
            ));
        } else if !maker.tradable || !taker.tradable {
            // On the steps and still not tradable. The symbol was not open at
            // the point the order sits. Either the log had never listed the
            // symbol, or the log had delisted it and not listed it again. The
            // exchange refuses those orders on arrival too, so no book ever
            // held them.
            self.known.fail(format!(
                "trade {} joins order {} and {} on {}, which the log had not listed when at \
                 least one of them was published; neither could have entered a book",
                trade.trade_id, trade.maker_order, trade.taker_order, trade.symbol
            ));
        }

        self.opposed.checked += 1;
        if maker.side == taker.side {
            self.opposed.fail(format!(
                "trade {} matched two {:?} orders",
                trade.trade_id, maker.side
            ));
        }
        if taker.side != trade.taker_side {
            self.opposed.fail(format!(
                "trade {} says taker side {:?}, order {} is {:?}",
                trade.trade_id, trade.taker_side, trade.taker_order, taker.side
            ));
        }

        self.resting.checked += 1;
        if trade.maker_order >= trade.taker_order {
            self.resting.fail(format!(
                "trade {}: maker {} did not precede taker {}",
                trade.trade_id, trade.maker_order, trade.taker_order
            ));
        }

        self.symbols.checked += 1;
        if maker.symbol != trade.symbol || taker.symbol != trade.symbol {
            self.symbols.fail(format!(
                "trade {} on {} joined {} and {}",
                trade.trade_id, trade.symbol, maker.symbol, taker.symbol
            ));
        }

        self.accounts.checked += 1;
        if maker.account != trade.maker_account || taker.account != trade.taker_account {
            self.accounts.fail(format!(
                "trade {} claims accounts {}/{}, orders say {}/{}",
                trade.trade_id,
                trade.maker_account,
                trade.taker_account,
                maker.account,
                taker.account
            ));
        }

        self.maker_price.checked += 1;
        if trade.price_cents != maker.price_cents {
            self.maker_price.fail(format!(
                "trade {} printed at {} but maker {} rested at {}",
                trade.trade_id, trade.price_cents, trade.maker_order, maker.price_cents
            ));
        }

        self.taker_price.checked += 1;
        let honoured = match taker.side {
            Side::Buy => trade.price_cents <= taker.price_cents,
            Side::Sell => trade.price_cents >= taker.price_cents,
        };
        if !honoured {
            self.taker_price.fail(format!(
                "trade {} filled a {:?} at {} against a limit of {}",
                trade.trade_id, taker.side, trade.price_cents, taker.price_cents
            ));
        }

        // The two cash sides. Each side takes its price and its account from
        // its own source. One stored price applied to both sides can only
        // cancel itself out. That is why the old check, which asked whether
        // the cash added up to zero, passed on any input at all, invented rows
        // included.
        self.cash.checked += 1;
        let (Some(logged_notional), Some(feed_notional)) = (
            trade.qty_tenths.checked_mul(trade.price_cents),
            trade.qty_tenths.checked_mul(maker.price_cents),
        ) else {
            self.cash_usable = false;
            self.cash.fail(format!(
                "trade {}: {} tenths at {} cents does not fit in the ledger's arithmetic, \
                 so no cash statement can be made about this row",
                trade.trade_id, trade.qty_tenths, trade.price_cents
            ));
            return true;
        };
        let (Some(logged_debit), Some(feed_debit)) =
            (logged_notional.checked_neg(), feed_notional.checked_neg())
        else {
            self.cash_usable = false;
            self.cash.fail(format!(
                "trade {}: its notional cannot be negated without overflow, so the buyer's \
                 side of it cannot be stated",
                trade.trade_id
            ));
            return true;
        };
        let (logged_buyer, logged_seller) = match trade.taker_side {
            Side::Buy => (trade.taker_account, trade.maker_account),
            Side::Sell => (trade.maker_account, trade.taker_account),
        };
        let (feed_buyer, feed_seller) = match taker.side {
            Side::Buy => (taker.account, maker.account),
            Side::Sell => (maker.account, taker.account),
        };
        let posted = add_cash(&mut self.logged_cash, logged_buyer, logged_debit)
            && add_cash(&mut self.logged_cash, logged_seller, logged_notional)
            && add_cash(&mut self.feed_cash, feed_buyer, feed_debit)
            && add_cash(&mut self.feed_cash, feed_seller, feed_notional);
        if !posted {
            self.cash_usable = false;
            self.cash.fail(format!(
                "trade {} overflows the running cash total of one of its accounts; the \
                 totals below it cannot be trusted",
                trade.trade_id
            ));
        }
        true
    }

    /// What the trade rows moved, against what the sequencer's own orders and
    /// prices say the same trades moved. An account whose two totals differ is
    /// holding money the sequencer cannot account for. Two ways that happens:
    /// a trade at a price the maker never offered, or one side of a trade
    /// credited to an account that never placed the order.
    fn compare_the_ledgers(&mut self) {
        if !self.cash_usable {
            return;
        }
        let mut accounts_seen: Vec<AccountId> = self
            .logged_cash
            .keys()
            .chain(self.feed_cash.keys())
            .copied()
            .collect();
        accounts_seen.sort_unstable();
        accounts_seen.dedup();
        for account in accounts_seen {
            let logged = self.logged_cash.get(&account).copied().unwrap_or(0);
            let derived = self.feed_cash.get(&account).copied().unwrap_or(0);
            if logged != derived {
                self.cash.fail(format!(
                    "account {}: the trade rows leave it {} mills, the feed's own orders and \
                     prices leave it {}",
                    account, logged, derived
                ));
            }
        }
    }
}

/// What `replay_the_history` found: one `Check` for each rule it tested.
///
/// Five of them ride on the replayed book. Each of those needs the book as it
/// stood when an order arrived, and the replay is the only place that has it.
/// They come from rules that were written apart from each other. They stay
/// separate checks, so that one check being wrong does not silence the others:
///
/// - **every fill went to the order next in line.** The best price on the
///   other side, and the oldest order resting at that price.
/// - **no trade joins an account to itself.** Read straight off the trade
///   row, once the log has turned self-trade prevention on.
/// - **no trade against the taker's own resting order.** The same rule from
///   the other side, and this side needs the book. An order that arrives and
///   could trade against another account's order, and against its own resting
///   order too, is refused whole. The trade the exchange then recorded joins
///   two different accounts, so the check above it sees nothing wrong.
/// - **an order the exchange's own rules refuse never traded.** Three cases.
///   First, a post-only order that would take from the book. Post-only means
///   the order may only rest, and must never trade on arrival. Second, a
///   fill-or-kill order the book cannot fill in full. Fill-or-kill means the
///   whole quantity trades at once, or none of it trades. Third, a market
///   order with no reference price. Each of those three must produce no trade
///   at all. A trade that names one of them as taker is the exchange breaking
///   its own rule.
/// - **a market order traded inside its collar.** The collar is a price bound
///   the exchange sets around a reference price, so a market order cannot
///   trade far from the prices the book has been showing. The other price
///   check in this file compares a trade against the bound the sender signed,
///   and a market order's signed bound is the wide one. The collar is the
///   narrow one, and the exchange applies it for itself. The collar is worked
///   out in the replay from the mid prices it watched the book show. The mid
///   price is the price half way between the best buy price and the best sell
///   price.
///
/// The rest are in `Rows`. They read a trade row against the two orders the
/// sequencer published, and they need no book.
struct Replayed {
    priority: Check,
    /// The two self-trade checks. They belong to one rule, so they live in the
    /// module that states that rule.
    self_trade: self_trade::Checks,
    /// The two order-term checks, for the same reason. The order-term refusal
    /// is kept apart from the self-trade refusal. The two rules were written
    /// from different sections of ENGINE.md, and either rule may be wrong on
    /// its own. Two struct fields cannot share a name, so the compiler now
    /// refuses the merge that would give one counter two meanings.
    order_terms: order_terms::Checks,
    /// The checks that read a trade row against two published orders.
    rows: Rows,
    too_old: Option<TooOld>,
    /// The symbols the log had open when the walk ended. Test builds only. A
    /// test asks whether one operator message opened a market, and this walk
    /// is the only one that reads a listing message now.
    #[cfg(test)]
    open_symbols: Listings,
    /// Every order this walk built from a New message the trade record names.
    /// Test builds only, and kept past the row that named it. A test asks what
    /// the walk made of one published order. The run itself drops each order
    /// as soon as the last row that names it is checked, which is the whole
    /// point of this file, so the run cannot answer that question and does not
    /// need to.
    #[cfg(test)]
    published: HashMap<OrderId, FeedOrder>,
}

impl Replayed {
    fn new() -> Self {
        Replayed {
            // The two refusals end in the same answer: this order made no
            // trade. So an order that breaks both rules is named by whichever
            // rule looks at it first. The two counts stay apart, so neither
            // count can stand in for the other one having gone quiet.
            priority: Check::new("every fill went to the order next in line"),
            self_trade: self_trade::Checks::new(),
            order_terms: order_terms::Checks::new(),
            rows: Rows::new(),
            too_old: None,
            #[cfg(test)]
            open_symbols: Listings::default(),
            #[cfg(test)]
            published: HashMap::new(),
        }
    }

    /// Every check this walk made, in the order the report prints them.
    fn checks(self) -> Vec<Check> {
        vec![
            self.rows.ids,
            self.rows.known,
            self.rows.opposed,
            self.rows.resting,
            self.rows.symbols,
            self.rows.accounts,
            self.rows.maker_price,
            self.rows.taker_price,
            self.rows.positive,
            self.rows.overfill,
            self.rows.cancelled,
            self.priority,
            self.self_trade.paired,
            self.self_trade.refused,
            self.order_terms.refused,
            self.order_terms.collared,
            self.rows.cash,
        ]
    }
}

/// The rows the replay never reached, held back until the walk has finished.
///
/// A trade the replay never reached names a taker the sequencer never
/// published. Counting it stops the priority check from passing because it
/// looked at nothing. An invented trade would pass in exactly that way.
///
/// The report prints these after the failures the replay found, which is the
/// order this check has always printed them in. So they are held here and
/// added at the end. `FAILURES_SHOWN` is the most a report ever prints, so
/// this holds no more than that many lines however many rows are wrong.
#[derive(Default)]
struct NotReached {
    count: usize,
    shown: Vec<String>,
}

impl NotReached {
    fn note(&mut self, trade: &LoggedTrade) {
        self.count += 1;
        if self.shown.len() < FAILURES_SHOWN {
            self.shown.push(format!(
                "trade {} names taker order {}, which the feed never published, so no book \
                 state puts it against order {}",
                trade.trade_id, trade.taker_order, trade.maker_order
            ));
        }
    }

    fn add_to(self, priority: &mut Check) {
        priority.checked += self.count;
        let shown = self.shown.len();
        for line in self.shown {
            priority.fail(line);
        }
        // The lines past the first few are counted and not printed, which is
        // what `Check::fail` does with any failure past `FAILURES_SHOWN`.
        priority.failed += self.count - shown;
    }
}

/// Whether the walk checks this row here, at this one of its two orders.
///
/// A row is checked at whichever of its two orders the walk reaches second,
/// because that is the first message where both orders are in hand. The maker
/// comes first in an honest record, so that is normally the taker. A row whose
/// maker the sequencer published after its own taker is checked at the maker.
fn checked_here(side: &TradeSide) -> bool {
    if side.taker {
        side.trade.maker_order <= side.trade.taker_order
    } else {
        side.trade.maker_order > side.trade.taker_order
    }
}

/// Walks the sequencer's history a second time, rebuilds the book from the
/// messages, and checks every row of the trade record against it.
///
/// The headline check is that every trade went to the order that was next in
/// line. Next in line means the best price on the other side, and the oldest
/// order resting at that price. That check asks whether a trade was earned.
/// Without it, a trade may name any resting order at any price the taker's
/// limit allows, and every other check here still passes. The two orders
/// exist. They are on opposite sides. The price is the maker's own price. Both
/// limits are kept. The order that should have traded, and was skipped, never
/// appears in the trade at all. So a check that reads only the trades can
/// never see the skip.
///
/// The checker rebuilds the book from the sequencer's messages. Only the
/// traded quantities come from the trade record. How much of a resting order
/// is left is a result of the very trades under check. A wrong quantity there
/// is already a failure of the overfill check.
///
/// Two answers stay apart here, and they have to. "The sequencer never
/// published that maker" is another check's business, and the priority check
/// says nothing about it. "This walk has not reached that maker yet" is a
/// trade against an order that did not exist yet, and the priority check
/// reports it, at the message that publishes the maker, which is where this
/// walk learns which of the two answers it has.
///
/// `too_old` is the first message this build could not read. The survey walk
/// covers this same history and ends the run before this check runs. So
/// `too_old` here is normally impossible. Only normally: a sequencer is free
/// to serve different bytes to the second walk. A book that quietly lost an
/// order would then fail honest trades as trades against nothing.
///
/// # Why this holds no trade row it is not using
///
/// `record` hands every row over twice, once at each of the row's two orders,
/// in message order. So the only rows this function holds are the fills of the
/// one order that is arriving, which the book bounds, and the one row read
/// ahead inside `Sides`. `verify/trades.rs` states that rule.
async fn replay_the_history(
    history: &History<'_>,
    session: &mut Option<String>,
    record: &Record<'_>,
    stop_at: OrderId,
) -> Result<Replayed, String> {
    let mut replayed = Replayed::new();

    // The two checks a row answers on its own, in trade id order. They need no
    // message and no book, so they run over their own scan of the record and
    // hold nothing.
    let mut row_number: u64 = 0;
    record.by_trade_id(|trade| {
        row_number += 1;
        replayed.rows.ids.checked += 1;
        if trade.trade_id != row_number {
            replayed.rows.ids.fail(format!(
                "row {} has trade_id {}, expected {}",
                row_number, trade.trade_id, row_number
            ));
        }
        replayed.rows.positive.checked += 1;
        if trade.qty_tenths <= 0 {
            replayed.rows.positive.fail(format!(
                "trade {} filled {} tenths",
                trade.trade_id, trade.qty_tenths
            ));
        }
    })?;

    // A history runs under rule set 1 until it names a rule set. Rule set 1
    // lets one account trade with itself.
    let mut rules = Rules::GENESIS;
    let mut named = NamedOrders::default();
    let mut book = ReplayBook::default();
    // This walk keeps its own listing state. What decides whether an order
    // could rest is the state of the log at the point that order sits. The
    // variable is named for what it holds, and not for the module the rule
    // lives in, so `listings::replayed` below reads as a module name.
    let mut open_symbols = Listings::default();
    let mut mids = MidHistory::default();
    // This walk keeps its own operator state, for the same reason the listings
    // above are its own. What decides whether a message may act is the key in
    // force at the point that message sits. The two walks read the same
    // messages in the same order and reach the same answer, so this walk
    // ignores exactly the messages the first walk ignored. The first walk's
    // count is the one reported. This copy is here to make the book replay
    // agree with that count.
    let mut operator = Operator::new();
    let mut not_reached = NotReached::default();

    // The trade record, read in the order the messages arrive. The statement
    // is held here because the rows borrow it.
    let mut statement = record.prepare()?;
    let mut sides = Sides::open(statement.as_mut(), record)?;
    // A trade record that stops being readable part way through. The walk
    // takes a closure that returns nothing, so the reason comes out here and
    // ends the run below. A checker that walked on would report on a trade
    // record it had read only in part.
    let mut unreadable_record: Option<String> = None;

    // No tree on the second walk. The first walk already hashed every message
    // and checked the log's nodes against them. Doing that twice would ask the
    // sequencer for the same pages again.
    walk_history(history, session, Some(stop_at), None, |raw, session| {
        if unreadable_record.is_some() {
            return;
        }
        // Every row of the trade record that names this message, before the
        // message itself is read. Each one holds its order open until the row
        // is checked, so an order the book drops early is still here to check
        // the row against.
        //
        // `fills` is what the trade record gives this one arriving order. The
        // book bounds how many that is: a fill takes a resting order, and one
        // arriving order cannot take more orders than the book holds.
        //
        // A message that reuses an id it has already published takes its rows
        // here once, at the first message under that id, and the second copy
        // gets none. The whole trade record used to be indexed by taker id, so
        // both copies replayed the same rows and the report named the second
        // copy as a fill against an order that had already gone. The check
        // `the feed published each order id once` reports the reused id
        // either way, and the run fails on it.
        let mut here: Vec<TradeSide> = Vec::new();
        let mut fills: Vec<LoggedTrade> = Vec::new();
        loop {
            match sides.take_up_to(raw.id) {
                Ok(Some(side)) => {
                    named.wanted(side.at);
                    if side.taker && side.at == raw.id {
                        fills.push(side.trade.clone());
                    }
                    here.push(side);
                }
                Ok(None) => break,
                Err(why) => {
                    unreadable_record = Some(why);
                    return;
                }
            }
        }

        // A message this build cannot read moves no book. The rows above are
        // still checked, below, so every row of the trade record is read the
        // same number of times whatever this build makes of the messages. The
        // run ends at exit 3 on `too_old` before any of it is printed.
        //
        // An operator message the log's operator did not write acts on
        // nothing, and the same holds for it.
        let read = raw.parse();
        if let Err(unreadable) = &read {
            replayed.too_old.get_or_insert(unreadable.clone());
        }
        if let Ok(message) = &read
            && operator.accepts(raw.id, message, session)
        {
            match message {
                OrderMessage::New { id, timestamp, .. } => {
                    named.published(*id, &message, &open_symbols);
                    #[cfg(test)]
                    if let Some(order) = named.get(*id) {
                        replayed.published.insert(*id, order.clone());
                    }
                    // The terms this order traded on are the terms the
                    // sequencer published first under this id. Three sources,
                    // in order: the copy this walk kept for the trade record,
                    // the copy still resting in the book, and this message.
                    // This message is used only when it is the only copy.
                    if let Some(taker) = named
                        .get(*id)
                        .or_else(|| book.order(*id))
                        .cloned()
                        .or_else(|| FeedOrder::published(&message, &open_symbols))
                    {
                        arrived(
                            &mut replayed,
                            &mut named,
                            &mut book,
                            &mut mids,
                            rules,
                            *id,
                            *timestamp,
                            &taker,
                            &fills,
                        );
                    }
                }
                OrderMessage::Cancel {
                    id,
                    timestamp,
                    account,
                    target_id,
                    ..
                } => {
                    // The record the `no fill against an already cancelled
                    // order` check reads. The owner comes from the order the
                    // sequencer published, and not from the book: an order
                    // that has already traded in full still has an owner, and
                    // a row that names it after this cancel is still a row
                    // against a cancelled order.
                    named.cancelled(*target_id, *id, *account);
                    // Only a cancel from the order's own account empties a
                    // price level. A cancel from another account is refused,
                    // and the order it names keeps its place in line. An order
                    // that is not resting has no place to lose. So the book is
                    // the only record this code needs.
                    if cancel_takes_effect(
                        book.order(*target_id).map(|target| target.account),
                        *id,
                        *account,
                        *target_id,
                    ) {
                        let symbol = book
                            .order(*target_id)
                            .map(|target| target.symbol.clone())
                            .unwrap_or_default();
                        book.remove(*target_id);
                        // A cancel moves a book, so it ends the mid price that
                        // book was showing. Without this line, an account
                        // could place an order, have the order counted into
                        // the reference price, and cancel it again at no cost.
                        mids.showed(&symbol, *timestamp, book.mid_cents(&symbol));
                    }
                }
                // The listing rule, on the walk that holds a book. A delist
                // empties the book it closed, and closes every order the trade
                // record still names on that market.
                OrderMessage::ListSymbol { .. } | OrderMessage::DelistSymbol { .. } => {
                    listings::replayed(
                        &mut open_symbols,
                        &mut book,
                        &mut mids,
                        &mut named,
                        &message,
                    );
                }
                // The rules the messages after this one are replayed under.
                // This walk is the one that has to act on the change.
                // Everything above depends on which orders rest, and rule set
                // 2 changes that.
                OrderMessage::EngineRule { version, .. } => match Rules::known(*version) {
                    Some(named_set) => rules = named_set,
                    None => {
                        replayed
                            .too_old
                            .get_or_insert_with(|| unknown_rule_set(raw, *version));
                    }
                },
            }
        }

        // Every row whose second order the walk has now reached, in trade id
        // order. The trade record hands the maker side of a row over before
        // the taker side at the same message, and both can be a row's second
        // side. A report that named its rows in that order would be harder to
        // read against the trade record than one that names them in the order
        // the rows are written.
        here.sort_by_key(|side| side.trade.trade_id);
        for side in here {
            if !checked_here(&side) {
                continue;
            }
            settle(&mut replayed, &mut named, &mut not_reached, &side);
        }
    })
    .await?;

    if let Some(why) = unreadable_record {
        return Err(why);
    }

    // Every row the walk never reached. Both of its orders name a message the
    // sequencer has not published, so no message will ever bring it in.
    while let Some(side) = sides.take_rest()? {
        named.wanted(side.at);
        if checked_here(&side) {
            settle(&mut replayed, &mut named, &mut not_reached, &side);
        }
    }

    not_reached.add_to(&mut replayed.priority);
    // Every order still open. A row the walk never reached leaves its two
    // orders open, so the overfill check counts those fills here.
    named.finish(&mut replayed.rows.overfill);
    replayed.rows.compare_the_ledgers();
    #[cfg(test)]
    {
        replayed.open_symbols = open_symbols;
    }
    Ok(replayed)
}

/// Runs the checks that need the book as it stood when one order arrived.
///
/// `fills` is what the trade record gives this arriving order. The book is
/// moved by those fills, and by what the rules leave resting of the order.
#[allow(clippy::too_many_arguments)]
fn arrived(
    replayed: &mut Replayed,
    named: &mut NamedOrders,
    book: &mut ReplayBook,
    mids: &mut MidHistory,
    rules: Rules,
    id: OrderId,
    timestamp: u64,
    taker: &FeedOrder,
    fills: &[LoggedTrade],
) {
    // Cancel newest, before anything else this order might do. Cancel newest
    // means the arriving order is the one removed when an account would trade
    // with itself. `self_trade` states the rule. It reports both of its checks
    // and says whether the order was refused.
    if self_trade::observe(&mut replayed.self_trade, taker, book, rules, fills) {
        // The rule refused the order, so it made no trade and does not rest.
        // The priority check reads none of these rows, and `settle` needs to
        // know that when it reaches a maker the sequencer published later.
        named.refused(id);
        return;
    }

    let maker_side = match taker.side {
        Side::Buy => Side::Sell,
        Side::Sell => Side::Buy,
    };
    // Worked out before the trades below move the book. That is the moment the
    // exchange had to decide. The reference price is what the book had already
    // shown, and the terms are read against the book this order arrived at.
    let reference_cents = mids.reference_cents(&taker.symbol, timestamp);
    let fate = order_terms::observe(
        &mut replayed.order_terms,
        id,
        taker,
        book,
        reference_cents,
        fills,
    );
    let mut remaining = taker.qty_tenths;
    for trade in fills {
        replayed.priority.checked += 1;
        if !named.reached(trade.maker_order) {
            // The walk has not reached the message that published this maker.
            // Two histories give that answer: one where the sequencer
            // published the maker after its own taker, and one where the
            // sequencer published no order under that id at all. The two are a
            // different fault, and this walk knows which only when it gets
            // there. So the maker side of this row carries the answer, and
            // `settle` reports it at that message.
            continue;
        }
        let Some(maker) = named.get(trade.maker_order) else {
            // The "both sides exist on the feed" check names this trade. There
            // is no place in the book to check the trade against.
            continue;
        };
        if book.remaining(trade.maker_order).is_none() {
            replayed.priority.fail(format!(
                "trade {}: order {} was not resting in the feed's own book \
                 when order {} arrived",
                trade.trade_id, trade.maker_order, trade.taker_order
            ));
            continue;
        }
        match book.next_in_line(&taker.symbol, maker_side) {
            Some((price, first)) if (price, first) != (maker.price_cents, trade.maker_order) => {
                replayed.priority.fail(format!(
                    "trade {}: order {} filled order {} at {} cents, but order {} \
                     at {} cents was ahead of it",
                    trade.trade_id,
                    trade.taker_order,
                    trade.maker_order,
                    maker.price_cents,
                    first,
                    price
                ));
            }
            None => replayed.priority.fail(format!(
                "trade {}: nothing was resting to {:?} on {} when order {} arrived",
                trade.trade_id, maker_side, taker.symbol, trade.taker_order
            )),
            _ => {}
        }
        // The collar, on the price the exchange was allowed to trade this
        // order at. That is not the bound the sender signed. Only a market
        // order has two bounds.
        if let OrderFate::Allowed { limit_cents, .. } = &fate
            && matches!(taker.order_type, OrderType::Market)
        {
            replayed.order_terms.collared.checked += 1;
            let inside = match taker.side {
                Side::Buy => trade.price_cents <= *limit_cents,
                Side::Sell => trade.price_cents >= *limit_cents,
            };
            if !inside {
                replayed.order_terms.collared.fail(format!(
                    "trade {}: market order {} filled a {:?} at {}, and the collar \
                     around a reference price of {} allowed no worse than {}",
                    trade.trade_id,
                    trade.taker_order,
                    taker.side,
                    trade.price_cents,
                    reference_cents.unwrap_or_default(),
                    limit_cents
                ));
            }
        }
        book.take(trade.maker_order, trade.qty_tenths);
        remaining = remaining.saturating_sub(trade.qty_tenths);
    }
    // Only what the rules leave resting goes into the book. Four things are
    // gone by now. What is left of an immediate-or-cancel order, which trades
    // what it can at once and drops the rest. What is left of a market order.
    // An order the rules refuse. And an order for a symbol the log had not
    // opened, which never entered a book at all; `tradable` is that part of
    // the answer. A replay that kept any of the four would report correct
    // trades that went past them as trades that jumped the line.
    let rests = matches!(fate, OrderFate::Allowed { rests: true, .. });
    let symbol = taker.symbol.clone();
    if taker.tradable && rests && remaining > 0 {
        book.rest(id, taker.clone(), remaining);
    }
    // What the book shows once this message is done with it. That is the
    // sample the reference price is built from.
    mids.showed(&symbol, timestamp, book.mid_cents(&symbol));
}

/// Checks one row of the trade record, at whichever of its two orders the walk
/// reached second, and closes the two orders' records if nothing else names
/// them.
fn settle(
    replayed: &mut Replayed,
    named: &mut NamedOrders,
    not_reached: &mut NotReached,
    side: &TradeSide,
) {
    let trade = &side.trade;
    // Whether the replay put this row through the book. It did that at the
    // message that published the row's taker, and only if the sequencer
    // published an order there.
    let taker_arrived = named.get(trade.taker_order).is_some();
    if !taker_arrived {
        not_reached.note(trade);
    } else if !side.taker
        && named.get(trade.maker_order).is_some()
        && named.took_the_book(trade.taker_order)
    {
        // The sequencer published this maker later in the history than the
        // maker's own taker. So the maker was not resting when the taker
        // arrived: it did not exist yet. The priority check counted this row
        // at the taker's message and waited for this answer, because a walk
        // that had not reached the maker could not tell this case from the
        // one below.
        //
        // A maker the sequencer published no order for at all is the other
        // case, and the priority check says nothing about it. The check
        // `both sides of every trade exist on the feed` reports that one. Two
        // faults, two checks, and each one names what it found.
        replayed.priority.fail(format!(
            "trade {}: order {} was not resting in the feed's own book \
             when order {} arrived",
            trade.trade_id, trade.maker_order, trade.taker_order
        ));
    }
    replayed.rows.check(trade, named);
    named.done_with(trade.maker_order, &mut replayed.rows.overfill);
    named.done_with(trade.taker_order, &mut replayed.rows.overfill);
}

/// Adds one side of a trade to an account's running cash, and refuses to wrap
/// round.
///
/// Returns false when the row would overflow the total. A changed price is
/// exactly the input this check exists to catch. So a changed price must not
/// be the input that crashes the checker.
fn add_cash(ledger: &mut HashMap<AccountId, i64>, account: AccountId, amount: i64) -> bool {
    let total = ledger.entry(account).or_default();
    match total.checked_add(amount) {
        Some(sum) => {
            *total = sum;
            true
        }
        None => false,
    }
}

/// The answer for a history this build could not read to the end.
///
/// ENGINE.md section 6 gives three states. It says a failed check outranks
/// cannot-interpret. Without that order, a binary older than the log would be
/// a way to turn a failing report into a status nobody acts on.
/// `checks_passed` covers every check this build could still make over the
/// bytes the sequencer served: the signed head, and who wrote the operator
/// messages the build did read. A signature that does not check out is a
/// definite answer about a message this build read. So that case is exit 1,
/// and never exit 3.
fn incomplete(checks_passed: bool, too_old: &TooOld) -> Verdict {
    if checks_passed {
        Verdict::TooOld(too_old.clone())
    } else {
        Verdict::Failed
    }
}

/// Compares the latest run in `state_db` against the sequencer at `feed_url`.
///
/// Prints one line for every check, whatever the answer. A check whose result
/// is only an exit code is a check nobody reads.
///
/// Three answers, not two. `Verdict::TooOld` was added when the readers
/// stopped serializing the messages again. It means two things at once. The
/// sequencer's signed chain was checked over the bytes it served, and the
/// chain holds. This binary cannot read one of the messages in that same
/// history, so the checks that need the messages read were not made. That is
/// a fact about this binary. Reporting it as "reconciliation failed" would
/// send an operator looking for fraud in an exchange that is working
/// correctly.
pub async fn verify_trades(
    state_db: &Path,
    feed_url: &str,
    root_anchor: Option<&RootAnchorSource>,
) -> Result<Verdict, String> {
    // What the run says about itself, and how far its trade record goes. No
    // trade row is held: the checks below read the record in two scans of
    // their own, and each scan stops at the row this call fixed.
    let run = Run::open(state_db)?;
    let record = run.record();
    let client = fetch::client()?;
    let history = History::Feed {
        client: &client,
        url: feed_url,
    };
    // Head first, then messages. The messages then always reach past the
    // signed id, even though the sequencer keeps publishing between the two
    // requests.
    let head = read_feed_head(&client, feed_url).await;
    // The tree head and the anchors, for the same reason and before the same
    // walk. Both name the tree sizes the walk has to keep a root at, and the
    // walk passes each size only once.
    let sth = crate::anchor::fetch_tree_head(&client, feed_url).await;
    let anchors = read_root_anchors(root_anchor).await;
    let mut tree = TreeWalk::new(&root_sizes(&sth, anchors.as_ref()));
    let mut session_seen: Option<String> = None;
    let survey = survey_history(&history, &mut session_seen, &head, &mut tree).await?;
    let wire_session = session_seen.clone();
    let mut head_checks = check_feed_head(
        run.run_id,
        run.public_key.as_deref(),
        &head,
        &folded_chain(&survey.chain),
        // How far the run went, as far as the checker can show it. That is the
        // highest message id a recorded trade names. The run committed at
        // least that far, so a signed head that stops earlier leaves those
        // messages unsigned. The trade record is the only cursor the checker
        // reads, so an empty trade record claims nothing. SQLite works the
        // number out as it walks the rows, so no row is held to find it.
        run.claimed_to,
    );
    // The tree, beside the chain, and printed with it. Both are hashes over
    // the bytes the sequencer served. So both hold over a history this build
    // cannot read, and both are as true here as they ever are.
    let tree_checks = check_tree(&sth, anchors.as_ref(), tree.fold());
    head_checks.extend(tree_checks.checks);
    let mut tree_notes = tree_checks.notes;
    // And the log's own nodes against the nodes these messages make. Same
    // hashing, same walk. These nodes are the one record of this exchange that
    // nobody outside the operator used to check.
    let (nodes, no_log) = tree.finish();
    head_checks.push(nodes);
    tree_notes.extend(no_log);

    // Who the log's operator is, and whether the operator really wrote every
    // operator message in the log. This is the checker's own copy of ENGINE.md
    // section 3.1. It is taken from the walk above, and not made again here,
    // because the walk is where the messages went past.
    let operator_line = survey.operator.line();
    let operator = survey.operator.into_check();

    // The one thing this build can still say about a history it cannot read,
    // said before anything that needs the messages read. The chain check above
    // hashes the bytes the sequencer served, so it is as good here as it ever
    // is. Every check below asks what an order was, and there is a message
    // this build has no answer for.
    if let Some(too_old) = survey.too_old {
        println!(
            "Reconciling {} trades from run {} of {} against the feed\n",
            run.rows,
            run.run_id,
            state_db.display(),
        );
        let head_passed = head_checks
            .iter()
            .map(|c| c.report())
            .fold(true, |every, ok| every && ok);
        for note in &tree_notes {
            println!("{}", note);
        }
        // The operator check belongs on this side of the line too. It reads a
        // signature over a message this build did read. So it is a definite
        // answer about that message, and not a gap in what this build can say.
        let operator_passed = operator.report();
        println!("{}", operator_line);
        // Unless one of those checks failed. They hash the bytes the sequencer
        // served, and they check signatures over those bytes. So they are as
        // true against a history this build cannot read as against one it can.
        // A real failure outranks being too old. Without that order, an old
        // binary would be a way to turn a failing check into an exit status
        // nobody is called out for.
        if let Verdict::Failed = incomplete(head_passed && operator_passed, &too_old) {
            println!(
                "\nReconciliation FAILED. A check over the bytes the feed served did not \
                 hold.\n  {}\n  so the checks that read the messages stop there.",
                too_old
            );
            return Ok(Verdict::Failed);
        }
        println!(
            "\nReconciliation INCOMPLETE, exit status 3.\n  {}",
            too_old.notice(
                "The feed's signed chain was checked over the bytes it served, as far as \
                 its head, and it holds."
            )
        );
        return Ok(Verdict::TooOld(too_old));
    }

    // Which history is on the wire, before anything is compared against it.
    // The exchange records the session it read on first contact. A sequencer
    // that serves a different session is serving a different history. A
    // different history that hands out the same order ids again would let this
    // run's trades be checked against another market's orders, and pass.
    let mut session = Check::new("the feed is the history this run consumed");
    session.checked = 1;
    let replaced_feed = match (&run.session, &wire_session) {
        (Some(ours), Some(theirs)) if ours == theirs => false,
        (Some(ours), Some(theirs)) => {
            session.fail(format!(
                "run {} consumed feed session {}, this feed serves session {}",
                run.run_id, ours, theirs
            ));
            true
        }
        (Some(ours), None) => {
            session.fail(format!(
                "run {} consumed feed session {}, this feed announces no session at all",
                run.run_id, ours
            ));
            true
        }
        (None, _) => {
            session.fail(format!(
                "run {} never recorded a feed session, so its trades cannot be tied to \
                 the history this feed is serving",
                run.run_id
            ));
            false
        }
    };

    let mut duplicates = Check::new("the feed published each order id once");
    duplicates.checked = survey.published + survey.duplicates;
    for id in &survey.duplicate_ids {
        duplicates.fail(format!(
            "order id {} appears more than once in the feed's history; a trade naming it \
             cannot be said to mean either order",
            id
        ));
    }

    // The second walk of the history, before anything is printed. A sequencer
    // that fails part way through the walk ends the run with a reason, and
    // with no report half written. The walk is skipped in the two cases where
    // its result would never be printed. With no trades there is no order to
    // check. A sequencer that serves another session is not serving this run's
    // history to replay.
    let replayed = if replaced_feed || run.rows == 0 {
        None
    } else {
        let replayed =
            replay_the_history(&history, &mut session_seen, &record, survey.last_id).await?;
        // The first walk read every one of these messages. So this can only
        // happen if the sequencer served different bytes to the second walk.
        // The run ends here, instead of printing a book replay that skipped a
        // message.
        if let Some(too_old) = replayed.too_old {
            println!(
                "\nReconciliation INCOMPLETE, exit status 3.\n  {}",
                too_old.notice(
                    "The feed's signed chain holds, and this message was readable when the \
                     history was walked the first time."
                )
            );
            return Ok(Verdict::TooOld(too_old));
        }
        Some(replayed)
    };

    println!(
        "Reconciling {} trades from run {} of {} against {} orders on the feed\n",
        run.rows,
        run.run_id,
        state_db.display(),
        survey.published
    );

    // `fold`, not `all`. `all` stops at the first false. It would print the
    // first failing check and drop every check after it without a word. The
    // run with the most to say about what went wrong would then say the least.
    let head_passed = head_checks
        .iter()
        .map(|c| c.report())
        .fold(true, |every, ok| every && ok);
    for note in &tree_notes {
        println!("{}", note);
    }
    let session_passed = session.report();
    // Who opened this log, printed under the check, so a reader sees the key
    // and not only that the check held.
    let operator_passed = operator.report();
    println!("{}", operator_line);
    let duplicates_passed = duplicates.report();
    if replaced_feed {
        println!(
            "\nReconciliation FAILED. This feed is not serving the history run {} was built \
             from, so its trades were not checked against it.",
            run.run_id
        );
        return Ok(Verdict::Failed);
    }
    if run.rows == 0 {
        println!("  nothing else to check: the log has no trades yet");
        return Ok(Verdict::of(
            head_passed && session_passed && operator_passed && duplicates_passed,
        ));
    }

    // The second walk ran above, before the report started printing. There are
    // trades, and this is the run's own sequencer, so it ran.
    let replayed = replayed.expect("the book replay runs whenever its result is reported");

    // Every check that walk made, in the order it prints them.
    let checks = replayed.checks();
    let passed = checks
        .iter()
        .map(|c| c.report())
        .fold(true, |every, ok| every && ok)
        && head_passed
        && session_passed
        && operator_passed
        && duplicates_passed;
    println!();
    if passed {
        println!("All checks passed: the trade log and the feed agree.");
    } else {
        println!("Reconciliation FAILED. The engine and the feed disagree.");
    }
    Ok(Verdict::of(passed))
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use crate::domain::OPERATOR_ACCOUNT;
    use rusqlite::{Connection, params};

    /// The check that reports a fill against an order a message had already
    /// taken out of the book: a cancel from the order's own account, or a
    /// delist that closed the whole market.
    const CLOSED: &str = "no fill against an already cancelled order";

    /// The head checks over a head whose key the run recorded, and over a run
    /// whose trades claim nothing. An honest sequencer passes that. So a test
    /// about the chain hash does not have to state a key or a cursor.
    fn head_checks(head: &Result<FeedHead, String>, folded: &HeadChain) -> Vec<Check> {
        let pinned = head.as_ref().ok().map(|head| head.public_key.clone());
        check_feed_head(1, pinned.as_deref(), head, &folded_chain(folded), 0)
    }

    fn cancel(id: OrderId, account: AccountId, target_id: OrderId) -> OrderMessage {
        OrderMessage::Cancel {
            id,
            timestamp: id * 1000,
            account,
            target_id,
            nonce: None,
        }
    }

    /// The whole report over one fixed history, asserted as one list.
    ///
    /// Every other test in this file reads one check by name. A check that
    /// stops counting still passes all of those tests. This test names every
    /// check the second walk makes, how many rows the check read, and how many
    /// rows it failed, in one assertion. The history holds one message of most
    /// kinds, and one order of each shape the checks answer about. So every
    /// count below is above zero.
    ///
    /// The list used to hold the five checks the book replay made. It holds
    /// all seventeen now, because the checks that read a trade row against two
    /// published orders moved into the same walk when the trade record stopped
    /// being read into memory. Those counts are what says the move changed
    /// what the checker reports about nothing.
    ///
    /// Moving this code into modules must leave every number here unchanged.
    #[tokio::test]
    async fn the_whole_report_over_one_fixed_history_is_counted() {
        let messages = vec![
            list_eth(1),
            engine_rule(2, 2),
            new_order(3, 5, Side::Sell, 100.0, 5.0),
            new_order(4, 6, Side::Buy, 99.0, 5.0),
            new_order(5, 7, Side::Buy, 100.0, 5.0),
            new_order(6, 5, Side::Sell, 100.0, 5.0),
            // Account 5 buys at the price of its own sell order. Rule set 2
            // refuses the whole arriving order.
            new_order(7, 5, Side::Buy, 100.0, 5.0),
            new_order(8, 8, Side::Buy, 100.0, 5.0),
            cancel(9, 6, 4),
            new_order(10, 5, Side::Sell, 100.0, 5.0),
            new_order(11, 6, Side::Buy, 99.0, 5.0),
            // Two market orders against a mid price of 9,950 that has held for
            // the whole window. The collar then allows no price worse than
            // 10,149.
            termed(
                12,
                41_000,
                9,
                Side::Buy,
                200.0,
                2.0,
                OrderType::Market,
                TimeInForce::GoodTillCancel,
                false,
            ),
            termed(
                13,
                41_000,
                9,
                Side::Buy,
                200.0,
                3.0,
                OrderType::Market,
                TimeInForce::GoodTillCancel,
                false,
            ),
            // A post-only sell at a price that would take a resting buy order.
            // The rules refuse it.
            termed(
                14,
                42_000,
                5,
                Side::Sell,
                99.0,
                5.0,
                OrderType::Limit,
                TimeInForce::GoodTillCancel,
                true,
            ),
            delist(15, "ETH-USDC"),
        ];
        let trades = vec![
            fill_between(1, (3, 5), (5, 7), 10_000, 50, Side::Buy),
            fill_between(2, (6, 5), (7, 5), 10_000, 50, Side::Buy),
            // The row says account 8 traded with itself. The sequencer
            // published order 6 under account 5, so only the row's own fields
            // catch this.
            fill_between(3, (6, 8), (8, 8), 10_000, 50, Side::Buy),
            fill_between(4, (10, 5), (12, 9), 10_000, 20, Side::Buy),
            fill_between(5, (10, 5), (13, 9), 10_500, 30, Side::Buy),
            fill_between(6, (11, 6), (14, 5), 9_900, 50, Side::Sell),
        ];

        let surveyed = survey(&messages).await;
        assert_eq!(
            (surveyed.published, surveyed.duplicates, surveyed.last_id),
            (11, 0, 15),
            "the first walk over this history"
        );

        let report: Vec<(&str, usize, usize)> = replay(&messages, &trades)
            .await
            .checks()
            .iter()
            .map(|check| (check.name, check.checked, check.failures.len()))
            .collect();
        assert_eq!(
            report,
            vec![
                ("trade ids are 1..n with no gaps", 6, 0),
                ("both sides of every trade exist on the feed", 6, 0),
                ("maker and taker are on opposite sides", 6, 0),
                ("maker order was published before the taker", 6, 0),
                ("trade symbol matches both orders", 6, 0),
                // Row 3 says account 8 was the maker. The sequencer published
                // order 6 under account 5.
                ("trade accounts match the orders' accounts", 6, 1),
                // Row 5 printed at 10,500. Order 10 rested at 10,000.
                ("trade executed at the maker's limit price", 6, 1),
                ("price honours the taker's limit", 6, 0),
                ("every fill has positive quantity", 6, 0),
                // Ten orders took a fill. Order 6 offered 5.0 and rows 2 and 3
                // together gave it 10.0.
                ("no order filled beyond the quantity it offered", 10, 1),
                ("no fill against an already cancelled order", 6, 0),
                ("every fill went to the order next in line", 5, 0),
                ("no trade joins an account to itself", 5, 1),
                ("no fill against the taker's own resting order", 11, 1),
                ("no fill for an order the rules refuse", 1, 1),
                ("every market order filled inside its collar", 2, 1),
                // The two wrong rows above move money, and three accounts end
                // holding a total the sequencer's own orders do not produce.
                ("cash matches the prices the feed published", 6, 3),
            ],
            "the second walk over this history"
        );
    }

    /// The checker builds the sequencer's chain again from the bytes it was
    /// served. So a field the checker does not read is still hashed like every
    /// other byte. The sender's nonce is such a field: nothing else in this
    /// file looks at it. The checker used to serialize the message again
    /// instead. A build that dropped the nonce field would then report an
    /// honest sequencer as serving a history it did not sign. That is the
    /// worst false alarm the checker can raise, when the whole job of the
    /// checker is to tell the truth about the operator.
    #[tokio::test]
    async fn a_history_carrying_nonces_reconciles_against_its_signed_head() {
        let mut messages = vec![
            new_order(1, 7, Side::Buy, 100.25, 5.0),
            new_order(2, 9, Side::Sell, 100.25, 5.0),
            cancel(3, 7, 1),
        ];
        if let OrderMessage::New { nonce, .. } = &mut messages[1] {
            *nonce = Some("9f2b1c04d7e58a36bb0147fe29c3d580".to_string());
        }
        if let OrderMessage::Cancel { nonce, .. } = &mut messages[2] {
            *nonce = Some("1d47a90fe3b25c8871face0426b9d013".to_string());
        }

        // The sequencer signs the chain over what it published. The checker
        // receives those same bytes and hashes them again.
        let key = crate::logchain::ephemeral_key();
        let received = served(&messages);
        let chain = received
            .iter()
            .fold(crate::logchain::EMPTY_CHAIN, |chain, msg| {
                crate::logchain::extend_bytes(&chain, &msg.bytes)
            });
        let head = Ok(FeedHead {
            session: "sess".to_string(),
            last_id: 3,
            chain: crate::logchain::to_hex(&chain),
            public_key: crate::logchain::to_hex(key.verifying_key().as_bytes()),
            signature: crate::logchain::to_hex(
                &crate::logchain::sign_head(&key, "sess", 3, &chain).to_bytes(),
            ),
        });
        // Hashed as the pages arrive, which is the only way the checker ever
        // sees a history now.
        let mut session = None;
        let surveyed = survey_history(
            &History::Held(&received),
            &mut session,
            &head,
            &mut TreeWalk::new(&[]),
        )
        .await
        .expect("a held history is walked to its end");
        assert_eq!(surveyed.chain.counted, 3, "every message reaches the fold");
        assert!(surveyed.too_old.is_none());
        for check in head_checks(&head, &surveyed.chain) {
            assert!(
                check.failures.is_empty(),
                "{} must pass over a nonce-bearing history: {:?}",
                check.name,
                check.failures
            );
        }
    }

    /// The same check over a history whose middle message is a kind this build
    /// has never seen. The chain still holds. The checker names the message it
    /// cannot read, instead of reporting a mismatch.
    #[tokio::test]
    async fn a_history_holding_an_unknown_kind_still_verifies_its_signed_head() {
        let mut body = Vec::new();
        body.extend_from_slice(&crate::logchain::canonical_bytes(&new_order(
            1,
            7,
            Side::Buy,
            100.0,
            5.0,
        )));
        body.push(b'\n');
        body.extend_from_slice(
            br#"{"Market":{"id":2,"timestamp":2000,"account":9,"symbol":"ETH-USDC","side":"Sell","quantity":5.0}}"#,
        );
        body.push(b'\n');
        let received = wire::split_ndjson(&body).expect("the feed serves one message per line");

        let key = crate::logchain::ephemeral_key();
        let chain = received
            .iter()
            .fold(crate::logchain::EMPTY_CHAIN, |chain, msg| {
                crate::logchain::extend_bytes(&chain, &msg.bytes)
            });
        let head = Ok(FeedHead {
            session: "sess".to_string(),
            last_id: 2,
            chain: crate::logchain::to_hex(&chain),
            public_key: crate::logchain::to_hex(key.verifying_key().as_bytes()),
            signature: crate::logchain::to_hex(
                &crate::logchain::sign_head(&key, "sess", 2, &chain).to_bytes(),
            ),
        });

        let mut session = None;
        let surveyed = survey_history(
            &History::Held(&received),
            &mut session,
            &head,
            &mut TreeWalk::new(&[]),
        )
        .await
        .expect("a held history is walked to its end");

        assert_eq!(
            surveyed.chain.counted, 2,
            "a message this build cannot read is still a message it hashes"
        );
        for check in head_checks(&head, &surveyed.chain) {
            assert!(
                check.failures.is_empty(),
                "{} must not fail over a kind this build does not know: {:?}",
                check.name,
                check.failures
            );
        }
        let too_old = surveyed.too_old.expect("message 2 cannot be read");
        assert_eq!(too_old.id, 2);
        assert_eq!(too_old.kind, "Market");
        assert_eq!(Verdict::TooOld(too_old).exit_code(), 3);
    }

    /// Every kind this build reads has a replay rule, and the checker walks
    /// past none of them.
    ///
    /// This test used to make the opposite claim. It listed the kinds nothing
    /// here ran, and checked that each one ended the run at exit 3. That list
    /// is empty now. `EngineRule` left the list when this file learned to
    /// replay rule sets. `ListSymbol` and `DelistSymbol` left the list when
    /// this file learned the listing rule.
    ///
    /// So the test now claims the opposite, and the opposite is the stronger
    /// of the two claims: a history that holds one message of every kind is
    /// replayed in full. The kinds are counted, not sampled. If a sixth kind
    /// is added and nothing here reads it, this test fails. The run it
    /// protects then reports exit 3, instead of a pass over a history it
    /// understood only in part.
    #[tokio::test]
    async fn every_kind_this_build_reads_has_a_replay_rule() {
        let history = [
            OrderMessage::EngineRule {
                id: 1,
                timestamp: 1000,
                account: OPERATOR_ACCOUNT,
                version: 1,
                nonce: None,
                public_key: String::new(),
                signature: String::new(),
            },
            list_eth(2),
            new_order(3, 7, Side::Buy, 100.0, 5.0),
            cancel(4, 7, 3),
            delist(5, "ETH-USDC"),
        ];
        let kinds: Vec<&str> = history
            .iter()
            .map(|message| match message {
                OrderMessage::New { .. } => "New",
                OrderMessage::Cancel { .. } => "Cancel",
                OrderMessage::EngineRule { .. } => "EngineRule",
                OrderMessage::ListSymbol { .. } => "ListSymbol",
                OrderMessage::DelistSymbol { .. } => "DelistSymbol",
            })
            .collect();
        assert_eq!(kinds.len(), 5, "every kind this build knows is here");

        let received = served(&history);
        let surveyed = survey_raw(&received).await;
        assert!(
            surveyed.too_old.is_none(),
            "the survey stopped at a kind it should replay: {:?}",
            surveyed.too_old.map(|t| t.kind)
        );
        assert_eq!(surveyed.last_id, 5, "and it reached the end");

        // The second walk too, which is the one that holds a book.
        let mut session = None;
        let (replayed, too_old) = replay_the_history(
            &History::Held(&received),
            &mut session,
            &Record::Held(&[]),
            surveyed.last_id,
        )
        .await
        .map(|r| (r.priority.checked, r.too_old))
        .expect("a held history is replayed to its end");
        assert!(
            too_old.is_none(),
            "the book replay stopped at a kind it should replay"
        );
        assert_eq!(replayed, 0, "there are no trades in this history to check");
    }

    /// And the failing case still fails over the same history. One byte of the
    /// message this build cannot read is changed, and the chain check fails.
    #[tokio::test]
    async fn tampering_is_still_caught_over_a_history_this_build_cannot_read() {
        let honest =
            br#"{"Market":{"id":1,"timestamp":1000,"account":9,"symbol":"ETH-USDC","side":"Sell","quantity":5.0}}"#;
        let tampered =
            br#"{"Market":{"id":1,"timestamp":1000,"account":8,"symbol":"ETH-USDC","side":"Sell","quantity":5.0}}"#;
        let signed_chain =
            crate::logchain::extend_bytes(&crate::logchain::EMPTY_CHAIN, honest.as_slice());
        let key = crate::logchain::ephemeral_key();
        let head = Ok(FeedHead {
            session: "sess".to_string(),
            last_id: 1,
            chain: crate::logchain::to_hex(&signed_chain),
            public_key: crate::logchain::to_hex(key.verifying_key().as_bytes()),
            signature: crate::logchain::to_hex(
                &crate::logchain::sign_head(&key, "sess", 1, &signed_chain).to_bytes(),
            ),
        });

        let mut body = tampered.to_vec();
        body.push(b'\n');
        let received = wire::split_ndjson(&body).expect("one message");
        let mut session = None;
        let surveyed = survey_history(
            &History::Held(&received),
            &mut session,
            &head,
            &mut TreeWalk::new(&[]),
        )
        .await
        .expect("a held history is walked to its end");

        let failures: Vec<String> = head_checks(&head, &surveyed.chain)
            .iter()
            .flat_map(|check| check.failures.clone())
            .collect();
        assert_eq!(failures.len(), 1, "{:?}", failures);
        assert!(failures[0].contains("recomputed chain"), "{}", failures[0]);
    }

    /// Writes a state database that holds one run and no trades, so a test can
    /// read back what the run recorded.
    fn run_db(dir: &tempfile::TempDir, name: &str, pubkey: Option<&str>) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let conn = Connection::open(&path).expect("create the state database");
        conn.execute_batch(
            "CREATE TABLE runs (
               run_id       INTEGER PRIMARY KEY,
               feed_session TEXT,
               feed_pubkey  TEXT
             );
             CREATE TABLE trades (
               run_id        INTEGER NOT NULL,
               trade_id      INTEGER NOT NULL,
               timestamp     INTEGER NOT NULL,
               symbol        TEXT    NOT NULL,
               price_cents   INTEGER NOT NULL,
               qty_tenths    INTEGER NOT NULL,
               maker_order   INTEGER NOT NULL,
               maker_account INTEGER NOT NULL,
               taker_order   INTEGER NOT NULL,
               taker_account INTEGER NOT NULL,
               taker_side    TEXT    NOT NULL
             );",
        )
        .expect("the columns this tool reads");
        conn.execute(
            "INSERT INTO runs (run_id, feed_session, feed_pubkey) VALUES (1, 'sess', ?1)",
            params![pubkey],
        )
        .expect("one run");
        path
    }

    /// The head signs itself. So the key the head carries proves only that the
    /// head agrees with itself. Anyone can sign a head with a key they made
    /// up. What stops the operator denying the history later is the key the
    /// run recorded on first contact. The checker has to read that key and
    /// compare.
    ///
    /// Two runs, two answers. The first run recorded a key, and the sequencer
    /// now serves a head signed by another key. That is a different authority,
    /// and the check fails. The second run recorded no key at all. Nothing
    /// ties its trades to any authority, so that check fails too. A state
    /// database written before the column existed now reports a failed head
    /// check, where it used to report nothing.
    #[test]
    fn a_head_signed_by_a_key_the_run_never_pinned_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let pinned = crate::logchain::ephemeral_key();
        let pinned_hex = crate::logchain::to_hex(pinned.verifying_key().as_bytes());

        // The head is honest about itself. It is signed over the chain of an
        // empty history, by a key that is not the recorded one.
        let other = crate::logchain::ephemeral_key();
        let chain = crate::logchain::EMPTY_CHAIN;
        let head = Ok(FeedHead {
            session: "sess".to_string(),
            last_id: 0,
            chain: crate::logchain::to_hex(&chain),
            public_key: crate::logchain::to_hex(other.verifying_key().as_bytes()),
            signature: crate::logchain::to_hex(
                &crate::logchain::sign_head(&other, "sess", 0, &chain).to_bytes(),
            ),
        });
        let folded = FoldedChain { chain, counted: 0 };

        let path = run_db(&dir, "pinned.db", Some(&pinned_hex));
        let run = Run::open(&path).expect("read the run");
        assert_eq!(run.run_id, 1);
        assert_eq!(run.rows, 0, "this run recorded no trades");
        assert_eq!(run.claimed_to, 0, "so it claims no message");
        assert_eq!(
            run.public_key.as_deref(),
            Some(pinned_hex.as_str()),
            "the checker reads the key the run pinned"
        );

        let failures: Vec<String> =
            check_feed_head(run.run_id, run.public_key.as_deref(), &head, &folded, 0)
                .iter()
                .flat_map(|check| check.failures.clone())
                .collect();
        assert_eq!(failures.len(), 1, "{:?}", failures);
        assert!(
            failures[0].contains("consumed a history signed by"),
            "{}",
            failures[0]
        );

        // The same head against a run that pinned nothing.
        let path = run_db(&dir, "unpinned.db", None);
        let run = Run::open(&path).expect("read the run");
        assert_eq!(run.public_key, None);
        let failures: Vec<String> =
            check_feed_head(run.run_id, run.public_key.as_deref(), &head, &folded, 0)
                .iter()
                .flat_map(|check| check.failures.clone())
                .collect();
        assert_eq!(failures.len(), 1, "{:?}", failures);
        assert!(
            failures[0].contains("recorded no feed public key"),
            "{}",
            failures[0]
        );
    }

    // The rule sets a history runs under. The log says which rules a message
    // is replayed under, and this binary does not. So a rule set this build
    // cannot replay has to end the run.

    /// A rule set this build knows does not stop the checker. A rule set is
    /// the first thing the genesis log says: ENGINE.md section 3 opens the log
    /// with `EngineRule` rules v1. A checker that stopped here would be
    /// useless from the log's first message.
    ///
    /// The listing comes first, so the orders after it have a book to rest in.
    #[tokio::test]
    async fn an_engine_rule_this_build_replays_does_not_stop_the_checker() {
        for version in [1u32, 2] {
            let messages = vec![
                list_eth(1),
                engine_rule(2, version),
                new_order(3, 5, Side::Sell, 100.0, 5.0),
                new_order(4, 7, Side::Buy, 100.0, 5.0),
            ];
            let trades = vec![fill_between(1, (3, 5), (4, 7), 10_000, 50, Side::Buy)];
            let surveyed = survey(&messages).await;
            assert!(
                surveyed.too_old.is_none(),
                "rule set {} stopped the survey",
                version
            );
            let replayed = replay(&messages, &trades).await;
            assert!(
                replayed.priority.failures.is_empty(),
                "{:?}",
                replayed.priority.failures
            );
            assert!(replayed.self_trade.paired.failures.is_empty());
            assert!(replayed.self_trade.refused.failures.is_empty());
        }
    }

    /// A rule set the checker cannot replay does stop the checker, and the
    /// checker names that rule set. The exchange makes the opposite choice. It
    /// counts the message and goes on serving books, because an exchange that
    /// stops is an exchange that is down. The whole job of the checker is to
    /// refuse to say a history holds when it could not check the history.
    #[tokio::test]
    async fn an_engine_rule_this_build_cannot_replay_stops_the_checker() {
        let messages = vec![
            new_order(1, 5, Side::Sell, 100.0, 5.0),
            engine_rule(2, 9),
            new_order(3, 7, Side::Buy, 100.0, 5.0),
        ];
        let surveyed = survey(&messages).await;
        let too_old = surveyed
            .too_old
            .expect("rule set 9 is not a rule set this build replays");
        assert_eq!(too_old.id, 2);
        assert_eq!(too_old.kind, "EngineRule");
        assert!(
            too_old.reason.contains("rule set 9"),
            "the reason names the rule set: {}",
            too_old.reason
        );
        assert!(
            too_old.reason.contains("cannot apply"),
            "{}",
            too_old.reason
        );
        // The notice says the sequencer did nothing wrong, in those words.
        assert!(
            too_old
                .notice("The chain verified to message 3.")
                .contains("not tampering")
        );
        assert_eq!(Verdict::TooOld(too_old).exit_code(), 3);
    }

    /// Account 9 cannot cancel account 5's order. The exchange refuses that
    /// cancel and the order goes on resting. So the checker must not record
    /// the order as cancelled. Recording it would accuse the trade that
    /// follows.
    ///
    /// The trade is what makes this test say anything. The checker keeps only
    /// the cancels of an order that some trade names. A history checked
    /// against no trades has an empty cancel index, whatever its cancels say.
    #[tokio::test]
    async fn a_cancel_from_another_account_cancels_nothing() {
        let messages = vec![
            list_eth(1),
            new_order(2, 5, Side::Sell, 100.0, 5.0),
            cancel(3, 9, 2),
        ];
        let trades = vec![fill(2, 4, 10_000, 50)];
        let closed = replay_check(&messages, &trades, CLOSED).await;
        assert_eq!(closed.checked, 1, "the trade names order 2");
        assert_eq!(closed.failed, 0, "{:?}", closed.failures);
    }

    #[tokio::test]
    async fn a_cancel_from_the_account_that_placed_the_order_cancels_it() {
        let messages = vec![
            list_eth(1),
            new_order(2, 5, Side::Sell, 100.0, 5.0),
            cancel(3, 5, 2),
        ];
        let trades = vec![fill(2, 4, 10_000, 50)];
        let closed = replay_check(&messages, &trades, CLOSED).await;
        assert_eq!(closed.failed, 1, "{:?}", closed.failures);
        assert!(
            closed.failures[0].contains("message 3 had cancelled"),
            "{}",
            closed.failures[0]
        );
    }

    /// The same rule inside the book replay. A refused cancel leaves the order
    /// in its price level. So the trade that takes the order is the trade that
    /// was next in line, and not a trade against an order that had left the
    /// book.
    #[tokio::test]
    async fn a_fill_after_a_refused_cancel_keeps_its_place_in_line() {
        let messages = vec![
            list_eth(1),
            new_order(2, 5, Side::Sell, 100.0, 5.0),
            cancel(3, 9, 2),
            new_order(4, 7, Side::Buy, 100.0, 5.0),
        ];
        let trades = vec![fill(2, 4, 10_000, 50)];
        let check = priority(&messages, &trades).await;
        assert_eq!(check.checked, 1);
        assert!(check.failures.is_empty(), "{:?}", check.failures);
    }

    #[tokio::test]
    async fn a_fill_after_the_owner_cancelled_is_reported() {
        let messages = vec![
            list_eth(1),
            new_order(2, 5, Side::Sell, 100.0, 5.0),
            cancel(3, 5, 2),
            new_order(4, 7, Side::Buy, 100.0, 5.0),
        ];
        let trades = vec![fill(2, 4, 10_000, 50)];
        let check = priority(&messages, &trades).await;
        assert_eq!(check.failures.len(), 1, "{:?}", check.failures);
        assert!(
            check.failures[0].contains("was not resting"),
            "{}",
            check.failures[0]
        );
        let closed = replay_check(&messages, &trades, CLOSED).await;
        assert!(
            closed.failures[0].contains("message 3 had cancelled"),
            "{}",
            closed.failures[0]
        );
    }

    /// The history arrives one page at a time. So the case that has to keep
    /// working is a history longer than one page. An order published on the
    /// first page trades against a taker published on the third page. The book
    /// that puts the two in line was rebuilt from messages, and the checker
    /// holds none of those messages when it checks the trade.
    #[tokio::test]
    async fn a_fill_across_pages_is_checked_against_a_book_no_page_still_holds() {
        let last = crate::feed::PAGE_LIMIT as OrderId * 2 + 250;
        let mut messages = vec![list_eth(1), new_order(2, 5, Side::Sell, 100.0, 5.0)];
        // Sell orders at a worse price than the best one. They never stand at
        // the front of the line, so no trade takes them first.
        messages.extend((3..last).map(|id| new_order(id, 11, Side::Sell, 200.0, 5.0)));
        messages.push(new_order(last, 7, Side::Buy, 100.0, 5.0));
        let trades = vec![fill(2, last, 10_000, 50)];

        let surveyed = survey(&messages).await;
        assert_eq!(surveyed.last_id, last, "the walk reaches the last page");
        assert_eq!(
            surveyed.published,
            messages.len() - 1,
            "every order is counted, and the listing is not an order"
        );
        assert_eq!(surveyed.duplicates, 0);
        let known = replay_check(
            &messages,
            &trades,
            "both sides of every trade exist on the feed",
        )
        .await;
        assert_eq!(known.failed, 0, "{:?}", known.failures);
        assert_eq!(
            known.checked, 1,
            "the order the trade names is kept across the pages between them"
        );

        let check = priority(&messages, &trades).await;
        assert_eq!(check.checked, 1);
        assert!(check.failures.is_empty(), "{:?}", check.failures);
    }

    /// An id published twice, found without keeping every id ever published.
    /// The sequencer's ids are its sequence numbers. So an id that does not
    /// rise is an id the sequencer has already used.
    #[tokio::test]
    async fn an_order_id_the_feed_published_twice_is_reported() {
        let messages = vec![
            list_eth(1),
            new_order(2, 5, Side::Sell, 100.0, 5.0),
            new_order(3, 7, Side::Buy, 99.0, 5.0),
            new_order(3, 9, Side::Buy, 98.0, 5.0),
        ];
        let surveyed = survey(&messages).await;
        assert_eq!(surveyed.duplicates, 1);
        assert_eq!(surveyed.duplicate_ids, vec![3]);
        assert_eq!(
            surveyed.published, 2,
            "the second copy is not a third order"
        );
    }

    /// A trade against an order the sequencer published after the taker. The
    /// order does exist in the history, so this is not the "never published"
    /// case that another check reports. It is a trade against an order that
    /// did not exist yet, and this check has to say so. This case is also why
    /// the checker walks the history twice. One streaming walk that reaches
    /// the taker has not seen the maker, and could not tell the two cases
    /// apart.
    #[tokio::test]
    async fn a_fill_against_an_order_published_later_is_reported() {
        let messages = vec![
            list_eth(1),
            new_order(2, 5, Side::Sell, 100.0, 5.0),
            new_order(3, 7, Side::Buy, 100.0, 5.0),
            new_order(4, 5, Side::Sell, 100.0, 5.0),
        ];
        let trades = vec![fill(4, 3, 10_000, 50)];
        let check = priority(&messages, &trades).await;
        assert_eq!(check.checked, 1);
        assert_eq!(check.failures.len(), 1, "{:?}", check.failures);
        assert!(
            check.failures[0].contains("was not resting"),
            "{}",
            check.failures[0]
        );
    }

    /// The same shape again, with the taker an order the rules refused.
    ///
    /// The self-trade rule refuses the arriving order whole, so it makes no
    /// fill and this check reads none of the rows that name it. The maker the
    /// sequencer published later must then be reported by nothing here
    /// either. The report used to be able to hold more failures than the
    /// check had read rows, which is a report a reader cannot make sense of.
    #[tokio::test]
    async fn a_refused_taker_is_not_reported_again_at_a_maker_published_later() {
        let messages = vec![
            list_eth(1),
            engine_rule(2, 2),
            new_order(3, 5, Side::Sell, 100.0, 5.0),
            // Account 5 buys at the price of its own resting sell order.
            // Rule set 2 refuses the whole arriving order.
            new_order(4, 5, Side::Buy, 100.0, 5.0),
            new_order(5, 5, Side::Sell, 100.0, 5.0),
        ];
        // The row names order 5 as its maker, and the sequencer published
        // order 5 after order 4.
        let trades = vec![fill(5, 4, 10_000, 50)];
        let check = priority(&messages, &trades).await;
        assert_eq!(check.checked, 0, "a refused order makes no fill to check");
        assert!(check.failures.is_empty(), "{:?}", check.failures);
        // The rule that did refuse it still says so.
        let refused = replay_check(
            &messages,
            &trades,
            "no fill against the taker's own resting order",
        )
        .await;
        assert_eq!(refused.failed, 1, "{:?}", refused.failures);
    }

    /// The other half of that difference. A maker the sequencer never
    /// published at all is the business of the check "both sides of every
    /// trade exist on the feed". This check says nothing about that case,
    /// beyond having looked.
    #[tokio::test]
    async fn a_fill_against_an_order_the_feed_never_published_is_left_to_the_other_check() {
        let messages = vec![
            list_eth(1),
            new_order(2, 5, Side::Sell, 100.0, 5.0),
            new_order(3, 7, Side::Buy, 100.0, 5.0),
        ];
        let trades = vec![fill(9, 3, 10_000, 50)];
        let check = priority(&messages, &trades).await;
        assert_eq!(check.checked, 1);
        assert!(check.failures.is_empty(), "{:?}", check.failures);
    }
}
