use axum::{
    Json, Router,
    body::Bytes,
    extract::{FromRef, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::get,
};
use std::convert::Infallible;
// `Stream` here is the same trait axum's `Sse` asks for; tokio-stream re-exports
// it so this file needs no direct dependency on `futures`.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, broadcast, watch};
use tokio::time::sleep;
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use tokio_stream::{Stream, StreamExt};
use tracing::{Level, error, info, warn};
use tracing_subscriber::FmtSubscriber;

use crate::domain::{AccountId, OrderId, OrderMessage, Side, to_grid};
use crate::inbox::warn_if_public;
use crate::logchain::{self, AttestStatus, Chain, EMPTY_CHAIN, StateRoot};
use crate::operator::{self, valid_symbol};
use crate::store::{
    Change, ClaimRow, Counters, HistoryReader, ListingRow, OrderRow, Snapshot, Store, StoreError,
    status,
};
use crate::wire::{self, RawMessage, ReadMessage, TooOld};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

// The exchange runs one `New` message through six steps, in this fixed order.
// Each step is its own module, and **a step never calls another step**:
// `apply_new` below is the only caller of any of them, and it runs them in
// order. A step that needs another step's answer takes that answer as a
// parameter.
//
// ```text
// submit
//   ├─►  1  resolve symbol        listed? price step, quantity step
//   ├─►  2  validate order type   limit / market / post-only
//   ├─►  3  bound the price       protection collar
//   ├─►  4  self-trade check      cancel newest
//   ├─►  5  match against book    price-time priority
//   └─►  6  remainder policy      GTC / IOC / FOK
// ```
//
// The words in that drawing:
//
// - limit: an order that names the worst price the trader accepts.
// - market: an order that names no price. It takes what the book offers.
// - post-only: an order that must wait in the book. The exchange refuses it
//   when it would trade at once.
// - protection collar: a price range around a recent price. Step 3 pulls a
//   price outside the range back to the edge of the range.
// - cancel newest: when one account would trade with itself, the exchange
//   refuses the order that just arrived.
// - price-time priority: the best price trades first. At one price, the order
//   that arrived first trades first.
// - remainder: the quantity left after step 5 matched what it could. GTC keeps
//   the remainder in the book. IOC throws the remainder away. FOK needs the
//   whole quantity to match, or none of it matches.
//
// | Step | Owner | May read | May change |
// |---|---|---|---|
// | 1 | Listings | symbol registry | nothing |
// | 2 | Order types | the order, the book | nothing |
// | 3 | Order types | the book, the reference price | the order's limit price |
// | 4 | Self-trade | the book, the order's account | rejects the arriving order |
// | 5 | nobody | the book | the book, trades |
// | 6 | Order types | the remainder | the book, through its answer |
//
// The function signatures carry that table. A step that changes nothing takes
// `&`. The two steps that change something say so in what they take or return.
// Step 5 is owned by nobody, and nothing else may be added to it. See its
// module comment.
//
// Step 4 refuses an arriving order that would trade against a resting order of
// the same account. It did nothing when these files were first split. The file
// was made early so that the features built in parallel (PLAN.md step 4) each
// had one file to write in, and the self-trade rule then filled it in. The rule
// starts at rule set 2, so the messages published under rule set 1 replay the
// way they always did.
//
// `reference_price` is not a step and never runs as one. It holds the middle
// price of the book, weighted by how long the book held it. The middle price is
// halfway between the best buy price and the best sell price. Step 3 measures
// the collar from that price. The middle price is state that lives across
// messages, and no step may own such state, ENGINE.md section 4.0.
// `apply_new` and `apply_cancel` hand `reference_price` a sample once they
// have finished with a book. They then hand step 3 the number
// `reference_price` answers with.
//
// This is the exchange's copy of the rules. `verify.rs` holds a second,
// separate copy, and `verify.rs` must not import any of this, ENGINE.md
// section 5. Two implementations that share matching code cannot catch each
// other's bugs.
mod pipeline;
mod reference_price;
mod step1_resolve_symbol;
mod step2_validate_order_type;
mod step3_bound_the_price;
mod step4_self_trade_check;
mod step5_match_against_book;
mod step6_remainder_policy;

use pipeline::{IncomingOrder, Rejected, RuleSet, Terms};
use reference_price::MidWindow;
use step5_match_against_book::{BookAndTrades, Matched};
use step6_remainder_policy::Remainder;

/// What `BUILD_COMMIT` says when the build did not name a commit.
///
/// A local `cargo build` passes no build argument. The exchange serves this
/// word instead of an empty string. So a reader can tell "this build does not
/// know its commit" from "this field is broken".
const BUILD_COMMIT_UNKNOWN: &str = "unknown";

/// The commit this binary was built from, as `/market` reports it.
///
/// The image build passes the commit in the `BUILD_COMMIT` environment
/// variable. `option_env!` reads that variable at compile time, so the value is
/// fixed in the binary. No build script and no dependency is needed for it.
///
/// The value is the full commit hash the CI workflow builds from. That hash is
/// also the image tag the workflow publishes. So a reader can compare this
/// field to the tag of the image the server pulled, without a second lookup.
///
/// This is a response value only. It never reaches the state root and never
/// reaches a signed claim. Two exchanges built from different commits must
/// still agree on the same state root after the same messages.
const BUILD_COMMIT: &str = match option_env!("BUILD_COMMIT") {
    Some(commit) if !commit.is_empty() => commit,
    _ => BUILD_COMMIT_UNKNOWN,
};

// The exchange keeps a price as whole cents and a quantity as whole tenths.
// That matches the sequencer's rounding: two decimals for a price, one decimal
// for a quantity. Whole-number arithmetic keeps the books exact. Repeated f64
// subtraction would in the end leave tiny leftover quantities, such as
// 0.0000000001, waiting in a price level.

/// Test-only conversions, so a test can write an expected value in whole cents
/// or whole tenths. Live input goes through `to_grid` instead. `to_grid`
/// refuses a value that these two functions would round.
#[cfg(test)]
fn to_cents(price: f64) -> i64 {
    (price * 100.0).round() as i64
}

#[cfg(test)]
fn to_tenths(quantity: f64) -> i64 {
    (quantity * 10.0).round() as i64
}

// These three functions are the only place where the exchange leaves exact
// arithmetic. Everything inside this engine is whole numbers. Everything these
// three functions produce is f64, which serde writes as a JSON number.
//
// That is a deliberate simplification, not an oversight. A production API sends
// money fields as decimal strings ("100.25"), so the exact value survives the
// client's parser as well as the server's arithmetic. A JSON number hands the
// client a binary float. The client then has the same rounding problem on their
// side that whole-number arithmetic solves inside this engine. Nothing looks
// wrong in practice: these values are either exact in binary, or they come back
// unchanged through serde's shortest representation. But a client that added
// thousands of them would drift, where this engine does not.

fn cents_to_f64(cents: i64) -> f64 {
    cents as f64 / 100.0
}

fn tenths_to_f64(tenths: i64) -> f64 {
    tenths as f64 / 10.0
}

/// The exchange keeps a money amount from a quantity times a price in "mills".
/// One mill is one tenth of a quantity times one cent of a price, which is one
/// thousandth of a USDC.
fn mills_to_f64(mills: i64) -> f64 {
    mills as f64 / 1000.0
}

/// What the log says about one symbol.
///
/// The price step and the quantity step are whole counts, not the `f64` that
/// the `ListSymbol` message carries. That is deliberate. This value goes into
/// the state root. A float has two values that compare equal and hash
/// differently (`0.0` and `-0.0`), and a value that compares unequal to itself
/// (`NaN`). A step is a count of the units this engine keeps its books in, and
/// a count is a whole number.
///
/// `listed` is what step 1 asks about. A delisted symbol keeps its row. The
/// trades it made are still in the log, and the exchange can still answer about
/// them. So `/trades` and `/candles` go on accepting its name, and the exchange
/// refuses only new orders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Listing {
    /// The smallest price difference, in cents. `1` is a step of 0.01.
    price_step_cents: i64,
    /// The smallest quantity difference, in tenths. `1` is a step of 0.1.
    quantity_step_tenths: i64,
    /// Whether the symbol is tradable at this point in the log.
    listed: bool,
    /// The id of the `ListSymbol` message that opened this market. Sorting on
    /// these ids gives the order the operator opened the markets in. `0` when no
    /// message said so: a test that lists symbols directly, or a run resumed
    /// from a database written before this field existed.
    ///
    /// The field is here because the registry is a `BTreeMap`, and a `BTreeMap`
    /// is in name order. So the listing order cannot be read back out of the
    /// map. `/market` serves the markets in listing order, so a browser opens on
    /// the market the operator listed first, MERKLE-USDC, instead of on
    /// whichever name sorts first.
    ///
    /// `state_root` does not hash this field. The field decides no order and no
    /// fill. It only decides the row order of one endpoint. Hashing it would
    /// stop every run recorded before it from resuming, for a field that changes
    /// nothing about matching.
    listed_by: OrderId,
}

/// The listing the dishonest build hands step 1 for a symbol nobody listed.
/// The function is behind a cargo feature, so a release binary does not
/// contain it.
#[cfg(feature = "dishonest")]
fn phantom_listing() -> Option<Listing> {
    crate::dishonest::telling(crate::dishonest::Lie::PhantomMarket).then_some(Listing {
        price_step_cents: 1,
        quantity_step_tenths: 1,
        listed: true,
        // No message listed it. That is the lie.
        listed_by: 0,
    })
}

/// Which symbols may be traded, and on what steps, at this point in the log.
///
/// **This is the answer to "was this symbol listed at this point in the log",
/// and the log alone builds it.** The registry starts empty. A build that has
/// never seen a `ListSymbol` message trades nothing. Every other build gives
/// the same answer for the same history, and that agreement is the reason the
/// registry exists. The old rule asked "is this symbol in `domain::SYMBOLS`".
/// That constant is part of a binary. Two builds compiled from different
/// constants replayed the same history to different state roots, and the build
/// missing a symbol ignored every order naming it without a word.
///
/// A `BTreeMap` and not a `HashMap`, because `state_root` hashes the symbols in
/// name order and a sorted map is already in that order.
#[derive(Debug, Default)]
struct SymbolRegistry {
    symbols: BTreeMap<String, Listing>,
}

impl SymbolRegistry {
    /// The terms `symbol` is listed on right now, or `None`. `None` means the
    /// log has never listed the symbol, or has delisted it. This is the whole
    /// question step 1 asks.
    fn listing(&self, symbol: &str) -> Option<&Listing> {
        self.symbols.get(symbol).filter(|listing| listing.listed)
    }

    /// Whether the log has ever listed `symbol`. A delisted symbol answers
    /// true. Its trades happened and are still in the record, so a reader may
    /// still ask about them.
    fn ever_listed(&self, symbol: &str) -> bool {
        self.symbols.contains_key(symbol)
    }

    /// Every symbol tradable right now, in name order.
    fn listed(&self) -> impl Iterator<Item = &String> {
        self.symbols
            .iter()
            .filter(|(_, listing)| listing.listed)
            .map(|(symbol, _)| symbol)
    }

    /// Every symbol tradable right now, in the order the log listed them: by
    /// the id of the `ListSymbol` message that opened each market, and by name
    /// where no message said so.
    ///
    /// This is what `/market` serves. The map is in name order, so the listing
    /// order needs a sort and not a walk.
    fn listed_in_listing_order(&self) -> Vec<(&String, &Listing)> {
        let mut markets: Vec<(&String, &Listing)> = self
            .symbols
            .iter()
            .filter(|(_, listing)| listing.listed)
            .collect();
        markets.sort_by_key(|(symbol, listing)| (listing.listed_by, *symbol));
        markets
    }

    /// Lists `symbol` on the given steps. Answers `false` when the symbol is
    /// already listed. A second list is refused, not treated as a change of
    /// terms. New steps would leave orders waiting at prices the new steps
    /// forbid, and no message asked for that state. The log can say the same
    /// thing with no ambiguity: a delist, and then a list.
    fn list(&mut self, symbol: &str, listing: Listing) -> bool {
        if self.listing(symbol).is_some() {
            return false;
        }
        self.symbols.insert(symbol.to_string(), listing);
        true
    }

    /// Stops `symbol` being tradable and keeps its row. Answers `false` when
    /// the symbol was not listed, so there was nothing to close.
    fn delist(&mut self, symbol: &str) -> bool {
        match self.symbols.get_mut(symbol) {
            Some(listing) if listing.listed => {
                listing.listed = false;
                true
            }
            _ => false,
        }
    }

    /// Rebuilds the registry from rows read back out of the state database.
    fn from_rows(rows: Vec<ListingRow>) -> Self {
        SymbolRegistry {
            symbols: rows
                .into_iter()
                .map(|row| {
                    (
                        row.symbol,
                        Listing {
                            price_step_cents: row.price_step_cents,
                            quantity_step_tenths: row.quantity_step_tenths,
                            listed: row.listed,
                            listed_by: row.listed_by,
                        },
                    )
                })
                .collect(),
        }
    }
}

/// The name `/market` counts an order under when the account's position cannot
/// hold the next fill. No step refuses such an order: step 5 has already booked
/// the earlier fills. So the name lives here and not in a step module.
const POSITION_OVERFLOW: &str = "position_overflow";

/// An open order that waits in the book until the other side trades with it.
/// Its price is the key of the price level that holds it.
#[derive(Debug, Clone)]
struct RestingOrder {
    id: OrderId,
    account: AccountId,
    qty_tenths: i64,
}

/// The buy orders and the sell orders for one symbol. A price level is keyed by
/// the price as a whole number. Each level is a queue, first in and first out.
/// So at one price the order that arrived first trades first.
#[derive(Debug, Default)]
struct Book {
    bids: BTreeMap<i64, VecDeque<RestingOrder>>,
    asks: BTreeMap<i64, VecDeque<RestingOrder>>,
}

/// Where an open order lives, so cancels can find it without scanning.
#[derive(Debug)]
struct OrderRef {
    symbol: String,
    side: Side,
    price_cents: i64,
}

/// A match between an order that was waiting in the book and an order that just
/// arrived. The waiting order is the maker. The arriving order is the taker.
/// The trade happens at the maker's price. So a price better than the taker
/// asked for goes to the taker, as on a real exchange.
///
/// An account can match with itself. The sequencer gives orders to accounts at
/// random, and this engine has no ownership rule that forbids it. Such a trade
/// adds up to zero in that account's position and cash, so it never changes the
/// account's profit. It does count toward `traded_volume` and `trade_count`. A
/// real exchange would stop the match instead.
#[derive(Debug, Clone, Serialize)]
pub struct Trade {
    pub trade_id: u64,
    pub symbol: String,
    pub price: f64,
    pub quantity: f64,
    pub maker_order: OrderId,
    pub maker_account: AccountId,
    pub taker_order: OrderId,
    pub taker_account: AccountId,
    pub taker_side: Side,
    pub timestamp: u64,
}

/// One account's holding in one symbol. Every fill the account takes part in
/// updates the holding.
///
/// Locked-in profit uses the average cost of the open quantity. A fill that
/// makes the position smaller books the difference between the fill price and
/// that average. A fill large enough to take the position through zero and out
/// the other side starts a new position at the fill price.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Position {
    /// The quantity held, in tenths. Positive means the account bought more
    /// than it sold. Negative means it sold more than it bought.
    net_qty_tenths: i64,
    /// Cash paid out (negative) or taken in (positive) by this account's fills.
    cash_mills: i64,
    /// What the open quantity cost to take on, in mills. Always a positive
    /// number, whichever side the position is on.
    cost_basis_mills: i64,
    /// Profit already locked in by closing quantity, in mills.
    realized_mills: i64,
}

/// A fill the exchange cannot book, because one of the position's totals would
/// leave the i64 range. The position does not change. The caller refuses the
/// fill rather than record a number that wrapped around.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FillOverflow;

impl std::fmt::Display for FillOverflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the fill would overflow the position's 64-bit accumulators")
    }
}

impl Position {
    /// What this position becomes after one fill. `None` when any step of the
    /// arithmetic would leave the i64 range.
    ///
    /// The function works on a copy, and that is what makes the overflow safe
    /// to act on. The caller can ask whether a fill fits before anything in the
    /// books moves. So a refused fill never leaves half a trade behind.
    fn after_fill(&self, side: Side, qty_tenths: i64, price_cents: i64) -> Option<Position> {
        let notional_mills = qty_tenths.checked_mul(price_cents)?;
        let signed_qty = match side {
            Side::Buy => qty_tenths,
            Side::Sell => qty_tenths.checked_neg()?,
        };
        let cash_delta = match side {
            Side::Buy => notional_mills.checked_neg()?,
            Side::Sell => notional_mills,
        };

        let open = self.net_qty_tenths;
        let mut next = Position {
            net_qty_tenths: open.checked_add(signed_qty)?,
            cash_mills: self.cash_mills.checked_add(cash_delta)?,
            cost_basis_mills: self.cost_basis_mills,
            realized_mills: self.realized_mills,
        };

        let opening_or_adding = open == 0 || (open > 0) == (signed_qty > 0);
        if opening_or_adding {
            next.cost_basis_mills = self.cost_basis_mills.checked_add(notional_mills)?;
        } else {
            // The fill closes open quantity. Any quantity beyond that turns
            // the position to the other side.
            let open_abs = open.checked_abs()?;
            let closed = qty_tenths.min(open_abs);
            // Split the cost in proportion, and divide last to limit rounding.
            // The answer is never larger than the cost it came from, so it
            // fits i64 whenever the cost does.
            let closed_basis =
                i64::try_from(self.cost_basis_mills as i128 * closed as i128 / open_abs as i128)
                    .ok()?;
            let closed_proceeds = closed.checked_mul(price_cents)?;
            let realized_delta = if open > 0 {
                closed_proceeds.checked_sub(closed_basis)?
            } else {
                closed_basis.checked_sub(closed_proceeds)?
            };
            next.realized_mills = self.realized_mills.checked_add(realized_delta)?;
            next.cost_basis_mills = self.cost_basis_mills.checked_sub(closed_basis)?;
            let flipped = qty_tenths - closed;
            if flipped > 0 {
                next.cost_basis_mills = flipped.checked_mul(price_cents)?;
            }
        }

        if next.net_qty_tenths == 0 {
            next.cost_basis_mills = 0;
        }
        Some(next)
    }

    /// Books one fill against this position, or reports that the fill does not
    /// fit. On `Err` the position is exactly as it was before the call.
    fn apply_fill(
        &mut self,
        side: Side,
        qty_tenths: i64,
        price_cents: i64,
    ) -> Result<(), FillOverflow> {
        *self = self
            .after_fill(side, qty_tenths, price_cents)
            .ok_or(FillOverflow)?;
        Ok(())
    }

    /// The average price of one unit of the open quantity. `None` when the
    /// account holds nothing in this symbol.
    ///
    /// The cost is in mills, which is tenths of quantity times cents of price.
    /// So a division by the open tenths gives cents, and a division by 100 turns
    /// cents into USDC.
    fn avg_entry_price(&self) -> Option<f64> {
        (self.net_qty_tenths != 0)
            .then(|| self.cost_basis_mills as f64 / self.net_qty_tenths.abs() as f64 / 100.0)
    }

    /// The profit the open quantity would book if it closed at `at_cents`.
    ///
    /// The caller chooses that price. This engine holds only the prices of
    /// trades that happened, so the caller passes the price of the last trade. A
    /// real exchange would value a position at a reference price worked out
    /// separately.
    ///
    /// This function only reads. API handlers call it while they hold the engine
    /// lock, so it has no fill to refuse. The arithmetic runs in i128 and stops
    /// at the i64 edge. It does not wrap around (release build) and does not
    /// panic (debug build). A panic here would poison the lock for every other
    /// handler.
    fn unrealized_mills(&self, at_cents: i64) -> i64 {
        let signed_basis = if self.net_qty_tenths >= 0 {
            self.cost_basis_mills as i128
        } else {
            -(self.cost_basis_mills as i128)
        };
        let value = self.net_qty_tenths as i128 * at_cents as i128 - signed_basis;
        value.clamp(i64::MIN as i128, i64::MAX as i128) as i64
    }
}

/// The running totals for one symbol. Every trade updates them.
#[derive(Debug, Default)]
struct SymbolAgg {
    last_trade_cents: i64,
    volume_tenths: i64,
    trade_count: u64,
}

/// How many of the messages it consumed most recently the engine keeps for the
/// user interface. The state database holds its own copy to the same limit.
pub(crate) const RECENT_MESSAGES_CAP: usize = 200;

/// How many of the newest trades the engine keeps in memory.
///
/// The record written to disk is the `trades` table, one row for each fill, and
/// that table is complete. This window is what the endpoints that answer in
/// milliseconds read. `/trades` shows twenty, and the user interface chart shows
/// a few hundred. A poll of either must cost the same whether the run is an hour
/// or a year old.
///
/// 10,000 is far more than any of those need, and that is the point. A reader
/// that wants more than the newest few thousand trades is asking a question
/// about the run's history, and the table answers those questions. At about 150
/// bytes a trade in memory, this window is about 1.5 MB.
pub(crate) const TRADE_WINDOW: usize = 10_000;

/// Why the engine refused a message from the sequencer outright.
///
/// This is not "the order was invalid". The engine still consumes and counts an
/// order with an unusable price. This is "the message is not the next message of
/// the history this engine follows", and no later code can repair that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyError {
    /// The message's id does not follow the cursor. The message is a duplicate,
    /// a replayed message, or a jump over ids the engine never saw.
    OutOfOrder { expected: OrderId, got: OrderId },
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::OutOfOrder { expected, got } => write!(
                f,
                "feed message {} arrived where {} was expected ({})",
                got,
                expected,
                if got < expected {
                    "already consumed"
                } else {
                    "the messages between them are missing"
                }
            ),
        }
    }
}

impl std::error::Error for ApplyError {}

/// Everything the matching engine holds: one book for each symbol, an index of
/// open orders so a cancel needs no scan, the trades, the totals for each
/// symbol, the position of each account, a window of the messages it consumed
/// most recently, and the counters that account for every message it saw.
pub struct MatcherState {
    /// Which symbols may be traded, and on what steps. Built from the
    /// `ListSymbol` and `DelistSymbol` messages in the log and from nothing
    /// else. See `SymbolRegistry`. The registry is state that lives across
    /// messages, so it lives here and not inside matching step 1. Step 1 only
    /// reads it.
    symbols: SymbolRegistry,
    /// One book for each symbol that has an order waiting in it. A symbol with
    /// no waiting orders has no entry. `apply_new` creates an entry when an
    /// order for the symbol arrives, and `prune_book` drops the entry when the
    /// last order leaves. So this map holds exactly what `restore` rebuilds from
    /// the open orders in the state database, and that is why the two hash to
    /// the same state root.
    books: HashMap<String, Book>,
    open_orders: HashMap<OrderId, OrderRef>,
    /// The newest `TRADE_WINDOW` trades, oldest first. The complete trade record
    /// of the run is the `trades` table in the state database. The exchange
    /// writes that table before it serves any of this, and it deletes no row
    /// from the table.
    ///
    /// This window has a limit because it once had none. Every trade the engine
    /// ever executed stayed here, and every resume rebuilt the whole vector. So
    /// an engine that ran long enough could neither run nor restart. Anything
    /// that needs more than this window reads the table: the profit series, the
    /// profit series, and a filtered trade list that reaches further back.
    trades: VecDeque<Trade>,
    /// The five chart intervals the browser offers, kept as at most 1,000
    /// continuous buckets per symbol. This is a derived view: it is not part of
    /// the state root and is rebuilt from the same trade rows as positions on a
    /// resume. Keeping it here makes a chart read independent of run length.
    candle_cache: CandleCache,
    /// How many trades this run has executed in total. `trade_id` counts from
    /// this number, and an execution claim commits to it. It is deliberately not
    /// `trades.len()`. The window in memory drops old trades, and the run does
    /// not.
    trades_total: u64,
    aggregates: HashMap<String, SymbolAgg>,
    /// The holding of each account in each symbol, built from executed fills
    /// and from nothing else.
    positions: HashMap<(AccountId, String), Position>,
    /// The newest messages from the sequencer, unchanged, so the user interface
    /// can show the order flow without its own connection to the sequencer. The
    /// window has a limit, because the sequencer can run longer than the
    /// exchange.
    recent_messages: VecDeque<OrderMessage>,
    /// The highest message id the engine has run so far. The poller asks the
    /// sequencer for everything after this id.
    last_seen: OrderId,
    messages_processed: u64,
    cancels_applied: u64,
    /// Cancels that name an order already fully filled, or an order the engine
    /// never saw. The sequencer warns that such cancels will happen, so the
    /// engine counts them and does not fail.
    cancels_ignored: u64,
    /// Cancels the engine refused, because the account that sent them does not
    /// own the order they name. A count above zero means somebody tried to
    /// cancel another account's order. Not written to disk, so a resume reports
    /// it from zero.
    cancels_rejected: u64,
    /// New orders the engine refused, because they do not fit it. The reasons
    /// are a price or a quantity that is not a whole number of steps, a symbol
    /// the engine does not trade, and a fill whose arithmetic would overflow.
    /// The engine counts them so that no order disappears unaccounted for.
    orders_ignored: u64,
    /// Messages this build read but did not act on.
    ///
    /// **No kind of message counts here today.** `EngineRule` names a rule set
    /// this build replays, and `ListSymbol` and `DelistSymbol` build the
    /// registry. The counter stays because a sixth kind added to `OrderMessage`
    /// and not executed here belongs in exactly one place. A count above zero
    /// tells the operator that this binary's books are not the books a build
    /// that executed the new kind would hold. Not written to disk, like
    /// `cancels_rejected`, so a resume reports it from zero.
    kinds_not_acted_on: u64,
    /// How many of those refusals were of each kind: `unlisted_symbol`,
    /// `off_grid`, `off_price_step`, `off_quantity_step`, `self_trade`,
    /// `position_overflow`. The steps that refuse choose these names, so there
    /// is no shared list here to keep in step with them. A kind appears only
    /// after it has happened once. A `BTreeMap`, so `/market` writes the same
    /// key order every time.
    ///
    /// Written to disk beside `orders_ignored`, in the same commit. The split
    /// was once held in memory only. A restart then served a total that counted
    /// every life, beside a split that counted the newest life only: 620
    /// refusals against 320 of a named kind, on the exchange as it ran.
    ///
    /// The keys are owned strings and not `&'static str`, because they come back
    /// out of the state database. A file can hold a kind this build does not
    /// name, and this build must carry that count and not drop it.
    orders_ignored_by_kind: BTreeMap<String, u64>,
    /// The rule set the messages this engine consumes run under, as the last
    /// `EngineRule` message named it. The rule set is 1 until an `EngineRule`
    /// message says otherwise. Under rule set 1 an account may match itself.
    /// Every message published so far has run under rule set 1.
    rules: RuleSet,
    /// The key this log's operator messages must be signed by, as the first
    /// operator message in the log named it. `None` until that message
    /// arrives.
    ///
    /// ENGINE.md section 3.1: the log names its operator once, and every later
    /// operator message must name that same key and verify under it. The key
    /// never changes, so the engine writes this field once for each log and then
    /// only reads it. The key is in the state root and in the state database,
    /// because two engines under different operator keys do not accept the same
    /// future operator messages.
    operator_key: Option<VerifyingKey>,
    /// Operator messages the engine read and refused. A listing has three
    /// reasons to be refused: steps this engine cannot represent, a second
    /// listing of a symbol already listed, and a delist of a symbol that is not
    /// listed. Any of the three kinds can also have a fourth reason: the
    /// signature does not verify under the operator key the log named. None of
    /// them changes the registry or the rule set. Not written to disk.
    listings_ignored: u64,
    /// Waiting orders that a `DelistSymbol` message took out of a book.
    /// ENGINE.md section 3: an order that waits and can never fill is worse than
    /// no order. Counted apart from `cancels_applied`, which counts what
    /// `Cancel` messages did and is written to disk. A delist is not a cancel
    /// that anybody sent.
    orders_delisted: u64,
    /// The changes to write to disk since the last commit to the state database,
    /// in the order they happened. `None` when the engine runs without a state
    /// database, so nothing collects here that nobody will ever drain.
    pending: Option<Vec<Change>>,
    /// Where the resumable state is kept, and which run inside it this engine
    /// writes. `/market` reports both. `None` when the engine writes no state to
    /// disk.
    state_db: Option<String>,
    run_id: Option<i64>,
    /// The cursor at the last commit that worked. Anything between this field
    /// and `last_seen` is in memory only. After a crash the engine fetches those
    /// messages from the sequencer again.
    durable_last_seen: OrderId,
    /// The session this engine's cursor counts messages of. `None` until the
    /// sequencer announces a session, and `None` for ever against a sequencer
    /// that never announces one.
    feed_session: Option<String>,
    /// One hash over every message this engine has consumed, in order. `None` on
    /// a run recorded before the chain existed. Unknown stays unknown, and the
    /// engine does not claim the run was verified.
    feed_chain: Option<Chain>,
    /// The sequencer's public key, in hex, fixed at the first contact. The
    /// engine accepts a signed head from this key only, for the rest of the run.
    feed_pubkey: Option<String>,
    /// Responses the engine refused because it could not trust them. The reasons
    /// are a missing session, a missing signed head, a bad signature, a key other
    /// than the fixed one, and ids that do not continue this engine's cursor. The
    /// engine applies none of those batches.
    feed_integrity_failures: u64,
    /// Polls where the sequencer's signed chain did not match the messages it
    /// served beside the chain, or did not cover them. A count above zero means
    /// the sequencer's history and the exchange's history are different. The
    /// engine applied none of those batches.
    feed_chain_mismatches: u64,
    /// The highest cursor position where the exchange's chain matched a signed
    /// head. In a healthy run this number rises together with `last_seen`.
    chain_verified_at: OrderId,
    /// Recent checkpoints, each one a message id with the chain at that id. A
    /// validator that reports a position a little behind the cursor can still be
    /// compared with what this engine consumed. The window has a limit. At 100
    /// messages a second it covers about forty seconds.
    recent_chains: VecDeque<(OrderId, Chain)>,
    /// The exchange's own public key, in hex. The exchange signs its execution
    /// claims with the matching private key. `/market` serves this key, and each
    /// claim carries it too, so a caller can check a claim without being told
    /// the key some other way.
    matcher_pubkey: Option<String>,
    /// The highest position that enough validators agree on, counting only
    /// validators whose chain matches the exchange's chain. The sequencer alone
    /// cannot rewrite history at or below this position.
    quorum_verified_at: OrderId,
    /// How many validators this engine was told to count, and how many
    /// answered the most recent round.
    validators_configured: usize,
    validators_responding: usize,
    /// Reports from validators that failed a check: a bad signature, a changed
    /// key, or a chain that disagrees with what this engine consumed. Each one
    /// is evidence that somebody is not honest: the validator, or the
    /// sequencer.
    validator_disputes: u64,
    /// Batches the engine could not write to disk. A count above zero means the
    /// engine still matches correctly, but can no longer resume to its current
    /// position. The engine reports the count, instead of writing one log line
    /// that nobody reads again.
    state_commit_failures: u64,
    /// The middle price of each book, and how long the book held that price.
    /// Step 3 measures the collar from this price, ENGINE.md section 4.2.1. It
    /// is here and not in a step, because it is state that lives across messages
    /// and no step owns such state.
    ///
    /// The window is not in `state_root` and not in the state database. Both of
    /// those are deliberate. Putting it in the root would change how the root is
    /// encoded, and every run in the log has already committed to the current
    /// encoding. So a restored engine starts with an empty window. It refuses
    /// market orders until it has watched a book long enough to have a middle
    /// price. That is a refusal and never a wrong fill.
    /// `reference_price.rs` records this as the thing to fix before market
    /// orders are turned on for real.
    mids: MidWindow,
}

impl MatcherState {
    pub fn new() -> Self {
        MatcherState {
            symbols: SymbolRegistry::default(),
            books: HashMap::new(),
            open_orders: HashMap::new(),
            trades: VecDeque::new(),
            candle_cache: CandleCache::default(),
            trades_total: 0,
            aggregates: HashMap::new(),
            positions: HashMap::new(),
            recent_messages: VecDeque::new(),
            last_seen: 0,
            messages_processed: 0,
            cancels_applied: 0,
            cancels_ignored: 0,
            cancels_rejected: 0,
            orders_ignored: 0,
            orders_ignored_by_kind: BTreeMap::new(),
            rules: RuleSet::GENESIS,
            operator_key: None,
            kinds_not_acted_on: 0,
            listings_ignored: 0,
            orders_delisted: 0,
            pending: None,
            state_db: None,
            run_id: None,
            durable_last_seen: 0,
            feed_session: None,
            feed_chain: Some(EMPTY_CHAIN),
            feed_pubkey: None,
            feed_integrity_failures: 0,
            feed_chain_mismatches: 0,
            chain_verified_at: 0,
            recent_chains: VecDeque::new(),
            matcher_pubkey: None,
            quorum_verified_at: 0,
            validators_configured: 0,
            validators_responding: 0,
            validator_disputes: 0,
            state_commit_failures: 0,
            mids: MidWindow::default(),
        }
    }

    /// An empty engine that replays the log `session` names.
    ///
    /// **Use this and not `new` in any program that runs a log again**: the
    /// audit, a bot's copy of the book, a test over a real history. A program
    /// that runs a log again has two inputs and not one: the messages, and the
    /// name of the log they came from.
    ///
    /// The reason is the operator messages. A check of one needs the session,
    /// and **the session is not in the message**. The session is the second line
    /// of the statement the operator signed. A reader gets the session from the
    /// sequencer's `x-feed-session` response header, and the poller reads it
    /// from there too. An engine built by `new` names no session. So it checks
    /// every operator statement against the empty string. It refuses every
    /// `ListSymbol` a real sequencer published. It opens no market, and then
    /// refuses every order after that as an unlisted symbol. A tool that did
    /// this would report a disaster against an exchange that did nothing wrong,
    /// and the session is the whole of what the tool was missing.
    ///
    /// An empty `session` means the sequencer announced none. That is what `new`
    /// already assumes, and it is right for such a log. The engine that consumed
    /// the log also checked against the empty string, so the two agree.
    pub fn replaying(session: &str) -> Self {
        let mut state = MatcherState::new();
        state.feed_session = (!session.is_empty()).then(|| session.to_string());
        state
    }

    /// An empty engine that records every change it must write to disk, ready
    /// to commit to `store`.
    fn recording(store: &Store) -> Self {
        let mut state = MatcherState::new();
        state.pending = Some(Vec::new());
        state.state_db = Some(store.path().display().to_string());
        state.run_id = Some(store.run_id());
        state
    }

    /// Rebuilds an engine from a run read back out of the state database.
    ///
    /// The engine does not read positions and totals from the database. It
    /// builds them here from the stored trades, through the same `apply_fill`
    /// the live path uses. The maker fill goes first and the taker fill second,
    /// as `apply_new` does. An account that matched itself takes both fills on
    /// one position, and their order decides how the locked-in profit splits.
    fn restore(snapshot: Snapshot, store: &Store) -> Self {
        let mut state = MatcherState::recording(store);
        // The registry comes first, because it decides what every message after
        // the resume point may do. A resumed engine that rebuilt its books and
        // forgot its listings would refuse every order from the resume point on.
        // It would say only "not a listed symbol" while it did so.
        state.symbols = SymbolRegistry::from_rows(snapshot.listings);
        let counters = snapshot.counters;
        state.last_seen = counters.last_seen;
        state.durable_last_seen = counters.last_seen;
        state.messages_processed = counters.messages_processed;
        state.cancels_applied = counters.cancels_applied;
        state.cancels_ignored = counters.cancels_ignored;
        state.orders_ignored = counters.orders_ignored;
        // The split of that total, so `/market` reports the same breakdown this
        // run committed, and not one that starts again at the restart.
        // `Store::load` refuses a run whose split does not add up to the total,
        // so the two arrive here in agreement.
        state.orders_ignored_by_kind = counters.orders_ignored_by_kind.clone();
        // The rule set the previous life matched under. The rule set is in the
        // state root. So a return under the wrong rule set would hash to a root
        // that the run's last claim disagrees with, and `open_state` would end
        // the run. That is the loud failure, but the aim is still to come back
        // correct. This build cannot have written a version it does not know, so
        // such a file came from a newer binary. Say so, and keep rule set 1
        // rather than match under rules this build does not have.
        state.rules = match RuleSet::known(counters.rule_version) {
            Some(rules) => rules,
            None => {
                error!(
                    "run {} was matching under rule set {}, and this build knows rule sets {} to \
                     {}. Its books were matched under rules this binary does not have",
                    store.run_id(),
                    counters.rule_version,
                    RuleSet::GENESIS.version(),
                    RuleSet::NEWEST.version()
                );
                RuleSet::GENESIS
            }
        };
        // The operator key the previous life ran under. The engine checks the
        // next operator message against the key this log named, and not against
        // whichever key that message carries. The key is in the state root too,
        // so a resume that lost it hashes to a root the run's last claim
        // disagrees with, and `open_state` ends the run. The live path only ever
        // writes a key it verified a signature with. So 32 bytes that are not a
        // point on the curve were put there by something else.
        state.operator_key = match counters.operator_key {
            Some(bytes) => match VerifyingKey::from_bytes(&bytes) {
                Ok(key) => Some(key),
                Err(_) => {
                    error!(
                        "run {} records an operator key of {} that is not a point on the curve; \
                         no key signed anything this engine executed",
                        store.run_id(),
                        logchain::to_hex(&bytes)
                    );
                    None
                }
            },
            None => None,
        };
        state.feed_session = snapshot.feed_session.clone();
        state.feed_chain = counters.chain;
        state.feed_pubkey = snapshot.feed_pubkey.clone();
        // Put the resume position in the checkpoint window. Then the engine can
        // compare a validator that stands at or behind that position right away.
        if let Some(chain) = counters.chain {
            state.recent_chains.push_back((counters.last_seen, chain));
        }

        // Rows arrive with the order id going up. That is also the queue order
        // inside every price level, so one pass of `push_back` rebuilds each
        // queue. Only a symbol with an order in it gets a book here. The live
        // engine keeps the same rule. See `prune_book`.
        for order in snapshot.orders {
            let book = state.books.entry(order.symbol.clone()).or_default();
            let level = match order.side {
                Side::Buy => &mut book.bids,
                Side::Sell => &mut book.asks,
            };
            level
                .entry(order.price_cents)
                .or_default()
                .push_back(RestingOrder {
                    id: order.order_id,
                    account: order.account,
                    qty_tenths: order.qty_tenths,
                });
            state.open_orders.insert(
                order.order_id,
                OrderRef {
                    symbol: order.symbol,
                    side: order.side,
                    price_cents: order.price_cents,
                },
            );
        }

        // Every trade of the run goes past, one at a time, because the positions
        // and the totals are sums over all of them. Only the newest trades stay.
        // The engine is left holding the same window a live engine would have.
        let replayed = store.stream_trades(store.run_id(), |row| {
            let maker_side = match row.taker_side {
                Side::Buy => Side::Sell,
                Side::Sell => Side::Buy,
            };
            for (account, side) in [
                (row.maker_account, maker_side),
                (row.taker_account, row.taker_side),
            ] {
                if let Err(e) = state
                    .positions
                    .entry((account, row.symbol.clone()))
                    .or_default()
                    .apply_fill(side, row.qty_tenths, row.price_cents)
                {
                    // The live path refuses a fill like this. So a stored fill
                    // like this means somebody edited the rows. Say so. The
                    // state root check in `open_state` is what stops the run.
                    error!(
                        "stored trade {} cannot be replayed onto account {}: {}",
                        row.trade_id, account, e
                    );
                }
            }
            let agg = state.aggregates.entry(row.symbol.clone()).or_default();
            agg.last_trade_cents = row.price_cents;
            agg.volume_tenths = agg.volume_tenths.saturating_add(row.qty_tenths);
            agg.trade_count = agg.trade_count.saturating_add(1);
            let price_cents = row.price_cents;
            let qty_tenths = row.qty_tenths;
            let trade = Trade {
                trade_id: row.trade_id,
                symbol: row.symbol,
                price: cents_to_f64(row.price_cents),
                quantity: tenths_to_f64(row.qty_tenths),
                maker_order: row.maker_order,
                maker_account: row.maker_account,
                taker_order: row.taker_order,
                taker_account: row.taker_account,
                taker_side: row.taker_side,
                timestamp: row.timestamp,
            };
            Self::push_trade(
                &mut state.trades,
                &mut state.trades_total,
                &mut state.candle_cache,
                trade,
                price_cents,
                qty_tenths,
            );
        });
        match replayed {
            // The rows that went past must be the rows the snapshot counted.
            // `trade_id` continues from that count, and every claim this engine
            // signs from here on commits to it. So the engine checks the count
            // and does not assume it.
            Ok(count) if count == snapshot.trades_total => {}
            Ok(count) => {
                error!(
                    "run {} counted {} trades but {} were read back; the trade record and the \
                     count this engine would sign its next claim with do not agree",
                    store.run_id(),
                    snapshot.trades_total,
                    count
                );
                std::process::exit(2);
            }
            Err(e) => {
                error!(
                    "run {} cannot be resumed: its trades could not be read back ({}). \
                     The positions this engine would serve are sums over those rows",
                    store.run_id(),
                    e
                );
                std::process::exit(2);
            }
        }

        state.recent_messages = snapshot.recent.into_iter().collect();
        state
    }

    /// One hash over everything the engine runs on: every waiting order of every
    /// book, every position, in a fixed order, and the cursor. Two engines with
    /// equal roots match all future messages the same way. That is what makes
    /// the root the right thing for an execution claim to commit to, and later,
    /// for a zero-knowledge proof.
    ///
    /// The totals, the candles and the recent-message window are not hashed.
    /// The engine works them out from the trades, or they only change what a
    /// screen shows. Hashing worked-out data would only add ways for two equal
    /// states to look unequal.
    ///
    /// Every field goes in with its own length or with a fixed width, and every
    /// list goes in with its count. So a reader can read the encoding of a state
    /// back with one meaning only, and two different states cannot produce the
    /// same bytes. A `format!` with `|` separators could not promise that. A
    /// symbol that contains `|` or a newline would move a field boundary. A
    /// state built on purpose could then hash to a root that a different state
    /// already committed, and stopping that is the one thing this root exists
    /// for.
    pub fn state_root(&self) -> [u8; 32] {
        /// Puts one field of any length into the hash, the length first.
        fn field(hasher: &mut Sha256, bytes: &[u8]) {
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }

        let mut hasher = Sha256::new();
        field(&mut hasher, b"exchange-state-v4");
        hasher.update(self.last_seen.to_le_bytes());

        // The registry decides what the engine may run, so it goes in first. Two
        // engines with equal roots must match every future message the same way.
        // Two engines that hold the same books over different symbol registries
        // do not: one trades a symbol the other refuses. Leaving the registry out
        // would also leave one table that `restore` reads and the root does not
        // cover. An edited `listings` row would then resume without a word, and
        // the engine would execute orders nobody listed.
        //
        // This line moves the version from v2 to v3. A run committed by a build
        // that hashed v2 does not resume under this build. That is the honest
        // answer: its books were matched under rules this build no longer has.
        hasher.update((self.symbols.symbols.len() as u64).to_le_bytes());
        for (symbol, listing) in &self.symbols.symbols {
            field(&mut hasher, symbol.as_bytes());
            hasher.update(listing.price_step_cents.to_le_bytes());
            hasher.update(listing.quantity_step_tenths.to_le_bytes());
            hasher.update([u8::from(listing.listed)]);
        }

        // The map holds a book only while an order waits in it. So the symbol
        // list below is the same list a restored engine builds. The whole resume
        // path depends on that rule. The check runs wherever a root is taken,
        // and is not left to the two places that keep the rule.
        debug_assert!(
            !self
                .books
                .values()
                .any(|book| book.bids.is_empty() && book.asks.is_empty()),
            "an empty book is in the map; a restored engine would not have it and \
             the roots would not match"
        );

        let mut symbols: Vec<&String> = self.books.keys().collect();
        symbols.sort();
        hasher.update((symbols.len() as u64).to_le_bytes());
        for symbol in symbols {
            field(&mut hasher, symbol.as_bytes());
            let book = &self.books[symbol];
            for (tag, side) in [(0u8, &book.bids), (1u8, &book.asks)] {
                hasher.update([tag]);
                let orders: u64 = side.values().map(|level| level.len() as u64).sum();
                hasher.update(orders.to_le_bytes());
                for (price, level) in side {
                    for order in level {
                        hasher.update(price.to_le_bytes());
                        hasher.update(order.id.to_le_bytes());
                        hasher.update(order.account.to_le_bytes());
                        hasher.update(order.qty_tenths.to_le_bytes());
                    }
                }
            }
        }

        // The positions go in sorted by account number first, and by symbol
        // where two positions share an account. That is the order
        // `(AccountId, String)` gives.
        //
        // The code copies the account number and the symbol into the list, and
        // copies the position in beside them. The old list held
        // `&(AccountId, String)`. It read the account number through a pointer
        // into the table on every comparison, and then looked each position up
        // again by hashing its key. One pass builds this list instead. So a
        // comparison between two different accounts finishes on two numbers that
        // are already in the list, and the loop below looks nothing up.
        //
        // Measured by `measures_the_state_root_over_a_book` over 100,001
        // positions: one root fell from 14,416 to 8,376 microseconds. That is
        // 144 nanoseconds a position, down to 84.
        //
        // The lookup was the cost, not the comparison. The same run with the
        // sort taken out altogether takes 8,709 microseconds, which is no faster
        // than sorting. What is left is reading 100,001 symbols out of the table
        // and hashing 4.9 megabytes, and no comparison key changes either. One
        // waiting order still costs 15 nanoseconds, because a book is a
        // `BTreeMap` and is already in order. Putting positions in order without
        // a sort means holding them in a `BTreeMap` too, and that would move the
        // cost onto every fill. So the code does not do that.
        //
        // The bytes do not move. `Ord` for `&str` compares the same bytes in the
        // same order as `Ord` for `String`, so the sequence is the one the old
        // sort produced. `the_state_root_orders_positions_the_way_it_always_did`
        // checks that over keys chosen to be hard.
        let mut holders: Vec<(AccountId, &str, &Position)> = self
            .positions
            .iter()
            .map(|((account, symbol), position)| (*account, symbol.as_str(), position))
            .collect();
        // No two keys of a map are equal. So no two entries here compare equal,
        // and a sort that may reorder equal entries cannot change the answer.
        holders
            .sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)));
        hasher.update((holders.len() as u64).to_le_bytes());
        for (account, symbol, position) in holders {
            hasher.update(account.to_le_bytes());
            field(&mut hasher, symbol.as_bytes());
            hasher.update(position.net_qty_tenths.to_le_bytes());
            hasher.update(position.cash_mills.to_le_bytes());
            hasher.update(position.cost_basis_mills.to_le_bytes());
            hasher.update(position.realized_mills.to_le_bytes());
        }

        // The rule set goes in, because two engines with equal roots must match
        // all future messages the same way, and two engines under different rule
        // sets do not. It goes in only when it is not the first rule set. So
        // every root already committed over a history with no `EngineRule`
        // message in it stays the same byte string it always was. The encoding
        // keeps its single meaning: everything above carries a length or a fixed
        // width, so the bytes after the position list are the rule set and
        // nothing else.
        if self.rules != RuleSet::GENESIS {
            field(&mut hasher, b"rules");
            hasher.update(self.rules.version().to_le_bytes());
        }
        // The operator key goes in for the same reason the rule set does. Two
        // engines that hold the same books under different operator keys accept
        // different future operator messages. One opens the market the next
        // `ListSymbol` names, and the other ignores that message. Equal roots
        // must mean the two engines run the same, so the key is part of the
        // state.
        //
        // This block and the tag above move the version from v3 to v4 together.
        // A run committed by a build that hashed v3 does not resume under this
        // build. That is the honest answer: its operator messages were executed
        // and nobody checked who signed them.
        //
        // The key goes in only once the log has named one, and it goes in last.
        // So the encoding keeps its single meaning: everything before the key
        // carries a length or a fixed width, and each optional part carries its
        // own tag.
        if let Some(key) = &self.operator_key {
            field(&mut hasher, b"operator");
            field(&mut hasher, key.as_bytes());
        }
        hasher.finalize().into()
    }

    /// The newest trades this engine has executed, oldest first. The audit runs
    /// the messages again and compares the trades it gets against these.
    ///
    /// This is a window and not the whole run. Use `trade` to ask for one trade
    /// by id, and `trades_total` for how many trades there have been.
    pub fn trades(&self) -> impl Iterator<Item = &Trade> {
        self.trades.iter()
    }

    /// How many trades this run has executed. Also the id of the newest one:
    /// trade ids start at 1 and step by one.
    pub fn trades_total(&self) -> u64 {
        self.trades_total
    }

    /// The trade with this id, when it is still in the window. `None` has two
    /// meanings. The trade was executed too long ago to be in memory, and its
    /// row is in the state database. Or this engine never executed it.
    pub fn trade(&self, trade_id: u64) -> Option<&Trade> {
        let first = self.trades.front()?.trade_id;
        let index = usize::try_from(trade_id.checked_sub(first)?).ok()?;
        self.trades.get(index)
    }

    /// Records one executed trade: the running total first, then the window.
    ///
    /// It takes the two fields and not `&mut self`, for the same reason `record`
    /// does. The caller calls it while a symbol's book is already borrowed
    /// mutably.
    fn push_trade(
        trades: &mut VecDeque<Trade>,
        total: &mut u64,
        candle_cache: &mut CandleCache,
        trade: Trade,
        price_cents: i64,
        qty_tenths: i64,
    ) {
        // Record the derived chart view at the same boundary as the durable
        // trade. A single market order may cross more orders than the recent
        // trade window holds, so rebuilding it later from that window could
        // silently lose the first fills of the order.
        candle_cache.record(&trade.symbol, trade.timestamp, price_cents, qty_tenths);
        *total = total.saturating_add(1);
        if trades.len() == TRADE_WINDOW {
            trades.pop_front();
        }
        trades.push_back(trade);
    }

    /// Every counter, read as one set that describes one moment, for a commit.
    fn counters(&self) -> Counters {
        Counters {
            last_seen: self.last_seen,
            messages_processed: self.messages_processed,
            cancels_applied: self.cancels_applied,
            cancels_ignored: self.cancels_ignored,
            orders_ignored: self.orders_ignored,
            orders_ignored_by_kind: self.orders_ignored_by_kind.clone(),
            rule_version: self.rules.version(),
            operator_key: self.operator_key.map(|key| key.to_bytes()),
            chain: self.feed_chain,
        }
    }

    /// Everything one commit and its execution claim need. The engine reads all
    /// of it under one lock, so all of it describes one moment.
    fn take_pending(&mut self) -> Option<PendingCommit> {
        let counters = self.counters();
        let root = self.state_root();
        let trades_total = self.trades_total;
        // The session is part of the statement the claim signs. So the engine
        // reads it here, together with the cursor and the root, and does not
        // fetch it again later under a different lock.
        let session = self.feed_session.clone().unwrap_or_default();
        let pending = self.pending.as_mut()?;
        Some(PendingCommit {
            changes: std::mem::take(pending),
            counters,
            root,
            trades_total,
            session,
        })
    }

    /// Puts changes back after a commit failed, in front of anything recorded
    /// since. So the batch keeps the sequencer's order on the next try. Answers
    /// with how many changes now wait.
    fn requeue(&mut self, mut changes: Vec<Change>) -> usize {
        let Some(pending) = self.pending.as_mut() else {
            return 0;
        };
        changes.append(pending);
        *pending = changes;
        pending.len()
    }

    /// Records one change to write to disk, when this engine writes state to
    /// disk at all.
    ///
    /// It takes the field and not `&mut self`, because the caller calls it while
    /// a symbol's book is already borrowed mutably.
    fn record(pending: &mut Option<Vec<Change>>, change: Change) {
        if let Some(pending) = pending {
            pending.push(change);
        }
    }

    /// The one message id this engine accepts next. Message ids start at 1 and
    /// step by one, so the cursor names the next id exactly.
    pub fn next_expected_id(&self) -> OrderId {
        self.last_seen.saturating_add(1)
    }

    /// Runs one message this engine built or already holds, and hashes the bytes
    /// it serializes for that message.
    ///
    /// This is for a caller that has no bytes from the sequencer: the bot's own
    /// copy of the book, and tests that build a history of their own. A program
    /// that follows a sequencer it must verify uses `apply_received` instead.
    /// There, the only bytes whose hash means anything are the bytes that
    /// arrived.
    pub fn apply_message(&mut self, msg: &OrderMessage) -> Result<(), ApplyError> {
        self.apply_inner(msg, None)
    }

    /// Runs one message the sequencer served, and hashes the bytes it served.
    ///
    /// `raw.bytes` and `msg` are the same message twice: the bytes to hash, and
    /// the reading of those bytes to run. They are separate parameters because
    /// they are separate jobs. The chain covers what arrived. Serializing `msg`
    /// again to work the chain out would tie this engine's chain to the exact
    /// shape of `OrderMessage` in this build.
    pub fn apply_received(
        &mut self,
        raw: &RawMessage,
        msg: &OrderMessage,
    ) -> Result<(), ApplyError> {
        self.apply_inner(msg, Some(&raw.bytes))
    }

    /// Runs one message from the sequencer against the books.
    ///
    /// The message must be the next one in the history this engine follows.
    /// `apply_message` gives a different answer when it runs the same message
    /// twice, and a different answer when the messages arrive in another order.
    /// So the engine refuses a repeat, a replay, or a jump over a gap, and does
    /// not run it. A repeat would put a second copy of an order in the book that
    /// no cancel can reach. A jump past a gap would build books from a history
    /// nobody signed. The caller decides what a refusal means. A refusal leaves
    /// the engine's state unchanged.
    ///
    /// `received` is the bytes the sequencer served for this message, when there
    /// are any. `None` means nobody sent this message to this engine, because
    /// the engine built it. Then the only bytes that exist for it are the bytes
    /// serialized here.
    fn apply_inner(
        &mut self,
        msg: &OrderMessage,
        received: Option<&[u8]>,
    ) -> Result<(), ApplyError> {
        let expected = self.next_expected_id();
        if msg.id() != expected {
            return Err(ApplyError::OutOfOrder {
                expected,
                got: msg.id(),
            });
        }
        // Check who signed the message, before anything acts on it. ENGINE.md
        // section 3.1: the log names its operator once, and every operator
        // message after that must be signed by the key the log already named. A
        // trader's message carries no operator statement, and this check says
        // nothing about such a message.
        let operator_stands = match msg {
            OrderMessage::New { .. } | OrderMessage::Cancel { .. } => true,
            _ => self.operator_signed(msg),
        };
        match msg {
            // The engine does not read the nonce, and that is on purpose. The
            // nonce belongs to the step that takes an order in, and the
            // sequencer has already settled it by the time a message exists.
            // The engine's job is to run the message. The nonce still reaches
            // this module inside `msg`, so the chain this engine hashes covers
            // the nonce like every other field.
            OrderMessage::New {
                id,
                timestamp,
                account,
                symbol,
                side,
                price,
                quantity,
                nonce: _,
                order_type,
                time_in_force,
                post_only,
            } => {
                self.apply_new(
                    *id,
                    *timestamp,
                    *account,
                    symbol,
                    *side,
                    *price,
                    *quantity,
                    Terms {
                        order_type: *order_type,
                        time_in_force: *time_in_force,
                        post_only: *post_only,
                    },
                );
            }
            // The timestamp goes on to `apply_cancel`, because a cancel changes
            // a book. The middle price the collar measures from is a record of
            // what each book showed, and for how long, ENGINE.md 4.2.1.
            // Without the timestamp an account could put an order in the book,
            // have its middle price counted, take the order back, and leave that
            // middle price in the average until the average dropped it for age.
            OrderMessage::Cancel {
                timestamp,
                account,
                target_id,
                ..
            } => {
                self.apply_cancel(*account, *target_id, *timestamp);
            }
            OrderMessage::ListSymbol {
                id,
                symbol,
                price_step,
                quantity_step,
                ..
            } => {
                if operator_stands {
                    self.apply_list_symbol(*id, symbol, *price_step, *quantity_step);
                }
            }
            OrderMessage::DelistSymbol {
                id,
                timestamp,
                symbol,
                ..
            } => {
                if operator_stands {
                    self.apply_delist_symbol(*id, *timestamp, symbol);
                }
            }
            // The rule set the messages after this one run under. ENGINE.md
            // section 3: the rules live in the log, because a change to a rule
            // makes the same messages produce a different result. The engine
            // counts a version it does not know and does not guess at it. The
            // engine serves books to a browser and must not stop, and
            // `kinds_not_acted_on` above zero tells the operator that these
            // books are not the books a newer build would hold.
            //
            // This arm runs when `operator_signed` refused the message, counted
            // it, and said why. The rule set does not change, so the messages
            // after this one go on running under the rules the log already
            // named.
            OrderMessage::EngineRule { .. } if !operator_stands => {}
            OrderMessage::EngineRule { version, .. } => match RuleSet::known(*version) {
                Some(rules) => {
                    if rules != self.rules {
                        info!(
                            "message {}: rule set {} from here on (was {})",
                            msg.id(),
                            rules.version(),
                            self.rules.version()
                        );
                    }
                    self.rules = rules;
                }
                None => {
                    self.kinds_not_acted_on = self.kinds_not_acted_on.saturating_add(1);
                    warn!(
                        "message {} names rule set {}, and this build knows rule sets {} to {}. \
                         It goes on matching under rule set {}, so its books are not the books a \
                         build that knows rule set {} would hold",
                        msg.id(),
                        version,
                        RuleSet::GENESIS.version(),
                        RuleSet::NEWEST.version(),
                        self.rules.version(),
                        version
                    );
                }
            },
        }
        self.last_seen = msg.id();
        self.messages_processed = self.messages_processed.saturating_add(1);
        // The chain hashes every message the engine consumed, in order. So this
        // engine always knows what its history is, and not only how long it is.
        if let Some(chain) = &mut self.feed_chain {
            *chain = match received {
                Some(bytes) => logchain::extend_bytes(chain, bytes),
                None => logchain::extend(chain, msg),
            };
            const RECENT_CHAINS_CAP: usize = 4096;
            if self.recent_chains.len() >= RECENT_CHAINS_CAP {
                self.recent_chains.pop_front();
            }
            self.recent_chains.push_back((self.last_seen, *chain));
        }
        if self.recent_messages.len() >= RECENT_MESSAGES_CAP {
            self.recent_messages.pop_front();
        }
        self.recent_messages.push_back(msg.clone());
        Self::record(&mut self.pending, Change::Consumed(msg.clone()));
        Ok(())
    }

    // These functions read the engine's state and change nothing. They exist so
    // that a trading bot in this crate can run a `MatcherState` as an exact copy
    // of the exchange's book and read that copy. Without them the bot would need
    // a second copy of the matching rules, which could drift from this one.

    /// The highest price somebody is waiting to buy `symbol` at, in cents.
    pub fn best_bid_cents(&self, symbol: &str) -> Option<i64> {
        self.books
            .get(symbol)
            .and_then(|book| book.bids.keys().next_back().copied())
    }

    /// The lowest price somebody is waiting to sell `symbol` at, in cents.
    pub fn best_ask_cents(&self, symbol: &str) -> Option<i64> {
        self.books
            .get(symbol)
            .and_then(|book| book.asks.keys().next().copied())
    }

    /// The total open quantity, in tenths, that waits at one price level. Zero
    /// when the symbol or the price level is not in the book.
    pub fn level_qty_tenths(&self, symbol: &str, side: Side, price_cents: i64) -> i64 {
        let Some(book) = self.books.get(symbol) else {
            return 0;
        };
        let levels = match side {
            Side::Buy => &book.bids,
            Side::Sell => &book.asks,
        };
        levels
            .get(&price_cents)
            .map_or(0, |level| level.iter().map(|order| order.qty_tenths).sum())
    }

    /// The total quantity, in tenths, that waits on `side` at prices an order
    /// with a limit of `limit_cents` would trade with. For sell orders that is
    /// at or below the limit. For buy orders it is at or above the limit.
    ///
    /// An arriving order needs this number before it is sent: the quantity it
    /// can really get at a price it accepts. `exclude` drops one account's own
    /// orders from the total. This engine lets an account match itself, so a bot
    /// that counted its own waiting quantity as available would size an order
    /// against quantity that is its own.
    pub fn qty_through_cents(
        &self,
        symbol: &str,
        side: Side,
        limit_cents: i64,
        exclude: Option<AccountId>,
    ) -> i64 {
        let Some(book) = self.books.get(symbol) else {
            return 0;
        };
        let levels: Box<dyn Iterator<Item = &VecDeque<RestingOrder>>> = match side {
            Side::Sell => Box::new(book.asks.range(..=limit_cents).map(|(_, level)| level)),
            Side::Buy => Box::new(book.bids.range(limit_cents..).map(|(_, level)| level)),
        };
        levels
            .flat_map(|level| level.iter())
            .filter(|order| exclude != Some(order.account))
            .map(|order| order.qty_tenths)
            .sum()
    }

    /// New orders this engine refused, for any reason.
    ///
    /// The reasons are a symbol the engine does not trade, a price or a
    /// quantity that is not a whole number of steps, terms the book cannot
    /// serve, a market order with no reference price, a fill-or-kill order the
    /// collar moved, a self-trade, and a fill whose arithmetic would overflow a
    /// position. `orders_ignored_by_kind` splits this total by reason.
    ///
    /// The sender of an order needs this count. As far as the sequencer is
    /// concerned, a refused order disappears without a word. So anything counted
    /// here is quantity its sender may believe is waiting in the book, when it
    /// never entered the book at all.
    pub fn orders_ignored(&self) -> u64 {
        self.orders_ignored
    }

    /// Why this engine refused the orders it refused: one count for each kind.
    /// The counts add up to `orders_ignored`.
    ///
    /// The kinds are the words the steps name their own refusals with:
    /// `unlisted_symbol`, `off_price_step`, `self_trade`, `position_overflow`
    /// and the rest. A kind appears after that refusal has happened once. So an
    /// empty map means nothing has been refused, and not that nothing is
    /// counted.
    ///
    /// The function is public because the split tells one refusal apart from
    /// another, and one total cannot. Before the function existed, the only
    /// reader was the `/market` handler. Any program outside this crate that
    /// needed the split had to work it out again by writing the matching steps
    /// again: a checker, a dashboard, or `services/tests/market_health.rs`,
    /// which needed the split to say why the markets stop trading. A second
    /// version of a rule, written to read a counter, is a second version that
    /// can be wrong.
    pub fn orders_ignored_by_kind(&self) -> &BTreeMap<String, u64> {
        &self.orders_ignored_by_kind
    }

    /// Messages this build read but did not act on, since it started.
    ///
    /// No kind of message counts here today. This engine runs `EngineRule`: it
    /// looks the named rule set up and matches under it from that message on.
    /// The counter moves when an `EngineRule` names a rule set this build does
    /// not know. A count above zero means this binary is older than the log it
    /// follows, and its books are not the books a build that knows that rule
    /// set would hold.
    pub fn kinds_not_acted_on(&self) -> u64 {
        self.kinds_not_acted_on
    }

    /// `ListSymbol` and `DelistSymbol` messages this engine read and refused.
    ///
    /// Unlike `kinds_not_acted_on`, this counter is not a sign of an old binary.
    /// Every build refuses the same listings for the same reasons. So a history
    /// that moves this counter moves it by the same amount for every build.
    pub fn listings_ignored(&self) -> u64 {
        self.listings_ignored
    }

    /// The operator key this log named, in hex, after an operator message has
    /// named one. `None` means the log has published no operator message this
    /// engine accepted. Then the log has no operator yet and trades nothing.
    pub fn operator_key(&self) -> Option<String> {
        self.operator_key
            .map(|key| logchain::to_hex(key.as_bytes()))
    }

    /// Waiting orders a `DelistSymbol` message took out of a book, since this
    /// engine started. Nobody told their senders. A delist closes a market, and
    /// nothing that waited in that market waits any more.
    pub fn orders_delisted(&self) -> u64 {
        self.orders_delisted
    }

    /// Whether `symbol` may take a new order at this point in the log.
    pub fn is_listed(&self, symbol: &str) -> bool {
        self.symbols.listing(symbol).is_some()
    }

    /// Every symbol tradable at this point in the log, in name order.
    pub fn listed_symbols(&self) -> Vec<String> {
        self.symbols.listed().cloned().collect()
    }

    /// An engine with every symbol in `domain::SYMBOLS` already listed, on the
    /// steps of 0.01 and 0.1 that the sequencer's generator publishes on.
    ///
    /// This is the fixture for every test about matching, and not about
    /// listings. `SYMBOLS` is the fixture here and nothing more. It is what the
    /// generator sends and what every test history names. The engine never reads
    /// it. `apply_new` asks the registry, and outside these tests `ListSymbol`
    /// messages build the registry and nothing else does.
    #[cfg(test)]
    pub(crate) fn with_default_listings() -> Self {
        MatcherState::new()
            .with_symbols_listed(&crate::domain::SYMBOLS.map(|(symbol, _, _)| symbol))
    }

    /// The same fixture, and it records into `store`, for the tests that resume.
    #[cfg(test)]
    pub(crate) fn recording_with_default_listings(store: &Store) -> Self {
        MatcherState::recording(store)
            .with_symbols_listed(&crate::domain::SYMBOLS.map(|(symbol, _, _)| symbol))
    }

    /// Lists `symbols` on the default steps of 0.01 and 0.1, without a message
    /// saying so.
    ///
    /// This is the same way in that `restore` uses: a registry set from
    /// something other than a message the engine just consumed. It exists for
    /// the tests about matching, and not about listings. A test about listings
    /// builds `ListSymbol` messages and runs them, because that is the path
    /// under test.
    ///
    /// It also records the change to write to disk. So a recording engine set up
    /// this way resumes with the same registry it ran with. Without that record,
    /// every resume test would pass over an engine that had stopped trading
    /// without a word.
    #[cfg(test)]
    pub(crate) fn with_symbols_listed(mut self, symbols: &[&str]) -> Self {
        for symbol in symbols {
            let listing = Listing {
                price_step_cents: 1,
                quantity_step_tenths: 1,
                listed: true,
                // No message listed these symbols. So there is no listing order
                // to record, and `/market` shows them in name order.
                listed_by: 0,
            };
            if self.symbols.list(symbol, listing) {
                Self::record(
                    &mut self.pending,
                    Change::SymbolListed(ListingRow {
                        symbol: symbol.to_string(),
                        price_step_cents: listing.price_step_cents,
                        quantity_step_tenths: listing.quantity_step_tenths,
                        listed: true,
                        listed_by: listing.listed_by,
                    }),
                );
            }
        }
        self
    }

    /// The symbol's last traded price, in cents, when the symbol has traded.
    pub fn last_trade_cents(&self, symbol: &str) -> Option<i64> {
        self.aggregates
            .get(symbol)
            .map(|agg| agg.last_trade_cents)
            .filter(|cents| *cents > 0)
    }

    /// Where an open order waits: (symbol, side, price in cents, tenths left).
    /// `None` after the order has fully filled, or after a cancel took it out.
    pub fn open_order(&self, id: OrderId) -> Option<(&str, Side, i64, i64)> {
        let order_ref = self.open_orders.get(&id)?;
        let book = self.books.get(&order_ref.symbol)?;
        let levels = match order_ref.side {
            Side::Buy => &book.bids,
            Side::Sell => &book.asks,
        };
        let qty_tenths = levels
            .get(&order_ref.price_cents)?
            .iter()
            .find(|order| order.id == id)?
            .qty_tenths;
        Some((
            order_ref.symbol.as_str(),
            order_ref.side,
            order_ref.price_cents,
            qty_tenths,
        ))
    }

    /// One account's holding in one symbol: (net tenths, realized mills, cash
    /// mills). Zeros when the account has never traded the symbol.
    pub fn position_of(&self, account: AccountId, symbol: &str) -> (i64, i64, i64) {
        self.positions
            .get(&(account, symbol.to_string()))
            .map_or((0, 0, 0), |position| {
                (
                    position.net_qty_tenths,
                    position.realized_mills,
                    position.cash_mills,
                )
            })
    }

    /// The profit of one account across every symbol it holds, in mills, as
    /// (locked in, not locked in). It values open quantity at each symbol's last
    /// traded price. `GET /positions` reports the same arithmetic, so a bot that
    /// reads this function and the exchange's API see the same numbers.
    pub fn account_pnl_mills(&self, account: AccountId) -> (i64, i64) {
        let mut realized_mills = 0i64;
        let mut unrealized_mills = 0i64;
        for ((holder, symbol), position) in &self.positions {
            if *holder != account {
                continue;
            }
            realized_mills = realized_mills.saturating_add(position.realized_mills);
            unrealized_mills = unrealized_mills.saturating_add(
                self.last_trade_cents(symbol)
                    .map_or(0, |cents| position.unrealized_mills(cents)),
            );
        }
        (realized_mills, unrealized_mills)
    }

    /// How many trades this engine has executed so far.
    pub fn trade_count(&self) -> u64 {
        self.trades_total
    }

    /// Counts and reports an order a step refused.
    ///
    /// Every refusal from steps 1 to 4 comes through here. So all of them move
    /// the same counter, and all of them read the same on the terminal:
    /// `order 41 ignored: 'FOO-BAR' is not a listed symbol`. The step writes the
    /// part after the colon and nothing else.
    fn ignore_order(&mut self, id: OrderId, why: &Rejected) {
        self.count_ignored(why.kind());
        warn!("order {} ignored: {}", id, why);
    }

    /// Moves the total and the count of the one kind together. So the split
    /// `/market` serves always adds up to `orders_ignored`. The engine commits
    /// both to the state database together, so the sum holds across a restart
    /// too.
    ///
    /// The code copies the key only the first time a kind happens. Every later
    /// refusal of that kind finds the row and adds to it.
    fn count_ignored(&mut self, kind: &'static str) {
        self.orders_ignored = self.orders_ignored.saturating_add(1);
        match self.orders_ignored_by_kind.get_mut(kind) {
            Some(counted) => *counted = counted.saturating_add(1),
            None => {
                self.orders_ignored_by_kind.insert(kind.to_string(), 1);
            }
        }
    }

    /// Runs one `New` message through the six matching steps, in order.
    ///
    /// The top of this file lists the steps, with what each one may read and
    /// change. This function is the only caller of any of them, and no step
    /// calls another. An answer one step needs from another arrives as a
    /// parameter, or as the previous step's return value.
    ///
    /// Every step acts. Step 2 refuses an order whose terms the book cannot
    /// serve. Step 3 moves a market order's price to the edge of the collar.
    /// Step 4 refuses a self-trade. Step 6 decides whether the remainder rests.
    /// This function acts on both answers each of them can give, so a new
    /// feature needs writing in one step's module and nowhere else.
    fn apply_new(
        &mut self,
        id: OrderId,
        timestamp: u64,
        account: AccountId,
        symbol: &str,
        side: Side,
        price: f64,
        quantity: f64,
        terms: Terms,
    ) {
        // Step 1: resolve the symbol. The symbol arrives as a string with no
        // fixed form, and the price and the quantity arrive as f64. This step
        // turns them into a listed symbol and whole numbers of its steps, or it
        // refuses the order.
        let resolved = match step1_resolve_symbol::resolve(&self.symbols, symbol, price, quantity) {
            Ok(resolved) => resolved,
            Err(why) => {
                self.ignore_order(id, &why);
                return;
            }
        };
        let mut order = IncomingOrder {
            id,
            timestamp,
            account,
            symbol: symbol.to_string(),
            side,
            limit_cents: resolved.limit_cents,
            qty_tenths: resolved.qty_tenths,
            order_type: terms.order_type,
            time_in_force: terms.time_in_force,
            post_only: terms.post_only,
        };

        // Step 2: validate the order type. The step reads the symbol's book,
        // and no book is created for it. Fill-or-kill needs an answer before
        // step 5 books anything, and post-only needs to know whether the order
        // would trade at once. So this line uses `get` and not `entry`. A
        // refusal here then leaves no empty book behind and needs no cleaning
        // up. `state_root` needs the map to hold no empty book.
        if let Err(why) = step2_validate_order_type::validate(&order, self.books.get(&order.symbol))
        {
            self.ignore_order(id, &why);
            return;
        }

        // These two lines read before the book is borrowed, because
        // `books.entry` below borrows all of `self`. Step 4 needs the rule set
        // the log runs under. Step 3 needs the price its collar is measured
        // from. Neither step owns the state it reads. The rule set and the price
        // window are both state that lives across messages, and ENGINE.md 4.0
        // keeps such state out of the steps.
        let rules = self.rules;
        let reference_cents = self.mids.reference_cents(&order.symbol, timestamp);

        // The book is created here, because steps 3, 4 and 5 all read it, and a
        // symbol with nothing waiting in it has no entry in the map. The book
        // may still be empty when this function returns. That is why every path
        // out of here from this point on ends in `prune_book`. `state_root`
        // needs the map to hold no empty book, because a restored engine
        // rebuilds books from open orders and would not have an empty one.
        let book = self.books.entry(order.symbol.clone()).or_default();

        // Step 3: bound the price. The step answers with the price the order
        // may fill at. This assignment is the only change any step makes to the
        // order.
        match step3_bound_the_price::bound(&order, book, reference_cents) {
            Ok(limit_cents) => order.limit_cents = limit_cents,
            Err(why) => {
                self.prune_book(symbol);
                self.ignore_order(id, &why);
                return;
            }
        }

        // Step 4: self-trade check. The step reads the book and refuses the
        // arriving order. The order already in the book stays where it is.
        if let Err(why) = step4_self_trade_check::check(&order, book, rules) {
            self.prune_book(symbol);
            self.ignore_order(id, &why);
            return;
        }

        // Step 5: match against the book. Nobody owns this step, and nothing
        // is added to it. It gets the book and the records a fill changes, and
        // nothing else the exchange holds.
        let mut into = BookAndTrades {
            book,
            open_orders: &mut self.open_orders,
            positions: &mut self.positions,
            aggregates: &mut self.aggregates,
            trades: &mut self.trades,
            trades_total: &mut self.trades_total,
            candle_cache: &mut self.candle_cache,
            pending: &mut self.pending,
        };
        let remaining = match step5_match_against_book::execute(&order, &mut into) {
            Matched::Crossed { remaining_tenths } => remaining_tenths,
            Matched::Overflowed { remaining_tenths } => {
                self.count_ignored(POSITION_OVERFLOW);
                error!(
                    "order {} stopped with {} tenths unfilled: booking the next fill at {} \
                     would overflow account {}'s position in {}. The order does not rest",
                    id, remaining_tenths, order.limit_cents, account, symbol
                );
                self.prune_book(symbol);
                // Fills happened before the overflow, so the book changed. The
                // engine records the middle price as of this message, the same
                // as for any other message.
                self.observe_mid(symbol, timestamp);
                return;
            }
        };

        // Step 6: remainder policy. The engine asks this step only when
        // quantity is left over.
        if remaining > 0 {
            match step6_remainder_policy::decide(&order, remaining) {
                // The quantity that did not fill waits in the book, ready for
                // the next arriving order to trade with.
                Remainder::Rest => {
                    let own_side = match order.side {
                        Side::Buy => &mut into.book.bids,
                        Side::Sell => &mut into.book.asks,
                    };
                    own_side
                        .entry(order.limit_cents)
                        .or_default()
                        .push_back(RestingOrder {
                            id: order.id,
                            account: order.account,
                            qty_tenths: remaining,
                        });
                    into.open_orders.insert(
                        order.id,
                        OrderRef {
                            symbol: order.symbol.clone(),
                            side: order.side,
                            price_cents: order.limit_cents,
                        },
                    );
                    Self::record(
                        into.pending,
                        Change::OrderRested(OrderRow {
                            order_id: order.id,
                            account: order.account,
                            symbol: order.symbol.clone(),
                            side: order.side,
                            price_cents: order.limit_cents,
                            qty_tenths: remaining,
                        }),
                    );
                }
                // Nothing waits in the book. The sender keeps only what filled.
                Remainder::Cancel => {}
            }
        }
        // The entry above is created before the match runs. So an order that
        // fills completely against the book, and empties the book while it does
        // so, would otherwise leave a book with nothing in it behind.
        self.prune_book(symbol);
        self.observe_mid(symbol, timestamp);
    }

    /// Records what a symbol's middle price became, after a message has finished
    /// with its book.
    ///
    /// This is the one write to the reference-price window. It is here and not
    /// in a step, because ENGINE.md section 4.0 leaves nowhere else for it. Step
    /// 3 may only read the reference price. Step 5 is what changes the book, and
    /// nobody edits step 5. And no step holds anything from one message to the
    /// next. The rule this write feeds is ENGINE.md 4.2.1.
    ///
    /// A book with one side empty has no middle price, and `None` says so. That
    /// is not the same as recording nothing. Recording nothing would leave the
    /// price of an order that was later cancelled sitting in the average for a
    /// whole window.
    ///
    /// The engine calls this only where the book really changed. A message that
    /// steps 1 to 4 refused changed nothing, so the sample before it still
    /// describes the book.
    fn observe_mid(&mut self, symbol: &str, at_ms: u64) {
        let mid = self
            .best_bid_cents(symbol)
            .zip(self.best_ask_cents(symbol))
            .map(|(bid, ask)| (bid + ask) / 2);
        self.mids.observe(symbol, at_ms, mid);
    }

    /// Drops a symbol's book once no order waits on either side of it.
    ///
    /// A book with no orders in it and no book at all are the same state.
    /// `apply_new` creates a book the moment an order for the symbol arrives,
    /// and every read of `books` treats a missing entry and an empty entry
    /// alike. The map must agree with that, because `restore` rebuilds books
    /// from the orders that are open. So a symbol whose last order filled, or
    /// was cancelled, comes back with no entry at all. Leaving an empty entry in
    /// the live engine made the two hash to different state roots. `open_state`
    /// refuses to resume a run whose state does not hash to the root it
    /// committed. So a symbol that went quiet ended the run for good.
    fn prune_book(&mut self, symbol: &str) {
        if self
            .books
            .get(symbol)
            .is_some_and(|book| book.bids.is_empty() && book.asks.is_empty())
        {
            self.books.remove(symbol);
        }
    }

    /// Whether the key this log named signed this operator message, so the
    /// message may act.
    ///
    /// ENGINE.md section 3.1. The first operator message in the log sets the
    /// key. There is nothing before it to check against. So the engine trusts
    /// **which** key the log runs under because of where that message sits: it
    /// is a message in the log, covered by the tree and anchored, and a reader
    /// sees the key and the moment. The engine does not trust that message's
    /// signature because of where it sits. The signature must still verify under
    /// the key the message names, or nothing shows that the key exists and
    /// opened this log.
    ///
    /// The engine checks every operator message after the first against the key
    /// already in force, and `operator::verify` refuses a message that names any
    /// other key. That refusal is the whole rule. The signed statement covers
    /// the prefix, the session, the fields and the nonce. It does not cover the
    /// `public_key` field. So a message that names a second key shows nothing
    /// about that key, however good the signature under it is. The key never
    /// changes. A new operator key means a new log.
    ///
    /// The engine refuses a message with no nonce here too. The nonce is one
    /// line of the statement, so without it there is no statement to check.
    ///
    /// A refusal is counted and answers false. The message stays in the log and
    /// in the chain this engine hashes. It changes no book, no registry and no
    /// rule set.
    fn operator_signed(&mut self, msg: &OrderMessage) -> bool {
        // The session names this log, and it is the second line of every
        // operator statement. An empty session is what the rest of this engine
        // means by "the sequencer announced none". `take_pending` reads it the
        // same way.
        let session = self.feed_session.clone().unwrap_or_default();
        let first = self.operator_key.is_none();
        let key = match self.operator_key {
            Some(key) => key,
            None => match operator::named_key(msg) {
                Ok(named) => named,
                Err(why) => {
                    self.listings_ignored = self.listings_ignored.saturating_add(1);
                    warn!("operator message {} ignored: {}", msg.id(), why);
                    return false;
                }
            },
        };
        match operator::verify(msg, &session, &key) {
            Ok(()) => {
                if first {
                    self.operator_key = Some(key);
                    info!(
                        "message {} opens this log under operator key {}; every operator \
                         message after it must be signed by that key",
                        msg.id(),
                        logchain::to_hex(key.as_bytes())
                    );
                }
                true
            }
            Err(why) => {
                self.listings_ignored = self.listings_ignored.saturating_add(1);
                warn!(
                    "operator message {} ignored: {}. This log runs under operator key {}",
                    msg.id(),
                    why,
                    logchain::to_hex(key.as_bytes())
                );
                false
            }
        }
    }

    /// Adds `symbol` to the registry, on the steps the message names.
    ///
    /// There are three refusals, and each one leaves the registry exactly as it
    /// was.
    ///
    /// This function refuses a symbol whose name breaks the rule in ENGINE.md
    /// section 4.0: 1 to 32 characters, each one `A`-`Z`, `0`-`9` or `-`. Here
    /// is the only place that name can be refused. `state_root` hashes every
    /// listed symbol, the `listings` table keeps every listed symbol, and nobody
    /// can edit the log. So a symbol of a megabyte of text would sit in every
    /// state root after it, for the life of the log. `valid_symbol` is the same
    /// check the owner runs before signing the message. Both belong to the
    /// exchange, so they share the one check.
    ///
    /// This function refuses a step this engine cannot represent here, and not
    /// at every order. The books hold whole cents and whole tenths, so a price
    /// step of 0.001 names prices no book can hold. Listing it would leave a
    /// symbol that is listed and can never take an order. The engine would then
    /// refuse every order for it, one at a time, with a reason about the order
    /// and not about the listing. `domain::MAX_GRID_UNITS` is the other end of
    /// the same rule, and it is the same number in every build. So this refusal
    /// is the same refusal everywhere, and a replay gives the same result.
    ///
    /// A symbol that is already listed is refused for the reason written on
    /// `SymbolRegistry::list`.
    fn apply_list_symbol(
        &mut self,
        id: OrderId,
        symbol: &str,
        price_step: f64,
        quantity_step: f64,
    ) {
        if let Err(why) = valid_symbol(symbol) {
            self.listings_ignored = self.listings_ignored.saturating_add(1);
            warn!("listing {} ignored: {}", id, why);
            return;
        }
        let (Some(price_step_cents), Some(quantity_step_tenths)) =
            (to_grid(price_step, 100.0), to_grid(quantity_step, 10.0))
        else {
            self.listings_ignored = self.listings_ignored.saturating_add(1);
            warn!(
                "listing {} of '{}' ignored: a price step of {} or a quantity step of {} is not a \
                 whole number of the cents and tenths this engine keeps its books in",
                id, symbol, price_step, quantity_step
            );
            return;
        };
        let listing = Listing {
            price_step_cents,
            quantity_step_tenths,
            listed: true,
            listed_by: id,
        };
        if !self.symbols.list(symbol, listing) {
            self.listings_ignored = self.listings_ignored.saturating_add(1);
            warn!(
                "listing {} of '{}' ignored: it is already listed. Delist it first if its steps \
                 are to change, so no order rests at a price the new steps forbid",
                id, symbol
            );
            return;
        }
        info!(
            "message {} lists '{}': price step {} cents, quantity step {} tenths",
            id, symbol, price_step_cents, quantity_step_tenths
        );
        Self::record(
            &mut self.pending,
            Change::SymbolListed(ListingRow {
                symbol: symbol.to_string(),
                price_step_cents,
                quantity_step_tenths,
                listed: true,
                listed_by: id,
            }),
        );
    }

    /// Stops `symbol` being tradable, and takes every waiting order out of its
    /// book.
    ///
    /// ENGINE.md section 3: an order that waits and can never fill is worse than
    /// no order. Section 4.0: a cancel is not one of the six matching steps. So
    /// this function sits here beside `apply_cancel`, and not inside step 1.
    ///
    /// This is not `apply_cancel` in a loop. `apply_cancel` answers "may this
    /// account remove this order", which is a question about who sent the
    /// message. A delist removes every order, whoever placed it. So there is no
    /// ownership to check and no cancel to refuse. What the two do share is the
    /// record-keeping each removal owes: the entry in the open-order index goes,
    /// and a row goes to the state database. Without that row a resumed engine
    /// would put the order back.
    ///
    /// **Nothing that already happened changes.** The trades this symbol made
    /// stay in the trade record. The positions they moved stay moved. The
    /// messages stay in the log, and their inclusion proofs go on verifying. A
    /// delist stops new orders. It does not erase a history.
    fn apply_delist_symbol(&mut self, id: OrderId, timestamp: u64, symbol: &str) {
        if !self.symbols.delist(symbol) {
            self.listings_ignored = self.listings_ignored.saturating_add(1);
            warn!(
                "delisting {} of '{}' ignored: the log has not listed it, so there is nothing \
                 to close",
                id, symbol
            );
            return;
        }
        // The whole book leaves at once, so there is no `prune_book` call to
        // make. An empty book and no book are the same state, and `state_root`
        // needs the map to hold no empty book.
        let cancelled = match self.books.remove(symbol) {
            Some(book) => {
                let mut cancelled = 0u64;
                for level in book.bids.values().chain(book.asks.values()) {
                    for resting in level {
                        self.open_orders.remove(&resting.id);
                        Self::record(
                            &mut self.pending,
                            Change::OrderClosed {
                                order_id: resting.id,
                            },
                        );
                        cancelled += 1;
                    }
                }
                cancelled
            }
            None => 0,
        };
        self.orders_delisted = self.orders_delisted.saturating_add(cancelled);
        // This is the third place a book changes, beside `apply_new` and the
        // success path of `apply_cancel`. It is the only one that changes a
        // whole book at once. Without this sample, the middle price the book
        // showed before the delist would go on averaging into the reference
        // price for the rest of the window. The first market order after a new
        // listing would then be bounded against a book that no longer exists. No
        // order waits now, so `observe_mid` records "no middle price". That is
        // what the window needs, and it is not the same as recording nothing.
        self.observe_mid(symbol, timestamp);
        Self::record(
            &mut self.pending,
            Change::SymbolDelisted {
                symbol: symbol.to_string(),
            },
        );
        info!(
            "message {} delists '{}': {} resting orders cancelled, its trades and positions \
             stay as they are",
            id, symbol, cancelled
        );
    }

    /// Removes the target order from the book, when the order is still open and
    /// the account that asks owns it. The engine counts and ignores a cancel for
    /// an order that already traded away.
    ///
    /// The ownership check is the whole reason `account` is a parameter here.
    /// The sequencer's cancels name only a target id. Without the check, any
    /// account could name any waiting order and take it off the book.
    fn apply_cancel(&mut self, account: AccountId, target_id: OrderId, timestamp: u64) {
        // Find the order and its owner first. Then a cancel the engine refuses
        // leaves the book and the index exactly as they were.
        let owner = self.open_orders.get(&target_id).and_then(|order_ref| {
            let book = self.books.get(&order_ref.symbol)?;
            let side = match order_ref.side {
                Side::Buy => &book.bids,
                Side::Sell => &book.asks,
            };
            side.get(&order_ref.price_cents)?
                .iter()
                .find(|resting| resting.id == target_id)
                .map(|resting| resting.account)
        });
        let Some(owner) = owner else {
            // Either no order is open under that id, or the index lived on
            // after the order it pointed at. Neither one is an order a cancel
            // can remove.
            self.open_orders.remove(&target_id);
            self.cancels_ignored = self.cancels_ignored.saturating_add(1);
            return;
        };
        if owner != account {
            self.cancels_rejected = self.cancels_rejected.saturating_add(1);
            warn!(
                "cancel of order {} from account {} refused: the order belongs to account {}",
                target_id, account, owner
            );
            return;
        }

        // The dishonest build records the cancel and leaves the order in the
        // book. So a later order can still fill against that order.
        #[cfg(feature = "dishonest")]
        if crate::dishonest::telling(crate::dishonest::Lie::CancelledFill) {
            self.cancels_applied = self.cancels_applied.saturating_add(1);
            Self::record(
                &mut self.pending,
                Change::OrderClosed {
                    order_id: target_id,
                },
            );
            return;
        }
        let order_ref = self
            .open_orders
            .remove(&target_id)
            .expect("the order was just read out of this index");
        let book = self
            .books
            .get_mut(&order_ref.symbol)
            .expect("open order index points at an existing book");
        let side = match order_ref.side {
            Side::Buy => &mut book.bids,
            Side::Sell => &mut book.asks,
        };
        if let Some(level) = side.get_mut(&order_ref.price_cents) {
            level.retain(|o| o.id != target_id);
            if level.is_empty() {
                side.remove(&order_ref.price_cents);
            }
        }
        // A cancel of the last waiting order of a symbol empties its book.
        self.prune_book(&order_ref.symbol);
        // A cancel is one of the three things that change a book, so it is one
        // of the three places the engine records the middle price. Taking an
        // order back must end the middle price that order produced. Without
        // that, an account could put an order in and take it out again, and move
        // the reference price at no cost. The third place is `DelistSymbol`,
        // which takes a whole book back at once.
        self.observe_mid(&order_ref.symbol, timestamp);
        self.cancels_applied = self.cancels_applied.saturating_add(1);
        Self::record(
            &mut self.pending,
            Change::OrderClosed {
                order_id: target_id,
            },
        );
    }
}

/// One batch on its way to the database, with everything its execution claim
/// signs. The engine read all of it under one lock.
struct PendingCommit {
    changes: Vec<Change>,
    counters: Counters,
    root: StateRoot,
    trades_total: u64,
    /// The history this claim belongs to. Empty against a sequencer that
    /// announces no session. Every other signed statement in this system treats
    /// a missing session the same way.
    session: String,
}

/// Takes the engine lock, and gets the state back when a task panicked while it
/// held the lock.
///
/// `Mutex::lock().unwrap()` would not get the state back. One request handler
/// that panicked would poison the mutex. Every later `unwrap` would then panic
/// for ever: every other endpoint, and the poller. So one bad request could
/// take the whole service down. The handlers below check their input, so they do
/// not panic in the first place, and this function makes the second check agree
/// with the first. The engine's rules do not need a locked section to run to the
/// end: `apply_batch` is the only writer that touches more than one field, and
/// it checks everything before it changes anything.
fn lock_state(state: &Mutex<MatcherState>) -> std::sync::MutexGuard<'_, MatcherState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The settings the matching engine runs under, for the life of one process.
pub struct MatcherOptions {
    /// The base URL of the sequencer this engine reads.
    pub feed_url: String,
    /// Address the market API listens on. `127.0.0.1` unless `--bind` says
    /// otherwise.
    pub bind: IpAddr,
    /// Port the market API listens on.
    pub port: u16,
    /// How often the engine asks the sequencer for new messages, in
    /// milliseconds.
    pub poll_ms: u64,
    /// The SQLite file that holds the state the engine can resume from. `None`
    /// keeps the state in memory only, and then every restart runs the whole log
    /// again.
    pub state_db: Option<PathBuf>,
    /// Leaves the run it could resume, and starts a new run in the same file.
    /// The old run's rows stay where they are.
    pub reset_state: bool,
    /// The validators whose reports this engine counts. Empty means the engine
    /// does not track whether validators agree. It still verifies the
    /// sequencer's own signature, but no part of the history reaches the mark
    /// where enough validators agree.
    pub validators: Vec<String>,
    /// The sequencer address a *browser* posts submissions to. `GET /config`
    /// serves it to the user interface.
    ///
    /// This is separate from `feed_url`, which is the address this process
    /// dials. The two differ in every deployment that is not one machine. Behind
    /// a reverse proxy the engine reaches the sequencer on
    /// `http://127.0.0.1:3000`, and a visitor reaches it on
    /// `https://exchange.example.com/feed`. Writing either one into the page
    /// would break the other.
    pub public_feed_url: String,
    /// The address of the separate service that a *browser* posts to when the
    /// sequencer does not answer. `GET /config` serves it to the user interface.
    /// `None` means no browser can reach that service, and the page offers no
    /// second route.
    ///
    /// This is separate from the sequencer's own `--inbox-url`, for the same
    /// reason `public_feed_url` is separate from `feed_url`. The address the
    /// sequencer dials to empty that service is not the address a visitor's
    /// browser can reach it on.
    pub public_inbox_url: Option<String>,
}

/// Starts the matching engine: one task that reads the sequencer, and an API
/// server that serves the current market state.
///
/// With a state database, the engine carries on where the previous process
/// stopped. Without one it starts empty. Then it runs the log again from its
/// first message, and it depends on the sequencer still holding that message.
pub async fn start_matcher(options: MatcherOptions) {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let MatcherOptions {
        feed_url,
        bind,
        port,
        poll_ms,
        state_db,
        reset_state,
        validators,
        public_feed_url,
        public_inbox_url,
    } = options;

    let (mut store, mut state) = open_state(&state_db, &feed_url, poll_ms, reset_state);
    state.validators_configured = validators.len();
    // The key this engine signs its execution claims with. The key sits next to
    // the state it makes claims about: `state.db` gets `state.key`. The
    // sequencer's key sits next to `feed.db` the same way, and a validator's key
    // sits next to its own database. Whoever holds this file can sign claims as
    // this exchange.
    let claim_key = load_claim_key(&state_db);
    let claim_pubkey = logchain::to_hex(claim_key.verifying_key().as_bytes());
    state.matcher_pubkey = Some(claim_pubkey.clone());
    if let Some(store) = &mut store {
        pin_claim_key(store, &claim_pubkey);
    }
    // The poller's "last committed" starting point is the state as loaded, and
    // not zero. A resumed run's first claim must start at the resume point, and
    // its `root_before` must be the root the previous life committed.
    let committed = state.counters();
    let committed_root = state.state_root();

    // A second view of the same file, which only reads, for the endpoints that
    // serve history one page at a time. Without a state database there is no
    // claim history on disk to serve. Those endpoints say so, and do not serve
    // an empty list that a reader would take to mean "this exchange has claimed
    // nothing".
    let history =
        state_db
            .as_ref()
            .and_then(|path| match HistoryPool::open(path, HISTORY_READERS) {
                Ok(pool) => Some(Arc::new(pool)),
                Err(e) => {
                    error!(
                        "cannot open {} for the /claims and /trade-log endpoints: {}. \
                 This engine will match and commit as usual, but a remote auditor \
                 cannot read its claims",
                        path.display(),
                        e
                    );
                    None
                }
            });

    let shared_state = Arc::new(Mutex::new(state));
    if !validators.is_empty() {
        let quorum_state = Arc::clone(&shared_state);
        tokio::spawn(async move {
            poll_validators(quorum_state, validators).await;
        });
    }
    // One sender and two listeners. The poller finishes its batch and closes
    // the run. The server stops accepting connections.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut server_shutdown = shutdown_tx.subscribe();

    // One channel, written by the poller and read by every open stream.
    let live = LiveFeed::new();

    let poller = tokio::spawn(poll_feed(Poller {
        state: Arc::clone(&shared_state),
        live: live.clone(),
        feed_url,
        poll_ms,
        store,
        shutdown: shutdown_rx,
        committed,
        committed_root,
        claim_key,
        last_heartbeat: Instant::now(),
    }));

    let anchor = load_anchor_config(std::env::var(ANCHOR_CONFIG_ENV).ok());
    let mut connect_urls = vec![public_feed_url.clone()];
    if let Some(url) = &public_inbox_url {
        connect_urls.push(url.clone());
    }
    if let Some(config) = &anchor {
        connect_urls.extend(config.rpcs.iter().cloned());
    }
    let security = crate::http_security::browser(&connect_urls);

    let app = crate::http_security::guard(
        Router::new()
            .route("/", get(get_ui))
            .route("/favicon.ico", get(get_favicon))
            .route("/icon.png", get(get_icon))
            .route("/apple-icon.png", get(get_apple_icon))
            .route("/app.css", get(get_app_css))
            .route("/app.js", get(get_app_js))
            .route("/ed25519.js", get(get_signer))
            .route("/config", get(get_config))
            .route("/market", get(get_market))
            .route("/book", get(get_book))
            .route("/open-orders", get(get_open_orders))
            .route("/trades", get(get_trades))
            .route("/positions", get(get_positions))
            .route("/pnl", get(get_pnl))
            .route("/messages", get(get_messages))
            .route("/candles", get(get_candles))
            .route("/claims", get(get_claims))
            .route("/trade-log", get(get_trade_log))
            .route("/anchor-config", get(get_anchor_config))
            .route("/stream", get(get_stream))
            .with_state(ApiState {
                engine: Arc::clone(&shared_state),
                history,
                live,
                public_feed_url,
                public_inbox_url,
                // Read once, here. The file does not change while this process
                // runs, and a read for each request would put a disk read and a
                // JSON parse on an endpoint the user interface polls.
                anchor,
            }),
        security,
    );

    let addr = SocketAddr::new(bind, port);
    // The bind fails on a port something else already holds. That is outside
    // this engine's control, so the message says which port and why, instead of
    // a bare panic from `unwrap`.
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "could not bind matcher to {}: {} (try --matcher-port)",
                addr, e
            )
        });
    info!("matcher listening on {}", addr);
    warn_if_public(addr, "the trading UI and this engine's market state");

    let server = tokio::spawn(async move {
        let stop = async move {
            let _ = server_shutdown.changed().await;
        };
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(stop)
            .await
        {
            error!("matcher server stopped: {}", e);
        }
    });

    // A stop signal is the normal way an exchange comes down, so it gets the
    // same care as a crash. The poller finishes the batch it holds, writes the
    // batch to disk, and marks the run closed. Without this, the only way to get
    // the last few hundred milliseconds of matching back would be to run those
    // messages again.
    wait_for_stop().await;
    info!("stop requested: committing state before exit");
    let _ = shutdown_tx.send(true);
    let (server, poller) = tokio::join!(server, poller);
    if let Err(e) = server {
        error!("server task did not finish: {}", e);
    }
    if let Err(e) = poller {
        error!("poller task did not finish: {}", e);
    }
    info!("matcher stopped");
}

/// What the API handlers share: the live engine, and a view of the state
/// database that only reads, for the endpoints that serve the history on disk.
///
/// `FromRef` below is what keeps every handler that needs only the engine
/// written exactly as it was. Such a handler still asks for
/// `State<Arc<Mutex<MatcherState>>>`, and axum hands it the field.
#[derive(Clone)]
struct ApiState {
    engine: Arc<Mutex<MatcherState>>,
    history: Option<Arc<HistoryPool>>,
    /// The batches, for `GET /stream`.
    live: LiveFeed,
    /// Where a browser sends submissions. `GET /config` serves it. See
    /// `MatcherOptions::public_feed_url`.
    public_feed_url: String,
    /// Where a browser sends a submission when the sequencer does not answer.
    /// `None` when no browser can reach that service. See
    /// `MatcherOptions::public_inbox_url`.
    public_inbox_url: Option<String>,
    /// The anchor deployment this exchange writes commitments to, or `None`
    /// when it writes them nowhere. See `load_anchor_config`.
    anchor: Option<AnchorConfig>,
}

impl FromRef<ApiState> for Arc<Mutex<MatcherState>> {
    fn from_ref(state: &ApiState) -> Self {
        Arc::clone(&state.engine)
    }
}

/// Loads the key this engine signs execution claims with, or creates one on the
/// first run.
///
/// Without a state database the engine keeps nothing across a restart. So the
/// key lasts only as long as the process, and the engine says so. A reader can
/// check claims signed by a key that will not exist tomorrow today, and those
/// claims are worth nothing as evidence later. An operator must know which of
/// the two they run.
fn load_claim_key(state_db: &Option<PathBuf>) -> SigningKey {
    let Some(path) = state_db else {
        warn!(
            "no state database: this engine signs its execution claims with a key that \
             lives only as long as the process, so its claims cannot be checked against \
             anything after it exits"
        );
        return logchain::ephemeral_key();
    };
    let key_path = path.with_extension("key");
    match logchain::load_or_create_key(&key_path) {
        Ok(key) => {
            info!(
                "signing execution claims as {} (key {})",
                logchain::to_hex(key.verifying_key().as_bytes()),
                key_path.display()
            );
            key
        }
        Err(e) => {
            // The same refusal as for a state database the engine cannot use,
            // and for the same reason. The operator asked for an exchange whose
            // claims are evidence. An exchange that signs with a new key at
            // every restart is not that.
            error!("cannot use matcher claim key {}: {}", key_path.display(), e);
            std::process::exit(2);
        }
    }
}

/// Records which key signs this run's claims, and refuses to continue a run
/// whose key has changed.
///
/// A run's claims are worth something only as a set. They chain root to root,
/// and a reader checks all of them against one key. Somebody could replace the
/// key file: delete it and create it again, or restore it from the wrong backup.
/// If this function then overwrote the column without a word, the run would hold
/// two batches of claims signed by two keys, and nothing would say so. The audit
/// would report the older half as forged. Stopping here says which two keys and
/// why, while the file is still exactly as the last process left it.
fn pin_claim_key(store: &mut Store, pubkey: &str) {
    match store.matcher_pubkey() {
        Ok(Some(recorded)) if recorded == pubkey => {}
        Ok(Some(recorded)) => {
            error!(
                "run {} in {} has claims signed by {}, but the key file now holds {}. \
                 Restore the original key file, or start a fresh run with --reset-state \
                 (the old run's claims stay in the file and stay checkable against the \
                 old key)",
                store.run_id(),
                store.path().display(),
                recorded,
                pubkey
            );
            std::process::exit(2);
        }
        Ok(None) => {
            if let Err(e) = store.set_matcher_pubkey(pubkey) {
                error!("could not record the claim signing key: {}", e);
            }
        }
        Err(e) => error!("could not read this run's claim signing key: {}", e),
    }
}

/// Opens the state database, when one is configured, and builds the engine to
/// match. The engine resumes from the run it finds, or starts empty when there
/// is nothing to resume.
///
/// The process stops on a database it cannot open, a database that disagrees
/// with itself, or a database another exchange already uses. That is deliberate,
/// and it is the one place this engine refuses to carry on with less than it
/// promised. Starting anyway would run an exchange that cannot resume and says
/// nothing about it, and the operator asked for one that can resume. The trade
/// log is a convenience and not a promise, so it still only warns.
fn open_state(
    state_db: &Option<PathBuf>,
    feed_url: &str,
    poll_ms: u64,
    reset_state: bool,
) -> (Option<Store>, MatcherState) {
    let Some(path) = state_db else {
        warn!(
            "no state database: this engine keeps its books in memory only, \
             and a restart replays the feed from its first message"
        );
        return (None, MatcherState::new());
    };

    let (store, snapshot) = match Store::open(path, feed_url, poll_ms, reset_state) {
        Ok(opened) => opened,
        Err(e) => {
            error!("cannot use state database {}: {}", path.display(), e);
            match e {
                StoreError::Busy(_) => error!(
                    "point the second matcher at another file with --state-db, \
                     or stop the one that is running"
                ),
                StoreError::Corrupt(_) => error!(
                    "start a fresh run with --reset-state (the existing rows are kept) \
                     or move the file aside"
                ),
                _ => {}
            }
            std::process::exit(2);
        }
    };

    let state = match snapshot {
        Some(snapshot) => {
            if snapshot.feed_url != feed_url {
                warn!(
                    "resuming state built from feed {} against feed {}",
                    snapshot.feed_url, feed_url
                );
            }
            info!(
                "resuming run {} from {}: feed message {}, {} trades, {} resting orders",
                store.run_id(),
                path.display(),
                snapshot.counters.last_seen,
                snapshot.trades_total,
                snapshot.orders.len(),
            );
            let expected_root = snapshot.last_claim_root;
            let state = MatcherState::restore(snapshot, &store);
            // The rebuilt state must hash to the root the previous life
            // committed in its last claim. A database whose rows somebody
            // edited can still look correct and pass the store's row checks. It
            // does not pass this check.
            if let Some(expected) = expected_root {
                let actual = state.state_root();
                if actual != expected {
                    error!(
                        "restored state hashes to {} but the last committed claim says {}: \
                         the database does not describe the state it claims. Start a fresh \
                         run with --reset-state, or restore the file from a good copy",
                        logchain::to_hex(&actual),
                        logchain::to_hex(&expected)
                    );
                    std::process::exit(2);
                }
            }
            state
        }
        None => {
            info!("new run {} in {}", store.run_id(), path.display());
            MatcherState::recording(&store)
        }
    };
    (Some(store), state)
}

/// Finishes when the operator asks the engine to stop, with Ctrl-C or SIGTERM.
async fn wait_for_stop() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => info!("SIGINT"),
                    _ = term.recv() => info!("SIGTERM"),
                }
            }
            Err(e) => {
                // A lost SIGTERM is worth saying out loud. Under a process
                // supervisor, SIGTERM is the normal stop signal. Without it the
                // supervisor kills the engine in the middle of a batch, instead
                // of letting it stop cleanly.
                warn!(
                    "cannot listen for SIGTERM ({}); only Ctrl-C will stop cleanly",
                    e
                );
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// How many empty poll responses in a row the poller accepts before it checks
/// whether the sequencer restarted. At the default 200ms tick that is about six
/// seconds. That is far longer than any gap the generator produces at a normal
/// rate.
const EMPTY_POLLS_BEFORE_PROBE: u32 = 30;

/// How long an idle engine may go without writing to the state database before
/// it writes a heartbeat. Without the heartbeat, the next process to open the
/// file would read a live but quiet run as a crashed one.
const HEARTBEAT_EVERY: Duration = Duration::from_secs(5);

/// How many recorded changes may wait, uncommitted, before the engine stops
/// writing state to disk. The engine reaches this number only when every commit
/// has failed for a long time, which means the disk is gone. Queueing past this
/// point would add an out-of-memory kill to a database that is already lost.
const MAX_PENDING_CHANGES: usize = 1_000_000;

/// Everything the poller task owns.
struct Poller {
    state: Arc<Mutex<MatcherState>>,
    /// Where each applied batch goes, for the streams to read.
    live: LiveFeed,
    feed_url: String,
    poll_ms: u64,
    /// The one writer to the state database. The API handlers never touch it.
    /// They read the engine's state in memory.
    store: Option<Store>,
    shutdown: watch::Receiver<bool>,
    /// The counters at the last commit that worked, so an idle tick can tell
    /// that there is nothing to write.
    committed: Counters,
    /// The state root at the last commit that worked. It is the `root_before` of
    /// the next claim.
    committed_root: StateRoot,
    /// The key the engine signs every execution claim with, before it writes the
    /// claim.
    claim_key: SigningKey,
    last_heartbeat: Instant,
}

/// Asks the sequencer for the messages after the last id it saw, and runs them
/// in order. A sequencer that is down gets another try on the next tick. On
/// start, the poller catches up from the cursor last written to disk on its own.
///
/// The poller checks a response before it runs any of it. The session and the
/// signed head must be there. The signature must verify under the key fixed at
/// the first contact. The ids must continue the cursor with no gap and no
/// repeat. And the chain the messages produce must be the chain the sequencer
/// signed. Only then does the poller run the batch and commit it. Checking first
/// is what makes a refusal cheap. No message of a refused batch ever touched the
/// books, so there is nothing to undo, and the cursor on disk cannot drift from
/// the cursor in memory.
///
/// The poller runs each accepted batch against memory, and then commits it to
/// the state database in one transaction. A crash between the two loses nothing.
/// The cursor in the database still points at the start of the batch, so the
/// next process fetches those messages again and runs them again. That is safe
/// only because the same messages always rebuild the same books, and
/// `replaying_the_same_messages_rebuilds_identical_state` holds the engine to
/// that.
///
/// This engine is the sequencer's only reader here. Two pollers that shared one
/// state would fetch ranges that overlap, and would run the same orders twice.
/// `apply_message` is deliberately not safe to run twice: it trusts the cursor.
/// The run claim in `Store::open` is what stops two pollers starting on one
/// database.
async fn poll_feed(mut poller: Poller) {
    let client = reqwest::Client::new();
    let mut empty_polls = 0;
    loop {
        let stopping = tokio::select! {
            _ = sleep(Duration::from_millis(poller.poll_ms)) => false,
            _ = poller.shutdown.changed() => true,
        };
        if stopping {
            break;
        }

        let since = lock_state(&poller.state).last_seen;
        // The endpoint that serves raw bytes, and not `/orders`. The chain this
        // engine builds must hash the same bytes the sequencer hashed, and this
        // endpoint serves exactly those bytes. See `wire::MESSAGES_PATH`.
        let url = wire::messages_url(&poller.feed_url, since);
        let response = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("feed unreachable at {}: {}", poller.feed_url, e);
                poller.heartbeat();
                continue;
            }
        };
        let session = response
            .headers()
            .get(crate::wire::SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(String::from);
        let head = parse_signed_head(response.headers());
        let status = response.status();
        let body = match response.bytes().await {
            Ok(body) if status.is_success() => body,
            Ok(_) => {
                warn!("{} answered {}", url, status);
                poller.heartbeat();
                continue;
            }
            Err(e) => {
                warn!("could not read the feed's response: {}", e);
                poller.heartbeat();
                continue;
            }
        };
        // Split the body into messages and read each one, with one parse of each
        // line. This engine runs what it consumes, so it needs both the bytes
        // the chain covers and the message inside those bytes.
        //
        // The reading here decides nothing here. A message this build cannot
        // interpret travels on as an error beside its bytes. `apply_batch`
        // raises that error only after it has checked the ids and the chain. So
        // "the sequencer rewrote its history" is still decided before "this
        // build is too old to read it".
        let messages = match wire::read_ndjson::<OrderMessage>(&body) {
            Ok(messages) => messages,
            Err(e) => {
                warn!("the feed answered {} with something else: {}", url, e);
                poller.heartbeat();
                continue;
            }
        };

        // A response without a session and a signed head says nothing about
        // which history it comes from, or who stands behind it. Removing the
        // headers must not be an easier way past these checks than forging a
        // signature. So the poller refuses such a response whole. It runs
        // nothing in that response, and the cursor stays where it is.
        let (Some(session), Some(head)) = (session, head) else {
            poller.count_integrity_failure();
            error!(
                "feed response for ?since={} carries no session or no signed head: \
                 refusing its messages. An unsigned response is not evidence of anything",
                since
            );
            poller.heartbeat();
            continue;
        };

        // The signature comes first, because everything below trusts the
        // session string, and the session is part of what the sequencer signed.
        if !poller.accept_head(&head, &session) {
            poller.heartbeat();
            continue;
        }

        // The session names the history this engine's cursor counts messages of.
        // A different session means these messages come from a history this
        // engine has never read, whatever their ids are. Running them against
        // the current books would mix two markets and say nothing about it. This
        // check catches the case the check below cannot: a replaced sequencer
        // whose ids have already grown past this engine's cursor.
        let (known_session, cursor) = {
            let state = lock_state(&poller.state);
            (state.feed_session.clone(), state.last_seen)
        };
        match known_session {
            Some(known) if known != session => {
                warn!(
                    "feed session changed from {} to {}: the feed's history was \
                     replaced; starting a new run and replaying from its first message",
                    known, session
                );
                poller.start_new_run(Some(&session)).await;
                continue;
            }
            // A run that never learned a session, and already holds a cursor,
            // cannot take a session now. Its books were built from messages of a
            // history it cannot name. Message 5001 of this sequencer need not be
            // the message that follows the 5000 the run consumed. Taking the
            // session would join two histories into one run.
            None if cursor > 0 => {
                warn!(
                    "feed announces session {} but this run reached cursor {} without one: \
                     its history cannot be matched to this feed's; starting a new run and \
                     replaying from the first message",
                    session, cursor
                );
                poller.start_new_run(Some(&session)).await;
                continue;
            }
            None => poller.adopt_session(&session),
            _ => {}
        }

        // A restart of the sequencer sets its ids back to 1, and this engine's
        // cursor stays high. Then `?since=<high>` would answer with nothing for
        // ever, and the engine would stop working with no error to show for it.
        // After a long enough silence, ask for the newest message. An id below
        // this engine's cursor means the sequencer it reads is not the one this
        // state was built from.
        if messages.is_empty() {
            empty_polls += 1;
            if empty_polls >= EMPTY_POLLS_BEFORE_PROBE {
                empty_polls = 0;
                if feed_restarted(&client, &poller.feed_url, since).await {
                    warn!(
                        "feed restarted (its newest id is below our cursor {}); \
                         starting a new run and replaying from the first message",
                        since
                    );
                    poller.start_new_run(Some(&session)).await;
                    continue;
                }
            }
            // There is nothing to run, and the poller can still compare the head
            // against the history it already consumed. That is what marks a
            // resumed run verified before its first batch arrives.
            poller.check_idle_chain(&head);
            // Another try costs nothing when nothing waits in the queue. It is
            // also how a run comes back after a failed disk works again.
            poller.commit().await;
            poller.heartbeat();
            continue;
        }
        empty_polls = 0;

        // Check the whole batch and run it under one lock, so that no other task
        // can move the cursor between the two. The poller runs no part of a
        // batch that fails any check, and that is why there is nothing to undo
        // here.
        // Built with the lock held, sent after it is let go. An exchange that
        // writes to sockets while it holds its matching lock is an exchange
        // whose matching speed is set by its slowest reader.
        let (rejection, tick) = {
            let mut state = lock_state(&poller.state);
            let trades_before = state.trades_total();
            match apply_batch(&mut state, &messages, &head) {
                Ok(()) => (
                    None,
                    poller
                        .live
                        .wanted()
                        .then(|| tick_of(&state, trades_before, &messages, STREAM_DEPTH)),
                ),
                Err(rejected) => (Some(rejected), None),
            }
        };
        if let Some(tick) = tick {
            poller.live.send(tick);
        }
        if let Some(rejection) = rejection {
            error!(
                "refusing feed messages {}..{}: {}. Nothing was applied and the cursor \
                 stays at {}; the next poll asks for the same range again",
                messages.first().map(|m| m.raw.id).unwrap_or(0),
                messages.last().map(|m| m.raw.id).unwrap_or(0),
                rejection,
                since
            );
            poller.heartbeat();
            continue;
        }
        poller.commit().await;
    }

    poller.finish().await;
}

/// Why the poller refused a whole response. Every variant means the same thing
/// in operation: the poller ran no part of the batch, the cursor did not move,
/// and the next tick fetches the same range again.
#[derive(Debug)]
enum BatchRejection {
    /// The ids do not continue this engine's cursor.
    OutOfOrder(ApplyError),
    /// The sequencer signed a head that does not stand at the end of the batch
    /// it served. So no signature covers the last message of the batch.
    HeadDoesNotCover {
        signed_at: OrderId,
        batch_ends: OrderId,
    },
    /// The messages hash to a different history from the one the sequencer
    /// signed.
    ChainMismatch {
        at: OrderId,
        ours: Chain,
        signed: Chain,
    },
    /// The sequencer published a message this build cannot interpret. This
    /// engine runs what it consumes, so it cannot go past that message.
    ///
    /// This is deliberately its own variant. The chain over these bytes matched
    /// the head, because the check above ran and passed before this one. So the
    /// sequencer serves the history it signed, and this binary is older than the
    /// message format. That is a deploy and not an incident. It must not be
    /// counted or logged as the sequencer having rewritten anything.
    CannotInterpret(TooOld),
}

impl std::fmt::Display for BatchRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchRejection::OutOfOrder(e) => write!(f, "{}", e),
            BatchRejection::HeadDoesNotCover {
                signed_at,
                batch_ends,
            } => write!(
                f,
                "the batch ends at message {} but the feed signed its head at {}, \
                 so nothing here is covered by a signature",
                batch_ends, signed_at
            ),
            BatchRejection::ChainMismatch { at, ours, signed } => write!(
                f,
                "chain mismatch at message {}: these messages hash to {}, the feed \
                 signed {}. The history served is not the history signed",
                at,
                logchain::to_hex(ours),
                logchain::to_hex(signed)
            ),
            BatchRejection::CannotInterpret(too_old) => write!(
                f,
                "{}. The chain over these messages matched the head the feed signed, so \
                 the history is intact and this engine is older than it. It cannot execute \
                 what it cannot read, so it stops here rather than skipping a message and \
                 matching against books that are missing it",
                too_old
            ),
        }
    }
}

/// Checks a whole batch, and runs it only when every check passes.
///
/// There are three checks. The ids continue the cursor one by one, with no gap
/// and no repeat. The sequencer's signed head stands at the last message of the
/// batch. And the chain those messages extend this engine's chain into is the
/// chain the sequencer signed.
///
/// All of that happens before the function runs the first message. That order is
/// the point. Running while checking would leave half a batch applied at the
/// first bad message, with the books holding messages the state database's
/// cursor says were never consumed. This function runs nothing until nothing can
/// fail, so a refusal costs exactly one wasted fetch.
///
/// The caller has already checked the head's signature. This function checks
/// that the messages beside the head are the ones the head commits to.
///
/// The checks come before the reading, and that order is the point. The function
/// checks the ids and the chain over the bytes the sequencer served, with no
/// opinion about what any message means. Only then may a message this build
/// cannot interpret stop the batch. `wire::read_ndjson` parses the lines before
/// this function runs, and holds any failure it finds until here. So the order
/// the answers arrive in has not moved. "The sequencer rewrote its history" is
/// still decided before "this build understands every message in it", and
/// nobody can confuse the two answers.
fn apply_batch(
    state: &mut MatcherState,
    messages: &[ReadMessage<OrderMessage>],
    head: &SignedHead,
) -> Result<(), BatchRejection> {
    let mut expected = state.next_expected_id();
    for msg in messages {
        if msg.raw.id != expected {
            let error = ApplyError::OutOfOrder {
                expected,
                got: msg.raw.id,
            };
            state.feed_integrity_failures = state.feed_integrity_failures.saturating_add(1);
            return Err(BatchRejection::OutOfOrder(error));
        }
        expected = expected.saturating_add(1);
    }
    let batch_ends = match messages.last() {
        Some(msg) => msg.raw.id,
        None => return Ok(()),
    };

    // The chain can be checked only when the signed head stands at the end of
    // what the sequencer served. The sequencer builds both under one lock, so an
    // honest response always does. A response that does not serves messages no
    // signature covers.
    if let Some(chain) = state.feed_chain {
        if head.last_id != batch_ends {
            state.feed_chain_mismatches = state.feed_chain_mismatches.saturating_add(1);
            return Err(BatchRejection::HeadDoesNotCover {
                signed_at: head.last_id,
                batch_ends,
            });
        }
        let ours = messages.iter().fold(chain, |chain, msg| {
            logchain::extend_bytes(&chain, &msg.raw.bytes)
        });
        if ours != head.chain {
            state.feed_chain_mismatches = state.feed_chain_mismatches.saturating_add(1);
            return Err(BatchRejection::ChainMismatch {
                at: batch_ends,
                ours,
                signed: head.chain,
            });
        }
    }

    // Every message of the batch must read, before the function runs any of
    // them. The reason is the same one that puts the checks above first. A
    // message this build cannot interpret, in the middle of a batch, must leave
    // the books exactly as they were, and not half way to that message.
    //
    // The reading already happened, in `wire::read_ndjson`, which parsed each
    // line once. The failure it found waited until here, so the two checks above
    // still answer first.
    for read in messages {
        if let Err(too_old) = &read.parsed {
            return Err(BatchRejection::CannotInterpret(too_old.clone()));
        }
    }

    for read in messages {
        let msg = read
            .parsed
            .as_ref()
            .expect("every message of the batch was just checked to read");
        state
            .apply_received(&read.raw, msg)
            .expect("the batch's ids were just checked against the cursor");
    }
    // Only a run that carries a chain may claim a verified position. A run
    // restored from before the chain existed leaves this field at zero, and
    // `/market` reports it as null and not as verified.
    if state.feed_chain.is_some() {
        state.chain_verified_at = head.last_id;
    }
    Ok(())
}

/// One report from a validator, as its `GET /attest` served it, still unchecked.
/// A report says which messages the validator saw, and in which order.
///
/// The two status flags are part of what the validator signed. So a flag that is
/// missing or edited does not pass as `false`. It changes the statement the
/// signature must cover, and the report then fails to verify instead of being
/// counted. The flags default to `false` only so that such a response is refused
/// as unverifiable, and not dropped as unreadable. A validator that says "I
/// caught the sequencer lying" must not be able to disappear without a word.
#[derive(Deserialize)]
struct WireAttestation {
    validator: String,
    session: String,
    last_id: OrderId,
    chain: String,
    signature: String,
    /// The validator caught the sequencer signing a history that its own
    /// messages do not produce. This is the strongest thing this system can say.
    #[serde(default)]
    disputed: bool,
    /// The validator has been unable to check the sequencer for so long that its
    /// position is no longer current evidence.
    #[serde(default)]
    stalled: bool,
}

/// How many of `n` validators must stand behind a history before the exchange
/// counts it as agreed: two thirds, rounded up. Three validators need two, four
/// need three, seven need five.
fn quorum(n: usize) -> usize {
    (2 * n).div_ceil(3)
}

/// Counts validator reports against this engine's own chain, and moves the mark
/// that says how far enough validators agree.
///
/// A report at position P, with a chain that matches this engine's chain, stands
/// behind the whole history up to P. Each chain hash covers every message before
/// it. So sort the matching positions highest first. The position at the count
/// `quorum` gives is the highest position that enough validators stand behind.
///
/// Only different keys count, and only from validators that stand behind what
/// they signed. A validator that reports itself disputed or late is not counted
/// at all. One key that answers at three URLs is one voice and not three. The
/// count is a statement about how many separate validators stand behind a
/// history, and neither of those two cases is that.
///
/// This task decides when history is settled. It does not decide whether the
/// exchange keeps running: matching never waits for it. A validator set that is
/// all dead holds `quorum_verified_at` still while trading goes on, and the gap
/// between that field and the cursor is visible on `/market`.
async fn poll_validators(state: Arc<Mutex<MatcherState>>, validators: Vec<String>) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .expect("http client");
    // A repeated URL in --validators raises the number needed, and adds no
    // voice. The number needed comes from how many validators the operator
    // named, and each key counts once however many URLs it answers on.
    let distinct_urls: HashSet<&String> = validators.iter().collect();
    if distinct_urls.len() != validators.len() {
        error!(
            "--validators lists {} URLs but only {} are distinct. Quorum counts each \
             validator key once, so the repeats cannot help it be reached",
            validators.len(),
            distinct_urls.len()
        );
    }
    // For each validator URL, the first key that produced a report that verified
    // is fixed for the life of this process. A validator that changes its key
    // stops counting, instead of counting twice.
    //
    // The key is fixed only after a signature verifies, and that matters. Fixing
    // it on first sight would let one false reply choose the key, anyone who
    // can answer that URL once. Every honest report after that would then be
    // refused as "changed key" for the rest of the process.
    let mut pinned: HashMap<String, String> = HashMap::new();
    loop {
        sleep(Duration::from_millis(500)).await;

        let mut responding = 0;
        // Keyed by the public key that verified, and not by the URL. Each value
        // is the highest position that one validator stands behind this round.
        let mut matching: HashMap<String, OrderId> = HashMap::new();
        let mut disputes = 0u64;

        for url in &validators {
            let attestation: WireAttestation =
                match client.get(format!("{}/attest", url)).send().await {
                    Ok(response) => match response.json().await {
                        Ok(a) => a,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                };
            responding += 1;

            let already_pinned = pinned.get(url).cloned();
            if let Some(known) = &already_pinned
                && *known != attestation.validator
            {
                warn!(
                    "validator {} changed key from {} to {}; not counting it",
                    url, known, attestation.validator
                );
                disputes += 1;
                continue;
            }
            // Either the key already fixed, or, on first contact, a key that
            // gets fixed below once it has signed something the engine could
            // check.
            let key_hex = attestation.validator.clone();

            let Some(chain) = logchain::from_hex::<32>(&attestation.chain) else {
                disputes += 1;
                continue;
            };
            let Some(signature) = logchain::from_hex::<64>(&attestation.signature) else {
                disputes += 1;
                continue;
            };
            let signature = Signature::from_bytes(&signature);
            let status = AttestStatus {
                disputed: attestation.disputed,
                stalled: attestation.stalled,
            };
            let verified = logchain::from_hex::<32>(&key_hex)
                .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
                .is_some_and(|key| {
                    logchain::verify_attest(
                        &key,
                        &attestation.session,
                        attestation.last_id,
                        &chain,
                        &status,
                        &signature,
                    )
                });
            if !verified {
                warn!("attestation from {} does not verify; not counting it", url);
                disputes += 1;
                continue;
            }
            if already_pinned.is_none() {
                // Two URLs that answer with one key are one validator behind
                // two addresses. An operator can do that by accident, because
                // validators share a default database file name. And it is
                // exactly what the count of agreeing validators must not be
                // fooled by.
                let twin = pinned
                    .iter()
                    .find(|(_, known)| *known == &key_hex)
                    .map(|(other, _)| other.clone());
                if let Some(twin) = twin {
                    error!(
                        "validators {} and {} attest with the same key {}: that is one \
                         validator, not two. It counts once toward quorum",
                        twin, url, key_hex
                    );
                }
                info!("pinning validator {} key {}", url, key_hex);
                pinned.insert(url.clone(), key_hex.clone());
            }

            // A validator that has caught the sequencer lying, or that can no
            // longer check the sequencer, says that its own position is not
            // evidence. Counting it would turn the system's strongest warning
            // into a vote of confidence.
            if !status.is_vouching() {
                error!(
                    "validator {} reports disputed = {}, stalled = {} at message {}: \
                     not counting it toward quorum",
                    url, status.disputed, status.stalled, attestation.last_id
                );
                disputes += 1;
                continue;
            }

            // The lock is held only for the lookup. The counting maps belong to
            // the poller, and nothing inside the lock awaits.
            let ours = {
                let state = lock_state(&state);
                if state.feed_session.as_deref() != Some(attestation.session.as_str()) {
                    continue; // a different history; not right and not wrong here
                }
                state
                    .recent_chains
                    .iter()
                    .find(|(id, _)| *id == attestation.last_id)
                    .map(|(_, chain)| *chain)
            };
            match ours {
                Some(ours) if ours == chain => {
                    let highest = matching.entry(key_hex).or_insert(attestation.last_id);
                    *highest = (*highest).max(attestation.last_id);
                }
                Some(ours) => {
                    error!(
                        "validator {} attests chain {} at message {}, we consumed {}: \
                         someone was served a different history",
                        url,
                        attestation.chain,
                        attestation.last_id,
                        logchain::to_hex(&ours)
                    );
                    disputes += 1;
                }
                // The position is outside this engine's checkpoint window. It is
                // too old or too new to compare this round, and it is evidence
                // of nothing.
                None => {}
            }
        }

        let needed = quorum(validators.len());
        let order_position = quorum_position(&matching, needed);

        let mut state = lock_state(&state);
        state.validators_responding = responding;
        state.validator_disputes = state.validator_disputes.saturating_add(disputes);
        if let Some(position) = order_position
            && position > state.quorum_verified_at
        {
            state.quorum_verified_at = position;
        }
    }
}

/// The highest position that `needed` separate validators stand behind, given
/// the highest matching position each one reported this round.
///
/// The map is keyed by the public key that verified. That is what makes this a
/// count of validators and not a count of answers. Three URLs served by one
/// process leave one entry here. So one validator can never meet a requirement
/// of two by being listed three times.
fn quorum_position(matching: &HashMap<String, OrderId>, needed: usize) -> Option<OrderId> {
    let mut positions: Vec<OrderId> = matching.values().copied().collect();
    positions.sort_unstable_by(|a, b| b.cmp(a));
    positions.get(needed.checked_sub(1)?).copied()
}

/// A signed head, as read out of the headers of a response from the sequencer,
/// still unchecked.
pub(crate) struct SignedHead {
    pub(crate) last_id: OrderId,
    pub(crate) chain: Chain,
    pub(crate) public_key: String,
    pub(crate) signature: Signature,
}

/// Reads the signed head out of the response headers. `None` against a
/// sequencer that does not sign. All four headers must be there together.
pub(crate) fn parse_signed_head(headers: &reqwest::header::HeaderMap) -> Option<SignedHead> {
    let text = |name: &str| headers.get(name)?.to_str().ok();
    let last_id: OrderId = text(crate::wire::HEAD_LAST_ID_HEADER)?.parse().ok()?;
    let chain: Chain = logchain::from_hex(text(crate::wire::HEAD_CHAIN_HEADER)?)?;
    let public_key = text(crate::wire::HEAD_PUBKEY_HEADER)?.to_string();
    let signature = Signature::from_bytes(&logchain::from_hex::<64>(text(
        crate::wire::HEAD_SIGNATURE_HEADER,
    )?)?);
    Some(SignedHead {
        last_id,
        chain,
        public_key,
        signature,
    })
}

impl Poller {
    /// Writes everything the engine has matched since the last commit, and then
    /// records how far the database can now resume from.
    ///
    /// The commit runs on a blocking thread. With `synchronous = FULL` it ends
    /// in an fsync, and the poller shares its runtime with the API server.
    async fn commit(&mut self) {
        let Some(store) = self.store.take() else {
            return;
        };
        let taken = lock_state(&self.state).take_pending();
        let Some(PendingCommit {
            changes,
            counters,
            #[cfg(not(feature = "dishonest"))]
            root,
            #[cfg(feature = "dishonest")]
                root: honest_root,
            trades_total,
            session,
        }) = taken
        else {
            self.store = Some(store);
            return;
        };
        // Every claim this build signs commits to a root the state does not hash
        // to. The chain from claim to claim still holds, because this build
        // changes every root the same way. Only the link between a claim and its
        // state is broken.
        #[cfg(feature = "dishonest")]
        let root = crate::dishonest::doctor_root(honest_root);
        if changes.is_empty() && counters == self.committed {
            self.store = Some(store);
            return;
        }

        // The claim states what this batch did: the committed root, plus these
        // messages, gave this root. A batch that consumed no messages claims
        // nothing. A repeated heartbeat is such a batch.
        //
        // The claim is signed here, before it goes to the store, and the store
        // refuses a claim that is not signed. A claim and its signature reach
        // the file in the same INSERT, inside the same transaction as the batch
        // they describe. So there is no moment at which this database holds an
        // execution claim that nobody put their name to.
        let claim = (counters.last_seen > self.committed.last_seen).then(|| {
            let from_msg = self.committed.last_seen + 1;
            let to_msg = counters.last_seen;
            let signature = logchain::sign_claim(
                &self.claim_key,
                &session,
                from_msg,
                to_msg,
                &self.committed_root,
                &root,
                trades_total,
            );
            ClaimRow {
                from_msg,
                to_msg,
                root_before: self.committed_root,
                root_after: root,
                trades_total,
                signature: Some(signature.to_bytes()),
            }
        });

        let (store, changes, result) =
            commit_off_thread(store, changes, counters.clone(), claim).await;
        self.store = Some(store);

        let mut state = lock_state(&self.state);
        match result {
            Ok(()) => {
                state.durable_last_seen = counters.last_seen;
                self.committed = counters;
                self.committed_root = root;
                self.last_heartbeat = Instant::now();
            }
            Err(e) => {
                state.state_commit_failures += 1;
                let queued = state.requeue(changes);
                error!(
                    "state not committed: {}. The engine is still matching, but a restart \
                     would resume from feed message {}, not {}",
                    e, state.durable_last_seen, counters.last_seen
                );
                if queued > MAX_PENDING_CHANGES {
                    error!(
                        "giving up on {}: {} changes could not be written. \
                         This engine is no longer resumable; restart it once the \
                         database is writable again",
                        state.state_db.as_deref().unwrap_or("the state database"),
                        queued
                    );
                    state.pending = None;
                    state.state_db = None;
                    state.run_id = None;
                    drop(state);
                    self.store = None;
                }
            }
        }
    }

    /// Closes the current run and starts an empty run in the same database.
    ///
    /// The engine calls this when the sequencer has been replaced. The books it
    /// holds describe a market that no longer exists. It closes the old run and
    /// does not delete it, because the old run is still a true record of what
    /// this engine matched, and of the trades its CSV already published.
    async fn start_new_run(&mut self, session: Option<&str>) {
        self.commit().await;
        // The fixed key survives into the new run. The history changed, and the
        // key that signs it should not have. If the operator really replaced
        // both, --reset-state starts a run with no fixed key. The validator set
        // is a setting of this process, so it survives too.
        let (pinned, validators_configured, matcher_pubkey) = {
            let state = lock_state(&self.state);
            (
                state.feed_pubkey.clone(),
                state.validators_configured,
                state.matcher_pubkey.clone(),
            )
        };
        let mut fresh = match &mut self.store {
            Some(store) => {
                if let Err(e) = store.start_new_run(status::FEED_RESTARTED, &self.feed_url) {
                    error!("could not open a new run in the state database: {}", e);
                }
                if let Some(session) = session
                    && let Err(e) = store.set_feed_session(session)
                {
                    warn!("could not record the feed session: {}", e);
                }
                if let Some(pinned) = &pinned
                    && let Err(e) = store.set_feed_pubkey(pinned)
                {
                    warn!("could not record the feed public key: {}", e);
                }
                // The new run signs with the same key, and records that key. So
                // the audit can check this run on its own.
                if let Some(key) = &matcher_pubkey
                    && let Err(e) = store.set_matcher_pubkey(key)
                {
                    warn!("could not record the claim signing key: {}", e);
                }
                info!("new run {} after feed restart", store.run_id());
                MatcherState::recording(store)
            }
            None => MatcherState::new(),
        };
        fresh.feed_session = session.map(String::from);
        fresh.feed_pubkey = pinned;
        fresh.validators_configured = validators_configured;
        // The claim key belongs to the engine and not to one run. The same key
        // signs the new run's claims. That is what lets a reader that fixed the
        // key go on checking across a restart of the sequencer.
        fresh.matcher_pubkey = matcher_pubkey;
        self.committed = Counters::default();
        self.committed_root = fresh.state_root();
        *lock_state(&self.state) = fresh;
    }

    /// Counts one response this engine refused because it could not trust it. So
    /// a sequencer that somebody is tampering with shows on `/market`, and not
    /// only in the log.
    fn count_integrity_failure(&mut self) {
        let mut state = lock_state(&self.state);
        state.feed_integrity_failures = state.feed_integrity_failures.saturating_add(1);
    }

    /// Decides whether the engine may trust a signed head. The key must be the
    /// key this run fixed, and the signature must verify over exactly the
    /// session, the id and the chain the sequencer sent.
    ///
    /// A run that has fixed no key yet fixes the key of the first head whose
    /// signature *verifies*, and not the first key it is shown. Fixing the key
    /// before the check would let one bad response decide the key for the rest
    /// of the run. Every head from the real sequencer would then be refused as
    /// "key changed", and the only way out would be to start again with
    /// --reset-state. A fixed key is worth having only when it names a key that
    /// really signed this history.
    ///
    /// Once the key is fixed, the *first* sequencer this run verified is the
    /// authority for the rest of the run. A different key that appears later is
    /// not "the sequencer changed its key". Nothing in this protocol announces
    /// such a change. It is a different signer on the same address.
    fn accept_head(&mut self, head: &SignedHead, session: &str) -> bool {
        let pinned = lock_state(&self.state).feed_pubkey.clone();
        if let Some(pinned) = &pinned
            && *pinned != head.public_key
        {
            self.count_integrity_failure();
            error!(
                "feed public key changed from {} to {}: refusing its messages. \
                 If the key change is intentional, start a fresh run with --reset-state",
                pinned, head.public_key
            );
            return false;
        }

        let verified = logchain::from_hex::<32>(&head.public_key)
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
            .is_some_and(|key| {
                logchain::verify_head(&key, session, head.last_id, &head.chain, &head.signature)
            });
        if !verified {
            self.count_integrity_failure();
            error!(
                "feed head signature at message {} does not verify under key {}: \
                 refusing its messages",
                head.last_id, head.public_key
            );
            return false;
        }

        if pinned.is_none() {
            info!("pinning feed public key {}", head.public_key);
            if let Some(store) = &mut self.store
                && let Err(e) = store.set_feed_pubkey(&head.public_key)
            {
                warn!("could not record the feed public key: {}", e);
            }
            lock_state(&self.state).feed_pubkey = Some(head.public_key.clone());
        }
        true
    }

    /// Compares a verified head against the history already consumed, on a poll
    /// that carried no messages.
    ///
    /// There is nothing to refuse here, because the batch is empty. So this
    /// function only reports. A match is what marks a resumed run verified
    /// before its first batch arrives. A mismatch means the engine's own history
    /// disagrees with what the sequencer signs. `apply_batch` then refuses the
    /// next batch that does arrive, for the same reason, and the cursor stops.
    fn check_idle_chain(&mut self, head: &SignedHead) {
        let mut state = lock_state(&self.state);
        if state.last_seen != head.last_id {
            return;
        }
        let Some(chain) = state.feed_chain else {
            // A run from before the chain existed. The engine cannot verify it,
            // and it says so instead of claiming otherwise.
            return;
        };
        if chain == head.chain {
            state.chain_verified_at = head.last_id;
        } else {
            state.feed_chain_mismatches = state.feed_chain_mismatches.saturating_add(1);
            error!(
                "chain mismatch at message {}: the history this engine consumed is not \
                 the history the feed signed. Our chain {}, feed's signed chain {}. \
                 No further messages will be applied",
                head.last_id,
                logchain::to_hex(&chain),
                logchain::to_hex(&head.chain)
            );
        }
    }

    /// Learns the session the first time the sequencer announces one, and writes
    /// it to disk. Then the next resume can compare its session against the one
    /// the sequencer serves.
    fn adopt_session(&mut self, session: &str) {
        info!("feed session is {}", session);
        if let Some(store) = &mut self.store
            && let Err(e) = store.set_feed_session(session)
        {
            warn!("could not record the feed session: {}", e);
        }
        lock_state(&self.state).feed_session = Some(session.to_string());
    }

    /// Says the process is alive, and writes no state. So the next process does
    /// not read an engine that watches a silent sequencer as a crashed one.
    fn heartbeat(&mut self) {
        if self.last_heartbeat.elapsed() < HEARTBEAT_EVERY {
            return;
        }
        if let Some(store) = &mut self.store {
            match store.heartbeat() {
                Ok(()) => self.last_heartbeat = Instant::now(),
                Err(e) => warn!("could not write heartbeat: {}", e),
            }
        }
    }

    /// Writes the last batch to disk and marks the run closed. Then the next
    /// start can tell a deliberate stop from a crash.
    async fn finish(&mut self) {
        self.commit().await;
        let Some(store) = &mut self.store else {
            return;
        };
        match store.close_stopped() {
            Ok(()) => info!(
                "state saved to {} (run {}) up to feed message {}; \
                 restart with the same --state-db to continue",
                store.path().display(),
                store.run_id(),
                self.committed.last_seen
            ),
            Err(e) => error!("could not close the run cleanly: {}", e),
        }
    }
}

/// Runs one commit on a blocking thread, and hands the store and the batch back.
/// So the poller can queue a failed batch again, and does not lose it.
async fn commit_off_thread(
    mut store: Store,
    changes: Vec<Change>,
    counters: Counters,
    claim: Option<ClaimRow>,
) -> (Store, Vec<Change>, Result<(), StoreError>) {
    tokio::task::spawn_blocking(move || {
        let result = store.commit(&changes, &counters, claim.as_ref());
        (store, changes, result)
    })
    .await
    .expect("state commit task panicked")
}

/// Asks the sequencer for its newest message, and reports whether that message
/// is older than the cursor this engine holds. That happens only when the
/// sequencer restarted. A check that failed, or that found nothing, is not
/// evidence of a restart, so the function answers false.
///
/// The check needs one number out of that message: its id. It takes the id out
/// of the bytes and does not parse the message. `/orders?n=1` serves the end of
/// the history, so the newest message is the one most likely to be of a kind
/// this build has never seen. A check that parsed would see nothing against the
/// newest sequencer, and would never report a restart at all.
async fn feed_restarted(client: &reqwest::Client, feed_url: &str, since: OrderId) -> bool {
    let url = format!("{}/orders?n=1", feed_url);
    let Ok(response) = client.get(&url).send().await else {
        return false;
    };
    let Ok(body) = response.bytes().await else {
        return false;
    };
    let Ok(newest) = wire::message_ids(&body) else {
        return false;
    };
    newest.first().is_some_and(|id| *id < since)
}

/// One price level as the API serves it, with the quantities of its orders
/// added up.
#[derive(Serialize)]
struct LevelView {
    price: f64,
    quantity: f64,
    orders: usize,
}

/// A short report of one symbol's market.
#[derive(Serialize)]
struct MarketSymbol {
    symbol: String,
    /// The steps this symbol is listed on, as the `ListSymbol` message in the
    /// log named them. The sender of an order reads them here, and does not
    /// assume the 0.01 and 0.1 that every symbol happens to be listed with
    /// today.
    price_step: f64,
    quantity_step: f64,
    best_bid: Option<f64>,
    best_ask: Option<f64>,
    spread: Option<f64>,
    last_trade_price: Option<f64>,
    traded_volume: f64,
    trade_count: u64,
    open_bid_orders: usize,
    open_ask_orders: usize,
}

/// The response for GET /market: the engine's counters, and one short report
/// for each symbol.
#[derive(Serialize)]
struct MarketResponse {
    last_feed_id: OrderId,
    messages_processed: u64,
    total_trades: u64,
    cancels_applied: u64,
    cancels_ignored: u64,
    /// Cancels the engine refused, because the account that sent them does not
    /// own the order they name. A count above zero means somebody tried to
    /// cancel an order that is not theirs. Counted in memory only, so a resume
    /// starts it at zero.
    cancels_rejected: u64,
    orders_ignored: u64,
    /// The same total, split by reason. `unlisted_symbol`, `off_grid`,
    /// `off_price_step` and `off_quantity_step` come from step 1. `self_trade`
    /// comes from step 4. `position_overflow` comes from a fill that would not
    /// fit in a position. A key appears after that refusal has happened at least
    /// once, so an empty object means nothing has been refused.
    ///
    /// These values add up to `orders_ignored`, and they still add up to it
    /// after a restart. The state database stores both, and reads them back
    /// together. `not_recorded` counts refusals a build before schema 10 made.
    /// That build counted them and stored no reason for any of them.
    orders_ignored_by_reason: BTreeMap<String, u64>,
    /// The rule set this engine matches under, as the last `EngineRule` message
    /// in the log named it. 1 is the rule set the log has run under since
    /// message 1.
    rule_set: u32,
    /// The newest rule set this build can run. `rule_set` says which rule set
    /// the log has put this engine in. This field says how far the binary goes.
    /// The two differ on every upgrade, because the log puts the engine in the
    /// new rule set only once the `EngineRule` message arrives.
    ///
    /// An operator reads this field to see whether the exchange can act on the
    /// rule set they are about to publish. A higher number still reaches the
    /// log. The engine then goes on matching under the rule set it has, and
    /// every checker stops on that message.
    ///
    /// This field describes the binary and not the state, so it is not in the
    /// state root. Two builds with different newest rule sets must still reach
    /// the same root over the same log.
    newest_rule_set: u32,
    /// `ListSymbol` and `DelistSymbol` messages the engine refused. The reasons
    /// are a step it cannot represent, a symbol already listed, and a delist of
    /// a symbol that is not listed. Counted in memory only.
    listings_ignored: u64,
    /// Waiting orders a `DelistSymbol` message took out of a book. Counted in
    /// memory only.
    orders_delisted: u64,
    /// The file this engine can resume from. Null when it runs in memory only,
    /// and then a restart runs the whole log again.
    state_db: Option<String>,
    /// Which run inside that file this engine writes.
    state_run_id: Option<i64>,
    /// The commit this binary was built from. `unknown` when the build named
    /// none, and a local build names none. It tells an operator which source the
    /// running exchange came from, so they can check a deployment and not only
    /// assume it.
    build_commit: &'static str,
    /// The message a restart would resume from. In normal operation it is below
    /// `last_feed_id` by at most one batch. A gap that grows means commits are
    /// failing.
    durable_feed_id: OrderId,
    /// Batches the engine could not write to disk. A count above zero means the
    /// books on screen are correct, and the database no longer holds them.
    state_commit_failures: u64,
    /// The history this engine's cursor belongs to, as the sequencer named it.
    /// Null against a sequencer that announces no session.
    feed_session: Option<String>,
    /// The sequencer key this run fixed. The engine refuses a signed head from
    /// any other key. Null until the sequencer announces a key.
    feed_public_key: Option<String>,
    /// The highest cursor position where the chain this engine worked out
    /// matched a head the sequencer signed. A healthy run keeps this at or near
    /// `last_feed_id`. Null means this run cannot verify, because it started
    /// before the chain existed.
    chain_verified_at: Option<OrderId>,
    /// Responses the engine refused because it could not trust them: no session,
    /// no signed head, the wrong key, a bad signature, or ids that skip or
    /// repeat. The engine ran none of those batches.
    feed_integrity_failures: u64,
    /// Polls where the sequencer's signed history disagreed with the messages
    /// served beside it, or did not cover them. A count above zero is a warning:
    /// the engine refused those batches, and the cursor has stopped moving.
    feed_chain_mismatches: u64,
    /// The highest position that enough validators stand behind. The sequencer
    /// alone cannot rewrite history at or below this position. In a healthy run
    /// it follows `last_feed_id` by a moment. It stops moving when too few
    /// validators agree.
    quorum_verified_at: OrderId,
    /// How many validators the operator named, and how many answered the last
    /// round.
    validators_configured: usize,
    validators_responding: usize,
    /// Validator reports the engine refused, or that disagree with this engine's
    /// history. Each one is evidence that somebody is dishonest.
    validator_disputes: u64,
    /// One SHA-256 hash over everything the engine runs on: the books, the
    /// positions and the cursor, in hex. Anyone who runs the same messages again
    /// works out the same hash. `--audit` checks it.
    state_root: String,
    /// The key this engine signs its execution claims with, in hex. Fix this
    /// key, and every claim `/claims` serves can be checked against it.
    matcher_public_key: Option<String>,
    symbols: Vec<MarketSymbol>,
}

/// Answers GET /market with the current state of every symbol.
async fn get_market(State(state): State<Arc<Mutex<MatcherState>>>) -> Json<MarketResponse> {
    let state = lock_state(&state);
    // The symbols the log has listed and not delisted. That is the market as it
    // stands. A delisted symbol leaves this list the moment the engine consumes
    // its message, because it takes no more orders. `/trades` and `/candles` go
    // on answering about it, because what it traded still happened.
    //
    // The rows come in the order the log listed the symbols, and not in name
    // order. The first messages of the log list MERKLE-USDC, ETH-USDC and
    // BTC-USDC. A browser opens on the first row it is served. In name order
    // that row was BTC-USDC, which is the market the operator opened last.
    let symbols = state
        .symbols
        .listed_in_listing_order()
        .into_iter()
        .map(|(symbol, listing)| {
            let book = state.books.get(symbol);
            let best_bid = book.and_then(|b| b.bids.keys().next_back().copied());
            let best_ask = book.and_then(|b| b.asks.keys().next().copied());
            let agg = state.aggregates.get(symbol);
            MarketSymbol {
                symbol: symbol.clone(),
                price_step: cents_to_f64(listing.price_step_cents),
                quantity_step: tenths_to_f64(listing.quantity_step_tenths),
                best_bid: best_bid.map(cents_to_f64),
                best_ask: best_ask.map(cents_to_f64),
                spread: match (best_bid, best_ask) {
                    (Some(b), Some(a)) => Some(cents_to_f64(a - b)),
                    _ => None,
                },
                last_trade_price: agg.map(|a| cents_to_f64(a.last_trade_cents)),
                traded_volume: tenths_to_f64(agg.map(|a| a.volume_tenths).unwrap_or(0)),
                trade_count: agg.map(|a| a.trade_count).unwrap_or(0),
                open_bid_orders: book
                    .map(|b| b.bids.values().map(|l| l.len()).sum())
                    .unwrap_or(0),
                open_ask_orders: book
                    .map(|b| b.asks.values().map(|l| l.len()).sum())
                    .unwrap_or(0),
            }
        })
        .collect();
    Json(MarketResponse {
        last_feed_id: state.last_seen,
        messages_processed: state.messages_processed,
        total_trades: state.trades_total,
        cancels_applied: state.cancels_applied,
        cancels_ignored: state.cancels_ignored,
        cancels_rejected: state.cancels_rejected,
        orders_ignored: state.orders_ignored,
        orders_ignored_by_reason: state.orders_ignored_by_kind().clone(),
        rule_set: state.rules.version(),
        newest_rule_set: RuleSet::NEWEST.version(),
        listings_ignored: state.listings_ignored,
        orders_delisted: state.orders_delisted,
        state_db: state.state_db.clone(),
        state_run_id: state.run_id,
        build_commit: BUILD_COMMIT,
        durable_feed_id: state.durable_last_seen,
        state_commit_failures: state.state_commit_failures,
        feed_session: state.feed_session.clone(),
        feed_public_key: state.feed_pubkey.clone(),
        chain_verified_at: state.feed_chain.map(|_| state.chain_verified_at),
        feed_integrity_failures: state.feed_integrity_failures,
        feed_chain_mismatches: state.feed_chain_mismatches,
        quorum_verified_at: state.quorum_verified_at,
        validators_configured: state.validators_configured,
        validators_responding: state.validators_responding,
        validator_disputes: state.validator_disputes,
        state_root: logchain::to_hex(&state.state_root()),
        matcher_public_key: state.matcher_pubkey.clone(),
        symbols,
    })
}

/// The most rows any one `/claims` or `/trade-log` response returns.
///
/// The same rule and the same reason as `feed::PAGE_LIMIT`. SQLite applies the
/// limit inside the query. So `?since=0` against a run with ten million trades
/// costs one page of rows to answer, and not ten million rows read with one page
/// of them served. A caller polls with `?since=` and takes as many requests as it
/// needs. A page shorter than this limit is the end.
pub const PAGE_LIMIT: usize = 1000;

/// Query parameters for the two paged history endpoints.
#[derive(Deserialize)]
struct SinceQuery {
    /// Answer with only the rows above this value, and not the value itself.
    /// The key is `from_msg` for claims and `trade_id` for trades. Start at 0.
    since: Option<u64>,
}

/// One execution claim, as the API serves it. Every byte value is hex, as
/// everywhere else this system sends bytes.
#[derive(Serialize)]
struct ClaimView {
    from_msg: OrderId,
    to_msg: OrderId,
    root_before: String,
    root_after: String,
    trades_total: u64,
    /// The exchange's signature over
    /// `exchange-claim-v1\n<session>\n<from_msg>\n<to_msg>\n<root_before>\n<root_after>\n<trades_total>`.
    /// Null only on rows a build wrote before claims were signed. This engine
    /// never writes such a row.
    signature: Option<String>,
}

/// The response for GET /claims: one page of the current run's execution
/// claims, with everything a caller needs to check them.
///
/// The session, the key and the cursor travel with the page on purpose. A caller
/// that had to make three requests to learn what a signature covers would get
/// three answers from three different moments, and they might not fit together.
/// Here one response either verifies or does not.
#[derive(Serialize)]
struct ClaimsResponse {
    /// Which run inside the state database these claims belong to.
    run_id: i64,
    /// The history the claims are signed over. It is part of every claim's
    /// signed statement, so a caller cannot check a claim without it.
    session: String,
    /// The message this run has committed up to. The claims must cover it. An
    /// audit that finds the claims stopping short has found matching that
    /// nobody committed to.
    cursor: OrderId,
    /// The key the claims are signed with, in hex.
    matcher_public_key: String,
    /// The sequencer key this run fixed at the first contact, in hex. So the
    /// audit can check the sequencer's signed head against the same key this
    /// engine accepted, and not against whichever key the sequencer offers
    /// today.
    feed_public_key: Option<String>,
    claims: Vec<ClaimView>,
}

/// One recorded trade, as the API serves it: the whole numbers the match was
/// worked out from, and not the floats `/trades` shows a browser. The audit
/// compares these against a second run of the same messages, and that comparison
/// must use the units the engine matched on.
#[derive(Serialize)]
struct TradeLogRow {
    trade_id: u64,
    timestamp: u64,
    symbol: String,
    price_cents: i64,
    qty_tenths: i64,
    maker_order: OrderId,
    maker_account: AccountId,
    taker_order: OrderId,
    taker_account: AccountId,
    taker_side: Side,
}

/// The response for GET /trade-log: one page of the current run's trades.
#[derive(Serialize)]
struct TradeLogResponse {
    run_id: i64,
    trades: Vec<TradeLogRow>,
}

/// What the engine writes right now: the run, its session, its cursor and the
/// keys. The engine reads all four under one lock, so they describe one moment.
struct RunHeader {
    run_id: i64,
    session: String,
    cursor: OrderId,
    matcher_public_key: String,
    feed_public_key: Option<String>,
}

/// Reads the run header, or says why this engine has no claim history on disk
/// to serve.
fn run_header(state: &ApiState) -> Result<RunHeader, (StatusCode, String)> {
    let engine = lock_state(&state.engine);
    let (Some(run_id), Some(matcher_public_key)) = (engine.run_id, engine.matcher_pubkey.clone())
    else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "this matcher is running without a state database, so it has no durable \
             execution claims to serve"
                .to_string(),
        ));
    };
    Ok(RunHeader {
        run_id,
        session: engine.feed_session.clone().unwrap_or_default(),
        cursor: engine.durable_last_seen,
        matcher_public_key,
        feed_public_key: engine.feed_pubkey.clone(),
    })
}

/// How many batches a reader of `GET /stream` may fall behind before it is
/// told to start again.
///
/// The engine applies a batch every `--poll-ms`, 200ms by default, so this is
/// about twelve seconds of a reader that has stopped reading. A browser tab
/// that a laptop suspended is the case this exists for. It is told, and it
/// answers by reading the snapshot endpoints again; it is not sent twelve
/// seconds of stale batches one after another, and the exchange does not hold
/// them for it.
const LIVE_BACKLOG: usize = 64;

/// One batch of the log, ready to send.
///
/// Pre-serialised, once, for each symbol. A stream is opened for one symbol and
/// a reader of MERKLE-USDC is not sent the ETH-USDC book, so the alternative is
/// serialising the same batch again for every reader. There are three symbols
/// and there may be many readers.
struct Tick {
    /// The message the engine has read up to, as `id:` on every event. A
    /// browser sends it back as `Last-Event-ID` when it reconnects.
    cursor: u64,
    /// The JSON body, by symbol.
    body: HashMap<String, String>,
}

/// What every open stream is sent as the engine consumes.
///
/// A `broadcast` channel and not one channel per reader: the engine builds each
/// batch once and hands the same `Arc` to everyone. A reader that stops reading
/// costs `LIVE_BACKLOG` messages of memory and no more, and is then dropped
/// from the channel's point of view with a count of what it missed. That count
/// is what the page turns into "read the snapshots again".
#[derive(Clone)]
struct LiveFeed {
    to_readers: broadcast::Sender<Arc<Tick>>,
}

impl LiveFeed {
    fn new() -> LiveFeed {
        LiveFeed {
            to_readers: broadcast::channel(LIVE_BACKLOG).0,
        }
    }

    /// Whether anything is listening.
    ///
    /// Asked before a batch is built, not after. Building one serialises the
    /// book of every symbol, which is about 9 KB five times a second, and an
    /// exchange with nobody watching should not spend that. Most of the time
    /// there is nobody watching.
    fn wanted(&self) -> bool {
        self.to_readers.receiver_count() > 0
    }

    /// Sends a batch. A reader that closed the tab between `wanted` and here is
    /// not a failure, so the result is dropped.
    fn send(&self, tick: Tick) {
        let _ = self.to_readers.send(Arc::new(tick));
    }
}

/// How many levels a side the streamed book carries.
///
/// The page fits its own depth to the panel and asks `/book` for that number;
/// `MAX_DEPTH` there is 50 and a tall window asks for about 30. A stream is
/// written once for every reader, so it cannot answer each reader's number, and
/// it carries the most any of them draws. 50 levels a side is about 3 KB a
/// symbol, sent five times a second, and a reader takes the rows it has room
/// for.
const STREAM_DEPTH: usize = 50;

/// What one symbol's reader is sent for one batch.
///
/// Only what changed. The page holds the last 40 trades and the last 40
/// messages and redrew both from a fresh answer twice a second: 8,039 and 5,339
/// bytes to learn about the two or three that were new. This carries the new
/// ones. The book is a snapshot because a book is a snapshot, and it is 1.4 KB.
#[derive(Serialize)]
struct TickBody<'a> {
    /// The message this engine has read up to. The same number `/market`
    /// answers with, so a reader can always say whether what it draws is
    /// current, which is the question this whole page exists to answer.
    cursor: OrderId,
    /// The trades this batch produced in this symbol, oldest first.
    trades: Vec<&'a Trade>,
    /// The messages this batch consumed for this symbol, in the order the log
    /// holds them.
    messages: Vec<&'a OrderMessage>,
    /// This symbol's depth after the batch, to the depth a reader asked for.
    book: BookResponse,
}

/// Builds one batch's event for every symbol that has ever been listed.
///
/// Called with the engine locked, and it does not send: it returns the strings,
/// and the caller sends them after it has let the lock go. An exchange that
/// holds its matching lock while it writes to sockets is an exchange whose
/// matching speed is set by its slowest reader.
fn tick_of(
    state: &MatcherState,
    trades_before: u64,
    batch: &[ReadMessage<OrderMessage>],
    depth: usize,
) -> Tick {
    let made = state
        .trades_total()
        .saturating_sub(trades_before)
        .min(state.trades.len() as u64) as usize;
    let fresh = state.trades.iter().skip(state.trades.len() - made);
    let level_view = |(&price, level): (&i64, &VecDeque<RestingOrder>)| LevelView {
        price: cents_to_f64(price),
        quantity: tenths_to_f64(level.iter().map(|o| o.qty_tenths).sum()),
        orders: level.len(),
    };
    let mut body = HashMap::new();
    // Every symbol the log has ever listed, so a reader watching a delisted one
    // still gets its cancels and the empty book that is the true answer for it.
    let symbols: Vec<String> = state.symbols.symbols.keys().cloned().collect();
    for symbol in symbols {
        let trades: Vec<&Trade> = fresh.clone().filter(|t| t.symbol == symbol).collect();
        // A cancel names no symbol, so it goes to every reader. The page reads
        // it against the order it holds, which is the same rule `/messages`
        // follows for the same reason.
        // A message this build is too old to read is left out. The page draws
        // what it can read, and `newest_rule_set` on the strip is what tells a
        // reader that this exchange has moved past the page in front of them.
        let messages: Vec<&OrderMessage> = batch
            .iter()
            .filter_map(|read| read.parsed.as_ref().ok())
            .filter(|m| match m {
                OrderMessage::New { symbol: s, .. } => *s == symbol,
                _ => true,
            })
            .collect();
        let (bids, asks) = match state.books.get(&symbol) {
            Some(book) => (
                book.bids.iter().rev().take(depth).map(level_view).collect(),
                book.asks.iter().take(depth).map(level_view).collect(),
            ),
            None => (Vec::new(), Vec::new()),
        };
        let payload = TickBody {
            cursor: state.last_seen,
            trades,
            messages,
            book: BookResponse {
                symbol: symbol.clone(),
                bids,
                asks,
            },
        };
        if let Ok(json) = serde_json::to_string(&payload) {
            body.insert(symbol, json);
        }
    }
    Tick {
        cursor: state.last_seen,
        body,
    }
}

/// How many read-only handles on the state database the history endpoints
/// share.
///
/// There was one, behind a `Mutex`, and every request that reads that database
/// waited for every other one. Measured on the live exchange with one browser
/// open: `/candles` answers in 657ms on its own and in 4,374ms from inside the
/// page. The page asks for the same 400 candles about six times before the
/// first answer arrives, and all six queue on the one handle.
///
/// SQLite does not need that queue. `store.rs` opens the database with
/// `journal_mode = WAL` and says why a second connection is safe: "a reader
/// does not block the poller's commits, and a commit does not block a reader".
/// Many readers may read at once. The `Mutex` was giving that away.
///
/// Eight, and not one, and not a hundred. A handle is one file descriptor and
/// one SQLite page cache, 2MB by default, so eight is about 16MB against the
/// 3GB this deployment runs with. Eight also covers what one page asks for:
/// a refresh opens at most six reads of this database at a time.
const HISTORY_READERS: usize = 8;

/// The handles the history endpoints share, and the count of how many may be
/// out at once.
struct HistoryPool {
    /// The handles nobody is using. `permits` bounds how many leave, so a
    /// caller that holds a permit always finds one here.
    free: Mutex<Vec<HistoryReader>>,
    /// One permit per handle. Held for the length of one read, and taken in the
    /// async task rather than on a blocking thread: a request that waits for a
    /// handle should cost a future and not a thread.
    permits: Arc<Semaphore>,
}

impl HistoryPool {
    /// Opens every handle, or none. The endpoints that read this database say
    /// they cannot serve it when this fails, and that answer is decided once
    /// here rather than per request.
    fn open(path: &std::path::Path, readers: usize) -> Result<HistoryPool, StoreError> {
        let mut free = Vec::with_capacity(readers);
        for _ in 0..readers {
            free.push(HistoryReader::open(path)?);
        }
        Ok(HistoryPool {
            free: Mutex::new(free),
            permits: Arc::new(Semaphore::new(readers)),
        })
    }
}

/// One handle, out of the pool, returned when this is dropped.
///
/// A `Drop` and not a line at the end of the read, because a query that panics
/// must cost one answer and not one handle. Without this the pool would shrink
/// on the first panic and the pop below would then fail for every request after
/// it.
struct Lease {
    pool: Arc<HistoryPool>,
    reader: Option<HistoryReader>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.take() {
            self.pool
                .free
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(reader);
        }
    }
}

/// Runs one read against the state database, away from the async runtime.
///
/// A SQLite read blocks, and the engine shares its runtime with the poller. So
/// this uses the same `spawn_blocking` the sequencer uses for its own state.
async fn read_history<T, F>(state: &ApiState, read: F) -> Result<T, (StatusCode, String)>
where
    F: FnOnce(&HistoryReader) -> Result<T, StoreError> + Send + 'static,
    T: Send + 'static,
{
    let Some(pool) = state.history.clone() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "this matcher cannot read its own state database, so it cannot serve its \
             execution history"
                .to_string(),
        ));
    };
    // Waited for here, in the async task. A request that arrives when all eight
    // handles are out holds a future until one is free, and holds no thread.
    let permit = match Arc::clone(&pool.permits).acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "the matcher is shutting down".to_string(),
            ));
        }
    };
    tokio::task::spawn_blocking(move || {
        // Held until the read is over, so the handle is not lent twice.
        let _permit = permit;
        let reader = pool
            .free
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop()
            .expect("a permit is a free handle: `permits` counts what `free` holds");
        let lease = Lease {
            pool: Arc::clone(&pool),
            reader: Some(reader),
        };
        read(lease.reader.as_ref().expect("the lease holds its handle"))
    })
    .await
    .map_err(|e| {
        error!("history read task failed: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "history read failed".to_string(),
        )
    })?
    .map_err(|e| {
        error!("cannot read execution history: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cannot read execution history: {}", e),
        )
    })
}

/// Answers GET /claims with one page of the current run's signed execution
/// claims, starting after `?since=<from_msg>`.
///
/// This endpoint is what lets somebody who is not the operator reach an
/// execution claim. Before it existed, the claims lived in a SQLite file on the
/// operator's disk, and "audit us" meant "ask us for our database".
async fn get_claims(
    State(state): State<ApiState>,
    Query(params): Query<SinceQuery>,
) -> Result<Json<ClaimsResponse>, (StatusCode, String)> {
    let header = run_header(&state)?;
    let since = params.since.unwrap_or(0);
    let run_id = header.run_id;
    let rows = read_history(&state, move |reader| {
        reader.claims_since(run_id, since, PAGE_LIMIT)
    })
    .await?;
    Ok(Json(ClaimsResponse {
        run_id: header.run_id,
        session: header.session,
        cursor: header.cursor,
        matcher_public_key: header.matcher_public_key,
        feed_public_key: header.feed_public_key,
        claims: rows
            .into_iter()
            .map(|claim| ClaimView {
                from_msg: claim.from_msg,
                to_msg: claim.to_msg,
                root_before: logchain::to_hex(&claim.root_before),
                root_after: logchain::to_hex(&claim.root_after),
                trades_total: claim.trades_total,
                signature: claim.signature.map(|s| logchain::to_hex(&s)),
            })
            .collect(),
    }))
}

/// Answers GET /trade-log with one page of the current run's trades, starting
/// after `?since=<trade_id>`.
///
/// `/trades` stays what it was: the newest few trades, from memory, for the user
/// interface. This endpoint is the record. It serves every trade of the run, in
/// order, in the whole numbers it was matched on. So an audit somewhere else can
/// compare the whole trades table against a second run of the same messages, and
/// nobody has to hand over the database file.
async fn get_trade_log(
    State(state): State<ApiState>,
    Query(params): Query<SinceQuery>,
) -> Result<Json<TradeLogResponse>, (StatusCode, String)> {
    let header = run_header(&state)?;
    let since = params.since.unwrap_or(0);
    let run_id = header.run_id;
    let rows = read_history(&state, move |reader| {
        reader.trades_since(run_id, since, PAGE_LIMIT)
    })
    .await?;
    Ok(Json(TradeLogResponse {
        run_id: header.run_id,
        trades: rows
            .into_iter()
            .map(|trade| TradeLogRow {
                trade_id: trade.trade_id,
                timestamp: trade.timestamp,
                symbol: trade.symbol,
                price_cents: trade.price_cents,
                qty_tenths: trade.qty_tenths,
                maker_order: trade.maker_order,
                maker_account: trade.maker_account,
                taker_order: trade.taker_order,
                taker_account: trade.taker_account,
                taker_side: trade.taker_side,
            })
            .collect(),
    }))
}

/// The most price levels one GET /book may ask for, on each side.
///
/// The handler holds the engine lock while it walks the levels and adds up the
/// waiting orders in each one. Without a limit on `depth`, the caller would
/// decide how long every other endpoint waits. The size of the book is the real
/// cost today -- 423 levels and 18 KB on the live exchange, against 1 KB for the
/// 12 the page asks for -- so this is a missing limit and not a live fault. The
/// limit is still worth setting, because the page is about to work out its own
/// depth from the panel height, and because the book grows.
///
/// The same value and the same reason as `PAGE_LIMIT` and `MAX_CANDLES`: one
/// request buys a limited amount of work.
const MAX_BOOK_DEPTH: usize = 1000;

/// Query parameters for GET /book.
#[derive(Deserialize)]
struct BookQuery {
    symbol: String,
    /// How many price levels to show on each side. The default is 10, and the
    /// most is `MAX_BOOK_DEPTH`.
    depth: Option<usize>,
}

/// The response for GET /book: both sides of one symbol's book, best price
/// first.
#[derive(Serialize)]
struct BookResponse {
    symbol: String,
    bids: Vec<LevelView>,
    asks: Vec<LevelView>,
}

/// What the three read endpoints answer for a symbol the log never listed.
///
/// They refuse such a symbol, and do not answer with an empty book or an empty
/// trade list. So a typing mistake cannot read as "this symbol has never
/// traded". The question they ask is "has the log ever listed this symbol", and
/// not "is it listed now". A delisted symbol's trades happened, and an endpoint
/// that stopped answering about them would erase a history the log still holds.
fn unlisted(symbol: &str) -> (StatusCode, String) {
    (
        StatusCode::BAD_REQUEST,
        format!("'{}' is not a symbol this log has listed", symbol),
    )
}

/// Answers GET /book with one symbol's book, with the quantities at each price
/// added up.
async fn get_book(
    State(state): State<Arc<Mutex<MatcherState>>>,
    Query(params): Query<BookQuery>,
) -> Result<Json<BookResponse>, (StatusCode, String)> {
    // The handler cuts the number down and does not refuse the request. `/book`
    // already answers with fewer levels than asked whenever the book holds
    // fewer. So a caller cannot tell a cut from a thin market, and both mean the
    // same thing: this is everything there is to show. `get_messages` and
    // `get_candles` cut their counts the same way. A 400 is kept for a value
    // that names something that does not exist.
    let depth = params.depth.unwrap_or(10).min(MAX_BOOK_DEPTH);
    let state = lock_state(&state);
    // The question is "ever listed", and not "listed now". A delisted symbol has
    // an empty book, and that is the true answer about it. A symbol the log
    // never listed is a typing mistake, and the handler says so.
    if !state.symbols.ever_listed(&params.symbol) {
        return Err(unlisted(&params.symbol));
    }
    let level_view = |(&price, level): (&i64, &VecDeque<RestingOrder>)| LevelView {
        price: cents_to_f64(price),
        quantity: tenths_to_f64(level.iter().map(|o| o.qty_tenths).sum()),
        orders: level.len(),
    };
    let (bids, asks) = match state.books.get(&params.symbol) {
        Some(book) => (
            book.bids.iter().rev().take(depth).map(level_view).collect(),
            book.asks.iter().take(depth).map(level_view).collect(),
        ),
        None => (Vec::new(), Vec::new()),
    };
    Ok(Json(BookResponse {
        symbol: params.symbol,
        bids,
        asks,
    }))
}

/// Query parameters for GET /trades.
#[derive(Deserialize)]
struct TradesQuery {
    /// When given, only the trades for this symbol.
    symbol: Option<String>,
    /// When given, only the trades this account took part in, on either side.
    ///
    /// Both sides, because an account's fills are the fills it was in. The
    /// account does not choose whether it was waiting in the book or arriving
    /// when a fill happened.
    account: Option<AccountId>,
    /// How many of the newest trades to answer with. The default is 20.
    n: Option<usize>,
}

/// Answers GET /trades with the newest trades, oldest first.
///
/// The handler refuses an unknown symbol, and does not answer with an empty
/// list. So a typing mistake cannot read as "this symbol has never traded".
/// `/book` refuses the same input the same way.
///
/// The window in memory answers this whenever it can, which is every request the
/// user interface makes. A filter that finds fewer than `n` matches inside the
/// window gets the rest from the trades table, below the window, with SQLite
/// applying the same filter. An account that last traded hours ago is such a
/// case. Without that top-up, the answer would turn into "this account has not
/// traded recently" dressed as "this account has not traded", and would say
/// nothing about the difference.
async fn get_trades(
    State(state): State<ApiState>,
    Query(params): Query<TradesQuery>,
) -> Result<Json<Vec<Trade>>, (StatusCode, String)> {
    if let Some(symbol) = &params.symbol
        && !lock_state(&state.engine).symbols.ever_listed(symbol)
    {
        return Err(unlisted(symbol));
    }
    if let Some(account) = params.account {
        // Every side of every fill creates a position entry, including a
        // self-trade whose net position is zero. The map is rebuilt from every
        // durable trade on startup and entries are never removed. An account
        // absent here therefore has no trade to find below the window. Answering
        // now also keeps an unused-account request independent of a busy history
        // pool.
        let known = lock_state(&state.engine)
            .positions
            .keys()
            .any(|(holder, _)| *holder == account);
        if !known {
            return Ok(Json(Vec::new()));
        }
    }
    let n = params.n.unwrap_or(20).min(PAGE_LIMIT);
    let matches = |symbol: &str, maker: AccountId, taker: AccountId| {
        params.symbol.as_ref().is_none_or(|s| s == symbol)
            && params.account.is_none_or(|a| maker == a || taker == a)
    };
    // Walk back from the newest trade and stop at n. A walk forward would copy
    // every matching trade in the run's history on every request, and the user
    // interface asks twice a second against a list that only grows.
    let (mut newest_first, oldest_held, run_id) = {
        let engine = lock_state(&state.engine);
        let held: Vec<Trade> = engine
            .trades
            .iter()
            .rev()
            .filter(|t| matches(&t.symbol, t.maker_account, t.taker_account))
            .take(n)
            .cloned()
            .collect();
        (
            held,
            engine.trades.front().map_or(0, |t| t.trade_id),
            engine.run_id,
        )
    };

    // There is nothing to top up from on an engine with no state database, or on
    // one whose file could not be opened for reading. The engine reports that at
    // startup. The window is then all there is, and the handler serves the
    // window instead of failing the whole request.
    if newest_first.len() < n && oldest_held > 1 && state.history.is_some() {
        let Some(run_id) = run_id else {
            return Ok(Json(reversed(newest_first)));
        };
        let wanted = n - newest_first.len();
        let rows = read_history(&state, move |reader| {
            reader.trades_before(run_id, oldest_held, params.symbol, params.account, wanted)
        })
        .await?;
        newest_first.extend(rows.into_iter().map(|row| Trade {
            trade_id: row.trade_id,
            symbol: row.symbol,
            price: cents_to_f64(row.price_cents),
            quantity: tenths_to_f64(row.qty_tenths),
            maker_order: row.maker_order,
            maker_account: row.maker_account,
            taker_order: row.taker_order,
            taker_account: row.taker_account,
            taker_side: row.taker_side,
            timestamp: row.timestamp,
        }));
    }
    Ok(Json(reversed(newest_first)))
}

/// Turns newest first into oldest first. Every trade list this API serves is in
/// oldest-first order.
fn reversed(mut trades: Vec<Trade>) -> Vec<Trade> {
    trades.reverse();
    trades
}

/// Query parameters for GET /pnl.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PnlQuery {
    /// The one account whose history the caller wants.
    account: AccountId,
    /// About how many samples to answer with for each account. The default is
    /// 200.
    points: Option<usize>,
}

/// One sample of an account's profit, at the moment of one trade.
#[derive(Serialize)]
struct PnlPoint {
    timestamp: u64,
    realized: f64,
    unrealized: f64,
    total: f64,
}

/// One account's profit over time.
#[derive(Serialize)]
struct PnlSeries {
    account: AccountId,
    points: Vec<PnlPoint>,
}

/// Answers GET /pnl with profit over time. A chart of it shows how an account
/// reached the number `/positions` reports, and not only what that number is
/// now.
///
/// The handler reads only this account's fills through the account indexes. At
/// each sampled trade it reads the last price of the symbols that account has
/// traded. That produces the same position and mark as a full replay without
/// making an unused account scan the run.
async fn get_pnl(
    State(state): State<ApiState>,
    Query(params): Query<PnlQuery>,
) -> Result<Json<Vec<PnlSeries>>, (StatusCode, String)> {
    let account = params.account;
    let (run_id, window_from, total, symbols, window, known) = {
        let engine = lock_state(&state.engine);
        let symbols: Vec<String> = engine
            .positions
            .keys()
            .filter(|(holder, _)| *holder == account)
            .map(|(_, symbol)| symbol.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        (
            engine.run_id,
            engine.trades.front().map_or(1, |t| t.trade_id),
            engine.trades_total,
            symbols.clone(),
            engine.trades.iter().cloned().collect::<Vec<_>>(),
            !symbols.is_empty(),
        )
    };

    if !known || total == 0 {
        return Ok(Json(vec![PnlSeries {
            account,
            points: Vec::new(),
        }]));
    }

    let sample_ids = pnl_sample_ids(total, params.points.unwrap_or(200));
    let samples_before_window: Vec<u64> = sample_ids
        .iter()
        .copied()
        .take_while(|trade_id| *trade_id < window_from)
        .collect();
    let mut replay = AccountPnlReplay::new(account);

    // The durable part is read by account, in bounded pages. Price marks and
    // sample timestamps are index lookups at the few moments returned.
    if window_from > 1 {
        let Some(run_id) = run_id else {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "this matcher has no state database, so the trades before the ones it still \
                 holds in memory are gone and a profit series over the run cannot be built"
                    .to_string(),
            ));
        };
        let durable_through = window_from - 1;
        replay = read_history(&state, move |reader| {
            let newest = reader.newest_trade_id(run_id)?;
            if newest < durable_through {
                return Err(StoreError::Corrupt(format!(
                    "run {} has durable trades through {}, but the memory window starts at {}",
                    run_id, newest, window_from
                )));
            }

            let mut cursor = 0u64;
            for sample_id in samples_before_window {
                apply_account_until(reader, &mut replay, run_id, &mut cursor, sample_id)?;
                set_pnl_marks(reader, &mut replay, run_id, &symbols, sample_id)?;
                let timestamp = reader.trade_timestamp(run_id, sample_id)?.ok_or_else(|| {
                    StoreError::Corrupt(format!(
                        "run {} has no trade {} for its profit series",
                        run_id, sample_id
                    ))
                })?;
                replay.sample(timestamp);
            }
            apply_account_until(reader, &mut replay, run_id, &mut cursor, durable_through)?;
            set_pnl_marks(reader, &mut replay, run_id, &symbols, durable_through)?;
            Ok(replay)
        })
        .await?;
    }

    let wanted: HashSet<u64> = sample_ids.iter().copied().collect();
    for trade in window.iter().filter(|trade| trade.trade_id <= total) {
        replay.apply_live_trade(trade).map_err(|message| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "cannot build account {} profit history: {}",
                    account, message
                ),
            )
        })?;
        if wanted.contains(&trade.trade_id) {
            replay.sample(trade.timestamp);
        }
    }

    if replay.points.len() != sample_ids.len() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "account {} profit history expected {} samples and built {}",
                account,
                sample_ids.len(),
                replay.points.len()
            ),
        ));
    }

    Ok(Json(vec![PnlSeries {
        account,
        points: replay.points,
    }]))
}

fn pnl_sample_ids(total: u64, points: usize) -> Vec<u64> {
    if total == 0 {
        return Vec::new();
    }
    let count = points.clamp(2, 2000) as u64;
    let step = total.div_ceil(count).max(1);
    let mut ids = Vec::with_capacity(count as usize + 1);
    let mut trade_id = 1u64;
    while trade_id <= total {
        ids.push(trade_id);
        let Some(next) = trade_id.checked_add(step) else {
            break;
        };
        trade_id = next;
    }
    if ids.last().copied() != Some(total) {
        ids.push(total);
    }
    ids
}

fn apply_account_until(
    reader: &HistoryReader,
    replay: &mut AccountPnlReplay,
    run_id: i64,
    cursor: &mut u64,
    through: u64,
) -> Result<(), StoreError> {
    while *cursor < through {
        let rows =
            reader.account_trades_between(run_id, replay.account, *cursor, through, PAGE_LIMIT)?;
        let Some(last) = rows.last().map(|row| row.trade_id) else {
            break;
        };
        if last <= *cursor {
            return Err(StoreError::Corrupt(format!(
                "account trade index did not advance past {}",
                cursor
            )));
        }
        for row in rows {
            replay.apply_fill(
                &row.symbol,
                row.price_cents,
                row.qty_tenths,
                row.maker_account,
                row.taker_account,
                row.taker_side,
            );
        }
        *cursor = last;
    }
    Ok(())
}

fn set_pnl_marks(
    reader: &HistoryReader,
    replay: &mut AccountPnlReplay,
    run_id: i64,
    symbols: &[String],
    trade_id: u64,
) -> Result<(), StoreError> {
    for symbol in symbols {
        replay.set_mark(symbol, reader.last_price_at(run_id, symbol, trade_id)?);
    }
    Ok(())
}

/// One account's exact position state while its sampled history is rebuilt.
struct AccountPnlReplay {
    account: AccountId,
    points: Vec<PnlPoint>,
    positions: HashMap<String, Position>,
    last: HashMap<String, i64>,
}

impl AccountPnlReplay {
    fn new(account: AccountId) -> Self {
        AccountPnlReplay {
            account,
            points: Vec::new(),
            positions: HashMap::new(),
            last: HashMap::new(),
        }
    }

    fn apply_fill(
        &mut self,
        symbol: &str,
        price_cents: i64,
        qty_tenths: i64,
        maker_account: AccountId,
        taker_account: AccountId,
        taker_side: Side,
    ) {
        let maker_side = match taker_side {
            Side::Buy => Side::Sell,
            Side::Sell => Side::Buy,
        };
        for (account, side) in [(maker_account, maker_side), (taker_account, taker_side)] {
            if account == self.account {
                let _ = self
                    .positions
                    .entry(symbol.to_string())
                    .or_default()
                    .apply_fill(side, qty_tenths, price_cents);
            }
        }
    }

    fn set_mark(&mut self, symbol: &str, price_cents: Option<i64>) {
        match price_cents.filter(|price| *price > 0) {
            Some(price) => {
                self.last.insert(symbol.to_string(), price);
            }
            None => {
                self.last.remove(symbol);
            }
        }
    }

    fn apply_live_trade(&mut self, trade: &Trade) -> Result<(), String> {
        let price_cents = to_grid(trade.price, 100.0)
            .ok_or_else(|| format!("trade {} has an off-grid price", trade.trade_id))?;
        let qty_tenths = to_grid(trade.quantity, 10.0)
            .ok_or_else(|| format!("trade {} has an off-grid quantity", trade.trade_id))?;
        self.last.insert(trade.symbol.clone(), price_cents);
        self.apply_fill(
            &trade.symbol,
            price_cents,
            qty_tenths,
            trade.maker_account,
            trade.taker_account,
            trade.taker_side,
        );
        Ok(())
    }

    fn sample(&mut self, timestamp: u64) {
        // Every listed market in this demo is quoted in USDC. If a later rule
        // permits another quote currency, this response must split by quote
        // currency rather than add unlike amounts.
        let (mut realized, mut unrealized) = (0i64, 0i64);
        for (symbol, position) in &self.positions {
            realized = realized.saturating_add(position.realized_mills);
            if let Some(cents) = self.last.get(symbol).filter(|price| **price > 0) {
                unrealized = unrealized.saturating_add(position.unrealized_mills(*cents));
            }
        }
        self.points.push(PnlPoint {
            timestamp,
            realized: mills_to_f64(realized),
            unrealized: mills_to_f64(unrealized),
            total: mills_to_f64(realized.saturating_add(unrealized)),
        });
    }
}

/// How many accounts one GET /positions answers with, when the caller asks for
/// no number.
///
/// The route had no limit and no default before this constant. One account costs
/// 663 bytes, measured by `POSITIONS_BYTES_PER_ACCOUNT` in
/// `services/tests/market_health.rs`, and the page asks for the route every
/// 500 ms. At the 42 accounts the exchange ran with, that is 27,882 bytes a
/// request. At the 600 accounts `how_many_accounts_the_markets_need` says the
/// markets need, it is 397,800. This is the same missing limit `/book` had
/// before `MAX_BOOK_DEPTH`, and it is worth setting for the same reason: one
/// request should buy a limited amount of work.
///
/// 50 and not `PAGE_LIMIT`, because this is the default a caller gets without
/// saying anything, and the accounts panel of the page shows about 15 rows. A
/// caller that wants every account asks for pages until one comes back short,
/// the same way a caller reads `/claims` and `/trades-since`.
const POSITIONS_PAGE: usize = 50;

/// Query parameters for GET /positions.
#[derive(Deserialize)]
struct PositionsQuery {
    /// When given, only this account.
    account: Option<AccountId>,
    /// Answer with only the accounts numbered above this one, and not this one.
    /// Start at 0, and pass the last account of a page to read the next page.
    ///
    /// The answer is in account-number order, and always was. So a number is all
    /// a cursor needs to be here. `/claims` and `/trades-since` name the same
    /// parameter `since` over their own key.
    since: Option<AccountId>,
    /// How many accounts to answer with. The default is `POSITIONS_PAGE`, and
    /// the most is `PAGE_LIMIT`.
    n: Option<usize>,
    /// Answer with each account's four totals and leave the per-symbol rows
    /// out.
    ///
    /// The rows are most of the answer. Measured on the live exchange:
    /// `/positions?n=50` is 28,634 bytes, and about 500 of every 570 bytes of
    /// an account are its three symbols, eight fields each. The page that reads
    /// this endpoint twice a second draws four numbers from it and sums the
    /// rows into a fifth, which `open_notional` now carries.
    ///
    /// A caller that asks for totals gets an answer with no `positions` key at
    /// all, rather than an empty list. An empty list is what an account that
    /// holds nothing looks like, and an answer must not say two things with one
    /// shape.
    ///
    /// `true` or `false`, and nothing else. `totals=1` is answered with
    /// "provided string was not `true` or `false`", which is the deserializer
    /// naming exactly what it wanted. Written down here because the page sent
    /// `totals=1` first and read that sentence back.
    totals: Option<bool>,
}

/// One account's holding in one symbol, valued at the last traded price.
///
/// Every field name here says exactly which price it came from. This engine sees
/// only the prices of its own trades. So `last_trade_price` is the honest name
/// for what values the position. It is the price of a trade that happened, and
/// not a reference price worked out apart from the book.
#[derive(Serialize)]
struct PositionView {
    symbol: String,
    net_quantity: f64,
    /// The average price of one unit of the open quantity.
    avg_entry_price: Option<f64>,
    /// The last traded price for this symbol. It values the open quantity.
    last_trade_price: Option<f64>,
    /// The running total of cash from this account's fills. Negative is paid
    /// out, and positive is taken in.
    net_cash: f64,
    realized_pnl: f64,
    unrealized_pnl: f64,
    total_pnl: f64,
}

/// One account's holdings and totals across every symbol it traded.
#[derive(Serialize)]
struct AccountView {
    account: AccountId,
    realized_pnl: f64,
    unrealized_pnl: f64,
    total_pnl: f64,
    /// What the open quantity is worth, summed over the symbols below, each
    /// valued at its own last traded price.
    ///
    /// The sum is here because it was being made 50 times a second in a
    /// browser, out of 24 numbers an account, none of which that browser drew.
    /// A symbol that has never traded has no price and adds nothing, which is
    /// the same rule `unrealized_pnl` follows.
    open_notional: f64,
    /// Left out when the request asked for `totals`. See `PositionsQuery`.
    #[serde(skip_serializing_if = "Option::is_none")]
    positions: Option<Vec<PositionView>>,
}

/// Answers GET /positions with what each account holds, and what it has made.
///
/// Open quantity is valued at the symbol's last traded price. A symbol that has
/// not traded yet has no price to value against. So its open quantity reports no
/// profit that is not locked in, and not an invented number.
///
/// The answer is one page of accounts, in account-number order. A page shorter
/// than the count asked for is the end. Every paged answer in this API says the
/// end the same way.
async fn get_positions(
    State(state): State<Arc<Mutex<MatcherState>>>,
    Query(params): Query<PositionsQuery>,
) -> Json<Vec<AccountView>> {
    // The handler cuts the number down and does not refuse the request, the same
    // way `/book` and `/messages` cut their counts. A page shorter than the
    // number asked for already means "this is everything there is", so a cut
    // tells the caller nothing new.
    let n = params.n.unwrap_or(POSITIONS_PAGE).min(PAGE_LIMIT);
    let state = lock_state(&state);
    // Which accounts the page covers, decided before the handler builds a single
    // view. A view holds one string for each position. So choosing the accounts
    // first is what keeps a request's cost to the page it asked for, instead of
    // to every account the engine holds. The loop walks the keys in the order
    // the hash map gives them, so the set does the sorting.
    let mut wanted: BTreeSet<AccountId> = BTreeSet::new();
    for (account, _) in state.positions.keys() {
        if params.account.is_some_and(|w| w != *account)
            || params.since.is_some_and(|s| *account <= s)
        {
            continue;
        }
        wanted.insert(*account);
        // Keep the lowest n accounts above the cursor. Then the pages a caller
        // reads in order cover every account exactly once.
        if wanted.len() > n {
            wanted.pop_last();
        }
    }

    // The handler adds the totals in whole mills and converts once. So an
    // account with three symbols reports 24.724 and not 24.723999999999997.
    let mut accounts: BTreeMap<AccountId, (Vec<PositionView>, i64, i64)> = BTreeMap::new();

    for ((account, symbol), position) in &state.positions {
        if !wanted.contains(account) {
            continue;
        }
        let last_trade_cents = state
            .aggregates
            .get(symbol)
            .map(|agg| agg.last_trade_cents)
            .filter(|cents| *cents > 0);
        let realized_mills = position.realized_mills;
        // The dishonest build reports a locked-in profit that the fills do not
        // give. Nothing on disk changes. The position, the trade record and the
        // state root all stay as they are.
        #[cfg(feature = "dishonest")]
        let realized_mills = if crate::dishonest::telling(crate::dishonest::Lie::Positions) {
            realized_mills.saturating_add(crate::dishonest::POSITION_LIE_MILLS)
        } else {
            realized_mills
        };
        let unrealized_mills = last_trade_cents.map_or(0, |c| position.unrealized_mills(c));
        let entry = accounts.entry(*account).or_default();
        entry.0.push(PositionView {
            symbol: symbol.clone(),
            net_quantity: tenths_to_f64(position.net_qty_tenths),
            avg_entry_price: position.avg_entry_price(),
            last_trade_price: last_trade_cents.map(cents_to_f64),
            net_cash: mills_to_f64(position.cash_mills),
            realized_pnl: mills_to_f64(realized_mills),
            unrealized_pnl: mills_to_f64(unrealized_mills),
            total_pnl: mills_to_f64(realized_mills.saturating_add(unrealized_mills)),
        });
        entry.1 = entry.1.saturating_add(realized_mills);
        entry.2 = entry.2.saturating_add(unrealized_mills);
    }

    let totals_only = params.totals.unwrap_or(false);
    let views = accounts
        .into_iter()
        .map(
            |(account, (mut positions, realized_mills, unrealized_mills))| {
                positions.sort_by(|a, b| a.symbol.cmp(&b.symbol));
                let open_notional = positions
                    .iter()
                    .map(|p| p.net_quantity.abs() * p.last_trade_price.unwrap_or(0.0))
                    .sum();
                AccountView {
                    account,
                    realized_pnl: mills_to_f64(realized_mills),
                    unrealized_pnl: mills_to_f64(unrealized_mills),
                    total_pnl: mills_to_f64(realized_mills.saturating_add(unrealized_mills)),
                    open_notional,
                    positions: if totals_only { None } else { Some(positions) },
                }
            },
        )
        .collect();
    Json(views)
}

/// Query parameters for GET /messages.
#[derive(Deserialize)]
struct MessagesQuery {
    /// When given, only the messages for this symbol. A cancel carries no
    /// symbol. So the answer includes a cancel when the order it names is in
    /// the recent window and belongs to the symbol asked for.
    symbol: Option<String>,
    /// How many of the newest messages to answer with. The default is 30.
    n: Option<usize>,
}

/// Answers GET /messages with the messages the engine has seen, unchanged,
/// newest last.
async fn get_messages(
    State(state): State<Arc<Mutex<MatcherState>>>,
    Query(params): Query<MessagesQuery>,
) -> Json<Vec<OrderMessage>> {
    let n = params.n.unwrap_or(30);
    let state = lock_state(&state);
    // Find the symbol of each cancel's target, from the `New` messages still in
    // the recent window.
    let order_symbols: HashMap<OrderId, &str> = state
        .recent_messages
        .iter()
        .filter_map(|m| match m {
            OrderMessage::New { id, symbol, .. } => Some((*id, symbol.as_str())),
            // Only a `New` names the symbol an order waits under. A
            // `ListSymbol` names a symbol too, and no order is under it.
            OrderMessage::Cancel { .. }
            | OrderMessage::EngineRule { .. }
            | OrderMessage::ListSymbol { .. }
            | OrderMessage::DelistSymbol { .. } => None,
        })
        .collect();
    let messages: Vec<OrderMessage> = state
        .recent_messages
        .iter()
        .filter(|m| match (&params.symbol, m) {
            (None, _) => true,
            (Some(s), OrderMessage::New { symbol, .. }) => symbol == s,
            (Some(s), OrderMessage::Cancel { target_id, .. }) => {
                order_symbols.get(target_id) == Some(&s.as_str())
            }
            // A symbol filter asks for the orders of one book. These three
            // kinds are not orders, so the answer leaves them out.
            (
                Some(_),
                OrderMessage::EngineRule { .. }
                | OrderMessage::ListSymbol { .. }
                | OrderMessage::DelistSymbol { .. },
            ) => false,
        })
        .cloned()
        .collect();
    let start = messages.len().saturating_sub(n);
    Json(messages[start..].to_vec())
}

/// The page and its static assets. All are compiled in, so they remain the same
/// bytes for the life of this process.
const UI_PAGE: &str = include_str!("../static/index.html");
const APP_CSS: &str = include_str!("../static/app.css");
const APP_JS: &str = include_str!("../static/app.js");
const SIGNER_JS: &str = include_str!("../static/ed25519.js");
const FAVICON: &[u8] = include_bytes!("../static/favicon.ico");
const ICON: &[u8] = include_bytes!("../static/icon.png");
const APPLE_ICON: &[u8] = include_bytes!("../static/apple-icon.png");

/// What each of them answers `If-None-Match` with.
///
/// The tag is a hash of the bytes and not the build commit, so it is right in a
/// build that was given no commit, and so two builds of the same asset share it.
static UI_ETAG: LazyLock<String> = LazyLock::new(|| etag_of(UI_PAGE.as_bytes()));
static APP_CSS_ETAG: LazyLock<String> = LazyLock::new(|| etag_of(APP_CSS.as_bytes()));
static APP_JS_ETAG: LazyLock<String> = LazyLock::new(|| etag_of(APP_JS.as_bytes()));
static SIGNER_ETAG: LazyLock<String> = LazyLock::new(|| etag_of(SIGNER_JS.as_bytes()));
static FAVICON_ETAG: LazyLock<String> = LazyLock::new(|| etag_of(FAVICON));
static ICON_ETAG: LazyLock<String> = LazyLock::new(|| etag_of(ICON));
static APPLE_ICON_ETAG: LazyLock<String> = LazyLock::new(|| etag_of(APPLE_ICON));

fn etag_of(body: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(body);
    // Sixteen characters of it. An entity tag is compared and never read, and
    // eight bytes of SHA-256 do not collide across the handful of builds one
    // browser sees.
    let digest = logchain::to_hex(&hash.finalize());
    format!("\"{}\"", &digest[..16])
}

/// One compiled-in asset, with the headers that let a second visit skip it.
///
/// The page is roughly 400 KB and it changes when this binary changes and at no
/// other time. It carried no `ETag`, no `Cache-Control` and no `Last-Modified`,
/// so every reload downloaded all of it again.
///
/// `no-cache` is not "do not cache". It is "ask before you use what you have",
/// which is the answer this page needs: a visitor must never read a page older
/// than the exchange serving it, and a visitor who reloads twice a minute must
/// not fetch the whole page. A reload now sends the tag back and reads 304 with
/// no body at all.
fn compiled_in(
    headers: &HeaderMap,
    etag: &str,
    content_type: &'static str,
    body: &'static [u8],
) -> Response {
    let known = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        // A browser sends back what it was given. A proxy may send several tags
        // in one header, so this asks whether ours is among them rather than
        // whether it is the whole header.
        .is_some_and(|sent| sent.split(',').any(|one| one.trim() == etag));
    let head = [
        (header::ETAG, etag.to_string()),
        (header::CACHE_CONTROL, "no-cache".to_string()),
    ];
    if known {
        return (StatusCode::NOT_MODIFIED, head).into_response();
    }
    (
        head,
        [(header::CONTENT_TYPE, content_type)],
        Bytes::from_static(body),
    )
        .into_response()
}

/// Query parameters for GET /stream.
#[derive(Deserialize)]
struct StreamQuery {
    /// Which symbol's trades, messages and book this reader wants. A stream is
    /// written once for every reader of a symbol, so a reader names one.
    symbol: String,
}

/// The live view: one batch of the log, as the engine finishes applying it.
///
/// This is the same information the read endpoints answer with, sent as it
/// happens instead of on request. It replaces nothing: a reader still opens the
/// page, reads the snapshots, and then follows this. That order is not a
/// convenience, it is what makes the stream checkable. Every event carries the
/// engine's cursor, so a reader can always say whether what it draws is
/// current, and a reader that falls behind is told so and reads the snapshots
/// again rather than drawing from a gap.
///
/// Server-Sent Events, and not a WebSocket. This is one direction. The matcher
/// answers 14 routes and every one of them is a GET; an order goes to the
/// sequencer or to the separate service, on their own hostnames, signed. So the
/// second direction of a WebSocket would carry nothing, and its handshake,
/// framing, ping and reconnect would all have to be written and kept. An event
/// stream is an HTTP response that does not end.
async fn get_stream(
    State(state): State<ApiState>,
    Query(params): Query<StreamQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, String)> {
    if !lock_state(&state.engine)
        .symbols
        .ever_listed(&params.symbol)
    {
        return Err(unlisted(&params.symbol));
    }
    let symbol = params.symbol;
    let batches = BroadcastStream::new(state.live.to_readers.subscribe()).map(move |batch| {
        Ok(match batch {
            Ok(tick) => match tick.body.get(&symbol) {
                Some(json) => Event::default()
                    .event("tick")
                    .id(tick.cursor.to_string())
                    .data(json),
                // A symbol listed after this stream opened. The reader asked
                // for a symbol that had no book in this batch, which is not an
                // error and not a batch it needs.
                None => Event::default().event("idle").data("{}"),
            },
            // The reader stopped reading for longer than `LIVE_BACKLOG`
            // batches. It is told what it missed and reads the snapshots again.
            // Sending it the batches it missed, one after another, would draw a
            // market that already moved on.
            Err(BroadcastStreamRecvError::Lagged(missed)) => Event::default()
                .event("behind")
                .data(format!("{{\"missed\":{}}}", missed)),
        })
    });
    // A market can be quiet, and a proxy between here and the reader may close
    // a connection that says nothing. The keep-alive is a comment line, which
    // an `EventSource` ignores and a proxy counts as traffic.
    Ok(Sse::new(batches).keep_alive(KeepAlive::default()))
}

/// Serves the exchange user interface shell. Its style and code are separate
/// same-origin assets so the response can forbid inline script and style.
async fn get_ui(headers: HeaderMap) -> Response {
    compiled_in(
        &headers,
        &UI_ETAG,
        "text/html; charset=utf-8",
        UI_PAGE.as_bytes(),
    )
}

async fn get_app_css(headers: HeaderMap) -> Response {
    compiled_in(
        &headers,
        &APP_CSS_ETAG,
        "text/css; charset=utf-8",
        APP_CSS.as_bytes(),
    )
}

async fn get_app_js(headers: HeaderMap) -> Response {
    compiled_in(
        &headers,
        &APP_JS_ETAG,
        "text/javascript; charset=utf-8",
        APP_JS.as_bytes(),
    )
}

/// Serves the icon files copied from th3nolo.com with this build.
async fn get_favicon(headers: HeaderMap) -> Response {
    compiled_in(&headers, &FAVICON_ETAG, "image/x-icon", FAVICON)
}

async fn get_icon(headers: HeaderMap) -> Response {
    compiled_in(&headers, &ICON_ETAG, "image/png", ICON)
}

async fn get_apple_icon(headers: HeaderMap) -> Response {
    compiled_in(&headers, &APPLE_ICON_ETAG, "image/png", APPLE_ICON)
}

/// Serves the Ed25519 signer the page imports, out of this binary.
///
/// It is a separate file and not another script inside the page. So what this
/// serves is the published `@noble/ed25519` release, byte for byte, and a reader
/// can compare the two. It is compiled in, like the page itself, so the user
/// interface still fetches nothing from anywhere but this process. A script tag
/// pointing at a CDN, on a page whose whole subject is checking things, would be
/// the one thing on that page nobody could check.
async fn get_signer(headers: HeaderMap) -> Response {
    compiled_in(
        &headers,
        &SIGNER_ETAG,
        "text/javascript; charset=utf-8",
        SIGNER_JS.as_bytes(),
    )
}

/// What the user interface needs to know and this binary does not hold: where a
/// browser sends its submissions, by either route.
#[derive(Serialize)]
struct UiConfig {
    feed_url: String,
    /// The second route, or `null` when no browser can reach the separate
    /// service. Null and not a missing field, so a page that reads it can tell
    /// "the operator runs no second route" from "this exchange is older than
    /// the flag".
    inbox_url: Option<String>,
}

/// Answers GET /config with the two addresses the page posts submissions to.
///
/// The page cannot guess either address. In every deployment the sequencer and
/// the separate service are both a different origin from this user interface:
/// different ports on one machine, and different host names or paths behind a
/// reverse proxy. The operator is the one who knows which. Each address must
/// appear in that service's own `--ui-origin`, or the browser refuses the
/// submission before it sends it.
async fn get_config(State(state): State<ApiState>) -> Json<UiConfig> {
    Json(UiConfig {
        feed_url: state.public_feed_url.clone(),
        inbox_url: state.public_inbox_url.clone(),
    })
}

/// The environment variable that names the anchor deployment file, which
/// `anchor/deploy.py` writes. It is an environment variable and not a flag,
/// because the deploy step produces the file. The operator who runs this binary
/// does not choose the file, and whatever runs both connects the two.
const ANCHOR_CONFIG_ENV: &str = "ANCHOR_CONFIG";

/// What the user interface needs to find the anchor contract on its own: where
/// the contract is, on which chain, and from which block it has been writing.
///
/// This is the other half of what lets a browser check this exchange without
/// trusting the operator. The page can already build the sequencer's chain from
/// `/messages.ndjson`, and check the sequencer's signature over it. With this
/// configuration the page can also go to a chain nobody here controls and read
/// what the anchor recorded. The operator cannot answer for that chain.
#[derive(Debug, Clone, Serialize, PartialEq)]
struct AnchorConfig {
    address: String,
    chain_id: u64,
    /// What to call the chain in the user interface. This binary works the name
    /// out, and does not read it from the file. So a deployment file that
    /// somebody edited by hand cannot label Base Sepolia as mainnet on the page.
    chain_name: String,
    /// Every RPC the browser may read this chain through, best first.
    ///
    /// A list and not one address, because one public endpoint is one thing
    /// that can be slow, rate-limited or blocked, and when it is, the one
    /// number on this page that the operator cannot fabricate is the number
    /// that disappears. The browser tries them in order and stops at the first
    /// that answers.
    ///
    /// Every one of them is a third party. That is the point of this box and it
    /// is not negotiable: an RPC served by this exchange would turn a reading
    /// from a chain the operator does not run into another number the operator
    /// is asserting.
    rpcs: Vec<String>,
    /// Where a reader can look the contract up. Missing for a chain this binary
    /// does not know. The page then shows the address as plain text, and not as
    /// a link to a block explorer that may not exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    explorer: Option<String>,
    deployed_block: u64,
    writer: String,
}

/// The fields this binary reads out of the deployment file. The file holds
/// more: the ABI selectors, the compiler settings and the transaction that
/// deployed the contract. None of that is the browser's business, so this binary
/// serves none of it.
#[derive(Deserialize)]
struct AnchorDeployment {
    address: String,
    chain_id: u64,
    rpc: String,
    /// More endpoints for the same chain, after `rpc`. Absent in a file written
    /// before this existed, and then the browser has the one it always had.
    #[serde(default)]
    rpc_fallbacks: Vec<String>,
    block_number: u64,
    writer: String,
}

/// What to call a chain, and where to look things up on it.
///
/// An unknown chain id is a supported answer and not a failure. Somebody who
/// anchors into a chain this list does not hold gets a page that names the chain
/// by its id and offers no explorer link. That is exactly as much as this binary
/// honestly knows about the chain.
fn chain_labels(chain_id: u64) -> (String, Option<String>) {
    let (name, explorer) = match chain_id {
        1 => ("Ethereum", Some("https://etherscan.io")),
        8453 => ("Base", Some("https://basescan.org")),
        84532 => ("Base Sepolia", Some("https://sepolia.basescan.org")),
        11155111 => ("Sepolia", Some("https://sepolia.etherscan.io")),
        _ => return (format!("chain {}", chain_id), None),
    };
    (name.to_string(), explorer.map(str::to_string))
}

/// Reads the anchor deployment file that `path` names, or says once why there is
/// nothing to serve.
///
/// Every failure gives the same answer: `None`, and `/anchor-config` then
/// answers 404. An exchange that runs without an anchor is a normal deployment
/// and not a broken one. The sequencer still signs its heads, and the user
/// interface hides the anchor section. So a missing variable, a missing file and
/// a file this binary cannot read all leave this engine serving everything else
/// exactly as before. The one line logged here is where an operator who *meant*
/// to anchor finds out.
fn load_anchor_config(path: Option<String>) -> Option<AnchorConfig> {
    let Some(path) = path else {
        info!(
            "no {}: this exchange serves no anchor configuration, and the UI will hide its \
             anchor section",
            ANCHOR_CONFIG_ENV
        );
        return None;
    };
    let deployment = std::fs::read_to_string(&path)
        .map_err(|e| e.to_string())
        .and_then(|text| {
            serde_json::from_str::<AnchorDeployment>(&text).map_err(|e| e.to_string())
        });
    match deployment {
        Ok(deployment) => {
            let (chain_name, explorer) = chain_labels(deployment.chain_id);
            info!(
                "anchor configuration from {}: {} on {}",
                path, deployment.address, chain_name
            );
            Some(AnchorConfig {
                address: deployment.address,
                chain_id: deployment.chain_id,
                chain_name,
                // The file's own endpoint first. An operator who names an
                // endpoint has named the one they trust.
                rpcs: std::iter::once(deployment.rpc)
                    .chain(deployment.rpc_fallbacks)
                    .collect(),
                explorer,
                deployed_block: deployment.block_number,
                writer: deployment.writer,
            })
        }
        Err(e) => {
            warn!(
                "cannot read the anchor configuration at {} ({}={}): {}. This exchange will run \
                 as usual and the UI will hide its anchor section",
                path, ANCHOR_CONFIG_ENV, path, e
            );
            None
        }
    }
}

/// Answers GET /anchor-config with where the anchor contract is. A browser can
/// then read the contract from the chain, and ask this operator nothing.
///
/// 404 is a real answer here and not an error. It means this exchange writes
/// commitments nowhere, which is a deployment somebody may run on purpose. The
/// page then hides its whole anchor section.
async fn get_anchor_config(
    State(state): State<ApiState>,
) -> Result<Json<AnchorConfig>, (StatusCode, String)> {
    state.anchor.clone().map(Json).ok_or((
        StatusCode::NOT_FOUND,
        "this exchange is not anchored to a chain, so there is no anchor configuration to \
         serve\n"
            .to_string(),
    ))
}

/// Query parameters for GET /open-orders.
#[derive(Deserialize)]
struct OpenOrdersQuery {
    account: AccountId,
}

/// One of an account's orders that still waits in a book.
#[derive(Serialize)]
struct OpenOrderView {
    /// The message id the order arrived as. A cancel names that id.
    id: OrderId,
    symbol: String,
    side: Side,
    price: f64,
    /// What is left of the order. An order that half filled waits for the rest.
    quantity: f64,
}

/// Answers GET /open-orders with what one account still has waiting in the
/// books.
///
/// `account` is required and not optional. Every other read endpoint here serves
/// the whole market, because the whole market is public. This one could too: the
/// books are public and the ids are on the sequencer. It takes an account
/// anyway, because the answer is useful only for one account at a time, and a
/// caller that must ask for one writes a request that says what it is for.
///
/// This endpoint is what makes a cancel from the user interface honest. Without
/// it a page can only remember the ids it sent. It cannot tell an order that
/// still waits from one that filled a second later. So every cancel button looks
/// live and half of them do nothing. The engine already knows, and this endpoint
/// says it.
async fn get_open_orders(
    State(state): State<Arc<Mutex<MatcherState>>>,
    Query(params): Query<OpenOrdersQuery>,
) -> Json<Vec<OpenOrderView>> {
    let state = lock_state(&state);
    let mut open: Vec<OpenOrderView> = Vec::new();
    for (symbol, book) in &state.books {
        for (side, levels) in [(Side::Buy, &book.bids), (Side::Sell, &book.asks)] {
            for (price_cents, level) in levels {
                for resting in level {
                    if resting.account != params.account {
                        continue;
                    }
                    open.push(OpenOrderView {
                        id: resting.id,
                        symbol: symbol.clone(),
                        side,
                        price: cents_to_f64(*price_cents),
                        quantity: tenths_to_f64(resting.qty_tenths),
                    });
                }
            }
        }
    }
    // Oldest first. That is the order the account sent them in, and the order
    // the book fills them in at one price.
    open.sort_by_key(|order| order.id);
    Json(open)
}

/// Query parameters for GET /candles.
#[derive(Deserialize)]
struct CandlesQuery {
    symbol: String,
    /// The width of one bucket, in seconds. The default is 15. The accepted
    /// values are the five intervals the browser offers.
    interval: Option<u64>,
    /// How many of the newest buckets to answer with, counting the buckets that
    /// hold no trade. The default is 150.
    ///
    /// So `n` names a span of time: `n` buckets is `n * interval` seconds. A
    /// request for 400 15-second buckets covers the newest 6,000 seconds.
    ///
    /// This used to count only the buckets that hold a trade, and the answer
    /// skipped the rest. Measured on the live exchange on 16 August 2026:
    /// the old `?symbol=BTC-USDC&interval=1&n=400` route answered 400 buckets
    /// that covered 3716 seconds. The page then inserted the 3316 missing
    /// buckets itself, so it asked for 400 candles and drew 3716. Its own window
    /// arithmetic counted candles, so every number it worked out was wrong by
    /// that ratio. One-second candles are no longer part of the public contract.
    n: Option<usize>,
}

/// The chart intervals this API serves, in seconds. A fixed set lets the matcher
/// maintain every answer while it already walks trades, instead of letting one
/// request choose an interval that scans millions of durable fills.
const CANDLE_INTERVALS: [u64; 5] = [15, 300, 900, 3_600, 14_400];

/// One bucket of trades: the first price, the highest, the lowest, the last, and
/// the quantity traded. The code adds the quantity in whole tenths and converts
/// only for display, so a chart never adds floats.
#[derive(Debug, Clone, Serialize)]
struct Candle {
    start: u64,
    open: f64,
    high: f64,
    low: f64,
    close: f64,
    volume: f64,
    trades: u64,
}

/// The same candle while the matcher maintains it. Prices stay in cents and
/// volume stays in tenths until `view` prepares the JSON response.
#[derive(Debug, Clone)]
struct CandleBucket {
    start: u64,
    open_cents: i64,
    high_cents: i64,
    low_cents: i64,
    close_cents: i64,
    volume_tenths: i64,
    trades: u64,
}

impl CandleBucket {
    fn view(&self) -> Candle {
        Candle {
            start: self.start,
            open: cents_to_f64(self.open_cents),
            high: cents_to_f64(self.high_cents),
            low: cents_to_f64(self.low_cents),
            close: cents_to_f64(self.close_cents),
            volume: tenths_to_f64(self.volume_tenths),
            trades: self.trades,
        }
    }
}

/// The most candles one maintained window and one `/candles` response holds.
///
/// The cap bounds both retained memory and JSON response size. More importantly,
/// a read never walks the trade table: its cost is the number of rows returned,
/// whether the run has one trade or millions.
const MAX_CANDLES: usize = 1000;

/// The previous backwards builder, retained as a test oracle for the bounded
/// forward projection below.
///
/// It works backwards because that matches the question. A chart wants the last
/// n buckets, and no trade older than those can change them. Working forwards
/// meant reading every trade of the run to answer. That was free while every
/// trade was in memory, and it is not free now that the older ones are rows in a
/// table.
///
/// `finish` puts the buckets that hold no trade back in, so the answer is one
/// run of buckets with no hole in it. An empty bucket carries the close of the
/// bucket before it as its open, high, low and close, and 0 for volume and
/// trades. That is the price the market stood at while nobody traded.
///
/// The page did this itself before, in a function named `fillGaps`. The server
/// does it because the server is the side that knows which buckets are empty:
/// the page could only guess at the ones below the oldest bucket it received,
/// and it could not tell "no trades here" from "you asked for too few".
///
/// Trades must arrive newest first, which is trade id going down. Inside one
/// symbol a timestamp never goes down as messages arrive, so a trade id going
/// down is time going down.
///
/// `interval_ms` must be greater than zero. The handler refuses the request
/// before it builds anything when the value is zero.
#[cfg(test)]
struct CandleTail {
    /// The buckets that hold a trade, newest first. `finish` turns the list
    /// around and puts the empty buckets between them.
    candles: Vec<Candle>,
    /// The bucket of the newest trade seen. The answer ends at this bucket.
    /// `None` until the first trade arrives.
    newest: Option<u64>,
    /// The price of the newest trade below the answer's range.
    ///
    /// `Some` means the walk stopped because it reached past the range, so the
    /// range is full and the answer starts `n` buckets back. Any empty bucket
    /// at the start of the range stood at this price. `None` means the walk
    /// reached the first trade of the run, so there is no older price and the
    /// answer starts at the oldest bucket that holds a trade.
    below: Option<f64>,
    interval_ms: u64,
    n: usize,
}

#[cfg(test)]
impl CandleTail {
    fn new(interval_ms: u64, n: usize) -> Self {
        assert!(
            interval_ms > 0,
            "candle interval is validated by the caller"
        );
        CandleTail {
            candles: Vec::new(),
            newest: None,
            below: None,
            interval_ms,
            n,
        }
    }

    /// Adds one trade. Answers false once no older trade can change the answer,
    /// so the caller stops reading.
    fn push(&mut self, timestamp: u64, price: f64, quantity: f64) -> bool {
        if self.n == 0 {
            return false;
        }
        let bucket = timestamp - (timestamp % self.interval_ms);
        let newest = *self.newest.get_or_insert(bucket);
        // How far back this bucket is, counting both ends. The newest bucket is
        // 1. A bucket past `n` is older than the range the answer covers, so
        // the walk stops and keeps the price for the empty buckets at the start
        // of the range.
        if (newest - bucket) / self.interval_ms + 1 > self.n as u64 {
            self.below = Some(price);
            return false;
        }
        let qty_tenths = (quantity * 10.0).round() as i64;
        match self.candles.last_mut() {
            Some(c) if c.start == bucket => {
                c.high = c.high.max(price);
                c.low = c.low.min(price);
                // The walk goes backwards, so the oldest trade of a bucket is
                // the last one seen. The oldest trade of a bucket is its first
                // price.
                c.open = price;
                c.volume =
                    tenths_to_f64(((c.volume * 10.0).round() as i64).saturating_add(qty_tenths));
                c.trades = c.trades.saturating_add(1);
            }
            _ => {
                self.candles.push(Candle {
                    start: bucket,
                    open: price,
                    high: price,
                    low: price,
                    close: price,
                    volume: tenths_to_f64(qty_tenths),
                    trades: 1,
                });
            }
        }
        true
    }

    /// The candles, oldest first, with no bucket missing. The API serves them in
    /// that order.
    fn finish(mut self) -> Vec<Candle> {
        let Some(newest) = self.newest else {
            return Vec::new();
        };
        self.candles.reverse();
        // Where the answer starts, and the price an empty bucket there stood at.
        //
        // A trade below the range means the range is full, so the answer starts
        // `n` buckets back from the newest one and opens at that trade's price.
        // No trade below the range means the walk reached the first trade of the
        // run, so the answer starts at that trade's own bucket.
        let (start, mut prev_close) = match self.below {
            Some(price) => (
                newest.saturating_sub((self.n as u64 - 1) * self.interval_ms),
                price,
            ),
            None => (self.candles[0].start, self.candles[0].open),
        };
        let mut out = Vec::with_capacity(self.n);
        let mut traded = self.candles.into_iter().peekable();
        let mut bucket = start;
        while bucket <= newest {
            match traded.peek() {
                Some(c) if c.start == bucket => {
                    let c = traded.next().expect("peek said there is one");
                    prev_close = c.close;
                    out.push(c);
                }
                _ => out.push(Candle {
                    start: bucket,
                    open: prev_close,
                    high: prev_close,
                    low: prev_close,
                    close: prev_close,
                    volume: 0.0,
                    trades: 0,
                }),
            }
            bucket += self.interval_ms;
        }
        out
    }
}

/// One continuous, bounded interval for one symbol. Empty buckets are stored,
/// not invented per request, so every read is a slice of at most 1,000 rows.
#[derive(Debug, Default)]
struct CandleWindow {
    rows: VecDeque<CandleBucket>,
}

impl CandleWindow {
    fn flat(start: u64, price_cents: i64) -> CandleBucket {
        CandleBucket {
            start,
            open_cents: price_cents,
            high_cents: price_cents,
            low_cents: price_cents,
            close_cents: price_cents,
            volume_tenths: 0,
            trades: 0,
        }
    }

    /// Records one trade in forward trade order. False means timestamps moved
    /// backwards and the projection can no longer claim to be ordered.
    fn record(
        &mut self,
        timestamp: u64,
        price_cents: i64,
        qty_tenths: i64,
        interval_secs: u64,
    ) -> bool {
        let interval_ms = interval_secs * 1000;
        let bucket = timestamp - timestamp % interval_ms;
        if let Some(last) = self.rows.back_mut() {
            if bucket < last.start {
                return false;
            }
            if bucket == last.start {
                last.high_cents = last.high_cents.max(price_cents);
                last.low_cents = last.low_cents.min(price_cents);
                last.close_cents = price_cents;
                last.volume_tenths = last.volume_tenths.saturating_add(qty_tenths);
                last.trades = last.trades.saturating_add(1);
                return true;
            }

            let prior_close_cents = last.close_cents;
            let widths = (bucket - last.start) / interval_ms;
            if widths >= MAX_CANDLES as u64 {
                self.rows.clear();
                let mut start = bucket - (MAX_CANDLES as u64 - 1) * interval_ms;
                while start < bucket {
                    self.rows.push_back(Self::flat(start, prior_close_cents));
                    start += interval_ms;
                }
            } else {
                let mut start = last.start + interval_ms;
                while start < bucket {
                    self.rows.push_back(Self::flat(start, prior_close_cents));
                    start += interval_ms;
                }
            }
        }
        self.rows.push_back(CandleBucket {
            start: bucket,
            open_cents: price_cents,
            high_cents: price_cents,
            low_cents: price_cents,
            close_cents: price_cents,
            volume_tenths: qty_tenths,
            trades: 1,
        });
        while self.rows.len() > MAX_CANDLES {
            self.rows.pop_front();
        }
        true
    }

    fn newest(&self, n: usize) -> Vec<Candle> {
        self.rows
            .iter()
            .skip(self.rows.len().saturating_sub(n))
            .map(CandleBucket::view)
            .collect()
    }
}

#[derive(Debug)]
struct SymbolCandles {
    last_timestamp: Option<u64>,
    windows: [CandleWindow; CANDLE_INTERVALS.len()],
}

impl Default for SymbolCandles {
    fn default() -> Self {
        Self {
            last_timestamp: None,
            windows: std::array::from_fn(|_| CandleWindow::default()),
        }
    }
}

/// The browser-facing candle projection. `valid` becomes false instead of
/// serving partial history if an invariant the projection relies on is broken.
#[derive(Debug)]
struct CandleCache {
    valid: bool,
    symbols: HashMap<String, SymbolCandles>,
}

impl Default for CandleCache {
    fn default() -> Self {
        Self {
            valid: true,
            symbols: HashMap::new(),
        }
    }
}

impl CandleCache {
    fn invalidate(&mut self) {
        self.valid = false;
        self.symbols.clear();
    }

    fn record(&mut self, symbol_name: &str, timestamp: u64, price_cents: i64, qty_tenths: i64) {
        if !self.valid {
            return;
        }
        // Avoid allocating a copy of the symbol on every replayed trade. A
        // production restart walks millions of rows; only the first trade for a
        // symbol needs to create a key.
        if !self.symbols.contains_key(symbol_name) {
            self.symbols
                .insert(symbol_name.to_string(), SymbolCandles::default());
        }
        let symbol = self
            .symbols
            .get_mut(symbol_name)
            .expect("the symbol was inserted above");
        if symbol
            .last_timestamp
            .is_some_and(|last_timestamp| timestamp < last_timestamp)
        {
            self.invalidate();
            return;
        }
        symbol.last_timestamp = Some(timestamp);
        if symbol
            .windows
            .iter_mut()
            .zip(CANDLE_INTERVALS)
            .any(|(window, interval)| !window.record(timestamp, price_cents, qty_tenths, interval))
        {
            self.invalidate();
        }
    }

    fn newest(&self, symbol: &str, interval: u64, n: usize) -> Option<Vec<Candle>> {
        if !self.valid {
            return None;
        }
        let at = CANDLE_INTERVALS
            .iter()
            .position(|candidate| *candidate == interval)?;
        Some(
            self.symbols
                .get(symbol)
                .map_or_else(Vec::new, |candles| candles.windows[at].newest(n)),
        )
    }
}

/// Answers GET /candles with the candles for one symbol, oldest first.
///
/// The answer is one run of buckets with no hole in it. `n` buckets cover
/// `n * interval` seconds, and a bucket that holds no trade is in the answer
/// with volume 0. A chart can draw the answer straight onto a time axis.
///
/// The handler takes a slice of the projection built while trades are already
/// being applied. Its cost is bounded by the response size and does not change
/// when the durable trade record grows.
async fn get_candles(
    State(state): State<ApiState>,
    Query(params): Query<CandlesQuery>,
) -> Result<Json<Vec<Candle>>, (StatusCode, String)> {
    let interval_secs = params.interval.unwrap_or(15);
    if !CANDLE_INTERVALS.contains(&interval_secs) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "interval must be one of 15, 300, 900, 3600 or 14400 seconds, not {}",
                interval_secs
            ),
        ));
    }
    let n = params.n.unwrap_or(150).min(MAX_CANDLES);
    let candles = {
        let engine = lock_state(&state.engine);
        if !engine.symbols.ever_listed(&params.symbol) {
            return Err(unlisted(&params.symbol));
        }
        engine
            .candle_cache
            .newest(&params.symbol, interval_secs, n)
            .ok_or_else(|| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the candle projection is unavailable; restart the matcher to rebuild it"
                        .to_string(),
                )
            })?
    };
    Ok(Json(candles))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::OPERATOR_ACCOUNT;
    use std::path::Path;

    fn new_order(id: OrderId, side: Side, price: f64, quantity: f64) -> OrderMessage {
        OrderMessage::New {
            id,
            timestamp: id * 1000,
            account: 1,
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

    /// Messages as a poll really delivers them. The test writes them into one
    /// `/messages.ndjson` body the way the sequencer writes it. The test then
    /// reads them back the way the poller reads them. A test that handed
    /// `apply_batch` structs it had built itself would test a path the engine
    /// no longer has.
    fn served(messages: &[OrderMessage]) -> Vec<ReadMessage<OrderMessage>> {
        let mut body = Vec::new();
        for msg in messages {
            body.extend_from_slice(&logchain::canonical_bytes(msg));
            body.push(b'\n');
        }
        wire::read_ndjson(&body).expect("the feed serves one message per line")
    }

    /// Like `new_order`, but from a named account. A test can then say which
    /// account a fill belongs to.
    fn new_order_for(
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

    /// A buy of one unit for a named symbol. Some tests care only which symbol
    /// an order names, and not what the order does to a book.
    fn order_for_symbol(id: OrderId, symbol: &str) -> OrderMessage {
        OrderMessage::New {
            id,
            timestamp: id * 1000,
            account: 7,
            symbol: symbol.to_string(),
            side: Side::Buy,
            price: 1.0,
            quantity: 1.0,
            nonce: None,
            order_type: Default::default(),
            time_in_force: Default::default(),
            post_only: false,
        }
    }

    /// Like `new_order_for`, but naming its own symbol.
    fn order_on(
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

    /// The key that signs every operator message in these tests. One key,
    /// because a log has one operator. The first message of a history names
    /// the key. The exchange checks every message after it against that key.
    fn operator_key() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    /// The session those signatures cover. An engine in these tests has never
    /// spoken to a sequencer, so the engine announces no session.
    /// `operator_signed` then reads an empty session. `take_pending` reads the
    /// same field in the same way.
    const TEST_SESSION: &str = "";

    /// Signs an operator message as the operator of this log.
    ///
    /// ENGINE.md section 3.1: the exchange ignores a message that does not
    /// verify under the key the log named. An unsigned fixture would therefore
    /// list no symbol, and every test below it would read an empty registry.
    fn signed_by_operator(key: &SigningKey, message: OrderMessage) -> OrderMessage {
        operator::signed_as(key, TEST_SESSION, message)
    }

    /// The nonce one operator message carries. It is 32 lowercase hex
    /// characters, one value per message id. The signed statement covers the
    /// nonce.
    fn operator_nonce(id: OrderId) -> Option<String> {
        Some(format!("{:032x}", id))
    }

    /// A `ListSymbol` message on the steps the sequencer has always published.
    fn list_symbol(id: OrderId, symbol: &str) -> OrderMessage {
        list_symbol_on(id, symbol, 0.01, 0.1)
    }

    /// A `ListSymbol` message naming its own steps.
    fn list_symbol_on(
        id: OrderId,
        symbol: &str,
        price_step: f64,
        quantity_step: f64,
    ) -> OrderMessage {
        signed_by_operator(
            &operator_key(),
            OrderMessage::ListSymbol {
                id,
                timestamp: id * 1000,
                account: OPERATOR_ACCOUNT,
                symbol: symbol.to_string(),
                price_step,
                quantity_step,
                nonce: operator_nonce(id),
                public_key: String::new(),
                signature: String::new(),
            },
        )
    }

    /// A `DelistSymbol` message.
    fn delist_symbol(id: OrderId, symbol: &str) -> OrderMessage {
        signed_by_operator(
            &operator_key(),
            OrderMessage::DelistSymbol {
                id,
                timestamp: id * 1000,
                account: OPERATOR_ACCOUNT,
                symbol: symbol.to_string(),
                nonce: operator_nonce(id),
                public_key: String::new(),
                signature: String::new(),
            },
        )
    }

    /// What a visitor's page asks for after it has placed an order. The page
    /// asks which of this account's orders are still in the book and waiting.
    /// The page then shows a cancel button only for an order a cancel can
    /// still reach.
    #[tokio::test]
    async fn open_orders_are_this_account_s_and_disappear_when_they_stop_resting() {
        let mut engine = MatcherState::with_default_listings();
        // Two accounts wait on the same side and at the same price. The filter
        // must then do real work instead of reading an empty book.
        engine
            .apply_message(&new_order_for(1, 5000000, Side::Buy, 100.0, 5.0))
            .unwrap();
        engine
            .apply_message(&new_order_for(2, 7, Side::Buy, 100.0, 3.0))
            .unwrap();
        engine
            .apply_message(&new_order_for(3, 5000000, Side::Sell, 101.0, 2.0))
            .unwrap();
        let engine = Arc::new(Mutex::new(engine));

        let mine = get_open_orders(
            State(Arc::clone(&engine)),
            Query(OpenOrdersQuery { account: 5000000 }),
        )
        .await
        .0;
        assert_eq!(
            mine.iter().map(|o| o.id).collect::<Vec<_>>(),
            vec![1, 3],
            "only this account's orders, oldest first"
        );
        assert_eq!(mine[0].side, Side::Buy);
        assert_eq!(mine[0].price, 100.0);
        assert_eq!(mine[0].quantity, 5.0);
        assert_eq!(mine[1].side, Side::Sell);

        // A part fill leaves the rest of the order waiting in the book. A
        // cancel would take out that rest, so the page must show it.
        lock_state(&engine)
            .apply_message(&new_order_for(4, 9, Side::Sell, 100.0, 4.0))
            .unwrap();
        let after_fill = get_open_orders(
            State(Arc::clone(&engine)),
            Query(OpenOrdersQuery { account: 5000000 }),
        )
        .await
        .0;
        assert_eq!(after_fill.len(), 2);
        assert_eq!(
            after_fill[0].quantity, 1.0,
            "5 rested, 4 filled, 1 is still cancellable"
        );

        // After the cancel, order 1 is gone from the list. It does not stay as
        // a button that does nothing.
        lock_state(&engine)
            .apply_message(&cancel_from(5, 5000000, 1))
            .unwrap();
        let after_cancel = get_open_orders(
            State(Arc::clone(&engine)),
            Query(OpenOrdersQuery { account: 5000000 }),
        )
        .await
        .0;
        assert_eq!(
            after_cancel.iter().map(|o| o.id).collect::<Vec<_>>(),
            vec![3]
        );

        // An account that has never traded gets an empty list, not somebody
        // else's orders.
        let stranger = get_open_orders(
            State(Arc::clone(&engine)),
            Query(OpenOrdersQuery { account: 4242 }),
        )
        .await
        .0;
        assert!(stranger.is_empty());
    }

    /// The page cannot guess where to send an order. The sequencer and the
    /// separate service sit on a different address in every deployment. Only
    /// the operator knows that address.
    #[tokio::test]
    async fn the_ui_is_told_where_to_submit() {
        let engine = Arc::new(Mutex::new(MatcherState::with_default_listings()));
        let mut state = api(&engine);
        state.public_feed_url = "https://exchange.example.com/feed".to_string();
        state.public_inbox_url = Some("https://exchange.example.com/inbox".to_string());
        let config = get_config(State(state)).await.0;
        assert_eq!(config.feed_url, "https://exchange.example.com/feed");
        assert_eq!(
            config.inbox_url.as_deref(),
            Some("https://exchange.example.com/inbox")
        );
    }

    /// An operator that runs no separate service is told so by name. The page
    /// must not fall back to a guessed address. A link to a port that holds
    /// nothing looks to a visitor like the second way to send an order is
    /// broken.
    #[tokio::test]
    async fn no_inbox_means_the_page_is_offered_no_route() {
        let engine = Arc::new(Mutex::new(MatcherState::with_default_listings()));
        let config = get_config(State(api(&engine))).await.0;
        assert_eq!(config.inbox_url, None);
    }

    fn position<'a>(state: &'a MatcherState, account: AccountId) -> &'a Position {
        state
            .positions
            .get(&(account, "ETH-USDC".to_string()))
            .expect("account has no position in ETH-USDC")
    }

    fn cancel(id: OrderId, target_id: OrderId) -> OrderMessage {
        cancel_from(id, 1, target_id)
    }

    /// A cancel sent by a named account, for checking who may cancel what.
    fn cancel_from(id: OrderId, account: AccountId, target_id: OrderId) -> OrderMessage {
        OrderMessage::Cancel {
            id,
            timestamp: id * 1000,
            account,
            target_id,
            nonce: None,
        }
    }

    /// How many orders wait on one side of ETH-USDC. A symbol with nothing
    /// waiting on either side has no book at all, because `prune_book` drops
    /// the book. That case is zero orders, not a missing answer.
    fn open_orders(state: &MatcherState, side: Side) -> usize {
        state.books.get("ETH-USDC").map_or(0, |book| {
            let map = match side {
                Side::Buy => &book.bids,
                Side::Sell => &book.asks,
            };
            map.values().map(|l| l.len()).sum()
        })
    }

    // Step 4: the self-trade check. ENGINE.md section 4.1 names the rule:
    // cancel newest. The rule arrives as an `EngineRule` message that names
    // rule set 2. A replay of the messages before that message still
    // self-trades.

    /// An `EngineRule` message. This message turns a rule set on.
    fn engine_rule(id: OrderId, version: u32) -> OrderMessage {
        signed_by_operator(
            &operator_key(),
            OrderMessage::EngineRule {
                id,
                timestamp: id * 1000,
                account: OPERATOR_ACCOUNT,
                version,
                nonce: operator_nonce(id),
                public_key: String::new(),
                signature: String::new(),
            },
        )
    }

    /// An engine told to match under rule set 2, with nothing else in its
    /// history. The `EngineRule` is message 1. ENGINE.md section 3 says the
    /// log opens that way.
    ///
    /// The symbols are listed without a message, because these tests are about
    /// the self-trade rule and not about listings. See
    /// `with_default_listings`. A real log carries both the listing and the
    /// `EngineRule`. Only the `EngineRule` is under test here.
    fn under_rule_set_2() -> MatcherState {
        let mut engine = MatcherState::with_default_listings();
        engine
            .apply_message(&engine_rule(1, 2))
            .expect("the first message of the log");
        engine
    }

    /// Cancel newest, in one sentence. The exchange refuses the arriving
    /// order, and leaves the waiting order untouched.
    #[test]
    fn an_account_that_would_trade_with_itself_has_the_arriving_order_refused() {
        let mut engine = under_rule_set_2();
        engine
            .apply_message(&new_order_for(2, 7, Side::Buy, 100.0, 5.0))
            .expect("in feed order");
        // Account 7 now sells into its own buy order.
        engine
            .apply_message(&new_order_for(3, 7, Side::Sell, 100.0, 4.0))
            .expect("read, then refused");

        assert_eq!(engine.trades_total, 0, "no fill happened");
        assert_eq!(engine.orders_ignored, 1);
        assert_eq!(
            engine.orders_ignored_by_kind.get("self_trade").copied(),
            Some(1),
            "the refusal is counted as a self-trade and not as something else"
        );
        // The waiting order is exactly as it was: same id, same account, same
        // quantity. It is not reduced, and it does not move to the back of its
        // price level.
        assert_eq!(
            engine.open_order(2),
            Some(("ETH-USDC", Side::Buy, to_cents(100.0), to_tenths(5.0)))
        );
        assert_eq!(
            engine.open_order(3),
            None,
            "the arriving order never rested"
        );
        assert_eq!(engine.position_of(7, "ETH-USDC"), (0, 0, 0));
    }

    /// The same order, from another account, is an ordinary fill. Without this
    /// test, the test above would also pass on an engine that refused every
    /// order.
    #[test]
    fn the_same_order_from_another_account_fills_normally() {
        let mut engine = under_rule_set_2();
        engine
            .apply_message(&new_order_for(2, 7, Side::Buy, 100.0, 5.0))
            .expect("in feed order");
        engine
            .apply_message(&new_order_for(3, 8, Side::Sell, 100.0, 4.0))
            .expect("in feed order");

        assert_eq!(engine.trades_total, 1);
        assert_eq!(engine.orders_ignored, 0);
        assert!(engine.orders_ignored_by_kind.is_empty());
        assert_eq!(
            engine.open_order(2),
            Some(("ETH-USDC", Side::Buy, to_cents(100.0), to_tenths(1.0))),
            "5.0 rested, 4.0 filled, 1.0 is left"
        );
    }

    /// Cancel oldest is the rule the exchange does not use. Under cancel
    /// oldest the exchange takes the waiting order off the book. The arriving
    /// order then trades against whatever order was behind it. That is the
    /// attack the rule exists to stop: an account removes its own order to
    /// reach the orders behind it.
    ///
    /// So the book holds another order behind the account's own order. The
    /// test names what each rule would leave. Cancel newest leaves both
    /// waiting orders and no trade. Cancel oldest leaves the second order
    /// filled.
    #[test]
    fn the_resting_order_is_the_survivor_and_not_the_arriving_one() {
        let mut engine = under_rule_set_2();
        // Account 7's own buy order, first in line at 100.
        engine
            .apply_message(&new_order_for(2, 7, Side::Buy, 100.0, 5.0))
            .expect("in feed order");
        // Another account's buy order behind it, at the same price.
        engine
            .apply_message(&new_order_for(3, 9, Side::Buy, 100.0, 5.0))
            .expect("in feed order");
        // Account 7 sells 5.0 at 100. Cancel oldest would remove order 2 and
        // fill this sell against order 3.
        engine
            .apply_message(&new_order_for(4, 7, Side::Sell, 100.0, 5.0))
            .expect("read, then refused");

        assert_eq!(engine.trades_total, 0, "cancel oldest would print a trade");
        assert_eq!(
            engine.open_order(2),
            Some(("ETH-USDC", Side::Buy, to_cents(100.0), to_tenths(5.0))),
            "the account's own resting order is the survivor"
        );
        assert_eq!(
            engine.open_order(3),
            Some(("ETH-USDC", Side::Buy, to_cents(100.0), to_tenths(5.0))),
            "the liquidity behind it was not reached"
        );
        assert_eq!(open_orders(&engine, Side::Buy), 2);
    }

    /// The other decision this step makes. A price the arriving order does not
    /// reach is not the arriving order's business. It does not matter how much
    /// of the same account's own quantity waits at that price.
    #[test]
    fn an_own_order_at_a_price_the_arrival_does_not_cross_is_not_a_self_trade() {
        let mut engine = under_rule_set_2();
        // Account 7 sells at 101. A buy with a limit of 100 does not reach 101.
        engine
            .apply_message(&new_order_for(2, 7, Side::Sell, 101.0, 5.0))
            .expect("in feed order");
        engine
            .apply_message(&new_order_for(3, 7, Side::Buy, 100.0, 5.0))
            .expect("accepted");

        assert_eq!(
            engine.orders_ignored, 0,
            "101 is not crossed by a bid of 100"
        );
        assert_eq!(
            engine.open_order(3),
            Some(("ETH-USDC", Side::Buy, to_cents(100.0), to_tenths(5.0))),
            "the arriving order rested, as any order that crosses nothing does"
        );
    }

    /// One log, one replay, and the rule turns on at the message that names it.
    ///
    /// This is the property the whole `EngineRule` design exists for. The same
    /// messages produce the same answer for everyone. The messages before the
    /// rule still self-trade. Turning the rule on in plain code instead would
    /// replay the 1,008 self-trades already in the live log differently. Every
    /// signed claim and every anchor over those messages would then stop
    /// verifying.
    #[test]
    fn a_self_trade_happens_before_the_engine_rule_message_and_not_after() {
        let mut engine = MatcherState::with_default_listings();
        // Before the rule: account 7 matches itself and the trade happens.
        engine
            .apply_message(&new_order_for(1, 7, Side::Buy, 100.0, 5.0))
            .expect("in feed order");
        engine
            .apply_message(&new_order_for(2, 7, Side::Sell, 100.0, 5.0))
            .expect("in feed order");
        assert_eq!(
            engine.trades_total, 1,
            "rule set 1 lets an account match itself"
        );
        let self_traded = engine.trades().last().expect("a trade");
        assert_eq!(self_traded.maker_account, self_traded.taker_account);

        // The rule arrives.
        engine
            .apply_message(&engine_rule(3, 2))
            .expect("in feed order");
        assert_eq!(
            engine.kinds_not_acted_on(),
            0,
            "this build acts on rule set 2 rather than counting it as unread"
        );

        // After the rule: the exchange refuses the same pair of orders.
        engine
            .apply_message(&new_order_for(4, 7, Side::Buy, 100.0, 5.0))
            .expect("in feed order");
        engine
            .apply_message(&new_order_for(5, 7, Side::Sell, 100.0, 5.0))
            .expect("read, then refused");
        assert_eq!(engine.trades_total, 1, "no second self-trade");
        assert_eq!(engine.orders_ignored, 1);
        assert_eq!(
            engine.open_order(4),
            Some(("ETH-USDC", Side::Buy, to_cents(100.0), to_tenths(5.0)))
        );
    }

    /// The regression that matters. A history with no `EngineRule` message in
    /// it reaches the books and positions it always reached.
    ///
    /// The expected value is written out as hex. The test does not compare it
    /// against another engine in this build, because a root computed twice by
    /// the same code agrees with itself even when both values are wrong. The
    /// hex came from the build before the self-trade rule existed.
    ///
    /// The test compares through `state_root_v2`. That function is the old
    /// build's encoding of the books and the positions and nothing else. The
    /// full root moved when the symbol registry joined it. That move was
    /// deliberate: a delisted symbol and a listed symbol over the same books
    /// lead to different results, so they must not share a root. What must not
    /// move is what the same three orders did, and this test holds that.
    #[test]
    fn a_history_with_no_engine_rule_message_hashes_to_the_root_it_always_did() {
        let mut engine = MatcherState::with_default_listings();
        for msg in [
            new_order_for(1, 7, Side::Buy, 100.0, 5.0),
            new_order_for(2, 8, Side::Sell, 101.0, 3.0),
            new_order_for(3, 9, Side::Sell, 100.0, 2.0),
        ] {
            engine.apply_message(&msg).expect("in feed order");
        }
        assert_eq!(
            logchain::to_hex(&state_root_v2(&engine)),
            "b50c373875c3642727f6faf3fab674f42e106985588ba736c5ff8965ca073c42",
            "the rule set or the registry changed what a history that names \
             neither of them executes to"
        );

        // The same history with an explicit rule set 1 message in it hashes to
        // the same books. The genesis log opens with that message.
        let mut named = MatcherState::with_default_listings();
        for msg in [
            new_order_for(1, 7, Side::Buy, 100.0, 5.0),
            new_order_for(2, 8, Side::Sell, 101.0, 3.0),
            new_order_for(3, 9, Side::Sell, 100.0, 2.0),
            engine_rule(4, 1),
        ] {
            named.apply_message(&msg).expect("in feed order");
        }
        let mut cursor_only = MatcherState::with_default_listings();
        for msg in [
            new_order_for(1, 7, Side::Buy, 100.0, 5.0),
            new_order_for(2, 8, Side::Sell, 101.0, 3.0),
            new_order_for(3, 9, Side::Sell, 100.0, 2.0),
            new_order_for(4, 7, Side::Buy, 1.0, 1.0),
        ] {
            cursor_only.apply_message(&msg).expect("in feed order");
        }
        // The fourth message of the control engine rests, so that message is
        // not the comparison. It is here only to move the cursor, because
        // `state_root` covers `last_seen`.
        assert_ne!(named.state_root(), cursor_only.state_root());
        assert_eq!(named.rules, RuleSet::GENESIS);
    }

    /// Rule set 2 is part of the state root. Two engines that hold the same
    /// books under different rule sets match the same future messages
    /// differently. Equal roots are supposed to mean the two engines behave
    /// the same way, so the rule set must be in the root.
    #[test]
    fn the_rule_set_is_part_of_the_state_root() {
        let history = |version: u32| {
            let mut engine = MatcherState::new();
            for msg in [
                new_order_for(1, 7, Side::Buy, 100.0, 5.0),
                new_order_for(2, 8, Side::Sell, 101.0, 3.0),
                engine_rule(3, version),
            ] {
                engine.apply_message(&msg).expect("in feed order");
            }
            engine
        };
        let one = history(1);
        let two = history(2);
        assert_eq!(
            one.books.len(),
            two.books.len(),
            "same books, so only the rule set can tell the roots apart"
        );
        assert_eq!(one.last_seen, two.last_seen);
        assert_ne!(
            logchain::to_hex(&one.state_root()),
            logchain::to_hex(&two.state_root()),
            "two engines that match future messages differently must not share a root"
        );
    }

    /// The exchange counts a rule set this build does not know. It does not
    /// guess what the rule set means. The exchange serves books to a browser
    /// and must not stop. So it reports that its books are not the books a
    /// newer build would hold. `verify.rs` makes the opposite choice for the
    /// opposite reason.
    #[test]
    fn an_engine_rule_this_build_cannot_execute_is_counted_and_changes_no_rule() {
        let mut engine = under_rule_set_2();
        engine
            .apply_message(&engine_rule(2, 9))
            .expect("read, not executed");
        assert_eq!(engine.kinds_not_acted_on(), 1);
        assert_eq!(engine.rules, RuleSet::NEWEST, "it kept the rules it knows");

        // The exchange goes on refusing self-trades under the rules it knows.
        engine
            .apply_message(&new_order_for(3, 7, Side::Buy, 100.0, 5.0))
            .expect("in feed order");
        engine
            .apply_message(&new_order_for(4, 7, Side::Sell, 100.0, 5.0))
            .expect("read, then refused");
        assert_eq!(engine.trades_total, 0);
        assert_eq!(engine.orders_ignored, 1);
    }

    /// A refusal after step 1 must drop the book if that book is now empty.
    /// `state_root` asserts that no empty book is in the map. That assert is
    /// compiled out of the release build. So an empty book left in the map
    /// would make a restored engine hash differently from a live one, and the
    /// run would end for good.
    ///
    /// A self-trade refusal cannot leave an empty book. It fires only when an
    /// order of the same account waits in the book, and such a book holds at
    /// least one order. This test holds the stronger statement: the whole map
    /// is left as it was, and not only free of empty books.
    #[test]
    fn a_refused_self_trade_leaves_the_book_exactly_as_it_was() {
        let mut engine = under_rule_set_2();
        engine
            .apply_message(&new_order_for(2, 7, Side::Buy, 100.0, 5.0))
            .expect("in feed order");
        engine
            .apply_message(&new_order_for(3, 9, Side::Sell, 102.0, 4.0))
            .expect("in feed order");
        let before = engine.state_root();
        let books_before = engine.books.len();

        engine
            .apply_message(&new_order_for(4, 7, Side::Sell, 100.0, 4.0))
            .expect("read, then refused");

        assert!(
            !engine
                .books
                .values()
                .any(|book| book.bids.is_empty() && book.asks.is_empty()),
            "a refusal left an empty book in the map"
        );
        assert_eq!(engine.books.len(), books_before);
        // The root moves only because the cursor moved. Setting the cursor
        // back is the way to show that nothing but the message number
        // changed. There is no second engine here to compare against.
        let after = engine.state_root();
        assert_ne!(after, before, "the cursor moved");
        engine.last_seen = 3;
        assert_eq!(
            logchain::to_hex(&engine.state_root()),
            logchain::to_hex(&before),
            "the refusal changed a book, a position, or the rule set"
        );

        // A refusal on a symbol whose book this message created is the path
        // that really can leave an empty book. Step 4 cannot reach that path,
        // because a book that did not exist holds no order of the account. So
        // an unlisted symbol is used instead.
        engine.last_seen = 4;
        let unlisted = match new_order_for(5, 7, Side::Buy, 100.0, 5.0) {
            OrderMessage::New {
                id,
                timestamp,
                account,
                side,
                price,
                quantity,
                ..
            } => OrderMessage::New {
                id,
                timestamp,
                account,
                symbol: "NOT-LISTED".to_string(),
                side,
                price,
                quantity,
                nonce: None,
                order_type: Default::default(),
                time_in_force: Default::default(),
                post_only: false,
            },
            other => other,
        };
        engine.apply_message(&unlisted).expect("read, then refused");
        assert!(!engine.books.contains_key("NOT-LISTED"));
    }

    /// ENGINE.md section 4.1: the exchange must tell a refused order why it
    /// was refused. Section 4.0 says one counter is not enough. A submitter
    /// that reads `/market` cannot tell an unlisted symbol from a self-trade
    /// refusal when both add to the same number.
    ///
    /// So `orders_ignored` stays the total, and `/market` also reports the
    /// count for each reason.
    #[tokio::test]
    async fn a_self_trade_refusal_reads_differently_from_an_unlisted_symbol() {
        let mut engine = under_rule_set_2();
        engine
            .apply_message(&new_order_for(2, 7, Side::Buy, 100.0, 5.0))
            .expect("in feed order");
        engine
            .apply_message(&new_order_for(3, 7, Side::Sell, 100.0, 4.0))
            .expect("refused: self-trade");
        let unlisted = match new_order_for(4, 7, Side::Buy, 100.0, 5.0) {
            OrderMessage::New {
                id,
                timestamp,
                account,
                side,
                price,
                quantity,
                ..
            } => OrderMessage::New {
                id,
                timestamp,
                account,
                symbol: "NOT-LISTED".to_string(),
                side,
                price,
                quantity,
                nonce: None,
                order_type: Default::default(),
                time_in_force: Default::default(),
                post_only: false,
            },
            other => other,
        };
        engine.apply_message(&unlisted).expect("refused: unlisted");
        engine
            .apply_message(&new_order_for(5, 7, Side::Buy, 100.253, 5.0))
            .expect("refused: off the price step");

        let market = get_market(State(Arc::new(Mutex::new(engine)))).await.0;
        assert_eq!(market.orders_ignored, 3, "the total still counts all three");
        assert_eq!(
            market.orders_ignored_by_reason,
            BTreeMap::from([
                ("self_trade".to_string(), 1),
                ("unlisted_symbol".to_string(), 1),
                ("off_grid".to_string(), 1),
            ]),
            "three refusals a submitter can tell apart"
        );
        assert_eq!(
            market.orders_ignored_by_reason.values().sum::<u64>(),
            market.orders_ignored,
            "the split has to add up to the total, or one of them is lying"
        );
        assert_eq!(market.rule_set, 2);
    }

    /// `/market` names the commit the running binary was built from.
    ///
    /// Without that field, an operator cannot read back which source a
    /// deployment serves. The field must never be empty. A build that does not
    /// know its commit says `unknown`, and that is an answer. An empty string
    /// looks like a broken field.
    #[tokio::test]
    async fn market_names_the_commit_this_binary_was_built_from() {
        let market = get_market(State(Arc::new(Mutex::new(MatcherState::new()))))
            .await
            .0;
        assert!(
            !market.build_commit.is_empty(),
            "an empty build_commit tells a reader nothing"
        );
        assert_eq!(market.build_commit, BUILD_COMMIT);

        // This test binary is built the way a local build is, unless the build
        // argument was set for the test too. The fallback holds in both cases.
        let named = option_env!("BUILD_COMMIT").filter(|commit| !commit.is_empty());
        match named {
            None => assert_eq!(
                market.build_commit, BUILD_COMMIT_UNKNOWN,
                "a build with no commit argument reports the fallback word"
            ),
            Some(commit) => assert_eq!(
                market.build_commit, commit,
                "a build with a commit argument reports that commit"
            ),
        }
    }

    /// `/market` answers two different questions about rule sets. An operator
    /// needs both answers.
    ///
    /// `rule_set` is the rule set the log has put this engine in.
    /// `newest_rule_set` is the newest rule set the build can run. On a fresh
    /// log the first is 1 and the second is 2. A reader that takes one for the
    /// other reads the wrong number. `--engine-rule` reads `newest_rule_set`.
    /// Publishing rule set 2 to a build that runs rule set 2 is the normal
    /// upgrade, and it must not warn.
    ///
    /// The test checks the JSON key as a string, because `--engine-rule` looks
    /// the key up by name over HTTP. A renamed field makes the command read
    /// nothing. That is the failure this test catches.
    #[tokio::test]
    async fn the_market_reports_the_newest_rule_set_apart_from_the_running_one() {
        let fresh = MatcherState::with_default_listings();
        let market = get_market(State(Arc::new(Mutex::new(fresh)))).await.0;
        assert_eq!(market.rule_set, 1, "no EngineRule message in this log");
        assert_eq!(
            market.newest_rule_set,
            RuleSet::NEWEST.version(),
            "the newest rule set this build runs"
        );
        assert_ne!(
            market.rule_set, market.newest_rule_set,
            "the two answers differ, so they cannot be one field"
        );

        let body = serde_json::to_value(&market).expect("the response serializes");
        assert_eq!(
            body.get("newest_rule_set").and_then(|set| set.as_u64()),
            Some(u64::from(RuleSet::NEWEST.version())),
            "the key --engine-rule reads"
        );

        // Once the log names rule set 2, the two answers agree. That is the
        // state of an upgraded exchange.
        let upgraded = get_market(State(Arc::new(Mutex::new(under_rule_set_2()))))
            .await
            .0;
        assert_eq!(upgraded.rule_set, upgraded.newest_rule_set);
    }

    /// Calls `/book` the way the router calls it. The test uses the handler,
    /// the state the handler locks, and the query the router parsed. Nothing
    /// sits in between.
    async fn book_of(
        engine: MatcherState,
        symbol: &str,
        depth: Option<usize>,
    ) -> Result<BookResponse, (StatusCode, String)> {
        get_book(
            State(Arc::new(Mutex::new(engine))),
            Query(BookQuery {
                symbol: symbol.to_string(),
                depth,
            }),
        )
        .await
        .map(|json| json.0)
    }

    /// An exchange with orders on one side only. It holds `levels` buy prices,
    /// one order at each price, one price step apart. The best price is
    /// 100.00.
    ///
    /// Every order is a limit order, and nothing waits on the sell side. So no
    /// order matches, and every order comes to rest in the book. Step 1 takes
    /// the prices, because each price is a whole number of the 0.01 price
    /// step. Step 3 bounds a market order against the reference price and
    /// leaves a limit order alone, so step 3 takes these orders too. The test
    /// asserts that every order rested, rather than trusting it.
    fn one_deep_side(levels: usize) -> MatcherState {
        let mut engine = MatcherState::with_default_listings();
        for step in 0..levels {
            let price = cents_to_f64(10_000 - step as i64);
            engine
                .apply_message(&new_order_for(
                    step as OrderId + 1,
                    7,
                    Side::Buy,
                    price,
                    1.0,
                ))
                .expect("in feed order");
        }
        assert_eq!(engine.orders_ignored(), 0, "every order rests");
        engine
    }

    /// One request may ask for at most `MAX_BOOK_DEPTH` price levels on each
    /// side.
    ///
    /// The book here holds more levels than the cap, and the request asks for
    /// every level. The exchange answers with the cap. The levels it keeps are
    /// the ones with the best prices.
    #[tokio::test]
    async fn a_book_deeper_than_the_cap_answers_with_the_cap() {
        let engine = one_deep_side(MAX_BOOK_DEPTH + 5);
        let book = book_of(engine, "ETH-USDC", Some(usize::MAX))
            .await
            .expect("ETH-USDC is listed");

        assert_eq!(
            book.bids.len(),
            MAX_BOOK_DEPTH,
            "a request asked for every level and the cap held"
        );
        assert!(book.asks.is_empty(), "nothing rests on the other side");
        assert_eq!(
            book.bids[0].price, 100.0,
            "the cap drops the levels far from the spread, not the best ones"
        );
        assert_eq!(
            book.bids[MAX_BOOK_DEPTH - 1].price,
            cents_to_f64(10_000 - (MAX_BOOK_DEPTH as i64 - 1)),
            "the last level kept is one cap of price steps below the best bid"
        );
    }

    /// Asks `get_positions` the way the router does.
    async fn positions_of(
        engine: &Arc<Mutex<MatcherState>>,
        since: Option<AccountId>,
        n: Option<usize>,
    ) -> Vec<AccountView> {
        get_positions(
            State(Arc::clone(engine)),
            Query(PositionsQuery {
                account: None,
                since,
                n,
                totals: None,
            }),
        )
        .await
        .0
    }

    /// An exchange where `traders` accounts each hold a position. The accounts
    /// are numbered from 1 upwards. Account 0 is the other side of every
    /// trade, so the engine holds `traders + 1` accounts.
    ///
    /// Every trade is one unit at 100.00. The accounts then differ only by
    /// number, and a page that drops the wrong accounts is easy to read.
    fn one_position_each(traders: usize) -> MatcherState {
        let mut engine = MatcherState::with_default_listings();
        for trader in 1..=traders {
            let rest = (trader as OrderId - 1) * 2 + 1;
            engine
                .apply_message(&new_order_for(rest, 0, Side::Sell, 100.0, 1.0))
                .expect("in feed order");
            engine
                .apply_message(&new_order_for(
                    rest + 1,
                    trader as AccountId,
                    Side::Buy,
                    100.0,
                    1.0,
                ))
                .expect("in feed order");
        }
        assert_eq!(engine.orders_ignored(), 0, "every order was taken");
        engine
    }

    /// A caller that names no count gets `POSITIONS_PAGE` accounts. It gets
    /// the accounts with the lowest numbers.
    ///
    /// The route served every account before this change. One page is what
    /// stops 600 accounts from costing 397,800 bytes twice a second.
    #[tokio::test]
    async fn positions_answers_one_page_when_no_count_is_asked_for() {
        let engine = Arc::new(Mutex::new(one_position_each(POSITIONS_PAGE + 20)));
        let page = positions_of(&engine, None, None).await;

        assert_eq!(page.len(), POSITIONS_PAGE, "one page, not every account");
        assert_eq!(page[0].account, 0, "the page starts at the lowest account");
        assert_eq!(
            page[POSITIONS_PAGE - 1].account,
            POSITIONS_PAGE as AccountId - 1,
            "and runs to the account one page up from it"
        );
    }

    /// Pages read one after another cover every account exactly once. A page
    /// shorter than the count asked for is the last page.
    ///
    /// The zero-sum check on the page walks these pages. It must see every
    /// account, and no account twice. If it does not, the total it adds up is
    /// not the real total.
    #[tokio::test]
    async fn positions_pages_cover_every_account_exactly_once() {
        let traders = 47;
        let engine = Arc::new(Mutex::new(one_position_each(traders)));
        let mut seen: Vec<AccountId> = Vec::new();
        let mut since = None;
        loop {
            let page = positions_of(&engine, since, Some(10)).await;
            seen.extend(page.iter().map(|a| a.account));
            if page.len() < 10 {
                break;
            }
            since = page.last().map(|a| a.account);
        }

        let every: Vec<AccountId> = (0..=traders as AccountId).collect();
        assert_eq!(seen, every, "every account, in order, none of them twice");
    }

    /// One request may ask for at most `PAGE_LIMIT` accounts. `/claims` and
    /// `/trades-since` answer under the same cap.
    #[tokio::test]
    async fn a_positions_request_for_everything_answers_with_the_cap() {
        let engine = Arc::new(Mutex::new(one_position_each(PAGE_LIMIT + 5)));
        let page = positions_of(&engine, None, Some(usize::MAX)).await;

        assert_eq!(
            page.len(),
            PAGE_LIMIT,
            "a request asked for every account and the cap held"
        );
        assert_eq!(page[0].account, 0, "the cap drops the highest accounts");
    }

    /// Both lists start at the best price: the highest buy price first, the
    /// lowest sell price first. The page draws the two lists towards each
    /// other from there.
    ///
    /// The orders arrive out of price order. A handler that returned them in
    /// arrival order would fail this test.
    #[tokio::test]
    async fn book_levels_come_back_best_price_first_on_both_sides() {
        let mut engine = MatcherState::with_default_listings();
        for (id, side, price) in [
            (1, Side::Buy, 99.0),
            (2, Side::Buy, 100.0),
            (3, Side::Buy, 98.0),
            (4, Side::Sell, 102.0),
            (5, Side::Sell, 101.0),
            (6, Side::Sell, 103.0),
        ] {
            engine
                .apply_message(&new_order_for(id, 7, side, price, 1.0))
                .expect("in feed order");
        }
        assert_eq!(engine.orders_ignored(), 0, "every order rests");

        let book = book_of(engine, "ETH-USDC", Some(3))
            .await
            .expect("ETH-USDC is listed");

        assert_eq!(
            book.bids.iter().map(|l| l.price).collect::<Vec<_>>(),
            vec![100.0, 99.0, 98.0],
            "the highest bid is nearest the spread"
        );
        assert_eq!(
            book.asks.iter().map(|l| l.price).collect::<Vec<_>>(),
            vec![101.0, 102.0, 103.0],
            "the lowest ask is nearest the spread"
        );
        assert_eq!(book.symbol, "ETH-USDC");
    }

    /// The page adds the quantities up in the order this endpoint returns
    /// them. It prints the running sum in its Total column. So the running sum
    /// must grow as the prices move away from the best price. The first total
    /// is the quantity at the best price. The last total is the whole side.
    ///
    /// Each price level holds a different quantity. A list in the other order
    /// gives different totals.
    #[tokio::test]
    async fn book_quantities_add_up_outward_from_the_spread() {
        let mut engine = MatcherState::with_default_listings();
        for (id, side, price, quantity) in [
            (1, Side::Buy, 100.0, 1.0),
            (2, Side::Buy, 99.0, 2.0),
            (3, Side::Buy, 98.0, 4.0),
            (4, Side::Sell, 101.0, 8.0),
            (5, Side::Sell, 102.0, 16.0),
            (6, Side::Sell, 103.0, 32.0),
        ] {
            engine
                .apply_message(&new_order_for(id, 7, side, price, quantity))
                .expect("in feed order");
        }
        assert_eq!(engine.orders_ignored(), 0, "every order rests");

        let book = book_of(engine, "ETH-USDC", Some(3))
            .await
            .expect("ETH-USDC is listed");

        let running = |levels: &[LevelView]| {
            let mut sum = 0.0;
            levels
                .iter()
                .map(|level| {
                    sum += level.quantity;
                    sum
                })
                .collect::<Vec<f64>>()
        };
        assert_eq!(
            running(&book.bids),
            vec![1.0, 3.0, 7.0],
            "the bid total starts at the best bid and grows down the book"
        );
        assert_eq!(
            running(&book.asks),
            vec![8.0, 24.0, 56.0],
            "the ask total starts at the best ask and grows up the book"
        );
    }

    /// One level is every waiting order at one price. The level's quantity is
    /// the sum of those orders' quantities. `orders` is how many orders the
    /// level holds.
    ///
    /// Three accounts wait at 100.00 and one waits at 99.00. A handler that
    /// reported only the first order of a level would fail this test. So would
    /// a handler that counted the levels instead of the orders in them.
    #[tokio::test]
    async fn a_book_level_holds_every_resting_order_at_that_price() {
        let mut engine = MatcherState::with_default_listings();
        for (id, account, price, quantity) in [
            (1, 7, 100.0, 1.0),
            (2, 8, 100.0, 2.0),
            (3, 9, 100.0, 3.5),
            (4, 7, 99.0, 5.0),
        ] {
            engine
                .apply_message(&new_order_for(id, account, Side::Buy, price, quantity))
                .expect("in feed order");
        }
        assert_eq!(engine.orders_ignored(), 0, "every order rests");

        let book = book_of(engine, "ETH-USDC", None)
            .await
            .expect("ETH-USDC is listed");

        assert_eq!(book.bids.len(), 2, "two prices, so two levels");
        assert_eq!(book.bids[0].price, 100.0);
        assert_eq!(book.bids[0].quantity, 6.5, "1.0 and 2.0 and 3.5");
        assert_eq!(book.bids[0].orders, 3, "three orders rest at 100.00");
        assert_eq!(book.bids[1].price, 99.0);
        assert_eq!(book.bids[1].quantity, 5.0);
        assert_eq!(book.bids[1].orders, 1);
    }

    /// A book with fewer levels than the request asked for is not an error.
    /// The exchange answers with the levels it holds.
    ///
    /// The cap behaves the same way. A caller cannot tell a capped answer from
    /// a book with few levels. Both answers mean the same thing: this is
    /// everything there is to show.
    #[tokio::test]
    async fn a_book_thinner_than_the_depth_asked_for_is_not_an_error() {
        let engine = one_deep_side(2);
        let book = book_of(engine, "ETH-USDC", Some(50))
            .await
            .expect("a thin book is an answer, not an error");

        assert_eq!(book.bids.len(), 2, "the request asked for 50 and 2 rest");
        assert!(book.asks.is_empty(), "an empty side is an empty list");
    }

    /// Two symbols the exchange does not trade, and two different answers.
    ///
    /// A symbol the log never listed is a spelling mistake, and the exchange
    /// says so. A delisted symbol was traded, and its trades are still in the
    /// log. The question about a delisted symbol has an answer: the book is
    /// empty. The two answers must differ. If they read the same, a spelling
    /// mistake would look like an empty market.
    #[tokio::test]
    async fn a_never_listed_symbol_is_refused_and_a_delisted_one_answers_empty() {
        // The test matches instead of calling `expect_err`. `BookResponse` is
        // a serialized answer and does not derive `Debug`, and `expect_err`
        // needs `Debug`.
        let never_listed =
            match book_of(MatcherState::with_default_listings(), "NOT-LISTED", None).await {
                Err(refused) => refused,
                Ok(_) => panic!("the log has never listed 'NOT-LISTED', so /book must refuse it"),
            };
        assert_eq!(never_listed.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            never_listed.1,
            "'NOT-LISTED' is not a symbol this log has listed"
        );

        // The same symbol, after orders waited in it and the operator closed
        // the market.
        let mut engine = one_deep_side(3);
        // Message 4: `one_deep_side` used 1 to 3, and the exchange reads the
        // log in order.
        engine
            .apply_message(&delist_symbol(4, "ETH-USDC"))
            .expect("the operator closes the market");
        let delisted = book_of(engine, "ETH-USDC", None)
            .await
            .expect("a delisted symbol has an empty book, and that is an answer");
        assert!(delisted.bids.is_empty(), "the delist took the orders out");
        assert!(delisted.asks.is_empty());
        assert_eq!(delisted.symbol, "ETH-USDC");
    }

    /// `depth=0` asks for no levels, and no levels is a list with nothing in
    /// it. The exchange answers with two empty sides and does not refuse.
    #[tokio::test]
    async fn depth_zero_answers_with_two_empty_sides() {
        let engine = one_deep_side(3);
        let book = book_of(engine, "ETH-USDC", Some(0))
            .await
            .expect("zero levels is an answer, not an error");

        assert!(
            book.bids.is_empty(),
            "the book has 3 bid levels and 0 asked"
        );
        assert!(book.asks.is_empty());
    }

    /// The check that stops step 4 and step 5 from drifting apart.
    ///
    /// An arriving order reaches a price level when its limit price allows a
    /// trade at that level. Step 4 walks the levels the order reaches, to see
    /// whether any of them holds an order of the same account. Step 5 then
    /// walks the same levels to fill them. ENGINE.md section 4.0 records that
    /// repeat as the price of the rule that a step never calls another step.
    /// Step 5 has no owner, so the two copies of the reach rule cannot be
    /// merged into one.
    ///
    /// The test runs both and compares. It takes step 5's answer by sending
    /// one order with a quantity large enough to clear every level it reaches,
    /// under rule set 1, and recording which levels emptied. It takes step 4's
    /// answer by placing an order of the arriving account at each level in
    /// turn, under rule set 2, and recording where the arrival is refused. The
    /// two lists must be equal at every limit price, including the price that
    /// sits exactly on a level.
    ///
    /// Change either reach rule, `<=` to `<` in step 5, `..=` to `..` in step
    /// 4, and this test fails.
    fn crossing_levels_agree(taker: Side) {
        let levels = [99.0f64, 100.0, 101.0, 102.0, 103.0];
        let resting = match taker {
            Side::Buy => Side::Sell,
            Side::Sell => Side::Buy,
        };
        // Account 9 places one order at every level. The arriving account is
        // 4242.
        let quoted = || {
            let mut engine = MatcherState::with_default_listings();
            for (n, price) in levels.iter().enumerate() {
                engine
                    .apply_message(&new_order_for(n as OrderId + 1, 9, resting, *price, 1.0))
                    .expect("in feed order");
            }
            engine
        };
        let level_prices = |engine: &MatcherState| -> Vec<i64> {
            engine.books.get("ETH-USDC").map_or(Vec::new(), |book| {
                match resting {
                    Side::Buy => &book.bids,
                    Side::Sell => &book.asks,
                }
                .keys()
                .copied()
                .collect()
            })
        };

        for limit in [98.0f64, 99.0, 100.0, 101.0, 102.0, 103.0, 104.0] {
            // What step 5 fills, with nothing to stop it early.
            let mut swept = quoted();
            let next = swept.last_seen + 1;
            swept
                .apply_message(&new_order_for(next, 4242, taker, limit, 100.0))
                .expect("in feed order");
            let left = level_prices(&swept);
            let crossed: Vec<i64> = level_prices(&quoted())
                .into_iter()
                .filter(|price| !left.contains(price))
                .collect();

            // What step 4 refuses, one level at a time.
            let mut refused: Vec<i64> = Vec::new();
            for price in levels {
                let mut engine = quoted();
                let rule = engine.last_seen + 1;
                engine
                    .apply_message(&engine_rule(rule, 2))
                    .expect("in feed order");
                engine
                    .apply_message(&new_order_for(rule + 1, 4242, resting, price, 1.0))
                    .expect("in feed order");
                let before = engine.orders_ignored;
                engine
                    .apply_message(&new_order_for(rule + 2, 4242, taker, limit, 100.0))
                    .expect("in feed order");
                if engine.orders_ignored > before {
                    refused.push(to_cents(price));
                }
            }

            assert_eq!(
                crossed, refused,
                "at a limit of {} a {:?} crosses {:?} in step 5 and {:?} in step 4",
                limit, taker, crossed, refused
            );
        }
    }

    #[test]
    fn step_4_and_step_5_agree_on_which_levels_a_buy_crosses() {
        crossing_levels_agree(Side::Buy);
    }

    #[test]
    fn step_4_and_step_5_agree_on_which_levels_a_sell_crosses() {
        crossing_levels_agree(Side::Sell);
    }

    /// The rule set must survive a restart. The state root makes that a hard
    /// requirement, because the root covers the rule set. An engine that came
    /// back under rule set 1 would hash to a root its own last claim
    /// contradicts, and `open_state` would end the run.
    #[test]
    fn a_resumed_run_comes_back_under_the_rule_set_it_was_matching_under() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");

        let (root, run_id) = {
            let (mut store, _) = Store::open(&path, "http://feed", 200, false).expect("a store");
            let mut state = MatcherState::recording_with_default_listings(&store);
            state
                .apply_message(&engine_rule(1, 2))
                .expect("in feed order");
            state
                .apply_message(&new_order_for(2, 7, Side::Buy, 100.0, 5.0))
                .expect("in feed order");
            assert_eq!(state.rules, RuleSet::NEWEST);

            let pending = state.take_pending().expect("a recording engine");
            let claim = ClaimRow {
                from_msg: 1,
                to_msg: state.last_seen,
                root_before: MatcherState::with_default_listings().state_root(),
                root_after: pending.root,
                trades_total: pending.trades_total,
                signature: Some([7u8; 64]),
            };
            store
                .commit(&pending.changes, &pending.counters, Some(&claim))
                .expect("committed");
            store.close_stopped().expect("closed");
            (state.state_root(), store.run_id())
        };

        let (store, snapshot) =
            Store::open_with_grace(&path, "http://feed", 0, false).expect("reopened");
        let snapshot = snapshot.expect("a resumable run");
        assert_eq!(store.run_id(), run_id);
        assert_eq!(snapshot.counters.rule_version, 2);
        let mut restored = MatcherState::restore(snapshot, &store);
        assert_eq!(restored.rules, RuleSet::NEWEST);
        assert_eq!(
            logchain::to_hex(&restored.state_root()),
            logchain::to_hex(&root),
            "a resume that forgot the rule set hashes to a root the claim contradicts"
        );

        // The restored engine goes on refusing. That is what the root check
        // protects: the books are the same, and so is what happens next.
        restored
            .apply_message(&new_order_for(3, 7, Side::Sell, 100.0, 5.0))
            .expect("read, then refused");
        assert_eq!(restored.trades_total, 0);
        assert_eq!(restored.orders_ignored, 1);
    }

    /// A committed run that refused three orders for three different reasons,
    /// read back. The two tests below ask two different things of that run.
    ///
    /// The function returns the `TempDir` with the engine on purpose. Dropping
    /// the `TempDir` deletes the file. A test that dropped it early would read
    /// a state database that is no longer there.
    fn a_run_that_refused_three_orders() -> (tempfile::TempDir, MatcherState) {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");

        {
            let (mut store, _) = Store::open(&path, "http://feed", 200, false).expect("a store");
            let mut state = MatcherState::recording_with_default_listings(&store);
            // Rule set 2, so account 7 cannot match itself.
            state
                .apply_message(&engine_rule(1, 2))
                .expect("in feed order");
            // This order waits in the book, so the next message has something
            // to match against.
            state
                .apply_message(&new_order_for(2, 7, Side::Buy, 100.0, 5.0))
                .expect("in feed order");
            state
                .apply_message(&new_order_for(3, 7, Side::Sell, 100.0, 4.0))
                .expect("refused: self-trade");
            state
                .apply_message(&order_for_symbol(4, "NOT-LISTED"))
                .expect("refused: unlisted symbol");
            state
                .apply_message(&new_order_for(5, 7, Side::Buy, 100.253, 5.0))
                .expect("refused: off the price step");
            assert_eq!(state.orders_ignored, 3, "three refusals before the restart");

            let pending = state.take_pending().expect("a recording engine");
            let claim = ClaimRow {
                from_msg: 1,
                to_msg: state.last_seen,
                root_before: MatcherState::with_default_listings().state_root(),
                root_after: pending.root,
                trades_total: pending.trades_total,
                signature: Some([7u8; 64]),
            };
            store
                .commit(&pending.changes, &pending.counters, Some(&claim))
                .expect("committed");
            store.close_stopped().expect("closed");
        }

        let (store, snapshot) =
            Store::open_with_grace(&path, "http://feed", 0, false).expect("reopened");
        let snapshot = snapshot.expect("a resumable run");
        let restored = MatcherState::restore(snapshot, &store);
        (dir, restored)
    }

    /// The reason an order was refused is state. It is not a report about one
    /// run of the process. The exchange held the reasons in memory only before
    /// this change, and the cost showed on screen: 620 orders ignored next to
    /// 320 with a named reason. The total counted every run, and the split
    /// counted only the newest run.
    #[test]
    fn a_resumed_run_comes_back_with_the_reasons_it_refused_orders_for() {
        let (_dir, restored) = a_run_that_refused_three_orders();

        assert_eq!(restored.orders_ignored, 3, "the total comes back");
        assert_eq!(
            restored.orders_ignored_by_kind,
            BTreeMap::from([
                ("self_trade".to_string(), 1),
                ("unlisted_symbol".to_string(), 1),
                ("off_grid".to_string(), 1),
            ]),
            "and so does every reason behind it"
        );
    }

    /// `count_ignored` adds to the total and to one reason at the same time.
    /// The split `/market` serves therefore adds up to `orders_ignored`. A
    /// restart is where that stopped being true. So this test checks over a
    /// restart, and not only inside one run of the process.
    #[test]
    fn the_reasons_still_add_up_to_the_total_after_a_restart() {
        let (_dir, restored) = a_run_that_refused_three_orders();

        assert_eq!(
            restored.orders_ignored_by_kind.values().sum::<u64>(),
            restored.orders_ignored,
            "a restart must not leave refusals with no reason"
        );
    }

    /// The operator key must survive a restart for the same reason the rule
    /// set must. There is one more reason. A resumed engine that forgot the
    /// key would take the key inside the next operator message as the log's
    /// key. ENGINE.md section 3.1 exists to stop exactly that.
    #[test]
    fn a_resumed_run_comes_back_under_the_operator_key_it_was_running_under() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        let ours = logchain::to_hex(operator_key().verifying_key().as_bytes());

        let (root, run_id) = {
            let (mut store, _) = Store::open(&path, "http://feed", 200, false).expect("a store");
            let mut state = MatcherState::recording(&store);
            state
                .apply_message(&list_symbol(1, "ETH-USDC"))
                .expect("in feed order");
            state
                .apply_message(&new_order_for(2, 7, Side::Buy, 100.0, 5.0))
                .expect("in feed order");
            assert_eq!(state.operator_key(), Some(ours.clone()));

            let pending = state.take_pending().expect("a recording engine");
            let claim = ClaimRow {
                from_msg: 1,
                to_msg: state.last_seen,
                root_before: MatcherState::new().state_root(),
                root_after: pending.root,
                trades_total: pending.trades_total,
                signature: Some([7u8; 64]),
            };
            store
                .commit(&pending.changes, &pending.counters, Some(&claim))
                .expect("committed");
            store.close_stopped().expect("closed");
            (state.state_root(), store.run_id())
        };

        let (store, snapshot) =
            Store::open_with_grace(&path, "http://feed", 0, false).expect("reopened");
        let snapshot = snapshot.expect("a resumable run");
        assert_eq!(store.run_id(), run_id);
        assert_eq!(
            snapshot
                .counters
                .operator_key
                .map(|key| logchain::to_hex(&key)),
            Some(ours.clone()),
            "the key is in the state database and not only in memory"
        );
        let mut restored = MatcherState::restore(snapshot, &store);
        assert_eq!(restored.operator_key(), Some(ours));
        assert_eq!(
            logchain::to_hex(&restored.state_root()),
            logchain::to_hex(&root),
            "a resume that forgot the operator key hashes to a root the claim contradicts"
        );

        // The restored engine goes on checking against that key. It does not
        // adopt the next key it is shown.
        let stranger = SigningKey::from_bytes(&[9u8; 32]);
        restored
            .apply_message(&signed_by_operator(
                &stranger,
                OrderMessage::ListSymbol {
                    id: 3,
                    timestamp: 3000,
                    account: OPERATOR_ACCOUNT,
                    symbol: "BTC-USDC".to_string(),
                    price_step: 0.01,
                    quantity_step: 0.1,
                    nonce: operator_nonce(3),
                    public_key: String::new(),
                    signature: String::new(),
                },
            ))
            .expect("read, then refused");
        assert!(!restored.is_listed("BTC-USDC"));
        assert_eq!(restored.listings_ignored(), 1);
    }

    #[test]
    fn crossing_orders_trade_at_resting_price() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order(1, Side::Sell, 100.0, 5.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order(2, Side::Buy, 100.5, 5.0))
            .expect("test messages arrive in feed order");

        assert_eq!(state.trades.len(), 1);
        let trade = &state.trades[0];
        // The trade is at the price of the order that was already in the book,
        // and not at the arriving order's 100.5.
        assert_eq!(trade.price, 100.0);
        assert_eq!(trade.quantity, 5.0);
        assert_eq!(trade.maker_order, 1);
        assert_eq!(trade.taker_order, 2);
        assert_eq!(open_orders(&state, Side::Buy), 0);
        assert_eq!(open_orders(&state, Side::Sell), 0);
    }

    #[test]
    fn non_crossing_orders_rest_in_the_book() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order(1, Side::Sell, 101.0, 5.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order(2, Side::Buy, 99.0, 5.0))
            .expect("test messages arrive in feed order");

        assert_eq!(state.trades.len(), 0);
        assert_eq!(open_orders(&state, Side::Buy), 1);
        assert_eq!(open_orders(&state, Side::Sell), 1);
    }

    #[test]
    fn partial_fill_leaves_remainder_resting() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order(1, Side::Sell, 100.0, 5.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order(2, Side::Buy, 100.0, 2.0))
            .expect("test messages arrive in feed order");

        assert_eq!(state.trades.len(), 1);
        assert_eq!(state.trades[0].quantity, 2.0);
        // 3.0 of the sell order stays in the book.
        let book = state.books.get("ETH-USDC").unwrap();
        let level = book.asks.get(&to_cents(100.0)).unwrap();
        assert_eq!(level[0].qty_tenths, to_tenths(3.0));
    }

    #[test]
    fn taker_sweeps_best_priced_levels_first() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order(1, Side::Sell, 100.0, 1.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order(2, Side::Sell, 99.0, 1.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order(3, Side::Buy, 101.0, 2.0))
            .expect("test messages arrive in feed order");

        assert_eq!(state.trades.len(), 2);
        assert_eq!(state.trades[0].price, 99.0); // cheapest sell fills first
        assert_eq!(state.trades[1].price, 100.0);
    }

    #[test]
    fn cancel_removes_open_order() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order(1, Side::Sell, 100.0, 5.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&cancel(2, 1))
            .expect("test messages arrive in feed order");

        assert_eq!(state.cancels_applied, 1);
        assert_eq!(open_orders(&state, Side::Sell), 0);

        // No arriving order can match the cancelled order now.
        state
            .apply_message(&new_order(3, Side::Buy, 100.5, 5.0))
            .expect("test messages arrive in feed order");
        assert_eq!(state.trades.len(), 0);
        assert_eq!(open_orders(&state, Side::Buy), 1);
    }

    #[test]
    fn cancel_of_already_filled_order_is_ignored() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order(1, Side::Sell, 100.0, 5.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order(2, Side::Buy, 100.0, 5.0))
            .expect("test messages arrive in feed order"); // fills order 1
        state
            .apply_message(&cancel(3, 1))
            .expect("test messages arrive in feed order");

        assert_eq!(state.cancels_applied, 0);
        assert_eq!(state.cancels_ignored, 1);
        assert_eq!(state.trades.len(), 1);
    }

    /// The generator only sends values that sit on the price step and the
    /// quantity step. `POST /order` accepts any positive f64. So the three
    /// values below can still reach the engine from a submitted order.
    #[test]
    fn off_grid_orders_are_ignored_and_counted() {
        let mut state = MatcherState::with_default_listings();
        // A price below one cent, so not a whole number of price steps.
        state
            .apply_message(&new_order(1, Side::Buy, 100.253, 5.0))
            .expect("test messages arrive in feed order");
        // A quantity below the quantity step.
        state
            .apply_message(&new_order(2, Side::Buy, 100.0, 0.04))
            .expect("test messages arrive in feed order");
        // A quantity so large that the conversion to an integer overflows.
        state
            .apply_message(&new_order(3, Side::Buy, 100.0, 1e18))
            .expect("test messages arrive in feed order");

        assert_eq!(state.orders_ignored, 3);
        assert_eq!(state.trades.len(), 0);
        // Nothing reached the books, and nothing is claimed as open.
        assert!(
            state
                .books
                .get("ETH-USDC")
                .is_none_or(|b| b.bids.is_empty())
        );
        assert!(state.open_orders.is_empty());
        // The engine still read the messages, so the cursor keeps moving.
        assert_eq!(state.last_seen, 3);
        assert_eq!(state.messages_processed, 3);
    }

    /// Sends `pairs` pairs of orders through the engine. Each pair is one sell
    /// order that waits in the book and one buy order that matches it. Each
    /// pair makes one trade.
    fn trade_pairs(state: &mut MatcherState, pairs: u64) {
        let mut id = state.last_seen;
        for _ in 0..pairs {
            id += 1;
            state
                .apply_message(&new_order_for(id, 7, Side::Sell, 100.0, 1.0))
                .expect("in feed order");
            id += 1;
            state
                .apply_message(&new_order_for(id, 9, Side::Buy, 100.0, 1.0))
                .expect("in feed order");
        }
    }

    /// The trade window keeps the newest fills and nothing else. The ids keep
    /// counting from the run's total, and not from the number of trades in
    /// memory. `trade_id` used to be `trades.len() + 1`. That would have
    /// handed out ids that already existed, from the moment the window dropped
    /// its oldest trade.
    #[test]
    fn trade_ids_keep_counting_when_the_window_rolls() {
        let mut state = MatcherState::with_default_listings();
        let total = TRADE_WINDOW as u64 + 250;
        trade_pairs(&mut state, total);

        assert_eq!(state.trades_total(), total);
        assert_eq!(state.trade_count(), total);
        assert_eq!(state.trades.len(), TRADE_WINDOW, "the window is bounded");
        assert_eq!(
            state.trades.back().expect("a newest trade").trade_id,
            total,
            "the newest trade carries the run's total as its id"
        );
        assert!(
            state.trade(1).is_none(),
            "trade 1 is long out of the window"
        );
        assert_eq!(state.trade(total).expect("still held").trade_id, total);
        assert_eq!(
            state
                .trade(total - TRADE_WINDOW as u64 + 1)
                .expect("the oldest held")
                .trade_id,
            total - TRADE_WINDOW as u64 + 1
        );
        // Every id was handed out exactly once, so the window is a run of
        // consecutive ids ending at the total.
        for (offset, trade) in state.trades.iter().enumerate() {
            assert_eq!(
                trade.trade_id,
                total - TRADE_WINDOW as u64 + 1 + offset as u64
            );
        }
    }

    /// A resume reads every trade of the run back to rebuild the positions,
    /// but it holds only the window in memory. The positions and the running
    /// total must come out identical to the engine that wrote them. If they do
    /// not, the state root check in `open_state` refuses the run. That check is
    /// what this test stands behind.
    #[test]
    fn a_resume_past_the_trade_window_rebuilds_the_whole_run() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        let pairs = TRADE_WINDOW as u64 + 250;

        let (root, positions, run_id) = {
            let (mut store, _) = Store::open(&path, "http://feed", 200, false).expect("a store");
            let mut state = MatcherState::recording_with_default_listings(&store);
            trade_pairs(&mut state, pairs);
            // One order is left waiting in the book, so the run resumes with a
            // book as well as a trade history. The other case is a symbol
            // whose book is empty at the resume point. That case is
            // `a_resume_of_an_emptied_book_matches_the_committed_root`.
            state
                .apply_message(&new_order_for(
                    state.last_seen + 1,
                    7,
                    Side::Sell,
                    500.0,
                    2.0,
                ))
                .expect("in feed order");
            let pending = state.take_pending().expect("a recording engine");
            let claim = ClaimRow {
                from_msg: 1,
                to_msg: state.last_seen,
                root_before: MatcherState::with_default_listings().state_root(),
                root_after: pending.root,
                trades_total: pending.trades_total,
                signature: Some([7u8; 64]),
            };
            store
                .commit(&pending.changes, &pending.counters, Some(&claim))
                .expect("committed");
            store.close_stopped().expect("closed");
            (state.state_root(), state.positions.clone(), store.run_id())
        };

        let (store, snapshot) =
            Store::open_with_grace(&path, "http://feed", 0, false).expect("reopened");
        let snapshot = snapshot.expect("a resumable run");
        assert_eq!(store.run_id(), run_id);
        assert_eq!(snapshot.trades_total, pairs);
        let state = MatcherState::restore(snapshot, &store);

        assert_eq!(state.trades_total(), pairs, "the count survives the resume");
        assert_eq!(state.trades.len(), TRADE_WINDOW, "the window does not grow");
        assert_eq!(
            state.trades.back().expect("a newest trade").trade_id,
            pairs,
            "and holds the newest trades of the run"
        );
        assert_eq!(state.positions, positions, "positions are the same sums");
        assert_eq!(
            state.state_root(),
            root,
            "the restored state hashes to what the previous life committed"
        );
    }

    /// A quiet period empties a symbol's book. The last waiting orders fill or
    /// are cancelled, and no new order replaces them. The state the engine
    /// resumes into must hash to the root it committed when it stopped. If it
    /// does not, `open_state` refuses the run and the process exits with code
    /// 2. That happens at every restart, until somebody deletes the file.
    #[test]
    fn a_resume_of_an_emptied_book_matches_the_committed_root() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");

        let (root, run_id) = {
            let (mut store, _) = Store::open(&path, "http://feed", 200, false).expect("a store");
            let mut state = MatcherState::recording_with_default_listings(&store);
            // The symbol trades, so it has a history and a position...
            trade_pairs(&mut state, 3);
            // ...and then every waiting order in it goes away. One order is
            // filled by the other side. One order is cancelled by its owner.
            state
                .apply_message(&new_order_for(
                    state.last_seen + 1,
                    7,
                    Side::Sell,
                    101.0,
                    1.0,
                ))
                .expect("in feed order");
            state
                .apply_message(&new_order_for(
                    state.last_seen + 1,
                    9,
                    Side::Buy,
                    101.0,
                    1.0,
                ))
                .expect("in feed order");
            let resting = state.last_seen + 1;
            state
                .apply_message(&new_order_for(resting, 7, Side::Sell, 500.0, 2.0))
                .expect("in feed order");
            state
                .apply_message(&cancel_from(state.last_seen + 1, 7, resting))
                .expect("in feed order");
            assert!(state.open_orders.is_empty(), "nothing is left resting");

            let pending = state.take_pending().expect("a recording engine");
            let claim = ClaimRow {
                from_msg: 1,
                to_msg: state.last_seen,
                root_before: MatcherState::with_default_listings().state_root(),
                root_after: pending.root,
                trades_total: pending.trades_total,
                signature: Some([7u8; 64]),
            };
            store
                .commit(&pending.changes, &pending.counters, Some(&claim))
                .expect("committed");
            store.close_stopped().expect("closed");
            (state.state_root(), store.run_id())
        };

        let (store, snapshot) =
            Store::open_with_grace(&path, "http://feed", 0, false).expect("reopened");
        let snapshot = snapshot.expect("a resumable run");
        assert_eq!(store.run_id(), run_id);
        assert_eq!(
            snapshot.last_claim_root,
            Some(root),
            "the committed claim is the root the resume is checked against"
        );
        assert!(
            snapshot.orders.is_empty(),
            "no order survived to be restored"
        );
        let restored = MatcherState::restore(snapshot, &store);

        assert_eq!(
            logchain::to_hex(&restored.state_root()),
            logchain::to_hex(&root),
            "a symbol whose book emptied out must restore to the same state, \
             not to one the root check refuses"
        );
    }

    /// An engine served over the API with no state database behind it. A
    /// handler then sees only the trade window, and answers from that window
    /// alone.
    fn api(engine: &Arc<Mutex<MatcherState>>) -> ApiState {
        ApiState {
            engine: Arc::clone(engine),
            history: None,
            live: LiveFeed::new(),
            public_feed_url: "http://127.0.0.1:3000".to_string(),
            public_inbox_url: None,
            anchor: None,
        }
    }

    /// The same, with the run's trades table behind it. The handlers see this
    /// in production. A trade older than the window is a row the handler reads
    /// from the table.
    fn api_with_history(engine: MatcherState, path: &Path) -> ApiState {
        ApiState {
            engine: Arc::new(Mutex::new(engine)),
            history: Some(Arc::new(
                HistoryPool::open(path, HISTORY_READERS).expect("a read-only view"),
            )),
            live: LiveFeed::new(),
            public_feed_url: "http://127.0.0.1:3000".to_string(),
            public_inbox_url: None,
            anchor: None,
        }
    }

    /// A committed run whose trades go well past the window. Every read below
    /// must reach the table for part of its answer.
    ///
    /// Account 9 is the arriving order in every fill. Account 7 is the order
    /// that waits in the book, except for one fill at the very start where
    /// account 3 waits. That first fill is the row a filtered `/trades` must
    /// find below the window.
    fn run_past_the_trade_window(path: &Path) -> MatcherState {
        let (mut store, _) = Store::open(path, "http://feed", 200, false).expect("a store");
        let mut state = MatcherState::recording_with_default_listings(&store);
        state
            .apply_message(&new_order_for(1, 3, Side::Sell, 100.0, 1.0))
            .expect("in feed order");
        state
            .apply_message(&new_order_for(2, 9, Side::Buy, 100.0, 1.0))
            .expect("in feed order");
        trade_pairs(&mut state, TRADE_WINDOW as u64 + 250);
        let pending = state.take_pending().expect("a recording engine");
        let claim = ClaimRow {
            from_msg: 1,
            to_msg: state.last_seen,
            root_before: MatcherState::with_default_listings().state_root(),
            root_after: pending.root,
            trades_total: pending.trades_total,
            signature: Some([7u8; 64]),
        };
        store
            .commit(&pending.changes, &pending.counters, Some(&claim))
            .expect("committed");
        store.close_stopped().expect("closed");
        state
    }

    /// The browser is given every endpoint, best first.
    ///
    /// One public RPC is one thing that can time out, rate-limit, or sit on a
    /// browser extension's block list, and when it does, the one number on the
    /// strip that this operator cannot fabricate is the number that disappears.
    #[test]
    fn the_anchor_config_names_every_rpc_the_file_does() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("deployment.json");
        std::fs::write(
            &path,
            r#"{"address":"0xabc","chain_id":84532,"rpc":"https://first.example",
                "rpc_fallbacks":["https://second.example","https://third.example"],
                "block_number":7,"writer":"0xdef"}"#,
        )
        .expect("wrote it");

        let config =
            load_anchor_config(Some(path.to_string_lossy().to_string())).expect("a config");
        assert_eq!(
            config.rpcs,
            vec![
                "https://first.example",
                "https://second.example",
                "https://third.example"
            ],
            "the operator's own endpoint first, then the fallbacks in file order"
        );
    }

    /// A deployment file written before fallbacks existed still works.
    #[test]
    fn a_file_with_one_rpc_answers_a_list_of_one() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("deployment.json");
        std::fs::write(
            &path,
            r#"{"address":"0xabc","chain_id":84532,"rpc":"https://only.example",
                "block_number":7,"writer":"0xdef"}"#,
        )
        .expect("wrote it");

        let config =
            load_anchor_config(Some(path.to_string_lossy().to_string())).expect("a config");
        assert_eq!(config.rpcs, vec!["https://only.example"]);
    }

    /// A batch reaches a reader of that symbol, and only that symbol.
    ///
    /// The stream is the same information the read endpoints answer with, sent
    /// as it happens. What it must never do is send one symbol's book to a
    /// reader watching another, because the page draws what it is sent.
    #[test]
    fn a_batch_carries_each_symbol_its_own_trades_and_its_own_book() {
        let mut engine = MatcherState::with_default_listings();
        let before = engine.trades_total();
        // One trade in ETH-USDC, which is what `new_order_for` names, and a
        // resting order in another symbol so its book is not empty either.
        // Through the same reader the poller uses, so the batch this is given is
        // the shape a batch really has, `TooOld` variant and all.
        let lines: Vec<u8> = [
            new_order_for(1, 7, Side::Sell, 100.0, 1.0),
            new_order_for(2, 9, Side::Buy, 100.0, 1.0),
        ]
        .iter()
        .flat_map(|m| {
            let mut line = serde_json::to_vec(m).expect("a message");
            line.push(b'\n');
            line
        })
        .collect();
        let batch = wire::read_ndjson::<OrderMessage>(&lines).expect("one message a line");
        for message in &batch {
            engine
                .apply_message(message.parsed.as_ref().expect("readable"))
                .expect("in feed order");
        }

        let tick = tick_of(&engine, before, &batch, STREAM_DEPTH);
        assert_eq!(tick.cursor, engine.last_seen, "the cursor is the engine's");

        let eth: serde_json::Value =
            serde_json::from_str(tick.body.get("ETH-USDC").expect("a body for ETH-USDC"))
                .expect("json");
        let btc: serde_json::Value =
            serde_json::from_str(tick.body.get("BTC-USDC").expect("a body for BTC-USDC"))
                .expect("json");

        assert_eq!(
            eth["trades"].as_array().expect("trades").len(),
            1,
            "the one trade this batch made is in the symbol it happened in"
        );
        assert!(
            btc["trades"].as_array().expect("trades").is_empty(),
            "and in no other symbol"
        );
        assert_eq!(eth["book"]["symbol"], "ETH-USDC");
        assert_eq!(btc["book"]["symbol"], "BTC-USDC");
        assert_eq!(
            eth["messages"].as_array().expect("messages").len(),
            2,
            "both orders were for this symbol"
        );
        assert!(
            btc["messages"].as_array().expect("messages").is_empty(),
            "and neither was for this one"
        );
    }

    /// A batch is not built when nobody is reading.
    ///
    /// Building one serialises every symbol's book, five times a second. An
    /// exchange with no browser open is the ordinary case and must not pay it.
    #[test]
    fn nothing_is_built_for_nobody() {
        let live = LiveFeed::new();
        assert!(!live.wanted(), "no reader, nothing to build");
        let reader = live.to_readers.subscribe();
        assert!(live.wanted(), "one reader is enough to build for");
        drop(reader);
        assert!(!live.wanted(), "and it stops when the last one goes");
    }

    /// `totals=1` leaves the per-symbol rows out and carries their sum.
    ///
    /// The page draws four numbers an account and sums the rows into a fifth.
    /// It was reading 24 numbers an account to do it, 50 accounts at a time,
    /// twice a second.
    #[tokio::test]
    async fn totals_answer_without_the_rows_and_still_value_what_is_open() {
        // Account 0 is the other side of every trade in this fixture, so it
        // holds what the traders bought. One symbol is enough to show the two
        // shapes apart; `open_notional` sums over as many as the account holds.
        let engine = Arc::new(Mutex::new(one_position_each(3)));
        let whole = get_positions(
            State(Arc::clone(&engine)),
            Query(PositionsQuery {
                account: None,
                since: None,
                n: None,
                totals: None,
            }),
        )
        .await
        .0;
        let totals = get_positions(
            State(Arc::clone(&engine)),
            Query(PositionsQuery {
                account: None,
                since: None,
                n: None,
                totals: Some(true),
            }),
        )
        .await
        .0;

        let full = whole.first().expect("one account");
        let slim = totals.first().expect("one account");
        let rows = full.positions.as_ref().expect("the rows");
        assert!(!rows.is_empty(), "the account holds something");
        assert!(
            slim.positions.is_none(),
            "no `positions` key at all, and not an empty list: an empty list is \
             what an account holding nothing looks like"
        );

        // The sum the browser used to make, made here instead.
        let by_hand: f64 = rows
            .iter()
            .map(|p| p.net_quantity.abs() * p.last_trade_price.unwrap_or(0.0))
            .sum();
        assert_eq!(full.open_notional, by_hand);
        assert_eq!(slim.open_notional, by_hand);
        assert!(by_hand > 0.0, "the account holds something worth something");

        // Everything else is the same answer.
        assert_eq!(slim.account, full.account);
        assert_eq!(slim.realized_pnl, full.realized_pnl);
        assert_eq!(slim.unrealized_pnl, full.unrealized_pnl);
        assert_eq!(slim.total_pnl, full.total_pnl);
    }

    /// The page answers a second visit with 304 and no body.
    ///
    /// Roughly 400 KB of page, and a visitor who reloads pays for all of it
    /// again without this. The tag is a hash of the bytes, so it is the same
    /// tag until the page changes and a different one the moment it does.
    #[tokio::test]
    async fn the_page_is_not_sent_twice_to_a_browser_that_has_it() {
        let first = get_ui(HeaderMap::new()).await;
        assert_eq!(first.status(), StatusCode::OK);
        let tag = first
            .headers()
            .get(header::ETAG)
            .expect("an entity tag")
            .to_str()
            .expect("ascii")
            .to_string();
        assert_eq!(
            first.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-cache",
            "a visitor must ask before using the page it has"
        );

        let mut asking = HeaderMap::new();
        asking.insert(header::IF_NONE_MATCH, tag.parse().expect("a header"));
        let again = get_ui(asking).await;
        assert_eq!(again.status(), StatusCode::NOT_MODIFIED);

        // A proxy may send more than one tag in the header.
        let mut among_others = HeaderMap::new();
        among_others.insert(
            header::IF_NONE_MATCH,
            format!("\"0000000000000000\", {}", tag)
                .parse()
                .expect("a header"),
        );
        assert_eq!(
            get_ui(among_others).await.status(),
            StatusCode::NOT_MODIFIED,
            "ours among others is still ours"
        );

        // A tag from another build is not this page.
        let mut stale = HeaderMap::new();
        stale.insert(
            header::IF_NONE_MATCH,
            "\"0123456789abcdef\"".parse().expect("a header"),
        );
        assert_eq!(get_ui(stale).await.status(), StatusCode::OK);
    }

    /// The signer is a second file and gets the same answer.
    #[tokio::test]
    async fn the_signer_is_not_sent_twice_either() {
        let first = get_signer(HeaderMap::new()).await;
        let tag = first
            .headers()
            .get(header::ETAG)
            .expect("an entity tag")
            .to_str()
            .expect("ascii")
            .to_string();
        assert_ne!(tag, *UI_ETAG, "two files, two tags");
        let mut asking = HeaderMap::new();
        asking.insert(header::IF_NONE_MATCH, tag.parse().expect("a header"));
        assert_eq!(get_signer(asking).await.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn the_page_code_and_style_are_same_origin_assets() {
        for (response, content_type) in [
            (
                get_app_css(HeaderMap::new()).await,
                "text/css; charset=utf-8",
            ),
            (
                get_app_js(HeaderMap::new()).await,
                "text/javascript; charset=utf-8",
            ),
        ] {
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                content_type
            );
            assert!(response.headers().contains_key(header::ETAG));
        }
    }

    #[tokio::test]
    async fn the_site_icons_are_served_from_the_binary() {
        for (response, content_type) in [
            (get_favicon(HeaderMap::new()).await, "image/x-icon"),
            (get_icon(HeaderMap::new()).await, "image/png"),
            (get_apple_icon(HeaderMap::new()).await, "image/png"),
        ] {
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                content_type
            );
            assert!(response.headers().contains_key(header::ETAG));
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-cache"
            );
        }
    }

    /// Two reads of the state database run at the same time.
    ///
    /// This is the whole point of `HistoryPool`. Before it there was one
    /// `HistoryReader` behind a `Mutex`, so the second read of a pair waited
    /// for the first to finish. Measured on the live exchange, that queue made
    /// `/candles` answer in 4,374ms where it answers in 657ms alone, because
    /// one browser asks for the same candles about six times a second.
    ///
    /// Each read says it arrived and then waits to hear the other one arrive.
    /// Both hear each other only if both are inside at once.
    ///
    /// The wait has a deadline, and that is not decoration. A `Barrier` here
    /// deadlocked the whole test binary when this was checked against a pool of
    /// one: the first read parked a blocking thread forever, and a tokio
    /// runtime does not finish dropping while a blocking task is still parked,
    /// so the test hung instead of failing. A test that hangs on a regression
    /// costs a CI job and says nothing. This one answers in five seconds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_history_reads_do_not_wait_for_each_other() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        let engine = run_past_the_trade_window(&path);
        let state = api_with_history(engine, &path);

        let (one_arrived, hear_one) = std::sync::mpsc::channel::<()>();
        let (two_arrived, hear_two) = std::sync::mpsc::channel::<()>();
        let both = Duration::from_secs(5);

        let one = {
            let state = state.clone();
            tokio::spawn(async move {
                read_history(&state, move |_| {
                    let _ = one_arrived.send(());
                    Ok(hear_two.recv_timeout(both).is_ok())
                })
                .await
            })
        };
        let two = {
            let state = state.clone();
            tokio::spawn(async move {
                read_history(&state, move |_| {
                    let _ = two_arrived.send(());
                    Ok(hear_one.recv_timeout(both).is_ok())
                })
                .await
            })
        };

        let one = one.await.expect("first task").expect("first read");
        let two = two.await.expect("second task").expect("second read");
        assert!(
            one && two,
            "the two reads did not overlap, so the pool is lending one handle at \
             a time again: first read saw the second {}, second saw the first {}",
            one,
            two
        );
    }

    /// A query that panics costs one answer, not one handle.
    ///
    /// `Lease` returns the handle in `Drop`, so the unwind puts it back. Without
    /// that the pool would hold seven handles and eight permits, and the eighth
    /// request after a panic would find `free` empty.
    #[tokio::test]
    async fn a_panicking_read_gives_its_handle_back() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        let engine = run_past_the_trade_window(&path);
        let state = api_with_history(engine, &path);
        let pool = state.history.clone().expect("a pool");

        let boom: Result<u8, _> = read_history(&state, |_| panic!("a query gave up")).await;
        assert!(boom.is_err(), "the request fails");

        assert_eq!(
            pool.free.lock().expect("free list").len(),
            HISTORY_READERS,
            "every handle is back in the pool"
        );
    }

    /// `/trades` filtered by an account that last traded before the window
    /// starts. The answer from memory is empty. The answer for the whole run
    /// is one fill, and that fill comes from the table. An empty list would
    /// look like an account that has never traded.
    #[tokio::test]
    async fn a_filtered_trade_list_reaches_below_the_window() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        let engine = run_past_the_trade_window(&path);
        let total = engine.trades_total();
        let state = api_with_history(engine, &path);

        let old = get_trades(
            State(state.clone()),
            Query(TradesQuery {
                symbol: None,
                account: Some(3),
                n: Some(20),
            }),
        )
        .await
        .expect("a trade list")
        .0;
        assert_eq!(old.len(), 1, "account 3's only fill is trade 1");
        assert_eq!(old[0].trade_id, 1);
        assert_eq!(old[0].maker_account, 3);

        // The newest trades still come out of memory, oldest first.
        let recent = get_trades(
            State(state.clone()),
            Query(TradesQuery {
                symbol: Some("ETH-USDC".to_string()),
                account: None,
                n: Some(5),
            }),
        )
        .await
        .expect("a trade list")
        .0;
        assert_eq!(recent.len(), 5);
        assert_eq!(recent[4].trade_id, total);
        assert_eq!(recent[0].trade_id, total - 4);
    }

    /// An account absent from the position map never appeared on either side of
    /// a fill. The trade endpoint answers that fact without waiting for a
    /// history reader. Closing the pool proves the handler did not try to take
    /// one.
    #[tokio::test]
    async fn an_unused_account_trade_query_does_not_open_history() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        let engine = run_past_the_trade_window(&path);
        let state = api_with_history(engine, &path);
        state
            .history
            .as_ref()
            .expect("a history pool")
            .permits
            .close();

        let trades = get_trades(
            State(state),
            Query(TradesQuery {
                symbol: None,
                account: Some(u32::MAX),
                n: Some(100),
            }),
        )
        .await
        .expect("an unused account is cheap")
        .0;
        assert!(trades.is_empty());
    }

    /// An account with no fills is answered from the in-memory position map.
    /// It does not need a history handle and cannot turn an empty result into a
    /// walk over the durable trade record.
    #[tokio::test]
    async fn an_unused_account_profit_query_does_not_open_history() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        let engine = Arc::new(Mutex::new(run_past_the_trade_window(&path)));
        let state = api(&engine);

        let series = get_pnl(
            State(state),
            Query(PnlQuery {
                account: u32::MAX,
                points: Some(2000),
            }),
        )
        .await
        .expect("an unused account is cheap")
        .0;
        assert_eq!(series.len(), 1);
        assert_eq!(series[0].account, u32::MAX);
        assert!(series[0].points.is_empty());
    }

    #[test]
    fn a_profit_request_has_a_bounded_sample_count() {
        let ids = pnl_sample_ids(2_500_000, usize::MAX);
        assert_eq!(ids.first().copied(), Some(1));
        assert_eq!(ids.last().copied(), Some(2_500_000));
        assert!(ids.len() <= 2001, "{} samples", ids.len());
    }

    /// The profit series covers the whole run. The trades below the window
    /// come from the table. The newest trades come from memory. The two join
    /// up, and no trade is counted twice or skipped.
    #[tokio::test]
    async fn the_profit_series_covers_trades_below_the_window() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        let engine = run_past_the_trade_window(&path);
        let total = engine.trades_total();
        let realized = engine.account_pnl_mills(9);
        let state = api_with_history(engine, &path);

        let series = get_pnl(
            State(state),
            Query(PnlQuery {
                account: 9,
                points: Some(200),
            }),
        )
        .await
        .expect("a series")
        .0;
        assert_eq!(series.len(), 1);
        let points = &series[0].points;
        assert!(!points.is_empty(), "the series has samples");
        let last = points.last().expect("a last point");
        assert!(
            (last.realized - mills_to_f64(realized.0)).abs() < 1e-9,
            "the series ends where /positions stands: {} vs {}",
            last.realized,
            mills_to_f64(realized.0)
        );
        assert!(
            points.len() > 100,
            "every trade of the run was applied, not only the window's {}: {} points over {} \
             trades",
            TRADE_WINDOW,
            points.len(),
            total
        );
    }

    /// Candles reach below the window too. That is the reason the code walks
    /// backwards.
    ///
    /// The numbers in this test come from `run_past_the_trade_window`. It makes
    /// 10,251 trades, one every two seconds, so the run is 20,502 seconds long.
    /// The window in memory keeps the newest 10,000 of those trades, so it holds
    /// the newest 20,000 seconds and the first 502 seconds are rows in the
    /// table only.
    ///
    /// A bucket 3600 seconds wide, asked for 20 times, covers 72,000 seconds.
    /// That is longer than the run, so the projection starts at the first trade.
    /// The answer is the 6 buckets the run really covers, and the oldest starts
    /// at 0. The history pool is closed below: a cache read must still work.
    #[tokio::test]
    async fn candles_reach_below_the_window() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        let engine = run_past_the_trade_window(&path);
        let state = api_with_history(engine, &path);
        state
            .history
            .as_ref()
            .expect("a history pool")
            .permits
            .close();

        let candles = get_candles(
            State(state),
            Query(CandlesQuery {
                symbol: "ETH-USDC".to_string(),
                interval: Some(3600),
                n: Some(20),
            }),
        )
        .await
        .expect("candles")
        .0;
        assert_eq!(candles.len(), 6, "the whole run, in one-hour buckets");
        assert_eq!(
            candles[0].start, 0,
            "the oldest bucket holds the first trade of the run, which is in \
             the table and not in the window"
        );
        for pair in candles.windows(2) {
            assert_eq!(
                pair[1].start - pair[0].start,
                3_600_000,
                "one bucket width apart, oldest first, no hole"
            );
        }
        for candle in &candles {
            assert!(candle.trades > 0 && candle.volume > 0.0);
            assert!(candle.high >= candle.low);
        }
    }

    /// Everything an observer can see, written into one string for comparison.
    fn observable(state: &MatcherState) -> String {
        let mut positions: Vec<String> = state
            .positions
            .iter()
            .map(|((account, symbol), p)| {
                format!(
                    "{account}/{symbol} qty={} cash={} realized={} basis={}",
                    p.net_qty_tenths, p.cash_mills, p.realized_mills, p.cost_basis_mills
                )
            })
            .collect();
        positions.sort();
        let trades: Vec<String> = state
            .trades
            .iter()
            .map(|t| {
                format!(
                    "{}x{}@{} m{} t{}",
                    t.quantity, t.symbol, t.price, t.maker_order, t.taker_order
                )
            })
            .collect();
        let mut books: Vec<String> = state
            .books
            .iter()
            .map(|(symbol, book)| format!("{symbol} bids={:?} asks={:?}", book.bids, book.asks))
            .collect();
        books.sort();
        format!(
            "{trades:?}\n{positions:?}\n{books:?}\ncursor={} cancels={}/{} orders_ignored={}",
            state.last_seen, state.cancels_applied, state.cancels_ignored, state.orders_ignored
        )
    }

    /// The restart path throws the state away and replays the log from the
    /// first message. That is safe only because the same messages always
    /// rebuild the same books, positions, and trades.
    #[test]
    fn replaying_the_same_messages_rebuilds_identical_state() {
        let messages = vec![
            new_order_for(1, 7, Side::Sell, 100.0, 10.0),
            new_order_for(2, 9, Side::Buy, 100.0, 6.0),
            new_order_for(3, 8, Side::Buy, 101.0, 4.0),
            cancel(4, 1),
            new_order_for(5, 9, Side::Sell, 99.0, 3.0),
            new_order_for(6, 7, Side::Buy, 99.5, 5.0),
            new_order(7, Side::Buy, 100.253, 5.0), // refused, still counted
            cancel(8, 999),                        // targets nothing, still counted
        ];

        let mut original = MatcherState::with_default_listings();
        for msg in &messages {
            original
                .apply_message(msg)
                .expect("test messages arrive in feed order");
        }

        // A fresh engine, like the one a restart creates after it throws the
        // state away.
        let mut replayed = MatcherState::with_default_listings();
        for msg in &messages {
            replayed
                .apply_message(msg)
                .expect("test messages arrive in feed order");
        }

        assert_eq!(observable(&original), observable(&replayed));
        assert!(
            !original.trades.is_empty(),
            "the sequence must actually trade"
        );
    }

    #[test]
    fn trade_records_both_counterparties() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order_for(1, 7, Side::Sell, 100.0, 5.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(2, 9, Side::Buy, 100.5, 5.0))
            .expect("test messages arrive in feed order");

        let trade = &state.trades[0];
        assert_eq!(trade.maker_account, 7);
        assert_eq!(trade.taker_account, 9);
        assert_eq!(trade.maker_order, 1);
        assert_eq!(trade.taker_order, 2);
    }

    #[test]
    fn both_sides_of_a_fill_get_opposite_positions() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order_for(1, 7, Side::Sell, 100.0, 5.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(2, 9, Side::Buy, 100.0, 5.0))
            .expect("test messages arrive in feed order");

        // The seller now holds -5 units and the buyer +5 units. The two cash
        // amounts add up to zero.
        assert_eq!(position(&state, 7).net_qty_tenths, to_tenths(-5.0));
        assert_eq!(position(&state, 9).net_qty_tenths, to_tenths(5.0));
        assert_eq!(
            position(&state, 7).cash_mills + position(&state, 9).cash_mills,
            0
        );
    }

    #[test]
    fn closing_a_long_realizes_the_price_difference() {
        let mut state = MatcherState::with_default_listings();
        // Account 9 buys 10 at 100, then sells all 10 at 110.
        state
            .apply_message(&new_order_for(1, 7, Side::Sell, 100.0, 10.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(2, 9, Side::Buy, 100.0, 10.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(3, 8, Side::Buy, 110.0, 10.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(4, 9, Side::Sell, 110.0, 10.0))
            .expect("test messages arrive in feed order");

        let pos = position(&state, 9);
        assert_eq!(pos.net_qty_tenths, 0);
        assert_eq!(pos.cost_basis_mills, 0);
        assert_eq!(mills_to_f64(pos.realized_mills), 100.0); // 10 units * 10.0 gain
        // The position is back to zero units, so cash alone is the profit.
        assert_eq!(mills_to_f64(pos.cash_mills), 100.0);
    }

    #[test]
    fn closing_a_short_realizes_the_price_difference() {
        let mut state = MatcherState::with_default_listings();
        // Account 7 sells 10 at 100, then buys it back at 90.
        state
            .apply_message(&new_order_for(1, 7, Side::Sell, 100.0, 10.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(2, 9, Side::Buy, 100.0, 10.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(3, 8, Side::Sell, 90.0, 10.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(4, 7, Side::Buy, 90.0, 10.0))
            .expect("test messages arrive in feed order");

        let pos = position(&state, 7);
        assert_eq!(pos.net_qty_tenths, 0);
        assert_eq!(mills_to_f64(pos.realized_mills), 100.0); // sold high, bought low
    }

    #[test]
    fn selling_past_flat_flips_to_a_short_at_the_new_price() {
        let mut state = MatcherState::with_default_listings();
        // Account 9 buys 10 at 100, then sells 15 at 110.
        state
            .apply_message(&new_order_for(1, 7, Side::Sell, 100.0, 10.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(2, 9, Side::Buy, 100.0, 10.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(3, 8, Side::Buy, 110.0, 15.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(4, 9, Side::Sell, 110.0, 15.0))
            .expect("test messages arrive in feed order");

        let pos = position(&state, 9);
        assert_eq!(pos.net_qty_tenths, to_tenths(-5.0)); // -5 units held
        assert_eq!(mills_to_f64(pos.realized_mills), 100.0); // only the closed 10 counts
        // The new -5 units are carried at 110, not at the old 100.
        assert_eq!(pos.cost_basis_mills, to_tenths(5.0) * to_cents(110.0));
    }

    /// The reported average price must be in the same units as the prices the
    /// sequencer publishes. It must not be in cents or in mills.
    #[test]
    fn avg_entry_price_is_reported_in_price_units() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order_for(1, 7, Side::Sell, 10.02, 2.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(2, 9, Side::Sell, 10.04, 2.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(3, 8, Side::Buy, 10.10, 4.0))
            .expect("test messages arrive in feed order");

        // Bought 2 at 10.02 and 2 at 10.04, so the average is 10.03.
        let pos = position(&state, 8);
        assert_eq!(pos.net_qty_tenths, to_tenths(4.0));
        assert_eq!(pos.avg_entry_price(), Some(10.03));
        // A position of zero units has no average to report.
        assert_eq!(Position::default().avg_entry_price(), None);
    }

    #[test]
    fn open_position_is_marked_at_the_last_trade_price() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order_for(1, 7, Side::Sell, 100.0, 10.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(2, 9, Side::Buy, 100.0, 10.0))
            .expect("test messages arrive in feed order");

        let pos = position(&state, 9);
        assert_eq!(pos.realized_mills, 0); // nothing closed yet
        assert_eq!(mills_to_f64(pos.unrealized_mills(to_cents(110.0))), 100.0);
        assert_eq!(mills_to_f64(pos.unrealized_mills(to_cents(95.0))), -50.0);
        assert_eq!(pos.unrealized_mills(to_cents(100.0)), 0); // marked at cost
    }

    /// Total profit has two independent formulas. One is cash plus the value
    /// of what the account still holds. The other is the closed profit plus
    /// the open profit. The two must agree for every account, after any
    /// sequence of fills.
    #[test]
    fn the_two_pnl_formulas_agree() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order_for(1, 7, Side::Sell, 100.0, 10.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(2, 9, Side::Buy, 100.0, 6.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(3, 8, Side::Buy, 101.0, 4.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(4, 9, Side::Sell, 101.0, 9.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(5, 8, Side::Buy, 102.0, 5.0))
            .expect("test messages arrive in feed order");

        let mark = to_cents(102.0);
        for account in [7, 8, 9] {
            let pos = position(&state, account);
            let by_cash = pos.cash_mills + pos.net_qty_tenths * mark;
            let by_pnl = pos.realized_mills + pos.unrealized_mills(mark);
            assert_eq!(by_cash, by_pnl, "account {} disagrees", account);
        }

        // Trading adds up to zero. Another account sold every unit bought.
        let total: i64 = state
            .positions
            .values()
            .map(|p| p.cash_mills + p.net_qty_tenths * mark)
            .sum();
        assert_eq!(total, 0);
    }

    #[test]
    fn fifo_within_a_price_level() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order(1, Side::Sell, 100.0, 1.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order(2, Side::Sell, 100.0, 1.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order(3, Side::Buy, 100.0, 1.0))
            .expect("test messages arrive in feed order");

        assert_eq!(state.trades.len(), 1);
        assert_eq!(state.trades[0].maker_order, 1); // oldest order fills first
    }

    #[test]
    fn bounded_candle_projection_matches_the_backwards_builder() {
        let trades = vec![
            Trade {
                trade_id: 1,
                symbol: "ETH-USDC".to_string(),
                price: 100.0,
                quantity: 2.0,
                maker_order: 1,
                maker_account: 7,
                taker_order: 2,
                taker_account: 9,
                taker_side: Side::Buy,
                timestamp: 2_000,
            },
            Trade {
                trade_id: 2,
                symbol: "ETH-USDC".to_string(),
                price: 101.0,
                quantity: 1.0,
                maker_order: 3,
                maker_account: 8,
                taker_order: 4,
                taker_account: 9,
                taker_side: Side::Buy,
                timestamp: 4_000,
            },
            Trade {
                trade_id: 3,
                symbol: "ETH-USDC".to_string(),
                price: 99.0,
                quantity: 3.0,
                maker_order: 5,
                maker_account: 8,
                taker_order: 6,
                taker_account: 9,
                taker_side: Side::Buy,
                timestamp: 61_000,
            },
        ];
        let mut cache = CandleCache::default();
        for (trade, (price_cents, qty_tenths)) in
            trades.iter().zip([(10_000, 20), (10_100, 10), (9_900, 30)])
        {
            cache.record(&trade.symbol, trade.timestamp, price_cents, qty_tenths);
        }
        let cached = cache
            .newest("ETH-USDC", 15, 150)
            .expect("a valid projection");

        let mut oracle = CandleTail::new(15_000, 150);
        for trade in trades.iter().rev() {
            assert!(oracle.push(trade.timestamp, trade.price, trade.quantity));
        }
        let oracle = oracle.finish();
        let shape = |rows: &[Candle]| {
            rows.iter()
                .map(|row| {
                    (
                        row.start,
                        row.open.to_bits(),
                        row.high.to_bits(),
                        row.low.to_bits(),
                        row.close.to_bits(),
                        row.volume.to_bits(),
                        row.trades,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(shape(&cached), shape(&oracle));
    }

    #[test]
    fn candle_projection_keeps_fills_the_recent_trade_window_evicts() {
        let mut trades = VecDeque::new();
        let mut total = 0;
        let mut candles = CandleCache::default();
        let made = TRADE_WINDOW as u64 + 1;
        for trade_id in 1..=made {
            MatcherState::push_trade(
                &mut trades,
                &mut total,
                &mut candles,
                Trade {
                    trade_id,
                    symbol: "ETH-USDC".to_string(),
                    price: 100.0,
                    quantity: 0.1,
                    maker_order: trade_id,
                    maker_account: 7,
                    taker_order: trade_id + made,
                    taker_account: 9,
                    taker_side: Side::Buy,
                    timestamp: trade_id * 15_000,
                },
                10_000,
                1,
            );
        }

        assert_eq!(total, made);
        assert_eq!(trades.len(), TRADE_WINDOW);
        assert_eq!(trades.front().expect("a recent trade").trade_id, 2);
        let rows = candles
            .newest("ETH-USDC", 15, MAX_CANDLES)
            .expect("a valid projection");
        assert_eq!(rows.len(), MAX_CANDLES);
        assert_eq!(
            rows.first().expect("the oldest retained candle").start,
            (made - MAX_CANDLES as u64 + 1) * 15_000
        );
        assert_eq!(
            rows.last().expect("the newest retained candle").start,
            made * 15_000
        );
    }

    #[tokio::test]
    async fn candles_bucket_trades_into_ohlcv() {
        let mut state = MatcherState::with_default_listings();
        // Two trades inside one 15s bucket, one trade in the next.
        state
            .apply_message(&new_order_for(1, 7, Side::Sell, 100.0, 2.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(2, 9, Side::Buy, 100.0, 2.0))
            .expect("test messages arrive in feed order"); // t=2000, @100
        state
            .apply_message(&new_order_for(3, 8, Side::Sell, 101.0, 1.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(4, 9, Side::Buy, 101.0, 1.0))
            .expect("test messages arrive in feed order"); // t=4000, @101
        state
            .apply_message(&OrderMessage::New {
                id: 5,
                timestamp: 16_000,
                account: 8,
                symbol: "ETH-USDC".to_string(),
                side: Side::Sell,
                price: 99.0,
                quantity: 3.0,
                nonce: None,
                order_type: Default::default(),
                time_in_force: Default::default(),
                post_only: false,
            })
            .expect("test messages arrive in feed order");
        state
            .apply_message(&OrderMessage::New {
                id: 6,
                timestamp: 16_500,
                account: 9,
                symbol: "ETH-USDC".to_string(),
                side: Side::Buy,
                price: 99.0,
                quantity: 3.0,
                nonce: None,
                order_type: Default::default(),
                time_in_force: Default::default(),
                post_only: false,
            })
            .expect("test messages arrive in feed order");

        // The test calls the handler, so it covers the backwards walk the
        // endpoint really does. It does not call a builder that nothing else
        // uses.
        let state = Arc::new(Mutex::new(state));
        let candles = get_candles(
            State(api(&state)),
            Query(CandlesQuery {
                symbol: "ETH-USDC".to_string(),
                interval: Some(15),
                n: None,
            }),
        )
        .await
        .expect("two buckets")
        .0;
        assert_eq!(candles.len(), 2);

        let first = &candles[0];
        assert_eq!(first.start, 0);
        assert_eq!(first.open, 100.0);
        assert_eq!(first.high, 101.0);
        assert_eq!(first.low, 100.0);
        assert_eq!(first.close, 101.0);
        assert_eq!(first.volume, 3.0);
        assert_eq!(first.trades, 2);

        let second = &candles[1];
        assert_eq!(second.start, 15_000);
        assert_eq!(second.open, 99.0);
        assert_eq!(second.close, 99.0);
        assert_eq!(second.trades, 1);
    }

    /// `n` counts buckets, and the answer has no hole in it.
    ///
    /// The market here trades in the bucket that starts at 0 and then again in
    /// the bucket that starts at 60,000, with nothing between. The answer holds
    /// the three empty buckets between them, each one flat at 101, which is the
    /// price the market stood at while nobody traded.
    ///
    /// The second request asks for 3 buckets. There is a trade below those 3, so
    /// the answer is exactly 3 buckets and it starts 3 bucket widths back from
    /// the newest one. The two empty buckets at the start open at 101, which is
    /// the price of that trade below the range.
    ///
    /// This is the bug the page had. `n` used to count only the buckets that
    /// hold a trade, so this market answered 2 candles for any `n` above 1, and
    /// the page drew 5. Every window number the page worked out counted candles,
    /// so every one of them was wrong by that ratio.
    #[tokio::test]
    async fn candles_count_buckets_and_fill_the_empty_ones() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order_for(1, 7, Side::Sell, 100.0, 2.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(2, 9, Side::Buy, 100.0, 2.0))
            .expect("test messages arrive in feed order"); // t=2000, @100
        state
            .apply_message(&new_order_for(3, 8, Side::Sell, 101.0, 1.0))
            .expect("test messages arrive in feed order");
        state
            .apply_message(&new_order_for(4, 9, Side::Buy, 101.0, 1.0))
            .expect("test messages arrive in feed order"); // t=4000, @101
        for (id, account, side, timestamp) in [
            (5, 8, Side::Sell, 60_000),
            (6, 9, Side::Buy, 61_000), // t=61000, @99
        ] {
            state
                .apply_message(&OrderMessage::New {
                    id,
                    timestamp,
                    account,
                    symbol: "ETH-USDC".to_string(),
                    side,
                    price: 99.0,
                    quantity: 3.0,
                    nonce: None,
                    order_type: Default::default(),
                    time_in_force: Default::default(),
                    post_only: false,
                })
                .expect("test messages arrive in feed order");
        }
        let state = Arc::new(Mutex::new(state));

        let whole = get_candles(
            State(api(&state)),
            Query(CandlesQuery {
                symbol: "ETH-USDC".to_string(),
                interval: Some(15),
                n: None,
            }),
        )
        .await
        .expect("candles")
        .0;
        let shape: Vec<(u64, f64, f64, u64)> = whole
            .iter()
            .map(|c| (c.start, c.open, c.close, c.trades))
            .collect();
        assert_eq!(
            shape,
            vec![
                (0, 100.0, 101.0, 2),
                (15_000, 101.0, 101.0, 0),
                (30_000, 101.0, 101.0, 0),
                (45_000, 101.0, 101.0, 0),
                (60_000, 99.0, 99.0, 1),
            ]
        );
        for candle in &whole {
            assert!(candle.high >= candle.low);
            assert_eq!(candle.volume == 0.0, candle.trades == 0);
        }

        let three = get_candles(
            State(api(&state)),
            Query(CandlesQuery {
                symbol: "ETH-USDC".to_string(),
                interval: Some(15),
                n: Some(3),
            }),
        )
        .await
        .expect("candles")
        .0;
        let shape: Vec<(u64, f64, f64, u64)> = three
            .iter()
            .map(|c| (c.start, c.open, c.close, c.trades))
            .collect();
        assert_eq!(
            shape,
            vec![
                (30_000, 101.0, 101.0, 0),
                (45_000, 101.0, 101.0, 0),
                (60_000, 99.0, 99.0, 1),
            ],
            "exactly the buckets asked for, and the oldest ones stand at the \
             price of the trade below the range"
        );
    }

    /// A cancel names only a target id. Without a check on who owns the order,
    /// any account could take another account's order off the book.
    #[test]
    fn a_cancel_from_another_account_is_refused() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order_for(1, 7, Side::Sell, 100.0, 5.0))
            .expect("in order");
        state
            .apply_message(&cancel_from(2, 9, 1))
            .expect("in order");

        assert_eq!(state.cancels_applied, 0);
        assert_eq!(state.cancels_ignored, 0);
        assert_eq!(state.cancels_rejected, 1);
        // The order still waits in the book, and an arriving order can still
        // match it.
        assert_eq!(open_orders(&state, Side::Sell), 1);
        state
            .apply_message(&new_order_for(3, 8, Side::Buy, 100.0, 5.0))
            .expect("in order");
        assert_eq!(state.trades.len(), 1);

        // The owner can still cancel its own order.
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order_for(1, 7, Side::Sell, 100.0, 5.0))
            .expect("in order");
        state
            .apply_message(&cancel_from(2, 7, 1))
            .expect("in order");
        assert_eq!(state.cancels_applied, 1);
        assert_eq!(state.cancels_rejected, 0);
        assert_eq!(open_orders(&state, Side::Sell), 0);
    }

    /// A repeated `New` message would put a second copy of the same order in
    /// the book. Only one of the two copies could ever be cancelled.
    #[test]
    fn a_repeated_or_skipped_message_is_not_applied() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&new_order(1, Side::Sell, 100.0, 5.0))
            .expect("in order");

        let replay = state.apply_message(&new_order(1, Side::Sell, 100.0, 5.0));
        assert_eq!(
            replay,
            Err(ApplyError::OutOfOrder {
                expected: 2,
                got: 1
            })
        );
        let gap = state.apply_message(&new_order(7, Side::Sell, 100.0, 5.0));
        assert_eq!(
            gap,
            Err(ApplyError::OutOfOrder {
                expected: 2,
                got: 7
            })
        );

        // Neither message changed the book, the cursor, or the counters.
        assert_eq!(open_orders(&state, Side::Sell), 1);
        assert_eq!(state.last_seen, 1);
        assert_eq!(state.messages_processed, 1);
        // And the next real message still applies.
        state
            .apply_message(&new_order(2, Side::Buy, 100.0, 5.0))
            .expect("in order");
        assert_eq!(state.trades.len(), 1);
    }

    /// The exchange opens a book only for a symbol the log lists. Any other
    /// symbol would let a submitter put a string of their choice into the
    /// state root, and would add a book nobody trades.
    #[test]
    fn an_unlisted_symbol_is_refused() {
        let mut state = MatcherState::with_default_listings();
        state
            .apply_message(&OrderMessage::New {
                id: 1,
                timestamp: 1000,
                account: 7,
                symbol: "ETH-USDC|9|0|0|0".to_string(),
                side: Side::Buy,
                price: 100.0,
                quantity: 5.0,
                nonce: None,
                order_type: Default::default(),
                time_in_force: Default::default(),
                post_only: false,
            })
            .expect("in order");

        assert_eq!(state.orders_ignored, 1);
        assert!(state.books.is_empty());
        assert!(state.open_orders.is_empty());
        // The engine still read the message, so the cursor keeps moving.
        assert_eq!(state.last_seen, 1);
    }

    /// Two different states must never hash to the same root. The root is what
    /// the tamper check and the resume check compare. Two states with one root
    /// would let somebody swap one state for the other, and no check would see
    /// it.
    #[test]
    fn the_state_root_cannot_be_collided_through_a_field_separator() {
        // One position whose symbol carries what looks like the end of its
        // own record and the start of another.
        let mut smuggled = MatcherState::with_default_listings();
        smuggled
            .positions
            .insert((1, "X|0|0|0|0\nP|2|Y".to_string()), Position::default());
        // Two ordinary positions that the old `format!` encoding wrote as
        // exactly the same bytes.
        let mut honest = MatcherState::with_default_listings();
        honest
            .positions
            .insert((1, "X".to_string()), Position::default());
        honest
            .positions
            .insert((2, "Y".to_string()), Position::default());

        // The old encoding really did write the two states as the same bytes.
        let old_encoding = |state: &MatcherState| {
            let mut keys: Vec<&(AccountId, String)> = state.positions.keys().collect();
            keys.sort();
            keys.iter()
                .map(|key| {
                    let p = &state.positions[*key];
                    format!(
                        "P|{}|{}|{}|{}|{}|{}\n",
                        key.0,
                        key.1,
                        p.net_qty_tenths,
                        p.cash_mills,
                        p.cost_basis_mills,
                        p.realized_mills
                    )
                })
                .collect::<String>()
        };
        assert_eq!(old_encoding(&smuggled), old_encoding(&honest));
        assert_ne!(smuggled.state_root(), honest.state_root());
    }

    /// Twenty positions with keys chosen to be hard to sort.
    ///
    /// Account 2 and account 10 catch an account number read as text. As text,
    /// "10" sorts before "2". As a number, 2 sorts before 10. `ETH` and
    /// `ETH-USDC` catch a symbol whose bytes are the start of another symbol.
    /// `Z` and `a` catch a sort that ignores upper and lower case, because `Z`
    /// is byte 90 and `a` is byte 97. The two symbols that hold `|` and a
    /// newline are the pair the old `format!` encoding could not tell apart.
    /// The last two hold bytes above 127. A sort on characters and a sort on
    /// bytes can disagree about those bytes.
    fn awkward_positions() -> MatcherState {
        let mut state = MatcherState::with_default_listings();
        let keys: [(AccountId, &str); 20] = [
            (0, "ETH-USDC"),
            (0, "ETH"),
            (0, "ETH-USDD"),
            (0, ""),
            (1, "Z"),
            (1, "a"),
            (1, "ZZ"),
            (2, "BTC-USDC"),
            (10, "BTC-USDC"),
            (10, "BTC-USDB"),
            (2, "X|0|0|0|0\nP|2|Y"),
            (2, "X"),
            (3, "AAAAAAAAAAAAAAAA1"),
            (3, "AAAAAAAAAAAAAAAA0"),
            (3, "AAAAAAAAAAAAAAAA"),
            (u32::MAX, "MERKLE-USDC"),
            (u32::MAX - 1, "MERKLE-USDC"),
            (7, "\u{00e9}TH"),
            (7, "eTH"),
            (7, "\u{10330}"),
        ];
        for (index, (account, symbol)) in keys.into_iter().enumerate() {
            state.positions.insert(
                (account, symbol.to_string()),
                Position {
                    net_qty_tenths: index as i64 - 7,
                    cash_mills: index as i64 * 31 - 100,
                    cost_basis_mills: index as i64 * 17,
                    realized_mills: 5 - index as i64 * 3,
                },
            );
        }
        assert_eq!(state.positions.len(), 20, "every key is a different key");
        state
    }

    /// The order `state_root` puts positions in has not moved.
    ///
    /// The root below was measured on the build before the sort changed. That
    /// build used the same twenty positions, the same encoding, the old
    /// `Vec<&(AccountId, String)>` and `sort()`. The new sort copies the
    /// account number and the symbol into the list and compares the copies.
    /// That gives the same order at a different cost. If the two sorts ever
    /// disagree, this value is what says so. A root that has moved is worse
    /// than a root that is slow.
    #[test]
    fn the_state_root_orders_positions_the_way_it_always_did() {
        const AWKWARD_POSITIONS_ROOT: &str =
            "cff3dc12f2580f6274bcb1850af505928d22138dd08a57b6e2e7245299ec05af";
        let state = awkward_positions();
        assert_eq!(
            logchain::to_hex(&state.state_root()),
            AWKWARD_POSITIONS_ROOT,
            "the positions are hashed in a different order than they were"
        );

        // The same positions, put into the map in the opposite order. A map
        // hands its keys back in any order it likes. Two engines that hold the
        // same state reach one root only because the root sorts the keys.
        let mut reversed = MatcherState::with_default_listings();
        let mut pairs: Vec<((AccountId, String), Position)> = state
            .positions
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        pairs.sort_by(|left, right| right.0.cmp(&left.0));
        for (key, position) in pairs {
            reversed.positions.insert(key, position);
        }
        assert_eq!(reversed.state_root(), state.state_root());
    }

    /// The books and positions the old `state_root` covered, hashed the way
    /// that version hashed them.
    ///
    /// The function is written out here once. It lets the claim "every order
    /// before the change still executes identically" be checked against a
    /// value the running exchange already published, and not against a value
    /// taken from this build. It is `state_root` without the symbol registry
    /// and with the old version string, and nothing else. So a difference
    /// between the two is a difference in the books, the positions or the
    /// cursor. The rule-set block is missing from both under rule set 1, and
    /// every history checked against this function runs under rule set 1.
    ///
    /// The function stops being useful as soon as it disagrees, and that is
    /// the point. On the day the six steps execute the live page differently,
    /// this function is what says so. Two tests read it: the live 500-message
    /// page, and the three-order history whose root was measured before either
    /// rule existed.
    fn state_root_v2(state: &MatcherState) -> [u8; 32] {
        fn field(hasher: &mut Sha256, bytes: &[u8]) {
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        let mut hasher = Sha256::new();
        field(&mut hasher, b"exchange-state-v2");
        hasher.update(state.last_seen.to_le_bytes());
        let mut symbols: Vec<&String> = state.books.keys().collect();
        symbols.sort();
        hasher.update((symbols.len() as u64).to_le_bytes());
        for symbol in symbols {
            field(&mut hasher, symbol.as_bytes());
            let book = &state.books[symbol];
            for (tag, side) in [(0u8, &book.bids), (1u8, &book.asks)] {
                hasher.update([tag]);
                let orders: u64 = side.values().map(|level| level.len() as u64).sum();
                hasher.update(orders.to_le_bytes());
                for (price, level) in side {
                    for order in level {
                        hasher.update(price.to_le_bytes());
                        hasher.update(order.id.to_le_bytes());
                        hasher.update(order.account.to_le_bytes());
                        hasher.update(order.qty_tenths.to_le_bytes());
                    }
                }
            }
        }
        let mut holders: Vec<&(AccountId, String)> = state.positions.keys().collect();
        holders.sort();
        hasher.update((holders.len() as u64).to_le_bytes());
        for key in holders {
            let position = &state.positions[key];
            hasher.update(key.0.to_le_bytes());
            field(&mut hasher, key.1.as_bytes());
            hasher.update(position.net_qty_tenths.to_le_bytes());
            hasher.update(position.cash_mills.to_le_bytes());
            hasher.update(position.cost_basis_mills.to_le_bytes());
            hasher.update(position.realized_mills.to_le_bytes());
        }
        hasher.finalize().into()
    }

    /// The 500 real messages of the running sequencer, replayed through the
    /// six steps, must reach the books and positions they have always reached.
    ///
    /// `logchain.rs` proves this build writes those messages as the bytes the
    /// sequencer published. This test proves this build executes them the same
    /// way: same books, same positions, same open orders, hashed into one
    /// value.
    ///
    /// **This is part 2 of the listings goal, over a real history.** The claim
    /// "every order before the change still executes identically" is checked
    /// against `d48006b2…`. That is the value the exchange reached over this
    /// page before the symbol registry existed. Step 1 asks a different
    /// question now: it asks the registry instead of a constant. This page
    /// names three symbols, and all three are listed on the steps every symbol
    /// has always used. So step 1 must give the same answer to every one of
    /// the 500 messages.
    ///
    /// The root itself moved, and only the root. The root now covers the
    /// registry and says `exchange-state-v4`. Two engines with equal roots
    /// must match every future message identically. Two engines that hold
    /// these same books over different registries do not.
    ///
    /// The root moved a second time when the tag went from `exchange-state-v3`
    /// to `exchange-state-v4`. The tag is the only cause here, and this test
    /// checks that instead of stating it. This page holds no operator message.
    /// So the engine below names no operator, and the operator key adds
    /// nothing to the bytes hashed. The books, the positions and the registry
    /// are the same ones, and `d48006b2…` is still reached under the old
    /// encoding.
    ///
    /// The messages arrive the way a poll delivers them. They are bytes off a
    /// page, framed by `split_ndjson`, hashed as they arrived and parsed
    /// separately. So this test also walks the path a real consumer walks.
    #[test]
    fn replaying_the_live_page_reaches_the_state_root_it_always_did() {
        const LIVE_PAGE: &str = include_str!("testdata/live-500.ndjson");
        // Session 349d462ced25bb2b, the chain the sequencer signed over these
        // 500 messages. `logchain.rs` holds the same value, and the Merkle
        // root beside it.
        const LIVE_CHAIN_500: &str =
            "bf2768dbe1de80be58d51cb0242142af6eceecefc5d0d2e3e36bbde6c138e6a9";
        // Measured on the build before `OrderMessage` grew the three order
        // terms and the three kinds. That measurement used a worktree at the
        // parent commit, the same fixture and the same replay. The value was
        // the same then, and it is the same now under `state_root_v2`, which
        // is that build's encoding of the books and the positions.
        const LIVE_BOOKS_AND_POSITIONS_500: &str =
            "d48006b2bcdc30fb0f8ac71c164d70328abc06b226a43fc5b13c6c8a738a9d4e";
        // The same state under this build's root, which also covers the three
        // listings the engine below was given. The value was
        // 257d8910a5486aa61d76dce4274fc9c505806b942592afa0369398d6d27f1a05
        // under `exchange-state-v3`. The tag is the whole of the difference,
        // and the assertions below are what show that.
        const LIVE_STATE_ROOT_500: &str =
            "d7207cf1146fffa1e9e4a4787a2912984e12cf1519780c003190146d062d9daa";

        let received = wire::split_ndjson(LIVE_PAGE.as_bytes()).expect("the page the feed served");
        assert_eq!(received.len(), 500);

        // The same page read the way the engine reads it, with one parse per
        // line. Both readings must produce the same 500 messages, the same
        // bytes and the same envelopes. A difference would mean the engine and
        // every other consumer read two different histories out of one page.
        let read_once =
            wire::read_ndjson::<OrderMessage>(LIVE_PAGE.as_bytes()).expect("the same page");
        assert_eq!(read_once.len(), 500);
        for (raw, read) in received.iter().zip(&read_once) {
            assert_eq!(*raw, read.raw, "the two readings disagree about a message");
            let twice: OrderMessage = raw.parse().expect("this build reads the live page");
            let once = read
                .parsed
                .as_ref()
                .expect("this build reads the live page");
            assert_eq!(
                logchain::canonical_bytes(&twice),
                logchain::canonical_bytes(once),
                "message {} reads as two different messages",
                raw.id
            );
        }

        // The three symbols this page names, listed on 0.01 and 0.1. Those are
        // the steps the sequencer has published on since message 1. A real
        // history says this in `ListSymbol` messages. This fixture is older
        // than those messages, and that is exactly why it is the history worth
        // checking the change against.
        let mut engine = MatcherState::with_default_listings();
        for raw in &received {
            let message: OrderMessage = raw.parse().expect("this build reads the live page");
            assert!(
                matches!(
                    message,
                    OrderMessage::New { .. } | OrderMessage::Cancel { .. }
                ),
                "message {} is an operator message, so the root below moved for \
                 more than the tag",
                raw.id
            );
            engine
                .apply_received(raw, &message)
                .unwrap_or_else(|e| panic!("message {} was refused: {:?}", raw.id, e));
        }

        assert_eq!(engine.messages_processed, 500);
        assert_eq!(
            engine.operator_key(),
            None,
            "this page names no operator, so the key hashes into nothing"
        );
        assert_eq!(
            engine.kinds_not_acted_on(),
            0,
            "the live page holds nothing this build walks past"
        );
        assert_eq!(
            logchain::to_hex(&engine.feed_chain.expect("following a chain")),
            LIVE_CHAIN_500
        );
        assert_eq!(
            logchain::to_hex(&state_root_v2(&engine)),
            LIVE_BOOKS_AND_POSITIONS_500,
            "the registry changed how the six steps execute the same 500 messages"
        );
        assert_eq!(
            logchain::to_hex(&engine.state_root()),
            LIVE_STATE_ROOT_500,
            "the six steps reached a different state over the same 500 messages"
        );
    }

    /// The engine executes every message kind it reads, and
    /// `kinds_not_acted_on` stays at zero.
    ///
    /// This test used to work the other way round. It listed the kinds the
    /// engine read and did not act on, and it checked that each of them moved
    /// nothing but the message number. That list is empty now. `EngineRule`
    /// left the list when the self-trade rule arrived. `ListSymbol` and
    /// `DelistSymbol` left it when the symbol registry arrived.
    ///
    /// The counter stays, and so does the claim it carries. A count above zero
    /// means this binary's books are not the books a build that executed that
    /// kind would hold. A sixth kind added to `OrderMessage` and not executed
    /// here makes this test fail. That failure is where the notice has to
    /// start.
    ///
    /// The engine is the one program that must not stop on a kind it cannot
    /// execute, because it serves the books to a browser. `verify.rs` makes
    /// the opposite choice for the opposite reason. `verify.rs` reports and
    /// does not serve, so it ends the run with exit code 3.
    #[test]
    fn every_kind_this_build_reads_is_executed() {
        let history = [
            engine_rule(1, 1),
            list_symbol(2, "ETH-USDC"),
            new_order_for(3, 7, Side::Buy, 100.0, 5.0),
            cancel_from(4, 7, 3),
            delist_symbol(5, "ETH-USDC"),
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

        let state = replay(&history);
        assert_eq!(
            state.kinds_not_acted_on(),
            0,
            "a kind this build reads landed in the counter for kinds it does not"
        );
        assert_eq!(state.messages_processed, 5);
        // Each message did what it is for. The engine read the rule set,
        // opened the symbol and traded it, rested the order, took the order
        // out on the cancel, and closed the market.
        assert_eq!(state.rules.version(), 1);
        assert!(state.symbols.ever_listed("ETH-USDC"));
        assert!(!state.is_listed("ETH-USDC"));
        assert_eq!(state.cancels_applied, 1);
        assert_eq!(state.orders_ignored(), 0);
        assert_eq!(state.listings_ignored(), 0);
        assert!(state.open_orders.is_empty());
    }

    /// The running totals are i64. A fill at the largest price and quantity
    /// the steps allow is 1e18 mills. Ten such fills do not fit in an i64. The
    /// exchange must refuse the tenth fill. It must not let the total wrap
    /// around.
    #[test]
    fn a_fill_that_would_overflow_a_position_is_refused() {
        // 1e8 units at 1e7 each: the largest order the steps accept.
        let (quantity, price) = (100_000_000.0, 10_000_000.0);
        let mut state = MatcherState::with_default_listings();
        let mut id = 0;
        for _ in 0..10 {
            id += 1;
            state
                .apply_message(&new_order_for(id, 7, Side::Sell, price, quantity))
                .expect("in order");
            id += 1;
            state
                .apply_message(&new_order_for(id, 9, Side::Buy, price, quantity))
                .expect("in order");
        }

        // Nine fills fit. The exchange refuses the whole of the tenth.
        assert_eq!(state.trades.len(), 9);
        assert_eq!(state.orders_ignored, 1);
        assert_eq!(
            position(&state, 9).cash_mills,
            -9 * 1_000_000_000_000_000_000
        );
        assert_eq!(
            position(&state, 7).cash_mills,
            9 * 1_000_000_000_000_000_000
        );
        // The refused buy never rested. The sell order it could not take is
        // still in the book with its full quantity.
        assert_eq!(open_orders(&state, Side::Buy), 0);
        assert_eq!(open_orders(&state, Side::Sell), 1);
        assert_eq!(
            state.level_qty_tenths("ETH-USDC", Side::Sell, 1_000_000_000),
            1_000_000_000
        );
        // Reading profit off an engine at this size must not panic either.
        let (realized, unrealized) = state.account_pnl_mills(9);
        assert_eq!(realized, 0);
        assert!(unrealized <= 0);
    }

    /// The engine must compute the same chain over messages that carry a
    /// submitter's nonce as the sequencer computed when it signed them.
    ///
    /// This needs a test of its own, because the engine never reads the nonce.
    /// `apply_message` ignores the nonce. A consumer that computed the chain
    /// from only the fields it uses would call an honest sequencer a liar, as
    /// soon as one real signed submission appeared in the history. Here the
    /// engine builds the chain one message at a time, instead of over the
    /// whole list at once, and that is the case most likely to drop a field.
    #[test]
    fn a_nonce_bearing_history_produces_the_chain_the_feed_signed() {
        let with_nonce =
            |id: OrderId, nonce: &str| match new_order_for(id, 7, Side::Buy, 100.0, 5.0) {
                OrderMessage::New {
                    id,
                    timestamp,
                    account,
                    symbol,
                    side,
                    price,
                    quantity,
                    order_type,
                    time_in_force,
                    post_only,
                    ..
                } => OrderMessage::New {
                    id,
                    timestamp,
                    account,
                    symbol,
                    side,
                    price,
                    quantity,
                    nonce: Some(nonce.to_string()),
                    order_type,
                    time_in_force,
                    post_only,
                },
                other => other,
            };
        let messages = vec![
            new_order_for(1, 7, Side::Buy, 100.0, 5.0),
            with_nonce(2, "9f2b1c04d7e58a36bb0147fe29c3d580"),
            OrderMessage::Cancel {
                id: 3,
                timestamp: 3000,
                account: 7,
                target_id: 2,
                nonce: Some("1d47a90fe3b25c8871face0426b9d013".to_string()),
            },
        ];
        // The sequencer's own chain, over the messages as published.
        let signed = messages
            .iter()
            .fold(EMPTY_CHAIN, |chain, msg| logchain::extend(&chain, msg));

        // The engine's chain, built one message at a time as it reads them. It
        // is built over the bytes the sequencer published, which is how the
        // messages really arrive.
        let received = served(&messages);
        let mut state = MatcherState::with_default_listings();
        for read in &received {
            state
                .apply_received(
                    &read.raw,
                    read.parsed.as_ref().expect("this build knows these"),
                )
                .expect("in order");
        }
        assert_eq!(
            state.feed_chain,
            Some(signed),
            "the engine must not dispute an honest feed over a field it does not read"
        );

        // A batch that carries that head is accepted, not refused.
        let mut state = MatcherState::with_default_listings();
        let head = SignedHead {
            last_id: 3,
            chain: signed,
            public_key: String::new(),
            signature: Signature::from_bytes(&[0u8; 64]),
        };
        apply_batch(&mut state, &received, &head).expect("the chain agrees");
        assert_eq!(state.feed_chain_mismatches, 0);
        assert_eq!(state.last_seen, 3);
    }

    /// A head that does not match the messages beside it means the sequencer
    /// serves one history and signs another. The engine must not apply any
    /// part of that batch.
    #[test]
    fn a_batch_whose_chain_does_not_match_the_signed_head_is_refused() {
        let messages = vec![
            new_order_for(1, 7, Side::Sell, 100.0, 5.0),
            new_order_for(2, 9, Side::Buy, 100.0, 5.0),
        ];
        let chain = messages
            .iter()
            .fold(EMPTY_CHAIN, |chain, msg| logchain::extend(&chain, msg));
        let head = |last_id, chain| SignedHead {
            last_id,
            chain,
            public_key: String::new(),
            signature: Signature::from_bytes(&[0u8; 64]),
        };

        let received = served(&messages);
        // The chain the sequencer signed is not the chain these messages
        // produce.
        let mut state = MatcherState::with_default_listings();
        let refused = apply_batch(&mut state, &received, &head(2, EMPTY_CHAIN));
        assert!(matches!(refused, Err(BatchRejection::ChainMismatch { .. })));
        assert_eq!(state.last_seen, 0);
        assert_eq!(state.messages_processed, 0);
        assert!(state.trades.is_empty());
        assert!(state.books.is_empty());
        assert!(state.pending.is_none() || state.pending.as_ref().unwrap().is_empty());
        assert_eq!(state.feed_chain_mismatches, 1);

        // The mismatch stays visible. The same batch refused again counts
        // again.
        let refused = apply_batch(&mut state, &received, &head(2, EMPTY_CHAIN));
        assert!(refused.is_err());
        assert_eq!(state.feed_chain_mismatches, 2);

        // A head that stops short of the batch covers none of it.
        let short = apply_batch(&mut state, &received, &head(1, chain));
        assert!(matches!(
            short,
            Err(BatchRejection::HeadDoesNotCover { .. })
        ));
        assert_eq!(state.last_seen, 0);

        // Ids that do not continue the cursor are refused before anything is
        // applied, even when the head agrees with them.
        let gapped = vec![
            new_order_for(2, 7, Side::Sell, 100.0, 5.0),
            new_order_for(3, 9, Side::Buy, 100.0, 5.0),
        ];
        let gapped_chain = gapped
            .iter()
            .fold(EMPTY_CHAIN, |chain, msg| logchain::extend(&chain, msg));
        let refused = apply_batch(&mut state, &served(&gapped), &head(3, gapped_chain));
        assert!(matches!(refused, Err(BatchRejection::OutOfOrder(_))));
        assert_eq!(state.last_seen, 0);
        assert_eq!(state.feed_integrity_failures, 1);

        // The honest batch applies and marks the position as verified.
        apply_batch(&mut state, &received, &head(2, chain)).expect("the batch is the signed one");
        assert_eq!(state.last_seen, 2);
        assert_eq!(state.trades.len(), 1);
        assert_eq!(state.chain_verified_at, 2);
    }

    /// A message kind this build cannot execute is refused as exactly that. It
    /// is never refused as the sequencer having rewritten its history.
    ///
    /// The engine executes every message it reads, so it really cannot go past
    /// message 2 here. Skipping message 2 would leave every book after it
    /// missing whatever that message did. What the engine must not do is call
    /// an honest sequencer a forger. The chain over these bytes matched the
    /// signed head. This refusal says so, and leaves the mismatch counter
    /// alone. An operator who reads the refusal is told to upgrade the
    /// exchange, and not to investigate the sequencer.
    #[test]
    fn a_message_this_build_cannot_execute_is_refused_as_too_old_not_as_tampering() {
        let market = br#"{"Market":{"id":2,"timestamp":2000,"account":7,"symbol":"ETH-USDC","side":"Buy","quantity":3.0}}"#;
        let mut body = Vec::new();
        body.extend_from_slice(&logchain::canonical_bytes(&new_order_for(
            1,
            7,
            Side::Sell,
            100.0,
            5.0,
        )));
        body.push(b'\n');
        body.extend_from_slice(market);
        body.push(b'\n');
        let received =
            wire::read_ndjson::<OrderMessage>(&body).expect("the feed serves one message per line");

        // The sequencer is honest. The head it signed is the chain over
        // exactly these bytes.
        let chain = received.iter().fold(EMPTY_CHAIN, |chain, msg| {
            logchain::extend_bytes(&chain, &msg.raw.bytes)
        });
        let head = SignedHead {
            last_id: 2,
            chain,
            public_key: String::new(),
            signature: Signature::from_bytes(&[0u8; 64]),
        };

        let mut state = MatcherState::with_default_listings();
        let refused = apply_batch(&mut state, &received, &head);

        let Err(rejection) = refused else {
            panic!("a message this build cannot read must not be applied");
        };
        let BatchRejection::CannotInterpret(too_old) = &rejection else {
            panic!("expected a refusal naming the message, got {:?}", rejection);
        };
        assert_eq!(too_old.id, 2);
        assert_eq!(too_old.kind, "Market");
        assert_eq!(
            state.feed_chain_mismatches, 0,
            "an honest feed must not be counted as having served a history it did not sign"
        );
        assert_eq!(state.feed_integrity_failures, 0);
        assert_eq!(
            state.last_seen, 0,
            "nothing is applied, not even the message before the unreadable one"
        );
        let text = rejection.to_string();
        assert!(text.contains("cannot interpret message 2"), "{}", text);
        assert!(text.contains("history is intact"), "{}", text);
    }

    /// `interval` arrives from the query string with no limit on its size. The
    /// old code multiplied it before it checked it. The multiply wrapped to
    /// zero, and the divide by zero happened while the code held the engine
    /// lock. That poisoned the lock for every other endpoint.
    #[tokio::test]
    async fn an_out_of_range_candle_interval_is_an_error_not_a_panic() {
        let state = Arc::new(Mutex::new(MatcherState::with_default_listings()));

        let crafted = get_candles(
            State(api(&state)),
            Query(CandlesQuery {
                symbol: "ETH-USDC".to_string(),
                interval: Some(u64::MAX / 1000 + 1),
                n: None,
            }),
        )
        .await;
        let (status, _) = crafted.expect_err("an interval this large has no candles to build");
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let zero = get_candles(
            State(api(&state)),
            Query(CandlesQuery {
                symbol: "ETH-USDC".to_string(),
                interval: Some(0),
                n: None,
            }),
        )
        .await;
        assert_eq!(
            zero.expect_err("a zero-width bucket is not a bucket").0,
            StatusCode::BAD_REQUEST
        );

        let unmaintained = get_candles(
            State(api(&state)),
            Query(CandlesQuery {
                symbol: "ETH-USDC".to_string(),
                interval: Some(2000),
                n: None,
            }),
        )
        .await;
        assert_eq!(
            unmaintained
                .expect_err("an interval with no bounded projection is refused")
                .0,
            StatusCode::BAD_REQUEST
        );

        // The engine still works after the errors. Nothing poisoned the
        // lock.
        let ok = get_candles(
            State(api(&state)),
            Query(CandlesQuery {
                symbol: "ETH-USDC".to_string(),
                interval: Some(15),
                n: None,
            }),
        )
        .await;
        assert!(ok.is_ok());
    }

    /// The count is a count of validators, not a count of answers. One process
    /// can serve three URLs. That is easy to do by accident, because every
    /// validator uses the same database filename by default, and therefore the
    /// same key. Three such URLs leave one entry here, and one entry is not the
    /// two validators that must agree.
    #[test]
    fn one_key_answering_several_urls_counts_once_toward_quorum() {
        let needed = quorum(3);
        assert_eq!(needed, 2);

        let one_key: HashMap<String, OrderId> = [("key-a".to_string(), 9)].into();
        assert_eq!(
            quorum_position(&one_key, needed),
            None,
            "one validator listed three times reached a quorum of two"
        );

        let three_keys: HashMap<String, OrderId> = [
            ("key-a".to_string(), 9),
            ("key-b".to_string(), 9),
            ("key-c".to_string(), 7),
        ]
        .into();
        assert_eq!(quorum_position(&three_keys, needed), Some(9));

        // Two validators must agree, so the second highest position is the
        // highest position that two validators stand behind.
        let trailing: HashMap<String, OrderId> =
            [("key-a".to_string(), 9), ("key-b".to_string(), 4)].into();
        assert_eq!(quorum_position(&trailing, needed), Some(4));

        assert_eq!(quorum_position(&HashMap::new(), needed), None);
        // A list with no validator in it vouches for nothing. It does not
        // panic on `needed - 1`.
        assert_eq!(quorum_position(&three_keys, quorum(0)), None);
    }

    // -----------------------------------------------------------------
    // Counting ordering attestations
    // -----------------------------------------------------------------

    /// An engine that has read `messages`, in the state the poll loop leaves
    /// it in. The chain checkpoint at each message comes from `apply_message`.
    fn engine_at(messages: &[OrderMessage]) -> MatcherState {
        let mut state = MatcherState::with_default_listings();
        for msg in messages {
            state.apply_message(msg).expect("the history is in order");
        }
        state
    }

    fn chain_of(messages: &[OrderMessage]) -> Chain {
        messages
            .iter()
            .fold(EMPTY_CHAIN, |chain, msg| logchain::extend(&chain, msg))
    }

    /// Serves one fixed attestation on a real port, the way a validator does.
    /// The counting loop under test fetches over HTTP, parses and verifies
    /// exactly as it does in production. The test chooses only what the
    /// validator says.
    async fn mock_validator(attestation: crate::validator::Attestation) -> String {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("a port");
        let addr = listener.local_addr().expect("an address");
        let app = Router::new().route(
            "/attest",
            get(move || {
                let attestation = attestation.clone();
                async move { Json(attestation) }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{}", addr)
    }

    /// Signs an attestation the way a validator does, over whatever the test
    /// wants it to say.
    fn signed_attestation(
        key: &ed25519_dalek::SigningKey,
        session: &str,
        last_id: OrderId,
        chain: &Chain,
    ) -> crate::validator::Attestation {
        let status = AttestStatus::default();
        let signature = logchain::sign_attest(key, session, last_id, chain, &status);
        crate::validator::Attestation {
            validator: logchain::to_hex(key.verifying_key().as_bytes()),
            session: session.to_string(),
            last_id,
            chain: logchain::to_hex(chain),
            signature: logchain::to_hex(&signature.to_bytes()),
            disputed: false,
            stalled: false,
            unchecked_polls: 0,
        }
    }

    /// Runs the real counting loop against real validators on real ports for
    /// long enough to take one round, and reports what it counted.
    async fn count_one_round(
        engine: MatcherState,
        attestations: Vec<crate::validator::Attestation>,
    ) -> (u64, OrderId) {
        let mut urls = Vec::new();
        for attestation in attestations {
            urls.push(mock_validator(attestation).await);
        }
        let shared = Arc::new(Mutex::new(engine));
        let counting = Arc::clone(&shared);
        let task = tokio::spawn(async move { poll_validators(counting, urls).await });
        // The loop sleeps before its first round. So this wait must outlast
        // one sleep and one round of requests to loopback. It can take more
        // than one round on a busy machine. That is why the assertions below
        // say *which* counter moved, and not how far it moved.
        sleep(Duration::from_millis(1200)).await;
        task.abort();
        let state = lock_state(&shared);
        (state.validator_disputes, state.quorum_verified_at)
    }

    /// The counting loop end to end, over real HTTP. Enough validators that
    /// followed the same history move `quorum_verified_at` forward. A
    /// validator that was served a different history is counted as a dispute,
    /// and moves nothing forward. An operator who reads `/market` sees which
    /// of the two happened.
    #[tokio::test]
    async fn a_live_quorum_advances_and_a_history_dispute_is_counted() {
        let messages = [
            new_order(1, Side::Sell, 100.0, 5.0),
            new_order(2, Side::Buy, 100.0, 5.0),
        ];
        let session = "one-history";
        let honest_chain = chain_of(&messages);

        // Three validators that agree. The verified position moves to their
        // position, and nothing is counted against any validator.
        let mut engine = engine_at(&messages);
        engine.feed_session = Some(session.to_string());
        let agreeing: Vec<_> = (0..3)
            .map(|_| signed_attestation(&logchain::ephemeral_key(), session, 2, &honest_chain))
            .collect();
        let (disputes, quorum_at) = count_one_round(engine, agreeing).await;
        assert_eq!(disputes, 0);
        assert_eq!(quorum_at, 2);

        // One validator that was served a different history. That is a
        // dispute, and no position has enough validators behind it.
        let mut engine = engine_at(&messages);
        engine.feed_session = Some(session.to_string());
        let other_history = [
            new_order(1, Side::Sell, 101.0, 5.0),
            new_order(2, Side::Buy, 101.0, 5.0),
        ];
        let wrong_chain = signed_attestation(
            &logchain::ephemeral_key(),
            session,
            2,
            &chain_of(&other_history),
        );
        let (disputes, quorum_at) = count_one_round(engine, vec![wrong_chain]).await;
        assert!(
            disputes >= 1,
            "a different history has to be counted as a dispute"
        );
        assert_eq!(quorum_at, 0);
    }

    /// The position is inside the signature, so a proxy between a validator
    /// and this engine cannot change it. An edit makes the whole attestation
    /// fail to verify. The engine counts that as a dispute. It never treats
    /// the edited value as something the validator said.
    #[tokio::test]
    async fn an_edited_attestation_fails_the_signature_rather_than_being_believed() {
        let messages = [new_order(1, Side::Buy, 100.0, 5.0)];
        let session = "one-history";
        let mut engine = engine_at(&messages);
        engine.feed_session = Some(session.to_string());

        let mut tampered =
            signed_attestation(&logchain::ephemeral_key(), session, 1, &chain_of(&messages));
        tampered.chain = logchain::to_hex(&[7u8; 32]);

        let (disputes, quorum_at) = count_one_round(engine, vec![tampered]).await;
        assert!(
            disputes >= 1,
            "an attestation that does not verify has to be refused"
        );
        assert_eq!(quorum_at, 0);
    }

    /// An exchange with no anchor is a deployment somebody runs on purpose. So
    /// the endpoint answers 404 instead of failing. The page reads 404 as "no
    /// anchor" and hides the section.
    #[tokio::test]
    async fn anchor_config_is_404_when_this_exchange_is_anchored_to_nothing() {
        assert_eq!(load_anchor_config(None), None, "no ANCHOR_CONFIG set");

        let dir = tempfile::TempDir::new().expect("temp dir");
        let missing = dir.path().join("nowhere.json");
        assert_eq!(
            load_anchor_config(Some(missing.display().to_string())),
            None,
            "a file that is not there"
        );
        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, "{not json").expect("written");
        assert_eq!(
            load_anchor_config(Some(broken.display().to_string())),
            None,
            "a file that is not a deployment"
        );

        let engine = Arc::new(Mutex::new(MatcherState::with_default_listings()));
        let (status, _) = get_anchor_config(State(api(&engine)))
            .await
            .expect_err("nothing to serve");
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// With a real deployment file behind it, the endpoint serves the seven
    /// things a browser needs to read the anchor itself. It serves nothing
    /// else from that file.
    ///
    /// This pins the shape of the answer, which is why it is the test that
    /// failed when `rpc` became `rpcs`. That is the test working: a browser
    /// reads these names, and a field that quietly changes name is a browser
    /// that quietly stops reading the chain.
    #[tokio::test]
    async fn anchor_config_serves_the_deployment_the_browser_needs() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("deployment.json");
        std::fs::write(
            &path,
            r#"{"contract":"ExchangeAnchor",
                "address":"0x2A4A287EC1F01b5bCb5568D2Ed0765Faf860a62b",
                "chain_id":84532,
                "rpc":"https://sepolia.base.org",
                "tx_hash":"0x26bd",
                "block_number":45495043,
                "writer":"0x6192D3FD82917eAb2864F46cb63b69bC8C6E09CE",
                "anchor_interval_seconds":300}"#,
        )
        .expect("written");

        let anchor = load_anchor_config(Some(path.display().to_string())).expect("a deployment");
        let engine = Arc::new(Mutex::new(MatcherState::with_default_listings()));
        let state = ApiState {
            anchor: Some(anchor),
            ..api(&engine)
        };
        let served = get_anchor_config(State(state)).await.expect("a config").0;
        assert_eq!(
            serde_json::to_value(&served).unwrap(),
            serde_json::json!({
                "address": "0x2A4A287EC1F01b5bCb5568D2Ed0765Faf860a62b",
                "chain_id": 84532,
                "chain_name": "Base Sepolia",
                // A list, and one long here: this file names no fallbacks.
                "rpcs": ["https://sepolia.base.org"],
                "explorer": "https://sepolia.basescan.org",
                "deployed_block": 45495043,
                "writer": "0x6192D3FD82917eAb2864F46cb63b69bC8C6E09CE"
            }),
            "the chain name and explorer come from the chain id, and the rest of the \
             deployment file is not the browser's business"
        );

        // A chain this code does not know is named by its id, and gets no
        // explorer at all. It does not get a link into another chain's
        // explorer.
        let path = dir.path().join("unknown-chain.json");
        std::fs::write(
            &path,
            r#"{"address":"0xabc","chain_id":31337,"rpc":"http://127.0.0.1:8545",
                "block_number":1,"writer":"0xdef"}"#,
        )
        .expect("written");
        let anchor = load_anchor_config(Some(path.display().to_string())).expect("a deployment");
        assert_eq!(anchor.chain_name, "chain 31337");
        assert_eq!(anchor.explorer, None);
        assert!(
            !serde_json::to_string(&anchor).unwrap().contains("explorer"),
            "an absent explorer is omitted, not null"
        );
    }

    // ---------------------------------------------------------------------
    // Listings. PLAN.md step 4, stated as a test:
    //
    //   A market can be opened and closed while the exchange runs, and
    //   everyone who replays the log gets the same answer.
    //
    // `DelistSymbol` is correct when all three of these hold, and each one is
    // checked on its own below:
    //
    //   1. new orders for that symbol are refused after it;
    //   2. every order before it still executes identically;
    //   3. the state root over the whole history is the same for anyone,
    //      whatever binary they run.
    // ---------------------------------------------------------------------

    /// A history that opens a market, trades in it, and closes it.
    ///
    /// Message 1 lists ETH-USDC. Messages 2 and 3 match and leave a trade and
    /// a position. Message 4 leaves a sell order in the book that nobody
    /// takes. Message 5 delists the symbol.
    fn open_trade_close() -> Vec<OrderMessage> {
        vec![
            list_symbol(1, "ETH-USDC"),
            new_order_for(2, 7, Side::Buy, 100.0, 5.0),
            new_order_for(3, 8, Side::Sell, 100.0, 5.0),
            new_order_for(4, 9, Side::Sell, 101.0, 3.0),
            delist_symbol(5, "ETH-USDC"),
        ]
    }

    fn replay(messages: &[OrderMessage]) -> MatcherState {
        let mut state = MatcherState::new();
        for msg in messages {
            state
                .apply_message(msg)
                .unwrap_or_else(|e| panic!("message {} was refused: {:?}", msg.id(), e));
        }
        state
    }

    /// Part 1. After the delist, the exchange refuses an order for that
    /// symbol. The refused order does not put a book back in the map.
    #[test]
    fn part_1_a_delisted_symbol_takes_no_new_order() {
        let mut state = replay(&open_trade_close());
        assert!(!state.is_listed("ETH-USDC"));
        let ignored_before = state.orders_ignored();

        state
            .apply_message(&new_order_for(6, 7, Side::Buy, 100.0, 5.0))
            .expect("the message is consumed either way");

        assert_eq!(
            state.orders_ignored(),
            ignored_before + 1,
            "the order after the delist was not refused"
        );
        assert!(
            !state.books.contains_key("ETH-USDC"),
            "a refused order must not open a book for a symbol nobody lists"
        );
        assert!(state.open_orders.is_empty());
        assert_eq!(state.last_seen, 6, "and the message is still consumed");
    }

    /// Part 2. Everything that happened before the delist is exactly what it
    /// was: the trade, the two positions, and the trade count.
    ///
    /// A delist stops new orders. It does not erase a history.
    #[test]
    fn part_2_every_order_before_the_delist_still_executed_identically() {
        let history = open_trade_close();
        // The same history with the delist removed. That is what the exchange
        // held one message earlier.
        let before = replay(&history[..history.len() - 1]);
        let after = replay(&history);

        assert_eq!(after.trades_total(), before.trades_total());
        assert_eq!(after.trades_total(), 1, "messages 2 and 3 crossed");
        assert_eq!(
            after.trade(1).map(|t| (t.price, t.quantity)),
            before.trade(1).map(|t| (t.price, t.quantity)),
            "the trade the delisted market made is still the trade it made"
        );
        assert_eq!(
            after.positions, before.positions,
            "the positions that trade moved are still moved"
        );
        assert_eq!(after.position_of(7, "ETH-USDC").0, 50);
        assert_eq!(after.position_of(8, "ETH-USDC").0, -50);
        assert_eq!(
            after.last_trade_cents("ETH-USDC"),
            Some(10_000),
            "and the market's last price is still readable"
        );
        // One thing did change. The sell order waiting at 101.00 is gone, and
        // nothing else.
        assert_eq!(before.open_orders.len(), 1);
        assert!(after.open_orders.is_empty());
        assert_eq!(after.orders_delisted(), 1);
    }

    /// Part 3, first half. The same history replayed twice reaches the same
    /// root, over a history that lists and delists.
    #[test]
    fn part_3_a_history_with_a_list_and_a_delist_replays_to_the_same_root_twice() {
        let history = open_trade_close();
        assert_eq!(
            logchain::to_hex(&replay(&history).state_root()),
            logchain::to_hex(&replay(&history).state_root())
        );
    }

    /// Part 3, second half, and the whole point of the change. **The answer
    /// comes from the log and not from the binary.**
    ///
    /// Two histories over symbols that the constant `domain::SYMBOLS`
    /// disagrees with, replayed by an engine that reads no constant at all:
    ///
    /// - `ZULU-USD` is in no build's `SYMBOLS`. An order for it trades,
    ///   because the log listed it.
    /// - `BTC-USDC` is in every build's `SYMBOLS`. An order for it is refused,
    ///   because the log did not list it.
    ///
    /// Under the old rule the first order was refused and the second traded.
    /// That was the measured bug. Removing `ETH-USDC` from the constant moved
    /// the state root of the same 2,480-message log, and ignored 613 orders.
    #[test]
    fn part_3_the_answer_comes_from_the_log_and_not_from_the_constant() {
        let unknown_to_every_binary = "ZULU-USD";
        assert!(
            !crate::domain::SYMBOLS
                .iter()
                .any(|(known, _, _)| *known == unknown_to_every_binary),
            "this test needs a symbol no build was compiled with"
        );

        let listed_only_in_the_log = replay(&[
            list_symbol(1, unknown_to_every_binary),
            order_on(2, 7, unknown_to_every_binary, Side::Buy, 100.0, 5.0),
        ]);
        assert_eq!(listed_only_in_the_log.orders_ignored(), 0);
        assert_eq!(
            listed_only_in_the_log.best_bid_cents(unknown_to_every_binary),
            Some(10_000),
            "the log listed it, so it trades, whatever the binary was built with"
        );

        let in_the_constant_but_not_in_the_log =
            replay(&[order_on(1, 7, "BTC-USDC", Side::Buy, 100.0, 5.0)]);
        assert_eq!(
            in_the_constant_but_not_in_the_log.orders_ignored(),
            1,
            "the constant lists BTC-USDC and the log does not; the log decides"
        );
        assert!(in_the_constant_but_not_in_the_log.books.is_empty());
    }

    /// The exchange refuses an order for a symbol nobody listed, and opens no
    /// book for it.
    ///
    /// The old `SYMBOLS` check had this property, and the property had to
    /// survive the change. A sequencer must not be able to invent a symbol and
    /// put a string of its choice into the state root.
    #[test]
    fn an_order_for_a_symbol_never_listed_is_refused_and_opens_no_book() {
        let mut state = MatcherState::new();
        state
            .apply_message(&order_for_symbol(1, "MADE-UP"))
            .expect("consumed");
        assert_eq!(state.orders_ignored(), 1);
        assert!(state.books.is_empty(), "no book for a symbol nobody listed");
        assert!(state.open_orders.is_empty());
        // And the root does not carry the string either.
        assert_eq!(
            logchain::to_hex(&state.state_root()),
            logchain::to_hex(&{
                let mut empty = MatcherState::new();
                empty.last_seen = 1;
                empty.state_root()
            })
        );
    }

    /// A delist takes out every waiting order in that book, on both sides. It
    /// takes out nothing in any other book.
    #[test]
    fn a_delist_cancels_every_resting_order_in_that_book_and_none_in_another() {
        let mut state = replay(&[
            list_symbol(1, "ETH-USDC"),
            list_symbol(2, "BTC-USDC"),
            // Two buy orders and two sell orders on the symbol that closes, at
            // two prices each. That covers both sides and more than one price
            // level.
            new_order_for(3, 7, Side::Buy, 99.0, 1.0),
            new_order_for(4, 7, Side::Buy, 98.0, 1.0),
            new_order_for(5, 8, Side::Sell, 101.0, 1.0),
            new_order_for(6, 8, Side::Sell, 102.0, 1.0),
            // And one of each on the symbol that stays.
            order_on(7, 9, "BTC-USDC", Side::Buy, 900.0, 1.0),
            order_on(8, 9, "BTC-USDC", Side::Sell, 1100.0, 1.0),
        ]);
        assert_eq!(state.open_orders.len(), 6);

        state
            .apply_message(&delist_symbol(9, "ETH-USDC"))
            .expect("consumed");

        assert_eq!(state.orders_delisted(), 4, "both sides, both levels");
        assert_eq!(
            state.open_orders.len(),
            2,
            "the two BTC-USDC orders are untouched"
        );
        for id in 3..=6 {
            assert!(
                state.open_order(id).is_none(),
                "order {} is still open after its market closed",
                id
            );
        }
        assert_eq!(state.best_bid_cents("BTC-USDC"), Some(90_000));
        assert_eq!(state.best_ask_cents("BTC-USDC"), Some(110_000));
        assert_eq!(
            state.cancels_applied, 0,
            "a delist is not a cancel anyone sent"
        );
    }

    /// A delist that empties a book must leave no book behind.
    ///
    /// ENGINE.md section 4.0: `state_root` asserts that no empty book is in
    /// the map. A restored engine rebuilds the books from the orders that are
    /// open, so it would hold no empty book. That assertion is a
    /// `debug_assert`, so this test states the same thing where a release
    /// build can see it too.
    #[test]
    fn state_root_never_sees_an_empty_book_after_a_delist() {
        let state = replay(&open_trade_close());
        assert!(
            !state.books.contains_key("ETH-USDC"),
            "the delisted book is gone, not left empty"
        );
        assert!(
            !state
                .books
                .values()
                .any(|book| book.bids.is_empty() && book.asks.is_empty()),
            "an empty book is in the map"
        );
        // The same check for the one case where a delist removes no book: a
        // symbol that never had a book.
        let never_traded = replay(&[list_symbol(1, "ETH-USDC"), delist_symbol(2, "ETH-USDC")]);
        assert!(never_traded.books.is_empty());
        never_traded.state_root();
    }

    /// A relisted symbol trades again. The orders sent while the market was
    /// closed stay ignored.
    #[test]
    fn a_relisted_symbol_trades_again_and_the_orders_in_between_stay_ignored() {
        let mut state = replay(&[
            list_symbol(1, "ETH-USDC"),
            new_order_for(2, 7, Side::Buy, 100.0, 5.0),
            delist_symbol(3, "ETH-USDC"),
            // Refused: the market is closed here.
            new_order_for(4, 7, Side::Buy, 100.0, 5.0),
            list_symbol(5, "ETH-USDC"),
            new_order_for(6, 7, Side::Buy, 100.0, 5.0),
        ]);
        assert_eq!(state.orders_ignored(), 1, "only message 4");
        assert_eq!(
            state.open_order(6).map(|(_, _, price, qty)| (price, qty)),
            Some((10_000, 50)),
            "the order after the relisting rests"
        );
        assert!(state.open_order(2).is_none(), "the delist took it out");
        assert!(state.open_order(4).is_none(), "and 4 never rested");
        assert_eq!(state.open_orders.len(), 1);

        // The market really is open. A sell order at the same price fills
        // against the buy order.
        state
            .apply_message(&new_order_for(7, 8, Side::Sell, 100.0, 5.0))
            .expect("consumed");
        assert_eq!(state.trades_total(), 1);
    }

    /// The price step and the quantity step come from the listing. They do not
    /// come from one setting shared by every symbol.
    #[test]
    fn an_order_off_the_symbol_s_own_step_is_refused() {
        let state = replay(&[
            list_symbol_on(1, "ETH-USDC", 0.05, 0.5),
            // Two thousand steps of 0.05 and ten steps of 0.5: accepted.
            new_order_for(2, 7, Side::Buy, 100.0, 5.0),
            // A whole number of cents, and not a whole number of 0.05.
            new_order_for(3, 7, Side::Buy, 100.03, 5.0),
            // A whole number of tenths, and not a whole number of 0.5.
            new_order_for(4, 7, Side::Buy, 100.0, 5.2),
        ]);
        assert_eq!(state.orders_ignored(), 2);
        assert_eq!(state.open_orders.len(), 1);
        assert!(state.open_order(2).is_some());
    }

    /// A listing this engine cannot represent lists nothing. The engine counts
    /// the listing once, and not once for every order after it.
    ///
    /// The books hold whole cents and whole tenths. So a price step of 0.001
    /// names prices no book can hold. A symbol listed on that step would be
    /// listed and unable to take a single order.
    #[test]
    fn a_listing_on_a_step_no_book_can_hold_lists_nothing() {
        let state = replay(&[
            list_symbol_on(1, "ETH-USDC", 0.001, 0.1),
            list_symbol_on(2, "BTC-USDC", 0.01, 0.01),
            new_order_for(3, 7, Side::Buy, 100.0, 5.0),
        ]);
        assert_eq!(
            state.listings_ignored(),
            2,
            "both steps are unrepresentable"
        );
        assert!(!state.is_listed("ETH-USDC"));
        assert!(!state.is_listed("BTC-USDC"));
        assert_eq!(state.orders_ignored(), 1, "so the order is refused too");
        assert!(state.listed_symbols().is_empty());
    }

    /// A listing whose symbol breaks the name rule lists nothing. The engine
    /// counts the listing once, and not once for every order after it.
    ///
    /// ENGINE.md section 4.0: 1 to 32 characters, each one `A`-`Z`, `0`-`9` or
    /// `-`. A symbol is hashed into every state root after it, and no message
    /// can take it out again. So the only place to refuse a bad name is here.
    #[test]
    fn a_listing_whose_name_breaks_the_rule_lists_nothing() {
        let state = replay(&[
            list_symbol_on(1, "eth-usdc", 0.01, 0.1),
            order_on(2, 7, "eth-usdc", Side::Buy, 100.0, 5.0),
        ]);
        assert_eq!(state.listings_ignored(), 1, "the listing, once");
        assert!(!state.is_listed("eth-usdc"));
        assert!(state.listed_symbols().is_empty());
        assert_eq!(
            state.orders_ignored(),
            1,
            "and the order after it finds no market"
        );
        assert!(state.open_orders.is_empty());
    }

    /// The edges of the name rule, in the exchange.
    ///
    /// 32 characters is a name. 33 characters is not. An empty name is not a
    /// name. Nor is a name with lower case letters, a space or a dot.
    #[test]
    fn the_name_rule_takes_32_characters_and_only_a_z_0_9_and_a_dash() {
        let longest = "BTC-USDC-2026-12-31-SETTLED-0001";
        assert_eq!(longest.len(), 32, "the test data is the boundary");
        let too_long = "BTC-USDC-2026-12-31-SETTLED-00012";
        assert_eq!(too_long.len(), 33);
        let state = replay(&[
            list_symbol_on(1, longest, 0.01, 0.1),
            list_symbol_on(2, too_long, 0.01, 0.1),
            list_symbol_on(3, "", 0.01, 0.1),
            list_symbol_on(4, "btc-usdc", 0.01, 0.1),
            list_symbol_on(5, "BTC USDC", 0.01, 0.1),
            list_symbol_on(6, "BTC.USDC", 0.01, 0.1),
        ]);
        assert_eq!(state.listed_symbols(), vec![longest.to_string()]);
        assert_eq!(state.listings_ignored(), 5, "the other five");
    }

    /// A second listing of a symbol already listed changes nothing. A delist
    /// of a symbol that is not listed changes nothing.
    ///
    /// The engine counts both. Neither may move the steps under orders that
    /// already wait in the book. Neither may close a market that was never
    /// open.
    #[test]
    fn a_repeated_listing_and_a_delist_of_nothing_are_refused_and_counted() {
        let state = replay(&[
            list_symbol_on(1, "ETH-USDC", 0.01, 0.1),
            new_order_for(2, 7, Side::Buy, 100.03, 5.0),
            // These steps would forbid the order that already waits above.
            list_symbol_on(3, "ETH-USDC", 0.05, 0.5),
            delist_symbol(4, "BTC-USDC"),
        ]);
        assert_eq!(state.listings_ignored(), 2);
        assert_eq!(
            state.orders_ignored(),
            0,
            "the order was fine when it arrived"
        );
        assert_eq!(
            state.open_order(2).map(|(_, _, price, _)| price),
            Some(10_003),
            "and it is still resting where it rested"
        );
        assert_eq!(state.listed_symbols(), vec!["ETH-USDC".to_string()]);
        assert_eq!(state.orders_delisted(), 0);
    }

    // ENGINE.md section 3.1: the log names its operator, and every operator
    // message after that must be signed by the key the log already named.

    /// The first operator message names the key. A later message that names
    /// another key is ignored, however good the signature under that other key
    /// is.
    ///
    /// This is the whole rule in one history. The other account's listing
    /// verifies perfectly under that account's own key, and that is what makes
    /// it the case worth holding. The signed statement covers the prefix, the
    /// session, the symbol, the steps and the nonce. It never covers the
    /// `public_key` field. So a message that names a second key shows nothing
    /// at all about that key. A sequencer that could open a market this way
    /// would be the operator.
    #[test]
    fn a_later_operator_message_naming_another_key_is_ignored() {
        let stranger = SigningKey::from_bytes(&[9u8; 32]);
        let theirs = signed_by_operator(
            &stranger,
            OrderMessage::ListSymbol {
                id: 2,
                timestamp: 2000,
                account: OPERATOR_ACCOUNT,
                symbol: "BTC-USDC".to_string(),
                price_step: 0.01,
                quantity_step: 0.1,
                nonce: operator_nonce(2),
                public_key: String::new(),
                signature: String::new(),
            },
        );
        // The stranger really did sign it, under the key it names.
        assert!(
            operator::verify(&theirs, TEST_SESSION, &stranger.verifying_key()).is_ok(),
            "the test data is a message with a good signature under its own key"
        );

        let state = replay(&[list_symbol(1, "ETH-USDC"), theirs]);
        assert_eq!(
            state.operator_key(),
            Some(logchain::to_hex(operator_key().verifying_key().as_bytes())),
            "message 1 named the operator and message 2 did not replace it"
        );
        assert_eq!(state.listed_symbols(), vec!["ETH-USDC".to_string()]);
        assert!(
            !state.is_listed("BTC-USDC"),
            "the stranger opened no market"
        );
        assert_eq!(state.listings_ignored(), 1, "and it is counted, once");
    }

    /// A message that names the right key and carries a signature that key did
    /// not make is ignored too.
    ///
    /// This is the other half of the same rule. The first message fixes the
    /// key. After that, both halves must hold: the message names the right
    /// key, and that key really made the signature.
    #[test]
    fn an_operator_message_the_named_key_did_not_sign_is_ignored() {
        // The operator signed this message over one symbol, and the test then
        // pointed it at another symbol. The key on it is the log's own key,
        // and the signature is a real one. The signature covers different
        // bytes.
        let signed = list_symbol(2, "BTC-USDC");
        let OrderMessage::ListSymbol {
            public_key,
            signature,
            ..
        } = signed.clone()
        else {
            panic!("it is a listing");
        };
        let moved = OrderMessage::ListSymbol {
            id: 2,
            timestamp: 2000,
            account: OPERATOR_ACCOUNT,
            symbol: "ZULU-USD".to_string(),
            price_step: 0.01,
            quantity_step: 0.1,
            nonce: operator_nonce(2),
            public_key,
            signature,
        };

        let state = replay(&[list_symbol(1, "ETH-USDC"), moved]);
        assert_eq!(state.listed_symbols(), vec!["ETH-USDC".to_string()]);
        assert!(!state.is_listed("ZULU-USD"));
        assert_eq!(state.listings_ignored(), 1);
    }

    /// The rule covers `EngineRule` as well. A refused `EngineRule` leaves the
    /// rule set where the log put it.
    ///
    /// `EngineRule` is the operator message with the widest effect. It decides
    /// how the exchange matches every message after it. A build that checked
    /// the two listing kinds and not this one would have left the most
    /// important of the three unchecked.
    #[test]
    fn an_engine_rule_the_operator_did_not_sign_does_not_move_the_rule_set() {
        let stranger = SigningKey::from_bytes(&[9u8; 32]);
        let theirs = signed_by_operator(
            &stranger,
            OrderMessage::EngineRule {
                id: 2,
                timestamp: 2000,
                account: OPERATOR_ACCOUNT,
                version: 2,
                nonce: operator_nonce(2),
                public_key: String::new(),
                signature: String::new(),
            },
        );
        let state = replay(&[list_symbol(1, "ETH-USDC"), theirs]);
        assert_eq!(
            state.rules.version(),
            RuleSet::GENESIS.version(),
            "a rule set nobody the log trusts asked for"
        );
        assert_eq!(state.listings_ignored(), 1);
        assert_eq!(
            state.kinds_not_acted_on(),
            0,
            "this build reads rule set 2; it refused who asked for it"
        );
    }

    /// An operator message with no nonce is ignored. Without a nonce there is
    /// no statement to check.
    ///
    /// The nonce is one line of the signed statement. Nobody can sign a
    /// message that has no nonce. So this is a refusal about the message, and
    /// not an internal error.
    #[test]
    fn an_operator_message_with_no_nonce_is_ignored() {
        let no_nonce = signed_by_operator(
            &operator_key(),
            OrderMessage::ListSymbol {
                id: 1,
                timestamp: 1000,
                account: OPERATOR_ACCOUNT,
                symbol: "ETH-USDC".to_string(),
                price_step: 0.01,
                quantity_step: 0.1,
                nonce: None,
                public_key: String::new(),
                signature: String::new(),
            },
        );
        let state = replay(&[no_nonce]);
        assert!(state.listed_symbols().is_empty());
        assert_eq!(state.listings_ignored(), 1);
        assert_eq!(
            state.operator_key(),
            None,
            "a message that did nothing names no operator, so the next one is still the first"
        );
    }

    /// Two engines that hold the same books under different operator keys do
    /// not share a state root.
    ///
    /// The reason is the reason the rule set is in the root. The two engines
    /// below accept different future operator messages. One opens the market
    /// the next `ListSymbol` names. The other ignores that message. Equal
    /// roots are supposed to mean two engines behave the same way.
    #[test]
    fn two_engines_under_different_operator_keys_have_different_roots() {
        let books = |key: &SigningKey| {
            let mut state = MatcherState::new();
            for message in [
                signed_by_operator(
                    key,
                    OrderMessage::ListSymbol {
                        id: 1,
                        timestamp: 1000,
                        account: OPERATOR_ACCOUNT,
                        symbol: "ETH-USDC".to_string(),
                        price_step: 0.01,
                        quantity_step: 0.1,
                        nonce: operator_nonce(1),
                        public_key: String::new(),
                        signature: String::new(),
                    },
                ),
                new_order_for(2, 7, Side::Buy, 100.0, 5.0),
            ] {
                state.apply_message(&message).expect("in feed order");
            }
            state
        };
        let ours = books(&operator_key());
        let theirs = books(&SigningKey::from_bytes(&[9u8; 32]));

        // The same book, the same registry, the same cursor.
        assert_eq!(ours.listed_symbols(), theirs.listed_symbols());
        assert_eq!(
            logchain::to_hex(&state_root_v2(&ours)),
            logchain::to_hex(&state_root_v2(&theirs)),
            "the test data is two engines whose books really are the same"
        );
        assert_ne!(ours.operator_key(), theirs.operator_key());
        assert_ne!(
            logchain::to_hex(&ours.state_root()),
            logchain::to_hex(&theirs.state_root()),
            "two engines that will accept different operator messages share a root"
        );
    }

    /// A delist ends the middle price its book was showing. The reference
    /// price is the price the exchange bounds a later market order against.
    /// That reference must come from the book that exists, and not from the
    /// book that closed.
    ///
    /// ENGINE.md 4.2.1 makes the reference a middle price weighted by time.
    /// The middle price is halfway between the best buy price and the best
    /// sell price. A delist is the third thing that moves a book. `apply_new`
    /// and the success path of `apply_cancel` are the other two. A delist
    /// moves a book harder than either, because it empties the book. Without a
    /// sample at the delist, the middle price from before the delist would go
    /// on counting for the rest of the window.
    ///
    /// Measured on the history below. With the sample the answer is 15,000.
    /// The value 10,000 held for the first second, nothing held for nineteen
    /// seconds, and 20,000 held for the last second. Without the sample,
    /// 10,000 would hold for twenty seconds and the answer would be 10,476.
    /// The closed market would then set the bound for the market that replaced
    /// it.
    #[test]
    fn a_delist_ends_the_mid_its_book_was_showing() {
        let at = |id: OrderId, ms: u64, side: Side, price: f64| OrderMessage::New {
            id,
            timestamp: ms,
            account: 7,
            symbol: "ETH-USDC".to_string(),
            side,
            price,
            quantity: 1.0,
            nonce: None,
            order_type: Default::default(),
            time_in_force: Default::default(),
            post_only: false,
        };
        // The two operator messages carry the millisecond this test chooses,
        // and not the millisecond the shared builders derive from the id. So
        // the test builds them here. It signs them here too, because the
        // engine ignores an operator message it cannot check.
        let delist_at = |id: OrderId, ms: u64| {
            signed_by_operator(
                &operator_key(),
                OrderMessage::DelistSymbol {
                    id,
                    timestamp: ms,
                    account: OPERATOR_ACCOUNT,
                    symbol: "ETH-USDC".to_string(),
                    nonce: operator_nonce(id),
                    public_key: String::new(),
                    signature: String::new(),
                },
            )
        };
        let list_at = |id: OrderId, ms: u64| {
            signed_by_operator(
                &operator_key(),
                OrderMessage::ListSymbol {
                    id,
                    timestamp: ms,
                    account: OPERATOR_ACCOUNT,
                    symbol: "ETH-USDC".to_string(),
                    price_step: 0.01,
                    quantity_step: 0.1,
                    nonce: operator_nonce(id),
                    public_key: String::new(),
                    signature: String::new(),
                },
            )
        };

        let state = replay(&[
            list_at(1, 0),
            // Orders wait on both sides, so the book shows a middle price of
            // 10,000.
            at(2, 0, Side::Buy, 99.0),
            at(3, 0, Side::Sell, 101.0),
            // One second later the market closes.
            delist_at(4, 1_000),
            // Nineteen seconds after that it opens again, twice as dear.
            list_at(5, 20_000),
            at(6, 20_000, Side::Buy, 199.0),
            at(7, 20_000, Side::Sell, 201.0),
        ]);

        assert_eq!(
            state.mids.reference_cents("ETH-USDC", 21_000),
            Some(15_000),
            "the closed book is still weighing into the reference price"
        );
    }

    /// The registry survives a resume. The record that a delisted symbol was
    /// once listed survives too.
    ///
    /// A resumed engine that forgot its listings would refuse every order
    /// after the resume point. It would say only "not a listed symbol" while
    /// it did so. `state_root` covers the registry, so the root check in
    /// `open_state` is what catches a `listings` table somebody edited behind
    /// the engine's back. This test walks that path end to end.
    #[test]
    fn a_resume_rebuilds_the_registry_the_log_built() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");

        let (root, run_id) = {
            let (mut store, _) = Store::open(&path, "http://feed", 200, false).expect("a store");
            let mut state = MatcherState::recording(&store);
            for msg in [
                list_symbol(1, "ETH-USDC"),
                list_symbol_on(2, "ZULU-USD", 0.05, 0.5),
                new_order_for(3, 7, Side::Buy, 100.0, 5.0),
                delist_symbol(4, "ZULU-USD"),
            ] {
                state.apply_message(&msg).expect("in feed order");
            }
            let pending = state.take_pending().expect("a recording engine");
            let claim = ClaimRow {
                from_msg: 1,
                to_msg: state.last_seen,
                root_before: MatcherState::new().state_root(),
                root_after: pending.root,
                trades_total: pending.trades_total,
                signature: Some([7u8; 64]),
            };
            store
                .commit(&pending.changes, &pending.counters, Some(&claim))
                .expect("committed");
            store.close_stopped().expect("closed");
            (state.state_root(), store.run_id())
        };

        let (store, snapshot) =
            Store::open_with_grace(&path, "http://feed", 0, false).expect("reopened");
        let snapshot = snapshot.expect("a resumable run");
        assert_eq!(store.run_id(), run_id);
        let mut state = MatcherState::restore(snapshot, &store);

        assert_eq!(
            state.state_root(),
            root,
            "the restored state hashes to what the previous life committed"
        );
        assert!(state.is_listed("ETH-USDC"), "and it can still trade");
        assert!(!state.is_listed("ZULU-USD"), "and it is still closed");
        assert!(
            state.symbols.ever_listed("ZULU-USD"),
            "and the log's record that it was once open survives"
        );

        // The engine goes on matching where it left off.
        state
            .apply_message(&new_order_for(5, 8, Side::Sell, 100.0, 5.0))
            .expect("in feed order");
        assert_eq!(state.orders_ignored(), 0);
        assert_eq!(state.trades_total(), 1);
    }
    // ---------------------------------------------------------------------
    // Throughput. How many messages a second this engine matches, measured
    // rather than estimated.
    //
    //   cargo test --release -- --ignored --nocapture measures_
    //
    // These tests are ignored by default. A number from a debug build is a
    // number about the debug build, and each test runs for tens of seconds.
    // Nothing here is a stand-in: the tests call `apply_message` and
    // `state_root`, which is what the poll loop calls. So what they time is
    // what the exchange runs.
    // ---------------------------------------------------------------------

    /// The symbol the throughput tests trade.
    const BENCH_SYMBOL: &str = "ETH-USDC";

    /// How many accounts send the messages. With eight accounts, an arriving
    /// order usually meets another account's order.
    const BENCH_ACCOUNTS: u64 = 8;

    /// The price the mix starts at, in cents.
    const BENCH_CENTER_CENTS: i64 = 10_000;

    /// A new order for the throughput tests, priced in whole cents.
    fn bench_order(
        id: OrderId,
        account: AccountId,
        side: Side,
        price_cents: i64,
        timestamp: u64,
    ) -> OrderMessage {
        OrderMessage::New {
            id,
            timestamp,
            account,
            symbol: BENCH_SYMBOL.to_string(),
            side,
            price: price_cents as f64 / 100.0,
            quantity: 1.0,
            nonce: None,
            order_type: Default::default(),
            time_in_force: Default::default(),
            post_only: false,
        }
    }

    /// A cancel for the throughput tests. It carries its own timestamp. The
    /// reference-price window reads the timestamps, and the tests below change
    /// how far apart the timestamps are.
    fn bench_cancel(
        id: OrderId,
        account: AccountId,
        target_id: OrderId,
        timestamp: u64,
    ) -> OrderMessage {
        OrderMessage::Cancel {
            id,
            timestamp,
            account,
            target_id,
            nonce: None,
        }
    }

    /// How many orders wait in all the books of `state`. `state_root` hashes
    /// that list, so this number sets what one root costs.
    fn bench_resting_orders(state: &MatcherState) -> usize {
        state
            .books
            .values()
            .map(|book| {
                let bids: usize = book.bids.values().map(|level| level.len()).sum();
                let asks: usize = book.asks.values().map(|level| level.len()).sum();
                bids + asks
            })
            .sum()
    }

    /// What one mix of messages turned out to be, counted while the mix was
    /// built.
    ///
    /// A generator cannot decide whether an order rests or trades. The book
    /// the order meets decides that. So the code builds the mix once on a
    /// throwaway engine, and that engine counts what every message did. The
    /// same messages are then timed on a fresh engine. The counts therefore
    /// describe the work that was timed.
    struct Mix {
        /// The messages that fill the book to its starting size. The code
        /// applies them before the clock starts.
        warmup: Vec<OrderMessage>,
        /// The messages under measurement.
        messages: Vec<OrderMessage>,
        /// New orders that joined the book.
        rested: u64,
        /// New orders that matched and traded.
        traded: u64,
        cancels_applied: u64,
        cancels_ignored: u64,
        /// Trades executed by the measured messages.
        trades: u64,
        /// Orders waiting in the book when the mix ends.
        resting: usize,
        /// Accounts holding a position when the mix ends.
        positions: usize,
    }

    impl Mix {
        /// The mix as one line, so every number printed below says which
        /// workload produced it.
        fn stated(&self) -> String {
            format!(
                "{} messages: {} orders rested, {} orders crossed and traded, {} cancels \
                 applied, {} cancels ignored; {} trades; {} resting orders and {} positions \
                 at the end",
                self.messages.len(),
                self.rested,
                self.traded,
                self.cancels_applied,
                self.cancels_ignored,
                self.trades,
                self.resting,
                self.positions,
            )
        }
    }

    /// A limit order priced inside the best price on the other side, so it
    /// joins the book and cannot trade.
    fn bench_resting_order(
        probe: &MatcherState,
        id: OrderId,
        account: AccountId,
        buying: bool,
        center_cents: i64,
        depth: i64,
        timestamp: u64,
    ) -> OrderMessage {
        if buying {
            let top = probe
                .best_ask_cents(BENCH_SYMBOL)
                .map_or(center_cents + 1, |ask| ask.min(center_cents + 1));
            bench_order(id, account, Side::Buy, top - 1 - depth, timestamp)
        } else {
            let bottom = probe
                .best_bid_cents(BENCH_SYMBOL)
                .map_or(center_cents - 1, |bid| bid.max(center_cents - 1));
            bench_order(id, account, Side::Sell, bottom + 1 + depth, timestamp)
        }
    }

    /// The oldest order the mix sent that still waits in the book, and the
    /// account that sent it. The function drops orders that already traded as
    /// it finds them, because nobody can cancel one of those again.
    fn bench_oldest_resting(
        sent: &mut VecDeque<(OrderId, AccountId)>,
        probe: &MatcherState,
    ) -> Option<(OrderId, AccountId)> {
        while let Some((id, account)) = sent.pop_front() {
            if probe.open_orders.contains_key(&id) {
                return Some((id, account));
            }
        }
        None
    }

    /// Builds the workload the throughput tests measure. Five orders in ten
    /// rest. Three in ten match and trade. Two in ten cancel an order the mix
    /// already sent.
    ///
    /// `step_ms` is how far apart the message timestamps are. It is a
    /// parameter because the engine reads the timestamps. Every new order asks
    /// the reference-price window for the middle price over the last 30
    /// seconds. That window holds one sample for every millisecond that moved
    /// a middle price. So a step of 400 ms leaves at most 75 samples to walk
    /// for each order, and a step of 1 ms leaves up to 30,000. The live
    /// sequencer publishes 2.433 messages a second, which is a step of about
    /// 411 ms.
    ///
    /// The center price walks by up to two cents a message, the way the
    /// sequencer's order generator walks its own middle price. The best prices
    /// then really move, and the reference-price window really fills. A
    /// resting order is priced inside the best price on the other side, so it
    /// cannot match. A matching order is priced at the best price on the other
    /// side, for the quantity waiting there, so it fills whole and leaves no
    /// remainder. That is what holds the book at the size `warm` gives it:
    /// five orders join and five leave every ten messages.
    fn bench_mix(warm: u64, total: u64, step_ms: u64) -> Mix {
        let mut probe = MatcherState::with_default_listings();

        let mut warmup = Vec::with_capacity(warm as usize);
        for index in 0..warm {
            let id = index + 1;
            let depth = 1 + (index % 5) as i64;
            let account = (index % BENCH_ACCOUNTS) as AccountId + 1;
            let msg = if index % 2 == 0 {
                bench_order(
                    id,
                    account,
                    Side::Buy,
                    BENCH_CENTER_CENTS - depth,
                    id * step_ms,
                )
            } else {
                bench_order(
                    id,
                    account,
                    Side::Sell,
                    BENCH_CENTER_CENTS + depth,
                    id * step_ms,
                )
            };
            probe.apply_message(&msg).expect("in feed order");
            warmup.push(msg);
        }

        let trades_before = probe.trades_total;
        let mut messages = Vec::with_capacity(total as usize);
        let mut sent: VecDeque<(OrderId, AccountId)> = VecDeque::new();
        let mut center_cents = BENCH_CENTER_CENTS;
        // A repeatable number source. It stands in for the arriving orders, so
        // it needs no statistical quality. It needs only the same answer on
        // every run.
        let mut noise: u64 = 0x243f_6a88_85a3_08d3;
        let mut rested = 0u64;
        let mut traded = 0u64;
        let mut cancels_applied = 0u64;
        let mut cancels_ignored = 0u64;

        for index in 0..total {
            let id = warm + index + 1;
            let timestamp = id * step_ms;
            noise = noise
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let roll = (noise >> 33) as i64;
            center_cents = (center_cents + roll % 5 - 2).clamp(9_000, 11_000);
            let account = (roll as u64 % BENCH_ACCOUNTS) as AccountId + 1;
            let buying = roll % 2 == 0;
            let depth = (roll / 8) % 5;

            let message = match index % 10 {
                // Three in ten match the book and trade.
                0..=2 => {
                    let best = if buying {
                        probe.best_ask_cents(BENCH_SYMBOL).map(|p| (Side::Buy, p))
                    } else {
                        probe.best_bid_cents(BENCH_SYMBOL).map(|p| (Side::Sell, p))
                    };
                    match best {
                        Some((side, price)) => bench_order(id, account, side, price, timestamp),
                        // Nothing waits on that side, so there is nothing to
                        // match. The order rests instead, which is what the
                        // same order does at an empty book.
                        None => bench_resting_order(
                            &probe,
                            id,
                            account,
                            buying,
                            center_cents,
                            depth,
                            timestamp,
                        ),
                    }
                }
                // Two in ten cancel an order the mix already sent.
                3 | 4 => match bench_oldest_resting(&mut sent, &probe) {
                    Some((target, owner)) => bench_cancel(id, owner, target, timestamp),
                    None => bench_resting_order(
                        &probe,
                        id,
                        account,
                        buying,
                        center_cents,
                        depth,
                        timestamp,
                    ),
                },
                // Five in ten rest.
                _ => {
                    bench_resting_order(&probe, id, account, buying, center_cents, depth, timestamp)
                }
            };

            let trades_at = probe.trades_total;
            let applied_at = probe.cancels_applied;
            let ignored_at = probe.cancels_ignored;
            probe.apply_message(&message).expect("in feed order");
            if matches!(message, OrderMessage::New { .. }) {
                if probe.trades_total > trades_at {
                    traded += 1;
                } else {
                    rested += 1;
                    sent.push_back((id, account));
                }
            } else {
                cancels_applied += probe.cancels_applied - applied_at;
                cancels_ignored += probe.cancels_ignored - ignored_at;
            }
            messages.push(message);
        }

        // The mix is a workload only if the engine accepted all of it. A
        // refused order or a refused cancel would mean the counts above
        // describe messages the engine threw away.
        assert_eq!(
            probe.orders_ignored, 0,
            "the mix sent an order this engine refuses"
        );
        assert_eq!(
            probe.cancels_rejected, 0,
            "the mix sent a cancel for another account's order"
        );

        Mix {
            warmup,
            messages,
            rested,
            traded,
            cancels_applied,
            cancels_ignored,
            trades: probe.trades_total - trades_before,
            resting: bench_resting_orders(&probe),
            positions: probe.positions.len(),
        }
    }

    /// Applies `mix` to a fresh engine. It returns how long the measured
    /// messages took, and the root the run ended on.
    ///
    /// The warm-up runs first, and the clock does not cover it. `root_every`
    /// is how many messages pass between two `state_root` calls. `None` takes
    /// no root at all, which times the matching on its own.
    fn bench_replay(mix: &Mix, root_every: Option<u64>) -> (Duration, [u8; 32]) {
        let mut state = MatcherState::with_default_listings();
        for msg in &mix.warmup {
            state.apply_message(msg).expect("in feed order");
        }
        let started = Instant::now();
        for (index, msg) in mix.messages.iter().enumerate() {
            state.apply_message(msg).expect("in feed order");
            if root_every.is_some_and(|every| (index as u64 + 1).is_multiple_of(every)) {
                std::hint::black_box(state.state_root());
            }
        }
        let elapsed = started.elapsed();
        (elapsed, state.state_root())
    }

    /// Messages a second, from a count and how long it took.
    fn bench_per_second(messages: usize, elapsed: Duration) -> f64 {
        messages as f64 / elapsed.as_secs_f64()
    }

    /// How many messages a second the exchange matches when it takes no state
    /// root. This times `apply_message` and nothing else.
    ///
    /// Four timestamp steps, because the step changes the answer. The engine
    /// reads the timestamps to keep the reference price that bounds a market
    /// order. Keeping that price means a walk over every middle-price sample
    /// inside a 30-second window, for every new order. Messages 400 ms apart
    /// leave 75 samples in the window. Messages 1 ms apart leave 30,000. The
    /// four runs carry the same orders and the same cancels, and they end on
    /// the same state root. So the walk is the only difference between them.
    #[test]
    #[ignore = "matches a million messages; run it with --release"]
    fn measures_matching_a_mix_of_orders_and_cancels() {
        const WARM: u64 = 2_000;
        const TOTAL: u64 = 200_000;
        let mut expected: Option<[u8; 32]> = None;
        println!();
        for step_ms in [400u64, 100, 10, 1] {
            let mix = bench_mix(WARM, TOTAL, step_ms);
            let (elapsed, root) = bench_replay(&mix, None);
            match expected {
                None => {
                    expected = Some(root);
                    println!("mix: {}", mix.stated());
                    println!(
                        "     {} warm-up messages build the book before the clock starts",
                        mix.warmup.len()
                    );
                }
                // Only the timestamps differ between the runs, and the state
                // root does not cover a timestamp. Two different roots would
                // mean the runs matched different orders, and the rates below
                // could not be compared.
                Some(first) => assert_eq!(root, first, "the four runs matched different orders"),
            }
            println!(
                "timestamps {:>4} ms apart ({:>7.1} messages a second of feed time): \
                 {:>10.0} messages a second matched, {:.3} us a message",
                step_ms,
                1000.0 / step_ms as f64,
                bench_per_second(mix.messages.len(), elapsed),
                elapsed.as_secs_f64() * 1e6 / mix.messages.len() as f64,
            );
        }
        println!();
    }

    /// An engine that holds `resting` open orders and `holders` positions.
    ///
    /// The positions come first. Each pair below is one sell order from
    /// account 1 that waits in the book, and one buy order that takes it.
    /// Account 1 and the buyer both end up holding something. The book is
    /// empty again after every pair. The waiting orders are placed after that,
    /// at prices that cannot match.
    fn bench_book_of(resting: u64, holders: u64) -> MatcherState {
        let mut state = MatcherState::with_default_listings();
        let mut id = 0u64;
        for holder in 0..holders {
            id += 1;
            state
                .apply_message(&bench_order(id, 1, Side::Sell, 10_100, id * 1_000))
                .expect("in feed order");
            id += 1;
            state
                .apply_message(&bench_order(
                    id,
                    holder as AccountId + 2,
                    Side::Buy,
                    10_100,
                    id * 1_000,
                ))
                .expect("in feed order");
        }
        for index in 0..resting {
            id += 1;
            let depth = 1 + (index % 500) as i64;
            let account = (index % BENCH_ACCOUNTS) as AccountId + 1;
            let (side, price) = if index % 2 == 0 {
                (Side::Buy, BENCH_CENTER_CENTS - depth)
            } else {
                (Side::Sell, BENCH_CENTER_CENTS + depth)
            };
            state
                .apply_message(&bench_order(id, account, side, price, id * 1_000))
                .expect("in feed order");
        }
        assert_eq!(bench_resting_orders(&state), resting as usize);
        state
    }

    /// The average `state_root` call over `state`, timed over at least 200 ms.
    fn bench_time_root(state: &MatcherState) -> Duration {
        let started = Instant::now();
        let mut calls = 0u32;
        while started.elapsed() < Duration::from_millis(200) {
            for _ in 0..8 {
                std::hint::black_box(state.state_root());
                calls += 1;
            }
        }
        started.elapsed() / calls
    }

    /// What one `state_root` costs, and how that cost grows.
    ///
    /// The cost is not a constant. The root hashes every listed symbol, then
    /// every waiting order in every book, then every position. So the cost
    /// grows with the book and with the number of accounts that hold
    /// something. The exchange takes one root at every claim boundary, so this
    /// number decides what a claim costs.
    #[test]
    #[ignore = "builds a book of 200,000 orders; run it with --release"]
    fn measures_the_state_root_over_a_book() {
        println!();
        for resting in [0u64, 100, 1_000, 10_000, 100_000, 200_000] {
            let state = bench_book_of(resting, 64);
            let each = bench_time_root(&state);
            println!(
                "{:>7} resting orders, {:>6} positions: {:>9.2} us a root, {:>6.1} ns an order",
                resting,
                state.positions.len(),
                each.as_secs_f64() * 1e6,
                if resting == 0 {
                    0.0
                } else {
                    each.as_secs_f64() * 1e9 / resting as f64
                },
            );
        }
        for holders in [0u64, 100, 1_000, 10_000, 100_000] {
            let state = bench_book_of(1_000, holders);
            let each = bench_time_root(&state);
            println!(
                "  1,000 resting orders, {:>6} positions: {:>9.2} us a root",
                state.positions.len(),
                each.as_secs_f64() * 1e6,
            );
        }
        println!();
    }

    /// Matching with the state root taken at a claim boundary, which is what
    /// the exchange really does.
    ///
    /// How often that happens in production: the poll loop sleeps
    /// `--poll-ms`, which is 200 ms by default. It then fetches what the
    /// sequencer has, applies it, and calls `commit`. `commit` calls
    /// `take_pending`, and `take_pending` takes one root. So the exchange
    /// takes at most five roots a second, however fast the messages arrive.
    /// That is one root for every `rate / 5` messages.
    ///
    /// Two rates from the live system are printed beside the rest. The
    /// deployment publishes 2.433 messages a second, so one poll carries about
    /// half a message, and the exchange takes a root about once per message.
    /// The audit of the local log ran 232,204 messages again across 1,136
    /// claims, which is one root for every 204 messages.
    #[test]
    #[ignore = "matches a million messages; run it with --release"]
    fn measures_matching_with_the_state_root_at_a_claim_boundary() {
        const WARM: u64 = 2_000;
        const TOTAL: u64 = 200_000;
        let mix = bench_mix(WARM, TOTAL, 400);
        let (bare, root) = bench_replay(&mix, None);
        println!("\nmix: {}", mix.stated());
        println!(
            "no root taken: {:>10.0} messages a second",
            bench_per_second(mix.messages.len(), bare)
        );
        for every in [1u64, 5, 40, 204, 1_000, 10_000] {
            let (elapsed, checked) = bench_replay(&mix, Some(every));
            assert_eq!(checked, root, "taking a root changed the state");
            let added =
                (elapsed.as_secs_f64() - bare.as_secs_f64()) * 1e6 / mix.messages.len() as f64;
            println!(
                "a root every {:>6} messages: {:>10.0} messages a second, {:>8.3} us a message \
                 added",
                every,
                bench_per_second(mix.messages.len(), elapsed),
                added,
            );
        }
        println!();
    }
    /// The whole intake of the poll loop, timed. The code splits the page the
    /// sequencer serves into messages, hashes the chain again over their
    /// bytes, reads each message, and applies it. This is `apply_batch`, which
    /// is what `poll_feed` calls. So this is what a message really costs the
    /// exchange, and not only the matching part of it.
    ///
    /// Every message is read from JSON once on this path. `wire::read_ndjson`
    /// parses each line into an `OrderMessage`, and takes the id and the kind
    /// out of what it parsed. So no line is read twice. The engine used to
    /// read each line a second time for its envelope, and that second parse is
    /// what this number lost.
    ///
    /// `poll` is how many messages one page carries. The poll loop sleeps
    /// `--poll-ms`, 200 ms by default. So one page holds a fifth of a second
    /// of the sequencer's output: two messages at the live rate, and 20,000 at
    /// 100,000 a second.
    fn bench_intake(mix: &Mix, poll: usize) -> (Duration, [u8; 32]) {
        let mut state = MatcherState::with_default_listings();
        for msg in &mix.warmup {
            state.apply_message(msg).expect("in feed order");
        }

        // The pages, built before the clock starts. Each page is the byte
        // string `/messages.ndjson` serves, with the head the sequencer signs
        // beside it. Nothing checks the signature here. `accept_head` checks
        // it once per page, before `apply_batch`, so any 64 bytes will do.
        let mut pages: Vec<(Vec<u8>, SignedHead)> = Vec::new();
        let mut chain = state.feed_chain.expect("a fresh engine folds a chain");
        for page in mix.messages.chunks(poll) {
            let mut body = Vec::new();
            for msg in page {
                let bytes = logchain::canonical_bytes(msg);
                chain = logchain::extend_bytes(&chain, &bytes);
                body.extend_from_slice(&bytes);
                body.push(b'\n');
            }
            pages.push((
                body,
                SignedHead {
                    last_id: page.last().expect("a page holds messages").id(),
                    chain,
                    public_key: String::new(),
                    signature: Signature::from_bytes(&[0u8; 64]),
                },
            ));
        }

        let started = Instant::now();
        for (body, head) in &pages {
            let messages = wire::read_ndjson::<OrderMessage>(body).expect("one message a line");
            apply_batch(&mut state, &messages, head).expect("the page is in feed order");
        }
        let elapsed = started.elapsed();
        (elapsed, state.state_root())
    }

    /// What one message costs the exchange from the sequencer's bytes to the
    /// books, next to what the matching alone costs.
    ///
    /// The gap between the two is the reading: splitting the page, copying
    /// each line, hashing the chain again over it, and parsing it. The reading
    /// is the larger half, and it is the part
    /// `measures_matching_a_mix_of_orders_and_cancels` leaves out.
    #[test]
    #[ignore = "consumes a million messages; run it with --release"]
    fn measures_the_poll_loop_intake() {
        const WARM: u64 = 2_000;
        const TOTAL: u64 = 200_000;
        println!();
        // Both timestamp steps, because the reading is the same work at each
        // step and the matching is not. At 400 ms the reference-price window
        // holds 75 samples, and the reading is the larger half of a message.
        // At 1 ms the window holds up to 30,000 samples, and the reading stops
        // mattering.
        for step_ms in [400u64, 1] {
            let mix = bench_mix(WARM, TOTAL, step_ms);
            let (matching, root) = bench_replay(&mix, None);
            if step_ms == 400 {
                println!("mix: {}", mix.stated());
            }
            println!(
                "timestamps {:>4} ms apart, apply_message alone:  {:>9.0} messages a second, \
                 {:.3} us a message",
                step_ms,
                bench_per_second(mix.messages.len(), matching),
                matching.as_secs_f64() * 1e6 / mix.messages.len() as f64,
            );
            for poll in [2usize, 100, 1_000, 20_000] {
                let (elapsed, checked) = bench_intake(&mix, poll);
                assert_eq!(checked, root, "the intake path matched different orders");
                println!(
                    "  split, fold, parse and apply, {:>6} a page: {:>9.0} messages a second, \
                     {:.3} us a message",
                    poll,
                    bench_per_second(mix.messages.len(), elapsed),
                    elapsed.as_secs_f64() * 1e6 / mix.messages.len() as f64,
                );
            }
        }
        println!();
    }
}
