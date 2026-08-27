//! The state the exchange writes to disk, in SQLite.
//!
//! The exchange runs the messages the sequencer serves. A message is one order
//! or one cancel. Everything the exchange holds comes from those messages and
//! from nothing else. So only two things must survive a restart: the cursor,
//! which is the number of the last message the exchange ran, and what running
//! those messages produced. This module stores both, in one transaction. A
//! transaction is a group of writes that SQLite applies all together, or not
//! at all. So the cursor can never point past the state it describes.
//!
//! What is stored, and what is not:
//!
//! - resting orders, executed trades, the message cursor and the counters are
//!   stored, because nothing cheaper can work them out again. A resting order
//!   is an order in the book, waiting to trade;
//! - positions and per-symbol totals are *not* stored. The exchange adds them
//!   up again from the trades table on load, through the same
//!   `Position::apply_fill` it uses live. A stored copy could disagree with
//!   the trades it says it sums up. A copy added up again cannot.
//!
//! No price and no quantity here is ever a float. A price is a whole number of
//! cents. A quantity is a whole number of tenths. These are the same whole
//! units `matcher` computes on. SQL `REAL` is a binary float, and a binary
//! float cannot hold every decimal number exactly. Storing a price as `REAL`
//! would put that small error between the exchange and its own record, and
//! hand the error back on the way in. Whole cents and whole tenths exist to
//! stop that error. The `trades_readable` view divides them by 100 and by 10
//! so a person can read them.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};

use crate::domain::{AccountId, OrderId, OrderMessage, Side};
use crate::logchain::Chain;
use crate::sqlite;

/// The schema version this build understands. A database written by a newer
/// build is refused, not half-read. This build would read a column it does not
/// know as if the column were absent, and that would silently drop state the
/// exchange is meant to resume from.
///
/// Version 2 added `runs.feed_session`. It names which history of the
/// sequencer this run's cursor counts messages of.
///
/// Version 3 added `resume_point.chain_hash` and `runs.feed_pubkey`. The chain
/// hash is one hash over every message the run has consumed. Each message's
/// hash covers the hash before it, so one value covers the whole history. The
/// chain hash is written in the same transaction as the cursor it belongs to.
/// `runs.feed_pubkey` is the sequencer's public key. This run pinned that key
/// the first time it read from the sequencer.
///
/// Version 4 removed the two columns of the CSV trade log, `runs.trade_log`
/// and `resume_point.trade_log_failures`. The trades table is the trade record
/// now, so those two columns described a file that no longer exists.
///
/// Version 5 added the `claims` table: one row per committed batch. A row
/// states which state root, plus which messages, produced which state root. A
/// state root is one hash that covers everything the exchange holds.
///
/// Version 6 added `claims.signature` and `runs.matcher_pubkey`.
/// `claims.signature` is the exchange's own Ed25519 signature over that
/// statement. Ed25519 is a signature scheme: the holder of a private key signs
/// bytes, and anybody who holds the matching public key can check the
/// signature. With the signature a claim is evidence outside this file, and
/// not only a row inside it. `runs.matcher_pubkey` is the public key those
/// signatures are made with, so somebody who holds only this file can still
/// check them.
///
/// Version 7 added `resume_point.rule_version`, the rule set the run was
/// matching under when it committed. The column is not a report for a person.
/// The state root covers the rule set. So a resume that came back under the
/// wrong rule set would hash to a root that the run's last claim contradicts,
/// and the run would stop. NULL means the run was recorded before rule sets
/// existed, which is rule set 1: a build with no self-trade rule matched under
/// rule set 1 whatever the log said.
///
/// Version 8 added the `listings` table: the symbol registry the exchange
/// builds from the log's `ListSymbol` and `DelistSymbol` messages. The
/// registry is state that carries from one message to the next, and it decides
/// what every later order is allowed to do. A resume that could not read the
/// registry back would refuse every order it went on to see.
///
/// Version 9 added `resume_point.operator_key`, the key the log's operator
/// messages must be signed by. The key carries from one message to the next
/// for the same reason the rule set does. A resume that lost the key would
/// take the next operator message's own key as the log's key, and that is the
/// one thing ENGINE.md section 3.1 exists to stop. NULL means the log had
/// named no operator yet.
///
/// Version 10 added the `orders_ignored_kinds` table: one row per refusal
/// reason, holding how many orders that reason refused. `orders_ignored` was
/// already stored and the split by reason was not. So a restarted exchange
/// served a total that counted every restart, beside a split that counted only
/// the time since the last restart, and the two stopped adding up. The upgrade
/// puts the whole stored total under the kind `not_recorded`. That is what an
/// older run knows about its own refusals: it counted them, and it did not
/// record why.
///
/// Version 11 added `listings.listed_by`, the id of the `ListSymbol` message
/// that opened each market. The registry is a `BTreeMap`, and a `BTreeMap`
/// keeps its keys in name order. So the order the operator listed the markets
/// in is not in the registry and cannot be worked out from it. `/market`
/// serves its rows in the order the operator listed them. An upgraded run gets
/// 0, which is truthful: that run stored no listing id, and those rows fall
/// back to name order.
///
/// Version 12 added the account, account-and-symbol, and symbol trade indexes.
/// They change no stored fact. They bound filtered reads over a long run.
const SCHEMA_VERSION: i64 = 12;

/// A running exchange writes the time into its run row again and again. That
/// time is the heartbeat. A run whose heartbeat is 30 000 ms old or older
/// counts as dead, so a new exchange process can take a crashed run over.
/// `Store::open` makes the wait longer when the poll interval is slow.
const HEARTBEAT_GRACE_MS: u64 = 30_000;

/// What state a run is in.
///
/// A run left in `OPEN` and a run left in `STOPPED` can both be resumed, and
/// that is the point. An exchange that was shut down on purpose must come back
/// where it left off, exactly as much as one that crashed. The only difference
/// between the two is whether the last process got to write its status before
/// it exited. An operator can read that off the row.
///
/// The other two states end a run for good. A `FEED_RESTARTED` run describes a
/// sequencer history that no longer exists. Somebody abandoned a `RESET` run on
/// purpose. Resuming either one would mix two unrelated markets into one set of
/// books.
pub mod status {
    pub const OPEN: &str = "open";
    pub const STOPPED: &str = "stopped";
    pub const FEED_RESTARTED: &str = "feed_restarted";
    pub const RESET: &str = "reset";
}

/// Anything that can stop the exchange from trusting its own database.
#[derive(Debug)]
pub enum StoreError {
    /// SQLite itself refused the operation.
    Sql(rusqlite::Error),
    /// Another exchange process is running on this database.
    Busy(String),
    /// The stored state contradicts itself. Resuming from it would serve
    /// numbers the exchange cannot stand behind, so the exchange refuses to
    /// start.
    Corrupt(String),
    /// SQLite could not open the file at all: the wrong owner after a `chown`,
    /// a full disk, a directory that is not writable.
    ///
    /// This is a separate variant from `Corrupt` on purpose. The rows in the
    /// file are very probably fine, so nobody must tell the operator to start
    /// a fresh run. An operator who reads "reset" and acts on it deletes a
    /// working database because the disk was full.
    CannotOpen(String),
    /// The file was written by a build with a different schema.
    Version(i64),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Sql(e) => write!(f, "database error: {}", e),
            StoreError::Busy(m) => write!(f, "{}", m),
            StoreError::Corrupt(m) => write!(f, "stored state is inconsistent: {}", m),
            StoreError::CannotOpen(m) => {
                write!(f, "cannot open the database file: {}", m)
            }
            StoreError::Version(v) => write!(
                f,
                "database has schema version {}, this build understands {}",
                v, SCHEMA_VERSION
            ),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sql(e)
    }
}

/// A resting order, as stored: an order that sits in the book and waits to
/// trade. The row holds everything the exchange needs to put the order back at
/// its price level. A price level is all the orders in the book at one price.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderRow {
    pub order_id: OrderId,
    pub account: AccountId,
    pub symbol: String,
    pub side: Side,
    pub price_cents: i64,
    pub qty_tenths: i64,
}

/// One symbol's listing, as stored.
///
/// A price step is the smallest price difference this market allows. A
/// quantity step is the smallest quantity difference. Both steps are stored as
/// whole cents and whole tenths, and not as the `f64` the `ListSymbol` message
/// carries them as. The reason is the reason the books hold whole numbers. A
/// step read back as a slightly different float would give a resumed exchange
/// a different set of allowed prices from the live exchange that wrote the
/// row.
///
/// A delisted symbol keeps its row, with `listed` false. Deleting the row
/// would lose the fact that the log ever listed the symbol. The read endpoints
/// still answer about a delisted symbol's trades, because those trades
/// happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingRow {
    pub symbol: String,
    pub price_step_cents: i64,
    pub quantity_step_tenths: i64,
    pub listed: bool,
    /// The id of the `ListSymbol` message that opened this market. `0` when no
    /// message said so. See `matcher::Listing::listed_by`.
    pub listed_by: OrderId,
}

/// An executed trade, as stored: whole numbers, not the `f64` the API serves.
///
/// A trade has two sides. The taker is the order that arrived and traded
/// against the book. The maker is the order that was already in the book and
/// waited there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradeRow {
    pub trade_id: u64,
    pub timestamp: u64,
    pub symbol: String,
    pub price_cents: i64,
    pub qty_tenths: i64,
    pub maker_order: OrderId,
    pub maker_account: AccountId,
    pub taker_order: OrderId,
    pub taker_account: AccountId,
    pub taker_side: Side,
}

/// Every counter the exchange reports, read at one moment together. A commit
/// then writes one set of numbers that agree with each other, and not a
/// mixture of two moments.
///
/// This struct is not `Copy`, because the split below is a map. Holding the
/// split here, instead of passing it to `commit` beside the totals, is the
/// point. The exchange reads the total and the split at one moment and writes
/// them in one transaction, so the two cannot describe two moments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counters {
    pub last_seen: OrderId,
    pub messages_processed: u64,
    pub cancels_applied: u64,
    pub cancels_ignored: u64,
    pub orders_ignored: u64,
    /// How many of those refusals each reason caused: `unlisted_symbol`,
    /// `off_grid`, `self_trade` and the rest. The values add up to
    /// `orders_ignored`, and the exchange stores them so they still add up
    /// after a restart.
    ///
    /// The keys come back out of the database, so they are owned strings and
    /// not `&'static str`. A file can hold a reason this build does not name.
    /// A newer build wrote that reason, or the version 10 upgrade wrote
    /// `not_recorded`. This build must carry that count and not drop it.
    pub orders_ignored_by_kind: BTreeMap<String, u64>,
    /// The rule set the exchange was matching under at `last_seen`, as the
    /// last `EngineRule` message named it. Rule set 1 is the rules the log has
    /// run under since message 1.
    ///
    /// This is state, not a counter. `MatcherState::state_root` hashes the
    /// rule set in. Two exchanges with the same books but different rule sets
    /// do not match the same later messages the same way. So a resume that
    /// forgot the rule set would rebuild a state that hashes to a root the
    /// run's last claim contradicts, and `open_state` would end the run.
    pub rule_version: u32,
    /// The operator key the log had named at `last_seen`, as the first
    /// operator message in the log gave it. `None` until that message arrives.
    ///
    /// State, not a counter, like `rule_version`. `MatcherState::state_root`
    /// hashes the key in. So a resume that forgot the key would rebuild a
    /// state that hashes to a root the run's last claim contradicts, and
    /// `open_state` would end the run.
    pub operator_key: Option<[u8; 32]>,
    /// One hash over every message consumed up to `last_seen`. Each message's
    /// hash covers the hash before it, so this one value covers the whole
    /// history. `commit` writes the hash in the same transaction as the
    /// cursor, because the hash *is* the cursor's content: it says which bytes
    /// those `last_seen` messages were. `None` on a run recorded before the
    /// chain existed. Unknown stays unknown, and is not written as zero.
    pub chain: Option<Chain>,
}

/// Zero for every counter, and rule set 1, which is not zero. This `Default`
/// is written out by hand and not derived, for that one field. A derived
/// default would say rule set 0. Rule set 0 is not a rule set at all, and no
/// build could resume a run committed with it.
impl Default for Counters {
    fn default() -> Self {
        Counters {
            last_seen: 0,
            messages_processed: 0,
            cancels_applied: 0,
            cancels_ignored: 0,
            orders_ignored: 0,
            orders_ignored_by_kind: BTreeMap::new(),
            rule_version: 1,
            operator_key: None,
            chain: None,
        }
    }
}

/// One change the exchange made that must be written to disk. The exchange
/// collects these changes as it matches and hands the batch to
/// `Store::commit`. `commit` writes them in message order, inside one
/// transaction.
#[derive(Debug, Clone)]
pub enum Change {
    /// An order did not trade in full. What is left of it now rests in the
    /// book and waits.
    OrderRested(OrderRow),
    /// A resting order traded in part. `qty_tenths` is what is left of it.
    OrderReduced { order_id: OrderId, qty_tenths: i64 },
    /// A resting order left the book. It traded in full, or somebody cancelled
    /// it.
    OrderClosed { order_id: OrderId },
    /// Two orders traded with each other.
    Traded(TradeRow),
    /// The exchange consumed one message from the sequencer. The row stays for
    /// the recent-message window the UI shows.
    Consumed(OrderMessage),
    /// A `ListSymbol` message opened a market.
    SymbolListed(ListingRow),
    /// A `DelistSymbol` message closed a market. The row stays, and only the
    /// `listed` flag changes, so a resumed exchange still knows the log once
    /// listed this symbol.
    SymbolDelisted { symbol: String },
}

/// One execution claim. A claim is a statement: the exchange took the state
/// whose hash is `root_before`, ran a range of the sequencer's messages on it,
/// and reached the state whose hash is `root_after`. `trades_total` is how
/// many trades the run has executed since the run began.
///
/// This is exactly the statement a zero-knowledge execution proof would cover.
/// Such a proof is one short value that anybody can check without running the
/// messages again. No program here makes one yet. So `--audit` checks a claim
/// the expensive way: it runs the messages again and computes the two roots
/// again.
///
/// The signature is what takes the claim out of this file. Without a signature
/// a row is only as good as the operator's word that the exchange wrote it. A
/// row signed with the exchange's key is the exchange's own statement, and
/// anybody who holds the public key can check it. Two signed rows for one
/// message range with different roots are the exchange's own signature on its
/// own contradiction.
#[derive(Debug, Clone)]
pub struct ClaimRow {
    pub from_msg: OrderId,
    pub to_msg: OrderId,
    pub root_before: [u8; 32],
    pub root_after: [u8; 32],
    pub trades_total: u64,
    /// Ed25519 signature over the statement `logchain::sign_claim` builds,
    /// made with the exchange's key. `None` only on a row that a build before
    /// schema 6 wrote. `commit` refuses to write an unsigned claim, so no
    /// claim recorded from now on can exist without a signature.
    pub signature: Option<[u8; 64]>,
}

/// Everything the exchange needs to rebuild a `MatcherState`, read back from
/// one run.
#[derive(Debug)]
pub struct Snapshot {
    pub counters: Counters,
    /// Resting orders, smallest order id first. That is also the order in
    /// which they trade inside one price level: the order that arrived first
    /// trades first.
    pub orders: Vec<OrderRow>,
    /// Every symbol this run's log has listed, delisted symbols included. The
    /// exchange builds its registry again from these rows. Without them a
    /// resumed exchange would see no listed symbol, and would refuse every
    /// order after the resume point.
    pub listings: Vec<ListingRow>,
    /// How many trades this run recorded. The snapshot does not hold the
    /// trades themselves. A run with ten million fills would need ten million
    /// rows in memory to resume, and that is what stopped a long-lived
    /// exchange from ever starting again. `stream_trades` reads them back one
    /// at a time.
    pub trades_total: u64,
    /// The recent-message window, oldest first.
    pub recent: Vec<OrderMessage>,
    /// The sequencer URL this run was built from, so a resume against a
    /// different sequencer can be reported.
    pub feed_url: String,
    /// The session name the cursor was counted against, if the sequencer ever
    /// gave one. A session is a name for one log. A different session name
    /// from the sequencer means the cursor is a position in a history that no
    /// longer exists.
    pub feed_session: Option<String>,
    /// The sequencer's public key this run pinned the first time it read from
    /// the sequencer, written as hex. A different key from the sequencer means
    /// somebody else signs the log now.
    pub feed_pubkey: Option<String>,
    /// The state root of the last committed claim, if the run has one. The
    /// restored state must hash back to exactly this value. If it does not,
    /// somebody changed the database from outside the exchange.
    pub last_claim_root: Option<[u8; 32]>,
}

/// A handle on the state database, bound to one run.
///
/// Only the poller holds one. The poller is the part of the exchange that
/// fetches new messages from the sequencer and runs them. The poller is the
/// only writer of this database. The API handlers read the exchange's
/// in-memory state and never touch this handle.
pub struct Store {
    conn: Connection,
    path: PathBuf,
    run_id: i64,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn side_text(side: Side) -> &'static str {
    match side {
        Side::Buy => "Buy",
        Side::Sell => "Sell",
    }
}

fn side_from_text(text: &str) -> Result<Side, StoreError> {
    match text {
        "Buy" => Ok(Side::Buy),
        "Sell" => Ok(Side::Sell),
        other => Err(StoreError::Corrupt(format!("'{}' is not a side", other))),
    }
}

impl Store {
    /// Opens the database at `path`, claims the run left in it, and returns
    /// the state to resume from, if there is one.
    ///
    /// A run left in `stopped` can always be resumed, because nothing else
    /// uses it. A run left in `open` was not shut down cleanly. So `open`
    /// checks whether the process that owned that run still runs, before it
    /// takes the run over. Applying a message twice does not give the same
    /// result as applying it once, so two exchanges that share one cursor
    /// would apply every message between them twice.
    ///
    /// `reset` abandons the resumable run and starts a new one. `reset` closes
    /// the old run and does not delete it, so the old run's trades and books
    /// can still be read.
    pub fn open(
        path: &Path,
        feed_url: &str,
        poll_ms: u64,
        reset: bool,
    ) -> Result<(Store, Option<Snapshot>), StoreError> {
        // The exchange writes the heartbeat once per poll tick. So the wait
        // must be longer than one slow tick, or a running run would look
        // abandoned. 20 ticks is the margin.
        let grace = HEARTBEAT_GRACE_MS.max(poll_ms.saturating_mul(20));
        Store::open_with_grace(path, feed_url, grace, reset)
    }

    /// `open`, with the heartbeat age limit given instead of worked out from
    /// the poll interval. The tests use this, because a test must be able to
    /// claim a run that the same process still holds.
    pub(crate) fn open_with_grace(
        path: &Path,
        feed_url: &str,
        grace_ms: u64,
        reset: bool,
    ) -> Result<(Store, Option<Snapshot>), StoreError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| {
                StoreError::CannotOpen(format!(
                    "cannot create the directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        // The file gets owner-only permissions. It holds every account's
        // positions and profit, and no other user on the machine may read
        // that. `sqlite::open_durable` creates the file owner-only before
        // SQLite opens it. It also sets the `-wal` and `-shm` files beside it
        // to owner-only on every start. SQLite writes those two files as well
        // in WAL mode, and they hold the same account numbers. The old code
        // here set the permissions of the main file only, and only on the run
        // that created the file.
        let mut conn = sqlite::open_durable(path, true).map_err(StoreError::CannotOpen)?;
        // `PRAGMA foreign_keys = ON` makes SQLite refuse a row whose `run_id`
        // names no run in the `runs` table. Only this schema needs that check,
        // so it is not in the shared pragmas.
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        migrate(&mut conn)?;

        let mut store = Store {
            conn,
            path: path.to_path_buf(),
            run_id: 0,
        };
        match store.claim_open_run(grace_ms, reset)? {
            Some(run_id) => {
                store.run_id = run_id;
                let snapshot = store.load(run_id)?;
                Ok((store, Some(snapshot)))
            }
            None => {
                store.start_run(feed_url)?;
                Ok((store, None))
            }
        }
    }

    /// The database file this store writes to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The run this store is currently writing.
    pub fn run_id(&self) -> i64 {
        self.run_id
    }

    /// Closes the current run and opens a fresh one in the same database.
    ///
    /// Called when the sequencer restarts with a new history. The state this
    /// store holds then describes a history that no longer exists. That state
    /// is still a true record of what this exchange did, so `start_new_run`
    /// closes the old run and keeps it, and does not delete it.
    pub fn start_new_run(&mut self, reason: &str, feed_url: &str) -> Result<(), StoreError> {
        self.close_run(reason)?;
        self.start_run(feed_url)
    }

    /// Marks the current run closed. After this the run can no longer be
    /// resumed. That is what lets an operator tell a `--start-matcher` after a
    /// clean stop apart from a `--start-matcher` after a crash.
    pub fn close_run(&mut self, status: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE runs SET status = ?2, closed_at = ?3 WHERE run_id = ?1",
            params![self.run_id, status, now_millis() as i64],
        )?;
        Ok(())
    }

    /// Marks this run as stopped on purpose.
    pub fn close_stopped(&mut self) -> Result<(), StoreError> {
        self.close_run(status::STOPPED)
    }

    /// Records which of the sequencer's sessions this run's cursor counts
    /// messages of. A later resume can then tell whether the sequencer still
    /// serves that same history.
    pub fn set_feed_session(&mut self, session: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE runs SET feed_session = ?2 WHERE run_id = ?1",
            params![self.run_id, session],
        )?;
        Ok(())
    }

    /// Records the sequencer's public key this run trusts. The run pinned that
    /// key the first time it read from the sequencer.
    pub fn set_feed_pubkey(&mut self, pubkey: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE runs SET feed_pubkey = ?2 WHERE run_id = ?1",
            params![self.run_id, pubkey],
        )?;
        Ok(())
    }

    /// The public key this run's claims are signed with, as recorded. `None`
    /// on a run that has signed nothing yet, and on a run written before
    /// claims were signed at all.
    pub fn matcher_pubkey(&self) -> Result<Option<String>, StoreError> {
        Ok(self.conn.query_row(
            "SELECT matcher_pubkey FROM runs WHERE run_id = ?1",
            params![self.run_id],
            |row| row.get::<_, Option<String>>(0),
        )?)
    }

    /// Records the public key this run's execution claims are signed with.
    pub fn set_matcher_pubkey(&mut self, pubkey: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE runs SET matcher_pubkey = ?2 WHERE run_id = ?1",
            params![self.run_id, pubkey],
        )?;
        Ok(())
    }

    /// Writes the current time into the run row and writes no state. An
    /// exchange with no messages to run then does not look like a crashed one.
    pub fn heartbeat(&mut self) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE runs SET heartbeat_ms = ?2 WHERE run_id = ?1",
            params![self.run_id, now_millis() as i64],
        )?;
        Ok(())
    }

    /// Writes one batch of changes, the counters those changes produced, and
    /// the execution claim that covers the batch.
    ///
    /// All of it goes into one transaction, and SQLite applies a transaction
    /// all together or not at all. So a crash in the middle of a write leaves
    /// the previous batch whole, and leaves the cursor pointing at that batch.
    /// The poller then fetches again from that cursor and runs the lost
    /// messages again, which rebuilds exactly the same trades and books.
    pub fn commit(
        &mut self,
        changes: &[Change],
        counters: &Counters,
        claim: Option<&ClaimRow>,
    ) -> Result<(), StoreError> {
        let run_id = self.run_id;
        let recent_cap = crate::matcher::RECENT_MESSAGES_CAP as i64;
        let tx = self.conn.transaction()?;

        for change in changes {
            match change {
                Change::OrderRested(order) => {
                    tx.execute(
                        "INSERT OR REPLACE INTO open_orders
                           (run_id, order_id, account, symbol, side, price_cents, qty_tenths)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            run_id,
                            order.order_id as i64,
                            order.account as i64,
                            order.symbol,
                            side_text(order.side),
                            order.price_cents,
                            order.qty_tenths,
                        ],
                    )?;
                }
                Change::OrderReduced {
                    order_id,
                    qty_tenths,
                } => {
                    tx.execute(
                        "UPDATE open_orders SET qty_tenths = ?3
                         WHERE run_id = ?1 AND order_id = ?2",
                        params![run_id, *order_id as i64, qty_tenths],
                    )?;
                }
                Change::OrderClosed { order_id } => {
                    tx.execute(
                        "DELETE FROM open_orders WHERE run_id = ?1 AND order_id = ?2",
                        params![run_id, *order_id as i64],
                    )?;
                }
                Change::Traded(trade) => {
                    // OR REPLACE, and not a plain INSERT. A batch whose commit
                    // failed is tried again with the next batch, and a trade
                    // tried again carries the id it already had.
                    tx.execute(
                        "INSERT OR REPLACE INTO trades
                           (run_id, trade_id, timestamp, symbol, price_cents, qty_tenths,
                            maker_order, maker_account, taker_order, taker_account, taker_side)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                        params![
                            run_id,
                            trade.trade_id as i64,
                            trade.timestamp as i64,
                            trade.symbol,
                            trade.price_cents,
                            trade.qty_tenths,
                            trade.maker_order as i64,
                            trade.maker_account as i64,
                            trade.taker_order as i64,
                            trade.taker_account as i64,
                            side_text(trade.taker_side),
                        ],
                    )?;
                }
                Change::SymbolListed(listing) => {
                    tx.execute(
                        "INSERT OR REPLACE INTO listings
                           (run_id, symbol, price_step_cents, quantity_step_tenths, listed,
                            listed_by)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            run_id,
                            listing.symbol,
                            listing.price_step_cents,
                            listing.quantity_step_tenths,
                            i64::from(listing.listed),
                            listing.listed_by as i64,
                        ],
                    )?;
                }
                Change::SymbolDelisted { symbol } => {
                    // An UPDATE and not a DELETE. The row is how a resumed
                    // exchange knows the log once listed this symbol. The read
                    // endpoints need that row to answer about the symbol's old
                    // trades.
                    tx.execute(
                        "UPDATE listings SET listed = 0 WHERE run_id = ?1 AND symbol = ?2",
                        params![run_id, symbol],
                    )?;
                }
                Change::Consumed(message) => {
                    let json = serde_json::to_string(message).map_err(|e| {
                        StoreError::Corrupt(format!("cannot serialise feed message: {}", e))
                    })?;
                    tx.execute(
                        "INSERT OR REPLACE INTO recent_messages (run_id, msg_id, json)
                         VALUES (?1, ?2, ?3)",
                        params![run_id, message.id() as i64, json],
                    )?;
                }
            }
        }

        // The recent-message window has a fixed size in memory, so this DELETE
        // gives the table the same fixed size. Without it the table would grow
        // for ever, and nobody reads it past its newest 200 rows.
        tx.execute(
            "DELETE FROM recent_messages
             WHERE run_id = ?1 AND msg_id NOT IN (
               SELECT msg_id FROM recent_messages
               WHERE run_id = ?1 ORDER BY msg_id DESC LIMIT ?2
             )",
            params![run_id, recent_cap],
        )?;

        tx.execute(
            "INSERT INTO resume_point
               (run_id, last_seen, messages_processed, cancels_applied,
                cancels_ignored, orders_ignored, chain_hash, rule_version,
                operator_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(run_id) DO UPDATE SET
               last_seen = excluded.last_seen,
               messages_processed = excluded.messages_processed,
               cancels_applied = excluded.cancels_applied,
               cancels_ignored = excluded.cancels_ignored,
               orders_ignored = excluded.orders_ignored,
               chain_hash = excluded.chain_hash,
               rule_version = excluded.rule_version,
               operator_key = excluded.operator_key",
            params![
                run_id,
                counters.last_seen as i64,
                counters.messages_processed as i64,
                counters.cancels_applied as i64,
                counters.cancels_ignored as i64,
                counters.orders_ignored as i64,
                counters.chain.as_ref().map(|c| c.as_slice()),
                counters.rule_version as i64,
                counters.operator_key.as_ref().map(|key| key.as_slice()),
            ],
        )?;

        // One row per refusal reason, written beside the total in the same
        // transaction. Each row holds the count so far, and not the change
        // since the last write. So a batch that failed and is tried again with
        // the next batch writes the same answer as a batch that landed the
        // first time.
        //
        // A reason never leaves the map, and a count only grows. So this
        // replaces rows and never deletes one.
        for (kind, count) in &counters.orders_ignored_by_kind {
            tx.execute(
                "INSERT OR REPLACE INTO orders_ignored_kinds (run_id, kind, count)
                 VALUES (?1, ?2, ?3)",
                params![run_id, kind, *count as i64],
            )?;
        }

        // OR REPLACE for the same reason as the trades. A batch whose commit
        // failed is merged into the next attempt, and the merged claim keeps
        // the `from_msg` the first attempt had.
        //
        // The signature goes into the same INSERT as the claim, inside the
        // same transaction as the batch the claim describes. So there is no
        // moment in which this file holds a claim that nobody signed. An
        // unsigned claim is refused here, and not written now and fixed later.
        // "The row is there, the signature is coming" is exactly the state an
        // operator would want to be able to leave behind, so `commit` does not
        // allow it.
        if let Some(claim) = claim {
            let Some(signature) = claim.signature else {
                return Err(StoreError::Corrupt(format!(
                    "the claim for feed messages {}..{} carries no signature; \
                     an unsigned claim is not evidence of anything and is not written",
                    claim.from_msg, claim.to_msg
                )));
            };
            tx.execute(
                "INSERT OR REPLACE INTO claims
                   (run_id, from_msg, to_msg, root_before, root_after, trades_total, signature)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    run_id,
                    claim.from_msg as i64,
                    claim.to_msg as i64,
                    claim.root_before.as_slice(),
                    claim.root_after.as_slice(),
                    claim.trades_total as i64,
                    signature.as_slice(),
                ],
            )?;
        }

        tx.execute(
            "UPDATE runs SET heartbeat_ms = ?2 WHERE run_id = ?1",
            params![run_id, now_millis() as i64],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Opens a new run and points this store at it.
    ///
    /// Both rows go into one transaction. `load` refuses a run that has no
    /// resume point and calls it corrupt. So a crash between the two inserts
    /// used to leave an open run that every later start found, refused, and
    /// could not get past. Somebody had to delete that row by hand.
    fn start_run(&mut self, feed_url: &str) -> Result<(), StoreError> {
        let now = now_millis() as i64;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO runs (started_at, heartbeat_ms, status, feed_url, owner_pid)
             VALUES (?1, ?1, ?2, ?3, ?4)",
            params![now, status::OPEN, feed_url, std::process::id() as i64],
        )?;
        let run_id = tx.last_insert_rowid();
        // A new run starts at the empty chain, and not at "unknown". The run
        // consumes its history from the first message and hashes as it goes.
        tx.execute(
            "INSERT INTO resume_point
               (run_id, last_seen, messages_processed, cancels_applied,
                cancels_ignored, orders_ignored, chain_hash)
             VALUES (?1, 0, 0, 0, 0, 0, ?2)",
            params![run_id, crate::logchain::EMPTY_CHAIN.as_slice()],
        )?;
        tx.commit()?;
        self.run_id = run_id;
        Ok(())
    }

    /// Finds the resumable run and takes it over. Returns `None` when there is
    /// nothing to resume.
    fn claim_open_run(&mut self, grace_ms: u64, reset: bool) -> Result<Option<i64>, StoreError> {
        let resumable: Option<(i64, String, i64, i64)> = self
            .conn
            .query_row(
                "SELECT run_id, status, heartbeat_ms, owner_pid FROM runs
                 WHERE status IN (?1, ?2) ORDER BY run_id DESC LIMIT 1",
                params![status::OPEN, status::STOPPED],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;

        let Some((run_id, run_status, heartbeat_ms, owner_pid)) = resumable else {
            return Ok(None);
        };

        // Only a run that nobody closed can still have an owner process. Both
        // tests must pass before this calls a run live. A fresh heartbeat on
        // its own would lock out a supervisor that restarts a crashed exchange
        // for the whole grace period. A running pid on its own would be wrong
        // when the system has given that pid number to a different program.
        let age = now_millis().saturating_sub(heartbeat_ms.max(0) as u64);
        if run_status == status::OPEN && age < grace_ms && process_is_alive(owner_pid) {
            return Err(StoreError::Busy(format!(
                "run {} in {} is live (pid {}, heartbeat {}ms ago); \
                 another matcher is already using this database",
                run_id,
                self.path.display(),
                owner_pid,
                age
            )));
        }

        if !self.take_run(run_id, heartbeat_ms, owner_pid)? {
            return Err(StoreError::Busy(format!(
                "run {} in {} was claimed by another matcher a moment ago; \
                 another matcher is already using this database",
                run_id,
                self.path.display()
            )));
        }

        if reset {
            // This claims the run first and abandons it second. Without the
            // claim, two processes that reset the same run at the same moment
            // would each start a run of their own in this database, and both
            // would write to it.
            self.run_id = run_id;
            self.close_run(status::RESET)?;
            self.run_id = 0;
            return Ok(None);
        }

        Ok(Some(run_id))
    }

    /// Takes ownership of one run, but only if nobody else took it first.
    ///
    /// The claim is one `UPDATE`. Its `WHERE` names the exact heartbeat and
    /// owner pid this process read a moment ago, and the `UPDATE` reports how
    /// many rows it changed. Two exchanges that both saw the same unclaimed
    /// run both try the `UPDATE`. SQLite runs the two writes one after the
    /// other. The winner writes new values over the ones the loser's `WHERE`
    /// looks for. The loser then changes no row, and learns that somebody
    /// holds the run. The old code read the row and then updated it with no
    /// condition. That let both processes believe they held the run, and apply
    /// overlapping messages to one cursor.
    fn take_run(
        &self,
        run_id: i64,
        seen_heartbeat: i64,
        seen_owner: i64,
    ) -> Result<bool, StoreError> {
        let claimed = self.conn.execute(
            "UPDATE runs SET status = ?2, closed_at = NULL, heartbeat_ms = ?3, owner_pid = ?4
             WHERE run_id = ?1 AND status IN (?2, ?5)
               AND heartbeat_ms = ?6 AND owner_pid = ?7",
            params![
                run_id,
                status::OPEN,
                now_millis() as i64,
                std::process::id() as i64,
                status::STOPPED,
                seen_heartbeat,
                seen_owner,
            ],
        )?;
        Ok(claimed == 1)
    }

    /// Hands every trade of one run to `each`, in trade order, one at a time.
    ///
    /// This is how the exchange builds its positions again on a resume. It
    /// hands over one row at a time instead of returning a vector, and that is
    /// the whole point. A run's trade record has no upper size, and the memory
    /// used to run it again must have one. SQLite walks the primary key, and
    /// this function holds one row at a time.
    pub fn stream_trades(
        &self,
        run_id: i64,
        mut each: impl FnMut(TradeRow),
    ) -> Result<u64, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT trade_id, timestamp, symbol, price_cents, qty_tenths,
                    maker_order, maker_account, taker_order, taker_account, taker_side
             FROM trades WHERE run_id = ?1 ORDER BY trade_id",
        )?;
        let mut rows = statement.query(params![run_id])?;
        let mut count = 0u64;
        while let Some(row) = rows.next()? {
            let side: String = row.get(9)?;
            each(TradeRow {
                trade_id: row.get::<_, i64>(0)? as u64,
                timestamp: row.get::<_, i64>(1)? as u64,
                symbol: row.get(2)?,
                price_cents: row.get(3)?,
                qty_tenths: row.get(4)?,
                maker_order: row.get::<_, i64>(5)? as OrderId,
                maker_account: row.get::<_, i64>(6)? as AccountId,
                taker_order: row.get::<_, i64>(7)? as OrderId,
                taker_account: row.get::<_, i64>(8)? as AccountId,
                taker_side: side_from_text(&side)?,
            });
            count += 1;
        }
        Ok(count)
    }

    /// Reads one run back and checks it against itself before handing it over.
    fn load(&self, run_id: i64) -> Result<Snapshot, StoreError> {
        let (counters, chain_blob, operator_blob) = self
            .conn
            .query_row(
                "SELECT last_seen, messages_processed, cancels_applied,
                        cancels_ignored, orders_ignored, chain_hash, rule_version,
                        operator_key
                 FROM resume_point WHERE run_id = ?1",
                params![run_id],
                |row| {
                    Ok((
                        Counters {
                            last_seen: row.get::<_, i64>(0)? as OrderId,
                            messages_processed: row.get::<_, i64>(1)? as u64,
                            cancels_applied: row.get::<_, i64>(2)? as u64,
                            cancels_ignored: row.get::<_, i64>(3)? as u64,
                            orders_ignored: row.get::<_, i64>(4)? as u64,
                            // NULL means somebody recorded the run before rule
                            // sets existed. That build had no self-trade rule,
                            // so it matched under rule set 1 whatever the log
                            // said. 1 is the true reading, and not a guess.
                            rule_version: row
                                .get::<_, Option<i64>>(6)?
                                .unwrap_or(1)
                                .try_into()
                                .unwrap_or(1),
                            operator_key: None,
                            orders_ignored_by_kind: BTreeMap::new(),
                            chain: None,
                        },
                        row.get::<_, Option<Vec<u8>>>(5)?,
                        row.get::<_, Option<Vec<u8>>>(7)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StoreError::Corrupt(format!("run {} has no resume point", run_id)))?;
        // NULL means the run is older than the chain hash. Somebody wrote that
        // run at schema v2, before v3 added the column. Nobody knows the value,
        // and that is not corruption. The run resumes, and the hash checking
        // starts again on the next run.
        let mut counters = counters;
        counters.chain = match chain_blob {
            Some(blob) => Some(blob.try_into().map_err(|blob: Vec<u8>| {
                StoreError::Corrupt(format!("chain hash has {} bytes, expected 32", blob.len()))
            })?),
            None => None,
        };
        // NULL means the log had named no operator yet. Every log is in that
        // state until its first operator message. A blob of any other length
        // did not come from this exchange. The exchange only ever stores the
        // 32 bytes of a key that it checked a signature with.
        counters.operator_key = match operator_blob {
            Some(blob) => Some(blob.try_into().map_err(|blob: Vec<u8>| {
                StoreError::Corrupt(format!(
                    "run {} records an operator key of {} bytes, expected 32",
                    run_id,
                    blob.len()
                ))
            })?),
            None => None,
        };

        // The split of `orders_ignored` by reason. No rows means the run
        // refused no order, which is what a run that refused no order wrote.
        // The upgrade from version 9 writes a `not_recorded` row for a run
        // that did refuse orders, so the two cases stay apart.
        //
        // A negative count did not come from this exchange. `commit` only ever
        // stores a `u64` that it counted up from zero.
        let mut by_kind: BTreeMap<String, u64> = BTreeMap::new();
        let mut kinds = self
            .conn
            .prepare("SELECT kind, count FROM orders_ignored_kinds WHERE run_id = ?1")?;
        let mut rows = kinds.query(params![run_id])?;
        while let Some(row) = rows.next()? {
            let kind: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            if count < 0 {
                return Err(StoreError::Corrupt(format!(
                    "run {} says it refused {} orders for '{}'",
                    run_id, count, kind
                )));
            }
            by_kind.insert(kind, count as u64);
        }
        // The whole promise of the split is that it adds up to the total. A
        // file where it does not add up describes two different histories.
        // Resuming from that file would serve a number the exchange cannot
        // stand behind.
        let split: u64 = by_kind.values().copied().sum();
        if split != counters.orders_ignored {
            return Err(StoreError::Corrupt(format!(
                "run {} ignored {} orders but its reasons add up to {}",
                run_id, counters.orders_ignored, split
            )));
        }
        counters.orders_ignored_by_kind = by_kind;

        // Smallest order id first is also the trading order inside one price
        // level, where the order that arrived first trades first. The exchange
        // adds each order to the back of its price level as the sequencer
        // delivers it, and message ids always increase. So the two orders are
        // the same order.
        let orders: Vec<OrderRow> = self
            .conn
            .prepare(
                "SELECT order_id, account, symbol, side, price_cents, qty_tenths
                 FROM open_orders WHERE run_id = ?1 ORDER BY order_id",
            )?
            .query_map(params![run_id], |row| {
                Ok((
                    row.get::<_, i64>(0)? as OrderId,
                    row.get::<_, i64>(1)? as AccountId,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(
                |(order_id, account, symbol, side, price_cents, qty_tenths)| {
                    Ok(OrderRow {
                        order_id,
                        account,
                        symbol,
                        side: side_from_text(&side)?,
                        price_cents,
                        qty_tenths,
                    })
                },
            )
            .collect::<Result<Vec<_>, StoreError>>()?;

        // In symbol name order, which is the order the exchange's registry
        // keeps, and the order `state_root` hashes them in.
        let listings: Vec<ListingRow> = self
            .conn
            .prepare(
                "SELECT symbol, price_step_cents, quantity_step_tenths, listed, listed_by
                 FROM listings WHERE run_id = ?1 ORDER BY symbol",
            )?
            .query_map(params![run_id], |row| {
                Ok(ListingRow {
                    symbol: row.get(0)?,
                    price_step_cents: row.get(1)?,
                    quantity_step_tenths: row.get(2)?,
                    listed: row.get::<_, i64>(3)? != 0,
                    listed_by: row.get::<_, i64>(4)? as OrderId,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        // The exchange checks a price by taking a remainder, so a step of zero
        // would divide by zero. A negative step names no set of allowed
        // prices. The live code can write neither, because `apply_list_symbol`
        // refuses both. So somebody edited a row that holds one from outside
        // the exchange.
        if let Some(bad) = listings
            .iter()
            .find(|row| row.price_step_cents <= 0 || row.quantity_step_tenths <= 0)
        {
            return Err(StoreError::Corrupt(format!(
                "run {} lists '{}' on a price step of {} and a quantity step of {}; \
                 a step is a positive count of grid units",
                run_id, bad.symbol, bad.price_step_cents, bad.quantity_step_tenths
            )));
        }

        // This checks the trades here and reads them back one at a time later.
        // Three summary numbers from one SQL query answer exactly what the old
        // row-by-row loop answered. `(run_id, trade_id)` is a primary key, so
        // no two rows can hold the same trade id. Ids that count N and reach N
        // are then the ids 1 to N with no hole. And a smallest price above
        // zero, with a smallest quantity above zero, means every row is above
        // zero.
        let (trades_total, highest, cheapest, smallest): (i64, i64, i64, i64) =
            self.conn.query_row(
                "SELECT COUNT(*), COALESCE(MAX(trade_id), 0),
                        COALESCE(MIN(price_cents), 1), COALESCE(MIN(qty_tenths), 1)
                 FROM trades WHERE run_id = ?1",
                params![run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
        if highest != trades_total {
            return Err(StoreError::Corrupt(format!(
                "run {} holds {} trades but its highest trade id is {}; the log has a hole",
                run_id, trades_total, highest
            )));
        }
        if cheapest <= 0 || smallest <= 0 {
            return Err(StoreError::Corrupt(format!(
                "run {} holds a trade with price {} and quantity {}",
                run_id, cheapest, smallest
            )));
        }
        let trades_total = trades_total.max(0) as u64;

        let recent: Vec<OrderMessage> = self
            .conn
            .prepare("SELECT json FROM recent_messages WHERE run_id = ?1 ORDER BY msg_id")?
            .query_map(params![run_id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .map(|json| {
                serde_json::from_str(json).map_err(|e| {
                    StoreError::Corrupt(format!("recent message is not readable: {}", e))
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;

        let (feed_url, feed_session, feed_pubkey): (String, Option<String>, Option<String>) =
            self.conn.query_row(
                "SELECT feed_url, feed_session, feed_pubkey FROM runs WHERE run_id = ?1",
                params![run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;

        let last_claim_root: Option<[u8; 32]> = self
            .conn
            .query_row(
                "SELECT root_after FROM claims WHERE run_id = ?1 ORDER BY to_msg DESC LIMIT 1",
                params![run_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|blob| {
                blob.try_into().map_err(|blob: Vec<u8>| {
                    StoreError::Corrupt(format!("claim root has {} bytes, expected 32", blob.len()))
                })
            })
            .transpose()?;

        // Every batch that moved the cursor wrote a claim in the same
        // transaction as the cursor. So a run that consumed messages has a
        // claim root, and the restored state must hash back to that root. A
        // run that consumed messages and holds no claim is not a run with one
        // check unavailable. Deleting the claims table is exactly how somebody
        // who edits rows would turn that check off, and the check went off
        // with no message: `if let Some(root)` had nothing to compare. So the
        // missing root is the finding, and `load` refuses to resume on it.
        if counters.last_seen > 0 && last_claim_root.is_none() {
            return Err(StoreError::Corrupt(format!(
                "run {} consumed {} messages but holds no execution claim to check its state \
                 against; the claims table was emptied, or the run predates it. Resume with \
                 nothing vouching for the state is refused: start a fresh run with --reset-state",
                run_id, counters.last_seen
            )));
        }

        let snapshot = Snapshot {
            counters,
            orders,
            listings,
            trades_total,
            recent,
            feed_url,
            feed_session,
            feed_pubkey,
            last_claim_root,
        };
        check(&snapshot)?;
        Ok(snapshot)
    }
}

/// A second handle on the state database that can only read. The API's paged
/// history endpoints use it.
///
/// `Store` stays what it always was: the one writer, held by the poller, never
/// touched by a request handler. `HistoryReader` reads and never writes, on a
/// connection of its own.
///
/// `SQLITE_OPEN_READ_ONLY` is what makes "never writes" a fact instead of a
/// promise. SQLite itself refuses every write on a connection opened with that
/// flag. So a mistake in a request handler cannot damage the run the poller is
/// writing. A second read-write handle was rejected for that reason: it would
/// give a request handler a way to write, and the poller would no longer be
/// the one writer.
///
/// The same flag also makes SQLite refuse to create a file that is not there.
/// Opening with the create flag was rejected too. This handle is a view of a
/// database the writer already made, so a missing file is a fault to report,
/// and not an empty database to create.
///
/// `Store` opens the database with `journal_mode = WAL`. WAL is the
/// write-ahead log. In WAL mode SQLite appends new data to a second file
/// beside the database, and a reader keeps reading the older copy in the main
/// file until the writer finishes. So a reader does not block the poller's
/// commits, and a commit does not block a reader. That is what makes this
/// second connection safe.
///
/// Every query hands its page size to SQLite as a `LIMIT`, and the caller does
/// not cut the rows down after the read. `feed.rs` learned that rule the
/// expensive way. A `LIMIT` inside the statement makes a request for a million
/// rows cost one page of rows. Cutting the rows down after the read makes the
/// same request cost a million rows of memory first, and a page of them
/// second.
pub struct HistoryReader {
    conn: Connection,
}

const TRADES_BEFORE: &str = "SELECT trade_id, timestamp, symbol, price_cents, qty_tenths,
            maker_order, maker_account, taker_order, taker_account, taker_side
     FROM trades WHERE run_id = ?1 AND trade_id < ?2
     ORDER BY trade_id DESC LIMIT ?3";

const TRADES_BEFORE_SYMBOL: &str = "SELECT trade_id, timestamp, symbol, price_cents, qty_tenths,
            maker_order, maker_account, taker_order, taker_account, taker_side
     FROM trades WHERE run_id = ?1 AND trade_id < ?2 AND symbol = ?3
     ORDER BY trade_id DESC LIMIT ?4";

const TRADES_BEFORE_ACCOUNT: &str = "SELECT * FROM (
       SELECT * FROM (
         SELECT trade_id, timestamp, symbol, price_cents, qty_tenths,
                maker_order, maker_account, taker_order, taker_account, taker_side
         FROM trades
         WHERE run_id = ?1 AND maker_account = ?3 AND trade_id < ?2
         ORDER BY trade_id DESC LIMIT ?4
       )
       UNION
       SELECT * FROM (
         SELECT trade_id, timestamp, symbol, price_cents, qty_tenths,
                maker_order, maker_account, taker_order, taker_account, taker_side
         FROM trades
         WHERE run_id = ?1 AND taker_account = ?3 AND trade_id < ?2
         ORDER BY trade_id DESC LIMIT ?4
       )
     )
     ORDER BY trade_id DESC LIMIT ?4";

const TRADES_BEFORE_ACCOUNT_SYMBOL: &str = "SELECT * FROM (
       SELECT * FROM (
         SELECT trade_id, timestamp, symbol, price_cents, qty_tenths,
                maker_order, maker_account, taker_order, taker_account, taker_side
         FROM trades
         WHERE run_id = ?1 AND maker_account = ?3 AND symbol = ?4 AND trade_id < ?2
         ORDER BY trade_id DESC LIMIT ?5
       )
       UNION
       SELECT * FROM (
         SELECT trade_id, timestamp, symbol, price_cents, qty_tenths,
                maker_order, maker_account, taker_order, taker_account, taker_side
         FROM trades
         WHERE run_id = ?1 AND taker_account = ?3 AND symbol = ?4 AND trade_id < ?2
         ORDER BY trade_id DESC LIMIT ?5
       )
     )
     ORDER BY trade_id DESC LIMIT ?5";

const ACCOUNT_TRADES_BETWEEN: &str = "SELECT * FROM (
       SELECT * FROM (
         SELECT trade_id, timestamp, symbol, price_cents, qty_tenths,
                maker_order, maker_account, taker_order, taker_account, taker_side
         FROM trades
         WHERE run_id = ?1 AND maker_account = ?4
           AND trade_id > ?2 AND trade_id <= ?3
         ORDER BY trade_id LIMIT ?5
       )
       UNION
       SELECT * FROM (
         SELECT trade_id, timestamp, symbol, price_cents, qty_tenths,
                maker_order, maker_account, taker_order, taker_account, taker_side
         FROM trades
         WHERE run_id = ?1 AND taker_account = ?4
           AND trade_id > ?2 AND trade_id <= ?3
         ORDER BY trade_id LIMIT ?5
       )
     )
     ORDER BY trade_id LIMIT ?5";

impl HistoryReader {
    /// Opens `path` read-only. SQLite returns an error here instead of
    /// creating a file, because this handle is a view of a database the writer
    /// already made.
    pub fn open(path: &Path) -> Result<HistoryReader, StoreError> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )?;
        // SQLite lets only one connection write at a time, and it makes the
        // other connections wait. The poller commits while these queries run,
        // so a read here can meet the poller's lock. The busy timeout tells
        // SQLite to wait up to 5 seconds for that lock instead of returning an
        // error at once. Waiting is better than answering a request with an
        // error.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(HistoryReader { conn })
    }

    /// One page of a run's claims, in message order, starting after `since`.
    /// A page shorter than `limit` is the end of the run's claims.
    pub fn claims_since(
        &self,
        run_id: i64,
        since: OrderId,
        limit: usize,
    ) -> Result<Vec<ClaimRow>, StoreError> {
        self.conn
            .prepare(
                "SELECT from_msg, to_msg, root_before, root_after, trades_total, signature
                 FROM claims WHERE run_id = ?1 AND from_msg > ?2
                 ORDER BY from_msg LIMIT ?3",
            )?
            .query_map(params![run_id, since as i64, limit as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(
                |(from_msg, to_msg, before, after, trades_total, signature)| {
                    Ok(ClaimRow {
                        from_msg: from_msg.max(0) as OrderId,
                        to_msg: to_msg.max(0) as OrderId,
                        root_before: fixed(before, "claim root")?,
                        root_after: fixed(after, "claim root")?,
                        trades_total: trades_total.max(0) as u64,
                        signature: signature
                            .map(|bytes| fixed::<64>(bytes, "claim signature"))
                            .transpose()?,
                    })
                },
            )
            .collect()
    }

    /// The newest trades of a run with an id below `before`, newest first. The
    /// caller can also give a symbol, an account, or both.
    ///
    /// Each filter has its own statement. In particular, an account lookup is
    /// two bounded index reads, one for each side of a fill. Keeping the account
    /// predicate inside an optional `OR` made an unused account walk every
    /// trade in the run before it could answer with an empty list.
    pub fn trades_before(
        &self,
        run_id: i64,
        before: u64,
        symbol: Option<String>,
        account: Option<AccountId>,
        limit: usize,
    ) -> Result<Vec<TradeRow>, StoreError> {
        match (symbol, account) {
            (None, None) => {
                self.read_trades(TRADES_BEFORE, params![run_id, before as i64, limit as i64])
            }
            (Some(symbol), None) => self.read_trades(
                TRADES_BEFORE_SYMBOL,
                params![run_id, before as i64, symbol, limit as i64],
            ),
            (None, Some(account)) => self.read_trades(
                TRADES_BEFORE_ACCOUNT,
                params![run_id, before as i64, account as i64, limit as i64],
            ),
            (Some(symbol), Some(account)) => self.read_trades(
                TRADES_BEFORE_ACCOUNT_SYMBOL,
                params![run_id, before as i64, account as i64, symbol, limit as i64],
            ),
        }
    }

    /// One page of a run's trades, in trade order, starting after `since`.
    pub fn trades_since(
        &self,
        run_id: i64,
        since: u64,
        limit: usize,
    ) -> Result<Vec<TradeRow>, StoreError> {
        self.read_trades(
            "SELECT trade_id, timestamp, symbol, price_cents, qty_tenths,
                    maker_order, maker_account, taker_order, taker_account, taker_side
             FROM trades WHERE run_id = ?1 AND trade_id > ?2
             ORDER BY trade_id LIMIT ?3",
            params![run_id, since as i64, limit as i64],
        )
    }

    /// One bounded page of the trades one account took part in, oldest first.
    ///
    /// A self-trade appears on both sides of the union. `UNION`, rather than
    /// `UNION ALL`, keeps it one row so a caller can apply both sides exactly
    /// once from that row.
    pub fn account_trades_between(
        &self,
        run_id: i64,
        account: AccountId,
        after: u64,
        through: u64,
        limit: usize,
    ) -> Result<Vec<TradeRow>, StoreError> {
        self.read_trades(
            ACCOUNT_TRADES_BETWEEN,
            params![
                run_id,
                after as i64,
                through as i64,
                account as i64,
                limit as i64
            ],
        )
    }

    /// The newest durable trade id in one run.
    pub fn newest_trade_id(&self, run_id: i64) -> Result<u64, StoreError> {
        let id: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(trade_id), 0) FROM trades WHERE run_id = ?1",
            params![run_id],
            |row| row.get(0),
        )?;
        Ok(id.max(0) as u64)
    }

    /// The timestamp carried by one trade id.
    pub fn trade_timestamp(&self, run_id: i64, trade_id: u64) -> Result<Option<u64>, StoreError> {
        self.conn
            .query_row(
                "SELECT timestamp FROM trades WHERE run_id = ?1 AND trade_id = ?2",
                params![run_id, trade_id as i64],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map(|value| value.map(|timestamp| timestamp.max(0) as u64))
            .map_err(StoreError::from)
    }

    /// The newest price one symbol had at or before a trade id.
    pub fn last_price_at(
        &self,
        run_id: i64,
        symbol: &str,
        trade_id: u64,
    ) -> Result<Option<i64>, StoreError> {
        self.conn
            .query_row(
                "SELECT price_cents FROM trades
                 WHERE run_id = ?1 AND symbol = ?2 AND trade_id <= ?3
                 ORDER BY trade_id DESC LIMIT 1",
                params![run_id, symbol, trade_id as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// One page of trades, whichever query selected them. Every trade query
    /// shares this function, so they all read the columns back the same way.
    fn read_trades(
        &self,
        sql: &str,
        args: impl rusqlite::Params,
    ) -> Result<Vec<TradeRow>, StoreError> {
        self.conn
            .prepare(sql)?
            .query_map(args, |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)? as OrderId,
                    row.get::<_, i64>(6)? as AccountId,
                    row.get::<_, i64>(7)? as OrderId,
                    row.get::<_, i64>(8)? as AccountId,
                    row.get::<_, String>(9)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|row| {
                Ok(TradeRow {
                    trade_id: row.0,
                    timestamp: row.1,
                    symbol: row.2,
                    price_cents: row.3,
                    qty_tenths: row.4,
                    maker_order: row.5,
                    maker_account: row.6,
                    taker_order: row.7,
                    taker_account: row.8,
                    taker_side: side_from_text(&row.9)?,
                })
            })
            .collect()
    }
}

/// Reads a stored blob as a value of exactly `N` bytes. `what` names the value
/// in the error message, so a wrong byte count says which value was wrong.
fn fixed<const N: usize>(bytes: Vec<u8>, what: &str) -> Result<[u8; N], StoreError> {
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt(format!("{} has {} bytes, expected {}", what, len, N)))
}

/// Refuses a snapshot that contradicts itself.
///
/// These checks are cheap, and they are the difference between resuming and
/// resuming *correctly*. A database that somebody edited by hand, or that was
/// cut short, or that a half-finished migration wrote, fails one of them.
/// Failing to start is a far better result than serving positions worked out
/// from a hole in the record.
fn check(snapshot: &Snapshot) -> Result<(), StoreError> {
    for order in &snapshot.orders {
        if order.order_id > snapshot.counters.last_seen {
            return Err(StoreError::Corrupt(format!(
                "order {} is resting but the cursor only reached {}",
                order.order_id, snapshot.counters.last_seen
            )));
        }
        if order.qty_tenths <= 0 || order.price_cents <= 0 {
            return Err(StoreError::Corrupt(format!(
                "resting order {} has price {} and quantity {}",
                order.order_id, order.price_cents, order.qty_tenths
            )));
        }
    }

    if snapshot.trades_total > 0 && snapshot.counters.messages_processed == 0 {
        return Err(StoreError::Corrupt(
            "the run has trades but its cursor says it consumed no messages".to_string(),
        ));
    }

    Ok(())
}

/// Whether the process that last claimed a run still runs.
///
/// Answers `true` when it cannot tell. Taking over a run that another process
/// still holds applies every message that other exchange consumes a second
/// time. So an unknown answer must fall on the side of leaving the run alone.
fn process_is_alive(pid: i64) -> bool {
    if pid <= 0 {
        return false;
    }
    let procfs = Path::new("/proc");
    if !procfs.is_dir() {
        return true;
    }
    procfs.join(pid.to_string()).exists()
}

/// One row per committed batch: which state, plus which messages, gave which
/// state, and the exchange's signature over exactly that. Today `--audit` and
/// `--audit-url` check a row by running the run again. The row is also the
/// statement a zero-knowledge execution proof would cover, if somebody ever
/// builds one. Such a proof is one short value that anybody can check without
/// running the messages again. The fresh schema and the v4 -> v5 migration
/// share this constant, so the two can never differ.
///
/// `signature` allows NULL only so that a file written before schema 6 still
/// opens. `commit` refuses to write a row without a signature.
///
/// No comment goes inside this CREATE either. See `CREATE_SCHEMA`'s note on
/// `runs` for what a `--` comment does to a later `DROP COLUMN`.
const CREATE_CLAIMS: &str = "CREATE TABLE IF NOT EXISTS claims (
    run_id       INTEGER NOT NULL REFERENCES runs(run_id),
    from_msg     INTEGER NOT NULL,
    to_msg       INTEGER NOT NULL,
    root_before  BLOB    NOT NULL,
    root_after   BLOB    NOT NULL,
    trades_total INTEGER NOT NULL,
    signature    BLOB,
    PRIMARY KEY (run_id, from_msg)
);";

/// The symbol registry, one row per symbol the run's log has listed.
///
/// These rows go to disk because they are state that carries from one message
/// to the next. The exchange builds its registry again from them on a resume.
/// Without them it would resume with no symbol listed, and refuse every order
/// after the resume point.
///
/// `listed` is 0 for a delisted symbol, and the row stays. What the log listed
/// once, it listed. The read endpoints can still answer about the trades that
/// symbol made.
///
/// The two steps are counts of the exchange's own whole units, cents and
/// tenths. A `CHECK` keeps both above zero. A step of zero divides by zero in
/// the exchange's remainder test, and a negative step names no set of allowed
/// prices.
///
/// The fresh schema and the v6 -> v7 migration share this constant, so the two
/// can never differ. No comment inside the CREATE. See `CREATE_SCHEMA`.
const CREATE_LISTINGS: &str = "CREATE TABLE IF NOT EXISTS listings (
    run_id               INTEGER NOT NULL REFERENCES runs(run_id),
    symbol               TEXT    NOT NULL,
    price_step_cents     INTEGER NOT NULL CHECK (price_step_cents > 0),
    quantity_step_tenths INTEGER NOT NULL CHECK (quantity_step_tenths > 0),
    listed               INTEGER NOT NULL CHECK (listed IN (0,1)),
    listed_by            INTEGER NOT NULL DEFAULT 0 CHECK (listed_by >= 0),
    PRIMARY KEY (run_id, symbol)
);";

/// The split of `orders_ignored` by reason, one row per reason. A fresh file
/// and the v9 -> v10 upgrade both create the table from this constant, so the
/// two can never differ.
///
/// The reason is text and not a number, because there is no fixed list of
/// reasons to number. Each check names the reason it refuses on, and a check
/// added later names a new reason with no change to this file.
const CREATE_IGNORED_KINDS: &str = "CREATE TABLE IF NOT EXISTS orders_ignored_kinds (
    run_id INTEGER NOT NULL REFERENCES runs(run_id),
    kind   TEXT    NOT NULL,
    count  INTEGER NOT NULL CHECK (count >= 0),
    PRIMARY KEY (run_id, kind)
);";

/// Whether `table` already has `column`.
///
/// A migration asks before it alters. An older build ran its migrations
/// outside a transaction, so that build could leave a file half upgraded.
/// Asking first lets the next start finish such a file, instead of failing for
/// ever on a duplicate column.
fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool, StoreError> {
    // Every table name passed here is a literal in this file. None of them
    // comes from input, so this format string cannot carry an SQL injection.
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        if row.get::<_, String>(1)? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Runs one migration step, and the version number that step earns, in one
/// transaction.
///
/// The next start reads the version number to decide what still has to happen.
/// So the number must become true at the same instant the schema change does.
/// The old code wrote the number separately. A crash in between then left a
/// database that was at neither version: the next start ran an `ALTER` that
/// had already happened, and died on it.
fn migration_step<F>(conn: &mut Connection, to_version: i64, apply: F) -> Result<(), StoreError>
where
    F: FnOnce(&rusqlite::Transaction<'_>) -> Result<(), StoreError>,
{
    // IMMEDIATE makes SQLite take the write lock at the start of the
    // transaction, and not at the first write. So this holds the lock before
    // it reads the schema. Two processes that open the same old file then wait
    // for each other, instead of working at the same time. The second one
    // reads the schema the first one left, and finds the first one's `ALTER`
    // already done. Without IMMEDIATE the second one would read the old schema
    // and then fail to apply an `ALTER` that had already happened.
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    apply(&tx)?;
    tx.pragma_update(None, "user_version", to_version)?;
    tx.commit()?;
    Ok(())
}

/// Creates the schema on a new file, upgrades an older one it knows how to
/// upgrade, or refuses one it does not.
fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version > 0 && version < SCHEMA_VERSION {
        // The upgrades run one after the other. Each one is small enough to
        // read whole, and each one commits with its own version number.
        if version < 2 {
            // v1 -> v2: a run row now names which of the sequencer's sessions
            // its cursor belongs to. NULL on an older run is truthful: nobody
            // recorded a session for that run.
            migration_step(conn, 2, |tx| {
                if !has_column(tx, "runs", "feed_session")? {
                    tx.execute_batch("ALTER TABLE runs ADD COLUMN feed_session TEXT;")?;
                }
                Ok(())
            })?;
        }
        if version < 3 {
            // v2 -> v3: the hash chain over the consumed history joins the
            // resume point, and a run row now names which sequencer key that
            // run pinned. NULL in either column means somebody recorded the
            // run before these columns existed. The exchange reads that as
            // unknown and invents no value.
            migration_step(conn, 3, |tx| {
                if !has_column(tx, "resume_point", "chain_hash")? {
                    tx.execute_batch("ALTER TABLE resume_point ADD COLUMN chain_hash BLOB;")?;
                }
                if !has_column(tx, "runs", "feed_pubkey")? {
                    tx.execute_batch("ALTER TABLE runs ADD COLUMN feed_pubkey TEXT;")?;
                }
                Ok(())
            })?;
        }
        if version < 4 {
            // v3 -> v4: the CSV trade log is gone. The trades table is the
            // trade record now, so the two columns that described the CSV file
            // go with it.
            migration_step(conn, 4, |tx| {
                if has_column(tx, "runs", "trade_log")? {
                    tx.execute_batch("ALTER TABLE runs DROP COLUMN trade_log;")?;
                }
                if has_column(tx, "resume_point", "trade_log_failures")? {
                    tx.execute_batch("ALTER TABLE resume_point DROP COLUMN trade_log_failures;")?;
                }
                Ok(())
            })?;
        }
        if version < 5 {
            // v4 -> v5: execution claims. See the CREATE TABLE below.
            migration_step(conn, 5, |tx| {
                tx.execute_batch(CREATE_CLAIMS)?;
                Ok(())
            })?;
        }
        if version < 6 {
            // v5 -> v6: a claim now carries the exchange's signature. NULL on
            // a row written before the key existed, which is truthful: nobody
            // signed that row. The audit says so, and invents no signature
            // that would check against nothing.
            migration_step(conn, 6, |tx| {
                if !has_column(tx, "claims", "signature")? {
                    tx.execute_batch("ALTER TABLE claims ADD COLUMN signature BLOB;")?;
                }
                if !has_column(tx, "runs", "matcher_pubkey")? {
                    tx.execute_batch("ALTER TABLE runs ADD COLUMN matcher_pubkey TEXT;")?;
                }
                Ok(())
            })?;
        }
        if version < 7 {
            // v6 -> v7: the rule set the run was matching under. NULL on a run
            // an older build wrote, and that means rule set 1: the older build
            // had no self-trade rule to turn on.
            migration_step(conn, 7, |tx| {
                if !has_column(tx, "resume_point", "rule_version")? {
                    tx.execute_batch("ALTER TABLE resume_point ADD COLUMN rule_version INTEGER;")?;
                }
                Ok(())
            })?;
        }
        if version < 8 {
            // v7 -> v8: the symbol registry. An upgraded run comes back with
            // no listing at all, which is truthful: its log never carried a
            // `ListSymbol` message, so nobody listed anything in it. That run
            // does not resume anyway. Its committed claim roots were hashed
            // under `exchange-state-v2`, and this build hashes v3.
            migration_step(conn, 8, |tx| {
                tx.execute_batch(CREATE_LISTINGS)?;
                Ok(())
            })?;
        }
        if version < 9 {
            // v8 -> v9: the operator key the log named. NULL on an upgraded
            // run, which is truthful: nobody checked an operator signature in
            // that run, so it named no operator. That run does not resume
            // anyway. Its claim roots were hashed under `exchange-state-v3`,
            // and this build hashes v4.
            migration_step(conn, 9, |tx| {
                if !has_column(tx, "resume_point", "operator_key")? {
                    tx.execute_batch("ALTER TABLE resume_point ADD COLUMN operator_key BLOB;")?;
                }
                Ok(())
            })?;
        }
        if version < 10 {
            // v9 -> v10: the split of `orders_ignored` by reason. An upgraded
            // run gets its whole stored total under the reason
            // `not_recorded`, which is the truth about that run: the older
            // build counted those refusals and stored no reason for any of
            // them.
            //
            // An empty table would read as "no order was ever refused". The
            // exchange would then serve a split of nothing beside a total of
            // 620, which is the exact mismatch this version exists to end. One
            // row makes the split add up to the total from the first restart.
            //
            // A run that refused no order gets no row, because it has nothing
            // to say.
            migration_step(conn, 10, |tx| {
                tx.execute_batch(CREATE_IGNORED_KINDS)?;
                tx.execute(
                    "INSERT OR REPLACE INTO orders_ignored_kinds (run_id, kind, count)
                     SELECT run_id, 'not_recorded', orders_ignored
                     FROM resume_point WHERE orders_ignored > 0",
                    [],
                )?;
                Ok(())
            })?;
        }
        if version < 11 {
            // v10 -> v11: the id of the message that listed each market. An
            // upgraded run gets 0 on every row, which is the truth about that
            // run: it recorded which markets were listed, and not the order
            // somebody listed them in. `/market` prints those rows in name
            // order.
            //
            // This asks whether the column is there, and does not assume,
            // because `CREATE_LISTINGS` already names the column. A file that
            // upgrades from v7 gets the table with this column already in it,
            // and must not be altered a second time.
            //
            // `state_root` does not hash this field, so an older run still
            // resumes. Its committed claim roots are the roots this build
            // computes.
            migration_step(conn, 11, |tx| {
                if !has_column(tx, "listings", "listed_by")? {
                    tx.execute_batch(
                        "ALTER TABLE listings
                         ADD COLUMN listed_by INTEGER NOT NULL DEFAULT 0 CHECK (listed_by >= 0);",
                    )?;
                }
                Ok(())
            })?;
        }
        if version < 12 {
            // v11 -> v12: the public trade filters can now answer an account
            // or a symbol without walking unrelated fills. These indexes hold
            // no new fact and can be rebuilt from the trades table.
            migration_step(conn, 12, |tx| {
                tx.execute_batch(CREATE_TRADE_INDEXES)?;
                Ok(())
            })?;
        }
        return Ok(());
    }
    if version != 0 {
        return Err(StoreError::Version(version));
    }

    // The fresh schema, the claims table, the listings table, the refusal
    // reasons, and the version number that says they are all there: one
    // transaction, for the same reason as the upgrades above.
    migration_step(conn, SCHEMA_VERSION, |tx| {
        tx.execute_batch(CREATE_SCHEMA)?;
        tx.execute_batch(CREATE_CLAIMS)?;
        tx.execute_batch(CREATE_LISTINGS)?;
        tx.execute_batch(CREATE_IGNORED_KINDS)?;
        tx.execute_batch(CREATE_TRADE_INDEXES)?;
        Ok(())
    })
}

/// Read indexes over the append-only trade record.
///
/// The primary key already answers an unfiltered history walk. The five
/// indexes below bound the public filters without changing which rows they
/// return. Maker and taker stay separate so SQLite can enter each side at one
/// account instead of treating `maker = account OR taker = account` as a scan.
const CREATE_TRADE_INDEXES: &str = "
    CREATE INDEX IF NOT EXISTS trades_maker_account
      ON trades (run_id, maker_account, trade_id);
    CREATE INDEX IF NOT EXISTS trades_taker_account
      ON trades (run_id, taker_account, trade_id);
    CREATE INDEX IF NOT EXISTS trades_maker_account_symbol
      ON trades (run_id, maker_account, symbol, trade_id);
    CREATE INDEX IF NOT EXISTS trades_taker_account_symbol
      ON trades (run_id, taker_account, symbol, trade_id);
    CREATE INDEX IF NOT EXISTS trades_symbol
      ON trades (run_id, symbol, trade_id);
";

/// The schema a new database starts with, without the claims table. `migrate`
/// creates that table from `CREATE_CLAIMS`, so the fresh file and the v4 -> v5
/// upgrade can never differ.
const CREATE_SCHEMA: &str = "
         -- One row per engine lifetime. Nothing is ever deleted from here: a
         -- run that ended because the feed restarted is still a true record of
         -- what this engine matched, and an operator has to be able to read it.
         --
         -- `matcher_pubkey` is the key this run's execution claims are signed
         -- with, recorded so an auditor holding only this file can check them
         -- and so a resume can refuse to continue a run whose key changed.
         --
         -- No comment goes inside this CREATE, and that is not a style
         -- preference. ALTER TABLE ... DROP COLUMN rewrites the statement
         -- SQLite stored, and a -- comment attached to the last column ends
         -- up swallowing the closing bracket: the drop then fails as
         -- incomplete input, and that column can never be removed from any
         -- database ever created with it. The v3 -> v4 step below drops a
         -- column from this very table, so this is a live foot-gun.
         CREATE TABLE runs (
           run_id       INTEGER PRIMARY KEY AUTOINCREMENT,
           started_at   INTEGER NOT NULL,
           closed_at    INTEGER,
           heartbeat_ms INTEGER NOT NULL,
           status       TEXT    NOT NULL,
           feed_url     TEXT    NOT NULL,
           owner_pid    INTEGER NOT NULL,
           feed_session TEXT,
           feed_pubkey  TEXT,
           matcher_pubkey TEXT
         );

         -- The resume point, written in the same transaction as the state it
         -- describes so it can never run ahead of it. The chain hash is the
         -- cursor's content: which bytes the consumed messages were.
         CREATE TABLE resume_point (
           run_id             INTEGER PRIMARY KEY REFERENCES runs(run_id),
           last_seen          INTEGER NOT NULL,
           messages_processed INTEGER NOT NULL,
           cancels_applied    INTEGER NOT NULL,
           cancels_ignored    INTEGER NOT NULL,
           orders_ignored     INTEGER NOT NULL,
           chain_hash         BLOB,
           rule_version       INTEGER,
           operator_key       BLOB
         );

         CREATE TABLE open_orders (
           run_id      INTEGER NOT NULL REFERENCES runs(run_id),
           order_id    INTEGER NOT NULL,
           account     INTEGER NOT NULL,
           symbol      TEXT    NOT NULL,
           side        TEXT    NOT NULL CHECK (side IN ('Buy','Sell')),
           price_cents INTEGER NOT NULL CHECK (price_cents > 0),
           qty_tenths  INTEGER NOT NULL CHECK (qty_tenths > 0),
           PRIMARY KEY (run_id, order_id)
         );
         CREATE INDEX open_orders_level
           ON open_orders (run_id, symbol, side, price_cents, order_id);

         CREATE TABLE trades (
           run_id        INTEGER NOT NULL REFERENCES runs(run_id),
           trade_id      INTEGER NOT NULL,
           timestamp     INTEGER NOT NULL,
           symbol        TEXT    NOT NULL,
           price_cents   INTEGER NOT NULL CHECK (price_cents > 0),
           qty_tenths    INTEGER NOT NULL CHECK (qty_tenths > 0),
           maker_order   INTEGER NOT NULL,
           maker_account INTEGER NOT NULL,
           taker_order   INTEGER NOT NULL,
           taker_account INTEGER NOT NULL,
           taker_side    TEXT    NOT NULL CHECK (taker_side IN ('Buy','Sell')),
           PRIMARY KEY (run_id, trade_id)
         );

         CREATE TABLE recent_messages (
           run_id INTEGER NOT NULL REFERENCES runs(run_id),
           msg_id INTEGER NOT NULL,
           json   TEXT    NOT NULL,
           PRIMARY KEY (run_id, msg_id)
         );

         -- For reading the trades by hand. The engine never selects from this:
         -- dividing by 100 and 10 produces the floats the tables exist to keep
         -- out of the arithmetic.
         CREATE VIEW trades_readable AS
           SELECT run_id, trade_id, timestamp, symbol,
                  price_cents / 100.0 AS price,
                  qty_tenths / 10.0   AS quantity,
                  maker_order, maker_account, taker_order, taker_account, taker_side
           FROM trades;
";

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// The schema exactly as version 5 left it: `claims` with no signature
    /// column, `runs` with no key column. Written out in full, and not built
    /// from today's constants. The point of the test is that a file an *older
    /// build* wrote still opens.
    const V5_SCHEMA: &str = "
        CREATE TABLE runs (
          run_id       INTEGER PRIMARY KEY AUTOINCREMENT,
          started_at   INTEGER NOT NULL,
          closed_at    INTEGER,
          heartbeat_ms INTEGER NOT NULL,
          status       TEXT    NOT NULL,
          feed_url     TEXT    NOT NULL,
          owner_pid    INTEGER NOT NULL,
          feed_session TEXT,
          feed_pubkey  TEXT
        );
        CREATE TABLE resume_point (
          run_id             INTEGER PRIMARY KEY REFERENCES runs(run_id),
          last_seen          INTEGER NOT NULL,
          messages_processed INTEGER NOT NULL,
          cancels_applied    INTEGER NOT NULL,
          cancels_ignored    INTEGER NOT NULL,
          orders_ignored     INTEGER NOT NULL,
          chain_hash         BLOB
        );
        CREATE TABLE open_orders (
          run_id      INTEGER NOT NULL REFERENCES runs(run_id),
          order_id    INTEGER NOT NULL,
          account     INTEGER NOT NULL,
          symbol      TEXT    NOT NULL,
          side        TEXT    NOT NULL CHECK (side IN ('Buy','Sell')),
          price_cents INTEGER NOT NULL CHECK (price_cents > 0),
          qty_tenths  INTEGER NOT NULL CHECK (qty_tenths > 0),
          PRIMARY KEY (run_id, order_id)
        );
        CREATE TABLE trades (
          run_id        INTEGER NOT NULL REFERENCES runs(run_id),
          trade_id      INTEGER NOT NULL,
          timestamp     INTEGER NOT NULL,
          symbol        TEXT    NOT NULL,
          price_cents   INTEGER NOT NULL CHECK (price_cents > 0),
          qty_tenths    INTEGER NOT NULL CHECK (qty_tenths > 0),
          maker_order   INTEGER NOT NULL,
          maker_account INTEGER NOT NULL,
          taker_order   INTEGER NOT NULL,
          taker_account INTEGER NOT NULL,
          taker_side    TEXT    NOT NULL CHECK (taker_side IN ('Buy','Sell')),
          PRIMARY KEY (run_id, trade_id)
        );
        CREATE TABLE recent_messages (
          run_id INTEGER NOT NULL REFERENCES runs(run_id),
          msg_id INTEGER NOT NULL,
          json   TEXT    NOT NULL,
          PRIMARY KEY (run_id, msg_id)
        );
        CREATE TABLE claims (
          run_id       INTEGER NOT NULL REFERENCES runs(run_id),
          from_msg     INTEGER NOT NULL,
          to_msg       INTEGER NOT NULL,
          root_before  BLOB    NOT NULL,
          root_after   BLOB    NOT NULL,
          trades_total INTEGER NOT NULL,
          PRIMARY KEY (run_id, from_msg)
        );
        PRAGMA user_version = 5;
    ";

    /// The schema exactly as version 9 left it: every table this build has,
    /// except `orders_ignored_kinds`. Written out in full for the reason
    /// `V5_SCHEMA` is. The test is about a file an *older build* wrote.
    /// Building the schema from today's constants would quietly turn it into a
    /// file this build wrote, as soon as one of those constants changes.
    const V9_SCHEMA: &str = "
        CREATE TABLE runs (
          run_id       INTEGER PRIMARY KEY AUTOINCREMENT,
          started_at   INTEGER NOT NULL,
          closed_at    INTEGER,
          heartbeat_ms INTEGER NOT NULL,
          status       TEXT    NOT NULL,
          feed_url     TEXT    NOT NULL,
          owner_pid    INTEGER NOT NULL,
          feed_session TEXT,
          feed_pubkey  TEXT,
          matcher_pubkey TEXT
        );
        CREATE TABLE resume_point (
          run_id             INTEGER PRIMARY KEY REFERENCES runs(run_id),
          last_seen          INTEGER NOT NULL,
          messages_processed INTEGER NOT NULL,
          cancels_applied    INTEGER NOT NULL,
          cancels_ignored    INTEGER NOT NULL,
          orders_ignored     INTEGER NOT NULL,
          chain_hash         BLOB,
          rule_version       INTEGER,
          operator_key       BLOB
        );
        CREATE TABLE open_orders (
          run_id      INTEGER NOT NULL REFERENCES runs(run_id),
          order_id    INTEGER NOT NULL,
          account     INTEGER NOT NULL,
          symbol      TEXT    NOT NULL,
          side        TEXT    NOT NULL CHECK (side IN ('Buy','Sell')),
          price_cents INTEGER NOT NULL CHECK (price_cents > 0),
          qty_tenths  INTEGER NOT NULL CHECK (qty_tenths > 0),
          PRIMARY KEY (run_id, order_id)
        );
        CREATE TABLE trades (
          run_id        INTEGER NOT NULL REFERENCES runs(run_id),
          trade_id      INTEGER NOT NULL,
          timestamp     INTEGER NOT NULL,
          symbol        TEXT    NOT NULL,
          price_cents   INTEGER NOT NULL CHECK (price_cents > 0),
          qty_tenths    INTEGER NOT NULL CHECK (qty_tenths > 0),
          maker_order   INTEGER NOT NULL,
          maker_account INTEGER NOT NULL,
          taker_order   INTEGER NOT NULL,
          taker_account INTEGER NOT NULL,
          taker_side    TEXT    NOT NULL CHECK (taker_side IN ('Buy','Sell')),
          PRIMARY KEY (run_id, trade_id)
        );
        CREATE TABLE recent_messages (
          run_id INTEGER NOT NULL REFERENCES runs(run_id),
          msg_id INTEGER NOT NULL,
          json   TEXT    NOT NULL,
          PRIMARY KEY (run_id, msg_id)
        );
        CREATE TABLE claims (
          run_id       INTEGER NOT NULL REFERENCES runs(run_id),
          from_msg     INTEGER NOT NULL,
          to_msg       INTEGER NOT NULL,
          root_before  BLOB    NOT NULL,
          root_after   BLOB    NOT NULL,
          trades_total INTEGER NOT NULL,
          signature    BLOB,
          PRIMARY KEY (run_id, from_msg)
        );
        CREATE TABLE listings (
          run_id               INTEGER NOT NULL REFERENCES runs(run_id),
          symbol               TEXT    NOT NULL,
          price_step_cents     INTEGER NOT NULL CHECK (price_step_cents > 0),
          quantity_step_tenths INTEGER NOT NULL CHECK (quantity_step_tenths > 0),
          listed               INTEGER NOT NULL CHECK (listed IN (0,1)),
          PRIMARY KEY (run_id, symbol)
        );
        PRAGMA user_version = 9;
    ";

    fn columns(conn: &Connection, table: &str) -> Vec<String> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({})", table))
            .expect("the table exists");
        stmt.query_map([], |row| row.get::<_, String>(1))
            .expect("columns")
            .collect::<rusqlite::Result<Vec<String>>>()
            .expect("columns")
    }

    fn indexes(conn: &Connection, table: &str) -> Vec<String> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA index_list({})", table))
            .expect("the table exists");
        stmt.query_map([], |row| row.get::<_, String>(1))
            .expect("indexes")
            .collect::<rusqlite::Result<Vec<String>>>()
            .expect("indexes")
    }

    fn query_plan(conn: &Connection, sql: &str, args: impl rusqlite::Params) -> Vec<String> {
        let mut statement = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .expect("the query has a plan");
        statement
            .query_map(args, |row| row.get::<_, String>(3))
            .expect("the plan runs")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("the plan is readable")
    }

    /// A database an older build left behind opens, gains the two columns that
    /// version 6 adds, and keeps the run and the claim it already held. The
    /// old claim keeps a NULL signature, which is the truth about that claim:
    /// nobody signed it. The audit says so, and invents no signature.
    #[test]
    fn a_version_5_database_is_upgraded_in_place() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        {
            let conn = Connection::open(&path).expect("opens");
            conn.execute_batch(V5_SCHEMA).expect("the v5 schema");
            conn.execute_batch(
                "INSERT INTO runs (started_at, heartbeat_ms, status, feed_url, owner_pid,
                                   feed_session, feed_pubkey)
                   VALUES (0, 0, 'stopped', 'http://feed', 0, 'sess', 'ff');
                 INSERT INTO resume_point (run_id, last_seen, messages_processed,
                                           cancels_applied, cancels_ignored, orders_ignored,
                                           chain_hash)
                   VALUES (1, 3, 3, 0, 0, 0, zeroblob(32));
                 INSERT INTO claims (run_id, from_msg, to_msg, root_before, root_after,
                                     trades_total)
                   VALUES (1, 1, 3, zeroblob(32), zeroblob(32), 0);",
            )
            .expect("some v5 rows");
        }

        let (store, snapshot) =
            Store::open_with_grace(&path, "http://feed", 0, false).expect("an older file opens");
        let snapshot = snapshot.expect("the run is resumable");
        assert_eq!(snapshot.counters.last_seen, 3);
        assert_eq!(store.run_id(), 1);
        assert_eq!(store.matcher_pubkey().expect("readable"), None);

        let conn = Connection::open(&path).expect("opens");
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("a version");
        assert_eq!(version, SCHEMA_VERSION);
        assert!(columns(&conn, "claims").iter().any(|c| c == "signature"));
        assert!(columns(&conn, "runs").iter().any(|c| c == "matcher_pubkey"));
        let trade_indexes = indexes(&conn, "trades");
        for required in [
            "trades_maker_account",
            "trades_taker_account",
            "trades_maker_account_symbol",
            "trades_taker_account_symbol",
            "trades_symbol",
        ] {
            assert!(
                trade_indexes.iter().any(|name| name == required),
                "the v12 upgrade adds {}: {:?}",
                required,
                trade_indexes
            );
        }
        let old_signature: Option<Vec<u8>> = conn
            .query_row(
                "SELECT signature FROM claims WHERE from_msg = 1",
                [],
                |row| row.get(0),
            )
            .expect("the old claim is still there");
        assert_eq!(
            old_signature, None,
            "an unsigned claim from an older build must stay unsigned"
        );

        // The symbol registry the v7 -> v8 step adds. It comes back empty,
        // which is the truth about a run whose log never carried a
        // `ListSymbol` message: nobody listed anything in that run. A table
        // that did not exist would make `load` fail on every upgraded file.
        assert_eq!(
            snapshot.listings,
            Vec::new(),
            "an upgraded run lists nothing, because its log never listed anything"
        );
    }

    #[test]
    fn account_trade_queries_enter_the_account_indexes() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        let (store, _) = Store::open(&path, "http://feed", 0, false).expect("opens");
        drop(store);
        let conn = Connection::open(&path).expect("opens");

        let account = query_plan(
            &conn,
            TRADES_BEFORE_ACCOUNT,
            params![1i64, i64::MAX, 4_294_967_295i64, 20i64],
        )
        .join("\n");
        assert!(account.contains("trades_maker_account"), "{account}");
        assert!(account.contains("trades_taker_account"), "{account}");
        assert!(
            !account.lines().any(|line| line.contains("SCAN trades")),
            "{account}"
        );

        let account_symbol = query_plan(
            &conn,
            TRADES_BEFORE_ACCOUNT_SYMBOL,
            params![1i64, i64::MAX, 4_294_967_295i64, "ABSENT-USDC", 20i64],
        )
        .join("\n");
        assert!(
            account_symbol.contains("trades_maker_account_symbol ("),
            "{account_symbol}"
        );
        assert!(
            account_symbol.contains("trades_taker_account_symbol ("),
            "{account_symbol}"
        );
    }

    /// A database a version 9 build wrote opens, and its run comes back with a
    /// split of `orders_ignored` that adds up to `orders_ignored`.
    ///
    /// Version 9 counted refusals and stored no reason for any of them. So the
    /// reasons are gone: the refused orders are not in this file, and nothing
    /// can bring them back. The upgrade says exactly that, under the reason
    /// `not_recorded`. The run resumes with 5 refusals it cannot explain, and
    /// not with 5 refusals and an empty split.
    ///
    /// An empty split is what the exchange had before this version, and it is
    /// the wrong answer. `/market` then served 620 orders ignored, beside
    /// reasons that added up to 320. The 300 in between looked like a fault in
    /// the count, and not like a gap in the record.
    #[test]
    fn a_version_9_database_comes_back_with_refusals_it_recorded_no_reason_for() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        {
            let conn = Connection::open(&path).expect("opens");
            conn.execute_batch(V9_SCHEMA).expect("the v9 schema");
            conn.execute_batch(
                "INSERT INTO runs (started_at, heartbeat_ms, status, feed_url, owner_pid,
                                   feed_session, feed_pubkey, matcher_pubkey)
                   VALUES (0, 0, 'stopped', 'http://feed', 0, 'sess', 'ff', 'ee');
                 INSERT INTO resume_point (run_id, last_seen, messages_processed,
                                           cancels_applied, cancels_ignored, orders_ignored,
                                           chain_hash, rule_version)
                   VALUES (1, 9, 9, 0, 0, 5, zeroblob(32), 2);
                 INSERT INTO claims (run_id, from_msg, to_msg, root_before, root_after,
                                     trades_total, signature)
                   VALUES (1, 1, 9, zeroblob(32), zeroblob(32), 0, zeroblob(64));",
            )
            .expect("some v9 rows");
        }

        let (store, snapshot) =
            Store::open_with_grace(&path, "http://feed", 0, false).expect("an older file opens");
        let snapshot = snapshot.expect("the run is resumable");
        assert_eq!(store.run_id(), 1);
        assert_eq!(snapshot.counters.orders_ignored, 5, "the total is kept");
        assert_eq!(
            snapshot.counters.orders_ignored_by_kind,
            BTreeMap::from([("not_recorded".to_string(), 5)]),
            "an older build counted these and stored no reason for any of them"
        );
        assert_eq!(
            snapshot
                .counters
                .orders_ignored_by_kind
                .values()
                .sum::<u64>(),
            snapshot.counters.orders_ignored,
            "the reasons add up to the total even when the reason is 'nobody wrote one'"
        );

        let conn = Connection::open(&path).expect("opens");
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("a version");
        assert_eq!(version, SCHEMA_VERSION);
    }

    /// A version 9 run that refused no order gets no row at all. So an empty
    /// split keeps one meaning, "no order was refused", and never gains the
    /// second meaning "the reasons were lost".
    #[test]
    fn a_version_9_database_that_refused_nothing_gains_no_reason() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        {
            let conn = Connection::open(&path).expect("opens");
            conn.execute_batch(V9_SCHEMA).expect("the v9 schema");
            conn.execute_batch(
                "INSERT INTO runs (started_at, heartbeat_ms, status, feed_url, owner_pid)
                   VALUES (0, 0, 'stopped', 'http://feed', 0);
                 INSERT INTO resume_point (run_id, last_seen, messages_processed,
                                           cancels_applied, cancels_ignored, orders_ignored,
                                           chain_hash)
                   VALUES (1, 4, 4, 0, 0, 0, zeroblob(32));
                 INSERT INTO claims (run_id, from_msg, to_msg, root_before, root_after,
                                     trades_total, signature)
                   VALUES (1, 1, 4, zeroblob(32), zeroblob(32), 0, zeroblob(64));",
            )
            .expect("some v9 rows");
        }

        let (_store, snapshot) =
            Store::open_with_grace(&path, "http://feed", 0, false).expect("an older file opens");
        let snapshot = snapshot.expect("the run is resumable");
        assert_eq!(snapshot.counters.orders_ignored, 0);
        assert!(snapshot.counters.orders_ignored_by_kind.is_empty());
    }

    /// A later migration can still drop every column of every table this
    /// schema creates.
    ///
    /// SQLite stores the CREATE statement of each table. `ALTER TABLE ... DROP
    /// COLUMN` writes that stored statement again, without the column. A `--`
    /// comment runs to the end of its line, so a `--` comment attached to the
    /// last column takes the closing bracket into the comment. The rewrite
    /// then fails with "incomplete input", and no database ever created with
    /// that statement can drop that column. This is not a theory: the v3 -> v4
    /// step drops a column from `runs`. A comment placed one line lower than
    /// it should be would leave the next person who touches this schema with a
    /// migration that fails on every existing file, and with nothing that says
    /// why.
    #[test]
    fn every_column_of_the_fresh_schema_can_still_be_dropped() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        let (store, _) = Store::open(&path, "http://feed", 200, false).expect("opens");
        drop(store);

        let mut conn = Connection::open(&path).expect("opens");
        // The view reads from `trades`, and SQLite refuses to drop a column
        // that a view names. That refusal is a real SQLite rule and not the
        // fault this test hunts. So this drops the view first, and then checks
        // the trades table.
        conn.execute_batch("DROP VIEW trades_readable;")
            .expect("view drops");
        for table in [
            "runs",
            "resume_point",
            "claims",
            "trades",
            "open_orders",
            "listings",
            "orders_ignored_kinds",
        ] {
            let names: Vec<String> = columns(&conn, table);
            for column in names {
                // Each drop runs inside a transaction this test throws away,
                // so the next drop starts from the full schema.
                let tx = conn.transaction().expect("a transaction");
                let attempt = tx.execute_batch(&format!(
                    "ALTER TABLE {} DROP COLUMN \"{}\";",
                    table, column
                ));
                if let Err(e) = attempt {
                    let text = e.to_string();
                    // SQLite refuses to drop a primary key column or an indexed
                    // column, and that refusal is the schema working as it
                    // should. The failure this test exists for is the one that
                    // says "incomplete input".
                    assert!(
                        !text.contains("incomplete input"),
                        "{}.{} cannot be dropped because the stored CREATE \
                         statement does not survive the rewrite: {}. Move the \
                         comment above the CREATE",
                        table,
                        column,
                        text
                    );
                }
                tx.rollback().expect("rolls back");
            }
        }
    }

    /// A signed claim goes into the file with its signature in the same
    /// statement, and comes back out of the paged reader with the signature
    /// still on it. Without the signature the endpoint would serve claims that
    /// nobody could check.
    #[test]
    fn a_signed_claim_round_trips_through_the_paged_reader() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("state.db");
        let (mut store, _) = Store::open(&path, "http://feed", 200, false).expect("opens");
        store.set_matcher_pubkey("aa").expect("key recorded");

        for id in 1..=3u64 {
            let claim = ClaimRow {
                from_msg: id,
                to_msg: id,
                root_before: [id as u8; 32],
                root_after: [id as u8 + 1; 32],
                trades_total: id,
                signature: Some([id as u8; 64]),
            };
            let counters = Counters {
                last_seen: id,
                messages_processed: id,
                ..Counters::default()
            };
            store.commit(&[], &counters, Some(&claim)).expect("commits");
        }
        let run_id = store.run_id();
        assert_eq!(
            store.matcher_pubkey().expect("readable").as_deref(),
            Some("aa")
        );
        drop(store);

        let reader = HistoryReader::open(&path).expect("a read-only view");
        let all = reader.claims_since(run_id, 0, 10).expect("a page");
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].signature, Some([1u8; 64]));

        // SQLite applies the page size, and `since` continues after the last
        // row of the page before.
        let first = reader.claims_since(run_id, 0, 2).expect("a page");
        assert_eq!(first.len(), 2);
        let rest = reader
            .claims_since(run_id, first[1].from_msg, 2)
            .expect("a page");
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].from_msg, 3);
        assert!(
            reader
                .claims_since(run_id, 3, 2)
                .expect("a page")
                .is_empty()
        );
    }

    /// A file that SQLite cannot open is not a file whose rows are wrong.
    ///
    /// The exchange prints different advice for each variant, and the advice
    /// for `Corrupt` is "start a fresh run with --reset-state". An operator
    /// whose disk is full, or whose `state.db` changed owner, would follow
    /// that advice and throw away a database with nothing wrong in it.
    #[test]
    fn a_file_that_cannot_be_opened_is_not_reported_as_corrupt() {
        let dir = TempDir::new().expect("a directory");

        // A path that is a directory. SQLite cannot open it.
        let err = Store::open_with_grace(dir.path(), "http://feed", 0, false)
            .err()
            .expect("a directory is not a database");
        assert!(matches!(err, StoreError::CannotOpen(_)), "got {:?}", err);
        assert!(
            err.to_string()
                .starts_with("cannot open the database file:"),
            "got {}",
            err
        );

        // The parent path is already a file, so nothing can create the
        // directory.
        let blocker = dir.path().join("not-a-directory");
        fs::write(&blocker, b"").expect("a file");
        let err = Store::open_with_grace(&blocker.join("state.db"), "http://feed", 0, false)
            .err()
            .expect("the parent is a file");
        assert!(matches!(err, StoreError::CannotOpen(_)), "got {:?}", err);
    }
}
