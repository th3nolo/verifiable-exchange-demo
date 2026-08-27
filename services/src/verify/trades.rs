//! The run's trade record, read one row at a time and never held whole.
//!
//! The checker used to read the whole trade record into one vector. That
//! vector, and the four indexes built over it, were the checker's largest
//! allocation: 259 bytes for every message the sequencer had published,
//! measured. At 24 messages a second, seven days of log needed 3.7 GB and
//! exceeded the deployment budget. The tool that carries this project's
//! central claim could not remain usable as the history grew.
//!
//! This module reads the same rows and keeps none of them. Two scans, both
//! read-only, both stopping at the same row:
//!
//! - `by_trade_id` walks the rows in trade id order. `trade ids are 1..n with
//!   no gaps` and `every fill has positive quantity` are the two checks that
//!   need that order, and neither needs anything but the row in hand.
//! - `sides` walks the rows in the order the messages that published their
//!   orders arrive. Every row comes out twice: once where its maker was
//!   published, and once where its taker was published. The book replay then
//!   meets each row at a message where both of the row's orders are already
//!   known, and never has to look up an order it has walked past.
//!
//! # Why every row comes out twice
//!
//! A trade names two orders. The checks compare the row against both of them:
//! the accounts, the symbols, the two sides, the maker's price, the taker's
//! limit. A walk that goes forward through the messages has the taker in hand
//! when the taker arrives, and needs the maker, which arrived earlier. So the
//! walk must have kept the maker. It keeps the maker from the message that
//! published it, which is where the maker side of the row comes out.
//!
//! The second copy is what lets the checker keep an order for exactly as long
//! as the trade record still names it, and drop it after. On an honest record
//! that is the time the order rests in the book. `services/ROADMAP.md` has the
//! measured numbers.
//!
//! # Why the scans stop at one row
//!
//! The exchange goes on writing trades while the checker runs. Two scans that
//! each read "every trade" would read two different sets of rows, and a check
//! whose two halves came from two different sets says nothing. So `open` reads
//! the highest trade id once, and every scan stops there.
//!
//! # Why the database is opened read-only
//!
//! `SQLITE_OPEN_READ_ONLY`. A checker that could write to the exchange's
//! record would be able to repair the fault it must report.

use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, Statement, params};
use std::path::Path;

use crate::domain::{AccountId, OrderId, Side};

use super::LoggedTrade;

/// One side of one row of the trade record, read at the message that published
/// that side's order.
pub(super) struct TradeSide {
    /// The message that published this side's order.
    pub(super) at: OrderId,
    /// True for the row's taker. False for the row's maker.
    pub(super) taker: bool,
    /// The row itself. Both sides carry it, so the walk can check the row at
    /// whichever of the two messages comes second.
    pub(super) trade: LoggedTrade,
}

/// Where the trades to check come from.
///
/// The walk below never sees which variant it has. Both hand over the same
/// rows in the same order. The loop that runs against a real state database is
/// the loop the tests run against a trade record they wrote themselves.
pub(super) enum Record<'a> {
    /// The latest run in a state database, opened read-only.
    Db {
        conn: &'a Connection,
        run_id: i64,
        /// The highest trade id the run had when the checker opened the file.
        /// Every scan stops there.
        up_to: u64,
    },
    /// A trade record already in hand.
    #[cfg(test)]
    Held(&'a [LoggedTrade]),
}

/// What one state database says about its latest run, with no trade row held.
pub(super) struct Run {
    pub(super) conn: Connection,
    pub(super) run_id: i64,
    /// The session the run consumed. It names the history that produced this
    /// run's trades. The sequencer on the wire has to serve that same history,
    /// or none of the trades mean anything.
    pub(super) session: Option<String>,
    /// The sequencer public key the run recorded on first contact. A head
    /// checks against the key the head itself carries, which proves only that
    /// the head agrees with itself. This key is what ties the history to the
    /// authority the run trusted.
    pub(super) public_key: Option<String>,
    /// The highest trade id in the run when the checker opened the file.
    pub(super) up_to: u64,
    /// How many rows that is. The report's first line prints it.
    pub(super) rows: usize,
    /// The highest message id any of those rows names. The run committed at
    /// least that far, so a signed head that stops earlier leaves those
    /// messages unsigned.
    pub(super) claimed_to: OrderId,
}

impl Run {
    /// Opens the state database read-only and reads what the latest run says
    /// about itself. No trade row is held: the three numbers below come from
    /// one aggregate query, and SQLite computes them as it walks the rows.
    pub(super) fn open(path: &Path) -> Result<Run, String> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| format!("cannot open {}: {}", path.display(), e))?;

        // How much memory SQLite may use for this connection, written out
        // here rather than inherited from whichever SQLite the build linked.
        // The scan that orders the rows by message has no index to walk, so
        // SQLite sorts. Its sorter fills this much memory and then writes the
        // rest to a temporary file, which is why the sort costs disk and not
        // memory. Both numbers are SQLite's own defaults. They are stated
        // because the whole point of this module is a memory bound, and a
        // bound that comes from a build option is not a bound this repository
        // decided.
        //
        // -2000 means 2,000 KB. `temp_store = 1` means the temporary file is
        // a file. `temp_store = 2` would put the sort back in memory and undo
        // the change this module exists to make.
        for (name, value) in [("cache_size", -2000i64), ("temp_store", 1)] {
            conn.pragma_update(None, name, value)
                .map_err(|e| format!("cannot set {} on {}: {}", name, path.display(), e))?;
        }

        let (run_id, session, public_key): (i64, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT run_id, feed_session, feed_pubkey FROM runs ORDER BY run_id DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|e| format!("cannot read runs from {}: {}", path.display(), e))?
            .ok_or_else(|| format!("{} holds no runs to verify", path.display()))?;

        // One statement, so the three numbers describe one set of rows. The
        // exchange may commit another trade between two statements.
        let (rows, up_to, claimed_to): (i64, i64, i64) = conn
            .query_row(
                "SELECT COUNT(*),
                        COALESCE(MAX(trade_id), 0),
                        COALESCE(MAX(MAX(maker_order, taker_order)), 0)
                 FROM trades WHERE run_id = ?1",
                params![run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|e| format!("cannot read trades from {}: {}", path.display(), e))?;

        Ok(Run {
            conn,
            run_id,
            session,
            public_key,
            up_to: up_to.max(0) as u64,
            rows: rows.max(0) as usize,
            claimed_to: claimed_to.max(0) as OrderId,
        })
    }

    /// The record this run's trades are read from.
    pub(super) fn record(&self) -> Record<'_> {
        Record::Db {
            conn: &self.conn,
            run_id: self.run_id,
            up_to: self.up_to,
        }
    }
}

/// The columns every scan reads, in one place. Both scans build the same
/// `LoggedTrade` from the same columns, so a column read one way in one scan
/// and another way in the other scan is not possible.
const COLUMNS: &str = "trade_id, symbol, price_cents, qty_tenths,
     maker_order, maker_account, taker_order, taker_account, taker_side";

/// Builds one trade from the nine columns above, starting at `first`.
fn trade_at(row: &Row<'_>, first: usize) -> Result<LoggedTrade, String> {
    let trade_id = row.get::<_, i64>(first).map_err(|e| e.to_string())? as u64;
    let side: String = row.get(first + 8).map_err(|e| e.to_string())?;
    Ok(LoggedTrade {
        trade_id,
        symbol: row.get(first + 1).map_err(|e| e.to_string())?,
        price_cents: row.get(first + 2).map_err(|e| e.to_string())?,
        qty_tenths: row.get(first + 3).map_err(|e| e.to_string())?,
        maker_order: row.get::<_, i64>(first + 4).map_err(|e| e.to_string())? as OrderId,
        maker_account: row.get::<_, i64>(first + 5).map_err(|e| e.to_string())? as AccountId,
        taker_order: row.get::<_, i64>(first + 6).map_err(|e| e.to_string())? as OrderId,
        taker_account: row.get::<_, i64>(first + 7).map_err(|e| e.to_string())? as AccountId,
        taker_side: match side.as_str() {
            "Buy" => Side::Buy,
            "Sell" => Side::Sell,
            other => return Err(format!("trade {}: bad side '{}'", trade_id, other)),
        },
    })
}

impl Record<'_> {
    /// Hands every row to `each`, in trade id order, and keeps none of them.
    ///
    /// SQLite walks the primary key here, `(run_id, trade_id)`, so this scan
    /// sorts nothing and holds one row at a time.
    pub(super) fn by_trade_id(&self, mut each: impl FnMut(&LoggedTrade)) -> Result<(), String> {
        match self {
            Record::Db {
                conn,
                run_id,
                up_to,
            } => {
                let sql = format!(
                    "SELECT {} FROM trades WHERE run_id = ?1 AND trade_id <= ?2 ORDER BY trade_id",
                    COLUMNS
                );
                let mut statement = conn.prepare(&sql).map_err(|e| e.to_string())?;
                let mut rows = statement
                    .query(params![run_id, *up_to as i64])
                    .map_err(|e| e.to_string())?;
                while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                    each(&trade_at(row, 0)?);
                }
                Ok(())
            }
            #[cfg(test)]
            Record::Held(held) => {
                for trade in *held {
                    each(trade);
                }
                Ok(())
            }
        }
    }

    /// The statement the two sides of every row come out of.
    ///
    /// It is prepared here and held by the caller, because the rows borrow it.
    /// A held record prepares nothing.
    pub(super) fn prepare(&self) -> Result<Option<Statement<'_>>, String> {
        match self {
            Record::Db { conn, .. } => {
                // Both halves read the same nine columns, so the walk builds
                // the same trade whichever half it came out of. `at` is the
                // message that published that half's order, and `taker` says
                // which half this is. The order is by `at`, then by `taker`,
                // so a row whose maker and taker are one order comes out at
                // its maker half first.
                //
                // SQLite sorts this. There is no index on `maker_order`, and
                // there cannot be one: the file is opened read-only, and the
                // exchange owns the schema. The sorter writes everything past
                // the `cache_size` set in `open` to a temporary file, so the
                // sort costs disk and not memory. The deployment's storage
                // budget is much larger than its memory budget, which is why
                // that trade is the right way round here. `services/ROADMAP.md`
                // has the peak measured over a real run.
                let sql = format!(
                    "SELECT at, taker, {cols} FROM (
                       SELECT maker_order AS at, 0 AS taker, {cols}
                         FROM trades WHERE run_id = ?1 AND trade_id <= ?2
                       UNION ALL
                       SELECT taker_order AS at, 1 AS taker, {cols}
                         FROM trades WHERE run_id = ?1 AND trade_id <= ?2
                     ) ORDER BY at, taker, trade_id",
                    cols = COLUMNS
                );
                conn.prepare(&sql).map(Some).map_err(|e| e.to_string())
            }
            #[cfg(test)]
            Record::Held(_) => Ok(None),
        }
    }
}

/// The two sides of every row, in the order the walk meets them.
///
/// The walk asks "is the next side for this message" before it takes the side,
/// so one side is always read ahead and held here. That is the only row this
/// type keeps.
pub(super) struct Sides<'a> {
    rows: Option<rusqlite::Rows<'a>>,
    /// A held record, already in the order the database would have served.
    /// Test builds only.
    #[cfg(test)]
    held: Vec<TradeSide>,
    #[cfg(test)]
    next: usize,
    /// The side read and not yet handed over.
    ahead: Option<TradeSide>,
}

impl<'a> Sides<'a> {
    /// Starts the scan. `statement` is the one `Record::prepare` returned.
    pub(super) fn open(
        statement: Option<&'a mut Statement<'_>>,
        record: &Record<'_>,
    ) -> Result<Sides<'a>, String> {
        let rows = match (statement, record) {
            (Some(statement), Record::Db { run_id, up_to, .. }) => Some(
                statement
                    .query(params![run_id, *up_to as i64])
                    .map_err(|e| e.to_string())?,
            ),
            _ => None,
        };
        #[cfg(test)]
        let held = match record {
            Record::Held(held) => {
                let mut sides: Vec<TradeSide> = Vec::new();
                for trade in *held {
                    sides.push(TradeSide {
                        at: trade.maker_order,
                        taker: false,
                        trade: trade.clone(),
                    });
                    sides.push(TradeSide {
                        at: trade.taker_order,
                        taker: true,
                        trade: trade.clone(),
                    });
                }
                // The same order the database serves: by the message that
                // published the order, then the maker half, then the trade id.
                sides.sort_by_key(|side| (side.at, side.taker, side.trade.trade_id));
                sides
            }
            _ => Vec::new(),
        };
        let mut sides = Sides {
            rows,
            #[cfg(test)]
            held,
            #[cfg(test)]
            next: 0,
            ahead: None,
        };
        sides.ahead = sides.read()?;
        Ok(sides)
    }

    /// Reads one side out of the record, or `None` at the end of it.
    fn read(&mut self) -> Result<Option<TradeSide>, String> {
        if let Some(rows) = self.rows.as_mut() {
            let Some(row) = rows.next().map_err(|e| e.to_string())? else {
                return Ok(None);
            };
            let at = row.get::<_, i64>(0).map_err(|e| e.to_string())? as OrderId;
            let taker = row.get::<_, i64>(1).map_err(|e| e.to_string())? != 0;
            return Ok(Some(TradeSide {
                at,
                taker,
                trade: trade_at(row, 2)?,
            }));
        }
        #[cfg(test)]
        if self.next < self.held.len() {
            let side = &self.held[self.next];
            self.next += 1;
            return Ok(Some(TradeSide {
                at: side.at,
                taker: side.taker,
                trade: side.trade.clone(),
            }));
        }
        Ok(None)
    }

    /// The next side, if its message has arrived. `None` means the walk has
    /// not reached that message yet, or the record is finished.
    ///
    /// A side whose message the walk has already gone past is handed over
    /// here too. The walk covers every message id in order, so that happens
    /// only for a row naming order 0, which no message can be.
    pub(super) fn take_up_to(&mut self, message: OrderId) -> Result<Option<TradeSide>, String> {
        if self.ahead.as_ref().is_none_or(|side| side.at > message) {
            return Ok(None);
        }
        let taken = self.ahead.take();
        self.ahead = self.read()?;
        Ok(taken)
    }

    /// Every side the walk never reached, once the walk has ended. Those name
    /// a message the sequencer has not published.
    pub(super) fn take_rest(&mut self) -> Result<Option<TradeSide>, String> {
        let taken = self.ahead.take();
        if taken.is_some() {
            self.ahead = self.read()?;
        }
        Ok(taken)
    }
}
