//! Checks the exchange's execution claims by running them again. V5 calls
//! this program the audit.
//!
//! Every committed batch left a claim behind. A claim says: "state root A,
//! plus the sequencer's messages a..b, gives state root B, and T trades have
//! executed so far". The exchange signs each claim with its own key. A state
//! root is one hash that covers everything the exchange holds. The audit runs
//! the same messages through the same transition function, computes the roots
//! again, and compares them. The transition function turns one state and one
//! message into the next state, and it gives the same answer every time for
//! the same input.
//!
//! `verify` shares no code with the exchange on purpose. It works the market
//! rules out again from the raw records. The audit does the opposite and
//! shares the transition function on purpose. The transition function is the
//! thing under audit. It is also what a zero-knowledge prover would run as its
//! guest program.
//!
//! That is the honest statement of what the audit is: proven execution without
//! the proof. A zkVM would run this same re-execution once, inside a prover,
//! and produce a receipt that anyone checks in milliseconds. Until a zkVM does
//! that, anyone becomes the prover by running `--audit`. The work is done
//! again instead of checked, but the claims checked are the same claims.
//!
//! There are two ways in. Both share every line of the checking:
//!
//! - `--audit [STATE_DB]` reads the claims and the trades out of a local state
//!   database. The database is the operator's own file. So this way is the
//!   operator, or anyone the operator hands the file to, checking the
//!   operator's own exchange.
//! - `--audit-url <MATCHER_URL>` reads the same claims and the same trades
//!   over HTTP from a live exchange. It checks each claim's signature against
//!   the key the exchange publishes, and it never asks for a database. This
//!   way is a stranger checking an exchange. That exchange has no reason to
//!   help, beyond serving the endpoints it already serves.
//!
//! Both ways drive one `Replay`, one message at a time, in pages of a bounded
//! size. The audit never holds a whole history. The sequencer's messages
//! arrive one page at a time, and the audit applies each message and drops it.
//! The claims arrive one page at a time, and the audit uses each claim when
//! the re-execution reaches its boundary. The recorded trades arrive one page
//! at a time, and the audit compares each trade as the re-execution produces
//! it. The audit does hold the whole re-executed exchange: its books, its
//! positions and its trade list. The live exchange holds exactly the same
//! thing, and no audit of a program that keeps state can work without it.
//!
//! Before any of that, the audit proves that the history it is about to run
//! again is the right history. Running an edited history again proves nothing:
//!
//! - The audit checks the sequencer's signed head against the sequencer's own
//!   messages. It computes the chain hash again from the bytes, and it checks
//!   the signature with the key this run pinned. `verify` and the exchange's
//!   poll loop make the same check.
//! - The audit computes the run's own stored chain hash again from those
//!   messages. That ties the messages to the exact bytes the run read. Only a
//!   local audit can do this. A remote audit is never shown that value. A
//!   remote audit is tied to the run instead by the exchange's signature over
//!   roots that only these messages produce.
//! - The audit checks that the claims cover everything the run committed. A
//!   claims table that was cut short or emptied then fails loudly, instead of
//!   passing as "nothing to audit".

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::anchor::{AnchorHistory, AnchorSource, RootAnchorHistory, RootAnchorSource, TreeHead};
use crate::domain::{OrderId, OrderMessage, Side};
use crate::fetch::{self, MAX_PAGE_BYTES, read_bounded, reason};
use crate::logchain::{self, Chain};
use crate::matcher::MatcherState;
use crate::reporting::{
    Check, FeedHead, FoldedChain, TreeWalk, check_feed_head, check_tree, read_root_anchors,
    root_sizes,
};
use crate::store::ClaimRow;
use crate::wire::{self, RawMessage, TooOld, Verdict};

/// How many claims or trades one page of a local audit gives at a time.
/// The remote endpoints page at `matcher::PAGE_LIMIT`. A local file uses the
/// same number, so both ways in run the same loop.
const LOCAL_PAGE: usize = crate::matcher::PAGE_LIMIT;

/// A trade as recorded, cut down to the fields a re-execution must produce
/// exactly. These are named fields and not a tuple. A tuple made one field
/// easy to forget, and `taker_side` was in fact forgotten: the audit read it
/// out of the database and compared it with nothing. The taker is the order
/// that arrives and trades against the orders already waiting.
///
/// `/trade-log` sends these same integers on purpose, and not the floats
/// `/trades` shows a browser. The comparison must happen on the price steps
/// and quantity steps the exchange matched on.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
struct DbTrade {
    trade_id: u64,
    timestamp: u64,
    symbol: String,
    price_cents: i64,
    qty_tenths: i64,
    maker_order: u64,
    maker_account: u64,
    taker_order: u64,
    taker_account: u64,
    taker_side: String,
}

/// One run in the file, as the report lists it. Enough to see whether a run
/// has history that nobody has audited.
#[derive(Debug)]
struct RunSummary {
    run_id: i64,
    status: String,
    cursor: OrderId,
    claims: usize,
    covered_to: OrderId,
}

/// What the audit knows about the run before it re-executes anything.
///
/// A local audit reads these facts out of the state database. A remote audit
/// reads them off the `/claims` envelope. The checks below take `RunFacts` and
/// do not care which audit read it.
#[derive(Debug)]
struct RunFacts {
    run_id: i64,
    /// The sequencer session this run counted its messages against, if the run
    /// recorded one. A session is a name for one log. `None` does not mean "no
    /// need to check". It means "cannot check".
    session: Option<String>,
    /// The sequencer public key this run pinned on first contact, in hex.
    feed_pubkey: Option<String>,
    /// The key that signed this run's claims, in hex.
    matcher_pubkey: Option<String>,
    /// The run's cursor as written to disk: the highest sequencer message the
    /// run committed.
    cursor: OrderId,
}

/// What ties the messages under re-execution to this one run.
enum HistoryTie {
    /// The chain hash the run committed over the messages it read, in the same
    /// transaction as the cursor. This is the strongest tie there is. Only a
    /// reader of the run's own database has it.
    StoredChain(Option<Chain>),
    /// Nothing but the signed claims. A remote audit is never shown the run's
    /// private chain hash. What ties these messages to this run instead is the
    /// exchange's own signature. That signature covers roots that only these
    /// messages produce.
    SignedClaims,
}

/// Everything a local audit reads out of the state database, as one snapshot.
#[derive(Debug)]
struct RunRecord {
    facts: RunFacts,
    /// The chain hash over the messages the run read, at its cursor.
    chain: Option<Chain>,
    claims: Vec<ClaimRow>,
    trades: Vec<DbTrade>,
    /// Every run in the file, so the report can name the runs this command did
    /// not look at.
    runs: Vec<RunSummary>,
}

/// What the checks produced: the counts to print, and the numbers the summary
/// line must state honestly.
struct Outcome {
    checks: Vec<Check>,
    /// What was not checked, one sentence each. The audit prints these under
    /// the checks and never as a pass. A reader who saw only passing lines
    /// would take these things to have been checked.
    ///
    /// Every note comes from `check_tree` or from `TreeWalk::finish`, and
    /// there are three. Nobody named a root anchor contract, so there is no
    /// anchored root to compare against. The contract that was named holds no
    /// root anchor yet. The history was not read from a log, so it has no
    /// stored nodes beside it.
    ///
    /// The state-root anchors `check_anchors` reads write no note. An anchor
    /// that cannot be read is a failing `Check` there, because an unreadable
    /// anchor is a claim the audit was asked to check and could not.
    notes: Vec<String>,
    /// Why the re-execution did not run, when it did not run.
    stopped: Option<String>,
    /// The message this build could not read, when the re-execution stopped
    /// because this binary is older than the sequencer's message format. This
    /// is not a failed check and must never be printed as one. `report` says
    /// so in its own words, and the process exits 3 and not 1.
    too_old: Option<TooOld>,
    messages_replayed: usize,
    /// Claim boundaries whose root the audit computed again and compared.
    boundaries_checked: usize,
    /// How many claim boundaries there are: one for each claim, plus the state
    /// before the first claim.
    boundaries_total: usize,
    elapsed: Duration,
}

impl Outcome {
    fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed())
    }

    /// Every failure message, for a caller that reads them instead of printing
    /// them.
    #[cfg(test)]
    fn failure_text(&self) -> String {
        self.checks
            .iter()
            .flat_map(|c| c.failures.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// The text the store writes for a side. `store.rs` writes exactly these two
/// strings, and the trades table has a CHECK constraint that says so.
fn side_text(side: Side) -> &'static str {
    match side {
        Side::Buy => "Buy",
        Side::Sell => "Sell",
    }
}

/// Reads a stored integer as a sequencer message number.
///
/// Every id in this system is a sequence number. It is never negative and it
/// always fits. A row that says otherwise has been edited. A cast with `as`
/// would panic in a debug build, and the README tells people to run the debug
/// build. In a release build the same cast would wrap into a huge id and
/// produce a nonsense report.
fn checked_id(value: i64, what: &str) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| {
        format!(
            "{} is {} in the database, which is not a feed id: the row has been edited",
            what, value
        )
    })
}

// ---------------------------------------------------------------------------
// Reading a local state database
// ---------------------------------------------------------------------------

/// Reads the run's claims, trades, cursor and session out of the database, in
/// one read transaction.
///
/// The transaction is the point. Read one statement at a time from a live
/// exchange and the claims can come from before a commit while the trades come
/// from after it. The re-execution then stops at the older cursor, and the
/// trades table already holds the next batch's fills. A healthy exchange then
/// gets reported as "recorded 1250 trades, re-execution produced 1247". That
/// is a fraud verdict on nothing. `BEGIN DEFERRED` takes the snapshot at the
/// first read and holds it for the rest, so every row describes one moment.
fn read_db(path: &Path, wanted_run: Option<i64>) -> Result<RunRecord, String> {
    let mut conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| format!("cannot open {}: {}", path.display(), e))?;
    // The exchange commits while the audit runs. Wait a few milliseconds for
    // the lock the exchange holds, instead of failing the audit on it.
    conn.busy_timeout(Duration::from_secs(5))
        .map_err(|e| format!("cannot set a busy timeout on {}: {}", path.display(), e))?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|e| {
            format!(
                "cannot start a read transaction on {}: {}",
                path.display(),
                e
            )
        })?;

    let runs = read_run_summaries(&tx, path)?;
    let run_id = match wanted_run {
        Some(wanted) => {
            if !runs.iter().any(|r| r.run_id == wanted) {
                return Err(format!(
                    "{} has no run {}. It holds {}",
                    path.display(),
                    wanted,
                    describe_runs(&runs)
                ));
            }
            wanted
        }
        None => match runs.last() {
            Some(latest) => latest.run_id,
            None => return Err(format!("{} records no runs at all", path.display())),
        },
    };

    let (session, feed_pubkey, matcher_pubkey): (Option<String>, Option<String>, Option<String>) =
        tx.query_row(
            "SELECT feed_session, feed_pubkey, matcher_pubkey FROM runs WHERE run_id = ?1",
            params![run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|e| format!("cannot read run {} of {}: {}", run_id, path.display(), e))?;

    let resume: Option<(i64, Option<Vec<u8>>)> = tx
        .query_row(
            "SELECT last_seen, chain_hash FROM resume_point WHERE run_id = ?1",
            params![run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| format!("cannot read the resume point of run {}: {}", run_id, e))?;
    let (cursor, chain) = match resume {
        Some((last_seen, chain)) => {
            let cursor = checked_id(last_seen, "the run's cursor")?;
            let chain = match chain {
                Some(bytes) => Some(
                    Chain::try_from(bytes.as_slice())
                        .map_err(|_| "the run's stored chain is not 32 bytes".to_string())?,
                ),
                None => None,
            };
            (cursor, chain)
        }
        // Every run gets its resume point in the same transaction that creates
        // the run. A run without a resume point is a file somebody edited by
        // hand.
        None => {
            return Err(format!(
                "run {} of {} has no resume point, so how far it got cannot be read",
                run_id,
                path.display()
            ));
        }
    };

    let claims = read_claims(&tx, run_id)?;
    let trades = read_trades(&tx, run_id)?;

    Ok(RunRecord {
        facts: RunFacts {
            run_id,
            session,
            feed_pubkey,
            matcher_pubkey,
            cursor,
        },
        chain,
        claims,
        trades,
        runs,
    })
}

/// Every run in the file, with how far the run got and how much of that its
/// claims cover. The report uses this to name the runs this command did not
/// audit.
fn read_run_summaries(conn: &Connection, path: &Path) -> Result<Vec<RunSummary>, String> {
    conn.prepare(
        "SELECT r.run_id, r.status,
                COALESCE(p.last_seen, 0),
                COUNT(c.from_msg),
                COALESCE(MAX(c.to_msg), 0)
         FROM runs r
         LEFT JOIN resume_point p ON p.run_id = r.run_id
         LEFT JOIN claims c ON c.run_id = r.run_id
         GROUP BY r.run_id, r.status, p.last_seen
         ORDER BY r.run_id",
    )
    .map_err(|e| format!("cannot read runs from {}: {}", path.display(), e))?
    .query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })
    .map_err(|e| format!("cannot read runs from {}: {}", path.display(), e))?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(|e| format!("cannot read runs from {}: {}", path.display(), e))?
    .into_iter()
    .map(|(run_id, status, cursor, claims, covered_to)| {
        Ok(RunSummary {
            run_id,
            status,
            cursor: checked_id(cursor, "a run's cursor")?,
            claims: usize::try_from(claims).unwrap_or(0),
            covered_to: checked_id(covered_to, "a claim's to_msg")?,
        })
    })
    .collect()
}

fn describe_runs(runs: &[RunSummary]) -> String {
    if runs.is_empty() {
        return "no runs at all".to_string();
    }
    runs.iter()
        .map(|r| format!("run {} ({}, cursor {})", r.run_id, r.status, r.cursor))
        .collect::<Vec<_>>()
        .join(", ")
}

fn read_claims(conn: &Connection, run_id: i64) -> Result<Vec<ClaimRow>, String> {
    conn.prepare(
        "SELECT from_msg, to_msg, root_before, root_after, trades_total, signature
         FROM claims WHERE run_id = ?1 ORDER BY from_msg",
    )
    .map_err(|e| e.to_string())?
    .query_map(params![run_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, Option<Vec<u8>>>(5)?,
        ))
    })
    .map_err(|e| e.to_string())?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(|e| e.to_string())?
    .into_iter()
    .map(
        |(from_msg, to_msg, before, after, trades_total, signature)| {
            Ok(ClaimRow {
                from_msg: checked_id(from_msg, "a claim's from_msg")?,
                to_msg: checked_id(to_msg, "a claim's to_msg")?,
                root_before: before
                    .try_into()
                    .map_err(|_| "claim root is not 32 bytes".to_string())?,
                root_after: after
                    .try_into()
                    .map_err(|_| "claim root is not 32 bytes".to_string())?,
                trades_total: u64::try_from(trades_total).map_err(|_| {
                    format!(
                        "a claim says {} trades had executed, which is not a count",
                        trades_total
                    )
                })?,
                signature: signature
                    .map(|bytes| {
                        <[u8; 64]>::try_from(bytes.as_slice())
                            .map_err(|_| "a claim signature is not 64 bytes".to_string())
                    })
                    .transpose()?,
            })
        },
    )
    .collect()
}

fn read_trades(conn: &Connection, run_id: i64) -> Result<Vec<DbTrade>, String> {
    conn.prepare(
        "SELECT trade_id, timestamp, symbol, price_cents, qty_tenths,
                maker_order, maker_account, taker_order, taker_account, taker_side
         FROM trades WHERE run_id = ?1 ORDER BY trade_id",
    )
    .map_err(|e| e.to_string())?
    .query_map(params![run_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, i64>(8)?,
            row.get::<_, String>(9)?,
        ))
    })
    .map_err(|e| e.to_string())?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(|e| e.to_string())?
    .into_iter()
    .map(|row| {
        Ok(DbTrade {
            trade_id: checked_id(row.0, "a trade id")?,
            timestamp: checked_id(row.1, "a trade timestamp")?,
            symbol: row.2,
            price_cents: row.3,
            qty_tenths: row.4,
            maker_order: checked_id(row.5, "a trade's maker order")?,
            maker_account: checked_id(row.6, "a trade's maker account")?,
            taker_order: checked_id(row.7, "a trade's taker order")?,
            taker_account: checked_id(row.8, "a trade's taker account")?,
            taker_side: row.9,
        })
    })
    .collect()
}

// ---------------------------------------------------------------------------
// Talking to live services
// ---------------------------------------------------------------------------

/// Fetches one body of a bounded size, with the session the service announced
/// beside it.
///
/// This is separate from `fetch_json` because the audit fetches the
/// sequencer's history as bytes and never as a parsed document. The chain hash
/// covers those bytes. A body that passed through a struct on the way in could
/// not be hashed afterwards.
async fn fetch_bytes(
    client: &reqwest::Client,
    url: &str,
    what: &str,
) -> Result<(Vec<u8>, Option<String>), String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("cannot reach {}: {}", url, reason(&e)))?;
    let status = response.status();
    let session = response
        .headers()
        .get(crate::wire::SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(String::from);
    if !status.is_success() {
        // The body of an error carries the reason the service refused. If the
        // audit drops that body, the reader sees only a bare 503.
        let detail = read_bounded(response, what, MAX_PAGE_BYTES)
            .await
            .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_string())
            .unwrap_or_default();
        return Err(if detail.is_empty() {
            format!("{} answered {}", url, status)
        } else {
            format!("{} answered {}: {}", url, status, detail)
        });
    }
    Ok((read_bounded(response, what, MAX_PAGE_BYTES).await?, session))
}

/// Fetches one JSON document of a bounded size.
async fn fetch_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    what: &str,
) -> Result<(T, Option<String>), String> {
    let (body, session) = fetch_bytes(client, url, what).await?;
    let parsed = serde_json::from_slice(&body)
        .map_err(|e| format!("cannot read what {} served: {}", url, reason(&e)))?;
    Ok((parsed, session))
}

/// Fetches the sequencer's signed head, or the reason there is no head to
/// check. The audit never passes a head it could not fetch. The signature over
/// the head is the only proof that the history under re-execution is the
/// history the sequencer stands behind.
async fn read_feed_head(client: &reqwest::Client, feed_url: &str) -> Result<FeedHead, String> {
    fetch_json(client, &format!("{}/head", feed_url), "the feed's head")
        .await
        .map(|(head, _)| head)
}

/// What the exchange answers on `GET /config`: the addresses it gives anyone
/// for the rest of the exchange. The user interface reads the addresses to
/// know where a browser posts submissions. A remote audit reads them for the
/// same reason a browser does. The sequencer runs on its own address, and only
/// the operator knows which address.
#[derive(Debug, serde::Deserialize)]
struct ExchangeConfig {
    /// Optional here, and not required. An exchange that names no sequencer
    /// then produces a sentence about the exchange, and not a JSON parse
    /// error.
    feed_url: Option<String>,
    // `inbox_url` is served beside this field and has nothing to do with an
    // audit.
}

/// The address `--audit-url` reads the sequencer's history from.
///
/// The audit uses `--feed-url` when the reader gave one. Otherwise it uses the
/// address the exchange announces for itself. That is the public address the
/// exchange gives a browser, and not the loopback address its own programs use
/// between themselves.
///
/// Asking the exchange is what makes the one-URL audit true. The claims are on
/// the exchange. The history those claims are about is on the sequencer, which
/// is a different program at a different address. Before this, an audit of a
/// remote exchange used whatever `--feed-url` defaults to. It then failed
/// against a loopback address the reader never typed, which reads as a broken
/// exchange and not as a missing flag.
///
/// An explicit `--feed-url` wins, and the audit does not compare it with what
/// the exchange says. A reader who reaches the sequencer through a tunnel, a
/// mirror, or another route names something the exchange cannot know about. An
/// explicit `--feed-url` also skips the request. So the override still works
/// against an exchange that serves no `/config` at all.
async fn resolve_feed_url(
    client: &reqwest::Client,
    matcher_url: &str,
    explicit: Option<&str>,
) -> Result<String, String> {
    if let Some(url) = explicit {
        return Ok(url.trim().trim_end_matches('/').to_string());
    }
    let advertised = fetch_json::<ExchangeConfig>(
        client,
        &format!("{}/config", matcher_url),
        "the exchange's configuration",
    )
    .await
    .map(|(config, _)| config.feed_url);
    feed_url_from_config(matcher_url, advertised)
}

/// Turns what `GET /config` said, or the reason it said nothing, into an
/// address or into a sentence that names the flag which supplies one.
///
/// This is separate from the request, so the sentence states a fact about this
/// exchange. This function puts no default address in place. The failure it
/// fixes was an audit that fell back to an address the reader never typed.
fn feed_url_from_config(
    matcher_url: &str,
    advertised: Result<Option<String>, String>,
) -> Result<String, String> {
    match &advertised {
        Ok(Some(url)) if !url.trim().is_empty() => Ok(url.trim().trim_end_matches('/').to_string()),
        _ => Err(format!(
            "{} did not advertise a feed address{}, and the history to re-execute is on the \
             feed rather than on the matcher. Pass --feed-url <URL> with the address you \
             reach this exchange's feed at",
            matcher_url,
            match advertised {
                Err(reason) => format!(" ({})", reason),
                _ => " on GET /config".to_string(),
            }
        )),
    }
}

/// The reason the sequencer could not be read, plus where its address came
/// from.
///
/// Without the second half, a reader who typed one URL gets an error that
/// names a different address, and nothing on the screen says the exchange
/// named that address. An announced address is the address a browser is told
/// to submit to. So it is wrong in exactly two cases: the operator's
/// `--public-feed-url` is wrong, or the reader reaches the sequencer by
/// another route. The same flag fixes both cases.
fn unreachable_feed(reason: String, matcher_url: &str, feed_url: &str, advertised: bool) -> String {
    if !advertised {
        return reason;
    }
    format!(
        "{}. {} is the feed address {} advertises on GET /config; pass --feed-url <URL> if \
         you reach its feed at another address",
        reason, feed_url, matcher_url
    )
}

/// One page of the sequencer's history, with the session the sequencer
/// announced beside it.
struct FeedPage {
    /// The messages as bytes. The audit hashes these bytes into the chain
    /// hash. Reading them as `OrderMessage` is the re-execution's job, and it
    /// happens separately in `Replay::apply`. See `wire`.
    messages: Vec<RawMessage>,
    session: Option<String>,
}

/// Where a re-execution's messages come from, one page at a time.
///
/// The point of the enum is that `Replay` below never sees it. Both variants
/// give pages of the same size. So the loop that reads from a live sequencer
/// is the same loop the tests run against a history the tests built
/// themselves.
enum Messages<'a> {
    /// Pages fetched from a live sequencer with `?since=`, the way every
    /// reader in this repository reads it.
    Feed {
        client: &'a reqwest::Client,
        url: &'a str,
    },
    /// A history the caller already holds, given out in pages of the same
    /// size. The tests build the exact history a run read, instead of starting
    /// a sequencer. Paging it here makes the tests drive the same loop the
    /// real program drives, and not a shortcut around it.
    #[cfg(test)]
    Held(&'a [RawMessage]),
}

impl Messages<'_> {
    /// The nodes the log stored when it appended the leaves
    /// `from .. from+count`, or `None` when there is no log to ask. See
    /// `verify::History::tree_nodes`. The checker makes the same request.
    async fn tree_nodes(&self, from: u64, count: u64) -> Result<Option<wire::TreeNodes>, String> {
        match self {
            Messages::Feed { client, url } => {
                let page = wire::tree_nodes_url(url, from, count);
                let (body, _) = fetch_bytes(client, &page, "a page of stored nodes").await?;
                serde_json::from_slice(&body)
                    .map(Some)
                    .map_err(|e| format!("cannot read the nodes {} served: {}", page, e))
            }
            #[cfg(test)]
            Messages::Held(_) => Ok(None),
        }
    }

    async fn page(&self, since: OrderId) -> Result<FeedPage, String> {
        match self {
            Messages::Feed { client, url } => {
                // The raw-bytes endpoint. The audit checks the signed head
                // against a chain hash over the bytes the sequencer hashed.
                // So the audit asks for those bytes, and not for a JSON array
                // it would have to take the bytes back out of. See
                // `wire::MESSAGES_PATH`.
                let page = wire::messages_url(url, since);
                let (body, session) = fetch_bytes(client, &page, "a page of feed history").await?;
                let messages = wire::split_ndjson(&body)
                    .map_err(|e| format!("{} did not serve a page of messages: {}", page, e))?;
                Ok(FeedPage { messages, session })
            }
            #[cfg(test)]
            Messages::Held(all) => {
                let start = all.partition_point(|m| m.id <= since);
                let end = (start + crate::feed::PAGE_LIMIT).min(all.len());
                Ok(FeedPage {
                    messages: all[start..end].to_vec(),
                    session: None,
                })
            }
        }
    }
}

/// The `/claims` envelope: one page of signed claims, and everything the audit
/// needs to check them.
#[derive(Debug, serde::Deserialize)]
struct ClaimsPage {
    run_id: i64,
    session: String,
    cursor: OrderId,
    matcher_public_key: String,
    feed_public_key: Option<String>,
    claims: Vec<WireClaim>,
}

/// One claim as served. In hex, like everything else on the wire here.
#[derive(Debug, serde::Deserialize)]
struct WireClaim {
    from_msg: OrderId,
    to_msg: OrderId,
    root_before: String,
    root_after: String,
    trades_total: u64,
    signature: Option<String>,
}

impl WireClaim {
    /// The claim in the form the checks want. A field that is not readable hex
    /// is a failure of the claim, and not a failure of the parser. So the
    /// audit returns a named reason and never drops the row.
    fn parse(self) -> Result<ClaimRow, String> {
        let root_before = logchain::from_hex::<32>(&self.root_before).ok_or_else(|| {
            format!(
                "the claim for messages {}..{} has a root_before that is not a 32-byte hex \
                 value",
                self.from_msg, self.to_msg
            )
        })?;
        let root_after = logchain::from_hex::<32>(&self.root_after).ok_or_else(|| {
            format!(
                "the claim for messages {}..{} has a root_after that is not a 32-byte hex \
                 value",
                self.from_msg, self.to_msg
            )
        })?;
        let signature = match &self.signature {
            Some(hex) => Some(logchain::from_hex::<64>(hex).ok_or_else(|| {
                format!(
                    "the claim for messages {}..{} has a signature that is not a 64-byte \
                     hex value",
                    self.from_msg, self.to_msg
                )
            })?),
            None => None,
        };
        Ok(ClaimRow {
            from_msg: self.from_msg,
            to_msg: self.to_msg,
            root_before,
            root_after,
            trades_total: self.trades_total,
            signature,
        })
    }
}

/// The `/trade-log` envelope.
#[derive(Debug, serde::Deserialize)]
struct TradeLogPage {
    #[allow(dead_code)]
    run_id: i64,
    trades: Vec<DbTrade>,
}

/// Where the claims under audit come from.
enum Claims<'a> {
    /// Rows already read out of a local state database.
    Held(&'a [ClaimRow]),
    /// Pages fetched from a live exchange's `/claims`.
    Remote {
        client: &'a reqwest::Client,
        url: &'a str,
    },
}

impl Claims<'_> {
    /// How many claims there are, when the audit can know that without
    /// fetching them all. A remote audit learns the count only when it reaches
    /// the end.
    fn len_hint(&self) -> Option<usize> {
        match self {
            Claims::Held(all) => Some(all.len()),
            Claims::Remote { .. } => None,
        }
    }

    async fn page(&self, since: OrderId) -> Result<Vec<ClaimRow>, String> {
        match self {
            Claims::Held(all) => {
                let start = all.partition_point(|c| c.from_msg <= since);
                let end = (start + LOCAL_PAGE).min(all.len());
                Ok(all[start..end].to_vec())
            }
            Claims::Remote { client, url } => {
                let (page, _) = fetch_json::<ClaimsPage>(
                    client,
                    &format!("{}/claims?since={}", url, since),
                    "a page of claims",
                )
                .await?;
                page.claims.into_iter().map(WireClaim::parse).collect()
            }
        }
    }
}

/// Where the recorded trades under audit come from.
enum Trades<'a> {
    Held(&'a [DbTrade]),
    Remote {
        client: &'a reqwest::Client,
        url: &'a str,
    },
}

impl Trades<'_> {
    async fn page(&self, since: u64) -> Result<Vec<DbTrade>, String> {
        match self {
            Trades::Held(all) => {
                let start = all.partition_point(|t| t.trade_id <= since);
                let end = (start + LOCAL_PAGE).min(all.len());
                Ok(all[start..end].to_vec())
            }
            Trades::Remote { client, url } => {
                let (page, _) = fetch_json::<TradeLogPage>(
                    client,
                    &format!("{}/trade-log?since={}", url, since),
                    "a page of trades",
                )
                .await?;
                Ok(page.trades)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The shared re-execution
// ---------------------------------------------------------------------------

/// Which fields of a recorded trade the re-execution disagrees with.
///
/// This returns a list of the fields that differ, and not one fixed sentence.
/// A trade that differed only in `taker_side` used to print a line where every
/// number matched. That line looked like a bug in the audit, and not like the
/// mismatch it was.
fn trade_differences(ours: &crate::matcher::Trade, theirs: &DbTrade) -> Vec<String> {
    let mut diffs = Vec::new();
    let mut note = |field: &str, recorded: String, replayed: String| {
        diffs.push(format!(
            "{} {} recorded, re-execution {}",
            field, recorded, replayed
        ));
    };
    if ours.trade_id != theirs.trade_id {
        note("id", theirs.trade_id.to_string(), ours.trade_id.to_string());
    }
    if ours.symbol != theirs.symbol {
        note("symbol", theirs.symbol.clone(), ours.symbol.clone());
    }
    let price_cents = (ours.price * 100.0).round() as i64;
    if price_cents != theirs.price_cents {
        note(
            "price",
            format!("{} cents", theirs.price_cents),
            format!("{} cents", price_cents),
        );
    }
    let qty_tenths = (ours.quantity * 10.0).round() as i64;
    if qty_tenths != theirs.qty_tenths {
        note(
            "quantity",
            format!("{} tenths", theirs.qty_tenths),
            format!("{} tenths", qty_tenths),
        );
    }
    if ours.maker_order != theirs.maker_order {
        note(
            "maker order",
            theirs.maker_order.to_string(),
            ours.maker_order.to_string(),
        );
    }
    if ours.maker_account as u64 != theirs.maker_account {
        note(
            "maker account",
            theirs.maker_account.to_string(),
            ours.maker_account.to_string(),
        );
    }
    if ours.taker_order != theirs.taker_order {
        note(
            "taker order",
            theirs.taker_order.to_string(),
            ours.taker_order.to_string(),
        );
    }
    if ours.taker_account as u64 != theirs.taker_account {
        note(
            "taker account",
            theirs.taker_account.to_string(),
            ours.taker_account.to_string(),
        );
    }
    if side_text(ours.taker_side) != theirs.taker_side {
        note(
            "taker side",
            theirs.taker_side.clone(),
            side_text(ours.taker_side).to_string(),
        );
    }
    // The timestamp comes from the sequencer's own message. A trade with an
    // edited time is a trade the messages do not produce, the same as a trade
    // with an edited price.
    if ours.timestamp != theirs.timestamp {
        note(
            "timestamp",
            theirs.timestamp.to_string(),
            ours.timestamp.to_string(),
        );
    }
    diffs
}

/// Hashes the sequencer's chain over the messages as they go past, and keeps
/// the chain value at the two positions the audit compares against: where the
/// sequencer's signed head stands, and where the run's cursor stands.
///
/// One walk of the history, not two. The head check and the "these are the
/// messages the run read" check used to walk the whole history separately.
/// That was the same arithmetic twice, and two places for it to drift apart.
struct ChainFold {
    chain: Chain,
    /// The highest message id hashed in so far.
    reached: OrderId,
    /// How many messages went into the head's chain, for the check's count.
    counted: usize,
    head_at: Option<OrderId>,
    at_head: Option<Chain>,
    cursor: OrderId,
    at_cursor: Option<Chain>,
    /// Every message that an anchor on Base commits to, in ascending order,
    /// and the chain value this walk had at each of those messages it reached.
    ///
    /// This same walk records them, instead of a second walk of the history.
    /// Each anchor commits to the chain at one message, and this walk already
    /// computes the chain at every message. So a check of a hundred anchors
    /// costs a hundred comparisons, and not one extra request.
    anchors_at: Vec<OrderId>,
    at_anchors: BTreeMap<OrderId, Chain>,
}

impl ChainFold {
    fn new(head_at: Option<OrderId>, cursor: OrderId, anchors_at: Vec<OrderId>) -> Self {
        let mut fold = ChainFold {
            chain: logchain::EMPTY_CHAIN,
            reached: 0,
            counted: 0,
            head_at,
            at_head: None,
            cursor,
            at_cursor: None,
            anchors_at,
            at_anchors: BTreeMap::new(),
        };
        // A head, a cursor or an anchor at message 0 stands on the empty
        // chain. No message ever arrives to record that value, so record it
        // here.
        if head_at == Some(0) {
            fold.at_head = Some(logchain::EMPTY_CHAIN);
        }
        if cursor == 0 {
            fold.at_cursor = Some(logchain::EMPTY_CHAIN);
        }
        if fold.anchors_at.first() == Some(&0) {
            fold.at_anchors.insert(0, logchain::EMPTY_CHAIN);
        }
        fold
    }

    /// The highest message any anchor commits to. The audit must hash the
    /// history up to that message to check every anchor.
    fn anchors_end(&self) -> Option<OrderId> {
        self.anchors_at.last().copied()
    }

    /// Hashes one message's bytes into the chain, exactly as the sequencer
    /// served them.
    ///
    /// This walk never reads inside the message. That keeps the head check and
    /// the anchor checks correct over a history that holds a message kind this
    /// build cannot execute. The re-execution stops at such a message, and the
    /// chain goes on to the sequencer's signed head. So "the messages are
    /// intact and this audit is old" stays a different answer from "the
    /// messages were rewritten".
    fn feed(&mut self, msg: &RawMessage) {
        self.chain = logchain::extend_bytes(&self.chain, &msg.bytes);
        self.reached = msg.id;
        if self.head_at.is_some_and(|at| msg.id <= at) {
            self.counted += 1;
        }
        if self.head_at == Some(msg.id) {
            self.at_head = Some(self.chain);
        }
        if self.cursor == msg.id {
            self.at_cursor = Some(self.chain);
        }
        if self.anchors_at.binary_search(&msg.id).is_ok() {
            self.at_anchors.insert(msg.id, self.chain);
        }
    }
}

/// Runs a history again against a run's claims, one message at a time.
///
/// This is the whole of what an audit means, and both ways in drive this same
/// object. There is one call to `apply_message`, one call to `state_root`, and
/// one definition of what makes a claim hold. A second copy of this code for
/// the streaming way in would be a second opinion about what the claims say.
/// The tool that settles the question must not hold two opinions.
struct Replay {
    engine: MatcherState,
    /// How far this audit's view reaches, when the audit had to fix a limit.
    ///
    /// A local audit reads its claims and its trades inside one SQLite read
    /// transaction, so both describe one moment. A remote audit has no such
    /// transaction. It reads the claims, then the sequencer, then the trades,
    /// and a live exchange commits between those requests. Without a limit,
    /// the trades table the audit reads last holds more rows than the claims
    /// it read first. A healthy exchange then gets reported as having invented
    /// seven fills. That is a fraud verdict on nothing, and it is the same
    /// failure `read_db`'s transaction prevents on a local audit.
    ///
    /// So a live audit fixes its view at the cursor the exchange reported when
    /// the audit started. Claims past that cursor belong to the next audit.
    /// The audit reads the trades table only as far as the last claim inside
    /// that view says it goes. A run against a live exchange found this. Every
    /// test in this file had passed.
    horizon: Option<OrderId>,
    /// Claims whose boundary the re-execution has not reached yet, in order.
    ahead: VecDeque<ClaimRow>,
    /// Where the first claim starts, learned from the first claim pushed in.
    first_from: Option<OrderId>,
    checked_first_before: bool,
    /// The highest `to_msg` pushed so far, and whether more may come.
    last_needed: OrderId,
    claims_ended: bool,
    claims_seen: usize,
    /// The previous claim pushed, for the continuity check.
    previous: Option<ClaimRow>,
    roots: Check,
    totals: Check,
    trades: Check,
    continuity: Check,
    /// Recorded trades the audit fetched but has not compared yet, because the
    /// re-execution has not reached them. At most one page. The driver fetches
    /// another page only when `pending_trades` is empty.
    pending_trades: VecDeque<DbTrade>,
    /// Recorded trades seen in total, and the highest trade id among them. The
    /// highest trade id is the cursor the audit asks the next page for. It is
    /// an id and not a count. So a table with a hole in its ids still pages
    /// forward, instead of asking for the same page again.
    recorded_trades: usize,
    last_trade_id: u64,
    /// Recorded trades compared field by field against a re-executed one.
    compared_trades: usize,
    /// Set once the audit applies no more messages. Rows the re-execution can
    /// never reach are then counted and not kept.
    replay_ended: bool,
    /// The highest trade id this audit's view includes, once the audit knows
    /// it. That is the running total the last claim inside the view commits
    /// to. `None` on a local audit, which reads one snapshot instead.
    trades_bound: Option<u64>,
    /// Set when the trades source has nothing more inside the view.
    trades_ended: bool,
    messages_replayed: usize,
    boundaries_checked: usize,
    /// Set when the audit cannot run the history any further.
    halted: bool,
    /// The message this build could not read, when that message is what
    /// stopped the re-execution.
    ///
    /// This is separate from every `Check` in this struct, and on purpose. A
    /// failed check is the audit saying the exchange's record is wrong. This
    /// field is the audit saying the audit is older than the exchange. To put
    /// the second inside the first would sign the audit's name to a fraud
    /// finding that is really a missing deploy.
    too_old: Option<TooOld>,
    /// The trade count the last claim states, for the trades-table check.
    last_trades_total: Option<u64>,
    /// The messages that the anchors on Base commit to the state after, and
    /// the state root this re-execution had at each of those messages it
    /// reached.
    ///
    /// The audit takes the root at the message, and not at a claim boundary.
    /// That is on purpose. The exchange writes an anchor at a boundary, so the
    /// two are normally the same message. But the state root after message N
    /// depends on the state alone, and not on how the exchange grouped its
    /// commits into batches. A check tied to a boundary would report a history
    /// with different batch sizes as an anchor failure, which it is not.
    anchors_at: Vec<OrderId>,
    at_anchors: BTreeMap<OrderId, logchain::StateRoot>,
}

impl Replay {
    /// `session` names the log under re-execution, and the re-execution needs
    /// the name. The operator signs an operator message over a statement whose
    /// second line is the session. An exchange that does not know the session
    /// refuses every listing the operator published. The audit would then
    /// report an honest exchange as one that opened no market at all. The run
    /// recorded the session, and `check_execution` reads it from there.
    fn new(horizon: Option<OrderId>, anchors_at: Vec<OrderId>, session: &str) -> Self {
        let mut at_anchors = BTreeMap::new();
        // An anchor at message 0 stands on an exchange that has applied
        // nothing. No message ever arrives to record that state, so record it
        // here.
        if anchors_at.first() == Some(&0) {
            at_anchors.insert(0, MatcherState::replaying(session).state_root());
        }
        Replay {
            engine: MatcherState::replaying(session),
            horizon,
            ahead: VecDeque::new(),
            first_from: None,
            checked_first_before: false,
            last_needed: 0,
            claims_ended: false,
            claims_seen: 0,
            previous: None,
            roots: Check::new("re-executed state roots match the claims"),
            totals: Check::new("claimed trade counts match the re-execution"),
            trades: Check::new("recorded trades match the re-execution"),
            continuity: Check::new("claims form an unbroken chain of roots"),
            pending_trades: VecDeque::new(),
            recorded_trades: 0,
            last_trade_id: 0,
            compared_trades: 0,
            replay_ended: false,
            trades_bound: None,
            trades_ended: false,
            messages_replayed: 0,
            boundaries_checked: 0,
            halted: false,
            too_old: None,
            last_trades_total: None,
            anchors_at,
            at_anchors,
        }
    }

    /// The `from_msg` to ask the claims source for next.
    fn claims_cursor(&self) -> OrderId {
        self.previous
            .as_ref()
            .map(|c| c.from_msg)
            .or_else(|| self.ahead.back().map(|c| c.from_msg))
            .unwrap_or(0)
    }

    /// Takes one page of claims. It checks as it goes that each claim
    /// continues the claim before it.
    fn push_claims(&mut self, page: Vec<ClaimRow>) {
        if page.is_empty() {
            self.claims_ended = true;
            return;
        }
        for claim in page {
            self.claims_seen += 1;
            self.continuity.checked += 1;
            if claim.from_msg == 0 || claim.to_msg < claim.from_msg {
                self.continuity.fail(format!(
                    "claim {} covers messages {}..{}, which is not a range of feed ids",
                    self.claims_seen, claim.from_msg, claim.to_msg
                ));
            }
            if let Some(previous) = &self.previous {
                self.continuity.checked += 1;
                if claim.root_before != previous.root_after {
                    self.continuity.fail(format!(
                        "claim at message {} starts from a root claim at {} did not produce",
                        claim.from_msg, previous.from_msg
                    ));
                }
                // `+ 1` on an id read from a database or off the wire. An
                // edited `to_msg` at the top of the range would panic the
                // audit in a debug build, and wrap around in a release build.
                match previous.to_msg.checked_add(1) {
                    Some(next) if next == claim.from_msg => {}
                    Some(next) => self.continuity.fail(format!(
                        "claim at message {} does not continue from message {}: the next \
                         claimed message would be {}",
                        claim.from_msg, previous.to_msg, next
                    )),
                    None => self.continuity.fail(format!(
                        "a claim ends at message {}, which nothing can follow",
                        previous.to_msg
                    )),
                }
            }
            self.first_from.get_or_insert(claim.from_msg);
            self.last_needed = self.last_needed.max(claim.to_msg);
            self.last_trades_total = Some(claim.trades_total);
            let reached_horizon = self.horizon.is_some_and(|at| claim.to_msg >= at);
            self.previous = Some(claim.clone());
            self.ahead.push_back(claim);
            // A claim that reaches the cursor this audit fixed its view at is
            // the last claim the audit looks at. The test is `>=` and not
            // `==`. So a claim that runs past the cursor still comes in, and
            // the coverage check still reports it, instead of the audit
            // dropping it without a word.
            if reached_horizon {
                self.claims_ended = true;
                return;
            }
        }
    }

    /// True while the audit may still need more claims to know where the next
    /// boundary is.
    fn wants_claims(&self) -> bool {
        !self.claims_ended && self.ahead.is_empty()
    }

    /// True while history is left that is worth running again.
    fn wants_messages(&self) -> bool {
        !self.halted && (!self.claims_ended || !self.ahead.is_empty())
    }

    /// Applies one message and checks every claim boundary that message lands
    /// on.
    ///
    /// The message arrives as bytes and is read here. This is the point where
    /// the audit stops hashing a history and starts running it. A message this
    /// build cannot read stops the re-execution. An audit that skipped such a
    /// message would compute every root after it from a state the exchange
    /// never had. The stop does not fail a check.
    fn apply(&mut self, raw: &RawMessage) {
        if self.halted || raw.id > self.last_needed {
            return;
        }
        let msg = match raw.parse::<OrderMessage>() {
            Ok(msg) => msg,
            Err(too_old) => {
                self.too_old = Some(too_old);
                self.halted = true;
                return;
            }
        };
        let msg = &msg;
        // The state just before the first claim. If the run's claims start
        // past message 1, this one check covers every message before that
        // point. The state at that point depends on all of those messages.
        if !self.checked_first_before && self.first_from == Some(msg.id()) {
            self.roots.checked += 1;
            self.boundaries_checked += 1;
            let root = self.engine.state_root();
            let claimed = self.ahead[0].root_before;
            if root != claimed {
                self.roots.fail(format!(
                    "state before message {} hashes to {}, the first claim says {}",
                    msg.id(),
                    logchain::to_hex(&root),
                    logchain::to_hex(&claimed)
                ));
            }
            self.checked_first_before = true;
        }
        // The exchange applies only the next message of one history. If the
        // sequencer serves a history with a gap or a repeat in it, the
        // re-execution cannot go on. Every root after that point would come
        // from messages the run never read. The audit would then report
        // failures that say nothing about the claims.
        if let Err(e) = self.engine.apply_received(raw, msg) {
            self.roots.checked += 1;
            self.roots.fail(format!(
                "the feed's history cannot be re-executed: {}. The claims after message \
                 {} were not checked",
                e,
                msg.id()
            ));
            self.halted = true;
            return;
        }
        self.messages_replayed += 1;
        if self.anchors_at.binary_search(&msg.id()).is_ok() {
            self.at_anchors.insert(msg.id(), self.engine.state_root());
        }

        while self.ahead.front().is_some_and(|c| c.to_msg == msg.id()) {
            let claim = self.ahead.pop_front().expect("just checked");
            self.roots.checked += 1;
            self.boundaries_checked += 1;
            let root = self.engine.state_root();
            if root != claim.root_after {
                self.roots.fail(format!(
                    "after message {} the state hashes to {}, the claim says {}",
                    msg.id(),
                    logchain::to_hex(&root),
                    logchain::to_hex(&claim.root_after)
                ));
            }
            // The claim commits to the running trade count as well as to the
            // root. The audit used to read that count out of the database and
            // compare it with nothing, so `UPDATE claims SET trades_total = 0`
            // passed.
            self.totals.checked += 1;
            let replayed_trades = self.engine.trades_total();
            if replayed_trades != claim.trades_total {
                self.totals.fail(format!(
                    "the claim for messages {}..{} says {} trades had executed by then, \
                     the re-execution had {}",
                    claim.from_msg, claim.to_msg, claim.trades_total, replayed_trades
                ));
            }
        }
    }

    /// True while the re-execution has produced trades that no recorded row
    /// has been compared against, and the audit holds no page to compare them
    /// with. The driver fetches a page only then. That keeps one page of rows
    /// in memory, and not the whole table.
    fn wants_trades(&self) -> bool {
        !self.trades_ended
            && self.pending_trades.is_empty()
            && self.engine.trades_total() > self.compared_trades as u64
    }

    /// Fixes how far into the trades table this audit reads, now that the
    /// audit has seen every claim inside its view. A local audit sets nothing.
    /// Its claims and its trades already came from one read transaction.
    ///
    /// This must also reach backwards, into the rows the audit already read. A
    /// page of trades holds a thousand rows, and a whole run's trades often
    /// fit in one page. So the first fetch, made long before the last claim is
    /// known, often brings back rows past where this audit's view ends. A
    /// limit on the later fetches alone left those rows counted, and a live
    /// exchange was reported as having twenty-one fills too many.
    fn set_trades_bound(&mut self) {
        if self.horizon.is_none() {
            return;
        }
        let bound = self.last_trades_total.unwrap_or(0);
        self.trades_bound = Some(bound);
        if self.pending_trades.iter().any(|row| row.trade_id > bound) {
            // The audit has already seen rows past the view, so there is
            // nothing left to fetch.
            self.trades_ended = true;
        }
        self.pending_trades.retain(|row| row.trade_id <= bound);
    }

    /// The `trade_id` to ask the trades source for next.
    fn trades_cursor(&self) -> u64 {
        self.last_trade_id
    }

    /// Takes one page of recorded trades and compares what it can.
    fn push_trades(&mut self, page: Vec<DbTrade>) {
        for row in page {
            if self.trades_bound.is_some_and(|bound| row.trade_id > bound) {
                // Past the view this audit fixed. These rows are trades the
                // exchange committed after the audit started, and the next
                // audit covers them.
                self.trades_ended = true;
                break;
            }
            self.last_trade_id = self.last_trade_id.max(row.trade_id);
            self.pending_trades.push_back(row);
        }
        self.compare_trades();
    }

    /// Compares recorded trades against re-executed trades, in order, as far
    /// as both go. The audit drops rows the re-execution will never reach,
    /// once the re-execution is over. Those rows are already counted, and
    /// `finish` reports the count.
    ///
    /// The driver calls this after every message the re-execution applies, and
    /// not only when a page of rows arrives. The re-execution keeps only its
    /// newest trades, in a window of `matcher::TRADE_WINDOW` trades, and not
    /// every trade of the run. So the audit must compare a row while the trade
    /// it describes is still inside that window. The driver used to leave the
    /// comparison until the pages ran out, because a page of a thousand rows
    /// normally runs ahead of the re-execution and stopped the driver asking
    /// for more. That compared the run's first trades against a window which
    /// had long moved past them.
    fn compare_trades(&mut self) {
        while !self.pending_trades.is_empty() {
            let next = self.compared_trades as u64 + 1;
            let Some(ours) = self.engine.trade(next) else {
                if self.engine.trades_total() >= next {
                    // The re-execution produced this trade and no longer holds
                    // it. Nothing here can compare the row against the trade.
                    // To skip the row without a word would turn an unchecked
                    // trade into a checked one, so the audit reports it as the
                    // failure it is.
                    let row = self.pending_trades.pop_front().expect("just checked");
                    self.trades.fail(format!(
                        "trade {} could not be compared: the re-execution has moved more than \
                         {} trades past it",
                        row.trade_id,
                        crate::matcher::TRADE_WINDOW
                    ));
                    self.compared_trades += 1;
                    self.recorded_trades += 1;
                    continue;
                }
                if self.replay_ended {
                    // Rows the re-execution will never reach. They are inside
                    // this audit's view, so they count toward the recorded
                    // total the checks below compare against. There is nothing
                    // to compare them with field by field.
                    self.recorded_trades += self.pending_trades.len();
                    self.pending_trades.clear();
                }
                return;
            };
            let row = self.pending_trades.pop_front().expect("just checked");
            let diffs = trade_differences(ours, &row);
            if !diffs.is_empty() {
                self.trades
                    .fail(format!("trade {}: {}", row.trade_id, diffs.join("; ")));
            }
            self.compared_trades += 1;
            self.recorded_trades += 1;
        }
    }

    /// The checks, once every message and every recorded trade has gone past.
    fn finish(mut self, cursor: OrderId) -> ReplayResult {
        self.replay_ended = true;
        self.compare_trades();
        if let Some(first_from) = self.first_from
            && !self.checked_first_before
        {
            self.roots.checked += 1;
            self.roots.fail(format!(
                "the feed's history has no message {}, where the first claim starts, so the \
                 state that claim starts from was never checked",
                first_from
            ));
        }
        if !self.ahead.is_empty() {
            let unreached = &self.ahead[0];
            self.roots.checked += 1;
            self.roots.fail(format!(
                "{} claim boundaries were never reached in the feed's history; the first is \
                 the claim for messages {}..{}",
                self.ahead.len(),
                unreached.from_msg,
                unreached.to_msg
            ));
        }

        // The last claim states how many trades the run had executed in total.
        // So the last claim is also a statement about the trades table itself.
        if let Some(total) = self.last_trades_total {
            self.totals.checked += 1;
            if total != self.recorded_trades as u64 {
                self.totals.fail(format!(
                    "the last claim says {} trades had executed by message {}, the trades \
                     table holds {} rows for this run",
                    total,
                    self.previous.as_ref().map(|c| c.to_msg).unwrap_or(0),
                    self.recorded_trades
                ));
            }
        }

        let replayed = self.engine.trades_total() as usize;
        self.trades.checked = replayed.max(self.recorded_trades);
        if replayed != self.recorded_trades {
            self.trades.fail(format!(
                "the run recorded {} trades, re-execution produced {}",
                self.recorded_trades, replayed
            ));
        }

        // Claims that stop short of what the run committed are the difference
        // between "audited" and "nothing was checked". An empty claims table
        // on a run that read 5000 messages used to print one line and exit 0.
        let mut coverage = Check::new("the claims cover everything the run committed");
        coverage.checked = 1;
        match &self.previous {
            None if cursor == 0 => {}
            None => coverage.fail(format!(
                "this run committed feed messages up to {} and holds no claims at all: its \
                 execution was never committed to and cannot be audited",
                cursor
            )),
            Some(last) if last.to_msg == cursor => {}
            Some(last) if last.to_msg < cursor => coverage.fail(format!(
                "this run's claims stop at message {} but the run committed up to message \
                 {}: messages {}..{} were executed without a claim over them",
                last.to_msg,
                cursor,
                last.to_msg.saturating_add(1),
                cursor
            )),
            Some(last) => coverage.fail(format!(
                "this run's claims reach message {}, past the run's own cursor at {}: they \
                 describe messages the run never committed",
                last.to_msg, cursor
            )),
        }

        ReplayResult {
            coverage,
            continuity: self.continuity,
            roots: self.roots,
            totals: self.totals,
            trades: self.trades,
            messages_replayed: self.messages_replayed,
            boundaries_checked: self.boundaries_checked,
            claims_to: self.previous.as_ref().map(|c| c.to_msg).unwrap_or(0),
            at_anchors: self.at_anchors,
        }
    }
}

/// What one re-execution produced.
struct ReplayResult {
    coverage: Check,
    continuity: Check,
    roots: Check,
    totals: Check,
    trades: Check,
    messages_replayed: usize,
    boundaries_checked: usize,
    /// The last message any claim covers, for the "the signed head covers it"
    /// check.
    claims_to: OrderId,
    /// The state root this re-execution had at each anchored message it
    /// reached.
    at_anchors: BTreeMap<OrderId, logchain::StateRoot>,
}

// ---------------------------------------------------------------------------
// The checks around the re-execution
// ---------------------------------------------------------------------------

/// Checks the sequencer's signed head, with the key this run pinned and how
/// far the run went. `reporting::check_feed_head` states the rule. This
/// function gives it the two values the audit's own walk of the history keeps.
fn check_head(
    facts: &RunFacts,
    head: &Result<FeedHead, String>,
    fold: &ChainFold,
    claimed_to: OrderId,
) -> Vec<Check> {
    check_feed_head(
        facts.run_id,
        facts.feed_pubkey.as_deref(),
        head,
        &FoldedChain {
            chain: fold.at_head.unwrap_or(logchain::EMPTY_CHAIN),
            counted: fold.counted,
        },
        claimed_to.max(facts.cursor),
    )
}

/// Checks the exchange's current history and execution against every
/// commitment somebody wrote to a public chain.
///
/// This is the only check in this file that does not come out of the
/// operator's own machine. It is also the only check that still works after
/// the operator deletes their databases. Every other check here proves that
/// the served history and the served claims agree with each other. An exchange
/// that rewound, ran a different history, and signed every statement again
/// over that history passes all of them. What that exchange cannot do is go
/// back and change a value in a block.
///
/// The audit checks every anchor, and not only the newest one. Take an
/// operator who rewound to message 500, published different messages from
/// there, and ran on to message 1500. That operator anchors `(1500, H_new)`,
/// and today's history produces that newest entry exactly. A check of the
/// newest anchor alone sees nothing. The entry at message 1000 is the one that
/// does not come out the same, and the block that carried it is when the
/// operator committed to the other version. So the audit hashes the history to
/// every anchor and compares every one. A read of the log that missed anchors
/// is itself a failure.
///
/// The audit compares three things at every anchor. Each failure names both
/// values, the same way the rest of this report does:
///
/// - The anchored session against the session the sequencer serves now. A
///   different session is not a small mismatch. It means the log was thrown
///   away and started again, which is the exact event an anchor exists to
///   expose. So the check fails loudly and says so.
/// - The anchored chain hash against the chain hash over today's messages at
///   the anchored position.
/// - The anchored state root against the state root this re-execution had
///   after the anchored message.
fn check_anchors(
    facts: &RunFacts,
    history: &Result<AnchorHistory, String>,
    fold: &ChainFold,
    replayed: &BTreeMap<OrderId, logchain::StateRoot>,
    cursor: OrderId,
) -> Vec<Check> {
    let history = match history {
        Ok(history) => history,
        Err(reason) => {
            // An anchor the audit could not read is an unchecked claim, and
            // not a satisfied one. A pass here would report the one property
            // the rest of this audit cannot prove as proven.
            let mut unreadable = Check::new("the on-chain anchors are readable");
            unreadable.checked = 1;
            unreadable.fail(format!(
                "{}. An anchor that cannot be read is an unchecked claim, not a satisfied \
                 one: nothing here shows this history is the one that existed before now",
                reason
            ));
            return vec![unreadable];
        }
    };

    let mut read = Check::new("every anchor this contract holds was read");
    let mut agrees = Check::new("the newest anchor and the contract agree");
    let mut sessions = Check::new("every on-chain anchor names this history");
    let mut chains = Check::new("every on-chain anchor matches the feed");
    let mut execution = Check::new("every on-chain anchor matches this execution");

    read.checked = history.anchors.len();
    if !history.complete {
        read.fail(format!(
            "{} says it has written {} anchors and only {} were found, scanning its log back to \
             block {}. The ones that were not read are the older ones, which are exactly the \
             ones a rewind would contradict, so this is not a set of anchors that can be called \
             checked. Pass --anchor-from-block <BLOCK> with the block the contract was deployed \
             in, and the whole range is read instead of the recent window an open-ended scan \
             stops at. The block is in the deployment record beside the address",
            history.contract,
            history.total,
            history.anchors.len(),
            history.scanned_from,
        ));
    }
    // The newest event and the contract's own state are two forms of one
    // write. No other check here would see them disagree. They disagree only
    // when the endpoint is not serving one consistent view of one chain. In
    // that case none of the anchors below mean anything either.
    agrees.checked = 1;
    if !history.latest_agrees {
        agrees.fail(format!(
            "{} holds anchor {} for message {} of session {} in its state, and its own log does \
             not carry that write. The endpoint answering is not serving one consistent view of \
             one chain, so nothing read from it is evidence",
            history.contract, history.latest.index, history.latest.last_id, history.latest.session
        ));
    }

    for anchor in &history.anchors {
        // Where and when the operator committed to this anchor. A failure
        // below is then evidence somebody can act on, and not two hashes on a
        // screen.
        let written = format!(
            "written in block {} at {} ({})",
            anchor.block_number,
            anchor.anchored_at,
            anchor.age()
        );

        sessions.checked += 1;
        let same_history = facts.session.as_deref() == Some(anchor.session.as_str());
        match &facts.session {
            Some(ours) if *ours == anchor.session => {}
            Some(ours) => sessions.fail(format!(
                "anchor {} of {} committed to feed session {} at message {}, {}; this exchange \
                 serves session {}. The history the anchor names has been replaced, which is \
                 exactly the event an anchor exists to expose",
                anchor.index, history.total, anchor.session, anchor.last_id, written, ours
            )),
            None => sessions.fail(format!(
                "anchor {} of {} committed to feed session {} at message {}, {}; this exchange \
                 names no session at all, so nothing ties what it serves to the history that \
                 was anchored",
                anchor.index, history.total, anchor.session, anchor.last_id, written
            )),
        }

        // If the session is a different one, the anchored id names a message
        // of another history, and there is nothing here to compare it with.
        // This is still a failure, because an anchor the audit cannot check is
        // not a satisfied anchor. But the audit must not report it as a
        // rewound chain or a rolled-back exchange. Those are exact accusations
        // about *this* history that the evidence does not support.
        if !same_history {
            let reason = format!(
                "anchor {} of {} names message {} of history {}, {}; this exchange serves \
                 history {}, where that id is a different message. There is nothing here to \
                 compare it against",
                anchor.index,
                history.total,
                anchor.last_id,
                anchor.session,
                written,
                facts.session.as_deref().unwrap_or("(none announced)")
            );
            chains.checked += 1;
            chains.fail(reason.clone());
            execution.checked += 1;
            execution.fail(reason);
            continue;
        }

        chains.checked += 1;
        match fold.at_anchors.get(&anchor.last_id) {
            Some(ours) if *ours == anchor.chain => {}
            Some(ours) => chains.fail(format!(
                "anchor {} of {} holds chain {} at message {}, {}; this feed's messages hash to \
                 {} there. The history served today is not the history that was anchored",
                anchor.index,
                history.total,
                logchain::to_hex(&anchor.chain),
                anchor.last_id,
                written,
                logchain::to_hex(ours)
            )),
            None => chains.fail(format!(
                "anchor {} of {} commits to message {}, {}; this feed's history stops at message \
                 {}. The history it names is not here to check",
                anchor.index, history.total, anchor.last_id, written, fold.reached
            )),
        }

        execution.checked += 1;
        match replayed.get(&anchor.last_id) {
            Some(ours) if *ours == anchor.state_root => {}
            Some(ours) => execution.fail(format!(
                "anchor {} of {} holds state root {} after message {}, {}; the re-execution \
                 produced {} there. The same messages no longer produce the state that was \
                 anchored",
                anchor.index,
                history.total,
                logchain::to_hex(&anchor.state_root),
                anchor.last_id,
                written,
                logchain::to_hex(ours)
            )),
            None if anchor.last_id > cursor => execution.fail(format!(
                "anchor {} of {} commits to the state after message {}, {}; this run has \
                 committed only up to message {}. The exchange has been rolled back past its \
                 own anchor",
                anchor.index, history.total, anchor.last_id, written, cursor
            )),
            None => execution.fail(format!(
                "the re-execution never reached message {}, which anchor {} of {} commits to \
                 the state after, so that state was never recomputed",
                anchor.last_id, anchor.index, history.total
            )),
        }
    }

    vec![read, agrees, sessions, chains, execution]
}

/// Checks that every claim carries the exchange's signature over exactly what
/// the claim says.
///
/// This check is what makes a claim mean something outside the operator's own
/// machine. A root in a database row is only the operator's word. A root
/// inside a signature is signed by the operator's key. Two signatures over the
/// same message range with different roots are proof the operator cannot take
/// back.
fn check_claim_signatures(facts: &RunFacts, session: &str, claims: &[ClaimRow], check: &mut Check) {
    let key = facts
        .matcher_pubkey
        .as_deref()
        .and_then(logchain::from_hex::<32>)
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok());
    for claim in claims {
        check.checked += 1;
        let Some(key) = &key else {
            check.fail(format!(
                "the claim for messages {}..{} cannot be checked: this run names no key \
                 ({}) that its claims are signed with",
                claim.from_msg,
                claim.to_msg,
                facts.matcher_pubkey.as_deref().unwrap_or("none recorded")
            ));
            continue;
        };
        let Some(signature) = claim.signature else {
            check.fail(format!(
                "the claim for messages {}..{} carries no signature: it is a row in a file \
                 and nothing more",
                claim.from_msg, claim.to_msg
            ));
            continue;
        };
        if !logchain::verify_claim(
            key,
            session,
            claim.from_msg,
            claim.to_msg,
            &claim.root_before,
            &claim.root_after,
            claim.trades_total,
            &Signature::from_bytes(&signature),
        ) {
            check.fail(format!(
                "the claim for messages {}..{} (roots {} -> {}, {} trades) does not verify \
                 under the key this run signs with",
                claim.from_msg,
                claim.to_msg,
                logchain::to_hex(&claim.root_before),
                logchain::to_hex(&claim.root_after),
                claim.trades_total
            ));
        }
    }
}

/// Runs every check against one run and one history. This is the one place an
/// audit is defined. Both ways in call it, and they differ only in where the
/// three sources read from.
///
/// The parameter list is long because an audit does take that many separate
/// things. To put them in one struct would move the list somewhere the two
/// call sites cannot see it.
#[allow(clippy::too_many_arguments)]
async fn check_run(
    facts: &RunFacts,
    tie: &HistoryTie,
    head: &Result<FeedHead, String>,
    wire_session: Option<&str>,
    messages: Messages<'_>,
    claims: Claims<'_>,
    trades: Trades<'_>,
    horizon: Option<OrderId>,
    anchors: Option<&Result<AnchorHistory, String>>,
    sth: &Result<TreeHead, String>,
    root_anchors: Option<&Result<RootAnchorHistory, String>>,
) -> Result<Outcome, String> {
    let mut checks = Vec::new();
    // The tree sizes the walk must keep a root at. The audit knows them before
    // it reads a message: the signed tree head names its own size, and each
    // root anchor names the size it commits to.
    let root_sizes = root_sizes(sth, root_anchors);
    let mut tree = TreeWalk::new(&root_sizes);
    let wanted_leaves = root_sizes.last().copied().unwrap_or(0);
    // Where the anchors stand. The audit needs this before it hashes a single
    // message. The one pass this audit already makes records the chain hash
    // and the state root at every one of those positions, instead of one walk
    // of the history for each anchor.
    let anchors_at = anchors
        .and_then(|a| a.as_ref().ok())
        .map(|history| history.positions())
        .unwrap_or_default();

    // Which history is on the wire, before the audit compares anything against
    // it.
    let mut session = Check::new("the feed is the history this run consumed");
    session.checked = 1;
    // Set when the sequencer serves a history this run can be shown never to
    // have seen. To run that history again would fail every root for reasons
    // that say nothing about the claims. So the audit stops, instead of
    // printing thousands of failure lines.
    let mut replaced_feed = false;
    match (&facts.session, wire_session) {
        (Some(ours), Some(theirs)) if ours == theirs => {}
        (Some(ours), Some(theirs)) => {
            session.fail(format!(
                "run {} consumed feed session {}, this feed serves session {}",
                facts.run_id, ours, theirs
            ));
            replaced_feed = true;
        }
        (Some(ours), None) => {
            session.fail(format!(
                "run {} consumed feed session {}, this feed announces no session at all",
                facts.run_id, ours
            ));
            replaced_feed = true;
        }
        // A NULL session used to skip this check. That made
        // `UPDATE runs SET feed_session = NULL` a one-statement way past it.
        // Unknown does not mean fine. It means the check could not run, and a
        // check that could not run has not passed. The re-execution still goes
        // ahead, because the chain check below can tie the messages to this
        // run without the session name.
        (None, _) => session.fail(format!(
            "run {} recorded no feed session, so the history this feed serves cannot be \
             shown to be the history the run consumed",
            facts.run_id
        )),
    }
    checks.push(session);

    if replaced_feed {
        let empty = ChainFold::new(None, facts.cursor, anchors_at);
        checks.extend(check_head(facts, head, &empty, 0));
        // A sequencer that serves a different history is the strongest reason
        // to state what the anchors say. The audit ran nothing again, so the
        // only evidence left about what this exchange used to be is on the
        // public chain.
        if let Some(anchors) = anchors {
            checks.extend(check_anchors(
                facts,
                anchors,
                &empty,
                &BTreeMap::new(),
                facts.cursor,
            ));
        }
        // The tree over the same nothing. The audit hashed no message, so a
        // signed head or an anchor over any size at all fails here. That is
        // the honest answer about a sequencer that serves a history this run
        // never saw.
        let tree_report = check_tree(sth, root_anchors, tree.fold());
        checks.extend(tree_report.checks);
        let (nodes, no_log) = tree.finish();
        checks.push(nodes);
        let mut notes = tree_report.notes;
        notes.extend(no_log);
        return Ok(Outcome {
            checks,
            notes,
            stopped: Some(format!(
                "this feed is not serving the history run {} was built from, so its claims \
                 were not re-executed against it",
                facts.run_id
            )),
            too_old: None,
            messages_replayed: 0,
            boundaries_checked: 0,
            boundaries_total: claims.len_hint().map_or(0, boundaries_total),
            elapsed: Duration::ZERO,
        });
    }

    // The session the claims are signed over, and the log the re-execution
    // runs again. A run whose sequencer never named a session signed the empty
    // string. The exchange used the same value, and it checked operator
    // statements against the empty string too.
    let claim_session = facts.session.clone().unwrap_or_default();
    let mut signatures = Check::new("every claim is signed by this run's key");

    let started = Instant::now();
    let mut replay = Replay::new(horizon, anchors_at.clone(), &claim_session);
    let mut fold = ChainFold::new(
        head.as_ref().ok().map(|h| h.last_id),
        facts.cursor,
        anchors_at,
    );
    let mut at: OrderId = 0;
    let mut feed_session: Option<String> = None;
    let mut history_ends_at: Option<OrderId> = None;

    loop {
        // The re-execution is not the only reason to keep reading. The audit
        // must check the sequencer's signed head against a chain hash taken
        // all the way to where that head stands. It must check the run's own
        // chain hash against one taken to the run's cursor. Both positions can
        // be past the last claim.
        // An anchored position past the last claim is also a reason to keep
        // reading. The audit can still hash the chain there, even when it
        // cannot compute the state root there. "The messages are intact but
        // the exchange was rolled back" is a different answer from "the
        // messages were rewritten".
        // The tree gives the same kind of reason. A signed tree head or an
        // anchored root over more messages than the audit has hashed is a root
        // the audit cannot produce without reading further.
        let more_needed = replay.wants_messages()
            || fold.head_at.is_some_and(|at| fold.reached < at)
            || (fold.at_cursor.is_none() && fold.reached < facts.cursor)
            || fold.anchors_end().is_some_and(|at| fold.reached < at)
            || tree.fold().len() < wanted_leaves;
        if !more_needed {
            break;
        }

        let page = messages.page(at).await?;
        // A sequencer that changes session part way through the fetch serves
        // two different histories into one audit.
        match (&feed_session, &page.session) {
            (None, Some(now)) => feed_session = Some(now.clone()),
            (Some(first), Some(now)) if first != now => {
                return Err(format!(
                    "the feed changed session from {} to {} while its history was being \
                     read: these are two different histories and cannot be audited as one",
                    first, now
                ));
            }
            _ => {}
        }
        if page.messages.is_empty() {
            history_ends_at = Some(at);
            break;
        }
        // Where the audit asked this page to start from. A page that comes
        // back with no message past that point leaves `at` where it was, and
        // the loop asks the same question again, forever. The conditions above
        // now include one whose limit comes off a public chain, and not off
        // the exchange. So "the exchange stops answering usefully" must end
        // the audit, and not hang it.
        let asked_from = at;
        // Where this page's leaves start. Message n is leaf n-1. The check
        // below refuses a page that does not carry the history forward, so the
        // leaves arrive in order and with no gap.
        let leaves_from = at;
        let mut leaves = 0u64;
        for msg in &page.messages {
            fold.feed(msg);
            // The same bytes into the tree, with nothing read out of them.
            tree.feed(&msg.bytes);
            leaves += 1;
            // Fetch more claims here, message by message, and not once for
            // each page of messages. A page holds a thousand messages, and a
            // page of claims may cover fewer messages than that. A fetch once
            // per page let the claim queue empty in the middle of a page of
            // messages. The audit then skipped every message after that point
            // as "past the last claim", while the claims covering those
            // messages arrived a moment later. Real boundaries were never
            // reached. This showed up only against a live exchange, where the
            // claims are more than one page.
            while replay.wants_claims() {
                let claim_page = claims.page(replay.claims_cursor()).await?;
                let short = claim_page.len() < LOCAL_PAGE;
                check_claim_signatures(facts, &claim_session, &claim_page, &mut signatures);
                replay.push_claims(claim_page);
                if short {
                    replay.claims_ended = true;
                }
            }
            replay.apply(msg);
            at = msg.id;
            // Compare here, message by message, while the trades this message
            // produced are still inside the re-execution's window. See
            // `compare_trades`.
            replay.compare_trades();
            // The audit fetches recorded trades only as the re-execution
            // produces trades to compare them against. So at most one page of
            // recorded trades is in memory, however many the run holds.
            while replay.wants_trades() {
                let rows = trades.page(replay.trades_cursor()).await?;
                if rows.is_empty() {
                    replay.trades_ended = true;
                    break;
                }
                replay.push_trades(rows);
            }
        }
        if at <= asked_from {
            return Err(format!(
                "the feed answered a request for the messages after {} with {} message(s) that \
                 do not go past it. The last is {}, so its history cannot be read forward",
                asked_from,
                page.messages.len(),
                at
            ));
        }
        // The log's own nodes for the leaves this page hashed in. The audit
        // asks page by page, so neither side ever holds a whole tree.
        if tree.wants_nodes() && leaves > 0 {
            match messages.tree_nodes(leaves_from, leaves).await {
                Ok(Some(served)) => tree.page(&served),
                Ok(None) => tree.no_source(),
                Err(reason) => tree.unreadable(reason),
            }
        }
    }

    // Whatever claims are left. The coverage check then sees the whole set,
    // even when the sequencer's history ran out before them. A run whose
    // claims reach message 900, against a sequencer that serves only 400, must
    // be reported as 500 messages of claims the audit could not reach. It must
    // not be reported as a shorter run.
    while replay.wants_claims() {
        let claim_page = claims.page(replay.claims_cursor()).await?;
        let short = claim_page.len() < LOCAL_PAGE;
        check_claim_signatures(facts, &claim_session, &claim_page, &mut signatures);
        replay.push_claims(claim_page);
        if short {
            replay.claims_ended = true;
        }
    }

    // Whatever is left of the recorded trades. The audit counts them, so the
    // totals are honest even when the table holds more rows than the messages
    // produce. `replay_ended` is set first, so the audit counts rows past the
    // re-execution's last trade and then drops them, instead of holding them.
    // A table with a million invented fills in it must not cost a million rows
    // of memory to report.
    replay.replay_ended = true;
    replay.set_trades_bound();
    while !replay.trades_ended {
        let rows = trades.page(replay.trades_cursor()).await?;
        if rows.is_empty() {
            break;
        }
        replay.push_trades(rows);
    }

    let claims_seen = replay.claims_seen;
    let too_old = replay.too_old.clone();
    let result = replay.finish(facts.cursor);
    let elapsed = started.elapsed();

    checks.extend(check_head(facts, head, &fold, result.claims_to));

    // A message this build cannot read stopped the re-execution. The head
    // checks just added are hashes over the bytes the sequencer served, and
    // they hold exactly as they always did. That is the point of hashing
    // bytes. Every check below this line runs messages again. This binary
    // cannot run one of these messages, so the audit did not make those
    // checks, and it must not report them as failed. A failure here would read
    // as "this exchange's records are wrong". What is true is "this audit is
    // older than this exchange".
    if let Some(too_old) = too_old {
        checks.push(signatures);
        // The tree belongs above that line, and not below it. The tree is a
        // hash over the bytes the sequencer served, and nothing in it reads
        // inside a message. So it holds over a history that carries a message
        // kind this build does not know. That is the same reason the chain
        // check is still made here.
        let tree_report = check_tree(sth, root_anchors, tree.fold());
        checks.extend(tree_report.checks);
        let (nodes, no_log) = tree.finish();
        checks.push(nodes);
        let mut notes = tree_report.notes;
        notes.extend(no_log);
        return Ok(Outcome {
            checks,
            notes,
            stopped: None,
            too_old: Some(too_old),
            messages_replayed: result.messages_replayed,
            boundaries_checked: result.boundaries_checked,
            boundaries_total: boundaries_total(claims_seen),
            elapsed,
        });
    }

    // The strongest tie between the messages in hand and this run, where the
    // audit has that tie.
    let mut history = Check::new("the messages are the ones the run consumed");
    history.checked = 1;
    match tie {
        HistoryTie::StoredChain(None) => history.fail(format!(
            "run {} recorded no hash chain for the history it consumed, so these messages \
             cannot be shown to be that history",
            facts.run_id
        )),
        HistoryTie::StoredChain(Some(recorded)) => match fold.at_cursor {
            None => history.fail(format!(
                "the feed's history ends at message {}, but run {} committed up to \
                 message {}",
                history_ends_at.unwrap_or(fold.reached),
                facts.run_id,
                facts.cursor
            )),
            Some(ours) if ours != *recorded => history.fail(format!(
                "run {} consumed a history hashing to {} at message {}, these messages \
                 hash to {}",
                facts.run_id,
                logchain::to_hex(recorded),
                facts.cursor,
                logchain::to_hex(&ours)
            )),
            Some(_) => {}
        },
        // A remote audit is never shown the run's own chain hash. What ties
        // these messages to this run instead is the claim signatures above and
        // the roots below. The exchange signed roots that only the state these
        // messages produce can hash to.
        HistoryTie::SignedClaims => {
            if fold.reached < facts.cursor {
                history.fail(format!(
                    "the feed's history ends at message {}, but this run committed up to \
                     message {}",
                    fold.reached, facts.cursor
                ));
            }
        }
    }

    checks.push(signatures);
    checks.push(history);
    checks.push(result.coverage);
    checks.push(result.continuity);
    checks.push(result.roots);
    checks.push(result.totals);
    checks.push(result.trades);
    // Last, because these checks ask a question none of the others can. They
    // do not ask "does this exchange agree with itself". They ask "is this the
    // same exchange it was".
    if let Some(anchors) = anchors {
        checks.extend(check_anchors(
            facts,
            anchors,
            &fold,
            &result.at_anchors,
            facts.cursor,
        ));
    }
    // And the tree beside them, for the same reason. The audit compares the
    // root the sequencer signs at `/sth`, and every root somebody wrote to a
    // public chain, against the root these messages make.
    let tree_report = check_tree(sth, root_anchors, tree.fold());
    checks.extend(tree_report.checks);
    let (nodes, no_log) = tree.finish();
    checks.push(nodes);
    let mut notes = tree_report.notes;
    notes.extend(no_log);

    Ok(Outcome {
        checks,
        notes,
        stopped: None,
        too_old: None,
        messages_replayed: result.messages_replayed,
        boundaries_checked: result.boundaries_checked,
        boundaries_total: boundaries_total(claims_seen),
        elapsed,
    })
}

/// One boundary for each claim, plus the state before the first claim.
fn boundaries_total(claims: usize) -> usize {
    if claims == 0 { 0 } else { claims + 1 }
}

/// Prints the checks, what the audit covered, and the verdict.
fn report(outcome: &Outcome, claims: usize, run_id: i64) -> Verdict {
    // The audit prints every check before it takes the verdict. To take the
    // verdict outside `report()` with `all` would stop at the first failure
    // and drop every check after it. The run with the most to say about what
    // went wrong would then say the least.
    for check in &outcome.checks {
        check.report();
    }
    for note in &outcome.notes {
        println!("{}", note);
    }
    let passed = outcome.passed();

    if let Some(stopped) = &outcome.stopped {
        println!("\nAudit FAILED. {}", stopped);
        return Verdict::Failed;
    }

    // Printed before the pass or fail line, and in place of it. An audit that
    // cannot read a message has found nothing wrong with the exchange. The one
    // sentence an operator takes away from this run must not say it has.
    //
    // This does not apply when a check that did run failed. Those checks are
    // the sequencer's chain hash, the sequencer's signature, and the
    // exchange's signature on every claim. They are hashes and signature
    // checks over bytes. They are as true against a history this build cannot
    // read as against one it can. A real failure wins over being too old.
    // Otherwise an old binary would be a way to turn a failing audit into an
    // exit status that raises no alert.
    if let Some(too_old) = &outcome.too_old
        && passed
    {
        println!(
            "\n  re-execution stopped after {} messages",
            outcome.messages_replayed
        );
        println!(
            "\nAudit INCOMPLETE, exit status 3.\n  {}",
            too_old.notice(
                "The feed's signed chain was checked over the bytes it served, as far as \
                 its head, and it holds."
            )
        );
        return Verdict::TooOld(too_old.clone());
    }

    println!(
        "\n  re-execution took {:.2}s for {} messages ({} of {} claim boundaries hashed)",
        outcome.elapsed.as_secs_f64(),
        outcome.messages_replayed,
        outcome.boundaries_checked,
        outcome.boundaries_total,
    );
    if outcome.boundaries_checked < outcome.boundaries_total {
        println!(
            "  {} claim boundaries were not reached, so their roots were never compared",
            outcome.boundaries_total - outcome.boundaries_checked
        );
    }

    if passed {
        if claims == 0 {
            println!(
                "\nRun {} consumed no messages, so there was no execution to check. The \
                 feed's signed history checked out.",
                run_id
            );
        } else {
            println!(
                "\nAll claims hold: the recorded execution is the one the messages produce, \
                 and the matcher's own signature is on every claim checked.\n\
                 (A zk proof would replace this re-execution with a millisecond \
                 verification.)"
            );
        }
    } else {
        println!("\nAudit FAILED. The recorded execution is not what the messages produce.");
        // The failure is the main answer. This is still a fact about the run
        // that an operator must know before reading the list above as
        // complete.
        if let Some(too_old) = &outcome.too_old {
            println!("  {}", too_old);
            println!("  so the checks that re-execute the history stop there.");
        }
    }
    Verdict::of(passed)
}

/// Names the runs this command did not audit. A file keeps every run it ever
/// had. After the sequencer restarts, the exchange opens a new run. An audit
/// that always takes the newest run then never looks at the run before it, or
/// at that run's claims.
fn print_other_runs(record: &RunRecord) {
    let others: Vec<&RunSummary> = record
        .runs
        .iter()
        .filter(|r| r.run_id != record.facts.run_id)
        .collect();
    if others.is_empty() {
        return;
    }
    println!(
        "\n  {} other run(s) in this file were not audited by this command:",
        others.len()
    );
    for run in others {
        println!(
            "    run {:<4} {:<15} cursor {:<9} {} claims, covering up to message {}",
            run.run_id, run.status, run.cursor, run.claims, run.covered_to
        );
    }
    println!("    audit one of them with --audit --audit-run <RUN_ID>");
}

// ---------------------------------------------------------------------------
// The two entry points
// ---------------------------------------------------------------------------

/// Fetches every anchor the contract holds, or the reason they could not be
/// read.
///
/// `check_anchors` needs the whole set and not only the newest. It fails when
/// the contract says it wrote more anchors than were found, because the ones
/// that were not read are the older ones, which are exactly the ones a rewind
/// would contradict. `AnchorHistory` carries the newest anchor beside the set,
/// for the check that the contract's own state and its own log agree.
///
/// `None` in gives `None` out. An audit with no anchor configured runs exactly
/// as it did before anchors existed. It adds no check to the report and makes
/// no extra request. That is the honest default. Most exchanges have no
/// anchor, and an audit of one must not print a failure for a feature its
/// operator never claimed to have.
async fn read_anchors(source: Option<&AnchorSource>) -> Option<Result<AnchorHistory, String>> {
    let source = source?;
    let history = crate::anchor::read_history(source).await;
    match &history {
        Ok(history) => println!(
            "  anchors  {} on chain {}\n           {} of {} read, back to block {}\n           \
             newest: message {} of session {}, written {}\n",
            history.contract,
            history.chain_id,
            history.anchors.len(),
            history.total,
            history.scanned_from,
            history.latest.last_id,
            history.latest.session,
            history.latest.age()
        ),
        Err(reason) => println!("  anchors  {}\n", reason),
    }
    Some(history)
}

/// Runs the latest run in `state_db` again from the sequencer's history, and
/// checks every claim that run made.
pub async fn audit(state_db: &Path, feed_url: &str) -> Result<Verdict, String> {
    audit_run(state_db, feed_url, None, None, None).await
}

/// `audit`, for one named run instead of the newest run in the file.
pub async fn audit_run(
    state_db: &Path,
    feed_url: &str,
    run: Option<i64>,
    anchor: Option<&AnchorSource>,
    root_anchor: Option<&RootAnchorSource>,
) -> Result<Verdict, String> {
    let record = read_db(state_db, run)?;
    let client = fetch::client()?;

    // The head first, then the messages. The messages then always reach past
    // the signed id, even when the sequencer publishes more between the two
    // requests.
    let head = read_feed_head(&client, feed_url).await;
    // The session as the sequencer announces it on the wire, read from the
    // first page the way every reader in this repository reads it.
    let wire_session = Messages::Feed {
        client: &client,
        url: feed_url,
    }
    .page(0)
    .await?
    .session;

    println!(
        "Auditing run {} of {}: {} claims covering messages {}..{}, cursor at {}, \
         {} trades recorded\n",
        record.facts.run_id,
        state_db.display(),
        record.claims.len(),
        record.claims.first().map(|c| c.from_msg).unwrap_or(0),
        record.claims.last().map(|c| c.to_msg).unwrap_or(0),
        record.facts.cursor,
        record.trades.len(),
    );
    let anchors = read_anchors(anchor).await;
    let sth = crate::anchor::fetch_tree_head(&client, feed_url).await;
    let root_anchors = read_root_anchors(root_anchor).await;

    let outcome = check_run(
        &record.facts,
        &HistoryTie::StoredChain(record.chain),
        &head,
        wire_session.as_deref(),
        Messages::Feed {
            client: &client,
            url: feed_url,
        },
        Claims::Held(&record.claims),
        Trades::Held(&record.trades),
        // No view limit. `read_db` already took one snapshot of the claims and
        // the trades, so both describe the same moment.
        None,
        anchors.as_ref(),
        &sth,
        root_anchors.as_ref(),
    )
    .await?;
    let verdict = report(&outcome, record.claims.len(), record.facts.run_id);
    print_other_runs(&record);
    Ok(verdict)
}

/// Audits a live exchange over HTTP, with no access to its database.
///
/// This is the version that matters to somebody who is not the operator. It
/// fetches the signed claims and the trade log from the exchange's own
/// endpoints. It checks each claim's signature against the key the exchange
/// publishes. It then runs the sequencer's signed history again against those
/// claims, in pages of a bounded size. Nothing here needs help from the
/// exchange beyond the endpoints it already serves, and nothing here holds a
/// whole history in memory.
///
/// `feed_url` is `--feed-url` when the reader named one, and `None` when the
/// reader did not. With `None`, the audit asks the exchange where its
/// sequencer is: see `resolve_feed_url`. That is what lets this command take
/// one URL and nothing else, which is the whole claim the command makes.
///
/// `expect_key` pins the key the claims must be signed with. Without it, the
/// audit takes the key the exchange serves on first contact. That proves the
/// claims agree with each other. It does not prove they came from the exchange
/// the reader meant to audit. Every other pin in this system starts the same
/// way: it trusts the key it sees on first contact. Anyone who has seen this
/// exchange's key before should pass it.
///
/// `anchor` is the contract the reader wants this exchange checked against. It
/// comes from the reader's own flags, and not from anything the exchange says.
/// Left unset, this command behaves exactly as it did before anchors existed.
/// Set, an exchange that cannot produce again what somebody committed to a
/// public chain fails. An anchor that cannot be read at all also fails.
pub async fn audit_url(
    matcher_url: &str,
    feed_url: Option<&str>,
    expect_key: Option<&str>,
    anchor: Option<&AnchorSource>,
    root_anchor: Option<&RootAnchorSource>,
) -> Result<Verdict, String> {
    let client = fetch::client()?;
    let matcher_url = matcher_url.trim_end_matches('/');

    // One request for the envelope: which run, which session, how far the run
    // committed, and which keys to check against. The loop below fetches the
    // claims themselves again, from the start.
    let (envelope, _) = fetch_json::<ClaimsPage>(
        &client,
        &format!("{}/claims?since=0", matcher_url),
        "the claims envelope",
    )
    .await?;

    if let Some(expected) = expect_key
        && expected != envelope.matcher_public_key
    {
        return Err(format!(
            "{} signs its claims with {}, not the key {} this audit was told to expect. \
             Either this is not the exchange you meant, or its key changed, and nothing \
             in this protocol announces a key change",
            matcher_url, envelope.matcher_public_key, expected
        ));
    }

    let facts = RunFacts {
        run_id: envelope.run_id,
        session: (!envelope.session.is_empty()).then(|| envelope.session.clone()),
        feed_pubkey: envelope.feed_public_key.clone(),
        matcher_pubkey: Some(envelope.matcher_public_key.clone()),
        cursor: envelope.cursor,
    };

    // Where the history comes from. The audit asks after the claims, and not
    // before. An exchange that does not answer at all must then fail with the
    // URL the reader typed. It must not get reported as an exchange that names
    // no sequencer.
    let advertised = feed_url.is_none();
    let feed_url = resolve_feed_url(&client, matcher_url, feed_url).await?;
    let feed_url = feed_url.as_str();

    let head = read_feed_head(&client, feed_url).await;
    let wire_session = Messages::Feed {
        client: &client,
        url: feed_url,
    }
    .page(0)
    .await
    .map_err(|reason| unreachable_feed(reason, matcher_url, feed_url, advertised))?
    .session;

    println!(
        "Auditing run {} of {} against feed {}{}\n  session {}\n  claims signed by {}\n  \
         committed up to feed message {}\n",
        facts.run_id,
        matcher_url,
        feed_url,
        if advertised {
            " (the address it advertises)"
        } else {
            ""
        },
        if envelope.session.is_empty() {
            "(none announced)"
        } else {
            &envelope.session
        },
        envelope.matcher_public_key,
        facts.cursor,
    );
    if expect_key.is_none() {
        println!(
            "  the signing key was taken from this exchange on first contact. Record it and \
             pass --matcher-key next time: a key checked against itself proves the claims \
             agree with each other, not who made them.\n"
        );
    }
    let anchors = read_anchors(anchor).await;
    let sth = crate::anchor::fetch_tree_head(&client, feed_url).await;
    let root_anchors = read_root_anchors(root_anchor).await;

    let outcome = check_run(
        &facts,
        &HistoryTie::SignedClaims,
        &head,
        wire_session.as_deref(),
        Messages::Feed {
            client: &client,
            url: feed_url,
        },
        Claims::Remote {
            client: &client,
            url: matcher_url,
        },
        Trades::Remote {
            client: &client,
            url: matcher_url,
        },
        // The exchange is live and keeps committing while the audit runs. So
        // the audit fixes its view at the cursor the exchange reported a
        // moment ago.
        Some(facts.cursor),
        anchors.as_ref(),
        &sth,
        root_anchors.as_ref(),
    )
    .await?;
    // A live exchange is always a batch or two behind the sequencer. So claims
    // that reach less far than the sequencer's head are normal, and the audit
    // reports that as a fact and not as a failure. Claims that stop short of
    // the exchange's own committed cursor are not normal, and they are a
    // failure.
    if let Ok(head) = &head
        && head.last_id > facts.cursor
    {
        println!(
            "\n  the feed has published up to message {} and this run has committed up to \
             {}; the {} messages in between are not claimed yet",
            head.last_id,
            facts.cursor,
            head.last_id - facts.cursor
        );
    }
    // The first page is empty exactly when the run has claimed nothing. The
    // closing line must then say that, and not "all claims hold".
    Ok(report(&outcome, envelope.claims.len(), facts.run_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::Anchor;
    use crate::domain::{AccountId, OPERATOR_ACCOUNT};
    use crate::store::{Change, Counters, Store, TradeRow};
    use ed25519_dalek::SigningKey;
    use std::path::PathBuf;
    use tempfile::TempDir;

    const SESSION: &str = "test-session";

    fn new_order(id: OrderId, account: AccountId, side: Side, price: f64) -> OrderMessage {
        OrderMessage::New {
            id,
            timestamp: id * 1000,
            account,
            symbol: "ETH-USDC".to_string(),
            side,
            price,
            quantity: 5.0,
            nonce: None,
            order_type: Default::default(),
            time_in_force: Default::default(),
            post_only: false,
        }
    }

    /// The `ListSymbol` message that every history here starts with. Without
    /// this message the symbol is not listed, and the exchange refuses every
    /// order. The database this module builds would then hold no trades.
    fn list_eth(id: OrderId) -> OrderMessage {
        // Signed, because the exchange that runs this history again ignores an
        // operator message it cannot check. See ENGINE.md section 3.1. The
        // audit checks no operator signature itself. It runs again what the
        // exchange ran, and this is what the exchange runs.
        //
        // Signed for `SESSION`, which is the session the run below records and
        // the session its claims are signed over. That is what a real log
        // holds. It also makes every test in this module fail if the audit
        // ever runs a log again without knowing which log it is.
        crate::operator::signed_as(
            &ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]),
            SESSION,
            OrderMessage::ListSymbol {
                id,
                timestamp: id * 1000,
                account: OPERATOR_ACCOUNT,
                symbol: "ETH-USDC".to_string(),
                price_step: 0.01,
                quantity_step: 0.1,
                nonce: Some(format!("{:032x}", id)),
                public_key: String::new(),
                signature: String::new(),
            },
        )
    }

    /// A history of `count` messages. Message 1 lists `ETH-USDC`. Then every
    /// even message puts a sell order in the book to wait, and every odd
    /// message buys against it. So the history holds both waiting orders and
    /// trades. That gives `(count - 1) / 2` trades.
    ///
    /// The listing is a real message, and not a test-only constructor. The
    /// audit runs this history again through `MatcherState::replaying`, which
    /// builds its registry from the log alone. A test fixture that listed the
    /// symbol some other way would hide the exact step the audit must produce
    /// again.
    fn history(count: u64) -> Vec<OrderMessage> {
        std::iter::once(list_eth(1))
            .chain((2..=count).map(|id| {
                if id % 2 == 0 {
                    new_order(id, 1, Side::Sell, 100.0)
                } else {
                    new_order(id, 2, Side::Buy, 100.0)
                }
            }))
            .collect()
    }

    fn feed_chain(messages: &[OrderMessage]) -> Chain {
        messages.iter().fold(logchain::EMPTY_CHAIN, |chain, m| {
            logchain::extend(&chain, m)
        })
    }

    /// A history as the audit receives it. These are the bytes the sequencer
    /// published, split out of one `/messages.ndjson` body the way the real
    /// fetch splits them. Building the messages first and serving them here is
    /// the sequencer's half of the round trip. Everything the audit does
    /// starts from the bytes.
    fn served(messages: &[OrderMessage]) -> Vec<RawMessage> {
        let mut body = Vec::new();
        for msg in messages {
            body.extend_from_slice(&logchain::canonical_bytes(msg));
            body.push(b'\n');
        }
        wire::split_ndjson(&body).expect("the feed serves one message per line")
    }

    /// The head a sequencer that serves `messages` would sign.
    fn signed_head(key: &SigningKey, session: &str, messages: &[OrderMessage]) -> FeedHead {
        let chain = feed_chain(messages);
        let last_id = messages.last().map(|m| m.id()).unwrap_or(0);
        let signature = logchain::sign_head(key, session, last_id, &chain);
        FeedHead {
            session: session.to_string(),
            last_id,
            chain: logchain::to_hex(&chain),
            public_key: logchain::to_hex(key.verifying_key().as_bytes()),
            signature: logchain::to_hex(&signature.to_bytes()),
        }
    }

    /// Writes a real state database for `messages`, through the store the
    /// exchange itself commits with. It writes one signed claim for each
    /// message, the trades the exchange produced, the cursor, and the chain
    /// hash over the history the run read. `claim_key` is the exchange's key,
    /// exactly as `matcher.rs` uses it.
    fn build_db(
        dir: &TempDir,
        messages: &[OrderMessage],
        feed_key: &SigningKey,
        claim_key: &SigningKey,
    ) -> PathBuf {
        let path = dir.path().join("state.db");
        let (mut store, _) = Store::open(&path, "http://feed", 200, false).expect("open store");
        store.set_feed_session(SESSION).expect("session");
        store
            .set_feed_pubkey(&logchain::to_hex(feed_key.verifying_key().as_bytes()))
            .expect("pubkey");
        store
            .set_matcher_pubkey(&logchain::to_hex(claim_key.verifying_key().as_bytes()))
            .expect("claim key");

        // The matching engine the exchange ran. It knows which log it is on,
        // so it can check who signed the listing that starts the history.
        let mut engine = MatcherState::replaying(SESSION);
        let mut root_before = engine.state_root();
        let mut chain = logchain::EMPTY_CHAIN;
        let mut written = 0u64;
        for msg in messages {
            engine.apply_message(msg).expect("apply");
            chain = logchain::extend(&chain, msg);
            let changes: Vec<Change> = engine
                .trades()
                .filter(|t| t.trade_id > written)
                .map(|t| {
                    Change::Traded(TradeRow {
                        trade_id: t.trade_id,
                        timestamp: t.timestamp,
                        symbol: t.symbol.clone(),
                        price_cents: (t.price * 100.0).round() as i64,
                        qty_tenths: (t.quantity * 10.0).round() as i64,
                        maker_order: t.maker_order,
                        maker_account: t.maker_account,
                        taker_order: t.taker_order,
                        taker_account: t.taker_account,
                        taker_side: t.taker_side,
                    })
                })
                .collect();
            written = engine.trades_total();
            let root_after = engine.state_root();
            let signature = logchain::sign_claim(
                claim_key,
                SESSION,
                msg.id(),
                msg.id(),
                &root_before,
                &root_after,
                written,
            );
            let claim = ClaimRow {
                from_msg: msg.id(),
                to_msg: msg.id(),
                root_before,
                root_after,
                trades_total: written,
                signature: Some(signature.to_bytes()),
            };
            let counters = Counters {
                last_seen: msg.id(),
                messages_processed: msg.id(),
                cancels_applied: 0,
                cancels_ignored: 0,
                orders_ignored: 0,
                chain: Some(chain),
                ..Counters::default()
            };
            store
                .commit(&changes, &counters, Some(&claim))
                .expect("commit");
            root_before = root_after;
        }
        drop(store);
        path
    }

    /// A database whose claims are signed by the key that also signs the
    /// sequencer's heads. Most tests do not care which key is which.
    fn build(dir: &TempDir, messages: &[OrderMessage], key: &SigningKey) -> PathBuf {
        build_db(dir, messages, key, key)
    }

    /// Edits the database without telling the audit, the way an operator at a
    /// sqlite3 prompt would.
    fn doctor(path: &Path, sql: &str) {
        let conn = Connection::open(path).expect("open for editing");
        conn.execute_batch(sql).expect("edit");
    }

    /// Runs the real checking code over sources held in memory. It calls the
    /// same `check_run` the real program calls, with the history given out in
    /// pages instead of fetched.
    async fn check_held(
        record: &RunRecord,
        head: &Result<FeedHead, String>,
        wire_session: Option<&str>,
        messages: &[OrderMessage],
    ) -> Outcome {
        check_held_anchored(record, head, wire_session, messages, None).await
    }

    /// The signed tree head an honest sequencer would serve over `received`.
    ///
    /// Built here, and not fetched. These tests give `check_run` a history
    /// they hold, and there is no sequencer to ask. The tree check compares
    /// the root the sequencer signs against the root the messages make. So an
    /// honest sequencer's head is the root of exactly these bytes.
    fn tree_head_over(received: &[RawMessage]) -> Result<TreeHead, String> {
        let entries: Vec<&[u8]> = received.iter().map(|msg| msg.bytes.as_slice()).collect();
        let tree = crate::merkle::MerkleTree::from_entries(&entries);
        Ok(TreeHead {
            session: SESSION.to_string(),
            timestamp: 0,
            tree_size: tree.len(),
            root: tree.root(),
            public_key: String::new(),
        })
    }

    /// `check_held`, with an anchor in hand. This is separate, so every test
    /// that has nothing to do with anchors reads as it did before.
    async fn check_held_anchored(
        record: &RunRecord,
        head: &Result<FeedHead, String>,
        wire_session: Option<&str>,
        messages: &[OrderMessage],
        anchors: Option<&Result<AnchorHistory, String>>,
    ) -> Outcome {
        let received = served(messages);
        check_run(
            &record.facts,
            &HistoryTie::StoredChain(record.chain),
            head,
            wire_session,
            Messages::Held(&received),
            Claims::Held(&record.claims),
            Trades::Held(&record.trades),
            None,
            anchors,
            &tree_head_over(&received),
            None,
        )
        .await
        .expect("the held sources never fail to produce a page")
    }

    /// Reads the run back and checks it against an honest sequencer that
    /// serves `messages`.
    async fn audit_against(path: &Path, key: &SigningKey, messages: &[OrderMessage]) -> Outcome {
        let record = read_db(path, None).expect("read the database");
        let head = Ok(signed_head(key, SESSION, messages));
        check_held(&record, &head, Some(SESSION), messages).await
    }

    #[tokio::test]
    async fn an_untouched_run_passes() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(60);
        let path = build(&dir, &messages, &key);

        let outcome = audit_against(&path, &key, &messages).await;
        assert!(outcome.passed(), "{}", outcome.failure_text());
        // Finding 5: every boundary, and not one boundary in fifty.
        assert_eq!(outcome.boundaries_checked, outcome.boundaries_total);
        assert_eq!(outcome.boundaries_total, 61);
    }

    /// The audit accepts a log whose operator messages were signed for a real
    /// session. The session is an input somebody must give the audit.
    ///
    /// This is the false accusation the audit came closest to making. A check
    /// of an operator message needs the session, because the session is the
    /// second line of the statement the operator signed. The session is not
    /// inside the message. It reaches a reader on the sequencer's
    /// `x-feed-session` header, and the run records it. An audit that ran the
    /// log again without the session would refuse the `ListSymbol` that starts
    /// the history. It would hold no market, refuse every order after that as
    /// an unlisted symbol, and report a disaster against an exchange that did
    /// nothing wrong.
    ///
    /// The second half of the test is what makes the first half mean
    /// something. The same messages, run again under the wrong session, open
    /// nothing at all. That is the state the audit would have been in.
    #[tokio::test]
    async fn a_log_opened_under_a_real_session_audits_clean() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(20);
        assert!(
            matches!(messages[0], OrderMessage::ListSymbol { .. }),
            "this history opens with a listing signed for {}",
            SESSION
        );
        let path = build(&dir, &messages, &key);

        let outcome = audit_against(&path, &key, &messages).await;
        assert!(outcome.passed(), "{}", outcome.failure_text());

        // The matching engine the audit builds, built both ways, over the same
        // messages.
        let replay_as = |session: &str| {
            let mut engine = MatcherState::replaying(session);
            for msg in &messages {
                engine.apply_message(msg).expect("in feed order");
            }
            engine
        };
        assert_eq!(
            replay_as(SESSION).listed_symbols(),
            vec!["ETH-USDC".to_string()],
            "the log names its market and the replay has to hold it"
        );
        assert!(
            replay_as("").listed_symbols().is_empty(),
            "a replay that does not know which log it is on must not still open the market; \
             this assertion is what pins the session as an input"
        );
        assert!(
            replay_as("some-other-log").listed_symbols().is_empty(),
            "a statement signed for one log does not verify in another"
        );
    }

    /// The audit runs the sequencer's history again and computes its chain
    /// hash again. So it serializes every published field again, including the
    /// submitter's nonce, which no arithmetic in this file reads. A build that
    /// dropped the nonce would compute a chain hash the sequencer never
    /// signed. It would then fail the audit of an honest run. That is a false
    /// accusation from the tool that exists to make accusations checkable.
    #[tokio::test]
    async fn a_run_over_a_nonce_bearing_history_passes() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let mut messages = history(20);
        // Every third message came in through a signed submission.
        for (index, msg) in messages.iter_mut().enumerate() {
            if index % 3 != 0 {
                continue;
            }
            if let OrderMessage::New { nonce, .. } = msg {
                *nonce = Some(logchain::to_hex(&[index as u8; 16]));
            }
        }
        let path = build(&dir, &messages, &key);

        // Served and parsed the way a page really arrives.
        let served = serde_json::to_vec(&messages).expect("the feed serializes");
        let received: Vec<OrderMessage> = serde_json::from_slice(&served).expect("parsed");
        assert!(
            received
                .iter()
                .any(|m| matches!(m, OrderMessage::New { nonce: Some(_), .. })),
            "the history under audit really does carry nonces"
        );

        let outcome = audit_against(&path, &key, &received).await;
        assert!(outcome.passed(), "{}", outcome.failure_text());
        assert_eq!(outcome.boundaries_checked, outcome.boundaries_total);
    }

    /// Finding 5: with 60 claims, the old step size checked one boundary in
    /// fifty. A root edited in the middle then passed unseen.
    #[tokio::test]
    async fn a_doctored_root_between_sampled_boundaries_is_caught() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(60);
        let path = build(&dir, &messages, &key);
        // Claim 37's root_after and claim 38's root_before, both set to the
        // same invented value. The continuity check between them still passes.
        doctor(
            &path,
            "UPDATE claims SET root_after  = zeroblob(32) WHERE to_msg = 37;
             UPDATE claims SET root_before = zeroblob(32) WHERE from_msg = 38;",
        );

        let outcome = audit_against(&path, &key, &messages).await;
        assert!(!outcome.passed());
        assert!(
            outcome.failure_text().contains("after message 37"),
            "{}",
            outcome.failure_text()
        );
    }

    /// Finding 2: an emptied claims table must not read as "audited".
    #[tokio::test]
    async fn an_emptied_claims_table_fails_instead_of_passing() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(10);
        let path = build(&dir, &messages, &key);
        doctor(&path, "DELETE FROM claims;");

        let outcome = audit_against(&path, &key, &messages).await;
        assert!(!outcome.passed());
        let text = outcome.failure_text();
        assert!(text.contains("holds no claims at all"), "{}", text);
        assert!(
            text.contains("committed feed messages up to 10"),
            "{}",
            text
        );
    }

    /// Finding 2: claims that stop short of the cursor leave real execution
    /// unaudited. That is not a pass either.
    #[tokio::test]
    async fn claims_that_stop_short_of_the_cursor_fail() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(10);
        let path = build(&dir, &messages, &key);
        doctor(&path, "DELETE FROM claims WHERE to_msg > 6;");

        let outcome = audit_against(&path, &key, &messages).await;
        assert!(!outcome.passed());
        assert!(
            outcome
                .failure_text()
                .contains("claims stop at message 6 but the run committed up to message 10"),
            "{}",
            outcome.failure_text()
        );
    }

    /// Finding 4: the audit read `taker_side` out of the database and then
    /// compared it with nothing.
    #[tokio::test]
    async fn a_doctored_taker_side_is_caught() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(10);
        let path = build(&dir, &messages, &key);
        doctor(&path, "UPDATE trades SET taker_side = 'Sell';");

        let outcome = audit_against(&path, &key, &messages).await;
        assert!(!outcome.passed());
        assert!(
            outcome.failure_text().contains("taker side Sell recorded"),
            "{}",
            outcome.failure_text()
        );
    }

    /// Finding 4: the audit parsed `trades_total` and never checked it.
    #[tokio::test]
    async fn a_doctored_trades_total_is_caught() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(10);
        let path = build(&dir, &messages, &key);
        doctor(&path, "UPDATE claims SET trades_total = 0;");

        let outcome = audit_against(&path, &key, &messages).await;
        assert!(!outcome.passed());
        assert!(
            outcome
                .failure_text()
                .contains("trades had executed by then"),
            "{}",
            outcome.failure_text()
        );
    }

    /// Finding 6: `to_msg = -1` used to be cast to a huge unsigned id. The
    /// `+ 1` on that id then panicked in a debug build, which is the build the
    /// README tells people to use.
    #[tokio::test]
    async fn an_out_of_range_claim_fails_cleanly_instead_of_panicking() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(4);
        let path = build(&dir, &messages, &key);
        doctor(&path, "UPDATE claims SET to_msg = -1 WHERE from_msg = 2;");

        let error = read_db(&path, None).expect_err("a negative id must not be accepted");
        assert!(error.contains("not a feed id"), "{}", error);
    }

    /// Finding 6, the other half: a trade id that cannot be a trade id.
    #[tokio::test]
    async fn an_out_of_range_trade_fails_cleanly() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(4);
        let path = build(&dir, &messages, &key);
        doctor(&path, "UPDATE trades SET maker_account = -3;");

        let error = read_db(&path, None).expect_err("a negative account must not be accepted");
        assert!(error.contains("not a feed id"), "{}", error);
    }

    /// Finding 3: a history the sequencer did not sign must not pass the
    /// audit.
    #[tokio::test]
    async fn a_head_signed_by_another_key_fails() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(6);
        let path = build(&dir, &messages, &key);

        let stranger = logchain::ephemeral_key();
        let record = read_db(&path, None).expect("read");
        let head = Ok(signed_head(&stranger, SESSION, &messages));
        let outcome = check_held(&record, &head, Some(SESSION), &messages).await;

        assert!(!outcome.passed());
        assert!(
            outcome
                .failure_text()
                .contains("consumed a history signed by"),
            "{}",
            outcome.failure_text()
        );
    }

    /// Finding 3: an edited history that the sequencer signed again still
    /// fails. The run's own chain hash names the bytes the run read.
    #[tokio::test]
    async fn an_edited_history_the_feed_resigned_still_fails() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(6);
        let path = build(&dir, &messages, &key);

        // The operator edits feed.db. The sequencer repairs its chain links on
        // load, and it signs the edited history with its own key from then on.
        let mut edited = messages.clone();
        edited[2] = new_order(3, 1, Side::Sell, 101.0);
        let record = read_db(&path, None).expect("read");
        let head = Ok(signed_head(&key, SESSION, &edited));
        let outcome = check_held(&record, &head, Some(SESSION), &edited).await;

        assert!(!outcome.passed());
        assert!(
            outcome
                .failure_text()
                .contains("consumed a history hashing to"),
            "{}",
            outcome.failure_text()
        );
    }

    /// Finding 3: a NULL session is "cannot check", not "skip the check".
    #[tokio::test]
    async fn a_null_session_fails_instead_of_skipping_the_check() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(6);
        let path = build(&dir, &messages, &key);
        doctor(&path, "UPDATE runs SET feed_session = NULL;");

        let outcome = audit_against(&path, &key, &messages).await;
        assert!(!outcome.passed());
        assert!(
            outcome.failure_text().contains("recorded no feed session"),
            "{}",
            outcome.failure_text()
        );
    }

    /// A sequencer that will not serve a head is not a pass either.
    #[tokio::test]
    async fn a_missing_head_fails() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(4);
        let path = build(&dir, &messages, &key);

        let record = read_db(&path, None).expect("read");
        let outcome = check_held(
            &record,
            &Err("connection refused".to_string()),
            Some(SESSION),
            &messages,
        )
        .await;
        assert!(!outcome.passed());
        assert!(
            outcome.failure_text().contains("connection refused"),
            "{}",
            outcome.failure_text()
        );
    }

    /// An invented fill is what the trades check exists for.
    #[tokio::test]
    async fn an_invented_fill_is_caught() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(10);
        let path = build(&dir, &messages, &key);
        doctor(
            &path,
            "UPDATE trades SET price_cents = 9900 WHERE trade_id = 2;",
        );

        let outcome = audit_against(&path, &key, &messages).await;
        assert!(!outcome.passed());
        assert!(
            outcome.failure_text().contains("price 9900 cents recorded"),
            "{}",
            outcome.failure_text()
        );
    }

    /// A trade whose time was edited is a trade the messages do not produce.
    #[tokio::test]
    async fn a_doctored_trade_timestamp_is_caught() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(10);
        let path = build(&dir, &messages, &key);
        doctor(&path, "UPDATE trades SET timestamp = 1 WHERE trade_id = 3;");

        let outcome = audit_against(&path, &key, &messages).await;
        assert!(!outcome.passed());
        assert!(
            outcome.failure_text().contains("timestamp 1 recorded"),
            "{}",
            outcome.failure_text()
        );
    }

    /// The audit takes a run named by id, instead of the newest run. The
    /// newest run is not the only run in the file that an audit can read.
    #[tokio::test]
    async fn an_older_run_can_be_audited_by_id() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(6);
        let path = build(&dir, &messages, &key);
        // A second run in the same file, the way a sequencer restart leaves
        // one.
        doctor(
            &path,
            "UPDATE runs SET status = 'feed_restarted';
             INSERT INTO runs (started_at, heartbeat_ms, status, feed_url, owner_pid,
                               feed_session, feed_pubkey)
               VALUES (0, 0, 'open', 'http://feed', 0, NULL, NULL);
             INSERT INTO resume_point (run_id, last_seen, messages_processed, cancels_applied,
                                       cancels_ignored, orders_ignored, chain_hash)
               VALUES ((SELECT MAX(run_id) FROM runs), 0, 0, 0, 0, 0, zeroblob(32));",
        );

        let newest = read_db(&path, None).expect("read newest");
        assert_eq!(newest.facts.run_id, 2);
        assert!(newest.claims.is_empty());
        assert_eq!(newest.runs.len(), 2);

        let record = read_db(&path, Some(1)).expect("read run 1");
        assert_eq!(record.facts.run_id, 1);
        let head = Ok(signed_head(&key, SESSION, &messages));
        let outcome = check_held(&record, &head, Some(SESSION), &messages).await;
        assert!(outcome.passed(), "{}", outcome.failure_text());

        let error = read_db(&path, Some(99)).expect_err("run 99 does not exist");
        assert!(error.contains("has no run 99"), "{}", error);
    }

    // -----------------------------------------------------------------
    // The signature on a claim
    // -----------------------------------------------------------------

    /// The property that the whole of piece one exists for. A claim carries
    /// the exchange's signature, and that signature verifies.
    #[tokio::test]
    async fn every_committed_claim_is_signed_and_verifies() {
        let dir = TempDir::new().unwrap();
        let feed_key = logchain::ephemeral_key();
        let claim_key = logchain::ephemeral_key();
        let messages = history(8);
        let path = build_db(&dir, &messages, &feed_key, &claim_key);

        let record = read_db(&path, None).expect("read");
        assert_eq!(record.claims.len(), 8);
        let public = claim_key.verifying_key();
        for claim in &record.claims {
            let signature = claim.signature.expect("every claim carries a signature");
            assert!(
                logchain::verify_claim(
                    &public,
                    SESSION,
                    claim.from_msg,
                    claim.to_msg,
                    &claim.root_before,
                    &claim.root_after,
                    claim.trades_total,
                    &Signature::from_bytes(&signature),
                ),
                "claim {}..{} does not verify",
                claim.from_msg,
                claim.to_msg
            );
        }

        let head = Ok(signed_head(&feed_key, SESSION, &messages));
        let outcome = check_held(&record, &head, Some(SESSION), &messages).await;
        assert!(outcome.passed(), "{}", outcome.failure_text());
    }

    /// The store refuses a claim nobody signed, so the file can never hold an
    /// unsigned claim. This rule means an unsigned claim never gets written.
    /// Nobody has to notice such a row later.
    #[test]
    fn the_store_refuses_to_write_an_unsigned_claim() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.db");
        let (mut store, _) = Store::open(&path, "http://feed", 200, false).expect("open");
        let unsigned = ClaimRow {
            from_msg: 1,
            to_msg: 1,
            root_before: [0u8; 32],
            root_after: [1u8; 32],
            trades_total: 0,
            signature: None,
        };
        let counters = Counters {
            last_seen: 1,
            messages_processed: 1,
            ..Counters::default()
        };
        let error = store
            .commit(&[], &counters, Some(&unsigned))
            .expect_err("an unsigned claim must be refused");
        assert!(
            error.to_string().contains("carries no signature"),
            "{}",
            error
        );
    }

    /// An edited root does not fail only the re-execution. It fails the
    /// signature too, and that failure names the exchange and not the audit.
    /// Nobody can make an edited claim in the file look honest without the
    /// key.
    #[tokio::test]
    async fn a_doctored_claim_fails_its_own_signature() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(10);
        let path = build(&dir, &messages, &key);
        doctor(
            &path,
            "UPDATE claims SET root_after = zeroblob(32) WHERE to_msg = 5;",
        );

        let outcome = audit_against(&path, &key, &messages).await;
        assert!(!outcome.passed());
        let text = outcome.failure_text();
        assert!(
            text.contains("does not verify under the key this run signs with"),
            "{}",
            text
        );
        assert!(text.contains("after message 5"), "{}", text);
    }

    /// A signature taken from another claim is a signature over a different
    /// statement. The check says so.
    #[tokio::test]
    async fn a_swapped_claim_signature_is_rejected() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(10);
        let path = build(&dir, &messages, &key);
        doctor(
            &path,
            "UPDATE claims
               SET signature = (SELECT signature FROM claims WHERE from_msg = 7)
             WHERE from_msg = 4;",
        );

        let outcome = audit_against(&path, &key, &messages).await;
        assert!(!outcome.passed());
        assert!(
            outcome
                .failure_text()
                .contains("does not verify under the key this run signs with"),
            "{}",
            outcome.failure_text()
        );
    }

    /// To remove the signature is not a way past the check. The audit names an
    /// unsigned claim as unsigned.
    #[tokio::test]
    async fn a_claim_stripped_of_its_signature_is_rejected() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(6);
        let path = build(&dir, &messages, &key);
        doctor(
            &path,
            "UPDATE claims SET signature = NULL WHERE from_msg = 3;",
        );

        let outcome = audit_against(&path, &key, &messages).await;
        assert!(!outcome.passed());
        assert!(
            outcome.failure_text().contains("carries no signature"),
            "{}",
            outcome.failure_text()
        );
    }

    /// Claims signed by somebody else's key are not this run's claims.
    #[tokio::test]
    async fn claims_signed_by_another_key_are_rejected() {
        let dir = TempDir::new().unwrap();
        let feed_key = logchain::ephemeral_key();
        let claim_key = logchain::ephemeral_key();
        let messages = history(6);
        let path = build_db(&dir, &messages, &feed_key, &claim_key);
        // The run now names a key that signed nothing in the run.
        let stranger = logchain::ephemeral_key();
        doctor(
            &path,
            &format!(
                "UPDATE runs SET matcher_pubkey = '{}';",
                logchain::to_hex(stranger.verifying_key().as_bytes())
            ),
        );

        let record = read_db(&path, None).expect("read");
        let head = Ok(signed_head(&feed_key, SESSION, &messages));
        let outcome = check_held(&record, &head, Some(SESSION), &messages).await;
        assert!(!outcome.passed());
        assert!(
            outcome
                .failure_text()
                .contains("does not verify under the key this run signs with"),
            "{}",
            outcome.failure_text()
        );
    }

    /// A claim's signature covers the session. So claims taken from one
    /// history do not verify under another history.
    #[tokio::test]
    async fn claims_from_another_session_do_not_verify() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(6);
        let path = build(&dir, &messages, &key);
        doctor(
            &path,
            "UPDATE runs SET feed_session = 'a-different-history';",
        );

        let record = read_db(&path, None).expect("read");
        let head = Ok(signed_head(&key, "a-different-history", &messages));
        let outcome = check_held(&record, &head, Some("a-different-history"), &messages).await;
        assert!(!outcome.passed());
        assert!(
            outcome
                .failure_text()
                .contains("does not verify under the key this run signs with"),
            "{}",
            outcome.failure_text()
        );
    }

    // -----------------------------------------------------------------
    // The streaming sources
    // -----------------------------------------------------------------

    /// The audit reads its history in pages of a bounded size, and a history
    /// longer than one page still passes. Without this test, the only history
    /// that runs the paging loop would fit in one page. That is what every
    /// other test in this file uses.
    #[tokio::test]
    async fn a_history_longer_than_one_page_audits_across_pages() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let long = crate::feed::PAGE_LIMIT as u64 + 250;
        let messages = history(long);
        let path = build(&dir, &messages, &key);

        // The source does give more than one page.
        let received = served(&messages);
        let source = Messages::Held(&received);
        let first = source.page(0).await.expect("a page");
        assert_eq!(first.messages.len(), crate::feed::PAGE_LIMIT);
        let second = source
            .page(first.messages.last().unwrap().id)
            .await
            .expect("a page");
        assert_eq!(second.messages.len(), 250);

        let outcome = audit_against(&path, &key, &messages).await;
        assert!(outcome.passed(), "{}", outcome.failure_text());
        assert_eq!(outcome.messages_replayed, long as usize);
        assert_eq!(outcome.boundaries_checked, outcome.boundaries_total);
    }

    /// A sequencer newer than this audit. Message 3 is a kind that no struct
    /// in this binary can produce, so the only form of it that exists is its
    /// bytes.
    ///
    /// This is the case `--audit-url` meets most often in real use: a stranger
    /// audits an exchange that somebody upgraded. The two answers the audit
    /// must keep apart are both in this one run. The sequencer's signed chain
    /// is a hash over the bytes it served, so the audit checks it and it
    /// holds. The re-execution must read the messages, so it stops at message
    /// 3. The verdict says which of those two happened, and it exits 3 and not
    /// 1.
    #[tokio::test]
    async fn an_audit_of_a_history_this_build_cannot_execute_is_incomplete_not_failed() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(4);
        let path = build(&dir, &messages, &key);
        let record = read_db(&path, None).expect("read the database");

        // What the sequencer publishes: the same history, with message 3
        // replaced by a kind added after somebody compiled this binary.
        let mut body = Vec::new();
        for (index, msg) in messages.iter().enumerate() {
            if index == 2 {
                body.extend_from_slice(
                    br#"{"Market":{"id":3,"timestamp":3000,"account":1,"symbol":"ETH-USDC","side":"Sell","quantity":5.0}}"#,
                );
            } else {
                body.extend_from_slice(&logchain::canonical_bytes(msg));
            }
            body.push(b'\n');
        }
        let received = wire::split_ndjson(&body).expect("one message per line");
        assert!(
            received[2].parse::<OrderMessage>().is_err(),
            "message 3 must be unreadable"
        );

        // The sequencer is honest. It signs the chain over exactly those
        // bytes.
        let chain = received.iter().fold(logchain::EMPTY_CHAIN, |chain, msg| {
            logchain::extend_bytes(&chain, &msg.bytes)
        });
        let head = Ok(FeedHead {
            session: SESSION.to_string(),
            last_id: 4,
            chain: logchain::to_hex(&chain),
            public_key: logchain::to_hex(key.verifying_key().as_bytes()),
            signature: logchain::to_hex(&logchain::sign_head(&key, SESSION, 4, &chain).to_bytes()),
        });

        let outcome = check_run(
            &record.facts,
            &HistoryTie::SignedClaims,
            &head,
            Some(SESSION),
            Messages::Held(&received),
            Claims::Held(&record.claims),
            Trades::Held(&record.trades),
            Some(record.facts.cursor),
            None,
            &tree_head_over(&received),
            None,
        )
        .await
        .expect("held sources");

        let too_old = outcome
            .too_old
            .clone()
            .expect("message 3 stopped the replay");
        assert_eq!(too_old.id, 3);
        assert_eq!(too_old.kind, "Market");
        assert_eq!(
            outcome.messages_replayed, 2,
            "everything before the unreadable message is still re-executed"
        );
        assert!(
            outcome.passed(),
            "no check may fail over an honest feed this build cannot fully read: {}",
            outcome.failure_text()
        );
        // The audit hashed the chain all the way to the signed head, past the
        // message where the re-execution stopped.
        let chain_check = outcome
            .checks
            .iter()
            .find(|c| c.name == "the feed's signed chain matches its history")
            .expect("the head check ran");
        assert_eq!(chain_check.checked, 4);
        assert!(
            chain_check.failures.is_empty(),
            "{:?}",
            chain_check.failures
        );

        let verdict = report(&outcome, record.claims.len(), record.facts.run_id);
        assert_eq!(verdict, Verdict::TooOld(too_old));
        assert_eq!(verdict.exit_code(), 3);
        assert!(!verdict.passed());
    }

    /// The same history, with one byte of that unreadable message changed. The
    /// chain check is a hash over bytes, so the check finds the change. The
    /// stronger answer wins: exit 1, and not exit 3.
    #[tokio::test]
    async fn tampering_with_an_unreadable_message_still_fails_loudly() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(4);
        let path = build(&dir, &messages, &key);
        let record = read_db(&path, None).expect("read the database");

        let market =
            br#"{"Market":{"id":3,"timestamp":3000,"account":1,"symbol":"ETH-USDC","side":"Sell","quantity":5.0}}"#;
        let edited =
            br#"{"Market":{"id":3,"timestamp":3000,"account":2,"symbol":"ETH-USDC","side":"Sell","quantity":5.0}}"#;
        let page = |third: &[u8]| {
            let mut body = Vec::new();
            for (index, msg) in messages.iter().enumerate() {
                if index == 2 {
                    body.extend_from_slice(third);
                } else {
                    body.extend_from_slice(&logchain::canonical_bytes(msg));
                }
                body.push(b'\n');
            }
            wire::split_ndjson(&body).expect("one message per line")
        };

        // Signed over the honest history, and served with the edited history.
        let signed = page(market)
            .iter()
            .fold(logchain::EMPTY_CHAIN, |chain, msg| {
                logchain::extend_bytes(&chain, &msg.bytes)
            });
        let head = Ok(FeedHead {
            session: SESSION.to_string(),
            last_id: 4,
            chain: logchain::to_hex(&signed),
            public_key: logchain::to_hex(key.verifying_key().as_bytes()),
            signature: logchain::to_hex(&logchain::sign_head(&key, SESSION, 4, &signed).to_bytes()),
        });
        let received = page(edited);

        let outcome = check_run(
            &record.facts,
            &HistoryTie::SignedClaims,
            &head,
            Some(SESSION),
            Messages::Held(&received),
            Claims::Held(&record.claims),
            Trades::Held(&record.trades),
            Some(record.facts.cursor),
            None,
            &tree_head_over(&received),
            None,
        )
        .await
        .expect("held sources");

        assert!(outcome.too_old.is_some(), "message 3 is still unreadable");
        assert!(
            !outcome.passed(),
            "a rewritten message this build cannot read is still a rewritten message"
        );
        assert!(
            outcome.failure_text().contains("recomputed chain"),
            "{}",
            outcome.failure_text()
        );
        let verdict = report(&outcome, record.claims.len(), record.facts.run_id);
        assert_eq!(verdict, Verdict::Failed);
        assert_eq!(verdict.exit_code(), 1);
    }

    /// A run with more fills than the re-execution can hold in memory still
    /// gets every fill compared.
    ///
    /// The audit's matching engine keeps a window of the newest trades
    /// (`matcher::TRADE_WINDOW`), and not every trade of the run. So the audit
    /// must compare each trade while that trade is still inside the window.
    /// This test says so: 10,250 fills, a window of 10,000, and the trades
    /// check must come out with every row checked and no row skipped.
    #[tokio::test]
    async fn a_run_with_more_trades_than_the_window_compares_all_of_them() {
        let key = logchain::ephemeral_key();
        let trades_wanted = crate::matcher::TRADE_WINDOW as u64 + 250;
        // One listing message, then two orders for each fill.
        let messages = history(trades_wanted * 2 + 1);

        // The record the exchange would have written: one claim over the whole
        // history, and one row for each fill, taken as the matching engine
        // produces them.
        let mut engine = MatcherState::replaying(SESSION);
        let root_before = engine.state_root();
        let mut recorded: Vec<DbTrade> = Vec::new();
        for msg in &messages {
            engine.apply_message(msg).expect("in feed order");
            let seen = recorded.len() as u64;
            let fresh: Vec<DbTrade> = engine
                .trades()
                .filter(|t| t.trade_id > seen)
                .map(|trade| DbTrade {
                    trade_id: trade.trade_id,
                    timestamp: trade.timestamp,
                    symbol: trade.symbol.clone(),
                    price_cents: (trade.price * 100.0).round() as i64,
                    qty_tenths: (trade.quantity * 10.0).round() as i64,
                    maker_order: trade.maker_order,
                    maker_account: trade.maker_account as u64,
                    taker_order: trade.taker_order,
                    taker_account: trade.taker_account as u64,
                    taker_side: format!("{:?}", trade.taker_side),
                })
                .collect();
            recorded.extend(fresh);
        }
        assert_eq!(recorded.len() as u64, trades_wanted);
        assert_eq!(engine.trades_total(), trades_wanted);

        let last = messages.last().expect("a history").id();
        let claim = ClaimRow {
            from_msg: 1,
            to_msg: last,
            root_before,
            root_after: engine.state_root(),
            trades_total: trades_wanted,
            signature: Some(
                logchain::sign_claim(
                    &key,
                    SESSION,
                    1,
                    last,
                    &root_before,
                    &engine.state_root(),
                    trades_wanted,
                )
                .to_bytes(),
            ),
        };
        let record = RunRecord {
            facts: RunFacts {
                run_id: 1,
                session: Some(SESSION.to_string()),
                feed_pubkey: Some(logchain::to_hex(key.verifying_key().as_bytes())),
                matcher_pubkey: Some(logchain::to_hex(key.verifying_key().as_bytes())),
                cursor: last,
            },
            chain: Some(feed_chain(&messages)),
            claims: vec![claim],
            trades: recorded,
            runs: Vec::new(),
        };

        let head = Ok(signed_head(&key, SESSION, &messages));
        let outcome = check_held(&record, &head, Some(SESSION), &messages).await;
        assert!(outcome.passed(), "{}", outcome.failure_text());
        let trades = outcome
            .checks
            .iter()
            .find(|c| c.name.contains("recorded trades"))
            .expect("the trades check ran");
        assert_eq!(
            trades.checked, trades_wanted as usize,
            "every recorded fill was compared, not only the ones still in the window"
        );
    }

    /// A page source gives back exactly the rows after the cursor. That is
    /// what lets `?since=` carry on from one page to the next.
    #[tokio::test]
    async fn the_claim_and_trade_sources_page_from_a_cursor() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(10);
        let path = build(&dir, &messages, &key);
        let record = read_db(&path, None).expect("read");

        let claims = Claims::Held(&record.claims);
        let page = claims.page(4).await.expect("a page");
        assert_eq!(page.first().map(|c| c.from_msg), Some(5));
        assert_eq!(page.len(), 6);
        assert!(claims.page(10).await.expect("a page").is_empty());

        let trades = Trades::Held(&record.trades);
        let all = trades.page(0).await.expect("a page");
        assert!(!all.is_empty());
        let rest = trades.page(all[0].trade_id).await.expect("a page");
        assert_eq!(rest.len(), all.len() - 1);
    }

    /// Both ways in must reach the same verdict on the same run. Otherwise
    /// "audited remotely" would mean something weaker than "audited". This
    /// drives `check_run` twice over one database: once the way `--audit`
    /// does, and once with the claims and trades parsed from exactly the JSON
    /// the `/claims` and `/trade-log` endpoints serve.
    async fn remote_shaped_outcome(
        record: &RunRecord,
        head: &Result<FeedHead, String>,
        messages: &[OrderMessage],
    ) -> Outcome {
        // The claims, sent through the wire form and read back.
        let wire: Vec<WireClaim> = record
            .claims
            .iter()
            .map(|c| WireClaim {
                from_msg: c.from_msg,
                to_msg: c.to_msg,
                root_before: logchain::to_hex(&c.root_before),
                root_after: logchain::to_hex(&c.root_after),
                trades_total: c.trades_total,
                signature: c.signature.map(|s| logchain::to_hex(&s)),
            })
            .collect();
        let parsed: Vec<ClaimRow> = wire
            .into_iter()
            .map(|c| c.parse().expect("the wire form round-trips"))
            .collect();
        let received = served(messages);
        check_run(
            &record.facts,
            // What a remote audit has: no private chain hash, and only the
            // signed claims.
            &HistoryTie::SignedClaims,
            head,
            Some(SESSION),
            Messages::Held(&received),
            Claims::Held(&parsed),
            Trades::Held(&record.trades),
            // A remote audit fixes its view at the cursor the exchange
            // reported, the way `audit_url` does.
            Some(record.facts.cursor),
            None,
            &tree_head_over(&received),
            None,
        )
        .await
        .expect("held sources")
    }

    #[tokio::test]
    async fn the_remote_shaped_audit_agrees_with_the_local_one() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(20);
        let path = build(&dir, &messages, &key);
        let head = Ok(signed_head(&key, SESSION, &messages));

        let record = read_db(&path, None).expect("read");
        assert!(
            check_held(&record, &head, Some(SESSION), &messages)
                .await
                .passed()
        );
        assert!(
            remote_shaped_outcome(&record, &head, &messages)
                .await
                .passed()
        );

        // The remote shape catches every kind of edit the local way in
        // catches. The checks are the same objects.
        for (sql, expected) in [
            (
                "UPDATE trades SET price_cents = 9900 WHERE trade_id = 2;",
                "price 9900 cents recorded",
            ),
            (
                "UPDATE claims SET root_after = zeroblob(32) WHERE to_msg = 9;",
                "after message 9",
            ),
            (
                "UPDATE claims SET trades_total = 0 WHERE from_msg = 8;",
                "trades had executed by then",
            ),
            (
                "DELETE FROM claims WHERE to_msg > 12;",
                "claims stop at message 12",
            ),
            (
                "UPDATE claims SET signature = NULL WHERE from_msg = 3;",
                "carries no signature",
            ),
        ] {
            let dir = TempDir::new().unwrap();
            let path = build(&dir, &messages, &key);
            doctor(&path, sql);
            let record = read_db(&path, None).expect("read");
            let outcome = remote_shaped_outcome(&record, &head, &messages).await;
            assert!(!outcome.passed(), "{} was not caught remotely", sql);
            assert!(
                outcome.failure_text().contains(expected),
                "{} produced {}",
                sql,
                outcome.failure_text()
            );
        }
    }

    /// The exchange under audit is live. It keeps committing while the audit
    /// reads it. So the trade log answers with rows that the claims fetched a
    /// moment earlier do not cover, and the sequencer serves messages past the
    /// cursor. None of that is an edit. A remote audit that reported it as an
    /// edit would report fraud against every healthy exchange it read. This
    /// test is the shape of that race, and of both live bugs it caused.
    #[tokio::test]
    async fn an_exchange_that_keeps_trading_during_the_audit_still_passes() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        // A history long enough that the claims are more than one page. That
        // is what made the second bug reachable at all: a claim queue that
        // empties in the middle of a page of messages.
        let messages = history(crate::feed::PAGE_LIMIT as u64 + 400);
        let path = build(&dir, &messages, &key);
        let record = read_db(&path, None).expect("read");

        // The audit's view: the run as it stood at message 900. Everything
        // after that is the exchange carrying on while the audit runs.
        let horizon: OrderId = 900;
        let claims: Vec<ClaimRow> = record
            .claims
            .iter()
            .filter(|c| c.to_msg <= horizon + 200)
            .cloned()
            .collect();
        let facts = RunFacts {
            run_id: record.facts.run_id,
            session: record.facts.session.clone(),
            feed_pubkey: record.facts.feed_pubkey.clone(),
            matcher_pubkey: record.facts.matcher_pubkey.clone(),
            cursor: horizon,
        };
        // The sequencer and the trade log both answer with everything they
        // have, which reaches well past the audit's view.
        let head = Ok(signed_head(&key, SESSION, &messages));
        let received = served(&messages);
        let outcome = check_run(
            &facts,
            &HistoryTie::SignedClaims,
            &head,
            Some(SESSION),
            Messages::Held(&received),
            Claims::Held(&claims),
            Trades::Held(&record.trades),
            Some(horizon),
            None,
            &tree_head_over(&received),
            None,
        )
        .await
        .expect("held sources");

        assert!(
            outcome.passed(),
            "a live exchange that kept trading was reported as dishonest: {}",
            outcome.failure_text()
        );
        assert_eq!(
            outcome.boundaries_checked, outcome.boundaries_total,
            "every boundary inside the view must be reached, not skipped when the \
             claim queue empties in the middle of a page of messages"
        );
    }

    /// A remote audit has no chain hash to compare against. So the roots must
    /// catch a sequencer that serves a history the run never read. They do.
    /// The exchange's signature covers roots that only the real history
    /// produces.
    #[tokio::test]
    async fn a_remote_audit_catches_a_rewritten_history_through_the_roots() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(10);
        let path = build(&dir, &messages, &key);
        let record = read_db(&path, None).expect("read");

        // The operator rewrites one old order's price and signs the whole
        // history again. The chain check that a local audit makes is not
        // available here. The signatures on the claims still verify, because
        // they are the exchange's real signatures over its real roots.
        let mut edited = messages.clone();
        edited[2] = new_order(3, 1, Side::Sell, 101.0);
        let head = Ok(signed_head(&key, SESSION, &edited));
        let outcome = remote_shaped_outcome(&record, &head, &edited).await;

        assert!(!outcome.passed());
        let text = outcome.failure_text();
        assert!(
            text.contains("the state hashes to") || text.contains("state before message"),
            "the rewritten history has to fail a root: {}",
            text
        );
    }

    /// `--feed-url` is the reader's own route, so the audit takes it as given
    /// and does not ask the exchange. Nothing answers on port 1. So this test
    /// fails the moment the flag stops skipping the request.
    #[tokio::test]
    async fn an_explicit_feed_url_needs_nothing_from_the_exchange() {
        let client = fetch::client().expect("a client");
        let resolved = resolve_feed_url(
            &client,
            "http://127.0.0.1:1",
            Some("http://feed.example.com:3000/"),
        )
        .await
        .expect("an explicit --feed-url is used as given");
        assert_eq!(resolved, "http://feed.example.com:3000");
    }

    /// With no flag, the sequencer's address is the address the exchange
    /// publishes for a browser. That is the public address, and not the
    /// loopback address its own programs use between themselves.
    #[test]
    fn the_feed_address_comes_from_what_the_exchange_advertises() {
        let resolved = feed_url_from_config(
            "http://exchange.example.com:3001",
            Ok(Some("http://exchange.example.com:3000/".to_string())),
        )
        .expect("an advertised address is used");
        assert_eq!(resolved, "http://exchange.example.com:3000");
    }

    /// An exchange that names no sequencer ends the audit with a message that
    /// names the flag which supplies one. The audit must never fall back to a
    /// default. This command used to use `http://127.0.0.1:3000` for a remote
    /// exchange. It then reported a loopback address the reader never typed,
    /// which reads as a broken exchange and not as a missing flag.
    #[test]
    fn an_exchange_that_advertises_no_feed_says_so_and_names_the_flag() {
        for advertised in [
            Ok(None),
            Ok(Some("   ".to_string())),
            Err("http://exchange.example.com:3001/config answered 404 Not Found".to_string()),
        ] {
            let reason = feed_url_from_config("http://exchange.example.com:3001", advertised)
                .expect_err("with no address there is nothing to re-execute");
            assert!(
                reason.contains("--feed-url"),
                "the message has to name the flag that fixes it: {}",
                reason
            );
            assert!(
                !reason.contains("127.0.0.1"),
                "the message must not point at an address the auditor never typed: {}",
                reason
            );
        }
    }

    // -----------------------------------------------------------------------
    // The on-chain anchor
    // -----------------------------------------------------------------------

    /// The anchor an honest anchor sender would have written at message `at`
    /// of this history. It holds the chain hash over the messages, and the
    /// state root the matching engine had after it applied them. This function
    /// computes both the long way. So a test that passes says the audit agrees
    /// with the definition, and not with itself.
    fn anchor_over(messages: &[OrderMessage], at: OrderId, session: &str, index: u64) -> Anchor {
        let mut chain = logchain::EMPTY_CHAIN;
        let mut engine = MatcherState::replaying(session);
        for msg in messages.iter().take_while(|m| m.id() <= at) {
            chain = logchain::extend(&chain, msg);
            engine.apply_message(msg).expect("apply");
        }
        Anchor {
            last_id: at,
            session: session.to_string(),
            chain,
            state_root: engine.state_root(),
            anchored_at: 1_786_758_564,
            block_number: 45_495_000 + index,
            index,
        }
    }

    /// A contract that holds exactly these anchors, and that was read in full.
    fn anchors_of(anchors: Vec<Anchor>) -> Result<AnchorHistory, String> {
        let latest = anchors.last().cloned().expect("at least one anchor");
        Ok(AnchorHistory {
            contract: "0x2a4a287ec1f01b5bcb5568d2ed0765faf860a62b".to_string(),
            chain_id: 84532,
            total: anchors.len() as u64,
            anchors,
            latest,
            scanned_from: 45_495_000,
            complete: true,
            latest_agrees: true,
        })
    }

    /// The anchors that an anchor sender which writes every `every` messages
    /// would have left while the sequencer published this history.
    fn anchors_every(messages: &[OrderMessage], every: OrderId, session: &str) -> Vec<Anchor> {
        (1..)
            .map(|n| n * every)
            .take_while(|at| *at <= messages.len() as OrderId)
            .enumerate()
            .map(|(i, at)| anchor_over(messages, at, session, i as u64 + 1))
            .collect()
    }

    /// Every failure the anchor checks produced, as one string.
    fn anchor_failures(outcome: &Outcome) -> String {
        outcome
            .checks
            .iter()
            .filter(|c| c.name.contains("anchor"))
            .flat_map(|c| c.failures.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The base case: an exchange that still produces what was anchored.
    #[tokio::test]
    async fn an_anchor_this_history_reproduces_passes() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(40);
        let path = build(&dir, &messages, &key);
        let record = read_db(&path, None).expect("read");
        let head = Ok(signed_head(&key, SESSION, &messages));

        // An anchor sender that wrote every 8 messages. That is what a sender
        // on a timer produces: several anchors, and none of them at the end.
        let anchors = anchors_of(anchors_every(&messages, 8, SESSION));
        let outcome =
            check_held_anchored(&record, &head, Some(SESSION), &messages, Some(&anchors)).await;

        assert!(
            outcome.passed(),
            "an exchange that reproduces its own anchors was reported as dishonest: {}",
            outcome.failure_text()
        );
        let checked: usize = outcome
            .checks
            .iter()
            .filter(|c| c.name == "every on-chain anchor matches the feed")
            .map(|c| c.checked)
            .sum();
        assert_eq!(
            checked, 5,
            "every anchor has to be folded to, not just the newest"
        );
    }

    /// The attack that a read of only the newest anchor misses.
    ///
    /// The exchange ran to message 30, and anchors went out at messages 10, 20
    /// and 30. The operator then rewound to message 20, published different
    /// messages from there, ran on to message 40, and anchored that. The
    /// contract accepts the new anchor, because 40 is further forward than
    /// anything it holds. Today's history produces that newest anchor exactly,
    /// so an audit that read one value would pass. The anchor at message 30 is
    /// the one that does not come out the same, and the block that carried it
    /// is when the operator committed to the other version.
    #[tokio::test]
    async fn a_rewind_that_kept_anchoring_is_caught_by_the_older_anchors() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();

        let original = history(30);
        let mut replayed = history(40);
        for id in 21..=40u64 {
            replayed[(id - 1) as usize] = new_order(id, 4, Side::Buy, 98.0);
        }

        // What the contract holds: three anchors over the history as it was,
        // and a fourth written after the rewind.
        let mut written = anchors_every(&original, 10, SESSION);
        written.push(anchor_over(&replayed, 40, SESSION, 4));
        let anchors = anchors_of(written);

        let path = build(&dir, &replayed, &key);
        let record = read_db(&path, None).expect("read");
        let head = Ok(signed_head(&key, SESSION, &replayed));

        // The newest anchor on its own agrees with what is served today, which
        // is the whole reason this test exists.
        let newest = anchors_of(vec![anchor_over(&replayed, 40, SESSION, 1)]);
        assert!(
            check_held_anchored(&record, &head, Some(SESSION), &replayed, Some(&newest))
                .await
                .passed(),
            "this test is only meaningful if the newest anchor still matches"
        );

        let outcome =
            check_held_anchored(&record, &head, Some(SESSION), &replayed, Some(&anchors)).await;
        assert!(!outcome.passed(), "a rewind that kept anchoring passed");
        let text = anchor_failures(&outcome);
        assert!(
            text.contains("at message 30") && text.contains("in block 45495"),
            "the failure must name the anchor and the block that carried it: {}",
            text
        );
        assert!(
            !text.contains("at message 10") && !text.contains("at message 40"),
            "the anchors that still hold must not be reported as failures: {}",
            text
        );
    }

    /// A log the audit did not read to the end leaves exactly the anchors that
    /// a rewind would contradict unchecked. So the audit cannot report it as a
    /// pass.
    #[tokio::test]
    async fn an_incompletely_read_anchor_log_fails() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(40);
        let path = build(&dir, &messages, &key);
        let record = read_db(&path, None).expect("read");
        let head = Ok(signed_head(&key, SESSION, &messages));

        let mut anchors = anchors_of(anchors_every(&messages, 8, SESSION)).expect("built");
        anchors.total = 400;
        anchors.complete = false;
        let anchors = Ok(anchors);

        let outcome =
            check_held_anchored(&record, &head, Some(SESSION), &messages, Some(&anchors)).await;
        assert!(!outcome.passed(), "a partial log read passed");
        assert!(
            anchor_failures(&outcome).contains("--anchor-from-block"),
            "the failure has to name the flag that fixes it: {}",
            anchor_failures(&outcome)
        );
    }

    /// The whole point of the feature. The operator stops, deletes the
    /// databases, runs a *different* history, signs every head and every claim
    /// again over that history, and starts again. Every other check in this
    /// file passes on the result, because the exchange agrees with itself
    /// everywhere. The anchor is the only thing left that says it is not the
    /// same exchange.
    #[tokio::test]
    async fn a_rewound_and_replayed_history_fails_against_its_own_anchor() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();

        // What was anchored: the history as it stood.
        let original = history(40);
        let anchors = anchors_of(vec![anchor_over(&original, 25, SESSION, 4)]);

        // What is served now: the same length, the same session, the same
        // keys, and one message different. Everything is signed again over the
        // new history.
        let mut replayed = original.clone();
        replayed[10] = new_order(11, 3, Side::Buy, 99.5);
        let path = build(&dir, &replayed, &key);
        let record = read_db(&path, None).expect("read");
        let head = Ok(signed_head(&key, SESSION, &replayed));

        let honest = check_held_anchored(&record, &head, Some(SESSION), &replayed, None).await;
        assert!(
            honest.passed(),
            "the replayed history has to pass every self-consistent check, or this test is \
             not testing what the anchor adds: {}",
            honest.failure_text()
        );

        let outcome =
            check_held_anchored(&record, &head, Some(SESSION), &replayed, Some(&anchors)).await;
        assert!(
            !outcome.passed(),
            "a replayed history passed its own anchor"
        );

        let text = anchor_failures(&outcome);
        let anchored = &anchors.as_ref().expect("built above").anchors[0];
        assert!(
            text.contains(&logchain::to_hex(&anchored.chain)),
            "the failure must name the anchored chain: {}",
            text
        );
        assert!(
            text.contains(&logchain::to_hex(&anchored.state_root)),
            "the failure must name the anchored state root: {}",
            text
        );
        assert!(
            text.contains("message 25"),
            "the failure must name where the two disagree: {}",
            text
        );
    }

    /// If somebody empties the log and starts again, the sequencer gets a new
    /// session and the ids start at 1 again. Nothing else in the audit then
    /// has anything to compare. This is the event the anchor exists to expose,
    /// and it must read as a failure and not as a note.
    #[tokio::test]
    async fn an_anchor_for_a_replaced_feed_session_fails_loudly() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(40);
        let path = build(&dir, &messages, &key);
        let record = read_db(&path, None).expect("read");
        let head = Ok(signed_head(&key, SESSION, &messages));

        let anchors = anchors_of(vec![anchor_over(
            &messages,
            25,
            "a-history-that-was-thrown-away",
            4,
        )]);
        let outcome =
            check_held_anchored(&record, &head, Some(SESSION), &messages, Some(&anchors)).await;

        assert!(!outcome.passed(), "a replaced feed history passed");
        let text = anchor_failures(&outcome);
        assert!(
            text.contains("a-history-that-was-thrown-away") && text.contains(SESSION),
            "the failure must name both sessions: {}",
            text
        );
        assert!(
            text.contains("has been replaced"),
            "the failure must say what happened, not just that two strings differ: {}",
            text
        );
        // The anchored id names a message of a history this exchange does not
        // serve, so there is nothing to compare it with. To say the chain was
        // rewritten, or the exchange rolled back, would be an exact accusation
        // about *this* history that the evidence does not support.
        assert!(
            !text.contains("rolled back") && !text.contains("messages hash to"),
            "an anchor from another history must not be reported as a rewind: {}",
            text
        );
        assert!(
            text.contains("nothing here to compare it against"),
            "the failure has to say why the comparison could not be made: {}",
            text
        );
    }

    /// An exchange that somebody rolled back behind its own anchor. Every
    /// message may still be there, so the chain hash still matches. What is
    /// missing is the execution the anchor committed to.
    #[tokio::test]
    async fn an_anchor_past_the_run_is_reported_as_a_rollback() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(40);
        // The run committed only to message 20. The anchor says message 30.
        let path = build(&dir, &messages[..20], &key);
        let record = read_db(&path, None).expect("read");
        let head = Ok(signed_head(&key, SESSION, &messages));

        let anchors = anchors_of(vec![anchor_over(&messages, 30, SESSION, 4)]);
        let outcome =
            check_held_anchored(&record, &head, Some(SESSION), &messages, Some(&anchors)).await;

        assert!(!outcome.passed(), "a rolled-back run passed its own anchor");
        let text = anchor_failures(&outcome);
        assert!(
            text.contains("rolled back"),
            "the failure must say the run is behind its anchor: {}",
            text
        );
        // Nobody edited the messages, so that half of the check must still
        // pass. The report must not blame the sequencer for the rollback.
        assert!(
            !text.contains("this feed's messages hash to"),
            "the history check must not fail when the history is intact: {}",
            text
        );
    }

    /// An anchor nobody could read is an unchecked claim. A report of a pass
    /// would state the one property this audit cannot prove as proven.
    #[tokio::test]
    async fn an_unreachable_anchor_fails_rather_than_passing() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(20);
        let path = build(&dir, &messages, &key);
        let record = read_db(&path, None).expect("read");
        let head = Ok(signed_head(&key, SESSION, &messages));

        let anchors: Result<AnchorHistory, String> =
            Err("cannot reach the anchor's RPC at https://sepolia.base.org: timed out".to_string());
        let outcome =
            check_held_anchored(&record, &head, Some(SESSION), &messages, Some(&anchors)).await;

        assert!(!outcome.passed(), "an unreadable anchor passed");
        let text = anchor_failures(&outcome);
        assert!(
            text.contains("unchecked claim"),
            "the failure has to say why silence is not agreement: {}",
            text
        );
    }

    /// The other half of failing honestly. An audit with no anchor configured
    /// must be the audit it was before anchors existed, including the checks
    /// it prints.
    #[tokio::test]
    async fn no_anchor_configured_leaves_the_audit_exactly_as_it_was() {
        let dir = TempDir::new().unwrap();
        let key = logchain::ephemeral_key();
        let messages = history(20);
        let path = build(&dir, &messages, &key);
        let record = read_db(&path, None).expect("read");
        let head = Ok(signed_head(&key, SESSION, &messages));

        let without = check_held(&record, &head, Some(SESSION), &messages).await;
        assert!(without.passed());
        assert!(
            !without
                .checks
                .iter()
                .any(|c| c.name.starts_with("the on-chain anchor")),
            "an unconfigured anchor must not add a check to the report"
        );
    }
}
