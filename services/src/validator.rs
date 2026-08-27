//! A validator: one member of the group that makes the sequencer's history
//! final. This is the ordering half of design V4.
//!
//! A validator reads the log and says which messages it saw, in which order.
//! It follows the sequencer's log on its own. It computes the chain hash
//! again from the message bytes. It compares that hash with the head the
//! sequencer signed. Then it signs what it saw with its own key. That signed
//! statement is an attestation.
//!
//! Whoever reads the attestations counts them. A history that enough
//! validators vouched for cannot be replaced later by the sequencer alone.
//! Replacing it needs a second set of signatures over a different history,
//! from enough of the same validators to reach the count again. Any
//! validator that signs two different chain hashes for one message number
//! has signed the proof of its own dishonesty.
//!
//! A validator attests to the *order* of the messages and to nothing else. A
//! chain hash that does not match the sequencer's signature means the
//! sequencer published a history it did not sign. That is the `disputed`
//! verdict below, and that verdict sticks.
//!
//! What the messages do when the exchange runs them is not this service's
//! subject. `--audit` and `--audit-url` run the history again and check the
//! exchange's signed claims against it. That is a stronger statement than a
//! vote, and it holds without any group of independent validators.
//!
//! BFT ordering means Byzantine fault tolerant ordering: ordering that still
//! holds when some machines lie. It has two halves. The safety half stops two
//! different histories from both being accepted. The liveness half keeps the
//! system running when the leader stops. This file is a small version of the
//! safety half: validators sign what they saw, instead of running full
//! consensus rounds. The liveness half, replacing a stalled or refusing
//! sequencer with another leader, needs view-change machinery, the code that
//! elects a new leader. That half is deliberately out of scope; the roadmap
//! says so.
//!
//! Two rules keep an attestation worth counting:
//!
//! - **The cursor never passes what was checked.** The validator hashes a
//!   batch into the chain only when three things hold. The message numbers
//!   continue the cursor one by one. The sequencer's signed head stands at
//!   the last message of the batch. The chain hash those messages produce is
//!   the chain hash the sequencer signed. Nothing else moves the cursor, so
//!   every message number this validator signs is one it verified. Without
//!   that rule a repeated message would be hashed in twice. The validator
//!   would then sign two different chain hashes for one message number, the
//!   proof of its own dishonesty, produced by an honest validator only
//!   because the sequencer served the same message twice.
//! - **Not being able to check is reported, not hidden.** The validator
//!   counts the polls in a row that end without confirming the cursor. Past
//!   `UNCHECKED_POLLS_BEFORE_STALL` polls it marks itself stalled in the
//!   attestation it serves. A sequencer nobody can check is not a sequencer
//!   anybody should count attestations against.
//!
//! A validator that catches the sequencer lying stops attesting, keeps
//! serving its last good attestation, and marks itself disputed. Lying here
//! means a signed head that does not match the chain hash the validator
//! computed. The verdict is written to disk: it survives a restart, and only
//! an operator clears it. The validator does not follow a history it cannot
//! vouch for.
//!
//! A validator attests to the *order* of the messages, so it never needs to
//! know what a message means. This file does not mention `OrderMessage` at
//! all. It reads the bytes the sequencer served, takes each message's number
//! out of them, and hashes those bytes into the chain. A history that
//! carries a message kind this build has never seen is one this validator
//! attests to normally. That property lets the sequencer's message format
//! grow without every validator being redeployed on the same day. A
//! validator that had to parse the messages would have refused that history,
//! or worse, disputed it.

use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{Level, error, info, warn};
use tracing_subscriber::FmtSubscriber;

use crate::inbox::warn_if_public;
use crate::logchain::{self, AttestStatus, Chain, EMPTY_CHAIN};
use crate::matcher::{SignedHead, parse_signed_head};
use crate::sqlite;
use crate::wire::{self, RawMessage};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, params};

/// How many consecutive polls may end without confirming the cursor before
/// the validator says so in what it serves.
///
/// An honest sequencer builds the messages and the signed head under one
/// lock. Every one of its responses therefore stands exactly on the head it
/// signs, and every poll confirms the cursor. Reaching this many polls in a
/// row means the sequencer answers but can never be checked. The causes are:
/// served message numbers that skip the cursor, a head that never covers
/// what was served, a key that is not the pinned one, or no answer at all.
/// At the default 200 ms poll, 20 polls is four seconds with no check. That
/// is short enough that nobody counts a stale attestation for long, and long
/// enough that one bad poll during a sequencer restart does not trip it.
pub const UNCHECKED_POLLS_BEFORE_STALL: u32 = 20;

/// What a validator serves on GET /attest: its signed view of the history.
#[derive(Debug, Clone, Serialize)]
pub struct Attestation {
    /// The validator's public key, hex. Whoever reads this attestation pins
    /// the key on first contact.
    pub validator: String,
    pub session: String,
    /// The highest message number this validator has followed and vouches
    /// for.
    pub last_id: u64,
    /// The chain hash this validator computed itself from the messages, hex.
    pub chain: String,
    /// Ed25519 signature over (session, last_id, chain, disputed, stalled).
    /// Every one of those is inside the signature, so nobody can remove the
    /// `disputed` or `stalled` warning on the way to whoever reads it.
    pub signature: String,
    /// True when this validator caught the sequencer signing a history that
    /// does not match the messages it served. The attestation above stays at
    /// the last message number the validator could vouch for.
    pub disputed: bool,
    /// True when this validator has not been able to confirm its cursor
    /// against a verified signed head for `UNCHECKED_POLLS_BEFORE_STALL`
    /// polls in a row. The message number below is still one it verified. It
    /// is only old enough that nobody should treat it as current.
    pub stalled: bool,
    /// How many polls in a row have ended without confirming the cursor.
    /// Zero on a healthy validator. This number is not signed, unlike the
    /// two flags above, so read it as a hint and nothing more.
    pub unchecked_polls: u32,
}

/// The validator's whole state.
struct ValidatorState {
    conn: Connection,
    signing_key: SigningKey,
    session: Option<String>,
    feed_pubkey: Option<String>,
    cursor: u64,
    chain: Chain,
    /// Set when the sequencer was caught signing a history its own messages
    /// do not produce. Written to disk, and cleared only by `clear_dispute`.
    disputed: bool,
    /// What was caught, written for the operator who reads it months later.
    dispute_reason: Option<String>,
    /// How many polls in a row since the cursor was last confirmed against a
    /// verified signed head. Written to disk, so restarting the process
    /// cannot be used to keep the count below the stall limit forever.
    unchecked_polls: u32,
}

impl ValidatorState {
    /// True once the validator has been unable to check the sequencer for
    /// long enough that its attestation must not be counted as current.
    fn stalled(&self) -> bool {
        self.unchecked_polls >= UNCHECKED_POLLS_BEFORE_STALL
    }

    /// What this validator thinks of its own view, as signed.
    fn status(&self) -> AttestStatus {
        AttestStatus {
            disputed: self.disputed,
            stalled: self.stalled(),
        }
    }

    /// The current attestation, signed fresh from the stored message number.
    fn attest(&self) -> Attestation {
        let session = self.session.clone().unwrap_or_default();
        let status = self.status();
        let signature = logchain::sign_attest(
            &self.signing_key,
            &session,
            self.cursor,
            &self.chain,
            &status,
        );
        Attestation {
            validator: logchain::to_hex(self.signing_key.verifying_key().as_bytes()),
            session,
            last_id: self.cursor,
            chain: logchain::to_hex(&self.chain),
            signature: logchain::to_hex(&signature.to_bytes()),
            disputed: status.disputed,
            stalled: status.stalled,
            unchecked_polls: self.unchecked_polls,
        }
    }

    /// Records one poll that ended without confirming the cursor. It logs an
    /// error the moment the count reaches the stall limit.
    fn unchecked(&mut self, why: Unchecked) -> Ingest {
        self.unchecked_polls = self.unchecked_polls.saturating_add(1);
        warn!(
            "cannot check the feed at cursor {}: {} ({} polls in a row)",
            self.cursor, why, self.unchecked_polls
        );
        if self.unchecked_polls == UNCHECKED_POLLS_BEFORE_STALL {
            error!(
                "STALLED at message {}: {} polls in a row could not be checked against a \
                 signed head. This validator now serves stalled = true and its attestation \
                 must not be counted. Last reason: {}",
                self.cursor, self.unchecked_polls, why
            );
        }
        Ingest::Unchecked(why)
    }

    /// Records the verdict this validator exists to reach, once.
    fn dispute(&mut self, reason: String) -> Ingest {
        error!(
            "DISPUTE at message {}: {}. Refusing to attest further; this validator now \
             serves disputed = true and keeps its last good attestation. \
             The verdict survives restarts; clear it only after investigating",
            self.cursor, reason
        );
        self.disputed = true;
        self.dispute_reason = Some(reason);
        Ingest::Disputed
    }

    /// Writes the followed message number to disk. One row, one transaction:
    /// the cursor is saved together with the chain hash it belongs to, the
    /// same rule as everywhere else in this system.
    ///
    /// The dispute verdict and the unchecked-poll count are written with the
    /// message number on purpose. A validator that forgot either one on
    /// restart would start attesting again to a history it had already caught
    /// being forged, which is the same as never having caught it.
    fn save(&self) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO validator_state
               (id, session, feed_pubkey, cursor, chain, disputed, dispute_reason, unchecked_polls)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
               session = excluded.session,
               feed_pubkey = excluded.feed_pubkey,
               cursor = excluded.cursor,
               chain = excluded.chain,
               disputed = excluded.disputed,
               dispute_reason = excluded.dispute_reason,
               unchecked_polls = excluded.unchecked_polls",
            params![
                self.session,
                self.feed_pubkey,
                self.cursor as i64,
                self.chain.as_slice(),
                self.disputed as i64,
                self.dispute_reason,
                self.unchecked_polls as i64
            ],
        )?;
        Ok(())
    }
}

/// What one poll response did to the validator's state.
#[derive(Debug, PartialEq, Eq)]
enum Ingest {
    /// The head verified and the chain hash matched. The cursor now stands on
    /// a message number this validator vouches for.
    Verified(u64),
    /// The response could not be checked. Nothing was hashed into the chain
    /// and the cursor did not move.
    Unchecked(Unchecked),
    /// The sequencer signed a history its own messages do not produce.
    Disputed,
}

/// Why a poll ended without confirming the cursor. Every variant has the same
/// effect: nothing was hashed into the chain, the cursor stayed where it was,
/// and the count of polls in a row went up by one.
#[derive(Debug, PartialEq, Eq)]
enum Unchecked {
    /// The sequencer did not answer at all.
    NoAnswer,
    /// The sequencer answered with something that is not a page of messages:
    /// an error body, or bytes with no readable message number in them.
    /// Nothing here can be placed in the history, so nothing here can be
    /// hashed into the chain either. This is deliberately not a dispute. A
    /// response the validator cannot read proves nothing about what the
    /// sequencer published. It only proves this one response is unusable.
    Unreadable(String),
    /// The response carried no session or no signed head. Removing the
    /// headers must not be an easier way past these checks than forging a
    /// signature.
    NoSignedHead,
    /// The head names a key that is not the pinned one. Nothing announces a
    /// key change in this protocol, so this is a different signer at the same
    /// address.
    ForeignKey { pinned: String, got: String },
    /// The head does not verify under the key it names.
    BadSignature { key: String, at: u64 },
    /// The signed head does not stand at the end of what was served, so no
    /// signature covers the last message in the response.
    HeadDoesNotCover { signed_at: u64, served_to: u64 },
    /// The message numbers do not continue the cursor: a gap, or a message
    /// served twice.
    OutOfOrder { expected: u64, got: u64 },
}

impl fmt::Display for Unchecked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unchecked::NoAnswer => write!(f, "the feed did not answer with messages"),
            Unchecked::Unreadable(reason) => write!(f, "{}", reason),
            Unchecked::NoSignedHead => write!(
                f,
                "the response carries no session or no signed head, and an unsigned \
                 response is not evidence of anything"
            ),
            Unchecked::ForeignKey { pinned, got } => write!(
                f,
                "the head is signed by {} but this validator pinned {}",
                got, pinned
            ),
            Unchecked::BadSignature { key, at } => write!(
                f,
                "the head at message {} does not verify under the key {} it names",
                at, key
            ),
            Unchecked::HeadDoesNotCover {
                signed_at,
                served_to,
            } => write!(
                f,
                "the feed served up to message {} but signed its head at {}, so nothing \
                 here can be compared against a signature",
                served_to, signed_at
            ),
            Unchecked::OutOfOrder { expected, got } => write!(
                f,
                "expected message {} next but the feed served {}",
                expected, got
            ),
        }
    }
}

/// Starts one validator: a loop that polls the sequencer, and a small HTTP
/// server that serves the signed attestation.
pub async fn start_validator(bind: IpAddr, port: u16, db: PathBuf, feed_url: String, poll_ms: u64) {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    // Bind the port before opening the database, as everywhere in this
    // system. The port is the lock: a second process cannot bind it.
    let addr = SocketAddr::new(bind, port);
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            error!(
                "could not bind validator to {}: {} (try --validator-port)",
                addr, e
            );
            std::process::exit(2);
        }
    };
    warn_if_public(addr, "this validator's signed attestation");

    let key_path = db.with_extension("key");
    let signing_key = match logchain::load_or_create_key(&key_path) {
        Ok(key) => key,
        Err(e) => {
            error!("cannot use validator key {}: {}", key_path.display(), e);
            std::process::exit(2);
        }
    };
    let state = match open_validator_db(&db, signing_key) {
        Ok(state) => state,
        Err(e) => {
            error!("cannot use validator database {}: {}", db.display(), e);
            std::process::exit(2);
        }
    };
    info!(
        "validator {} on {}: cursor {} in {}",
        logchain::to_hex(state.signing_key.verifying_key().as_bytes()),
        addr,
        state.cursor,
        db.display()
    );
    // A dispute is the most important thing this process can report. A
    // restart is exactly when it would otherwise go unnoticed, so the
    // validator reports it again here.
    if state.disputed {
        error!(
            "this validator is DISPUTED at message {}: {}. It will not follow the feed \
             and serves disputed = true. After investigating, clear it with: \
             sqlite3 {} \"UPDATE validator_state SET disputed = 0, dispute_reason = NULL \
             WHERE id = 1\"",
            state.cursor,
            state
                .dispute_reason
                .as_deref()
                .unwrap_or("reason not recorded"),
            db.display()
        );
    }

    let shared = Arc::new(Mutex::new(state));
    let poller_state = Arc::clone(&shared);
    tokio::spawn(async move {
        follow_feed(poller_state, feed_url, poll_ms).await;
    });

    let app = Router::new()
        .route("/attest", get(get_attest))
        .with_state(shared);
    axum::serve(listener, app)
        .await
        .expect("validator server stopped unexpectedly");
}

fn open_validator_db(path: &Path, signing_key: SigningKey) -> Result<ValidatorState, String> {
    // The database file is not owner-only. The session, the sequencer's
    // public key, the cursor, the chain hash and the dispute verdict are all
    // what this validator already serves at `/attest`. A validator says in
    // public what it saw.
    let conn = sqlite::open_durable(path, false)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS validator_state (
           id              INTEGER PRIMARY KEY CHECK (id = 1),
           session         TEXT,
           feed_pubkey     TEXT,
           cursor          INTEGER NOT NULL,
           chain           BLOB    NOT NULL,
           disputed        INTEGER NOT NULL DEFAULT 0,
           dispute_reason  TEXT,
           unchecked_polls INTEGER NOT NULL DEFAULT 0
         );",
    )
    .map_err(|e| e.to_string())?;
    add_missing_columns(&conn)?;

    let stored: Option<(
        Option<String>,
        Option<String>,
        i64,
        Vec<u8>,
        i64,
        Option<String>,
        i64,
    )> = conn
        .query_row(
            "SELECT session, feed_pubkey, cursor, chain, disputed, dispute_reason, unchecked_polls
             FROM validator_state WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(|e| e.to_string())?;

    let (session, feed_pubkey, cursor, chain, disputed, dispute_reason, unchecked_polls) =
        match stored {
            Some((session, feed_pubkey, cursor, chain, disputed, reason, unchecked)) => {
                let chain: Chain = chain
                    .try_into()
                    .map_err(|_| "stored chain is not 32 bytes".to_string())?;
                (
                    session,
                    feed_pubkey,
                    cursor as u64,
                    chain,
                    disputed != 0,
                    reason,
                    unchecked.max(0) as u32,
                )
            }
            None => (None, None, 0, EMPTY_CHAIN, false, None, 0),
        };
    Ok(ValidatorState {
        conn,
        signing_key,
        session,
        feed_pubkey,
        cursor,
        chain,
        disputed,
        dispute_reason,
        unchecked_polls,
    })
}

/// Brings a database written by an older build up to the current columns.
///
/// `CREATE TABLE IF NOT EXISTS` does nothing to a table that already exists.
/// A validator.db written before the dispute verdict was written to disk
/// would therefore still be missing those columns, and every save would fail.
/// Each column is added only if it is not already there, which is also what
/// makes running this on every start harmless.
fn add_missing_columns(conn: &Connection) -> Result<(), String> {
    let mut statement = conn
        .prepare("PRAGMA table_info(validator_state)")
        .map_err(|e| e.to_string())?;
    let columns: Vec<String> = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<String>>>()
        .map_err(|e| e.to_string())?;
    drop(statement);

    for (column, ddl) in [
        (
            "disputed",
            "ALTER TABLE validator_state ADD COLUMN disputed INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "dispute_reason",
            "ALTER TABLE validator_state ADD COLUMN dispute_reason TEXT",
        ),
        (
            "unchecked_polls",
            "ALTER TABLE validator_state ADD COLUMN unchecked_polls INTEGER NOT NULL DEFAULT 0",
        ),
    ] {
        if !columns.iter().any(|existing| existing == column) {
            info!("adding column {} to validator_state", column);
            conn.execute(ddl, []).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Clears a dispute an operator has investigated, and the stall count with
/// it. Returns whether there was a dispute to clear.
///
/// There is deliberately no automatic way back. A validator that caught the
/// sequencer forging history stays disputed until a person decides what
/// happened. Clearing does not rewind the cursor, so a sequencer that is
/// still signing the history this validator refused is caught again on the
/// next poll.
pub fn clear_dispute(path: &Path) -> Result<bool, String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    add_missing_columns(&conn)?;
    let cleared = conn
        .execute(
            "UPDATE validator_state
             SET disputed = 0, dispute_reason = NULL, unchecked_polls = 0
             WHERE id = 1 AND disputed != 0",
            [],
        )
        .map_err(|e| e.to_string())?;
    Ok(cleared > 0)
}

/// Follows the sequencer. It checks every response before it believes any of
/// it, hashes in only what a verified signed head covers, and saves the
/// message number it reached.
async fn follow_feed(state: Arc<Mutex<ValidatorState>>, feed_url: String, poll_ms: u64) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("http client");
    loop {
        sleep(Duration::from_millis(poll_ms)).await;
        if lock(&state).disputed {
            // Nothing to follow anymore: this validator refuses the history.
            continue;
        }

        let since = lock(&state).cursor;
        // The raw-bytes endpoint, not `/orders`. The chain hash combines the
        // bytes the sequencer hashed, and this endpoint serves exactly those
        // bytes, one message per line. See `wire::MESSAGES_PATH`.
        let url = wire::messages_url(&feed_url, since);
        let fetched = match client.get(&url).send().await {
            Ok(response) => {
                let session = response
                    .headers()
                    .get(crate::wire::SESSION_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .map(String::from);
                let head = parse_signed_head(response.headers());
                let status = response.status();
                match response.bytes().await {
                    Ok(_) if !status.is_success() => {
                        Some((session, head, Err(format!("{} answered {}", url, status))))
                    }
                    Ok(body) => Some((session, head, wire::split_ndjson(&body))),
                    Err(e) => {
                        warn!("could not read the feed's response: {}", e);
                        None
                    }
                }
            }
            Err(e) => {
                warn!("feed unreachable at {}: {}", feed_url, e);
                None
            }
        };

        // The lock is taken after every await, never across one.
        let mut state = lock(&state);
        match fetched {
            // A sequencer that does not answer is a sequencer that cannot be
            // checked. It counts toward the stall like any other unchecked
            // poll. Seen from outside, "the validator could not reach the
            // sequencer" and "the sequencer lied about what it served" both
            // mean the same thing: this attestation is not current evidence.
            None => {
                state.unchecked(Unchecked::NoAnswer);
            }
            Some((_, _, Err(reason))) => {
                state.unchecked(Unchecked::Unreadable(reason));
            }
            Some((session, head, Ok(messages))) => {
                ingest(&mut state, session.as_deref(), head.as_ref(), &messages);
            }
        }
        if let Err(e) = state.save() {
            warn!("could not save validator position: {}", e);
        }
    }
}

/// Applies one poll response to the validator's state.
///
/// Everything is checked before anything is hashed into the chain, in this
/// order: the response carries a session and a signed head; the head is
/// signed by the pinned key; the signature verifies; the message numbers
/// continue the cursor one by one; the head stands at the last message
/// served; and the chain hash those messages produce is the chain hash the
/// sequencer signed. Only the last check can produce a dispute. The rest mean
/// "this response proves nothing", so the cursor stays where it is and the
/// poll counts as unchecked.
///
/// The order matters twice over.
///
/// First, verifying before pinning keeps one bad response from choosing this
/// validator's sequencer key for good. Pinning on first sight would let
/// anything that can answer the sequencer URL once pin its own key: a stale
/// process still holding the port, a wrong `--feed-url`, or a local proxy.
/// Every honest head afterwards would then be refused as "key changed", while
/// the validator keeps signing its frozen message number with
/// disputed = false.
///
/// Second, verifying before believing the session header is the same rule.
/// The session is inside what the sequencer signs. So the validator acts on a
/// session change, and on the restart from message 1 that follows it, only
/// when the real sequencer signed that session.
fn ingest(
    state: &mut ValidatorState,
    session: Option<&str>,
    head: Option<&SignedHead>,
    messages: &[RawMessage],
) -> Ingest {
    let (Some(session), Some(head)) = (session, head) else {
        return state.unchecked(Unchecked::NoSignedHead);
    };

    if let Some(pinned) = &state.feed_pubkey
        && *pinned != head.public_key
    {
        return state.unchecked(Unchecked::ForeignKey {
            pinned: pinned.clone(),
            got: head.public_key.clone(),
        });
    }
    let verified = logchain::from_hex::<32>(&head.public_key)
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        .is_some_and(|key| {
            logchain::verify_head(&key, session, head.last_id, &head.chain, &head.signature)
        });
    if !verified {
        return state.unchecked(Unchecked::BadSignature {
            key: head.public_key.clone(),
            at: head.last_id,
        });
    }
    if state.feed_pubkey.is_none() {
        info!(
            "pinning feed public key {} (its head at message {} verified)",
            head.public_key, head.last_id
        );
        state.feed_pubkey = Some(head.public_key.clone());
    }

    // Past this line the session string and the head are backed by a
    // signature from the pinned key.

    // A new session is a new history, so follow it from message 1. The old
    // attestations stay valid for the old session, because the session is
    // part of the signed statement. A dispute is not reset here and cannot
    // be: the loop above does not poll while disputed, so changing the
    // session is not a way to clear a verdict.
    if state.session.as_deref() != Some(session) {
        if state.session.is_some() {
            warn!(
                "feed session changed to {} (signed by the pinned key); following the \
                 new history from its first message",
                session
            );
        } else {
            info!("feed session is {}", session);
        }
        state.session = Some(session.to_string());
        state.cursor = 0;
        state.chain = EMPTY_CHAIN;
        state.unchecked_polls = 0;
    }

    // The message numbers must continue the cursor exactly. A repeat is
    // refused here, and that refusal is the whole point. Hashing message N in
    // twice gives a second chain hash for a message number this validator has
    // already signed. Two signed chain hashes for one message number are the
    // proof of a validator's own dishonesty, produced in that case by an
    // honest validator that was served the same message twice.
    let mut expected = state.cursor.saturating_add(1);
    for msg in messages {
        if msg.id != expected {
            return state.unchecked(Unchecked::OutOfOrder {
                expected,
                got: msg.id,
            });
        }
        expected = expected.saturating_add(1);
    }

    // The signature says something only about a history that ends where the
    // signature stands. A sequencer whose head sits one message ahead of what
    // it serves cannot be checked at all. That used to leave this validator
    // hashing in and signing message numbers it had never compared against
    // anything.
    let served_to = messages.last().map(|msg| msg.id).unwrap_or(state.cursor);
    if head.last_id != served_to {
        return state.unchecked(Unchecked::HeadDoesNotCover {
            signed_at: head.last_id,
            served_to,
        });
    }

    // The check that can produce a dispute: the chain hash the messages
    // produce must be the chain hash the sequencer signed over them.
    //
    // The hash combines the bytes that arrived, never bytes rebuilt from a
    // parsed message. That is what makes this validator's verdict a statement
    // about the sequencer, and not a statement about how old this build is. A
    // message kind this build cannot read hashes exactly like any other, and
    // this line does not tell the two apart.
    let chain = messages.iter().fold(state.chain, |chain, msg| {
        logchain::extend_bytes(&chain, &msg.bytes)
    });
    if chain != head.chain {
        return state.dispute(format!(
            "the feed signed chain {} at message {} but the messages it served hash to {}",
            logchain::to_hex(&head.chain),
            head.last_id,
            logchain::to_hex(&chain)
        ));
    }

    if state.stalled() {
        info!(
            "no longer stalled: the feed is checkable again at message {}",
            head.last_id
        );
    }
    state.chain = chain;
    state.cursor = served_to;
    state.unchecked_polls = 0;
    Ingest::Verified(state.cursor)
}

/// Handles GET /attest: the validator's signed view of the history, signed
/// fresh over the message number it wrote to disk.
/// Takes the validator's lock, or stops the process.
///
/// The same shape as the sequencer's, and for a stronger reason. A poisoned
/// lock means a thread panicked partway through an update, so the cursor and
/// the chain hash beside it may no longer describe the same message number.
/// This validator *signs* what it serves. An attestation built from
/// half-updated state is a signed statement about a message number the
/// validator never verified, and two signed statements that disagree are what
/// this system treats as proof a signer is dishonest. A validator that keeps
/// answering after a panic can produce the proof of its own dishonesty.
///
/// Stopping is also the safe way to fail. The exchange counts the
/// attestations it can reach and does not count one it cannot reach. A
/// validator that exits therefore lowers how many validators agree, and does
/// nothing else. Answering with a wrong signature would be worse than not
/// answering at all.
fn lock(state: &Arc<Mutex<ValidatorState>>) -> MutexGuard<'_, ValidatorState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(_) => {
            error!(
                "the validator state lock is poisoned: a thread panicked while holding it, so \
                 the cursor and the chain may no longer describe the same position. Stopping \
                 rather than signing an attestation for a position this validator cannot stand \
                 behind; a restart rebuilds from the database and re-follows the feed"
            );
            std::process::exit(2);
        }
    }
}

async fn get_attest(State(state): State<Arc<Mutex<ValidatorState>>>) -> Json<Attestation> {
    Json(lock(&state).attest())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{OrderMessage, Side};
    use ed25519_dalek::Signature;
    use tempfile::TempDir;

    /// One message as it arrives at a validator: bytes, not a struct. The
    /// tests build the bytes with the sequencer's own serialization, because
    /// that is what the sequencer publishes. They then pass on only the
    /// bytes, which is all the validator ever sees.
    fn message(id: u64) -> RawMessage {
        RawMessage::of(&OrderMessage::New {
            id,
            timestamp: id * 1000,
            account: 1,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            price: 100.25,
            quantity: 5.0,
            nonce: None,
            order_type: Default::default(),
            time_in_force: Default::default(),
            post_only: false,
        })
    }

    fn chain_of(messages: &[RawMessage]) -> Chain {
        messages.iter().fold(EMPTY_CHAIN, |chain, msg| {
            logchain::extend_bytes(&chain, &msg.bytes)
        })
    }

    /// A sequencer under test: one key, one session, one message log. It
    /// signs heads exactly as `feed.rs` does, so what the validator checks
    /// here is what it checks in production.
    struct TestFeed {
        key: SigningKey,
        session: String,
        messages: Vec<RawMessage>,
    }

    impl TestFeed {
        fn new(len: u64) -> Self {
            TestFeed {
                key: logchain::ephemeral_key(),
                session: "feed-session".to_string(),
                messages: (1..=len).map(message).collect(),
            }
        }

        fn public_key(&self) -> String {
            logchain::to_hex(self.key.verifying_key().as_bytes())
        }

        /// The head this sequencer signs when its log holds `through`
        /// messages.
        fn head(&self, through: u64) -> SignedHead {
            self.head_claiming(through, chain_of(&self.messages[..through as usize]))
        }

        /// A head signed over any chain hash the test chooses: a correctly
        /// signed claim that may or may not be true about the messages
        /// served.
        fn head_claiming(&self, last_id: u64, chain: Chain) -> SignedHead {
            let signature = logchain::sign_head(&self.key, &self.session, last_id, &chain);
            SignedHead {
                last_id,
                chain,
                public_key: self.public_key(),
                signature,
            }
        }

        /// Messages `from + 1 ..= to`, as `?since=from` would serve them.
        fn since(&self, from: u64, to: u64) -> Vec<RawMessage> {
            self.messages[from as usize..to as usize].to_vec()
        }

        /// Serves those messages the way the sequencer really does: one line
        /// holds the bytes that were hashed, then one newline. It splits them
        /// back out, so a test uses the same line format production uses.
        fn served(&self, from: u64, to: u64) -> Vec<RawMessage> {
            let mut body = Vec::new();
            for msg in &self.messages[from as usize..to as usize] {
                body.extend_from_slice(&msg.bytes);
                body.push(b'\n');
            }
            wire::split_ndjson(&body).expect("the feed serves one message per line")
        }
    }

    /// A validator with its own file, so a test can close it and open it
    /// again the way a restart does.
    fn open_at(dir: &TempDir, name: &str) -> ValidatorState {
        open_validator_db(&dir.path().join(name), logchain::ephemeral_key())
            .expect("validator database opens")
    }

    fn fresh() -> (TempDir, ValidatorState) {
        let dir = TempDir::new().expect("temp dir");
        let state = open_at(&dir, "validator.db");
        (dir, state)
    }

    /// Drives a validator up to `through` the way a first poll does.
    fn follow_to(state: &mut ValidatorState, feed: &TestFeed, through: u64) {
        let outcome = ingest(
            state,
            Some(&feed.session),
            Some(&feed.head(through)),
            &feed.since(0, through),
        );
        assert_eq!(outcome, Ingest::Verified(through));
    }

    #[test]
    fn following_an_honest_feed_verifies_every_position() {
        let (_dir, mut state) = fresh();
        let feed = TestFeed::new(3);

        follow_to(&mut state, &feed, 3);
        assert_eq!(state.cursor, 3);
        assert_eq!(state.chain, chain_of(&feed.messages));
        assert_eq!(
            state.feed_pubkey.as_deref(),
            Some(feed.public_key().as_str())
        );
        assert_eq!(state.unchecked_polls, 0);
        assert!(!state.disputed);
        assert!(!state.stalled());

        // An idle poll: no new messages, and the head still stands on the
        // validator's cursor.
        let outcome = ingest(&mut state, Some(&feed.session), Some(&feed.head(3)), &[]);
        assert_eq!(outcome, Ingest::Verified(3));
        assert_eq!(state.unchecked_polls, 0);
    }

    /// The same test, over a history that carries nonces from submitters and
    /// a price that JSON can spell in more than one way. A nonce is a
    /// one-time number a submitter puts in an order so the same order cannot
    /// be replayed.
    ///
    /// This validator's dispute stays set until an operator clears it. So a
    /// build that computed the chain hash from anything but the bytes it
    /// received would not only be wrong once. It would record an accusation
    /// of dishonesty against an honest sequencer, and a person would have to
    /// clear it by hand. Real signed submissions put nonces in the history,
    /// so this is the ordinary case, not a rare one. `100.0` is here for the
    /// other half of the test: serde writes that f64 as `100.0` and other
    /// writers write it as `100`, and the two spellings hash differently.
    #[test]
    fn a_history_carrying_nonces_verifies_rather_than_disputes() {
        let (_dir, mut state) = fresh();
        let mut feed = TestFeed::new(3);
        // Message 2 came from a signed submission. Messages 1 and 3 are
        // generated by the test.
        feed.messages[1] = RawMessage::of(&OrderMessage::New {
            id: 2,
            timestamp: 2000,
            account: 1,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            price: 100.0,
            quantity: 5.0,
            nonce: Some("9f2b1c04d7e58a36bb0147fe29c3d580".to_string()),
            order_type: Default::default(),
            time_in_force: Default::default(),
            post_only: false,
        });
        assert!(
            String::from_utf8_lossy(&feed.messages[1].bytes).contains("100.0"),
            "the case this test is about is a price serde spells with a decimal point"
        );

        // Served and split the way a real poll delivers them.
        let outcome = ingest(
            &mut state,
            Some(&feed.session),
            Some(&feed.head(3)),
            &feed.served(0, 3),
        );

        assert_eq!(
            outcome,
            Ingest::Verified(3),
            "an honest feed whose history holds nonces must verify"
        );
        assert!(!state.disputed, "and must not be accused of anything");
        assert_eq!(state.chain, chain_of(&feed.messages));
    }

    /// The property this whole service was reworked for: a validator attests
    /// to the order of a history that holds a message kind it cannot read.
    ///
    /// Message 2 here is a kind no struct in this binary can produce. The
    /// only form of it that exists is its bytes. That is exactly the place a
    /// validator is in when the sequencer is upgraded before the validator
    /// is. Order is all this service claims to attest to, so nothing about
    /// that message stops it. It hashes the bytes in, matches the sequencer's
    /// signed chain hash, and signs the message number. Before this change it
    /// would have failed to parse the response, hashed nothing in, and marked
    /// itself stalled after twenty polls, so it would no longer have counted
    /// toward the validators that agree.
    #[test]
    fn a_validator_attests_to_a_history_it_cannot_interpret() {
        let (_dir, mut state) = fresh();
        let mut feed = TestFeed::new(3);
        feed.messages[1] = RawMessage::from_bytes(
            br#"{"Market":{"id":2,"timestamp":2000,"account":7,"symbol":"ETH-USDC","side":"Buy","quantity":3.0}}"#,
        );
        assert!(
            feed.messages[1].parse::<OrderMessage>().is_err(),
            "this build must genuinely not know this kind, or the test proves nothing"
        );

        let outcome = ingest(
            &mut state,
            Some(&feed.session),
            Some(&feed.head(3)),
            &feed.served(0, 3),
        );

        assert_eq!(outcome, Ingest::Verified(3));
        assert!(
            !state.disputed,
            "a message this build cannot read is not evidence the feed forged anything"
        );
        assert_eq!(state.chain, chain_of(&feed.messages));
        let attestation = state.attest();
        assert_eq!(attestation.last_id, 3);
        assert!(!attestation.disputed && !attestation.stalled);
        assert!(
            logchain::verify_attest(
                &state.signing_key.verifying_key(),
                &attestation.session,
                attestation.last_id,
                &logchain::from_hex::<32>(&attestation.chain).expect("chain is hex"),
                &AttestStatus::default(),
                &Signature::from_bytes(
                    &logchain::from_hex::<64>(&attestation.signature).expect("signature is hex")
                ),
            ),
            "the attestation over a history it cannot read still verifies"
        );
    }

    /// And the sequencer forging that same unreadable message is still
    /// caught. A message a validator cannot read is not a message it stops
    /// checking: one changed byte in it changes the chain hash, like any
    /// other message.
    #[test]
    fn tampering_with_a_message_this_build_cannot_read_is_still_disputed() {
        let (_dir, mut state) = fresh();
        let mut feed = TestFeed::new(3);
        feed.messages[1] = RawMessage::from_bytes(
            br#"{"Market":{"id":2,"timestamp":2000,"account":7,"symbol":"ETH-USDC","side":"Buy","quantity":3.0}}"#,
        );
        // The head is signed over the history above. The message served under
        // number 2 is a different one.
        let honest_head = feed.head(3);
        feed.messages[1] = RawMessage::from_bytes(
            br#"{"Market":{"id":2,"timestamp":2000,"account":8,"symbol":"ETH-USDC","side":"Buy","quantity":3.0}}"#,
        );

        let outcome = ingest(
            &mut state,
            Some(&feed.session),
            Some(&honest_head),
            &feed.served(0, 3),
        );

        assert_eq!(outcome, Ingest::Disputed);
        assert!(state.disputed);
        assert!(
            state
                .dispute_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("hash to")),
            "{:?}",
            state.dispute_reason
        );
    }

    /// A response that is not a page of messages stops the poll without
    /// accusing anyone. It is the answer an older sequencer gives to the
    /// endpoint this validator now reads. "Your sequencer is older than this
    /// validator" must never arrive as "your sequencer forged its history".
    #[test]
    fn an_unreadable_response_is_unchecked_and_not_a_dispute() {
        let (_dir, mut state) = fresh();
        let feed = TestFeed::new(2);
        follow_to(&mut state, &feed, 2);

        let refused = wire::split_ndjson(b"404 page not found\n")
            .expect_err("this is not a page of messages");
        let outcome = state.unchecked(Unchecked::Unreadable(refused));

        assert!(matches!(
            outcome,
            Ingest::Unchecked(Unchecked::Unreadable(_))
        ));
        assert!(!state.disputed);
        assert_eq!(state.cursor, 2, "and nothing was folded");
        assert_eq!(state.unchecked_polls, 1);
    }

    /// Finding 2, exactly as it happens. The validator signs message 3 with
    /// chain hash C3. The sequencer's next response repeats message 3.
    /// Hashing it in again would produce a second signed chain hash for
    /// message number 3: the proof of this validator's own dishonesty, from
    /// an honest validator.
    #[test]
    fn a_repeated_message_is_refused_and_the_attestation_does_not_move() {
        let (_dir, mut state) = fresh();
        let feed = TestFeed::new(3);
        follow_to(&mut state, &feed, 3);
        let signed_at_3 = state.attest();

        let repeat = vec![message(3)];
        let outcome = ingest(
            &mut state,
            Some(&feed.session),
            Some(&feed.head(3)),
            &repeat,
        );

        assert_eq!(
            outcome,
            Ingest::Unchecked(Unchecked::OutOfOrder {
                expected: 4,
                got: 3
            })
        );
        assert_eq!(state.cursor, 3);
        assert_eq!(state.chain, chain_of(&feed.messages));
        // The same message number and the same chain hash, so the same
        // signature: this validator has signed one chain hash for message 3
        // and only one.
        let after = state.attest();
        assert_eq!(after.last_id, signed_at_3.last_id);
        assert_eq!(after.chain, signed_at_3.chain);
        assert_eq!(after.signature, signed_at_3.signature);
    }

    /// A gap is refused for the same reason a repeat is: the chain hash would
    /// cover messages this validator never saw.
    #[test]
    fn a_gap_in_the_ids_is_refused() {
        let (_dir, mut state) = fresh();
        let feed = TestFeed::new(5);
        follow_to(&mut state, &feed, 3);

        let outcome = ingest(
            &mut state,
            Some(&feed.session),
            Some(&feed.head(5)),
            &feed.since(4, 5),
        );

        assert_eq!(
            outcome,
            Ingest::Unchecked(Unchecked::OutOfOrder {
                expected: 4,
                got: 5
            })
        );
        assert_eq!(state.cursor, 3);
    }

    /// Finding 1: the first response does not automatically come from the
    /// sequencer. The validator pins a key only after a head signed by that
    /// key has verified. Until then it believes nothing in the response.
    #[test]
    fn an_unverifiable_first_response_does_not_pin_a_key() {
        let (_dir, mut state) = fresh();
        let feed = TestFeed::new(2);
        let impostor = logchain::ephemeral_key();

        // What a stale process on the port, or a local proxy, can do: name
        // its own key next to a signature it cannot produce.
        let honest = feed.head(2);
        let forged = SignedHead {
            last_id: honest.last_id,
            chain: honest.chain,
            public_key: logchain::to_hex(impostor.verifying_key().as_bytes()),
            signature: honest.signature,
        };
        let outcome = ingest(
            &mut state,
            Some(&feed.session),
            Some(&forged),
            &feed.since(0, 2),
        );

        assert!(matches!(
            outcome,
            Ingest::Unchecked(Unchecked::BadSignature { .. })
        ));
        assert_eq!(
            state.feed_pubkey, None,
            "an unverified key must not be pinned"
        );
        assert_eq!(state.cursor, 0);
        assert_eq!(state.session, None);

        // The real sequencer can still be pinned, and still be followed.
        follow_to(&mut state, &feed, 2);
        assert_eq!(
            state.feed_pubkey.as_deref(),
            Some(feed.public_key().as_str())
        );
    }

    /// Once a key is pinned, a head from any other key is refused rather than
    /// followed, and it does not move the cursor.
    #[test]
    fn a_head_from_another_key_is_refused() {
        let (_dir, mut state) = fresh();
        let feed = TestFeed::new(3);
        follow_to(&mut state, &feed, 3);

        let stranger = TestFeed {
            key: logchain::ephemeral_key(),
            session: feed.session.clone(),
            messages: feed.messages.clone(),
        };
        let outcome = ingest(
            &mut state,
            Some(&stranger.session),
            Some(&stranger.head(3)),
            &[],
        );

        assert!(matches!(
            outcome,
            Ingest::Unchecked(Unchecked::ForeignKey { .. })
        ));
        assert_eq!(state.cursor, 3);
        assert_eq!(
            state.feed_pubkey.as_deref(),
            Some(feed.public_key().as_str())
        );
    }

    /// A new session sends the validator back to message 1. So the validator
    /// acts on a session change only when the pinned key signed it.
    #[test]
    fn an_unverified_session_change_cannot_rewind_the_validator() {
        let (_dir, mut state) = fresh();
        let feed = TestFeed::new(3);
        follow_to(&mut state, &feed, 3);

        // The right key is named, the session is new, and the signature does
        // not cover that new session.
        let head = feed.head(3);
        let lying = SignedHead {
            last_id: head.last_id,
            chain: head.chain,
            public_key: head.public_key.clone(),
            signature: head.signature,
        };
        let outcome = ingest(&mut state, Some("a-different-session"), Some(&lying), &[]);

        assert!(matches!(
            outcome,
            Ingest::Unchecked(Unchecked::BadSignature { .. })
        ));
        assert_eq!(
            state.cursor, 3,
            "an unsigned session change rewound the cursor"
        );
        assert_eq!(state.session.as_deref(), Some(feed.session.as_str()));

        // A real session change, signed by the pinned key, does restart the
        // follow.
        let restarted = TestFeed {
            key: feed.key.clone(),
            session: "second-history".to_string(),
            messages: (1..=2).map(message).collect(),
        };
        let outcome = ingest(
            &mut state,
            Some(&restarted.session),
            Some(&restarted.head(2)),
            &restarted.since(0, 2),
        );
        assert_eq!(outcome, Ingest::Verified(2));
        assert_eq!(state.session.as_deref(), Some("second-history"));
    }

    /// Finding 3: a sequencer that always reports itself one message ahead of
    /// what it serves can never be checked. Nobody could see that before. Now
    /// it stalls the validator, and the stall is in what the validator
    /// serves.
    #[test]
    fn a_feed_that_stays_one_ahead_stalls_the_validator() {
        let (_dir, mut state) = fresh();
        let feed = TestFeed::new(4);
        follow_to(&mut state, &feed, 3);

        // Served up to message 3, head signed at message 4: the validator has
        // nothing it can compare.
        for poll in 1..=UNCHECKED_POLLS_BEFORE_STALL {
            let outcome = ingest(&mut state, Some(&feed.session), Some(&feed.head(4)), &[]);
            assert_eq!(
                outcome,
                Ingest::Unchecked(Unchecked::HeadDoesNotCover {
                    signed_at: 4,
                    served_to: 3
                })
            );
            assert_eq!(state.unchecked_polls, poll);
            assert_eq!(state.stalled(), poll >= UNCHECKED_POLLS_BEFORE_STALL);
        }

        let attestation = state.attest();
        assert!(attestation.stalled);
        assert!(!attestation.disputed);
        assert_eq!(
            attestation.last_id, 3,
            "a stalled validator still vouches for what it checked"
        );

        // The stall flag is inside the signature: nobody can edit it out.
        let public = state.signing_key.verifying_key();
        let signature = Signature::from_bytes(
            &logchain::from_hex::<64>(&attestation.signature).expect("signature is hex"),
        );
        let chain = logchain::from_hex::<32>(&attestation.chain).expect("chain is hex");
        assert!(logchain::verify_attest(
            &public,
            &attestation.session,
            attestation.last_id,
            &chain,
            &AttestStatus {
                disputed: false,
                stalled: true
            },
            &signature
        ));
        assert!(
            !logchain::verify_attest(
                &public,
                &attestation.session,
                attestation.last_id,
                &chain,
                &AttestStatus::default(),
                &signature
            ),
            "the stall could be stripped out of the attestation"
        );

        // One poll the validator can check, and it is current again.
        let outcome = ingest(
            &mut state,
            Some(&feed.session),
            Some(&feed.head(4)),
            &feed.since(3, 4),
        );
        assert_eq!(outcome, Ingest::Verified(4));
        assert!(!state.stalled());
        assert_eq!(state.unchecked_polls, 0);
    }

    /// A sequencer nobody can reach is a sequencer nobody can check.
    #[test]
    fn polls_with_no_answer_count_toward_the_stall() {
        let (_dir, mut state) = fresh();
        let feed = TestFeed::new(1);
        follow_to(&mut state, &feed, 1);

        for _ in 0..UNCHECKED_POLLS_BEFORE_STALL {
            state.unchecked(Unchecked::NoAnswer);
        }
        assert!(state.stalled());
        assert!(state.attest().stalled);
        assert_eq!(state.cursor, 1);
    }

    /// An unsigned response proves nothing, so the validator does not hash it
    /// into the chain.
    #[test]
    fn a_response_without_a_signed_head_is_not_followed() {
        let (_dir, mut state) = fresh();
        let feed = TestFeed::new(2);

        let outcome = ingest(&mut state, Some(&feed.session), None, &feed.since(0, 2));

        assert_eq!(outcome, Ingest::Unchecked(Unchecked::NoSignedHead));
        assert_eq!(state.cursor, 0);
        assert_eq!(state.chain, EMPTY_CHAIN);
    }

    /// Finding 4: the verdict is the whole product of this service. A restart
    /// that forgot the verdict would put the validator back to vouching for a
    /// history it had already caught being forged.
    #[test]
    fn a_dispute_survives_a_restart_and_only_an_operator_clears_it() {
        let dir = TempDir::new().expect("temp dir");
        let feed = TestFeed::new(3);
        let db = dir.path().join("validator.db");

        {
            let mut state = open_at(&dir, "validator.db");
            follow_to(&mut state, &feed, 3);

            // The sequencer signs, under its own key, a chain hash that its
            // messages do not produce.
            let forged = feed.head_claiming(3, chain_of(&[message(9), message(9)]));
            let outcome = ingest(&mut state, Some(&feed.session), Some(&forged), &[]);

            assert_eq!(outcome, Ingest::Disputed);
            assert!(state.disputed);
            assert!(state.dispute_reason.is_some());
            state.save().expect("state saves");
        }

        // The restart.
        let state = open_at(&dir, "validator.db");
        assert!(state.disputed, "a restart cleared the dispute");
        assert_eq!(state.cursor, 3, "the last position it could vouch for");
        assert!(
            state.dispute_reason.is_some(),
            "the reason must outlive the process"
        );
        let attestation = state.attest();
        assert!(attestation.disputed);

        // The dispute is inside the signature too.
        let public = state.signing_key.verifying_key();
        let signature = Signature::from_bytes(
            &logchain::from_hex::<64>(&attestation.signature).expect("signature is hex"),
        );
        let chain = logchain::from_hex::<32>(&attestation.chain).expect("chain is hex");
        assert!(!logchain::verify_attest(
            &public,
            &attestation.session,
            attestation.last_id,
            &chain,
            &AttestStatus::default(),
            &signature
        ));
        drop(state);

        assert!(clear_dispute(&db).expect("clearing works"));
        assert!(
            !clear_dispute(&db).expect("clearing works"),
            "nothing left to clear"
        );
        let state = open_at(&dir, "validator.db");
        assert!(!state.disputed);
        assert_eq!(
            state.cursor, 3,
            "clearing a dispute does not rewind the cursor"
        );
    }

    /// The stall count is written to disk for the same reason the dispute is:
    /// a restart must not be a way to make a validator that cannot check the
    /// sequencer look healthy.
    #[test]
    fn the_unchecked_poll_count_survives_a_restart() {
        let dir = TempDir::new().expect("temp dir");
        {
            let mut state = open_at(&dir, "validator.db");
            for _ in 0..UNCHECKED_POLLS_BEFORE_STALL {
                state.unchecked(Unchecked::NoAnswer);
            }
            assert!(state.stalled());
            state.save().expect("state saves");
        }
        let state = open_at(&dir, "validator.db");
        assert_eq!(state.unchecked_polls, UNCHECKED_POLLS_BEFORE_STALL);
        assert!(state.stalled());
        assert!(state.attest().stalled);
    }

    /// A database written before the dispute columns existed still opens, and
    /// gains them.
    #[test]
    fn an_older_database_is_migrated_in_place() {
        let dir = TempDir::new().expect("temp dir");
        let db = dir.path().join("old.db");
        {
            let conn = Connection::open(&db).expect("database opens");
            conn.execute_batch(
                "CREATE TABLE validator_state (
                   id          INTEGER PRIMARY KEY CHECK (id = 1),
                   session     TEXT,
                   feed_pubkey TEXT,
                   cursor      INTEGER NOT NULL,
                   chain       BLOB    NOT NULL
                 );
                 INSERT INTO validator_state (id, session, feed_pubkey, cursor, chain)
                 VALUES (1, 'old-session', NULL, 7, zeroblob(32));",
            )
            .expect("the old schema is created");
        }

        let mut state = open_validator_db(&db, logchain::ephemeral_key())
            .expect("an older database still opens");
        assert_eq!(state.cursor, 7);
        assert_eq!(state.session.as_deref(), Some("old-session"));
        assert!(!state.disputed);
        state.dispute("checked by hand".to_string());
        state.save().expect("saving works after the migration");

        let state = open_validator_db(&db, logchain::ephemeral_key()).expect("reopens");
        assert!(state.disputed);
    }
}
