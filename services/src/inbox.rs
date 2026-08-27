//! A second way to submit an order, which the sequencer does not control (V3
//! of the roadmap).
//!
//! V2 made a change to *sequenced* history detectable. V2 could not stop the
//! sequencer from refusing a message before the message is sequenced. Nobody
//! else sees that refusal, so nobody can prove it. This service closes as much
//! of that gap as can be closed without a base chain:
//!
//! - users submit orders here, to a separate process with its own database.
//!   This service writes what was asked and when to disk, and only then
//!   answers;
//! - the sequencer must empty this service: every pending entry must be
//!   sequenced within the inclusion deadline;
//! - `GET /status` reports an entry still pending past the deadline as
//!   `overdue`. The sequencer's signed head provably does not contain that
//!   entry. The two together are evidence of censorship a third party can
//!   check.
//!
//! On a blockchain this service is a contract, the record is backed by the
//! validators that agree on it, and a late entry triggers a penalty. On one
//! machine this service is a neutral process and the penalty is an alarm. The
//! mechanism is the same: intake nobody else controls, forced inclusion, and a
//! violation that can be proved.
//!
//! # Who may mark an entry sequenced
//!
//! `POST /mark` is the only way an entry leaves the pending set. So
//! `POST /mark` is the one call that can make the evidence disappear. Left
//! open, it undoes the whole service. Anyone who knows an entry id could mark
//! that entry against a sequencer message that does not exist. `GET /status`
//! would then report `pending: 0, overdue: []` for a submission the sequencer
//! never sequenced.
//!
//! So a mark is authenticated, and it carries its own proof. The sequencer
//! signs the mark with the same Ed25519 key it signs its heads with
//! (`feed.key`). The mark carries the message's **stored bytes** together with
//! an RFC 9162 inclusion proof against a signed tree head. Before this service
//! writes anything it checks:
//!
//! 1. the mark's signature verifies under the sequencer key this service has
//!    pinned;
//! 2. the tree head's signature verifies under that same key, so the root the
//!    proof lands on is one the sequencer really committed to. A proof checked
//!    against a root nobody signed always succeeds and proves nothing;
//! 3. the inclusion proof lands on that root, for leaf `feed_id - 1`. This
//!    step hashes bytes and reads nothing else, so it works for a message kind
//!    this build has never heard of;
//! 4. the message's own id is the `feed_id` the mark claims. The message's
//!    account and nonce are the account and nonce of the submission this entry
//!    holds. One account never has two entries under one nonce, so that pair
//!    says which entry a message belongs to. See `message_matches`. All three
//!    values are read out of the bytes without knowing the kind;
//! 5. the message says what the user submitted: same account, symbol, side,
//!    price and quantity, or same account and target for a cancel, **when
//!    this build can read the kind.**
//!
//! Step 5 is the only step that can be skipped. A skipped step 5 is a third
//! outcome, not a failure. See `Confirmation`.
//!
//! The stored bytes are kept with the entry, exactly as they arrived and
//! without being serialised again. The record is then checkable later against
//! the sequencer's own signed history. If sequencer message `feed_id` in that
//! history is not these bytes, this service holds the sequencer's signature on
//! a claim the sequencer's own log contradicts. The stored bytes are also what
//! lets an upgraded build come back and make the content comparison an older
//! build could not.
//!
//! The key is pinned once. The key comes from `--feed-key`. If the operator
//! gave none, the key comes from the sequencer's `GET /head` on first contact,
//! after a check that the head really is signed by the key it carries. The pin
//! is stored in the database, so a restart keeps trusting the same sequencer.
//! With no key and no reachable sequencer this service refuses every mark.
//! Entries then stay pending and go late, which is the visible failure, not
//! the silent one.
//!
//! # Who may submit as an account
//!
//! Every submission carries an Ed25519 public key and a signature over what is
//! being asked. The signed part is account, symbol, side, price and quantity
//! for an order, and account and target for a cancel
//! (`submission_statement`). The account's key is pinned on first use, in
//! `inbox_accounts`. After that, a submission naming that account is only
//! accepted under the pinned key.
//!
//! The key is trusted on first use, for the same reason the sequencer key
//! above is pinned that way. There is no registry to check a key against, and
//! no certificate authority in this system. A list of account keys held by the
//! operator would give the operator a way to censor at intake: refuse to
//! register an account, and that account cannot submit. That is the exact
//! power this service exists to take away.
//!
//! Every ownership rule downstream rests on this pin. `matcher.rs`'s
//! cancel-ownership check ("the order belongs to account N") and `verify.rs`'s
//! `cancel_takes_effect` compare account numbers carried on sequencer
//! messages. Those numbers now mean "the holder of account N's key asked for
//! this", because nothing else can get a message with account N into the log.
//!
//! The sequencer checks the same signature again when it drains an entry
//! (`sequence_drained`), against its own pin. The sequencer has to.
//! `--inbox-url` is a plain flag that can point at anything, and the sequencer
//! signs what it sequences. This service's word that a submission was
//! authenticated is not evidence to the party that must stand behind the
//! result.
//!
//! # When the sequencer refuses to sequence an entry
//!
//! Not every entry the sequencer leaves pending is censorship. Two refusals
//! are the submitter's own doing: a nonce reused for two different
//! submissions, and an account whose key reached the sequencer and this
//! service in a different order. The sequencer keeps both reasons to itself.
//! The reason reaches the sequencer's own log and nothing else. So a mistake
//! by the submitter and real censorship both show up here as a plain late
//! entry with no explanation, and that is all this service reports about them.
//! Nothing stops a dishonest sequencer from having a reason for an entry it
//! refused. This service does not decide who is right, and the alarm stays up
//! either way.
//!
//! # Replay
//!
//! Every signed statement carries a nonce the submitter chose. The sequencer
//! enforces that one `(account, nonce)` pair produces at most one sequencer
//! message, over its whole published history. A captured submission sent again
//! to either path therefore cannot become a second order. The sequencer is the
//! only enforcement point, because the sequencer is the only party that
//! creates messages. The check this service does on `POST /submit` is a cheap
//! intake filter, not the correctness boundary. See `submission_statement` and
//! `feed.rs`'s `nonces` map.

use axum::{
    Json, Router,
    extract::{ConnectInfo, FromRequestParts, Query, State, rejection::JsonRejection},
    http::{HeaderValue, StatusCode, request::Parts},
    routing::{get, post},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{Level, error, info, warn};
use tracing_subscriber::FmtSubscriber;

use crate::cors::{self, CorsPolicy};
use crate::domain::{
    AccountId, MAX_GRID_UNITS, OrderId, OrderMessage, OrderType, Side, TimeInForce, not_post_only,
    to_grid,
};
use crate::logchain;
use crate::merkle;
use crate::operator::valid_symbol;
use crate::sqlite;
use crate::wire;

/// How long the sequencer has to include a pending entry before this service
/// calls the entry late. The operator can set another value.
pub const DEFAULT_DEADLINE_MS: u64 = 5_000;

/// The most entries any one response returns. `GET /pending` and
/// `GET /entries` apply this limit *in SQL*. A large database then costs a
/// bounded query, not a full table read that is cut down in memory afterwards.
///
/// The sequencer drains oldest first and comes back every tick. A limited page
/// still empties this service; it takes more ticks.
pub const PAGE_LIMIT: usize = 200;

/// The response header that names this service's epoch, sent with
/// `GET /pending`.
///
/// The epoch names one `inbox.db`, the way the sequencer's session names one
/// sequencer history. The epoch is created once per `inbox.db` and survives a
/// restart, because the entries survive with it. The epoch changes exactly
/// when the database is new or was deleted.
///
/// The sequencer needs the epoch because `inbox_id` restarts at 1 with a new
/// database. Without an epoch, the sequencer's record "entry 1 became
/// sequencer message 7" applies to the *new* entry 1, whose submission is
/// something else. The sequencer then marks the new entry 1 with a message the
/// user never submitted. This service refuses that mark as a content mismatch,
/// and the entry can never be sequenced. Nothing recovers from that state.
/// Keyed by epoch, the new entry 1 has no record and is sequenced normally.
pub const PENDING_EPOCH_HEADER: &str = "x-inbox-epoch";

/// The most entries allowed to be pending at once. At this count,
/// `POST /submit` refuses with 503. The alternative is to let anyone grow
/// `inbox.db` without limit. Growth without limit slows down every
/// `GET /status` and every drain tick, and that is one way real censorship
/// evidence becomes hard to find.
///
/// The refusal is visible on purpose. A service that refuses submissions
/// is itself a failure of the independent submission path. `GET /status`
/// reports this cap beside the pending count, so a third party can see which
/// limit they reached.
pub const MAX_PENDING: i64 = 5_000;

/// The submission rate limit per caller: at most this many submissions from
/// one IP address per `SUBMIT_WINDOW`. The number is high on purpose. A hard
/// limit on the independent submission path is another form of censorship. The
/// number is still low enough that one client cannot fill the pending set in
/// one burst.
///
/// `feed.rs` enforces the same two numbers on its own `POST /order` and
/// `POST /cancel`. One definition, deliberately. If the sequencer's own
/// endpoints allowed more, the limit here would only push callers onto the
/// path the sequencer controls.
pub(crate) const SUBMIT_BURST: usize = 120;
pub(crate) const SUBMIT_WINDOW: Duration = Duration::from_secs(10);

/// The most mark rejections kept in the database. Only a mark that carries a
/// valid sequencer signature writes a rejection row, so a stranger cannot fill
/// the table. This cap bounds a sequencer that misbehaves.
const MAX_REJECTIONS: i64 = 1_000;

/// The price step and the quantity step of the matching engine. A price is a
/// whole number of cents. A quantity is a whole number of tenths. Neither may
/// exceed `domain::MAX_GRID_UNITS` units. These two numbers are the `scale`
/// argument that `domain::to_grid` takes. The exchange, this service and the
/// checker all read a price with that one function.
pub(crate) const PRICE_SCALE: f64 = 100.0;
pub(crate) const QUANTITY_SCALE: f64 = 10.0;

/// One thing a user can ask the exchange to do. This service accepts it, and
/// the sequencer sequences it later.
///
/// `nonce` is 32 lowercase hex characters the submitter picks (see
/// `new_nonce`). The nonce is part of the signed statement, and part of the
/// sequencer message the submission becomes. The nonce is what separates one
/// submission from a replay of the same submission. The sequencer refuses a
/// second message for an `(account, nonce)` pair it has already published one
/// for.
///
/// `session` names the log this submission is for. It is the sequencer's own
/// session, as `GET /head` and the `x-feed-session` header report it. It is
/// part of the signed statement, so the same signed bytes cannot be replayed
/// into a different log, or into the same log after it was emptied and got a
/// new session. The operator statements put the session on the same line for
/// the same reason. See `operator.rs`.
///
/// The session is carried on the submission and not beside it. That is what
/// lets `submission_statement` build the statement from the submission alone,
/// so both submission paths verify a signature without having to know which
/// log is current. Whether the session *is* the current one is a separate
/// question, and only the sequencer can answer it. See the note on
/// `checked_session`.
///
/// `nonce` and `session` are both `Option` for one reason. A `Submission` read
/// back from an `inbox.db` written before either field existed must still
/// decode, so this service can report the entry. Such an entry has no v3
/// statement, so `validate_submission` refuses it by name instead of letting
/// it fail as an unreadable row.
///
/// # The three order terms
///
/// `order_type`, `time_in_force` and `post_only` are the terms
/// `OrderMessage::New` carries, with the same defaults and the same
/// absent-means-default rule. A submission that names none of them serializes
/// to exactly the bytes it did before they existed, so a row already in an
/// `inbox.db` reads back unchanged.
///
/// The signed statement is not like the wire. It always prints all three, even
/// when they hold their defaults. See `submission_statement`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Submission {
    Order {
        account: AccountId,
        symbol: String,
        side: Side,
        price: f64,
        quantity: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<String>,
        #[serde(default, skip_serializing_if = "OrderType::is_limit")]
        order_type: OrderType,
        #[serde(default, skip_serializing_if = "TimeInForce::is_good_till_cancel")]
        time_in_force: TimeInForce,
        #[serde(default, skip_serializing_if = "not_post_only")]
        post_only: bool,
    },
    Cancel {
        account: AccountId,
        target_id: OrderId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<String>,
    },
}

/// A submission, with the proof that the account named in it asked for it.
///
/// This is the request body of `POST /submit`, and what this service stores.
/// The entry keeps the user's own signature. So "account 7 asked for this" is
/// checkable later by anyone who holds the entry, not only by the service that
/// accepted it. `MarkRequest` has the same shape. `MarkRequest` carries the
/// sequencer message it proves, not a bare signature over an id.
///
/// # Replay
///
/// The statement covers a nonce the submitter chose. The sequencer publishes
/// at most one message per `(account, nonce)` over its whole history. So a
/// resend of captured bytes cannot produce a second order. Two cheaper
/// defences were rejected. The first is a highest-seen sequence number per
/// account. It refuses an entry the sequencer drains *after* a direct
/// submission with a higher number. The entry then stays pending and is
/// reported late, which is a false censorship alarm. The second is a plain set
/// of the signatures already seen. It has the same problem. It refuses the
/// entry whose signature was already published on the direct path, instead of
/// seeing that the entry is satisfied by that message. This design resolves
/// that case instead of refusing it, and that is what makes the nonce rule
/// safe to use here. See `sequence_drained`.
///
/// The nonce covers one log. The session covers which log, and it is the
/// second line of the statement. Uniqueness is enforced over the published
/// history, and an emptied database is a new history under a new session, so
/// without the session a submission captured before a reset would still be
/// good after it. The sequencer checks the session, because the sequencer is
/// the only party that knows which log is running. See `checked_session`.
///
/// There is deliberately no expiry and no validity window on the wall clock.
/// The published history is never pruned, so there is nothing to forget. A
/// rule based on time, evaluated when the sequencer drains a pending entry,
/// has a hole. A stalled sequencer can wait out the window and then
/// "correctly" refuse an entry that was never a replay. That is a false
/// censorship alarm, which in this system is worse than the hole such a rule
/// would close.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSubmission {
    pub submission: Submission,
    /// The account's Ed25519 public key, in hex. This service pins the key on
    /// this account's first submission. Every later submission for the account
    /// must carry the same key.
    pub public_key: String,
    /// Ed25519 signature over `submission_statement`, in hex.
    pub signature: String,
}

/// One entry, as served to the sequencer and to auditors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub inbox_id: i64,
    /// When this service wrote the submission to disk and accepted it. The
    /// inclusion clock starts here.
    pub received_at: u64,
    pub submission: Submission,
    /// The key the submission was signed under, and the signature, exactly as
    /// the submitter sent them. They stay with the entry for two reasons. The
    /// sequencer checks them against its own pin when it drains. The record
    /// then proves who asked.
    pub public_key: String,
    pub signature: String,
    /// The sequencer message this entry became, once the sequencer included
    /// the entry.
    pub feed_id: Option<OrderId>,
    pub sequenced_at: Option<u64>,
    /// Whether the fields of that message were compared against this
    /// submission, or only the message's inclusion and nonce were. See
    /// `Confirmation`.
    ///
    /// `None` while the entry is still pending. `None` also for an entry that
    /// was marked before this column existed. Such a row predates the
    /// question, and is not an answer to it. Read this field beside `feed_id`:
    /// `feed_id` set with `content_checked` `None` is such a row.
    ///
    /// `serde(default)` so a sequencer reads the entries of a service built
    /// before this field existed, instead of refusing the whole page.
    #[serde(default)]
    pub content_checked: Option<bool>,
}

impl Entry {
    /// The submission and its proof, as they were submitted and stored.
    pub fn signed(&self) -> SignedSubmission {
        SignedSubmission {
            submission: self.submission.clone(),
            public_key: self.public_key.clone(),
            signature: self.signature.clone(),
        }
    }
}

/// The clock this service uses.
///
/// This service reads the wall clock exactly once, at startup. Every timestamp
/// after that is that one reading plus the time elapsed on a monotonic
/// `Instant`. Both `received_at` and the deadline comparison come from here.
/// Inside one run of the process the two are on the same timeline, and a jump
/// in the wall clock cannot move one against the other.
///
/// That matters because a jump in either direction breaks the alarm. A clock
/// moved backwards makes `now - received_at` clamp to zero. Real evidence of a
/// late entry is then hidden for as long as the jump lasts. An NTP correction,
/// a resumed virtual machine, or an operator who wants the alarm quiet all
/// move the clock backwards. A clock moved forwards reports every entry late
/// at once.
///
/// Entries carried over from an earlier run of the process are the one case
/// this clock cannot cover. Their `received_at` came from that run's wall
/// clock, and no monotonic clock survives a restart. A jump between runs still
/// distorts how long those entries appear to have waited.
///
/// `feed.rs` stamps its message timestamps from the same clock, for the same
/// reasons, and to keep one definition of "now" in the system.
pub(crate) struct Clock {
    wall_base_ms: u64,
    mono_base: Instant,
}

impl Clock {
    pub(crate) fn from_wall(wall_base_ms: u64) -> Self {
        Self {
            wall_base_ms,
            mono_base: Instant::now(),
        }
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.wall_base_ms
            .saturating_add(self.mono_base.elapsed().as_millis() as u64)
    }
}

/// Reads the wall clock. `None` means the system clock is before 1970. That is
/// a broken host, not a timestamp. The caller refuses to start instead of
/// falling back to zero. Zero would make every entry read as 1.7e12
/// milliseconds late, forever.
pub(crate) fn wall_clock_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}

/// Counts submissions per caller, in a fixed window. The counts stay in
/// memory. The purpose is to bound one burst, and a restart that clears the
/// counts costs nothing.
pub(crate) struct RateLimiter {
    seen: HashMap<IpAddr, (Instant, usize)>,
}

impl RateLimiter {
    pub(crate) fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    pub(crate) fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        // Drop old addresses only when the map has grown. The common path is
        // then one lookup.
        if self.seen.len() > 10_000 {
            self.seen
                .retain(|_, (start, _)| now.duration_since(*start) < SUBMIT_WINDOW);
        }
        let counter = self.seen.entry(ip).or_insert((now, 0));
        if now.duration_since(counter.0) >= SUBMIT_WINDOW {
            *counter = (now, 0);
        }
        counter.1 += 1;
        counter.1 <= SUBMIT_BURST
    }
}

// ---------------------------------------------------------------------------
// Which address a caller is rate limited on
// ---------------------------------------------------------------------------
//
// The limiter above needs one address per caller. The socket peer address is
// that address when a client connects to this service directly. When a client
// does not connect directly, the socket peer address is the *proxy*. Behind
// Traefik every visitor and the bot arrive from the proxy's address. They then
// share one count of `SUBMIT_BURST` and block each other.
//
// `X-Forwarded-For` carries the original client. Believing that header without
// a condition is worse than the shared count. Anyone can write that header, so
// anyone could give themselves a fresh count on every request, and the limit
// would do nothing. Two facts decide when the header is evidence:
//
// - a proxy appends to the header. A client that sends
//   `X-Forwarded-For: 1.2.3.4` produces `1.2.3.4, <the address the proxy saw>`
//   after the proxy adds what it saw. The leftmost entry is whatever the
//   client chose. The rightmost entry is what a machine observed. Reading left
//   to right is the common mistake, and it reads exactly the value an attacker
//   picked;
// - the header is evidence only when the request came from a proxy this
//   operator named. From anywhere else the header is a string a stranger
//   typed.
//
// So the rule has three parts. With no trusted proxy configured, this service
// never reads the header. When the peer is a trusted proxy, this service walks
// the chain from right to left, past any further trusted proxies, and takes
// the first entry that is not one. Anything unreadable falls back to the
// socket address, which is stricter than the truth and never looser.

/// The header a reverse proxy records the original client address in.
pub(crate) const FORWARDED_FOR: &str = "x-forwarded-for";

/// One address, or one network, whose `X-Forwarded-For` this service believes.
///
/// `base` always has every bit below `prefix` cleared. `TrustedProxies::parse`
/// refuses a value that does not. A match here is then one masked comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProxyNet {
    base: IpAddr,
    prefix: u32,
}

impl ProxyNet {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(base), IpAddr::V4(ip)) => mask_v4(ip, self.prefix) == base,
            (IpAddr::V6(base), IpAddr::V6(ip)) => mask_v6(ip, self.prefix) == base,
            // An IPv4 address is not inside an IPv6 network, and an IPv6
            // address is not inside an IPv4 network. `canonical_ip` has
            // already rewritten ::ffff:1.2.3.4 as 1.2.3.4 on both sides, so
            // what is left here is a real difference.
            _ => false,
        }
    }
}

impl fmt::Display for ProxyNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.base, self.prefix)
    }
}

/// Clears every bit below the prefix. `prefix` is 0..=32, checked at parse
/// time. The zero case is written out on its own, because a shift of a `u32`
/// by 32 is not defined.
fn mask_v4(ip: Ipv4Addr, prefix: u32) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    Ipv4Addr::from(u32::from(ip) & (u32::MAX << (32 - prefix)))
}

/// The same for IPv6, with `prefix` 0..=128.
fn mask_v6(ip: Ipv6Addr, prefix: u32) -> Ipv6Addr {
    if prefix == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    Ipv6Addr::from(u128::from(ip) & (u128::MAX << (128 - prefix)))
}

/// The one spelling every address is compared in.
///
/// A dual-stack listener reports an IPv4 client as `::ffff:127.0.0.1`. A proxy
/// writes the same client into `X-Forwarded-For` as `127.0.0.1`. They are one
/// address. A rate limiter that treats them as two gives the same caller two
/// counts.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// The addresses whose `X-Forwarded-For` this service believes: the reverse
/// proxy it runs behind, and nothing else.
///
/// The list is empty unless the operator passes `--trusted-proxy`. An empty
/// list means the socket peer address is the caller, and the header is never
/// read. That is exactly what these services did before this list existed. A
/// deployment that forgets the flag is no worse off than before, and is never
/// permissive by accident.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies {
    nets: Vec<ProxyNet>,
}

impl TrustedProxies {
    /// Trusts no address. This is the default, and what every test that is not
    /// about proxies uses.
    pub fn none() -> Self {
        Self { nets: Vec::new() }
    }

    /// Reads every `--trusted-proxy` value, refusing the whole list if one is
    /// not an address or a network.
    ///
    /// The refusal happens at startup, and the bad entry is not skipped. This
    /// is the reason `parse_ui_origins` gives. An operator who mistyped their
    /// proxy's address would otherwise learn about it from a visitor who
    /// cannot submit. The two ways to be wrong without any message, matching
    /// nothing and matching everything, are exactly the two failures that
    /// matter here.
    ///
    /// An entry that is empty after trimming is dropped. So
    /// `--trusted-proxy ''` means "none" and does not stop the start.
    pub fn parse(specs: &[String]) -> Result<Self, String> {
        let mut nets: Vec<ProxyNet> = Vec::new();
        for spec in specs {
            let spec = spec.trim();
            if spec.is_empty() {
                continue;
            }
            let net = parse_trusted_proxy(spec)?;
            if !nets.contains(&net) {
                nets.push(net);
            }
        }
        Ok(Self { nets })
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// Answers whether this address is one of the proxies.
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        self.nets.iter().any(|net| net.contains(ip))
    }

    /// What the operator configured, as one line for the startup log.
    pub fn describe(&self) -> String {
        if self.nets.is_empty() {
            return "(none)".to_string();
        }
        self.nets
            .iter()
            .map(ProxyNet::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Reads one `--trusted-proxy` value: an address (`172.17.0.3`) or a network
/// in prefix form (`172.17.0.0/16`).
///
/// A prefix is allowed, and not only an exact address, because the proxy is a
/// Docker container. The container's address comes out of a bridge network and
/// can change when the container restarts. An exact address therefore gives a
/// deployment that breaks on a restart and falls back to one shared count for
/// everybody. The match is a masked comparison of two integers, `mask_v4`
/// above, so this code is written here instead of adding a dependency for it.
///
/// Bits set below the prefix are refused, and not masked away.
/// `172.17.0.5/16` is how an operator writes the address they observed while
/// they mean one host. Reading that value without a message as "every address
/// in 172.17.0.0/16" would trust 65,536 addresses.
fn parse_trusted_proxy(spec: &str) -> Result<ProxyNet, String> {
    let (addr_text, prefix_text) = match spec.split_once('/') {
        Some((addr, prefix)) => (addr.trim(), Some(prefix.trim())),
        None => (spec, None),
    };
    let Ok(addr) = addr_text.parse::<IpAddr>() else {
        return Err(format!(
            "--trusted-proxy {}: {:?} is not an IP address. Give the address the proxy connects \
             from, or the network it is on, for example 172.17.0.0/16",
            spec, addr_text
        ));
    };
    // ::ffff:172.17.0.3 and 172.17.0.3 are one address. The prefix after the
    // address is read in the family of this one spelling.
    let addr = canonical_ip(addr);
    let (bits, family) = match addr {
        IpAddr::V4(_) => (32, "IPv4"),
        IpAddr::V6(_) => (128, "IPv6"),
    };
    let prefix = match prefix_text {
        None => bits,
        Some(text) => match text.parse::<u32>() {
            Ok(prefix) => prefix,
            Err(_) => {
                return Err(format!(
                    "--trusted-proxy {}: {:?} is not a prefix length. Write it as a number of \
                     bits, for example 172.17.0.0/16",
                    spec, text
                ));
            }
        },
    };
    if prefix > bits {
        return Err(format!(
            "--trusted-proxy {}: /{} is longer than an {} address, which is {} bits",
            spec, prefix, family, bits
        ));
    }
    let base = match addr {
        IpAddr::V4(v4) => IpAddr::V4(mask_v4(v4, prefix)),
        IpAddr::V6(v6) => IpAddr::V6(mask_v6(v6, prefix)),
    };
    if base != addr {
        return Err(format!(
            "--trusted-proxy {} has bits set below the /{}, so it does not name the host {}: it \
             names every address in {}/{}. Write {}/{} if that is what you meant, or {} on its \
             own to trust that one host",
            spec, prefix, addr, base, prefix, base, prefix, addr
        ));
    }
    Ok(ProxyNet { base, prefix })
}

/// One `X-Forwarded-For` entry as an address, or `None` if it is not one.
///
/// Proxies write a bare address. The forms with a port are common enough to
/// read too: `1.2.3.4:5678`, and `[2001:db8::1]:5678` for IPv6. The brackets
/// are the only spelling that the colons inside an IPv6 address cannot make
/// ambiguous. Anything else is not an address, and this function does not
/// guess at it: RFC 7239's hidden identifiers (`_hidden`), `unknown`, and a
/// hostname.
fn parse_forwarded_entry(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    if let Some(rest) = entry.strip_prefix('[') {
        let (inside, _port) = rest.split_once(']')?;
        return Some(canonical_ip(IpAddr::V6(inside.parse::<Ipv6Addr>().ok()?)));
    }
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(canonical_ip(ip));
    }
    // `1.2.3.4:5678`. Only IPv4 reaches this line. A bare IPv6 address parsed
    // above, and an IPv6 address with a port must carry brackets.
    let (host, _port) = entry.rsplit_once(':')?;
    Some(canonical_ip(IpAddr::V4(host.parse::<Ipv4Addr>().ok()?)))
}

/// Who sent one request: the address the socket reports, and the
/// `X-Forwarded-For` values exactly as they arrived.
///
/// The two values are one type because neither answers "who is being rate
/// limited" on its own. The header is evidence only when the socket peer is a
/// proxy the operator trusts. A handler that could read one value without the
/// other is how the header gets believed by accident.
#[derive(Debug, Clone)]
pub(crate) struct Caller {
    pub(crate) peer: SocketAddr,
    /// Every `x-forwarded-for` header on the request, in the order they
    /// arrived. All of them are kept. Repeated headers are one list in HTTP,
    /// so reading only the first would let a second one hide the entry that
    /// decides the answer.
    forwarded: Vec<HeaderValue>,
}

impl Caller {
    /// The address this caller is rate limited on.
    ///
    /// With no trusted proxy configured, the answer is the socket peer
    /// address, and the header is not read at all. That is what these services
    /// did before the flag existed.
    pub(crate) fn client_ip(&self, trusted: &TrustedProxies) -> IpAddr {
        let peer = canonical_ip(self.peer.ip());
        if !trusted.contains(peer) {
            return peer;
        }
        let mut entries: Vec<&str> = Vec::new();
        for value in &self.forwarded {
            let Ok(text) = value.to_str() else {
                // Bytes that are not text are not an address list. A guess at
                // them is how a forged header gets believed.
                return peer;
            };
            entries.extend(text.split(',').map(str::trim));
        }
        // Right to left. The proxy this request really came from wrote the
        // rightmost entry. Everything to the left of that entry is whatever
        // the client sent. So the leftmost entry, the one a left-to-right
        // reader takes, is the attacker's own choice.
        for entry in entries.iter().rev() {
            let Some(ip) = parse_forwarded_entry(entry) else {
                // A chain that cannot be read stops here. The walk does not
                // continue past it, because the next entry to the left is
                // exactly where a forged value sits.
                return peer;
            };
            if !trusted.contains(ip) {
                return ip;
            }
        }
        // No header, an empty header, or nothing but trusted proxies in it.
        // The proxy is then the closest thing to a caller there is. Everyone
        // behind that proxy shares one count, which is stricter than the truth
        // and never looser.
        peer
    }

    /// A caller with no forwarded header. Tests only. In a running service a
    /// `Caller` is only built from a real request.
    #[cfg(test)]
    pub(crate) fn from_socket(peer: &str) -> Self {
        Self::with_forwarded(peer, &[])
    }

    /// A caller arriving from `peer` with these `X-Forwarded-For` headers.
    #[cfg(test)]
    pub(crate) fn with_forwarded(peer: &str, forwarded: &[&str]) -> Self {
        Self::with_forwarded_bytes(
            peer,
            &forwarded.iter().map(|v| v.as_bytes()).collect::<Vec<_>>(),
        )
    }

    /// The same builder, for a header value that is not text.
    #[cfg(test)]
    pub(crate) fn with_forwarded_bytes(peer: &str, forwarded: &[&[u8]]) -> Self {
        Self {
            peer: peer.parse().expect("a socket address"),
            forwarded: forwarded
                .iter()
                .map(|v| HeaderValue::from_bytes(v).expect("a header value"))
                .collect(),
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Caller {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ConnectInfo(peer) = ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
            .await
            .map_err(|_| {
                // This line is reachable only if a server is built without
                // `into_make_service_with_connect_info`. There is no address
                // to rate limit on then. An answer anyway would put every
                // caller in the world under one count.
                error!(
                    "a request arrived with no peer address, so it cannot be rate limited per \
                     caller; refusing it"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "this service could not see the address this request came from".to_string(),
                )
            })?;
        Ok(Self {
            peer,
            forwarded: parts
                .headers
                .get_all(FORWARDED_FOR)
                .iter()
                .cloned()
                .collect(),
        })
    }
}

/// Writes which addresses this service believes a forwarded header from. Both
/// services use this one wording at startup. Both services rate limit, and an
/// operator who compares two log files should not have to compare two
/// sentences.
pub fn log_trusted_proxies(trusted: &TrustedProxies) {
    if trusted.is_empty() {
        info!(
            "no --trusted-proxy: callers are rate limited on the address the socket reports, and \
             X-Forwarded-For is ignored. Behind a reverse proxy that is one bucket for everybody"
        );
    } else {
        info!(
            "X-Forwarded-For is believed from {}, and ignored from every other address",
            trusted.describe()
        );
    }
}

/// Writes one line at startup when a service was told to listen on more than
/// this machine. `exposes` names what becomes reachable, because that differs
/// per service. The sequencer and this service take submissions. The exchange
/// and a validator only answer reads.
///
/// This is a warning and not a refusal. A container behind a reverse proxy
/// needs to bind every address. A process bound to `127.0.0.1` inside its own
/// network namespace cannot be reached from the proxy's namespace. The proxy
/// then gets a refused connection and the service looks down. The same flag
/// typed on a host is a different deployment with the same spelling, and that
/// deployment should not happen without a line in the log.
pub fn warn_if_public(addr: SocketAddr, exposes: &str) {
    if addr.ip().is_loopback() {
        return;
    }
    warn!(
        "listening on {}, which is not only this machine: anything that can route to this \
         address reaches {}. That is the point inside a container behind a reverse proxy. \
         Directly on a host it is published to whatever network that host is on",
        addr, exposes
    );
}

/// Everything this service holds.
///
/// `pub(crate)` only because `inbox_router` names the type, and the
/// sequencer's tests build routers the same way.
pub(crate) struct InboxState {
    conn: Connection,
    deadline_ms: u64,
    clock: Clock,
    /// Names this `inbox.db`. Served with `GET /pending` and carried in every
    /// mark. See `PENDING_EPOCH_HEADER`.
    epoch: String,
    /// The only key whose marks this service accepts. `None` until a key is
    /// pinned. While the field is `None` every mark is refused.
    feed_key: Option<VerifyingKey>,
    /// Where to fetch the sequencer key from, if the operator configured no
    /// key.
    feed_url: Option<String>,
    limiter: RateLimiter,
    /// The proxies whose `X-Forwarded-For` this service believes when it
    /// decides which caller a submission is limited against. Empty by default.
    /// See `TrustedProxies`.
    trusted_proxies: TrustedProxies,
    /// Rows in the database that could not be decoded into an entry.
    /// `GET /status` reports the count. A row that cannot be read disappears
    /// from `/pending`, from `/entries` and from the late list at the same
    /// time, so its absence has to be counted somewhere.
    unreadable_entries: u64,
    /// Marks refused because the pinned sequencer key did not sign them. The
    /// count stays in memory and is not stored. Anyone can send such a mark,
    /// and one row per attempt would be a way to fill the disk.
    marks_unauthenticated: u64,
}

/// Starts this service.
///
/// The port is bound before the database is opened, for the same reason the
/// sequencer binds first. The port is the lock that stops a second copy of
/// this service from writing the same file.
///
/// `ui_origins` is the operator's `--ui-origin` list: the web origins whose
/// browsers may submit here. The exchange serves the trading UI, so the UI is
/// cross-origin to this service in every deployment: another port on one
/// machine, another hostname or path behind a reverse proxy. A browser sends
/// no submission until this service says which origins may.
pub async fn start_inbox(
    bind: IpAddr,
    port: u16,
    db: PathBuf,
    deadline_ms: u64,
    feed_key_hex: Option<String>,
    feed_url: Option<String>,
    trusted_proxies: TrustedProxies,
    ui_origins: Vec<String>,
) {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let addr = SocketAddr::new(bind, port);
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            error!(
                "could not bind inbox to {}: {} (is another inbox running? try --inbox-port)",
                addr, e
            );
            std::process::exit(2);
        }
    };
    warn_if_public(addr, "an unauthenticated order-submission endpoint");

    let Some(wall_base_ms) = wall_clock_ms() else {
        error!("the system clock is before 1970; the inclusion deadline cannot be measured");
        std::process::exit(2);
    };

    let conn = match open_inbox_db(&db) {
        Ok(conn) => conn,
        Err(e) => {
            error!("cannot use inbox database {}: {}", db.display(), e);
            std::process::exit(2);
        }
    };

    // The pinned sequencer key is what the operator gave. If the operator gave
    // none, it is what an earlier run pinned. A `--feed-key` that differs from
    // the stored pin replaces the stored pin, with a warning. Such a change
    // changes which sequencer this service works for.
    let stored_key_hex: Option<String> = conn
        .query_row(
            "SELECT value FROM inbox_meta WHERE key = 'feed_pubkey'",
            [],
            |row| row.get(0),
        )
        .optional()
        .unwrap_or(None);
    let feed_key = match (&feed_key_hex, &stored_key_hex) {
        (Some(given), stored) => {
            let Some(key) = parse_public_key(given) else {
                error!(
                    "--feed-key {} is not a 32-byte hex Ed25519 public key",
                    given
                );
                std::process::exit(2);
            };
            if let Some(stored) = stored {
                if stored != &logchain::to_hex(key.as_bytes()) {
                    warn!(
                        "--feed-key replaces the feed key this database had pinned ({}); \
                         marks signed by the old key will now be refused",
                        stored
                    );
                }
            }
            if let Err(e) = conn.execute(
                "INSERT OR REPLACE INTO inbox_meta (key, value) VALUES ('feed_pubkey', ?1)",
                params![logchain::to_hex(key.as_bytes())],
            ) {
                error!("could not record the pinned feed key: {}", e);
            }
            Some(key)
        }
        (None, Some(stored)) => match parse_public_key(stored) {
            Some(key) => Some(key),
            None => {
                error!(
                    "the pinned feed key in {} is not readable; marks will be refused until --feed-key is given",
                    db.display()
                );
                None
            }
        },
        (None, None) => None,
    };
    match &feed_key {
        Some(key) => info!("inbox trusts feed key {}", logchain::to_hex(key.as_bytes())),
        None => match &feed_url {
            Some(url) => info!(
                "no feed key configured: the inbox will pin the key {}/head serves on the first mark",
                url
            ),
            None => warn!(
                "no feed key and no feed URL: every POST /mark will be refused, so entries will \
                 stay pending and be reported overdue"
            ),
        },
    }

    // The epoch names this database. A database left here by an earlier run
    // keeps the epoch it was given. A new database, or one that was deleted
    // and recreated, gets a new epoch. That is exactly the case where
    // `inbox_id` 1 means a different submission than it did before.
    let epoch = match load_or_create_epoch(&conn) {
        Ok(epoch) => epoch,
        Err(e) => {
            error!(
                "cannot read or create this inbox's epoch in {}: {}",
                db.display(),
                e
            );
            std::process::exit(2);
        }
    };

    let pending: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM inbox_entries WHERE feed_id IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    info!(
        "inbox database {}: epoch {}, {} entries pending, inclusion deadline {}ms",
        db.display(),
        epoch,
        pending,
        deadline_ms
    );

    log_trusted_proxies(&trusted_proxies);

    let state = Arc::new(Mutex::new(InboxState {
        conn,
        deadline_ms,
        clock: Clock::from_wall(wall_base_ms),
        epoch,
        feed_key,
        feed_url,
        limiter: RateLimiter::new(),
        trusted_proxies,
        unreadable_entries: 0,
        marks_unauthenticated: 0,
    }));
    cors::log_ui_origins("inbox", &ui_origins);
    let app = inbox_router(state, ui_origins);

    info!("inbox listening on {}", addr);
    // The connection info is passed in because the rate limiter and the
    // rejection log both name the caller.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("inbox server stopped unexpectedly");
}

/// The paths a browser may send a preflight request to on this service: the
/// one path that takes submissions, and nothing else.
///
/// `POST /mark` is deliberately absent, although `POST /mark` also takes a
/// POST. `POST /mark` is the sequencer's call. It is answered only under the
/// pinned sequencer key, and it is the one call that can make censorship
/// evidence disappear. A preflight for it would let a web page try to mark
/// entries, and this service exists to stop that. The sequencer's drain is not
/// a browser and sends no `Origin`, so nothing about the drain changes.
const SUBMISSION_PATHS: [&str; 1] = ["/submit"];

/// Everything this service serves, behind the operator's `--ui-origin` list.
///
/// This function is separate from `start_inbox` so tests can drive the
/// cross-origin rules. Those rules live in a middleware layer, and a handler
/// called directly never runs a middleware layer.
///
/// This service needs the rules as much as the sequencer does, and for a
/// stronger reason. The person V3 exists for is remote by definition. An
/// operator does not need a second path around their own sequencer. So a
/// second path a browser cannot reach is a path only the operator can use.
pub(crate) fn inbox_router(state: Arc<Mutex<InboxState>>, ui_origins: Vec<String>) -> Router {
    crate::http_security::guard(
        cors::guard(
            Router::new()
                .route("/submit", post(submit))
                .route("/pending", get(get_pending))
                .route("/mark", post(mark))
                .route("/entries", get(get_entries))
                .route("/status", get(get_status))
                .with_state(state),
            CorsPolicy::new(ui_origins, &SUBMISSION_PATHS, "inbox"),
        ),
        crate::http_security::api(),
    )
}

/// Reads this database's epoch, and creates one the first time. The epoch is
/// stored beside the pinned sequencer key, so the epoch moves with the entries
/// it names.
fn load_or_create_epoch(conn: &Connection) -> Result<String, String> {
    let stored: Option<String> = conn
        .query_row(
            "SELECT value FROM inbox_meta WHERE key = 'epoch'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if let Some(epoch) = stored {
        return Ok(epoch);
    }
    let epoch = format!("{:016x}", rand::Rng::r#gen::<u64>(&mut rand::thread_rng()));
    conn.execute(
        "INSERT INTO inbox_meta (key, value) VALUES ('epoch', ?1)",
        params![epoch],
    )
    .map_err(|e| e.to_string())?;
    Ok(epoch)
}

/// Reads a 32-byte Ed25519 public key from hex: the sequencer's, or an
/// account's.
fn parse_public_key(hex: &str) -> Option<VerifyingKey> {
    VerifyingKey::from_bytes(&logchain::from_hex::<32>(hex.trim())?).ok()
}

fn open_inbox_db(path: &Path) -> Result<Connection, String> {
    // The file is readable by its owner only. The file holds the submissions,
    // and an accepted submission is the whole point of this service.
    // `sqlite::open_durable` creates the file owner-only before SQLite opens
    // it. It also narrows the `-wal` and `-shm` files beside it on every
    // start.
    let conn = sqlite::open_durable(path, true)?;
    init_schema(&conn)?;
    Ok(conn)
}

fn init_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS inbox_entries (
           inbox_id     INTEGER PRIMARY KEY AUTOINCREMENT,
           received_at  INTEGER NOT NULL,
           json         TEXT    NOT NULL,
           feed_id      INTEGER,
           sequenced_at INTEGER,
           feed_message TEXT,
           -- The account and nonce of the submission in `json`, copied out so
           -- that a real index can enforce the pair being unique. These two
           -- columns are a copy, not the record. `json` holds the signed
           -- submission, and the signature covers the nonce inside `json`.
           account      INTEGER,
           nonce        TEXT
         );
         -- Every frequent query here asks the same question: which entries are
         -- still pending? A partial index answers that question without
         -- reading the sequenced rows, which are the rows that keep growing.
         CREATE INDEX IF NOT EXISTS inbox_pending
           ON inbox_entries (inbox_id) WHERE feed_id IS NULL;
         CREATE TABLE IF NOT EXISTS inbox_meta (
           key   TEXT PRIMARY KEY,
           value TEXT NOT NULL
         );
         -- The public key each account submits under, pinned on that
         -- account's first submission. After that, a submission naming the
         -- account is only accepted under this key. That pin is what makes
         -- the account field on a sequencer message mean anything.
         CREATE TABLE IF NOT EXISTS inbox_accounts (
           account    INTEGER PRIMARY KEY,
           public_key TEXT    NOT NULL,
           pinned_at  INTEGER NOT NULL
         );
         -- Marks this service refused although the sequencer signed them
         -- correctly. There are three such marks: a second sequencing of one
         -- entry, a message that is not what the user submitted, and a
         -- message the sequencer could not prove is in the log it signed. A
         -- refusal on its own is not enough. The record has to say the
         -- refusal happened, or this service hides the exact fault it exists
         -- to show.
         CREATE TABLE IF NOT EXISTS inbox_mark_rejections (
           id       INTEGER PRIMARY KEY AUTOINCREMENT,
           at       INTEGER NOT NULL,
           inbox_id INTEGER,
           feed_id  INTEGER,
           kind     TEXT NOT NULL,
           detail   TEXT NOT NULL
         );",
    )
    .map_err(|e| e.to_string())?;
    // Columns added after the first version of this table. A database written
    // before one of these columns is migrated, not refused. Nothing here is
    // reconstructed. The old rows hold NULL, and a row with a NULL nonce is
    // one this service already refuses to sequence for its own reasons.
    for (column, decl) in [
        ("feed_message", "feed_message TEXT"),
        ("account", "account INTEGER"),
        ("nonce", "nonce TEXT"),
        ("content_checked", "content_checked INTEGER"),
    ] {
        let present = conn
            .prepare("SELECT 1 FROM pragma_table_info('inbox_entries') WHERE name = ?1")
            .and_then(|mut stmt| stmt.query_row(params![column], |_| Ok(())).optional())
            .map_err(|e| e.to_string())?
            .is_some();
        if !present {
            conn.execute_batch(&format!("ALTER TABLE inbox_entries ADD COLUMN {};", decl))
                .map_err(|e| e.to_string())?;
        }
    }
    // One `(account, nonce)` pair may sit in this service once. This index is
    // not the correctness boundary. The sequencer enforces uniqueness over the
    // published history, and the sequencer has to, because this service and
    // the sequencer do not trust each other. This index closes an availability
    // hole. Without the index, one captured signature sent again `MAX_PENDING`
    // times fills the pending set, and every other user is refused with 503.
    // That is censorship done by flooding the service that reports censorship.
    //
    // SQLite treats NULLs as different from each other in a unique index. So
    // the rows carried over from a database written before nonces existed do
    // not collide with each other.
    conn.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS inbox_account_nonce
           ON inbox_entries (account, nonce);",
    )
    .map_err(|e| e.to_string())?;
    // `GET /status` counts the entries confirmed without a content check on
    // every call. A partial index answers that count without reading the rows
    // that were fully checked, which are the rows that keep growing.
    // `inbox_pending` exists for the same reason.
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS inbox_content_unchecked
           ON inbox_entries (inbox_id) WHERE content_checked = 0;",
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Takes the state lock, and recovers from a poisoned lock.
///
/// A panic in one request must not end the service for every later request.
/// The data behind the lock is a SQLite connection and a few counters, and
/// SQLite commits or rolls back each statement on its own. A refusal of every
/// submission after such a panic would be exactly the outage this service
/// exists to show.
fn lock(state: &Arc<Mutex<InboxState>>) -> MutexGuard<'_, InboxState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Runs a database operation off the async runtime.
///
/// Every write here calls `fsync` (`synchronous = FULL`) while it holds the
/// state lock. On an async worker thread that wait stops every other request
/// the runtime scheduled on that thread. So the work runs on a blocking thread
/// instead.
async fn with_db<T, F>(state: &Arc<Mutex<InboxState>>, f: F) -> Result<T, (StatusCode, String)>
where
    F: FnOnce(&mut InboxState) -> T + Send + 'static,
    T: Send + 'static,
{
    let state = Arc::clone(state);
    tokio::task::spawn_blocking(move || f(&mut lock(&state)))
        .await
        .map_err(|e| {
            error!("inbox database worker failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "inbox database worker failed".to_string(),
            )
        })
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Checks a submission against the rules the matching engine really applies.
///
/// The check happens here, and not at sequencing time. An entry the sequencer
/// could fairly refuse would make a late entry mean two things. Everything
/// this service accepts, the sequencer must sequence.
///
/// The check has to match the *engine*, and not only look reasonable. The
/// engine drops an order that is off the price step, and reports nothing. A
/// price of 100.253 is counted in `orders_ignored` and never enters the books.
/// A service that accepted such a price would give the user an entry id, an
/// inclusion deadline and a mark for an order that never existed. That is
/// proof of inclusion for nothing.
///
/// # Every check here reads only the message
///
/// The nonce check, the two step checks and the symbol name rule read the
/// message and nothing else. Nothing here reads a registry, a book, or a
/// clock. So this function gives the same answer for the same message at any
/// time.
///
/// That is a requirement, and not a property that happened to hold.
/// `feed/drain.rs` runs this function again over every entry it drains from
/// this service, and treats a refusal as evidence that the service is not the
/// service it claims to be. An entry carries an inclusion deadline by then. So
/// a refusal there leaves the entry pending, and this service then publicly
/// reports an honest sequencer as late. That is the false alarm ENGINE.md
/// section 7 exists to remove. A rule that can change between intake and
/// sequencing cannot be checked in both places, and this rule is checked in
/// both places.
///
/// # The symbol check is the name rule, not the symbol list
///
/// The symbol must hold 1 to 32 characters, and only `A`-`Z`, `0`-`9` and `-`
/// (ENGINE.md section 4.0, `operator::valid_symbol`). That is all this
/// function asks about a symbol.
///
/// This function deliberately does **not** ask whether the symbol is listed.
/// Being listed is a fact about the log. The exchange builds its registry from
/// `ListSymbol` and `DelistSymbol` messages, so the answer changes as the log
/// grows. This service does not replay the log. A request to the sequencer for
/// the registry would put the party this service exists to distrust back into
/// the admission path. That is the same argument as the cancel target below.
/// The old check read `domain::SYMBOLS`, a compile-time list the exchange no
/// longer reads. So the old check refused symbols the exchange would trade,
/// and a market could not be opened while the exchange ran.
///
/// The submitter pays for a mistyped symbol with one message that does
/// nothing. The order enters the log, its inclusion proof verifies, and the
/// exchange counts it under `unlisted_symbol`. Clients read the listed symbols
/// from `GET /market` and stop the typo before it is sent.
///
/// What cannot be checked here, and why:
///
/// - whether a cancel's target is open, and whose it is. The answer depends on
///   the book at sequencing time, which this service does not have. A request
///   to the sequencer would put the party this service exists to distrust back
///   into the admission path. A sequencer that censors could answer "no such
///   order" and refuse submissions at intake. A cancel for an order that is
///   gone is a race the engine resolves. A price off the price step is not
///   such a race.
/// - whether the caller owns the `account` they name. That is checked, but
///   separately, by `verify_account_signature` and `check_account_key`. It is
///   a question about the submitter's key, not about what the engine can
///   execute. The signed statement is built from the whole step units this
///   function computes.
pub fn validate_submission(submission: &Submission) -> Result<(), String> {
    // The nonce is checked first, and for every kind of submission. The nonce
    // is what separates this submission from a replay of it. The nonce is also
    // part of the statement that everything below is signed over.
    checked_nonce(submission)?;
    // The session names the log. It is the second line of the statement, so a
    // session this function let through unchecked would be a way to write the
    // rest of the statement: a session holding a newline splits into two lines
    // and shifts every field after it. The character rule below is what stops
    // that.
    checked_session(submission)?;
    match submission {
        Submission::Order {
            symbol,
            price,
            quantity,
            ..
        } => {
            // The name rule only. Whether the symbol is listed is a fact about
            // the log, and that fact changes as the log grows. So this
            // function cannot ask it. See the comment above.
            valid_symbol(symbol)?;
            if to_grid(*price, PRICE_SCALE).is_none() {
                return Err(format!(
                    "price {} is not a whole number of cents between 0.01 and {}: the engine \
                     would drop this order without a trace",
                    price,
                    MAX_GRID_UNITS as f64 / PRICE_SCALE
                ));
            }
            if to_grid(*quantity, QUANTITY_SCALE).is_none() {
                return Err(format!(
                    "quantity {} is not a whole number of tenths between 0.1 and {}: the engine \
                     would drop this order without a trace",
                    quantity,
                    MAX_GRID_UNITS as f64 / QUANTITY_SCALE
                ));
            }
            Ok(())
        }
        Submission::Cancel { target_id, .. } => {
            // Sequencer ids start at 1 and step by one, so 0 names no message
            // that can ever exist. Everything else about a cancel is a
            // question about the book, answered at sequencing time.
            if *target_id == 0 {
                return Err("target_id 0 is not a feed message: feed ids start at 1".to_string());
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Account authentication
// ---------------------------------------------------------------------------

/// The account a submission is made for.
pub fn account_of(submission: &Submission) -> AccountId {
    match submission {
        Submission::Order { account, .. } => *account,
        Submission::Cancel { account, .. } => *account,
    }
}

/// How many random bytes a nonce carries. 128 bits. A submitter that draws
/// nonces from the operating system will not draw the same nonce twice in any
/// practical time. A collision costs that submitter their own second
/// submission and nothing more. It cannot be used against anybody else,
/// because the sequencer enforces uniqueness per account.
pub const NONCE_BYTES: usize = 16;

/// A fresh nonce for one submission: 32 lowercase hex characters over 128 bits
/// from the operating system.
///
/// One nonce per *action*, not per account and not per process. The bot sends
/// the same cancel again on every poll until it sees the cancel take effect.
/// Each of those sends is a separate signed submission with its own nonce. So
/// the sequencer sequences each of them exactly as it did before nonces
/// existed.
///
/// `rand::rngs::OsRng` is the same source `logchain::ephemeral_key` draws
/// signing keys from. A nonce a third party can predict is no worse than one a
/// third party can read. There is still no reason to use a weaker source than
/// the one already here.
pub fn new_nonce() -> String {
    let mut bytes = [0u8; NONCE_BYTES];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    logchain::to_hex(&bytes)
}

/// The 128 bits a nonce names, or `None` if the text is not the one spelling
/// this system accepts for those bits.
///
/// The trip back through `to_hex` is the check. `from_hex` on its own accepts
/// `AB` as well as `ab`, and two spellings of one nonce would be two different
/// keys in the sequencer's map. That is a replay hole that looks like a
/// formatting question. Everything downstream keys on the decoded bytes, so a
/// nonce that passes this function is exactly one 128-bit value.
pub fn canonical_nonce(nonce: &str) -> Option<[u8; NONCE_BYTES]> {
    let bytes = logchain::from_hex::<NONCE_BYTES>(nonce)?;
    (logchain::to_hex(&bytes) == nonce).then_some(bytes)
}

/// How many bytes a session names. `feed::new_session` prints eight random
/// bytes as 16 lowercase hex characters, and every session this system has
/// ever had is that shape.
pub const SESSION_BYTES: usize = 8;

/// The session text a submission carries, for either kind of submission.
pub fn session_of(submission: &Submission) -> Option<&str> {
    match submission {
        Submission::Order { session, .. } => session.as_deref(),
        Submission::Cancel { session, .. } => session.as_deref(),
    }
}

/// The session this submission names, or why it names none this system will
/// accept.
///
/// The rule is the one `canonical_nonce` uses, for the same reason: 16
/// lowercase hex characters, checked by decoding and printing again. `AB` and
/// `ab` are the same eight bytes and two different strings, and a statement
/// that accepted both would have two spellings for one log.
///
/// # What this does not ask
///
/// It does not ask whether this is the session the log is on *now*. Only the
/// sequencer knows that, and only the sequencer checks it: `feed/http.rs` on
/// `POST /order` and `feed/drain.rs` when it drains an entry.
///
/// This service deliberately does not check it, and the reason is the reason
/// this service exists. It could only learn the current session by asking the
/// sequencer, and the sequencer is the party this service is here to distrust.
/// A sequencer that wanted to censor could then serve an older signed head,
/// this service would refuse every current submission at intake, and there
/// would be no entry, no deadline and no overdue report. The censorship would
/// leave no evidence at all. That is worse than what checking would buy.
///
/// What it costs to leave the check out is one entry: a submission signed for
/// a session that has gone is refused by the drain and reported overdue, which
/// reads as censorship and is not. Reaching that needs an operator who deletes
/// `feed.db` and keeps `inbox.db`, or a reset landing between the moment a page
/// read the session and the moment the visitor clicked, which is under half a
/// second wide. A deployment reset renames the whole volume, so
/// all three databases go together.
pub fn checked_session(submission: &Submission) -> Result<&str, String> {
    let Some(session) = session_of(submission) else {
        return Err(
            "this submission names no session, so it does not say which log it is for and the \
             same signed bytes would still verify against a log that was emptied and started \
             again. Every submission needs the sequencer's session, 16 lowercase hex characters, \
             as GET /head reports it; a submission signed before sessions were covered \
             (statement version v2) is no longer accepted and has to be signed again"
                .to_string(),
        );
    };
    let canonical = logchain::from_hex::<SESSION_BYTES>(session)
        .filter(|bytes| logchain::to_hex(bytes) == session)
        .is_some();
    if !canonical {
        return Err(format!(
            "session {:?} is not 16 lowercase hex characters, so it is not a session this \
             sequencer can have named",
            session.chars().take(80).collect::<String>()
        ));
    }
    Ok(session)
}

/// The nonce text a submission carries, for either kind of submission.
pub fn nonce_of(submission: &Submission) -> Option<&str> {
    match submission {
        Submission::Order { nonce, .. } => nonce.as_deref(),
        Submission::Cancel { nonce, .. } => nonce.as_deref(),
    }
}

/// The 128 bits this submission's nonce names, or why it has none this system
/// will accept.
///
/// Every caller that needs the decoded nonce calls this function. No caller
/// asserts that `validate_submission` already checked the nonce. Such an
/// assertion is true today. A later edit that reorders two checks turns that
/// assertion into a panic. A panic on the sequencer's submission path poisons
/// its state lock, which stops the process. One function, one answer, and no
/// assumption that a later edit can break.
pub fn checked_nonce(submission: &Submission) -> Result<[u8; NONCE_BYTES], String> {
    let Some(nonce) = nonce_of(submission) else {
        return Err(
            "this submission carries no nonce, so it cannot be told apart from a replay of \
             itself. Every submission needs a fresh nonce of 32 lowercase hex characters; a \
             submission signed before nonces existed (statement version v1) is no longer \
             accepted and has to be signed again"
                .to_string(),
        );
    };
    canonical_nonce(nonce).ok_or_else(|| {
        format!(
            "nonce {:?} is not 32 lowercase hex characters, so the same 128 bits could be \
             written more than one way and each spelling would be a separate submission",
            nonce.chars().take(80).collect::<String>()
        )
    })
}

/// The statement an account's signature covers: everything the submission
/// asks for. The statement starts with a prefix of its own that carries a
/// version. So a signature made here can never be read as a sequencer head, a
/// validator attestation or a mark.
///
/// Price and quantity appear as the engine's whole step units: cents and
/// tenths. They are the same values `validate_submission` computes, and the
/// same values `matcher.rs` runs on. They are not the decimal floats on the
/// wire. That choice is deliberate. A caller in any language has to be able to
/// build the signed statement byte for byte. "How does this language print
/// 100.25" is not a question a signing scheme should depend on. `10025` is a
/// question every language answers the same way.
///
/// The second line is the session, which names the log. The last line is the
/// submitter's nonce. A replay cannot change either without breaking the
/// signature. A replay cannot keep the nonce without being recognised as the
/// submission it already is, and it cannot keep the session once the log it
/// names has gone.
///
/// ```text
/// exchange-account-order-v3\n<session>\n<account>\n<symbol>\n<side>\n<price_cents>\n<quantity_tenths>\n<order_type>\n<time_in_force>\n<post_only>\n<nonce>
/// exchange-account-cancel-v3\n<session>\n<account>\n<target_id>\n<nonce>
/// ```
///
/// # The three order terms are always printed
///
/// All three appear on every order statement, in a fixed order, even when they
/// hold their defaults. The wire form skips a default term to keep the bytes
/// the sequencer already hashed. That is about bytes, not about what a
/// signature covers. A statement that skipped them would give one order two
/// possible statements, and a term that is not signed is a term the sequencer
/// can change: the submitter would then hold a receipt for an order they did
/// not place. This is the same argument the operator statements follow.
///
/// # The version is `v3`, and `v2` is not accepted
///
/// A v2 statement covers neither the session nor the terms. Accepting v2 as
/// well would let a sequencer take a v2 signature and publish a market order
/// with it, into whichever log it liked. So the bump is clean, the same way
/// `exchange-inbox-mark-v2` stopped being accepted when the epoch was added to
/// that statement. A v2 signature captured before this change has to stop
/// verifying, or every captured one stays a working replay forever, which is
/// the exact thing being fixed.
///
/// `None` means there is no statement to sign or check. The submission is off
/// the engine's price step or quantity step, or its nonce or its session is
/// missing or not in the one accepted spelling. `validate_submission` refuses
/// every one of those cases by name. This `None` is what stops any of them
/// being verified as if it were fine.
pub fn submission_statement(submission: &Submission) -> Option<Vec<u8>> {
    let nonce = canonical_nonce(nonce_of(submission)?)?;
    // The nonce is printed again from the decoded bytes, and never copied from
    // the wire. The statement then commits to the 128 bits, and not to
    // whatever spelling of those bits arrived.
    let nonce = logchain::to_hex(&nonce);
    // The session goes through the same check, so a session holding a newline
    // or an upper-case digit never reaches a statement.
    let session = checked_session(submission).ok()?;
    match submission {
        Submission::Order {
            account,
            symbol,
            side,
            price,
            quantity,
            order_type,
            time_in_force,
            post_only,
            ..
        } => {
            let price_cents = to_grid(*price, PRICE_SCALE)?;
            let quantity_tenths = to_grid(*quantity, QUANTITY_SCALE)?;
            // Every name below is written out here, and not taken from Debug.
            // The statement is a wire format, and a derived Debug is free to
            // change what it prints.
            let side = match side {
                Side::Buy => "Buy",
                Side::Sell => "Sell",
            };
            Some(
                format!(
                    "exchange-account-order-v3\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
                    session,
                    account,
                    symbol,
                    side,
                    price_cents,
                    quantity_tenths,
                    named_order_type(*order_type),
                    named_time_in_force(*time_in_force),
                    named_post_only(*post_only),
                    nonce
                )
                .into_bytes(),
            )
        }
        Submission::Cancel {
            account, target_id, ..
        } => Some(
            format!(
                "exchange-account-cancel-v3\n{}\n{}\n{}\n{}",
                session, account, target_id, nonce
            )
            .into_bytes(),
        ),
    }
}

/// How an order type prints in the signed statement. The variant names of
/// `domain::OrderType`, written out.
fn named_order_type(order_type: OrderType) -> &'static str {
    match order_type {
        OrderType::Limit => "Limit",
        OrderType::Market => "Market",
    }
}

/// How a time in force prints in the signed statement. The variant names of
/// `domain::TimeInForce`, written out.
fn named_time_in_force(time_in_force: TimeInForce) -> &'static str {
    match time_in_force {
        TimeInForce::GoodTillCancel => "GoodTillCancel",
        TimeInForce::ImmediateOrCancel => "ImmediateOrCancel",
        TimeInForce::FillOrKill => "FillOrKill",
    }
}

/// How post-only prints in the signed statement. Written out rather than left
/// to `bool`'s own `Display`, which prints the same two words today and is not
/// this crate's to pin.
fn named_post_only(post_only: bool) -> &'static str {
    if post_only { "true" } else { "false" }
}

/// The sequencer message a submission becomes, under the id and the timestamp
/// the sequencer gives it.
///
/// Two paths take a submission: `POST /order` on the sequencer, and the drain
/// of this service. The same signed bytes have to become the same message on
/// both paths. Before this function existed, each path built the message
/// itself, field by field. Every new order term was then two edits that had to
/// agree, and nothing compared them. One wrong edit gives a submitter a market
/// order on one path and a limit order on the other, under one signature. Now
/// there is one place to edit.
///
/// This function sits beside `submission_statement` on purpose.
/// `submission_statement` says what the submitter signs. This function says
/// what the exchange runs. A term added to one belongs in the other, so the
/// two stay next to each other.
///
/// The three order terms are read here, once, and both submission paths carry
/// them. The session is not: it names the log the message goes into, and a
/// message does not repeat what the log it sits in already says.
pub fn message_from(id: OrderId, timestamp: u64, submission: &Submission) -> OrderMessage {
    match submission.clone() {
        Submission::Order {
            account,
            symbol,
            side,
            price,
            quantity,
            nonce,
            session: _,
            order_type,
            time_in_force,
            post_only,
        } => OrderMessage::New {
            id,
            timestamp,
            account,
            symbol,
            side,
            price,
            quantity,
            nonce,
            order_type,
            time_in_force,
            post_only,
        },
        Submission::Cancel {
            account,
            target_id,
            nonce,
            session: _,
        } => OrderMessage::Cancel {
            id,
            timestamp,
            account,
            target_id,
            nonce,
        },
    }
}

/// Signs a submission as the account that makes it. The bot and the CLI use
/// this function. A caller in another language builds `submission_statement`
/// again and signs those bytes.
pub fn sign_submission(key: &SigningKey, submission: &Submission) -> Option<SignedSubmission> {
    let statement = submission_statement(submission)?;
    Some(SignedSubmission {
        submission: submission.clone(),
        public_key: logchain::to_hex(key.verifying_key().as_bytes()),
        signature: logchain::to_hex(&key.sign(&statement).to_bytes()),
    })
}

/// Checks that a submission really was signed by the key it carries.
///
/// This function reads no database and no pin. It answers one question:
/// whoever sent this holds the private half of `public_key`, and that key
/// signed exactly these terms. Which key may speak for the account is the next
/// question, and `check_account_key` answers it.
///
/// The two failures stay apart because they mean different things to a caller.
/// A 400 is a request that was built wrong. A 401 is a signature that does not
/// cover what was sent.
pub fn verify_account_signature(
    signed: &SignedSubmission,
) -> Result<VerifyingKey, (StatusCode, String)> {
    let Some(key_bytes) = logchain::from_hex::<32>(signed.public_key.trim()) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "public_key must be a 32-byte Ed25519 public key in hex (64 characters)".to_string(),
        ));
    };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "public_key {} is not a valid Ed25519 point",
                signed.public_key
            ),
        ));
    };
    let Some(signature_bytes) = logchain::from_hex::<64>(signed.signature.trim()) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "signature must be a 64-byte Ed25519 signature in hex (128 characters)".to_string(),
        ));
    };
    let Some(statement) = submission_statement(&signed.submission) else {
        // The handlers validate first, so they never reach this line. A caller
        // that uses this function on its own can reach it.
        return Err((
            StatusCode::BAD_REQUEST,
            "this submission is not on the engine's price and quantity grid, so there is no \
             statement to verify"
                .to_string(),
        ));
    };
    // `verify_strict` for the same reason the head and mark signatures use it.
    // Plain `verify` accepts edge cases where a signature can be changed and
    // still verify, and nothing here needs those cases.
    if key
        .verify_strict(&statement, &Signature::from_bytes(&signature_bytes))
        .is_err()
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!(
                "the signature does not verify under public_key {} for this submission; it must \
                 cover exactly: {}",
                signed.public_key,
                String::from_utf8_lossy(&statement).replace('\n', " | ")
            ),
        ));
    }
    Ok(key)
}

/// What a pin check decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountPin {
    /// Nothing was on file for this account, so this key becomes its key.
    First,
    /// The key presented is the one already on file.
    Known,
}

/// Decides whether a submission names the log that is running.
///
/// `current` is the sequencer's own session. Only the sequencer knows it, so
/// only the sequencer calls this: `POST /order` before it takes an id, and
/// `sequence_drained` before it sequences an entry. Both call it so that the
/// two ways into the log answer one signed submission the same way.
///
/// A refusal here is not a broken signature. The signature is fine; it covers
/// a different log. So the message names both sessions, because the caller can
/// act on that: sign again against the session this sequencer reports.
///
/// `checked_session` says why this service does not call it.
pub fn check_session(current: &str, submission: &Submission) -> Result<(), (StatusCode, String)> {
    let named = checked_session(submission).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if named == current {
        return Ok(());
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!(
            "this submission is signed for session {}, and this log is session {}. A session \
             names one log. The signature is good, but it covers a log this sequencer is not \
             serving, so this submission cannot become a message here. Read the session from GET \
             /head and sign again",
            named, current
        ),
    ))
}

/// Decides whether a key may speak for an account, from what is on file.
///
/// This service and the sequencer share this function, so the rule and the
/// wording of the refusal have one definition. Each program keeps its own
/// pins. Neither can ask the other without putting the party it distrusts back
/// into its admission path. So the two can disagree when a different key
/// reaches each of them first. The sequencer's refusal at drain time says
/// exactly that.
pub fn check_account_key(
    account: AccountId,
    pinned: Option<&VerifyingKey>,
    presented: &VerifyingKey,
) -> Result<AccountPin, (StatusCode, String)> {
    match pinned {
        None => Ok(AccountPin::First),
        Some(known) if known == presented => Ok(AccountPin::Known),
        Some(known) => Err((
            // The caller is authenticated as somebody, but not as this
            // account. The caller holds a real key, and that key is not the
            // one this account speaks with. That is an attempt to act as
            // another account. It is not a malformed request, and it is not a
            // broken signature. A reader should be able to tell the three
            // apart from the status code alone.
            StatusCode::FORBIDDEN,
            format!(
                "account {} is pinned to public key {}, and this submission is signed by {}. The \
                 first key an account submits under is the key it keeps; nothing else can submit \
                 as that account",
                account,
                logchain::to_hex(known.as_bytes()),
                logchain::to_hex(presented.as_bytes())
            ),
        )),
    }
}

/// Reads the key pinned for an account, if there is one. `Err` is a database
/// failure. A caller must never read `Err` as "no key on file". That reading
/// would pin an attacker's key on the next submission.
fn pinned_account_key(
    conn: &Connection,
    account: AccountId,
) -> Result<Option<VerifyingKey>, (StatusCode, String)> {
    let stored: Option<String> = conn
        .query_row(
            "SELECT public_key FROM inbox_accounts WHERE account = ?1",
            params![account],
            |row| row.get(0),
        )
        .optional()
        .map_err(internal)?;
    match stored {
        None => Ok(None),
        Some(hex) => match parse_public_key(&hex) {
            Some(key) => Ok(Some(key)),
            None => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "the key pinned for account {} in this inbox is unreadable ({}); no \
                     submission for that account can be checked until an operator fixes it",
                    account, hex
                ),
            )),
        },
    }
}

/// Checks a submission's key against this service's pins. If the account has
/// no pin yet, this function pins the key.
fn pin_or_check_account(
    state: &mut InboxState,
    account: AccountId,
    key: &VerifyingKey,
) -> Result<AccountPin, (StatusCode, String)> {
    let pinned = pinned_account_key(&state.conn, account)?;
    let decision = check_account_key(account, pinned.as_ref(), key)?;
    if decision == AccountPin::First {
        let hex = logchain::to_hex(key.as_bytes());
        state
            .conn
            .execute(
                "INSERT INTO inbox_accounts (account, public_key, pinned_at) VALUES (?1, ?2, ?3)",
                params![account, hex, state.clock.now_ms() as i64],
            )
            .map_err(internal)?;
        info!(
            "pinned account {} to public key {}: only submissions signed by that key are accepted \
             for it from now on",
            account,
            logchain::to_hex(key.as_bytes())
        );
    }
    Ok(decision)
}

// ---------------------------------------------------------------------------
// Mark authentication
// ---------------------------------------------------------------------------

/// What a mark settled about an entry.
///
/// Two of the three outcomes of `docs/ENGINE.md` section 7. The third outcome
/// is "late". "Late" is not a mark outcome at all. `GET /status` reports it
/// when no mark arrived before the deadline, and it is the only outcome that
/// is an alarm.
///
/// | Outcome | Meaning |
/// |---|---|
/// | `Confirmed` | the proof verified, the account and nonce match, every field matches |
/// | `ContentNotChecked` | the proof verified and the account and nonce match, but this build cannot read the kind |
/// | late | nothing arrived in time. **The censorship alarm.** |
///
/// `wire::Verdict::exit_code` already gives the one-shot checks this shape,
/// and this enum has the same shape on purpose. Exit 1 means a check failed.
/// Exit 3 means the history verified, and this build is too old to read part
/// of what it verified. Those are facts about different parties. One answer
/// for both either accuses an honest sequencer or hides a real failure.
/// `ContentNotChecked` is this service's exit 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    /// Everything was checked and everything held.
    Confirmed,
    /// The message is provably in the log the sequencer signed, and provably
    /// under this entry's account and nonce. This build cannot read the
    /// message's kind, so its fields were not compared. The bytes are kept, so
    /// an upgraded build can make the comparison later.
    ContentNotChecked,
}

impl Confirmation {
    /// Answers whether the message's content was compared against the
    /// submission.
    fn content_checked(self) -> bool {
        matches!(self, Confirmation::Confirmed)
    }
}

/// The signed tree head a mark's inclusion proof is checked against: the three
/// RFC 9162 `TreeHeadDataV2` fields, plus the session, exactly as the
/// sequencer's `GET /sth` serves them.
///
/// There is no public key in this struct. A key carried beside its own
/// signature verifies whatever it is asked to verify, so it is evidence about
/// nobody. This service has one pinned sequencer key and checks this signature
/// against that key. A head from any other key is refused, not believed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeHead {
    /// The sequencer history this head is over. One session per sequencer
    /// database, so tree sizes from two different histories can never be read
    /// as one.
    pub session: String,
    /// Milliseconds since the Unix epoch.
    pub timestamp: u64,
    /// How many messages the tree held when the head was signed.
    pub tree_size: u64,
    /// `MTH` over those messages, 64 hex characters.
    pub root_hash: String,
    /// Ed25519 signature over `logchain::tree_head_statement`, in hex.
    pub signature: String,
}

/// The longest inclusion path this service will decode at all. An RFC 9162
/// proof holds `ceil(log2(tree_size))` nodes, so 64 covers a tree of 2^64
/// leaves, and anything longer is not a proof. Without this limit, a caller
/// whose mark signature checks out could send a megabyte of hex to parse.
const MAX_INCLUSION_PATH: usize = 64;

/// Request body for `POST /mark`. It is the sequencer's signed claim that
/// entry `inbox_id` was sequenced as sequencer message `feed_id`. It carries
/// the message's stored bytes and an inclusion proof as the evidence for that
/// claim.
///
/// The message is **bytes, not a parsed message**. The sequencer used to send
/// back an `OrderMessage` it had serialised again, and that caused a real bug.
/// A kind the sequencer could not read produced no mark at all. The entry
/// stayed pending, and this service publicly reported an honest sequencer as
/// late. Bytes plus a proof are checkable by hashing alone, so a mark can be
/// built and checked for every kind, forever.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkRequest {
    pub inbox_id: i64,
    pub feed_id: OrderId,
    /// The database the entry id belongs to, as `GET /pending` announced it.
    /// It is signed, so it cannot be edited on the way here.
    ///
    /// The epoch stops a mark meant for a previous database from closing an
    /// entry in this one, or from being recorded as a lie about it. Entry ids
    /// restart at 1 with a new database, so without the epoch the two entries
    /// look the same.
    pub inbox_epoch: String,
    /// The message the entry became, byte for byte as the sequencer stored it
    /// and as `/messages.ndjson` serves it. This is the leaf the proof is
    /// over: `leaf_hash = SHA-256(0x00 || message)`.
    pub message: String,
    /// The head the proof is checked against. Its session names the sequencer
    /// history the message belongs to. The session is recorded and not pinned,
    /// because a sequencer that lost its database starts a new session for a
    /// good reason. The session is what tells an auditor which history to look
    /// the message up in.
    pub tree_head: TreeHead,
    /// The node hashes of the inclusion proof, the leaf's sibling first, each
    /// 64 hex characters. They are not signed, and they do not need to be.
    /// Arithmetic refuses a path that does not hash up to the signed root.
    pub inclusion_path: Vec<String>,
    /// Ed25519 signature over `mark_statement`, in hex.
    pub signature: String,
}

/// The statement a mark signature covers. The prefix differs from the
/// sequencer's head statement and from a validator's attestation, for the same
/// reason those two differ from each other. A signature made for one purpose
/// must never verify as another.
///
/// The version is `v3`, and `v2` is not accepted. A v2 statement covered a
/// message that had been serialised again, so its digest is over different
/// bytes. A reader must never confuse the two.
///
/// The tree size and the root are in the statement, so the mark and the head
/// it travels with cannot be separated. Without them, a mark signed for one
/// head still verifies beside any other head from the same session. The pair
/// this signature exists to fix would then be a pair the sequencer never made.
fn mark_statement(
    inbox_epoch: &str,
    inbox_id: i64,
    feed_id: OrderId,
    message: &[u8],
    head: &TreeHead,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let digest: [u8; 32] = hasher.finalize().into();
    format!(
        "exchange-inbox-mark-v3\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        head.session,
        inbox_epoch,
        inbox_id,
        feed_id,
        head.tree_size,
        head.root_hash,
        logchain::to_hex(&digest)
    )
    .into_bytes()
}

/// Builds the signed mark the sequencer sends after it sequences an entry.
///
/// `message` is the message's stored bytes. The sequencer passes what it
/// wrote, and never something it serialised again for this call. See
/// `MarkRequest`.
pub fn signed_mark(
    key: &SigningKey,
    inbox_epoch: &str,
    inbox_id: i64,
    feed_id: OrderId,
    message: &str,
    tree_head: TreeHead,
    inclusion_path: Vec<String>,
) -> MarkRequest {
    let signature = key.sign(&mark_statement(
        inbox_epoch,
        inbox_id,
        feed_id,
        message.as_bytes(),
        &tree_head,
    ));
    MarkRequest {
        inbox_id,
        feed_id,
        inbox_epoch: inbox_epoch.to_string(),
        message: message.to_string(),
        tree_head,
        inclusion_path,
        signature: logchain::to_hex(&signature.to_bytes()),
    }
}

/// Checks a mark signature. `verify_strict` for the same reason the head
/// signatures use it. Plain `verify` accepts edge cases where a signature can
/// be changed and still verify, and nothing here needs those cases.
///
/// `pub(crate)` so the sequencer's own tests can check that what
/// `sequence_drained` builds is what this service accepts. Two halves that are
/// each consistent on their own and disagree with each other is exactly the
/// failure this whole change is about.
pub(crate) fn verify_mark(key: &VerifyingKey, req: &MarkRequest) -> bool {
    let Some(bytes) = logchain::from_hex::<64>(&req.signature) else {
        return false;
    };
    let signature = Signature::from_bytes(&bytes);
    key.verify_strict(
        &mark_statement(
            &req.inbox_epoch,
            req.inbox_id,
            req.feed_id,
            req.message.as_bytes(),
            &req.tree_head,
        ),
        &signature,
    )
    .is_ok()
}

/// Checks that the message really is in the tree the sequencer signed.
///
/// This function does two checks, and both are needed. It checks the tree head
/// under the pinned sequencer key first. An inclusion proof checked against a
/// root nobody signed always succeeds and says nothing at all. Then it checks
/// the proof itself, with `merkle::verify_entry_inclusion` over the bytes.
/// That step parses nothing and holds no opinion about what the message says,
/// so it works for a kind this build has never heard of.
///
/// This function computes the leaf index, and never takes it from the mark.
/// The sequencer's own rule is that leaf `n` is message `n + 1`. So message
/// `feed_id` sits at leaf `feed_id - 1` and nowhere else. A leaf index read
/// off the request would let a sequencer pass this check with a leaf the
/// message is not at.
///
/// `pub(crate)` for the same reason as `verify_mark`.
pub(crate) fn verify_inclusion(key: &VerifyingKey, req: &MarkRequest) -> Result<(), String> {
    let head = &req.tree_head;
    let (Some(root), Some(signature)) = (
        logchain::from_hex::<{ merkle::HASH_SIZE }>(&head.root_hash),
        logchain::from_hex::<64>(&head.signature).map(|b| Signature::from_bytes(&b)),
    ) else {
        return Err(format!(
            "the tree head on this mark is malformed: root {:?}, signature {:?}",
            head.root_hash, head.signature
        ));
    };
    if !logchain::verify_tree_head(
        key,
        &head.session,
        head.timestamp,
        head.tree_size,
        &root,
        &signature,
    ) {
        return Err(format!(
            "the tree head this proof is checked against is not signed by the feed key this \
             inbox trusts: session {}, size {}, root {}. A proof against a root nobody signed \
             always verifies and proves nothing",
            head.session, head.tree_size, head.root_hash
        ));
    }
    if req.feed_id == 0 {
        return Err("feed ids start at 1, so feed message 0 names no leaf".to_string());
    }
    let leaf_index = req.feed_id - 1;
    if leaf_index >= head.tree_size {
        return Err(format!(
            "feed message {} is leaf {}, which is outside the tree of {} this head is over: the \
             head is older than the message it is supposed to prove",
            req.feed_id, leaf_index, head.tree_size
        ));
    }
    if req.inclusion_path.len() > MAX_INCLUSION_PATH {
        return Err(format!(
            "the inclusion path has {} nodes; no proof over a tree of {} needs more than {}",
            req.inclusion_path.len(),
            head.tree_size,
            MAX_INCLUSION_PATH
        ));
    }
    let path: Option<Vec<merkle::Hash>> = req
        .inclusion_path
        .iter()
        .map(|node| logchain::from_hex::<{ merkle::HASH_SIZE }>(node))
        .collect();
    let Some(path) = path else {
        return Err("the inclusion path holds something that is not a 32-byte hash".to_string());
    };
    if !merkle::verify_entry_inclusion(
        leaf_index,
        head.tree_size,
        req.message.as_bytes(),
        &path,
        &root,
    ) {
        return Err(format!(
            "the inclusion proof for feed message {} does not reach root {} over a tree of {}: \
             these bytes are not in the history the feed signed",
            req.feed_id, head.root_hash, head.tree_size
        ));
    }
    Ok(())
}

/// The first part of a message, cut to `SHOWN` characters, for a record an
/// operator has to read. Characters and not bytes, so the cut never splits a
/// character in the middle. Only the request body limit bounds a mark's
/// message, and a rejection row is written to disk.
fn preview(message: &str) -> String {
    const SHOWN: usize = 200;
    let text: String = message.chars().take(SHOWN).collect();
    if text.len() < message.len() {
        format!("{}…", text)
    } else {
        text
    }
}

/// The message with its price and its quantity moved to the exact step they
/// name, or `None` if either one is off its step.
///
/// This makes two messages that name one price comparable as bytes. The value
/// is computed back from the whole step units, so one step always prints the
/// same 64 bits, whatever spelling arrived.
///
/// The value has to be on the step. Two values that are each off the step are
/// not "equally off it", and `None == None` would call them a match without
/// saying so.
fn grid_form(message: &OrderMessage) -> Option<OrderMessage> {
    let mut message = message.clone();
    if let OrderMessage::New {
        price, quantity, ..
    } = &mut message
    {
        *price = to_grid(*price, PRICE_SCALE)? as f64 / PRICE_SCALE;
        *quantity = to_grid(*quantity, QUANTITY_SCALE)? as f64 / QUANTITY_SCALE;
    }
    Some(message)
}

/// Answers whether this sequencer message is the submission the user made.
///
/// Prices and quantities are compared as whole step units, and not as float
/// bits. A comparison of the exact bits was right while the sequencer only
/// ever copied the value it read from `/pending` straight into the message.
/// That stopped being the only path when the sequencer gained the ability to
/// answer a drained entry with a message it had *already* published. Such a
/// message came in through `POST /order` and carried the same signed
/// statement. It holds the float the direct caller sent. That float is the
/// same price step the signature covers, and it need not be the same 64 bits
/// as the float this service stored. A refusal on the bits would report a
/// content mismatch for a message that is exactly this submission.
///
/// The nonce is compared too, and that closes a separate hole. Nothing makes a
/// sequencer id claimable by only one entry. So before the nonce check, a
/// sequencer could satisfy two different entries with one message whose
/// content matched both. Two entries never share an account and a nonce
/// together, so the sequencer can no longer do that.
///
/// The check is on the pair, and not on the nonce alone. The unique index is
/// on `(account, nonce)`, and `GET /pending` publishes the nonces. So two
/// accounts can hold entries under one nonce. A check on the nonce alone would
/// let the sequencer close one account's entry with another account's message.
///
/// # Every field, not a list of fields
///
/// The check builds the message this submission has to become, with
/// `message_from`, and compares the bytes. The check named the fields one by
/// one before, and that list left out the order terms. A sequencer could then
/// publish a market order for a submission the account signed as a limit
/// order, and this function returned `true`. A list has to be edited every
/// time a field is added, and the edit that is forgotten is the edit that
/// matters. A byte comparison needs no edit.
///
/// The order terms needed no edit here when a submission gained them, and that
/// is the property this shape was built for: `message_from` now copies them
/// across, so they are in the bytes on both sides of the comparison.
///
/// The id and the timestamp come from the message under test, because the
/// sequencer chooses both and no submission names them. The session is not
/// compared at all, because a message does not carry one. The log it sits in
/// is the log it is in. Whether the submission named the current session is a
/// question the sequencer answers before it publishes.
pub(crate) fn message_matches(submission: &Submission, message: &OrderMessage) -> bool {
    let timestamp = match message {
        OrderMessage::New { timestamp, .. } | OrderMessage::Cancel { timestamp, .. } => *timestamp,
        // No submission becomes any other kind of message.
        _ => return false,
    };
    let expected = message_from(message.id(), timestamp, submission);
    match (grid_form(&expected), grid_form(message)) {
        (Some(expected), Some(message)) => {
            logchain::canonical_bytes(&expected) == logchain::canonical_bytes(&message)
        }
        _ => false,
    }
}

/// The sequencer key this service accepts marks from. If the operator
/// configured no key, this function pins one on first contact.
///
/// The key is trusted on first use, against a URL the operator gave. The
/// exchange pins the sequencer key it first sees the same way. The key is
/// checked against a live signed head before it is pinned. So the stored key
/// is one that has provably signed this sequencer's history, and not only a
/// string that a server sent.
async fn feed_key(state: &Arc<Mutex<InboxState>>) -> Option<VerifyingKey> {
    let (pinned, url) = with_db(state, |state| (state.feed_key, state.feed_url.clone()))
        .await
        .ok()?;
    if pinned.is_some() {
        return pinned;
    }
    let url = url?;
    let key = fetch_feed_key(&url).await?;
    let hex = logchain::to_hex(key.as_bytes());
    with_db(state, move |state| {
        // Another mark may have pinned a key while this one waited on the
        // network. The first pin wins.
        if let Some(existing) = state.feed_key {
            return Some(existing);
        }
        if let Err(e) = state.conn.execute(
            "INSERT OR REPLACE INTO inbox_meta (key, value) VALUES ('feed_pubkey', ?1)",
            params![hex],
        ) {
            error!("could not record the pinned feed key: {}", e);
        }
        info!(
            "pinned feed public key {}",
            logchain::to_hex(key.as_bytes())
        );
        state.feed_key = Some(key);
        Some(key)
    })
    .await
    .ok()
    .flatten()
}

async fn fetch_feed_key(feed_url: &str) -> Option<VerifyingKey> {
    #[derive(Deserialize)]
    struct Head {
        session: String,
        last_id: u64,
        chain: String,
        public_key: String,
        signature: String,
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    let url = format!("{}/head", feed_url.trim_end_matches('/'));
    let head: Head = match client.get(&url).send().await {
        Ok(response) => match response.json().await {
            Ok(head) => head,
            Err(e) => {
                error!("could not read the signed head from {}: {}", url, e);
                return None;
            }
        },
        Err(e) => {
            error!("could not reach {} to learn the feed key: {}", url, e);
            return None;
        }
    };
    let key = parse_public_key(&head.public_key)?;
    let chain = logchain::from_hex::<32>(&head.chain)?;
    let signature = Signature::from_bytes(&logchain::from_hex::<64>(&head.signature)?);
    if !logchain::verify_head(&key, &head.session, head.last_id, &chain, &signature) {
        error!(
            "{} served a head that its own key did not sign; not pinning that key",
            url
        );
        return None;
    }
    Some(key)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Answers POST /submit. It checks that the account named really asked for
/// this submission. It checks the terms. It writes both to disk. It then
/// answers with the entry id and the moment the inclusion clock started.
///
/// The order of the checks is the order of the questions. Is this a request at
/// all? Is it something the engine can execute? That question computes the
/// whole step units the signature covers. Did the account's key sign it? Is
/// that key the one this account speaks with? Only after all four is anything
/// written.
async fn submit(
    State(state): State<Arc<Mutex<InboxState>>>,
    caller: Caller,
    body: Result<Json<SignedSubmission>, JsonRejection>,
) -> Result<Json<Entry>, (StatusCode, String)> {
    let signed = signed_body(body)?;
    validate_submission(&signed.submission).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // This check runs off the state lock and reads no database. A request with
    // a signature that does not cover what it asks for never reaches the
    // database at all.
    let key = verify_account_signature(&signed)?;
    let account = account_of(&signed.submission);
    // The nonce is decoded again here, and not assumed from the check above.
    // No order of the checks can then turn a missing nonce into a panic here.
    let nonce = logchain::to_hex(
        &checked_nonce(&signed.submission).map_err(|e| (StatusCode::BAD_REQUEST, e))?,
    );

    let json =
        serde_json::to_string(&signed).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let accepted = with_db(&state, move |state| {
        // The address is worked out here, where the operator's trusted-proxy
        // list is. Behind a reverse proxy the socket peer is the proxy on
        // every request, so a limit on the socket peer would give every
        // visitor and the bot one shared count. See `Caller::client_ip`.
        let ip = caller.client_ip(&state.trusted_proxies);
        if !state.limiter.allow(ip, Instant::now()) {
            warn!(
                "submission from {} refused: more than {} in {:?}",
                ip, SUBMIT_BURST, SUBMIT_WINDOW
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "more than {} submissions from {} in {} seconds",
                    SUBMIT_BURST,
                    ip,
                    SUBMIT_WINDOW.as_secs()
                ),
            ));
        }
        let pending: i64 = state
            .conn
            .query_row(
                "SELECT COUNT(*) FROM inbox_entries WHERE feed_id IS NULL",
                [],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if pending >= MAX_PENDING {
            error!(
                "submission from {} refused: {} entries are already pending, the cap is {}. \
                 The sequencer is not draining the inbox",
                ip, pending, MAX_PENDING
            );
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "{} entries are pending, at the cap of {}; the sequencer is not draining them",
                    pending, MAX_PENDING
                ),
            ));
        }
        // The key is pinned before the entry is written. So every entry that
        // exists is one whose key this service had already accepted for the
        // account. The other order could record a submission and then fail to
        // record who may make it.
        pin_or_check_account(state, account, &key)?;
        let received_at = state.clock.now_ms();
        // The unique index on `(account, nonce)` answers this, and not a
        // lookup followed by an insert. A lookup is a decision made before the
        // write, and another write can arrive between the two.
        if let Err(e) = state.conn.execute(
            "INSERT INTO inbox_entries (received_at, json, account, nonce) VALUES (?1, ?2, ?3, ?4)",
            params![received_at as i64, json, account, nonce],
        ) {
            if is_constraint_violation(&e) {
                let existing: Option<i64> = state
                    .conn
                    .query_row(
                        "SELECT inbox_id FROM inbox_entries WHERE account = ?1 AND nonce = ?2",
                        params![account, nonce],
                        |row| row.get(0),
                    )
                    .optional()
                    .unwrap_or(None);
                warn!(
                    "submission from {} refused: account {} already submitted nonce {} as entry \
                     {:?}",
                    ip, account, nonce, existing
                );
                return Err((
                    StatusCode::CONFLICT,
                    match existing {
                        Some(inbox_id) => format!(
                            "account {} already submitted this nonce; it is inbox entry {}. \
                             Re-sending the same signed bytes cannot produce a second order. \
                             Sign a new submission with a fresh nonce",
                            account, inbox_id
                        ),
                        None => format!(
                            "account {} already submitted this nonce. Re-sending the same signed \
                             bytes cannot produce a second order. Sign a new submission with a \
                             fresh nonce",
                            account
                        ),
                    },
                ));
            }
            return Err(internal(e));
        }
        Ok((state.conn.last_insert_rowid(), received_at))
    })
    .await?;
    let (inbox_id, received_at) = accepted?;
    info!(
        "inbox entry {}: {:?} signed by account {}'s key {}",
        inbox_id, signed.submission, account, signed.public_key
    );
    Ok(Json(Entry {
        inbox_id,
        received_at,
        submission: signed.submission,
        public_key: signed.public_key,
        signature: signed.signature,
        feed_id: None,
        sequenced_at: None,
        content_checked: None,
    }))
}

/// Turns a body axum could not decode into a refusal that says what the
/// endpoint wants. The extractor would answer with a general 422 instead.
///
/// The shape of the body changed when submissions started to carry a
/// signature. So the most likely reason a body fails to parse is that the
/// caller sends the old shape, and the answer says so.
fn signed_body(
    body: Result<Json<SignedSubmission>, JsonRejection>,
) -> Result<SignedSubmission, (StatusCode, String)> {
    match body {
        Ok(Json(signed)) => Ok(signed),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "this body is not a signed submission ({}). POST /submit takes \
                 {{\"submission\": {{\"Order\": {{...}}}}, \"public_key\": \"<64 hex>\", \
                 \"signature\": \"<128 hex>\"}}, where the signature covers the account's \
                 statement for this submission. See the README",
                e.body_text()
            ),
        )),
    }
}

/// Answers GET /pending with the oldest entries the sequencer has not yet
/// included, up to `PAGE_LIMIT`. This is what the sequencer drains on every
/// tick. The epoch travels in a header, and not inside each entry. The body
/// then stays a plain array of entries, and the epoch can never come from a
/// different moment than the entries beside it. The sequencer puts its session
/// in a header for the same reason.
async fn get_pending(
    State(state): State<Arc<Mutex<InboxState>>>,
) -> Result<([(axum::http::HeaderName, String); 1], Json<Vec<Entry>>), (StatusCode, String)> {
    with_db(&state, |state| {
        let (entries, unreadable) = read_pending(&state.conn, PAGE_LIMIT);
        state.unreadable_entries += unreadable;
        (
            [(
                axum::http::HeaderName::from_static(PENDING_EPOCH_HEADER),
                state.epoch.clone(),
            )],
            Json(entries),
        )
    })
    .await
}

/// Answers POST /mark, where the sequencer reports which sequencer message an
/// entry became. A repeat is safe. A mark on a marked entry with the same
/// sequencer id and the same message changes nothing, so the sequencer can
/// send the mark again after a crash.
///
/// Only the sequencer can mark an entry. See the note at the top of this file.
async fn mark(
    State(state): State<Arc<Mutex<InboxState>>>,
    caller: Caller,
    Json(req): Json<MarkRequest>,
) -> Result<Json<Entry>, (StatusCode, String)> {
    let Some(key) = feed_key(&state).await else {
        let ip = refused_mark(&state, &caller).await;
        error!(
            "mark for inbox entry {} from {} refused: this inbox has no feed key to check it \
             against, so it cannot tell the feed from anyone else",
            req.inbox_id, ip
        );
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "the inbox has no pinned feed key, so no mark can be authenticated".to_string(),
        ));
    };
    if !verify_mark(&key, &req) {
        let ip = refused_mark(&state, &caller).await;
        warn!(
            "mark for inbox entry {} as feed message {} from {} refused: not signed by the feed \
             this inbox trusts",
            req.inbox_id, req.feed_id, ip
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            "this mark is not signed by the feed this inbox trusts".to_string(),
        ));
    }
    let marked = with_db(&state, move |state| mark_entry(state, &key, req)).await?;
    marked.map(Json)
}

/// Counts one mark that failed authentication, and returns the address to name
/// in the log.
///
/// Both happen under the one lock this path already takes. The trusted-proxy
/// list lives in the state, and a separate read of it would put a second lock
/// on the drain path for the sake of one log line. The address is worked out
/// the same way a submission's address is. An operator who reads `inbox.log`
/// then sees one idea of who called, and not the proxy in one line and the
/// client in another.
async fn refused_mark(state: &Arc<Mutex<InboxState>>, caller: &Caller) -> IpAddr {
    let peer = canonical_ip(caller.peer.ip());
    let caller = caller.clone();
    with_db(state, move |state| {
        state.marks_unauthenticated += 1;
        caller.client_ip(&state.trusted_proxies)
    })
    .await
    // A failed worker is a broken host, and not a caller. Name the socket
    // address, which needs nothing from the state.
    .unwrap_or(peer)
}

/// The database half of `POST /mark`, after the mark's own signature is known
/// to be good.
///
/// The order of the checks is the order of the questions, and that order
/// decides what is filed as evidence against the sequencer. Is this mark about
/// this service at all? Is there an entry to mark? Does the sequencer's own
/// signed log contain these bytes? Are these bytes the message this mark
/// names? Are they this entry's message? Are they what the user asked for?
/// Only the last four can write a rejection row, because only those four are a
/// claim the sequencer made and got wrong. The first two are a mark about
/// something else.
fn mark_entry(
    state: &mut InboxState,
    key: &VerifyingKey,
    req: MarkRequest,
) -> Result<Entry, (StatusCode, String)> {
    // A mark for another database says nothing about this one, and its entry
    // id names a different submission here. The mark is refused before
    // anything is read or recorded. Such a mark is not evidence against the
    // sequencer. It is a sequencer that still holds records from a service
    // that lost its database. So it must not land in
    // `inbox_mark_rejections` beside the real faults.
    if req.inbox_epoch != state.epoch {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "this mark is for inbox epoch {}, but this inbox is epoch {}: entry {} in that \
                 database is not entry {} in this one",
                req.inbox_epoch, state.epoch, req.inbox_id, req.inbox_id
            ),
        ));
    }

    let row: Option<(String, Option<i64>)> = state
        .conn
        .query_row(
            "SELECT json, feed_id FROM inbox_entries WHERE inbox_id = ?1",
            params![req.inbox_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(internal)?;
    let Some((json, existing)) = row else {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("inbox entry {} does not exist", req.inbox_id),
        ));
    };
    let stored: SignedSubmission = serde_json::from_str(&json).map_err(internal)?;
    let submission = stored.submission;

    // The mark's signature proves the sequencer sent this mark. It does not
    // prove the sequencer's own log holds the message. Without the inclusion
    // check, the sequencer could sign a mark for a message it never published.
    // The entry would then stop being pending as surely as under a forged
    // mark.
    if let Err(why) = verify_inclusion(key, &req) {
        let detail = format!(
            "the mark for inbox entry {} as feed message {} proves nothing: {}, bytes: {}",
            req.inbox_id,
            req.feed_id,
            why,
            preview(&req.message)
        );
        error!("{}", detail);
        state.record_rejection(
            "proof_failed",
            Some(req.inbox_id),
            Some(req.feed_id as i64),
            &detail,
        );
        return Err((StatusCode::BAD_REQUEST, detail));
    }

    // The proof holds, so these bytes are in the sequencer's signed history.
    // What is left is *which* message they are. Every part of that question is
    // answered out of the bytes without knowing the kind: the id the mark
    // claims, and the account and nonce that say whose entry this is.
    // `message_matches` checks the nonce first for the same reason. One
    // account never has two entries under one nonce, so the pair names the
    // entry.
    let fields = match wire::envelope(req.message.as_bytes()) {
        Ok(fields) => fields,
        Err(why) => {
            let detail = format!(
                "the message on the mark for inbox entry {} is not a feed message: {}, bytes: {}",
                req.inbox_id,
                why,
                preview(&req.message)
            );
            error!("{}", detail);
            state.record_rejection(
                "proof_failed",
                Some(req.inbox_id),
                Some(req.feed_id as i64),
                &detail,
            );
            return Err((StatusCode::BAD_REQUEST, detail));
        }
    };
    if fields.id != req.feed_id {
        let detail = format!(
            "the mark claims feed message {} but carries message {}",
            req.feed_id, fields.id
        );
        error!("{}", detail);
        state.record_rejection(
            "proof_failed",
            Some(req.inbox_id),
            Some(req.feed_id as i64),
            &detail,
        );
        return Err((StatusCode::BAD_REQUEST, detail));
    }
    // The account is checked as well as the nonce, and the account is not
    // optional here. A nonce is unique per account, and not on its own.
    // `inbox_account_nonce` is an index over the pair. So two accounts may
    // hold entries under one nonce, and `GET /pending` publishes the nonces.
    // On the nonce alone, a sequencer could close account 1's entry with
    // account 2's message. That message is real, proved and in the log, and it
    // is not the submission the sequencer was asked for. That is the
    // censorship this service exists to catch, hidden inside a confirmation.
    //
    // `message_matches` compares the account too. This check only adds the
    // case `message_matches` cannot reach: a kind this build cannot read.
    if fields.account != Some(account_of(&submission))
        || fields.nonce.as_deref() != nonce_of(&submission)
    {
        let detail = format!(
            "feed message {} is account {:?}'s under nonce {:?}, and inbox entry {} is account \
             {}'s under nonce {:?}: this message is not this entry's",
            req.feed_id,
            fields.account,
            fields.nonce,
            req.inbox_id,
            account_of(&submission),
            nonce_of(&submission)
        );
        error!("{}", detail);
        state.record_rejection(
            "content_mismatch",
            Some(req.inbox_id),
            Some(req.feed_id as i64),
            &detail,
        );
        return Err((StatusCode::BAD_REQUEST, detail));
    }

    // The comparison field by field. This is the one check that has to
    // understand the kind. It catches a sequencer that logged a different
    // price under this nonce, and it must not be weakened.
    //
    // A build that cannot read the kind cannot make this comparison. That is
    // the third outcome, and not a failure. The entry is confirmed with its
    // content unchecked. It never counts as late, and `GET /status` reports it
    // under its own number. See `Confirmation`. The bytes are stored below, so
    // an upgraded build has everything it needs to make the comparison this
    // build could not.
    let confirmation = match serde_json::from_str::<OrderMessage>(&req.message) {
        Ok(message) => {
            if !message_matches(&submission, &message) {
                let detail = format!(
                    "feed message {} is not what inbox entry {} submitted: submitted {:?}, marked \
                     with {:?}",
                    req.feed_id, req.inbox_id, submission, message
                );
                error!("{}", detail);
                state.record_rejection(
                    "content_mismatch",
                    Some(req.inbox_id),
                    Some(req.feed_id as i64),
                    &detail,
                );
                return Err((StatusCode::BAD_REQUEST, detail));
            }
            Confirmation::Confirmed
        }
        Err(e) => {
            warn!(
                "inbox entry {} is confirmed as feed message {} with its content unchecked: the \
                 proof and the nonce hold, and this build cannot read the message ({}). This is \
                 not evidence against the sequencer and it is not overdue; upgrade this binary to \
                 compare the fields. Bytes: {}",
                req.inbox_id,
                req.feed_id,
                e,
                preview(&req.message)
            );
            Confirmation::ContentNotChecked
        }
    };

    match existing {
        Some(feed_id) if feed_id as OrderId != req.feed_id => {
            // Two different sequencer ids for one entry mean the sequencer
            // included the entry twice. A refusal of the second mark is not
            // enough on its own. Without a record, the only trace of a double
            // sequencing would be an HTTP status nobody kept.
            let detail = format!(
                "inbox entry {} is already feed message {}, so marking it as {} would be a second \
                 sequencing of the same submission",
                req.inbox_id, feed_id, req.feed_id
            );
            error!("{}", detail);
            state.record_rejection(
                "double_sequenced",
                Some(req.inbox_id),
                Some(req.feed_id as i64),
                &detail,
            );
            return Err((StatusCode::CONFLICT, detail));
        }
        // The same sequencer id again. The sequencer is sending a mark it
        // never got an answer to.
        Some(_) => {}
        None => {
            // The bytes are stored as they arrived, and never serialised again
            // here. These bytes are what the proof is over. Anything else
            // stored beside the entry would be evidence for a different leaf.
            state
                .conn
                .execute(
                    "UPDATE inbox_entries
                     SET feed_id = ?2, sequenced_at = ?3, feed_message = ?4, content_checked = ?5
                     WHERE inbox_id = ?1",
                    params![
                        req.inbox_id,
                        req.feed_id as i64,
                        state.clock.now_ms() as i64,
                        req.message,
                        confirmation.content_checked() as i64
                    ],
                )
                .map_err(internal)?;
        }
    }

    let row: RawRow = state
        .conn
        .query_row(
            "SELECT inbox_id, received_at, json, feed_id, sequenced_at, content_checked
             FROM inbox_entries WHERE inbox_id = ?1",
            params![req.inbox_id],
            read_raw_row,
        )
        .map_err(internal)?;
    decode_row(&row).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("inbox entry {} cannot be decoded: {}", row.0, e),
        )
    })
}

/// Query parameters for GET /entries.
#[derive(Deserialize)]
struct EntriesQuery {
    /// How many of the most recent entries to return (default 30, capped at
    /// `PAGE_LIMIT`). Ignored when `ids` is given.
    n: Option<usize>,
    /// Named entry ids, comma separated, at most `PAGE_LIMIT` of them.
    ids: Option<String>,
}

/// Answers GET /entries with the most recent entries, oldest first, for an
/// audit. With `?ids=` it answers with the named entries instead.
///
/// `?ids=` exists because "the most recent n" cannot answer "what happened to
/// *my* entry". A submitter holds one id, which `POST /submit` returned. The
/// submitter wants to know whether the entry is still pending, or which
/// sequencer message it became. `?n=` answers that only while nothing else was
/// submitted in between. After `PAGE_LIMIT` more submissions the entry falls
/// out of the page. Its absence then looks exactly like an entry the sequencer
/// never sequenced, and on this service that is the difference between "fine"
/// and "censored". A lookup by id has no page window, so it cannot produce
/// that false alarm.
async fn get_entries(
    State(state): State<Arc<Mutex<InboxState>>>,
    Query(params): Query<EntriesQuery>,
) -> Result<Json<Vec<Entry>>, (StatusCode, String)> {
    if let Some(spec) = params.ids {
        let ids = parse_entry_ids(&spec).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        return with_db(&state, move |state| {
            let (entries, unreadable) = read_by_ids(&state.conn, &ids);
            state.unreadable_entries += unreadable;
            Json(entries)
        })
        .await;
    }
    // The limit is applied in SQL. A read of the whole table, cut down
    // afterwards, made `?n=1` cost the same as a request for every row.
    let limit = params.n.unwrap_or(30).clamp(1, PAGE_LIMIT);
    with_db(&state, move |state| {
        let (entries, unreadable) = read_recent(&state.conn, limit);
        state.unreadable_entries += unreadable;
        Json(entries)
    })
    .await
}

/// Reads `?ids=` into the entry ids to look up.
///
/// The limit is the same as on every other read here: at most `PAGE_LIMIT`
/// ids. One request then cannot ask for a query without a bound, however long
/// the query string is. A longer list is refused, and not cut down. A caller
/// that asks about entries it holds ids for has to know it did not get an
/// answer about all of them. A dropped tail with no message would report an
/// entry as missing when the entry was never looked up. An id that is not a
/// number is refused for the same reason. Repeats and order do not matter. The
/// answer is oldest first either way.
fn parse_entry_ids(spec: &str) -> Result<Vec<i64>, String> {
    let mut ids = Vec::new();
    for field in spec.split(',').filter(|f| !f.trim().is_empty()) {
        let id: i64 = field.trim().parse().map_err(|_| {
            format!(
                "?ids={}: '{}' is not an entry id. It takes the inbox_id values POST /submit \
                 returned, comma separated",
                spec,
                field.trim()
            )
        })?;
        ids.push(id);
    }
    if ids.len() > PAGE_LIMIT {
        return Err(format!(
            "?ids= names {} entries and at most {} may be asked for at once; ask in pages",
            ids.len(),
            PAGE_LIMIT
        ));
    }
    Ok(ids)
}

/// One claim signed by the sequencer that this service refused, as served by
/// `GET /status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct MarkRejection {
    pub at: u64,
    pub inbox_id: Option<i64>,
    pub feed_id: Option<i64>,
    /// `double_sequenced`, `content_mismatch`, or `proof_failed`.
    pub kind: String,
    pub detail: String,
}

/// This service's verdict on the sequencer, computed from its own records.
#[derive(Serialize)]
struct StatusResponse {
    /// Entries accepted and not yet sequenced.
    pending: usize,
    /// Pending entries older than the deadline. Any count above zero means the
    /// sequencer censors or is down. Each late entry is the evidence: here is
    /// what was asked, here is when it was asked, and the sequencer's signed
    /// history provably does not contain it.
    ///
    /// The list stops at `PAGE_LIMIT`. `overdue_count` is the true total.
    overdue: Vec<Entry>,
    overdue_count: usize,
    /// Entries confirmed with their content unchecked. The proof verified and
    /// the account and nonce matched. This build could not read the message's
    /// kind, so its fields were not compared. See `Confirmation`.
    ///
    /// This is the middle of the three outcomes, and it is reported here so
    /// that it is visible. It is **not** an alarm, and `overdue_count` does
    /// not count it. The sequencer did include the entry, and proved it. A
    /// count above zero means this service is older than the messages the
    /// sequencer publishes, and an upgrade restores the field comparison.
    /// `GET /entries` lists the entries, each with `content_checked: false`.
    /// Their bytes are kept, so nothing has to be fetched again to check them.
    confirmed_content_unchecked: i64,
    /// Milliseconds the oldest pending entry has waited, if there is one.
    oldest_wait_ms: Option<u64>,
    deadline_ms: u64,
    /// The pending cap. `pending` at the cap means this service refuses
    /// submissions. That is its own kind of failure, and a reader should not
    /// have to work it out from a 503 that somebody else received.
    pending_cap: i64,
    /// Rows that could not be decoded into an entry since this process
    /// started. A row that cannot be read disappears from `/pending`, from
    /// `/entries` and from the late list at once, so this count says so.
    unreadable_entries: u64,
    /// Marks refused because the pinned sequencer key did not sign them.
    marks_unauthenticated: u64,
    /// Marks signed by the sequencer that this service refused: a double
    /// sequencing, or a mark that carries a message which is not the
    /// submission. Newest first.
    mark_rejections: Vec<MarkRejection>,
}

/// Answers GET /status: does the sequencer meet the inclusion deadline?
///
/// Everything in the answer comes from one query, under one lock. The old
/// version ran the pending query twice, once to count and once to list. It
/// could answer `pending: 0` beside a non-empty `overdue` list when an entry
/// was marked between the two queries. This endpoint exists to be evidence a
/// third party can trust, and an answer that contradicts itself is worse than
/// no answer.
async fn get_status(
    State(state): State<Arc<Mutex<InboxState>>>,
) -> Result<Json<StatusResponse>, (StatusCode, String)> {
    with_db(&state, |state| {
        let now = state.clock.now_ms();
        let deadline_ms = state.deadline_ms;
        let cutoff = now.saturating_sub(deadline_ms);
        let snapshot = pending_snapshot(&state.conn, cutoff, PAGE_LIMIT);
        state.unreadable_entries += snapshot.unreadable;
        let oldest_wait_ms = snapshot
            .entries
            .first()
            .map(|entry| now.saturating_sub(entry.received_at));
        let overdue: Vec<Entry> = snapshot
            .entries
            .into_iter()
            .filter(|entry| entry.received_at < cutoff)
            .collect();
        // The `inbox_content_unchecked` partial index answers this count. The
        // count never reads the fully checked rows, which are the rows that
        // keep growing.
        let confirmed_content_unchecked: i64 = state
            .conn
            .query_row(
                "SELECT COUNT(*) FROM inbox_entries WHERE content_checked = 0",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|e| {
                error!("the content-unchecked count could not be read: {}", e);
                0
            });
        Json(StatusResponse {
            pending: snapshot.pending,
            overdue_count: snapshot.overdue,
            overdue,
            confirmed_content_unchecked,
            oldest_wait_ms,
            deadline_ms,
            pending_cap: MAX_PENDING,
            unreadable_entries: state.unreadable_entries,
            marks_unauthenticated: state.marks_unauthenticated,
            mark_rejections: read_rejections(&state.conn, 20),
        })
    })
    .await
}

// ---------------------------------------------------------------------------
// Database reads
// ---------------------------------------------------------------------------

/// A row of `inbox_entries` before it is decoded.
type RawRow = (i64, u64, String, Option<i64>, Option<i64>, Option<i64>);

fn read_raw_row(row: &rusqlite::Row) -> rusqlite::Result<RawRow> {
    Ok((
        row.get::<_, i64>(0)?,
        row.get::<_, i64>(1)? as u64,
        row.get::<_, String>(2)?,
        row.get::<_, Option<i64>>(3)?,
        row.get::<_, Option<i64>>(4)?,
        row.get::<_, Option<i64>>(5)?,
    ))
}

/// Decodes one stored row. The `json` column holds the whole
/// `SignedSubmission`: the terms and the proof together. The proof is only
/// worth keeping if it cannot be separated from what it proves.
///
/// A row written before submissions were signed holds a bare `Submission`, and
/// fails here. That failure is deliberate, and such a row is not migrated.
/// Nobody can show that submission was authorised. An invented author for it
/// would be the exact thing this change exists to prevent. The row is counted
/// and reported as an unreadable entry, see `decode_rows`, so it cannot
/// disappear without a message. An `inbox.db` from before this change should
/// be deleted.
fn decode_row(row: &RawRow) -> Result<Entry, serde_json::Error> {
    let signed: SignedSubmission = serde_json::from_str(&row.2)?;
    Ok(Entry {
        inbox_id: row.0,
        received_at: row.1,
        submission: signed.submission,
        public_key: signed.public_key,
        signature: signed.signature,
        feed_id: row.3.map(|id| id as OrderId),
        sequenced_at: row.4.map(|t| t as u64),
        content_checked: row.5.map(|checked| checked != 0),
    })
}

/// Decodes one stored row, and reports a row that cannot be read instead of
/// dropping it with no message. Every read path calls this function, so the
/// report is the same wherever a row goes missing.
fn decode_row_reporting(row: &RawRow) -> Option<Entry> {
    match decode_row(row) {
        Ok(entry) => Some(entry),
        Err(e) => {
            let raw: String = row.2.chars().take(200).collect();
            error!(
                "inbox entry {} (received_at {}) cannot be decoded and is missing from every \
                 answer this inbox gives: {}, stored json: {}",
                row.0, row.1, e, raw
            );
            None
        }
    }
}

/// Decodes raw rows, and reports the ones that cannot be read instead of
/// dropping them with no message.
///
/// A stored entry that fails to decode disappears from `/pending`, from
/// `/entries` and from the late evidence at the same moment. Nothing
/// `POST /submit` accepts today can produce such a row. A schema change, or an
/// edit made directly against `inbox.db`, can. That is exactly the case where
/// a submission that stops existing must not stop existing without a message.
fn decode_rows(rows: Vec<RawRow>) -> (Vec<Entry>, u64) {
    let mut entries = Vec::with_capacity(rows.len());
    let mut unreadable = 0;
    for row in rows {
        match decode_row_reporting(&row) {
            Some(entry) => entries.push(entry),
            None => unreadable += 1,
        }
    }
    (entries, unreadable)
}

fn raw_rows(conn: &Connection, sql: &str, params: impl rusqlite::Params) -> Vec<RawRow> {
    let mut stmt = match conn.prepare(sql) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("inbox query failed to prepare: {}", e);
            return Vec::new();
        }
    };
    let rows = match stmt.query_map(params, read_raw_row) {
        Ok(rows) => rows,
        Err(e) => {
            error!("inbox query failed: {}", e);
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for row in rows {
        match row {
            Ok(row) => out.push(row),
            Err(e) => error!(
                "an inbox row could not be read and is missing from this answer: {}",
                e
            ),
        }
    }
    out
}

fn read_pending(conn: &Connection, limit: usize) -> (Vec<Entry>, u64) {
    decode_rows(raw_rows(
        conn,
        "SELECT inbox_id, received_at, json, feed_id, sequenced_at, content_checked
         FROM inbox_entries WHERE feed_id IS NULL ORDER BY inbox_id LIMIT ?1",
        params![limit as i64],
    ))
}

/// The named entries, oldest first. An id that nothing is stored under is
/// absent from the answer. The caller asked whether the entry exists, and an
/// empty result is that answer.
///
/// The ids are bound as parameters, one placeholder each, and never pasted
/// into the SQL. `parse_entry_ids` already refused anything that is not an
/// `i64`, so this is a second defence. A read endpoint that builds SQL out of
/// a query string is still a habit worth not having.
fn read_by_ids(conn: &Connection, ids: &[i64]) -> (Vec<Entry>, u64) {
    if ids.is_empty() {
        return (Vec::new(), 0);
    }
    let placeholders = std::iter::repeat_n("?", ids.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT inbox_id, received_at, json, feed_id, sequenced_at, content_checked
         FROM inbox_entries WHERE inbox_id IN ({}) ORDER BY inbox_id",
        placeholders
    );
    decode_rows(raw_rows(conn, &sql, rusqlite::params_from_iter(ids)))
}

fn read_recent(conn: &Connection, limit: usize) -> (Vec<Entry>, u64) {
    let (mut entries, unreadable) = decode_rows(raw_rows(
        conn,
        "SELECT inbox_id, received_at, json, feed_id, sequenced_at, content_checked
         FROM inbox_entries ORDER BY inbox_id DESC LIMIT ?1",
        params![limit as i64],
    ));
    entries.reverse();
    (entries, unreadable)
}

struct PendingSnapshot {
    pending: usize,
    overdue: usize,
    entries: Vec<Entry>,
    unreadable: u64,
}

impl PendingSnapshot {
    fn empty() -> Self {
        PendingSnapshot {
            pending: 0,
            overdue: 0,
            entries: Vec::new(),
            unreadable: 0,
        }
    }
}

/// The whole pending picture in one query: the exact number pending, the exact
/// number late, and the oldest `limit` of the pending entries.
///
/// `COUNT(*) OVER ()` and `SUM(...) OVER ()` are computed over every row the
/// `WHERE` selects, before `LIMIT` cuts the page. So the totals are true
/// totals and the page is still bounded. Everything `GET /status` answers with
/// comes from this one read of the database. Two reads let the answer
/// contradict itself.
fn pending_snapshot(conn: &Connection, cutoff_ms: u64, limit: usize) -> PendingSnapshot {
    let sql = "SELECT COUNT(*) OVER () AS pending_total,
                      SUM(CASE WHEN received_at < ?1 THEN 1 ELSE 0 END) OVER () AS overdue_total,
                      inbox_id, received_at, json, feed_id, sequenced_at, content_checked
               FROM inbox_entries
               WHERE feed_id IS NULL
               ORDER BY inbox_id
               LIMIT ?2";
    let mut stmt = match conn.prepare(sql) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("inbox status query failed to prepare: {}", e);
            return PendingSnapshot::empty();
        }
    };
    let rows = stmt.query_map(params![cutoff_ms as i64, limit as i64], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            (
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)? as u64,
                row.get::<_, String>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
            ),
        ))
    });
    let rows = match rows {
        Ok(rows) => rows,
        Err(e) => {
            error!("inbox status query failed: {}", e);
            return PendingSnapshot::empty();
        }
    };
    let mut snapshot = PendingSnapshot::empty();
    for row in rows {
        match row {
            Ok((pending_total, overdue_total, raw)) => {
                snapshot.pending = pending_total.max(0) as usize;
                snapshot.overdue = overdue_total.max(0) as usize;
                match decode_row_reporting(&raw) {
                    Some(entry) => snapshot.entries.push(entry),
                    None => snapshot.unreadable += 1,
                }
            }
            Err(e) => error!("an inbox row could not be read for /status: {}", e),
        }
    }
    snapshot
}

fn read_rejections(conn: &Connection, limit: usize) -> Vec<MarkRejection> {
    let mut stmt = match conn.prepare(
        "SELECT at, inbox_id, feed_id, kind, detail
         FROM inbox_mark_rejections ORDER BY id DESC LIMIT ?1",
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("inbox rejection query failed to prepare: {}", e);
            return Vec::new();
        }
    };
    let rows = stmt.query_map(params![limit as i64], |row| {
        Ok(MarkRejection {
            at: row.get::<_, i64>(0)? as u64,
            inbox_id: row.get(1)?,
            feed_id: row.get(2)?,
            kind: row.get(3)?,
            detail: row.get(4)?,
        })
    });
    match rows {
        Ok(rows) => rows
            .filter_map(|row| match row {
                Ok(rejection) => Some(rejection),
                Err(e) => {
                    error!("a mark rejection row could not be read: {}", e);
                    None
                }
            })
            .collect(),
        Err(e) => {
            error!("inbox rejection query failed: {}", e);
            Vec::new()
        }
    }
}

impl InboxState {
    /// Records a mark the sequencer signed and this service refused anyway.
    /// The record then lives longer than the HTTP response.
    fn record_rejection(
        &mut self,
        kind: &str,
        inbox_id: Option<i64>,
        feed_id: Option<i64>,
        detail: &str,
    ) {
        let at = self.clock.now_ms() as i64;
        if let Err(e) = self.conn.execute(
            "INSERT INTO inbox_mark_rejections (at, inbox_id, feed_id, kind, detail)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![at, inbox_id, feed_id, kind, detail],
        ) {
            error!("could not record the refused mark ({}): {}", kind, e);
            return;
        }
        if let Err(e) = self.conn.execute(
            "DELETE FROM inbox_mark_rejections
             WHERE id <= (SELECT MAX(id) FROM inbox_mark_rejections) - ?1",
            params![MAX_REJECTIONS],
        ) {
            error!("could not trim the refused-mark log: {}", e);
        }
    }
}

fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Answers whether a database constraint stopped this write, instead of the
/// write failing for another reason.
fn is_constraint_violation(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(err, _) if err.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{OPERATOR_ACCOUNT, OrderType, TimeInForce};
    use crate::matcher::MatcherState;

    /// The epoch every test copy of this service announces.
    const TEST_EPOCH: &str = "0123456789abcdef";

    /// A caller that connects to this service directly. That is the case in
    /// every test that is not about a proxy.
    fn peer() -> Caller {
        Caller::from_socket("127.0.0.1:40000")
    }

    /// This service on an in-memory database, already trusting the returned
    /// key.
    fn test_inbox(deadline_ms: u64) -> (Arc<Mutex<InboxState>>, SigningKey) {
        test_inbox_behind(deadline_ms, TrustedProxies::none())
    }

    /// The same builder, for a service the operator put behind a reverse
    /// proxy.
    fn test_inbox_behind(
        deadline_ms: u64,
        trusted_proxies: TrustedProxies,
    ) -> (Arc<Mutex<InboxState>>, SigningKey) {
        let key = logchain::ephemeral_key();
        let conn = Connection::open_in_memory().expect("in-memory database");
        init_schema(&conn).expect("schema");
        let state = InboxState {
            conn,
            deadline_ms,
            clock: Clock::from_wall(1_700_000_000_000),
            epoch: TEST_EPOCH.to_string(),
            feed_key: Some(key.verifying_key()),
            feed_url: None,
            limiter: RateLimiter::new(),
            trusted_proxies,
            unreadable_entries: 0,
            marks_unauthenticated: 0,
        };
        (Arc::new(Mutex::new(state)), key)
    }

    /// The session these tests sign for. Sixteen lowercase hex characters, the
    /// shape `feed::new_session` prints.
    const TEST_SESSION: &str = "349d462ced25bb2b";

    /// An order from account 7 under a fresh nonce. Every real submission
    /// carries a fresh nonce.
    fn order(price: f64, quantity: f64) -> Submission {
        order_with_nonce(price, quantity, &new_nonce())
    }

    fn order_with_nonce(price: f64, quantity: f64, nonce: &str) -> Submission {
        order_with_terms(
            price,
            quantity,
            nonce,
            OrderType::Limit,
            TimeInForce::GoodTillCancel,
            false,
        )
    }

    /// The same order, with the three terms named. Every test that cares about
    /// the terms builds its submission here, so the plain builder above stays
    /// the plain limit order it always was.
    fn order_with_terms(
        price: f64,
        quantity: f64,
        nonce: &str,
        order_type: OrderType,
        time_in_force: TimeInForce,
        post_only: bool,
    ) -> Submission {
        Submission::Order {
            account: 7,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            price,
            quantity,
            nonce: Some(nonce.to_string()),
            session: Some(TEST_SESSION.to_string()),
            order_type,
            time_in_force,
            post_only,
        }
    }

    /// The signed `ListSymbol` message that opens a market in a history.
    ///
    /// The engine these tests drive ignores an operator message it cannot
    /// check (ENGINE.md section 3.1). An unsigned listing would open no
    /// market, and every order after it would be refused for the one reason
    /// these tests are not about. The session is empty. An engine that has
    /// never spoken to a sequencer announces no session, and reads the
    /// statement's session line as empty.
    fn listing(id: OrderId, symbol: &str) -> OrderMessage {
        crate::operator::signed_as(
            &ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]),
            "",
            OrderMessage::ListSymbol {
                id,
                timestamp: 1,
                account: OPERATOR_ACCOUNT,
                symbol: symbol.to_string(),
                price_step: 0.01,
                quantity_step: 0.1,
                nonce: Some(format!("{:032x}", id)),
                public_key: String::new(),
                signature: String::new(),
            },
        )
    }

    /// The message a sequencer publishes for this submission. This helper
    /// calls the one conversion both submission paths call, so a test never
    /// stands in for a message the sequencer would not really produce.
    fn message_for(id: OrderId, submission: &Submission) -> OrderMessage {
        message_from(id, 1, submission)
    }

    /// A stand-in for the sequencer's side of a mark: an RFC 9162 tree over
    /// the stored bytes of a history, a head signed over its root, and
    /// inclusion proofs out of that tree.
    ///
    /// The tree and the proofs are real, and not stubs. `POST /mark` now
    /// checks arithmetic over those bytes, so a stubbed proof would only prove
    /// that the test agrees with itself.
    struct TestFeed {
        session: String,
        /// The stored bytes of every message published, in sequencer order.
        /// Message `n` is leaf `n - 1`, which is the sequencer's own rule.
        leaves: Vec<String>,
    }

    impl TestFeed {
        fn new() -> Self {
            TestFeed {
                session: "sess".to_string(),
                leaves: Vec::new(),
            }
        }

        /// Publishes `message` as sequencer message `message.id()`. It fills
        /// the history before that message with other traffic, so the leaf
        /// index is a real one.
        fn publish(&mut self, message: &OrderMessage) -> String {
            let json =
                String::from_utf8(logchain::canonical_bytes(message)).expect("json is utf-8");
            self.publish_bytes(message.id(), &json)
        }

        /// The same, for bytes this build did not produce: a message kind that
        /// a sequencer newer than this binary published.
        fn publish_bytes(&mut self, id: OrderId, json: &str) -> String {
            let index = (id - 1) as usize;
            while self.leaves.len() <= index {
                let filler = self.leaves.len() as OrderId + 1;
                self.leaves
                    .push(format!("{{\"Filler\":{{\"id\":{}}}}}", filler));
            }
            self.leaves[index] = json.to_string();
            json.to_string()
        }

        fn tree(&self) -> merkle::MerkleTree {
            merkle::MerkleTree::from_entries(&self.leaves)
        }

        /// The head this sequencer would serve now, signed by `key`.
        fn head(&self, key: &SigningKey) -> TreeHead {
            let tree = self.tree();
            let root = tree.root();
            let timestamp = 1_700_000_000_000;
            TreeHead {
                session: self.session.clone(),
                timestamp,
                tree_size: tree.len(),
                root_hash: logchain::to_hex(&root),
                signature: logchain::to_hex(
                    &logchain::sign_tree_head(key, &self.session, timestamp, tree.len(), &root)
                        .to_bytes(),
                ),
            }
        }

        fn path(&self, feed_id: OrderId) -> Vec<String> {
            let tree = self.tree();
            tree.inclusion_proof(feed_id - 1, tree.len())
                .expect("the message is in the tree")
                .iter()
                .map(|node| logchain::to_hex(node))
                .collect()
        }

        fn bytes(&self, feed_id: OrderId) -> String {
            self.leaves[(feed_id - 1) as usize].clone()
        }

        /// One mark, built the way `sequence_drained` builds it.
        fn mark(
            &self,
            key: &SigningKey,
            inbox_epoch: &str,
            inbox_id: i64,
            feed_id: OrderId,
        ) -> MarkRequest {
            signed_mark(
                key,
                inbox_epoch,
                inbox_id,
                feed_id,
                &self.bytes(feed_id),
                self.head(key),
                self.path(feed_id),
            )
        }
    }

    /// The mark the sequencer sends for one entry, over a history whose last
    /// message is that entry's message. This is the common case in these
    /// tests.
    fn mark_for(
        key: &SigningKey,
        inbox_epoch: &str,
        inbox_id: i64,
        message: &OrderMessage,
    ) -> MarkRequest {
        let mut feed = TestFeed::new();
        feed.publish(message);
        feed.mark(key, inbox_epoch, inbox_id, message.id())
    }

    /// Moves an entry far enough into the past that any deadline has passed.
    /// "Late" is then a fact about the test, and not about how long the test
    /// ran.
    async fn backdate(state: &Arc<Mutex<InboxState>>) {
        with_db(state, |state| {
            state
                .conn
                .execute("UPDATE inbox_entries SET received_at = 0", [])
                .expect("backdate");
        })
        .await
        .expect("worker");
    }

    /// The key the tests' account 7 submits under. The key is fixed, and not
    /// random, because the second submission for an account has to carry the
    /// key the first submission pinned.
    fn account_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// A submission with account 7's proof on it, in the shape `POST /submit`
    /// takes.
    ///
    /// A submission off the engine's price step or quantity step has no
    /// statement to sign, so it gets a placeholder signature. The checks
    /// refuse such a submission before any signature is read, which is the
    /// order the handler checks in.
    fn signed_by(key: &SigningKey, submission: Submission) -> SignedSubmission {
        match sign_submission(key, &submission) {
            Some(signed) => signed,
            None => SignedSubmission {
                submission,
                public_key: logchain::to_hex(key.verifying_key().as_bytes()),
                signature: logchain::to_hex(&[0u8; 64]),
            },
        }
    }

    fn signed(submission: Submission) -> SignedSubmission {
        signed_by(&account_key(), submission)
    }

    async fn submit_ok(state: &Arc<Mutex<InboxState>>, submission: Submission) -> Entry {
        submit(
            State(Arc::clone(state)),
            peer(),
            Ok(Json(signed(submission))),
        )
        .await
        .expect("submission accepted")
        .0
    }

    async fn status(state: &Arc<Mutex<InboxState>>) -> StatusResponse {
        get_status(State(Arc::clone(state)))
            .await
            .expect("status")
            .0
    }

    async fn entries_by_ids(state: &Arc<Mutex<InboxState>>, ids: &str) -> Vec<Entry> {
        get_entries(
            State(Arc::clone(state)),
            Query(EntriesQuery {
                n: None,
                ids: Some(ids.to_string()),
            }),
        )
        .await
        .expect("entries")
        .0
    }

    // -----------------------------------------------------------------------
    // Cross-origin submissions
    //
    // The rules and their own tests are in `cors.rs`. These tests fix what
    // this service grants under those rules.
    // -----------------------------------------------------------------------

    use crate::cors::testing::{default_origins, headers};
    use crate::cors::{Cors, cors_for};
    use axum::http::Method;

    /// This service's policy, exactly as `inbox_router` builds it.
    fn inbox_policy(allowed: Vec<String>) -> CorsPolicy {
        CorsPolicy::new(allowed, &SUBMISSION_PATHS, "inbox")
    }

    /// This service grants a browser one path and no more. `/mark` also takes
    /// a POST, and `/mark` is the one call that can make censorship evidence
    /// disappear. So no origin list may make `/mark` open to a preflight
    /// request.
    #[test]
    fn only_submit_may_be_preflighted() {
        let allowed = inbox_policy(default_origins());
        let preflight = headers(&[
            ("origin", "http://127.0.0.1:3001"),
            ("access-control-request-method", "POST"),
            ("access-control-request-headers", "content-type"),
        ]);
        let (_, decision) = cors_for(&allowed, &Method::OPTIONS, "/submit", &preflight);
        assert_eq!(decision, Cors::PreflightAllowed);
        for path in ["/mark", "/pending", "/status", "/entries", "/anything"] {
            let (_, decision) = cors_for(&allowed, &Method::OPTIONS, path, &preflight);
            assert_eq!(decision, Cors::PreflightRefused, "{}", path);
        }
        // A port next to the allowed one, and an origin that looks close to
        // the allowed one, are not on the list.
        for origin in [
            "http://127.0.0.1:3002",
            "https://127.0.0.1:3001",
            "http://127.0.0.1.evil.example",
            "null",
        ] {
            let refused = headers(&[
                ("origin", origin),
                ("access-control-request-method", "POST"),
            ]);
            let (seen, decision) = cors_for(&allowed, &Method::OPTIONS, "/submit", &refused);
            assert_eq!(seen.as_deref(), Some(origin));
            assert_eq!(decision, Cors::PreflightRefused, "{}", origin);
        }
    }

    /// The decisions above, over HTTP. The read endpoints matter as much as
    /// the write endpoint here. A page that may submit and may not read the
    /// answer can show the visitor that their entry exists, and never that the
    /// entry was sequenced. That transition is what V3 has to show.
    #[tokio::test]
    async fn the_router_grants_exactly_what_the_ui_needs_and_nothing_else() {
        use axum::body::Body;
        use axum::extract::Request;
        use axum::http::header;
        use tower::ServiceExt;

        let (state, _key) = test_inbox(5_000);
        let origins = default_origins();
        let router = || inbox_router(Arc::clone(&state), origins.clone());

        let granted = router()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/submit")
                    .header("origin", "http://localhost:3001")
                    .header("access-control-request-method", "POST")
                    .header("access-control-request-headers", "content-type")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("the router answers");
        assert_eq!(granted.status(), StatusCode::NO_CONTENT);
        let head = granted.headers();
        assert_eq!(
            head.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "http://localhost:3001",
            "the matched entry from the operator's list, not a reflection"
        );
        assert_eq!(
            head.get(header::ACCESS_CONTROL_ALLOW_METHODS).unwrap(),
            "POST"
        );
        assert_eq!(
            head.get(header::ACCESS_CONTROL_ALLOW_HEADERS).unwrap(),
            "content-type"
        );
        assert_eq!(head.get(header::VARY).unwrap(), "origin");
        assert!(
            head.get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS).is_none(),
            "a submission must never carry cookies: the signature is what speaks for an account"
        );

        // A mark is the sequencer's call. A preflight request from a browser
        // is refused, even from the origin the UI is served from.
        let mark = router()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/mark")
                    .header("origin", "http://localhost:3001")
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("the router answers");
        assert_eq!(mark.status(), StatusCode::FORBIDDEN);
        assert!(
            mark.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );

        // A visitor watches what happens to their entry. That is why this
        // service is on screen at all. So `/status` and `/entries` are
        // readable from a listed origin, and hidden from anything else.
        for path in ["/status", "/entries?n=5"] {
            for (origin, expected) in [
                ("http://127.0.0.1:3001", Some("http://127.0.0.1:3001")),
                ("https://evil.example", None),
            ] {
                let response = router()
                    .oneshot(
                        Request::builder()
                            .uri(path)
                            .header("origin", origin)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .expect("the router answers");
                assert_eq!(response.status(), StatusCode::OK, "{} {}", path, origin);
                assert_eq!(
                    response
                        .headers()
                        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                        .map(|v| v.to_str().unwrap()),
                    expected,
                    "{} {}",
                    path,
                    origin
                );
            }
        }

        // The sequencer's drain and the CLI send no Origin, and nothing about
        // their answers changes.
        let plain = router()
            .oneshot(
                Request::builder()
                    .uri("/pending")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("the router answers");
        assert_eq!(plain.status(), StatusCode::OK);
        // The answer grants nothing, and still says it varies on `Origin`.
        // That header is what stops a shared cache from serving this
        // not-granted copy to a browser. See the same assertion in `feed.rs`.
        assert!(
            plain
                .headers()
                .get_all(header::VARY)
                .iter()
                .any(|v| v.to_str().is_ok_and(|v| v.contains("origin")))
        );
        assert!(
            plain
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert!(
            plain.headers().get(PENDING_EPOCH_HEADER).is_some(),
            "the drain still gets the epoch it keys its records by"
        );
    }

    /// This service started with no `--ui-origin` grants nothing. That is
    /// worth a test on this service in particular. An empty list must mean
    /// "nobody", and never "everybody", on the path that exists for people the
    /// sequencer refused.
    #[tokio::test]
    async fn an_empty_allowlist_lets_no_browser_submit() {
        use axum::body::Body;
        use axum::extract::Request;
        use tower::ServiceExt;

        let (state, _key) = test_inbox(5_000);
        let response = inbox_router(state, Vec::new())
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/submit")
                    .header("origin", "http://127.0.0.1:3001")
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("the router answers");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// The read a submitter needs: what happened to the entry whose id they
    /// hold. `?n=` cannot answer that once other submissions have pushed the
    /// entry off the page. On this service an entry that cannot be found looks
    /// exactly like an entry the sequencer never sequenced.
    #[tokio::test]
    async fn an_entry_can_be_looked_up_by_its_own_id() {
        let (state, key) = test_inbox(5_000);
        let mine = submit_ok(&state, order(100.25, 5.0)).await;
        // Enough other traffic that the entry is far outside any page a client
        // would ask for.
        for i in 0..40 {
            submit_ok(&state, order(100.25, 1.0 + i as f64)).await;
        }

        let found = entries_by_ids(&state, &mine.inbox_id.to_string()).await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].inbox_id, mine.inbox_id);
        assert_eq!(found[0].feed_id, None, "still pending");

        // The entry is sequenced, and the same lookup now names the sequencer
        // message. This service has to be able to show that change.
        let request = mark_for(
            &key,
            TEST_EPOCH,
            mine.inbox_id,
            &message_for(4242, &mine.submission),
        );
        let _ = mark(State(Arc::clone(&state)), peer(), Json(request))
            .await
            .expect("the feed marks it");
        let found = entries_by_ids(&state, &mine.inbox_id.to_string()).await;
        assert_eq!(found[0].feed_id, Some(4242));

        // Several ids at once, oldest first. An id that nothing is stored
        // under is absent from the answer, and is not an error. The caller
        // asked whether the entry exists, and absence is that answer.
        let several = entries_by_ids(&state, &format!("3,{},99999,1", mine.inbox_id)).await;
        assert_eq!(
            several.iter().map(|e| e.inbox_id).collect::<Vec<_>>(),
            vec![1, 3]
        );

        // A malformed id is refused, and not skipped. A page larger than every
        // other read here allows is refused too. A caller that asked about 300
        // entries and got 200 with no message would read the missing 100 as
        // gone.
        assert!(parse_entry_ids("1,two,3").is_err());
        assert!(
            parse_entry_ids(
                &(0..PAGE_LIMIT + 1)
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )
            .is_err()
        );
        assert_eq!(parse_entry_ids(" 1 , 2 ,").unwrap(), vec![1, 2]);
    }

    /// This is why `/mark` is authenticated. Without authentication, anyone
    /// who knows an entry id can make that entry stop being pending, and the
    /// censorship alarm then reports nothing wrong.
    #[tokio::test]
    async fn an_unsigned_mark_is_refused_and_the_entry_stays_pending() {
        let (state, _key) = test_inbox(5_000);
        let entry = submit_ok(&state, order(100.25, 5.0)).await;

        let forged = MarkRequest {
            inbox_id: entry.inbox_id,
            feed_id: 999_999,
            inbox_epoch: TEST_EPOCH.to_string(),
            message: "{\"New\":{\"id\":999999}}".to_string(),
            tree_head: TreeHead {
                session: "whatever".to_string(),
                timestamp: 1,
                tree_size: 999_999,
                root_hash: logchain::to_hex(&[0u8; 32]),
                signature: String::new(),
            },
            inclusion_path: Vec::new(),
            signature: String::new(),
        };
        let refused = mark(State(Arc::clone(&state)), peer(), Json(forged))
            .await
            .expect_err("an unsigned mark must be refused");
        assert_eq!(refused.0, StatusCode::UNAUTHORIZED);

        let status = status(&state).await;
        assert_eq!(status.pending, 1, "the entry must still be pending");
        assert_eq!(status.marks_unauthenticated, 1);
    }

    /// The same attack, with a real signature made by the wrong key.
    #[tokio::test]
    async fn a_mark_signed_by_a_stranger_is_refused() {
        let (state, _key) = test_inbox(5_000);
        let entry = submit_ok(&state, order(100.25, 5.0)).await;
        let stranger = logchain::ephemeral_key();

        let message = message_for(12, &entry.submission);
        let forged = mark_for(&stranger, TEST_EPOCH, entry.inbox_id, &message);
        let refused = mark(State(Arc::clone(&state)), peer(), Json(forged))
            .await
            .expect_err("a stranger's signature must be refused");
        assert_eq!(refused.0, StatusCode::UNAUTHORIZED);
        assert_eq!(status(&state).await.pending, 1);
    }

    /// With no key pinned, and no sequencer to learn a key from, every mark is
    /// refused. The entry stays pending and goes late, which is the visible
    /// failure.
    #[tokio::test]
    async fn without_a_pinned_key_every_mark_is_refused() {
        let (state, key) = test_inbox(5_000);
        with_db(&state, |state| state.feed_key = None)
            .await
            .unwrap();
        let entry = submit_ok(&state, order(100.25, 5.0)).await;

        let message = message_for(12, &entry.submission);
        let honest = mark_for(&key, TEST_EPOCH, entry.inbox_id, &message);
        let refused = mark(State(Arc::clone(&state)), peer(), Json(honest))
            .await
            .expect_err("no pinned key means no mark can be checked");
        assert_eq!(refused.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status(&state).await.pending, 1);
    }

    #[tokio::test]
    async fn a_mark_the_feed_signed_is_accepted_and_repeatable() {
        let (state, key) = test_inbox(5_000);
        let entry = submit_ok(&state, order(100.25, 5.0)).await;
        let message = message_for(12, &entry.submission);
        let signed = mark_for(&key, TEST_EPOCH, entry.inbox_id, &message);

        let marked = mark(State(Arc::clone(&state)), peer(), Json(signed.clone()))
            .await
            .expect("a properly signed mark is accepted")
            .0;
        assert_eq!(marked.feed_id, Some(12));
        // The sequencer sends the mark again after a lost response. The answer
        // is the same, and there is no conflict.
        let again = mark(State(Arc::clone(&state)), peer(), Json(signed))
            .await
            .expect("a repeated mark is a no-op")
            .0;
        assert_eq!(again.feed_id, Some(12));

        let status = status(&state).await;
        assert_eq!(status.pending, 0);
        assert!(status.overdue.is_empty());
        assert!(status.mark_rejections.is_empty());
    }

    /// A signature proves who sent the mark. It does not prove the message is
    /// the user's order. A mark against some other message would close the
    /// entry as surely as an honest mark.
    #[tokio::test]
    async fn a_mark_carrying_a_different_order_is_refused_and_recorded() {
        let (state, key) = test_inbox(5_000);
        let entry = submit_ok(&state, order(100.25, 5.0)).await;
        // The same order, with a price one cent away.
        let message = message_for(12, &order(100.26, 5.0));
        let signed = mark_for(&key, TEST_EPOCH, entry.inbox_id, &message);

        let refused = mark(State(Arc::clone(&state)), peer(), Json(signed))
            .await
            .expect_err("the message is not what was submitted");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);

        let status = status(&state).await;
        assert_eq!(status.pending, 1);
        assert_eq!(status.mark_rejections.len(), 1);
        assert_eq!(status.mark_rejections[0].kind, "content_mismatch");
    }

    /// The 409 used to leave no trace: no log line, no row, nothing to find
    /// later.
    #[tokio::test]
    async fn a_second_sequencing_is_refused_and_recorded() {
        let (state, key) = test_inbox(5_000);
        let entry = submit_ok(&state, order(100.25, 5.0)).await;
        let first = mark_for(
            &key,
            TEST_EPOCH,
            entry.inbox_id,
            &message_for(12, &entry.submission),
        );
        let marked = mark(State(Arc::clone(&state)), peer(), Json(first))
            .await
            .expect("first mark")
            .0;
        assert_eq!(marked.feed_id, Some(12));

        let second = mark_for(
            &key,
            TEST_EPOCH,
            entry.inbox_id,
            &message_for(13, &entry.submission),
        );
        let refused = mark(State(Arc::clone(&state)), peer(), Json(second))
            .await
            .expect_err("marking the same entry as a second message is a conflict");
        assert_eq!(refused.0, StatusCode::CONFLICT);

        let status = status(&state).await;
        assert_eq!(status.mark_rejections.len(), 1);
        assert_eq!(status.mark_rejections[0].kind, "double_sequenced");
        assert_eq!(status.mark_rejections[0].inbox_id, Some(entry.inbox_id));
        assert_eq!(status.mark_rejections[0].feed_id, Some(13));
        // The first pair of entry and message stands.
        let entries = get_entries(
            State(Arc::clone(&state)),
            Query(EntriesQuery {
                n: Some(10),
                ids: None,
            }),
        )
        .await
        .expect("entries")
        .0;
        assert_eq!(entries[0].feed_id, Some(12));
    }

    // -----------------------------------------------------------------------
    // The three outcomes of ENGINE.md section 7
    //
    // The three outcomes are: confirmed; confirmed with the content unchecked;
    // late. Only the third is an alarm. These tests fix the behaviour after a
    // real bug, where the middle outcome came out as the third.
    // -----------------------------------------------------------------------

    /// The bug. A message kind this build cannot read used to produce no
    /// confirmation at all. The entry then sat pending until the deadline, and
    /// this service publicly reported an honest sequencer as late.
    ///
    /// Such an entry is confirmed now. The proof is hashing over bytes, and
    /// the nonce is read out of those bytes without knowing the kind.
    #[tokio::test]
    async fn a_kind_this_build_cannot_read_is_confirmed_not_reported_late() {
        let (state, key) = test_inbox(5_000);
        let entry = submit_ok(&state, order(100.25, 5.0)).await;
        let nonce = nonce_of(&entry.submission)
            .expect("submitted with a nonce")
            .to_string();
        backdate(&state).await;

        // Before the mark arrives, this is exactly what censorship looks like
        // here.
        let before = status(&state).await;
        assert_eq!(before.overdue_count, 1, "the deadline has passed");

        // A kind that a sequencer newer than this binary published. Its bytes
        // hash like any other leaf. Nothing here can turn those bytes into an
        // `OrderMessage`.
        let bytes = format!(
            "{{\"Swap\":{{\"id\":12,\"timestamp\":1,\"account\":7,\"nonce\":\"{}\",\
             \"legs\":[{{\"symbol\":\"ETH-USDC\"}}]}}}}",
            nonce
        );
        assert!(
            serde_json::from_str::<OrderMessage>(&bytes).is_err(),
            "the premise: this build cannot read this message"
        );
        let mut feed = TestFeed::new();
        feed.publish_bytes(12, &bytes);
        let request = feed.mark(&key, TEST_EPOCH, entry.inbox_id, 12);

        let marked = mark(State(Arc::clone(&state)), peer(), Json(request))
            .await
            .expect("a kind this build cannot read is still confirmed")
            .0;
        assert_eq!(marked.feed_id, Some(12));
        assert_eq!(
            marked.content_checked,
            Some(false),
            "and it says which of the two confirmations it got"
        );

        let after = status(&state).await;
        assert_eq!(
            after.overdue_count, 0,
            "an honest sequencer must not be reported late"
        );
        assert!(after.overdue.is_empty());
        assert_eq!(after.pending, 0);
        assert_eq!(
            after.confirmed_content_unchecked, 1,
            "the middle outcome has to be visible, not silent"
        );
        assert!(
            after.mark_rejections.is_empty(),
            "being older than the sequencer is not evidence against it"
        );
    }

    /// The alarm still works. An entry that nothing ever marks is still late.
    /// That report is the whole point of the service, and the fix above must
    /// not remove it.
    #[tokio::test]
    async fn an_entry_nothing_ever_marks_is_still_reported_late() {
        let (state, _key) = test_inbox(5_000);
        submit_ok(&state, order(100.25, 5.0)).await;
        backdate(&state).await;

        let status = status(&state).await;
        assert_eq!(status.pending, 1);
        assert_eq!(status.overdue_count, 1);
        assert_eq!(status.overdue.len(), 1);
        assert_eq!(
            status.confirmed_content_unchecked, 0,
            "nothing was confirmed, so nothing is in the middle state either"
        );
    }

    /// The check that must not be lost. Only the field comparison catches a
    /// sequencer that logs a different price under this entry's own nonce. The
    /// nonce matches, the proof is real, and the message really is in the log
    /// the sequencer signed.
    #[tokio::test]
    async fn a_different_price_under_the_same_nonce_is_still_caught() {
        let (state, key) = test_inbox(5_000);
        let entry = submit_ok(&state, order(100.25, 5.0)).await;
        let nonce = nonce_of(&entry.submission).expect("a nonce").to_string();

        // A price one cent away, under the nonce the user signed.
        let lie = message_for(12, &order_with_nonce(100.26, 5.0, &nonce));
        let request = mark_for(&key, TEST_EPOCH, entry.inbox_id, &lie);

        let refused = mark(State(Arc::clone(&state)), peer(), Json(request))
            .await
            .expect_err("a different price under this nonce is not this submission");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);

        let status = status(&state).await;
        assert_eq!(status.pending, 1, "the entry is not closed");
        assert_eq!(
            status.confirmed_content_unchecked, 0,
            "and it is not quietly parked in the middle state"
        );
        assert_eq!(status.mark_rejections.len(), 1);
        assert_eq!(status.mark_rejections[0].kind, "content_mismatch");
    }

    /// The middle outcome is not a hole. A message this build cannot read
    /// still has to carry this entry's account and this entry's nonce. Both
    /// values are read out of the bytes without knowing the kind.
    ///
    /// The account matters as much as the nonce. A nonce is unique per
    /// account, and not on its own. `inbox_account_nonce` is an index over the
    /// pair, and `GET /pending` publishes the nonces. On the nonce alone, a
    /// sequencer could close account 7's entry with a message of account 8's
    /// that is real, proved and sequenced. That is censorship hidden inside a
    /// confirmation.
    #[tokio::test]
    async fn an_unreadable_kind_that_is_not_this_entry_is_refused() {
        let (state, key) = test_inbox(5_000);
        let entry = submit_ok(&state, order(100.25, 5.0)).await;
        let nonce = nonce_of(&entry.submission).expect("a nonce").to_string();

        let swap = |account: u32, nonce: &str| {
            format!(
                "{{\"Swap\":{{\"id\":12,\"timestamp\":1,\"account\":{},\"nonce\":\"{}\",\
                 \"legs\":[]}}}}",
                account, nonce
            )
        };
        // Two messages. The first is account 8's message under account 7's
        // nonce, which is the case the account check exists for. The second is
        // account 7's message under another nonce. Neither message is this
        // entry's.
        for bytes in [swap(8, &nonce), swap(7, &new_nonce())] {
            let mut feed = TestFeed::new();
            feed.publish_bytes(12, &bytes);
            let request = feed.mark(&key, TEST_EPOCH, entry.inbox_id, 12);
            let refused = mark(State(Arc::clone(&state)), peer(), Json(request))
                .await
                .expect_err("this message is not this entry's");
            assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        }

        // A kind that carries no account at all cannot be shown to be
        // anybody's entry.
        let anonymous = format!(
            "{{\"Swap\":{{\"id\":12,\"timestamp\":1,\"nonce\":\"{}\",\"legs\":[]}}}}",
            nonce
        );
        let mut feed = TestFeed::new();
        feed.publish_bytes(12, &anonymous);
        let request = feed.mark(&key, TEST_EPOCH, entry.inbox_id, 12);
        let refused = mark(State(Arc::clone(&state)), peer(), Json(request))
            .await
            .expect_err("a message under no account is nobody's entry");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);

        let status = status(&state).await;
        assert_eq!(status.pending, 1);
        assert_eq!(status.confirmed_content_unchecked, 0);
        assert_eq!(status.mark_rejections.len(), 3);
        assert!(
            status
                .mark_rejections
                .iter()
                .all(|rejection| rejection.kind == "content_mismatch")
        );
    }

    /// A proof that does not verify closes nothing. This test uses three ways
    /// for a proof to fail, and none of them is a signature problem. The mark
    /// itself is signed correctly in every case, because the path is not
    /// signed and does not need to be.
    #[tokio::test]
    async fn a_proof_that_does_not_verify_is_refused() {
        let (state, key) = test_inbox(5_000);
        let entry = submit_ok(&state, order(100.25, 5.0)).await;
        let message = message_for(12, &entry.submission);
        let mut feed = TestFeed::new();
        feed.publish(&message);
        let honest = feed.mark(&key, TEST_EPOCH, entry.inbox_id, 12);
        assert!(
            verify_mark(&key.verifying_key(), &honest),
            "the mark is properly signed; what follows is about the proof"
        );

        // A node the tree does not contain.
        let mut tampered = honest.clone();
        tampered.inclusion_path[0] = logchain::to_hex(&[0u8; 32]);
        assert!(verify_mark(&key.verifying_key(), &tampered));
        let refused = mark(State(Arc::clone(&state)), peer(), Json(tampered))
            .await
            .expect_err("a path that does not reach the root proves nothing");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);

        // No path at all, against a tree that needs one.
        let mut empty = honest.clone();
        empty.inclusion_path = Vec::new();
        let refused = mark(State(Arc::clone(&state)), peer(), Json(empty))
            .await
            .expect_err("an empty path is not a proof over a tree of twelve");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);

        // A real proof, for a different leaf of the same real tree. The
        // computed leaf index catches this case. The bytes are message 12's
        // and the path is message 11's.
        let mut wrong_leaf = honest.clone();
        wrong_leaf.inclusion_path = feed.path(11);
        let refused = mark(State(Arc::clone(&state)), peer(), Json(wrong_leaf))
            .await
            .expect_err("another leaf's path is not this leaf's proof");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);

        let status = status(&state).await;
        assert_eq!(status.pending, 1, "the entry is not confirmed");
        assert_eq!(status.confirmed_content_unchecked, 0);
        assert_eq!(status.mark_rejections.len(), 3);
        assert!(
            status
                .mark_rejections
                .iter()
                .all(|rejection| rejection.kind == "proof_failed"),
            "each one is recorded: {:?}",
            status.mark_rejections
        );

        // The honest mark still closes the entry, so the checks above do not
        // refuse everything.
        let marked = mark(State(Arc::clone(&state)), peer(), Json(honest))
            .await
            .expect("the real proof is accepted")
            .0;
        assert_eq!(marked.feed_id, Some(12));
        assert_eq!(marked.content_checked, Some(true));
    }

    /// A proof is worth only what the root it lands on is worth. A proof
    /// checked against a root nobody signed always verifies. So a head this
    /// service cannot tie to the sequencer's key is refused before the proof
    /// is read at all.
    #[tokio::test]
    async fn a_tree_head_the_sequencer_did_not_sign_is_refused() {
        let (state, key) = test_inbox(5_000);
        let entry = submit_ok(&state, order(100.25, 5.0)).await;
        let message = message_for(12, &entry.submission);
        let mut feed = TestFeed::new();
        feed.publish(&message);
        let bytes = feed.bytes(12);
        let path = feed.path(12);

        // A stranger's signature over the real root. The proof itself is
        // correct.
        let stranger = logchain::ephemeral_key();
        let forged_head = feed.head(&stranger);
        let request = signed_mark(
            &key,
            TEST_EPOCH,
            entry.inbox_id,
            12,
            &bytes,
            forged_head,
            path.clone(),
        );
        let refused = mark(State(Arc::clone(&state)), peer(), Json(request))
            .await
            .expect_err("a head signed by a stranger commits this sequencer to nothing");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);

        // No signature at all.
        let mut unsigned_head = feed.head(&key);
        unsigned_head.signature = String::new();
        let request = signed_mark(
            &key,
            TEST_EPOCH,
            entry.inbox_id,
            12,
            &bytes,
            unsigned_head,
            path.clone(),
        );
        let refused = mark(State(Arc::clone(&state)), peer(), Json(request))
            .await
            .expect_err("an unsigned head is not a commitment");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);

        // The sequencer's own signature, over a size the sequencer never
        // signed for. The signature covers the size, so a changed size breaks
        // the head. That is what stops a proof from being reused under a tree
        // it does not belong to.
        let mut moved_head = feed.head(&key);
        moved_head.tree_size = 13;
        let request = signed_mark(
            &key,
            TEST_EPOCH,
            entry.inbox_id,
            12,
            &bytes,
            moved_head,
            path,
        );
        let refused = mark(State(Arc::clone(&state)), peer(), Json(request))
            .await
            .expect_err("a size the sequencer never signed for");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);

        let status = status(&state).await;
        assert_eq!(status.pending, 1);
        assert_eq!(status.mark_rejections.len(), 3);
        assert!(
            status
                .mark_rejections
                .iter()
                .all(|rejection| rejection.kind == "proof_failed")
        );
    }

    /// A head that does not reach the message it is supposed to prove. The
    /// leaf index is computed from `feed_id`, and never read off the request.
    /// So a mark cannot name a leaf the message is not at.
    #[tokio::test]
    async fn a_head_older_than_the_message_is_refused() {
        let (state, key) = test_inbox(5_000);
        let entry = submit_ok(&state, order(100.25, 5.0)).await;
        let message = message_for(12, &entry.submission);
        let mut feed = TestFeed::new();
        feed.publish(&message);
        let bytes = feed.bytes(12);
        let path = feed.path(12);

        // The history is cut to four messages, and a head is signed over that
        // tree. Message 12 is leaf 11, which that tree does not have.
        feed.leaves.truncate(4);
        let old_head = feed.head(&key);
        assert_eq!(old_head.tree_size, 4);
        let request = signed_mark(&key, TEST_EPOCH, entry.inbox_id, 12, &bytes, old_head, path);

        let refused = mark(State(Arc::clone(&state)), peer(), Json(request))
            .await
            .expect_err("a head of four cannot prove leaf eleven");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        assert_eq!(status(&state).await.pending, 1);
    }

    /// The pair `(account, nonce)` says which entry a message belongs to. The
    /// mark path has to read that pair out of a kind this build cannot parse.
    ///
    /// This service is deliberately not upgraded at the same time as the
    /// sequencer. ENGINE.md section 6.1 upgrades the sequencer last. So a mark
    /// can arrive carrying a kind that has no variant here. `wire::envelope`
    /// answers the question, and it is the same function `feed.rs` uses to
    /// rebuild which nonces its history has spent. This file used to hold a
    /// second copy of that function, which tried two layouts: the ENGINE.md
    /// section 2 envelope first, and the shape the sequencer really publishes
    /// second. The envelope cannot arrive before the clean genesis, so the
    /// first branch could never run.
    #[test]
    fn a_mark_reads_the_id_the_account_and_the_nonce_without_knowing_the_kind() {
        let unknown_kind = br#"{"Swap":{"id":9,"timestamp":1,"account":7,"nonce":"ab","legs":[]}}"#;
        assert!(
            serde_json::from_slice::<OrderMessage>(unknown_kind).is_err(),
            "the point of this test is a kind this build cannot parse"
        );
        let fields = wire::envelope(unknown_kind).expect("the mark path still reads it");
        assert_eq!(fields.id, 9);
        assert_eq!(fields.account, Some(7));
        assert_eq!(fields.nonce.as_deref(), Some("ab"));
    }

    /// The statement is the whole of the authentication. A field the statement
    /// does not cover can be changed on the way here, and the signature still
    /// verifies.
    #[test]
    fn a_submission_signature_binds_every_term() {
        let key = account_key();
        let signed_nonce = new_nonce();
        // Every case below changes exactly one field. Each case then shows
        // that the field is covered on its own. The nonce stays fixed for that
        // reason, and the last case changes the nonce on its own.
        #[allow(clippy::too_many_arguments)]
        let order_with = |account: AccountId,
                          symbol: &str,
                          side: Side,
                          price: f64,
                          quantity: f64,
                          nonce: &str,
                          session: &str,
                          order_type: OrderType,
                          time_in_force: TimeInForce,
                          post_only: bool| {
            Submission::Order {
                account,
                symbol: symbol.to_string(),
                side,
                price,
                quantity,
                nonce: Some(nonce.to_string()),
                session: Some(session.to_string()),
                order_type,
                time_in_force,
                post_only,
            }
        };
        let plain = |account, symbol: &str, side, price, quantity, nonce: &str| {
            order_with(
                account,
                symbol,
                side,
                price,
                quantity,
                nonce,
                TEST_SESSION,
                OrderType::Limit,
                TimeInForce::GoodTillCancel,
                false,
            )
        };
        let base = plain(7, "ETH-USDC", Side::Buy, 100.25, 5.0, &signed_nonce);
        let signed = sign_submission(&key, &base).expect("an on-grid order signs");
        verify_account_signature(&signed).expect("its own terms verify");

        // Each of these is one field of the order, changed on its own.
        let tampered = [
            plain(8, "ETH-USDC", Side::Buy, 100.25, 5.0, &signed_nonce),
            plain(7, "BTC-USDC", Side::Buy, 100.25, 5.0, &signed_nonce),
            plain(7, "ETH-USDC", Side::Sell, 100.25, 5.0, &signed_nonce),
            plain(7, "ETH-USDC", Side::Buy, 100.26, 5.0, &signed_nonce),
            plain(7, "ETH-USDC", Side::Buy, 100.25, 5.1, &signed_nonce),
            // The nonce, on its own. Without this case the signature would
            // not cover the nonce. A replay could then put in a fresh nonce
            // and pass every other check, and the whole scheme would do
            // nothing.
            plain(7, "ETH-USDC", Side::Buy, 100.25, 5.0, &new_nonce()),
            // The session, on its own. Without this case the same signed bytes
            // would still verify against a log that was emptied and started
            // again under a new session.
            order_with(
                7,
                "ETH-USDC",
                Side::Buy,
                100.25,
                5.0,
                &signed_nonce,
                "0000000000000001",
                OrderType::Limit,
                TimeInForce::GoodTillCancel,
                false,
            ),
            // Each of the three order terms, on its own. Without these three
            // cases the sequencer could publish a market order, or one that
            // does not rest, for a submission the account signed as a plain
            // limit order, and the submitter would hold a receipt for an
            // order they did not place.
            order_with(
                7,
                "ETH-USDC",
                Side::Buy,
                100.25,
                5.0,
                &signed_nonce,
                TEST_SESSION,
                OrderType::Market,
                TimeInForce::GoodTillCancel,
                false,
            ),
            order_with(
                7,
                "ETH-USDC",
                Side::Buy,
                100.25,
                5.0,
                &signed_nonce,
                TEST_SESSION,
                OrderType::Limit,
                TimeInForce::ImmediateOrCancel,
                false,
            ),
            order_with(
                7,
                "ETH-USDC",
                Side::Buy,
                100.25,
                5.0,
                &signed_nonce,
                TEST_SESSION,
                OrderType::Limit,
                TimeInForce::GoodTillCancel,
                true,
            ),
        ];
        for submission in tampered {
            let forged = SignedSubmission {
                submission: submission.clone(),
                ..signed.clone()
            };
            let refused = verify_account_signature(&forged)
                .expect_err(&format!("{:?} is not what was signed", submission));
            assert_eq!(refused.0, StatusCode::UNAUTHORIZED);
        }

        // A cancel's signature is not an order's signature, for any account.
        let cancel = Submission::Cancel {
            account: 7,
            target_id: 42,
            nonce: Some(new_nonce()),
            session: Some(TEST_SESSION.to_string()),
        };
        let signed_cancel = sign_submission(&key, &cancel).expect("a cancel signs");
        verify_account_signature(&signed_cancel).expect("its own terms verify");
        let crossed = SignedSubmission {
            submission: cancel,
            ..signed
        };
        assert_eq!(
            verify_account_signature(&crossed)
                .expect_err("an order's signature is not a cancel's")
                .0,
            StatusCode::UNAUTHORIZED
        );
    }

    /// The hole this closes. Anyone could submit as any account. So anyone
    /// could cancel another person's waiting order by writing that person's
    /// account number.
    #[tokio::test]
    async fn only_the_key_an_account_pinned_can_submit_for_it() {
        let (state, _key) = test_inbox(5_000);
        let stranger = SigningKey::from_bytes(&[9u8; 32]);

        // Account 7's first submission pins account 7's key.
        submit_ok(&state, order(100.25, 5.0)).await;

        // The stranger holds a real key and signs correctly, for account 7.
        let impersonation = signed_by(
            &stranger,
            Submission::Cancel {
                account: 7,
                target_id: 1,
                nonce: Some(new_nonce()),
                session: Some(TEST_SESSION.to_string()),
            },
        );
        let refused = submit(State(Arc::clone(&state)), peer(), Ok(Json(impersonation)))
            .await
            .expect_err("account 7 is not this key's to speak for");
        assert_eq!(refused.0, StatusCode::FORBIDDEN);
        assert!(
            refused.1.contains("is pinned to public key"),
            "the refusal has to say which key the account has: {}",
            refused.1
        );

        // The refusal happened before anything was written. One entry is
        // pending, and it is the honest one.
        assert_eq!(status(&state).await.pending, 1);

        // The stranger's own account is not changed by any of this.
        let own = signed_by(
            &stranger,
            Submission::Cancel {
                account: 9,
                target_id: 1,
                nonce: Some(new_nonce()),
                session: Some(TEST_SESSION.to_string()),
            },
        );
        let _ = submit(State(Arc::clone(&state)), peer(), Ok(Json(own)))
            .await
            .expect("a key may always speak for an account nobody has claimed");
        assert_eq!(status(&state).await.pending, 2);
    }

    /// A signature that does not cover what was sent is refused. The three
    /// ways a submission can fail to prove itself stay apart.
    #[tokio::test]
    async fn a_submission_that_cannot_prove_itself_is_refused_before_anything_is_written() {
        let (state, _key) = test_inbox(5_000);

        let mut broken = signed(order(100.25, 5.0));
        broken.signature = logchain::to_hex(&[0u8; 64]);
        let refused = submit(State(Arc::clone(&state)), peer(), Ok(Json(broken)))
            .await
            .expect_err("a signature of zeroes covers nothing");
        assert_eq!(refused.0, StatusCode::UNAUTHORIZED);
        assert!(
            refused.1.contains("does not verify"),
            "unexpected refusal: {}",
            refused.1
        );

        let mut malformed = signed(order(100.25, 5.0));
        malformed.public_key = "not-hex".to_string();
        let refused = submit(State(Arc::clone(&state)), peer(), Ok(Json(malformed)))
            .await
            .expect_err("a key that is not a key");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        assert!(
            refused.1.contains("64 characters"),
            "unexpected refusal: {}",
            refused.1
        );

        // The old body shape, which carried no signature, through the real
        // extractor.
        let request = axum::http::Request::builder()
            .method("POST")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&order(100.25, 5.0)).unwrap(),
            ))
            .unwrap();
        let body =
            <Json<SignedSubmission> as axum::extract::FromRequest<()>>::from_request(request, &())
                .await;
        let refused = submit(State(Arc::clone(&state)), peer(), body)
            .await
            .expect_err("an unsigned submission is not a submission any more");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        assert!(
            refused.1.contains("public_key") && refused.1.contains("signature"),
            "the refusal has to show the shape it wants: {}",
            refused.1
        );

        // None of the three left a trace. Nothing is pending, and no account
        // is pinned.
        assert_eq!(status(&state).await.pending, 0);
        let pinned: i64 = with_db(&state, |state| {
            state
                .conn
                .query_row("SELECT COUNT(*) FROM inbox_accounts", [], |row| row.get(0))
                .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(pinned, 0);
    }

    /// The entry keeps the submitter's own proof. Anyone who holds the record
    /// can then check what was asked. A mark carries the sequencer message it
    /// claims for the same reason.
    #[tokio::test]
    async fn an_entry_keeps_the_proof_that_the_account_asked_for_it() {
        let (state, _key) = test_inbox(5_000);
        let entry = submit_ok(&state, order(100.25, 5.0)).await;

        assert_eq!(
            entry.public_key,
            logchain::to_hex(account_key().verifying_key().as_bytes())
        );
        verify_account_signature(&entry.signed()).expect("the stored proof still verifies");

        // The proof survives the trip through the database and back. That is
        // what the sequencer reads when it drains.
        let served = get_pending(State(Arc::clone(&state)))
            .await
            .expect("pending")
            .1
            .0;
        assert_eq!(served.len(), 1);
        verify_account_signature(&served[0].signed()).expect("what /pending serves still verifies");
    }

    /// A cancel used to skip every check. The `Submission::Order` arm was the
    /// only arm that was checked.
    #[tokio::test]
    async fn a_cancel_is_validated_like_an_order() {
        let (state, _key) = test_inbox(5_000);

        let bad_cancel = Submission::Cancel {
            account: 7,
            target_id: 0,
            nonce: Some(new_nonce()),
            session: Some(TEST_SESSION.to_string()),
        };
        let refused = submit(
            State(Arc::clone(&state)),
            peer(),
            Ok(Json(signed(bad_cancel))),
        )
        .await
        .expect_err("target_id 0 names no message that can exist");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);

        let refused = submit(
            State(Arc::clone(&state)),
            peer(),
            Ok(Json(signed(order(100.253, 5.0)))),
        )
        .await
        .expect_err("an off-grid price is dropped by the engine, so it is refused here");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);

        // Both correct forms are still accepted.
        submit_ok(&state, order(100.25, 5.0)).await;
        submit_ok(
            &state,
            Submission::Cancel {
                account: 7,
                target_id: 42,
                nonce: Some(new_nonce()),
                session: Some(TEST_SESSION.to_string()),
            },
        )
        .await;
        assert_eq!(status(&state).await.pending, 2);
    }

    /// On a listed symbol, this service must accept exactly what the engine
    /// will execute. This test drives a real `MatcherState` and compares the
    /// engine's answer with `validate_submission`'s answer.
    ///
    /// Both sides now call `domain::to_grid`, so this test can no longer catch
    /// a rounding difference between two copies of that function. There are no
    /// two copies left. `domain.rs` holds the one copy, and states its edge
    /// cases in its own tests. This test still catches three faults. Intake
    /// can apply the step to the wrong field. Intake can apply the wrong
    /// scale, or no step at all. And the engine can ignore an order intake
    /// accepted, for a reason intake never asked about.
    ///
    /// The history opens with a `ListSymbol` for the symbol `order` names. An
    /// engine built by `MatcherState::new()` lists nothing, and would ignore
    /// every order here for the one reason this test is not about. That reason
    /// has its own test, below.
    #[test]
    fn validation_matches_the_engine() {
        let cases = [
            (100.25, 5.0),
            (0.01, 0.1),
            (100.253, 5.0),
            (100.25, 0.04),
            (0.0, 5.0),
            (-1.0, 5.0),
            (100.25, 0.0),
            (1e9, 5.0),
            (10_000_000.0, 5.0),
            (10_000_000.01, 5.0),
            (100.25, 100_000_000.0),
            (100.25, 100_000_000.1),
            (f64::MAX, 5.0),
        ];
        let mut engine = MatcherState::new();
        engine
            .apply_message(&listing(1, "ETH-USDC"))
            .expect("the first message of the history");
        for (id, (price, quantity)) in cases.iter().enumerate() {
            let submission = order(*price, *quantity);
            let before = engine.orders_ignored();
            engine
                .apply_message(&message_for(id as OrderId + 2, &submission))
                .expect("ids are sequential");
            let engine_took_it = engine.orders_ignored() == before;
            assert_eq!(
                validate_submission(&submission).is_ok(),
                engine_took_it,
                "inbox and engine disagree about price {} quantity {}",
                price,
                quantity
            );
        }
    }

    /// Intake applies the symbol name rule, and not the `SYMBOLS` constant.
    ///
    /// A market can be opened while the exchange runs. So a symbol this build
    /// was not compiled with must still be accepted. Only a name the rule
    /// refuses is refused here.
    #[test]
    fn intake_checks_the_symbol_name_rule_and_not_the_symbol_list() {
        let for_symbol = |symbol: &str| Submission::Order {
            account: 7,
            symbol: symbol.to_string(),
            side: Side::Buy,
            price: 100.25,
            quantity: 5.0,
            nonce: Some(new_nonce()),
            session: Some(TEST_SESSION.to_string()),
            order_type: OrderType::Limit,
            time_in_force: TimeInForce::GoodTillCancel,
            post_only: false,
        };

        // This symbol is not in the constant, and intake accepts it anyway. A
        // `ListSymbol` in the log can open this market after this binary was
        // built.
        let unknown = "ZULU-USD";
        assert!(
            !crate::domain::SYMBOLS
                .iter()
                .any(|(known, _, _)| *known == unknown),
            "this build was not compiled with ZULU-USD"
        );
        assert!(
            validate_submission(&for_symbol(unknown)).is_ok(),
            "intake takes a symbol the constant does not have"
        );

        // The name rule still refuses what it always refused.
        for bad in ["", "eth-usdc", "ETH_USDC", "ETH USDC", &"A".repeat(33)] {
            assert!(
                validate_submission(&for_symbol(bad)).is_err(),
                "the name rule refuses {:?}",
                bad
            );
        }
    }

    /// `feed/drain.rs` runs `validate_submission` again over every entry it
    /// drains, and treats a refusal as evidence that this service is not the
    /// service it claims to be. An entry carries an inclusion deadline by
    /// then, so a refusal there would report an honest sequencer as late.
    ///
    /// That holds only while every check reads the message and nothing else.
    /// This test checks the same submissions twice, and moves the log between
    /// the two checks. One symbol is listed, and the other is not. Neither
    /// answer may change.
    #[test]
    fn a_drained_entry_still_validates() {
        let for_symbol = |symbol: &str| Submission::Order {
            account: 7,
            symbol: symbol.to_string(),
            side: Side::Buy,
            price: 100.25,
            quantity: 5.0,
            nonce: Some(new_nonce()),
            session: Some(TEST_SESSION.to_string()),
            order_type: OrderType::Limit,
            time_in_force: TimeInForce::GoodTillCancel,
            post_only: false,
        };
        let listed = for_symbol("ZULU-USD");
        let never_listed = for_symbol("XRAY-USD");
        assert!(validate_submission(&listed).is_ok(), "at intake");
        assert!(validate_submission(&never_listed).is_ok(), "at intake");

        // The log moves on between intake and sequencing.
        let mut engine = MatcherState::new();
        engine
            .apply_message(&listing(1, "ZULU-USD"))
            .expect("the first message of the history");

        // This is what `feed/drain.rs` runs over every entry it drains.
        assert!(
            validate_submission(&listed).is_ok(),
            "the sequencer must still sequence what intake took"
        );
        assert!(
            validate_submission(&never_listed).is_ok(),
            "including an order the exchange will ignore: the entry belongs in \
             the log either way"
        );
    }

    /// The exact bytes of the two statements an account signs.
    ///
    /// Of the five statement builders, these two carry the most risk, because
    /// the other side of them is JavaScript. `services/static/app.js`
    /// builds both of these statements in the browser. CI runs a Rust job and
    /// a Go job, and nothing that runs that page. A field moved here, or a
    /// change to `v3`, returns 401 for every browser submission. The only
    /// person who finds out is somebody who opens the page and tries to trade.
    ///
    /// The side name is written out, and not taken from `Debug`, so this test
    /// fixes both spellings too.
    #[test]
    fn the_account_statements_are_exactly_these_bytes() {
        let text = |statement: Option<Vec<u8>>| {
            String::from_utf8(statement.expect("a statement")).expect("statements are text")
        };
        let nonce = "0123456789abcdef0123456789abcdef";

        // 100.25 is 10025 cents, and 5.0 is 50 tenths. The statement carries
        // the engine's whole step units, and never the decimals that arrived
        // on the wire.
        assert_eq!(
            text(submission_statement(&order_with_nonce(100.25, 5.0, nonce))),
            "exchange-account-order-v3\n\
             349d462ced25bb2b\n\
             7\n\
             ETH-USDC\n\
             Buy\n\
             10025\n\
             50\n\
             Limit\n\
             GoodTillCancel\n\
             false\n\
             0123456789abcdef0123456789abcdef",
            "the order statement changed; services/static/app.js builds the same bytes"
        );

        assert_eq!(
            text(submission_statement(&Submission::Order {
                account: 7,
                symbol: "ETH-USDC".to_string(),
                side: Side::Sell,
                price: 100.25,
                quantity: 5.0,
                nonce: Some(nonce.to_string()),
                session: Some(TEST_SESSION.to_string()),
                order_type: OrderType::Limit,
                time_in_force: TimeInForce::GoodTillCancel,
                post_only: false,
            })),
            "exchange-account-order-v3\n\
             349d462ced25bb2b\n\
             7\n\
             ETH-USDC\n\
             Sell\n\
             10025\n\
             50\n\
             Limit\n\
             GoodTillCancel\n\
             false\n\
             0123456789abcdef0123456789abcdef",
            "the order statement changed; services/static/app.js builds the same bytes"
        );

        // The three terms, each away from its default. A statement prints all
        // three whatever they hold, so this is the same shape as the two
        // above, with three lines changed.
        assert_eq!(
            text(submission_statement(&order_with_terms(
                100.25,
                5.0,
                nonce,
                OrderType::Market,
                TimeInForce::FillOrKill,
                true,
            ))),
            "exchange-account-order-v3\n\
             349d462ced25bb2b\n\
             7\n\
             ETH-USDC\n\
             Buy\n\
             10025\n\
             50\n\
             Market\n\
             FillOrKill\n\
             true\n\
             0123456789abcdef0123456789abcdef",
            "the order statement changed; services/static/app.js builds the same bytes"
        );

        // The one time in force neither case above prints.
        assert_eq!(
            text(submission_statement(&order_with_terms(
                100.25,
                5.0,
                nonce,
                OrderType::Limit,
                TimeInForce::ImmediateOrCancel,
                false,
            ))),
            "exchange-account-order-v3\n\
             349d462ced25bb2b\n\
             7\n\
             ETH-USDC\n\
             Buy\n\
             10025\n\
             50\n\
             Limit\n\
             ImmediateOrCancel\n\
             false\n\
             0123456789abcdef0123456789abcdef",
            "the order statement changed; services/static/app.js builds the same bytes"
        );

        assert_eq!(
            text(submission_statement(&Submission::Cancel {
                account: 7,
                target_id: 42,
                nonce: Some(nonce.to_string()),
                session: Some(TEST_SESSION.to_string()),
            })),
            "exchange-account-cancel-v3\n\
             349d462ced25bb2b\n\
             7\n\
             42\n\
             0123456789abcdef0123456789abcdef",
            "the cancel statement changed; services/static/app.js builds the same bytes"
        );
    }

    /// A submission signed under the v2 statement is refused.
    ///
    /// v2 covered neither the session nor the three order terms. If it were
    /// still accepted, a sequencer could take a v2 signature, publish a market
    /// order under it, and put it in whichever log it liked. The submitter
    /// would hold a receipt for an order they never placed. So the bump is
    /// clean, and this test is what says so.
    ///
    /// The v2 bytes are written out here rather than built, because the
    /// function that built them is gone. That is the point of the test: the
    /// bytes a captured v2 signature covers still exist in the world.
    #[test]
    fn a_v2_signature_is_not_accepted() {
        let key = account_key();
        let nonce = "0123456789abcdef0123456789abcdef";
        let submission = order_with_nonce(100.25, 5.0, nonce);

        let v2 = format!(
            "exchange-account-order-v2\n7\nETH-USDC\nBuy\n10025\n50\n{}",
            nonce
        );
        let signed = SignedSubmission {
            submission: submission.clone(),
            public_key: logchain::to_hex(key.verifying_key().as_bytes()),
            signature: logchain::to_hex(&key.sign(v2.as_bytes()).to_bytes()),
        };
        let refused = verify_account_signature(&signed)
            .expect_err("a v2 signature does not cover a v3 statement");
        assert_eq!(refused.0, StatusCode::UNAUTHORIZED);

        // The same account, the same terms, signed the way this build signs.
        // Only the statement version separates the two.
        let now = sign_submission(&key, &submission).expect("these terms have a statement");
        verify_account_signature(&now).expect("a v3 signature verifies");
    }

    /// The browser's copy of `domain::to_grid`, checked against
    /// `domain::to_grid`.
    ///
    /// `services/static/app.js` rounds the price and the quantity in
    /// JavaScript, and puts the two integers into the statement it signs. If
    /// that copy differs from `domain::to_grid` by one unit, the sequencer
    /// builds a different statement, answers 401, and the visitor sees an
    /// order refused with no reason on screen. The page is the fourth copy of
    /// this function, and the only copy this repository cannot delete. It runs
    /// in a browser and is written in another language.
    ///
    /// CI runs a Rust job and a Go job, and no browser. So this test reads the
    /// page as text. The Go job reads `services/src/anchor.rs` the same way.
    ///
    /// This test proves two things. The page holds the same three step
    /// constants as this build. The body of its `toGrid` is still the text a
    /// reader compared with `domain::to_grid`. It does not prove that the
    /// JavaScript runs and returns what `domain::to_grid` returns, because no
    /// JavaScript runs here. Any edit to `toGrid` fails this test. Whoever
    /// makes that edit must compare the two functions by hand, and update the
    /// expected text below.
    #[test]
    fn the_browser_rounds_on_the_same_grid_as_the_engine() {
        const PAGE: &str = include_str!("../static/app.js");

        // Reads `const NAME = VALUE;` out of the page.
        let page_const = |name: &str| -> f64 {
            let head = format!("\nconst {} = ", name);
            let start = PAGE
                .find(&head)
                .unwrap_or_else(|| panic!("static/app.js has no `const {}`", name))
                + head.len();
            let rest = &PAGE[start..];
            let end = rest.find(';').expect("the constant ends in a semicolon");
            rest[..end]
                .trim()
                .parse::<f64>()
                .unwrap_or_else(|_| panic!("`const {}` in static/app.js is not a number", name))
        };

        assert_eq!(
            page_const("PRICE_SCALE"),
            PRICE_SCALE,
            "static/app.js scales prices differently from inbox.rs"
        );
        assert_eq!(
            page_const("QUANTITY_SCALE"),
            QUANTITY_SCALE,
            "static/app.js scales quantities differently from inbox.rs"
        );
        assert_eq!(
            page_const("MAX_GRID_UNITS"),
            MAX_GRID_UNITS as f64,
            "static/app.js caps grid units differently from domain.rs"
        );

        // The rounding itself. `domain::to_grid` does the same three steps. It
        // multiplies by the scale. It refuses a value more than 1e-6 away from
        // a whole unit. It then rounds and applies the bound.
        let start = PAGE
            .find("function toGrid(")
            .expect("static/app.js defines toGrid");
        let rest = &PAGE[start..];
        let end = rest.find("\n}").expect("toGrid ends at a closing brace") + 2;
        let expected = r#"function toGrid(value, scale) {
  const scaled = value * scale;
  if (!Number.isFinite(scaled) || Math.abs(scaled - Math.round(scaled)) > 1e-6) return null;
  const units = Math.round(scaled);
  return units > 0 && units <= MAX_GRID_UNITS ? units : null;
}"#;
        assert_eq!(
            &rest[..end],
            expected,
            "toGrid in static/app.js changed; compare it with to_grid in domain.rs"
        );
    }

    /// `?n=1` used to read and decode the whole table, and cut it down
    /// afterwards.
    #[tokio::test]
    async fn entries_are_bounded_by_the_query() {
        let (state, _key) = test_inbox(5_000);
        for i in 0..10 {
            submit_ok(&state, order(100.25, 1.0 + i as f64)).await;
        }
        let entries = get_entries(
            State(Arc::clone(&state)),
            Query(EntriesQuery {
                n: Some(1),
                ids: None,
            }),
        )
        .await
        .expect("entries")
        .0;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].inbox_id, 10, "the newest entry, not the oldest");

        let capped = get_entries(
            State(Arc::clone(&state)),
            Query(EntriesQuery {
                n: Some(PAGE_LIMIT * 100),
                ids: None,
            }),
        )
        .await
        .expect("entries")
        .0;
        assert_eq!(capped.len(), 10);
    }

    /// `pending` and `overdue` come from one read of the database, so they
    /// cannot disagree. The old code counted in one query and listed in
    /// another. An entry marked between the two queries produced `pending: 0`
    /// next to a list of late entries that was not empty.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn status_never_contradicts_itself_while_entries_are_marked() {
        let (state, key) = test_inbox(0); // every entry older than now is late
        let mut signed = Vec::new();
        for i in 0..60u64 {
            let entry = submit_ok(&state, order(100.25, 1.0)).await;
            signed.push(mark_for(
                &key,
                TEST_EPOCH,
                entry.inbox_id,
                &message_for(i + 1, &entry.submission),
            ));
        }

        let marker = {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                for request in signed {
                    let _ = mark(State(Arc::clone(&state)), peer(), Json(request)).await;
                    tokio::task::yield_now().await;
                }
            })
        };
        let watcher = {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                for _ in 0..400 {
                    let status = status(&state).await;
                    assert!(
                        status.overdue.len() <= status.pending,
                        "reported {} overdue entries but only {} pending",
                        status.overdue.len(),
                        status.pending
                    );
                    assert_eq!(
                        status.overdue_count,
                        status.overdue.len(),
                        "the overdue total and the overdue list disagree"
                    );
                    if status.pending == 0 {
                        assert!(
                            status.overdue.is_empty(),
                            "reported nothing pending and {} overdue at the same time",
                            status.overdue.len()
                        );
                    }
                    tokio::task::yield_now().await;
                }
            })
        };
        marker.await.expect("marking finished");
        watcher.await.expect("the status invariant held");

        let status = status(&state).await;
        assert_eq!(status.pending, 0);
        assert_eq!(status.overdue_count, 0);
    }

    #[tokio::test]
    async fn overdue_entries_are_the_ones_past_the_deadline() {
        let (state, _key) = test_inbox(5_000);
        // Two entries that arrived long ago, and one that arrived now.
        let now = with_db(&state, |state| {
            let now = state.clock.now_ms();
            for age in [60_000u64, 30_000] {
                state
                    .conn
                    .execute(
                        "INSERT INTO inbox_entries (received_at, json) VALUES (?1, ?2)",
                        params![
                            (now - age) as i64,
                            serde_json::to_string(&signed(order(100.25, 5.0))).unwrap()
                        ],
                    )
                    .unwrap();
            }
            now
        })
        .await
        .unwrap();
        submit_ok(&state, order(100.25, 5.0)).await;

        let status = status(&state).await;
        assert_eq!(status.pending, 3);
        assert_eq!(status.overdue_count, 2);
        assert_eq!(status.overdue.len(), 2);
        assert!(status.oldest_wait_ms.unwrap() >= 60_000);
        assert!(status.oldest_wait_ms.unwrap() < 60_000 + 5_000);
        assert!(now > 0);
    }

    /// A row that cannot be decoded disappears from every answer at once. So
    /// this service counts the row and writes a log line, and does not drop it
    /// without a message.
    #[tokio::test]
    async fn rows_that_cannot_be_decoded_are_counted() {
        let (state, _key) = test_inbox(5_000);
        submit_ok(&state, order(100.25, 5.0)).await;
        with_db(&state, |state| {
            state
                .conn
                .execute(
                    "INSERT INTO inbox_entries (received_at, json) VALUES (?1, ?2)",
                    params![1_700_000_000_000i64, "{\"Order\":{\"account\":\"nope\"}}"],
                )
                .unwrap();
        })
        .await
        .unwrap();

        let pending = get_pending(State(Arc::clone(&state)))
            .await
            .expect("pending")
            .1
            .0;
        assert_eq!(pending.len(), 1, "the unreadable row cannot be served");
        let status = status(&state).await;
        assert_eq!(
            status.pending, 2,
            "but the count still knows the row is there"
        );
        assert!(status.unreadable_entries >= 1);
    }

    #[tokio::test]
    async fn submissions_are_refused_once_the_pending_cap_is_reached() {
        let (state, _key) = test_inbox(5_000);
        with_db(&state, |state| {
            let json = serde_json::to_string(&signed(order(100.25, 5.0))).unwrap();
            let tx = state.conn.transaction().unwrap();
            for _ in 0..MAX_PENDING {
                tx.execute(
                    "INSERT INTO inbox_entries (received_at, json) VALUES (?1, ?2)",
                    params![1_700_000_000_000i64, json],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        })
        .await
        .unwrap();

        let refused = submit(
            State(Arc::clone(&state)),
            peer(),
            Ok(Json(signed(order(100.25, 5.0)))),
        )
        .await
        .expect_err("the pending cap is reached");
        assert_eq!(refused.0, StatusCode::SERVICE_UNAVAILABLE);
        let status = status(&state).await;
        assert_eq!(status.pending as i64, MAX_PENDING);
        assert_eq!(status.pending_cap, MAX_PENDING);
    }

    /// The intake filter, and what it is for.
    ///
    /// This filter is not where a replay is *stopped*. The sequencer stops a
    /// replay, over its published history, and the sequencer must not ask this
    /// service anything. This filter stops one captured signature from filling
    /// the pending cap with copies. A full pending set would answer everybody
    /// else with a 503, and close the independent submission path.
    #[tokio::test]
    async fn a_replay_is_refused_at_intake_and_cannot_fill_the_pending_cap() {
        let (state, _key) = test_inbox(5_000);
        let submission = order(100.25, 5.0);
        let first = submit_ok(&state, submission.clone()).await;
        assert_eq!(first.inbox_id, 1);

        for _ in 0..3 {
            let replay = submit(
                State(Arc::clone(&state)),
                peer(),
                Ok(Json(signed(submission.clone()))),
            )
            .await
            .expect_err("the same signed bytes cannot make a second entry");
            assert_eq!(replay.0, StatusCode::CONFLICT);
            assert!(
                replay.1.contains("inbox entry 1"),
                "the refusal names the entry those bytes already made: {}",
                replay.1
            );
        }
        assert_eq!(status(&state).await.pending, 1, "one entry, not four");

        // A different nonce with the same terms is a different submission, and
        // this service accepts it. This filter does not slow the independent
        // submission path.
        let again = submit_ok(&state, order(100.25, 5.0)).await;
        assert_eq!(again.inbox_id, 2);
        assert_eq!(status(&state).await.pending, 2);

        // The same nonce under a different account is not a replay of
        // anything. Uniqueness is per account, so nobody can block another
        // account's submissions by guessing that account's nonces.
        let stranger = SigningKey::from_bytes(&[9u8; 32]);
        let shared = new_nonce();
        let mine = submit(
            State(Arc::clone(&state)),
            peer(),
            Ok(Json(signed(order_with_nonce(100.25, 5.0, &shared)))),
        )
        .await
        .expect("account 7 has not used this nonce")
        .0;
        let other_account = Submission::Order {
            account: 8,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            price: 100.25,
            quantity: 5.0,
            nonce: Some(shared),
            session: Some(TEST_SESSION.to_string()),
            order_type: OrderType::Limit,
            time_in_force: TimeInForce::GoodTillCancel,
            post_only: false,
        };
        let theirs = submit(
            State(Arc::clone(&state)),
            peer(),
            Ok(Json(signed_by(&stranger, other_account))),
        )
        .await
        .expect("account 8 has not used it either")
        .0;
        assert_ne!(mine.inbox_id, theirs.inbox_id, "both were accepted");
        assert_eq!(status(&state).await.pending, 4);
    }

    /// A submission without a nonce is refused. Anything signed under the v1
    /// statement has no nonce. The reason says so, and the submission does not
    /// fail as a broken signature.
    #[tokio::test]
    async fn a_submission_without_a_nonce_is_refused_by_name() {
        let (state, _key) = test_inbox(5_000);
        let no_nonce = Submission::Order {
            account: 7,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            price: 100.25,
            quantity: 5.0,
            nonce: None,
            session: Some(TEST_SESSION.to_string()),
            order_type: OrderType::Limit,
            time_in_force: TimeInForce::GoodTillCancel,
            post_only: false,
        };
        let refused = submit(
            State(Arc::clone(&state)),
            peer(),
            Ok(Json(signed(no_nonce))),
        )
        .await
        .expect_err("a v1 submission is not accepted");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        assert!(
            refused.1.contains("carries no nonce"),
            "unexpected reason: {}",
            refused.1
        );

        // A nonce that is the same bits written another way is refused too.
        // Two spellings of one nonce would be two keys in the sequencer's map.
        let shouty = order_with_nonce(100.25, 5.0, &new_nonce().to_uppercase());
        let refused = submit(State(Arc::clone(&state)), peer(), Ok(Json(signed(shouty))))
            .await
            .expect_err("a non-canonical nonce is not accepted");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        assert!(
            refused.1.contains("32 lowercase hex"),
            "unexpected reason: {}",
            refused.1
        );
        assert_eq!(status(&state).await.pending, 0);
    }

    /// Two bugs that already existed in one function. This design would have
    /// made both worse.
    #[test]
    fn a_mark_matches_on_grid_units_and_on_the_nonce() {
        let nonce = new_nonce();
        let submission = order_with_nonce(100.25, 5.0, &nonce);

        // The float the sequencer published need not be the same 64 bits as
        // the float this service stored. A message matched against a
        // submission that was already published carries whichever spelling
        // reached the sequencer's own endpoint. Both floats are 10025 cents,
        // which is what the signature covers and what the engine executes.
        let mut other_bits = message_for(7, &submission);
        if let OrderMessage::New { price, .. } = &mut other_bits {
            *price = 100.2500000001;
        }
        assert_ne!(100.25f64.to_bits(), 100.2500000001f64.to_bits());
        assert!(
            message_matches(&submission, &other_bits),
            "the same price on the grid is the same price"
        );

        // Two prices off the price step are not "equally off the price step".
        let mut off_grid = message_for(7, &submission);
        if let OrderMessage::New { price, .. } = &mut off_grid {
            *price = 100.253;
        }
        assert!(!message_matches(
            &order_with_nonce(100.253, 5.0, &nonce),
            &off_grid
        ));

        // The nonce has to match. Without the nonce check, nothing stops one
        // message from satisfying two different entries whose content agrees.
        // No rule anywhere says a sequencer id may be claimed by only one
        // entry.
        let someone_elses = message_for(7, &order_with_nonce(100.25, 5.0, &new_nonce()));
        assert!(
            !message_matches(&submission, &someone_elses),
            "identical terms under a different nonce is a different submission"
        );
        let unsigned = OrderMessage::New {
            id: 7,
            timestamp: 1,
            account: 7,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            price: 100.25,
            quantity: 5.0,
            nonce: None,
            order_type: Default::default(),
            time_in_force: Default::default(),
            post_only: false,
        };
        assert!(
            !message_matches(&submission, &unsigned),
            "and generated traffic satisfies no entry at all"
        );
    }

    /// The hole the comparison field by field left open, and the reason the
    /// check now compares the whole message.
    ///
    /// A submission that names no order terms becomes a message with the
    /// default terms: a limit order, good till cancel, and not post-only. A
    /// sequencer that writes any other term has published an order the account
    /// did not sign. The old check named account, symbol, side, price,
    /// quantity and nonce, and stopped there. Every one of the messages below
    /// then returned `true`. This service confirmed the entry and reported
    /// nothing, and the submitter held a signed receipt for terms they never
    /// agreed to.
    ///
    /// Now that a submission can name its terms, the check has to hold in the
    /// other direction too, and the second half of this test is that case: a
    /// submission that asks for a market order must not be satisfied by the
    /// limit order the sequencer would rather publish. Nothing in
    /// `message_matches` was edited for either direction: the comparison is
    /// over the bytes `message_from` builds, and `message_from` now carries the
    /// terms.
    #[test]
    fn a_mark_whose_order_terms_are_not_the_submitted_ones_is_refused() {
        let submission = order_with_nonce(100.25, 5.0, &new_nonce());
        let honest = message_for(7, &submission);
        assert!(
            message_matches(&submission, &honest),
            "the message the sequencer must publish still matches"
        );

        let mut market = message_for(7, &submission);
        if let OrderMessage::New { order_type, .. } = &mut market {
            *order_type = OrderType::Market;
        }
        assert!(
            !message_matches(&submission, &market),
            "a market order is not what this account signed"
        );

        let mut kill = message_for(7, &submission);
        if let OrderMessage::New { time_in_force, .. } = &mut kill {
            *time_in_force = TimeInForce::FillOrKill;
        }
        assert!(
            !message_matches(&submission, &kill),
            "fill or kill is not what this account signed"
        );

        let mut post_only_message = message_for(7, &submission);
        if let OrderMessage::New { post_only, .. } = &mut post_only_message {
            *post_only = true;
        }
        assert!(
            !message_matches(&submission, &post_only_message),
            "post-only is not what this account signed"
        );

        // The other direction. This submission asks for a market order that
        // fills whole or not at all, and the message the sequencer has to
        // publish carries both terms.
        let asked = order_with_terms(
            100.25,
            5.0,
            &new_nonce(),
            OrderType::Market,
            TimeInForce::FillOrKill,
            false,
        );
        assert!(
            message_matches(&asked, &message_for(7, &asked)),
            "the message the sequencer must publish carries the terms that were signed"
        );

        // The plain limit order the sequencer would rather have published.
        let mut plain = message_for(7, &asked);
        if let OrderMessage::New {
            order_type,
            time_in_force,
            ..
        } = &mut plain
        {
            *order_type = OrderType::Limit;
            *time_in_force = TimeInForce::GoodTillCancel;
        }
        assert!(
            !message_matches(&asked, &plain),
            "a limit order that rests is not what this account signed either"
        );

        // One term back, one term still wrong. A message has to carry all
        // three, and not most of them.
        let mut half = message_for(7, &asked);
        if let OrderMessage::New { time_in_force, .. } = &mut half {
            *time_in_force = TimeInForce::ImmediateOrCancel;
        }
        assert!(
            !message_matches(&asked, &half),
            "a market order that keeps what it filled is not one that fills whole or not at all"
        );

        // The session is not compared, because a message carries none. Two
        // submissions that differ only in the log they were signed for become
        // the same message, and this service is not the party that judges
        // which log is current. `checked_session` says why.
        let mut elsewhere = asked.clone();
        if let Submission::Order { session, .. } = &mut elsewhere {
            *session = Some("0000000000000001".to_string());
        }
        assert!(
            message_matches(&elsewhere, &message_for(7, &asked)),
            "the session names the log, and a message does not repeat the log it sits in"
        );
    }

    #[test]
    fn one_caller_cannot_submit_without_limit() {
        let mut limiter = RateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let start = Instant::now();
        for i in 0..SUBMIT_BURST {
            assert!(limiter.allow(ip, start), "submission {} was refused", i);
        }
        assert!(!limiter.allow(ip, start), "the burst must end somewhere");
        // A different caller keeps its own count, and the window opens again.
        assert!(limiter.allow("127.0.0.2".parse().unwrap(), start));
        assert!(limiter.allow(ip, start + SUBMIT_WINDOW));
    }

    // -----------------------------------------------------------------------
    // Which address a caller is rate limited on
    // -----------------------------------------------------------------------

    /// The operator's `--trusted-proxy` list, as the CLI hands it over.
    fn trusted(specs: &[&str]) -> TrustedProxies {
        TrustedProxies::parse(&specs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("these values have to parse")
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    /// The default, and what every deployment that never sets the flag does.
    /// The socket address is the caller, and the header is not read at all. A
    /// deployment that forgets `--trusted-proxy` behaves as it did before.
    #[test]
    fn with_no_trusted_proxy_the_header_is_not_read() {
        let none = TrustedProxies::none();
        assert!(none.is_empty());
        assert_eq!(
            Caller::from_socket("203.0.113.9:52000").client_ip(&none),
            ip("203.0.113.9")
        );
        assert_eq!(
            Caller::with_forwarded("203.0.113.9:52000", &["198.51.100.7"]).client_ip(&none),
            ip("203.0.113.9"),
            "with no proxy configured the header is a string a stranger typed"
        );
        // The flag parses to the same list whether it was left out or passed
        // empty.
        assert_eq!(TrustedProxies::parse(&[]).unwrap(), none);
        assert_eq!(TrustedProxies::parse(&["".to_string()]).unwrap(), none);
    }

    /// The header is evidence only when the request came from a proxy the
    /// operator named. From anywhere else the header is ignored. So a caller
    /// that reaches the service directly cannot pick their own count.
    #[test]
    fn a_forwarded_header_from_an_untrusted_peer_is_ignored() {
        let trusted = trusted(&["172.17.0.3"]);
        let forged = Caller::with_forwarded("203.0.113.9:52000", &["198.51.100.7"]);
        assert_eq!(forged.client_ip(&trusted), ip("203.0.113.9"));
        // A header that names the trusted proxy itself does not change that.
        let dressed_up = Caller::with_forwarded("203.0.113.9:52000", &["172.17.0.3, 198.51.100.7"]);
        assert_eq!(dressed_up.client_ip(&trusted), ip("203.0.113.9"));
    }

    /// The header is read from right to left. When a client sends
    /// `X-Forwarded-For: 1.2.3.4`, the proxy appends what it really saw. The
    /// leftmost entry is then the attacker's own choice, and the rightmost
    /// entry is what a machine observed.
    #[test]
    fn a_forwarded_chain_is_read_from_the_right() {
        let trusted = trusted(&["172.17.0.3"]);
        let spoofed = Caller::with_forwarded("172.17.0.3:41000", &["198.51.100.7, 203.0.113.9"])
            .client_ip(&trusted);
        assert_eq!(
            spoofed,
            ip("203.0.113.9"),
            "the entry the proxy appended is the client; the one before it is what the client sent"
        );
        // Repeated headers are one list in HTTP. The last entry of the last
        // header is still the address the proxy saw.
        let split = Caller::with_forwarded("172.17.0.3:41000", &["198.51.100.7", "203.0.113.9"])
            .client_ip(&trusted);
        assert_eq!(split, ip("203.0.113.9"));
    }

    /// Two proxies in front of the service. The rightmost entry is the inner
    /// proxy, which is trusted. So the walk continues to the left, and stops
    /// at the first entry that is not a proxy.
    #[test]
    fn a_chain_of_trusted_proxies_resolves_to_the_client() {
        let trusted = trusted(&["172.17.0.3", "172.18.0.0/16"]);
        let caller =
            Caller::with_forwarded("172.17.0.3:41000", &["203.0.113.9, 172.18.4.5, 172.18.9.9"]);
        assert_eq!(caller.client_ip(&trusted), ip("203.0.113.9"));
    }

    /// A header with nothing usable in it falls back to the socket address,
    /// which is the proxy. That gives one shared count for everyone behind the
    /// proxy. It is stricter than the truth, never looser, and never a value a
    /// caller chose.
    #[test]
    fn a_trusted_proxy_with_no_usable_header_falls_back_to_the_socket() {
        let trusted = trusted(&["172.17.0.3"]);
        let proxy = ip("172.17.0.3");
        // No header at all. An operator configured this proxy to send none.
        assert_eq!(
            Caller::from_socket("172.17.0.3:41000").client_ip(&trusted),
            proxy
        );
        for header in [
            "",
            "   ",
            ",",
            "not-an-address",
            "_hidden",
            "unknown",
            // Only trusted proxies in the chain, so there is no client entry.
            "172.17.0.3",
            // An entry that cannot be read stops the walk. The walk does not
            // continue past it, because the next entry to the left is where a
            // forged value sits.
            "203.0.113.9, garbage",
        ] {
            assert_eq!(
                Caller::with_forwarded("172.17.0.3:41000", &[header]).client_ip(&trusted),
                proxy,
                "header {:?} must fall back to the socket address",
                header
            );
        }
        // Bytes that are not text are not an address list either.
        assert_eq!(
            Caller::with_forwarded_bytes("172.17.0.3:41000", &[&[0xff, 0xfe]]).client_ip(&trusted),
            proxy
        );
    }

    /// The forms a proxy really writes, and the two spellings of one address.
    /// A dual-stack listener reports an IPv4 client as `::ffff:1.2.3.4`, and
    /// one caller must not get two counts out of that.
    #[test]
    fn the_forms_a_forwarded_entry_can_take_are_read() {
        let trusted = trusted(&["172.17.0.3"]);
        for (header, expected) in [
            ("203.0.113.9", "203.0.113.9"),
            ("203.0.113.9:52000", "203.0.113.9"),
            ("::ffff:203.0.113.9", "203.0.113.9"),
            ("2001:db8::1", "2001:db8::1"),
            ("[2001:db8::1]:52000", "2001:db8::1"),
        ] {
            assert_eq!(
                Caller::with_forwarded("172.17.0.3:41000", &[header]).client_ip(&trusted),
                ip(expected),
                "header {:?}",
                header
            );
        }
        // The same rewriting is applied to the socket address. A service on a
        // dual-stack listener then still recognises its own proxy.
        assert_eq!(
            Caller::from_socket("[::ffff:172.17.0.3]:41000").client_ip(&trusted),
            ip("172.17.0.3")
        );
    }

    /// The proxy is a Docker container, so its address comes from a bridge
    /// network and changes when the container restarts. A network in prefix
    /// form is what makes that deployment work. A bare address stays one host.
    #[test]
    fn a_trusted_proxy_can_be_a_network() {
        let trusted = trusted(&["172.17.0.0/16"]);
        assert!(trusted.contains(ip("172.17.0.3")));
        assert!(trusted.contains(ip("172.17.255.254")));
        assert!(!trusted.contains(ip("172.18.0.3")));
        assert!(!trusted.contains(ip("203.0.113.9")));
        assert_eq!(
            Caller::with_forwarded("172.17.9.9:41000", &["198.51.100.7, 203.0.113.9"])
                .client_ip(&trusted),
            ip("203.0.113.9")
        );
        // A bare address matches that address and no other.
        let one_host = self::trusted(&["172.17.0.3"]);
        assert!(one_host.contains(ip("172.17.0.3")));
        assert!(!one_host.contains(ip("172.17.0.4")));
        assert_eq!(one_host.describe(), "172.17.0.3/32");
        // An IPv6 proxy works the same way.
        let v6 = self::trusted(&["2001:db8::/32"]);
        assert!(v6.contains(ip("2001:db8:1234::1")));
        assert!(!v6.contains(ip("2001:db9::1")));
    }

    /// A value that is not an address and not a network is refused before the
    /// port is bound. The two failures that give no message, matching
    /// nothing and matching everything, are exactly what must not happen
    /// here.
    #[test]
    fn a_malformed_trusted_proxy_stops_the_service_starting() {
        for bad in [
            "not-an-address",
            "172.17.0.0/",
            "172.17.0.0/x",
            "172.17.0.0/33",
            "2001:db8::/129",
            "172.17.0.0/16/8",
            "*",
            "http://172.17.0.3",
            "172.17.0.0-172.17.255.255",
        ] {
            assert!(
                TrustedProxies::parse(&[bad.to_string()]).is_err(),
                "{} is not a proxy address and must be refused at startup",
                bad
            );
        }
        // Bits set below the prefix are refused, and not masked away. That is
        // how an operator writes the address they observed while they mean one
        // host. Reading it as a /16 would trust 65,536 addresses.
        let refused = TrustedProxies::parse(&["172.17.0.5/16".to_string()])
            .expect_err("host bits under a prefix must be refused");
        assert!(
            refused.contains("172.17.0.0/16"),
            "the message has to name what the value really matches: {}",
            refused
        );
        // One bad entry refuses the whole list, and is not skipped.
        assert!(
            TrustedProxies::parse(&["172.17.0.3".to_string(), "nonsense".to_string()]).is_err()
        );
    }

    /// The bug this whole mechanism exists for. Behind a proxy, two visitors
    /// used to share one count of `SUBMIT_BURST` submissions, and block each
    /// other.
    #[tokio::test]
    async fn two_clients_behind_one_proxy_do_not_share_a_bucket() {
        let (state, _key) = test_inbox_behind(DEFAULT_DEADLINE_MS, trusted(&["172.17.0.0/16"]));
        let first = Caller::with_forwarded("172.17.0.3:41000", &["203.0.113.9"]);
        let second = Caller::with_forwarded("172.17.0.3:41000", &["198.51.100.7"]);

        for i in 0..SUBMIT_BURST {
            let accepted = submit(
                State(Arc::clone(&state)),
                first.clone(),
                Ok(Json(signed(order(100.25, 5.0)))),
            )
            .await;
            assert!(accepted.is_ok(), "submission {} from the first client", i);
        }
        let refused = submit(
            State(Arc::clone(&state)),
            first.clone(),
            Ok(Json(signed(order(100.25, 5.0)))),
        )
        .await
        .expect_err("the first client has used its whole burst");
        assert_eq!(refused.0, StatusCode::TOO_MANY_REQUESTS);

        // The second visitor arrives through the same proxy, and keeps its own
        // count.
        assert!(
            submit(
                State(Arc::clone(&state)),
                second,
                Ok(Json(signed(order(100.25, 5.0)))),
            )
            .await
            .is_ok(),
            "a second client behind the same proxy must have its own bucket"
        );
    }

    /// The same header, from a peer nobody named. The header gains nothing.
    /// Both submissions are counted against the socket address, so a stranger
    /// cannot make new counts by writing addresses into a header.
    #[tokio::test]
    async fn a_forged_header_from_an_untrusted_peer_buys_no_second_bucket() {
        let (state, _key) = test_inbox_behind(DEFAULT_DEADLINE_MS, trusted(&["172.17.0.0/16"]));
        // 203.0.113.9 is not a trusted proxy. So everything it sends is
        // counted against 203.0.113.9, whatever the header says.
        for i in 0..SUBMIT_BURST {
            let caller =
                Caller::with_forwarded("203.0.113.9:52000", &[&format!("10.0.0.{}", i % 200)]);
            let accepted = submit(
                State(Arc::clone(&state)),
                caller,
                Ok(Json(signed(order(100.25, 5.0)))),
            )
            .await;
            assert!(accepted.is_ok(), "submission {}", i);
        }
        let refused = submit(
            State(Arc::clone(&state)),
            Caller::with_forwarded("203.0.113.9:52000", &["10.9.9.9"]),
            Ok(Json(signed(order(100.25, 5.0)))),
        )
        .await
        .expect_err("a header from an untrusted peer must not open a new bucket");
        assert_eq!(refused.0, StatusCode::TOO_MANY_REQUESTS);
    }

    /// The deadline is measured on a monotonic clock. So a jump in the wall
    /// clock cannot move `received_at` and `now` against each other.
    #[test]
    fn the_clock_never_goes_backwards() {
        let clock = Clock::from_wall(1_700_000_000_000);
        let first = clock.now_ms();
        let second = clock.now_ms();
        assert!(second >= first);
        assert!(first >= 1_700_000_000_000);
    }

    #[test]
    fn a_broken_wall_clock_is_not_a_timestamp() {
        // The error path used to fall back to 0. Every entry then read as
        // about 1.7e12 ms late, forever. The function now returns None, and
        // the service refuses to start.
        assert!(wall_clock_ms().is_some());
        assert!(wall_clock_ms().unwrap() > 1_700_000_000_000);
    }

    #[cfg(unix)]
    #[test]
    fn the_database_and_its_wal_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("inbox.db");
        let conn = open_inbox_db(&path).expect("database");
        conn.execute(
            "INSERT INTO inbox_entries (received_at, json) VALUES (1, '{}')",
            [],
        )
        .expect("a write, so the WAL file exists");

        use crate::sqlite::sidecar;
        for file in [path.clone(), sidecar(&path, "-wal"), sidecar(&path, "-shm")] {
            assert!(file.exists(), "{} should exist", file.display());
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} is mode {:o}", file.display(), mode);
        }

        // A reopen of an existing database narrows the permissions again. The
        // narrowing is not limited to the run that created the file.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        drop(conn);
        let _conn = open_inbox_db(&path).expect("database");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn a_mark_signature_binds_every_field() {
        let key = logchain::ephemeral_key();
        let public = key.verifying_key();
        let message = message_for(12, &order(100.25, 5.0));
        let request = mark_for(&key, TEST_EPOCH, 3, &message);

        assert!(verify_mark(&public, &request));
        let mut wrong_entry = request.clone();
        wrong_entry.inbox_id = 4;
        assert!(!verify_mark(&public, &wrong_entry));
        let mut wrong_feed_id = request.clone();
        wrong_feed_id.feed_id = 13;
        assert!(!verify_mark(&public, &wrong_feed_id));
        let mut wrong_session = request.clone();
        wrong_session.tree_head.session = "other".to_string();
        assert!(!verify_mark(&public, &wrong_session));
        let mut wrong_epoch = request.clone();
        wrong_epoch.inbox_epoch = "fedcba9876543210".to_string();
        assert!(!verify_mark(&public, &wrong_epoch));
        let mut wrong_message = request.clone();
        wrong_message.message = String::from_utf8(logchain::canonical_bytes(&message_for(
            12,
            &order(100.26, 5.0),
        )))
        .unwrap();
        assert!(!verify_mark(&public, &wrong_message));
        // The statement covers the head the proof is checked against. So a
        // mark and a head cannot be separated and paired with something else.
        let mut wrong_root = request.clone();
        wrong_root.tree_head.root_hash = logchain::to_hex(&[9u8; 32]);
        assert!(!verify_mark(&public, &wrong_root));
        let mut wrong_size = request.clone();
        wrong_size.tree_head.tree_size = 13;
        assert!(!verify_mark(&public, &wrong_size));
        assert!(!verify_mark(
            &logchain::ephemeral_key().verifying_key(),
            &request
        ));
    }

    /// The exact bytes of the mark statement.
    ///
    /// The test above shows that every field is covered. That test passes with
    /// any field order, so it cannot see two fields swapped. A swap breaks
    /// every mark the sequencer signs, and nothing else in this crate says so.
    /// `logchain.rs` fixes the four statements the sequencer signs the same
    /// way. Two of those four are also fixed in `anchor/anchor_test.go`.
    #[test]
    fn the_mark_statement_is_exactly_these_bytes() {
        let head = TreeHead {
            session: "349d462ced25bb2b".to_string(),
            timestamp: 1786767726360,
            tree_size: 102769,
            root_hash: logchain::to_hex(&[0x6fu8; 32]),
            signature: String::new(),
        };
        // The statement carries the SHA-256 of the message bytes, and not the
        // message itself.
        let statement = mark_statement("0123456789abcdef", 3, 12, b"a message", &head);
        assert_eq!(
            String::from_utf8(statement).expect("the statement is text"),
            "exchange-inbox-mark-v3\n\
             349d462ced25bb2b\n\
             0123456789abcdef\n\
             3\n\
             12\n\
             102769\n\
             6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f\n\
             f53c09ca39717a45c62d9aca8f8113eddbfd5f81dcab0b33b1c1834075225e68"
        );
    }

    /// A sequencer that still held records from a database that is gone used
    /// to mark this database's entry 1 with the message the *old* entry 1
    /// became. The content check refused that mark. It also recorded the
    /// sequencer as having marked an entry with something the user never
    /// submitted. The record stayed, and the entry could never be sequenced.
    #[tokio::test]
    async fn a_mark_from_a_previous_inbox_database_is_refused_without_blaming_the_feed() {
        let (state, key) = test_inbox(5_000);
        let entry = submit_ok(&state, order(100.25, 5.0)).await;

        // The same entry id, signed for the database this one replaced.
        let stale = mark_for(
            &key,
            "0000000000000000",
            entry.inbox_id,
            &message_for(12, &order(7.5, 1.0)),
        );
        let refused = mark(State(Arc::clone(&state)), peer(), Json(stale))
            .await
            .expect_err("a mark for another inbox database is not about this one");
        assert_eq!(refused.0, StatusCode::CONFLICT);

        let status = status(&state).await;
        assert_eq!(
            status.pending, 1,
            "the entry is still waiting to be sequenced"
        );
        assert!(
            status.mark_rejections.is_empty(),
            "a stale epoch is not evidence against the feed"
        );

        // The entry can still be sequenced normally after that refusal.
        let honest = mark_for(
            &key,
            TEST_EPOCH,
            entry.inbox_id,
            &message_for(12, &entry.submission),
        );
        let marked = mark(State(Arc::clone(&state)), peer(), Json(honest))
            .await
            .expect("this inbox's own epoch")
            .0;
        assert_eq!(marked.feed_id, Some(12));
    }

    /// The sequencer cannot key its records by epoch if the epoch is not on
    /// the response that carries the entries.
    #[tokio::test]
    async fn pending_names_the_inbox_epoch() {
        let (state, _key) = test_inbox(5_000);
        submit_ok(&state, order(100.25, 5.0)).await;
        let (headers, entries) = get_pending(State(Arc::clone(&state)))
            .await
            .expect("pending");
        assert_eq!(entries.0.len(), 1);
        assert_eq!(headers[0].0.as_str(), PENDING_EPOCH_HEADER);
        assert_eq!(headers[0].1, TEST_EPOCH);
    }
}
