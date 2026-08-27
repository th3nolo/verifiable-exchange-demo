//! The sequencer's messages as they arrived, before anything reads them.
//!
//! The hash chain is defined over the exact bytes of each message:
//!
//! ```text
//! chain_i = SHA-256(chain_{i-1} || the bytes published for message i)
//! ```
//!
//! Writing those bytes and checking them are two different jobs, and only one
//! program may do the first. The sequencer serializes a message it has just
//! created (`logchain::canonical_bytes`) and hashes what it wrote. Every other
//! program receives bytes somebody else wrote, and has to hash exactly those
//! bytes.
//!
//! Working the hash out again by parsing a message and serializing it looks
//! like the same thing, and it is not. serde drops what this build was not
//! compiled to know: a field added to `New` after this binary was built, or a
//! kind of message it has never heard of. The bytes come back different, so
//! the chain comes out different, and the reader reports the sequencer as
//! having rewritten its own history. The sequencer is correct, and the reader
//! is only old. For a validator that answer stays until an operator clears it
//! by hand.
//!
//! So a reader gets two separate things from this module:
//!
//! - `RawMessage::bytes`, hashed as they arrived. Hashing needs to know
//!   nothing about what a message means, so a history holding a kind this
//!   build has never seen still hashes to the chain the sequencer signed.
//! - `RawMessage::parse`, those same bytes read as whatever type the caller
//!   names, `raw.parse::<OrderMessage>()`, for a reader that has to run or
//!   understand the message. A failure here means "this build is too old to
//!   interpret message N". That is a fact about the reader, and "the history
//!   was tampered with" is a fact about the sequencer. The two must never
//!   reach an operator as the same thing.
//!
//! The exchange runs what it hashes. A reader that needs both would read
//! every line of a page twice: once for the envelope and once for the message.
//! `read_ndjson` does both in one parse. It reads the type the caller names,
//! and takes the id and the kind out of what it read. The bytes it keeps are
//! still the bytes that arrived.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;

/// The only thing this module borrows from the rest of the repository, and on
/// purpose the only kind of thing it may borrow. `pub type OrderId = u64` is a
/// name for a built-in type whose shape cannot change. Splitting a page into
/// messages needs an id, because a cursor counts them. Writing `u64` here
/// instead would look like independence, and it would drift apart from the
/// rest of the repository on the day the sequencer's ids get wider.
///
/// It does **not** import `OrderMessage`. Splitting NDJSON, reading a kind and
/// an id out of raw JSON, and handing back bytes all work the same whatever
/// the message turns out to be. `RawMessage::parse` is generic, so the caller
/// names the type it wants. That is what lets this module split up a history
/// holding a kind this build has never heard of.
///
/// `AccountId` is here on the same terms, `pub type AccountId = u32`, and
/// for the same reason. `envelope` below reads the account out of a message it
/// does not otherwise understand, and writing `u32` would look like
/// independence while drifting apart on the day accounts get wider.
use crate::domain::{AccountId, OrderId};

/// For `RawMessage::of` only, which is `#[cfg(test)]`. A test standing in for
/// the sequencer has to build a real message to serialize. Nothing in a
/// release build of this module knows the type exists.
#[cfg(test)]
use crate::domain::OrderMessage;

/// The response header carrying the sequencer's session id.
///
/// The session names one history. It is created once per database and survives
/// restarts, because the messages survive with it. It changes only when the
/// database is new. A database that lost messages does not get a new session;
/// it refuses to start. See `FeedState::with_db`. It is sent as a header, so
/// the body stays a plain array of messages, and the session can never come
/// from a different moment than the messages beside it.
pub const SESSION_HEADER: &str = "x-feed-session";

/// The headers carrying the signed head of the log on every `/orders`
/// response. They are: the newest message id, the hash chain over the whole
/// history up to that message, the sequencer's public key, and an Ed25519
/// signature that ties all three to the session. A reader that works the chain
/// out again from the messages it received can check, on every poll, that its
/// history is the one the sequencer signed.
///
/// The head always stands at the last message in the response body, and never
/// past it. Responses come in pages, see `feed::PAGE_LIMIT`, and a head
/// signed beyond the page would leave the last messages served covered by no
/// signature at all. Readers refuse such a response outright: `matcher.rs`'s
/// `HeadDoesNotCover` and `validator.rs`'s equivalent. So paging and this rule
/// have to arrive together.
///
/// These five names sit here and not in `feed.rs`, for the same reason
/// `MESSAGES_PATH` does. Seven modules read them, and six of those are readers
/// that must not have to import the sequencer to name a header they only read.
/// `feed.rs` is the seventh, on the writing side.
pub const HEAD_LAST_ID_HEADER: &str = "x-feed-last-id";
pub const HEAD_CHAIN_HEADER: &str = "x-feed-chain";
pub const HEAD_PUBKEY_HEADER: &str = "x-feed-pubkey";
pub const HEAD_SIGNATURE_HEADER: &str = "x-feed-signature";

/// The endpoint every reader builds the chain from.
///
/// It serves the bytes the sequencer hashed, one message per line, and nothing
/// else in the body. `/orders` serves the same messages as a JSON array. That
/// is the same information, but it is not the same layout. Taking the bytes
/// out of an array means running a scanner for quotes and braces inside the
/// hashing path, and a bug in that scanner produces a chain that does not
/// match the signed head. That reads as a sequencer which forged its history.
/// `anchor/exchange.go` has such a scanner, because it was written before this
/// endpoint existed.
///
/// Splitting on lines needs no knowledge of JSON at all. serde escapes every
/// control character inside a string, so a 0x0A byte in this body can only be
/// the separator the sequencer put between two messages.
pub const MESSAGES_PATH: &str = "/messages.ndjson";

/// The URL of the page of raw message bytes after `since`.
pub fn messages_url(feed_url: &str, since: OrderId) -> String {
    format!(
        "{}{}?since={}",
        feed_url.trim_end_matches('/'),
        MESSAGES_PATH,
        since
    )
}

/// The route that serves the Merkle nodes the sequencer stored.
///
/// `merkle_nodes` is the one table this exchange writes that nothing outside
/// the operator ever checked. The messages are signed, the chain is signed,
/// and the root is signed and anchored. The nodes between the leaves and the
/// root were only ever compared against the messages inside the operator's own
/// test suite, with the database file open. A stranger has HTTP and nothing
/// else, so this route makes the same comparison possible over HTTP.
pub const TREE_NODES_PATH: &str = "/tree/nodes";

/// The URL of the nodes the appends of leaves `from .. from + count` created.
///
/// It takes a window of leaves and not a range of nodes, because that is the
/// order a reader makes them in. A reader hashes the messages one page at a
/// time, and each page's messages make exactly the nodes this route answers
/// with. Neither side has to hold a whole tree to compare the two.
pub fn tree_nodes_url(feed_url: &str, from: u64, count: u64) -> String {
    format!(
        "{}{}?from={}&count={}",
        feed_url.trim_end_matches('/'),
        TREE_NODES_PATH,
        from,
        count
    )
}

/// One stored Merkle node, as `/tree/nodes` serves it.
///
/// `level` and `index` are on the wire, and not worked out from the position
/// in the list. A reader that worked them out would agree with a log that
/// served its nodes in the wrong order. The two fields say what each hash is:
/// the root of the perfect subtree over leaves `index * 2^level` to
/// `(index+1) * 2^level - 1`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TreeNode {
    pub level: u32,
    pub index: u64,
    pub hash: String,
}

/// What `GET /tree/nodes` answers with.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TreeNodes {
    pub session: String,
    /// The tree's size when this was answered, so a reader knows how far the
    /// log had published.
    pub tree_size: u64,
    /// The window of leaves this covers. `count` is what the sequencer served,
    /// which is the smaller of what the caller asked for and the cap.
    pub from: u64,
    pub count: u64,
    pub nodes: Vec<TreeNode>,
}

/// One message exactly as the sequencer served it, plus the two facts every
/// reader can take out of it without understanding the rest of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMessage {
    /// The message's position in the log, read out of the bytes below. Every
    /// reader needs it, because a cursor counts these numbers, and hashing the
    /// wrong range of the history is worse than hashing none of it. Nothing
    /// else is needed to hash.
    pub id: OrderId,
    /// What the sequencer called this message: `New`, `Cancel`, or a kind
    /// added after this build was compiled. It is a name and not an enum
    /// variant, so a kind this build does not know is a string to report and
    /// not a parse error.
    pub kind: String,
    /// The bytes the chain covers, exactly as they arrived.
    pub bytes: Vec<u8>,
}

/// What a message says about itself in the wire format, and not in this
/// build's `OrderMessage`. It is an object with one key, that key names the
/// kind, and the body under it carries the message number, the account and the
/// nonce.
///
/// Read this way, a kind this build has never seen is still readable. The kind
/// is a map key instead of an enum variant the compiler had to know about, and
/// serde ignores the fields it was not told about. So a `New` that grew three
/// new fields still gives up its id here.
#[derive(Deserialize)]
struct EnvelopeBody {
    id: OrderId,
    /// Read as any JSON number and narrowed below, and not declared as
    /// `Option<AccountId>`. A kind that carries no account, or an account
    /// number no `AccountId` can hold, must come back as "no account" and not
    /// as a parse failure. A failure here refuses the whole message, and the
    /// nonce beside it is what a sequencer needs to know it has already spent.
    #[serde(default)]
    account: Option<serde_json::Value>,
    /// The submitter's replay nonce. It has a type, and the account does not,
    /// and that difference is deliberate. A nonce that is present and is not a
    /// string refuses the message, instead of reading as "no nonce".
    /// `feed.rs` uses this field to rebuild which nonces its history has
    /// spent. A nonce it failed to read without saying so is a nonce it would
    /// honour a second time, and a refusal to start is the safe end of that.
    /// Nothing can write such a nonce: `OrderMessage::nonce` is
    /// `Option<String>` on all five kinds, and the way in only accepts one
    /// spelling of hex.
    #[serde(default)]
    nonce: Option<String>,
}

/// Everything a program may read out of a message's bytes without knowing what
/// kind of message it is.
///
/// These are the fields `docs/ENGINE.md` section 2 puts on the envelope, and
/// that is the point of the type. Section 2's rule is that no program may need
/// a field out of the body to stay correct, so this is the whole list of what
/// a program is allowed to need.
///
/// The bytes are not yet in section 2's shape, and they cannot be until the
/// clean genesis. `domain::OrderMessage` says why, in bytes. What that shape
/// would have bought is here anyway, because there is now one function that
/// reads these four things, and three callers of it. There used to be three
/// separate readers. This module read the kind and the id. `feed.rs` read the
/// id, the account and the nonce, to rebuild which nonces its history had
/// spent. `inbox.rs` read the same three and tried two layouts, top level
/// first, to be ready for a shape that does not exist yet. Three readers of
/// one format is three chances to disagree about which message a proof is
/// over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// What the sequencer called this message: `New`, `Cancel`, or a kind
    /// added after this build was compiled. It is a name and not an enum
    /// variant, so a kind this build does not know is a string to report and
    /// not a parse error.
    pub kind: String,
    /// The message's position in the log. Every reader needs it, because a
    /// cursor counts these numbers, and nothing else is needed to hash.
    pub id: OrderId,
    /// The account the message is under. It is `None` for a kind that carries
    /// no account, so such a message is read and not refused. A caller that
    /// needs the account to stay correct refuses `None` itself, where it can
    /// say what it was doing. `inbox.rs` does that, deciding whose entry a
    /// message closes.
    pub account: Option<AccountId>,
    /// The submitter's replay nonce. `None` is invented traffic, which nobody
    /// signed, nobody can replay, and which closes no entry in the separate
    /// service.
    pub nonce: Option<String>,
}

/// Reads the envelope out of one message's bytes.
///
/// A failure here is not "this build is too old". It means the bytes are not a
/// message at all. No reader can place them in the history, so no reader can
/// hash them, and the whole response has to be refused rather than believed in
/// part.
///
/// The caller names the thing. This function returns "it is not an object with
/// one key carrying an id", and each caller says what "it" was: a line of a
/// page, a row of `feed.db`, or the message on a mark.
pub fn envelope(bytes: &[u8]) -> Result<Envelope, String> {
    let outer: BTreeMap<String, EnvelopeBody> = serde_json::from_slice(bytes)
        .map_err(|e| format!("it is not a one-key object carrying an id: {}", e))?;
    if outer.len() != 1 {
        return Err(format!(
            "it names {} kinds, and a message has exactly one",
            outer.len()
        ));
    }
    let (kind, body) = outer.into_iter().next().expect("just counted one");
    Ok(Envelope {
        kind,
        id: body.id,
        account: body
            .account
            .as_ref()
            .and_then(serde_json::Value::as_u64)
            .and_then(|account| AccountId::try_from(account).ok()),
        nonce: body.nonce,
    })
}

/// The first of a message's bytes, for an error an operator has to read. Long
/// enough to recognise the message, short enough not to fill a terminal.
fn preview(bytes: &[u8]) -> String {
    const SHOWN: usize = 120;
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(SHOWN)]);
    if bytes.len() > SHOWN {
        format!("{}…", text)
    } else {
        text.into_owned()
    }
}

/// The lines of a `/messages.ndjson` body that carry a message.
///
/// The whole body is one message per line and nothing else, so a line is a
/// message and the bytes of that line are the bytes the chain covers. Empty
/// lines are skipped: the sequencer ends every message with a newline, so the
/// body ends with one.
///
/// A line padded with whitespace is refused. It is not trimmed, and it is not
/// hashed as it stands. Trimming would hash something other than what arrived.
/// Hashing it as it stands would produce a chain that does not match the
/// signed head, and every reader takes that as the sequencer having rewritten
/// its history. Whatever put a carriage return on the end of a line, it was
/// not the sequencer forging anything, so this has to come back as "this
/// response is unusable".
///
/// `split_ndjson` and `read_ndjson` split a page the same way and differ only
/// in what they read out of a line, so the splitting is written here once.
fn framed_lines(body: &[u8]) -> impl Iterator<Item = Result<&[u8], String>> {
    body.split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(|byte| byte.is_ascii_whitespace()))
        .map(|line| {
            if line
                .first()
                .into_iter()
                .chain(line.last())
                .any(|byte| byte.is_ascii_whitespace())
            {
                return Err(format!(
                    "a line of this page is padded with whitespace, so the bytes on it are not \
                     the bytes the feed hashed (in {})",
                    preview(line)
                ));
            }
            Ok(line)
        })
}

/// What a caller reads when a line of a page is not a message at all.
///
/// Both readers of a page say this, in these words, so a caller cannot tell
/// which one refused the page.
fn not_a_feed_message(reason: &str, line: &[u8]) -> String {
    format!(
        "this line is not a feed message: {} (in {})",
        reason,
        preview(line)
    )
}

/// Splits one `/messages.ndjson` body into the messages it carries.
///
/// It is for a reader that does not interpret a message. That reader gets the
/// bytes and the envelope, and nothing here needs to know what a `New` order
/// is. A reader that needs both the bytes and the message uses `read_ndjson`,
/// which reads a line once instead of twice.
pub fn split_ndjson(body: &[u8]) -> Result<Vec<RawMessage>, String> {
    let mut out = Vec::new();
    for line in framed_lines(body) {
        let line = line?;
        let read = envelope(line).map_err(|e| not_a_feed_message(&e, line))?;
        out.push(RawMessage {
            id: read.id,
            kind: read.kind,
            bytes: line.to_vec(),
        });
    }
    Ok(out)
}

/// What this build knows about a message it has already parsed.
///
/// `read_ndjson` parses a line once and still needs the id and the kind of the
/// message it built. Both are already in the parsed value. The id is a field,
/// and the kind is the map key serde matched to pick the variant. Reading them
/// from there costs nothing, while reading them out of the bytes costs a
/// second parse of the same bytes. That second parse is what this trait
/// removes.
///
/// The trait is declared here and implemented in `domain.rs`, so this module
/// still names no message type.
pub trait Interpreted {
    /// The message's position in the log, the same number `envelope` reads out
    /// of the bytes.
    fn id(&self) -> OrderId;
    /// The name the sequencer published this message under, and the same string
    /// `envelope` reads as the kind. The two must agree, or one message would
    /// report two kinds depending on which reader saw it.
    fn kind(&self) -> &'static str;
}

/// One message of a page, read once. It holds the bytes as they arrived, and
/// what this build made of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadMessage<T> {
    /// The part every reader gets: the id, the kind, and the bytes the chain
    /// covers.
    pub raw: RawMessage,
    /// The same bytes as a type this build can act on, or the reason it cannot.
    ///
    /// The failure waits here instead of stopping the split. The reader that
    /// asks for this, `matcher.rs`'s `apply_batch`, checks the ids and the
    /// chain over the bytes before it reads any message. So "the sequencer
    /// rewrote its history" is decided before "this build is too old". Failing
    /// the split would decide those two the other way round.
    pub parsed: Result<T, TooOld>,
}

/// Splits one `/messages.ndjson` body and reads every message in it, parsing
/// each line once.
///
/// It is for a reader that needs both halves: the bytes to hash, and the
/// message to run. `split_ndjson` followed by `RawMessage::parse` gives the
/// same answer and parses each line twice, once for the id and the kind and
/// once for the message. This function reads the id and the kind out of the
/// message instead.
///
/// The bytes do not move. `raw.bytes` is the line as it arrived, and nothing
/// here serializes anything.
///
/// A line this build cannot interpret is read by `envelope` afterwards, so the
/// failure still names the id and the kind the sequencer published. That is a
/// second parse of that one line, and it is the right line to spend it on. A
/// message this build is too old for stops the reader anyway.
///
/// A line that is not a message at all refuses the whole page, in the same
/// words `split_ndjson` uses, because `envelope` decides that here too.
pub fn read_ndjson<T>(body: &[u8]) -> Result<Vec<ReadMessage<T>>, String>
where
    T: serde::de::DeserializeOwned + Interpreted,
{
    let mut out = Vec::new();
    for line in framed_lines(body) {
        let line = line?;
        out.push(match serde_json::from_slice::<T>(line) {
            Ok(msg) => ReadMessage {
                raw: RawMessage {
                    id: msg.id(),
                    kind: msg.kind().to_string(),
                    bytes: line.to_vec(),
                },
                parsed: Ok(msg),
            },
            Err(cannot_interpret) => {
                let read = envelope(line)
                    .map_err(|not_a_message| not_a_feed_message(&not_a_message, line))?;
                ReadMessage {
                    raw: RawMessage {
                        id: read.id,
                        kind: read.kind.clone(),
                        bytes: line.to_vec(),
                    },
                    parsed: Err(TooOld {
                        id: read.id,
                        kind: read.kind,
                        reason: cannot_interpret.to_string(),
                    }),
                }
            }
        });
    }
    Ok(out)
}

/// The ids of the messages in a JSON array of them, and nothing else about
/// them.
///
/// It is for the one caller that asks the sequencer for the *end* of its
/// history: `/orders?n=1`, the exchange's restart probe. The chain runs from
/// message 1, so the end of a history alone cannot be hashed into it. Nothing
/// here is ever hashed, and an id is all that is wanted. serde parses the
/// array. There is deliberately no hand-written scanner over these bytes,
/// because with nothing to hash there is nothing a scanner would be for.
///
/// It reads ids the same way `envelope` does. So the newest message in the log
/// being of a kind this build has never seen does not blind the probe.
pub fn message_ids(body: &[u8]) -> Result<Vec<OrderId>, String> {
    let array: Vec<BTreeMap<String, EnvelopeBody>> = serde_json::from_slice(body)
        .map_err(|e| format!("this is not a list of feed messages: {}", e))?;
    array
        .into_iter()
        .map(|outer| {
            outer
                .into_values()
                .next()
                .map(|body| body.id)
                .ok_or_else(|| "a feed message names no kind".to_string())
        })
        .collect()
}

impl RawMessage {
    /// Reads these bytes as a message this build can act on.
    ///
    /// Only a reader that runs or interprets a message needs this. The chain
    /// is already hashed without it, and that is what lets a reader check a
    /// history it cannot fully read.
    ///
    /// The caller names the type, `raw.parse::<OrderMessage>()`, and this
    /// module does not. Splitting a page does not depend on what a message
    /// means, and a module that returned one concrete kind would be claiming
    /// that it does. The failure still reports the kind, because `kind` comes
    /// from `envelope`, which read it out of the bytes as a map key, and not
    /// from whatever type the caller asked for.
    pub fn parse<T: serde::de::DeserializeOwned>(&self) -> Result<T, TooOld> {
        serde_json::from_slice(&self.bytes).map_err(|e| TooOld {
            id: self.id,
            kind: self.kind.clone(),
            reason: e.to_string(),
        })
    }

    /// The raw form of a message the caller has just built.
    ///
    /// Test-only, and on purpose. Serializing a message to get its bytes is
    /// the sequencer's job. A reader that did it would be doing the
    /// sequencer's work again from its own struct, and that is the dependency
    /// this module exists to remove. The only callers are tests standing in
    /// for a sequencer.
    #[cfg(test)]
    pub fn of(msg: &OrderMessage) -> RawMessage {
        let bytes = crate::logchain::canonical_bytes(msg);
        let read = envelope(&bytes).expect("a message this build built is readable");
        RawMessage {
            id: read.id,
            kind: read.kind,
            bytes,
        }
    }

    /// A message whose bytes are written out by hand. It stands for a history
    /// from a sequencer newer than this build, written as it would arrive on
    /// the wire.
    #[cfg(test)]
    pub fn from_bytes(bytes: &[u8]) -> RawMessage {
        let read = envelope(bytes).expect("the test wrote a readable message");
        RawMessage {
            id: read.id,
            kind: read.kind,
            bytes: bytes.to_vec(),
        }
    }
}

/// A message this build cannot interpret. The sequencer published a kind, or a
/// shape, that this binary was compiled before.
///
/// This is never evidence of dishonesty. The chain over the same bytes still
/// verifies, and that is the whole reason the chain hashes bytes and not
/// structs. So what this type says is which message stopped the reading, and
/// that everything up to that message was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooOld {
    pub id: OrderId,
    pub kind: String,
    pub reason: String,
}

impl fmt::Display for TooOld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "this build cannot interpret message {}, which the feed published as a '{}' \
             message: {}",
            self.id, self.kind, self.reason
        )
    }
}

impl TooOld {
    /// What an operator reads when a tool stopped because it is older than the
    /// message format the sequencer publishes.
    ///
    /// It has to say three things, and it has to be clear about each of them:
    /// which message stopped the tool, that the hash chain still verified over
    /// the bytes the sequencer served, and that nothing here accuses anybody.
    /// An operator who reads this as a report of fraud takes an exchange down
    /// for a deploy they have not done yet.
    pub fn notice(&self, verified: &str) -> String {
        format!(
            "{}\n  {}\n  This is not tampering: the history is intact and this build is \
             older than the message format the feed publishes. Upgrade this binary to \
             interpret message {}.",
            self, verified, self.id
        )
    }
}

/// What a one-shot check concluded, and the exit status that says so.
///
/// Three answers, and not two. "The exchange and its own record disagree" is a
/// fact about the exchange. "This build is too old to read part of a history
/// whose chain checked out" is a fact about the tool. A caller that has to act
/// on them can only act if the process tells the two apart. That caller is a
/// person, a script, or CI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every check passed.
    Passed,
    /// A check failed. This is the answer that demands attention.
    Failed,
    /// The chain verified and this build cannot interpret all of what it
    /// verified, so the checks that need interpretation were not made.
    TooOld(TooOld),
}

impl Verdict {
    /// The process exit status.
    ///
    /// 0 and 1 keep the meanings they have always had, and 2 stays "the check
    /// could not run at all": a sequencer that would not answer, or a database
    /// that would not open. 3 is the new one, and it is deliberately not 2. A
    /// tool that could not reach the exchange has checked nothing. A tool that
    /// reports 3 has verified the sequencer's signed history byte for byte,
    /// and stopped only where it ran out of understanding.
    pub fn exit_code(&self) -> i32 {
        match self {
            Verdict::Passed => 0,
            Verdict::Failed => 1,
            Verdict::TooOld(_) => 3,
        }
    }

    /// True only for the verdict that says everything checked out.
    pub fn passed(&self) -> bool {
        matches!(self, Verdict::Passed)
    }

    /// The verdict a pass/fail check reaches.
    pub fn of(passed: bool) -> Verdict {
        if passed {
            Verdict::Passed
        } else {
            Verdict::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Side;
    use crate::logchain::{self, EMPTY_CHAIN};

    fn order(id: OrderId) -> OrderMessage {
        OrderMessage::New {
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
        }
    }

    /// A kind of message added to the log after this build was compiled. It is
    /// written out as bytes, because that is the only form of it that exists
    /// here. No struct in this binary can produce it.
    const MARKET_ORDER: &[u8] =
        br#"{"Market":{"id":2,"timestamp":2000,"account":7,"symbol":"ETH-USDC","side":"Buy","quantity":3.0,"max_slippage_bps":50}}"#;

    /// The body a sequencer serves for a three-message history whose middle
    /// message is a kind this build has never heard of.
    fn served() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&logchain::canonical_bytes(&order(1)));
        body.push(b'\n');
        body.extend_from_slice(MARKET_ORDER);
        body.push(b'\n');
        body.extend_from_slice(&logchain::canonical_bytes(&order(3)));
        body.push(b'\n');
        body
    }

    /// The behaviour the whole module exists for. A reader hashes a history
    /// holding a kind of message it does not know, and gets the chain the
    /// sequencer signed over those same bytes.
    #[test]
    fn an_unknown_kind_folds_to_the_chain_the_feed_signed() {
        let body = served();
        let messages = split_ndjson(&body).expect("the body is one message per line");
        assert_eq!(
            messages.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(messages[1].kind, "Market");

        // What the sequencer hashed: the bytes it published, in order.
        let signed = [
            logchain::canonical_bytes(&order(1)),
            MARKET_ORDER.to_vec(),
            logchain::canonical_bytes(&order(3)),
        ]
        .iter()
        .fold(EMPTY_CHAIN, |chain, bytes| {
            logchain::extend_bytes(&chain, bytes)
        });

        let folded = messages.iter().fold(EMPTY_CHAIN, |chain, msg| {
            logchain::extend_bytes(&chain, &msg.bytes)
        });
        assert_eq!(signed, folded);
    }

    /// And the other half. The same message cannot be interpreted, and it says
    /// so as itself, and not as a hash that does not match.
    #[test]
    fn an_unknown_kind_is_reported_as_too_old_to_interpret() {
        let messages = split_ndjson(&served()).expect("the body splits");
        assert!(messages[0].parse::<OrderMessage>().is_ok());
        assert!(messages[2].parse::<OrderMessage>().is_ok());

        let too_old = messages[1]
            .parse::<OrderMessage>()
            .expect_err("this build has no Market");
        assert_eq!(too_old.id, 2);
        assert_eq!(too_old.kind, "Market");
        let text = too_old.notice("The chain verified to message 3.");
        assert!(text.contains("cannot interpret message 2"), "{}", text);
        assert!(text.contains("not tampering"), "{}", text);
        assert_eq!(Verdict::TooOld(too_old).exit_code(), 3);
    }

    /// The split has to hold for bytes that would end a JSON element early if
    /// somebody scanned the body instead of splitting it on newlines: braces,
    /// brackets and quotes inside a string, and an escaped newline.
    #[test]
    fn braces_and_newlines_inside_a_string_do_not_split_a_message() {
        let awkward = OrderMessage::New {
            id: 1,
            timestamp: 1000,
            account: 1,
            symbol: "}{[\"\n]".to_string(),
            side: Side::Buy,
            price: 100.0,
            quantity: 5.0,
            nonce: None,
            order_type: Default::default(),
            time_in_force: Default::default(),
            post_only: false,
        };
        let mut body = logchain::canonical_bytes(&awkward);
        assert!(
            !body.contains(&b'\n'),
            "serde must escape the newline, or the framing is not safe"
        );
        body.push(b'\n');

        let messages = split_ndjson(&body).expect("one message");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].bytes, logchain::canonical_bytes(&awkward));
        assert_eq!(messages[0].parse::<OrderMessage>().expect("parses").id(), 1);
    }

    /// Bytes that are not a message at all are refused whole. A reader cannot
    /// place them in the history, so it cannot hash them either. Nobody must
    /// confuse this with a kind the reader only does not know.
    #[test]
    fn a_body_that_is_not_messages_is_refused_rather_than_folded() {
        assert!(split_ndjson(b"not json\n").is_err());
        assert!(split_ndjson(br#"{"New":{"no":"id"}}"#).is_err());
        assert!(split_ndjson(br#"{"New":{"id":1},"Cancel":{"id":2}}"#).is_err());
        // An empty body is an empty page, which is what a reader that is
        // already up to date gets on every idle poll.
        assert_eq!(split_ndjson(b""), Ok(Vec::new()));
        assert_eq!(split_ndjson(b"\n"), Ok(Vec::new()));
    }

    /// A line with a carriage return on the end still parses as JSON, and its
    /// bytes are not the bytes the sequencer hashed. Hashing it would produce
    /// a chain that does not match the signed head, and every reader takes
    /// that as forgery. So the line is refused as an unusable response
    /// instead.
    #[test]
    fn a_line_padded_with_whitespace_is_refused_rather_than_folded() {
        let mut body = logchain::canonical_bytes(&order(1));
        body.push(b'\r');
        body.push(b'\n');
        assert!(
            serde_json::from_slice::<OrderMessage>(&body[..body.len() - 1]).is_ok(),
            "serde accepts the trailing byte, which is exactly why this needs its own check"
        );

        let refused = split_ndjson(&body).expect_err("padded lines are not messages");
        assert!(refused.contains("padded with whitespace"), "{}", refused);
    }

    /// The one field read, checked on the shape the sequencer publishes today
    /// and on a kind this build has never heard of.
    ///
    /// This is what `feed.rs` calls to rebuild which nonces its history has
    /// spent, and what `inbox.rs` calls to decide whose entry a proved message
    /// closes. Both need the answer for a kind they cannot parse, and that is
    /// why neither may use `OrderMessage` for it.
    #[test]
    fn the_kind_the_id_the_account_and_the_nonce_are_read_without_knowing_the_kind() {
        let unknown_kind = br#"{"Swap":{"id":9,"timestamp":1,"account":7,"nonce":"ab","legs":[]}}"#;
        let read = envelope(unknown_kind).expect("a kind this build has never heard of");
        assert_eq!(read.kind, "Swap");
        assert_eq!(read.id, 9);
        assert_eq!(read.account, Some(7));
        assert_eq!(read.nonce.as_deref(), Some("ab"));

        // Invented traffic carries no nonce, so it closes no entry in the
        // separate service.
        let generated = br#"{"New":{"id":9,"timestamp":1,"account":7,"symbol":"ETH-USDC","side":"Buy","price":1.0,"quantity":1.0}}"#;
        let read = envelope(generated).expect("readable");
        assert_eq!(read.kind, "New");
        assert_eq!(read.nonce, None);
        assert_eq!(read.account, Some(7));

        // An account number no `AccountId` can hold is not an account, and it
        // is not a reason to refuse the message either. The nonce beside it is
        // what the sequencer must not lose.
        let too_big = br#"{"Swap":{"id":9,"account":4294967296,"nonce":"ab"}}"#;
        let read = envelope(too_big).expect("readable");
        assert_eq!(read.account, None);
        assert_eq!(read.nonce.as_deref(), Some("ab"));

        // A kind that carries no account at all.
        let no_account = br#"{"EngineRule":{"id":9,"timestamp":1,"version":2}}"#;
        assert_eq!(envelope(no_account).expect("readable").account, None);
    }

    /// Not a message at all. Each of these is refused and not guessed at. The
    /// id decides which leaf a proof is over, so a wrong id proves the wrong
    /// message.
    #[test]
    fn bytes_that_are_not_a_feed_message_are_refused_rather_than_guessed_at() {
        for not_a_message in [
            &b"[]"[..],
            br#""a string""#,
            br#"{"New":{},"Cancel":{}}"#,
            br#"{"New":{"timestamp":1}}"#,
            br#"{"New":7}"#,
            b"not json",
            b"{}",
        ] {
            assert!(
                envelope(not_a_message).is_err(),
                "{} was read as a feed message",
                String::from_utf8_lossy(not_a_message)
            );
        }
    }

    /// The envelope of ENGINE.md section 2 is not the shape on the wire yet,
    /// and this build must not read it as one. Reading it would let a
    /// sequencer publish two spellings of one message and have both honoured.
    /// See `domain::OrderMessage` for why the shape waits for the clean
    /// genesis.
    #[test]
    fn the_section_2_envelope_is_not_a_message_this_build_reads() {
        let envelope_shape =
            br#"{"v":1,"id":9,"timestamp":1,"account":7,"nonce":"ab","body":{"Swap":{"legs":[]}}}"#;
        assert!(envelope(envelope_shape).is_err());
    }

    /// The one-parse reader gives what the two-parse reader gives.
    ///
    /// Same messages, same ids, same kinds, same bytes, and the same `TooOld`
    /// for the kind this build has never heard of. The page holds one known
    /// kind, one unknown kind and one known kind, so the unknown one is read
    /// in the middle of a page rather than at its end.
    #[test]
    fn reading_a_page_once_gives_what_reading_it_twice_gives() {
        let body = served();
        let twice = split_ndjson(&body).expect("the body is one message per line");
        let once = read_ndjson::<OrderMessage>(&body).expect("the same body");

        assert_eq!(once.len(), twice.len());
        for (raw, read) in twice.iter().zip(&once) {
            assert_eq!(*raw, read.raw);
        }

        assert_eq!(once[0].raw.kind, "New");
        assert_eq!(once[1].raw.kind, "Market");
        assert_eq!(once[2].raw.id, 3);
        assert!(once[0].parsed.is_ok());
        assert!(once[2].parsed.is_ok());

        let read_once = once[1]
            .parsed
            .as_ref()
            .expect_err("this build has no Market");
        let read_twice = twice[1]
            .parse::<OrderMessage>()
            .expect_err("this build has no Market");
        assert_eq!(*read_once, read_twice);
        assert_eq!(read_once.id, 2);
        assert_eq!(read_once.kind, "Market");
    }

    /// Bytes that are not a message at all refuse the page on both readers,
    /// and in the same words. The one-parse reader uses `envelope` for these,
    /// so every refusal listed in `bytes_that_are_not_a_feed_message_are_refused_rather_than_guessed_at`
    /// still fires and still says the same thing.
    #[test]
    fn a_page_that_is_not_messages_is_refused_the_same_way_by_both_readers() {
        for not_a_message in [
            &b"[]"[..],
            br#""a string""#,
            br#"{"New":{},"Cancel":{}}"#,
            br#"{"New":{"timestamp":1}}"#,
            br#"{"New":7}"#,
            b"not json",
            b"{}",
            br#"{"New":{"no":"id"}}"#,
            br#"{"New":{"id":1},"Cancel":{"id":2}}"#,
            br#"{"v":1,"id":9,"timestamp":1,"account":7,"nonce":"ab","body":{"Swap":{"legs":[]}}}"#,
        ] {
            let mut body = not_a_message.to_vec();
            body.push(b'\n');
            let twice = split_ndjson(&body).expect_err("not a message");
            let once = read_ndjson::<OrderMessage>(&body).expect_err("not a message");
            assert_eq!(
                once,
                twice,
                "{} is refused differently by the two readers",
                String::from_utf8_lossy(not_a_message)
            );
        }

        // A padded line stops the page on both, before either reads it.
        let mut padded = logchain::canonical_bytes(&order(1));
        padded.push(b'\r');
        padded.push(b'\n');
        assert_eq!(
            read_ndjson::<OrderMessage>(&padded).expect_err("padded lines are not messages"),
            split_ndjson(&padded).expect_err("padded lines are not messages")
        );

        // An empty page is an empty page on both.
        assert_eq!(
            read_ndjson::<OrderMessage>(b"")
                .expect("an idle poll")
                .len(),
            0
        );
        assert_eq!(
            read_ndjson::<OrderMessage>(b"\n")
                .expect("an idle poll")
                .len(),
            0
        );
    }

    #[test]
    fn the_url_names_the_endpoint_that_serves_hashed_bytes() {
        assert_eq!(
            messages_url("http://127.0.0.1:3000/", 41),
            "http://127.0.0.1:3000/messages.ndjson?since=41"
        );
    }
}
