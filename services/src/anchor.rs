//! Reads the anchors the exchange wrote to Base. An anchor is V5's outside
//! record: a commitment a third party holds.
//!
//! Every other check in this repository runs the operator's own history again,
//! and that is the point of `--audit-url`. Those checks cannot say whether the
//! history served today is the history that existed yesterday. An operator can
//! stop the exchange, delete `feed.db` and `state.db`, publish a different
//! history, sign every head and every claim over it again, and start again. An
//! auditor who arrives afterwards runs a history that agrees with itself, and
//! every check passes.
//!
//! The operator cannot change an anchor after writing it. The anchor sender
//! (`anchor/`, a Go program that reads nothing but the public endpoints)
//! writes one record to an anchor contract every few minutes. There are two
//! contracts and two shapes of record, and this module reads both.
//!
//! ```text
//! ExchangeAnchor      (lastId, session, chainHash, stateRoot)
//! ExchangeRootAnchor  (treeSize, lastId, session, rootHash, stateRoot)
//! ```
//!
//! The first contract holds a chain hash. A chain hash is one SHA-256 value
//! that covers messages 1 to lastId, because each message is hashed together
//! with the hash before it. To prove one trade sits inside that value, a
//! checker needs every message in the window: 1.7 MB, measured. The second
//! contract holds the RFC 9162 Merkle root that the sequencer signs in its
//! tree head. A Merkle root is one hash over a tree of hashes, so proving one
//! trade sits inside *that* needs about 17 node hashes. `docs/ENGINE.md`
//! section 8 says why the second contract exists.
//!
//! # Why there are two contracts
//!
//! A root is 32 bytes and a chain hash is 32 bytes, so a root would fit in the
//! old contract's `chainHash` slot and every transaction would succeed. But
//! then nothing on chain would say which anchors hold a chain hash and which
//! hold a root. Both are 32 bytes of hash. An auditor would need a rule that
//! is not in the log, "entries after the 143rd are roots", kept inside a
//! program file. `docs/ENGINE.md` section 3 forbids exactly that.
//!
//! The name of the event settles it instead. `Anchored(...)` and
//! `AnchoredRoot(...)` hash to different topics. A topic is the fixed value
//! Ethereum puts in a log entry to say which event wrote it. So one
//! `eth_getLogs` filter returns chain anchors and the other returns root
//! anchors, and neither filter can return the other kind. That is why the two
//! readers below share their scan and share nothing else: the topic each one
//! filters on is the whole difference, and the two kinds cannot mix by
//! accident.
//!
//! The chain-hash contract is closed: nothing writes to it any more. It is not
//! forgotten. The anchors in it are promises the operator made and cannot take
//! back, so this module reads and checks them exactly as it did before it
//! could read roots.
//!
//! # The two message positions a root anchor carries
//!
//! A chain anchor put all four values at one message position, and the anchor
//! sender paid for that: it had to hash the whole history again on every run.
//! The sequencer signs the chain hash only at its own newest message, so the
//! chain hash at the exchange's own position had to be computed again from the
//! start. A tree head cannot be computed again at an earlier size either, so
//! the root anchor stops putting both values at one position. `rootHash`
//! belongs to `treeSize` and the sequencer signed it in its tree head.
//! `stateRoot` belongs to `lastId` and the exchange signed it in its claim.
//! The contract refuses a write unless `lastId <= treeSize`, so the messages
//! the exchange says it applied are inside the anchored tree.
//!
//! # Why this reads the whole log and not only the newest anchor
//!
//! `latest()` alone does not catch the attack this module exists for. An
//! operator rewinds the sequencer to message 500, publishes different messages
//! from there, runs on to 1500, and writes the anchor `(1500, H_new)`. The
//! *new* history reproduces that newest entry exactly: hash today's messages
//! up to 1500 and `H_new` comes out. Somebody who reads that one value sees no
//! rewind.
//!
//! An *older* anchor shows the rewind. The entry at message 1000 holds
//! `H_old`. Hashing today's messages up to 1000 gives something else, and the
//! block that carried the entry says when the operator committed to the other
//! version. So this module reads every `Anchored` event the contract ever
//! emitted, and `prove.rs` checks every one of them. `latest()` is still read,
//! for two reasons that are worth one extra call. It says how long ago the
//! last anchor was written, and its `count` is how the log scan below knows
//! when it has them all.
//!
//! # Why this needs no Ethereum library
//!
//! Reading a contract is one JSON-RPC POST and some hex. Both answers this
//! module reads have a fixed width: six 32-byte words from `latest()`, and
//! two topics plus four words from each event. So there are no offsets, no
//! lengths and no variable-size types to decode. `reqwest` already does HTTP
//! and `serde_json` already does JSON, so this module adds no dependency to
//! the tree. *Writing* an anchor would need secp256k1 signing and transaction
//! encoding, which is exactly why the anchor sender is a separate program in
//! another language.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::fetch::MAX_PAGE_BYTES;
use crate::logchain::{Chain, StateRoot};
use crate::merkle::{self, Hash, MerkleTree};

/// The 4-byte selector of `latest()`. A selector is the first 4 bytes of
/// `keccak256("latest()")`, and it says which function a call asks for.
///
/// This value and the event topic below are written out by hand, because
/// nothing in this crate computes Keccak-256. The `sha2` crate computes
/// SHA-2, which is a different hash. Adding a Keccak dependency to
/// compute two constants would be a poor trade against the promise that this
/// tree stays at twelve dependencies. Both values are also recorded beside the
/// contract in `anchor/ExchangeAnchor.json` as the compiler emitted them, and
/// `anchor/anchor_test.go` reads this file and checks both against a real
/// Keccak of the signatures the deployed contract was compiled from. Both fail
/// safe: a call with the wrong selector comes back empty and a filter with the
/// wrong topic comes back with no logs, and this module reports neither as
/// agreement.
///
/// These are the defaults, not the only possible values: `--latest-selector`
/// and `--anchored-topic` (or `LATEST_SELECTOR` and `ANCHORED_TOPIC`) replace
/// them for a contract compiled from different signatures. An auditor who sets
/// neither reads the deployed contract correctly.
const DEFAULT_LATEST_SELECTOR: &str = "0x52bfe789";

/// `keccak256("Anchored(uint64,bytes8,bytes32,bytes32,uint64,uint64)")`.
const DEFAULT_ANCHORED_TOPIC: &str =
    "0x846b388d9a84109263340756e41099d4945f475c34c4f401faf0850b7c6d8385";

/// The 4-byte selector of `ExchangeRootAnchor`'s `latest()`.
///
/// These are the same four bytes as the chain-hash contract's selector, and
/// that is not a mistake: a selector covers a function's name and its
/// arguments, and says nothing about what comes back. Both contracts declare
/// `latest()`, so both answer this call: the old one with six 32-byte words,
/// the root one with seven. The width of the answer is what tells the two
/// apart, and `decode_root_latest` refuses the wrong width by name rather than
/// slicing six words as though they were seven.
///
/// It is a separate constant from `DEFAULT_LATEST_SELECTOR` even though the
/// bytes are equal today, because the two come from two contracts. A rename in
/// one must not move the other without anybody noticing.
const DEFAULT_ROOT_LATEST_SELECTOR: &str = "0x52bfe789";

/// `keccak256("AnchoredRoot(uint64,bytes8,bytes32,uint64,bytes32,uint64,uint64)")`.
///
/// This value is what keeps root anchors and chain anchors apart on chain. A
/// filter on it never returns an `Anchored` event, and a filter on the topic
/// above never returns an `AnchoredRoot` event.
const DEFAULT_ROOT_ANCHORED_TOPIC: &str =
    "0xf17e064140470b4f4b89eb3a9324a477206c096df6cbc3dfed400e9b4a2c191f";

/// `ExchangeAnchor::latest()` returns six values, each of a fixed width, so
/// the answer is always six 32-byte words: no offsets, no lengths, and nothing
/// to decode beyond slicing the bytes.
const LATEST_WORDS: usize = 6;

/// An `Anchored` event carries two values in its topics and four fixed-width
/// values in its data. A topic is a value the log can be filtered on.
const EVENT_DATA_WORDS: usize = 4;

/// `ExchangeRootAnchor::latest()` returns seven values, each of a fixed width.
/// Seven words against six is what tells this contract from the chain-hash
/// one.
const ROOT_LATEST_WORDS: usize = 7;

/// An `AnchoredRoot` event carries two values in its topics and five
/// fixed-width values in its data.
const ROOT_EVENT_DATA_WORDS: usize = 5;

/// How long to wait for the sequencer. The consistency check below makes one
/// request to an exchange that may be down. A check that cannot be made has to
/// be reported as not made, so the request has to give up.
const FEED_TIMEOUT: Duration = Duration::from_secs(20);

/// How many blocks one `eth_getLogs` request asks for.
///
/// Public endpoints limit the range. Base's endpoint answers `eth_getLogs is
/// limited to a 10,000 range`, so the scan asks for one chunk at a time. A
/// chunk the endpoint still refuses is halved and asked for again, rather than
/// stopping the audit.
const LOG_CHUNK: u64 = 9_000;

/// The most chunks a scan makes when the auditor named no block to stop at.
///
/// 400 chunks of 9,000 blocks is 3.6M blocks, and Base makes one block every
/// two seconds, so that is about 83 days. Short enough that a wrong address
/// does not turn into thousands of requests, and long enough for any contract
/// that has not been anchoring for a quarter. Past that the scan stops and the
/// audit *fails*, saying how far it got, because the anchors it did not reach
/// are the old ones, which are the ones a rewind contradicts.
const MAX_OPEN_ENDED_REQUESTS: usize = 400;

/// The most chunks a scan makes when the auditor named a block to stop at.
///
/// An auditor who passes `--anchor-from-block` asked for that range on
/// purpose, so the scan reads all of it rather than stopping at the limit
/// above, which is what that limit would otherwise do to exactly the auditor
/// who knew the deployment block. 5,000 chunks reach 45M blocks, the whole of
/// Base Sepolia at the time of writing. A scan that long is slow and says so.
/// This limit exists only so a mistyped block number ends rather than runs
/// forever.
const MAX_BOUNDED_REQUESTS: usize = 5_000;

/// How long to wait for the RPC endpoint. An anchor that cannot be read has to
/// be reported, and the request has to give up before it can be reported.
const RPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// The most bytes one RPC answer may hold. One chunk of anchor logs is a few
/// hundred entries of 400 bytes each, so an answer past this size is not an
/// answer to the question that was asked.
const MAX_RPC_BYTES: usize = 8 * 1024 * 1024;

// ---------------------------------------------------------------------------
// The two values the requests are built from
// ---------------------------------------------------------------------------

/// One value an auditor can override: which flag sets it, which environment
/// variable stands behind that flag, how wide it is, and what it is when the
/// auditor sets neither.
///
/// The two values are described here rather than checked in place, because
/// every message this produces has to name the flag the auditor typed. An
/// error that says "bad hex" and not which of the two flags carried it leaves
/// the auditor guessing at exactly the moment they mistyped something.
struct AbiValue {
    flag: &'static str,
    env: &'static str,
    /// What the value is, in words, for the messages.
    what: &'static str,
    /// How many hex characters follow the `0x`.
    digits: usize,
    default: &'static str,
}

const TOPIC: AbiValue = AbiValue {
    flag: "--anchored-topic",
    env: "ANCHORED_TOPIC",
    what: "the Anchored event topic",
    digits: 64,
    default: DEFAULT_ANCHORED_TOPIC,
};

const SELECTOR: AbiValue = AbiValue {
    flag: "--latest-selector",
    env: "LATEST_SELECTOR",
    what: "the latest() function selector",
    digits: 8,
    default: DEFAULT_LATEST_SELECTOR,
};

const ROOT_TOPIC: AbiValue = AbiValue {
    flag: "--root-anchored-topic",
    env: "ROOT_ANCHORED_TOPIC",
    what: "the AnchoredRoot event topic",
    digits: 64,
    default: DEFAULT_ROOT_ANCHORED_TOPIC,
};

const ROOT_SELECTOR: AbiValue = AbiValue {
    flag: "--root-latest-selector",
    env: "ROOT_LATEST_SELECTOR",
    what: "the root anchor's latest() function selector",
    digits: 8,
    default: DEFAULT_ROOT_LATEST_SELECTOR,
};

impl AbiValue {
    /// Takes the flag first, then the environment variable, then the built-in
    /// default.
    ///
    /// Both sources arrive as arguments, and this function reads nothing from
    /// the process. So a test can check the order without setting an
    /// environment variable, which would reach every thread of a test binary
    /// that runs its tests in parallel.
    fn resolve(&self, flag: Option<&str>, env: Option<&str>) -> Result<String, String> {
        match (flag, env) {
            (Some(value), _) => self.check(value, self.flag.to_string()),
            (None, Some(value)) => self.check(
                value,
                format!(
                    "{} (the environment variable behind {})",
                    self.env, self.flag
                ),
            ),
            (None, None) => Ok(self.default.to_string()),
        }
    }

    /// Accepts `0x` and exactly `digits` lowercase hex characters. It runs
    /// before any request is made.
    ///
    /// It refuses uppercase rather than lowering it, on purpose. The RPC
    /// endpoint matches a topic filter and a call's data byte for byte, so a
    /// value that looks right and is not produces an empty answer rather than
    /// an error. Accepting one spelling of a value the auditor typed, and
    /// saying nothing, would teach them that spelling is not checked.
    fn check(&self, value: &str, source: String) -> Result<String, String> {
        let value = value.trim();
        let Some(body) = value.strip_prefix("0x") else {
            return Err(self.refuse(&source, value, "it does not start with 0x"));
        };
        if body.len() != self.digits {
            return Err(self.refuse(
                &source,
                value,
                &format!(
                    "it carries {} characters after the 0x, not {}",
                    body.len(),
                    self.digits
                ),
            ));
        }
        if !body.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(self.refuse(&source, value, "it is not hex"));
        }
        if body.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(self.refuse(
                &source,
                value,
                "it contains uppercase hex characters, which are not the same bytes to an RPC \
                 endpoint as the lowercase ones",
            ));
        }
        Ok(value.to_string())
    }

    fn refuse(&self, source: &str, value: &str, problem: &str) -> String {
        format!(
            "{} was given '{}', and {}: {} has to be 0x followed by exactly {} lowercase hex \
             characters. This value is matched byte for byte by the RPC endpoint, so one that is \
             nearly right finds nothing at all rather than failing.",
            source, value, problem, self.what, self.digits
        )
    }
}

/// The two values every anchor request is built from: which function
/// `latest()` is, and which topic an `Anchored` event carries.
///
/// The defaults are the deployed contract's values, so an audit that sets
/// nothing is a correct audit. An auditor can still replace them, because this
/// repository does not own the contract: anybody may compile their own from a
/// changed event signature and write anchors to it. A tool that can read only
/// one build of one contract has to be copied and edited before anybody else
/// can use it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorAbi {
    pub anchored_topic: String,
    pub latest_selector: String,
}

impl Default for AnchorAbi {
    fn default() -> Self {
        AnchorAbi {
            anchored_topic: DEFAULT_ANCHORED_TOPIC.to_string(),
            latest_selector: DEFAULT_LATEST_SELECTOR.to_string(),
        }
    }
}

impl AnchorAbi {
    /// Resolves both values from what the flags carried and what the
    /// environment held, and refuses a value that is malformed.
    pub fn resolve(
        topic_flag: Option<&str>,
        topic_env: Option<&str>,
        selector_flag: Option<&str>,
        selector_env: Option<&str>,
    ) -> Result<Self, String> {
        Ok(AnchorAbi {
            anchored_topic: TOPIC.resolve(topic_flag, topic_env)?,
            latest_selector: SELECTOR.resolve(selector_flag, selector_env)?,
        })
    }

    /// The same work, but this function reads the two environment variables
    /// itself. `main` calls this one. `resolve` above takes the two as
    /// arguments, so a test can check the order of the three sources alone.
    pub fn from_flags_and_env(
        topic_flag: Option<&str>,
        selector_flag: Option<&str>,
    ) -> Result<Self, String> {
        Self::resolve(
            topic_flag,
            std::env::var(TOPIC.env).ok().as_deref(),
            selector_flag,
            std::env::var(SELECTOR.env).ok().as_deref(),
        )
    }

    /// The lines the audit has to print before it runs: one line for each
    /// value the auditor replaced, and nothing at all when both values are the
    /// defaults.
    ///
    /// `check` above refuses a malformed value. The dangerous value is not a
    /// malformed one, but a well-formed wrong one. It turns a check for a
    /// changed history into a search that finds nothing, and finding nothing is
    /// what a contract with no anchors looks like.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.anchored_topic != DEFAULT_ANCHORED_TOPIC {
            warnings.push(format!(
                "warning: the Anchored topic was overridden to {}, and this audit will only find \
                 events matching it. An event topic that does not match the deployed contract \
                 produces an empty log list, which reads as 'no anchors' rather than as an error. \
                 The built-in default {} is the topic the deployed contract emits.",
                self.anchored_topic, DEFAULT_ANCHORED_TOPIC
            ));
        }
        if self.latest_selector != DEFAULT_LATEST_SELECTOR {
            warnings.push(format!(
                "warning: the latest() selector was overridden to {}, and this audit will call \
                 that function instead. A selector that does not match the deployed contract \
                 returns an empty answer, which is reported here as there being no contract at \
                 the address rather than as a wrong selector. The built-in default {} is the \
                 selector the deployed contract answers.",
                self.latest_selector, DEFAULT_LATEST_SELECTOR
            ));
        }
        warnings
    }
}

/// Where an audit reads anchors from. Every part comes from the auditor's own
/// command line, never from the exchange: an operator who could name the
/// contract their own audit reads could name an empty one.
#[derive(Debug, Clone)]
pub struct AnchorSource {
    pub rpc: String,
    pub contract: String,
    /// The block the backwards scan stops at, when the auditor knows one. The
    /// contract's deployment block makes the scan exact. Without it the scan
    /// stops as soon as it has as many anchors as the contract says exist.
    pub from_block: Option<u64>,
    /// The selector and the topic the two requests are built from. They are
    /// the deployed contract's values unless `with_abi` replaced them.
    pub abi: AnchorAbi,
}

impl AnchorSource {
    /// Builds a source. It refuses a string that is not an address before any
    /// request is made.
    pub fn new(rpc: &str, contract: &str, from_block: Option<u64>) -> Result<Self, String> {
        Ok(AnchorSource {
            rpc: rpc.trim().to_string(),
            contract: normalise_address(contract)?,
            from_block,
            abi: AnchorAbi::default(),
        })
    }

    /// Reads this contract with a selector and a topic that are not the
    /// deployed contract's.
    pub fn with_abi(mut self, abi: AnchorAbi) -> Self {
        self.abi = abi;
        self
    }
}

/// The same two values for the root anchor contract: which topic an
/// `AnchoredRoot` event carries, and which function `latest()` is there.
///
/// This is a separate type from `AnchorAbi`, not a field on it. Two commands
/// with two sets of flags read the two contracts. One struct holding four
/// strings would let a caller pass a chain topic where a root topic belongs.
/// No layer would report that as an error, because a topic that matches
/// nothing returns an empty log list, and an empty list reads as "no
/// anchors".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAnchorAbi {
    pub anchored_topic: String,
    pub latest_selector: String,
}

impl Default for RootAnchorAbi {
    fn default() -> Self {
        RootAnchorAbi {
            anchored_topic: DEFAULT_ROOT_ANCHORED_TOPIC.to_string(),
            latest_selector: DEFAULT_ROOT_LATEST_SELECTOR.to_string(),
        }
    }
}

impl RootAnchorAbi {
    /// Resolves both values from what the flags carried and what the
    /// environment held, and refuses a value that is malformed.
    pub fn resolve(
        topic_flag: Option<&str>,
        topic_env: Option<&str>,
        selector_flag: Option<&str>,
        selector_env: Option<&str>,
    ) -> Result<Self, String> {
        Ok(RootAnchorAbi {
            anchored_topic: ROOT_TOPIC.resolve(topic_flag, topic_env)?,
            latest_selector: ROOT_SELECTOR.resolve(selector_flag, selector_env)?,
        })
    }

    /// The same work, but this function reads the two environment variables
    /// itself.
    pub fn from_flags_and_env(
        topic_flag: Option<&str>,
        selector_flag: Option<&str>,
    ) -> Result<Self, String> {
        Self::resolve(
            topic_flag,
            std::env::var(ROOT_TOPIC.env).ok().as_deref(),
            selector_flag,
            std::env::var(ROOT_SELECTOR.env).ok().as_deref(),
        )
    }

    /// The lines the audit has to print before it runs, for the reason on
    /// `AnchorAbi::warnings`: a well-formed wrong value turns a check for a
    /// changed history into a search that finds nothing.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.anchored_topic != DEFAULT_ROOT_ANCHORED_TOPIC {
            warnings.push(format!(
                "warning: the AnchoredRoot topic was overridden to {}, and this audit will only \
                 find events matching it. An event topic that does not match the deployed \
                 contract produces an empty log list, which reads as 'no anchors' rather than as \
                 an error. The built-in default {} is the topic the deployed root anchor emits.",
                self.anchored_topic, DEFAULT_ROOT_ANCHORED_TOPIC
            ));
        }
        if self.latest_selector != DEFAULT_ROOT_LATEST_SELECTOR {
            warnings.push(format!(
                "warning: the root anchor's latest() selector was overridden to {}, and this \
                 audit will call that function instead. A selector that does not match the \
                 deployed contract returns an empty answer, which is reported here as there being \
                 no contract at the address rather than as a wrong selector. The built-in default \
                 {} is the selector the deployed root anchor answers.",
                self.latest_selector, DEFAULT_ROOT_LATEST_SELECTOR
            ));
        }
        warnings
    }
}

/// Where an audit reads root anchors from. Every part comes from the auditor's
/// own command line, never from the exchange.
#[derive(Debug, Clone)]
pub struct RootAnchorSource {
    pub rpc: String,
    pub contract: String,
    pub from_block: Option<u64>,
    pub abi: RootAnchorAbi,
}

impl RootAnchorSource {
    /// Builds a source. It refuses a string that is not an address before any
    /// request is made.
    pub fn new(rpc: &str, contract: &str, from_block: Option<u64>) -> Result<Self, String> {
        let normalised = normalise_address(contract)?;
        Ok(RootAnchorSource {
            rpc: rpc.trim().to_string(),
            contract: normalised,
            from_block,
            abi: RootAnchorAbi::default(),
        })
    }

    /// Reads this contract with a selector and a topic that are not the
    /// deployed contract's.
    pub fn with_abi(mut self, abi: RootAnchorAbi) -> Self {
        self.abi = abi;
        self
    }
}

/// Returns `0x` and 40 hex characters in lower case, or a sentence that says
/// the string is not an address. Both sources call this one function, so the
/// two cannot drift into accepting different strings.
fn normalise_address(contract: &str) -> Result<String, String> {
    let contract = contract.trim();
    let body = contract.strip_prefix("0x").unwrap_or(contract);
    if body.len() != 40 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "'{}' is not a contract address: an address is 0x followed by 40 hex characters",
            contract
        ));
    }
    Ok(format!("0x{}", body.to_ascii_lowercase()))
}

/// One anchor, as the contract recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// The message number this anchor commits to. It is the last message the
    /// anchor covers.
    pub last_id: u64,
    /// The session those message numbers belong to. A session is a name for
    /// one log, written as the 16 hex characters the sequencer names itself
    /// with. Message numbers start again at 1 when a log is replaced, so an
    /// anchored message number without a session names nothing.
    pub session: String,
    /// The chain hash over messages 1 to `last_id`: one hash that covers them
    /// all.
    pub chain: Chain,
    /// The state root after message `last_id`: one hash that covers
    /// everything the exchange holds.
    pub state_root: StateRoot,
    /// The time of the block that carried this anchor, in seconds since 1
    /// January 1970. The contract records `block.timestamp` inside the event,
    /// so reading it needs no second request for the block.
    pub anchored_at: u64,
    /// The block this anchor was written in. Zero for the anchor read from
    /// `latest()`, because that one is contract state and not a log entry.
    pub block_number: u64,
    /// Which anchor this was, counting from one.
    pub index: u64,
}

impl Anchor {
    /// How long ago this anchor was written, as a sentence. An anchor from
    /// last month covers much less than one from ten minutes ago, and the
    /// report has to say which one it is.
    pub fn age(&self) -> String {
        age_since(self.anchored_at)
    }
}

/// How long ago a block timestamp was, as a sentence.
fn age_since(anchored_at: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if anchored_at == 0 || now <= anchored_at {
        return "just now".to_string();
    }
    age_text(now - anchored_at)
}

fn age_text(seconds: u64) -> String {
    match seconds {
        0..=90 => format!("{} seconds ago", seconds),
        91..=5400 => format!("{} minutes ago", seconds / 60),
        5401..=172_800 => format!("{} hours ago", seconds / 3600),
        _ => format!("{} days ago", seconds / 86400),
    }
}

/// Every anchor one contract holds, and how completely they were read.
#[derive(Debug, Clone)]
pub struct AnchorHistory {
    pub contract: String,
    pub chain_id: u64,
    /// Every `Anchored` event found, oldest first.
    pub anchors: Vec<Anchor>,
    /// The newest anchor, as the contract's own state holds it. It is the same
    /// record as the last event. This module reads it separately because that
    /// one cheap call says how long ago the exchange last anchored at all.
    pub latest: Anchor,
    /// How many anchors the contract says it has written, ever.
    pub total: u64,
    /// The oldest block the log scan reached.
    pub scanned_from: u64,
    /// True when the scan found every anchor the contract has written, from
    /// the first to the `count`th. False means the scan stopped early. The
    /// report has to state that, rather than call the anchors it did find a
    /// checked set.
    pub complete: bool,
    /// True when the newest event in the log is the same write the contract's
    /// own state holds.
    ///
    /// The two are one write in two forms, read by two different methods, and
    /// nothing else in this audit would notice them disagreeing. They disagree
    /// when the endpoint does not serve one consistent view of one chain: a
    /// proxy joining two nodes, a fork, or an RPC endpoint that invents logs.
    /// Under none of those do the anchors below mean anything.
    pub latest_agrees: bool,
}

impl AnchorHistory {
    /// The message numbers the anchors commit to, in order and with no
    /// repeats. The audit takes its own chain hash and its own state root at
    /// exactly these numbers.
    pub fn positions(&self) -> Vec<u64> {
        let mut positions: Vec<u64> = self.anchors.iter().map(|a| a.last_id).collect();
        positions.sort_unstable();
        positions.dedup();
        positions
    }
}

/// One root anchor, as `ExchangeRootAnchor` recorded it.
///
/// It holds two message positions, and a separate signature covers each one.
/// See the note at the top of this file. No number here is the auditor's guess
/// about where a value stands: both numbers came out of the block with the
/// value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAnchor {
    /// How many messages the Merkle tree behind `root` holds. The tree holds
    /// messages 1 to `tree_size`, so message n sits at leaf n-1. A leaf is one
    /// message's stored bytes at the bottom of the tree.
    pub tree_size: u64,
    /// The last message the exchange had written to disk in its state
    /// database. It is always `<= tree_size`; the contract refuses otherwise.
    pub last_id: u64,
    /// The session both numbers belong to, written as the 16 hex characters
    /// the sequencer names itself with.
    pub session: String,
    /// The RFC 9162 Merkle root over messages 1 to `tree_size`, as the
    /// sequencer signed it in its tree head.
    pub root: Hash,
    /// The state root after message `last_id`: one hash that covers
    /// everything the exchange holds.
    pub state_root: StateRoot,
    /// The time of the block that carried this anchor, in seconds since 1
    /// January 1970.
    pub anchored_at: u64,
    /// The block this anchor was written in. Zero for the anchor read from
    /// `latest()`, because that one is contract state and not a log entry.
    pub block_number: u64,
    /// Which anchor this was, counting from one.
    pub index: u64,
}

impl RootAnchor {
    /// How long ago this anchor was written, as a sentence.
    pub fn age(&self) -> String {
        age_since(self.anchored_at)
    }
}

/// Every root anchor one contract holds, and how completely they were read.
///
/// It has the same shape as `AnchorHistory`, and it is a different type on
/// purpose. The two hold different records with different meanings. One type
/// carrying an optional root beside an optional chain hash would let a caller
/// check the wrong one and report a pass.
#[derive(Debug, Clone)]
pub struct RootAnchorHistory {
    pub contract: String,
    pub chain_id: u64,
    /// Every `AnchoredRoot` event found, oldest first.
    pub anchors: Vec<RootAnchor>,
    /// The newest anchor, as the contract's own state holds it.
    pub latest: RootAnchor,
    /// How many anchors the contract says it has written, ever.
    pub total: u64,
    /// The oldest block the log scan reached.
    pub scanned_from: u64,
    /// True when the scan found every anchor the contract has written. False
    /// means the scan stopped early. The report has to state that, rather than
    /// call the anchors it did find a checked set.
    pub complete: bool,
    /// True when the newest event in the log is the same write the contract's
    /// own state holds. They disagree when the endpoint does not serve one
    /// consistent view of one chain, and under none of those conditions do the
    /// anchors mean anything.
    pub latest_agrees: bool,
}

impl RootAnchorHistory {
    /// The tree sizes the anchors hold a root over, in order and with no
    /// repeats. An audit hashes the served messages in one pass and takes its
    /// own root at exactly these sizes.
    pub fn tree_sizes(&self) -> Vec<u64> {
        let mut sizes: Vec<u64> = self.anchors.iter().map(|a| a.tree_size).collect();
        sizes.sort_unstable();
        sizes.dedup();
        sizes
    }

    /// The message numbers the anchors hold a state root after, in order and
    /// with no repeats. This does the same job as `AnchorHistory::positions`,
    /// so it carries the same name. Calling it `tree_sizes` would have been
    /// misleading: these are message numbers, and the `tree_sizes` above are
    /// not.
    pub fn positions(&self) -> Vec<u64> {
        let mut positions: Vec<u64> = self.anchors.iter().map(|a| a.last_id).collect();
        positions.sort_unstable();
        positions.dedup();
        positions
    }
}

// ---------------------------------------------------------------------------
// Hex, the two shapes this needs
// ---------------------------------------------------------------------------

/// Decodes a hex string of any length, with or without an `0x` in front.
///
/// `logchain::from_hex` is the right function for a value of known width, and
/// everywhere else uses it for exactly that. An RPC answer arrives with an
/// `0x`, and its width is the thing being checked, so it needs this one.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let body = text.strip_prefix("0x").unwrap_or(text);
    if !body.len().is_multiple_of(2) || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    (0..body.len() / 2)
        .map(|i| u8::from_str_radix(&body[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Reads a number the way JSON-RPC writes one: `0x` and no leading zeros.
fn decode_quantity(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim().strip_prefix("0x").unwrap_or(text.trim()), 16).ok()
}

/// Reads a u64 out of the last 8 bytes of a 32-byte word, most significant
/// byte first. That is where Ethereum puts a `uint64`.
fn word_u64(word: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&word[24..32]);
    u64::from_be_bytes(bytes)
}

fn word_32(word: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&word[0..32]);
    out
}

// ---------------------------------------------------------------------------
// JSON-RPC
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct RpcAnswer {
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
}

#[derive(serde::Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

/// One raw log entry, as `eth_getLogs` serves it.
#[derive(serde::Deserialize)]
struct RawLog {
    topics: Vec<String>,
    data: String,
    #[serde(rename = "blockNumber")]
    block_number: String,
}

/// Makes one JSON-RPC call and returns its `result`.
async fn rpc_call(
    client: &reqwest::Client,
    rpc: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let response = client
        .post(rpc)
        .header("content-type", "application/json")
        // Some public endpoints refuse a request that names no client at all.
        .header("user-agent", "verifiable-exchange-audit/1")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("cannot reach the anchor's RPC at {}: {}", rpc, e))?;

    let status = response.status();
    let mut response = response;
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("cannot read what {} answered: {}", rpc, e))?
    {
        if bytes.len() + chunk.len() > MAX_RPC_BYTES {
            return Err(format!(
                "{} sent more than {} bytes for one {} answer",
                rpc, MAX_RPC_BYTES, method
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        return Err(format!(
            "{} answered {} to {}: {}",
            rpc,
            status,
            method,
            String::from_utf8_lossy(&bytes).trim()
        ));
    }
    let answer: RpcAnswer = serde_json::from_slice(&bytes)
        .map_err(|e| format!("cannot read what {} answered to {}: {}", rpc, method, e))?;
    if let Some(error) = answer.error {
        return Err(format!(
            "{} refused {}: {} (code {})",
            rpc, method, error.message, error.code
        ));
    }
    answer
        .result
        .ok_or_else(|| format!("{} answered {} with nothing at all", rpc, method))
}

/// The same call, for the methods whose answer is one hex string.
async fn rpc_string(
    client: &reqwest::Client,
    rpc: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<String, String> {
    match rpc_call(client, rpc, method, params).await? {
        serde_json::Value::String(text) => Ok(text),
        other => Err(format!(
            "{} answered {} with {}, which is not a hex string",
            rpc, method, other
        )),
    }
}

fn rpc_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(RPC_CONNECT_TIMEOUT)
        .timeout(RPC_TIMEOUT)
        .build()
        .map_err(|e| format!("cannot build an HTTP client for the anchor: {}", e))
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// Reads every anchor one contract holds.
///
/// It makes one `eth_chainId` call, one `eth_call` for `latest()`, one
/// `eth_blockNumber` call, and then `eth_getLogs` calls backwards in chunks.
/// It stops when it has found as many `Anchored` events as `latest()` says
/// exist. Counting down to a number the contract itself keeps is what lets the
/// scan end without the auditor knowing the deployment block. Passing
/// `--anchor-from-block` makes the scan stop at that block instead.
pub async fn read_history(source: &AnchorSource) -> Result<AnchorHistory, String> {
    let client = rpc_client()?;
    let chain_id = read_chain_id(&client, &source.rpc).await;

    let result = rpc_string(
        &client,
        &source.rpc,
        "eth_call",
        latest_call_params(&source.contract, &source.abi.latest_selector),
    )
    .await?;
    let latest = decode_latest(&result, &source.contract, chain_id)?;

    let scan = scan_events(
        &client,
        &source.rpc,
        &source.contract,
        &source.abi.anchored_topic,
        source.from_block,
        latest.index,
        decode_event,
        |anchor: &Anchor| anchor.index,
    )
    .await?;

    let latest_agrees = scan.found.get(&latest.index).is_some_and(|newest| {
        newest.last_id == latest.last_id
            && newest.session == latest.session
            && newest.chain == latest.chain
            && newest.state_root == latest.state_root
            && newest.anchored_at == latest.anchored_at
    });

    Ok(AnchorHistory {
        contract: source.contract.clone(),
        chain_id,
        anchors: scan.found.into_values().collect(),
        total: latest.index,
        latest,
        scanned_from: scan.scanned_from,
        complete: scan.complete,
        latest_agrees,
    })
}

/// Reads every root anchor one `ExchangeRootAnchor` holds.
///
/// It makes the same requests in the same order as `read_history`, with a
/// different topic and a different decoder. Everything the comment above says
/// about reading the whole log, and not `latest()` alone, is true here too. An
/// operator who rewound the log and wrote a new anchor leaves a contract whose
/// newest root today's tree reproduces exactly. The *older* entries are the
/// ones that do not.
pub async fn read_root_history(source: &RootAnchorSource) -> Result<RootAnchorHistory, String> {
    let client = rpc_client()?;
    let chain_id = read_chain_id(&client, &source.rpc).await;

    let result = rpc_string(
        &client,
        &source.rpc,
        "eth_call",
        latest_call_params(&source.contract, &source.abi.latest_selector),
    )
    .await?;
    let latest = decode_root_latest(&result, &source.contract, chain_id)?;

    let scan = scan_events(
        &client,
        &source.rpc,
        &source.contract,
        &source.abi.anchored_topic,
        source.from_block,
        latest.index,
        decode_root_event,
        |anchor: &RootAnchor| anchor.index,
    )
    .await?;

    let latest_agrees = scan.found.get(&latest.index).is_some_and(|newest| {
        newest.tree_size == latest.tree_size
            && newest.last_id == latest.last_id
            && newest.session == latest.session
            && newest.root == latest.root
            && newest.state_root == latest.state_root
            && newest.anchored_at == latest.anchored_at
    });

    Ok(RootAnchorHistory {
        contract: source.contract.clone(),
        chain_id,
        anchors: scan.found.into_values().collect(),
        total: latest.index,
        latest,
        scanned_from: scan.scanned_from,
        complete: scan.complete,
        latest_agrees,
    })
}

/// The chain id, or 0 when the endpoint will not say. The chain id appears in
/// messages and nowhere else, so a refusal here must not end an audit that
/// could otherwise run.
async fn read_chain_id(client: &reqwest::Client, rpc: &str) -> u64 {
    rpc_string(client, rpc, "eth_chainId", serde_json::json!([]))
        .await
        .ok()
        .and_then(|hex| decode_quantity(&hex))
        .unwrap_or(0)
}

/// What one backwards scan of a contract's log found.
struct Scan<T> {
    /// Keyed by the contract's own counter. See the note inside `scan_events`.
    found: BTreeMap<u64, T>,
    scanned_from: u64,
    complete: bool,
}

/// Calls `eth_getLogs` backwards in chunks. It stops when it has found as many
/// events as the contract's own counter says exist.
///
/// Both anchor kinds use this one function. The scan is the part that is easy
/// to get wrong in small ways, and it does not depend on what a record means.
/// The topic and the decoder are not shared, because those two are exactly
/// what must differ between a chain anchor and a root anchor. See the note at
/// the top of this file.
///
/// Counting down to a number the contract itself keeps is what lets the scan
/// end without the auditor knowing the deployment block. Passing `from_block`
/// makes the scan stop at that block instead.
#[allow(clippy::too_many_arguments)]
async fn scan_events<T, D, I>(
    client: &reqwest::Client,
    rpc: &str,
    contract: &str,
    topic: &str,
    from_block: Option<u64>,
    total: u64,
    decode: D,
    index_of: I,
) -> Result<Scan<T>, String>
where
    D: Fn(&RawLog, u64) -> Result<T, String>,
    I: Fn(&T) -> u64,
{
    let head =
        decode_quantity(&rpc_string(client, rpc, "eth_blockNumber", serde_json::json!([])).await?)
            .ok_or_else(|| format!("{} did not answer with a block number", rpc))?;

    let floor = from_block.unwrap_or(0);
    let budget = if from_block.is_some() {
        MAX_BOUNDED_REQUESTS
    } else {
        MAX_OPEN_ENDED_REQUESTS
    };

    // The key is the contract's own counter. The contract raises it by one
    // for each write, and it starts at one. A key taken from where a log
    // turned up, the block or the place of the log in one answer, would
    // make "how many are there" a question about what the endpoint sent, and
    // not about what the contract did. An answer that repeats an event, or a
    // provider that returns blocks a little outside the range it was asked
    // for, would raise the count, stop the scan early, and let the audit
    // report a partial read as a complete one. The anchors such a scan skips
    // are the old ones, and the old ones are what a rewind contradicts.
    let mut found: BTreeMap<u64, T> = BTreeMap::new();
    let has_every = |found: &BTreeMap<u64, T>| {
        found.len() as u64 >= total && (1..=total).all(|i| found.contains_key(&i))
    };

    let mut to = head;
    let mut scanned_from = head;
    let mut requests = 0;
    let mut chunk = LOG_CHUNK;

    while requests < budget && !has_every(&found) {
        let from = to.saturating_sub(chunk.saturating_sub(1)).max(floor);
        match get_logs(client, rpc, contract, topic, from, to).await {
            Ok(logs) => {
                for log in logs {
                    let block = decode_quantity(&log.block_number).ok_or_else(|| {
                        format!(
                            "{} served an anchor log with block number '{}', which is not a \
                             quantity",
                            rpc, log.block_number
                        )
                    })?;
                    let anchor = decode(&log, block)?;
                    found.insert(index_of(&anchor), anchor);
                }
                scanned_from = from;
                requests += 1;
                if from <= floor || from == 0 {
                    break;
                }
                to = from - 1;
            }
            Err(reason) if reason.contains("range") && chunk > 100 => {
                // The endpoint reached its own range limit, whatever that
                // limit is. Halve the chunk and ask for the same window
                // again, instead of losing the anchors inside it.
                chunk /= 2;
                requests += 1;
            }
            Err(reason) => return Err(reason),
        }
    }

    // `has_every` uses `>=` and not `==` on purpose. The anchor sender writes
    // every few minutes, so a new anchor can land between the `latest()` call
    // and this scan. Finding one more anchor than the count said means the
    // exchange is running, not that two answers disagree.
    let complete = has_every(&found);
    Ok(Scan {
        found,
        scanned_from,
        complete,
    })
}

/// Builds the `eth_call` that reads `latest()`. It is separate from the code
/// that sends it, so a test can read which selector it carries with no chain.
fn latest_call_params(contract: &str, selector: &str) -> serde_json::Value {
    serde_json::json!([
        { "to": contract, "data": selector },
        "latest"
    ])
}

/// Builds the `eth_getLogs` filter for one chunk of the scan. It is separate
/// for the same reason: the topic in it is the whole difference between
/// reading a contract's anchors and reading an empty list.
fn logs_params(contract: &str, topic: &str, from: u64, to: u64) -> serde_json::Value {
    serde_json::json!([{
        "address": contract,
        "topics": [topic],
        "fromBlock": format!("0x{:x}", from),
        "toBlock": format!("0x{:x}", to),
    }])
}

async fn get_logs(
    client: &reqwest::Client,
    rpc: &str,
    contract: &str,
    topic: &str,
    from: u64,
    to: u64,
) -> Result<Vec<RawLog>, String> {
    let result = rpc_call(
        client,
        rpc,
        "eth_getLogs",
        logs_params(contract, topic, from, to),
    )
    .await?;
    serde_json::from_value(result)
        .map_err(|e| format!("cannot read the anchor logs {} served: {}", rpc, e))
}

/// Turns the 192 bytes `ExchangeAnchor::latest()` returns into an anchor.
///
/// It is separate from the request, so a test can check the decoding with no
/// chain. It is also separate because each way this can go wrong needs a
/// different sentence for the auditor. An address with no contract at it
/// answers `0x`. An address with a *different* contract at it answers a number
/// of bytes that is not 192. This must report neither as "no anchor yet".
fn decode_latest(result: &str, contract: &str, chain_id: u64) -> Result<Anchor, String> {
    let bytes = decode_hex(result)
        .ok_or_else(|| format!("{} answered with '{}', which is not hex", contract, result))?;
    if bytes.is_empty() {
        return Err(format!(
            "there is no contract at {} on chain {}: the call for its newest anchor came back \
             empty. Check the address and that the RPC is on the right network",
            contract, chain_id
        ));
    }
    if bytes.len() == ROOT_LATEST_WORDS * 32 {
        return Err(format!(
            "{} answered latest() with {} bytes, which is what an ExchangeRootAnchor returns, not \
             the {} the chain-hash ExchangeAnchor returns. Both contracts declare latest(), so \
             both answer the same selector. That address holds the root anchor, whose anchors \
             commit a Merkle root and are read with --root-anchor-contract",
            contract,
            bytes.len(),
            LATEST_WORDS * 32
        ));
    }
    if bytes.len() != LATEST_WORDS * 32 {
        return Err(format!(
            "{} answered latest() with {} bytes, not the {} an ExchangeAnchor returns: whatever \
             is deployed there, it is not the anchor contract",
            contract,
            bytes.len(),
            LATEST_WORDS * 32
        ));
    }

    let index = word_u64(&bytes[160..192]);
    if index == 0 {
        return Err(format!(
            "{} on chain {} holds no anchors yet: nothing has been committed to it, so there is \
             nothing for this audit to check against",
            contract, chain_id
        ));
    }

    Ok(Anchor {
        last_id: word_u64(&bytes[0..32]),
        // A `bytes8` sits at the start of its 32-byte word. The sequencer
        // names its log with exactly these 8 bytes, or 16 hex characters.
        session: crate::logchain::to_hex(&bytes[32..40]),
        chain: word_32(&bytes[64..96]),
        state_root: word_32(&bytes[96..128]),
        anchored_at: word_u64(&bytes[128..160]),
        block_number: 0,
        index,
    })
}

/// Turns one `Anchored` event into an anchor. Two values sit in the topics and
/// four fixed-width values sit in the data. Nothing has a variable width.
fn decode_event(log: &RawLog, block_number: u64) -> Result<Anchor, String> {
    if log.topics.len() != 3 {
        return Err(format!(
            "an anchor log in block {} carries {} topics, not the 3 an Anchored event has",
            block_number,
            log.topics.len()
        ));
    }
    let last_id_topic = decode_hex(&log.topics[1])
        .filter(|b| b.len() == 32)
        .ok_or_else(|| format!("an anchor log in block {} has no message id", block_number))?;
    let session_topic = decode_hex(&log.topics[2])
        .filter(|b| b.len() == 32)
        .ok_or_else(|| format!("an anchor log in block {} has no session", block_number))?;
    let data = decode_hex(&log.data)
        .filter(|b| b.len() == EVENT_DATA_WORDS * 32)
        .ok_or_else(|| {
            format!(
                "an anchor log in block {} carries {} bytes of data, not the {} an Anchored \
                 event has",
                block_number,
                decode_hex(&log.data).map(|b| b.len()).unwrap_or(0),
                EVENT_DATA_WORDS * 32
            )
        })?;

    Ok(Anchor {
        last_id: word_u64(&last_id_topic),
        session: crate::logchain::to_hex(&session_topic[0..8]),
        chain: word_32(&data[0..32]),
        state_root: word_32(&data[32..64]),
        anchored_at: word_u64(&data[64..96]),
        block_number,
        index: word_u64(&data[96..128]),
    })
}

/// Turns the 224 bytes `ExchangeRootAnchor::latest()` returns into an anchor.
///
/// The width check does more work here than it looks. Both contracts declare
/// `latest()`, so both answer the same four selector bytes. An auditor who
/// points `--root-anchor-contract` at the closed chain-hash contract gets six
/// well-formed words back, not seven. Slicing six words as seven would build
/// an anchor full of values that look right and commit to nothing. So this
/// refuses the wrong width and says which contract the answer came from.
fn decode_root_latest(result: &str, contract: &str, chain_id: u64) -> Result<RootAnchor, String> {
    let bytes = decode_hex(result)
        .ok_or_else(|| format!("{} answered with '{}', which is not hex", contract, result))?;
    if bytes.is_empty() {
        return Err(format!(
            "there is no contract at {} on chain {}: the call for its newest anchor came back \
             empty. Check the address and that the RPC is on the right network",
            contract, chain_id
        ));
    }
    if bytes.len() == LATEST_WORDS * 32 {
        return Err(format!(
            "{} answered latest() with {} bytes, which is what the chain-hash ExchangeAnchor \
             returns, not the {} an ExchangeRootAnchor returns. Both contracts declare latest(), \
             so both answer the same selector. That address holds the closed contract, whose \
             anchors commit a hash chain and are read with --anchor-contract",
            contract,
            bytes.len(),
            ROOT_LATEST_WORDS * 32
        ));
    }
    if bytes.len() != ROOT_LATEST_WORDS * 32 {
        return Err(format!(
            "{} answered latest() with {} bytes, not the {} an ExchangeRootAnchor returns: \
             whatever is deployed there, it is not the root anchor contract",
            contract,
            bytes.len(),
            ROOT_LATEST_WORDS * 32
        ));
    }

    let index = word_u64(&bytes[192..224]);
    if index == 0 {
        return Err(format!(
            "{} on chain {} holds no anchors yet: nothing has been committed to it, so there is \
             nothing for this audit to check against",
            contract, chain_id
        ));
    }

    Ok(RootAnchor {
        tree_size: word_u64(&bytes[0..32]),
        last_id: word_u64(&bytes[32..64]),
        // A `bytes8` sits at the start of its 32-byte word. The sequencer
        // names its log with exactly these 8 bytes, or 16 hex characters.
        session: crate::logchain::to_hex(&bytes[64..72]),
        root: word_32(&bytes[96..128]),
        state_root: word_32(&bytes[128..160]),
        anchored_at: word_u64(&bytes[160..192]),
        block_number: 0,
        index,
    })
}

/// Turns one `AnchoredRoot` event into an anchor. Two values sit in the topics
/// and five fixed-width values sit in its data. Nothing has a variable width.
fn decode_root_event(log: &RawLog, block_number: u64) -> Result<RootAnchor, String> {
    if log.topics.len() != 3 {
        return Err(format!(
            "an anchor log in block {} carries {} topics, not the 3 an AnchoredRoot event has",
            block_number,
            log.topics.len()
        ));
    }
    let tree_size_topic = decode_hex(&log.topics[1])
        .filter(|b| b.len() == 32)
        .ok_or_else(|| format!("an anchor log in block {} has no tree size", block_number))?;
    let session_topic = decode_hex(&log.topics[2])
        .filter(|b| b.len() == 32)
        .ok_or_else(|| format!("an anchor log in block {} has no session", block_number))?;
    let data = decode_hex(&log.data)
        .filter(|b| b.len() == ROOT_EVENT_DATA_WORDS * 32)
        .ok_or_else(|| {
            format!(
                "an anchor log in block {} carries {} bytes of data, not the {} an AnchoredRoot \
                 event has",
                block_number,
                decode_hex(&log.data).map(|b| b.len()).unwrap_or(0),
                ROOT_EVENT_DATA_WORDS * 32
            )
        })?;

    Ok(RootAnchor {
        tree_size: word_u64(&tree_size_topic),
        session: crate::logchain::to_hex(&session_topic[0..8]),
        root: word_32(&data[0..32]),
        last_id: word_u64(&data[32..64]),
        state_root: word_32(&data[64..96]),
        anchored_at: word_u64(&data[96..128]),
        block_number,
        index: word_u64(&data[128..160]),
    })
}

// ---------------------------------------------------------------------------
// Checking an anchored root
// ---------------------------------------------------------------------------

/// The result of checking one anchored root. Three states, never two.
///
/// The middle state is the reason this is not a `bool`. A sequencer that is
/// down cannot serve a consistency proof. Reporting that as a pass would claim
/// the one thing the audit could not establish. Reporting it as a failure
/// would accuse an honest operator of rewinding the log every time their
/// computer restarts. `docs/ENGINE.md` section 6 states the same rule for the
/// same reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootCheck {
    /// The anchored root is the root of the history served today.
    Holds,
    /// The anchored root is not the root of the history served today, and the
    /// sentence names the two values that disagree.
    Fails(String),
    /// The check could not be made, and the sentence says why. Not a pass.
    NotChecked(String),
}

impl RootCheck {
    pub fn holds(&self) -> bool {
        matches!(self, RootCheck::Holds)
    }

    /// The sentence, for a report that prints one line for each anchor.
    pub fn reason(&self) -> Option<&str> {
        match self {
            RootCheck::Holds => None,
            RootCheck::Fails(reason) | RootCheck::NotChecked(reason) => Some(reason),
        }
    }
}

/// Checks one anchored root against a tree built over the messages the
/// sequencer serves today.
///
/// This is the check that catches a rewind, and it must always run. An
/// operator rewound the log to message 500, published different messages from
/// there, and ran on to 1500. Today's tree still reproduces the newest root in
/// the contract exactly. The anchor at 1000 is the one that does not: its root
/// covered the old messages, and building a tree over today's first 1000
/// messages gives another root. The block that carried that anchor says when
/// the operator committed to the other version.
///
/// `ours` is the root the tool computed over the served messages. It computes
/// that root in the same single pass that combines the chain hash and runs the
/// messages through the engine. The anchors name their sizes before the pass
/// starts, so the pass takes the root at each size as it goes past. A hundred
/// anchors then cost a hundred comparisons, not a hundred passes over the
/// history.
///
/// Nothing here reads what is inside a message. A leaf is the stored bytes and
/// a root is a hash of hashes. So this check works over a history that holds a
/// kind of message this build has never seen. That is `docs/ENGINE.md` section
/// 1.2, and it is why an anchor still means something after an upgrade.
pub fn check_root_by_folding(anchor: &RootAnchor, ours: &FoldedRoot) -> RootCheck {
    match ours.root {
        Some(ours) if ours == anchor.root => RootCheck::Holds,
        Some(ours) => RootCheck::Fails(format!(
            "anchor {} holds root {} over {} messages of session {}, written in block {}; this \
             feed's own messages produce {} over the same {}. The history served today is not the \
             history that was anchored",
            anchor.index,
            crate::logchain::to_hex(&anchor.root),
            anchor.tree_size,
            anchor.session,
            anchor.block_number,
            crate::logchain::to_hex(&ours),
            anchor.tree_size
        )),
        None => RootCheck::Fails(format!(
            "anchor {} commits to a root over {} messages of session {}, written in block {}; \
             this feed has served only {}. A history that stops short of what was anchored is a \
             history that lost the messages in between",
            anchor.index, anchor.tree_size, anchor.session, anchor.block_number, ours.served
        )),
    }
}

/// The root a tool computed over the served messages at one anchored size.
///
/// `None` means the history stopped short of that size, and that is not a
/// check that could not be made. The messages between the end of the history
/// and that size were published once, under a root the operator committed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoldedRoot {
    /// The root over the first `tree_size` messages the sequencer served.
    pub root: Option<Hash>,
    /// How many messages the sequencer served in all, for the sentence a
    /// short history produces.
    pub served: u64,
}

impl FoldedRoot {
    /// The root a `merkle::RootFold` took at `tree_size` while it walked the
    /// history. A `RootFold` holds only the few nodes it needs, not the whole
    /// tree.
    pub fn folded(fold: &merkle::RootFold, tree_size: u64) -> Self {
        FoldedRoot {
            root: fold.root_at(tree_size),
            served: fold.len(),
        }
    }

    /// The same root, out of a tree that kept every node. The tests here use
    /// this, and so would a caller holding a whole history in memory.
    pub fn of(tree: &MerkleTree, tree_size: u64) -> Self {
        FoldedRoot {
            root: tree.root_at(tree_size).ok(),
            served: tree.len(),
        }
    }
}

/// A signed tree head, as `GET /sth` serves it and as this module checks it. A
/// tree head is the sequencer's signed statement of one tree size and the root
/// over it.
///
/// Nothing builds one of these before the signature verifies. `fetch_tree_head`
/// is the only way to make one, and it refuses a head whose signature does not
/// verify. That is on purpose. A root from an unsigned head is a number the
/// sequencer never stood behind, and a consistency proof checked against such
/// a root always passes and proves nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeHead {
    pub session: String,
    pub timestamp: u64,
    pub tree_size: u64,
    pub root: Hash,
    pub public_key: String,
}

/// What `GET /sth` serves, before anything about it has been checked.
#[derive(serde::Deserialize)]
struct RawTreeHead {
    session: String,
    timestamp: u64,
    tree_size: u64,
    root_hash: String,
    public_key: String,
    signature: String,
}

/// What `GET /proof/consistency` serves.
#[derive(serde::Deserialize)]
struct RawConsistencyProof {
    first: u64,
    second: u64,
    consistency_path: Vec<String>,
}

/// Reads the sequencer's current signed tree head and verifies its Ed25519
/// signature before it returns the head.
///
/// The key comes from the same document as the signature. That is not circular
/// here, for the same reason it is not circular in the anchor sender. All this
/// establishes is that one key signed this pair of size and root. The pair is
/// then compared against roots the owner of that key wrote to the chain. A
/// caller that already holds the sequencer's key from `/claims` should compare
/// `public_key` against it. This function reports the key and does not choose
/// for the caller.
///
/// `client` belongs to the caller, so `/sth` is read with the same timeouts
/// and the same size limit as every other page the checker and the audit read.
/// See `fetch`.
pub async fn fetch_tree_head(client: &reqwest::Client, feed_url: &str) -> Result<TreeHead, String> {
    let url = format!("{}/sth", feed_url.trim_end_matches('/'));
    let raw: RawTreeHead = get_bounded_json(client, &url).await?;

    let root = crate::logchain::from_hex::<32>(&raw.root_hash).ok_or_else(|| {
        format!(
            "{} named root '{}', which is not 64 hex characters",
            url, raw.root_hash
        )
    })?;
    let key_bytes = crate::logchain::from_hex::<32>(&raw.public_key)
        .ok_or_else(|| format!("{} named no 32-byte hex public key", url))?;
    let signature_bytes = crate::logchain::from_hex::<64>(&raw.signature)
        .ok_or_else(|| format!("{} carried no 64-byte hex signature", url))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
        format!(
            "{} named a public key that is not a point on the curve",
            url
        )
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

    if !crate::logchain::verify_tree_head(
        &key,
        &raw.session,
        raw.timestamp,
        raw.tree_size,
        &root,
        &signature,
    ) {
        return Err(format!(
            "the tree head {} served does not verify under the key {} it names. Its root over {} \
             messages is a value nothing has signed, so nothing can be checked against it",
            url, raw.public_key, raw.tree_size
        ));
    }

    Ok(TreeHead {
        session: raw.session,
        timestamp: raw.timestamp,
        tree_size: raw.tree_size,
        root,
        public_key: raw.public_key,
    })
}

/// Checks one anchored root against the tree head the sequencer signs now. It
/// asks the sequencer for the consistency proof between the two tree sizes. A
/// consistency proof is a short list of node hashes that shows the smaller
/// tree is the start of the bigger one.
///
/// This says something that hashing the messages again cannot. Hashing says
/// "the bytes the sequencer served produce this root". A consistency proof that
/// verifies says the head this sequencer signs *this second* is an extension
/// of the root that was anchored. It says so under the sequencer's own key,
/// over a document the auditor did not choose. An operator who serves one
/// `/messages.ndjson` to the auditor and a different history to everybody else
/// still has one signing key and one current head.
///
/// The proof also costs about 17 hashes and one request for each different
/// anchored size, against one pass over the history for the hashing. So there
/// is no reason to pick between them. Both run.
///
/// A proof this cannot fetch is `NotChecked`, not a failure: a sequencer that
/// is down has rewritten nothing. A proof that does not verify *is* a failure,
/// and it is the strongest one here.
pub async fn check_root_by_consistency(
    feed_url: &str,
    anchor: &RootAnchor,
    head: &TreeHead,
) -> RootCheck {
    if let Some(verdict) = consistency_verdict(anchor, head) {
        return verdict;
    }

    let client = match feed_client() {
        Ok(client) => client,
        Err(reason) => return RootCheck::NotChecked(reason),
    };
    let url = format!(
        "{}/proof/consistency?first={}&second={}",
        feed_url.trim_end_matches('/'),
        anchor.tree_size,
        head.tree_size
    );
    let raw: RawConsistencyProof = match get_json(&client, &url).await {
        Ok(proof) => proof,
        Err(reason) => {
            return RootCheck::NotChecked(format!(
                "{}. Anchor {} was not checked against the head this feed signs now; the fold \
                 over its messages is what still checks it",
                reason, anchor.index
            ));
        }
    };
    if raw.first != anchor.tree_size || raw.second != head.tree_size {
        return RootCheck::NotChecked(format!(
            "asked {} for a consistency proof from {} to {} and was answered for {} to {}",
            url, anchor.tree_size, head.tree_size, raw.first, raw.second
        ));
    }

    let mut path: Vec<Hash> = Vec::with_capacity(raw.consistency_path.len());
    for (position, node) in raw.consistency_path.iter().enumerate() {
        match crate::logchain::from_hex::<32>(node) {
            Some(hash) => path.push(hash),
            None => {
                return RootCheck::NotChecked(format!(
                    "node {} of the consistency proof {} served is '{}', which is not 64 hex \
                     characters",
                    position, url, node
                ));
            }
        }
    }
    check_consistency_path(anchor, head, &path)
}

/// The part of the check above that needs no network. The anchored size and
/// the signed size settle the question on their own in three cases.
///
/// `None` means `anchor.tree_size < head.tree_size`. That is the ordinary
/// case, and the only one that needs a proof fetched. This is a separate
/// function so a test can check the three answers, and the sentence each one
/// carries, with no sequencer to serve them.
fn consistency_verdict(anchor: &RootAnchor, head: &TreeHead) -> Option<RootCheck> {
    if head.session != anchor.session {
        return Some(RootCheck::Fails(format!(
            "anchor {} commits to a root of feed session {} over {} messages, written in block \
             {}; this feed is signing session {}. The history the anchor names has been replaced, \
             which is exactly the event an anchor exists to expose",
            anchor.index, anchor.session, anchor.tree_size, anchor.block_number, head.session
        )));
    }
    if head.tree_size < anchor.tree_size {
        return Some(RootCheck::Fails(format!(
            "anchor {} commits to a root over {} messages of session {}, written in block {}; the \
             tree head this feed signs now holds {}. A log that has shrunk past a size it \
             committed to has lost entries",
            anchor.index, anchor.tree_size, anchor.session, anchor.block_number, head.tree_size
        )));
    }
    if head.tree_size == anchor.tree_size {
        // Nothing to prove, and nothing to fetch: one size has one root.
        return Some(if head.root == anchor.root {
            RootCheck::Holds
        } else {
            RootCheck::Fails(format!(
                "anchor {} holds root {} over {} messages of session {}, written in block {}; \
                 this feed signs {} over the same {}. The entries under that root have been \
                 rewritten",
                anchor.index,
                crate::logchain::to_hex(&anchor.root),
                anchor.tree_size,
                anchor.session,
                anchor.block_number,
                crate::logchain::to_hex(&head.root),
                head.tree_size
            ))
        });
    }
    None
}

/// The RFC 9162 consistency check itself, over a path that is already decoded.
fn check_consistency_path(anchor: &RootAnchor, head: &TreeHead, path: &[Hash]) -> RootCheck {
    if merkle::verify_consistency(
        anchor.tree_size,
        head.tree_size,
        &anchor.root,
        &head.root,
        path,
    ) {
        RootCheck::Holds
    } else {
        RootCheck::Fails(format!(
            "anchor {} holds root {} over {} messages of session {}, written in block {}; this \
             feed's own proof does not show that tree is a prefix of the {} messages under root \
             {} it is signing now. Entries this contract committed to have been changed, removed \
             or reordered",
            anchor.index,
            crate::logchain::to_hex(&anchor.root),
            anchor.tree_size,
            anchor.session,
            anchor.block_number,
            head.tree_size,
            crate::logchain::to_hex(&head.root)
        ))
    }
}

fn feed_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(RPC_CONNECT_TIMEOUT)
        .timeout(FEED_TIMEOUT)
        .build()
        .map_err(|e| format!("cannot build an HTTP client for the feed: {}", e))
}

/// The same as `get_json`, but it counts the bytes of the body as they arrive.
///
/// The sequencer belongs to the operator, and the operator is the party this
/// tool checks. The operator can make the body as long as they like, so it
/// must be read against a limit. That is what `fetch::read_bounded` is for,
/// and the checker already reads `/head` and every page of messages with it.
async fn get_bounded_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("cannot reach {}: {}", url, crate::fetch::reason(&e)))?;
    let status = response.status();
    let body = crate::fetch::read_bounded(response, "a signed tree head", MAX_PAGE_BYTES).await?;
    if !status.is_success() {
        let detail = String::from_utf8_lossy(&body).trim().to_string();
        return Err(format!(
            "{} answered {}: {}",
            url,
            status,
            detail.chars().take(200).collect::<String>()
        ));
    }
    serde_json::from_slice(&body).map_err(|e| format!("cannot read what {} served: {}", url, e))
}

async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, String> {
    let response = client
        .get(url)
        .header("user-agent", "verifiable-exchange-audit/1")
        .send()
        .await
        .map_err(|e| format!("cannot reach {}: {}", url, e))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("cannot read what {} answered: {}", url, e))?;
    if !status.is_success() {
        return Err(format!(
            "{} answered {}: {}",
            url,
            status,
            body.trim().chars().take(200).collect::<String>()
        ));
    }
    serde_json::from_str(&body).map_err(|e| format!("cannot read what {} served: {}", url, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real answer this contract gave on Base Sepolia. It is kept here so
    /// a test checks the decoding against a real answer from a chain, and not
    /// against another copy of the same arithmetic.
    const LIVE_LATEST: &str = concat!(
        "0x",
        "00000000000000000000000000000000000000000000000000000000000035ce",
        "349d462ced25bb2b000000000000000000000000000000000000000000000000",
        "4ff5480c5206432d6d8ed85b85663a27bca845aeda5343423477be4abe734aeb",
        "c49245c028768cd7f1d65bf3a3bb82b6549bd43dc1df492654e002d14bbbd75c",
        "000000000000000000000000000000000000000000000000000000006a7fc5a4",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );

    /// The `Anchored` event that same write emitted, as `eth_getLogs` served
    /// it. The anchor decoded from the log and the anchor decoded from the
    /// contract's stored state must agree. The test below says so.
    fn live_log() -> RawLog {
        RawLog {
            topics: vec![
                DEFAULT_ANCHORED_TOPIC.to_string(),
                "0x00000000000000000000000000000000000000000000000000000000000035ce".to_string(),
                "0x349d462ced25bb2b000000000000000000000000000000000000000000000000".to_string(),
            ],
            data: concat!(
                "0x",
                "4ff5480c5206432d6d8ed85b85663a27bca845aeda5343423477be4abe734aeb",
                "c49245c028768cd7f1d65bf3a3bb82b6549bd43dc1df492654e002d14bbbd75c",
                "000000000000000000000000000000000000000000000000000000006a7fc5a4",
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .to_string(),
            block_number: "0x2b636e2".to_string(),
        }
    }

    #[test]
    fn a_real_answer_decodes_to_the_tuple_that_was_written() {
        let anchor = decode_latest(LIVE_LATEST, "0x2a4a", 84532).expect("decodes");
        assert_eq!(anchor.last_id, 13774);
        assert_eq!(anchor.session, "349d462ced25bb2b");
        assert_eq!(
            crate::logchain::to_hex(&anchor.chain),
            "4ff5480c5206432d6d8ed85b85663a27bca845aeda5343423477be4abe734aeb"
        );
        assert_eq!(
            crate::logchain::to_hex(&anchor.state_root),
            "c49245c028768cd7f1d65bf3a3bb82b6549bd43dc1df492654e002d14bbbd75c"
        );
        assert_eq!(anchor.anchored_at, 1786758564);
        assert_eq!(anchor.index, 1);
    }

    /// The stored state and the log entry are one write in two forms. An audit
    /// that read the two differently would compare an anchor against itself.
    #[test]
    fn the_event_and_the_state_decode_to_the_same_anchor() {
        let from_state = decode_latest(LIVE_LATEST, "0x2a4a", 84532).expect("state");
        let from_log = decode_event(&live_log(), 45495010).expect("log");
        assert_eq!(from_log.last_id, from_state.last_id);
        assert_eq!(from_log.session, from_state.session);
        assert_eq!(from_log.chain, from_state.chain);
        assert_eq!(from_log.state_root, from_state.state_root);
        assert_eq!(from_log.anchored_at, from_state.anchored_at);
        assert_eq!(from_log.index, from_state.index);
        assert_eq!(from_log.block_number, 45495010);
    }

    /// The three ways an address can be wrong. Each one used to be easy to
    /// report as "nothing anchored yet". That is the one sentence this must
    /// never print, because a reader takes it for an audit that passed.
    #[test]
    fn a_wrong_address_is_never_reported_as_an_empty_anchor() {
        let no_code = decode_latest("0x", "0xdead", 84532).expect_err("no contract");
        assert!(no_code.contains("no contract at"), "{}", no_code);

        let other_contract = decode_latest(&format!("0x{}", "11".repeat(32)), "0xdead", 84532)
            .expect_err("wrong width");
        assert!(
            other_contract.contains("not the anchor contract"),
            "{}",
            other_contract
        );

        let not_hex = decode_latest("0xzz", "0xdead", 84532).expect_err("not hex");
        assert!(not_hex.contains("not hex"), "{}", not_hex);
    }

    /// A contract that is deployed but never written to has to be told apart
    /// from a contract that agrees with the exchange.
    #[test]
    fn a_contract_with_no_anchors_yet_is_not_a_passing_check() {
        let empty = format!("0x{}", "00".repeat(192));
        let reason = decode_latest(&empty, "0xdead", 84532).expect_err("no anchors");
        assert!(reason.contains("holds no anchors yet"), "{}", reason);
    }

    /// A log entry that is not an `Anchored` event must not decode into an
    /// anchor full of zeros that look like real values.
    #[test]
    fn a_log_of_the_wrong_shape_is_refused() {
        let mut short = live_log();
        short.data = "0x1234".to_string();
        assert!(decode_event(&short, 1).is_err());

        let mut topics = live_log();
        topics.topics.pop();
        assert!(decode_event(&topics, 1).is_err());
    }

    /// A contract address the tests below build a source around. Which address
    /// it is does not matter to any of them, because none of them send a
    /// request.
    const SOME_CONTRACT: &str = "0x2A4A287EC1F01b5bCb5568D2Ed0765Faf860a62b";

    /// The two values are written out here, not referred to. So an edit to
    /// either constant fails this test instead of becoming the new default
    /// without anybody noticing. `anchor/anchor_test.go` computes the same two
    /// values with a real Keccak, from the signatures the deployed contract
    /// was compiled from.
    #[test]
    fn the_defaults_are_the_deployed_contracts_values() {
        assert_eq!(DEFAULT_LATEST_SELECTOR, "0x52bfe789");
        assert_eq!(
            DEFAULT_ANCHORED_TOPIC,
            "0x846b388d9a84109263340756e41099d4945f475c34c4f401faf0850b7c6d8385"
        );

        // Setting nothing has to produce exactly those two values, because
        // that is what a stranger who runs --audit-url with no flags gets.
        let nothing_set = AnchorAbi::resolve(None, None, None, None).expect("no override");
        assert_eq!(nothing_set, AnchorAbi::default());
        assert_eq!(nothing_set.anchored_topic, DEFAULT_ANCHORED_TOPIC);
        assert_eq!(nothing_set.latest_selector, DEFAULT_LATEST_SELECTOR);
        assert!(
            nothing_set.warnings().is_empty(),
            "an audit that overrides nothing has nothing to warn about"
        );
    }

    /// Every shape a mistyped value can have. Each one is refused, and each
    /// message names the flag. A value that is nearly right is the reason this
    /// checking exists: it matches no logs at all, and no logs reads as a
    /// contract that holds no anchors.
    #[test]
    fn a_malformed_topic_or_selector_is_refused_by_name() {
        let topic_body = DEFAULT_ANCHORED_TOPIC.trim_start_matches("0x");
        let bad_topics = [
            ("too short", format!("0x{}", &topic_body[..62])),
            ("too long", format!("0x{}ab", topic_body)),
            ("not hex", format!("0x{}", "z".repeat(64))),
            (
                "uppercase",
                format!("0x{}", topic_body.to_ascii_uppercase()),
            ),
            ("no 0x", topic_body.to_string()),
        ];
        for (shape, bad) in &bad_topics {
            let flagged = AnchorAbi::resolve(Some(bad), None, None, None)
                .expect_err(&format!("a {} topic was accepted", shape));
            assert!(
                flagged.contains("--anchored-topic") && flagged.contains(bad),
                "{}: {}",
                shape,
                flagged
            );
            // The same value from the environment is refused the same way,
            // and the message still names the flag it belongs to.
            let from_env = AnchorAbi::resolve(None, Some(bad), None, None).expect_err(&format!(
                "a {} topic was accepted from the environment",
                shape
            ));
            assert!(
                from_env.contains("ANCHORED_TOPIC") && from_env.contains("--anchored-topic"),
                "{}: {}",
                shape,
                from_env
            );
        }

        let selector_body = DEFAULT_LATEST_SELECTOR.trim_start_matches("0x");
        let bad_selectors = [
            ("too short", format!("0x{}", &selector_body[..6])),
            ("too long", format!("0x{}ab", selector_body)),
            ("not hex", "0xzzzzzzzz".to_string()),
            (
                "uppercase",
                format!("0x{}", selector_body.to_ascii_uppercase()),
            ),
            ("no 0x", selector_body.to_string()),
        ];
        for (shape, bad) in &bad_selectors {
            let flagged = AnchorAbi::resolve(None, None, Some(bad), None)
                .expect_err(&format!("a {} selector was accepted", shape));
            assert!(
                flagged.contains("--latest-selector") && flagged.contains(bad),
                "{}: {}",
                shape,
                flagged
            );
            let from_env = AnchorAbi::resolve(None, None, None, Some(bad)).expect_err(&format!(
                "a {} selector was accepted from the environment",
                shape
            ));
            assert!(
                from_env.contains("LATEST_SELECTOR") && from_env.contains("--latest-selector"),
                "{}: {}",
                shape,
                from_env
            );
        }
    }

    /// The flag, then the environment variable, then the built-in default.
    #[test]
    fn a_flag_beats_the_environment_and_the_environment_beats_the_default() {
        let topic_flag = format!("0x{}", "11".repeat(32));
        let topic_env = format!("0x{}", "22".repeat(32));
        let selector_flag = "0xaabbccdd";
        let selector_env = "0x11223344";

        let both = AnchorAbi::resolve(
            Some(&topic_flag),
            Some(&topic_env),
            Some(selector_flag),
            Some(selector_env),
        )
        .expect("both are well formed");
        assert_eq!(both.anchored_topic, topic_flag);
        assert_eq!(both.latest_selector, selector_flag);

        let environment = AnchorAbi::resolve(None, Some(&topic_env), None, Some(selector_env))
            .expect("both are well formed");
        assert_eq!(environment.anchored_topic, topic_env);
        assert_eq!(environment.latest_selector, selector_env);

        let neither = AnchorAbi::resolve(None, None, None, None).expect("no override");
        assert_eq!(neither.anchored_topic, DEFAULT_ANCHORED_TOPIC);
        assert_eq!(neither.latest_selector, DEFAULT_LATEST_SELECTOR);
    }

    /// A value the auditor set has to reach both requests. A value that is
    /// read, checked, and then not used would pass every test above and read
    /// the wrong contract.
    #[test]
    fn an_override_reaches_the_requests_that_get_built() {
        let topic = format!("0x{}", "11".repeat(32));
        let selector = "0xaabbccdd";
        let abi =
            AnchorAbi::resolve(Some(&topic), None, Some(selector), None).expect("well formed");
        let source = AnchorSource::new("http://rpc", SOME_CONTRACT, None)
            .expect("a real address")
            .with_abi(abi);

        assert_eq!(
            latest_call_params(&source.contract, &source.abi.latest_selector)[0]["data"],
            selector
        );
        let logs = logs_params(&source.contract, &source.abi.anchored_topic, 1, 300);
        assert_eq!(logs[0]["topics"][0], topic);
        assert_eq!(logs[0]["fromBlock"], "0x1");
        assert_eq!(logs[0]["toBlock"], "0x12c");

        // And a source nobody changed reads the deployed contract.
        let plain = AnchorSource::new("http://rpc", SOME_CONTRACT, None).expect("a real address");
        assert_eq!(
            latest_call_params(&plain.contract, &plain.abi.latest_selector)[0]["data"],
            DEFAULT_LATEST_SELECTOR
        );
        assert_eq!(
            logs_params(&plain.contract, &plain.abi.anchored_topic, 1, 2)[0]["topics"][0],
            DEFAULT_ANCHORED_TOPIC
        );

        // The root source holds a different pair of values. Pointing one
        // source at the other's topic is the mistake that reads as "no
        // anchors".
        let root =
            RootAnchorSource::new("http://rpc", SOME_CONTRACT, None).expect("a real address");
        assert_eq!(
            logs_params(&root.contract, &root.abi.anchored_topic, 1, 2)[0]["topics"][0],
            DEFAULT_ROOT_ANCHORED_TOPIC
        );
        assert_ne!(DEFAULT_ROOT_ANCHORED_TOPIC, DEFAULT_ANCHORED_TOPIC);
    }

    /// A value that is well formed and wrong is the case checking cannot
    /// catch, so the audit prints a warning about it instead.
    #[test]
    fn an_override_is_reported_before_the_audit_runs() {
        let topic = format!("0x{}", "11".repeat(32));
        let abi = AnchorAbi::resolve(Some(&topic), None, Some("0xaabbccdd"), None).expect("valid");
        let warnings = abi.warnings();
        assert_eq!(warnings.len(), 2, "{:?}", warnings);
        assert!(warnings[0].contains(&topic), "{}", warnings[0]);
        assert!(warnings[0].contains("no anchors"), "{}", warnings[0]);
        assert!(warnings[1].contains("0xaabbccdd"), "{}", warnings[1]);

        // A change to one value warns about that value only, not both.
        let only_topic = AnchorAbi::resolve(Some(&topic), None, None, None).expect("valid");
        assert_eq!(only_topic.warnings().len(), 1);
    }

    #[test]
    fn an_address_is_checked_before_any_request_is_made() {
        assert!(AnchorSource::new("http://rpc", "not-an-address", None).is_err());
        assert!(AnchorSource::new("http://rpc", "0x1234", None).is_err());
        let good = AnchorSource::new(
            " https://sepolia.base.org ",
            "0x2A4A287EC1F01b5bCb5568D2Ed0765Faf860a62b",
            Some(45495043),
        )
        .expect("a real address");
        assert_eq!(good.rpc, "https://sepolia.base.org");
        assert_eq!(good.contract, "0x2a4a287ec1f01b5bcb5568d2ed0765faf860a62b");
        assert_eq!(good.from_block, Some(45495043));
    }

    #[test]
    fn quantities_and_positions_read_the_way_json_rpc_writes_them() {
        assert_eq!(decode_quantity("0x2b636e2"), Some(45496034));
        assert_eq!(decode_quantity("0x0"), Some(0));
        assert_eq!(decode_quantity("nonsense"), None);

        let history = AnchorHistory {
            contract: "0xdead".to_string(),
            chain_id: 84532,
            anchors: vec![
                decode_event(&live_log(), 10).expect("log"),
                decode_event(&live_log(), 11).expect("log"),
            ],
            latest: decode_latest(LIVE_LATEST, "0xdead", 84532).expect("state"),
            total: 2,
            scanned_from: 1,
            complete: true,
            latest_agrees: true,
        };
        assert_eq!(history.positions(), vec![13774], "duplicates collapse");
    }

    // -----------------------------------------------------------------------
    // The root anchor
    // -----------------------------------------------------------------------

    /// The real answer `ExchangeRootAnchor` gave on Base Sepolia after its
    /// second anchor. It is kept here so a test checks the decoding against a
    /// real answer from a chain, and not against another copy of the same
    /// arithmetic.
    ///
    /// Seven 32-byte words: treeSize, lastId, session, rootHash, stateRoot,
    /// anchoredAt, count. The chain-hash contract answers with six words, so
    /// the width of the answer is what tells the two contracts apart.
    const LIVE_ROOT_LATEST: &str = concat!(
        "0x",
        "0000000000000000000000000000000000000000000000000000000000019e78",
        "0000000000000000000000000000000000000000000000000000000000019e76",
        "349d462ced25bb2b000000000000000000000000000000000000000000000000",
        "836150d32cf90b2582016725d47099141ef0d2d1c61db3586a722dd5b4d7f242",
        "2731a6150985524269109d32791f6f29708ea372e9d50f51b497e9b1e84b1e25",
        "000000000000000000000000000000000000000000000000000000006a806838",
        "0000000000000000000000000000000000000000000000000000000000000002",
    );

    /// The `AnchoredRoot` event that same write emitted, as `eth_getLogs`
    /// served it.
    fn live_root_log() -> RawLog {
        RawLog {
            topics: vec![
                DEFAULT_ROOT_ANCHORED_TOPIC.to_string(),
                "0x0000000000000000000000000000000000000000000000000000000000019e78".to_string(),
                "0x349d462ced25bb2b000000000000000000000000000000000000000000000000".to_string(),
            ],
            data: concat!(
                "0x",
                "836150d32cf90b2582016725d47099141ef0d2d1c61db3586a722dd5b4d7f242",
                "0000000000000000000000000000000000000000000000000000000000019e76",
                "2731a6150985524269109d32791f6f29708ea372e9d50f51b497e9b1e84b1e25",
                "000000000000000000000000000000000000000000000000000000006a806838",
                "0000000000000000000000000000000000000000000000000000000000000002",
            )
            .to_string(),
            block_number: "0x2b684ac".to_string(),
        }
    }

    #[test]
    fn a_real_root_answer_decodes_to_the_tuple_that_was_written() {
        let anchor = decode_root_latest(LIVE_ROOT_LATEST, "0xce85", 84532).expect("decodes");
        assert_eq!(anchor.tree_size, 106104);
        assert_eq!(anchor.last_id, 106102);
        assert_eq!(anchor.session, "349d462ced25bb2b");
        assert_eq!(
            crate::logchain::to_hex(&anchor.root),
            "836150d32cf90b2582016725d47099141ef0d2d1c61db3586a722dd5b4d7f242"
        );
        assert_eq!(
            crate::logchain::to_hex(&anchor.state_root),
            "2731a6150985524269109d32791f6f29708ea372e9d50f51b497e9b1e84b1e25"
        );
        assert_eq!(anchor.anchored_at, 1786800184);
        assert_eq!(anchor.index, 2);
        // The contract refuses a write where this is false. A reader must
        // still check it: a `last_id` past the tree size would be a claim
        // about messages the anchored root does not cover.
        assert!(anchor.last_id <= anchor.tree_size);
    }

    #[test]
    fn the_root_event_and_the_root_state_decode_to_the_same_anchor() {
        let from_state = decode_root_latest(LIVE_ROOT_LATEST, "0xce85", 84532).expect("state");
        let from_log = decode_root_event(&live_root_log(), 45_515_948).expect("log");
        assert_eq!(from_log.tree_size, from_state.tree_size);
        assert_eq!(from_log.last_id, from_state.last_id);
        assert_eq!(from_log.session, from_state.session);
        assert_eq!(from_log.root, from_state.root);
        assert_eq!(from_log.state_root, from_state.state_root);
        assert_eq!(from_log.anchored_at, from_state.anchored_at);
        assert_eq!(from_log.index, from_state.index);
        assert_eq!(from_log.block_number, 45_515_948);
    }

    /// Both contracts declare `latest()`, so both answer the same selector.
    /// The chain-hash contract answers with six 32-byte words and the root
    /// contract answers with seven. A reader that meets the wrong width has to
    /// say which contract it found, and must not slice six words as seven.
    #[test]
    fn the_root_reader_names_the_chain_contract_rather_than_decoding_it() {
        let met_the_old_one =
            decode_root_latest(LIVE_LATEST, "0x2a4a", 84532).expect_err("192 bytes");
        assert!(
            met_the_old_one.contains("chain-hash ExchangeAnchor")
                && met_the_old_one.contains("--anchor-contract"),
            "{}",
            met_the_old_one
        );

        // And the other way round: the chain reader meets the root contract.
        // Both readers have to name the contract they found. An auditor who
        // holds two addresses will one day pass them to the wrong flag, and
        // "not the anchor contract" alone does not say which flag to move the
        // address to.
        let met_the_new_one =
            decode_latest(LIVE_ROOT_LATEST, "0xce85", 84532).expect_err("224 bytes");
        assert!(
            met_the_new_one.contains("ExchangeRootAnchor")
                && met_the_new_one.contains("--root-anchor-contract"),
            "{}",
            met_the_new_one
        );
        // A width that is neither 192 nor 224 bytes is refused, not decoded.
        let neither = decode_latest(&format!("0x{}", "11".repeat(32)), "0xdead", 84532)
            .expect_err("wrong width");
        assert!(neither.contains("not the anchor contract"), "{}", neither);

        // The three ways an address can be wrong. None of them may be
        // reported as "nothing anchored yet".
        assert!(
            decode_root_latest("0x", "0xdead", 84532)
                .expect_err("no contract")
                .contains("no contract at")
        );
        assert!(
            decode_root_latest(&format!("0x{}", "00".repeat(224)), "0xdead", 84532)
                .expect_err("no anchors")
                .contains("holds no anchors yet")
        );
        assert!(
            decode_root_latest("0xzz", "0xdead", 84532)
                .expect_err("not hex")
                .contains("not hex")
        );
    }

    #[test]
    fn a_root_log_of_the_wrong_shape_is_refused() {
        let mut short = live_root_log();
        short.data = "0x1234".to_string();
        assert!(decode_root_event(&short, 1).is_err());

        let mut topics = live_root_log();
        topics.topics.pop();
        assert!(decode_root_event(&topics, 1).is_err());

        // A chain anchor's event carries four data words where five belong.
        // The topic filter already keeps this out of a real scan. The width
        // check keeps it out if the filter is ever wrong.
        assert!(decode_root_event(&live_log(), 1).is_err());
    }

    /// The two values are written out here, not referred to. So an edit to
    /// either constant fails this test instead of becoming the new default
    /// without anybody noticing. `anchor/anchor_test.go` computes all four
    /// values with a real Keccak, from the signatures the two deployed
    /// contracts were compiled from.
    #[test]
    fn the_root_defaults_are_the_deployed_root_contracts_values() {
        assert_eq!(DEFAULT_ROOT_LATEST_SELECTOR, "0x52bfe789");
        assert_eq!(
            DEFAULT_ROOT_ANCHORED_TOPIC,
            "0xf17e064140470b4f4b89eb3a9324a477206c096df6cbc3dfed400e9b4a2c191f"
        );
        // The topic is the whole difference between reading root anchors and
        // reading chain anchors. Two equal topics would mean one filter
        // returned both kinds, and the decoder chose which one to believe.
        assert_ne!(DEFAULT_ROOT_ANCHORED_TOPIC, DEFAULT_ANCHORED_TOPIC);
        // The two selectors are equal. That is how Ethereum works, not a
        // mistake: a selector covers a function's name and its arguments only.
        // It is stated here so nobody "fixes" it.
        assert_eq!(DEFAULT_ROOT_LATEST_SELECTOR, DEFAULT_LATEST_SELECTOR);

        let nothing_set = RootAnchorAbi::resolve(None, None, None, None).expect("no override");
        assert_eq!(nothing_set, RootAnchorAbi::default());
        assert!(nothing_set.warnings().is_empty());

        let bad = format!("0x{}", "z".repeat(64));
        let refused = RootAnchorAbi::resolve(Some(&bad), None, None, None).expect_err("not hex");
        assert!(refused.contains("--root-anchored-topic"), "{}", refused);
    }

    // -----------------------------------------------------------------------
    // Checking an anchored root
    // -----------------------------------------------------------------------

    /// A history as the sequencer serves it: `count` messages, each one the
    /// bytes of one line of `/messages.ndjson`. Nothing here reads what is
    /// inside a message, and that is the point: a leaf is bytes.
    fn served_history(count: u64) -> Vec<Vec<u8>> {
        (1..=count)
            .map(|id| format!("{{\"New\":{{\"id\":{},\"price\":100.0}}}}", id).into_bytes())
            .collect()
    }

    /// The anchor an honest anchor sender would have written over the first
    /// `tree_size` of those messages. The root here is built from a whole
    /// tree, the long way. So a test that passes says the check agrees with
    /// RFC 9162, and not with itself.
    fn root_anchor_over(history: &[Vec<u8>], tree_size: u64, index: u64) -> RootAnchor {
        let tree = MerkleTree::from_entries(&history[..tree_size as usize]);
        RootAnchor {
            tree_size,
            last_id: tree_size,
            session: "349d462ced25bb2b".to_string(),
            root: tree.root(),
            state_root: [7u8; 32],
            anchored_at: 1_786_800_184,
            block_number: 45_515_000 + index,
            index,
        }
    }

    #[test]
    fn folding_the_messages_reproduces_an_honest_anchored_root() {
        let history = served_history(50);
        let tree = MerkleTree::from_entries(&history);
        for (index, size) in [1u64, 2, 3, 17, 32, 49, 50].iter().enumerate() {
            let anchor = root_anchor_over(&history, *size, index as u64 + 1);
            assert_eq!(
                check_root_by_folding(&anchor, &FoldedRoot::of(&tree, *size)),
                RootCheck::Holds,
                "an honest anchor over {} messages",
                size
            );
        }
    }

    /// The attack this whole module exists for. An operator rewinds the log to
    /// message 20, publishes different messages from there, runs on to 50, and
    /// writes a new anchor. The new history matches that newest anchor
    /// exactly, so a check of that anchor alone finds nothing. The anchor at
    /// 20 is the one that does not match.
    #[test]
    fn a_rewritten_history_fails_against_its_older_anchors_and_names_them() {
        let honest = served_history(50);
        let old_at_20 = root_anchor_over(&honest, 20, 3);
        let old_at_50 = root_anchor_over(&honest, 50, 4);

        let mut rewritten = honest.clone();
        rewritten[19] = b"{\"New\":{\"id\":20,\"price\":1.0}}".to_vec();
        let rewritten_tree = MerkleTree::from_entries(&rewritten);

        // The operator anchors the new history again at 50. That entry holds.
        let new_at_50 = root_anchor_over(&rewritten, 50, 5);
        assert_eq!(
            check_root_by_folding(&new_at_50, &FoldedRoot::of(&rewritten_tree, 50)),
            RootCheck::Holds,
            "the newest anchor of a rewritten history reproduces: that is why every anchor is read"
        );

        // Both older anchors contradict the new history. Each failure names
        // the anchor, its block, and the two roots.
        for old in [&old_at_20, &old_at_50] {
            match check_root_by_folding(old, &FoldedRoot::of(&rewritten_tree, old.tree_size)) {
                RootCheck::Fails(reason) => {
                    assert!(
                        reason.contains(&format!("anchor {}", old.index))
                            && reason.contains(&crate::logchain::to_hex(&old.root))
                            && reason.contains(&old.block_number.to_string()),
                        "{}",
                        reason
                    );
                }
                other => panic!(
                    "a rewritten history passed anchor {}: {:?}",
                    old.index, other
                ),
            }
        }
    }

    /// A history that stops short of an anchored size is a failure, not a
    /// check that could not be made. The messages between the end of that
    /// history and the anchored size were published once, under a root the
    /// operator committed to.
    #[test]
    fn a_history_that_stops_short_of_an_anchor_fails() {
        let history = served_history(50);
        let anchor = root_anchor_over(&history, 50, 1);
        let short = MerkleTree::from_entries(&history[..30]);
        match check_root_by_folding(&anchor, &FoldedRoot::of(&short, anchor.tree_size)) {
            RootCheck::Fails(reason) => {
                assert!(reason.contains("served only 30"), "{}", reason);
            }
            other => panic!("a short history passed: {:?}", other),
        }
    }

    /// The tree head a sequencer serving `history` would sign right now.
    fn head_over(history: &[Vec<u8>], session: &str) -> TreeHead {
        let tree = MerkleTree::from_entries(history);
        TreeHead {
            session: session.to_string(),
            timestamp: 1_786_800_184_000,
            tree_size: tree.len(),
            root: tree.root(),
            public_key: "89fd513e0711ca1522daa2be3953d3f49bed801b7484d53c4559ab3bea46c221"
                .to_string(),
        }
    }

    /// The second way an anchored root is checked, and the one that hashing
    /// the messages again cannot do. The head this sequencer signs *now* is an
    /// extension of what was anchored, and the sequencer itself proves that in
    /// about log2(n) hashes.
    #[test]
    fn a_consistency_proof_binds_an_anchored_root_to_the_head_signed_now() {
        let history = served_history(50);
        let head = head_over(&history, "349d462ced25bb2b");
        let tree = MerkleTree::from_entries(&history);

        for size in [1u64, 2, 20, 32, 49] {
            let anchor = root_anchor_over(&history, size, 1);
            let path = tree
                .consistency_proof(size, head.tree_size)
                .expect("the feed can prove it");
            assert_eq!(
                check_consistency_path(&anchor, &head, &path),
                RootCheck::Holds,
                "the proof from {} to {}",
                size,
                head.tree_size
            );
        }
    }

    /// A proof that does not verify is the strongest failure here. The
    /// sequencer's own key states that the tree it signs now is not an
    /// extension of the root the contract holds.
    #[test]
    fn a_consistency_proof_that_does_not_verify_names_the_fork() {
        let honest = served_history(50);
        let mut rewritten = honest.clone();
        rewritten[19] = b"{\"New\":{\"id\":20,\"price\":1.0}}".to_vec();

        let anchor = root_anchor_over(&honest, 20, 6);
        let forked_head = head_over(&rewritten, "349d462ced25bb2b");
        // The sequencer with the rewritten history proves a prefix of its own
        // tree. The proof is real, but the tree is the wrong one.
        let path = MerkleTree::from_entries(&rewritten)
            .consistency_proof(20, forked_head.tree_size)
            .expect("the forked feed proves its own tree");

        match check_consistency_path(&anchor, &forked_head, &path) {
            RootCheck::Fails(reason) => {
                assert!(
                    reason.contains("anchor 6")
                        && reason.contains("changed, removed or reordered")
                        && reason.contains(&crate::logchain::to_hex(&anchor.root)),
                    "{}",
                    reason
                );
            }
            other => panic!("a forked feed's proof was accepted: {:?}", other),
        }
    }

    /// The three answers that need no proof fetched, and the sentence each one
    /// carries. A sequencer that serves a smaller tree than one already
    /// anchored, or a different root at the same size, contradicts a block.
    #[test]
    fn the_verdicts_that_need_no_proof_are_settled_before_any_request() {
        let history = served_history(50);
        let anchor = root_anchor_over(&history, 40, 9);

        // Same size, same root: nothing to prove.
        let same = head_over(&history[..40], "349d462ced25bb2b");
        assert_eq!(consistency_verdict(&anchor, &same), Some(RootCheck::Holds));

        // Same size, another root.
        let mut rewritten = history.clone();
        rewritten[0] = b"different".to_vec();
        let other_root = head_over(&rewritten[..40], "349d462ced25bb2b");
        match consistency_verdict(&anchor, &other_root) {
            Some(RootCheck::Fails(reason)) => assert!(reason.contains("rewritten"), "{}", reason),
            other => panic!("another root at the anchored size passed: {:?}", other),
        }

        // A tree that has shrunk past what was anchored.
        let shrunk = head_over(&history[..30], "349d462ced25bb2b");
        match consistency_verdict(&anchor, &shrunk) {
            Some(RootCheck::Fails(reason)) => {
                assert!(reason.contains("lost entries"), "{}", reason)
            }
            other => panic!("a shrunken tree passed: {:?}", other),
        }

        // A different history altogether.
        let replaced = head_over(&history, "0123456789abcdef");
        match consistency_verdict(&anchor, &replaced) {
            Some(RootCheck::Fails(reason)) => {
                assert!(reason.contains("has been replaced"), "{}", reason)
            }
            other => panic!("a replaced history passed: {:?}", other),
        }

        // And the ordinary case, the only one that needs the sequencer.
        let ahead = head_over(&history, "349d462ced25bb2b");
        assert_eq!(consistency_verdict(&anchor, &ahead), None);
    }

    /// The two lists an audit has to take, and the two kinds of number that
    /// must not be confused. `tree_sizes` holds tree sizes. `positions` holds
    /// message numbers.
    #[test]
    fn a_root_history_reports_its_sizes_and_its_cursors_apart() {
        let latest = decode_root_latest(LIVE_ROOT_LATEST, "0xce85", 84532).expect("state");
        let history = RootAnchorHistory {
            contract: "0xce85983ce00cc964753410410c7ef3d24d1d995e".to_string(),
            chain_id: 84532,
            anchors: vec![
                decode_root_event(&live_root_log(), 45_515_948).expect("log"),
                decode_root_event(&live_root_log(), 45_515_949).expect("log"),
            ],
            latest,
            total: 2,
            scanned_from: 45_515_941,
            complete: true,
            latest_agrees: true,
        };
        assert_eq!(history.tree_sizes(), vec![106_104], "duplicates collapse");
        assert_eq!(history.positions(), vec![106_102]);
        assert_ne!(history.tree_sizes(), history.positions());
    }

    /// The whole root path against the real contract and the real sequencer:
    /// `eth_getLogs`, `latest()`, the tree head's signature, and a consistency
    /// proof for every anchor.
    ///
    /// This test is ignored, so `cargo test` stays offline and gives the same
    /// result every time. Run it by hand after deploying a contract, or after
    /// changing what the anchor sender writes:
    ///
    /// ```sh
    /// cargo test --lib anchor::tests::the_deployed_root_contract -- --ignored --nocapture
    /// ```
    ///
    /// Every check it makes is also made offline above, against fixtures taken
    /// from these same two writes. What this test adds is that a live endpoint
    /// answers the requests.
    #[tokio::test]
    #[ignore = "reads Base Sepolia and the live feed"]
    async fn the_deployed_root_contract_reads_and_its_anchors_hold() {
        const CONTRACT: &str = "0xCE85983ce00Cc964753410410c7EF3D24d1d995e";
        const DEPLOYED_IN: u64 = 45_515_433;
        const FEED: &str = "https://feed.exchange.th3nolo.com";

        let source = RootAnchorSource::new("https://sepolia.base.org", CONTRACT, Some(DEPLOYED_IN))
            .expect("a real address");
        let history = read_root_history(&source)
            .await
            .expect("the contract reads");
        assert!(history.complete, "the whole log was not read");
        assert!(
            history.latest_agrees,
            "the state and the newest event differ"
        );
        assert_eq!(history.anchors.len() as u64, history.total);
        assert!(history.total >= 2, "{} anchors", history.total);

        let client = crate::fetch::client().expect("an HTTP client");
        let head = fetch_tree_head(&client, FEED)
            .await
            .expect("the feed signs a head");
        for anchor in &history.anchors {
            assert_eq!(
                check_root_by_consistency(FEED, anchor, &head).await,
                RootCheck::Holds,
                "anchor {} over {} messages",
                anchor.index,
                anchor.tree_size
            );
        }
    }
}
