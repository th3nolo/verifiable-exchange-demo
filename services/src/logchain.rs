//! The signed hash chain over the sequencer's message log (V2 of the roadmap).
//!
//! The sequencer puts the messages in order and gives each one a number. This
//! file makes one hash that covers every message up to a point. That hash is
//! the chain. A reader below is any program that reads the log: the exchange,
//! a validator, the checker and the audit all read it.
//!
//! Every message extends a running SHA-256 chain:
//!
//! ```text
//! chain_0 = 0
//! chain_i = SHA-256(chain_{i-1} || canonical_bytes(message_i))
//! ```
//!
//! `canonical_bytes` turns a message the sequencer has just created into
//! bytes, and the sequencer is the only program that may turn a message into
//! bytes. The chain covers those bytes, not the struct behind them. So every
//! reader combines the bytes it received with `extend_bytes` instead.
//! `wire.rs` says why that difference decides whether a reader can be upgraded
//! on its own or must be rebuilt at the same moment as the sequencer.
//!
//! The sequencer then signs `(session, last_id, chain)` with an Ed25519 key. A
//! signature over a set of bytes proves two things: the holder of the key made
//! those exact bytes, and nobody changed a byte of them afterwards. So a
//! signed head at message N states the whole history 1..N. Change, drop or
//! reorder any earlier message and every chain value after it changes, and the
//! statement the sequencer signed no longer matches.
//!
//! What this buys, concretely:
//!
//! - a reader that computes the chain again from the messages it actually
//!   received can prove the sequencer's history is (or is not) the one the
//!   sequencer signed;
//! - two signed heads for the same `(session, last_id)` with different chains
//!   prove the sequencer served two different histories under one name. The
//!   proof is the sequencer's own signature on both heads;
//! - a submitter that holds a signed head at an id at or past their order's id
//!   holds a receipt: either the signed history contains their order, or the
//!   chain they compute from the public log shows that it does not.
//!
//! Signing does not stop the sequencer dropping a message. The sequencer can
//! still refuse a message before it gives it a number. Signing makes any
//! change to what *was* numbered detectable, which is the V2 step. Stopping
//! the sequencer dropping messages is V3.

use std::fs;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::domain::OrderMessage;
use crate::merkle::Hash;

/// One link value of the chain. The zero value is the chain of an empty log.
pub type Chain = [u8; 32];

/// The chain before any message.
pub const EMPTY_CHAIN: Chain = [0u8; 32];

/// The bytes of a message that are hashed into the chain: its JSON, exactly
/// as serde writes it.
///
/// **Making bytes and checking bytes are different jobs, and this function is
/// the making half.** Only the sequencer may call it, because only the
/// sequencer hashes a message it created itself. A reader that called it would
/// hash its own idea of the message instead of the message it was served.
/// serde writes the fields this build declares. A field or a message kind
/// added after this build was compiled comes back out missing, and the reader
/// computes a chain the sequencer never signed. The checking half is
/// `extend_bytes`, over the bytes that arrived. See `wire.rs`.
pub fn canonical_bytes(msg: &OrderMessage) -> Vec<u8> {
    serde_json::to_vec(msg).expect("feed messages serialize")
}

/// Extends the chain by the bytes of one message.
///
/// This function is what checking the chain is: a hash over the bytes that
/// arrived, with no opinion about what they mean. It is the only way a reader
/// may combine messages into a chain, and the reason a reader can check a
/// history that holds a message kind the reader cannot interpret.
pub fn extend_bytes(chain: &Chain, message_bytes: &[u8]) -> Chain {
    let mut hasher = Sha256::new();
    hasher.update(chain);
    hasher.update(message_bytes);
    hasher.finalize().into()
}

/// Extends the chain by one message the caller has in hand.
///
/// The making half again: this function turns the message into bytes itself,
/// so it is for the sequencer numbering a message it just created, and for
/// tests that stand in for the sequencer. A reader that holds bytes off the
/// wire uses `extend_bytes` instead.
pub fn extend(chain: &Chain, msg: &OrderMessage) -> Chain {
    extend_bytes(chain, &canonical_bytes(msg))
}

/// The statement a head signature covers. The signature covers these bytes in
/// this exact order, so the fixed first line keeps these signatures from ever
/// being valid as anything else the same key signs, and the session ties the
/// head to one sequencer history.
fn head_statement(session: &str, last_id: u64, chain: &Chain) -> Vec<u8> {
    format!(
        "exchange-feed-head-v1\n{}\n{}\n{}",
        session,
        last_id,
        to_hex(chain)
    )
    .into_bytes()
}

/// Signs the head of the log: "history `session`, after message `last_id`,
/// has chain `chain`."
pub fn sign_head(key: &SigningKey, session: &str, last_id: u64, chain: &Chain) -> Signature {
    key.sign(&head_statement(session, last_id, chain))
}

/// Checks a head signature. `verify_strict` refuses the odd signature values
/// that plain `verify` accepts, where more than one signature passes for one
/// set of bytes. Nothing here needs those values accepted.
pub fn verify_head(
    key: &VerifyingKey,
    session: &str,
    last_id: u64,
    chain: &Chain,
    signature: &Signature,
) -> bool {
    key.verify_strict(&head_statement(session, last_id, chain), signature)
        .is_ok()
}

/// The statement the checkpoint in `feed.db` covers: "history `session`, after
/// message `last_id`, has chain `chain`, and the tree over those same messages
/// has root `root`."
///
/// This statement never leaves the sequencer's own database, and no reader is
/// served one. It exists because the rows in `merkle_nodes` had nothing signed
/// to be checked against. The sequencer computes the root it signs
/// *from* those rows, so a row rewritten behind its back moves the root rather
/// than breaking any proof. The only thing that can catch that is a statement
/// made while the tree was still the tree the messages made. That is this one.
///
/// All four values are in one statement rather than the root alone, for the
/// reason every other statement here carries its session: a root signed on its
/// own could be lifted out of one history's checkpoint into another's, or out
/// of an earlier point in the same one, and would still pass the check.
///
/// The first line is `exchange-feed-checkpoint-v1`, and it differs from
/// `exchange-feed-head-v1` and `exchange-feed-sth-v1` for the reason those two
/// differ from each other.
fn checkpoint_statement(session: &str, last_id: u64, chain: &Chain, root: &Hash) -> Vec<u8> {
    format!(
        "exchange-feed-checkpoint-v1\n{}\n{}\n{}\n{}",
        session,
        last_id,
        to_hex(chain),
        to_hex(root)
    )
    .into_bytes()
}

/// Signs the checkpoint a publish writes: the chain head and the Merkle root
/// over the same messages, together.
pub fn sign_checkpoint(
    key: &SigningKey,
    session: &str,
    last_id: u64,
    chain: &Chain,
    root: &Hash,
) -> Signature {
    key.sign(&checkpoint_statement(session, last_id, chain, root))
}

/// Checks a stored checkpoint's signature over all four values.
pub fn verify_checkpoint(
    key: &VerifyingKey,
    session: &str,
    last_id: u64,
    chain: &Chain,
    root: &Hash,
    signature: &Signature,
) -> bool {
    key.verify_strict(
        &checkpoint_statement(session, last_id, chain, root),
        signature,
    )
    .is_ok()
}

/// The statement a signed tree head covers. A tree head says how many messages
/// the log held at one moment, and gives one hash over all of them.
///
/// The three fields after the session are the fields RFC 9162 calls
/// `TreeHeadDataV2`: `timestamp` in milliseconds, `tree_size`, and the Merkle
/// root over those leaves. See `docs/ENGINE.md` section 1.3.
///
/// The first line is `exchange-feed-sth-v1`, and it is a different first line
/// from `head_statement`'s. The sequencer serves a chain head and a tree head
/// at the same time under one key, and both statements start with a session
/// and a count. Without different first lines, a chain head at message 500 and
/// a tree head over 500 leaves would be two signatures a reader could swap for
/// each other.
///
/// The session is in the statement for the same reason it is in every other
/// statement here: tree sizes restart at 0 when a history is replaced, so two
/// honest heads over two unrelated histories would otherwise read as one key
/// signing two different roots for one size, which is exactly the evidence
/// this signature exists to produce when it really is one history.
fn tree_head_statement(
    session: &str,
    timestamp_ms: u64,
    tree_size: u64,
    root_hash: &Hash,
) -> Vec<u8> {
    format!(
        "exchange-feed-sth-v1\n{}\n{}\n{}\n{}",
        session,
        timestamp_ms,
        tree_size,
        to_hex(root_hash)
    )
    .into_bytes()
}

/// Signs a tree head: "history `session`, at `timestamp_ms`, had `tree_size`
/// messages under root `root_hash`."
pub fn sign_tree_head(
    key: &SigningKey,
    session: &str,
    timestamp_ms: u64,
    tree_size: u64,
    root_hash: &Hash,
) -> Signature {
    key.sign(&tree_head_statement(
        session,
        timestamp_ms,
        tree_size,
        root_hash,
    ))
}

/// Checks a tree head's signature.
///
/// This function is what ties a root to a size. `merkle::verify_inclusion`
/// never hashes `tree_size`, so a proof on its own cannot say which tree it
/// belongs to; the pairing comes from here.
pub fn verify_tree_head(
    key: &VerifyingKey,
    session: &str,
    timestamp_ms: u64,
    tree_size: u64,
    root_hash: &Hash,
    signature: &Signature,
) -> bool {
    key.verify_strict(
        &tree_head_statement(session, timestamp_ms, tree_size, root_hash),
        signature,
    )
    .is_ok()
}

/// One hash that covers the whole state of a matching engine, as
/// `MatcherState::state_root` computes it. It is the same width as a chain
/// link, and the name is different on purpose: a chain covers a *list* of
/// messages, a state root covers the *result* of running that list.
pub type StateRoot = [u8; 32];

/// The statement an execution claim covers: "in sequencer history `session`,
/// running messages `from_msg..=to_msg` against the state whose hash is
/// `root_before` produced the state whose hash is `root_after`, and
/// `trades_total` trades had run by then."
///
/// The session is inside the statement for the same reason it is inside the
/// sequencer's head and a validator's attestation: sequencer message ids
/// restart at 1 when a history is replaced, so without the session two honest
/// claims over two unrelated histories would read as one exchange signing two
/// answers to one question, which is exactly the evidence this signature
/// exists to produce when it *is* the same question.
fn claim_statement(
    session: &str,
    from_msg: u64,
    to_msg: u64,
    root_before: &StateRoot,
    root_after: &StateRoot,
    trades_total: u64,
) -> Vec<u8> {
    format!(
        "exchange-claim-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        session,
        from_msg,
        to_msg,
        to_hex(root_before),
        to_hex(root_after),
        trades_total
    )
    .into_bytes()
}

/// Signs one execution claim with the exchange's own key.
///
/// The signature is what stops the operator denying a claim later. Until the
/// signature existed, a claim was a row in the operator's private SQLite file:
/// true or false, but only ever as good as the operator's word that the row is
/// what the engine wrote. Signed, two claims naming the same history and the
/// same message range with different roots are the exchange's own signature on
/// the proof that it published two answers: the property V2 already gives the
/// sequencer's ordering, now covering execution.
pub fn sign_claim(
    key: &SigningKey,
    session: &str,
    from_msg: u64,
    to_msg: u64,
    root_before: &StateRoot,
    root_after: &StateRoot,
    trades_total: u64,
) -> Signature {
    key.sign(&claim_statement(
        session,
        from_msg,
        to_msg,
        root_before,
        root_after,
        trades_total,
    ))
}

/// Checks one execution claim's signature.
#[allow(clippy::too_many_arguments)]
pub fn verify_claim(
    key: &VerifyingKey,
    session: &str,
    from_msg: u64,
    to_msg: u64,
    root_before: &StateRoot,
    root_after: &StateRoot,
    trades_total: u64,
    signature: &Signature,
) -> bool {
    key.verify_strict(
        &claim_statement(
            session,
            from_msg,
            to_msg,
            root_before,
            root_after,
            trades_total,
        ),
        signature,
    )
    .is_ok()
}

/// How a validator rates its own attestation. An attestation is a validator's
/// signed statement about what it saw in the log. Both flags below are part of
/// the bytes that were signed, so nothing between a validator and the program
/// reading it can turn an alarm off: change either flag and the signature stops
/// matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AttestStatus {
    /// The validator caught the sequencer signing a history that the messages
    /// the validator holds do not produce. The flag stays set until an
    /// operator clears it.
    pub disputed: bool,
    /// The validator has not been able to check the sequencer for so long that
    /// its attestation says nothing about the log as it is now.
    pub stalled: bool,
}

impl AttestStatus {
    /// True when this validator vouches for the position it signed. Anything
    /// else must not be counted when the code asks whether enough validators
    /// agree.
    pub fn is_vouching(&self) -> bool {
        !self.disputed && !self.stalled
    }
}

/// The statement a validator's attestation covers. Its first line differs from
/// the first line of the sequencer's head statement, so the two kinds of
/// signature can never be passed off as each other even if a key were ever
/// shared.
///
/// The `v2` first line carries the two status flags. In `v1` the flags were
/// served beside the signature instead of inside it, which meant anything on
/// the path between a validator and the program reading it could rewrite a
/// validator's alarm to "all fine" without breaking the signature. The one
/// claim in this system that most needed to be unforgeable was the one field
/// nothing signed.
fn attest_statement(session: &str, last_id: u64, chain: &Chain, status: &AttestStatus) -> Vec<u8> {
    format!(
        "exchange-validator-attest-v2\n{}\n{}\n{}\n{}\n{}",
        session,
        last_id,
        to_hex(chain),
        status.disputed,
        status.stalled
    )
    .into_bytes()
}

/// Signs a validator's attestation: "I followed history `session` to message
/// `last_id` on my own, computed chain `chain` myself, and this is what I
/// think of my own view of it."
pub fn sign_attest(
    key: &SigningKey,
    session: &str,
    last_id: u64,
    chain: &Chain,
    status: &AttestStatus,
) -> Signature {
    key.sign(&attest_statement(session, last_id, chain, status))
}

/// Checks a validator's attestation.
pub fn verify_attest(
    key: &VerifyingKey,
    session: &str,
    last_id: u64,
    chain: &Chain,
    status: &AttestStatus,
    signature: &Signature,
) -> bool {
    key.verify_strict(
        &attest_statement(session, last_id, chain, status),
        signature,
    )
    .is_ok()
}

/// Loads the sequencer's signing key from `path`, or creates and saves one on
/// the first run. The file holds 32 bytes in hex, and only its owner can read
/// it: whoever reads it can sign histories as this sequencer.
pub fn load_or_create_key(path: &Path) -> Result<SigningKey, String> {
    if path.exists() {
        let hex = fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
        let bytes: [u8; 32] = from_hex(hex.trim())
            .ok_or_else(|| format!("{} does not hold a 32-byte hex key", path.display()))?;
        return Ok(SigningKey::from_bytes(&bytes));
    }
    let key = ephemeral_key();
    write_durably(path, to_hex(&key.to_bytes()).as_bytes())
        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
    restrict_permissions(path);
    Ok(key)
}

/// Writes a file and does not return until the bytes are on the disk.
///
/// `fs::write` returns once the operating system holds the bytes, not once the
/// disk holds them. That is fine for a file that can be made again. This file
/// cannot be made again: the database is opened with `synchronous = FULL`, so
/// after a power cut the history survives while an unsynced key file can be
/// lost or half written. Every checkpoint in that history is then signed by a
/// key nobody holds, and no later run can ever check them. The history is
/// whole and permanently uncheckable, which is the worse of the two outcomes.
///
/// The code syncs the directory as well as the file. On Linux the file's own
/// sync does not promise the file's name is in the directory yet, so a crash
/// between the two leaves a file written to disk with no path to it.
fn write_durably(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        // A directory that cannot be opened is not a reason to refuse the key:
        // the file itself is already written to disk, and the directory sync
        // is the weaker half.
        if let Ok(handle) = fs::File::open(dir) {
            let _ = handle.sync_all();
        }
    }
    Ok(())
}

/// A key that lives only as long as the process. The sequencer uses it when it
/// runs without a database: nothing else about that run survives a restart
/// either.
pub fn ephemeral_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    SigningKey::from_bytes(&bytes)
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn from_hex<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
        tracing::warn!(
            "could not restrict permissions on {}: {}",
            path.display(),
            e
        );
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{OPERATOR_ACCOUNT, Side};

    fn message(id: u64) -> OrderMessage {
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

    /// The whole scheme rests on this: the same messages give the same chain,
    /// and any change to any earlier message gives a different chain.
    #[test]
    fn chain_commits_to_the_whole_history() {
        let honest = [message(1), message(2), message(3)];
        let mut tampered = [message(1), message(2), message(3)];
        if let OrderMessage::New { price, .. } = &mut tampered[0] {
            *price = 100.26; // one cent, in the oldest message
        }

        let fold =
            |msgs: &[OrderMessage]| msgs.iter().fold(EMPTY_CHAIN, |chain, m| extend(&chain, m));
        assert_eq!(fold(&honest), fold(&honest));
        assert_ne!(fold(&honest), fold(&tampered));
    }

    #[test]
    fn signatures_verify_and_bind_every_field() {
        let key = ephemeral_key();
        let public = key.verifying_key();
        let chain = extend(&EMPTY_CHAIN, &message(1));
        let signature = sign_head(&key, "sess", 1, &chain);

        assert!(verify_head(&public, "sess", 1, &chain, &signature));
        assert!(!verify_head(&public, "other", 1, &chain, &signature));
        assert!(!verify_head(&public, "sess", 2, &chain, &signature));
        assert!(!verify_head(&public, "sess", 1, &EMPTY_CHAIN, &signature));
        let stranger = ephemeral_key().verifying_key();
        assert!(!verify_head(&stranger, "sess", 1, &chain, &signature));
    }

    /// Every field a tree head states has to be inside its signature.
    ///
    /// The root is the field that would be missed, because it is the only one
    /// a reader cannot check any other way. A signature that covered the size
    /// and not the root would let an operator serve any root at all under a
    /// size a client already trusted.
    #[test]
    fn a_tree_head_signature_binds_every_field() {
        let key = ephemeral_key();
        let public = key.verifying_key();
        let root = crate::merkle::MerkleTree::from_entries(&[b"a", b"b"]).root();
        let signature = sign_tree_head(&key, "sess", 1_700_000_000_000, 2, &root);

        assert!(verify_tree_head(
            &public,
            "sess",
            1_700_000_000_000,
            2,
            &root,
            &signature
        ));
        assert!(
            !verify_tree_head(&public, "other", 1_700_000_000_000, 2, &root, &signature),
            "the session is signed, so a head cannot be moved to another history"
        );
        assert!(
            !verify_tree_head(&public, "sess", 1_700_000_000_001, 2, &root, &signature),
            "the timestamp is signed, so an old head cannot be re-dated as current"
        );
        assert!(
            !verify_tree_head(&public, "sess", 1_700_000_000_000, 3, &root, &signature),
            "the size is signed, so a root cannot be re-used under a larger tree"
        );
        assert!(
            !verify_tree_head(
                &public,
                "sess",
                1_700_000_000_000,
                2,
                &crate::merkle::empty_root(),
                &signature
            ),
            "the root is signed, which is the whole point of the statement"
        );
        let stranger = ephemeral_key().verifying_key();
        assert!(!verify_tree_head(
            &stranger,
            "sess",
            1_700_000_000_000,
            2,
            &root,
            &signature
        ));
    }

    /// A tree head and a chain head must never be readable as each other. The
    /// sequencer signs both with its one key, and both start with a session
    /// and a count, so only the first line keeps them apart.
    #[test]
    fn a_tree_head_is_not_a_chain_head_under_the_same_key() {
        let key = ephemeral_key();
        let public = key.verifying_key();
        let value = [7u8; 32];

        let tree = sign_tree_head(&key, "sess", 9, 5, &value);
        let chain = sign_head(&key, "sess", 5, &value);
        assert_ne!(tree.to_bytes(), chain.to_bytes());
        assert!(!verify_head(&public, "sess", 5, &value, &tree));
        assert!(!verify_tree_head(&public, "sess", 9, 5, &value, &chain));
    }

    /// A validator's status is only worth serving if nothing can edit it on
    /// the way to the program that reads it.
    #[test]
    fn attestation_signature_covers_the_status_flags() {
        let key = ephemeral_key();
        let public = key.verifying_key();
        let chain = extend(&EMPTY_CHAIN, &message(1));
        let disputed = AttestStatus {
            disputed: true,
            stalled: false,
        };
        let signature = sign_attest(&key, "sess", 1, &chain, &disputed);

        assert!(verify_attest(
            &public, "sess", 1, &chain, &disputed, &signature
        ));
        // The forgery the flags exist to stop: same signature, alarm off.
        assert!(!verify_attest(
            &public,
            "sess",
            1,
            &chain,
            &AttestStatus::default(),
            &signature
        ));
        assert!(!verify_attest(
            &public,
            "sess",
            1,
            &chain,
            &AttestStatus {
                disputed: true,
                stalled: true
            },
            &signature
        ));
        assert!(AttestStatus::default().is_vouching());
        assert!(!disputed.is_vouching());
    }

    /// An execution claim is the exchange's own signature on what its engine
    /// did, so every field the claim names has to be inside the signature.
    #[test]
    fn a_claim_signature_binds_every_field() {
        let key = ephemeral_key();
        let public = key.verifying_key();
        let before = [1u8; 32];
        let after = [2u8; 32];
        let signature = sign_claim(&key, "sess", 5, 9, &before, &after, 17);

        assert!(verify_claim(
            &public, "sess", 5, 9, &before, &after, 17, &signature
        ));
        // Each of these is a different statement about execution.
        assert!(!verify_claim(
            &public, "other", 5, 9, &before, &after, 17, &signature
        ));
        assert!(!verify_claim(
            &public, "sess", 4, 9, &before, &after, 17, &signature
        ));
        assert!(!verify_claim(
            &public, "sess", 5, 10, &before, &after, 17, &signature
        ));
        assert!(!verify_claim(
            &public, "sess", 5, 9, &after, &after, 17, &signature
        ));
        assert!(!verify_claim(
            &public, "sess", 5, 9, &before, &before, 17, &signature
        ));
        assert!(!verify_claim(
            &public, "sess", 5, 9, &before, &after, 18, &signature
        ));
        let stranger = ephemeral_key().verifying_key();
        assert!(!verify_claim(
            &stranger, "sess", 5, 9, &before, &after, 17, &signature
        ));
    }

    /// Every field the checkpoint in `feed.db` states has to be inside its
    /// signature, and the root is the field that matters: it is the only value
    /// there that nothing else in the file can be checked against.
    ///
    /// The pairs below are the two ways a root could be moved rather than
    /// forged: taken from another history under the same key, or from an
    /// earlier point in this one. Both fail because the session and the
    /// chain are in the statement with the root.
    #[test]
    fn a_checkpoint_signature_binds_every_field() {
        let key = ephemeral_key();
        let public = key.verifying_key();
        let chain = extend(&EMPTY_CHAIN, &message(1));
        let root = [3u8; 32];
        let signature = sign_checkpoint(&key, "sess", 1, &chain, &root);

        assert!(verify_checkpoint(
            &public, "sess", 1, &chain, &root, &signature
        ));
        // The rewritten tree this signature exists to catch.
        assert!(!verify_checkpoint(
            &public, "sess", 1, &chain, &[4u8; 32], &signature
        ));
        assert!(!verify_checkpoint(
            &public, "other", 1, &chain, &root, &signature
        ));
        assert!(!verify_checkpoint(
            &public, "sess", 2, &chain, &root, &signature
        ));
        assert!(!verify_checkpoint(
            &public,
            "sess",
            1,
            &EMPTY_CHAIN,
            &root,
            &signature
        ));
        let stranger = ephemeral_key().verifying_key();
        assert!(!verify_checkpoint(
            &stranger, "sess", 1, &chain, &root, &signature
        ));
        // And it is not a chain head, which is the other signature stored in
        // the same row over three of the same four values.
        assert!(!verify_head(&public, "sess", 1, &chain, &signature));
    }

    /// The four statements this key type signs must never be readable as one
    /// another: a head, a checkpoint, an attestation and an execution claim
    /// are different promises, and one key signs all four.
    #[test]
    fn the_signed_statements_cannot_be_confused_for_each_other() {
        let root = [0u8; 32];
        let head = head_statement("sess", 1, &root);
        let checkpoint = checkpoint_statement("sess", 1, &root, &root);
        let attest = attest_statement("sess", 1, &root, &AttestStatus::default());
        let claim = claim_statement("sess", 1, 1, &root, &root, 0);
        assert_ne!(head, attest);
        assert_ne!(head, claim);
        assert_ne!(head, checkpoint);
        assert_ne!(checkpoint, attest);
        assert_ne!(checkpoint, claim);
        assert_ne!(attest, claim);
        for statement in [&head, &checkpoint, &attest, &claim] {
            let text = String::from_utf8(statement.clone()).expect("statements are text");
            let prefix = text.lines().next().expect("a prefix line");
            assert!(
                prefix.starts_with("exchange-") && prefix.ends_with(char::is_numeric),
                "{} is not a versioned, domain-separated prefix",
                prefix
            );
        }
    }

    /// The exact bytes of every statement this file signs.
    ///
    /// A signature covers a set of bytes in one exact order. Swap two fields
    /// and the bytes change, so every signature made before the swap stops
    /// matching.
    ///
    /// The test above only checks that the four first lines differ. It passes
    /// with any field order, so it cannot see a swap. Swapping two fields here
    /// breaks every signature the anchor sender checks, and nothing in this
    /// crate says so: the exchange keeps trading, the sender refuses every
    /// tree head, and the only sign is the anchor age growing on the page.
    /// This test is the one thing that says so.
    ///
    /// `anchor/anchor_test.go` pins the same two statements the sender builds
    /// again. The two expected strings there are character for character the
    /// two here, so a reader can open both files and compare them without
    /// running anything.
    #[test]
    fn the_signed_statements_are_exactly_these_bytes() {
        let text = |statement: Vec<u8>| String::from_utf8(statement).expect("statements are text");

        // The same values as TestSignedStatementsMatchTheExchangesFormat in
        // anchor_test.go.
        let session = "349d462ced25bb2b";
        let mut root = [0u8; 32];
        root[..4].copy_from_slice(&[0x6f, 0x94, 0x15, 0xdc]);
        assert_eq!(
            text(tree_head_statement(session, 1786767726360, 102769, &root)),
            "exchange-feed-sth-v1\n\
             349d462ced25bb2b\n\
             1786767726360\n\
             102769\n\
             6f9415dc00000000000000000000000000000000000000000000000000000000",
            "the tree head statement changed; anchor/anchor_test.go pins the same field order"
        );

        let mut before = [0u8; 32];
        before[0] = 0xaa;
        let mut after = [0u8; 32];
        after[0] = 0xbb;
        assert_eq!(
            text(claim_statement(session, 5, 9, &before, &after, 17)),
            "exchange-claim-v1\n\
             349d462ced25bb2b\n\
             5\n\
             9\n\
             aa00000000000000000000000000000000000000000000000000000000000000\n\
             bb00000000000000000000000000000000000000000000000000000000000000\n\
             17",
            "the claim statement changed; anchor/anchor_test.go pins the same field order"
        );

        // The sender never builds these three again, so only this file pins
        // them.
        let mut chain = [0u8; 32];
        chain[..2].copy_from_slice(&[0x11, 0x22]);
        assert_eq!(
            text(head_statement(session, 102769, &chain)),
            "exchange-feed-head-v1\n\
             349d462ced25bb2b\n\
             102769\n\
             1122000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            text(checkpoint_statement(session, 102769, &chain, &root)),
            "exchange-feed-checkpoint-v1\n\
             349d462ced25bb2b\n\
             102769\n\
             1122000000000000000000000000000000000000000000000000000000000000\n\
             6f9415dc00000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            text(attest_statement(
                session,
                102769,
                &chain,
                &AttestStatus {
                    disputed: true,
                    stalled: false,
                }
            )),
            "exchange-validator-attest-v2\n\
             349d462ced25bb2b\n\
             102769\n\
             1122000000000000000000000000000000000000000000000000000000000000\n\
             true\n\
             false"
        );
    }

    /// What the sequencer's own round trip has to preserve.
    ///
    /// This test used to be the statement that made every reader safe: all
    /// four of them turned the messages they were served back into bytes
    /// themselves, so the chain they computed was only right while every
    /// reader shared one `OrderMessage`. That was the coupling: the format
    /// could not grow unless every reader was rebuilt at the same moment. No
    /// reader turns a message back into bytes now; readers combine the bytes
    /// they received with `extend_bytes` (`wire.rs`), and
    /// `a_consumer_folds_a_history_it_cannot_fully_read` below pins that.
    ///
    /// The round trip still has to hold for the sequencer itself, which is why
    /// this test stayed. `feed.rs` stores each message's JSON in
    /// `feed_messages`, reads it back as an `OrderMessage` to serve pages
    /// older than its memory window, and writes it to JSON again on the way
    /// out. A field the sequencer dropped there would be a sequencer serving
    /// bytes that do not hash to the chain beside them in its own database.
    #[test]
    fn a_message_survives_the_round_trip_the_feed_makes() {
        let with_nonce = OrderMessage::New {
            id: 1,
            timestamp: 1000,
            account: 7,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            price: 100.25,
            quantity: 5.0,
            nonce: Some("9f2b1c04d7e58a36bb0147fe29c3d580".to_string()),
            order_type: Default::default(),
            time_in_force: Default::default(),
            post_only: false,
        };
        let messages = [message(1), with_nonce, message(3)];

        // What the sequencer publishes, and the chain it signs over it.
        let served = serde_json::to_vec(&messages.iter().collect::<Vec<_>>())
            .expect("the feed serializes its page");
        let signed = messages
            .iter()
            .fold(EMPTY_CHAIN, |chain, m| extend(&chain, m));

        // What a reader parses off the wire, and the chain it computes again.
        let received: Vec<OrderMessage> =
            serde_json::from_slice(&served).expect("a consumer parses the page");
        let recomputed = received
            .iter()
            .fold(EMPTY_CHAIN, |chain, m| extend(&chain, m));

        assert_eq!(signed, recomputed);
        assert_eq!(
            canonical_bytes(&messages[1]),
            canonical_bytes(&received[1]),
            "byte for byte, or every consumer disputes an honest feed"
        );
        assert!(
            String::from_utf8_lossy(&canonical_bytes(&received[1])).contains("nonce"),
            "the nonce really is in the bytes the chain covers"
        );
        assert!(
            !String::from_utf8_lossy(&canonical_bytes(&received[0])).contains("nonce"),
            "and a message that never had one still has no such key"
        );
    }

    /// The property that lets the message format grow without redeploying
    /// every reader at once.
    ///
    /// The history here holds a message kind no struct in this binary can
    /// produce, so the only form of that message that exists is its bytes.
    /// That is exactly the position a reader is in against a sequencer newer
    /// than itself. The chain the reader combines is the chain the sequencer
    /// signed, and the message the reader cannot read is still a message it
    /// can hash.
    #[test]
    fn a_consumer_folds_a_history_it_cannot_fully_read() {
        let market = br#"{"Market":{"id":2,"timestamp":2000,"account":7,"symbol":"ETH-USDC","side":"Buy","quantity":3.0}}"#;
        let history: [Vec<u8>; 3] = [
            canonical_bytes(&message(1)),
            market.to_vec(),
            canonical_bytes(&message(3)),
        ];

        // The sequencer's chain, hashed over the bytes it published.
        let signed = history
            .iter()
            .fold(EMPTY_CHAIN, |chain, bytes| extend_bytes(&chain, bytes));

        // The reader's chain, hashed over the bytes it received. Same bytes,
        // so same chain, and the reader never had to know what a Market
        // message is.
        let mut body = Vec::new();
        for bytes in &history {
            body.extend_from_slice(bytes);
            body.push(b'\n');
        }
        let received = crate::wire::split_ndjson(&body).expect("the page splits into messages");
        let recomputed = received
            .iter()
            .fold(EMPTY_CHAIN, |chain, msg| extend_bytes(&chain, &msg.bytes));

        assert_eq!(signed, recomputed);
        assert!(
            serde_json::from_slice::<OrderMessage>(market).is_err(),
            "this build must genuinely not know this kind, or the test proves nothing"
        );
        assert!(
            received[1].parse::<OrderMessage>().is_err(),
            "and reading it must fail as reading, not as hashing"
        );

        // A change to that same unknown message is still caught. Hashing bytes
        // lets the format grow and still catches a changed message.
        let mut edited = history.clone();
        edited[1] = br#"{"Market":{"id":2,"timestamp":2000,"account":8,"symbol":"ETH-USDC","side":"Buy","quantity":3.0}}"#.to_vec();
        let tampered = edited
            .iter()
            .fold(EMPTY_CHAIN, |chain, bytes| extend_bytes(&chain, bytes));
        assert_ne!(signed, tampered);
    }

    #[test]
    fn hex_round_trips() {
        let chain = extend(&EMPTY_CHAIN, &message(7));
        assert_eq!(from_hex::<32>(&to_hex(&chain)), Some(chain));
        assert_eq!(from_hex::<32>("zz"), None);
        assert_eq!(from_hex::<4>("0102030405"), None); // wrong length
    }

    /// The first 500 messages of the running sequencer, byte for byte:
    ///
    /// ```text
    /// curl -s 'https://feed.exchange.th3nolo.com/messages.ndjson?since=0&limit=500'
    /// ```
    ///
    /// Session `349d462ced25bb2b`, fetched at tree size 126,989. Nobody wrote
    /// this fixture to match the code. It is a page the deployed sequencer
    /// served, and its leaves are under the root the sequencer signs and the
    /// anchor contract on Base holds.
    const LIVE_PAGE: &str = include_str!("testdata/live-500.ndjson");

    /// The chain the sequencer hashed over those 500 messages, and the
    /// RFC 9162 root over the same 500 leaves.
    ///
    /// The root is not this build's opinion. The deployed sequencer answers
    /// `GET /proof/inclusion?leaf=1&tree_size=500` with a nine-hash path, and
    /// that path over leaf 1 reaches exactly this value, so the sequencer and
    /// this file agree about what the first 500 messages hash to. The
    /// sequencer's consistency proof from 500 to 126,989 then ties this value
    /// to the head it signs today; a consistency proof shows that the tree of
    /// 126,989 leaves still holds every leaf of the tree of 500, unchanged and
    /// in the same order.
    const LIVE_CHAIN_500: &str = "bf2768dbe1de80be58d51cb0242142af6eceecefc5d0d2e3e36bbde6c138e6a9";
    const LIVE_ROOT_500: &str = "709b86f1d9f34493b0db0736c733e022fc746947b3bd0c062dea91b8d6ee1ae1";

    fn live_page() -> Vec<&'static [u8]> {
        LIVE_PAGE
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::as_bytes)
            .collect()
    }

    /// Every message the sequencer has published still turns into the bytes it
    /// published, one message at a time, all 500 of them.
    ///
    /// The test checks all 500, not a sample, and reports by position: a
    /// failure names the first message this build writes differently, which is
    /// the message whose inclusion proof stops passing.
    ///
    /// This is the test that decides whether the shape may change at all. Add
    /// a field that is written even when it holds its default value, or wrap
    /// the message in the envelope of ENGINE.md section 2, and this test fails
    /// at line 1.
    #[test]
    fn all_five_hundred_published_messages_serialize_to_the_bytes_they_were_published_as() {
        let page = live_page();
        assert_eq!(page.len(), 500, "the fixture is the page the feed served");

        let mut news = 0;
        let mut cancels = 0;
        let mut with_nonce = 0;
        for (index, published) in page.iter().enumerate() {
            let message: OrderMessage = serde_json::from_slice(published).unwrap_or_else(|e| {
                panic!(
                    "message {} of the live page does not read: {}, {}",
                    index + 1,
                    e,
                    String::from_utf8_lossy(published)
                )
            });
            assert_eq!(
                canonical_bytes(&message),
                *published,
                "message {} of the live page is written differently by this build:\n                   published {}\n  written   {}",
                index + 1,
                String::from_utf8_lossy(published),
                String::from_utf8_lossy(&canonical_bytes(&message))
            );
            assert_eq!(message.id() as usize, index + 1);
            match message {
                OrderMessage::New { .. } => news += 1,
                OrderMessage::Cancel { .. } => cancels += 1,
                other => panic!("the live page holds no {:?}", other),
            }
            if message.nonce().is_some() {
                with_nonce += 1;
            }
        }
        // What the page is made of. A fixture replaced by 500 copies of one
        // message would not pass this file.
        assert_eq!((news, cancels, with_nonce), (446, 54, 88));
    }

    /// The two values a rewrite of the message shape would move: the chain the
    /// sequencer signed over the page, and the RFC 9162 root over the same
    /// leaves.
    ///
    /// The test computes both twice: over the bytes as served, and over the
    /// bytes this build writes for the same messages. Those are the two
    /// halves that must not drift apart. The first is what a reader
    /// combines. The second is what the sequencer would produce if it
    /// published the same history again.
    #[test]
    fn the_chain_and_the_root_over_the_live_page_are_unchanged() {
        let page = live_page();
        let reserialized: Vec<Vec<u8>> = page
            .iter()
            .map(|bytes| {
                let message: OrderMessage = serde_json::from_slice(bytes).expect("it reads");
                canonical_bytes(&message)
            })
            .collect();

        let served_chain = page
            .iter()
            .fold(EMPTY_CHAIN, |chain, bytes| extend_bytes(&chain, bytes));
        assert_eq!(to_hex(&served_chain), LIVE_CHAIN_500);

        let written_chain = reserialized
            .iter()
            .fold(EMPTY_CHAIN, |chain, bytes| extend_bytes(&chain, bytes));
        assert_eq!(
            to_hex(&written_chain),
            LIVE_CHAIN_500,
            "this build re-serializes the live page to a different chain"
        );

        let served_root = crate::merkle::MerkleTree::from_entries(&page).root();
        assert_eq!(to_hex(&served_root), LIVE_ROOT_500);
        let written_root = crate::merkle::MerkleTree::from_entries(&reserialized).root();
        assert_eq!(
            to_hex(&written_root),
            LIVE_ROOT_500,
            "this build re-serializes the live page to a different Merkle root"
        );
    }

    /// A build that does not know a message kind still computes the chain the
    /// sequencer signed. This was already true before the three new kinds
    /// existed; the test checks it over the real page rather than over three
    /// made-up messages.
    ///
    /// The test adds two kinds to the page: `ListSymbol`, which this build
    /// knows and does not run, and `Iceberg`, which no struct in this binary
    /// can produce. The code parses neither one before hashing it, so both
    /// hash the same way as every other message.
    #[test]
    fn a_page_holding_kinds_this_build_cannot_read_folds_to_the_chain_the_feed_signed() {
        const ICEBERG: &[u8] = br#"{"Iceberg":{"id":501,"timestamp":1786752662999,"account":6,"symbol":"BTC-USDC","side":"Buy","price":984.0,"quantity":40.0,"display_quantity":2.0}}"#;
        let listing = canonical_bytes(&OrderMessage::ListSymbol {
            id: 502,
            timestamp: 1786752663111,
            account: OPERATOR_ACCOUNT,
            symbol: "DELTA-USD".to_string(),
            price_step: 0.01,
            quantity_step: 0.1,
            nonce: None,
            public_key: String::new(),
            signature: String::new(),
        });

        let mut body = Vec::new();
        for line in live_page() {
            body.extend_from_slice(line);
            body.push(b'\n');
        }
        body.extend_from_slice(ICEBERG);
        body.push(b'\n');
        body.extend_from_slice(&listing);
        body.push(b'\n');

        // What the sequencer hashed: the bytes it published, in order, with no
        // opinion about what any of them says.
        let signed = live_page()
            .into_iter()
            .chain([ICEBERG, listing.as_slice()])
            .fold(EMPTY_CHAIN, |chain, bytes| extend_bytes(&chain, bytes));

        // What a reader hashes off the wire. It splits the page into messages
        // without parsing any message.
        let received = crate::wire::split_ndjson(&body).expect("one message per line");
        assert_eq!(received.len(), 502);
        assert_eq!(received[500].kind, "Iceberg");
        assert_eq!(received[501].kind, "ListSymbol");
        assert!(
            received[500].parse::<OrderMessage>().is_err(),
            "no struct in this binary produces an Iceberg"
        );
        let folded = received
            .iter()
            .fold(EMPTY_CHAIN, |chain, raw| extend_bytes(&chain, &raw.bytes));
        assert_eq!(signed, folded);
    }
}
