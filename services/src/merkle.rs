//! The Merkle tree of RFC 9162 (Certificate Transparency 2.0), sections 2.1.1
//! to 2.1.5.
//!
//! A Merkle tree turns a list of entries into one hash. Two words run through
//! the whole file:
//!
//! - a **leaf** is the hash of one entry. One entry makes one leaf, and the
//!   leaves stay in the order the entries arrived.
//! - a **node** is the hash of the two hashes under it. Nodes stack up in
//!   levels until one hash is left at the top. That top hash is the **root**.
//!
//! Change one byte of one entry and the root changes. So a reader who holds
//! the root can check any entry against it.
//!
//! This is the tree `docs/ENGINE.md` section 1 specifies. It is written here
//! as pure functions over bytes and imports nothing from the rest of this
//! repository, so a second implementation can be checked against it without
//! dragging in the sequencer, the store or the wire format.
//!
//! ```text
//! MTH({})   = HASH()
//! MTH({d0}) = HASH(0x00 || d0)
//! MTH(D_n)  = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))    k = largest 2^i < n
//! ```
//!
//! `MTH` is the root over a list of entries. `HASH` is SHA-256. The tree does
//! not have to be balanced. The number of leaves alone fixes its shape.
//!
//! The two verify functions copy RFC 9162 sections 2.1.3.2 and 2.1.4.2, step
//! for step, and the comments below carry the RFC's own step numbers. They do
//! not recompute the root some other way and compare. Copying the RFC exactly
//! has one reason: an auditor who writes the RFC out from its text gets the
//! same accept or reject answer as this code, on every input, including the
//! malformed ones.
//!
//! Two kinds of proof come out of this file:
//!
//! - an inclusion proof: a short list of hashes that shows one entry sits at
//!   one position in the tree with this root.
//! - a consistency proof: a short list of hashes that shows the older tree is
//!   the start of the newer tree. Entries were added, and nothing already in
//!   the tree was changed, removed or moved.
//!
//! # Costs
//!
//! `n` is the number of leaves. A subtree is *perfect* when it is full: it
//! covers `2^level` leaves and no place in it is empty. The tree keeps the
//! hash of every perfect subtree, level by level: `n` leaf hashes, `n/2` at
//! the next level up, and so on. That is under `2n` hashes, so 64 bytes per
//! leaf.
//!
//! - append: 1 leaf hash, plus one node hash for each trailing 1 bit in the
//!   new leaf's index. That is under 1 node hash per append on average, and
//!   `log2(n)` on the worst single append. An append never hashes a stored
//!   node again, which is what an exchange that appends constantly needs.
//! - root, and the root of any earlier tree size: `log2(n)` node hashes. Only
//!   the right edge is computed. The right edge is the run of nodes on the
//!   right of the tree that are not full yet, and it changes on every append.
//!   Every perfect node is a lookup.
//! - inclusion proof: at most `ceil(log2(n))` nodes, `log2(n)` node hashes.
//! - consistency proof: at most `ceil(log2(n)) + 1` nodes, `log2(n)` node
//!   hashes.
//! - verifying either proof: one node hash per proof element, and no access to
//!   the tree at all.
//!
//! # Where the nodes are kept
//!
//! The walks above need one thing from storage: the hash of a *perfect*
//! subtree, by level and index. That is the whole of `NodeSource`, and it is
//! why this file still imports nothing from the rest of this repository. Three
//! places keep the nodes, and each one implements `NodeSource`:
//!
//! - `MerkleTree` below keeps every node, in vectors in memory.
//! - the sequencer keeps them in a SQLite table, so a history longer than RAM
//!   has a tree that is never held in RAM.
//! - `RootFold`, also below, keeps the right edge alone, 64 hashes at most.
//!   The checker and the audit use it. Both walk a history they never hold,
//!   and both need the root at a few sizes they know before they start.
//!
//! All three go through the same `mth`, `path`, `proof` and `append_nodes`, so
//! there is one implementation of RFC 9162 here and not one per place the
//! nodes happen to live.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt;

use sha2::{Digest, Sha256};

/// A SHA-256 hash is 32 bytes wide. RFC 9162 calls this HASH_SIZE.
pub const HASH_SIZE: usize = 32;

/// One hash in the tree: a leaf, an internal node, or the root.
pub type Hash = [u8; HASH_SIZE];

/// Prefix byte of a leaf hash, RFC 9162 section 2.1.1.
///
/// **This byte and `NODE_PREFIX` are load bearing. Do not remove them to
/// "simplify" the hash.** They make leaf hashing and node hashing two
/// different functions.
///
/// Here is what the two prefix bytes stop somebody doing. Without them the two
/// functions are one function. An internal node is the hash of the 64 bytes
/// `left || right`, so those same 64 bytes, offered as an entry, hash to that
/// node. An attacker then presents 64 bytes nobody ever submitted as an entry,
/// and produces an inclusion proof for them that lands on the real signed
/// root. A reader who checks that proof accepts it. With the prefixes the
/// entry hashes to something else, and the proof fails.
///
/// The RFC calls this "domain separation ... required to give second preimage
/// resistance", RFC 9162 section 2.1.1. A second preimage is a second input
/// that hashes to the same value as the first one. The test
/// `an_internal_node_cannot_be_passed_off_as_a_leaf` at the bottom of this
/// file runs that attack both ways round.
const LEAF_PREFIX: u8 = 0x00;

/// Prefix byte of an internal node hash, RFC 9162 section 2.1.1. See
/// `LEAF_PREFIX` for why it exists.
const NODE_PREFIX: u8 = 0x01;

/// `MTH({})`: the hash of the empty list is the hash of the empty string.
///
/// Check it from a shell: `printf '' | sha256sum` gives
/// `e3b0c442...b7852b855`.
pub fn empty_root() -> Hash {
    Sha256::new().finalize().into()
}

/// `MTH({d0}) = HASH(0x00 || d0)`.
///
/// The entry is bytes and stays bytes. Computing a leaf parses nothing. So a
/// reader can hash a message kind it does not understand.
pub fn leaf_hash(entry: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(entry);
    hasher.finalize().into()
}

/// `HASH(0x01 || left || right)`: one internal node from its two children.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Why the tree could not produce a proof. Every one of these means the caller
/// asked for something that does not exist. None of them means the tree is
/// broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// The caller asked for a proof against a tree size this tree has not
    /// reached.
    UnknownTreeSize { tree_size: u64, have: u64 },
    /// `leaf_index >= tree_size`, so there is no such leaf to prove.
    LeafOutOfRange { leaf_index: u64, tree_size: u64 },
    /// `first > second`. A consistency proof only runs forwards.
    BackwardsConsistency { first: u64, second: u64 },
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::UnknownTreeSize { tree_size, have } => {
                write!(f, "tree size {tree_size} requested, tree holds {have}")
            }
            ProofError::LeafOutOfRange {
                leaf_index,
                tree_size,
            } => write!(f, "leaf {leaf_index} is outside a tree of size {tree_size}"),
            ProofError::BackwardsConsistency { first, second } => {
                write!(f, "consistency asked from {first} back to {second}")
            }
        }
    }
}

impl std::error::Error for ProofError {}

/// The `k` of RFC 9162 section 2.1.1: the largest power of two that is smaller
/// than `n`, and not equal to `n`. It is defined for `n >= 2`, which is the
/// only place the RFC uses it.
fn split_point(n: u64) -> u64 {
    debug_assert!(n >= 2, "RFC 9162 only defines k for n > 1");
    // `n.next_power_of_two()` is wrong here. When n is already a power of two
    // it returns n, and the RFC needs a k below n. The high bit of n - 1 gives
    // the largest power of two below n in both cases.
    1u64 << (u64::BITS - 1 - (n - 1).leading_zeros())
}

/// Where the perfect subtree hashes are kept.
///
/// `node(level, index)` is `MTH(D[index * 2^level : (index+1) * 2^level])`, the
/// root of a perfect subtree of `2^level` leaves that starts at leaf
/// `index * 2^level`. A perfect subtree never changes once it is full. So every
/// hash an implementation returns was written once by `append_nodes`, and is
/// never written again.
///
/// Nobody stores the tree's right edge, the nodes that *do* change on every
/// append. Those are computed when they are needed, from the perfect nodes
/// below them. So an implementation is only ever asked for a node it was given.
/// Asking for a node it was never given is a bug in the caller, not a case to
/// answer: storage in memory may panic on it. Storage that can really fail to
/// read, such as a database, reports that failure through `Error`.
pub trait NodeSource {
    /// Why a stored node could not be read back. `Infallible` for storage that
    /// cannot fail.
    type Error;

    /// The number of leaves. RFC 9162 calls this `tree_size`.
    fn tree_size(&self) -> u64;

    /// `MTH(D[index * 2^level : (index+1) * 2^level])`.
    fn node(&self, level: u32, index: u64) -> Result<Hash, Self::Error>;
}

/// Why a walk over a tree did not produce an answer.
///
/// Every call site must tell the two apart. `Proof` means the caller asked for
/// something that does not exist. `Source` means this log cannot read its own
/// storage. The first is an HTTP 400 and the second is an HTTP 500.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeError<E> {
    /// The tree does not hold what was asked for. See `ProofError`.
    Proof(ProofError),
    /// A stored node could not be read.
    Source(E),
}

impl<E: fmt::Display> fmt::Display for TreeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TreeError::Proof(error) => error.fmt(f),
            TreeError::Source(error) => write!(f, "the stored tree could not be read: {error}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for TreeError<E> {}

impl<E> From<ProofError> for TreeError<E> {
    fn from(error: ProofError) -> Self {
        TreeError::Proof(error)
    }
}

impl TreeError<Infallible> {
    /// Drops the half a `MerkleTree` cannot produce. Its storage cannot fail,
    /// so `ProofError` is the only thing a walk can return.
    fn certain(self) -> ProofError {
        match self {
            TreeError::Proof(error) => error,
            // `Infallible` has no values, so there is no arm to write here.
            TreeError::Source(never) => match never {},
        }
    }
}

/// `MTH(D[0:tree_size])`, RFC 9162 section 2.1.1: the root the log published
/// when it held `tree_size` entries.
pub fn mth<S: NodeSource + ?Sized>(nodes: &S, tree_size: u64) -> Result<Hash, TreeError<S::Error>> {
    let size = checked_size(nodes, tree_size)?;
    if size == 0 {
        return Ok(empty_root());
    }
    subtree_hash(nodes, 0, size).map_err(TreeError::Source)
}

/// `PATH(leaf_index, D[0:tree_size])`, RFC 9162 section 2.1.3.1: the inclusion
/// proof for one leaf.
///
/// The list starts at the leaf's sibling and goes up, which is the order
/// `verify_inclusion` reads it in.
pub fn path<S: NodeSource + ?Sized>(
    nodes: &S,
    leaf_index: u64,
    tree_size: u64,
) -> Result<Vec<Hash>, TreeError<S::Error>> {
    let size = checked_size(nodes, tree_size)?;
    if leaf_index >= size {
        return Err(TreeError::Proof(ProofError::LeafOutOfRange {
            leaf_index,
            tree_size,
        }));
    }
    let mut out = Vec::new();
    walk_path(nodes, leaf_index, 0, size, &mut out).map_err(TreeError::Source)?;
    Ok(out)
}

/// `PROOF(first, D[0:second])`, RFC 9162 section 2.1.4.1: the consistency
/// proof between two tree sizes.
///
/// It proves the tree at size `first` is the start of the tree at size
/// `second`. Entries were appended. Nothing was changed, removed or moved.
pub fn proof<S: NodeSource + ?Sized>(
    nodes: &S,
    first: u64,
    second: u64,
) -> Result<Vec<Hash>, TreeError<S::Error>> {
    let size = checked_size(nodes, second)?;
    if first > second {
        return Err(TreeError::Proof(ProofError::BackwardsConsistency {
            first,
            second,
        }));
    }
    // RFC 9162 defines PROOF for 0 < m < n only. Two sizes outside that range
    // happen in a running log, so this function decides them here and does not
    // leave them to the caller. Both get an empty proof, and
    // `verify_consistency` accepts an empty proof for exactly these two.
    //
    // first = 0: the empty tree is the start of every tree. There is nothing to
    // prove and nothing to send.
    //
    // first = second: the same tree twice. The RFC's own base case
    // SUBPROOF(m, D_m, true) = {} already gives the empty list. The line below
    // only says so out loud.
    if first == 0 || first == second {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    walk_proof(nodes, first, 0, size, true, &mut out).map_err(TreeError::Source)?;
    Ok(out)
}

/// The nodes that appending `leaf` to a tree of `nodes.tree_size()` leaves
/// makes, as `(level, index, hash)`, in the order they must be stored.
///
/// Always the new leaf itself, plus one node for each perfect subtree the
/// append fills. That count is the number of trailing 1 bits in the new leaf's
/// index: under one on average, and `log2(n)` on the worst single append. The
/// append reads nothing already stored except the children of those new nodes,
/// and writes over nothing already stored. That is what makes an append cheap,
/// whether the nodes are vectors in memory or rows in a database.
pub fn append_nodes<S: NodeSource + ?Sized>(
    nodes: &S,
    leaf: Hash,
) -> Result<Vec<(u32, u64, Hash)>, S::Error> {
    let size = nodes.tree_size();
    let numbering = appended_at(size);
    let mut made: Vec<(u32, u64, Hash)> = Vec::with_capacity(numbering.len());
    made.push((0, size, leaf));
    // How many nodes stand at the level below the one being made, once this
    // append is stored. The two that have just filled a perfect subtree are the
    // last two of them.
    let mut count = size + 1;
    for &(level, index) in &numbering[1..] {
        let child = level - 1;
        let left = made_or_stored(nodes, &made, child, count - 2)?;
        let right = made_or_stored(nodes, &made, child, count - 1)?;
        made.push((level, index, node_hash(&left, &right)));
        count /= 2;
    }
    Ok(made)
}

/// Which nodes appending the leaf at `leaf_index` makes, as `(level, index)`,
/// in the order they must be stored.
///
/// Numbering and no hashing. `append_nodes` above walks this list and fills in
/// the hashes. A reader that checks a log's stored nodes against its own
/// messages walks the same list, to say which nodes the log must be holding.
/// The numbering is defined once, so the two cannot disagree about which node
/// belongs to which message.
///
/// Always the new leaf, plus one node for each perfect subtree the append
/// fills. That count is the number of trailing 1 bits in `leaf_index`.
///
/// Leaf 3 is `0b11`, so it has two trailing 1 bits and the append makes two
/// nodes above the leaf. Leaf 7 is `0b111` and makes three. Leaf 2 is `0b10`
/// and makes none.
///
/// The loop below counts the same thing from the other end: it halves
/// `leaf_index + 1` while that is even, and `leaf_index + 1` is even exactly
/// as often as `leaf_index` ends in a 1.
///
/// This line said `leaf_index + 1` until it was checked against the loop. That
/// is 0 for every one of the three examples above, and the module doc and
/// `append_nodes` both already stated it correctly, so the file disagreed with
/// itself in the one place a reader checks hardest.
pub fn appended_at(leaf_index: u64) -> Vec<(u32, u64)> {
    let mut made = Vec::with_capacity(4);
    made.push((0u32, leaf_index));
    let mut level = 0u32;
    // An even count at a level means the last two nodes there have just filled
    // a perfect subtree, so they now have a parent. The loop stops at the first
    // odd count.
    let mut count = leaf_index + 1;
    while count.is_multiple_of(2) {
        made.push((level + 1, count / 2 - 1));
        level += 1;
        count /= 2;
    }
    made
}

/// How many nodes a tree of `leaves` leaves holds: every leaf, plus one node
/// per perfect subtree. That is one node per leaf, less one per set bit of
/// `leaves`.
///
/// A reader that has this number counts the nodes a log served, and then knows
/// whether any node is missing. The count also catches a reader that is
/// pointing at nothing: an empty store gives zero, and this gives
/// `2n - popcount(n)`, where `popcount` is the number of 1 bits in `n`.
pub fn nodes_in(leaves: u64) -> u64 {
    2 * leaves - leaves.count_ones() as u64
}

/// The leaf that fills the perfect subtree at `(level, index)`, as a `u128` so
/// a level near 64 cannot wrap.
///
/// The node covers leaves `index * 2^level` to `(index+1) * 2^level - 1`. So a
/// reader that has read `upto` leaves can check this node when that last leaf
/// is one of them, and only then.
fn last_leaf_under(level: u32, index: u64) -> u128 {
    ((index as u128 + 1) << level) - 1
}

/// Compares the nodes a log stored against the nodes its own entries make.
///
/// `ours` is what the entries make. `stored` is what the log holds. Both are
/// keyed by `(level, index)`, so neither side has to arrive in any order. The
/// answer is one sentence per fault, and is empty when the two agree.
///
/// `leaves` is the range of entries this comparison covers, and a node belongs
/// to the entry that filled it. Any node outside the range is left alone. That
/// is two rules in one:
///
/// - a log goes on publishing while somebody reads it. So a node that covers an
///   entry past the end of the range is a node for an entry the reader never
///   saw.
/// - a reader that compares page by page holds only that page's nodes. So a
///   node from an earlier page is not one it can say anything about.
///
/// The rule lives here and not in either side's storage. A reader with the file
/// open and a reader with only HTTP then apply the same rule.
///
/// Three faults, and each one names the node:
///
/// - a node the log holds that its own entries do not make. The tree and the
///   history disagree. Every inclusion proof that touches that node fails
///   against the root the log signs.
/// - a node the entries make that the log does not hold. The log cannot produce
///   the proofs that need it.
/// - a node the log holds at a position its entries never fill.
pub fn compare_nodes(
    ours: &BTreeMap<(u32, u64), Hash>,
    stored: &BTreeMap<(u32, u64), Hash>,
    leaves: std::ops::Range<u64>,
) -> Vec<String> {
    let covered = |level: u32, index: u64| {
        let leaf = last_leaf_under(level, index);
        leaf >= leaves.start as u128 && leaf < leaves.end as u128
    };
    let mut faults = Vec::new();
    for (&(level, index), our_hash) in ours {
        if !covered(level, index) {
            continue;
        }
        match stored.get(&(level, index)) {
            Some(theirs) if theirs == our_hash => {}
            Some(theirs) => faults.push(format!(
                "the node at level {} index {} is {}, and the log's own messages make {} there. \
                 Every inclusion proof that reads that node lands on a root the log did not sign",
                level,
                index,
                hex(theirs),
                hex(our_hash)
            )),
            None => faults.push(format!(
                "the log holds no node at level {} index {}, and a tree over its own messages has \
                 one there. The proofs that need it cannot be produced",
                level, index
            )),
        }
    }
    for &(level, index) in stored.keys() {
        if covered(level, index) && !ours.contains_key(&(level, index)) {
            faults.push(format!(
                "the log holds a node at level {} index {} that a tree over its own messages does \
                 not have",
                level, index
            ));
        }
    }
    faults
}

/// Hex for a failure message. This module has its own copy and does not import
/// the repository's `to_hex`, because it imports nothing from the repository.
fn hex(bytes: &Hash) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A node this append has just made, or one that storage already holds.
///
/// The right-hand child of every parent an append makes is a node from this
/// same append, and the caller has not stored it yet. The search covers at most
/// 64 entries.
fn made_or_stored<S: NodeSource + ?Sized>(
    nodes: &S,
    made: &[(u32, u64, Hash)],
    level: u32,
    index: u64,
) -> Result<Hash, S::Error> {
    match made
        .iter()
        .rev()
        .find(|(at_level, at_index, _)| *at_level == level && *at_index == index)
    {
        Some((_, _, hash)) => Ok(*hash),
        None => nodes.node(level, index),
    }
}

/// Turns a requested `tree_size` into an index bound. It refuses a size this
/// tree has not reached.
fn checked_size<S: NodeSource + ?Sized>(nodes: &S, tree_size: u64) -> Result<u64, ProofError> {
    let have = nodes.tree_size();
    if tree_size > have {
        return Err(ProofError::UnknownTreeSize { tree_size, have });
    }
    Ok(tree_size)
}

/// `MTH(D[lo:hi])`, RFC 9162 section 2.1.1.
fn subtree_hash<S: NodeSource + ?Sized>(nodes: &S, lo: u64, hi: u64) -> Result<Hash, S::Error> {
    debug_assert!(lo < hi, "MTH of an empty range is only defined at the root");
    let size = hi - lo;
    // A range is a perfect subtree when its length is a power of two and it
    // starts on a multiple of that length. Its hash is stored, so this costs no
    // hashing at all.
    if size.is_power_of_two() && lo.is_multiple_of(size) {
        let level = size.trailing_zeros();
        return nodes.node(level, lo >> level);
    }
    // Otherwise this node is on the right edge, where the subtree is not full.
    // Split it the way the RFC defines and recurse.
    let k = split_point(size);
    // Every range this module asks for has `lo` on a multiple of `k`. So the
    // left half below is perfect and aligned, and comes straight out of
    // storage. That is what keeps this to log2(n) node hashes, instead of
    // hashing the whole subtree again. The recursion stays correct for any
    // range, so the check below is a debug check on the cost and not on the
    // answer. A new caller that trips it still gets the right hash, by an
    // O(size) route.
    debug_assert_eq!(lo % k, 0, "unaligned range {lo}..{hi} costs O(size)");
    Ok(node_hash(
        &subtree_hash(nodes, lo, lo + k)?,
        &subtree_hash(nodes, lo + k, hi)?,
    ))
}

/// `PATH(m, D[lo:hi])`, RFC 9162 section 2.1.3.1, appended to `out`.
///
/// `m` counts from `lo`, which matches the RFC's `PATH(m - k, D[k:n])`.
fn walk_path<S: NodeSource + ?Sized>(
    nodes: &S,
    m: u64,
    lo: u64,
    hi: u64,
    out: &mut Vec<Hash>,
) -> Result<(), S::Error> {
    let n = hi - lo;
    // PATH(0, {d[0]}) = {}
    if n == 1 {
        return Ok(());
    }
    let k = split_point(n);
    if m < k {
        // PATH(m, D_n) = PATH(m, D[0:k]) : MTH(D[k:n])
        walk_path(nodes, m, lo, lo + k, out)?;
        out.push(subtree_hash(nodes, lo + k, hi)?);
    } else {
        // PATH(m, D_n) = PATH(m - k, D[k:n]) : MTH(D[0:k])
        walk_path(nodes, m - k, lo + k, hi, out)?;
        out.push(subtree_hash(nodes, lo, lo + k)?);
    }
    Ok(())
}

/// `SUBPROOF(m, D[lo:hi], complete)`, RFC 9162 section 2.1.4.1, appended to
/// `out`.
///
/// `complete` is the RFC's boolean. It is true while `D[0:m]` is still a whole
/// subtree of the range being walked. The verifier then already knows that
/// subtree's hash, so the log must not send it.
fn walk_proof<S: NodeSource + ?Sized>(
    nodes: &S,
    m: u64,
    lo: u64,
    hi: u64,
    complete: bool,
    out: &mut Vec<Hash>,
) -> Result<(), S::Error> {
    let n = hi - lo;
    if m == n {
        // SUBPROOF(m, D_m, true) = {}
        // SUBPROOF(m, D_m, false) = {MTH(D_m)}
        if !complete {
            out.push(subtree_hash(nodes, lo, hi)?);
        }
        return Ok(());
    }
    let k = split_point(n);
    if m <= k {
        // The right subtree is in the newer tree only. Prove the left one is
        // consistent, and send the hash of the right one.
        // SUBPROOF(m, D_n, b) = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])
        walk_proof(nodes, m, lo, lo + k, complete, out)?;
        out.push(subtree_hash(nodes, lo + k, hi)?);
    } else {
        // The left subtree is the same in both trees. Prove the right one is
        // consistent, and send the hash of the left one.
        // SUBPROOF(m, D_n, b) = SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k])
        walk_proof(nodes, m - k, lo + k, hi, false, out)?;
        out.push(subtree_hash(nodes, lo, lo + k)?);
    }
    Ok(())
}

/// A Merkle tree over an append-only list of entries.
///
/// It stores hashes, never the entries. The bytes of a message live in the
/// log. What this holds is one hash that covers them.
///
/// The layout is one vector per level. `levels[0]` is the leaf hashes in
/// order. `levels[d][i]` is `MTH(D[i * 2^d : (i+1) * 2^d])`, so every stored
/// node is the root of a *perfect* subtree. A perfect subtree never changes
/// once it is full, which is what makes an append cheap. The nodes on the
/// tree's right edge, the ones that do change on every append, are not stored.
/// `subtree_hash` computes them when they are needed.
///
/// This is `NodeSource` over vectors. Every method below calls the free
/// function that does the same job, with the vectors passed in. It costs 64
/// bytes per leaf and holds them for as long as the tree is alive. So it fits a
/// tree whose size is bounded by something: a test, a verifier that checks one
/// history, a log that is rebuilt from its entries on every start. A log that
/// only grows wants its nodes somewhere that is not RAM.
#[derive(Debug, Clone, Default)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl NodeSource for MerkleTree {
    /// Reading a vector cannot fail. What can happen is a request for a node
    /// this tree never stored. That is a bug in the caller. The index panics,
    /// and the bug does not turn into a value.
    type Error = Infallible;

    fn tree_size(&self) -> u64 {
        self.len()
    }

    fn node(&self, level: u32, index: u64) -> Result<Hash, Infallible> {
        Ok(self.levels[level as usize][index as usize])
    }
}

impl MerkleTree {
    /// An empty tree. Its root is `empty_root()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// A tree over entries already in hand.
    pub fn from_entries<E: AsRef<[u8]>>(entries: &[E]) -> Self {
        let mut tree = Self::new();
        for entry in entries {
            tree.push_entry(entry.as_ref());
        }
        tree
    }

    /// Appends one entry. Returns its leaf index.
    pub fn push_entry(&mut self, entry: &[u8]) -> u64 {
        self.push_leaf_hash(leaf_hash(entry))
    }

    /// Appends one leaf hash the caller computed. Returns its leaf index.
    ///
    /// The caller must have used `leaf_hash`. Pass an internal node hash here
    /// and the tree covers something nobody submitted. That is the attack
    /// `LEAF_PREFIX` stops from the *outside*. From the inside it is still the
    /// caller's job.
    pub fn push_leaf_hash(&mut self, leaf: Hash) -> u64 {
        let index = self.len();
        let made = append_nodes(self, leaf).unwrap_or_else(|never| match never {});
        for (level, at, hash) in made {
            let level = level as usize;
            if self.levels.len() == level {
                self.levels.push(Vec::new());
            }
            debug_assert_eq!(
                self.levels[level].len() as u64,
                at,
                "append_nodes numbered a node that is not the next one at its level"
            );
            self.levels[level].push(hash);
        }
        index
    }

    /// The number of leaves. RFC 9162 calls this `tree_size`.
    pub fn len(&self) -> u64 {
        self.levels.first().map_or(0, Vec::len) as u64
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The leaf hash at `index`, or `None` past the end.
    pub fn leaf(&self, index: u64) -> Option<Hash> {
        let index = usize::try_from(index).ok()?;
        self.levels.first()?.get(index).copied()
    }

    /// `MTH` over every leaf.
    pub fn root(&self) -> Hash {
        mth(self, self.len())
            .map_err(TreeError::certain)
            .expect("a tree can always hash the leaves it holds")
    }

    /// `MTH` over the first `tree_size` leaves: the root this tree published
    /// when it was that size.
    ///
    /// A caller always asks for a proof against a stated tree size, because the
    /// client holds a signed head from some earlier moment. Without this method
    /// the client could only ever verify against the newest root.
    pub fn root_at(&self, tree_size: u64) -> Result<Hash, ProofError> {
        mth(self, tree_size).map_err(TreeError::certain)
    }

    /// `PATH(leaf_index, D[0:tree_size])`, RFC 9162 section 2.1.3.1.
    ///
    /// The list starts at the leaf's sibling and goes up, which is the order
    /// `verify_inclusion` reads it in.
    pub fn inclusion_proof(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> Result<Vec<Hash>, ProofError> {
        path(self, leaf_index, tree_size).map_err(TreeError::certain)
    }

    /// `PROOF(first, D[0:second])`, RFC 9162 section 2.1.4.1.
    ///
    /// It proves the tree at size `first` is the start of the tree at size
    /// `second`. Entries were appended. Nothing was changed, removed or moved.
    pub fn consistency_proof(&self, first: u64, second: u64) -> Result<Vec<Hash>, ProofError> {
        proof(self, first, second).map_err(TreeError::certain)
    }
}

/// The tree's right edge, and the roots a tool asked it to keep.
///
/// `MerkleTree` above holds every node, which is 64 bytes a leaf. A tool does
/// not need them when it reads a history once and only has to answer "the root
/// over the first `n` messages is this", for a few `n` it already knows. The
/// root of a tree of any size is built from the perfect subtrees that stand on
/// its right edge, one per set bit of the size. So `RootFold` keeps those and
/// nothing else: at most 64 hashes, whatever the history is. The checker and
/// the audit both walk a history they never hold, and this is the tree in the
/// same shape.
///
/// The caller gives the sizes before the walk, because the caller knows them
/// before the walk. An anchor names the size it commits to, and a signed tree
/// head names its own. `RootFold` takes each root as it passes that size, and
/// keeps it from then on. So a hundred anchors cost a hundred lookups, and not
/// a hundred passes over the history.
///
/// This stores nodes and hashes nothing itself. Every hash still comes from
/// `append_nodes` and `mth`. So it is the same RFC 9162 arithmetic the
/// sequencer runs, over storage of a third shape.
#[derive(Debug, Clone)]
pub struct RootFold {
    /// The perfect subtrees on the right edge, largest first. At most one per
    /// level, so at most 64 of them.
    edge: Vec<(u32, u64, Hash)>,
    leaves: u64,
    /// The sizes a root was asked for, ascending and with no repeats.
    wanted: Vec<u64>,
    /// The root at each of those sizes `RootFold` has reached.
    roots: BTreeMap<u64, Hash>,
}

impl NodeSource for RootFold {
    /// Reading a vector cannot fail. A request for a node that is not on this
    /// tree's right edge is a bug in the caller. It panics and does not turn
    /// into a value, because `mth` at the current size and `append_nodes` ask
    /// for nothing else.
    type Error = Infallible;

    fn tree_size(&self) -> u64 {
        self.leaves
    }

    fn node(&self, level: u32, index: u64) -> Result<Hash, Infallible> {
        match self
            .edge
            .iter()
            .find(|(at_level, at_index, _)| *at_level == level && *at_index == index)
        {
            Some((_, _, hash)) => Ok(*hash),
            None => panic!(
                "a root fold holds only its right edge and was asked for the node at level \
                 {level}, index {index} of a tree of {} leaves",
                self.leaves
            ),
        }
    }
}

impl RootFold {
    /// A `RootFold` that will keep its root at each of `sizes`.
    ///
    /// A size it never reaches leaves no root, and `root_at` then answers
    /// `None`. That means the history stopped short of what something committed
    /// to. The caller decides what that means.
    pub fn new(sizes: &[u64]) -> Self {
        let mut wanted = sizes.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        let mut fold = RootFold {
            edge: Vec::new(),
            leaves: 0,
            wanted,
            roots: BTreeMap::new(),
        };
        // Size 0 is the empty tree, and no entry will ever arrive to record it.
        if fold.wanted.first() == Some(&0) {
            fold.roots.insert(0, empty_root());
        }
        fold
    }

    /// Adds one entry, exactly as it was served.
    ///
    /// It returns the nodes this entry made. Those are exactly the nodes a log
    /// that holds this history must have stored for it. A caller that only
    /// wants the root drops them.
    pub fn push_entry(&mut self, entry: &[u8]) -> Vec<(u32, u64, Hash)> {
        self.push_leaf_hash(leaf_hash(entry))
    }

    /// Adds one leaf hash the caller computed. The warning on
    /// `MerkleTree::push_leaf_hash` applies here for the same reason.
    pub fn push_leaf_hash(&mut self, leaf: Hash) -> Vec<(u32, u64, Hash)> {
        let made = append_nodes(self, leaf).unwrap_or_else(|never| match never {});
        // An append fills zero or more perfect subtrees. The last node it makes
        // is the only one still on the right edge afterwards. Every node below
        // that level went into it. So the edge drops those levels and gains
        // this one node, and it stays under 64 entries.
        let (top_level, top_index, top_hash) =
            *made.last().expect("an append makes at least the leaf");
        self.edge.retain(|(level, _, _)| *level > top_level);
        self.edge.push((top_level, top_index, top_hash));
        self.leaves += 1;
        if self.wanted.binary_search(&self.leaves).is_ok() {
            let root = match mth(self, self.leaves) {
                Ok(root) => root,
                Err(TreeError::Proof(e)) => {
                    unreachable!("a fold refused the size it has reached: {}", e)
                }
                Err(TreeError::Source(never)) => match never {},
            };
            self.roots.insert(self.leaves, root);
        }
        made
    }

    /// The number of entries added so far. RFC 9162 calls this `tree_size`.
    pub fn len(&self) -> u64 {
        self.leaves
    }

    pub fn is_empty(&self) -> bool {
        self.leaves == 0
    }

    /// The root over the first `tree_size` entries. It is `None` when nobody
    /// asked for that size, or when this `RootFold` never reached it.
    pub fn root_at(&self, tree_size: u64) -> Option<Hash> {
        self.roots.get(&tree_size).copied()
    }
}

/// Verifies an inclusion proof. This is RFC 9162 section 2.1.3.2, copied step
/// by step. The step numbers below are the RFC's.
///
/// `leaf_hash` must be `HASH(0x00 || entry)`. Prefer `verify_entry_inclusion`.
/// It takes the entry bytes, so no caller can hand it an internal node by
/// mistake.
///
/// It returns true only when the log has proven that this leaf sits at
/// `leaf_index`, in the tree of size `tree_size` whose root is `root_hash`.
///
/// Here is one thing the RFC's algorithm does not do, on purpose. It never
/// hashes `tree_size`. The size only decides the shape of the climb up the
/// tree. So two nearby sizes that give the same shape accept the same proof.
/// What ties a size to a root is the signature over the tree head, not this
/// function. `root_hash` is the trusted input here. A caller that pairs it with
/// a `tree_size` the log never signed for it makes an error this function
/// cannot catch.
#[must_use]
pub fn verify_inclusion(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: &Hash,
    inclusion_path: &[Hash],
    root_hash: &Hash,
) -> bool {
    // Step 1. This check is also why tree_size - 1 below cannot underflow. A
    // tree_size of 0 leaves no index that passes it.
    if leaf_index >= tree_size {
        return false;
    }
    // Step 2. fnode walks the leaf's index up the tree. snode walks the last
    // leaf's index up beside it. snode at 0 means the climb reached the root.
    // The low bit of fnode says which side the next sibling is on.
    let mut fnode = leaf_index;
    let mut snode = tree_size - 1;
    // Step 3.
    let mut r = *leaf_hash;
    // Step 4.
    for p in inclusion_path {
        // Step 4(a). A proof longer than the path to the root is refused here.
        // The extra nodes are not hashed into the answer without a word.
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            // Step 4(b)(i). The sibling is on the left.
            r = node_hash(p, &r);
            // Step 4(b)(ii). fnode == snode with an even fnode means the climb
            // is on the tree's right edge, where the subtree is not full. The
            // node just computed sits more than one level above its children.
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            // Step 4(b), "Otherwise", (i). The sibling is on the right.
            r = node_hash(&r, p);
        }
        // Step 4(c).
        fnode >>= 1;
        snode >>= 1;
    }
    // Step 5. snode != 0 means the proof ran out before the root. So a short
    // proof is refused too.
    snode == 0 && r == *root_hash
}

/// Verifies an inclusion proof for the bytes of an entry.
///
/// This is the call an application should make. It adds `LEAF_PREFIX` itself,
/// so there is no way to pass an internal node hash in where a leaf belongs.
#[must_use]
pub fn verify_entry_inclusion(
    leaf_index: u64,
    tree_size: u64,
    entry: &[u8],
    inclusion_path: &[Hash],
    root_hash: &Hash,
) -> bool {
    verify_inclusion(
        leaf_index,
        tree_size,
        &leaf_hash(entry),
        inclusion_path,
        root_hash,
    )
}

/// Verifies a consistency proof: the tree of size `first` with root
/// `first_hash` is the start of the tree of size `second` with root
/// `second_hash`. This is RFC 9162 section 2.1.4.2, copied step by step.
///
/// The RFC covers `0 < first < second`. The two sizes outside that range are
/// decided before the RFC steps begin, and are marked below.
#[must_use]
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_hash: &Hash,
    second_hash: &Hash,
    consistency_path: &[Hash],
) -> bool {
    // Outside the RFC. A consistency proof only runs forwards.
    if first > second {
        return false;
    }
    // Outside the RFC. The empty tree is the start of every tree, so there is
    // nothing to prove. But first_hash must really be the empty tree's root.
    // Otherwise the caller claims that something else is empty. This function
    // does not check second_hash, because nothing here can check it: "the empty
    // tree is the start of X" is true whatever X is. To answer anything about
    // second_hash would be to claim a check this function never made.
    if first == 0 {
        return consistency_path.is_empty() && *first_hash == empty_root();
    }
    // Outside the RFC. The same tree twice: nothing to prove, but the two
    // heads must be the same head.
    if first == second {
        return consistency_path.is_empty() && first_hash == second_hash;
    }

    // Step 1. From here on the RFC applies unchanged.
    if consistency_path.is_empty() {
        return false;
    }
    // Step 2. When `first` is a power of two, D[0:first] is itself a perfect
    // subtree of the second tree. The log does not send that node, because the
    // verifier already holds it as first_hash. This copies at most
    // log2(second) + 2 hashes.
    let mut path: Vec<Hash> = Vec::with_capacity(consistency_path.len() + 1);
    if first.is_power_of_two() {
        path.push(*first_hash);
    }
    path.extend_from_slice(consistency_path);

    // Step 3.
    let mut fnode = first - 1;
    let mut snode = second - 1;
    // Step 4. Climb out of the first tree's own right edge, before the two
    // trees are compared.
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    // Step 5. fr rebuilds the old root and sr rebuilds the new one. Both start
    // from the same node. That shared start is what makes this one proof about
    // both trees at once.
    let mut fr = path[0];
    let mut sr = path[0];
    // Step 6.
    for c in &path[1..] {
        // Step 6(a).
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            // Step 6(b)(i) and 6(b)(ii). This node is in both trees, so it goes
            // into both rebuilds.
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            // Step 6(b)(iii).
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            // Step 6(b), "Otherwise", (i). This node covers entries the first
            // tree did not have, so it goes into the new root only.
            sr = node_hash(&sr, c);
        }
        // Step 6(c).
        fnode >>= 1;
        snode >>= 1;
    }
    // Step 7.
    snode == 0 && fr == *first_hash && sr == *second_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(i: usize) -> Vec<u8> {
        format!("entry-{i}").into_bytes()
    }

    fn entries(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(entry).collect()
    }

    /// Three digests anyone can reproduce with `sha256sum`, with no Merkle
    /// code in the way. They pin the two prefix bytes and the empty tree to
    /// values that come from outside this file.
    #[test]
    fn hashes_match_values_reproducible_outside_this_code() {
        // printf '' | sha256sum
        assert_eq!(
            hex(&empty_root()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // printf '\x00' | sha256sum: the leaf prefix, with an empty entry.
        assert_eq!(
            hex(&leaf_hash(b"")),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
        // printf '\x00\x00' | sha256sum: the leaf prefix, entry 0x00.
        assert_eq!(
            hex(&leaf_hash(&[0x00])),
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"
        );
    }

    /// The seven-leaf tree drawn in RFC 9162 section 2.1.5.
    ///
    /// ```text
    ///             hash
    ///            /    \
    ///           k      l
    ///          / \    / \
    ///         g   h  i   j
    ///        /|  /|  /|  |
    ///       a b c d e f  d6
    ///       | | | | | |
    ///      d0 d1 d2 d3 d4 d5
    /// ```
    ///
    /// This struct builds the labels from `leaf_hash` and `node_hash` directly,
    /// and not from `MerkleTree`. The tree under test then has to agree with
    /// them. So this checks the tree against the RFC's structure, and not
    /// against itself.
    struct RfcExample {
        entries: Vec<Vec<u8>>,
        a: Hash,
        b: Hash,
        c: Hash,
        d: Hash,
        e: Hash,
        f: Hash,
        g: Hash,
        h: Hash,
        i: Hash,
        j: Hash,
        k: Hash,
        l: Hash,
        root: Hash,
    }

    impl RfcExample {
        fn build() -> Self {
            let entries = entries(7);
            let a = leaf_hash(&entries[0]);
            let b = leaf_hash(&entries[1]);
            let c = leaf_hash(&entries[2]);
            let d = leaf_hash(&entries[3]);
            let e = leaf_hash(&entries[4]);
            let f = leaf_hash(&entries[5]);
            // j has one child in the diagram, so j is d6's leaf hash. MTH of a
            // one-element list is that element's leaf hash.
            let j = leaf_hash(&entries[6]);
            let g = node_hash(&a, &b);
            let h = node_hash(&c, &d);
            let i = node_hash(&e, &f);
            let k = node_hash(&g, &h);
            let l = node_hash(&i, &j);
            let root = node_hash(&k, &l);
            Self {
                entries,
                a,
                b,
                c,
                d,
                e,
                f,
                g,
                h,
                i,
                j,
                k,
                l,
                root,
            }
        }

        fn tree(&self) -> MerkleTree {
            MerkleTree::from_entries(&self.entries)
        }
    }

    #[test]
    fn rfc_example_root_and_intermediate_nodes() {
        let x = RfcExample::build();
        let tree = x.tree();
        assert_eq!(tree.len(), 7);
        assert_eq!(tree.root(), x.root, "root of D[0:7]");

        // The three earlier roots the RFC draws in its incremental example.
        assert_eq!(tree.root_at(3).unwrap(), node_hash(&x.g, &x.c), "hash0");
        assert_eq!(tree.root_at(4).unwrap(), x.k, "hash1 = k");
        assert_eq!(tree.root_at(6).unwrap(), node_hash(&x.k, &x.i), "hash2");

        // The same four roots, as fixed digests. A separate implementation of
        // the same RFC produced them: Python hashlib, with no code from this
        // file. The RFC publishes no byte values for d0..d6, so these digests
        // are pinned here and are not quoted from it. Reproduce them with:
        //
        //   lh(b) = sha256(b"\x00" + b);  nh(l, r) = sha256(b"\x01" + l + r)
        //   entries "entry-0" .. "entry-6"
        //   g=nh(a,b) h=nh(c,d) i=nh(e,f) j=lh(d6) k=nh(g,h) l=nh(i,j)
        //
        // Delete the 0x00 and 0x01 prefixes and everything above this comment
        // still passes. Deleting them changes every digest and leaves the
        // tree's shape alone. These four lines and
        // `hashes_match_values_reproducible_outside_this_code` are the only
        // things that notice.
        assert_eq!(
            hex(&tree.root_at(3).unwrap()),
            "a64bf26e09128f6fe2fe6f8b2d8c801e166b57c047a7cd9b2b809e7a96a2f1cb"
        );
        assert_eq!(
            hex(&tree.root_at(4).unwrap()),
            "256b9e8825e5d370a4ae005d0901ea291977e2927f5cf8e3e72660dd09519edb"
        );
        assert_eq!(
            hex(&tree.root_at(6).unwrap()),
            "08783a523d260480de2ccf0976d7411ed8adaf06f75d5a5de2254c58f968eca9"
        );
        assert_eq!(
            hex(&tree.root()),
            "9139601cc1ca8ab2a7a0c2c134c04845f2b1ba549a83d6c845cfcda439cc585d"
        );

        // Every leaf hash is where the diagram puts it. The leaf hash of d6 is
        // j, because the diagram gives j a single child, and MTH of a
        // one-element list is that element's leaf hash.
        let leaves = [x.a, x.b, x.c, x.d, x.e, x.f, x.j];
        for (index, want) in leaves.iter().enumerate() {
            assert_eq!(tree.leaf(index as u64), Some(*want), "leaf {index}");
        }
        assert_eq!(tree.leaf(7), None);
    }

    /// The four known-answer inclusion proofs of RFC 9162 section 2.1.5.
    #[test]
    fn rfc_example_inclusion_proofs() {
        let x = RfcExample::build();
        let tree = x.tree();
        let cases: [(u64, Vec<Hash>); 4] = [
            (0, vec![x.b, x.h, x.l]),
            (3, vec![x.c, x.g, x.l]),
            (4, vec![x.f, x.j, x.k]),
            (6, vec![x.i, x.k]),
        ];
        for (leaf, expected) in cases {
            let proof = tree.inclusion_proof(leaf, 7).unwrap();
            assert_eq!(
                proof.iter().map(hex).collect::<Vec<_>>(),
                expected.iter().map(hex).collect::<Vec<_>>(),
                "inclusion proof for d{leaf}"
            );
            assert!(verify_entry_inclusion(
                leaf,
                7,
                &x.entries[leaf as usize],
                &proof,
                &x.root
            ));
        }
    }

    /// The three known-answer consistency proofs of RFC 9162 section 2.1.5.
    #[test]
    fn rfc_example_consistency_proofs() {
        let x = RfcExample::build();
        let tree = x.tree();
        let hash0 = node_hash(&x.g, &x.c);
        let hash1 = x.k;
        let hash2 = node_hash(&x.k, &x.i);
        let cases: [(u64, Hash, Vec<Hash>); 3] = [
            (3, hash0, vec![x.c, x.d, x.g, x.l]),
            (4, hash1, vec![x.l]),
            (6, hash2, vec![x.i, x.j, x.k]),
        ];
        for (first, first_hash, expected) in cases {
            let proof = tree.consistency_proof(first, 7).unwrap();
            assert_eq!(
                proof.iter().map(hex).collect::<Vec<_>>(),
                expected.iter().map(hex).collect::<Vec<_>>(),
                "consistency proof {first} -> 7"
            );
            assert!(verify_consistency(first, 7, &first_hash, &x.root, &proof));
        }
    }

    /// The RFC gives sizes 0 and 1 their own equations. So those two sizes are
    /// the ones most likely to get a special case here that panics.
    #[test]
    fn empty_and_single_entry_trees() {
        let empty = MerkleTree::new();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.root(), empty_root());
        assert_eq!(empty.root_at(0).unwrap(), empty_root());
        assert_eq!(empty.leaf(0), None);
        assert!(empty.inclusion_proof(0, 0).is_err());
        assert_eq!(empty.consistency_proof(0, 0).unwrap(), Vec::<Hash>::new());
        assert!(verify_consistency(0, 0, &empty_root(), &empty_root(), &[]));

        let mut one = MerkleTree::new();
        assert_eq!(one.push_entry(b"only"), 0);
        assert_eq!(one.root(), leaf_hash(b"only"));
        // PATH(0, {d0}) = {}
        let proof = one.inclusion_proof(0, 1).unwrap();
        assert!(proof.is_empty());
        assert!(verify_entry_inclusion(0, 1, b"only", &proof, &one.root()));
        assert!(one.inclusion_proof(1, 1).is_err());
        assert!(one.inclusion_proof(0, 2).is_err());
        // The empty tree is the start of the one-entry tree, with no proof.
        assert_eq!(one.consistency_proof(0, 1).unwrap(), Vec::<Hash>::new());
        assert!(verify_consistency(0, 1, &empty_root(), &one.root(), &[]));
    }

    /// Every leaf of every tree size up to `SWEEP` has an inclusion proof that
    /// verifies against that size's root.
    const SWEEP: u64 = 1024;

    #[test]
    fn every_leaf_of_every_size_has_a_proof_that_verifies() {
        let data = entries(SWEEP as usize);
        let tree = MerkleTree::from_entries(&data);
        for size in 0..=SWEEP {
            let root = tree.root_at(size).unwrap();
            for leaf in 0..size {
                let proof = tree.inclusion_proof(leaf, size).unwrap();
                assert!(
                    proof.len() as u64 <= 64 - (size - 1).leading_zeros() as u64,
                    "proof for leaf {leaf} of size {size} is longer than ceil(log2)"
                );
                assert!(
                    verify_entry_inclusion(leaf, size, &data[leaf as usize], &proof, &root),
                    "leaf {leaf} of size {size}"
                );
            }
        }
    }

    #[test]
    fn every_pair_of_sizes_has_a_consistency_proof_that_verifies() {
        let data = entries(SWEEP as usize);
        let tree = MerkleTree::from_entries(&data);
        let roots: Vec<Hash> = (0..=SWEEP).map(|n| tree.root_at(n).unwrap()).collect();
        for second in 0..=SWEEP {
            for first in 0..=second {
                let proof = tree.consistency_proof(first, second).unwrap();
                assert!(
                    verify_consistency(
                        first,
                        second,
                        &roots[first as usize],
                        &roots[second as usize],
                        &proof,
                    ),
                    "consistency {first} -> {second}"
                );
            }
        }
    }

    /// Change any byte of any entry and that entry's inclusion proof fails.
    /// This is the whole reason the log is hashed at all.
    #[test]
    fn changing_one_byte_of_an_entry_breaks_its_proof() {
        for size in 1u64..=130 {
            let data = entries(size as usize);
            let tree = MerkleTree::from_entries(&data);
            let root = tree.root();
            for leaf in 0..size {
                let proof = tree.inclusion_proof(leaf, size).unwrap();
                let original = &data[leaf as usize];
                for byte in 0..original.len() {
                    let mut tampered = original.clone();
                    tampered[byte] ^= 0x01;
                    assert!(
                        !verify_entry_inclusion(leaf, size, &tampered, &proof, &root),
                        "size {size}, leaf {leaf}, byte {byte} was accepted after a flip"
                    );
                }
            }
        }
    }

    /// A proof from one tree does not verify against another tree's root. That
    /// holds even when the two trees are the same size and differ in one
    /// entry.
    #[test]
    fn a_proof_does_not_carry_to_a_different_tree() {
        for size in 1u64..=66 {
            let mine = entries(size as usize);
            let mut theirs = mine.clone();
            theirs[(size - 1) as usize] = b"different".to_vec();
            let my_tree = MerkleTree::from_entries(&mine);
            let their_tree = MerkleTree::from_entries(&theirs);
            let their_root = their_tree.root();
            assert_ne!(my_tree.root(), their_root);
            for leaf in 0..size {
                let proof = my_tree.inclusion_proof(leaf, size).unwrap();
                assert!(
                    !verify_entry_inclusion(leaf, size, &mine[leaf as usize], &proof, &their_root),
                    "size {size}, leaf {leaf} crossed trees"
                );
            }
            // And a consistency proof from one history is not evidence about
            // the other.
            if size >= 2 {
                let proof = my_tree.consistency_proof(size - 1, size).unwrap();
                assert!(!verify_consistency(
                    size - 1,
                    size,
                    &my_tree.root_at(size - 1).unwrap(),
                    &their_root,
                    &proof,
                ));
            }
        }
    }

    /// A proof must be refused when it has the right nodes but the wrong
    /// length, or when it points at the wrong leaf. The RFC's `sn = 0` checks
    /// and its final `sn = 0` comparison exist for these cases.
    #[test]
    fn malformed_proofs_are_refused() {
        let size = 7u64;
        let data = entries(size as usize);
        let tree = MerkleTree::from_entries(&data);
        let root = tree.root();
        let proof = tree.inclusion_proof(0, size).unwrap();

        assert!(verify_entry_inclusion(0, size, &data[0], &proof, &root));
        // Too short.
        assert!(!verify_entry_inclusion(
            0,
            size,
            &data[0],
            &proof[..2],
            &root
        ));
        // Too long: an extra node after the root has been reached.
        let mut long = proof.clone();
        long.push(root);
        assert!(!verify_entry_inclusion(0, size, &data[0], &long, &root));
        // Right proof, wrong index.
        assert!(!verify_entry_inclusion(1, size, &data[0], &proof, &root));
        // A tree size too small for the proof runs out of tree. Step 4(a)
        // refuses it.
        assert!(!verify_entry_inclusion(0, 4, &data[0], &proof, &root));
        // Here is what RFC 9162 section 2.1.3.2 does *not* do. It never hashes
        // tree_size. The size only shapes the climb. Leaf 0 climbs left at
        // every step for any size in 5..=8. So the size-7 proof still verifies
        // when the caller says size 6 and hands in the size-7 root. See the
        // note on `verify_inclusion` for why that is not a hole.
        assert!(verify_entry_inclusion(0, 6, &data[0], &proof, &root));
        // Against the root the log actually published at size 6, it fails.
        let root6 = tree.root_at(6).unwrap();
        assert_ne!(root, root6);
        assert!(!verify_entry_inclusion(0, 6, &data[0], &proof, &root6));
        // Index outside the tree.
        assert!(!verify_entry_inclusion(size, size, &data[0], &proof, &root));

        // Consistency: an empty path is refused whenever the RFC's own range
        // applies. That is what stops "no proof" from reading as "consistent".
        let c = tree.consistency_proof(3, size).unwrap();
        let hash0 = tree.root_at(3).unwrap();
        assert!(verify_consistency(3, size, &hash0, &root, &c));
        assert!(!verify_consistency(3, size, &hash0, &root, &[]));
        assert!(!verify_consistency(3, size, &hash0, &root, &c[..2]));
        assert!(!verify_consistency(size, 3, &root, &hash0, &c));
        // A tree of size 0 whose claimed root is not the empty root.
        assert!(!verify_consistency(0, size, &root, &root, &[]));
        // The same size twice with two different roots. The log then says two
        // different things about one size, and this refuses it.
        assert!(!verify_consistency(size, size, &root, &hash0, &[]));
    }

    /// The second preimage attack the 0x00 and 0x01 prefixes exist to stop. A
    /// second preimage is a second input that hashes to the same value as the
    /// first one.
    ///
    /// Take the four-entry tree. `g` is the internal node over the first two
    /// leaves. The attacker claims a *two*-entry log whose first entry is the
    /// 64 bytes `a || b`. If leaf hashing and node hashing were one function,
    /// those 64 bytes would hash to exactly `g`, and the proof `[h]` would
    /// rebuild the real root. The attacker would then hold an inclusion proof,
    /// against a real signed root, for bytes nobody ever submitted.
    ///
    /// The second half of this test runs the attack against hashing with no
    /// prefixes, and shows the attack works. That is what shows the first half
    /// tests something real. It stays here for good, instead of a note that
    /// says "try deleting the prefixes".
    #[test]
    fn an_internal_node_cannot_be_passed_off_as_a_leaf() {
        let data = entries(4);
        let tree = MerkleTree::from_entries(&data);
        let root = tree.root();

        let a = leaf_hash(&data[0]);
        let b = leaf_hash(&data[1]);
        let c = leaf_hash(&data[2]);
        let d = leaf_hash(&data[3]);
        let g = node_hash(&a, &b);
        let h = node_hash(&c, &d);
        assert_eq!(node_hash(&g, &h), root);

        let forged_left = [a.as_slice(), b.as_slice()].concat();
        let forged_right = [c.as_slice(), d.as_slice()].concat();

        // The prefixes are what break the attack. Hashing those 64 bytes as an
        // entry gives something other than the node they came from.
        assert_ne!(leaf_hash(&forged_left), g);
        assert_ne!(leaf_hash(&forged_right), h);

        // So the forged inclusion proofs are refused.
        assert!(!verify_entry_inclusion(0, 2, &forged_left, &[h], &root));
        assert!(!verify_entry_inclusion(1, 2, &forged_right, &[g], &root));
        // And refused against the real tree size too.
        assert!(!verify_entry_inclusion(0, 4, &forged_left, &[h], &root));

        // Now the same tree with the prefixes deleted, to show the attack
        // really works and is not only an idea.
        let flat_leaf = |entry: &[u8]| -> Hash {
            let mut hasher = Sha256::new();
            hasher.update(entry);
            hasher.finalize().into()
        };
        let flat_node = |left: &Hash, right: &Hash| -> Hash {
            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            hasher.finalize().into()
        };
        let fa = flat_leaf(&data[0]);
        let fb = flat_leaf(&data[1]);
        let fc = flat_leaf(&data[2]);
        let fd = flat_leaf(&data[3]);
        let fg = flat_node(&fa, &fb);
        let fh = flat_node(&fc, &fd);
        let flat_root = flat_node(&fg, &fh);

        // The forged 64-byte entry hashes to the internal node itself. And the
        // two-entry tree over the two forged entries has the same root as the
        // four-entry tree. Both statements are the attack.
        let flat_forged_left = [fa.as_slice(), fb.as_slice()].concat();
        let flat_forged_right = [fc.as_slice(), fd.as_slice()].concat();
        assert_eq!(flat_leaf(&flat_forged_left), fg);
        assert_eq!(flat_leaf(&flat_forged_right), fh);
        assert_eq!(
            flat_node(
                &flat_leaf(&flat_forged_left),
                &flat_leaf(&flat_forged_right)
            ),
            flat_root
        );
    }

    /// Appending one entry at a time must give the same tree as building from
    /// the whole list at once. Every earlier root must still be there, and must
    /// not have changed.
    #[test]
    fn appending_matches_building_all_at_once() {
        let data = entries(300);
        // Built the slow way: one whole tree for each length from 0 to 300.
        let expected: Vec<Hash> = (0..=data.len())
            .map(|n| MerkleTree::from_entries(&data[..n]).root())
            .collect();

        let mut incremental = MerkleTree::new();
        for (i, e) in data.iter().enumerate() {
            assert_eq!(incremental.push_entry(e), i as u64);
            assert_eq!(
                incremental.root(),
                expected[i + 1],
                "root after {} entries",
                i + 1
            );
        }
        // Every root the log ever published is still there.
        for (size, want) in expected.iter().enumerate() {
            assert_eq!(
                incremental.root_at(size as u64).unwrap(),
                *want,
                "root at {size}"
            );
        }
    }

    #[test]
    fn split_point_is_the_largest_power_of_two_below_n() {
        assert_eq!(split_point(2), 1);
        assert_eq!(split_point(3), 2);
        assert_eq!(split_point(4), 2);
        assert_eq!(split_point(5), 4);
        assert_eq!(split_point(7), 4);
        assert_eq!(split_point(8), 4);
        assert_eq!(split_point(9), 8);
        assert_eq!(split_point(1 << 20), 1 << 19);
    }

    #[test]
    fn proof_errors_name_what_was_asked_for() {
        let tree = MerkleTree::from_entries(&entries(4));
        assert_eq!(
            tree.inclusion_proof(0, 5),
            Err(ProofError::UnknownTreeSize {
                tree_size: 5,
                have: 4
            })
        );
        assert_eq!(
            tree.inclusion_proof(4, 4),
            Err(ProofError::LeafOutOfRange {
                leaf_index: 4,
                tree_size: 4
            })
        );
        assert_eq!(
            tree.consistency_proof(3, 2),
            Err(ProofError::BackwardsConsistency {
                first: 3,
                second: 2
            })
        );
        assert!(
            !tree
                .consistency_proof(3, 2)
                .unwrap_err()
                .to_string()
                .is_empty()
        );
    }

    /// `RootFold`, which keeps at most 64 hashes, answers the same root as the
    /// tree that keeps every node. That holds at every size, for every history
    /// length up to 300 leaves.
    #[test]
    fn a_root_fold_agrees_with_the_whole_tree_at_every_size() {
        let all = entries(300);
        let sizes: Vec<u64> = (0..=300).collect();
        let mut fold = RootFold::new(&sizes);
        let mut tree = MerkleTree::new();
        assert_eq!(fold.root_at(0), Some(empty_root()));
        for entry in &all {
            fold.push_entry(entry);
            tree.push_entry(entry);
            assert_eq!(
                fold.root_at(tree.len()),
                Some(tree.root()),
                "the fold and the tree disagree at {} leaves",
                tree.len()
            );
        }
        // And the roots taken along the way are still there at the end.
        for size in 0..=300u64 {
            assert_eq!(
                fold.root_at(size),
                Some(tree.root_at(size).expect("a size the tree reached")),
                "the fold lost the root it took at {} leaves",
                size
            );
        }
    }

    /// The point of `RootFold`: what it holds is the right edge. That is one
    /// node per set bit of the size, and it never grows with the history.
    #[test]
    fn a_root_fold_holds_one_node_per_set_bit_of_its_size() {
        let mut fold = RootFold::new(&[]);
        for entry in &entries(1000) {
            fold.push_entry(entry);
            assert_eq!(
                fold.edge.len() as u32,
                fold.len().count_ones(),
                "the edge at {} leaves",
                fold.len()
            );
        }
        assert!(fold.edge.len() <= 64);
    }

    /// A size `RootFold` never reached has no root. That is a history which
    /// stops short of what something committed to.
    #[test]
    fn a_root_fold_has_no_root_at_a_size_it_never_reached() {
        let mut fold = RootFold::new(&[3, 40]);
        for entry in &entries(5) {
            fold.push_entry(entry);
        }
        assert!(fold.root_at(3).is_some());
        assert_eq!(fold.root_at(40), None);
        // A size nobody asked for is not kept either.
        assert_eq!(fold.root_at(4), None);
    }

    /// The numbering `append_nodes` uses is the numbering `appended_at`
    /// publishes. Two places decide which node belongs to which message: the
    /// log that stores the nodes, and a reader that checks them. The two must
    /// not be able to disagree.
    #[test]
    fn the_nodes_an_append_makes_are_the_nodes_it_is_numbered_for() {
        let mut tree = MerkleTree::new();
        for i in 0..500usize {
            let leaf = leaf_hash(&entry(i));
            let made = append_nodes(&tree, leaf).expect("a vector cannot fail");
            let numbering = appended_at(tree.len());
            assert_eq!(
                made.iter()
                    .map(|(level, index, _)| (*level, *index))
                    .collect::<Vec<_>>(),
                numbering,
                "leaf {}",
                i
            );
            tree.push_entry(&entry(i));
        }
    }

    /// Every node a tree of n leaves holds is one of the nodes its appends
    /// made. Exactly one append made each node, and there are
    /// `2n - popcount(n)` of them.
    #[test]
    fn every_node_of_a_tree_is_made_by_exactly_one_append() {
        for n in 1..200u64 {
            let mut all = BTreeMap::new();
            for leaf in 0..n {
                for (level, index) in appended_at(leaf) {
                    assert!(
                        all.insert((level, index), leaf).is_none(),
                        "two appends made the node at level {} index {}",
                        level,
                        index
                    );
                }
            }
            assert_eq!(all.len() as u64, nodes_in(n), "a tree of {} leaves", n);
        }
    }

    /// A log that stored one wrong node is caught, and the sentence names the
    /// node and both hashes.
    #[test]
    fn a_stored_node_the_messages_do_not_make_is_named() {
        let all = entries(300);
        let tree = MerkleTree::from_entries(&all);
        let mut ours = BTreeMap::new();
        for leaf in 0..300u64 {
            for (level, index) in appended_at(leaf) {
                ours.insert((level, index), tree.node(level, index).unwrap());
            }
        }
        assert!(
            compare_nodes(&ours, &ours, 0..300).is_empty(),
            "an honest log matches its own messages"
        );

        // The attack `adversarial.rs` runs: one leaf hash written over, inside
        // a perfect subtree, which leaves the root unchanged.
        let mut stored = ours.clone();
        stored.insert((0, 40), [0x99u8; 32]);
        assert_eq!(
            mth(&tree, 300).unwrap(),
            tree.root(),
            "the root is over the stored perfect subtree above leaf 40, not over leaf 40"
        );
        let faults = compare_nodes(&ours, &stored, 0..300);
        assert_eq!(faults.len(), 1, "{:?}", faults);
        assert!(
            faults[0].contains("level 0 index 40")
                && faults[0].contains(&hex(&[0x99u8; 32]))
                && faults[0].contains(&hex(&ours[&(0, 40)])),
            "{}",
            faults[0]
        );

        // A node the log lost.
        let mut short = ours.clone();
        short.remove(&(3, 2));
        let faults = compare_nodes(&ours, &short, 0..300);
        assert_eq!(faults.len(), 1, "{:?}", faults);
        assert!(
            faults[0].contains("holds no node at level 3 index 2"),
            "{}",
            faults[0]
        );

        // A node at a position these messages never fill. Node (3, 37) covers
        // leaves 296..303, and a tree of 300 leaves never fills it.
        let mut extra = ours.clone();
        extra.insert((3, 37), [2u8; 32]);
        let faults = compare_nodes(&ours, &extra, 0..304);
        assert_eq!(faults.len(), 1, "{:?}", faults);
        assert!(
            faults[0].contains("level 3 index 37") && faults[0].contains("does not have"),
            "{}",
            faults[0]
        );
    }

    /// A node covering a leaf the reader never read is not a node it can check.
    /// A log goes on publishing while somebody reads it.
    #[test]
    fn nodes_past_the_leaves_read_are_left_alone() {
        let all = entries(64);
        let tree = MerkleTree::from_entries(&all);
        let mut stored = BTreeMap::new();
        for leaf in 0..64u64 {
            for (level, index) in appended_at(leaf) {
                stored.insert((level, index), tree.node(level, index).unwrap());
            }
        }
        // The reader stopped at 40 leaves and hashed only those.
        let mut ours = BTreeMap::new();
        for leaf in 0..40u64 {
            for (level, index) in appended_at(leaf) {
                ours.insert((level, index), tree.node(level, index).unwrap());
            }
        }
        assert!(
            compare_nodes(&ours, &stored, 0..40).is_empty(),
            "a log that kept publishing is not a log that lied"
        );
        // And a reader that compares one page says nothing about the pages
        // before it. The log's nodes for leaves 0..20 are not this page's job.
        let mut page = BTreeMap::new();
        for leaf in 20..40u64 {
            for (level, index) in appended_at(leaf) {
                page.insert((level, index), tree.node(level, index).unwrap());
            }
        }
        assert!(
            compare_nodes(&page, &stored, 20..40).is_empty(),
            "a page of nodes is checked against the page of messages that made it"
        );
    }
}
