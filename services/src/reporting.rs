//! What one check counts and prints, and the two head checks both programs
//! run.
//!
//! The checker (`verify.rs`) and the audit (`prove.rs`) each print one line
//! per check. Both used to keep their own copy of the counting and their own
//! copy of the head check. The copies drifted apart. A fix went into one and
//! not the other, so the two programs counted the same failures differently
//! and gave different answers about the same signed head.
//!
//! The same holds for the tree. `check_tree` compares two things against the
//! root the served messages make: the root the sequencer signs at `/sth`, and
//! every root an anchor sender wrote to a public chain. Before `check_tree`
//! existed, `--verify` and `--audit` compared nothing about the tree at all.
//! The sequencer signed a root every few minutes, the anchor sender wrote that
//! root to Base, and no tool a stranger runs ever asked whether that root was
//! the root of the history being served.
//!
//! Nothing here states a matching rule. ENGINE.md section 5 says the checker
//! and the exchange must share no matching code, so the two can disagree about
//! a fill. Three things are not matching rules: how a check counts, what makes
//! a signed head trustworthy, and the RFC 9162 arithmetic that turns messages
//! into a root. So one copy of each is correct.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::anchor::{
    FoldedRoot, RootAnchorHistory, RootAnchorSource, RootCheck, TreeHead, check_root_by_folding,
};
use crate::domain::OrderId;
use crate::logchain::{self, Chain};
use crate::merkle::{self, Hash, RootFold};
use std::collections::BTreeMap;

/// How many failures one check prints before it prints a count instead. It has
/// a name because two places have to agree on the number. A check keeps this
/// many failures, and whatever fills a check keeps no more than it can print.
pub const FAILURES_SHOWN: usize = 5;

/// The running count of one check: how many rows it read, and what failed.
pub struct Check {
    pub name: &'static str,
    pub checked: usize,
    /// Every failure, counted. `failures` keeps only the first few to print,
    /// so this is the number the report has to state. Printing the length of
    /// the shortened list as the failure count reported "5 of 4000 bad" for a
    /// run in which every single row was bad.
    pub failed: usize,
    pub failures: Vec<String>,
}

impl Check {
    pub fn new(name: &'static str) -> Self {
        Check {
            name,
            checked: 0,
            failed: 0,
            failures: Vec::new(),
        }
    }

    pub fn fail(&mut self, message: String) {
        self.failed += 1;
        // Keep the report readable when one bug fails every row.
        if self.failures.len() < FAILURES_SHOWN {
            self.failures.push(message);
        }
    }

    pub fn passed(&self) -> bool {
        self.failed == 0
    }

    pub fn report(&self) -> bool {
        if self.passed() {
            println!("  PASS  {:<44} {} checked", self.name, self.checked);
            true
        } else {
            println!(
                "  FAIL  {:<44} {} of {} bad",
                self.name, self.failed, self.checked
            );
            for failure in &self.failures {
                println!("          {}", failure);
            }
            if self.failed > self.failures.len() {
                println!(
                    "          ... and {} more",
                    self.failed - self.failures.len()
                );
            }
            false
        }
    }
}

/// Reads every root anchor the contract holds, or the reason it could not be
/// read.
///
/// `None` in and `None` out. A tool run with no root anchor contract makes no
/// request, and it states that the anchored roots were not checked. Most
/// deployments have no anchor. A report that failed them for a feature their
/// operator never claimed to have would be a report nobody could use.
pub async fn read_root_anchors(
    source: Option<&RootAnchorSource>,
) -> Option<Result<RootAnchorHistory, String>> {
    Some(crate::anchor::read_root_history(source?).await)
}

/// The tree sizes a `RootFold` has to keep a root at.
///
/// Every one of these sizes is known before a single message is read. The
/// signed tree head names its own size, and each anchor names the size it
/// commits to. `RootFold` passes each size once, so a size that is not in this
/// list is a root nobody can produce later without walking the history again.
pub fn root_sizes(
    sth: &Result<TreeHead, String>,
    anchors: Option<&Result<RootAnchorHistory, String>>,
) -> Vec<u64> {
    let mut sizes = Vec::new();
    if let Ok(sth) = sth {
        sizes.push(sth.tree_size);
    }
    if let Some(Ok(history)) = anchors {
        sizes.extend(history.tree_sizes());
    }
    sizes.sort_unstable();
    sizes.dedup();
    sizes
}

/// The tree, walked beside the messages.
///
/// One `RootFold` does two jobs, because both are the same arithmetic. It
/// keeps the root at the sizes the signed tree head and the anchors name. It
/// also makes exactly the nodes a log holding this history must have stored,
/// so those nodes go straight against the nodes the log serves at
/// `/tree/nodes`.
///
/// This type holds the tree's right edge and one page of nodes, both under a
/// few thousand hashes. Neither grows with the length of the history.
///
/// `merkle_nodes` was the one record this exchange writes that nothing outside
/// the operator ever checked. A wrong node there forges nothing and hides no
/// message, because the root over a perfect subtree is stored beside it and
/// does not change. But every inclusion proof that reads that node lands on a
/// root the sequencer did not sign, so nobody can prove any more that the
/// messages under it are in the log.
pub struct TreeWalk {
    fold: RootFold,
    /// The nodes the messages of the page being walked made, cleared at the end
    /// of each page.
    made: BTreeMap<(u32, u64), Hash>,
    check: Check,
    /// The first leaf of the page being walked. A page's nodes are compared
    /// against the messages of that page and nothing else.
    page_from: u64,
    /// Set when the log stopped answering for its nodes. It is recorded once.
    /// A sequencer that is not serving them would otherwise fail one line per
    /// page.
    stopped: bool,
    /// Set when there is no log to ask, which is what a held history is.
    no_source: bool,
}

impl TreeWalk {
    pub fn new(root_sizes: &[u64]) -> Self {
        TreeWalk {
            fold: RootFold::new(root_sizes),
            made: BTreeMap::new(),
            check: Check::new("every stored node is the one the messages make"),
            page_from: 0,
            stopped: false,
            no_source: false,
        }
    }

    /// Hashes one message into the tree, exactly as the sequencer served it,
    /// and keeps the nodes that message made for this page's comparison.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.made.is_empty() {
            self.page_from = self.fold.len();
        }
        for (level, index, hash) in self.fold.push_entry(bytes) {
            self.made.insert((level, index), hash);
        }
    }

    /// Whether there is any point asking the log for another page of nodes.
    pub fn wants_nodes(&self) -> bool {
        !self.stopped && !self.no_source
    }

    /// Compares the nodes the log served for this page against the nodes this
    /// page's messages made.
    pub fn page(&mut self, served: &crate::wire::TreeNodes) {
        let mut stored = BTreeMap::new();
        for node in &served.nodes {
            match logchain::from_hex::<32>(&node.hash) {
                Some(hash) => {
                    stored.insert((node.level, node.index), hash);
                }
                None => self.check.fail(format!(
                    "the node the log serves at level {} index {} is '{}', which is not a 32-byte \
                     hash",
                    node.level, node.index, node.hash
                )),
            }
        }
        self.check.checked += self.made.len();
        for fault in merkle::compare_nodes(&self.made, &stored, self.page_from..self.fold.len()) {
            self.check.fail(fault);
        }
        self.made.clear();
    }

    /// There is no log to ask for nodes. That is not a failure and not a pass.
    /// A held history has no stored tree beside it.
    pub fn no_source(&mut self) {
        self.no_source = true;
        self.made.clear();
    }

    /// The log would not serve its nodes. A check that could not run has not
    /// passed, so this is a failure and it names the reason.
    pub fn unreadable(&mut self, reason: String) {
        if !self.stopped {
            self.stopped = true;
            self.check.checked += 1;
            self.check.fail(format!(
                "{}. The nodes between this log's messages and the root it signs are what every \
                 inclusion proof is built out of, and a log that will not serve them cannot be \
                 shown to hold the tree its messages make",
                reason
            ));
        }
        self.made.clear();
    }

    /// The tree the messages make, for the root comparisons.
    pub fn fold(&self) -> &RootFold {
        &self.fold
    }

    /// The check, and the sentence for a walk that had no log to ask.
    pub fn finish(self) -> (Check, Option<String>) {
        if self.no_source {
            return (
                self.check,
                Some(
                    "  the stored nodes were not checked: this history was not read from a log"
                        .to_string(),
                ),
            );
        }
        (self.check, None)
    }
}

/// What the tree checks said: the lines to print, and the things that were not
/// checked at all.
///
/// A note is not a pass. A deployment with no anchor key is a valid
/// deployment, so "no root anchor contract was named" must not fail the run,
/// and it must not vanish either, because a reader who sees only passing
/// checks would take the anchored roots to have been checked.
pub struct TreeReport {
    pub checks: Vec<Check>,
    pub notes: Vec<String>,
}

/// Checks the Merkle tree the sequencer publishes against the sequencer's own
/// messages.
///
/// Two comparisons, over one `RootFold`:
///
/// - the root the sequencer signs in its tree head at `/sth`, against the root
///   the served messages make at the size that head names. This says the tree
///   the sequencer hands proofs out of is the tree its own history makes.
/// - every root an anchor sender wrote to a public chain, against the root the
///   served messages make at the size that anchor names. This is the one check
///   the operator cannot pass by deleting their databases and publishing a new
///   history, because the older anchors still stand in blocks they cannot
///   edit. See `anchor::check_root_by_folding`.
///
/// A root that does not match is a failure and not "cannot interpret". This
/// function read the messages and it read the tree, and the two disagree. That
/// is a definite answer about the exchange, and not a gap in what this build
/// can say.
///
/// Nothing here parses a message. A leaf is the bytes the sequencer served, so
/// both comparisons hold over a history carrying a kind of message this build
/// has never heard of.
pub fn check_tree(
    sth: &Result<TreeHead, String>,
    anchors: Option<&Result<RootAnchorHistory, String>>,
    fold: &RootFold,
) -> TreeReport {
    let mut checks = Vec::new();
    let mut notes = Vec::new();

    let mut head = Check::new("the signed tree head is over these messages");
    head.checked = 1;
    match sth {
        // A tree head that cannot be read is a failure for the same reason
        // `/head` is. The signature over it is the only evidence that the tree
        // the sequencer serves proofs from is the tree it stands behind, and a
        // check that could not run has not passed.
        Err(reason) => head.fail(format!(
            "{}; without it nothing says which tree this feed hands inclusion proofs out of",
            reason
        )),
        Ok(sth) => match fold.root_at(sth.tree_size) {
            Some(ours) if ours == sth.root => {}
            Some(ours) => head.fail(format!(
                "the feed signs root {} over {} messages of session {}; its own messages produce \
                 {} over the same {}. The tree it hands proofs out of is not the tree its history \
                 makes",
                logchain::to_hex(&sth.root),
                sth.tree_size,
                sth.session,
                logchain::to_hex(&ours),
                sth.tree_size
            )),
            None => head.fail(format!(
                "the feed signs a root over {} messages of session {} and served {}. A signed \
                 head that reaches past the history behind it commits to messages nobody can \
                 read",
                sth.tree_size,
                sth.session,
                fold.len()
            )),
        },
    }
    checks.push(head);

    let Some(anchors) = anchors else {
        notes.push(
            "  the anchored roots were not checked: no root anchor contract was named. Pass \
             --root-anchor-contract and --root-anchor-rpc to check them"
                .to_string(),
        );
        return TreeReport { checks, notes };
    };
    let history = match anchors {
        Ok(history) => history,
        Err(reason) => {
            // The same rule the chain anchors are read under. An anchor that
            // cannot be read is an unchecked claim, and not a satisfied one.
            let mut unreadable = Check::new("the on-chain root anchors are readable");
            unreadable.checked = 1;
            unreadable.fail(format!(
                "{}. A root anchor that cannot be read is an unchecked claim, not a satisfied \
                 one",
                reason
            ));
            checks.push(unreadable);
            return TreeReport { checks, notes };
        }
    };

    let mut read = Check::new("every root anchor on the contract was read");
    read.checked = history.anchors.len();
    if !history.complete {
        read.fail(format!(
            "{} says it has written {} root anchors and only {} were found, scanning its log back \
             to block {}. The ones that were not read are the older ones, which are the ones a \
             rewind contradicts, so this is not a set of anchors that can be called checked. Pass \
             --root-anchor-from-block <BLOCK> with the block the contract was deployed in",
            history.contract,
            history.total,
            history.anchors.len(),
            history.scanned_from
        ));
    }
    checks.push(read);

    let mut agrees = Check::new("the newest root anchor and the contract agree");
    agrees.checked = 1;
    if !history.latest_agrees {
        agrees.fail(format!(
            "{} holds a root over {} messages of session {} in its own state, and its log does \
             not end with that write. The endpoint answering is not serving one view of one \
             chain, so none of these anchors mean anything",
            history.contract, history.latest.tree_size, history.latest.session
        ));
    }
    checks.push(agrees);

    let mut roots = Check::new("every anchored root is over these messages");
    if history.anchors.is_empty() {
        // A contract with nothing in it yet. An anchor sender that has not
        // run, or a deployment whose first write has not landed, is not a
        // failing exchange. It is not a passing check either.
        notes.push(format!(
            "  the anchored roots were not checked: {} holds no root anchor yet",
            history.contract
        ));
    }
    for anchor in &history.anchors {
        roots.checked += 1;
        if let RootCheck::Fails(reason) =
            check_root_by_folding(anchor, &FoldedRoot::folded(fold, anchor.tree_size))
        {
            roots.fail(reason);
        }
    }
    checks.push(roots);

    TreeReport { checks, notes }
}

/// The signed head of the sequencer's log, as served by GET /head. It is the
/// same shape `feed.rs` serialises, and the one shape both programs read.
#[derive(Debug, serde::Deserialize)]
pub struct FeedHead {
    pub session: String,
    pub last_id: OrderId,
    pub chain: String,
    pub public_key: String,
    pub signature: String,
}

/// The chain each program hashed again over the bytes the sequencer served,
/// taken at the head's message. Both programs hash more than this. The checker
/// stops at the head, and the audit also keeps the chain at its cursor and at
/// every anchor. So each program hands over the two values the head check
/// needs.
pub struct FoldedChain {
    pub chain: Chain,
    pub counted: usize,
}

/// Checks the sequencer's signed head against the sequencer's own messages and
/// against the key this run pinned. Three things are compared: the chain
/// hashed again from the messages, the signature, and whether the head reaches
/// as far as the run claims to have gone. It uses `logchain`'s functions, so
/// both programs check the same statement the sequencer signed and the
/// exchange accepted.
///
/// `pinned` is the sequencer's public key, as the run recorded it on first
/// contact. `claimed_to` is the highest message the caller can show the run
/// used.
pub fn check_feed_head(
    run_id: i64,
    pinned: Option<&str>,
    head: &Result<FeedHead, String>,
    folded: &FoldedChain,
    claimed_to: OrderId,
) -> Vec<Check> {
    let head = match head {
        Ok(head) => head,
        Err(reason) => {
            // A check that could not run is a failure, and not a pass.
            // Reporting it as "skipped" and returning success meant a
            // sequencer that stopped serving /head verified as well as one
            // that signs.
            let mut missing = Check::new("the feed serves a signed head");
            missing.checked = 1;
            missing.fail(format!(
                "{}; without it the history this run used is unsigned, and an unsigned \
                 history proves nothing about the run",
                reason
            ));
            return vec![missing];
        }
    };

    let mut chain_check = Check::new("the feed's signed chain matches its history");
    let mut sig_check = Check::new("the head is signed by the run's pinned key");
    let mut covers = Check::new("the signed head covers every claimed message");

    chain_check.checked = folded.counted;
    match logchain::from_hex::<32>(&head.chain) {
        Some(signed) if signed == folded.chain => {}
        Some(_) => chain_check.fail(format!(
            "recomputed chain at message {} is {}, the feed signed {}",
            head.last_id,
            logchain::to_hex(&folded.chain),
            head.chain
        )),
        None => chain_check.fail(format!("'{}' is not a 32-byte hex chain", head.chain)),
    }

    sig_check.checked = 1;
    let verified = logchain::from_hex::<32>(&head.public_key)
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        .zip(logchain::from_hex::<64>(&head.signature))
        .zip(logchain::from_hex::<32>(&head.chain))
        .is_some_and(|((key, signature), signed_chain)| {
            logchain::verify_head(
                &key,
                &head.session,
                head.last_id,
                &signed_chain,
                &Signature::from_bytes(&signature),
            )
        });
    if !verified {
        sig_check.fail(format!(
            "signature over (session {}, id {}, chain {}) does not verify with key {}",
            head.session, head.last_id, head.chain, head.public_key
        ));
    }
    // Verifying with the key the head itself carries only shows the head
    // agrees with itself. Anybody can sign a head with a key they made up. The
    // key this run pinned on first contact is the one that stops the operator
    // denying the history later.
    match pinned {
        Some(pinned) if pinned == head.public_key => {}
        Some(pinned) => sig_check.fail(format!(
            "run {} consumed a history signed by {}, this head is signed by {}",
            run_id, pinned, head.public_key
        )),
        None => sig_check.fail(format!(
            "run {} recorded no feed public key, so nothing ties this signed history to \
             the authority the run trusted",
            run_id
        )),
    }

    covers.checked = 1;
    if head.last_id < claimed_to {
        covers.fail(format!(
            "the feed's signed head stops at message {}, the run committed up to message \
             {}: messages {}..{} carry no feed signature at all",
            head.last_id,
            claimed_to,
            head.last_id.saturating_add(1),
            claimed_to
        ));
    }

    vec![chain_check, sig_check, covers]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A check states how many rows failed, and not how many failures it kept
    /// to print. The two are the same number until a check fails more than
    /// `FAILURES_SHOWN` rows. A state database whose every trade disagrees with
    /// the log is exactly that case. It used to be reported as "5 of 4000 bad",
    /// a line that says 3,995 trades reconciled when none did.
    #[test]
    fn a_check_counts_every_failure_and_not_only_the_ones_it_prints() {
        let mut check = Check::new("trade reconciliation");
        check.checked = 4000;
        for trade_id in 1..=4000 {
            check.fail(format!("trade {} does not match the log", trade_id));
        }

        assert_eq!(
            check.failures.len(),
            FAILURES_SHOWN,
            "the printed list stays short"
        );
        assert_eq!(check.failed, 4000, "the reported count is the real total");
        assert!(!check.passed());
    }
}
