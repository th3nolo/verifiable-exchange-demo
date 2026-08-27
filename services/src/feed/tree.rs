//! The Merkle tree's nodes, as rows in `feed.db`.
//!
//! `merkle.rs` implements RFC 9162 and says nothing about where a node is kept.
//! This file decides that. It implements `merkle::NodeSource` over one table,
//! and owns everything SQLite about the tree: the schema, the insert, the
//! counts and the root a start checks, and the rebuild for a database whose
//! tree is missing, or whose tree no signed checkpoint covers.
//!
//! ```text
//! merkle_nodes(level, idx, hash)   PRIMARY KEY (level, idx)
//! ```
//!
//! `hash` is `MTH(D[idx * 2^level : (idx+1) * 2^level])`: the root of a perfect
//! subtree of `2^level` leaves. Level 0 is the leaf hashes themselves. The
//! right edge of the tree carries subtrees that are not perfect, and none of
//! those nodes is stored. They change on every append, and `merkle.rs` computes
//! them from the perfect ones below.
//!
//! # What it costs, measured
//!
//! An append writes the new leaf, plus one row for each perfect subtree that
//! leaf completes. Over a history of `n` messages that is `2n - popcount(n)`
//! rows: just under two rows a message.
//!
//! On a 134,500-message sequencer database those 268,993 rows took 12,148,736
//! bytes, which is 90 bytes a message. That is 45 bytes a row, for a 32-byte
//! hash and the key that finds it. The messages themselves are 162 bytes a
//! message in the same file, so the tree makes `feed.db` 56% larger. At the
//! deployed rate of two messages a second that is 5.7 GB a year. In exchange
//! it saves 63 bytes a message of RAM, and that RAM
//! use had no upper limit at all.
//!
//! Halving the rows is possible and is not done. Level 0 is a hash of bytes
//! that are already in `feed_messages`, so those rows could be computed again
//! instead of stored. That would cost a message read and a SHA-256 on the one
//! level-0 node a proof needs. The part that decides it is the other cost: a
//! read of the previous message on every second append, inside the transaction.
//! Not worth it within the current storage budget.
//!
//! A proof reads `log2(n)` rows and hashes `log2(n)` times. That is 46
//! microseconds at 100,000 messages, and the same proof out of the in-memory
//! tree takes 17 microseconds. Nothing here is proportional to the history.

use std::fmt;
use std::time::Instant;

use rusqlite::{Connection, OptionalExtension, params};
use tracing::info;

use crate::domain::OrderId;
use crate::logchain::{self, Chain};
use crate::merkle::{self, Hash, MerkleTree, NodeSource, TreeError};

/// The table, created beside the sequencer's other three. See `db.rs`.
///
/// `WITHOUT ROWID` because the whole row is its own key plus 32 bytes. With a
/// rowid SQLite would keep the same data twice: once in a table B-tree keyed by
/// a rowid nobody names, and once in the index that finds `(level, idx)`.
pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS merkle_nodes (
           level INTEGER NOT NULL,
           idx   INTEGER NOT NULL,
           hash  BLOB    NOT NULL,
           PRIMARY KEY (level, idx)
         ) WITHOUT ROWID;";

/// Why a stored node could not be read back.
///
/// All three mean one thing to a caller: this sequencer cannot produce the
/// answer it was asked for. They are kept apart because they mean different
/// things to the person who has to fix the database.
#[derive(Debug)]
pub(super) enum Unreadable {
    /// SQLite refused the read.
    Sql(rusqlite::Error),
    /// The row is not there. An append commits every node it makes together
    /// with the message that made it. A row that is missing therefore means
    /// something other than this sequencer wrote to the table.
    Missing { level: u32, index: u64 },
    /// The row is there and is not 32 bytes.
    NotAHash {
        level: u32,
        index: u64,
        bytes: usize,
    },
}

impl fmt::Display for Unreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unreadable::Sql(error) => write!(f, "merkle_nodes could not be read: {error}"),
            Unreadable::Missing { level, index } => write!(
                f,
                "merkle_nodes has no node at level {level}, index {index}; the tree in this \
                 database is not the tree its messages make"
            ),
            Unreadable::NotAHash {
                level,
                index,
                bytes,
            } => write!(
                f,
                "the node at level {level}, index {index} of merkle_nodes is {bytes} bytes and a \
                 SHA-256 hash is 32"
            ),
        }
    }
}

impl std::error::Error for Unreadable {}

impl From<rusqlite::Error> for Unreadable {
    fn from(error: rusqlite::Error) -> Self {
        Unreadable::Sql(error)
    }
}

/// Where a sequencer's nodes are: rows in its database, or vectors in memory
/// when the sequencer was started with no database at all.
///
/// One type rather than two code paths. The same `merkle.rs` walk produces a
/// proof either way, and a test can compare the two answers.
pub(super) enum Nodes<'a> {
    /// `--no-feed-db`. Such a sequencer writes nothing to disk, so its tree is
    /// not written to disk either. The tree is the whole `MerkleTree`, in RAM,
    /// for as long as the process runs.
    Memory(&'a MerkleTree),
    /// The ordinary case: `merkle_nodes` in `feed.db`, and `leaves`, the tree
    /// size, as the only part of the tree this process holds.
    Disk { conn: &'a Connection, leaves: u64 },
}

impl NodeSource for Nodes<'_> {
    type Error = Unreadable;

    fn tree_size(&self) -> u64 {
        match self {
            Nodes::Memory(tree) => tree.len(),
            Nodes::Disk { leaves, .. } => *leaves,
        }
    }

    fn node(&self, level: u32, index: u64) -> Result<Hash, Unreadable> {
        match self {
            Nodes::Memory(tree) => Ok(tree
                .node(level, index)
                .unwrap_or_else(|never| match never {})),
            Nodes::Disk { conn, .. } => {
                let stored: Option<Vec<u8>> = conn
                    .prepare_cached("SELECT hash FROM merkle_nodes WHERE level = ?1 AND idx = ?2")?
                    .query_row(params![level, index], |row| row.get(0))
                    .optional()?;
                let bytes = stored.ok_or(Unreadable::Missing { level, index })?;
                let len = bytes.len();
                bytes.try_into().map_err(|_| Unreadable::NotAHash {
                    level,
                    index,
                    bytes: len,
                })
            }
        }
    }
}

/// `MTH` over the first `size` leaves of a tree that holds at least that many.
///
/// At most 64 stored nodes and 64 hashes, whatever the history is. The root of
/// a tree of any size is the perfect subtrees on its right edge combined, one
/// subtree for each set bit of the size. That is what makes the startup check
/// against the signed root cheap: it reads `log2(n)` rows, and never passes
/// over the messages.
pub(super) fn root(nodes: &Nodes<'_>, size: u64) -> Result<Hash, Unreadable> {
    match merkle::mth(nodes, size) {
        Ok(root) => Ok(root),
        Err(TreeError::Source(e)) => Err(e),
        // Every caller here passes a size the tree already reached, so there
        // is no size the tree can refuse.
        Err(TreeError::Proof(e)) => unreachable!("a tree refused its own size: {}", e),
    }
}

/// Appends `leaves` to the tree of `leaves_before` leaves in `conn`, and
/// returns how many rows that wrote.
///
/// **The caller runs this inside the transaction that writes the messages
/// themselves.** A node committed without its message, or a message committed
/// without its node, makes a tree that does not match the history beside it.
/// Nothing later can tell which of the two to believe. `sequence` passes the
/// transaction it already holds, so the two writes are one write. There is no
/// order between them to get wrong, and no moment between them for a crash to
/// land in.
pub(super) fn append(
    conn: &Connection,
    leaves_before: u64,
    leaves: &[Hash],
) -> Result<u64, Unreadable> {
    // A plain INSERT, not INSERT OR REPLACE, for the reason `feed_messages`
    // uses one. Every index here is one past what the table holds, so a row
    // that is already there means something is wrong. Overwriting that row
    // would rewrite a node that an already-published root was computed from.
    let mut insert =
        conn.prepare_cached("INSERT INTO merkle_nodes (level, idx, hash) VALUES (?1, ?2, ?3)")?;
    let mut written = 0;
    for (offset, leaf) in leaves.iter().enumerate() {
        let nodes = Nodes::Disk {
            conn,
            leaves: leaves_before + offset as u64,
        };
        // The reads inside `append_nodes` see the rows the earlier leaves of
        // the same burst wrote: those rows are on this connection, in this
        // transaction.
        for (level, index, hash) in merkle::append_nodes(&nodes, *leaf)? {
            insert.execute(params![level, index, hash.as_slice()])?;
            written += 1;
        }
    }
    Ok(written)
}

/// How many leaves' worth of nodes one `/tree/nodes` answer may carry.
///
/// The same rule as every other list this sequencer serves: the caller asks,
/// and the sequencer clamps rather than refuses. A caller cannot tell a clamp
/// from a short answer, and both mean one thing: ask again from where this
/// answer ended.
///
/// One leaf makes just under two nodes, so a page of 1,000 leaves is about
/// 2,000 nodes and 64 KB of hash. A page of 1,000 messages is 200 KB. The two
/// are asked for together, page for page.
pub(super) const MAX_NODE_LEAVES: u64 = 1000;

/// The nodes that appending leaves `from .. from + count` created, as this
/// database holds them.
///
/// `merkle::appended_at` says which nodes those are. This file writes no rule
/// of its own, so one list decides what an append stores and what a reader must
/// find.
///
/// A node the table does not hold is left out of the answer rather than turned
/// into an error. A reader knows which nodes it asked about, so a missing node
/// is a fact the reader can report: "the log holds no node at level 3 index
/// 12". A 500 would tell the reader nothing about which node is gone.
pub(super) fn window(
    nodes: &Nodes<'_>,
    from: u64,
    count: u64,
) -> Result<Vec<(u32, u64, Hash)>, Unreadable> {
    let leaves = nodes.tree_size();
    let count = count.min(MAX_NODE_LEAVES);
    let upto = from.saturating_add(count).min(leaves);
    let mut out = Vec::new();
    for leaf in from..upto {
        for (level, index) in merkle::appended_at(leaf) {
            match nodes {
                // Nothing in memory can be missing. The tree made every one of
                // these nodes itself, and holds them all.
                Nodes::Memory(tree) => out.push((
                    level,
                    index,
                    tree.node(level, index)
                        .unwrap_or_else(|never| match never {}),
                )),
                Nodes::Disk { conn, .. } => {
                    let stored: Option<Vec<u8>> = conn
                        .prepare_cached(
                            "SELECT hash FROM merkle_nodes WHERE level = ?1 AND idx = ?2",
                        )?
                        .query_row(params![level, index], |row| row.get(0))
                        .optional()?;
                    let Some(bytes) = stored else { continue };
                    let len = bytes.len();
                    out.push((
                        level,
                        index,
                        bytes.try_into().map_err(|_| Unreadable::NotAHash {
                            level,
                            index,
                            bytes: len,
                        })?,
                    ));
                }
            }
        }
    }
    Ok(out)
}

/// Empties the table.
///
/// For the one case that needs it. A database whose messages somebody deleted
/// starts a *new* history under a new session, and a new history starts with an
/// empty tree. `clear` is called from inside the first publish's transaction
/// and not at startup, because a start that has published nothing writes
/// nothing.
pub(super) fn clear(conn: &Connection) -> Result<usize, rusqlite::Error> {
    conn.execute("DELETE FROM merkle_nodes", [])
}

/// The number of leaves the table holds: one past the highest index at level 0,
/// or 0 for an empty table.
///
/// A single index seek, and not a scan. `(level, idx)` is the primary key, so
/// SQLite walks to the end of the level-0 range and stops.
pub(super) fn stored_leaves(conn: &Connection) -> Result<u64, rusqlite::Error> {
    let highest: Option<i64> = conn.query_row(
        "SELECT MAX(idx) FROM merkle_nodes WHERE level = 0",
        [],
        |row| row.get(0),
    )?;
    Ok(highest.map_or(0, |idx| idx as u64 + 1))
}

/// How many rows the table holds.
pub(super) fn stored_nodes(conn: &Connection) -> Result<u64, rusqlite::Error> {
    conn.query_row("SELECT COUNT(*) FROM merkle_nodes", [], |row| {
        row.get::<_, i64>(0)
    })
    .map(|count| count as u64)
}

/// How many rows a tree of `leaves` leaves has. `merkle::nodes_in` is the one
/// definition. A reader that checks this sequencer's nodes over HTTP counts
/// against the same number.
pub(super) fn expected_nodes(leaves: u64) -> u64 {
    merkle::nodes_in(leaves)
}

/// What a rebuild did, for the operator to read.
pub(super) struct Rebuilt {
    pub(super) leaves: u64,
    pub(super) nodes: u64,
    pub(super) millis: u128,
}

/// Builds the missing nodes from the messages, in one transaction.
///
/// A database that a build without `merkle_nodes` wrote pays this cost on its
/// first open. It is a one-time cost: the next start finds the table complete
/// and reads nothing but its two counts.
///
/// **Only ever called after the history has been checked against the signed
/// checkpoint.** The messages are what the tree commits to, so nodes are only
/// written for messages this sequencer has just proven are the ones it
/// published.
///
/// The chain is hashed a second time over the same bytes as they are hashed
/// into leaves, and the second pass has to arrive where the first pass arrived.
/// That is what makes reading the table twice safe. If the rows changed between
/// the two reads, the tree would commit to bytes the chain does not cover, and
/// `rebuild` refuses instead of storing them.
pub(super) fn rebuild(
    conn: &mut Connection,
    from: u64,
    upto: u64,
    chain_from: Chain,
    chain_upto: Chain,
) -> Result<Rebuilt, String> {
    let started = Instant::now();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut nodes = 0;
    let mut leaves = 0;
    {
        if from == 0 {
            // The stored tree is not a prefix of the tree these messages make,
            // so none of it can be kept. The rows of a history that somebody
            // deleted land here.
            clear(&tx).map_err(|e| e.to_string())?;
        }
        let mut statement = tx
            .prepare("SELECT id, json FROM feed_messages WHERE id > ?1 ORDER BY id")
            .map_err(|e| e.to_string())?;
        let mut rows = statement
            .query(params![from as i64])
            .map_err(|e| e.to_string())?;
        let mut chain = chain_from;
        let mut expect = from;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let id: i64 = row.get(0).map_err(|e| e.to_string())?;
            let json: String = row.get(1).map_err(|e| e.to_string())?;
            expect += 1;
            if id as u64 != expect {
                return Err(format!(
                    "message {} is missing while the tree was being built from the messages",
                    expect
                ));
            }
            chain = logchain::extend_bytes(&chain, json.as_bytes());
            // `leaf_hash` and never a hash from anywhere else. `leaf_hash`
            // applies RFC 9162's 0x00 leaf prefix, so nothing here can put an
            // internal node where a leaf belongs.
            nodes += append(&tx, from + leaves, &[merkle::leaf_hash(json.as_bytes())])
                .map_err(|e| e.to_string())?;
            leaves += 1;
        }
        if from + leaves != upto || chain != chain_upto {
            return Err(format!(
                "the messages moved while the tree was being built from them: {} of them were \
                 read reaching chain {}, and the pass that checked them against the signed \
                 checkpoint read {} reaching {}. Nothing has been stored",
                from + leaves,
                logchain::to_hex(&chain),
                upto,
                logchain::to_hex(&chain_upto)
            ));
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(Rebuilt {
        leaves,
        nodes,
        millis: started.elapsed().as_millis(),
    })
}

/// Reports what the start had to do to the tree, and how long that took.
///
/// Four different messages, because an operator who reads one of these lines
/// wants to know which of the four happened to their database.
pub(super) fn report(
    path: &std::path::Path,
    messages: OrderId,
    found_leaves: u64,
    found_nodes: u64,
    signed_root: bool,
    rebuilt: &Rebuilt,
) {
    let file = path.display();
    let Rebuilt {
        leaves,
        nodes,
        millis,
    } = rebuilt;
    if found_nodes > 0 && !signed_root {
        info!(
            "the checkpoint in {file} was signed before a checkpoint carried the Merkle root, so \
             nothing in this file says which tree its {messages} messages make. The {found_nodes} \
             nodes it held were discarded and built again from the messages: {nodes} nodes in \
             {millis} ms. The next message published writes a checkpoint that carries the root, \
             and the start after that reads the tree instead of building it"
        );
    } else if found_nodes == 0 {
        info!(
            "{file} holds no Merkle nodes, so it was written by a build that kept the tree in \
             memory. Its {messages} messages produced {nodes} nodes, stored in {millis} ms. This \
             is a one-time cost: the next start reads the tree rather than building it"
        );
    } else if found_leaves + leaves == messages {
        info!(
            "the Merkle tree in {file} covered {found_leaves} of its {messages} messages, so the \
             remaining {leaves} were added in {millis} ms"
        );
    } else {
        info!(
            "the Merkle tree in {file} held {found_nodes} nodes over {found_leaves} leaves, which \
             is not a tree the {messages} messages beside it make. It was discarded and rebuilt \
             from the messages: {nodes} nodes in {millis} ms"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(i: u64) -> Vec<u8> {
        format!("{{\"New\":{{\"id\":{}}}}}", i + 1).into_bytes()
    }

    /// A database holding `n` leaves, appended the way `sequence` appends them.
    fn stored(n: u64) -> Connection {
        let conn = Connection::open_in_memory().expect("an in-memory database");
        conn.execute_batch(SCHEMA).expect("the table is created");
        for leaf in 0..n {
            append(&conn, leaf, &[merkle::leaf_hash(&entry(leaf))]).expect("the append is stored");
        }
        conn
    }

    /// The endpoint serves what the messages of that page make: the same
    /// nodes, in the same order, with the same hashes.
    #[test]
    fn a_window_serves_the_nodes_its_leaves_made() {
        let leaves = 300u64;
        let conn = stored(leaves);
        let nodes = Nodes::Disk {
            conn: &conn,
            leaves,
        };
        let all: Vec<Vec<u8>> = (0..leaves).map(entry).collect();
        let tree = MerkleTree::from_entries(&all);

        for (from, count) in [(0u64, 300u64), (0, 1), (7, 1), (100, 50), (299, 1)] {
            let served = window(&nodes, from, count).expect("the nodes are readable");
            let expected: Vec<(u32, u64)> =
                (from..from + count).flat_map(merkle::appended_at).collect();
            assert_eq!(
                served
                    .iter()
                    .map(|(level, index, _)| (*level, *index))
                    .collect::<Vec<_>>(),
                expected,
                "the window {}..{}",
                from,
                from + count
            );
            for (level, index, hash) in served {
                assert_eq!(
                    hash,
                    tree.node(level, index).expect("the tree has this node"),
                    "the node at level {} index {}",
                    level,
                    index
                );
            }
        }
    }

    /// A window is clamped, not refused, and it stops at the tree's own size. A
    /// caller cannot tell a clamp from a short answer, and both mean one thing:
    /// ask again from where this answer ended.
    #[test]
    fn a_window_is_clamped_and_stops_at_the_last_leaf() {
        let conn = stored(10);
        let nodes = Nodes::Disk {
            conn: &conn,
            leaves: 10,
        };
        let served = window(&nodes, 0, u64::MAX).expect("the nodes are readable");
        assert_eq!(served.len() as u64, expected_nodes(10));
        assert!(
            window(&nodes, 10, 5).expect("no leaves there").is_empty(),
            "a window past the last leaf is empty and not an error"
        );
    }

    /// A node the table lost is left out rather than turned into an error. The
    /// reader can then say which node is gone.
    #[test]
    fn a_missing_node_is_left_out_of_the_window() {
        let conn = stored(64);
        conn.execute("DELETE FROM merkle_nodes WHERE level = 0 AND idx = 40", [])
            .expect("the node is removed");
        let nodes = Nodes::Disk {
            conn: &conn,
            leaves: 64,
        };
        let served = window(&nodes, 40, 1).expect("the window is readable");
        assert!(
            !served
                .iter()
                .any(|(level, index, _)| *level == 0 && *index == 40),
            "the missing node is not in the answer"
        );
    }
}
