//! `feed.db`: opened, its tables created, and refused if it was written before
//! a check this sequencer depends on.
//!
//! Not `crate::store`, which is the state the matching engine writes to disk.
//! This is the sequencer's own file: the messages it signed, the session and
//! the signed checkpoint beside them, the pairings with the separate service,
//! and the account key pins.

use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

use super::tree;
use crate::sqlite;

/// Opens the sequencer database and creates its tables if they are missing: the
/// messages exactly as served, the metadata holding the session and the signed
/// checkpoint, the pairings with the separate service, the account key pins,
/// and the Merkle tree's nodes.
///
/// A database written before `merkle_nodes` existed gets an empty `merkle_nodes`
/// here, filled in from its own messages on that first open. See
/// `tree::rebuild`. Nothing about the messages changes, so a build without the
/// table still opens the same file afterwards: that build reads the four tables
/// it knows and ignores the fifth.
pub(super) fn open_feed_db(path: &Path) -> Result<Connection, String> {
    // Not owner-only: every row in this file is a message the sequencer
    // serves to anybody who asks, plus the public keys it pinned them under.
    let conn = sqlite::open_durable(path, false)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS feed_meta (
           key   TEXT PRIMARY KEY,
           value TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS feed_messages (
           id    INTEGER PRIMARY KEY,
           json  TEXT NOT NULL,
           chain BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS inbox_sequenced (
           epoch    TEXT    NOT NULL,
           inbox_id INTEGER NOT NULL,
           feed_id  INTEGER NOT NULL,
           PRIMARY KEY (epoch, inbox_id)
         );
         -- The public key each account submits under, pinned on that
         -- account's first accepted submission. Nothing gets an account
         -- number onto this feed except a submission signed by the key here,
         -- which is what makes the account field on a published message a
         -- claim anyone downstream can rely on.
         CREATE TABLE IF NOT EXISTS feed_accounts (
           account    INTEGER PRIMARY KEY,
           public_key TEXT    NOT NULL,
           pinned_at  INTEGER NOT NULL
         );",
    )
    .map_err(|e| e.to_string())?;
    conn.execute_batch(tree::SCHEMA)
        .map_err(|e| e.to_string())?;
    // A file from before the chain column, or from before the separate
    // service's entry ids were qualified by that service's epoch, is not
    // migrated. Both changes are about what this sequencer is willing to sign,
    // and inventing the missing values would be inventing history. There is no
    // production data here to keep, so the answer is to start a new database.
    for (table, column) in [("feed_messages", "chain"), ("inbox_sequenced", "epoch")] {
        if !has_column(&conn, table, column).map_err(|e| e.to_string())? {
            return Err(format!(
                "{} has a `{}` table without a `{}` column, so it predates this feed's tamper \
                 checks. Delete the database (and feed.key beside it) and start a new history",
                path.display(),
                table,
                column
            ));
        }
    }
    Ok(conn)
}

fn has_column(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    // The table name is a literal from the list in `open_feed_db`, and never
    // caller input.
    Ok(conn
        .prepare(&format!(
            "SELECT 1 FROM pragma_table_info('{}') WHERE name = ?1",
            table
        ))?
        .query_row(params![column], |_| Ok(()))
        .optional()?
        .is_some())
}
