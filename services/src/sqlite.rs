//! One way to open a SQLite file, for every service that keeps one.
//!
//! The sequencer, the exchange, the separate service and a validator each open
//! a database and each want the same thing from it: a committed row must
//! survive a power cut, and a reader must not block a writer. They had four
//! copies of the same pragma batch. Three of the copies also missed the two
//! file permission fixes the fourth one had, so the same bug had to be found
//! and fixed four times. Four copies is how they drifted apart.
//!
//! The schema does not move here. Each service creates its own tables, because
//! the tables are that service's business.

use rusqlite::Connection;
use std::path::{Path, PathBuf};
use tracing::warn;

/// Opens a SQLite file and sets it up to survive a power cut.
///
/// `journal_mode = WAL` keeps a reader (an operator running sqlite3 against
/// the file) from blocking the writer. `synchronous = FULL` puts a committed
/// batch on the disk, not just in the operating system, which is the
/// difference between "resumable" and "usually resumable". `busy_timeout`
/// makes a second connection wait instead of failing at once.
///
/// `owner_only` says the file holds data that only its owner may read. It
/// covers the database and both sidecar files.
///
/// `false` means "do nothing about permissions", and it is a decision, not an
/// oversight. Two of the four databases pass `false` because their rows are
/// already public: every row in `feed.db` is a message the sequencer serves
/// over HTTP to anyone who asks, and everything in `validator.db` is what the
/// validator serves at `/attest`. Narrowing them would hide nothing and would
/// stop an operator reading them with sqlite3 as another user. `state.db` and
/// `inbox.db` pass `true`: positions, profit and submissions are not public.
pub fn open_durable(path: &Path, owner_only: bool) -> Result<Connection, String> {
    if owner_only {
        create_owner_only(path);
    }
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA busy_timeout = 5000;",
    )
    .map_err(|e| e.to_string())?;
    if owner_only {
        // WAL mode keeps the newest rows in the `-wal` file until a checkpoint
        // moves them, and the `-shm` file sits beside it. Restricting only the
        // main file left the newest rows at the default umask.
        //
        // Done on every start, not only when the database is new. A file that
        // an older build created is still loose today, and this is the start
        // that fixes it.
        restrict_permissions(path);
        restrict_permissions(&sidecar(path, "-wal"));
        restrict_permissions(&sidecar(path, "-shm"));
    }
    Ok(conn)
}

/// Creates the file owner-only *before* SQLite opens it.
///
/// The old code computed "is this new?" before the open and changed the mode
/// afterwards, which left the file readable by everyone for the moment in
/// between, and only ever on the run that created it.
#[cfg(unix)]
fn create_owner_only(path: &Path) {
    use std::os::unix::fs::OpenOptionsExt;
    if path.exists() {
        return;
    }
    if let Err(e) = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
    {
        warn!(
            "could not pre-create {} with owner-only permissions: {}",
            path.display(),
            e
        );
    }
}

#[cfg(not(unix))]
fn create_owner_only(_path: &Path) {}

/// Narrows one file to its owner.
#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    // A sidecar that does not exist yet is not a failure: SQLite creates the
    // WAL files when it needs them, and takes the database's mode when it
    // does.
    if !path.exists() {
        return;
    }
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        warn!(
            "could not restrict permissions on {}: {}",
            path.display(),
            e
        );
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

/// The path SQLite gives a sidecar file: the database path with the suffix
/// appended, not a replaced extension (`inbox.db-wal`, not `inbox.wal`).
pub(crate) fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("{} exists: {}", path.display(), e))
            .permissions()
            .mode()
            & 0o777
    }

    /// Writes one row, so SQLite has to create the `-wal` and `-shm` files.
    /// They only exist while a connection is open, so the caller holds it.
    fn write_a_row(conn: &Connection) {
        conn.execute_batch("CREATE TABLE t (a INTEGER); INSERT INTO t VALUES (1);")
            .expect("a row");
    }

    /// The point of this module: an owner-only database keeps its rows out of
    /// the `-wal` file's default umask as well as its own.
    #[cfg(unix)]
    #[test]
    fn an_owner_only_database_restricts_the_wal_and_shm_files_too() {
        let dir = TempDir::new().expect("a directory");
        let path = dir.path().join("state.db");

        let conn = open_durable(&path, true).expect("opens");
        write_a_row(&conn);

        assert_eq!(mode_of(&path), 0o600, "the database file");
        assert_eq!(mode_of(&sidecar(&path, "-wal")), 0o600, "the -wal file");
        assert_eq!(mode_of(&sidecar(&path, "-shm")), 0o600, "the -shm file");
    }

    /// The files an older build left readable by everyone are narrowed on the
    /// next start, not only on the start that created the database.
    ///
    /// This is the deployed case: `state.db-wal` on the server is at the
    /// default umask now, and the next container start has to fix it.
    #[cfg(unix)]
    #[test]
    fn loose_files_from_an_older_build_are_narrowed_on_the_next_open() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().expect("a directory");
        let path = dir.path().join("state.db");

        // A database and sidecars the old code left at the default umask. The
        // connection stays open, because SQLite removes the sidecars when the
        // last connection closes.
        let older_build = open_durable(&path, false).expect("opens");
        write_a_row(&older_build);
        let loose = [path.clone(), sidecar(&path, "-wal"), sidecar(&path, "-shm")];
        for file in &loose {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644))
                .expect("a loose mode");
        }

        // The next start of the service.
        let _restarted = open_durable(&path, true).expect("reopens");

        for file in &loose {
            assert_eq!(mode_of(file), 0o600, "{}", file.display());
        }
        drop(older_build);
    }
}
