//! Every filesystem write the sequencer makes is failed, one at a time, in
//! order, until a run finishes without meeting a failure.
//!
//! This is SQLite's own way of testing failure, applied to the program that
//! uses SQLite. Its malloc tests rig the nth allocation to fail, run the
//! operation, check the result, increase n, and repeat until the operation runs
//! to completion untouched; its crash tests do the same with writes. Nothing is
//! random and nothing is missed.
//!
//! [`crash_restart.rs`](../crash_restart.rs) is the enumerated half of this
//! already: SIGKILL after exactly n published messages, for n in 0..=12. Its
//! own report says what it cannot reach, the inside of one message's write
//! path. A signal aimed from outside lands somewhere in a 100 ms tick, and the
//! write path of one message is a few hundred microseconds of it, so that file
//! samples the path a few dozen times and says so. This file counts instead of
//! timing, and reaches every point in it.
//!
//! # The mechanism
//!
//! A small C library, compiled when the test runs and loaded into the sequencer
//! with `LD_PRELOAD`. It wraps `open`, `close`, `pwrite`, `write`, `pwritev`,
//! `fsync`, `fdatasync` and `ftruncate`; counts every one of them made against
//! `feed.db`, `feed.db-wal`, `feed.db-shm` or `feed.db-journal`; and fails the
//! nth. Which fd belongs to the database is learned from `open`, and forgotten
//! on `close`, because the sequencer writes `feed.key` first and the kernel
//! hands the same fd number to `feed.db` afterwards.
//!
//! The counter and the verdict live in a file the test creates and the library
//! maps `MAP_SHARED`. The test reads that file while the sequencer runs, so it
//! knows which operation the process is on at the moment it sees a new head,
//! which is how the operations below are attributed to the transaction that
//! published a message. Nothing is written per operation except a store into
//! mapped memory.
//!
//! The binary under test is the real one, unmodified: same `--start-feed`, same
//! startup checks, same exit codes.
//!
//! Three other ways to do this were possible, and each gives up something this
//! one keeps:
//!
//! - **A SQLite virtual file system**, which is what SQLite's own crash tests
//!   use. It counts the same operations more precisely and portably, and it has
//!   to be linked in, so the sequencer would have to run inside the test
//!   binary. That is a test of `feed.rs` rather than of the program an operator
//!   runs, and it stops covering the startup checks, the exit codes and the
//!   arguments.
//! - **A filesystem that is really full**: a loopback image, or a `tmpfs`
//!   mounted with a size. No shim, and the failures are as real as they get,
//!   but they cannot be aimed. "The nth write" is not something a full disk can
//!   be asked for; only "somewhere after this many bytes", which is sampling
//!   again. It also needs `mount`, which needs privileges this test does not
//!   have, and the only sized `tmpfs` here is `/tmp`, shared with everything
//!   else that runs.
//! - **SQLite's own error injection**, from outside the process. There is none
//!   to reach: `sqlite3_test_control`'s fault hooks need a `SQLITE_TEST` build
//!   and `rusqlite`'s bundled SQLite is not one, and no `PRAGMA` fails a write
//!   on demand. What *is* reachable is a trigger that makes an `INSERT` fail.
//!   `feed.rs`'s own unit tests use one. That fails a statement rather than
//!   a write, so it can never land between the message and the nodes, which is
//!   the point of this file.
//!
//! Three kinds of failure, because a disk fails in more than one way:
//!
//! - **transient**: the nth operation returns `EIO`, everything after it works.
//!   One bad sector. What is under test is that the feed carries on correctly.
//! - **persistent**: the nth operation and every one after it return `ENOSPC`.
//!   The disk filled and stayed full.
//! - **torn**: the nth write puts half its bytes on disk and reports that it
//!   wrote half; everything after it returns `ENOSPC`. This is what a real
//!   `pwrite` does when the filesystem runs out of room in the middle of one,
//!   and it is the closest a userspace shim gets to power loss: a WAL frame
//!   that is really, physically half there.
//!
//! # What this cannot reach
//!
//! - **Anything below the syscall.** A write that returns success and is lost in
//!   the page cache on power loss, a barrier a drive ignores, a sector that
//!   comes back with different bytes. Every operation here either happens whole,
//!   happens half, or does not happen. A real disk can also reorder.
//! - **The `-shm` file's contents.** SQLite maps it and stores into memory; the
//!   WAL index is not written through a syscall, so it cannot be failed here.
//!   It is derived state: SQLite rebuilds it from the WAL on the next open.
//! - **`feed.key`.** It is written with `fs::write` and never synced, and it is
//!   deliberately outside the counted set: this file is about the database. A
//!   lost `feed.key` makes every checkpoint in `feed.db` unverifiable for good,
//!   and nothing tests that, here or in `crash_restart.rs`.
//! - **A statically linked libc.** `LD_PRELOAD` interposes calls that go through
//!   the dynamic symbol table. This binary imports `open`, `open64`, `pwrite64`,
//!   `write`, `fsync`, `ftruncate64` and `close` from glibc, which is what makes
//!   this work; a musl-static build would need `ptrace` or `seccomp` instead.
//! - **Two writers, and the inbox drain.** Same gaps `crash_restart.rs` names.
//! - **A burst of a hundred.** These runs publish one message per transaction.
//!   `crash_restart.rs` crashes inside a hundred-message transaction; nothing
//!   enumerates the writes inside one.
//!
//! # What is checked after every injected failure
//!
//! The database the failure left is copied aside and read **without starting
//! the binary**, because a start would repair part of what is under test:
//! `FeedState::with_db` rebuilds `merkle_nodes` from the messages when the table
//! is short. That repair is right: the tree is derived from the messages. But
//! it means a test that reads the tree *after* a restart cannot tell a crash
//! that left a message without its nodes from one that did not. This reads the
//! tree before anything has had the chance to fix it.
//!
//! 0. The ids are 1..N with no gaps, and every stored chain link is the fold
//!    over the messages up to it.
//! 1. The checkpoint is signed by the key beside the database, over the session
//!    row beside it, and it names exactly the last message, the chain those
//!    messages produce, and the Merkle root they make. Messages with no
//!    checkpoint, or a checkpoint with no messages, is a half-written state and
//!    fails here. The root is the newest of these and the strongest: it is the
//!    feed's own signed statement of what the tree over those messages is,
//!    written in the transaction that writes both.
//! 2. `merkle_nodes` holds exactly the `2n - popcount(n)` nodes a tree over
//!    those n messages has, and every one of them is the node those messages
//!    make. **No message without its nodes, and no node without its message.**
//! 3. The sequencer that was still running when the write failed serves a head
//!    that is not ahead of what is on disk, and whose chain is the fold over the
//!    messages that are. This is the check the comment on `sequence` describes:
//!    the old code logged the write failure and published anyway.
//! 4. A restart on that database starts, or refuses with a named reason and an
//!    exit code of 2, and it is only allowed to refuse a database holding no
//!    messages. Refusing one that holds a history would be a history lost.
//! 5. The restart's head is at or past every head anything signed before it, its
//!    served messages fold to the chain it signs now, and they fold to the chain
//!    in each of those earlier heads at that earlier `last_id`. This is
//!    `crash_restart.rs`'s check 5 and it is the one that is not vacuous: a
//!    sequencer that repaired itself and signed the repair passes everything
//!    else and fails this.
//! 6. The restart publishes again. A feed that comes back readable and can never
//!    append is a feed that is down, and nothing else here would notice.
//!
//! # How much is enumerated, and what it found
//!
//! 190 failure points, in 202 trials, measured rather than fixed: the run under
//! test is timed once with nothing failing, and its operations are then failed
//! one at a time up to three past the last of them.
//!
//! | what the run does | operations | modes |
//! |---|---|---|
//! | restart on a three-message history, publish three more | 36 | all three |
//! | create the database, publish four | 82 | persistent |
//!
//! Nine of those 36 are the restart itself and 27 are three publishes, nine
//! operations each: four write-ahead log frames, each a 24-byte header and a
//! 4096-byte page, and the `fsync` that commits them. That is the whole write
//! path of one published message, and every point in it is failed.
//!
//! No check failed, at any point, in any mode. The shape of the write path is
//! printed by [`operations_of_a_publish_are_enumerated`].
//!
//! Two things worth writing down, both visible in that enumeration:
//!
//! - A restart on an existing history writes nothing to `feed.db` or its WAL
//!   until it publishes. The only counted operations before the first publish
//!   are the nine that set up `feed.db-shm`, which is derived state. A disk that
//!   is full cannot damage a history that is already there; it stops the feed
//!   from starting, with `cannot use feed database ...: disk I/O error`.
//! - The commit point is the WAL `fsync`, and failing it does not undo the
//!   transaction. The frames are already in the page cache, so a process killed
//!   right afterwards leaves a database that recovers *with* the message, while
//!   the process that wrote it was told the write failed and published nothing.
//!   The feed is behind its own disk for one message, which is the safe
//!   direction: it never hands out a receipt for that message, and the restart
//!   serves it as ordinary history. Check 3 is what pins that direction down.
//!
//! # Cost
//!
//! 17 seconds, in the normal suite, no `#[ignore]`. Each trial is two sequencer
//! processes, [`CONCURRENT`] trials at a time within each test. On four cores
//! (`taskset -c 0-3`) it is 19 seconds rather than 17: what these trials wait
//! for is the generator's 100 ms tick, not the processor, so a smaller machine
//! costs almost nothing here.
//!
//! Not ignored, because a crash test nobody runs is worth less than a slower one
//! that runs on every commit, and because the floor is the same 100 ms generator
//! tick `crash_restart.rs` pays: reaching a published message costs a tick and
//! no arrangement of the test makes that cheaper. What was traded to keep it at
//! 17 seconds is breadth: three publishes rather than thirty, one message per
//! transaction rather than a hundred, and only the persistent mode on a database
//! being created. Widening any of those is a matter of changing a number here.
//!
//! Run this file on its own with:
//!
//! ```text
//! cargo test --test fault_injection
//! ```
//!
//! Its temporary directories are under `$HOME/.cache`, not `/tmp`. `/tmp` here
//! is a 2 GB tmpfs mounted `noexec`: a shared library built into it cannot be
//! loaded at all, and databases written into it are RAM.

mod common;

use std::fs::{self, File};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{DEADLINE, Head, Sequencer, chain_over, client, head_of, history, wait_for_head};
use ed25519_dalek::Signature;
use rusqlite::Connection;
use serde::Deserialize;
use services::logchain::{self, Chain, EMPTY_CHAIN};
use services::merkle::{self, MerkleTree, NodeSource};
use tempfile::TempDir;
use tokio::task::JoinSet;
use tokio::time::sleep;

// ---------------------------------------------------------------------------
// The library that does the failing
// ---------------------------------------------------------------------------

/// The interposing library, compiled by `cc` when the test runs.
///
/// Kept here rather than in a `.c` file beside this one so that the whole
/// mechanism is one file: what is counted, what is failed, and what the test
/// reads back are three parts of one contract and drift if they are apart.
///
/// The control block is five `u64` and then a fixed log of four `u64` per
/// operation. All little-endian, no C layout to agree about: the reader picks
/// them out at fixed byte offsets.
const SHIM: &str = r##"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define MAX_FD 4096
#define LOG_SLOTS 512
#define SETUP_FAILED 97

struct control {
    uint64_t target;
    uint64_t mode;
    uint64_t count;
    uint64_t fired;
    uint64_t logged;
    uint64_t log[LOG_SLOTS * 4];
};

#define OP_PWRITE 1
#define OP_WRITE 2
#define OP_FSYNC 3
#define OP_FDATASYNC 4
#define OP_FTRUNCATE 5
#define OP_PWRITEV 6
#define OP_FAILED 0x100
#define OP_SHORT 0x200

static struct control *ctl;
static char prefix[PATH_MAX];
static size_t prefix_len;
static unsigned char watched[MAX_FD];
static unsigned char which[MAX_FD];

static int (*real_open)(const char *, int, ...);
static int (*real_open64)(const char *, int, ...);
static int (*real_openat)(int, const char *, int, ...);
static int (*real_close)(int);
static ssize_t (*real_pwrite)(int, const void *, size_t, off_t);
static ssize_t (*real_write)(int, const void *, size_t);
static ssize_t (*real_pwritev)(int, const struct iovec *, int, off_t);
static int (*real_fsync)(int);
static int (*real_fdatasync)(int);
static int (*real_ftruncate)(int, off_t);

/* Loud rather than inert: a library that quietly counts nothing would make
   every trial pass without failing anything. */
__attribute__((constructor)) static void setup(void)
{
    real_open = dlsym(RTLD_NEXT, "open");
    real_open64 = dlsym(RTLD_NEXT, "open64");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_close = dlsym(RTLD_NEXT, "close");
    real_pwrite = dlsym(RTLD_NEXT, "pwrite64");
    real_write = dlsym(RTLD_NEXT, "write");
    real_pwritev = dlsym(RTLD_NEXT, "pwritev");
    real_fsync = dlsym(RTLD_NEXT, "fsync");
    real_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
    real_ftruncate = dlsym(RTLD_NEXT, "ftruncate64");

    const char *db = getenv("FAULT_DB");
    const char *path = getenv("FAULT_CONTROL");
    if (!db || !path) {
        return;
    }
    if (!real_open || !real_pwrite || !real_close || !real_fsync || !real_ftruncate) {
        _exit(SETUP_FAILED);
    }
    size_t len = strlen(db);
    if (len == 0 || len >= sizeof(prefix)) {
        _exit(SETUP_FAILED);
    }
    memcpy(prefix, db, len + 1);
    prefix_len = len;

    int fd = real_open(path, O_RDWR, 0);
    if (fd < 0) {
        _exit(SETUP_FAILED);
    }
    void *map = mmap(NULL, sizeof(struct control), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    real_close(fd);
    if (map == MAP_FAILED) {
        _exit(SETUP_FAILED);
    }
    ctl = (struct control *)map;
}

/* Which descriptors are the database's. Set on open, cleared on close: the
   sequencer writes feed.key first and gets the same fd number back for
   feed.db afterwards. */
static void mark(int fd, const char *path)
{
    if (!ctl || fd < 0 || fd >= MAX_FD || !path) {
        return;
    }
    if (strncmp(path, prefix, prefix_len) != 0) {
        watched[fd] = 0;
        return;
    }
    const char *tail = path + prefix_len;
    watched[fd] = 1;
    if (strcmp(tail, "-wal") == 0) {
        which[fd] = 1;
    } else if (strcmp(tail, "-shm") == 0) {
        which[fd] = 2;
    } else if (strcmp(tail, "-journal") == 0) {
        which[fd] = 3;
    } else if (tail[0] == '\0') {
        which[fd] = 0;
    } else {
        which[fd] = 4;
    }
}

/* 0 run it, 1 fail it, 2 do half of it and report a short result. */
static int arrive(int fd, uint64_t op, uint64_t off, uint64_t len)
{
    if (!ctl || fd < 0 || fd >= MAX_FD || !watched[fd]) {
        return 0;
    }
    uint64_t n = __atomic_add_fetch(&ctl->count, 1, __ATOMIC_SEQ_CST);
    uint64_t target = ctl->target;
    int verdict = 0;
    if (target != 0 && ctl->mode != 0) {
        if (ctl->mode == 1) {
            verdict = (n == target) ? 1 : 0;
        } else if (ctl->mode == 3 && n == target) {
            verdict = 2;
        } else {
            verdict = (n >= target) ? 1 : 0;
        }
    }
    if (n <= LOG_SLOTS) {
        uint64_t *slot = &ctl->log[(n - 1) * 4];
        slot[0] = op | (verdict == 1 ? OP_FAILED : 0) | (verdict == 2 ? OP_SHORT : 0);
        slot[1] = which[fd];
        slot[2] = off;
        slot[3] = len;
        __atomic_store_n(&ctl->logged, n, __ATOMIC_SEQ_CST);
    }
    if (verdict != 0) {
        __atomic_add_fetch(&ctl->fired, 1, __ATOMIC_SEQ_CST);
    }
    return verdict;
}

static int creating(int flags)
{
#ifdef O_TMPFILE
    return (flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE;
#else
    return flags & O_CREAT;
#endif
}

int open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (creating(flags)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    int fd = real_open(path, flags, mode);
    mark(fd, path);
    return fd;
}

int open64(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (creating(flags)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    int fd = real_open64 ? real_open64(path, flags, mode) : real_open(path, flags, mode);
    mark(fd, path);
    return fd;
}

int openat(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (creating(flags)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    int fd = real_openat(dirfd, path, flags, mode);
    mark(fd, path);
    return fd;
}

int close(int fd)
{
    if (fd >= 0 && fd < MAX_FD) {
        watched[fd] = 0;
    }
    return real_close(fd);
}

static ssize_t hit_write(int fd, const void *buf, size_t count, off_t off, int positional)
{
    switch (arrive(fd, positional ? OP_PWRITE : OP_WRITE, (uint64_t)off, (uint64_t)count)) {
    case 1:
        errno = ENOSPC;
        return -1;
    case 2: {
        size_t half = count / 2;
        if (half == 0) {
            errno = ENOSPC;
            return -1;
        }
        return positional ? real_pwrite(fd, buf, half, off) : real_write(fd, buf, half);
    }
    default:
        return positional ? real_pwrite(fd, buf, count, off) : real_write(fd, buf, count);
    }
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t off)
{
    return hit_write(fd, buf, count, off, 1);
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off_t off)
{
    return hit_write(fd, buf, count, off, 1);
}

ssize_t write(int fd, const void *buf, size_t count)
{
    return hit_write(fd, buf, count, 0, 0);
}

ssize_t pwritev(int fd, const struct iovec *iov, int count, off_t off)
{
    size_t total = 0;
    for (int i = 0; i < count; i++) {
        total += iov[i].iov_len;
    }
    if (arrive(fd, OP_PWRITEV, (uint64_t)off, total) != 0) {
        errno = ENOSPC;
        return -1;
    }
    return real_pwritev(fd, iov, count, off);
}

int fsync(int fd)
{
    if (arrive(fd, OP_FSYNC, 0, 0) != 0) {
        errno = EIO;
        return -1;
    }
    return real_fsync(fd);
}

int fdatasync(int fd)
{
    if (arrive(fd, OP_FDATASYNC, 0, 0) != 0) {
        errno = EIO;
        return -1;
    }
    return real_fdatasync(fd);
}

int ftruncate(int fd, off_t length)
{
    if (arrive(fd, OP_FTRUNCATE, (uint64_t)length, 0) != 0) {
        errno = ENOSPC;
        return -1;
    }
    return real_ftruncate(fd, length);
}

int ftruncate64(int fd, off_t length)
{
    if (arrive(fd, OP_FTRUNCATE, (uint64_t)length, 0) != 0) {
        errno = ENOSPC;
        return -1;
    }
    return real_ftruncate(fd, length);
}
"##;

/// The one-shot failure: the nth operation returns `EIO` and nothing else does.
const TRANSIENT: u64 = 1;
/// The nth operation and every one after it return `ENOSPC`.
const PERSISTENT: u64 = 2;
/// The nth write puts half its bytes down and says so; the rest is `PERSISTENT`.
const TORN: u64 = 3;

/// The exit code the library uses when it is loaded and cannot set itself up.
/// Distinct from anything the sequencer exits with, so a broken shim reads as a
/// broken shim rather than as a broken sequencer.
const SHIM_BROKEN: i32 = 97;

/// Five `u64` of control block, then 512 operations of four `u64` each.
const LOG_SLOTS: usize = 512;
const CONTROL_BYTES: usize = 5 * 8 + LOG_SLOTS * 4 * 8;

/// The compiled library, and the directory holding it and every trial's files.
///
/// Under `$HOME/.cache` rather than `/tmp`, for two reasons that are both about
/// this machine and both real: `/tmp` is a 2 GB tmpfs, so databases written
/// there are RAM that other tests then do not have, and it is mounted `noexec`,
/// so a shared library built there cannot be loaded. The sequencer starts
/// normally with `ERROR: ld.so: object ... cannot be preloaded: ignored` on its
/// stderr and nothing is ever counted or failed.
struct Workspace {
    dir: TempDir,
    library: PathBuf,
}

impl Workspace {
    fn new(tag: &str) -> Workspace {
        let root = cache_root();
        fs::create_dir_all(&root).unwrap_or_else(|e| {
            panic!(
                "the test cache directory {} could not be made: {}",
                root.display(),
                e
            )
        });
        let dir = TempDir::with_prefix_in(format!("fault-{}-", tag), &root)
            .expect("a temporary directory for this test");
        let source = dir.path().join("fault.c");
        let library = dir.path().join("libfault.so");
        fs::write(&source, SHIM).expect("the shim source is written");
        // `cc` is not an extra requirement: `rusqlite` is built with `bundled`,
        // so nothing in this repository compiles at all without a C compiler.
        let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        let built = Command::new(&compiler)
            .args(["-O1", "-fPIC", "-shared", "-o"])
            .arg(&library)
            .arg(&source)
            .arg("-ldl")
            .output()
            .unwrap_or_else(|e| panic!("{} could not be run to build the shim: {}", compiler, e));
        assert!(
            built.status.success(),
            "the fault-injection shim did not compile with {}:\n{}",
            compiler,
            String::from_utf8_lossy(&built.stderr)
        );
        Workspace { dir, library }
    }

    /// A fresh directory for one trial. Named after the trial so a failure that
    /// leaves the workspace behind can be looked at.
    fn trial(&self, name: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        fs::create_dir_all(&path).expect("a directory for one trial");
        path
    }
}

/// Where this test may write. `$HOME/.cache/verifiable-exchange-tests`, or the
/// crate's own `target` directory when there is no `$HOME`, never the system
/// temporary directory, which is the one place the library cannot be loaded
/// from and the databases must not go.
fn cache_root() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => Path::new(&home)
            .join(".cache")
            .join("verifiable-exchange-tests"),
        None => Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("fault-injection"),
    }
}

// ---------------------------------------------------------------------------
// The control block
// ---------------------------------------------------------------------------

/// The file the shim maps: what to fail, and what it has done so far.
///
/// Read with ordinary file reads rather than a mapping of its own. The shim
/// writes through `MAP_SHARED`, which on Linux is the same page cache a `read`
/// comes out of, so the counter this returns is the counter the sequencer is
/// standing on right now: no crate, no `msync`, and it keeps working after the
/// process is killed.
struct Control {
    file: File,
    path: PathBuf,
}

impl Control {
    /// Creates the file, full size, with the verdict already in it. Full size
    /// matters: the shim maps the whole block, and a mapping past the end of a
    /// file is a `SIGBUS` on first touch.
    fn armed(path: PathBuf, target: u64, mode: u64) -> Control {
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("a control file for the shim");
        file.set_len(CONTROL_BYTES as u64)
            .expect("the control file is sized");
        let mut header = [0u8; 16];
        header[..8].copy_from_slice(&target.to_le_bytes());
        header[8..].copy_from_slice(&mode.to_le_bytes());
        file.write_all_at(&header, 0)
            .expect("the verdict is written");
        Control { file, path }
    }

    fn field(&self, index: u64) -> u64 {
        let mut bytes = [0u8; 8];
        self.file
            .read_exact_at(&mut bytes, index * 8)
            .expect("the control file is readable");
        u64::from_le_bytes(bytes)
    }

    /// How many operations against the database have happened so far.
    fn count(&self) -> u64 {
        self.field(2)
    }

    /// How many of them were failed. Zero after a run means the run finished
    /// without meeting a failure, which is where the enumeration stops.
    fn fired(&self) -> u64 {
        self.field(3)
    }

    /// Every operation the run made, in order, as far as the log holds.
    fn operations(&self) -> Vec<Operation> {
        let logged = self.field(4).min(LOG_SLOTS as u64) as usize;
        let mut bytes = vec![0u8; logged * 32];
        if logged > 0 {
            self.file
                .read_exact_at(&mut bytes, 5 * 8)
                .expect("the operation log is readable");
        }
        (0..logged)
            .map(|i| {
                let word = |k: usize| {
                    let at = i * 32 + k * 8;
                    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
                };
                Operation {
                    kind: word(0) & 0xff,
                    failed: word(0) & 0x100 != 0,
                    short: word(0) & 0x200 != 0,
                    file: word(1),
                    offset: word(2),
                    length: word(3),
                }
            })
            .collect()
    }
}

/// One counted filesystem operation, for the failure message. "the 20th
/// operation" says nothing; "fsync of feed.db-wal" says which one it was.
#[derive(Clone, Copy)]
struct Operation {
    kind: u64,
    failed: bool,
    short: bool,
    file: u64,
    offset: u64,
    length: u64,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self.kind {
            1 => "pwrite",
            2 => "write",
            3 => "fsync",
            4 => "fdatasync",
            5 => "ftruncate",
            6 => "pwritev",
            _ => "?",
        };
        let file = match self.file {
            0 => "feed.db",
            1 => "feed.db-wal",
            2 => "feed.db-shm",
            3 => "feed.db-journal",
            _ => "another file of the database",
        };
        write!(f, "{} of {}", kind, file)?;
        if self.length > 0 {
            write!(f, ", {} bytes at offset {}", self.length, self.offset)?;
        }
        if self.short {
            write!(f, " (half of it written)")?;
        } else if self.failed {
            write!(f, " (failed)")?;
        }
        Ok(())
    }
}

/// The operation the trial aimed at, named, or a note that the run never got
/// that far.
fn aimed_at(operations: &[Operation], n: u64) -> String {
    match operations.get((n - 1) as usize) {
        Some(op) => format!("operation {} is the {}", n, op),
        None => format!(
            "operation {} was never reached: the run made {} of them",
            n,
            operations.len()
        ),
    }
}

// ---------------------------------------------------------------------------
// The sequencer, as a process
// ---------------------------------------------------------------------------

/// One message every 100 ms, one transaction each. Same reason as
/// `crash_restart.rs`: it is what makes "after exactly n messages" something
/// the test can wait for from outside.
const RATE: &str = "10";

/// How many trials run at once. Each is two sequencer processes that spend
/// their time asleep between ticks.
const CONCURRENT: usize = 4;

/// How long the failed process is left alive after the failure, before it is
/// asked what it is serving.
///
/// One and a half generator ticks, so the process gets at least one whole tick
/// after the write failed. That tick is the interesting one: it is where a feed
/// that had published something it did not write would have to serve it.
const GRACE: Duration = Duration::from_millis(150);

// ---------------------------------------------------------------------------
// Reading the database the failure left behind
// ---------------------------------------------------------------------------

/// What one database holds, read without starting the binary on it.
struct Audit {
    /// How many messages, and the chain after each of them. Empty when the file
    /// holds no history.
    chains: Vec<Chain>,
    /// The session row, when there is one.
    session: Option<String>,
    /// The file could not be read as this feed's database at all. Only ever
    /// acceptable for a database that never held a message.
    unreadable: Option<String>,
}

impl Audit {
    fn messages(&self) -> u64 {
        self.chains.len() as u64
    }

    fn chain_at(&self, id: u64) -> Chain {
        if id == 0 {
            return EMPTY_CHAIN;
        }
        self.chains[(id - 1) as usize]
    }
}

/// The checkpoint row, as `feed.rs` writes it.
///
/// The last two are `None` in a checkpoint written before the feed signed its
/// tree root, and `feed.rs` reads them the same way: a database written by an
/// older build is a database with no statement about its tree, not a database
/// with a wrong one.
#[derive(Deserialize)]
struct Checkpoint {
    last_id: u64,
    chain: String,
    signature: String,
    #[serde(default)]
    root: Option<String>,
    #[serde(default)]
    root_signature: Option<String>,
}

/// Reads the database and checks everything that can be checked about it on its
/// own: the ids, the stored chain links, the signed checkpoint, and the tree.
///
/// **Runs on a copy, before anything has started on the original.** A start
/// would rebuild `merkle_nodes` from the messages when the table is short
/// (`FeedState::with_db`, via `tree::rebuild`), which is the right thing for a
/// derived table and is exactly what would hide a crash that left a message
/// without its nodes.
fn audit(db: &Path, key_path: &Path, what: &str) -> Audit {
    let unreadable = |e: rusqlite::Error| Audit {
        chains: Vec::new(),
        session: None,
        unreadable: Some(e.to_string()),
    };
    if !db.exists() {
        return Audit {
            chains: Vec::new(),
            session: None,
            unreadable: None,
        };
    }
    let conn = match Connection::open(db) {
        Ok(conn) => conn,
        Err(e) => return unreadable(e),
    };
    let table = |name: &str| -> Result<bool, rusqlite::Error> {
        conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |row| row.get::<_, i64>(0),
        )
        .map(|found| found == 1)
    };
    let tables = match (
        table("feed_messages"),
        table("feed_meta"),
        table("merkle_nodes"),
    ) {
        (Ok(messages), Ok(meta), Ok(nodes)) => (messages, meta, nodes),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return unreadable(e),
    };
    // A database whose CREATE TABLE was interrupted. There is no history in it:
    // the tables that would hold one do not exist. So it is an empty
    // database, and the caller checks that nothing was expected to be there.
    if !tables.0 {
        return Audit {
            chains: Vec::new(),
            session: None,
            unreadable: None,
        };
    }

    let rows: Vec<(i64, String, Vec<u8>)> = {
        let mut statement =
            match conn.prepare("SELECT id, json, chain FROM feed_messages ORDER BY id") {
                Ok(statement) => statement,
                Err(e) => return unreadable(e),
            };
        let read = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .and_then(|rows| rows.collect::<Result<Vec<_>, _>>());
        match read {
            Ok(rows) => rows,
            Err(e) => return unreadable(e),
        }
    };

    // 0. Ids 1..N with no gaps, and every stored link the fold up to it.
    let mut chains: Vec<Chain> = Vec::with_capacity(rows.len());
    let mut chain = EMPTY_CHAIN;
    for (index, (id, json, stored)) in rows.iter().enumerate() {
        let expected = index as i64 + 1;
        assert_eq!(
            *id, expected,
            "{}: row {} of feed_messages holds message {}, so a message below the head is missing",
            what, expected, id
        );
        chain = logchain::extend_bytes(&chain, json.as_bytes());
        assert_eq!(
            stored.as_slice(),
            chain.as_slice(),
            "{}: the chain link stored with message {} is not the chain its own messages produce",
            what,
            id
        );
        chains.push(chain);
    }
    let messages = chains.len() as u64;

    let meta = |key: &str| -> Option<String> {
        if !tables.1 {
            return None;
        }
        conn.query_row("SELECT value FROM feed_meta WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .ok()
    };
    let session = meta("session");
    let stored_checkpoint = meta("checkpoint");
    // The tree those messages make, built here rather than from the database:
    // it is what both the signed root in the checkpoint and the rows in
    // `merkle_nodes` are checked against.
    let entries: Vec<&[u8]> = rows.iter().map(|(_, json, _)| json.as_bytes()).collect();
    let tree = MerkleTree::from_entries(&entries);

    // 1. The checkpoint, the session and the messages are one write or none.
    match (&stored_checkpoint, messages) {
        (None, 0) => {}
        (None, count) => panic!(
            "{}: {} messages and no signed checkpoint. The two are written in one transaction, so \
             this is a state the feed cannot produce, and it is one a restart refuses to start on",
            what, count
        ),
        (Some(_), 0) => panic!(
            "{}: a signed checkpoint over a database with no messages in it. The checkpoint is \
             written in the transaction that writes the messages it covers",
            what
        ),
        (Some(stored), count) => {
            let session = session
                .as_deref()
                .unwrap_or_else(|| panic!("{}: a checkpoint with no session row beside it", what));
            let checkpoint: Checkpoint = serde_json::from_str(stored)
                .unwrap_or_else(|e| panic!("{}: the checkpoint is not readable: {}", what, e));
            assert_eq!(
                checkpoint.last_id, count,
                "{}: the checkpoint says the history ends at {} and the database holds {} messages",
                what, checkpoint.last_id, count
            );
            assert_eq!(
                checkpoint.chain,
                logchain::to_hex(&chain),
                "{}: the checkpoint's chain is not the one its own messages produce",
                what
            );
            assert!(
                key_path.exists(),
                "{}: the signing key beside the database is gone",
                what
            );
            let key = logchain::load_or_create_key(key_path)
                .unwrap_or_else(|e| panic!("{}: the signing key cannot be read: {}", what, e))
                .verifying_key();
            let signature = logchain::from_hex::<64>(&checkpoint.signature)
                .map(|bytes| Signature::from_bytes(&bytes))
                .unwrap_or_else(|| {
                    panic!("{}: the checkpoint's signature is not 64 hex bytes", what)
                });
            assert!(
                logchain::verify_head(&key, session, checkpoint.last_id, &chain, &signature),
                "{}: the checkpoint is not signed by the key beside the database for session {}",
                what,
                session
            );

            // And the root the feed signed beside that chain. It is the
            // strongest form of the claim this file is about: the checkpoint
            // states, under signature, what the tree over those messages is,
            // and it is written in the transaction that writes both.
            match (&checkpoint.root, &checkpoint.root_signature) {
                // A checkpoint from a build that did not sign the tree. No
                // statement about it, rather than a wrong one.
                (None, None) => {}
                (Some(root), Some(signature)) => {
                    let stored = logchain::from_hex::<32>(root).unwrap_or_else(|| {
                        panic!("{}: the checkpoint's root is not 32 hex bytes", what)
                    });
                    assert_eq!(
                        stored,
                        tree.root(),
                        "{}: the checkpoint names root {} and its own {} messages make a different \
                         one",
                        what,
                        root,
                        count
                    );
                    let signature = logchain::from_hex::<64>(signature)
                        .map(|bytes| Signature::from_bytes(&bytes))
                        .unwrap_or_else(|| {
                            panic!("{}: the root's signature is not 64 hex bytes", what)
                        });
                    assert!(
                        logchain::verify_checkpoint(
                            &key,
                            session,
                            checkpoint.last_id,
                            &chain,
                            &stored,
                            &signature
                        ),
                        "{}: the root in the checkpoint is not signed by the key beside the \
                         database",
                        what
                    );
                }
                _ => panic!(
                    "{}: the checkpoint holds one half of a signed root and not the other, and \
                     the two are one field of one row written once",
                    what
                ),
            }
        }
    }

    // 2. The tree is exactly the tree those messages make. Not one node short,
    // which is the shape a message written without its nodes would leave, and
    // not one node long, which is the shape nodes written without their message
    // would leave.
    if tables.2 {
        let mut statement = conn
            .prepare("SELECT level, idx, hash FROM merkle_nodes ORDER BY level, idx")
            .expect("the nodes table is readable");
        let stored = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .expect("the nodes are readable");
        let mut seen = 0u64;
        for row in stored {
            let (level, index, hash) = row.expect("a stored node");
            assert!(
                (index + 1) << level <= messages,
                "{}: merkle_nodes holds the node at level {} index {}, which covers leaves the \
                 {} messages beside it do not reach. Nodes were committed without their messages",
                what,
                level,
                index,
                messages
            );
            seen += 1;
            let node: merkle::Hash = hash.try_into().expect("a 32 byte node");
            assert_eq!(
                node,
                tree.node(level, index).expect("the tree has this node"),
                "{}: the node at level {} index {} is not the one its own messages make",
                what,
                level,
                index
            );
        }
        // A tree of n leaves is every leaf plus one node per perfect subtree,
        // which is n - popcount(n) of them.
        let expected = 2 * messages - messages.count_ones() as u64;
        assert_eq!(
            seen, expected,
            "{}: the database holds {} of the {} nodes a tree over its {} messages has, so a \
             message is on disk without the nodes that were written in the same transaction",
            what, seen, expected, messages
        );
    } else {
        assert_eq!(
            messages, 0,
            "{}: {} messages and no merkle_nodes table at all",
            what, messages
        );
    }

    Audit {
        chains,
        session,
        unreadable: None,
    }
}

/// Copies a database aside, exactly as it stands: the file, its write-ahead log
/// and its shared-memory index, which is what a crashed database is.
fn copy_database(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("a directory for the copy");
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let name = format!("feed.db{}", suffix);
        let source = from.join(&name);
        if source.exists() {
            fs::copy(&source, to.join(&name)).expect("the database is copied");
        }
    }
    let key = from.join("feed.key");
    if key.exists() {
        fs::copy(&key, to.join("feed.key")).expect("the key is copied");
    }
}

// ---------------------------------------------------------------------------
// One trial
// ---------------------------------------------------------------------------

/// What a trial starts from.
#[derive(Clone, Copy, PartialEq)]
enum Shape {
    /// An empty directory: the run creates the database, its tables and its
    /// first messages. The transaction that publishes message 1 is the one that
    /// writes the session and checkpoint rows for the first time and clears the
    /// tree before growing it.
    Fresh,
    /// A copy of a history the sequencer already published. The steady state: an
    /// insert into a table that has rows, a replace of two metadata rows, and an
    /// append onto a tree that already has nodes.
    Existing,
}

/// A history to start trials from, and the head it signed.
struct Base {
    dir: PathBuf,
    head: Head,
}

/// What one trial needs to know that is the same for all of them.
struct Setting {
    shape: Shape,
    /// How many messages a run publishes before the trial stops waiting.
    publish_to: u64,
    mode: u64,
}

/// Runs the sequencer once with nothing failed, to find out how many operations
/// the run makes and where each published message's transaction ends.
///
/// This is the last iteration of SQLite's loop, the one where the operation
/// runs to completion without meeting a simulated failure, run first so the
/// rest can go in parallel. The trials then enumerate 1 to that count.
async fn reference(
    workspace: &Workspace,
    base: Option<&Base>,
    setting: &Setting,
) -> (u64, Vec<(u64, u64)>, Vec<Operation>) {
    let dir = workspace.trial("reference");
    if let Some(base) = base {
        copy_database(&base.dir, &dir);
    }
    let db = dir.join("feed.db");
    let control = Control::armed(dir.join("control"), 0, 0);
    let mut running = Sequencer::start(
        &db,
        RATE,
        "reference",
        Some((&workspace.library, &control.path)),
    );
    let client = client();
    let mut url = running.url("/head");
    let give_up = Instant::now() + DEADLINE;
    // Where the count stood each time a new message appeared. Read from the
    // shim's counter at the moment the head moves, which is the only way from
    // outside the process to say which operations belong to which transaction.
    //
    // The first head this run answers with is where it starts, not something it
    // published: a restart on a three-message history serves 3 before it has
    // written anything. Only what moves after that is a transaction of this run.
    let mut marks: Vec<(u64, u64)> = Vec::new();
    let mut seen: Option<u64> = None;
    loop {
        if let Some(head) = head_of(&client, &url).await {
            match seen {
                None => seen = Some(head.last_id),
                Some(before) if head.last_id > before => {
                    seen = Some(head.last_id);
                    marks.push((head.last_id, control.count()));
                }
                Some(_) => {}
            }
            if head.last_id >= setting.publish_to {
                break;
            }
        }
        if running.lost_its_port() {
            // Nothing was opened and nothing was counted, so this starts over
            // rather than reporting a count of a run that did not happen.
            running = Sequencer::start(
                &db,
                RATE,
                "reference",
                Some((&workspace.library, &control.path)),
            );
            url = running.url("/head");
            marks.clear();
            seen = None;
            continue;
        }
        if let Some(status) = running.ended() {
            panic!(
                "the reference run ended with {} before publishing {} messages. It said:\n{}",
                status,
                setting.publish_to,
                running.said()
            );
        }
        assert!(
            Instant::now() < give_up,
            "the reference run did not publish {} messages within {:?}. It said:\n{}",
            setting.publish_to,
            DEADLINE,
            running.said()
        );
        sleep(Duration::from_millis(5)).await;
    }
    let count = control.count();
    let operations = control.operations();
    let said = running.said();
    running.kill_now();

    assert_eq!(
        control.fired(),
        0,
        "the reference run was supposed to fail nothing and failed {} operations",
        control.fired()
    );
    // The guard against a test that passes because it does nothing. A shim that
    // did not load, or loaded and matched no file, counts zero operations and
    // every trial below would then be a plain unfaulted run. `ld.so` says so on
    // the process's own stderr, which is in the log this prints.
    assert!(
        count > 0,
        "the shim counted no operation against {}. It is not intercepting: check that the \
         library loaded and that the database path it was given is the one SQLite opens. The \
         sequencer said:\n{}",
        db.display(),
        said
    );
    fs::remove_dir_all(&dir).ok();
    (count, marks, operations)
}

/// One failure point: start on a fresh copy, fail the nth operation, and check
/// everything that must still be true.
async fn trial(workspace: &Workspace, base: Option<&Base>, setting: &Setting, n: u64) -> u64 {
    let name = format!("mode{}-op{}", setting.mode, n);
    let dir = workspace.trial(&name);
    if let Some(base) = base {
        copy_database(&base.dir, &dir);
    }
    let db = dir.join("feed.db");
    let control = Control::armed(dir.join("control"), n, setting.mode);
    let client = client();

    let mut faulted = Sequencer::start(
        &db,
        RATE,
        "faulted",
        Some((&workspace.library, &control.path)),
    );
    let mut url = faulted.url("/head");
    let give_up = Instant::now() + DEADLINE;
    let mut ended = None;
    // Run until the failure has been delivered, or the run has published
    // everything it was going to publish without ever reaching operation n.
    loop {
        if control.fired() > 0 {
            break;
        }
        if faulted.lost_its_port() {
            // It never opened the database, so nothing it did has to be undone
            // and the shim has counted nothing. Another port, same trial.
            faulted = Sequencer::start(
                &db,
                RATE,
                "faulted",
                Some((&workspace.library, &control.path)),
            );
            url = faulted.url("/head");
            continue;
        }
        if let Some(status) = faulted.ended() {
            ended = Some(status);
            break;
        }
        if let Some(head) = head_of(&client, &url).await
            && head.last_id >= setting.publish_to
        {
            break;
        }
        assert!(
            Instant::now() < give_up,
            "{}: nothing had failed and nothing had been published within {:?}. It said:\n{}",
            name,
            DEADLINE,
            faulted.said()
        );
        sleep(Duration::from_millis(2)).await;
    }

    if control.fired() == 0 {
        // The run published everything it was going to publish and never
        // reached operation n. This is the iteration SQLite's loop stops at,
        // and there is nothing to check because nothing was failed.
        //
        // Killed here rather than after a wait, and that is the whole reason
        // this branch is separate: the generator publishes again 100 ms later,
        // and a run left alive for the wait below would reach operation n after
        // all and never let the enumeration end.
        let operations = control.operations();
        let said = faulted.said();
        faulted.kill_now();
        if let Some(status) = ended {
            panic!(
                "{}: the sequencer ended with {} without a single operation having been failed, \
                 so this trial tested nothing. It said:\n{}",
                name, status, said
            );
        }
        // Nothing counted at all is a shim that is not intercepting, which would
        // make every trial an ordinary run and this whole file vacuous.
        assert!(
            !operations.is_empty(),
            "{}: the shim counted no operation against the database, so nothing was under test. \
             It said:\n{}",
            name,
            said
        );
        assert!(
            n > operations.len() as u64,
            "{}: nothing was failed and the run made {} operations, so operation {} should have \
             been reached",
            name,
            operations.len(),
            n
        );
        fs::remove_dir_all(&dir).ok();
        return 0;
    }

    // One whole generator tick after the failure. What the process does with
    // the tick after a write has failed is the thing worth watching: this is
    // where a feed that published what it could not write would show it.
    sleep(GRACE).await;

    let fired = control.fired();
    let operations = control.operations();
    let ended = ended.or_else(|| faulted.ended());
    // Asked only of a process that is still running. One that has ended has let
    // go of its port, and an answer arriving on it afterwards is some other
    // sequencer's history rather than this one's.
    let live = match ended {
        Some(_) => None,
        None => head_of(&client, &url).await,
    };
    let said = faulted.said();
    faulted.kill_now();

    let at = aimed_at(&operations, n);
    if let Some(status) = ended {
        assert_ne!(
            status.code(),
            Some(SHIM_BROKEN),
            "{}: the fault-injection library could not set itself up inside the sequencer, so \
             this trial tested nothing",
            name
        );
        assert_eq!(
            status.code(),
            Some(2),
            "{}: {} failed and the sequencer ended with {} rather than refusing with exit 2. It \
             said:\n{}",
            name,
            at,
            status,
            said
        );
        assert!(
            said.contains("cannot use feed database") || said.contains("cannot use signing key"),
            "{}: {} failed and the sequencer exited 2 without naming a reason. It said:\n{}",
            name,
            at,
            said
        );
    }

    // Read the wreck on a copy, so nothing this test does can repair it and
    // nothing it reads can be something a restart rebuilt.
    let aside = dir.join("aside");
    copy_database(&dir, &aside);
    let what = format!("{} ({})", name, at);
    let found = audit(&aside.join("feed.db"), &aside.join("feed.key"), &what);

    // A file that cannot be read at all is only ever acceptable where there was
    // no history in it to lose: a database being created for the first time.
    if let Some(why) = &found.unreadable {
        assert!(
            setting.shape == Shape::Fresh && base.is_none(),
            "{}: {} failed and left a database that cannot be read: {}",
            what,
            at,
            why
        );
        assert!(
            live.as_ref().is_none_or(|head| head.last_id == 0),
            "{}: the sequencer signed a head over a database that cannot be read afterwards",
            what
        );
    }
    // The history the run started from is still all there. Said separately from
    // the checks on the restart below because this is about the file rather than
    // about what a process makes of it, and because a trial in which the audit
    // found nothing would pass every one of those checks by having nothing to
    // compare.
    if let Some(base) = base {
        assert!(
            found.messages() >= base.head.last_id,
            "{}: {} failed and the database now holds {} messages, and {} were published and \
             signed before this run started",
            what,
            at,
            found.messages(),
            base.head.last_id
        );
    }

    // 3. The process that was still running must not be ahead of its disk.
    if let Some(live) = &live {
        assert!(
            live.verifies(),
            "{}: the live sequencer's head is not signed: {:?}",
            what,
            live
        );
        assert!(
            live.last_id <= found.messages(),
            "{}: {} failed, and the sequencer went on serving a head at message {} while its \
             database holds {}. A message was published that was not written",
            what,
            at,
            live.last_id,
            found.messages()
        );
        assert_eq!(
            live.chain_bytes(),
            found.chain_at(live.last_id),
            "{}: the head the sequencer serves after the failure is not the chain the messages on \
             its disk produce",
            what
        );
    }

    // 4. A restart on the wreck.
    let mut restarted = Sequencer::start(&db, RATE, "restart", None);
    let after = loop {
        if let Some(head) = head_of(&client, &restarted.url("/head")).await {
            break head;
        }
        if restarted.lost_its_port() {
            restarted = Sequencer::start(&db, RATE, "restart", None);
            continue;
        }
        if let Some(status) = restarted.ended() {
            let said = restarted.said();
            assert_eq!(
                status.code(),
                Some(2),
                "{}: the restart ended with {} instead of serving or refusing. It said:\n{}",
                what,
                status,
                said
            );
            assert!(
                said.contains("cannot use feed database"),
                "{}: the restart refused without naming a reason. It said:\n{}",
                what,
                said
            );
            assert_eq!(
                found.messages(),
                0,
                "{}: the restart refused a database holding {} messages, so a published history \
                 can no longer be served. It said:\n{}",
                what,
                found.messages(),
                said
            );
            fs::remove_dir_all(&dir).ok();
            return fired;
        }
        assert!(
            Instant::now() < give_up,
            "{}: the restart neither answered nor ended within {:?}. It said:\n{}",
            what,
            DEADLINE,
            restarted.said()
        );
        sleep(Duration::from_millis(5)).await;
    };
    assert!(
        !restarted.said().contains("cannot use feed database"),
        "{}: the restart reported the database it was handed as unusable. It said:\n{}",
        what,
        restarted.said()
    );
    assert!(
        after.verifies(),
        "{}: the restarted head is not signed: {:?}",
        what,
        after
    );
    assert!(
        after.last_id >= found.messages(),
        "{}: the database holds {} messages and the restart serves a history ending at {}",
        what,
        found.messages(),
        after.last_id
    );

    // 6. And it can still publish. A feed that comes back readable and can
    // never append again is a feed that is down.
    let advanced = wait_for_head(
        &mut restarted,
        &client,
        after.last_id + 1,
        &format!("{}: restart", what),
    )
    .await
    .unwrap_or_else(|| {
        panic!(
            "{}: the restart lost a port it had already answered on",
            what
        )
    });
    let served = history(&client, &restarted, advanced.last_id).await;

    // 5. What it serves folds to what it signs, over ids with no gaps; and it
    // reproduces every head anything signed before it as a prefix.
    assert_eq!(
        chain_over(
            &served,
            advanced.last_id,
            &format!("{}: after the restart", what)
        ),
        advanced.chain_bytes(),
        "{}: the restarted sequencer signs a chain its own messages do not produce",
        what
    );
    for (whose, head) in [
        ("the base history", base.map(|base| &base.head)),
        ("the failed run", live.as_ref()),
    ] {
        let Some(head) = head else { continue };
        if head.last_id == 0 {
            continue;
        }
        assert_eq!(
            head.session, advanced.session,
            "{}: the restart opened session {} over a database whose history was signed as {}",
            what, advanced.session, head.session
        );
        assert_eq!(
            head.public_key, advanced.public_key,
            "{}: the restart signs with a different key than the history it continues",
            what
        );
        assert!(
            advanced.last_id >= head.last_id,
            "{}: message {} of {} was signed before the failure and the restart serves a history \
             ending at {}",
            what,
            head.last_id,
            whose,
            advanced.last_id
        );
        assert_eq!(
            chain_over(&served, head.last_id, &format!("{}: up to {}", what, whose)),
            head.chain_bytes(),
            "{}: {} signed message {} with chain {}. After the restart its own messages up to {} \
             produce a different chain, so the history was rewritten across the failure",
            what,
            whose,
            head.last_id,
            head.chain,
            head.last_id
        );
    }
    // The session survives, unless nothing was ever signed over this database,
    // in which case a new name is the point rather than an exception. See
    // `a_wiped_database_comes_back_under_a_new_session` in `crash_restart.rs`.
    // The row alone is not enough to keep a name: the checkpoint beside it is
    // what makes the name mean a history, and it is `with_db` that decides.
    if let Some(session) = found.session.as_ref().filter(|_| found.messages() > 0) {
        assert_eq!(
            &advanced.session, session,
            "{}: the database names history {} and the restart came back as {}",
            what, session, advanced.session
        );
    }

    restarted.kill_now();
    fs::remove_dir_all(&dir).ok();
    fired
}

/// Publishes a history with nothing failing, to start the `Existing` trials
/// from, and keeps the head it signed.
async fn build_base(workspace: &Workspace, messages: u64) -> Base {
    let dir = workspace.trial("base");
    let db = dir.join("feed.db");
    let client = client();
    let head = loop {
        let mut running = Sequencer::start(&db, RATE, "base", None);
        let head =
            wait_for_head(&mut running, &client, messages, "building the base history").await;
        running.kill_now();
        if let Some(head) = head {
            break head;
        }
    };
    assert!(
        head.verifies(),
        "the base history's head is signed by the key it names"
    );
    Base { dir, head }
}

/// Enumerates 1, 2, 3 … over one shape and one kind of failure, running
/// [`CONCURRENT`] trials at a time, and stops where SQLite's loop stops: at the
/// first run that finishes without meeting a failure.
async fn enumerate(setting: Setting, tag: &str) {
    let workspace = Workspace::new(tag);
    let base = match setting.shape {
        Shape::Fresh => None,
        Shape::Existing => Some(build_base(&workspace, 3).await),
    };
    let (operations, marks, _) = reference(&workspace, base.as_ref(), &setting).await;
    // The size of this enumeration, and where the transactions in it end. Shown
    // by `cargo test -- --nocapture`, and repeated in the failure messages.
    println!(
        "{}: {} filesystem operations to fail, one at a time; the transactions in it committed at \
         {:?}",
        tag, operations, marks
    );

    // Three past the end, so the loop reaches the iteration where nothing is
    // failed. The reference run's count is stable: the same run repeated gives
    // the same number, which `operations_of_a_publish_are_enumerated` checks.
    // But it is measured rather than assumed, and a run that does a little more
    // than the reference simply fails at a later point.
    let end = operations + 3;
    // Shared rather than borrowed because a spawned task outlives the borrow as
    // far as the compiler is concerned. Nothing in here is written after this
    // point; the trials only read the library path, the base history and the
    // setting.
    let shared = Arc::new((workspace, base, setting));
    let mut untouched = 0;
    let mut failed = 0;
    let points: Vec<u64> = (1..=end).collect();
    for batch in points.chunks(CONCURRENT) {
        let mut set = JoinSet::new();
        for &n in batch {
            let shared = Arc::clone(&shared);
            set.spawn(async move {
                let (workspace, base, setting) = &*shared;
                trial(workspace, base.as_ref(), setting, n).await
            });
        }
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(0) => untouched += 1,
                Ok(_) => failed += 1,
                Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
                Err(e) => panic!("a trial could not be run: {}", e),
            }
        }
    }
    // Every point was really failed, and the loop went past the last one. The
    // first is what makes this an enumeration rather than a sample; the second
    // is where SQLite's loop stops.
    assert!(
        failed >= operations,
        "only {} of the run's {} operations were failed, so this did not visit every point of the \
         write path. The transactions ended at {:?}",
        failed,
        operations,
        marks
    );
    assert!(
        untouched > 0,
        "every one of the {} trials met a failure, so the enumeration never reached the end of \
         the run's {} operations and the last point of the write path may be past it. The \
         transactions ended at {:?}",
        end,
        operations,
        marks
    );
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// The disk fills while the feed is running, and stays full, at every point in
/// the write path of a message.
///
/// The steady state: a history is already there, the transaction inserts into
/// tables that have rows, replaces the checkpoint and session rows, and appends
/// to a tree that already has nodes.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_disk_at_every_point_of_a_publish_leaves_a_whole_history() {
    enumerate(
        Setting {
            shape: Shape::Existing,
            publish_to: 6,
            mode: PERSISTENT,
        },
        "existing-persistent",
    )
    .await;
}

/// The disk fills in the middle of one write: half a WAL frame is really on
/// disk, and everything after it fails.
///
/// This is the one that reaches inside a single write rather than between two,
/// and it is the closest this can get to power loss without a kernel that lies.
/// What must hold is what the transaction promises: the message, its chain
/// link, the checkpoint over it and the nodes above it commit together or not at
/// all.
#[tokio::test(flavor = "multi_thread")]
async fn a_torn_write_at_every_point_of_a_publish_leaves_a_whole_history() {
    enumerate(
        Setting {
            shape: Shape::Existing,
            publish_to: 6,
            mode: TORN,
        },
        "existing-torn",
    )
    .await;
}

/// One bad write, then a disk that works again.
///
/// The failure the process is meant to survive rather than die of: `sequence`
/// returns the ids it allocated, the generator tries again on the next tick, and
/// the feed carries on. The check that matters here is the last one, that the
/// restart publishes again, and the one before it, that nothing was published
/// which was not written.
#[tokio::test(flavor = "multi_thread")]
async fn one_failed_write_is_survived_and_the_feed_keeps_publishing() {
    enumerate(
        Setting {
            shape: Shape::Existing,
            publish_to: 6,
            mode: TRANSIENT,
        },
        "existing-transient",
    )
    .await;
}

/// The disk fills while the database is being created: its header, its five
/// tables, its write-ahead log, and the first transaction that ever publishes
/// into it.
///
/// The first publish is not like the others. It writes the session and the
/// checkpoint rows for the first time rather than replacing them, and it clears
/// `merkle_nodes` before growing it, because a history that starts at leaf 0
/// must not land on another history's rows.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_disk_at_every_point_of_creating_a_database_loses_nothing_that_was_signed() {
    enumerate(
        Setting {
            shape: Shape::Fresh,
            publish_to: 4,
            mode: PERSISTENT,
        },
        "fresh-persistent",
    )
    .await;
}

/// The write path of one published message, named operation by operation.
///
/// Not an assertion about how many writes SQLite makes. That is SQLite's
/// business and it changes between versions. It is what makes the enumeration
/// above readable: it prints the operations a run makes and which of them belong
/// to the transaction that published each message, so "operation 20 failed" can
/// be read as "the fsync that commits message 4 failed".
///
/// It also holds the one claim the enumeration rests on: the same run repeated
/// makes the same operations in the same order, so the nth operation means the
/// same thing in every trial.
#[tokio::test(flavor = "multi_thread")]
async fn operations_of_a_publish_are_enumerated() {
    let workspace = Workspace::new("shape");
    let base = build_base(&workspace, 3).await;
    let setting = Setting {
        shape: Shape::Existing,
        publish_to: 6,
        mode: PERSISTENT,
    };

    let (first, marks, operations) = reference(&workspace, Some(&base), &setting).await;
    let mut report = String::new();
    for (index, operation) in operations.iter().enumerate() {
        let n = index as u64 + 1;
        let published = marks.iter().find(|(_, at)| *at == n).map(|(id, _)| *id);
        report.push_str(&format!(
            "  {:3} {}{}\n",
            n,
            operation,
            match published {
                Some(id) => format!("   <- message {} is committed here", id),
                None => String::new(),
            }
        ));
    }
    println!(
        "the sequencer's writes to feed.db, from a restart on a {}-message history to its {}th:\n{}",
        base.head.last_id, setting.publish_to, report
    );

    // The same run again, compared on what it did rather than on what the test
    // managed to watch. The operations come out of the shim's own log, so this
    // comparison does not depend on when the polling saw a head move; the
    // offsets are left out of it because they are where in the write-ahead log
    // a frame landed, which a checkpoint moves and nothing here promises.
    let (second, _, again) = reference(&workspace, Some(&base), &setting).await;
    let shape = |operations: &[Operation]| -> Vec<(u64, u64, u64)> {
        operations
            .iter()
            .map(|op| (op.kind, op.file, op.length))
            .collect()
    };
    assert_eq!(
        (first, shape(&operations)),
        (second, shape(&again)),
        "two runs of the same thing made different filesystem operations, so operation n in one \
         trial is not operation n in another. The enumeration is still complete: every point of \
         every run is visited. But a failure at a given number can no longer be compared between \
         runs, and the report above no longer says which write was failed"
    );
}

// ---------------------------------------------------------------------------
// The checks, shown catching what they are for
// ---------------------------------------------------------------------------
//
// Every trial above ends in `audit`, and every trial above passes. That is only
// worth something if `audit` would have said so had the database been wrong, so
// each of its three claims is shown here failing on a database built to break
// it. Without these, an `audit` that quietly checked nothing would pass the
// whole file, which is the same reason `crash_restart.rs` carries
// `a_rewritten_history_is_caught_by_the_head_from_before_the_crash`: that test
// is the one showing check 5 is not vacuous, and it is not repeated here.
//
// `#[should_panic]` rather than catching the unwinding by hand, so that a
// passing run prints nothing and the expected text names which check fired.

/// A history, published cleanly, for a check to be shown failing on.
async fn a_history_to_break(tag: &str) -> (Workspace, Base) {
    let workspace = Workspace::new(tag);
    let base = build_base(&workspace, 3).await;
    (workspace, base)
}

/// Check 2, on a message whose nodes are not there.
///
/// This is the state the whole file exists to rule out, and the one a restart
/// repairs on its own: `with_db` finds the tree short and builds the rest from
/// the messages. The audit runs before anything starts, which is the only place
/// the difference is visible.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "is on disk without the nodes")]
async fn a_message_without_its_nodes_is_caught() {
    let (workspace, base) = a_history_to_break("break-missing-node").await;
    let conn = Connection::open(base.dir.join("feed.db")).expect("the feed database opens");
    conn.execute(
        "DELETE FROM merkle_nodes WHERE level = 0 AND idx = (SELECT MAX(idx) FROM merkle_nodes \
         WHERE level = 0)",
        [],
    )
    .expect("the last leaf is removed");
    drop(conn);
    audit(
        &base.dir.join("feed.db"),
        &base.dir.join("feed.key"),
        "a leaf removed by hand",
    );
    drop(workspace);
}

/// Check 2 again, on a node that is there and is the wrong hash. A count that
/// comes out right is not a tree that comes out right.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "is not the one its own messages make")]
async fn a_node_the_messages_do_not_make_is_caught() {
    let (workspace, base) = a_history_to_break("break-wrong-node").await;
    let conn = Connection::open(base.dir.join("feed.db")).expect("the feed database opens");
    conn.execute(
        "UPDATE merkle_nodes SET hash = ?1 WHERE level = 0 AND idx = 0",
        rusqlite::params![[0u8; 32].as_slice()],
    )
    .expect("the first leaf is rewritten");
    drop(conn);
    audit(
        &base.dir.join("feed.db"),
        &base.dir.join("feed.key"),
        "a leaf rewritten by hand",
    );
    drop(workspace);
}

/// Check 1, on a checkpoint that covers a message the database no longer
/// holds, the shape a message written without the checkpoint beside it, or a
/// checkpoint written without its message, would leave.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "the checkpoint says the history ends at")]
async fn a_checkpoint_over_messages_that_are_not_there_is_caught() {
    let (workspace, base) = a_history_to_break("break-checkpoint").await;
    let conn = Connection::open(base.dir.join("feed.db")).expect("the feed database opens");
    conn.execute(
        "DELETE FROM feed_messages WHERE id = (SELECT MAX(id) FROM feed_messages)",
        [],
    )
    .expect("the last message is removed");
    drop(conn);
    audit(
        &base.dir.join("feed.db"),
        &base.dir.join("feed.key"),
        "a message removed by hand",
    );
    drop(workspace);
}

/// Check 1's last part, on a checkpoint that names a root its own messages do
/// not make.
///
/// The signed root is the strongest form of what this file is about: a
/// statement, in the same transaction as the messages and the nodes, of what
/// the tree over them is. A crash that left those disagreeing would land here.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "make a different one")]
async fn a_signed_root_the_messages_do_not_make_is_caught() {
    let (workspace, base) = a_history_to_break("break-root").await;
    let conn = Connection::open(base.dir.join("feed.db")).expect("the feed database opens");
    let stored: String = conn
        .query_row(
            "SELECT value FROM feed_meta WHERE key = 'checkpoint'",
            [],
            |row| row.get(0),
        )
        .expect("a published history has a checkpoint");
    let mut checkpoint: serde_json::Value =
        serde_json::from_str(&stored).expect("the checkpoint is a JSON object");
    if checkpoint.get("root").is_none_or(|root| root.is_null()) {
        // A build that does not sign the tree root has nothing here to break.
        panic!("this build writes no root, and its own messages make a different one");
    }
    checkpoint["root"] = serde_json::Value::String("11".repeat(32));
    conn.execute(
        "UPDATE feed_meta SET value = ?1 WHERE key = 'checkpoint'",
        rusqlite::params![checkpoint.to_string()],
    )
    .expect("the checkpoint is rewritten");
    drop(conn);
    audit(
        &base.dir.join("feed.db"),
        &base.dir.join("feed.key"),
        "a root rewritten by hand",
    );
    drop(workspace);
}
