//! The sequencer is killed mid-run and restarted on the same database.
//!
//! The claim under test is the one every other claim rests on: a message that
//! was published is on disk, and a restart continues that history rather than
//! rewriting it. Before this file that was covered by one restart on a happy
//! path.
//!
//! Everything here drives the real binary. Nothing calls `feed.rs`. A test that
//! starts the sequencer in process would be testing a function; this tests the
//! program an operator runs, including its startup checks and its exit codes,
//! and it keeps working while `feed.rs` is split into modules.
//!
//! # What is checked after every restart
//!
//! 1. The process starts, and does not report its own history as tampered.
//! 2. It serves the same session and the same public key as before the crash,
//!    unless the crash landed before it had published anything, in which case
//!    nothing was ever signed under that session and the restart mints a new
//!    one. See [`a_wiped_database_comes_back_under_a_new_session`] for why that
//!    distinction is the point rather than an exception.
//! 3. Its head stands at or past the last head the test saw before the crash.
//!    Nothing that was published and seen is lost.
//! 4. The messages it serves now fold to the chain in the head it signs now.
//! 5. The first `last_id` of those messages fold to the chain it signed
//!    *before* the crash.
//! 6. The ids it serves are 1..=last_id with no gaps.
//! 7. Every Merkle node in the database is the node those served messages make.
//!    The nodes are written in the same transaction as the messages, so a crash
//!    has no window between the two to land in; this is that claim under a real
//!    SIGKILL at a real moment rather than a comment saying so.
//!
//! Check 5 is the one that catches the failure the README describes. An earlier
//! sequencer recomputed the chain from its stored messages, found the stored
//! links disagreed after an edit, rewrote them to match, and signed the result.
//! That version passes checks 1 to 4 and 6: a sequencer that repairs itself is
//! self-consistent by construction. It fails check 5, because the head it
//! signed before the crash is a statement it can no longer reproduce.
//! [`a_rewritten_history_is_caught_by_the_head_from_before_the_crash`] builds
//! that database and shows the check firing on it, so this is a claim about the
//! test rather than about the design.
//!
//! Checks 4 and 6 together are what "wholly there or wholly absent" means from
//! outside the process. A half-written message is either missing, which leaves
//! a gap or a lower head, or present but not covered by the head, which breaks
//! the fold.
//!
//! # Enumerated, and not
//!
//! [`crash_after_each_of_the_first_messages`] is enumeration. It kills the
//! sequencer at head 0, then 1, then 2, up to [`ENUMERATED_END`], each on a
//! fresh database. Every one of those crash points is visited on every run, in
//! order, and a failure names the count it failed at.
//!
//! [`crash_at_a_random_moment_after_each_message`] is fuzzing, not enumeration,
//! and the difference is worth being exact about. It reaches each of the same
//! counts, then waits a random part of three generator ticks, then kills. Two
//! things follow from the delay. About two runs in three cross at least one
//! further commit, so the restart has to hand back messages the test never saw
//! while still reproducing the older head as a prefix of them. And the moment
//! of the signal is spread evenly across the tick, which is the only way this
//! file has of reaching the inside of one message's write path.
//!
//! It is a poor way. A SIGKILL that lands between the INSERT into
//! `feed_messages` and the checkpoint written beside it cannot be aimed at from
//! outside the process: the whole write path for one message is a few hundred
//! microseconds inside a 100 ms tick, so a signal at a moment chosen at random
//! lands inside it about one time in several hundred. 26 trials sample it 26
//! times. A run that passes is not evidence that every point in that path is
//! safe, and this file must not be read as saying so.
//!
//! [`crash_inside_a_burst_of_a_hundred_messages`] widens the target rather than
//! aiming better. At 1000 messages a second one transaction carries 100
//! inserts, so the process spends a larger share of each tick inside a write,
//! and the property under test is stronger: a crash has to leave all hundred
//! messages of a burst or none of them.
//!
//! A real enumeration needs the kill counted rather than timed: a filesystem
//! layer under SQLite that fails the nth write, which is what SQLite's own
//! crash tests use a virtual file system for. Two ways to get one here. Link a
//! VFS shim into a test binary, which means the sequencer has to run in
//! process and the test stops being a test of the program. Or interpose on the
//! process from outside, an LD_PRELOAD wrapper that counts `pwrite` and
//! `fdatasync` on `feed.db` and stops the process at the nth. The second keeps
//! the binary under test and is the one worth building. Neither exists here,
//! and until one does, the write path of a single message is sampled and not
//! covered.
//!
//! # What these tests do not reach
//!
//! - The disk-served read path. `MESSAGE_WINDOW` is 10,000 messages and the
//!   generator is capped at 1000 a second, so a restart that has to answer from
//!   `feed_messages` rather than from memory costs 10 seconds of running per
//!   trial. Every restart here is served from the window it rebuilt.
//! - Power loss. SIGKILL ends the process; it does not drop the page cache, so
//!   anything the process wrote without an fsync is still there afterwards.
//!   `feed.db` is opened with `synchronous = FULL` and does not depend on that.
//!   `feed.key` does: `logchain::load_or_create_key` writes it with `fs::write`
//!   and never syncs it or its directory. A crash loop built on SIGKILL cannot
//!   see that, and a lost `feed.key` makes every checkpoint in `feed.db`
//!   unverifiable for good.
//! - Inbox pairings. These runs are started without `--inbox-url`, so
//!   `inbox_sequenced` is never written and the crash points inside a drain are
//!   not visited.
//! - Two sequencers on one database. The port is bound before the database is
//!   opened so that a second process dies first, and nothing here checks that.
//!
//! # Cost
//!
//! About 9 seconds of wall time, in the normal suite, no `#[ignore]`. The five
//! tests run in parallel and each runs its trials four at a time. The floor is
//! the sequencer's own generator: it publishes on a 100 ms tick, so reaching a
//! head of n costs n tenths of a second and no arrangement of the test can make
//! that shorter.
//!
//! Run this file on its own with:
//!
//! ```text
//! cargo test --test crash_restart
//! ```

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use common::{Sequencer, chain_over, client, free_port, head_of, history, wait_for_head};
use rusqlite::Connection;
use serde::Deserialize;
use services::logchain::{self, Chain, EMPTY_CHAIN};
use services::merkle::{self, MerkleTree, NodeSource};
use services::wire;
use tempfile::TempDir;
use tokio::task::JoinSet;
use tokio::time::sleep;

// `logchain` and `wire` are the consumer's half of this repository: the fold
// over received bytes and the framing of a served page. Every validator, the
// exchange and the audit use exactly these two, and none of them is the
// sequencer. Reimplementing the fold here instead would put a second
// description of the chain format in the tree, and the two would drift.
//
// This is the one part of the file that the move from a hash chain to a Merkle
// tree changes. `chain_over` becomes a tree built from the same served bytes,
// and check 5 becomes `verify_consistency` between the head held from before
// the crash and the head found after it. Everything else is about the process
// and does not move: starting the binary, the signal, the restart, the
// assertions.

/// One message every 100 ms, and one database transaction for each.
///
/// The generator wakes on a fixed 100 ms tick and publishes whatever the rate
/// has accrued in one transaction. At 10 a second that accrues exactly one
/// message per tick, which is what makes "crash after exactly n messages"
/// something the test can wait for from outside.
const STEP_RATE: &str = "10";

/// The generator's ceiling: 100 messages accrued per tick, so one transaction
/// carries a hundred inserts. The case where a crash has to lose all hundred or
/// none of them.
const BURST_RATE: &str = "1000";

/// The last crash point the enumerated pass walks to.
///
/// 0 is a database with no messages and no checkpoint, so it is the only count
/// that reaches the branch of the startup check that mints a session instead of
/// reading one back. 1 is the first publish and the only one that inserts the
/// checkpoint and session rows rather than replacing them.
/// 2 and up are the steady state, and repeating it to 12 reaches no further
/// branch of the startup path. What the repetition buys is crash points for the
/// random-delay pass to sample, and it is cheap: 12 messages is 1.2 seconds of
/// the sequencer running.
///
/// The two size thresholds are out of reach here. A page is capped at 1000
/// messages and the memory window holds 10,000, and the generator cannot exceed
/// 1000 a second. [`crash_inside_a_burst_of_a_hundred_messages`] crosses the
/// first of them.
const ENUMERATED_END: u64 = 12;

/// How many trials run at once. Each trial is two sequencer processes and one
/// temporary directory, and the processes spend their time asleep between
/// ticks, so this is bounded by memory rather than by CPU.
const CONCURRENT: usize = 4;

/// How long the test waits, after the head it holds, before killing the
/// sequencer.
///
/// Three generator ticks rather than one. The head is read within 5 ms of a
/// commit, so a delay drawn from one tick almost never reaches the next commit:
/// measured over 26 trials, the restart came back at exactly the head the test
/// had seen every single time, and the crash never had a partly finished later
/// write to survive. Drawn from three ticks, the phase inside a tick is still
/// uniform and about two runs in three cross at least one further commit, so
/// the restart has to recover messages the test never saw, and still reproduce
/// the older head as a prefix of them.
fn random_linger() -> Duration {
    Duration::from_micros(rand::random::<u64>() % 300_000)
}

/// One crash and one restart.
///
/// The sequencer is started on an empty database at `rate` messages a second,
/// killed once its head has reached `at` and `linger` has passed, and started
/// again on the same database. `linger` is 0 for the enumerated pass and a
/// random delay for the fuzzing one; it is what moves the moment of the signal
/// relative to the write path.
///
/// The head is read once, before the delay, and deliberately not read again.
/// Holding a head that is older than the signal is the stronger claim: whatever
/// the sequencer published during the delay, and whatever it was part way
/// through publishing when the signal arrived, the history it serves after the
/// restart still has to reproduce that older head as a prefix.
async fn crash_and_restart(at: u64, rate: &str, linger: Duration) {
    let dir = TempDir::new().expect("a temporary directory");
    let db = dir.path().join("feed.db");
    let client = client();
    let what = format!("crash at {} messages, {:?} after the last head", at, linger);

    // The last statement the sequencer signed that this test actually saw. It
    // is a commitment: the messages were committed to disk before the head over
    // them was served. Everything after the crash is checked against it.
    //
    // The loop is for a sequencer that lost its port to another program before
    // it bound. That process opened no database and published nothing, so this
    // starts another one rather than reading the loss as a crash.
    let before = loop {
        let mut running = Sequencer::start(&db, rate, "before", None);
        let Some(head) = wait_for_head(&mut running, &client, at, &what).await else {
            continue;
        };
        sleep(linger).await;
        running.kill_now();
        break head;
    };
    assert!(
        before.verifies(),
        "the head signed before the crash is not signed by the key it names, so there is nothing \
         to check the restart against: {:?}",
        before
    );

    let (restarted, after) = loop {
        let mut restarted = Sequencer::start(&db, rate, "after", None);
        if let Some(head) = wait_for_head(&mut restarted, &client, 0, &what).await {
            break (restarted, head);
        }
    };

    // 1. It started, and it did not refuse its own history.
    assert!(
        !restarted.said().contains("cannot use feed database"),
        "crash at {} messages, {:?} after the last head: the sequencer refused the database it \
         wrote itself. It said:\n{}",
        at,
        linger,
        restarted.said()
    );

    // 2. The same history, continued, rather than a new one opened beside it.
    //
    // Except when the crash landed before the sequencer had published
    // anything. A session names a signed history and not a file, so a database
    // with nothing signed in it names nothing, and the restart mints a new
    // name rather than continuing one that never covered a message. That is
    // the whole of what tells a database emptied behind the sequencer's back
    // from one it has never written into, and it costs nothing here, because
    // an empty history has no receipt anywhere that refers to its name.
    if after.last_id == 0 {
        assert_ne!(
            after.session, before.session,
            "crash at {} messages: nothing had been signed under session {}, so a restart must \
             not carry that name onto whatever it publishes next",
            at, before.session
        );
    } else {
        assert_eq!(
            after.session, before.session,
            "crash at {} messages: the restart opened session {} over a database holding session \
             {}",
            at, after.session, before.session
        );
    }
    assert_eq!(
        after.public_key, before.public_key,
        "crash at {} messages: the restart signs with a different key than the history it \
         continues",
        at
    );

    // 3. Nothing that was published and seen was lost.
    assert!(
        after.last_id >= before.last_id,
        "crash at {} messages, {:?} after the last head: message {} was published and signed \
         before the crash, and the restart serves a history ending at {}",
        at,
        linger,
        before.last_id,
        after.last_id
    );
    assert!(
        after.verifies(),
        "crash at {} messages: the head served after the restart is not signed by the key it \
         names: {:?}",
        at,
        after
    );

    let served = history(&client, &restarted, after.last_id).await;

    // 4 and 6. What it serves folds to what it signs, over ids with no gaps.
    assert_eq!(
        chain_over(&served, after.last_id, "after the restart"),
        after.chain_bytes(),
        "crash at {} messages: the restarted sequencer signs a chain its own messages do not \
         produce",
        at
    );

    // 5. And the part of that history which existed before the crash still
    // produces the chain the sequencer signed then. A sequencer that repaired
    // itself and signed the repair fails here and nowhere else.
    assert_eq!(
        chain_over(&served, before.last_id, "up to the crash"),
        before.chain_bytes(),
        "crash at {} messages, {:?} after the last head: before the crash the sequencer signed \
         message {} with chain {}. After the restart its own messages up to {} produce a \
         different chain, so the history was rewritten across the restart",
        at,
        linger,
        before.last_id,
        before.chain,
        before.last_id
    );

    // 7. The Merkle tree in the database is the tree those messages make.
    //
    // This is the check that a crash cannot leave a message without its node or
    // a node without its message. The two are written in one transaction, so
    // there is no window between them to crash in, and every trial here is a
    // real SIGKILL at a real moment, so this is that claim tested rather than
    // asserted.
    stored_tree_matches(&db, &served, after.last_id, at);

    // `restarted` is dropped before `dir`, so the process is gone before the
    // directory holding its database is removed.
}

/// Checks every stored Merkle node against the tree `merkle.rs` builds from the
/// messages the sequencer served.
///
/// The comparison itself is `merkle::compare_nodes`, which is the same function
/// the checker and the audit run over the nodes `/tree/nodes` serves. Only the
/// source differs, and deliberately: this test is about what a crash leaves in
/// the file, so it reads the file. A stranger has HTTP.
///
/// `compare_nodes` also holds the rule about how far to compare: a node
/// covering a leaf past `upto` is a node for a message the reader never saw,
/// and the restarted sequencer keeps publishing while this runs.
fn stored_tree_matches(db: &Path, served: &[wire::RawMessage], upto: u64, at: u64) {
    let entries: Vec<&[u8]> = served
        .iter()
        .take(upto as usize)
        .map(|message| message.bytes.as_slice())
        .collect();
    let tree = MerkleTree::from_entries(&entries);
    // Every node those messages make, which is what the database must hold.
    let mut ours: BTreeMap<(u32, u64), merkle::Hash> = BTreeMap::new();
    for leaf in 0..upto {
        for (level, index) in merkle::appended_at(leaf) {
            ours.insert(
                (level, index),
                tree.node(level, index).expect("the tree has this node"),
            );
        }
    }

    // Read-only, and it fails rather than creating anything: a wrong path must
    // be an error and not an empty database that passes. The sequencer is still
    // publishing into this file, and a read-write handle can run recovery or a
    // checkpoint on open and on close, writing to the database a live process
    // owns. See `store::HistoryReader::open`, which is the same open.
    let conn = Connection::open_with_flags(
        db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .expect("the feed database opens read-only");
    conn.busy_timeout(Duration::from_secs(5))
        .expect("the busy timeout is set");
    let mut statement = conn
        .prepare("SELECT level, idx, hash FROM merkle_nodes ORDER BY level, idx")
        .expect("the nodes table is readable");
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .expect("the nodes are readable");
    let mut stored: BTreeMap<(u32, u64), merkle::Hash> = BTreeMap::new();
    for row in rows {
        let (level, index, hash) = row.expect("a stored node");
        stored.insert((level, index), hash.try_into().expect("a 32 byte node"));
    }

    let faults = merkle::compare_nodes(&ours, &stored, 0..upto);
    assert!(
        faults.is_empty(),
        "crash at {} messages: {}",
        at,
        faults.join("\n")
    );
    // And the count, which says the same thing a second way and catches one
    // thing the comparison cannot: a reader pointing at the wrong file. An
    // empty database gives zero here.
    let seen = stored
        .keys()
        .filter(|(level, index)| ((*index as u128 + 1) << level) <= upto as u128)
        .count() as u64;
    assert_eq!(
        seen,
        merkle::nodes_in(upto),
        "crash at {} messages: the database holds {} of the {} nodes a tree over its {} messages \
         has",
        at,
        seen,
        merkle::nodes_in(upto),
        upto
    );
}

/// Runs trials `CONCURRENT` at a time, keeping each trial's own panic message.
///
/// A trial that fails takes the whole test with it, and the others in flight
/// are dropped, which runs their `Sequencer` and `TempDir` destructors, so a
/// failure leaves nothing behind either.
async fn run_trials(trials: Vec<(u64, &'static str, Duration)>) {
    for batch in trials.chunks(CONCURRENT) {
        let mut set = JoinSet::new();
        for &(at, rate, linger) in batch {
            set.spawn(crash_and_restart(at, rate, linger));
        }
        while let Some(joined) = set.join_next().await {
            if let Err(e) = joined {
                if e.is_panic() {
                    std::panic::resume_unwind(e.into_panic());
                }
                panic!("a crash trial could not be run: {}", e);
            }
        }
    }
}

/// Enumeration: a crash after exactly 0, 1, 2 … [`ENUMERATED_END`] messages,
/// each on a database that starts empty.
///
/// Every count is visited on every run. Nothing here is random, and a failure
/// names the count.
#[tokio::test(flavor = "multi_thread")]
async fn crash_after_each_of_the_first_messages() {
    let trials = (0..=ENUMERATED_END)
        .map(|at| (at, STEP_RATE, Duration::ZERO))
        .collect();
    run_trials(trials).await;
}

/// Fuzzing: the same counts, with the signal delayed by a random part of three
/// generator ticks.
///
/// This is the only coverage of the inside of one message's write path, and it
/// is sampling rather than enumeration. See the note at the top of this file
/// for what it would take to enumerate that, why it cannot be done from outside
/// the process as it stands, and how thin the sampling is.
///
/// The delay is drawn fresh on every run, so this test does not check the same
/// thing twice. That is what a sampler is for, and it is why every failure
/// message in `crash_and_restart` carries the delay that produced it.
#[tokio::test(flavor = "multi_thread")]
async fn crash_at_a_random_moment_after_each_message() {
    let mut trials = Vec::new();
    for _ in 0..2 {
        for at in 0..=ENUMERATED_END {
            trials.push((at, STEP_RATE, random_linger()));
        }
    }
    run_trials(trials).await;
}

/// A crash while the sequencer is writing a hundred messages in one
/// transaction.
///
/// Two things this reaches and the other tests do not. The transaction carries
/// 100 inserts, so a crash inside it has to leave all hundred or none of them:
/// there is no partial burst that the checks above would accept. And 1200
/// messages is past the 1000 a page holds, so the restarted sequencer's history
/// is read back over two requests rather than one.
#[tokio::test(flavor = "multi_thread")]
async fn crash_inside_a_burst_of_a_hundred_messages() {
    crash_and_restart(1200, BURST_RATE, random_linger()).await;
}

/// After a crash, one row of `feed.db` is edited by hand. The sequencer has to
/// refuse to start and change nothing.
///
/// This is the behaviour README.md documents under "Tampering is refused, not
/// repaired", and it is checked after a crash rather than after a clean stop
/// because the two interact: the crash leaves the write-ahead log holding
/// committed messages, and the tamper check runs over a database SQLite has
/// just recovered.
#[tokio::test(flavor = "multi_thread")]
async fn an_edit_after_a_crash_is_refused_and_not_repaired() {
    let dir = TempDir::new().expect("a temporary directory");
    let db = dir.path().join("feed.db");
    let client = client();

    loop {
        let mut running = Sequencer::start(&db, STEP_RATE, "before", None);
        let head = wait_for_head(&mut running, &client, 3, "before the edit").await;
        running.kill_now();
        if head.is_some() {
            break;
        }
    }

    // The edit, and the two chain values the refusal has to name: the one the
    // sequencer signed, which is in the checkpoint the crash left behind, and
    // the one its messages produce now that one of them has been changed.
    let signed = checkpoint_chain(&db);
    edit_message_one(&db);
    let produced = logchain::to_hex(&fold_stored_messages(&db));
    assert_ne!(
        signed, produced,
        "the edit changed no bytes, so this test would pass without the check it is testing"
    );

    let before = stored_rows(&db);

    // `Command::output` rather than a `Sequencer`, because this start has to
    // end by itself. The port is bound before the database is opened, so the
    // process needs a free one even though it will never serve anything.
    let refused = Command::new(env!("CARGO_BIN_EXE_services"))
        .arg("--start-feed")
        .arg("--feed-port")
        .arg(free_port().to_string())
        .arg("--feed-db")
        .arg(&db)
        .arg("--rate")
        .arg(STEP_RATE)
        .output()
        .expect("the services binary starts");

    assert_eq!(
        refused.status.code(),
        Some(2),
        "the sequencer did not exit 2 over an edited row"
    );
    // Both streams, because the refusal is logged through `tracing`, whose
    // default writer is stdout rather than stderr.
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        said.contains("does not hold the history this feed last published"),
        "the sequencer refused an edited database for some other reason: {}",
        said
    );
    assert!(
        said.contains(&signed),
        "the refusal does not name the chain the sequencer signed ({}): {}",
        signed,
        said
    );
    assert!(
        said.contains(&produced),
        "the refusal does not name the chain the edited messages produce ({}): {}",
        produced,
        said
    );

    // "It changes nothing." A start that repaired the row, rewrote the stored
    // link, or moved the checkpoint to match would still have exited 2.
    assert_eq!(
        stored_rows(&db),
        before,
        "the sequencer wrote to a database it refused to start on"
    );
}

/// The wipe, against the running binary and the HTTP contract a consumer
/// reads: exactly the two `sqlite3` statements an operator would type.
///
/// This is the whole attack, and it is the only tampering path a start cannot
/// refuse. Delete every message and the checkpoint, leave the session row,
/// `feed_accounts` and `feed.key` where the sequencer put them, and start the
/// same binary on the same file. There is nothing left to refuse: the evidence
/// each of the three startup checks reads is the row the wipe removes. So it
/// starts, as it must.
///
/// What it must not do is come back under the name consumers pinned. It used
/// to: the same session and the same key on `/head`, standing at message 1
/// again, signing a second history that shared nothing with the first and that
/// no consumer could tell apart from the first still running.
#[tokio::test(flavor = "multi_thread")]
async fn a_wiped_database_comes_back_under_a_new_session() {
    let dir = TempDir::new().expect("a temporary directory");
    let db = dir.path().join("feed.db");
    let client = client();

    let before = loop {
        let mut running = Sequencer::start(&db, STEP_RATE, "before", None);
        let head = wait_for_head(&mut running, &client, 3, "before the wipe").await;
        running.kill_now();
        if let Some(head) = head {
            break head;
        }
    };
    assert!(before.verifies(), "the head before the wipe is signed");
    assert!(before.last_id >= 3);

    // `sqlite3 feed.db "DELETE FROM feed_messages;
    //                   DELETE FROM feed_meta WHERE key='checkpoint';"`
    {
        let conn = Connection::open(&db).expect("the feed database opens");
        conn.execute_batch(
            "DELETE FROM feed_messages;
             DELETE FROM feed_meta WHERE key = 'checkpoint';",
        )
        .expect("the wipe runs");
        let left: i64 = conn
            .query_row(
                "SELECT count(*) FROM feed_meta WHERE key = 'session'",
                [],
                |row| row.get(0),
            )
            .expect("the metadata table is readable");
        assert_eq!(left, 1, "the attack leaves the session row in place");
    }

    let (mut restarted, after) = loop {
        let mut restarted = Sequencer::start(&db, STEP_RATE, "after", None);
        if let Some(head) = wait_for_head(&mut restarted, &client, 1, "after the wipe").await {
            break (restarted, head);
        }
    };
    assert!(
        !restarted.said().contains("cannot use feed database"),
        "the wiped database was refused at startup, so this test is not reproducing the attack \
         it claims to. The sequencer said:\n{}",
        restarted.said()
    );

    assert!(after.verifies(), "the head after the wipe is signed");
    assert_eq!(
        after.public_key, before.public_key,
        "the key beside the database survives a wipe, which is why the name has to carry the \
         difference"
    );
    assert_ne!(
        after.session, before.session,
        "the wiped database published message 1 again under the name the first history was \
         signed under, so one name now covers two histories and no consumer can tell them apart"
    );

    // The new name is on disk, not only in the process that minted it: a
    // consumer that reconnects after a second restart must not find the old
    // one back.
    restarted.kill_now();
    let (_again, third) = loop {
        let mut again = Sequencer::start(&db, STEP_RATE, "again", None);
        if let Some(head) = wait_for_head(&mut again, &client, 1, "after the second start").await {
            break (again, head);
        }
    };
    assert_eq!(
        third.session, after.session,
        "the new history's name did not survive its own restart"
    );
}

/// The check that would have caught the bug the README describes, shown to
/// catch it.
///
/// A sequencer that rewrites its stored chain to match an edit and signs the
/// result is self-consistent afterwards. It starts, it serves a history, and
/// that history folds to the head it signs now. No check made after the restart
/// can tell the difference, because every value it could compare has been
/// brought into agreement.
///
/// So this builds that state from outside the process: one message edited,
/// every stored link rewritten, the checkpoint re-signed with the key beside
/// the database. It then makes the same two comparisons `crash_and_restart`
/// makes. The first has to pass and the second has to fail. Without this test,
/// a version of check 5 that compared the restart against itself would pass
/// every run above, exactly as the real one does.
#[tokio::test(flavor = "multi_thread")]
async fn a_rewritten_history_is_caught_by_the_head_from_before_the_crash() {
    let dir = TempDir::new().expect("a temporary directory");
    let db = dir.path().join("feed.db");
    let client = client();

    let before = loop {
        let mut running = Sequencer::start(&db, STEP_RATE, "before", None);
        if wait_for_head(&mut running, &client, 4, "before the rewrite")
            .await
            .is_none()
        {
            continue;
        }
        let head = head_of(&client, &running.url("/head"))
            .await
            .expect("the sequencer answers for its own head before it is killed");
        running.kill_now();
        break head;
    };
    rewrite_history(&db);

    let (restarted, after) = loop {
        let mut restarted = Sequencer::start(&db, STEP_RATE, "after", None);
        if let Some(head) = wait_for_head(&mut restarted, &client, 0, "after the rewrite").await {
            break (restarted, head);
        }
    };
    assert!(
        !restarted.said().contains("cannot use feed database"),
        "the rewritten history was refused at startup, so this test is not reproducing the bug \
         it claims to. The sequencer said:\n{}",
        restarted.said()
    );
    let served = history(&client, &restarted, after.last_id).await;
    assert_eq!(
        chain_over(&served, after.last_id, "after the rewrite"),
        after.chain_bytes(),
        "the rewritten database is not self-consistent, so this test is not reproducing the bug \
         it claims to"
    );

    assert_ne!(
        chain_over(&served, before.last_id, "up to the crash"),
        before.chain_bytes(),
        "a history rewritten across the crash was not caught by the head the sequencer signed \
         before it"
    );
}

/// Does to the database what the sequencer this project describes used to do to
/// itself: edit a message, bring every stored chain link and every Merkle node
/// into agreement with the edit, and sign the result with the sequencer's own
/// key.
///
/// The key is read from `feed.key` beside the database. That is the whole cost
/// of forging this: anyone holding that file can produce a history the
/// sequencer will start on, which is why the README says a signed checkpoint
/// only protects against edits made without the key.
///
/// The tree is rewritten here for the same reason the chain links are. The
/// checkpoint now states the root as well as the chain, so a forgery that left
/// the old nodes in place would be refused at startup, by the check for a
/// rewritten tree, not by anything about this edit. This test would then stop
/// reproducing the bug it is about.
fn rewrite_history(db: &Path) {
    let key = logchain::load_or_create_key(&db.with_extension("key"))
        .expect("the sequencer left its signing key beside the database");
    let conn = Connection::open(db).expect("the feed database opens");
    let session: String = conn
        .query_row(
            "SELECT value FROM feed_meta WHERE key = 'session'",
            [],
            |row| row.get(0),
        )
        .expect("the database names its session");

    let mut messages: Vec<(i64, String)> = {
        let mut statement = conn
            .prepare("SELECT id, json FROM feed_messages ORDER BY id")
            .expect("the messages table is readable");
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("the messages are readable");
        rows.map(|row| row.expect("a stored message")).collect()
    };
    assert!(!messages.is_empty(), "there is nothing to rewrite");
    messages[0].1 = bump_timestamp(&messages[0].1);

    let mut chain = EMPTY_CHAIN;
    let mut last_id = 0;
    for (id, json) in &messages {
        chain = logchain::extend_bytes(&chain, json.as_bytes());
        conn.execute(
            "UPDATE feed_messages SET json = ?1, chain = ?2 WHERE id = ?3",
            rusqlite::params![json, chain.as_slice(), id],
        )
        .expect("the row is rewritten");
        last_id = *id as u64;
    }

    // The tree over the edited messages, row for row over the one that is
    // there. A tree of n leaves stores the same (level, idx) whatever is under
    // them, so this replaces every row and adds none.
    let entries: Vec<&[u8]> = messages.iter().map(|(_, json)| json.as_bytes()).collect();
    let tree = MerkleTree::from_entries(&entries);
    let mut level = 0u32;
    while last_id >> level > 0 {
        for idx in 0..(last_id >> level) {
            let node = tree.node(level, idx).expect("the tree has this node");
            conn.execute(
                "INSERT OR REPLACE INTO merkle_nodes (level, idx, hash) VALUES (?1, ?2, ?3)",
                rusqlite::params![level, idx, node.as_slice()],
            )
            .expect("the node is rewritten");
        }
        level += 1;
    }

    let checkpoint = serde_json::json!({
        "last_id": last_id,
        "chain": logchain::to_hex(&chain),
        "signature": logchain::to_hex(
            &logchain::sign_head(&key, &session, last_id, &chain).to_bytes(),
        ),
        "root": logchain::to_hex(&tree.root()),
        "root_signature": logchain::to_hex(
            &logchain::sign_checkpoint(&key, &session, last_id, &chain, &tree.root()).to_bytes(),
        ),
    })
    .to_string();
    conn.execute(
        "INSERT OR REPLACE INTO feed_meta (key, value) VALUES ('checkpoint', ?1)",
        rusqlite::params![checkpoint],
    )
    .expect("the checkpoint is re-signed");
}

/// The chain the sequencer last signed, out of the checkpoint row.
fn checkpoint_chain(db: &Path) -> String {
    #[derive(Deserialize)]
    struct Checkpoint {
        chain: String,
    }
    let conn = Connection::open(db).expect("the feed database opens");
    let stored: String = conn
        .query_row(
            "SELECT value FROM feed_meta WHERE key = 'checkpoint'",
            [],
            |row| row.get(0),
        )
        .expect("a sequencer that published anything left a checkpoint");
    let checkpoint: Checkpoint =
        serde_json::from_str(&stored).expect("the checkpoint is a JSON object");
    checkpoint.chain
}

/// Changes one field of message 1, which is what the README's `sqlite3`
/// command does.
fn edit_message_one(db: &Path) {
    let conn = Connection::open(db).expect("the feed database opens");
    let json: String = conn
        .query_row("SELECT json FROM feed_messages WHERE id = 1", [], |row| {
            row.get(0)
        })
        .expect("message 1 is there");
    conn.execute(
        "UPDATE feed_messages SET json = ?1 WHERE id = 1",
        rusqlite::params![bump_timestamp(&json)],
    )
    .expect("the row is edited");
}

/// One message with its timestamp moved by a millisecond.
///
/// The timestamp rather than the price, because every message kind carries a
/// timestamp and only `New` carries a price. One digit rather than the whole
/// value, so the row is still a valid feed message of the same length: a
/// refusal has to be about the chain, not about bytes that no longer parse.
fn bump_timestamp(json: &str) -> String {
    const FIELD: &str = "\"timestamp\":";
    let start = json.find(FIELD).expect("every message carries a timestamp") + FIELD.len();
    let end = start
        + json[start..]
            .find(|c: char| !c.is_ascii_digit())
            .expect("the timestamp is followed by another field");
    let digits = json[start..end].as_bytes();
    let last = (digits[digits.len() - 1] - b'0' + 1) % 10;
    format!(
        "{}{}{}{}",
        &json[..start],
        &json[start..end - 1],
        last,
        &json[end..]
    )
}

/// The chain the stored messages produce right now.
fn fold_stored_messages(db: &Path) -> Chain {
    let conn = Connection::open(db).expect("the feed database opens");
    let mut statement = conn
        .prepare("SELECT json FROM feed_messages ORDER BY id")
        .expect("the messages table is readable");
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("the messages are readable");
    let mut chain = EMPTY_CHAIN;
    for json in rows {
        chain = logchain::extend_bytes(&chain, json.expect("a stored message").as_bytes());
    }
    chain
}

/// Every row a start could have rewritten: the messages with their stored
/// chain links, and the metadata holding the session and the checkpoint.
fn stored_rows(db: &Path) -> Vec<String> {
    let conn = Connection::open(db).expect("the feed database opens");
    let mut out = Vec::new();
    let mut messages = conn
        .prepare("SELECT id, json, chain FROM feed_messages ORDER BY id")
        .expect("the messages table is readable");
    let rows = messages
        .query_map([], |row| {
            Ok(format!(
                "{} {} {}",
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                logchain::to_hex(&row.get::<_, Vec<u8>>(2)?)
            ))
        })
        .expect("the messages are readable");
    for row in rows {
        out.push(row.expect("a stored message"));
    }
    let mut meta = conn
        .prepare("SELECT key, value FROM feed_meta ORDER BY key")
        .expect("the metadata table is readable");
    let rows = meta
        .query_map([], |row| {
            Ok(format!(
                "{} {}",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?
            ))
        })
        .expect("the metadata is readable");
    for row in rows {
        out.push(row.expect("a metadata row"));
    }
    out
}
