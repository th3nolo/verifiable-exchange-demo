//! Can a stranger tell that the operator lied?
//!
//! Every other test in this repository asks whether the code does the right
//! thing. This file asks the opposite question. It takes a working exchange,
//! breaks one specific thing, and then runs every tool a stranger has: the
//! checker (`--verify`), the audit (`--audit`), and the audit over HTTP
//! (`--audit-url`). It records what each one said.
//!
//! The result of a run is a table of attack against tool, with **caught** or
//! **missed** in every cell. The table is asserted, not printed, so a change
//! that closes a hole fails this file and the person closing it updates the
//! row. A change that *opens* one fails it too.
//!
//! # What counts as caught
//!
//! A tool catches an attack when it exits non-zero. Nothing here reads a
//! check's name to decide: a tool that failed for the wrong reason is still a
//! tool that refused to pass a broken exchange, and the report it printed is
//! kept in the temporary directory for a person to read.
//!
//! The exchange refusing to start is recorded separately and is **not** a
//! catch. It is the operator's own program refusing the operator's own
//! database, and an operator who edited the database can edit that check out.
//! A stranger never runs it.
//!
//! # Why the tests are `#[ignore]`d
//!
//! Each one starts real processes, publishes a few hundred messages, and runs
//! three tools over them. Tier 1 takes about a minute and Tier 2 about four.
//! `cargo test` runs the rest of the suite in less than that all together, so
//! these are behind `--ignored`:
//!
//! ```text
//! cargo test --release --test adversarial -- --ignored --nocapture
//! cargo test --release --features dishonest --test adversarial -- --ignored --nocapture
//! ```
//!
//! The second line is Tier 2, which needs the dishonest exchange. See
//! `src/dishonest.rs` for what that is and how it is kept out of a release.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use services::logchain::{self, Chain, EMPTY_CHAIN};

/// How long anything is waited for before the test gives up and says what it
/// was waiting for.
const DEADLINE: Duration = Duration::from_secs(60);

/// What one tool said about one attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// The tool exited non-zero: it refused to pass this exchange.
    Caught,
    /// The tool exited zero: it passed a broken exchange.
    Missed,
    /// The tool could not run at all: exit 2. Recorded apart from a catch,
    /// because "no exchange answered" is not "this exchange is lying".
    CouldNotRun,
}

impl Verdict {
    fn of(code: i32) -> Verdict {
        match code {
            0 => Verdict::Missed,
            2 => Verdict::CouldNotRun,
            _ => Verdict::Caught,
        }
    }
}

/// What every tool said about one attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row {
    verify: Verdict,
    audit: Verdict,
    audit_url: Verdict,
}

/// Every port this file has handed out. The operating system will not give one
/// port to two callers holding a socket, but the socket below is closed so a
/// service can bind it, and from then on the port is back in the pool.
static HANDED_OUT: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());

/// A port nothing is listening on, from the operating system, and that this
/// file has not used before.
///
/// Asked for rather than derived: any arithmetic on a process id can hand one
/// port to two attacks, and two attacks sharing a port read from the outside
/// as one exchange serving another's history.
fn free_port() -> u16 {
    for _ in 0..64 {
        let port = TcpListener::bind("127.0.0.1:0")
            .expect("the operating system has a free port")
            .local_addr()
            .expect("a bound listener has an address")
            .port();
        if HANDED_OUT
            .lock()
            .expect("the ports handed out")
            .insert(port)
        {
            return port;
        }
    }
    panic!("the operating system kept offering ports this file has already used");
}

/// One child process this test started, killed and reaped on drop so a failed
/// assertion leaves nothing holding a port or a database.
struct Service {
    child: Child,
    log: PathBuf,
}

impl Service {
    /// `dir` is the working directory, and it is not optional: every database
    /// path here is a bare file name, and a service started in the wrong
    /// directory quietly makes a *new* empty database rather than opening the
    /// one the attack edited. That reads from the outside as the sequencer
    /// having replaced its own history.
    fn start(
        binary: &str,
        dir: &Path,
        args: &[String],
        log: PathBuf,
        env: &[(&str, &str)],
    ) -> Service {
        let out = fs::File::create(&log).expect("a log file");
        let err = out.try_clone().expect("the same file for stderr");
        let mut command = Command::new(binary);
        command
            .args(args)
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err));
        for (key, value) in env {
            command.env(key, value);
        }
        let child = command.spawn().expect("the binary starts");
        Service { child, log }
    }

    fn said(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Waits for a URL to answer, or gives up. `false` means it never did.
fn answers(url: &str) -> bool {
    let give_up = Instant::now() + DEADLINE;
    while Instant::now() < give_up {
        let ok = Command::new("curl")
            .args(["-sf", "--max-time", "1", url])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Copies the exchange's live database into `frozen.db`, so the two tools that
/// read a file see one moment.
///
/// `VACUUM INTO` rather than `fs::copy`: the engine runs in write-ahead-log
/// mode, so the rows a copy of the main file holds are whatever was last
/// folded in, often no tables at all.
fn freeze(dir: &Path) {
    let _ = fs::remove_file(dir.join("frozen.db"));
    let live = Connection::open(dir.join("state.db")).expect("the state opens");
    live.execute(
        "VACUUM INTO ?1",
        rusqlite::params![dir.join("frozen.db").display().to_string()],
    )
    .expect("a snapshot of the state is made");
    fs::copy(dir.join("state.key"), dir.join("frozen.key")).expect("the claim key comes with it");
}

/// Runs one tool and returns its exit status and everything it printed.
fn run_tool(dir: &Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_services"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("the services binary runs");
    let mut said = String::from_utf8_lossy(&out.stdout).into_owned();
    said.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), said)
}

/// A clean exchange: a sequencer with a few hundred messages in it, an
/// exchange that consumed them, and the databases both left behind.
///
/// Built once and copied for every attack, so an attack is one edit away from
/// a history that passes every check.
struct Clean {
    dir: PathBuf,
}

impl Clean {
    fn build() -> Clean {
        let dir = std::env::temp_dir().join(format!("adversarial-clean-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a directory for the clean run");

        // The operator key, minted the way `demo.sh` mints one.
        let operator = SigningKey::from_bytes(&[7u8; 32]);
        fs::write(
            dir.join("operator.key"),
            logchain::to_hex(&operator.to_bytes()),
        )
        .expect("the operator key is written");
        let operator_public = logchain::to_hex(operator.verifying_key().as_bytes());

        let feed_port = free_port();
        let matcher_port = free_port();
        let feed_url = format!("http://127.0.0.1:{}", feed_port);
        let matcher_url = format!("http://127.0.0.1:{}", matcher_port);

        let feed = Service::start(
            env!("CARGO_BIN_EXE_services"),
            &dir,
            &[
                "--start-feed".into(),
                "--feed-port".into(),
                feed_port.to_string(),
                "--num-accounts".into(),
                "6".into(),
                "--rate".into(),
                "30".into(),
                "--feed-db".into(),
                "feed.db".into(),
                "--operator-key".into(),
                operator_public,
            ],
            dir.join("feed.log"),
            &[],
        );
        assert!(
            answers(&format!("{}/head", feed_url)),
            "the sequencer never came up. It said:\n{}",
            feed.said()
        );
        let matcher = Service::start(
            env!("CARGO_BIN_EXE_services"),
            &dir,
            &[
                "--start-matcher".into(),
                "--matcher-port".into(),
                matcher_port.to_string(),
                "--feed-url".into(),
                feed_url.clone(),
                "--state-db".into(),
                "state.db".into(),
            ],
            dir.join("matcher.log"),
            &[],
        );
        assert!(
            answers(&format!("{}/market", matcher_url)),
            "the exchange never came up. It said:\n{}",
            matcher.said()
        );

        open_the_log(&dir, &feed_url, &matcher_url);
        // Long enough for the generated flow to produce a few hundred
        // messages and a hundred trades at 30 a second.
        std::thread::sleep(Duration::from_secs(12));
        drop(feed);
        // The exchange finishes the history the sequencer stopped publishing.
        std::thread::sleep(Duration::from_secs(3));
        drop(matcher);
        std::thread::sleep(Duration::from_secs(1));

        // The write-ahead logs are folded back in, so a plain file copy is the
        // whole database. Without this a copy has no tables in it at all.
        for name in ["feed.db", "state.db"] {
            let conn = Connection::open(dir.join(name)).expect("the database opens");
            conn.pragma_update(None, "wal_checkpoint", "TRUNCATE")
                .expect("the write-ahead log folds back in");
        }
        Clean { dir }
    }

    /// A copy of the clean run, for one attack to edit.
    fn copy_to(&self, name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("adversarial-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a directory for this attack");
        for file in [
            "feed.db",
            "feed.key",
            "state.db",
            "state.key",
            "operator.key",
        ] {
            fs::copy(self.dir.join(file), dir.join(file)).expect("the clean run is copied");
        }
        dir
    }
}

impl Drop for Clean {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Publishes the rule set and one listing per market, exactly as
/// `docker/open-the-log.sh` does. Called through the shell script itself, so
/// what this covers is that file and not a copy of it.
fn open_the_log(dir: &Path, feed_url: &str, matcher_url: &str) {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the repository root is the parent of services/")
        .join("docker/open-the-log.sh");
    let status = Command::new("bash")
        .arg(&script)
        .arg(env!("CARGO_BIN_EXE_services"))
        .arg(feed_url)
        .arg(matcher_url)
        .arg("operator.key")
        .current_dir(dir)
        .output()
        .expect("open-the-log.sh runs");
    assert!(
        status.status.success(),
        "the log was not opened: {}{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
}

// ---------------------------------------------------------------------------
// What a dishonest operator can do to their own databases.
//
// These are not "corruption": an operator holds `feed.key` and `state.key`, so
// every signature over an edited record is one they can make again. Anything
// here that left a signature broken would be testing a mistake rather than a
// lie.
// ---------------------------------------------------------------------------

/// Folds the chain over the stored messages and writes each link back, so the
/// links match the bytes beside them again.
fn refold_chain(conn: &Connection) -> Chain {
    let mut rows = Vec::new();
    {
        let mut statement = conn
            .prepare("SELECT id, json FROM feed_messages ORDER BY id")
            .expect("the messages are read");
        let mut cursor = statement.query([]).expect("the messages are read");
        let mut chain = EMPTY_CHAIN;
        while let Some(row) = cursor.next().expect("a row") {
            let id: i64 = row.get(0).expect("an id");
            let json: String = row.get(1).expect("the bytes");
            chain = logchain::extend_bytes(&chain, json.as_bytes());
            rows.push((chain, id));
        }
    }
    let last = rows.last().map(|(chain, _)| *chain).unwrap_or(EMPTY_CHAIN);
    for (chain, id) in rows {
        conn.execute(
            "UPDATE feed_messages SET chain = ?1 WHERE id = ?2",
            rusqlite::params![chain.as_slice(), id],
        )
        .expect("the link is written");
    }
    last
}

/// Makes the sequencer's own tamper checks pass over an edited log.
///
/// The chain links are folded again, the tree is emptied, and the checkpoint
/// is signed again with the feed's own key over the new chain and no root. A
/// checkpoint that names no root is one the sequencer builds the tree from the
/// messages for, which is what a build from before the signed root leaves and
/// what `feed.rs` already handles.
fn repair(dir: &Path) {
    let conn = Connection::open(dir.join("feed.db")).expect("the log opens");
    let chain = refold_chain(&conn);
    conn.execute("DELETE FROM merkle_nodes", [])
        .expect("the tree is emptied");
    let session: String = conn
        .query_row(
            "SELECT value FROM feed_meta WHERE key = 'session'",
            [],
            |row| row.get(0),
        )
        .expect("the log names a session");
    let last_id: i64 = conn
        .query_row("SELECT MAX(id) FROM feed_messages", [], |row| row.get(0))
        .expect("the log holds messages");
    let key = load_key(&dir.join("feed.key"));
    let checkpoint = serde_json::json!({
        "last_id": last_id,
        "chain": logchain::to_hex(&chain),
        "signature": logchain::to_hex(
            &logchain::sign_head(&key, &session, last_id as u64, &chain).to_bytes(),
        ),
    });
    conn.execute(
        "UPDATE feed_meta SET value = ?1 WHERE key = 'checkpoint'",
        rusqlite::params![checkpoint.to_string()],
    )
    .expect("the checkpoint is written");
}

fn load_key(path: &Path) -> SigningKey {
    let hex = fs::read_to_string(path).expect("the key file is read");
    let bytes = logchain::from_hex::<32>(hex.trim()).expect("a 32-byte hex key");
    SigningKey::from_bytes(&bytes)
}

/// The maker order of a trade in the middle of the record, and its trade id.
fn a_traded_order(dir: &Path) -> (i64, i64) {
    let conn = Connection::open(dir.join("state.db")).expect("the state opens");
    conn.query_row(
        "SELECT trade_id, maker_order FROM trades ORDER BY trade_id LIMIT 1 OFFSET 20",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .expect("the run made more than twenty trades")
}

/// Rewrites one field of one stored message, in place.
fn edit_message(dir: &Path, id: i64, edit: impl Fn(&mut serde_json::Value)) {
    let conn = Connection::open(dir.join("feed.db")).expect("the log opens");
    let json: String = conn
        .query_row(
            "SELECT json FROM feed_messages WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        )
        .expect("the message is there");
    let mut value: serde_json::Value = serde_json::from_str(&json).expect("a stored message");
    let kind = value
        .as_object()
        .and_then(|o| o.keys().next().cloned())
        .expect("a message names its kind");
    edit(&mut value[&kind]);
    conn.execute(
        "UPDATE feed_messages SET json = ?1 WHERE id = ?2",
        rusqlite::params![value.to_string(), id],
    )
    .expect("the message is written");
}

fn sql(dir: &Path, file: &str, statement: &str) {
    let conn = Connection::open(dir.join(file)).expect("the database opens");
    conn.execute(statement, []).expect("the statement runs");
}

/// Every attack this file knows, and what each one does to a copy of the clean
/// run.
fn attacks() -> Vec<(&'static str, fn(&Path))> {
    vec![
        // --- the log ---
        ("log-price", |dir| {
            let (_, maker) = a_traded_order(dir);
            edit_message(dir, maker, |m| {
                let was = m["price"].as_f64().expect("a price");
                m["price"] = serde_json::json!(was + 5.0);
            });
            repair(dir);
        }),
        ("log-account", |dir| {
            let (_, maker) = a_traded_order(dir);
            edit_message(dir, maker, |m| {
                let was = m["account"].as_u64().expect("an account");
                m["account"] = serde_json::json!(was + 100);
            });
            repair(dir);
        }),
        ("log-swap-ids", |dir| {
            let conn = Connection::open(dir.join("feed.db")).expect("the log opens");
            let read = |id: i64| -> String {
                conn.query_row(
                    "SELECT json FROM feed_messages WHERE id = ?1",
                    rusqlite::params![id],
                    |row| row.get(0),
                )
                .expect("the message is there")
            };
            // The two bodies change places and each keeps the id of the slot
            // it lands in, so the log is still 1..N with no gap and no repeat.
            // What moved is the order of two messages, which is the one thing
            // the sequencer's whole job is to fix.
            let put = |at: i64, json: &str| {
                let mut value: serde_json::Value = serde_json::from_str(json).expect("a message");
                let kind = value
                    .as_object()
                    .and_then(|o| o.keys().next().cloned())
                    .expect("a kind");
                value[&kind]["id"] = serde_json::json!(at);
                conn.execute(
                    "UPDATE feed_messages SET json = ?1 WHERE id = ?2",
                    rusqlite::params![value.to_string(), at],
                )
                .expect("the message is written");
            };
            let (first, second) = (read(200), read(201));
            put(200, &second);
            put(201, &first);
            drop(conn);
            repair(dir);
        }),
        ("log-delete", |dir| {
            sql(dir, "feed.db", "DELETE FROM feed_messages WHERE id = 200");
            repair(dir);
        }),
        ("log-chain-hash", |dir| {
            sql(
                dir,
                "feed.db",
                "UPDATE feed_messages SET chain = randomblob(32) WHERE id = 150",
            );
        }),
        ("log-merkle-node", |dir| {
            sql(
                dir,
                "feed.db",
                "UPDATE merkle_nodes SET hash = randomblob(32) WHERE level = 0 AND idx = 40",
            );
        }),
        ("log-feed-accounts", |dir| {
            // The table nothing signs, and that no published message carries
            // the material to rebuild.
            sql(
                dir,
                "feed.db",
                "INSERT OR REPLACE INTO feed_accounts (account, public_key, pinned_at) \
                 VALUES (4, '1111111111111111111111111111111111111111111111111111111111111111', 1)",
            );
        }),
        ("log-head-other-key", |dir| {
            // A head signed by a key the run never pinned.
            let other = SigningKey::from_bytes(&[0x22; 32]);
            fs::write(dir.join("feed.key"), logchain::to_hex(&other.to_bytes()))
                .expect("the key is replaced");
            repair(dir);
        }),
        // --- the exchange ---
        ("state-trade-price", |dir| {
            sql(
                dir,
                "state.db",
                "UPDATE trades SET price_cents = price_cents + 300 \
                 WHERE trade_id = (SELECT trade_id FROM trades ORDER BY trade_id LIMIT 1 OFFSET 20)",
            );
        }),
        ("state-trade-qty", |dir| {
            sql(
                dir,
                "state.db",
                "UPDATE trades SET qty_tenths = qty_tenths + 5 \
                 WHERE trade_id = (SELECT trade_id FROM trades ORDER BY trade_id LIMIT 1 OFFSET 20)",
            );
        }),
        ("state-trade-delete", |dir| {
            sql(
                dir,
                "state.db",
                "DELETE FROM trades \
                 WHERE trade_id = (SELECT trade_id FROM trades ORDER BY trade_id LIMIT 1 OFFSET 20)",
            );
        }),
        ("state-open-order-qty", |dir| {
            sql(
                dir,
                "state.db",
                "UPDATE open_orders SET qty_tenths = qty_tenths + 40 \
                 WHERE order_id = (SELECT order_id FROM open_orders ORDER BY order_id LIMIT 1)",
            );
        }),
        ("state-listings", |dir| {
            sql(
                dir,
                "state.db",
                "UPDATE listings SET price_step_cents = 25 WHERE symbol = 'ETH-USDC'",
            );
        }),
        ("state-claim-root", |dir| {
            sql(
                dir,
                "state.db",
                "UPDATE claims SET root_after = randomblob(32) \
                 WHERE from_msg = (SELECT from_msg FROM claims ORDER BY from_msg LIMIT 1 OFFSET 5)",
            );
        }),
        ("state-claim-forged", |dir| {
            // The interesting version: the operator holds `state.key`, so a
            // claim they edit is a claim they can sign again.
            let conn = Connection::open(dir.join("state.db")).expect("the state opens");
            let key = load_key(&dir.join("state.key"));
            let session: String = conn
                .query_row(
                    "SELECT feed_session FROM runs ORDER BY run_id DESC",
                    [],
                    |r| r.get(0),
                )
                .expect("the run names a session");
            let (from, to, before, total): (u64, u64, Vec<u8>, u64) = conn
                .query_row(
                    "SELECT from_msg, to_msg, root_before, trades_total FROM claims \
                     ORDER BY from_msg LIMIT 1 OFFSET 5",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .expect("the run committed more than five claims");
            let mut root_before = [0u8; 32];
            root_before.copy_from_slice(&before);
            let root_after = [0x5au8; 32];
            let signature =
                logchain::sign_claim(&key, &session, from, to, &root_before, &root_after, total);
            conn.execute(
                "UPDATE claims SET root_after = ?1, signature = ?2 WHERE from_msg = ?3",
                rusqlite::params![root_after.as_slice(), signature.to_bytes().as_slice(), from],
            )
            .expect("the claim is written");
        }),
        ("state-resume-cursor", |dir| {
            sql(
                dir,
                "state.db",
                "UPDATE resume_point SET last_seen = last_seen - 50",
            );
        }),
        ("state-run-key", |dir| {
            sql(
                dir,
                "state.db",
                "UPDATE runs SET matcher_pubkey = \
                 '3333333333333333333333333333333333333333333333333333333333333333'",
            );
        }),
    ]
}

/// What every tool is expected to say. `Missed` in a cell is a hole this
/// repository has today, proved by this file rather than argued about.
fn expected() -> BTreeMap<&'static str, Row> {
    use Verdict::{Caught, CouldNotRun, Missed};
    let mut table = BTreeMap::new();
    let mut add = |name, verify, audit, audit_url| {
        table.insert(
            name,
            Row {
                verify,
                audit,
                audit_url,
            },
        );
    };
    add("control", Missed, Missed, Missed);
    // The sequencer refuses to serve these two at all, so no tool gets a
    // history to read. That is the operator's own program refusing, not a
    // stranger's tool catching anything.
    add("log-delete", CouldNotRun, CouldNotRun, CouldNotRun);
    add("log-chain-hash", CouldNotRun, CouldNotRun, CouldNotRun);
    add("log-price", Caught, Caught, Caught);
    add("log-account", Caught, Caught, Caught);
    // The checker still has no view of message order: it reads what a message
    // says, never where it sits. What it does see is the two messages carrying
    // different orders. Swapping the bodies at 200 and 201 gives the order at
    // 200 the other one's symbol, account and price, so a trade against either
    // of them fails `trade symbol matches both orders`, `trade accounts match
    // the orders' accounts` and `trade executed at the maker's limit price`:
    // "trade 69 on BTC-USDC joined BTC-USDC and MERKLE-USDC".
    //
    // **This cell depends on the generated flow**, which is random: it is
    // `Caught` when a trade names one of the two swapped ids and the two
    // messages differ, and `Missed` when neither is filled. Two runs of this
    // file gave `Caught`, and more markets in the log makes that the ordinary
    // case rather than the lucky one. Nothing about the tree is involved: both
    // tree checks pass in both runs. Making the cell mean one thing means
    // swapping two messages this file chose rather than two the generator
    // happened to produce.
    add("log-swap-ids", Caught, Caught, Caught);
    // Caught by all three since `/tree/nodes`: each tool folds the messages it
    // was served into the same tree and compares every node the log stored for
    // them. The report names the node: "the node at level 0 index 40 is X, and
    // the log's own messages make Y there".
    //
    // A root check alone does not find this one, and the report shows it: `the
    // signed tree head is over these messages` passes in the same run. `mth`
    // returns the stored hash of a perfect subtree without descending into it
    // (`merkle.rs`, `subtree_hash`), so over a 358-message history the root
    // reads the node at level 8 index 0 and never reads leaf 40 at all. The
    // corruption changes no root, and no signature, and no anchor. What it
    // changes is the inclusion proof for leaf 41, which is the only proof that
    // reads leaf 40. That is measured, not argued. So the messages under that
    // node can no longer be proven to be in the log, and nothing forged and
    // nothing hidden. That is why the node has to be compared with the messages
    // directly, and why the comparison is now something a stranger can run.
    add("log-merkle-node", Caught, Caught, Caught);
    // A published message carries the account and not the submitter's key, so
    // there is nothing to rebuild this table from and nothing signs it.
    add("log-feed-accounts", Missed, Missed, Missed);
    add("log-head-other-key", Caught, Caught, Caught);
    add("state-trade-price", Caught, Caught, CouldNotRun);
    add("state-trade-qty", Caught, Caught, CouldNotRun);
    add("state-trade-delete", Caught, Caught, CouldNotRun);
    // Neither tool reads the resting book: the checker has no book table and
    // the audit rebuilds one from the log instead of reading this one.
    add("state-open-order-qty", Missed, Missed, CouldNotRun);
    // The same for the symbol registry.
    add("state-listings", Missed, Missed, CouldNotRun);
    add("state-claim-root", Missed, Caught, Caught);
    add("state-claim-forged", Missed, Caught, Caught);
    add("state-resume-cursor", Missed, Caught, CouldNotRun);
    add("state-run-key", Missed, Caught, CouldNotRun);
    table
}

/// Runs one attack and returns what every tool said.
fn run_attack(clean: &Clean, name: &str, break_it: Option<fn(&Path)>) -> (Row, String) {
    let dir = clean.copy_to(name);
    if let Some(break_it) = break_it {
        break_it(&dir);
    }
    let feed_port = free_port();
    let matcher_port = free_port();
    let feed_url = format!("http://127.0.0.1:{}", feed_port);
    let matcher_url = format!("http://127.0.0.1:{}", matcher_port);

    let mut said = format!("########## {} ##########\n", name);
    let feed = Service::start(
        env!("CARGO_BIN_EXE_services"),
        &dir,
        &[
            "--start-feed".into(),
            "--feed-port".into(),
            feed_port.to_string(),
            "--num-accounts".into(),
            "6".into(),
            // The slowest the generator runs, so the history barely moves
            // while three tools read it.
            "--rate".into(),
            "0.1".into(),
            "--feed-db".into(),
            "feed.db".into(),
        ],
        dir.join("attack-feed.log"),
        &[],
    );
    // The sequencer refusing to serve an edited log is a real answer and not a
    // failure of this test.
    if !answers(&format!("{}/head", feed_url)) {
        said.push_str("the sequencer refused to serve this log:\n");
        said.push_str(&feed.said());
        return (
            Row {
                verify: Verdict::CouldNotRun,
                audit: Verdict::CouldNotRun,
                audit_url: Verdict::CouldNotRun,
            },
            said,
        );
    }

    // A snapshot the two file tools read, so a live exchange writing to
    // `state.db` cannot change what they see between one run and the next.
    freeze(&dir);

    let (verify_code, verify_said) =
        run_tool(&dir, &["--verify", "frozen.db", "--feed-url", &feed_url]);
    let (audit_code, audit_said) =
        run_tool(&dir, &["--audit", "frozen.db", "--feed-url", &feed_url]);
    said.push_str("===== services --verify =====\n");
    said.push_str(&verify_said);
    said.push_str("===== services --audit =====\n");
    said.push_str(&audit_said);

    let matcher = Service::start(
        env!("CARGO_BIN_EXE_services"),
        &dir,
        &[
            "--start-matcher".into(),
            "--matcher-port".into(),
            matcher_port.to_string(),
            "--feed-url".into(),
            feed_url.clone(),
            "--state-db".into(),
            "state.db".into(),
        ],
        dir.join("attack-matcher.log"),
        &[],
    );
    said.push_str("===== services --audit-url =====\n");
    let audit_url = if answers(&format!("{}/market", matcher_url)) {
        let (code, printed) = run_tool(
            &dir,
            &["--audit-url", &matcher_url, "--feed-url", &feed_url],
        );
        said.push_str(&printed);
        Verdict::of(code)
    } else {
        said.push_str("the exchange refused to start on this state; it said:\n");
        said.push_str(&matcher.said());
        Verdict::CouldNotRun
    };

    let row = Row {
        verify: Verdict::of(verify_code),
        audit: Verdict::of(audit_code),
        audit_url,
    };
    let _ = fs::write(dir.join("report.txt"), &said);
    (row, said)
}

/// Tier 1: take a real database and edit it.
///
/// One clean run, then one copy of it per attack. The whole table is asserted
/// at the end rather than each row as it is produced, so one changed cell does
/// not hide the rest.
#[test]
#[ignore = "starts real processes and publishes a few hundred messages: about a minute"]
fn tampering_with_the_stored_records() {
    let clean = Clean::build();
    let expected = expected();
    let mut found: BTreeMap<&'static str, Row> = BTreeMap::new();

    let (row, said) = run_attack(&clean, "control", None);
    println!("{}", said);
    found.insert("control", row);
    assert_eq!(
        row, expected["control"],
        "the clean run has to pass every tool, or nothing below means anything"
    );

    for (name, break_it) in attacks() {
        let (row, said) = run_attack(&clean, name, Some(break_it));
        println!("{}", said);
        found.insert(name, row);
    }

    println!("\nattack                     --verify        --audit         --audit-url");
    for (name, row) in &found {
        println!(
            "{:<26} {:<15?} {:<15?} {:?}",
            name, row.verify, row.audit, row.audit_url
        );
    }
    assert_eq!(
        found, expected,
        "the attack-by-tool table changed. A cell that went from Missed to Caught is a hole \
         somebody closed: update the table. A cell that went the other way is a hole somebody \
         opened."
    );
}

/// The release binary carries no trace of the dishonest exchange.
///
/// `src/dishonest.rs` is behind a feature that is not on by default, so this
/// is a fact about the object file and not about anybody's discipline.
#[test]
fn a_release_binary_holds_none_of_the_dishonest_engine() {
    let binary = fs::read(env!("CARGO_BIN_EXE_services")).expect("the services binary is readable");
    // The marker appears in `dishonest.rs` and nowhere else in the crate.
    let marker = b"DISHONEST-ENGINE-MARKER-8f2c";
    let found = binary
        .windows(marker.len())
        .any(|window| window == marker.as_slice());
    assert!(
        !found,
        "the services binary holds the dishonest engine's marker string. The `dishonest` \
         feature must never be on for the binary an operator or a stranger runs"
    );
    assert!(
        !cfg!(feature = "dishonest"),
        "this test build has the dishonest feature on, so it proves nothing about a release"
    );
}

// ---------------------------------------------------------------------------
// Tier 2: a dishonest exchange, running.
//
// Tier 1 edits stored bytes. This makes the engine misbehave while it runs,
// which is what a dishonest operator would actually do. Every record the
// engine writes is then consistent with every other record it writes, and the
// only thing that can disagree is a tool that re-derives the answer.
//
// The sequencer and all three tools are the honest release binary. Only the
// exchange is the dishonest one, which is the real shape of the threat: the
// operator runs a patched build and the stranger runs the published one.
// ---------------------------------------------------------------------------

#[cfg(feature = "dishonest")]
mod tier2 {
    use super::*;

    /// One lie, and what every tool said about it.
    fn run_lie(lie: &str, skip_listing: Option<&str>) -> (Row, String) {
        let dir =
            std::env::temp_dir().join(format!("adversarial-lie-{}-{}", lie, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a directory for this lie");
        let operator = SigningKey::from_bytes(&[9u8; 32]);
        fs::write(
            dir.join("operator.key"),
            logchain::to_hex(&operator.to_bytes()),
        )
        .expect("the operator key is written");
        let operator_public = logchain::to_hex(operator.verifying_key().as_bytes());

        let feed_port = free_port();
        let matcher_port = free_port();
        let feed_url = format!("http://127.0.0.1:{}", feed_port);
        let matcher_url = format!("http://127.0.0.1:{}", matcher_port);

        let feed = Service::start(
            env!("CARGO_BIN_EXE_services"),
            &dir,
            &[
                "--start-feed".into(),
                "--feed-port".into(),
                feed_port.to_string(),
                "--num-accounts".into(),
                "6".into(),
                "--rate".into(),
                "25".into(),
                "--feed-db".into(),
                "feed.db".into(),
                "--operator-key".into(),
                operator_public,
            ],
            dir.join("feed.log"),
            &[],
        );
        assert!(
            answers(&format!("{}/head", feed_url)),
            "the sequencer never came up: {}",
            feed.said()
        );
        // The dishonest exchange, and only the exchange.
        let matcher = Service::start(
            env!("CARGO_BIN_EXE_dishonest-exchange"),
            &dir,
            &[
                "--matcher-port".into(),
                matcher_port.to_string(),
                "--feed-url".into(),
                feed_url.clone(),
                "--state-db".into(),
                "state.db".into(),
            ],
            dir.join("matcher.log"),
            &[("DISHONEST", lie)],
        );
        assert!(
            answers(&format!("{}/market", matcher_url)),
            "the dishonest exchange never came up: {}",
            matcher.said()
        );
        match skip_listing {
            // A market nobody listed needs a log that lists one fewer symbol,
            // so this cannot go through open-the-log.sh.
            Some(skipped) => open_all_but(&dir, &feed_url, &matcher_url, skipped),
            None => open_the_log(&dir, &feed_url, &matcher_url),
        }
        std::thread::sleep(Duration::from_secs(14));
        drop(feed);
        std::thread::sleep(Duration::from_secs(3));

        // The sequencer has to be answering for the tools to read the history,
        // and it must publish almost nothing while they do.
        let feed = Service::start(
            env!("CARGO_BIN_EXE_services"),
            &dir,
            &[
                "--start-feed".into(),
                "--feed-port".into(),
                feed_port.to_string(),
                "--num-accounts".into(),
                "6".into(),
                "--rate".into(),
                "0.1".into(),
                "--feed-db".into(),
                "feed.db".into(),
            ],
            dir.join("feed2.log"),
            &[],
        );
        assert!(
            answers(&format!("{}/head", feed_url)),
            "the sequencer did not come back: {}",
            feed.said()
        );

        let mut said = format!("########## the lie: {} ##########\n", lie);
        said.push_str("===== GET /positions, which is what a trader reads =====\n");
        said.push_str(&positions(matcher_url));
        said.push('\n');

        freeze(&dir);

        let (verify_code, verify_said) =
            run_tool(&dir, &["--verify", "frozen.db", "--feed-url", &feed_url]);
        let (audit_code, audit_said) =
            run_tool(&dir, &["--audit", "frozen.db", "--feed-url", &feed_url]);
        let (audit_url_code, audit_url_said) = run_tool(
            &dir,
            &["--audit-url", &matcher_url, "--feed-url", &feed_url],
        );
        said.push_str("===== services --verify =====\n");
        said.push_str(&verify_said);
        said.push_str("===== services --audit =====\n");
        said.push_str(&audit_said);
        said.push_str("===== services --audit-url =====\n");
        said.push_str(&audit_url_said);
        let _ = fs::write(dir.join("report.txt"), &said);
        (
            Row {
                verify: Verdict::of(verify_code),
                audit: Verdict::of(audit_code),
                audit_url: Verdict::of(audit_url_code),
            },
            said,
        )
    }

    fn get(url: &str) -> String {
        curl(url).chars().take(400).collect()
    }

    /// The whole body, for the callers that read a paged route and cannot cut
    /// a page in half to do it.
    fn curl(url: &str) -> String {
        let out = Command::new("curl")
            .args(["-s", "--max-time", "5", url])
            .output()
            .expect("curl runs");
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    /// Reads every page of `GET /positions` and returns the start of the
    /// answer.
    ///
    /// The route is bounded: it answers with `POSITIONS_PAGE` accounts unless
    /// asked for a number, and a caller reads the next page by naming the last
    /// account it saw. A trader reading this route reads it that way, so the
    /// harness does too. A single unbounded request is no longer what anyone
    /// sees.
    ///
    /// The pages are joined and cut once at the end, so the report shows the
    /// start of one answer rather than the start of every page. The cut is
    /// where it always was: this is a record of what a tool said, not the
    /// input to a check.
    fn positions(matcher_url: &str) -> String {
        const PAGE: usize = 50;
        let mut said = String::new();
        let mut since: u64 = 0;
        // A ceiling as well as a cursor. An engine that answered the same page
        // forever would otherwise hold the harness open until its timeout.
        for _ in 0..20 {
            let page = curl(&format!(
                "{}/positions?since={}&n={}",
                matcher_url, since, PAGE
            ));
            said.push_str(&page);
            // Every account view names its account once, so the last one named
            // is the last account of the page.
            let last = page
                .rsplit("\"account\":")
                .next()
                .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|digits| digits.parse::<u64>().ok());
            match last {
                // A page holding fewer accounts than asked for is the end.
                Some(account) if page.matches("\"account\":").count() == PAGE => since = account,
                _ => break,
            }
        }
        said.chars().take(400).collect()
    }

    /// Opens the log with every market but one, so an order arrives for a
    /// symbol no `ListSymbol` ever named.
    fn open_all_but(dir: &Path, feed_url: &str, matcher_url: &str, skipped: &str) {
        let market = get(&format!("{}/market", matcher_url));
        let rule = market
            .split("\"newest_rule_set\":")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .expect("the exchange names the newest rule set it runs")
            .to_string();
        // `/symbols` serves one small flat object per market: the name and the
        // price step it opens on. So each market is listed on its own step,
        // the way `docker/open-the-log.sh` lists them.
        #[derive(serde::Deserialize)]
        struct SymbolEntry {
            symbol: String,
            price_step: f64,
        }
        let symbols: Vec<SymbolEntry> =
            serde_json::from_str(&get(&format!("{}/symbols", feed_url)))
                .expect("the sequencer names its markets and their steps");

        let publish = |body: &str| {
            let status = Command::new("curl")
                .args([
                    "-s",
                    "-o",
                    "/dev/null",
                    "-X",
                    "POST",
                    "-H",
                    "Content-Type: application/json",
                    "--data-binary",
                    body,
                    &format!("{}/operator", feed_url),
                ])
                .status()
                .expect("curl runs");
            assert!(status.success(), "the operator message was not published");
        };
        let sign = |args: &[&str]| -> String {
            let out = Command::new(env!("CARGO_BIN_EXE_services"))
                .args(args)
                .args([
                    "--feed-url",
                    feed_url,
                    "--matcher-url",
                    matcher_url,
                    "--operator-key-file",
                    "operator.key",
                    "--sign-only",
                ])
                .current_dir(dir)
                .output()
                .expect("the services binary runs");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        publish(&sign(&["--engine-rule", &rule]));
        for entry in symbols {
            if entry.symbol == skipped {
                continue;
            }
            publish(&sign(&[
                "--list-symbol",
                &entry.symbol,
                &entry.price_step.to_string(),
                "0.1",
            ]));
        }
    }

    /// Tier 2: the engine misbehaves while it runs.
    #[test]
    #[ignore = "starts a real exchange per lie, eight of them: about four minutes"]
    fn a_dishonest_engine_running() {
        use Verdict::{Caught, Missed};
        let lies: Vec<(&str, Option<&str>, Row)> = vec![
            (
                "none",
                None,
                Row {
                    verify: Missed,
                    audit: Missed,
                    audit_url: Missed,
                },
            ),
            (
                "priority",
                None,
                Row {
                    verify: Caught,
                    audit: Caught,
                    audit_url: Caught,
                },
            ),
            (
                "cancelled-fill",
                None,
                Row {
                    verify: Caught,
                    audit: Caught,
                    audit_url: Caught,
                },
            ),
            (
                "over-limit",
                None,
                Row {
                    verify: Caught,
                    audit: Caught,
                    audit_url: Caught,
                },
            ),
            (
                "self-trade",
                None,
                Row {
                    verify: Caught,
                    audit: Caught,
                    audit_url: Caught,
                },
            ),
            (
                "phantom-market",
                Some("MERKLE-USDC"),
                Row {
                    verify: Caught,
                    audit: Caught,
                    audit_url: Caught,
                },
            ),
            // An exchange that refuses to trade makes no trades, and the
            // checker only ever asks about trades.
            (
                "drop-resting",
                None,
                Row {
                    verify: Missed,
                    audit: Caught,
                    audit_url: Caught,
                },
            ),
            // No record moves, so there is nothing for any tool here to
            // re-derive: the position, the trade record and the state root are
            // all left alone and only the served profit changes.
            //
            // One thing does catch it, and it is not in this table because
            // this table scores command line tools. The page adds up the
            // profit of every account and shows the net, which must read 0.00
            // because a fill moves money from one account to another and
            // creates none. This lie adds to every realized profit the route
            // reports, so the net stops reading 0.00 and the browser says so.
            // `renderZeroSum` in services/static/app.js is that check, and
            // it re-derives the total from the accounts it was served rather
            // than reading a total the exchange states. An exchange that
            // stated the total could state a clean one.
            (
                "positions",
                None,
                Row {
                    verify: Missed,
                    audit: Missed,
                    audit_url: Missed,
                },
            ),
            (
                "root",
                None,
                Row {
                    verify: Missed,
                    audit: Caught,
                    audit_url: Caught,
                },
            ),
        ];
        let mut found = Vec::new();
        for (lie, skip, want) in &lies {
            let (row, said) = run_lie(lie, *skip);
            println!("{}", said);
            found.push((*lie, row, *want));
        }
        println!("\nlie                --verify        --audit         --audit-url");
        for (lie, row, _) in &found {
            println!(
                "{:<18} {:<15?} {:<15?} {:?}",
                lie, row.verify, row.audit, row.audit_url
            );
        }
        for (lie, row, want) in found {
            assert_eq!(row, want, "the lie '{}' is not caught the way it was", lie);
        }
    }
}
