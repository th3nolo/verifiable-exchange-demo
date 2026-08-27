//! What `crash_restart.rs` and `fault_injection.rs` both need to drive a real
//! sequencer process and read what it serves.
//!
//! Both files start the binary, wait for its head to move, read its history
//! back and fold that history into a chain. Each file used to carry its own
//! copy of that code. The copies drifted: `fault_injection.rs` grew two fixes
//! for the port race that `crash_restart.rs` never got, and a race that hands
//! one port to two trials reads from the outside as the sequencer losing
//! published messages, the very verdict both files exist to report. One copy
//! removes that.
//!
//! Nothing here calls `feed.rs`. Everything goes through the program an
//! operator runs and its HTTP contract.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use reqwest::Client;
use serde::Deserialize;
use services::logchain::{self, Chain, EMPTY_CHAIN};
use services::wire;
use tokio::time::sleep;

/// How often the tests ask the sequencer where its head is.
///
/// 5 ms rather than 1 ms because reads are rate limited by the sequencer, in
/// messages: `/head` costs 10 and a caller refills 5,000 a second. Polling
/// every 5 ms spends 2,000 a second and is never refused. It is also 20 times
/// finer than the 100 ms tick, so no value of `last_id` is stepped over.
pub const POLL: Duration = Duration::from_millis(5);

/// How long anything is waited for before the test gives up and says what it
/// was waiting for. Only reached when something is stuck: a child that exits is
/// noticed on the next poll.
pub const DEADLINE: Duration = Duration::from_secs(60);

/// Every port this test binary has handed out.
///
/// The operating system will not give the same port to two callers holding a
/// socket, but [`free_port`] closes its socket so the sequencer can bind it, and
/// from then on the port is back in the pool. `fault_injection.rs` asks for
/// about four hundred of them, five tests at a time, and it did hand the same
/// one to two trials: a trial whose sequencer had exited asked `/head` on its
/// old port and another trial's sequencer answered, with a history the asking
/// trial had never published. It read as a message published without being
/// written, which is the failure these files exist to look for.
///
/// Remembering them makes that impossible between trials in one test binary.
/// Another program on the machine taking one in the same moment is still
/// possible, and [`Sequencer::lost_its_port`] is what notices that.
static HANDED_OUT: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());

/// A port nothing is listening on, from the operating system, and that this
/// test binary has not used before.
///
/// Asked for rather than derived, because the operating system will not hand
/// the same port to two callers at once and any arithmetic on a thread id or a
/// process id can. Linux hands these out from 32768 upward, so they are far
/// above the 3000, 3001, 3002 and 3010 that `demo.sh` uses.
///
/// The port is free for a moment between this function and the sequencer
/// binding it. [`Sequencer::lost_its_port`] is what covers that moment.
pub fn free_port() -> u16 {
    for _ in 0..64 {
        let port = {
            let listener =
                TcpListener::bind("127.0.0.1:0").expect("the operating system has a free port");
            listener
                .local_addr()
                .expect("a bound listener has an address")
                .port()
        };
        if HANDED_OUT
            .lock()
            .expect("the list of ports handed out")
            .insert(port)
        {
            return port;
        }
    }
    panic!("the operating system kept offering ports this test has already used");
}

/// One running sequencer process.
///
/// The child is killed and reaped by `Drop`, so a failed assertion anywhere
/// still leaves no process holding a port or a database. That matters more
/// than it looks: an orphan sequencer keeps its port and its database open, and
/// the next run of the file would fail somewhere else entirely.
pub struct Sequencer {
    child: Child,
    port: u16,
    log: PathBuf,
}

impl Sequencer {
    /// Starts `services --start-feed` on this database, with the shim loaded if
    /// one is given.
    ///
    /// The output goes to a file rather than to a pipe. The sequencer logs one
    /// line per published message, and a pipe nobody is reading fills at 64 KB
    /// and blocks the process that is writing it, which at 1000 messages a
    /// second would stop the very thing the test is timing.
    ///
    /// `fault` is `None` for a plain run. It is the shim library and the
    /// control file for a run whose writes are made to fail.
    pub fn start(db: &Path, rate: &str, tag: &str, fault: Option<(&Path, &Path)>) -> Sequencer {
        let port = free_port();
        let log = db.with_file_name(format!("sequencer-{}-{}.log", tag, port));
        let out = File::create(&log).expect("a log file for the sequencer");
        let err = out.try_clone().expect("the same log file for stderr");
        let mut command = Command::new(env!("CARGO_BIN_EXE_services"));
        command
            .arg("--start-feed")
            .arg("--feed-port")
            .arg(port.to_string())
            .arg("--feed-db")
            .arg(db)
            .arg("--rate")
            .arg(rate)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err));
        if let Some((library, control)) = fault {
            command
                .env("LD_PRELOAD", library)
                .env("FAULT_DB", db)
                .env("FAULT_CONTROL", control);
        }
        let child = command.spawn().expect("the services binary starts");
        Sequencer { child, port, log }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }

    /// Everything the process has said so far. Read on failure, so an assertion
    /// can show why the sequencer would not start.
    pub fn said(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The status if the process has ended, without waiting for it.
    pub fn ended(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().unwrap_or(None)
    }

    /// True when this process died because something else took its port between
    /// the test asking the operating system for a free one and the sequencer
    /// binding it.
    ///
    /// Not a result about the feed, and not something the caller has to undo:
    /// `start_feed` binds before it opens the database, so a process that lost
    /// the race exits 2 having touched nothing: no file, and no operation for
    /// the shim to have counted. The caller starts another one on a new port.
    ///
    /// The window cannot be closed from here, because the port has to be free
    /// for the sequencer to bind it. It can be noticed, and these files start
    /// hundreds of processes a run against a pool every other program on the
    /// machine draws from, so noticing is the difference between a rare failure
    /// that reads like a lost history and none.
    pub fn lost_its_port(&mut self) -> bool {
        self.ended().is_some() && self.said().contains("could not bind")
    }

    /// SIGKILL, and wait for the process to be gone.
    ///
    /// `Child::kill` is SIGKILL on Unix. That is the signal these files need
    /// and SIGTERM is not: the sequencer must have no chance to flush anything,
    /// run a shutdown path or close its database. What is on disk at this
    /// instant is what the restart gets.
    ///
    /// The wait is what makes the next line safe. Without it the test could
    /// start the replacement while the kernel is still ending the old process,
    /// and the old one still has the database open.
    pub fn kill_now(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Sequencer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        // Reaped, or the process stays a zombie for as long as the test binary
        // runs.
        let _ = self.child.wait();
    }
}

/// The signed head, as `GET /head` serves it.
///
/// Declared here rather than imported because it is the sequencer's HTTP
/// contract, which is what a consumer depends on, and `SignedHead` in `feed.rs`
/// is private to that module.
#[derive(Debug, Clone, Deserialize)]
pub struct Head {
    pub session: String,
    pub last_id: u64,
    pub chain: String,
    pub public_key: String,
    pub signature: String,
}

impl Head {
    pub fn chain_bytes(&self) -> Chain {
        logchain::from_hex::<32>(&self.chain)
            .unwrap_or_else(|| panic!("a head's chain is not 32 hex bytes: {:?}", self))
    }

    /// True when the key this head names really signed this statement.
    ///
    /// Checked on both sides of the crash. A head nobody signed is not evidence
    /// of anything, so comparing chains against it would prove nothing.
    pub fn verifies(&self) -> bool {
        let Some(key) = logchain::from_hex::<32>(&self.public_key)
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        else {
            return false;
        };
        let Some(signature) =
            logchain::from_hex::<64>(&self.signature).map(|bytes| Signature::from_bytes(&bytes))
        else {
            return false;
        };
        logchain::verify_head(
            &key,
            &self.session,
            self.last_id,
            &self.chain_bytes(),
            &signature,
        )
    }
}

/// A client that gives up rather than hanging when the sequencer is gone.
pub fn client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("a HTTP client")
}

/// The head right now, or `None` while the sequencer is not answering yet.
pub async fn head_of(client: &Client, url: &str) -> Option<Head> {
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json::<Head>().await.ok()
}

/// Waits until the sequencer answers and has published at least `at` messages.
///
/// Returns the first head that reached the count. At 10 messages a second the
/// head moves every 100 ms and this polls every 5 ms, so in practice the head
/// returned stands exactly at `at`. Nothing is asserted about that, because it
/// is a fact about scheduling rather than about the sequencer.
///
/// Returns `None` when this process lost its port to another program before it
/// bound. Nothing was opened and nothing was published, so the caller starts
/// another sequencer rather than reading the loss as a result.
///
/// `what` names the trial in every panic message, because these files run many
/// trials at once.
pub async fn wait_for_head(
    sequencer: &mut Sequencer,
    client: &Client,
    at: u64,
    what: &str,
) -> Option<Head> {
    let url = sequencer.url("/head");
    let give_up = Instant::now() + DEADLINE;
    let mut last: Option<u64> = None;
    loop {
        if let Some(head) = head_of(client, &url).await {
            if head.last_id >= at {
                return Some(head);
            }
            last = Some(head.last_id);
        }
        if sequencer.lost_its_port() {
            return None;
        }
        if let Some(status) = sequencer.ended() {
            panic!(
                "{}: the sequencer ended with {} before it had published {} messages. It \
                 said:\n{}",
                what,
                status,
                at,
                sequencer.said()
            );
        }
        if Instant::now() >= give_up {
            panic!(
                "{}: the sequencer did not reach {} messages within {:?}; it got to {:?}. It \
                 said:\n{}",
                what,
                at,
                DEADLINE,
                last,
                sequencer.said()
            );
        }
        sleep(POLL).await;
    }
}

/// Every message the sequencer serves, as the bytes it hashed.
///
/// Read from `/messages.ndjson` rather than `/orders` because that endpoint
/// serves one stored message per line and nothing else, so a line is exactly
/// what the chain covers. Taking the bytes out of the JSON array `/orders`
/// serves would put a scanner inside the check, and a bug in that scanner
/// reads as the sequencer having rewritten its history.
///
/// Paged, because a page is capped at 1000 messages.
pub async fn history(client: &Client, sequencer: &Sequencer, upto: u64) -> Vec<wire::RawMessage> {
    let mut out: Vec<wire::RawMessage> = Vec::new();
    let mut since = 0u64;
    while (out.len() as u64) < upto {
        let url = sequencer.url(&format!("/messages.ndjson?since={}&limit=1000", since));
        let response = client
            .get(&url)
            .send()
            .await
            .expect("the restarted sequencer answers for its own history");
        assert!(
            response.status().is_success(),
            "GET {} answered {}",
            url,
            response.status()
        );
        let body = response.bytes().await.expect("a page arrives whole");
        let page = wire::split_ndjson(&body).expect("a page is one stored message per line");
        let Some(last) = page.last() else {
            break;
        };
        since = last.id;
        out.extend(page);
    }
    out
}

/// The chain over the first `upto` messages served, after checking their ids
/// are 1..=upto with no gaps.
///
/// The gap check is inside the fold rather than beside it because it is the
/// same property: ids are 1..N by construction, so a missing id is a message
/// that was half written, and folding past it would produce a chain that
/// disagrees for a reason nobody could name.
pub fn chain_over(messages: &[wire::RawMessage], upto: u64, what: &str) -> Chain {
    assert!(
        messages.len() as u64 >= upto,
        "{}: the sequencer's head stands at {} and it served {} messages",
        what,
        upto,
        messages.len()
    );
    let mut chain = EMPTY_CHAIN;
    for (index, message) in messages.iter().take(upto as usize).enumerate() {
        let expected = index as u64 + 1;
        assert_eq!(
            message.id, expected,
            "{}: message {} of the history says it is message {}, so an id below the head is \
             missing",
            what, expected, message.id
        );
        chain = logchain::extend_bytes(&chain, &message.bytes);
    }
    chain
}
