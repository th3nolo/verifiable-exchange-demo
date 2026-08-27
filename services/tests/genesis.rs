//! What a deployment publishes to open an empty log.
//!
//! A sequencer started with `--operator-key` publishes nothing of its own
//! while its log is empty, so the first messages are whatever the operator
//! writes. `docker/open-the-log.sh` is what writes them: the rule set the
//! build runs, then one listing per market. Both `./demo.sh` and
//! `docker/entrypoint.sh` run that file, and so does this test. The script is
//! what is covered here, not a copy of its steps in Rust. A shell script has
//! no compiler, so running it is the only check on it that means anything.
//!
//! Two halves, and the second is the one that matters.
//!
//! The first half is the opening itself: messages 1 to 4 are the rule set and
//! the three listings, message 5 is the first order, and a fresh engine
//! replaying 1 to 5 holds three listed symbols and rests that order.
//!
//! The second half is the restart. A container restarts on every deploy and
//! after every crash, and the entrypoint runs the opening step every time. A
//! second opening would publish a rule set the log already has and list three
//! symbols that already trade. The engine ignores all four, so the damage is
//! four dead messages per restart forever, and nothing in the running exchange
//! would look wrong. The guard is the head: the script publishes only when the
//! last id is 0.
//!
//! # Why the opening cannot race generated traffic
//!
//! The sequencer reserves messages 1 to 4 for the operator while an operator
//! key is configured. Direct submissions and inbox entries wait too. The
//! generator starts only after message 4 exists. This test once relied on the
//! opening script winning a timing race; a loaded full-suite run proved that
//! margin false by putting an order at message 2.
//!
//! Run this file on its own with:
//!
//! ```text
//! cargo test --test genesis
//! ```

use std::fs::File;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use reqwest::Client;
use serde::Deserialize;
use services::domain::{OrderMessage, SYMBOLS};
use services::matcher::MatcherState;
use services::wire;
use tempfile::TempDir;
use tokio::time::sleep;

/// The opening script, as the deployment and `./demo.sh` run it.
const OPEN_THE_LOG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../docker/open-the-log.sh");

/// Messages a second from the generator after the opening completes.
const RATE: &str = "1";

/// The quantity step every market opens on: one tenth, the finest grid the
/// engine holds. `docker/open-the-log.sh` names this one itself.
///
/// There is no `PRICE_STEP` beside it. The price step is per market and is
/// named in `domain::SYMBOLS`; the script reads it off the sequencer's
/// `/symbols`, so this test reads it from the same constant the sequencer
/// serves.
const QUANTITY_STEP: f64 = 0.1;

/// How long anything is waited for before the test gives up and says what it
/// was waiting for. Only reached when something is stuck.
const DEADLINE: Duration = Duration::from_secs(60);

/// How often the head is read while waiting for it to move.
const POLL: Duration = Duration::from_millis(20);

/// A port nothing is listening on, from the operating system. The same reason
/// as in `crash_restart.rs`: arithmetic on a thread id can hand two tests one
/// port and the operating system cannot.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the operating system has a free port");
    listener
        .local_addr()
        .expect("a bound listener has an address")
        .port()
}

/// One running service. Killed and reaped by `Drop`, so a failed assertion
/// leaves no process holding a port or a database.
struct Service {
    child: Child,
    port: u16,
    log: PathBuf,
}

impl Service {
    /// Starts the binary with these arguments, with its output in a file.
    ///
    /// A file and not a pipe: the sequencer writes a line per message and a
    /// pipe nobody reads blocks the process that is writing it.
    fn start(dir: &Path, name: &str, port: u16, args: &[&str]) -> Service {
        let log = dir.join(format!("{}-{}.log", name, port));
        let out = File::create(&log).expect("a log file for the service");
        let err = out.try_clone().expect("the same log file for stderr");
        let child = Command::new(env!("CARGO_BIN_EXE_services"))
            .args(args)
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("the services binary starts");
        Service { child, port, log }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Everything the process has said so far, read on failure so an assertion
    /// can show why a service would not start.
    fn said(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The status if the process has ended, without waiting for it.
    fn ended(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().unwrap_or(None)
    }

    /// Ends the process and waits for it to be gone, so the next process on
    /// this database does not open it while the old one still holds it.
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        // Reaped, or it stays a zombie for as long as the test binary runs.
        let _ = self.child.wait();
    }
}

/// The signed head, as `GET /head` serves it. Only the fields this test reads.
#[derive(Debug, Clone, Deserialize)]
struct Head {
    last_id: u64,
    /// The name of this log. A replay needs it: an operator message is signed
    /// over a statement whose second line is the session, and the session is
    /// nowhere in the message itself.
    session: String,
}

/// The exchange's `/market`, again only the field this test reads.
#[derive(Debug, Clone, Deserialize)]
struct Market {
    newest_rule_set: u32,
    /// The markets the exchange holds, in the order the log listed them.
    #[serde(default)]
    symbols: Vec<MarketSymbol>,
}

/// One market on `/market`. Only the two fields this test reads.
#[derive(Debug, Clone, Deserialize)]
struct MarketSymbol {
    symbol: String,
    price_step: f64,
}

fn client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("a HTTP client")
}

/// Waits until this path answers with a 2xx, or says what never came up.
async fn wait_for(client: &Client, service: &mut Service, path: &str, name: &str) {
    let give_up = Instant::now() + DEADLINE;
    let url = service.url(path);
    loop {
        if let Ok(response) = client.get(&url).send().await {
            if response.status().is_success() {
                return;
            }
        }
        if let Some(status) = service.ended() {
            panic!(
                "the {} ended with {} before it answered {}. It said:\n{}",
                name,
                status,
                url,
                service.said()
            );
        }
        assert!(
            Instant::now() < give_up,
            "the {} never answered {} within {:?}. It said:\n{}",
            name,
            url,
            DEADLINE,
            service.said()
        );
        sleep(POLL).await;
    }
}

/// The sequencer's head right now.
async fn head_of(client: &Client, sequencer: &Service) -> Head {
    client
        .get(sequencer.url("/head"))
        .send()
        .await
        .expect("the sequencer answers for its head")
        .json::<Head>()
        .await
        .expect("a head names its last id")
}

/// Waits until the sequencer has published at least `at` messages.
async fn wait_for_head(client: &Client, sequencer: &mut Service, at: u64) {
    let give_up = Instant::now() + DEADLINE;
    loop {
        let head = head_of(client, sequencer).await;
        if head.last_id >= at {
            return;
        }
        if let Some(status) = sequencer.ended() {
            panic!(
                "the sequencer ended with {} at message {}. It said:\n{}",
                status,
                head.last_id,
                sequencer.said()
            );
        }
        assert!(
            Instant::now() < give_up,
            "the sequencer stopped at message {} and never reached {} within {:?}. It said:\n{}",
            head.last_id,
            at,
            DEADLINE,
            sequencer.said()
        );
        sleep(POLL).await;
    }
}

/// Every message the sequencer has published, as the bytes it hashed.
///
/// From `/messages.ndjson`, which serves one stored message per line, for the
/// same reason `crash_restart.rs` reads it: a line is exactly the bytes the
/// chain covers, with no scanner of this test's own in the way.
async fn history(client: &Client, sequencer: &Service) -> Vec<wire::RawMessage> {
    let mut out: Vec<wire::RawMessage> = Vec::new();
    let mut since = 0u64;
    loop {
        let url = sequencer.url(&format!("/messages.ndjson?since={}&limit=1000", since));
        let response = client
            .get(&url)
            .send()
            .await
            .expect("the sequencer answers for its own history");
        assert!(
            response.status().is_success(),
            "GET {} answered {}",
            url,
            response.status()
        );
        let body = response.bytes().await.expect("a page arrives whole");
        let page = wire::split_ndjson(&body).expect("a page is one stored message per line");
        let Some(last) = page.last() else {
            return out;
        };
        since = last.id;
        out.extend(page);
    }
}

/// Runs `docker/open-the-log.sh` exactly as the entrypoint runs it.
fn open_the_log(dir: &Path, feed_url: &str, matcher_url: &str) -> std::process::Output {
    Command::new("bash")
        .arg(OPEN_THE_LOG)
        .arg(env!("CARGO_BIN_EXE_services"))
        .arg(feed_url)
        .arg(matcher_url)
        .arg("operator.key")
        .current_dir(dir)
        .output()
        .expect("bash runs the opening script")
}

/// The operator messages in a history: the ones no trader may publish.
fn operator_messages(history: &[wire::RawMessage]) -> Vec<(u64, String)> {
    history
        .iter()
        .filter(|raw| {
            matches!(
                raw.kind.as_str(),
                "EngineRule" | "ListSymbol" | "DelistSymbol"
            )
        })
        .map(|raw| (raw.id, raw.kind.clone()))
        .collect()
}

/// A fresh log opens with the rule set and the symbols, and a restart on the
/// same database opens nothing a second time.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_log_opens_with_the_rules_and_the_symbols() {
    let dir = TempDir::new().expect("a temporary directory");
    let client = client();

    // The operator key, as a deployment with no mounted secret mints one: 32
    // bytes of hex. The value does not matter, only that the sequencer is
    // started naming the public key of this file.
    std::fs::write(dir.path().join("operator.key"), "07".repeat(32)).expect("a key file");
    let public_key = Command::new(env!("CARGO_BIN_EXE_services"))
        .arg("--operator-public-key")
        .arg("--operator-key-file")
        .arg("operator.key")
        .current_dir(dir.path())
        .output()
        .expect("--operator-public-key runs");
    assert!(
        public_key.status.success(),
        "--operator-public-key failed: {}",
        String::from_utf8_lossy(&public_key.stderr)
    );
    let public_key = String::from_utf8(public_key.stdout)
        .expect("a public key is text")
        .trim()
        .to_string();

    let feed_port = free_port();
    let matcher_port = free_port();
    let feed_args = [
        "--start-feed",
        "--feed-port",
        &feed_port.to_string(),
        "--feed-db",
        "feed.db",
        "--rate",
        RATE,
        "--operator-key",
        &public_key,
    ];
    let mut sequencer = Service::start(dir.path(), "sequencer", feed_port, &feed_args);
    wait_for(&client, &mut sequencer, "/head", "sequencer").await;

    // The exchange, because the rule set the script publishes is read from its
    // /market and no other service reports it. It also has to answer on a log
    // with nothing in it, which is what the entrypoint's ordering rests on.
    let mut exchange = Service::start(
        dir.path(),
        "exchange",
        matcher_port,
        &[
            "--start-matcher",
            "--matcher-port",
            &matcher_port.to_string(),
            "--feed-url",
            &sequencer.base_url(),
            "--no-state-db",
        ],
    );
    wait_for(&client, &mut exchange, "/market", "exchange").await;

    // Nothing is published while the log is closed. Read before the opening,
    // so a sequencer that ignored --operator-key fails here and not later.
    assert_eq!(
        head_of(&client, &sequencer).await.last_id,
        0,
        "the sequencer published before the operator opened the log. It said:\n{}",
        sequencer.said()
    );

    let newest_rule_set = client
        .get(exchange.url("/market"))
        .send()
        .await
        .expect("the exchange answers for its market")
        .json::<Market>()
        .await
        .expect("a market names the newest rule set it runs")
        .newest_rule_set;

    // ---- The opening ----

    let opened = open_the_log(dir.path(), &sequencer.base_url(), &exchange.base_url());
    assert!(
        opened.status.success(),
        "open-the-log.sh failed: {}{}",
        String::from_utf8_lossy(&opened.stdout),
        String::from_utf8_lossy(&opened.stderr)
    );

    wait_for_head(&client, &mut sequencer, 5).await;
    let log = history(&client, &sequencer).await;
    assert!(log.len() >= 5, "the log holds {} messages", log.len());

    // Message 1 says what every message after it means.
    let rules: OrderMessage = log[0].parse().expect("message 1 is readable");
    match &rules {
        OrderMessage::EngineRule { id, version, .. } => {
            assert_eq!(*id, 1, "the rule set is not message 1");
            assert_eq!(
                *version, newest_rule_set,
                "message 1 names rule set {}, and this build runs {}",
                version, newest_rule_set
            );
        }
        other => panic!("message 1 is {:?} and not the rule set", other),
    }

    // Messages 2 to 4 open the three markets, in the order the sequencer
    // serves them on /symbols, which is domain::SYMBOLS.
    let mut listed = Vec::new();
    for (offset, (expected, _, expected_step)) in SYMBOLS.iter().enumerate() {
        let message: OrderMessage = log[offset + 1].parse().expect("a listing is readable");
        match &message {
            OrderMessage::ListSymbol {
                id,
                symbol,
                price_step,
                quantity_step,
                ..
            } => {
                assert_eq!(*id, offset as u64 + 2, "a listing is out of place");
                assert_eq!(symbol, expected, "message {} lists the wrong market", id);
                // The step the script read off `/symbols`, which is the step
                // this market is named with in `domain::SYMBOLS`. A market
                // opened on any other step is one the script named itself.
                assert_eq!(
                    *price_step, *expected_step,
                    "{} opened on a price step of {} and its step is {}",
                    symbol, price_step, expected_step
                );
                assert_eq!(
                    *quantity_step, QUANTITY_STEP,
                    "{} opened off the grid",
                    symbol
                );
                listed.push(symbol.clone());
            }
            other => panic!("message {} is {:?} and not a listing", offset + 2, other),
        }
    }
    assert_eq!(
        listed.len(),
        3,
        "three markets open, and {} did",
        listed.len()
    );

    // Message 5 is the first order, and nothing before it was one.
    let first_order: OrderMessage = log[4].parse().expect("message 5 is readable");
    assert!(
        matches!(first_order, OrderMessage::New { id: 5, .. }),
        "message 5 is {:?} and not the first order",
        first_order
    );
    assert_eq!(
        operator_messages(&log[..5]).len(),
        4,
        "the first five messages are the rules, three listings and one order"
    );

    // A fresh engine replaying 1 to 5 holds the three markets and the order.
    //
    // It is told which log it is replaying. The three listings are signed for
    // this session, so an engine that did not know it would refuse all three
    // and hold no market, see `MatcherState::replaying`.
    let session = head_of(&client, &sequencer).await.session;
    let mut engine = MatcherState::replaying(&session);
    for raw in &log[..5] {
        let message: OrderMessage = raw.parse().expect("this build reads its own log");
        engine
            .apply_message(&message)
            .unwrap_or_else(|e| panic!("message {} was refused in feed order: {:?}", raw.id, e));
    }
    assert_eq!(
        engine.listed_symbols().len(),
        3,
        "a replay of the opening listed {:?}",
        engine.listed_symbols()
    );
    for (symbol, _, _) in SYMBOLS.iter() {
        assert!(
            engine.is_listed(symbol),
            "{} does not trade after a replay",
            symbol
        );
    }
    assert!(
        engine.open_order(5).is_some(),
        "the first order did not rest; the engine ignored {}",
        engine.orders_ignored()
    );

    // ---- What the exchange serves ----
    //
    // The running exchange holds the same three markets, on the same steps,
    // and in the order the log listed them. The order is checked because the
    // registry inside the engine is a `BTreeMap` and a `BTreeMap` is in name
    // order: the browser opens on the first row `/market` serves, and in name
    // order that row was BTC-USDC, the market the operator listed last.
    let give_up = Instant::now() + DEADLINE;
    let market = loop {
        let market = client
            .get(exchange.url("/market"))
            .send()
            .await
            .expect("the exchange answers for its market")
            .json::<Market>()
            .await
            .expect("a market is readable");
        if market.symbols.len() == 3 {
            break market;
        }
        assert!(
            Instant::now() < give_up,
            "the exchange holds {:?} and the log listed three markets",
            market.symbols
        );
        sleep(POLL).await;
    };
    let served: Vec<(&str, f64)> = market
        .symbols
        .iter()
        .map(|s| (s.symbol.as_str(), s.price_step))
        .collect();
    let listed: Vec<(&str, f64)> = SYMBOLS
        .iter()
        .map(|(symbol, _, step)| (*symbol, *step))
        .collect();
    assert_eq!(
        served, listed,
        "the exchange serves its markets in a different order or on different steps \
         from the order the log listed them in"
    );

    // ---- The restart ----
    //
    // The same database, the same key, and the same opening step the
    // entrypoint runs on every start. Nothing new may be published.

    sequencer.stop();
    let mut restarted = Service::start(dir.path(), "restarted", feed_port, &feed_args);
    wait_for(&client, &mut restarted, "/head", "restarted sequencer").await;

    let again = open_the_log(dir.path(), &restarted.base_url(), &exchange.base_url());
    assert!(
        again.status.success(),
        "a restart made the opening step fail: {}{}",
        String::from_utf8_lossy(&again.stdout),
        String::from_utf8_lossy(&again.stderr)
    );
    let said = String::from_utf8_lossy(&again.stderr);
    assert!(
        said.contains("Publishing nothing"),
        "the restart did not say it was publishing nothing: {}",
        said
    );

    // Counted over the whole history rather than over its first messages: a
    // second opening would append to the end, behind whatever the generator
    // published while the test was restarting.
    let after = history(&client, &restarted).await;
    assert_eq!(
        operator_messages(&after),
        vec![
            (1, "EngineRule".to_string()),
            (2, "ListSymbol".to_string()),
            (3, "ListSymbol".to_string()),
            (4, "ListSymbol".to_string()),
        ],
        "the restart opened the log a second time"
    );
}
