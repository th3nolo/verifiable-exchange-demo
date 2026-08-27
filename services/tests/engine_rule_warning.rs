//! What `--engine-rule` prints about the rule set it is publishing.
//!
//! The warning reads one field off the exchange's `/market`, by name, over
//! HTTP. No unit test can hold that link: the exchange serves the name in one
//! file and the command looks it up in another. So this file runs the real
//! command line against a stub `/market` and reads what the process printed.
//!
//! The failure it pins is the one the field was added for. Reading `rule_set`,
//! the rule set the log has put the exchange in, made the warning fire on the
//! normal upgrade, publishing rule set 2 to an exchange still running rule
//! set 1, which is every correct run of this command. A warning that fires on
//! the correct path is one the operator stops reading.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};

/// What the stub feed serves on `/head`. The command reads the session from
/// there and signs for it. Any 16 hex characters work: nothing here verifies a
/// signature, and `--sign-only` sends nothing.
const FEED_HEAD: &str = r#"{"session":"349d462ced25bb2b"}"#;

/// Serves `body` as JSON to every request, on a loopback port the operating
/// system picks, and returns the URL to reach it on.
///
/// The thread runs until the test binary exits. Two stubs are needed per run:
/// the feed for `/head` and the exchange for `/market`. Each answers one
/// request in these tests, so nothing here has to route on the path.
fn stub(body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let url = format!("http://{}", listener.local_addr().expect("the port bound"));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // Read to the end of the headers, so the client is not answered
            // before it has finished sending. Nothing here reads the request.
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => request.push(byte[0]),
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    url
}

/// One run of `--engine-rule VERSION` against an exchange whose `/market`
/// serves `market`.
///
/// `--sign-only` prints the signed message instead of sending it, so the run
/// reaches the warning and then stops without a feed to publish to.
fn engine_rule(version: &str, market: &'static str) -> Output {
    let feed = stub(FEED_HEAD);
    let matcher = stub(market);
    // A directory of its own, and not a name built from the version. Two of
    // the tests below publish version 2, so a name holding the process id and
    // the version was the same name twice. The tests run at the same time, so
    // one deleted the other's key between the write and the read, and the run
    // that lost printed "does not exist; this is the operator key" on stderr
    // -- which the first test reads as the upgrade having warned. It passed
    // here and failed on CI, which is what a race does.
    let home = tempfile::tempdir().expect("a directory for the key");
    let key_file = home.path().join("operator.key");
    // The operator key is read and never created, so the test writes one. The
    // bytes only have to be 32 bytes of hex: nothing checks this signature.
    std::fs::write(&key_file, "07".repeat(32)).expect("the key file is written");
    let output = Command::new(env!("CARGO_BIN_EXE_services"))
        .arg("--engine-rule")
        .arg(version)
        .arg("--feed-url")
        .arg(&feed)
        .arg("--matcher-url")
        .arg(&matcher)
        .arg("--operator-key-file")
        .arg(&key_file)
        .arg("--sign-only")
        .output()
        .expect("the operator binary runs");
    // `home` is dropped here, which takes the key with it. It has to outlive
    // the command above, so it is not a temporary.
    output
}

/// An exchange that runs rule sets up to 2 and is still in rule set 1, which
/// is what every exchange looks like at the moment the upgrade is published.
const RUNS_1_IMPLEMENTS_2: &str = r#"{"rule_set":1,"newest_rule_set":2}"#;

/// Publishing the newest rule set the exchange runs is the upgrade itself. It
/// must say nothing.
#[test]
fn publishing_the_newest_rule_set_the_exchange_runs_warns_nothing() {
    let output = engine_rule("2", RUNS_1_IMPLEMENTS_2);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.is_empty(),
        "the normal upgrade printed a warning: {}",
        stderr
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""kind":"EngineRule""#) && stdout.contains(r#""version":2"#),
        "the signed message was not printed: {}",
        stdout
    );
}

/// Past the newest rule set is the typo this warning exists to catch. It is
/// still published, and the line has to name both numbers.
#[test]
fn publishing_past_the_newest_rule_set_warns_and_publishes_anyway() {
    let output = engine_rule("99", RUNS_1_IMPLEMENTS_2);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("runs rule sets up to 2") && stderr.contains("rule set 99"),
        "the warning did not name both rule sets: {}",
        stderr
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""kind":"EngineRule""#),
        "the message was withheld; this warning is advice and never a refusal: {}",
        stdout
    );
}

/// An exchange too old to name the field, and no exchange at all, are the same
/// answer: the value could not be checked, and the message goes out.
#[test]
fn an_exchange_that_does_not_name_the_field_is_not_a_refusal() {
    let output = engine_rule("2", r#"{"rule_set":1}"#);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot read newest_rule_set"),
        "the unchecked run said nothing about it: {}",
        stderr
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""kind":"EngineRule""#),
        "a missing exchange stopped the command: {}",
        stdout
    );
}
