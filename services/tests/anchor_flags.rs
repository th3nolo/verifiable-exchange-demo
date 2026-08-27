//! What `--anchored-topic` and `--latest-selector` do to the process itself.
//!
//! The unit tests in `anchor.rs` check that a malformed value is refused and
//! that the order of flag, environment and default is what it says it is. What
//! they cannot check is that the refusal reaches the exit code, and that the
//! environment variable is actually read by the binary an auditor runs. That is
//! what this file is for: it runs the real command line and looks at what the
//! process printed and what it exited with.

use std::process::{Command, Output};

/// The deployed contract. Nothing here connects to anything, so the address
/// only has to be a real address.
const CONTRACT: &str = "0x2A4A287EC1F01b5bCb5568D2Ed0765Faf860a62b";

/// Addresses with nothing behind them. Every run below has to fail before it
/// sends anything, and a run that reached the network would fail differently
/// and slowly rather than passing quietly.
const DEAD: &str = "http://127.0.0.1:1";

/// One run of the audit with an anchor configured, plus whatever the caller
/// wants set in the environment.
fn audit_with(extra: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_services"));
    command
        .arg("--audit")
        .arg("/nonexistent/state.db")
        .arg("--feed-url")
        .arg(DEAD)
        .arg("--anchor-contract")
        .arg(CONTRACT)
        .arg("--anchor-rpc")
        .arg(DEAD)
        .args(extra)
        // The two variables this reads are cleared first: a developer who has
        // one exported would otherwise get a different answer here than CI.
        .env_remove("ANCHORED_TOPIC")
        .env_remove("LATEST_SELECTOR");
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().expect("the audit binary runs")
}

const TOPIC: &str = "0x846b388d9a84109263340756e41099d4945f475c34c4f401faf0850b7c6d8385";
const SELECTOR: &str = "0x52bfe789";

/// Every shape a mistyped value can have, from the flag and from the
/// environment, has to stop the process rather than search for events that do
/// not exist.
#[test]
fn a_malformed_value_exits_nonzero_naming_the_flag() {
    let bad_topics = [
        "0x846b388d",                                                           // too short
        "0x846b388d9a84109263340756e41099d4945f475c34c4f401faf0850b7c6d8385ab", // too long
        "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",   // not hex
        "0x846B388D9A84109263340756E41099D4945F475C34C4F401FAF0850B7C6D8385",   // uppercase
        "846b388d9a84109263340756e41099d4945f475c34c4f401faf0850b7c6d8385",     // no 0x
    ];
    for bad in bad_topics {
        let from_flag = audit_with(&["--anchored-topic", bad], &[]);
        let said = String::from_utf8_lossy(&from_flag.stderr).to_string();
        assert_ne!(
            from_flag.status.code(),
            Some(0),
            "'{}' was accepted as a topic",
            bad
        );
        assert!(
            said.contains("--anchored-topic") && said.contains(bad),
            "'{}' was refused with: {}",
            bad,
            said
        );

        let from_env = audit_with(&[], &[("ANCHORED_TOPIC", bad)]);
        let said = String::from_utf8_lossy(&from_env.stderr).to_string();
        assert_ne!(
            from_env.status.code(),
            Some(0),
            "'{}' was accepted out of the environment",
            bad
        );
        assert!(
            said.contains("ANCHORED_TOPIC") && said.contains("--anchored-topic"),
            "'{}' was refused with: {}",
            bad,
            said
        );
    }

    for bad in [
        "0x52bfe7",
        "0x52bfe789ab",
        "0xzzzzzzzz",
        "0x52BFE789",
        "52bfe789",
    ] {
        let from_flag = audit_with(&["--latest-selector", bad], &[]);
        let said = String::from_utf8_lossy(&from_flag.stderr).to_string();
        assert_ne!(
            from_flag.status.code(),
            Some(0),
            "'{}' was accepted as a selector",
            bad
        );
        assert!(
            said.contains("--latest-selector") && said.contains(bad),
            "'{}' was refused with: {}",
            bad,
            said
        );

        let from_env = audit_with(&[], &[("LATEST_SELECTOR", bad)]);
        assert_ne!(
            from_env.status.code(),
            Some(0),
            "'{}' was accepted out of the environment",
            bad
        );
        assert!(
            String::from_utf8_lossy(&from_env.stderr).contains("LATEST_SELECTOR"),
            "'{}' was refused without naming where it came from",
            bad
        );
    }
}

/// The flag over the environment variable, the environment variable over the
/// default, checked through the binary rather than through the function that
/// decides it. The warning names the value that won, which is how this can see
/// which one the process picked without a chain to point it at.
#[test]
fn the_flag_wins_over_the_environment_and_both_over_the_default() {
    let from_flag = format!("0x{}", "11".repeat(32));
    let from_env = format!("0x{}", "22".repeat(32));

    let both = audit_with(
        &["--anchored-topic", &from_flag],
        &[("ANCHORED_TOPIC", &from_env)],
    );
    let said = String::from_utf8_lossy(&both.stderr).to_string();
    assert!(said.contains(&from_flag), "the flag did not win: {}", said);
    assert!(
        !said.contains(&from_env),
        "the environment variable was used anyway: {}",
        said
    );

    let environment = audit_with(&[], &[("ANCHORED_TOPIC", &from_env)]);
    let said = String::from_utf8_lossy(&environment.stderr).to_string();
    assert!(
        said.contains(&from_env),
        "the environment variable was ignored: {}",
        said
    );

    // Nothing set: the deployed contract's values, and no warning at all.
    let nothing = audit_with(&[], &[]);
    let said = String::from_utf8_lossy(&nothing.stderr).to_string();
    assert!(
        !said.contains("was overridden"),
        "an audit that configures nothing warned about an override: {}",
        said
    );
}

/// The warning an operator has to see. A well-formed wrong value is the one
/// case validation cannot catch, and the audit it produces looks like a
/// contract that was never anchored to.
#[test]
fn an_override_warns_about_what_it_will_and_will_not_find() {
    let topic = format!("0x{}", "11".repeat(32));
    let run = audit_with(
        &[
            "--anchored-topic",
            &topic,
            "--latest-selector",
            "0xaabbccdd",
        ],
        &[],
    );
    let said = String::from_utf8_lossy(&run.stderr).to_string();
    assert!(
        said.contains("the Anchored topic was overridden"),
        "{}",
        said
    );
    assert!(said.contains("no anchors"), "{}", said);
    assert!(said.contains(TOPIC), "the default is not named: {}", said);
    assert!(
        said.contains("the latest() selector was overridden"),
        "{}",
        said
    );
    assert!(
        said.contains(SELECTOR),
        "the default is not named: {}",
        said
    );
}

/// The defaults have to be usable on their own: `--audit-url <url>` with
/// nothing else is the command a stranger runs, and it may not require them to
/// know what a function selector is.
#[test]
fn the_two_flags_are_optional() {
    let plain = Command::new(env!("CARGO_BIN_EXE_services"))
        .arg("--audit-url")
        .arg(DEAD)
        .env_remove("ANCHORED_TOPIC")
        .env_remove("LATEST_SELECTOR")
        .output()
        .expect("the audit binary runs");
    let said = String::from_utf8_lossy(&plain.stderr).to_string();
    // It cannot reach the exchange at a dead address, which is the failure it
    // is expected to have. What it must not do is complain about the two flags
    // nobody gave it.
    assert!(
        !said.contains("--anchored-topic") && !said.contains("--latest-selector"),
        "an audit with no anchor configuration mentioned them: {}",
        said
    );
}

// ---------------------------------------------------------------------------
// The root anchor contract, and the checker
// ---------------------------------------------------------------------------

/// The root anchor flags reach the process the same way, and they reach
/// `--verify` as well as `--audit`.
///
/// `--verify` is the point of this one. The Merkle root is the value a stranger
/// checks an inclusion proof against, and the checker had no way to ask what
/// root anybody committed to until these flags existed.
fn run_with(command: &str, extra: &[&str]) -> Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_services"));
    process
        .arg(command)
        .arg("/nonexistent/state.db")
        .arg("--feed-url")
        .arg(DEAD)
        .args(extra)
        .env_remove("ANCHORED_ROOT_TOPIC")
        .env_remove("ROOT_LATEST_SELECTOR");
    process.output().expect("the binary runs")
}

#[test]
fn a_malformed_root_anchor_address_stops_the_run_before_anything_is_read() {
    for command in ["--verify", "--audit"] {
        let out = run_with(
            command,
            &[
                "--root-anchor-contract",
                "0xnope",
                "--root-anchor-rpc",
                DEAD,
            ],
        );
        let said = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(
            out.status.code(),
            Some(2),
            "{} with a bad root anchor address: {}",
            command,
            said
        );
        assert!(
            said.contains("cannot use that root anchor") && said.contains("0xnope"),
            "{} said: {}",
            command,
            said
        );
    }
}

#[test]
fn a_malformed_root_topic_stops_the_run_and_names_the_value() {
    let out = run_with(
        "--verify",
        &[
            "--root-anchor-contract",
            CONTRACT,
            "--root-anchor-rpc",
            DEAD,
            "--anchored-root-topic",
            "0x846b388d",
        ],
    );
    let said = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(2), "{}", said);
    assert!(said.contains("0x846b388d"), "{}", said);
}

/// An override says so before anything runs, for the reason the chain anchor's
/// does: a well-formed wrong topic matches no logs, which reads as a contract
/// holding no anchors rather than as a mistake.
#[test]
fn a_root_topic_override_warns_before_the_run() {
    let out = run_with(
        "--verify",
        &[
            "--root-anchor-contract",
            CONTRACT,
            "--root-anchor-rpc",
            DEAD,
            "--anchored-root-topic",
            TOPIC,
        ],
    );
    let said = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        said.contains("warning:") && said.contains(TOPIC),
        "an override has to be announced: {}",
        said
    );
}

/// Both flags unset is a correct run: no request is made and nothing is said
/// about a contract nobody named.
#[test]
fn the_root_anchor_flags_are_optional() {
    let out = run_with("--verify", &[]);
    let said = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !said.contains("root anchor"),
        "a run that named no root anchor must not mention one: {}",
        said
    );
}
