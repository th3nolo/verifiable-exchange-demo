//! The dishonest exchange the adversarial harness drives.
//!
//! It is `services --start-matcher` and nothing else: the same
//! `matcher::start_matcher`, on the same flags, writing the same state
//! database and signing the same claims. What differs is that this target is
//! built with the `dishonest` feature on, so the hooks in `matcher.rs` and in
//! the six matching steps are compiled in and the `DISHONEST` environment
//! variable picks one of them. See `src/dishonest.rs`.
//!
//! **This target is not in a release build.** `Cargo.toml` gives it
//! `required-features = ["dishonest"]`, and `dishonest` is not a default
//! feature, so `cargo build` and `cargo build --release` build the `services`
//! binary and skip this one. `services/tests/adversarial.rs` checks that the
//! release binary holds no trace of the module.
//!
//! The flags are the small set the harness uses, parsed by hand rather than
//! with clap, so this file cannot drift into being a second copy of the real
//! command line. Anyone wanting the whole tool runs `services`.

use std::net::IpAddr;
use std::path::PathBuf;

use services::{dishonest, matcher};

fn value(args: &[String], flag: &str) -> Option<String> {
    let at = args.iter().position(|a| a == flag)?;
    args.get(at + 1).cloned()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Said on stderr at every start, because a process that misbehaves on
    // purpose must never be mistaken for one that is failing.
    eprintln!(
        "{}: this is the DISHONEST exchange. It is telling the lie {:?}. Nothing it \
         records is evidence of anything.",
        dishonest::MARKER,
        dishonest::lie()
    );
    matcher::start_matcher(matcher::MatcherOptions {
        feed_url: value(&args, "--feed-url").unwrap_or_else(|| "http://127.0.0.1:3000".to_string()),
        public_feed_url: value(&args, "--feed-url")
            .unwrap_or_else(|| "http://127.0.0.1:3000".to_string()),
        public_inbox_url: None,
        bind: "127.0.0.1".parse::<IpAddr>().expect("a loopback address"),
        port: value(&args, "--matcher-port")
            .and_then(|p| p.parse().ok())
            .unwrap_or(3001),
        poll_ms: value(&args, "--poll-ms")
            .and_then(|p| p.parse().ok())
            .unwrap_or(200),
        state_db: Some(
            value(&args, "--state-db")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("state.db")),
        ),
        reset_state: args.iter().any(|a| a == "--reset-state"),
        validators: Vec::new(),
    })
    .await;
}
