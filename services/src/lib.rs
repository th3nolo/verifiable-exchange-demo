pub mod anchor;
pub mod bot;
pub mod cors;
/// A deliberately dishonest exchange, for the adversarial harness. Behind the
/// `dishonest` feature, which is not on by default, so `cargo build --release`
/// compiles none of it. See `dishonest.rs`.
#[cfg(feature = "dishonest")]
pub mod dishonest;
pub mod domain;
pub mod feed;
/// How this repository's programs read a bounded body over HTTP. Timeouts,
/// the client, the size cap, and the sentence an error turns into. Never a
/// rule about what a body means.
pub mod fetch;
mod http_security;
pub mod inbox;
pub mod logchain;
pub mod matcher;
pub mod merkle;
pub mod operator;
pub mod prove;
/// The checker and the audit share what a check counts and what makes a
/// signed head trustworthy. Not public: only these two programs report.
mod reporting;
pub mod sqlite;
/// The exchange, behind the market-harness stdio protocol. It reads that
/// harness's commands and writes that harness's events, so a suite this
/// repository did not write can score this exchange. It states no matching
/// rule and it holds no book.
pub mod stdio_engine;
pub mod store;
pub mod validator;
pub mod verify;
pub mod wire;
