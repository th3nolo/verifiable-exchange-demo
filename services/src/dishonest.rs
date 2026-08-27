//! A deliberately dishonest exchange, for the adversarial harness and for
//! nothing else.
//!
//! # Why this file exists
//!
//! Every other test in this repository asks "does the code do the right
//! thing". This one asks the opposite question: if the exchange did the wrong
//! thing, would any tool a stranger runs say so? That question cannot be
//! answered by editing a database, because a database edit is a lie told after
//! the fact. An operator who wants to steal edits the *engine*, and then every
//! record the engine writes is consistent with every other record it writes.
//! This file is that engine.
//!
//! # How it is kept out of a release binary
//!
//! The whole module is behind `#[cfg(feature = "dishonest")]`, and so is every
//! call site. `dishonest` is not in `[features]`'s default set, so
//! `cargo build --release` compiles none of it: not the module, not the
//! branch in `step5`, not the string `DISHONEST`. There is no runtime switch
//! to leave on by accident: the code is absent from the object file.
//!
//! `services/tests/adversarial.rs` proves that on every run. It reads the
//! release binary and asserts the marker string below is not in it.
//!
//! The one binary a harness can drive is `dishonest-exchange`, which carries
//! `required-features = ["dishonest"]` in `Cargo.toml`, so `cargo build` and
//! `cargo build --release` do not build it at all.
//!
//! # How it is driven
//!
//! One environment variable, `DISHONEST`, read once. Unset means an engine
//! that behaves exactly as the honest one does, which is what makes the
//! control run in the harness meaningful.

use std::sync::OnceLock;

/// The marker `services/tests/adversarial.rs` looks for in the release binary.
/// It must appear nowhere else in the crate.
pub const MARKER: &str = "DISHONEST-ENGINE-MARKER-8f2c";

/// One way the engine is made to misbehave. One at a time: an engine telling
/// two lies at once produces a report nobody can attribute.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Lie {
    /// Behaves exactly as the honest engine does.
    #[default]
    None,
    /// Fills the newest order at a price level instead of the oldest, so a
    /// fill goes to an order that was not next in line.
    Priority,
    /// Fills against a resting order the owner already cancelled.
    CancelledFill,
    /// Fills at a price past the taker's limit.
    OverLimit,
    /// Lets one account trade with itself after rule set 2.
    SelfTrade,
    /// Trades a symbol no `ListSymbol` message ever named.
    PhantomMarket,
    /// Drops an order that should have rested.
    DropResting,
    /// Reports a position's realized profit differently from what the fills
    /// imply. Nothing durable changes: only what `GET /positions` and
    /// `GET /pnl` answer.
    Positions,
    /// Signs every execution claim over a state root that is not the state's.
    Root,
}

/// How much `Positions` adds to every realized profit it reports, in mills.
pub const POSITION_LIE_MILLS: i64 = 1_000_000;

static LIE: OnceLock<Lie> = OnceLock::new();

/// The lie this process was started with. Read once from `DISHONEST`.
pub fn lie() -> Lie {
    *LIE.get_or_init(|| match std::env::var("DISHONEST").ok().as_deref() {
        Some("priority") => Lie::Priority,
        Some("cancelled-fill") => Lie::CancelledFill,
        Some("over-limit") => Lie::OverLimit,
        Some("self-trade") => Lie::SelfTrade,
        Some("phantom-market") => Lie::PhantomMarket,
        Some("drop-resting") => Lie::DropResting,
        Some("positions") => Lie::Positions,
        Some("root") => Lie::Root,
        _ => Lie::None,
    })
}

/// True when this process was started to tell exactly this lie.
pub fn telling(which: Lie) -> bool {
    lie() == which
}

/// What `Root` turns a state root into: a value the state does not hash to.
///
/// Every root is changed the same way, so the claims still form an unbroken
/// chain: `root_before` of one claim is `root_after` of the last. Only the
/// relation between a claim and the state it describes is broken, which is
/// the one thing an auditor has to re-derive rather than read.
pub fn doctor_root(root: [u8; 32]) -> [u8; 32] {
    if !telling(Lie::Root) {
        return root;
    }
    let mut doctored = root;
    doctored[0] ^= 0x01;
    doctored
}
