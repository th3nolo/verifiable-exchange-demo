//! The two types the six matching steps pass between them.
//!
//! Everything else a step needs is either in `matcher.rs` or private to that
//! step's own module. `matcher.rs` holds the book, a resting order, a trade,
//! a position. These two types are here because more than one step reads them.
//! A step that had to import a type from another step's module would depend
//! on that step.
//!
//! See `matcher.rs`, above the `mod` lines, for the list of the six steps and
//! the table of what each one may read and change.

use crate::domain::{AccountId, OrderId, OrderType, Side, TimeInForce};

/// The three terms a `New` message carries beside its price and quantity. They
/// travel from the message into `IncomingOrder` as one parameter.
///
/// This struct exists so `apply_new` keeps a signature a reader can hold in
/// their head. The alternative was three more single-value parameters on a
/// function that already takes seven. A caller writing `Buy, 997.16, 2.0,
/// Limit, GoodTillCancel, false` then has six arguments in a row, and the
/// compiler cannot tell two of them apart if they are swapped.
///
/// `Default` is what a message that names none of the three terms means, and
/// that is every message the sequencer has published so far.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Terms {
    pub(super) order_type: OrderType,
    pub(super) time_in_force: TimeInForce,
    pub(super) post_only: bool,
}

/// One `New` message on its way through the six steps.
///
/// `apply_new` builds it after step 1, because step 1 is what turns the price
/// and the quantity the sender wrote as `f64` into whole numbers of the
/// symbol's price step and quantity step. Before step 1 there is only an
/// `OrderMessage`.
///
/// # What may change it
///
/// Step 3, and only `limit_cents`. Step 3 does not even write that field. It
/// returns the bounded price, and `apply_new` assigns it. Every other step
/// takes `&IncomingOrder`.
///
/// `qty_tenths` is the size the order arrived with, and it stays that size.
/// What is left after the match is step 5's return value and not a field here,
/// so no step can rewrite the size of somebody's order without saying so.
#[derive(Debug, Clone)]
pub(super) struct IncomingOrder {
    /// The message number this order arrived as. Also the order's own id, and
    /// what a trade records as `taker_order`.
    pub(super) id: OrderId,
    /// The sender's timestamp, in milliseconds. Copied onto every trade this
    /// order makes.
    pub(super) timestamp: u64,
    /// Who sent the order. Step 4 compares this account against the accounts
    /// resting in the book.
    pub(super) account: AccountId,
    /// The listed symbol, checked by step 1.
    pub(super) symbol: String,
    pub(super) side: Side,
    /// The highest price a buy will pay, or the lowest a sell will accept, in
    /// cents. Step 3 may replace it. Nothing else may.
    pub(super) limit_cents: i64,
    /// The size the order arrived with, in tenths.
    pub(super) qty_tenths: i64,
    /// Limit or market, as the sender wrote it on the message. Steps 2, 3 and
    /// 6 read this field. Nothing writes it.
    ///
    /// Step 3 wants only `is_market`: whether the price it is bounding was
    /// named by the sender or worked out by the server. The method below
    /// answers that one question.
    pub(super) order_type: OrderType,
    /// What the sender asked to happen to the part that does not fill. Steps 2
    /// and 6 read it: step 6 chooses rest or cancel for good-till-cancel and
    /// immediate-or-cancel, and step 2 is where fill-or-kill is decided,
    /// because by step 6 the fills have already happened, ENGINE.md section
    /// 4.0. Step 3 reads it too, to refuse a fill-or-kill order whose price the
    /// collar moved after step 2 measured the book at the old one.
    pub(super) time_in_force: TimeInForce,
    /// The sender asked to be refused rather than trade at once against
    /// something already resting. Step 2 reads it, and step 2 is the only step
    /// that can answer it: by step 5 the trade has already happened.
    pub(super) post_only: bool,
}

impl IncomingOrder {
    /// Whether the price on this order is a bound the server worked out, and
    /// not a price the sender named. ENGINE.md section 4.2: a market order
    /// arrives as a limit order priced so that it trades at once. So
    /// `limit_cents` holds a real price either way, and this method is the
    /// only thing that tells the two apart.
    ///
    /// Steps 2, 3 and 6 all ask this question, and none of them asks anything
    /// else about the order type. The answer decides whether post-only
    /// contradicts the order, whether the collar applies, and whether the
    /// remainder may rest.
    pub(super) fn is_market(&self) -> bool {
        matches!(self.order_type, OrderType::Market)
    }
}

/// Why a step refused the order.
///
/// The caller turns one of these into a count in `orders_ignored` and one
/// warning that reads `order {id} ignored: {reason}`, see
/// `MatcherState::ignore_order`. A step therefore writes the second half of
/// that sentence and nothing else. A step does not touch the counter, it does
/// not log, and it does not decide what a refusal costs the sender.
///
/// The reason is a string, and not an enum of every refusal there is, **so
/// that four agents adding four refusals in four modules never edit one shared
/// list.**
#[derive(Debug)]
pub(super) struct Rejected {
    kind: &'static str,
    reason: String,
}

impl Rejected {
    /// Refuses the order, and says why. `reason` completes the sentence
    /// `order 41 ignored: ...`. Write it in lower case and with no full stop,
    /// like `"'FOO-BAR' is not a listed symbol"`.
    ///
    /// `kind` is the same refusal in one word a program can read. `/market`
    /// counts the refusal under that word, so a sender can tell an unlisted
    /// symbol from a self-trade refusal instead of reading one
    /// `orders_ignored` total for both. Each step names its own kinds in its
    /// own module. There is no shared list to edit, for the same reason
    /// `reason` is a string.
    pub(super) fn because(kind: &'static str, reason: impl Into<String>) -> Self {
        Rejected {
            kind,
            reason: reason.into(),
        }
    }

    /// The one word this refusal is counted under.
    pub(super) fn kind(&self) -> &'static str {
        self.kind
    }
}

/// The rule set the log is running under, as the last `EngineRule` message
/// named it.
///
/// ENGINE.md section 3: the rules live in the log, because changing a rule
/// changes what the same messages produce. A rule set is one number and not a
/// set of independent flags. Ten flags would be 1,024 combinations of replay
/// behaviour, and two implementations would have to agree on every one of
/// them. One number lines the rule sets up in order, so what a build must
/// implement is "every rule set up to N".
///
/// Which rule set turned a given rule on is written in the step that
/// implements that rule, not here. This type carries the number and nothing
/// else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RuleSet(u32);

impl RuleSet {
    /// Rule set 1: the rules the log has run under since message 1, and what
    /// a history with no `EngineRule` message in it means.
    pub(super) const GENESIS: RuleSet = RuleSet(1);

    /// The newest rule set this build can execute. A message naming a later
    /// rule set is a message this binary cannot act on.
    pub(super) const NEWEST: RuleSet = RuleSet(2);

    /// The rule set `version` names, or `None` when this build does not know
    /// that rule set. Rule sets are cumulative: a later rule set includes
    /// every rule of the rule sets before it.
    pub(super) fn known(version: u32) -> Option<RuleSet> {
        (RuleSet::GENESIS.0..=RuleSet::NEWEST.0)
            .contains(&version)
            .then_some(RuleSet(version))
    }

    /// The number, for the state root and for the state database.
    pub(super) fn version(self) -> u32 {
        self.0
    }

    /// Whether this rule set is `version` or a later one.
    pub(super) fn at_least(self, version: u32) -> bool {
        self.0 >= version
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        RuleSet::GENESIS
    }
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}
