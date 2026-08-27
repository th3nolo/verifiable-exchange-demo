//! Step 1: resolve the symbol.
//!
//! Was this symbol listed at this point in the log, and what are its price and
//! quantity steps? The answer is the order's price and quantity as whole
//! numbers of those steps.
//!
//! | | |
//! |---|---|
//! | Owner | the Listings feature |
//! | May read | the symbol registry, and the price and quantity being resolved |
//! | May change | nothing |
//!
//! This step takes the registry and three numbers, not the whole message.
//! That is on purpose. The step must not read the account, the side or the
//! nonce.
//!
//! # The one question this step asks, and where it asks it
//!
//! This step used to read `domain::SYMBOLS`, a list built into the binary. The
//! answer to "may this order trade" then depended on which binary ran the
//! replay, not on the history being replayed. Measured on the live log:
//! removing `ETH-USDC` from that list and replaying the same 2,480 messages
//! moved the state root from `ebc7c0f463d5895c…` to `3a5907ceed262e9e…`, and
//! 613 orders were ignored without a word.
//!
//! The registry answers the same question from the log's own `ListSymbol` and
//! `DelistSymbol` messages. Every replayer then reads the same answer out of
//! the same history. One thing is kept from the old rule: **a symbol nobody
//! listed is refused**. So the sequencer cannot invent a symbol and put a
//! string of its choosing into the state root.
//!
//! # Three refusals
//!
//! - a symbol the log has not listed, or has delisted, is refused;
//! - a price or a quantity that is not a whole number of the symbol's steps is
//!   refused. Rounding the number would change or erase somebody's order
//!   without saying so;
//! - a price or a quantity this engine cannot hold as a whole number is
//!   refused, for the same reason. That limit comes from the numbers the
//!   engine stores, not from the listing, and it is the same in every build,
//!   see `MAX_GRID_UNITS` in `domain.rs`.
//!
//! The books hold whole cents and whole tenths. A price step and a quantity
//! step are counted in those units, and this step answers in them too. A
//! symbol listed on a price step finer than one cent is refused when the
//! `ListSymbol` message runs, not here, see
//! `MatcherState::apply_list_symbol`.

use crate::domain::to_grid;

use super::pipeline::Rejected;
use super::{Listing, SymbolRegistry};

/// A price is multiplied by this number to reach the whole cents this engine
/// keeps its books in.
const PRICE_UNITS_PER_UNIT: f64 = 100.0;

/// A quantity is multiplied by this number to reach whole tenths.
const QUANTITY_UNITS_PER_UNIT: f64 = 10.0;

/// What `/market` counts a symbol this exchange does not trade under.
pub(super) const UNLISTED_SYMBOL: &str = "unlisted_symbol";

/// What `/market` counts a price or a quantity this engine cannot hold as a
/// whole number under. The limit comes from the numbers the engine stores. It
/// is the same in every build, and the listing did not choose it.
pub(super) const OFF_GRID: &str = "off_grid";

/// What `/market` counts a price off the symbol's own price step under.
///
/// Separate from `OFF_GRID` because the sender can act on the two differently.
/// A price `OFF_GRID` counts is a price no market here can take. A price off
/// the price step is a price this one market cannot take. `/market` serves the
/// symbol's steps beside this count, so the sender can correct the second one
/// without asking anybody.
pub(super) const OFF_PRICE_STEP: &str = "off_price_step";

/// What `/market` counts a quantity off the symbol's own quantity step under.
pub(super) const OFF_QUANTITY_STEP: &str = "off_quantity_step";

/// The order's price and quantity as whole numbers of the symbol's steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Resolved {
    pub(super) limit_cents: i64,
    pub(super) qty_tenths: i64,
}

/// Resolves `symbol` against the registry and puts `price` and `quantity` on
/// its steps.
pub(super) fn resolve(
    registry: &SymbolRegistry,
    symbol: &str,
    price: f64,
    quantity: f64,
) -> Result<Resolved, Rejected> {
    // The dishonest build opens a market nobody listed, on the finest steps
    // the engine holds.
    #[cfg(feature = "dishonest")]
    let phantom = super::phantom_listing();
    #[cfg(feature = "dishonest")]
    let found = registry.listing(symbol).or(phantom.as_ref());
    #[cfg(not(feature = "dishonest"))]
    let found = registry.listing(symbol);
    let Some(listing) = found else {
        return Err(Rejected::because(
            UNLISTED_SYMBOL,
            format!("'{}' is not a listed symbol", symbol),
        ));
    };
    let (Some(limit_cents), Some(qty_tenths)) = (
        to_grid(price, PRICE_UNITS_PER_UNIT),
        to_grid(quantity, QUANTITY_UNITS_PER_UNIT),
    ) else {
        // The message below has always said "off-grid" on the terminal.
        // GLOSSARY.md bans that word. The text stays anyway, because an
        // operator searches old terminal output for it, and this is the last
        // place the word is written.
        return Err(Rejected::because(
            OFF_GRID,
            format!("price {} or quantity {} is off-grid", price, quantity),
        ));
    };
    on_steps(listing, symbol, limit_cents, qty_tenths)?;
    Ok(Resolved {
        limit_cents,
        qty_tenths,
    })
}

/// Whether the order sits on the price step and the quantity step the log
/// listed this symbol on.
///
/// Both steps are whole counts of the engine's own units. So the check is a
/// remainder, and not a comparison of two `f64` values. Every symbol listed
/// today uses 0.01 and 0.1, which makes both divisors 1 and lets every order
/// through. That is why this check changes nothing for a log that lists no
/// coarser step.
fn on_steps(
    listing: &Listing,
    symbol: &str,
    limit_cents: i64,
    qty_tenths: i64,
) -> Result<(), Rejected> {
    if limit_cents % listing.price_step_cents != 0 {
        return Err(Rejected::because(
            OFF_PRICE_STEP,
            format!(
                "price {} is not a whole number of '{}''s price step of {}",
                super::cents_to_f64(limit_cents),
                symbol,
                super::cents_to_f64(listing.price_step_cents)
            ),
        ));
    }
    if qty_tenths % listing.quantity_step_tenths != 0 {
        return Err(Rejected::because(
            OFF_QUANTITY_STEP,
            format!(
                "quantity {} is not a whole number of '{}''s quantity step of {}",
                super::tenths_to_f64(qty_tenths),
                symbol,
                super::tenths_to_f64(listing.quantity_step_tenths)
            ),
        ));
    }
    Ok(())
}
