//! Funded-mode preflight hook. The matching owner can fold this into its full
//! plan: both positions and ledger must accept every fill before any effect.
use super::{Book, IncomingOrder, Position, Rejected};
use crate::domain::{AccountId, Side};
use crate::ledger::Ledger;
use std::collections::HashMap;

pub(super) fn preflight(
    order: &IncomingOrder,
    book: &Book,
    positions: &HashMap<(AccountId, String), Position>,
    ledger: &Ledger,
    trades_total: u64,
) -> Result<(), Rejected> {
    if !ledger.is_funded() {
        return Ok(());
    }
    let mut staged = ledger.clone();
    staged
        .reserve(
            order.id,
            order.account,
            &order.symbol,
            order.side,
            order.limit_cents,
            order.qty_tenths,
        )
        .map_err(|e| Rejected::because("insufficient_funds", e.to_string()))?;
    let mut projected: HashMap<(AccountId, String), Position> = HashMap::new();
    let mut remaining = order.qty_tenths;
    let mut next_trade = trades_total;
    let levels: Box<dyn Iterator<Item = (&i64, &std::collections::VecDeque<super::RestingOrder>)>> =
        match order.side {
            Side::Buy => Box::new(book.asks.iter()),
            Side::Sell => Box::new(book.bids.iter().rev()),
        };
    for (&price, level) in levels {
        if remaining == 0
            || match order.side {
                Side::Buy => price > order.limit_cents,
                Side::Sell => price < order.limit_cents,
            }
        {
            break;
        }
        for maker in level {
            next_trade = next_trade.checked_add(1).ok_or_else(|| {
                Rejected::because(
                    "position_overflow",
                    "funded command plan would overflow trade IDs",
                )
            })?;
            let fill = remaining.min(maker.qty_tenths);
            let maker_side = match order.side {
                Side::Buy => Side::Sell,
                Side::Sell => Side::Buy,
            };
            for (account, side) in [(maker.account, maker_side), (order.account, order.side)] {
                let key = (account, order.symbol.clone());
                let before = projected
                    .get(&key)
                    .or_else(|| positions.get(&key))
                    .copied()
                    .unwrap_or_default();
                let after = before.after_fill(side, fill, price).ok_or_else(|| {
                    Rejected::because(
                        "position_overflow",
                        "funded command plan would overflow a position",
                    )
                })?;
                projected.insert(key, after);
            }
            staged
                .settle_fill(maker.id, order.id, price, fill)
                .map_err(|e| Rejected::because("funds_overflow", e.to_string()))?;
            remaining -= fill;
            if remaining == 0 {
                break;
            }
        }
    }
    if order.time_in_force == crate::domain::TimeInForce::FillOrKill && remaining != 0 {
        return Err(Rejected::because(
            "fok_unfilled",
            "complete funded FOK plan is unavailable",
        ));
    }
    Ok(())
}
