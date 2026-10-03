//! Deterministic admission limits. Historical positions and listings retain
//! their meaning; capacity never expires accounting history.

use super::pipeline::{IncomingOrder, Rejected};
use super::{Book, Position};
use crate::domain::{AccountId, Side};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const RESOURCE_LIMITS_EXTENSION: &str = "resource-limits-v1";

/// Counts make admission independent of allocator and platform details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub max_active_orders: u64,
    pub max_positions: u64,
    /// Includes delisted symbols, which retain their historical identity.
    pub max_symbols: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{OrderMessage, OrderType, TimeInForce};
    use crate::logchain;
    use crate::matcher::MatcherState;

    fn limits(orders: u64, positions: u64) -> ResourceLimits {
        ResourceLimits {
            max_active_orders: orders,
            max_positions: positions,
            max_symbols: 8,
        }
    }

    fn new(id: u64, account: AccountId, side: Side, qty: f64) -> OrderMessage {
        OrderMessage::New {
            id,
            timestamp: id,
            account,
            symbol: "BTC-USDC".to_string(),
            side,
            price: 100.0,
            quantity: qty,
            nonce: None,
            order_type: OrderType::Limit,
            time_in_force: TimeInForce::GoodTillCancel,
            post_only: false,
        }
    }

    fn engine(limits: ResourceLimits) -> MatcherState {
        MatcherState::new()
            .with_resource_limits(limits)
            .unwrap()
            .with_symbols_listed(&["BTC-USDC"])
    }

    #[test]
    fn active_capacity_refuses_without_fills_and_cancel_recovers_capacity() {
        let mut engine = engine(limits(1, 4));
        engine.apply_message(&new(1, 3, Side::Sell, 1.0)).unwrap();
        engine.apply_message(&new(2, 4, Side::Buy, 1.0)).unwrap();
        assert_eq!(engine.orders_ignored_by_kind()["active_order_capacity"], 1);
        assert_eq!(engine.trades_total(), 0);
        assert!(engine.positions.is_empty());
        assert_eq!(engine.open_order(1).unwrap().3, 10);
        assert!(engine.open_order(2).is_none());
        assert_eq!(engine.next_expected_id(), 3);
        engine
            .apply_message(&OrderMessage::Cancel {
                id: 3,
                timestamp: 3,
                account: 3,
                target_id: 1,
                nonce: None,
            })
            .unwrap();
        engine.apply_message(&new(4, 4, Side::Sell, 1.0)).unwrap();
        assert!(engine.open_order(4).is_some());
    }

    #[test]
    fn all_position_slots_are_checked_before_any_fill() {
        let mut engine = engine(limits(8, 2));
        engine.apply_message(&new(1, 3, Side::Sell, 1.0)).unwrap();
        engine.apply_message(&new(2, 5, Side::Sell, 1.0)).unwrap();
        engine.apply_message(&new(3, 4, Side::Buy, 2.0)).unwrap();
        assert_eq!(engine.orders_ignored_by_kind()["position_capacity"], 1);
        assert_eq!(engine.trades_total(), 0);
        assert!(engine.positions.is_empty());
        assert_eq!(engine.open_order(1).unwrap().3, 10);
        assert_eq!(engine.open_order(2).unwrap().3, 10);
        assert!(engine.open_order(3).is_none());
    }

    #[test]
    fn repeated_accounts_use_one_slot_and_closed_history_is_preserved() {
        let mut engine = engine(limits(8, 2));
        engine.apply_message(&new(1, 3, Side::Sell, 1.0)).unwrap();
        engine.apply_message(&new(2, 3, Side::Sell, 1.0)).unwrap();
        engine.apply_message(&new(3, 4, Side::Buy, 2.0)).unwrap();
        assert_eq!(engine.trades_total(), 2);
        assert_eq!(engine.positions.len(), 2);
        engine.apply_message(&new(4, 3, Side::Buy, 2.0)).unwrap();
        engine.apply_message(&new(5, 4, Side::Sell, 2.0)).unwrap();
        assert_eq!(engine.positions.len(), 2);
        assert!(engine.positions.values().all(|p| p.net_qty_tenths == 0));
        engine.apply_message(&new(6, 5, Side::Sell, 1.0)).unwrap();
        let before = engine.trades_total();
        engine.apply_message(&new(7, 6, Side::Buy, 1.0)).unwrap();
        assert_eq!(engine.trades_total(), before);
        assert_eq!(engine.positions.len(), 2);
        assert!(engine.open_order(6).is_some());
    }

    #[test]
    fn configuration_has_distinct_snapshot_and_cannot_change_after_execution() {
        assert_ne!(
            engine(limits(8, 2)).resource_limits_snapshot(),
            engine(limits(9, 2)).resource_limits_snapshot()
        );
        let mut executed = engine(limits(8, 2));
        executed.apply_message(&new(1, 3, Side::Sell, 1.0)).unwrap();
        assert!(executed.with_resource_limits(limits(9, 2)).is_err());
        assert!(
            MatcherState::new()
                .with_resource_limits(limits(0, 2))
                .is_err()
        );
    }

    #[test]
    fn restored_policy_has_the_same_admission_behavior_and_rejects_unknown_versions() {
        let mut continuous = engine(limits(2, 2));
        let bytes = continuous.resource_limits_snapshot().unwrap();
        assert_eq!(
            ResourceLimits::from_snapshot_bytes(&bytes).unwrap(),
            limits(2, 2)
        );
        let mut restored = MatcherState::new();
        restored.restore_resource_limits(Some(&bytes)).unwrap();
        restored = restored.with_symbols_listed(&["BTC-USDC"]);
        for msg in [
            new(1, 3, Side::Sell, 1.0),
            new(2, 5, Side::Sell, 1.0),
            new(3, 4, Side::Buy, 2.0),
        ] {
            continuous.apply_message(&msg).unwrap();
            restored.apply_message(&msg).unwrap();
        }
        assert_eq!(
            continuous.orders_ignored_by_kind(),
            restored.orders_ignored_by_kind()
        );
        assert_eq!(continuous.trades_total(), restored.trades_total());
        assert_eq!(continuous.open_order(1), restored.open_order(1));
        assert!(restored.validate_resource_capacity().is_ok());
        assert!(restored.restore_resource_limits(Some(&bytes)).is_err());
        let mut unknown = bytes.clone();
        unknown[..4].copy_from_slice(&2u32.to_le_bytes());
        let mut fresh = MatcherState::new();
        assert!(
            fresh
                .restore_resource_limits(Some(&unknown))
                .unwrap_err()
                .contains("version 2")
        );
        assert!(fresh.resource_limits().is_none());
        assert!(fresh.restore_resource_limits(Some(&bytes[..27])).is_err());
        let mut zero = bytes;
        zero[4..12].fill(0);
        assert!(fresh.restore_resource_limits(Some(&zero)).is_err());
    }

    #[test]
    fn restored_entities_are_checked_without_truncation() {
        let mut loaded = engine(limits(1, 2));
        // Simulate reconstructed snapshot entities, including a retained
        // historical listing that exceeds the committed symbol cap.
        loaded.resource_limits = Some(ResourceLimits {
            max_symbols: 1,
            ..limits(1, 2)
        });
        loaded = loaded.with_symbols_listed(&["OTHER"]);
        assert!(loaded.validate_resource_capacity().is_err());
        assert!(loaded.is_listed("BTC-USDC"));
        assert!(loaded.is_listed("OTHER"));
    }

    #[test]
    fn self_match_and_a_quantity_cutoff_count_only_reachable_position_slots() {
        let mut self_match = engine(limits(3, 1));
        self_match
            .apply_message(&new(1, 3, Side::Sell, 1.0))
            .unwrap();
        self_match
            .apply_message(&new(2, 3, Side::Buy, 1.0))
            .unwrap();
        assert_eq!(self_match.trades_total(), 1);
        assert_eq!(self_match.positions.len(), 1);
        let mut cutoff = engine(limits(3, 2));
        cutoff.apply_message(&new(1, 3, Side::Sell, 1.0)).unwrap();
        cutoff.apply_message(&new(2, 5, Side::Sell, 1.0)).unwrap();
        cutoff.apply_message(&new(3, 4, Side::Buy, 1.0)).unwrap();
        assert_eq!(cutoff.trades_total(), 1);
        assert_eq!(cutoff.positions.len(), 2);
        assert_eq!(cutoff.open_order(2).unwrap().3, 10);
    }

    #[test]
    fn symbol_capacity_keeps_delisted_identity_and_allows_relisting_it() {
        let mut engine = MatcherState::new()
            .with_resource_limits(ResourceLimits {
                max_symbols: 1,
                ..limits(3, 2)
            })
            .unwrap();
        let key = logchain::ephemeral_key();
        for (id, symbol, delist) in [
            (1, "X", false),
            (2, "X", true),
            (3, "Y", false),
            (4, "X", false),
        ] {
            let msg = if delist {
                OrderMessage::DelistSymbol {
                    id,
                    timestamp: id,
                    account: crate::domain::OPERATOR_ACCOUNT,
                    symbol: symbol.into(),
                    nonce: Some(format!("{id:032x}")),
                    public_key: String::new(),
                    signature: String::new(),
                }
            } else {
                OrderMessage::ListSymbol {
                    id,
                    timestamp: id,
                    account: crate::domain::OPERATOR_ACCOUNT,
                    symbol: symbol.into(),
                    price_step: 0.01,
                    quantity_step: 0.1,
                    nonce: Some(format!("{id:032x}")),
                    public_key: String::new(),
                    signature: String::new(),
                }
            };
            engine
                .apply_message(&crate::operator::signed_as(&key, "", msg))
                .unwrap();
        }
        assert!(engine.is_listed("X"));
        assert!(!engine.is_listed("Y"));
        assert_eq!(engine.symbols.symbols.len(), 1);
        assert_eq!(engine.listings_ignored(), 1);
        assert!(engine.validate_resource_capacity().is_ok());
    }

    #[test]
    fn batch_capture_releases_temporary_changes_and_preserves_durable_changes() {
        for recording in [false, true] {
            let mut engine = MatcherState::with_default_listings();
            if recording {
                engine.pending = Some(Vec::new());
            }
            engine.apply_message(&new(1, 3, Side::Sell, 1.0)).unwrap();
            let queued = engine.pending.as_ref().map_or(0, Vec::len);
            let trades = engine
                .apply_message_with_trades(&new(2, 4, Side::Buy, 1.0))
                .unwrap();
            assert_eq!(trades.len(), 1);
            assert_eq!(trades[0].maker_order, 1);
            assert_eq!(trades[0].price_cents, 10000);
            assert_eq!(trades[0].qty_tenths, 10);
            if recording {
                assert!(engine.pending.as_ref().unwrap().len() > queued);
                assert!(
                    engine
                        .pending
                        .as_ref()
                        .unwrap()
                        .iter()
                        .any(|change| matches!(change, crate::store::Change::Traded(_)))
                );
            } else {
                assert!(engine.pending.is_none());
            }
            let queued = engine.pending.as_ref().map_or(0, Vec::len);
            assert!(
                engine
                    .apply_message_with_trades(&new(2, 4, Side::Buy, 1.0))
                    .is_err()
            );
            assert_eq!(engine.pending.as_ref().map_or(0, Vec::len), queued);
            assert_eq!(engine.pending.is_some(), recording);
        }
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_active_orders: 100_000,
            max_positions: 100_000,
            max_symbols: 4096,
        }
    }
}

impl ResourceLimits {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_active_orders == 0 || self.max_positions == 0 || self.max_symbols == 0 {
            return Err("resource limits must be positive".to_string());
        }
        Ok(())
    }

    /// Canonical configuration for the versioned state root and snapshot.
    pub fn canonical_bytes(&self) -> [u8; 24] {
        let mut bytes = [0; 24];
        bytes[..8].copy_from_slice(&self.max_active_orders.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.max_positions.to_le_bytes());
        bytes[16..].copy_from_slice(&self.max_symbols.to_le_bytes());
        bytes
    }

    /// u32 LE version 1, then three u64 LE capacities in canonical order.
    pub fn snapshot_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(28);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&self.canonical_bytes());
        bytes
    }

    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 28 {
            return Err("resource limits snapshot must contain exactly 28 bytes".to_string());
        }
        let version = u32::from_le_bytes(bytes[..4].try_into().expect("checked length"));
        if version != 1 {
            return Err(format!(
                "unsupported resource limits snapshot version {version}"
            ));
        }
        let limits = Self {
            max_active_orders: u64::from_le_bytes(bytes[4..12].try_into().expect("checked length")),
            max_positions: u64::from_le_bytes(bytes[12..20].try_into().expect("checked length")),
            max_symbols: u64::from_le_bytes(bytes[20..28].try_into().expect("checked length")),
        };
        limits.validate()?;
        Ok(limits)
    }

    pub(super) fn check_positions(
        &self,
        order: &IncomingOrder,
        book: &Book,
        positions: &HashMap<(AccountId, String), Position>,
    ) -> Result<(), Rejected> {
        // Preflight the whole command. Repeated maker accounts and self-match
        // each use a single slot. Stop allocating as soon as capacity fails.
        let mut added = HashSet::new();
        let mut remaining = order.qty_tenths;
        let mut check_level = |level: &std::collections::VecDeque<super::RestingOrder>| {
            for maker in level {
                if remaining == 0 {
                    break;
                }
                for account in [order.account, maker.account] {
                    if !positions.contains_key(&(account, order.symbol.clone())) {
                        added.insert(account);
                        if positions.len() as u64 + added.len() as u64 > self.max_positions {
                            return Err(Rejected::because(
                                "position_capacity",
                                format!(
                                    "position capacity {} would be exceeded",
                                    self.max_positions
                                ),
                            ));
                        }
                    }
                }
                remaining -= remaining.min(maker.qty_tenths);
            }
            Ok(())
        };
        match order.side {
            Side::Buy => {
                for (_, level) in book.asks.range(..=order.limit_cents) {
                    check_level(level)?;
                }
            }
            Side::Sell => {
                for (_, level) in book.bids.range(order.limit_cents..).rev() {
                    check_level(level)?;
                }
            }
        }
        Ok(())
    }
}
