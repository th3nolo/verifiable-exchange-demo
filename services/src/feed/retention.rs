//! Required replay-protection history is bounded by refusing new admission,
//! never by evicting a spent nonce or an account key.

use super::{FeedState, InboxKey, Storage, nonce_key};
use crate::domain::OrderMessage;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Operational intake budgets. They affect which submissions can become new
/// messages, not how already sequenced messages execute. Disk history remains
/// intact when a budget is exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionLimits {
    pub max_nonces: u64,
    pub max_accounts: u64,
    pub max_inbox_records: u64,
    /// RAM-only Merkle history cannot be evicted without losing proofs.
    pub max_memory_messages: u64,
    pub max_batch_messages: u64,
    pub max_retry_records: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{OrderMessage, Side};
    use crate::logchain;

    fn limits() -> RetentionLimits {
        RetentionLimits {
            max_nonces: 2,
            max_accounts: 2,
            max_inbox_records: 2,
            max_memory_messages: 100,
            max_batch_messages: 8,
            max_retry_records: 4,
        }
    }

    fn order(id: u64, nonce: Option<u64>) -> OrderMessage {
        OrderMessage::New {
            id,
            timestamp: id,
            account: 1,
            symbol: "BTC-USDC".into(),
            side: Side::Buy,
            price: 100.0,
            quantity: 1.0,
            nonce: nonce.map(|n| format!("{n:032x}")),
            order_type: Default::default(),
            time_in_force: Default::default(),
            post_only: false,
        }
    }

    #[test]
    fn exhausting_nonce_capacity_keeps_spent_nonces_and_published_state() {
        let mut state = FeedState::new(4, 0)
            .with_retention_limits(limits())
            .unwrap();
        state.publish(order(1, Some(1))).unwrap();
        state.publish(order(2, Some(2))).unwrap();
        let chain = state.chain;
        let root = state.signed_tree_head().unwrap().root_hash;
        let next = state.next_id;
        assert!(
            state
                .publish(order(3, Some(3)))
                .unwrap_err()
                .contains("nonce capacity")
        );
        assert!(
            state
                .publish(order(3, Some(1)))
                .unwrap_err()
                .contains("nonce already spent")
        );
        assert_eq!(state.nonces.len(), 2);
        assert_eq!(state.last_id(), 2);
        assert_eq!(state.next_id, next);
        assert_eq!(state.chain, chain);
        assert_eq!(state.signed_tree_head().unwrap().root_hash, root);
        assert_eq!(state.check_retention_growth(1, 1, 0).is_err(), true);
    }

    #[test]
    fn capacity_applies_to_all_new_nonces_in_one_batch_without_partial_publish() {
        let mut state = FeedState::new(4, 0)
            .with_retention_limits(limits())
            .unwrap();
        state.publish(order(1, Some(1))).unwrap();
        let chain = state.chain;
        assert!(
            state
                .publish_batch(vec![order(2, Some(2)), order(3, Some(3))])
                .is_err()
        );
        assert_eq!(state.last_id(), 1);
        assert_eq!(state.chain, chain);
        assert_eq!(state.nonces.len(), 1);
        assert!(
            state
                .publish_batch(vec![order(2, Some(2)), order(3, Some(2))])
                .is_err()
        );
        assert_eq!(state.nonces.len(), 1);
    }

    #[test]
    fn account_capacity_never_evicts_a_pinned_key() {
        let mut state = FeedState::new(4, 0)
            .with_retention_limits(limits())
            .unwrap();
        let first = logchain::ephemeral_key().verifying_key();
        let second = logchain::ephemeral_key().verifying_key();
        let third = logchain::ephemeral_key().verifying_key();
        state.pin_or_check_account(10, &first).unwrap();
        state.pin_or_check_account(11, &second).unwrap();
        assert!(state.pin_or_check_account(12, &third).is_err());
        state.pin_or_check_account(10, &first).unwrap();
        assert!(state.pin_or_check_account(10, &third).is_err());
        assert_eq!(state.accounts.len(), 2);
        assert_eq!(state.accounts[&10], first);
    }

    #[test]
    fn ram_proof_history_and_inbox_pairings_stop_at_capacity_without_eviction() {
        let mut state = FeedState::new(4, 0)
            .with_retention_limits(RetentionLimits {
                max_memory_messages: 2,
                ..limits()
            })
            .unwrap();
        for id in 1..=2 {
            state
                .sequence(vec![(
                    Some(("epoch".into(), id as i64)),
                    order(id, Some(id)),
                )])
                .unwrap();
        }
        assert!(
            state
                .sequence(vec![(Some(("epoch".into(), 3)), order(3, None))])
                .is_err()
        );
        assert_eq!(state.inbox_sequenced.len(), 2);
        assert_eq!(state.storage.leaves(), 2);
        assert_eq!(state.inbox_sequenced[&("epoch".to_string(), 1)], 1);
        assert!(state.inclusion_proof(0, 2).is_ok());
        assert!(state.check_retention_growth(1, 0, 0).is_err());
    }

    #[test]
    fn restart_retains_nonce_protection_and_refuses_over_capacity_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("feed.db");
        let key = logchain::ephemeral_key();
        {
            let mut state =
                FeedState::with_db_and_retention_limits(4, &path, key.clone(), 0, limits())
                    .unwrap();
            state.publish(order(1, Some(1))).unwrap();
            state.publish(order(2, Some(2))).unwrap();
        }
        let mut restored =
            FeedState::with_db_and_retention_limits(4, &path, key.clone(), 0, limits()).unwrap();
        assert!(restored.publish(order(3, Some(1))).is_err());
        assert_eq!(restored.nonces.len(), 2);
        drop(restored);
        assert!(
            FeedState::with_db_and_retention_limits(
                4,
                &path,
                key.clone(),
                0,
                RetentionLimits {
                    max_nonces: 1,
                    ..limits()
                }
            )
            .is_err()
        );
        let mut increased = FeedState::with_db_and_retention_limits(
            4,
            &path,
            key,
            0,
            RetentionLimits {
                max_nonces: 3,
                ..limits()
            },
        )
        .unwrap();
        assert!(increased.publish(order(3, Some(1))).is_err());
        increased.publish(order(3, Some(3))).unwrap();
        assert_eq!(increased.nonces.len(), 3);
    }
}

impl Default for RetentionLimits {
    fn default() -> Self {
        Self {
            max_nonces: 1_000_000,
            max_accounts: 100_000,
            max_inbox_records: 1_000_000,
            max_memory_messages: 1_000_000,
            max_batch_messages: 100_000,
            max_retry_records: 4096,
        }
    }
}

impl RetentionLimits {
    pub fn validate(&self) -> Result<(), String> {
        if [
            self.max_nonces,
            self.max_accounts,
            self.max_inbox_records,
            self.max_memory_messages,
            self.max_batch_messages,
            self.max_retry_records,
        ]
        .contains(&0)
        {
            return Err("feed retention limits must be positive".to_string());
        }
        Ok(())
    }
}

impl FeedState {
    pub fn with_retention_limits(mut self, limits: RetentionLimits) -> Result<Self, String> {
        limits.validate()?;
        if self.nonces.len() as u64 > limits.max_nonces
            || self.accounts.len() as u64 > limits.max_accounts
            || self.inbox_sequenced.len() as u64 > limits.max_inbox_records
            || (matches!(self.storage, Storage::Memory(_))
                && self.last_id() > limits.max_memory_messages)
        {
            return Err(
                "existing feed state exceeds retention limits; no history was removed".to_string(),
            );
        }
        self.retention_limits = limits;
        Ok(self)
    }

    pub fn retention_limits(&self) -> RetentionLimits {
        self.retention_limits
    }

    /// Check a whole pending burst before allocating ids or changing generator
    /// state. Counts include earlier new entries waiting in the same batch.
    pub(super) fn check_retention_growth(
        &self,
        messages: u64,
        nonces: u64,
        inbox: u64,
    ) -> Result<(), String> {
        let limits = self.retention_limits;
        if messages > limits.max_batch_messages {
            return Err(format!(
                "batch capacity {} exceeded",
                limits.max_batch_messages
            ));
        }
        if matches!(self.storage, Storage::Memory(_))
            && messages
                > limits
                    .max_memory_messages
                    .saturating_sub(self.storage.leaves())
        {
            return Err(format!(
                "RAM history capacity {} exhausted; proofs are retained",
                limits.max_memory_messages
            ));
        }
        if nonces > limits.max_nonces.saturating_sub(self.nonces.len() as u64) {
            return Err(format!(
                "nonce capacity {} exhausted; spent nonces are retained",
                limits.max_nonces
            ));
        }
        if inbox
            > limits
                .max_inbox_records
                .saturating_sub(self.inbox_sequenced.len() as u64)
        {
            return Err(format!(
                "inbox record capacity {} exhausted; pairings are retained",
                limits.max_inbox_records
            ));
        }
        Ok(())
    }

    pub(super) fn check_retention_batch(
        &self,
        batch: &[(Option<InboxKey>, OrderMessage)],
    ) -> Result<(), String> {
        let limits = self.retention_limits;
        if batch.len() as u64 > limits.max_batch_messages {
            return Err(format!(
                "batch capacity {} exceeded",
                limits.max_batch_messages
            ));
        }
        if matches!(self.storage, Storage::Memory(_))
            && batch.len() as u64
                > limits
                    .max_memory_messages
                    .saturating_sub(self.storage.leaves())
        {
            return Err(format!(
                "RAM history capacity {} exhausted; published proofs are retained",
                limits.max_memory_messages
            ));
        }
        let mut nonces = HashSet::new();
        let mut inbox = HashSet::new();
        for (key, msg) in batch {
            if let Some(nonce) = nonce_key(msg) {
                if self.nonces.contains_key(&nonce) || !nonces.insert(nonce) {
                    return Err("nonce already spent; no batch messages were published".to_string());
                }
                if nonces.len() as u64 > limits.max_nonces.saturating_sub(self.nonces.len() as u64)
                {
                    return Err(format!(
                        "nonce capacity {} exhausted; spent nonces are retained",
                        limits.max_nonces
                    ));
                }
            }
            if let Some(key) = key {
                if self.inbox_sequenced.contains_key(key) || !inbox.insert(key) {
                    return Err("inbox entry already sequenced".to_string());
                }
                if inbox.len() as u64
                    > limits
                        .max_inbox_records
                        .saturating_sub(self.inbox_sequenced.len() as u64)
                {
                    return Err(format!(
                        "inbox record capacity {} exhausted; prior pairings are retained",
                        limits.max_inbox_records
                    ));
                }
            }
        }
        Ok(())
    }
}
