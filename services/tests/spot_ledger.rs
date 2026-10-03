//! Regression gates for financed simulation; no RPC, custody or real funds.
use ed25519_dalek::SigningKey;
use services::domain::{AccountId, OPERATOR_ACCOUNT, OrderMessage, OrderType, Side, TimeInForce};
use services::ledger::{Balance, Funding, FundingConfig, Ledger, LedgerMode, MarketAssets};
use services::matcher::MatcherState;
use services::operator;

fn config(funding: &[(AccountId, &str, i64)]) -> FundingConfig {
    FundingConfig {
        markets: vec![
            MarketAssets {
                symbol: "ETH-USDC".into(),
                base_asset: "ETH".into(),
                quote_asset: "USDC".into(),
            },
            MarketAssets {
                symbol: "BTC-USDC".into(),
                base_asset: "BTC".into(),
                quote_asset: "USDC".into(),
            },
            MarketAssets {
                symbol: "ETH-DAI".into(),
                base_asset: "ETH".into(),
                quote_asset: "DAI".into(),
            },
        ],
        funding: funding
            .iter()
            .map(|(account, asset, units)| Funding {
                account: *account,
                asset: (*asset).into(),
                units: *units,
            })
            .collect(),
        fee_units: 0,
    }
}
fn list(id: u64, symbol: &str) -> OrderMessage {
    operator::signed_as(
        &SigningKey::from_bytes(&[3; 32]),
        "",
        OrderMessage::ListSymbol {
            id,
            timestamp: id * 1000,
            account: OPERATOR_ACCOUNT,
            symbol: symbol.into(),
            price_step: 0.01,
            quantity_step: 0.1,
            nonce: Some(format!("{id:032x}")),
            public_key: String::new(),
            signature: String::new(),
        },
    )
}
fn delist(id: u64, symbol: &str) -> OrderMessage {
    operator::signed_as(
        &SigningKey::from_bytes(&[3; 32]),
        "",
        OrderMessage::DelistSymbol {
            id,
            timestamp: id * 1000,
            account: OPERATOR_ACCOUNT,
            symbol: symbol.into(),
            nonce: Some(format!("{id:032x}")),
            public_key: String::new(),
            signature: String::new(),
        },
    )
}
fn order(
    id: u64,
    account: AccountId,
    symbol: &str,
    side: Side,
    price: f64,
    qty: f64,
    tif: TimeInForce,
) -> OrderMessage {
    OrderMessage::New {
        id,
        timestamp: id * 1000,
        account,
        symbol: symbol.into(),
        side,
        price,
        quantity: qty,
        nonce: None,
        order_type: OrderType::Limit,
        time_in_force: tif,
        post_only: false,
    }
}
fn cancel(id: u64, account: AccountId, target_id: u64) -> OrderMessage {
    OrderMessage::Cancel {
        id,
        timestamp: id * 1000,
        account,
        target_id,
        nonce: None,
    }
}
fn funded(grants: &[(AccountId, &str, i64)]) -> MatcherState {
    let mut state = MatcherState::funded_simulation(config(grants)).unwrap();
    state.apply_message(&list(1, "ETH-USDC")).unwrap();
    state
}
fn balance(state: &MatcherState, account: AccountId, asset: &str) -> Balance {
    Ledger::from_snapshot(state.ledger_snapshot())
        .unwrap()
        .balance(account, asset)
}
const GTC: TimeInForce = TimeInForce::GoodTillCancel;

#[test]
fn insufficient_quote_rejects_before_any_match_or_reservation() {
    let mut state = funded(&[(1, "USDC", 999), (2, "ETH", 100)]);
    state
        .apply_message(&order(2, 2, "ETH-USDC", Side::Sell, 10.0, 0.1, GTC))
        .unwrap();
    let before = state.ledger_snapshot();
    state
        .apply_message(&order(3, 1, "ETH-USDC", Side::Buy, 10.0, 0.1, GTC))
        .unwrap();
    assert_eq!(state.level_qty_tenths("ETH-USDC", Side::Sell, 1000), 1);
    assert_eq!(state.ledger_snapshot().balances, before.balances);
    assert_eq!(state.ledger_snapshot().reservations, before.reservations);
    assert_eq!(state.ledger_snapshot().last_sequence, 3);
    assert_eq!(state.trades_total(), 0);
    assert_eq!(state.position_of(1, "ETH-USDC"), (0, 0, 0));
    assert_eq!(
        state.orders_ignored_by_kind().get("insufficient_funds"),
        Some(&1)
    );
}

#[test]
fn insufficient_base_rejects_before_matching_a_funded_bid() {
    let mut state = funded(&[(1, "USDC", 1000), (2, "ETH", 99)]);
    state
        .apply_message(&order(2, 1, "ETH-USDC", Side::Buy, 10.0, 0.1, GTC))
        .unwrap();
    let before = state.ledger_snapshot();
    state
        .apply_message(&order(3, 2, "ETH-USDC", Side::Sell, 10.0, 0.1, GTC))
        .unwrap();
    assert_eq!(state.level_qty_tenths("ETH-USDC", Side::Buy, 1000), 1);
    assert_eq!(state.ledger_snapshot().balances, before.balances);
    assert_eq!(state.ledger_snapshot().reservations, before.reservations);
}

#[test]
fn two_symbols_compete_for_the_same_quote_balance() {
    let mut state = funded(&[(1, "USDC", 1000)]);
    state.apply_message(&list(2, "BTC-USDC")).unwrap();
    state
        .apply_message(&order(3, 1, "ETH-USDC", Side::Buy, 10.0, 0.1, GTC))
        .unwrap();
    state
        .apply_message(&order(4, 1, "BTC-USDC", Side::Buy, 10.0, 0.1, GTC))
        .unwrap();
    assert_eq!(
        balance(&state, 1, "USDC"),
        Balance {
            available: 0,
            reserved: 1000
        }
    );
    assert_eq!(state.best_bid_cents("BTC-USDC"), None);
    assert_eq!(state.ledger_snapshot().reservations.len(), 1);
}

#[test]
fn base_asset_is_shared_between_markets_with_different_quotes() {
    let mut state = funded(&[(1, "ETH", 100)]);
    state.apply_message(&list(2, "ETH-DAI")).unwrap();
    state
        .apply_message(&order(3, 1, "ETH-USDC", Side::Sell, 10.0, 0.1, GTC))
        .unwrap();
    state
        .apply_message(&order(4, 1, "ETH-DAI", Side::Sell, 10.0, 0.1, GTC))
        .unwrap();
    assert_eq!(
        balance(&state, 1, "ETH"),
        Balance {
            available: 0,
            reserved: 100
        }
    );
    assert_eq!(state.best_ask_cents("ETH-DAI"), None);
}

#[test]
fn partial_fill_releases_improvement_and_owner_cancel_releases_only_remainder() {
    let mut state = funded(&[(1, "USDC", 4000), (2, "ETH", 100)]);
    state
        .apply_message(&order(2, 2, "ETH-USDC", Side::Sell, 10.0, 0.1, GTC))
        .unwrap();
    state
        .apply_message(&order(3, 1, "ETH-USDC", Side::Buy, 12.0, 0.3, GTC))
        .unwrap();
    assert_eq!(
        balance(&state, 1, "USDC"),
        Balance {
            available: 600,
            reserved: 2400
        }
    );
    assert_eq!(
        balance(&state, 1, "ETH"),
        Balance {
            available: 100,
            reserved: 0
        }
    );
    assert_eq!(
        balance(&state, 2, "USDC"),
        Balance {
            available: 1000,
            reserved: 0
        }
    );
    assert_eq!(state.ledger_snapshot().reservations[0].remaining_tenths, 2);
    let before = state.ledger_snapshot();
    state.apply_message(&cancel(4, 2, 3)).unwrap();
    assert_eq!(state.ledger_snapshot().balances, before.balances);
    state.apply_message(&cancel(5, 1, 3)).unwrap();
    assert_eq!(
        balance(&state, 1, "USDC"),
        Balance {
            available: 3000,
            reserved: 0
        }
    );
    let released = state.ledger_snapshot();
    state.apply_message(&cancel(6, 1, 3)).unwrap();
    assert_eq!(state.ledger_snapshot().balances, released.balances);
    assert!(state.ledger_snapshot().reservations.is_empty());
}

#[test]
fn ioc_releases_unfilled_quote_without_new_funding() {
    let mut state = funded(&[(1, "USDC", 4000), (2, "ETH", 100)]);
    state
        .apply_message(&order(2, 2, "ETH-USDC", Side::Sell, 10.0, 0.1, GTC))
        .unwrap();
    state
        .apply_message(&order(
            3,
            1,
            "ETH-USDC",
            Side::Buy,
            12.0,
            0.3,
            TimeInForce::ImmediateOrCancel,
        ))
        .unwrap();
    assert_eq!(
        balance(&state, 1, "USDC"),
        Balance {
            available: 3000,
            reserved: 0
        }
    );
    assert_eq!(
        balance(&state, 1, "ETH"),
        Balance {
            available: 100,
            reserved: 0
        }
    );
    assert!(state.ledger_snapshot().reservations.is_empty());
    assert_eq!(state.best_bid_cents("ETH-USDC"), None);
}

#[test]
fn maker_buy_retains_only_its_remaining_obligation() {
    let mut state = funded(&[(1, "USDC", 4000), (2, "ETH", 100)]);
    state
        .apply_message(&order(2, 1, "ETH-USDC", Side::Buy, 12.0, 0.3, GTC))
        .unwrap();
    state
        .apply_message(&order(3, 2, "ETH-USDC", Side::Sell, 10.0, 0.1, GTC))
        .unwrap();
    assert_eq!(
        balance(&state, 1, "USDC"),
        Balance {
            available: 400,
            reserved: 2400
        }
    );
    assert_eq!(
        balance(&state, 2, "USDC"),
        Balance {
            available: 1200,
            reserved: 0
        }
    );
    state.apply_message(&cancel(4, 1, 2)).unwrap();
    assert_eq!(
        balance(&state, 1, "USDC"),
        Balance {
            available: 2800,
            reserved: 0
        }
    );
}

#[test]
fn rejected_fok_and_replay_have_zero_asset_effects() {
    let mut state = funded(&[(1, "USDC", 4000), (2, "ETH", 100)]);
    state
        .apply_message(&order(2, 2, "ETH-USDC", Side::Sell, 10.0, 0.1, GTC))
        .unwrap();
    let before = state.ledger_snapshot();
    let request = order(
        3,
        1,
        "ETH-USDC",
        Side::Buy,
        10.0,
        0.2,
        TimeInForce::FillOrKill,
    );
    state.apply_message(&request).unwrap();
    assert_eq!(state.ledger_snapshot().balances, before.balances);
    assert_eq!(state.ledger_snapshot().reservations, before.reservations);
    let rejected = state.ledger_canonical_bytes();
    assert!(state.apply_message(&request).is_err());
    assert_eq!(state.ledger_canonical_bytes(), rejected);
}

#[test]
fn funded_second_fill_overflow_rolls_back_all_fok_and_ioc_effects() {
    for tif in [TimeInForce::FillOrKill, TimeInForce::ImmediateOrCancel] {
        let mut state = funded(&[
            (1, "USDC", 5000),
            (2, "ETH", 200),
            (2, "USDC", i64::MAX - 1500),
        ]);
        state
            .apply_message(&order(2, 2, "ETH-USDC", Side::Sell, 10.0, 0.1, GTC))
            .unwrap();
        state
            .apply_message(&order(3, 2, "ETH-USDC", Side::Sell, 10.0, 0.1, GTC))
            .unwrap();
        let before = state.ledger_snapshot();
        state
            .apply_message(&order(4, 1, "ETH-USDC", Side::Buy, 10.0, 0.2, tif))
            .unwrap();
        assert_eq!(state.level_qty_tenths("ETH-USDC", Side::Sell, 1000), 2);
        assert_eq!(state.trades_total(), 0);
        assert_eq!(state.position_of(1, "ETH-USDC"), (0, 0, 0));
        assert_eq!(state.ledger_snapshot().balances, before.balances);
        assert_eq!(state.ledger_snapshot().reservations, before.reservations);
        assert_eq!(
            state.orders_ignored_by_kind().get("funds_overflow"),
            Some(&1)
        );
    }
}

#[test]
fn funded_full_fok_applies_both_sides_of_every_maker() {
    let mut state = funded(&[(1, "USDC", 4000), (2, "ETH", 100), (3, "ETH", 100)]);
    state
        .apply_message(&order(2, 2, "ETH-USDC", Side::Sell, 10.0, 0.1, GTC))
        .unwrap();
    state
        .apply_message(&order(3, 3, "ETH-USDC", Side::Sell, 11.0, 0.1, GTC))
        .unwrap();
    state
        .apply_message(&order(
            4,
            1,
            "ETH-USDC",
            Side::Buy,
            11.0,
            0.2,
            TimeInForce::FillOrKill,
        ))
        .unwrap();
    assert_eq!(
        balance(&state, 1, "USDC"),
        Balance {
            available: 1900,
            reserved: 0
        }
    );
    assert_eq!(
        balance(&state, 1, "ETH"),
        Balance {
            available: 200,
            reserved: 0
        }
    );
    assert_eq!(balance(&state, 2, "USDC").available, 1000);
    assert_eq!(balance(&state, 3, "USDC").available, 1100);
    assert!(state.ledger_snapshot().reservations.is_empty());
}

#[test]
fn same_account_both_sides_is_conservative_and_does_not_overflow_intermediate_credit() {
    let mut ledger = Ledger::funded(config(&[(1, "ETH", 100), (1, "USDC", i64::MAX)])).unwrap();
    ledger
        .reserve(1, 1, "ETH-USDC", Side::Sell, 1000, 1)
        .unwrap();
    ledger.finish_sequence(1).unwrap();
    ledger
        .reserve(2, 1, "ETH-USDC", Side::Buy, 1200, 1)
        .unwrap();
    ledger.settle_fill(1, 2, 1000, 1).unwrap();
    assert_eq!(
        ledger.balance(1, "ETH"),
        Balance {
            available: 100,
            reserved: 0
        }
    );
    assert_eq!(
        ledger.balance(1, "USDC"),
        Balance {
            available: i64::MAX,
            reserved: 0
        }
    );
    ledger.validate().unwrap();
    // Rule set 1 also supports this path through the actual matcher.
    let mut state = funded(&[(1, "ETH", 100), (1, "USDC", 2000)]);
    state
        .apply_message(&order(2, 1, "ETH-USDC", Side::Sell, 10.0, 0.1, GTC))
        .unwrap();
    state
        .apply_message(&order(3, 1, "ETH-USDC", Side::Buy, 12.0, 0.1, GTC))
        .unwrap();
    assert_eq!(balance(&state, 1, "ETH").available, 100);
    assert_eq!(balance(&state, 1, "USDC").available, 2000);
    assert!(state.ledger_snapshot().reservations.is_empty());
}

#[test]
fn delist_releases_all_remnants_once_and_replay_matches_ledger() {
    let grants = [(1, "USDC", 5000), (2, "ETH", 300)];
    let history = [
        list(1, "ETH-USDC"),
        order(2, 2, "ETH-USDC", Side::Sell, 10.0, 0.3, GTC),
        order(3, 1, "ETH-USDC", Side::Buy, 10.0, 0.1, GTC),
        delist(4, "ETH-USDC"),
        cancel(5, 2, 2),
        list(6, "ETH-USDC"),
    ];
    let mut state = MatcherState::funded_simulation(config(&grants)).unwrap();
    for msg in &history {
        state.apply_message(msg).unwrap();
    }
    assert_eq!(
        balance(&state, 2, "ETH"),
        Balance {
            available: 200,
            reserved: 0
        }
    );
    assert_eq!(
        balance(&state, 1, "USDC"),
        Balance {
            available: 4000,
            reserved: 0
        }
    );
    assert!(state.ledger_snapshot().reservations.is_empty());
    let mut replay = MatcherState::funded_simulation(config(&grants)).unwrap();
    for msg in &history {
        replay.apply_message(msg).unwrap();
    }
    assert_eq!(
        state.ledger_canonical_bytes(),
        replay.ledger_canonical_bytes()
    );
}

#[test]
fn snapshot_roundtrip_continues_reserves_and_rejects_replayed_sequence() {
    let mut ledger = Ledger::funded(config(&[(1, "USDC", 4000), (2, "ETH", 300)])).unwrap();
    ledger
        .reserve(1, 2, "ETH-USDC", Side::Sell, 1000, 3)
        .unwrap();
    ledger.finish_sequence(1).unwrap();
    ledger
        .reserve(2, 1, "ETH-USDC", Side::Buy, 1200, 1)
        .unwrap();
    ledger.settle_fill(1, 2, 1000, 1).unwrap();
    ledger.finish_sequence(2).unwrap();
    let mut restored =
        Ledger::from_snapshot(serde_json::from_slice(&ledger.canonical_bytes()).unwrap()).unwrap();
    assert_eq!(restored.canonical_bytes(), ledger.canonical_bytes());
    assert!(
        restored
            .reserve(2, 1, "ETH-USDC", Side::Buy, 1000, 1)
            .is_err()
    );
    assert!(restored.finish_sequence(2).is_err());
    for current in [&mut restored, &mut ledger] {
        current
            .reserve(3, 1, "ETH-USDC", Side::Buy, 1000, 1)
            .unwrap();
        current.settle_fill(1, 3, 1000, 1).unwrap();
        current.finish_sequence(3).unwrap();
        assert!(current.release(1).unwrap());
        assert!(!current.release(1).unwrap());
        current.validate().unwrap();
    }
    assert_eq!(restored.canonical_bytes(), ledger.canonical_bytes());
}

#[test]
fn snapshot_refuses_missing_ghost_tampered_or_unbacked_obligations() {
    let mut ledger = Ledger::funded(config(&[(1, "USDC", 4000)])).unwrap();
    ledger
        .reserve(1, 1, "ETH-USDC", Side::Buy, 1000, 2)
        .unwrap();
    ledger.finish_sequence(1).unwrap();
    let good = ledger.snapshot();
    let mut bad = good.clone();
    bad.reservations.clear();
    assert!(Ledger::from_snapshot(bad).is_err());
    let mut bad = good.clone();
    bad.reservations[0].units -= 1;
    assert!(Ledger::from_snapshot(bad).is_err());
    let mut bad = good.clone();
    bad.balances[0].balance.available += 1;
    assert!(Ledger::from_snapshot(bad).is_err());
    let mut bad = good.clone();
    bad.reservations[0].account = 99;
    assert!(Ledger::from_snapshot(bad).is_err());
    assert!(ledger.validate_obligations(&[]).is_err());
    let mut row = services::store::OrderRow {
        order_id: 1,
        account: 1,
        symbol: "ETH-USDC".into(),
        side: Side::Buy,
        price_cents: 1000,
        qty_tenths: 2,
    };
    ledger.validate_obligations(&[row.clone()]).unwrap();
    row.qty_tenths = 1;
    assert!(ledger.validate_obligations(&[row]).is_err());
}

#[test]
fn funding_canonical_order_is_stable_and_duplicates_or_fees_are_refused() {
    let grants = [(1, "USDC", 4000), (2, "ETH", 300), (1, "DAI", 500)];
    let left = config(&grants);
    let mut right = left.clone();
    right.markets.reverse();
    right.funding.reverse();
    assert_eq!(
        Ledger::funded(left.clone()).unwrap().canonical_bytes(),
        Ledger::funded(right).unwrap().canonical_bytes()
    );
    let mut duplicate = left.clone();
    duplicate.funding.push(duplicate.funding[0].clone());
    assert!(Ledger::funded(duplicate).is_err());
    let mut fees = left.clone();
    fees.fee_units = 1;
    assert!(Ledger::funded(fees).is_err());
    let mut negative = left;
    negative.funding[0].units = -1;
    assert!(Ledger::funded(negative).is_err());
    assert_eq!(
        Ledger::synthetic_legacy().mode(),
        LedgerMode::SyntheticLegacy
    );
}

#[test]
fn immutable_complete_plan_accumulates_funds_and_preserves_source_on_failure() {
    let mut ledger = Ledger::funded(config(&[
        (1, "USDC", 5000),
        (2, "ETH", 200),
        (2, "USDC", i64::MAX - 1500),
    ]))
    .unwrap();
    ledger
        .reserve(1, 2, "ETH-USDC", Side::Sell, 1000, 1)
        .unwrap();
    ledger.finish_sequence(1).unwrap();
    ledger
        .reserve(2, 2, "ETH-USDC", Side::Sell, 1000, 1)
        .unwrap();
    ledger.finish_sequence(2).unwrap();
    ledger
        .reserve(3, 1, "ETH-USDC", Side::Buy, 1000, 2)
        .unwrap();
    let before = ledger.canonical_bytes();
    let immutable_plan = [(1, 3, 1000, 1), (2, 3, 1000, 1)];
    assert!(ledger.stage_reserved_fills(immutable_plan).is_err());
    assert_eq!(ledger.canonical_bytes(), before);
    ledger.release(3).unwrap();
    ledger.validate().unwrap();
}

#[test]
fn unconfigured_market_and_quote_multiplication_overflow_have_no_effect() {
    let mut ledger = Ledger::funded(config(&[(1, "USDC", i64::MAX)])).unwrap();
    let before = ledger.canonical_bytes();
    assert!(
        ledger
            .reserve(1, 1, "FOO-USDC", Side::Buy, 1000, 1)
            .is_err()
    );
    assert!(
        ledger
            .reserve(1, 1, "ETH-USDC", Side::Buy, i64::MAX, 2)
            .is_err()
    );
    assert_eq!(ledger.canonical_bytes(), before);
}
#[test]
fn market_reserves_the_effective_collar_and_releases_its_unfilled_remainder() {
    let mut state = funded(&[(1, "USDC", 2050), (2, "ETH", 100), (3, "USDC", 1000)]);
    state
        .apply_message(&order(2, 3, "ETH-USDC", Side::Buy, 10.0, 0.1, GTC))
        .unwrap();
    state
        .apply_message(&order(3, 2, "ETH-USDC", Side::Sell, 10.1, 0.1, GTC))
        .unwrap();
    // The measured midpoint is 1005 cents: the effective buy collar is 1025.
    // Reserving the signed bound (2000) would incorrectly reject 2050 funding.
    let mut market = order(4, 1, "ETH-USDC", Side::Buy, 20.0, 0.2, GTC);
    if let OrderMessage::New { order_type, .. } = &mut market {
        *order_type = OrderType::Market;
    }
    state.apply_message(&market).unwrap();
    assert_eq!(state.trades_total(), 1);
    assert_eq!(
        balance(&state, 1, "USDC"),
        Balance {
            available: 1040,
            reserved: 0
        }
    );
    assert_eq!(
        balance(&state, 1, "ETH"),
        Balance {
            available: 100,
            reserved: 0
        }
    );
    assert_eq!(state.ledger_snapshot().reservations.len(), 1);
    assert_eq!(state.ledger_snapshot().reservations[0].order_id, 2);
}

#[test]
fn shared_asset_has_the_same_units_when_used_as_base_or_quote() {
    let mut cfg = config(&[(1, "USDC", 1000)]);
    cfg.markets.push(MarketAssets {
        symbol: "USDC-DAI".into(),
        base_asset: "USDC".into(),
        quote_asset: "DAI".into(),
    });
    let mut ledger = Ledger::funded(cfg).unwrap();
    ledger
        .reserve(1, 1, "ETH-USDC", Side::Buy, 1000, 1)
        .unwrap();
    ledger.finish_sequence(1).unwrap();
    assert!(
        ledger
            .reserve(2, 1, "USDC-DAI", Side::Sell, 1000, 1)
            .is_err()
    );
    ledger.release(1).unwrap();
    ledger
        .reserve(2, 1, "USDC-DAI", Side::Sell, 1000, 1)
        .unwrap();
    assert_eq!(
        ledger.balance(1, "USDC"),
        Balance {
            available: 900,
            reserved: 100
        }
    );
    ledger.validate().unwrap();
}

#[test]
fn completed_sequence_cannot_repeat_a_partial_fill_using_active_remainders() {
    let mut ledger = Ledger::funded(config(&[(1, "USDC", 4000), (2, "ETH", 300)])).unwrap();
    ledger
        .reserve(1, 2, "ETH-USDC", Side::Sell, 1000, 3)
        .unwrap();
    ledger.finish_sequence(1).unwrap();
    ledger
        .reserve(2, 1, "ETH-USDC", Side::Buy, 1200, 3)
        .unwrap();
    ledger.settle_fill(1, 2, 1000, 1).unwrap();
    ledger.finish_sequence(2).unwrap();
    let before = ledger.canonical_bytes();
    assert!(ledger.settle_fill(1, 2, 1000, 1).is_err());
    assert_eq!(ledger.canonical_bytes(), before);
}

#[test]
fn restore_hook_requires_the_same_cursor_and_book_obligations() {
    let mut state = funded(&[(1, "USDC", 4000)]);
    state
        .apply_message(&order(2, 1, "ETH-USDC", Side::Buy, 10.0, 0.2, GTC))
        .unwrap();
    let good = state.ledger_snapshot();
    let before = state.ledger_canonical_bytes();
    let mut wrong_cursor = good.clone();
    wrong_cursor.last_sequence += 1;
    assert!(state.restore_ledger(wrong_cursor).is_err());
    let mut wrong_book = good.clone();
    wrong_book.reservations[0].limit_cents = 2000;
    wrong_book.reservations[0].remaining_tenths = 1;
    assert!(
        Ledger::from_snapshot(wrong_book.clone()).is_ok(),
        "valid monetary snapshot can still disagree with its book"
    );
    assert!(state.restore_ledger(wrong_book).is_err());
    assert_eq!(state.ledger_canonical_bytes(), before);
    state.restore_ledger(good).unwrap();
    assert_eq!(state.ledger_canonical_bytes(), before);
}

#[test]
fn snapshot_rejects_unsupported_versions_scale_and_negative_balances() {
    let good = Ledger::funded(config(&[(1, "USDC", 4000)]))
        .unwrap()
        .snapshot();
    let mut version = good.clone();
    version.version += 1;
    assert!(Ledger::from_snapshot(version).is_err());
    let mut scale = good.clone();
    scale.asset_scale = 100;
    assert!(Ledger::from_snapshot(scale).is_err());
    let mut negative = good;
    negative.balances[0].balance.available = -1;
    assert!(Ledger::from_snapshot(negative).is_err());
}
