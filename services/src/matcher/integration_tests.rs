//! Combined funded-ledger, capacity, root and durable-publication regressions.
use super::*;
use crate::domain::{OrderType, TimeInForce};
use crate::ledger::{Funding, MarketAssets};

fn funding() -> FundingConfig {
    FundingConfig {
        markets: vec![MarketAssets {
            symbol: "ETH-USDC".into(),
            base_asset: "ETH".into(),
            quote_asset: "USDC".into(),
        }],
        funding: [1, 2, 3]
            .into_iter()
            .flat_map(|account| {
                [
                    Funding {
                        account,
                        asset: "ETH".into(),
                        units: 3_000,
                    },
                    Funding {
                        account,
                        asset: "USDC".into(),
                        units: 500_000,
                    },
                ]
            })
            .collect(),
        fee_units: 0,
    }
}

fn limits() -> ResourceLimits {
    ResourceLimits {
        max_active_orders: 8,
        max_positions: 4,
        max_symbols: 8,
    }
}

fn order(id: u64, account: AccountId, side: Side, quantity: f64, tif: TimeInForce) -> OrderMessage {
    OrderMessage::New {
        id,
        timestamp: id * 1_000,
        account,
        symbol: "ETH-USDC".into(),
        side,
        price: 100.0,
        quantity,
        nonce: None,
        order_type: OrderType::Limit,
        time_in_force: tif,
        post_only: false,
    }
}

fn cancel(id: u64, account: AccountId, target_id: u64) -> OrderMessage {
    OrderMessage::Cancel {
        id,
        timestamp: id * 1_000,
        account,
        target_id,
        nonce: None,
    }
}

fn state(store: &Store) -> MatcherState {
    let mut state = MatcherState::recording_with_default_listings(store)
        .with_resource_limits(limits())
        .unwrap();
    state.ledger = Ledger::funded(funding()).unwrap();
    state
}

fn commit(state: &mut MatcherState, store: &mut Store, key: &SigningKey, before: [u8; 32]) {
    let p = state.take_pending().unwrap();
    let signature = logchain::sign_claim(
        key,
        &p.session,
        1,
        p.counters.last_seen,
        &before,
        &p.root,
        p.trades_total,
    )
    .to_bytes();
    let claim = ClaimRow {
        from_msg: 1,
        to_msg: p.counters.last_seen,
        root_before: before,
        root_after: p.root,
        trades_total: p.trades_total,
        signature: Some(signature),
    };
    store.commit(&p.changes, &p.counters, Some(&claim)).unwrap();
}

#[test]
fn integrated_funded_restart_preserves_reserves_policy_and_future_execution() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let key = SigningKey::from_bytes(&[61; 32]);
    let (mut store, _) = Store::open(&path, "http://local", 200, false).unwrap();
    store
        .set_matcher_pubkey(&logchain::to_hex(key.verifying_key().as_bytes()))
        .unwrap();
    let mut live = state(&store);
    let before = live.state_root();
    live.apply_message(&order(1, 1, Side::Sell, 2.0, TimeInForce::GoodTillCancel))
        .unwrap();
    live.apply_message(&order(2, 2, Side::Buy, 0.5, TimeInForce::ImmediateOrCancel))
        .unwrap();
    let mut bid = order(3, 2, Side::Buy, 0.1, TimeInForce::GoodTillCancel);
    if let OrderMessage::New { price, .. } = &mut bid {
        *price = 99.0;
    }
    live.apply_message(&bid).unwrap();
    commit(&mut live, &mut store, &key, before);
    let saved = live.ledger_snapshot();
    assert_eq!(saved.reservations[0].remaining_tenths, 15);
    assert_eq!(saved.reservations[0].units, 1_500);
    store.close_stopped().unwrap();
    drop(store);
    let (store, snapshot) = Store::open(&path, "http://local", 200, false).unwrap();
    let snapshot = snapshot.unwrap();
    Store::authenticate_snapshot(&snapshot, &key.verifying_key()).unwrap();
    let mut restored = MatcherState::restore(snapshot, &store);
    assert_eq!(restored.ledger_snapshot(), saved);
    assert_eq!(restored.resource_limits(), Some(limits()));
    assert_eq!(restored.state_root(), live.state_root());
    let mut market = order(4, 3, Side::Buy, 0.5, TimeInForce::ImmediateOrCancel);
    if let OrderMessage::New { order_type, .. } = &mut market {
        *order_type = OrderType::Market;
    }
    for msg in [
        market,
        cancel(5, 1, 1),
        cancel(6, 2, 3),
        order(7, 2, Side::Buy, 6.0, TimeInForce::FillOrKill),
    ] {
        live.apply_message(&msg).unwrap();
        restored.apply_message(&msg).unwrap();
        assert_eq!(restored.state_root(), live.state_root());
        assert_eq!(restored.ledger_snapshot(), live.ledger_snapshot());
    }
    assert!(restored.ledger_snapshot().reservations.is_empty());
    assert_eq!(restored.trades_total(), 2);
}

#[test]
fn integrated_root_and_typed_policy_reject_missing_unknown_or_mutated_payloads() {
    let state = MatcherState::funded_simulation(funding())
        .unwrap()
        .with_resource_limits(limits())
        .unwrap();
    let execution = state.execution_state();
    let genesis = ExecutionGenesis::from_execution_state(&execution).unwrap();
    assert_eq!(genesis, state.execution_genesis());
    assert_eq!(
        genesis.replaying("").unwrap().state_root(),
        state.state_root()
    );
    let mut changed = execution.clone();
    changed.extensions.remove("ledger-v1");
    assert!(
        ExecutionGenesis::from_execution_state(&changed)
            .unwrap_err()
            .contains("missing")
    );
    let mut changed = execution.clone();
    changed
        .extensions
        .insert("future-policy-v9".into(), vec![1]);
    assert!(
        ExecutionGenesis::from_execution_state(&changed)
            .unwrap_err()
            .contains("unsupported")
    );
    let mut changed = execution.clone();
    changed
        .extensions
        .get_mut(resource_limits::RESOURCE_LIMITS_EXTENSION)
        .unwrap()[0] = 2;
    assert!(ExecutionGenesis::from_execution_state(&changed).is_err());
    let mut changed = state.clone();
    changed.resource_limits = Some(ResourceLimits {
        max_active_orders: 9,
        ..limits()
    });
    assert_ne!(changed.state_root(), state.state_root());
    assert_eq!(
        changed.state_root_for_version(4),
        state.state_root_for_version(4)
    );
    let legacy = MatcherState::new().with_resource_limits(limits()).unwrap();
    assert_ne!(legacy.state_root(), state.state_root());
}

#[test]
fn integrated_snapshot_refreshes_after_cancel_rejection_fok_and_delist() {
    let mut state = MatcherState::funded_simulation(funding())
        .unwrap()
        .with_symbols_listed(&["ETH-USDC"]);
    let commands = [
        order(1, 1, Side::Sell, 1.0, TimeInForce::GoodTillCancel),
        order(2, 2, Side::Buy, 0.5, TimeInForce::FillOrKill),
        cancel(3, 1, 1),
        order(4, 3, Side::Sell, 9.0, TimeInForce::GoodTillCancel),
    ];
    for msg in commands {
        state.apply_message(&msg).unwrap();
        let decoded: LedgerSnapshot =
            serde_json::from_slice(&state.execution_state().extensions["ledger-v1"]).unwrap();
        assert_eq!(decoded, state.ledger_snapshot());
        assert_eq!(decoded.last_sequence, msg.id());
    }
    state
        .apply_message(&order(5, 1, Side::Sell, 0.1, TimeInForce::GoodTillCancel))
        .unwrap();
    let delist = operator::signed_as(
        &SigningKey::from_bytes(&[62; 32]),
        "",
        OrderMessage::DelistSymbol {
            id: 6,
            timestamp: 6_000,
            account: crate::domain::OPERATOR_ACCOUNT,
            symbol: "ETH-USDC".into(),
            nonce: Some(format!("{:032x}", 6)),
            public_key: String::new(),
            signature: String::new(),
        },
    );
    state.apply_message(&delist).unwrap();
    assert!(state.ledger_snapshot().reservations.is_empty());
    assert_eq!(
        state.execution_state().extensions["ledger-v1"],
        state.ledger_canonical_bytes()
    );
}

#[tokio::test]
async fn integrated_failed_commit_preserves_published_funds_book_root_and_tick() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[63; 32]);
    let (mut store, _) =
        Store::open(&dir.path().join("state.db"), "http://local", 200, false).unwrap();
    store
        .set_matcher_pubkey(&logchain::to_hex(key.verifying_key().as_bytes()))
        .unwrap();
    let mut engine = state(&store);
    let before = engine.state_root();
    engine
        .apply_message(&order(1, 1, Side::Sell, 1.0, TimeInForce::GoodTillCancel))
        .unwrap();
    commit(&mut engine, &mut store, &key, before);
    engine.durable_last_seen = 1;
    let saved = engine.ledger_snapshot();
    let root = engine.state_root();
    let counters = engine.counters();
    let chain_before = engine.feed_chain.unwrap_or(EMPTY_CHAIN);
    let shared = Arc::new(Mutex::new(engine));
    let live = LiveFeed::new();
    let mut receiver = live.to_readers.subscribe();
    let (_, shutdown) = watch::channel(false);
    let mut poller = Poller {
        state: shared.clone(),
        store: Some(store),
        feed_url: "http://local".into(),
        committed: counters,
        committed_root: root,
        claim_key: key.clone(),
        last_heartbeat: Instant::now(),
        live,
        shutdown,
        poll_ms: 200,
    };
    // SQLite refuses the candidate's write. The candidate would settle a
    // funded fill if it were published before that failed commit.
    poller.store.as_mut().unwrap().fail_writes_for_test();
    let msg = order(2, 2, Side::Buy, 1.0, TimeInForce::FillOrKill);
    let mut bytes = logchain::canonical_bytes(&msg);
    let chain = logchain::extend_bytes(&chain_before, &bytes);
    let head = SignedHead {
        last_id: 2,
        chain,
        public_key: logchain::to_hex(key.verifying_key().as_bytes()),
        signature: logchain::sign_head(&key, "", 2, &chain),
    };
    bytes.push(b'\n');
    let messages = wire::read_ndjson(&bytes).unwrap();
    poller
        .apply_committed_batch(&messages, &head)
        .await
        .unwrap();
    let published = lock_state(&shared);
    assert!(published.execution_paused);
    assert_eq!(published.last_seen, 1);
    assert_eq!(published.durable_last_seen, 1);
    assert_eq!(published.ledger_snapshot(), saved);
    assert_eq!(published.state_root(), root);
    assert!(published.open_order(1).is_some());
    assert_eq!(published.trades_total(), 0);
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}
