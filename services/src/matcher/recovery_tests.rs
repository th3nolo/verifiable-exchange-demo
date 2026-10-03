use super::*;
use crate::domain::{OrderType, TimeInForce};

fn order(id: u64, at: u64, account: AccountId, side: Side, price: f64) -> OrderMessage {
    OrderMessage::New {
        id,
        timestamp: at,
        account,
        symbol: "ETH-USDC".into(),
        side,
        price,
        quantity: 1.0,
        nonce: None,
        order_type: OrderType::Limit,
        time_in_force: TimeInForce::GoodTillCancel,
        post_only: false,
    }
}

fn signed_commit(state: &mut MatcherState, store: &mut Store, key: &SigningKey) {
    let p = state.take_pending().unwrap();
    let claim = ClaimRow {
        from_msg: 1,
        to_msg: p.counters.last_seen,
        root_before: [0; 32],
        root_after: p.root,
        trades_total: p.trades_total,
        signature: Some(
            logchain::sign_claim(
                key,
                &p.session,
                1,
                p.counters.last_seen,
                &[0; 32],
                &p.root,
                p.trades_total,
            )
            .to_bytes(),
        ),
    };
    store.commit(&p.changes, &p.counters, Some(&claim)).unwrap();
}

#[test]
fn recovery_market_has_the_same_future_after_restart() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("state.db");
    let key = SigningKey::from_bytes(&[42; 32]);
    let (mut store, _) = Store::open(&path, "http://local", 200, false).unwrap();
    store
        .set_matcher_pubkey(&logchain::to_hex(key.verifying_key().as_bytes()))
        .unwrap();
    let mut live = MatcherState::recording_with_default_listings(&store);
    live.apply_message(&order(1, 0, 1, Side::Buy, 99.0))
        .unwrap();
    live.apply_message(&order(2, 0, 2, Side::Sell, 101.0))
        .unwrap();
    live.apply_message(&order(3, 1_000, 3, Side::Buy, 99.0))
        .unwrap();
    signed_commit(&mut live, &mut store, &key);
    store.close_stopped().unwrap();
    drop(store);
    let (store, snapshot) = Store::open(&path, "http://local", 200, false).unwrap();
    let snapshot = snapshot.unwrap();
    Store::authenticate_snapshot(&snapshot, &key.verifying_key()).unwrap();
    let mut restored = MatcherState::restore(snapshot, &store);
    assert_eq!(live.state_root(), restored.state_root());
    let mut market = order(4, 2_000, 4, Side::Buy, 102.0);
    if let OrderMessage::New {
        order_type,
        time_in_force,
        ..
    } = &mut market
    {
        *order_type = OrderType::Market;
        *time_in_force = TimeInForce::ImmediateOrCancel;
    }
    live.apply_message(&market).unwrap();
    restored.apply_message(&market).unwrap();
    assert_eq!(live.trades_total(), 1);
    assert_eq!(restored.trades_total(), 1);
    assert_eq!(live.state_root(), restored.state_root());
    assert_eq!(
        live.orders_ignored_by_kind(),
        restored.orders_ignored_by_kind()
    );
}

#[test]
fn recovery_claim_authentication_rejects_mutable_root_signature_and_bindings() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("state.db");
    let key = SigningKey::from_bytes(&[43; 32]);
    let (mut store, _) = Store::open(&path, "http://local", 200, false).unwrap();
    store
        .set_matcher_pubkey(&logchain::to_hex(key.verifying_key().as_bytes()))
        .unwrap();
    let mut live = MatcherState::recording_with_default_listings(&store);
    live.apply_message(&order(1, 0, 1, Side::Buy, 99.0))
        .unwrap();
    signed_commit(&mut live, &mut store, &key);
    store.close_stopped().unwrap();
    drop(store);
    let (_, snapshot) = Store::open(&path, "http://local", 200, false).unwrap();
    let snapshot = snapshot.unwrap();
    Store::authenticate_snapshot(&snapshot, &key.verifying_key()).unwrap();
    for case in 0..7 {
        let mut bad = snapshot.clone();
        match case {
            0 => bad.last_claim.as_mut().unwrap().signature.as_mut().unwrap()[0] ^= 1,
            1 => {
                bad.last_claim.as_mut().unwrap().root_after[0] ^= 1;
                bad.last_claim_root = Some(bad.last_claim.as_ref().unwrap().root_after);
            }
            2 => bad.feed_session = Some("another-session".into()),
            3 => bad.counters.last_seen += 1,
            4 => bad.trades_total += 1,
            5 => bad.last_claim.as_mut().unwrap().from_msg = 0,
            6 => {
                bad.matcher_pubkey = Some(logchain::to_hex(
                    SigningKey::from_bytes(&[44; 32]).verifying_key().as_bytes(),
                ))
            }
            _ => unreachable!(),
        }
        assert!(
            Store::authenticate_snapshot(&bad, &key.verifying_key()).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn recovery_root_authenticates_reference_and_canonical_extensions() {
    let mut state = MatcherState::with_default_listings();
    let before = state.state_root();
    let legacy = state.state_root_for_version(4);
    state.mids.observe("ETH-USDC", 0, Some(10_000));
    assert_ne!(state.state_root(), before);
    assert_eq!(
        state.state_root_for_version(4),
        legacy,
        "historical encoding remains unchanged"
    );
    let mut reordered = state.clone();
    state.set_execution_extension("z".into(), vec![2]);
    state.set_execution_extension("a".into(), vec![1]);
    reordered.set_execution_extension("a".into(), vec![1]);
    reordered.set_execution_extension("z".into(), vec![2]);
    assert_eq!(state.state_root(), reordered.state_root());
    reordered.set_execution_extension("ledger-v1".into(), vec![3]);
    assert_ne!(state.state_root(), reordered.state_root());
}

#[tokio::test]
async fn recovery_disk_failure_never_publishes_or_admits_another_batch() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("state.db");
    let key = SigningKey::from_bytes(&[45; 32]);
    let (store, _) = Store::open(&path, "http://local", 200, false).unwrap();
    let state = MatcherState::recording_with_default_listings(&store);
    let root = state.state_root();
    let committed = state.counters();
    let live = LiveFeed::new();
    let mut reader = live.to_readers.subscribe();
    let (_, shutdown) = watch::channel(false);
    let mut poller = Poller {
        state: Arc::new(Mutex::new(state)),
        live,
        feed_url: "http://local".into(),
        poll_ms: 200,
        store: Some(store),
        shutdown,
        committed,
        committed_root: root,
        claim_key: key.clone(),
        last_heartbeat: Instant::now(),
    };
    let msg = order(1, 0, 1, Side::Buy, 99.0);
    let bytes = logchain::canonical_bytes(&msg);
    let chain = logchain::extend_bytes(&EMPTY_CHAIN, &bytes);
    let mut body = bytes;
    body.push(b'\n');
    let messages = wire::read_ndjson(&body).unwrap();
    let head = SignedHead {
        last_id: 1,
        chain,
        public_key: logchain::to_hex(key.verifying_key().as_bytes()),
        signature: logchain::sign_head(&key, "", 1, &chain),
    };
    poller
        .apply_committed_batch(&messages, &head)
        .await
        .unwrap();
    assert_eq!(
        reader.try_recv().unwrap().cursor,
        1,
        "successful commit publishes its tick"
    );
    let root = lock_state(&poller.state).state_root();
    poller.store.as_mut().unwrap().fail_writes_for_test();
    let msg = order(2, 1_000, 2, Side::Sell, 99.0);
    let bytes = logchain::canonical_bytes(&msg);
    let chain = logchain::extend_bytes(&chain, &bytes);
    let mut body = bytes;
    body.push(b'\n');
    let messages = wire::read_ndjson(&body).unwrap();
    let head = SignedHead {
        last_id: 2,
        chain,
        public_key: logchain::to_hex(key.verifying_key().as_bytes()),
        signature: logchain::sign_head(&key, "", 2, &chain),
    };
    poller
        .apply_committed_batch(&messages, &head)
        .await
        .unwrap();
    let state = lock_state(&poller.state);
    assert!(state.execution_paused);
    assert_eq!(state.last_seen, 1);
    assert_eq!(state.durable_last_seen, 1);
    assert_eq!(state.state_root(), root);
    assert_eq!(
        state.trades_total(),
        0,
        "uncommitted fill is not authoritative"
    );
    assert_eq!(
        state.open_orders.len(),
        1,
        "committed maker remains available"
    );
    assert!(
        state.state_db.is_some(),
        "durable mode never degrades to volatile"
    );
    drop(state);
    assert!(
        reader.try_recv().is_err(),
        "no authoritative tick for failed commit"
    );
    poller
        .apply_committed_batch(&messages, &head)
        .await
        .unwrap();
    assert_eq!(
        lock_state(&poller.state).last_seen,
        1,
        "paused engine admits no next batch"
    );
    assert_eq!(lock_state(&poller.state).state_commit_failures, 1);
}

#[tokio::test]
async fn recovery_failed_stop_pauses_and_does_not_mark_the_run_saved() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("state.db");
    let (store, _) = Store::open(&path, "http://local", 200, false).unwrap();
    let state = MatcherState::recording(&store);
    let root = state.state_root();
    let committed = state.counters();
    let (_, shutdown) = watch::channel(false);
    let mut poller = Poller {
        state: Arc::new(Mutex::new(state)),
        live: LiveFeed::new(),
        feed_url: "http://local".into(),
        poll_ms: 200,
        store: Some(store),
        shutdown,
        committed,
        committed_root: root,
        claim_key: SigningKey::from_bytes(&[46; 32]),
        last_heartbeat: Instant::now(),
    };
    poller.store.as_mut().unwrap().fail_writes_for_test();
    poller.finish().await;
    let state = lock_state(&poller.state);
    assert!(state.execution_paused);
    assert_eq!(state.state_commit_failures, 1);
    assert_eq!(state.state_root(), root);
    drop(state);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let status: String = connection
        .query_row("SELECT status FROM runs WHERE run_id=1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(status, crate::store::status::OPEN);
}
