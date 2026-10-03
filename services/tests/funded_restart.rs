//! Exercise the actual funded matcher process against a signed local feed.
use axum::{Router, extract::Query, http::HeaderMap, routing::get};
use ed25519_dalek::SigningKey;
use services::{
    domain::{OPERATOR_ACCOUNT, OrderMessage, OrderType, Side, TimeInForce},
    ledger::LedgerSnapshot,
    logchain, operator, wire,
};
use std::{
    collections::HashMap,
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(dir: &Path, port: u16, feed: &str, funding: &Path) -> Running {
    Running(
        Command::new(env!("CARGO_BIN_EXE_services"))
            .current_dir(dir)
            .args([
                "--start-matcher",
                "--ledger-mode",
                "funded-simulation",
                "--funding",
            ])
            .arg(funding)
            .args([
                "--state-db",
                "state.db",
                "--poll-ms",
                "25",
                "--feed-url",
                feed,
                "--matcher-port",
            ])
            .arg(port.to_string())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

async fn balances(client: &reqwest::Client, child: &mut Running, base: &str) -> LedgerSnapshot {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "funded matcher exited before durable recovery"
        );
        if let Ok(response) = client.get(format!("{base}/balances")).send().await {
            if let Ok(snapshot) = response.json::<LedgerSnapshot>().await {
                if snapshot.last_sequence == 3 {
                    return snapshot;
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "funded matcher did not reach committed cursor 3"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn funded_process_restart_preserves_partial_fill_and_rejects_changed_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("funding.json");
    std::fs::write(&config, include_str!("../funding.example.json")).unwrap();
    let session = "funded-restart-regression";
    let key = SigningKey::from_bytes(&[71; 32]);
    let listing = operator::signed_as(
        &key,
        session,
        OrderMessage::ListSymbol {
            id: 1,
            timestamp: 1_000,
            account: OPERATOR_ACCOUNT,
            symbol: "ETH-USDC".into(),
            price_step: 0.01,
            quantity_step: 0.1,
            nonce: Some(format!("{:032x}", 1)),
            public_key: String::new(),
            signature: String::new(),
        },
    );
    let order = |id, account, side, quantity| OrderMessage::New {
        id,
        timestamp: id * 1_000,
        account,
        symbol: "ETH-USDC".into(),
        side,
        price: 100.0,
        quantity,
        nonce: None,
        order_type: OrderType::Limit,
        time_in_force: TimeInForce::GoodTillCancel,
        post_only: false,
    };
    let messages = vec![
        listing,
        order(2, 2, Side::Sell, 2.0),
        order(3, 1, Side::Buy, 0.5),
    ];
    let chain = messages.iter().fold(logchain::EMPTY_CHAIN, |chain, msg| {
        logchain::extend(&chain, msg)
    });
    let router = Router::new().route(
        wire::MESSAGES_PATH,
        get(move |Query(query): Query<HashMap<String, u64>>| {
            let messages = messages.clone();
            let key = key.clone();
            async move {
                let since = query.get("since").copied().unwrap_or(0);
                let body = messages
                    .iter()
                    .filter(|msg| msg.id() > since)
                    .map(|msg| String::from_utf8(logchain::canonical_bytes(msg)).unwrap() + "\n")
                    .collect::<String>();
                let mut headers = HeaderMap::new();
                for (name, value) in [
                    (wire::SESSION_HEADER, session.to_string()),
                    (wire::HEAD_LAST_ID_HEADER, "3".to_string()),
                    (wire::HEAD_CHAIN_HEADER, logchain::to_hex(&chain)),
                    (
                        wire::HEAD_PUBKEY_HEADER,
                        logchain::to_hex(key.verifying_key().as_bytes()),
                    ),
                    (
                        wire::HEAD_SIGNATURE_HEADER,
                        logchain::to_hex(&logchain::sign_head(&key, session, 3, &chain).to_bytes()),
                    ),
                ] {
                    headers.insert(name, value.parse().unwrap());
                }
                (headers, body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let feed = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let mut first = spawn(dir.path(), port, &feed, &config);
    let before = balances(&client, &mut first, &base).await;
    assert_eq!(before.reservations.len(), 1);
    assert_eq!(before.reservations[0].order_id, 2);
    assert_eq!(before.reservations[0].remaining_tenths, 15);
    assert_eq!(before.reservations[0].units, 1_500);
    let claims: serde_json::Value = client
        .get(format!("{base}/claims"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(claims["root_version"], 5);
    assert_eq!(claims["cursor"], 3);
    assert_eq!(
        claims["execution_genesis"]["ledger_mode"],
        "funded_simulation"
    );
    assert_eq!(claims["claims"].as_array().unwrap().len(), 1);
    first.0.kill().unwrap();
    first.0.wait().unwrap();
    drop(first);
    // Windows conservatively treats an unknown PID as alive. Honor the
    // production lease instead of rewriting ownership metadata in the test.
    if cfg!(windows) {
        tokio::time::sleep(Duration::from_secs(31)).await;
    }
    let mut second = spawn(dir.path(), port, &feed, &config);
    let after = balances(&client, &mut second, &base).await;
    assert_eq!(
        after, before,
        "restart must not issue funding twice or lose reserves"
    );
    let recovered: serde_json::Value = client
        .get(format!("{base}/claims"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(recovered, claims);
    second.0.kill().unwrap();
    second.0.wait().unwrap();
    drop(second);
    if cfg!(windows) {
        tokio::time::sleep(Duration::from_secs(31)).await;
    }
    let mut changed: serde_json::Value =
        serde_json::from_str(include_str!("../funding.example.json")).unwrap();
    changed["funding"][0]["units"] = serde_json::json!(20_000_000);
    std::fs::write(&config, serde_json::to_vec(&changed).unwrap()).unwrap();
    let mut incompatible = spawn(dir.path(), port, &feed, &config);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = incompatible.0.try_wait().unwrap() {
            assert_eq!(status.code(), Some(2));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "changed funding configuration was not refused"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    server.abort();
}
