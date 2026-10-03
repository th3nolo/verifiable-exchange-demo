//! The funded CLI is a runnable local simulation with explicit genesis state.
use services::ledger::{Ledger, LedgerMode, LedgerSnapshot};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn cli_requires_explicit_mode_and_funding() {
    for args in [
        vec!["--start-matcher", "--no-state-db"],
        vec![
            "--start-matcher",
            "--ledger-mode",
            "funded-simulation",
            "--no-state-db",
        ],
        vec![
            "--start-matcher",
            "--ledger-mode",
            "synthetic-legacy",
            "--funding",
            "unused.json",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_services"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("funding")
                || String::from_utf8_lossy(&output.stderr).contains("--ledger-mode")
        );
    }
}

#[tokio::test]
async fn funded_cli_serves_its_mode_funding_and_balances_over_http() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join("funding.json");
    let config = include_str!("../funding.example.json");
    std::fs::write(&config_path, config).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut running = Running(
        Command::new(env!("CARGO_BIN_EXE_services"))
            .current_dir(dir.path())
            .args([
                "--start-matcher",
                "--ledger-mode",
                "funded-simulation",
                "--funding",
            ])
            .arg(&config_path)
            .args([
                "--no-state-db",
                "--feed-url",
                "http://127.0.0.1:1",
                "--matcher-port",
            ])
            .arg(port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(10);
    let snapshot: LedgerSnapshot = loop {
        assert!(
            running.0.try_wait().unwrap().is_none(),
            "funded matcher exited before serving HTTP"
        );
        if let Ok(response) = client.get(format!("{base}/balances")).send().await {
            break response.error_for_status().unwrap().json().await.unwrap();
        }
        assert!(Instant::now() < deadline, "funded matcher failed to bind");
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(snapshot.mode, LedgerMode::FundedSimulation);
    assert_eq!(snapshot.asset_scale, 1000);
    assert_eq!(snapshot.last_sequence, 0);
    assert!(snapshot.reservations.is_empty());
    let expected = Ledger::funded(serde_json::from_str(config).unwrap()).unwrap();
    assert_eq!(snapshot, expected.snapshot());
    let market: serde_json::Value = client
        .get(format!("{base}/market"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(market["ledger_mode"], "funded_simulation");
    assert_eq!(market["asset_scale"], 1000);
    // An API read must never issue funding a second time.
    let again: LedgerSnapshot = client
        .get(format!("{base}/balances"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(again, snapshot);
}
