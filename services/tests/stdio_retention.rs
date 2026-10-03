use std::io::Write;
use std::process::{Command, Stdio};

fn run(input: String, args: &[&str]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_services"))
        .arg("--stdio-engine")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Drain stdout while input is written, so pipe capacity cannot deadlock a
    // long fixture with a response for every command.
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap().unwrap();
    output
}

#[test]
fn stdio_process_writes_10001_fills_and_completes_the_command() {
    let fills = 10_001;
    let mut input = String::from(
        "{\"type\":\"init\",\"markets\":[{\"name\":\"M1\",\"tick_size\":0.01}],\"stp\":\"reject_incoming\"}\n",
    );
    for id in 1..=fills + 1 {
        input.push_str(
            &serde_json::json!({"type":"command", "cmd_seq":id,
            "command":{"type":"Limit", "symbol":0, "order_id":id,
                "account": if id <= fills { 3 } else { 4 },
                "side": if id <= fills { "Sell" } else { "Buy" },
                "price_ticks":10000, "qty": if id <= fills { 1 } else { fills }}})
            .to_string(),
        );
        input.push('\n');
    }
    let output = run(input, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let events: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let mut trades = events.iter().filter(|event| event["type"] == "Trade");
    for maker in 1..=fills {
        let trade = trades.next().expect("every maker produces a fill");
        assert_eq!(trade["resting"], maker);
        assert_eq!(trade["qty"], 1);
        assert_eq!(trade["accounts"], serde_json::json!([4, 3]));
    }
    assert!(trades.next().is_none());
    assert_eq!(
        events.last().unwrap(),
        &serde_json::json!({"type":"events_end", "cmd_seq":fills + 1})
    );
}

#[test]
fn stdio_process_refuses_oversized_input_before_any_command() {
    let output = run(
        format!("{}\n", " ".repeat(65)),
        &["--stdio-max-line-bytes", "64"],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exceeds 64 bytes"));
}
