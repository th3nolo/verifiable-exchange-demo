use sha2::{Digest, Sha256};
use std::{fmt::Write as _, fs, path::Path};

fn root_file(path: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("services has a repository root");
    fs::read_to_string(root.join(path)).unwrap_or_else(|error| {
        panic!("could not read {path}: {error}");
    })
}

fn root_bytes(path: &str) -> Vec<u8> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("services has a repository root");
    fs::read(root.join(path)).unwrap_or_else(|error| {
        panic!("could not read {path}: {error}");
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[test]
fn the_page_uses_the_site_icons() {
    let page = root_file("services/static/index.html");
    for (href, path, expected_hash) in [
        (
            "/favicon.ico",
            "services/static/favicon.ico",
            "43a6b9d855fdb349514efe2df8861f14cc2524b5713378b390f8dd3ecbd7730e",
        ),
        (
            "/icon.png",
            "services/static/icon.png",
            "7e5e3520398f48357fc5a5a4733f15967f187b0ec47475f64a00c938c465d042",
        ),
        (
            "/apple-icon.png",
            "services/static/apple-icon.png",
            "ead940dd433ad9bca042d5a20180664097137c927b2cb1cb97c8a48952f7bfaf",
        ),
    ] {
        assert!(
            page.contains(&format!("href=\"{href}\"")),
            "the page does not name {href}"
        );
        assert_eq!(
            sha256_hex(&root_bytes(path)),
            expected_hash,
            "{path} is no longer the checked copy from th3nolo.com"
        );
    }
    assert!(
        !page.contains("href=\"data:,\""),
        "the empty icon came back"
    );
}

#[test]
fn the_trading_page_needs_no_inline_code() {
    let page = root_file("services/static/index.html");
    let script = root_file("services/static/app.js");
    assert!(page.contains("href=\"/app.css\""));
    assert!(page.contains("src=\"/app.js\""));
    assert!(!page.contains("<style"));
    assert!(!page.contains("<script type=\"module\">"));
    assert!(!script.contains("style=\""));

    let security = root_file("services/src/http_security.rs");
    assert!(security.contains("script-src 'self'; style-src 'self';"));
    assert!(security.contains("frame-ancestors 'none'"));
}

#[test]
fn a_first_visit_does_not_persist_an_account_key() {
    let page = root_file("services/static/index.html");
    let script = root_file("services/static/app.js");
    assert!(page.contains("id=\"remember-key\""));
    let load_identity = script
        .split("async function loadIdentity(fresh)")
        .nth(1)
        .and_then(|rest| rest.split("function renderIdentity()").next())
        .expect("the identity loader has a bounded source block");
    assert!(
        !load_identity.contains("writeKey("),
        "loading or generating an identity must not persist it"
    );
    assert!(script.contains("writeKey(toHex(identity.seed))"));
    assert!(script.contains("beforeunload"));
    assert!(script.contains("submissionsInFlight"));
    assert!(script.contains("hasSignedActivity"));
}

#[test]
fn trade_results_do_not_reinterpret_text_as_html() {
    let script = root_file("services/static/app.js");
    let renderer = script
        .split("function showResult(...nodes)")
        .nth(1)
        .and_then(|rest| rest.split("function showMessage(").next())
        .expect("the trade-result renderer has a bounded source block");
    assert!(renderer.contains("replaceChildren(...nodes)"));
    assert!(
        !renderer.contains("innerHTML"),
        "trade-result text must stay in DOM nodes instead of being reparsed as HTML"
    );
    assert!(script.contains("span.textContent = String(text);"));
    assert!(script.contains("function showOutcome(order, ...nodes)"));
    assert!(script.contains("receiptNodes: Array.from("));
    assert!(
        !script.contains("document.getElementById(\"trade-result\").innerHTML"),
        "neither receipts nor outcomes may round-trip through HTML"
    );
}

#[test]
fn market_orders_expose_partial_fills_and_slippage_before_signing() {
    let page = root_file("services/static/index.html");
    let script = root_file("services/static/app.js");
    assert!(page.contains("id=\"slippage-box\""));
    assert!(page.contains("id=\"slippage\""));
    assert!(page.contains("id=\"price-label\""));
    assert!(script.contains("label: \"Market, partial fill\""));
    assert!(script.contains("const MAX_MARKET_SLIPPAGE_BPS = 150;"));
    assert!(script.contains("function parseSlippageBps(text)"));
    assert!(script.contains("Partial fill allowed."));
    assert!(script.contains("A partial-fill market order never rests."));
}

#[test]
fn last_order_totals_the_exact_fill_interval_and_marks_its_candle() {
    let script = root_file("services/static/app.js");
    assert!(script.contains("/trade-log?since="));
    assert!(script.contains("Number(row.price_cents)"));
    assert!(script.contains("Number(row.qty_tenths)"));
    assert!(script.contains("BigInt(row.priceCents)"));
    assert!(script.contains("const ORDER_TRADE_PAGE = 1000;"));
    assert!(script.contains("let lastOwnFill = null;"));
    assert!(script.contains("your fill"));
    assert!(script.contains("most you accept; a sell price is the least"));
    assert!(script.contains("It changed no candle."));

    let resolver = script
        .split("async function resolveOutcome(market, openOrders)")
        .nth(1)
        .and_then(|rest| rest.split("// The inbox's answer").next())
        .expect("the outcome resolver has a bounded source block");
    assert!(
        !resolver.contains("&n=60"),
        "a large order outcome must not be cut off at 60 fills"
    );
}

#[test]
fn candle_answers_cannot_cross_symbols_or_intervals() {
    let script = root_file("services/static/app.js");
    let loader = script
        .split("const candleWindows =")
        .nth(1)
        .and_then(|rest| rest.split("async function refresh()").next())
        .expect("the candle loader has a bounded source block");

    assert!(loader.contains("const asked = { symbol, interval, lookback: candleLookback };"));
    assert!(loader.contains("const serial = ++candleRequestSerial;"));
    assert!(loader.contains("candleUrl(asked.symbol, asked.interval, asked.lookback)"));
    assert!(loader.contains("candleUrl(asked.symbol, asked.interval, CANDLE_TAIL)"));
    assert!(loader.contains("if (!current() || candleWindows.get(key) !== window) return null;"));

    let whole = loader
        .split("const whole = async () =>")
        .nth(1)
        .and_then(|rest| rest.split("const window = cachedCandleWindow(key);").next())
        .expect("the whole-window request has a bounded source block");
    let stale_guard = whole
        .find("if (!current()) return null;")
        .expect("a stale whole-window response is rejected");
    let cache_write = whole
        .find("rememberCandleWindow({ key, rows });")
        .expect("a current whole-window response is cached");
    assert!(
        stale_guard < cache_write,
        "a stale candle response must be rejected before it can replace the cache"
    );

    assert!(script.contains("candleRequestSerial += 1;"));
    assert!(script.contains("abortCandleRequests();"));
    assert!(script.contains("Candles unavailable; retrying..."));
    assert!(script.contains("return candleRows().then(drawCandleAnswer).catch((error) =>"));
}

#[test]
fn symbol_changes_start_one_small_candle_request_and_keep_recent_windows() {
    let script = root_file("services/static/app.js");
    assert!(script.contains("const FIRST_LOOKBACK = 200;"));
    assert!(script.contains("const LOOKBACK_STEP = 400;"));
    assert!(script.contains("const MAX_CANDLE_WINDOWS = 12;"));
    assert!(
        script.contains(
            "if (candlePending && candlePending.key === key) return candlePending.promise;"
        )
    );
    assert!(script.contains("const cached = cachedCandleWindow(currentCandleKey());"));

    let selection = script
        .split("function selectSymbol(next)")
        .nth(1)
        .and_then(|rest| rest.split("async function startTrading()").next())
        .expect("symbol selection has a bounded source block");
    let chart = selection
        .find("refreshCandleChart()")
        .expect("symbol selection starts the chart");
    let market = selection
        .find("refresh();")
        .expect("symbol selection refreshes the other panels");
    assert!(
        chart < market,
        "the candle request must start before the market refresh"
    );
}

#[test]
fn the_public_tree_has_a_private_security_route() {
    let policy = root_file("SECURITY.md");
    assert!(policy.contains("**Security** tab"));
    assert!(policy.contains("**Report a vulnerability**"));
    assert!(policy.contains("Do not open a public issue"));
    assert!(
        !policy.contains("github.com/th3nolo/"),
        "the security policy must not hard-code a repository name"
    );
}

#[test]
fn third_party_actions_are_pinned_to_commits() {
    for path in [
        ".github/workflows/ci.yml",
        ".github/workflows/experiments.yml",
    ] {
        let workflow = root_file(path);
        for (index, line) in workflow.lines().enumerate() {
            let Some(action) = line.trim().strip_prefix("- uses: ") else {
                continue;
            };
            let action = action
                .split_whitespace()
                .next()
                .expect("a uses line names an action");
            let (_, revision) = action
                .rsplit_once('@')
                .unwrap_or_else(|| panic!("{path}:{} has no revision", index + 1));
            assert!(
                revision.len() == 40
                    && revision
                        .chars()
                        .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
                "{path}:{} does not pin {action} to a full commit SHA",
                index + 1
            );
        }
    }
}

#[test]
fn private_deployment_configuration_is_not_published() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("services has a repository root");
    assert!(
        !root.join("docker-compose.yml").exists(),
        "the public tree must not contain the private deployment file"
    );

    let example = root_file(".env.example");
    let settings: Vec<_> = example
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert_eq!(settings, ["RATE=69", "NUM_ACCOUNTS=40"]);
}

#[test]
fn public_ci_verifies_without_deploying() {
    let workflow = root_file(".github/workflows/ci.yml");
    assert!(workflow.contains("load: true"));
    for forbidden in [
        "secrets.",
        "DEPLOY_",
        "docker/login-action",
        "packages: write",
        "push: true",
        "cat /tmp/out",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "public CI must verify without publishing or deploying: {forbidden}"
        );
    }
}

#[test]
fn common_local_secret_files_are_ignored() {
    let ignore = root_file(".gitignore");
    for pattern in [".env", "*.key", "*.pem", "*.p12", "*.pfx"] {
        assert!(
            ignore.lines().any(|line| line == pattern),
            "missing {pattern}"
        );
    }
}
