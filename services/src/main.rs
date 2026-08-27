use clap::{ArgGroup, Parser};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::json;
use services::fetch::reason;
use services::{bot, cors, domain, feed, inbox, logchain, matcher, operator, stdio_engine, verify};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Where the sequencer is when `--feed-url` was not given.
///
/// Every command that reads the sequencer falls back to this address.
/// `--audit-url` does not, on purpose. A person who audits a remote exchange
/// runs no sequencer on their own machine, so that command asks the exchange
/// where its sequencer is.
const DEFAULT_FEED_URL: &str = "http://127.0.0.1:3000";

/// The exit status for a command that could not run at all: a mistyped
/// argument, a key file that will not open, a sequencer that does not answer.
///
/// `wire::Verdict::exit_code` lists this repository's exit statuses. 0 is a
/// pass. 1 is a check that failed. 2 is a command that could not run at all.
/// 3 is a log this build is too old to read. A bad argument is "could not run
/// at all", so it is 2. This file follows that one list and invents no second
/// list, because a script that wraps this binary reads one number from every
/// command it runs.
const EXIT_CANNOT_RUN: i32 = 2;

/// The exit status for a command that ran and was refused: the service
/// answered, and it said no.
///
/// This is 1 in `wire::Verdict::exit_code`. It stays apart from
/// `EXIT_CANNOT_RUN` on purpose. A sequencer that refused an order answered.
/// A sequencer that is not running did not answer. A script retries the second
/// one and reports the first one.
const EXIT_REFUSED: i32 = 1;

/// Reads one command-line value. A value that does not parse stops the
/// program, and the line printed names the value and what the flag takes.
///
/// A mistyped number is the caller's typo, not a fault in this binary. A panic
/// answers a typo with a backtrace and the exit status of a crash. That tells
/// the caller the tool is broken, when the command line is what is broken.
fn arg_or_exit<T: FromStr>(flag: &str, what: &str, value: &str, expected: &str) -> T {
    match value.parse::<T>() {
        Ok(parsed) => parsed,
        Err(_) => {
            eprintln!("{}: {} '{}' is not {}", flag, what, value, expected);
            std::process::exit(EXIT_CANNOT_RUN);
        }
    }
}

/// Loads the caller's account key, creates the key file if it is not there,
/// and signs one submission with the key.
///
/// The key file is the account. The first submission for an account id pins
/// the key that signed it, and every later submission for that id must carry
/// the same key. A caller who loses the file can no longer submit or cancel
/// for that account. There is no way to recover it, on purpose: a recovery
/// path is a second way to speak for one account.
fn sign_or_exit(key_path: &Path, submission: inbox::Submission) -> inbox::SignedSubmission {
    let key = match logchain::load_or_create_key(key_path) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("cannot use account key {}: {}", key_path.display(), e);
            std::process::exit(EXIT_CANNOT_RUN);
        }
    };
    // This binary refuses the submission, and not the service. It applies the
    // same rule before the network call, and it gives the reason the exchange
    // would have given.
    if let Err(e) = inbox::validate_submission(&submission) {
        eprintln!("{}", e);
        std::process::exit(EXIT_CANNOT_RUN);
    }
    match inbox::sign_submission(&key, &submission) {
        Some(signed) => signed,
        None => {
            eprintln!("this submission is not on the engine's grid, so there is nothing to sign");
            std::process::exit(EXIT_CANNOT_RUN);
        }
    }
}

/// Loads the operator's signing key, or stops.
///
/// This never creates the key file, unlike an account key. The operator key is
/// the one key the exchange already trusts. A mistyped path that made a fresh
/// key would sign messages the sequencer refuses, and would leave no way to
/// drive the sequencer with the real key. See `operator::load_key`.
fn operator_signing_key_or_exit(path: &Path) -> SigningKey {
    match operator::load_key(path) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("cannot use operator key: {}", e);
            std::process::exit(EXIT_CANNOT_RUN);
        }
    }
}

/// Reads `--operator-key` into the one public key a sequencer publishes
/// operator messages for. A bad value stops the program before the port is
/// bound.
///
/// This stops and does not ignore the value, for the same reason as `--bind`
/// and `--ui-origin`. A sequencer that dropped a mistyped key would serve no
/// `/operator` route. The operator would then learn about the typo from a 404
/// on the message that opens the log.
fn operator_public_key_or_exit(spec: Option<&str>) -> Option<VerifyingKey> {
    let spec = spec?.trim();
    let bytes: Option<[u8; 32]> = logchain::from_hex(spec);
    match bytes.and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok()) {
        Some(key) => Some(key),
        None => {
            eprintln!(
                "--operator-key {} is not an Ed25519 public key. It takes 64 lowercase hex \
                 characters, the value `services --operator-public-key` prints for the key file \
                 the operator signs with",
                spec
            );
            std::process::exit(EXIT_CANNOT_RUN);
        }
    }
}

/// Reads the five root anchor flags into the contract the root hash is checked
/// against, or stops before anything is read. The root hash is one hash that
/// covers every message in the log.
///
/// The flags are read before the walk starts, for the same reason the chain
/// anchor is read first. A mistyped address, topic or selector must be a
/// sentence, and not a check that failed halfway through a history. None of
/// the three gives an error at the far end: a wrong selector answers empty,
/// and a wrong topic matches no logs. So an unchecked one would arrive as
/// "this contract holds no anchors".
fn root_anchor_source_or_exit(
    rpc: Option<&str>,
    contract: Option<&str>,
    from_block: Option<u64>,
    topic: Option<&str>,
    selector: Option<&str>,
) -> Option<services::anchor::RootAnchorSource> {
    let (rpc, contract) = rpc.zip(contract)?;
    let abi = match services::anchor::RootAnchorAbi::from_flags_and_env(topic, selector) {
        Ok(abi) => abi,
        Err(e) => {
            eprintln!("cannot use that root anchor: {}", e);
            std::process::exit(EXIT_CANNOT_RUN);
        }
    };
    // The warning comes before the run, and not after it. A value with the
    // right shape and the wrong content is the case nothing above catches, and
    // the report it produces looks like a contract with no anchors.
    for warning in abi.warnings() {
        eprintln!("{}", warning);
    }
    match services::anchor::RootAnchorSource::new(rpc, contract, from_block) {
        Ok(source) => Some(source.with_abi(abi)),
        Err(e) => {
            eprintln!("cannot use that root anchor: {}", e);
            std::process::exit(EXIT_CANNOT_RUN);
        }
    }
}

/// Reads `--trusted-proxy` into the addresses whose `X-Forwarded-For` header a
/// service believes, or stops before the port is bound.
///
/// This stops and does not skip the value, for the same reason as
/// `--ui-origin`. A mistyped proxy address matches nothing. Then every visitor
/// behind the proxy counts as one caller and shares one rate limit. The
/// operator would learn that from visitors locking each other out, and not
/// from a message.
fn trusted_proxies_or_exit(specs: &[String]) -> inbox::TrustedProxies {
    match inbox::TrustedProxies::parse(specs) {
        Ok(trusted) => trusted,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(EXIT_CANNOT_RUN);
        }
    }
}

/// Reads `--bind` into the address the service this run starts listens on, or
/// stops before the port is bound.
///
/// This stops and does not fall back to the default, for the same reason as
/// `--ui-origin` and `--trusted-proxy`. A service that kept listening on
/// `127.0.0.1` after a mistyped `--bind` is a container nothing outside it can
/// reach. The operator would learn that from the proxy answering 502, and not
/// from a message.
fn bind_addr_or_exit(spec: &str) -> IpAddr {
    match spec.trim().parse::<IpAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            eprintln!(
                "--bind {} is not an IP address. It takes an address to listen on, not a \
                 hostname, and not a port: 127.0.0.1 for this machine only, which is the \
                 default, or 0.0.0.0 for every address on this machine, which is what a \
                 container behind a reverse proxy needs",
                spec
            );
            std::process::exit(EXIT_CANNOT_RUN);
        }
    }
}

/// Reads `--ui-origin` into the web origins whose browsers may submit to the
/// service this run starts, or stops before the port is bound.
///
/// This stops and does not skip the value, for the same reason as
/// `--trusted-proxy` and `--bind`. An operator who mistyped the address of
/// their own UI would otherwise learn about the typo from a visitor whose
/// browser refused to send an order and said nothing.
fn ui_origins_or_exit(specs: &[String]) -> Vec<String> {
    match cors::parse_ui_origins(specs) {
        Ok(origins) => origins,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(EXIT_CANNOT_RUN);
        }
    }
}

/// The body the sequencer's `POST /order` and `POST /cancel` take: the fields
/// of the submission, with the account's key and signature beside them.
fn feed_body(signed: &inbox::SignedSubmission) -> serde_json::Value {
    // The nonce sits beside the terms it was signed with, and the key and the
    // signature sit beside both. A nonce is a number that makes one submission
    // different from another submission with the same terms. `--sign-only`
    // prints this object, so a caller who pipes it into curl sends a body the
    // sequencer can rebuild the signed statement from.
    let nonce = inbox::nonce_of(&signed.submission);
    // The session travels for the same reason as the nonce: it is a line of
    // the statement, and the sequencer rebuilds the statement from this body.
    let session = inbox::session_of(&signed.submission);
    // One expression names every field and builds the object, and nothing is
    // added after it. This replaced an
    // `as_object_mut().expect("a JSON object was just built")`. That line built
    // a value as an object, and then asked whether the value was an object.
    // Nothing asks now, because no step can turn it into anything else.
    match &signed.submission {
        inbox::Submission::Order {
            account,
            symbol,
            side,
            price,
            quantity,
            order_type,
            time_in_force,
            post_only,
            ..
        } => json!({
            "account": account,
            "symbol": symbol,
            "side": side,
            "price": price,
            "quantity": quantity,
            "nonce": nonce,
            "session": session,
            // All three are written, even when they hold their defaults. The
            // signature covers all three whatever they hold, so a body that
            // dropped a default term would be a body the sequencer rebuilds a
            // different statement from, and every such order would get a 401.
            "order_type": order_type,
            "time_in_force": time_in_force,
            "post_only": post_only,
            "public_key": signed.public_key,
            "signature": signed.signature,
        }),
        inbox::Submission::Cancel {
            account, target_id, ..
        } => json!({
            "account": account,
            "target_id": target_id,
            "nonce": nonce,
            "session": session,
            "public_key": signed.public_key,
            "signature": signed.signature,
        }),
    }
}

/// The session the sequencer at `feed_url` is on, or a message and a stop.
///
/// Every account statement names the log it is for, and only the sequencer
/// knows which log that is. So `--submit` and `--cancel` read `GET /head`
/// before they sign. `--sign-only` reads it too: there is nothing to sign
/// until the session is known.
///
/// A sequencer that cannot be reached stops the command. The alternative is to
/// sign for a guessed session, which produces a body that is refused with 401
/// and looks like a broken key.
async fn session_or_exit(feed_url: &str) -> String {
    #[derive(serde::Deserialize)]
    struct Head {
        session: String,
    }

    let url = format!("{}/head", feed_url.trim_end_matches('/'));
    let answer = reqwest::Client::new().get(&url).send().await;
    let head: Head = match answer {
        Ok(res) if res.status().is_success() => match res.json().await {
            Ok(head) => head,
            Err(e) => {
                eprintln!("{} did not answer with a signed head: {}", url, e);
                std::process::exit(EXIT_CANNOT_RUN);
            }
        },
        Ok(res) => {
            eprintln!(
                "{} answered {}, so this command cannot learn which log to sign for",
                url,
                res.status()
            );
            std::process::exit(EXIT_CANNOT_RUN);
        }
        Err(e) => {
            eprintln!(
                "cannot reach the sequencer at {} to read its session: {}. Every submission is \
                 signed for one log, so there is nothing to sign until that log names itself",
                url,
                reason(&e)
            );
            std::process::exit(EXIT_CANNOT_RUN);
        }
    };
    head.session
}

/// The three order terms `--order-terms` names, or a message and a stop.
///
/// The names are the Trade panel's names, so a person who sent an order from
/// the page and a person who sent one from here are talking about the same six
/// orders. Only combinations the exchange can act on have a name. The exchange
/// refuses post-only on a market order (`post_only_market`) and post-only on an
/// order that may not rest (`post_only_not_resting`), and neither can be asked
/// for here.
fn order_terms_or_exit(name: &str) -> (domain::OrderType, domain::TimeInForce, bool) {
    use domain::{OrderType, TimeInForce};
    match name {
        "limit" => (OrderType::Limit, TimeInForce::GoodTillCancel, false),
        "post-only" => (OrderType::Limit, TimeInForce::GoodTillCancel, true),
        "ioc" => (OrderType::Limit, TimeInForce::ImmediateOrCancel, false),
        "fok" => (OrderType::Limit, TimeInForce::FillOrKill, false),
        "market" => (OrderType::Market, TimeInForce::GoodTillCancel, false),
        "market-fok" => (OrderType::Market, TimeInForce::FillOrKill, false),
        other => {
            eprintln!(
                "--order-terms {:?} is not a kind of order this exchange runs. It takes limit, \
                 post-only, ioc, fok, market or market-fok",
                other
            );
            std::process::exit(EXIT_CANNOT_RUN);
        }
    }
}

/// The body the sequencer's `POST /operator` takes: the terms of the message,
/// with the operator's key and signature beside them.
///
/// This has the same shape as `feed_body`, for the same reason. `--sign-only`
/// prints this object, so a caller who pipes it into curl sends a body the
/// sequencer can rebuild the signed statement from.
fn operator_body(
    key: &SigningKey,
    session: &str,
    message: &domain::OrderMessage,
) -> serde_json::Value {
    let (kind, fields) = match operator::kind_and_fields(message) {
        Ok(both) => both,
        // These are the exchange's own rules, applied before the network
        // call, with the reason the sequencer would have given: a symbol it
        // refuses, or a step that is not a whole number of cents or tenths.
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(EXIT_CANNOT_RUN);
        }
    };
    let signature = operator::sign(key, kind, session, &fields);
    let public_key = logchain::to_hex(key.verifying_key().as_bytes());
    let nonce = message.nonce().unwrap_or_default();
    match message {
        domain::OrderMessage::ListSymbol {
            symbol,
            price_step,
            quantity_step,
            ..
        } => json!({
            "kind": "ListSymbol",
            "symbol": symbol,
            "price_step": price_step,
            "quantity_step": quantity_step,
            "nonce": nonce,
            "public_key": public_key,
            "signature": signature,
        }),
        domain::OrderMessage::DelistSymbol { symbol, .. } => json!({
            "kind": "DelistSymbol",
            "symbol": symbol,
            "nonce": nonce,
            "public_key": public_key,
            "signature": signature,
        }),
        domain::OrderMessage::EngineRule { version, .. } => json!({
            "kind": "EngineRule",
            "version": version,
            "nonce": nonce,
            "public_key": public_key,
            "signature": signature,
        }),
        domain::OrderMessage::New { .. } | domain::OrderMessage::Cancel { .. } => {
            eprintln!("this kind is published by a trader, not by the operator");
            std::process::exit(EXIT_CANNOT_RUN);
        }
    }
}

/// Reads the sequencer's session: the name of the log the operator signs for.
///
/// This reads the session every time, and does not take it from the command
/// line. The session is part of the signed statement, so a signature made for
/// one log verifies in no other log. A sequencer whose database was emptied
/// has a new session, and that is the case a value typed once by hand would
/// get wrong.
async fn feed_session_or_exit(feed_url: &str) -> String {
    let url = format!("{}/head", feed_url);
    let res = match reqwest::get(&url).await {
        Ok(res) => res,
        Err(e) => {
            eprintln!("cannot reach the feed at {}: {}", url, reason(&e));
            std::process::exit(EXIT_CANNOT_RUN);
        }
    };
    if !res.status().is_success() {
        eprintln!(
            "{} answered {}, so there is no session to sign for",
            url,
            res.status()
        );
        std::process::exit(EXIT_CANNOT_RUN);
    }
    let head: serde_json::Value = match res.json().await {
        Ok(head) => head,
        Err(e) => {
            eprintln!("cannot read what {} served: {}", url, reason(&e));
            std::process::exit(EXIT_CANNOT_RUN);
        }
    };
    match head.get("session").and_then(|session| session.as_str()) {
        Some(session) => session.to_string(),
        None => {
            eprintln!(
                "{} served a head with no session, so this is not a feed that names its history",
                url
            );
            std::process::exit(EXIT_CANNOT_RUN);
        }
    }
}

/// Says whether the exchange already trades this symbol, before a listing or a
/// delisting is published for it.
///
/// This is advice and not a rule, in the same way `--submit` refuses early. It
/// saves a network call on the common mistake, and it changes nothing about
/// what is allowed. The message is published either way.
///
/// The check asks the exchange (`--matcher-url`) and not the sequencer. The
/// sequencer holds no list of traded symbols and must not be given one. The
/// sequencer does not run messages, so any list it held would be a second
/// list, built from the same log and free to disagree. The rule that decides
/// whether a listing takes effect lives in the exchange and in the checker,
/// where the log runs again.
///
/// The exchange's answer comes from its own `--poll-ms` loop, so the answer
/// can be one poll old. That is another reason this is advice: a listing
/// published in the last 200 ms is not on `/market` yet.
async fn warn_about_the_symbol(matcher_url: &str, symbol: &str, listing: bool) {
    let url = format!("{}/market", matcher_url);
    let listed = market_of(matcher_url).await.and_then(|market| {
        market
            .get("symbols")
            .and_then(|symbols| symbols.as_array())
            .map(|symbols| {
                symbols
                    .iter()
                    .any(|listed| listed.get("symbol").and_then(|s| s.as_str()) == Some(symbol))
            })
    });
    match (listed, listing) {
        (Some(true), true) => eprintln!(
            "{} already trades on the exchange at {}. Publishing this listing anyway: what a \
             second listing for one symbol means is decided where the log is replayed",
            symbol, matcher_url
        ),
        (Some(false), false) => eprintln!(
            "{} does not trade on the exchange at {}. Publishing this delisting anyway: what a \
             delisting of a symbol that is not listed means is decided where the log is replayed",
            symbol, matcher_url
        ),
        (None, _) => eprintln!(
            "cannot read {}, so this is published without checking whether {} already trades",
            url, symbol
        ),
        _ => {}
    }
}

/// Says whether the exchange can run the rule set about to be published.
///
/// The number comes from the running exchange, on the same `/market` the
/// listing warning reads. It never comes from a constant in this binary. A
/// constant here would be a third copy of a number the exchange and the
/// checker each keep. On the day rule set 3 is added to those two and not to
/// this file, this command would refuse a message the exchange can run. Which
/// rule sets exist is a fact about what the exchange implements, so this asks
/// the exchange.
///
/// This reads the field `newest_rule_set`, the newest rule set that build can
/// run. It does not read `rule_set`, the rule set the log has put the exchange
/// in. The two differ on every correct upgrade, because the exchange stays in
/// the old rule set until the message lands. Reading `rule_set` warned on
/// `--engine-rule 2` against a build that runs rule set 2 as loudly as it
/// warned on `--engine-rule 99`. So the warning fired on the correct command,
/// the operator learned to skip it, and then it said nothing about the typo it
/// exists to catch.
///
/// This is advice, and the message is published either way. That choice has a
/// cost worth naming. `--engine-rule 99` now reaches the log if the operator
/// publishes it past this warning, and every checker then stops on that
/// message with "cannot interpret" instead of passing. The other choice costs
/// more because it is silent: a command that refuses correct messages after a
/// rule set is added, for a reason nobody outside can see.
async fn warn_about_the_rule_set(matcher_url: &str, version: u32) {
    let url = format!("{}/market", matcher_url);
    let newest = market_of(matcher_url)
        .await
        .and_then(|market| market.get("newest_rule_set").and_then(|set| set.as_u64()));
    match newest {
        Some(newest) if u64::from(version) > newest => eprintln!(
            "the exchange at {} runs rule sets up to {}, and this publishes rule set {}. \
             Publishing it anyway: an exchange that cannot run a rule set keeps matching under \
             the one it has, and a checker that cannot replay it stops on this message",
            matcher_url, newest, version
        ),
        // No exchange at that address, and an exchange too old to serve the
        // field, mean the same thing to the caller: this run publishes without
        // the check. Neither one stops the command.
        None => eprintln!(
            "cannot read newest_rule_set from {}, so this is published without checking which \
             rule sets the exchange can run",
            url
        ),
        _ => {}
    }
}

/// Reads `GET /market` from the exchange, or answers `None` when it cannot be
/// read.
///
/// The two warnings above share this function. `None` covers every way the
/// answer is unusable: no exchange at that address, a status that is not 2xx,
/// or a body that is not JSON. All of them mean the same thing to the caller.
/// This run publishes without that check.
async fn market_of(matcher_url: &str) -> Option<serde_json::Value> {
    let res = reqwest::get(format!("{}/market", matcher_url)).await.ok()?;
    if !res.status().is_success() {
        return None;
    }
    res.json::<serde_json::Value>().await.ok()
}

/// Sends one signed operator message to the sequencer, or prints the message
/// when `--sign-only` is set.
async fn publish_operator_or_exit(feed_url: &str, body: serde_json::Value, sign_only: bool) {
    if sign_only {
        println!("{}", body);
        return;
    }
    let url = format!("{}/operator", feed_url);
    let client = reqwest::Client::new();
    let res = match client.post(&url).json(&body).send().await {
        Ok(res) => res,
        Err(e) => {
            eprintln!("cannot reach the feed at {}: {}", url, reason(&e));
            std::process::exit(EXIT_CANNOT_RUN);
        }
    };
    if res.status().is_success() {
        let text = res.text().await.unwrap_or_default();
        println!("Operator message published: {}", text);
    } else {
        // The status on its own hides three answers the caller must tell
        // apart: a sequencer that names no operator (404), a sequencer that
        // names another key (403), and a signature made for another log (401).
        let status = res.status();
        let detail = res.text().await.unwrap_or_default();
        eprintln!(
            "Failed to publish the operator message. Status: {}, {}",
            status, detail
        );
        std::process::exit(EXIT_REFUSED);
    }
}

/// The command-line arguments of this program.
/// `clap` reads them and checks them.
/// The main commands exclude each other. More than one gives an error that
/// says so, and not a command skipped without a word.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(group(
    ArgGroup::new("command").args([
        "start_feed",
        "start_matcher",
        "submit",
        "cancel",
        "orders",
        "verify",
        "start_bot",
        "backtest_bot",
        "start_inbox",
        "start_validator",
        "audit",
        "audit_url",
        "list_symbol",
        "delist_symbol",
        "engine_rule",
        "operator_public_key",
        "stdio_engine",
    ]),
))]
struct Args {
    /// Starts the sequencer: it puts messages in order, signs the log, serves
    /// the messages, and generates simulated orders.
    #[arg(long)]
    start_feed: bool,

    /// The port the sequencer's API server listens on.
    #[arg(long, default_value_t = 3000)]
    feed_port: u16,

    /// Starts the exchange: it reads the sequencer's messages, matches a buy
    /// with a sell when the buy price is at or above the sell price, and serves
    /// the state of the market.
    #[arg(long)]
    start_matcher: bool,

    /// The base URL of the sequencer, http://127.0.0.1:3000 when not given.
    /// Everything that reads the sequencer calls this address: the exchange,
    /// the validator, the bot, --verify, --audit, and
    /// --submit/--cancel/--orders.
    ///
    /// --audit-url is the exception. Left unset, it asks the exchange it audits
    /// where the sequencer is (GET /config) instead of using that default,
    /// because a stranger who audits a remote exchange runs no sequencer on
    /// their own machine. Set it and it wins, which is what an auditor who
    /// reaches the sequencer through a tunnel or a mirror needs.
    // This field is an `Option` and carries no clap default value, for that
    // same reason. With a default filled in, "the auditor named an address" and
    // "nobody named one" are the same string, so --audit-url cannot tell
    // whether it may ask the exchange. `main` applies `DEFAULT_FEED_URL` once,
    // for every command that is not --audit-url.
    #[arg(long, value_name = "URL")]
    feed_url: Option<String>,

    /// The port the exchange's API server listens on.
    #[arg(long, default_value_t = 3001)]
    matcher_port: u16,

    /// How often the exchange asks the sequencer for new messages, in
    /// milliseconds.
    #[arg(long, default_value_t = 200)]
    poll_ms: u64,

    /// Runs the exchange behind the market-harness stdio protocol. It reads
    /// that harness's commands on standard input and writes that harness's
    /// events on standard output, so the harness can score this exchange with
    /// checks this repository did not write. There is no server, no sequencer
    /// and no database. See `services/src/stdio_engine.rs`.
    #[arg(long)]
    stdio_engine: bool,

    /// How many messages a second the stdio protocol counts, for turning a
    /// command number into a millisecond. The harness has no clock, and the
    /// collar's reference price is an average over the last 30 seconds. The
    /// incident ran at 6 messages a second.
    #[arg(long, default_value_t = 6.0)]
    stdio_messages_per_second: f64,

    /// SQLite file the exchange keeps its state in. On start the exchange
    /// continues the run this file was left in, whether the last process
    /// stopped or crashed.
    #[arg(long, default_value = "state.db")]
    state_db: PathBuf,

    /// Turns off the state database. The exchange then starts with empty books
    /// and runs the whole log again after every restart.
    #[arg(long)]
    no_state_db: bool,

    /// Stops using the run stored in the state database and starts a new run.
    /// The old run's trades and books stay in the file.
    #[arg(long)]
    reset_state: bool,

    /// Compares the newest run's trades in the state database with the
    /// sequencer messages that produced them. Takes the database path;
    /// defaults to state.db.
    #[arg(long, num_args = 0..=1, default_missing_value = "state.db", value_name = "STATE_DB")]
    verify: Option<PathBuf>,

    /// SQLite file the sequencer writes every message to before it publishes
    /// the message. On start the sequencer reloads its log and continues the
    /// same message numbers and the same session, so readers cannot tell that
    /// it restarted.
    #[arg(long, default_value = "feed.db")]
    feed_db: PathBuf,

    /// Turns off the sequencer database. The sequencer then keeps the log in
    /// memory only, and a restart loses every published message.
    #[arg(long)]
    no_feed_db: bool,

    /// Starts the separate service: it records orders, and the sequencer does
    /// not control it. The sequencer empties it on every tick. An entry the
    /// sequencer leaves pending past the deadline is listed in `overdue` by
    /// GET /status. That list is the sign the sequencer is holding orders back.
    #[arg(long)]
    start_inbox: bool,

    /// The port the separate service listens on.
    #[arg(long, default_value_t = 3002)]
    inbox_port: u16,

    /// SQLite file the separate service records submissions in.
    #[arg(long, default_value = "inbox.db")]
    inbox_db: PathBuf,

    /// How long the sequencer may leave an entry pending before the separate
    /// service lists it in `overdue`, in milliseconds.
    #[arg(long, default_value_t = services::inbox::DEFAULT_DEADLINE_MS)]
    inbox_deadline_ms: u64,

    /// The sequencer public key (hex) whose marks the separate service accepts,
    /// used with --start-inbox. `POST /mark` is the only way an entry stops
    /// being pending, so only the sequencer may call it. Leave this out and the
    /// separate service pins the key in `--feed-url`'s signed head, on first
    /// contact.
    #[arg(long)]
    feed_key: Option<String>,

    /// Where the separate service is. With --start-feed, this is the service
    /// the sequencer empties; leave it out to run the sequencer with no
    /// separate service. With --submit --via-inbox, this is the service to
    /// submit to; leave it out and the submission goes to 127.0.0.1 on
    /// --inbox-port, which only reaches a service on this machine.
    #[arg(long)]
    inbox_url: Option<String>,

    /// The web origins whose browsers may submit, comma separated. Used with
    /// --start-feed and --start-inbox, the two services a browser posts to. A
    /// browser sends a submission to an origin other than the one the page came
    /// from only when the receiving service says it may. The UI is never on
    /// either origin: on this machine the exchange's port serves it, and behind
    /// a reverse proxy another hostname or path serves it. Name the exact
    /// address visitors load the UI from, with the scheme and any port. Nothing
    /// else is accepted, and no wildcard is allowed. Pass an empty value to
    /// allow no origin.
    #[arg(long, value_delimiter = ',', default_value = cors::DEFAULT_UI_ORIGINS, value_name = "ORIGIN,...")]
    ui_origin: Vec<String>,

    /// The addresses whose X-Forwarded-For header a service believes, comma
    /// separated: the reverse proxy these services run behind. Used with
    /// --start-feed and --start-inbox, the two that limit the submission rate
    /// per caller. Takes an address (172.17.0.3) or a network in prefix form
    /// (172.17.0.0/16), which is what a proxy in a Docker bridge network needs,
    /// because the proxy address changes when the container restarts.
    ///
    /// Empty by default. Empty means the service takes the socket address as
    /// the caller and ignores the header. Anyone can write that header, so a
    /// service that believed it from an address that is not a named proxy would
    /// let one caller get a fresh rate limit on every request.
    #[arg(long, value_delimiter = ',', value_name = "ADDR[/PREFIX],...")]
    trusted_proxy: Vec<String>,

    /// The address the service this run starts listens on: the sequencer, the
    /// exchange, the separate service, or a validator. One flag and not four,
    /// because one run starts one service, and each service already has its own
    /// port flag.
    ///
    /// Defaults to 127.0.0.1, which is this machine only and is what every
    /// local run wants. Set 0.0.0.0 to listen on every address of this machine.
    /// A container needs that: a process bound to 127.0.0.1 inside one
    /// container's network namespace cannot be reached from a reverse proxy in
    /// another one, so the proxy gets a connection refused. On a host, 0.0.0.0
    /// publishes the service to whatever network the host is on, and the
    /// service says so at startup.
    #[arg(long, default_value = "127.0.0.1", value_name = "ADDR")]
    bind: String,

    /// The sequencer address the UI tells a browser to submit to, used with
    /// --start-matcher. Defaults to --feed-url, which is right when the browser
    /// reaches the sequencer at the same address this exchange does. Behind a
    /// reverse proxy the browser does not: set this to the public address, and
    /// set the sequencer's --ui-origin to the public address of this UI.
    #[arg(long, value_name = "URL")]
    public_feed_url: Option<String>,

    /// The address the UI tells a browser to submit to when the visitor picks
    /// the separate service, used with --start-matcher. Defaults to
    /// --inbox-url. Leave both unset and the UI offers no path through the
    /// separate service at all. That is right when no separate service runs:
    /// the page cannot guess the address, and a wrong guess would look to a
    /// visitor like the separate service being down. Behind a reverse proxy
    /// this is the public address, and the separate service's own --ui-origin
    /// must name the public address of this UI.
    #[arg(long, value_name = "URL")]
    public_inbox_url: Option<String>,

    /// Sends --submit through the separate service instead of the sequencer's
    /// own /order endpoint. This shows the separate service works from end to
    /// end.
    #[arg(long)]
    via_inbox: bool,

    /// Starts a validator: it follows the sequencer on its own, computes the
    /// chain hash again, and signs which messages it saw, in which order.
    /// Readers count these signed statements to find the highest position that
    /// enough validators agree on, and the log up to there is final.
    #[arg(long)]
    start_validator: bool,

    /// The port a validator serves /attest on.
    #[arg(long, default_value_t = 3010)]
    validator_port: u16,

    /// SQLite file a validator keeps its read position in. The validator's
    /// signing key sits beside that file, in a file whose name ends in .key.
    #[arg(long, default_value = "validator.db")]
    validator_db: PathBuf,

    /// The validator /attest URLs the exchange reads to count how many
    /// validators agree, comma separated, used with --start-matcher.
    #[arg(long, value_delimiter = ',')]
    validators: Vec<String>,

    /// Runs the newest run again from the sequencer's log, and checks every
    /// claim the exchange wrote down: state roots and trades. Takes the state
    /// database path; defaults to state.db.
    #[arg(long, num_args = 0..=1, default_missing_value = "state.db", value_name = "STATE_DB")]
    audit: Option<PathBuf>,

    /// Audits this run of the state database instead of the newest run. One
    /// file keeps every run it ever had, because the exchange opens a new run
    /// after a sequencer restart. Without this flag only the newest run could
    /// ever be checked. The audit lists the other runs and how much of each one
    /// the claims cover.
    #[arg(long, value_name = "RUN_ID", requires = "audit")]
    audit_run: Option<i64>,

    /// Audits a running exchange over HTTP instead of a local database file.
    /// Takes the exchange's base URL. The audit reads the claims and the trade
    /// log from the exchange's own endpoints, checks every claim's signature
    /// against the key the exchange publishes, and runs the sequencer's signed
    /// log again against those claims, one page at a time. This needs nothing
    /// from the operator beyond the endpoints they already serve.
    #[arg(long, num_args = 0..=1, default_missing_value = "http://127.0.0.1:3001", value_name = "MATCHER_URL")]
    audit_url: Option<String>,

    /// The exchange public key (hex) --audit-url requires every claim to be
    /// signed with. Without it the audit takes the key the exchange serves on
    /// first contact. That shows the claims agree with each other, but not who
    /// made them.
    #[arg(long, value_name = "HEX", requires = "audit_url")]
    matcher_key: Option<String>,

    /// The ExchangeAnchor contract an audit checks this exchange against.
    ///
    /// Every other check an audit makes only shows that the exchange agrees
    /// with itself. An operator who deleted their databases and ran a different
    /// log passes all of those checks. This is the one check that such an
    /// operator does not pass. The contract holds (message id, feed session,
    /// chain hash, state root), written at intervals by a program outside the
    /// exchange. The audit runs today's log again and either produces those
    /// same values at that position, or fails and prints both.
    ///
    /// Left unset, the audit runs exactly as it runs with no anchor. Set, an
    /// anchor that cannot be read is a failure and not a pass, because an
    /// anchor nobody can reach is a claim nobody checked.
    ///
    /// The address comes from the auditor, never from the exchange. An operator
    /// who could choose which contract their own audit reads could choose an
    /// empty one. Anyone may run their own anchor sender against their own
    /// contract, and audit against that contract instead.
    #[arg(long, value_name = "0xADDRESS", requires = "anchor_rpc")]
    anchor_contract: Option<String>,

    /// The JSON-RPC endpoint the anchor contract is read over, for example
    /// https://sepolia.base.org. Required with --anchor-contract, and it has no
    /// default. Which chain an anchor lives on is not something this binary
    /// decides for an auditor.
    #[arg(long, value_name = "URL", requires = "anchor_contract")]
    anchor_rpc: Option<String>,

    /// The block the anchor contract was deployed in, when the auditor knows
    /// it. The audit checks every anchor the contract ever wrote, and not only
    /// the newest one, so it reads the contract's whole event log. Public
    /// endpoints limit how many blocks one `eth_getLogs` call may cover, so the
    /// audit reads that log backwards in chunks. Without this flag the scan
    /// stops as soon as it has found as many anchors as the contract itself
    /// says exist. That is exact, but it reads more chunks than it has to. With
    /// this flag the scan stops at the deployment block. The block number is
    /// published in `anchor/deployment.json`.
    #[arg(long, value_name = "BLOCK", requires = "anchor_contract")]
    anchor_from_block: Option<u64>,

    /// The `Anchored` event topic the contract's log is filtered on, as 0x and
    /// 64 lowercase hex characters. An event topic is the hash that names one
    /// kind of event. Also read from the ANCHORED_TOPIC environment variable.
    /// The flag wins over the variable, and both win over the built-in default.
    ///
    /// The default is what the deployed contract writes, so an audit that sets
    /// nothing is a correct audit. Set this only for a contract built from a
    /// different event signature. A topic with the right shape and the wrong
    /// value matches no logs at all, which looks like a contract that holds no
    /// anchors, so an override is printed on stderr before the audit runs.
    #[arg(long, value_name = "0xTOPIC", requires = "anchor_contract")]
    anchored_topic: Option<String>,

    /// The `latest()` function selector the newest anchor is read with, as 0x
    /// and 8 lowercase hex characters. A function selector is the short hash
    /// that names one function of a contract. Also read from the
    /// LATEST_SELECTOR environment variable, in the same order: flag, then
    /// environment variable, then the built-in default.
    ///
    /// As with --anchored-topic, the default is the deployed contract's
    /// selector, and only a contract built from different code needs another
    /// one.
    #[arg(long, value_name = "0xSELECTOR", requires = "anchor_contract")]
    latest_selector: Option<String>,

    /// The ExchangeRootAnchor contract the checker and the audit check the root
    /// hash against. The root hash is one hash that covers every message in the
    /// log.
    ///
    /// The other contract holds a chain hash. To show that one trade sits
    /// inside a chain hash, a reader needs every message in that window. This
    /// contract holds (tree size, message id, feed session, root hash, state
    /// root). So the root a stranger checks is the root the sequencer signs in
    /// its tree head, and the root every proof of inclusion ends at. A proof of
    /// inclusion is a short list of hashes that shows one message is in the log.
    ///
    /// Left unset, the tools say the anchored roots were not checked, and go
    /// on. Set, a root that does not match is a failure: the tool read the
    /// messages, it read the root, and the two disagree.
    ///
    /// The address comes from the auditor, for the reason written on
    /// --anchor-contract.
    #[arg(long, value_name = "0xADDRESS", requires = "root_anchor_rpc")]
    root_anchor_contract: Option<String>,

    /// The JSON-RPC endpoint the root anchor contract is read over, for example
    /// https://sepolia.base.org. Required with --root-anchor-contract, and it
    /// has no default, for the reason written on --anchor-rpc.
    #[arg(long, value_name = "URL", requires = "root_anchor_contract")]
    root_anchor_rpc: Option<String>,

    /// The block the root anchor contract was deployed in, when the auditor
    /// knows it. Same meaning and same reason as --anchor-from-block. The block
    /// number is published in `anchor/deployment.json`.
    #[arg(long, value_name = "BLOCK", requires = "root_anchor_contract")]
    root_anchor_from_block: Option<u64>,

    /// The `AnchoredRoot` event topic the contract's log is filtered on, as 0x
    /// and 64 lowercase hex characters. Also read from the ANCHORED_ROOT_TOPIC
    /// environment variable. The flag wins over the variable, and both win over
    /// the built-in default.
    ///
    /// The default is what the deployed contract writes. A topic with the right
    /// shape and the wrong value matches no logs, which looks like a contract
    /// that holds no anchors, so an override is printed on stderr before the
    /// run.
    #[arg(long, value_name = "0xTOPIC", requires = "root_anchor_contract")]
    anchored_root_topic: Option<String>,

    /// The `latest()` function selector the newest root anchor is read with, as
    /// 0x and 8 lowercase hex characters. Also read from the
    /// ROOT_LATEST_SELECTOR environment variable, in the same order: flag, then
    /// environment variable, then the built-in default.
    #[arg(long, value_name = "0xSELECTOR", requires = "root_anchor_contract")]
    root_latest_selector: Option<String>,

    /// The number of simulated accounts that place orders on the sequencer.
    #[arg(long, default_value_t = 10)]
    num_accounts: u32,

    /// The mean number of messages the sequencer generates per second.
    ///
    /// It is a mean because the generator switches between three activity
    /// states. Above 24 a second the three are 24, this number, and
    /// `2 * this - 24`, each holding a third of the time. At 24 and below there
    /// is one state and the rate is fixed. See `feed::generate::Activity`.
    #[arg(long, default_value_t = 2.0)]
    rate: f64,

    /// Submits a new order. Takes the account id, the symbol, the side, the
    /// price and the quantity.
    ///
    /// The signed statement names the sequencer's session, so this command
    /// reads GET /head before it signs. That is true of --sign-only too: there
    /// is no session to sign for until the sequencer names one.
    #[arg(long, num_args = 5, value_names = ["ACCOUNT_ID", "SYMBOL", "SIDE", "PRICE", "QUANTITY"])]
    submit: Option<Vec<String>>,

    /// The terms of the order --submit sends. One of the six the Trade panel
    /// offers, by the same names:
    ///
    /// limit (the default), post-only, ioc, fok, market, market-fok.
    ///
    /// The three underlying fields are order_type, time_in_force and
    /// post_only. This flag names the combinations that can do something. The
    /// exchange always refuses two of them: post-only on a market order, and
    /// post-only on an order that may not rest. Those two have no name here,
    /// so they cannot be asked for.
    ///
    /// A market order carries the worst price it may fill at, and that is the
    /// price argument of --submit. The exchange bounds it again to two percent
    /// from its own reference price.
    #[arg(long, default_value = "limit", value_name = "TERMS")]
    order_terms: String,

    /// Submits a cancel. Takes the account id and the id of the order to
    /// cancel.
    #[arg(long, num_args = 2, value_names = ["ACCOUNT_ID", "ORDER_ID"])]
    cancel: Option<Vec<String>>,

    /// The Ed25519 key file --submit and --cancel sign with. It is created on
    /// first use. An account belongs to whoever submitted for it first, so the
    /// same account id must always use the same file.
    #[arg(long, default_value = "account.key", value_name = "FILE")]
    account_key: PathBuf,

    /// The Ed25519 key file the bot signs its own submissions with. It is
    /// created on first use. Used with --start-bot.
    #[arg(long, default_value = "bot.key", value_name = "FILE")]
    bot_key: PathBuf,

    /// Lists a symbol, so the exchange trades it. Takes the price step and the
    /// quantity step: every price must be a whole number of price steps, and
    /// every quantity a whole number of quantity steps. Signed with
    /// --operator-key-file and published on the sequencer's /operator endpoint.
    #[arg(long, num_args = 3, value_names = ["SYMBOL", "PRICE_STEP", "QUANTITY_STEP"])]
    list_symbol: Option<Vec<String>>,

    /// Delists a symbol, so the exchange stops trading it. Every resting order
    /// in its book is cancelled where the log runs again. A resting order is an
    /// order that waits in the book.
    #[arg(long, num_args = 1, value_name = "SYMBOL")]
    delist_symbol: Option<Vec<String>>,

    /// Publishes the rule set that the messages after it run under. Rule set 1
    /// is the set of rules the log has run under since message 1.
    #[arg(long, num_args = 1, value_name = "VERSION")]
    engine_rule: Option<Vec<String>>,

    /// Prints the public key of --operator-key-file. That value is what a
    /// sequencer takes as --operator-key. This reads the key file and publishes
    /// nothing.
    #[arg(long)]
    operator_public_key: bool,

    /// The Ed25519 key file --list-symbol, --delist-symbol and --engine-rule
    /// sign with. This program never creates it. It is the one key the exchange
    /// trusts, so a mistyped path is an error and not a new key.
    #[arg(long, default_value = "operator.key", value_name = "FILE")]
    operator_key_file: PathBuf,

    /// The operator public key (hex) whose messages the sequencer publishes,
    /// used with --start-feed. Without it the sequencer serves no /operator
    /// endpoint at all, and it generates orders from its first tick. With it,
    /// the sequencer reserves the opening for the operator's engine rule and
    /// compiled-market listings. User, inbox and generated traffic waits until
    /// that opening is complete.
    #[arg(long, value_name = "HEX")]
    operator_key: Option<String>,

    /// Where the exchange is, used with --list-symbol and --delist-symbol to
    /// warn when a symbol already trades, or does not trade yet. Leave it out
    /// and the check goes to 127.0.0.1 on --matcher-port, which only reaches an
    /// exchange on this machine.
    #[arg(long, value_name = "URL")]
    matcher_url: Option<String>,

    /// Prints the signed request body for --submit or --cancel instead of
    /// sending it. The body can be piped into curl or any other client:
    ///
    ///   curl -X POST http://127.0.0.1:3000/order -H 'Content-Type: application/json' \
    ///     -d "$(services --submit 1000 ETH-USDC Buy 100.25 5 --sign-only)"
    #[arg(long)]
    sign_only: bool,

    /// Fetches and prints the newest n messages from the sequencer.
    /// Defaults to 10 when no number is given.
    #[arg(long, num_args = 0..=1, default_missing_value = "10")]
    orders: Option<String>,

    /// Runs the trading bot against a running sequencer. The bot reads the
    /// messages, rebuilds the book, works out a fair value for each symbol, and
    /// trades against a resting order whose price is better for the bot than
    /// that fair value.
    #[arg(long)]
    start_bot: bool,

    /// Runs the bot against generated messages and prints what it made. This
    /// needs no sequencer and no exchange. Takes the number of messages to
    /// simulate.
    #[arg(long, num_args = 0..=1, default_missing_value = "120000", value_name = "MESSAGES")]
    backtest_bot: Option<usize>,

    /// Seeds the backtest generator, so a run can be repeated exactly.
    #[arg(long, default_value_t = 1)]
    backtest_seed: u64,

    /// The account the bot trades as.
    #[arg(long, default_value_t = 999)]
    bot_account: u32,

    /// How much better than fair value a resting price must be before the bot
    /// trades against it, in basis points. One basis point is one hundredth of
    /// one percent.
    #[arg(long, default_value_t = 6.0)]
    bot_take_bps: f64,

    /// How often the bot asks the sequencer for new messages, in milliseconds.
    #[arg(long, default_value_t = 50)]
    bot_poll_ms: u64,

    /// How far better than fair value the bot places its own resting orders, in
    /// basis points. Zero, the default, means the bot places no resting orders
    /// and only trades against the book. Resting orders were measured here and
    /// lose money in proportion to the size placed. The flag exists so that
    /// measurement can be repeated.
    #[arg(long, default_value_t = 0.0)]
    bot_quote_bps: f64,

    /// The size of one resting order the bot places, in units.
    #[arg(long, default_value_t = 5.0)]
    bot_quote_units: f64,

    /// The largest position the bot holds per symbol, counted in the second
    /// token of the pair: "BTC-USDC=20000,ETH-USDC=10000,MERKLE-USDC=5000". A
    /// symbol left out is not traded at all. Defaults to those three values.
    #[arg(long, value_name = "SYMBOL=AMOUNT,...")]
    bot_caps: Option<String>,
}

/// What an audit reads: a running exchange, or a database file.
///
/// `--audit` and `--audit-url` are in one clap group, so at most one of them is
/// ever set. This type writes that fact down. The audit branch used to test
/// both `Option`s to decide that it would run, and then unwrap one of them
/// again to find out which one. The second step had no answer for the state
/// where neither is set, so it carried an
/// `expect("one of the two is set")`. One value instead of two options leaves
/// no such state to answer for: the branch starts with the thing to audit
/// already in hand.
enum AuditTarget {
    /// `--audit-url`: an exchange that is running, checked over HTTP.
    Live(String),
    /// `--audit`: a state database on this machine.
    Local(PathBuf),
}

/// The entry point of the program.
/// It reads the command-line arguments and runs the command they name.
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    // The sequencer address for every command whose caller is expected to know
    // where the sequencer is. --audit-url is the one command that is not. It
    // reads `args.feed_url` itself, so "unset" reaches it as `None` and it can
    // ask the exchange instead of calling this default.
    let feed_url = args
        .feed_url
        .clone()
        .unwrap_or_else(|| DEFAULT_FEED_URL.to_string());
    // Where the operator commands ask whether a symbol already trades. The
    // same fallback as --inbox-url: this machine, on the port that program's
    // own flag names.
    let matcher_url = args
        .matcher_url
        .clone()
        .unwrap_or_else(|| format!("http://127.0.0.1:{}", args.matcher_port));
    // The two audit flags become one value here, before anything chooses a
    // branch. Both flags are in the same clap group, so this match has no case
    // where both are set. `--audit-url` comes first, which is the order the
    // branch below already read them in.
    let audit_target = match (args.audit_url, args.audit) {
        (Some(matcher_url), _) => Some(AuditTarget::Live(matcher_url)),
        (_, Some(state_db)) => Some(AuditTarget::Local(state_db)),
        _ => None,
    };

    // The argument the caller gave decides which branch runs. The program runs
    // one main command at a time.
    if let Some(submit_args) = args.submit {
        // The --submit command. It reads the arguments and sends a new order
        // to the sequencer.
        let account: u32 = arg_or_exit(
            "--submit",
            "account id",
            &submit_args[0],
            "a whole number from 0 to 4294967295",
        );
        let symbol = submit_args[1].to_uppercase();
        // Not `arg_or_exit`. `Side`'s own parse error already names the value,
        // and what the caller needs is the list of words `Side` accepts.
        let side = match domain::Side::from_str(&submit_args[2]) {
            Ok(side) => side,
            Err(e) => {
                eprintln!(
                    "--submit: {}. It takes Buy or Sell; bid, ask, b and s also work",
                    e
                );
                std::process::exit(EXIT_CANNOT_RUN);
            }
        };
        let price: f64 = arg_or_exit("--submit", "price", &submit_args[3], "a decimal number");
        let quantity: f64 =
            arg_or_exit("--submit", "quantity", &submit_args[4], "a decimal number");
        let (order_type, time_in_force, post_only) = order_terms_or_exit(&args.order_terms);
        // Read before anything is signed, and read from the sequencer even
        // when the order is going to the separate service. The statement names
        // the log the order is for, and the separate service is not that log.
        // It holds the order until the sequencer takes it.
        let session = session_or_exit(&feed_url).await;

        let signed = sign_or_exit(
            &args.account_key,
            inbox::Submission::Order {
                account,
                symbol,
                side,
                price,
                quantity,
                // One nonce per run. Two runs of --submit are two orders and
                // get two nonces. Sending the body that one run printed a
                // second time is still one order, and the sequencer says which
                // message that order already became.
                nonce: Some(inbox::new_nonce()),
                session: Some(session),
                order_type,
                time_in_force,
                post_only,
            },
        );
        // This path wraps the same signed submission and shows the separate
        // service works: the order reaches the market without ever touching the
        // sequencer's own submission endpoint. Both paths carry the same
        // signature over the same statement, and the sequencer checks that
        // signature again when it empties the separate service.
        let (url, body, channel) = if args.via_inbox {
            // Uses --inbox-url when it is set, so this reaches a deployed
            // separate service and not only one on this machine. The separate
            // service exists for a person the sequencer is refusing, and that
            // person is always somewhere else. A service that only the
            // operator's own machine can reach is a service only the operator
            // can submit to.
            (
                match &args.inbox_url {
                    Some(base) => format!("{}/submit", base.trim_end_matches('/')),
                    None => format!("http://127.0.0.1:{}/submit", args.inbox_port),
                },
                // This `expect` stays, and its message is the proof. The
                // conversion fails only for a `Serialize` that returns an
                // error, or for a map with keys that are not strings.
                // `SignedSubmission` is a struct of two `String`s and a
                // `Submission`, all derived. `validate_submission` above
                // refuses a price that is not a finite number, before the value
                // reaches here.
                //
                // The two ways to remove the `expect` are both worse. Building
                // this body by hand with `json!` copies the shape serde gives
                // the enum, the `{"submission":{"Order":{...}}}` tagging,
                // into this file, where it goes stale the day a field is added.
                // `json!(&signed)` only hides the same conversion inside the
                // macro, which unwraps it there.
                serde_json::to_value(&signed).expect("a signed submission serializes"),
                "inbox",
            )
        } else {
            (format!("{}/order", feed_url), feed_body(&signed), "feed")
        };
        if args.sign_only {
            println!("{}", body);
            return Ok(());
        }
        let client = reqwest::Client::new();
        // A call that got no answer is not a refused order. Nobody saw the
        // caller's order, so this prints the address that did not answer and
        // stops, and the exit status says the command could not run.
        let res = match client.post(&url).json(&body).send().await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("cannot reach the {} at {}: {}", channel, url, reason(&e));
                std::process::exit(EXIT_CANNOT_RUN);
            }
        };

        if res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            println!("Order submitted to {} successfully: {}", channel, text);
        } else {
            // The status on its own hides the two answers a caller most needs
            // to tell apart: a signature that does not verify, and an account
            // already pinned to another person's key.
            let status = res.status();
            let detail = res.text().await.unwrap_or_default();
            // This goes to stderr, like every other refusal here, because a
            // refusal is not this command's output.
            // `services --submit ... > receipt.json` leaves the file empty when
            // the service turned the order down, instead of filling it with a
            // sentence the next step would try to parse.
            eprintln!("Failed to submit order. Status: {}, {}", status, detail);
            std::process::exit(EXIT_REFUSED);
        }
    } else if let Some(cancel_args) = args.cancel {
        // The --cancel command. It reads the arguments and sends a cancel to
        // the sequencer.
        let account: u32 = arg_or_exit(
            "--cancel",
            "account id",
            &cancel_args[0],
            "a whole number from 0 to 4294967295",
        );
        let target_id: u64 = arg_or_exit("--cancel", "order id", &cancel_args[1], "a whole number");

        let session = session_or_exit(&feed_url).await;
        let signed = sign_or_exit(
            &args.account_key,
            inbox::Submission::Cancel {
                account,
                target_id,
                nonce: Some(inbox::new_nonce()),
                session: Some(session),
            },
        );
        let body = feed_body(&signed);
        if args.sign_only {
            println!("{}", body);
            return Ok(());
        }

        let client = reqwest::Client::new();
        let url = format!("{}/cancel", feed_url);
        // The message names the address and does not assume it, for the same
        // reason as --submit: a sequencer that is not running is not a cancel
        // that was refused.
        let res = match client.post(&url).json(&body).send().await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("cannot reach the feed at {}: {}", url, reason(&e));
                std::process::exit(EXIT_CANNOT_RUN);
            }
        };

        if res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            println!("Cancel submitted to feed successfully: {}", text);
        } else {
            let status = res.status();
            let detail = res.text().await.unwrap_or_default();
            eprintln!("Failed to submit cancel. Status: {}, {}", status, detail);
            std::process::exit(EXIT_REFUSED);
        }
    } else if let Some(list_args) = args.list_symbol {
        // The --list-symbol command: the operator opens a market by
        // publishing a signed message on the sequencer.
        let symbol = list_args[0].to_uppercase();
        let price_step: f64 = arg_or_exit(
            "--list-symbol",
            "price step",
            &list_args[1],
            "a decimal number, for example 0.01",
        );
        let quantity_step: f64 = arg_or_exit(
            "--list-symbol",
            "quantity step",
            &list_args[2],
            "a decimal number, for example 0.1",
        );
        let key = operator_signing_key_or_exit(&args.operator_key_file);
        let session = feed_session_or_exit(&feed_url).await;
        warn_about_the_symbol(&matcher_url, &symbol, true).await;
        // Id 0 and timestamp 0: the sequencer sets both, and neither one is in
        // the statement this signs. See `operator.rs`.
        let message = domain::OrderMessage::ListSymbol {
            id: 0,
            timestamp: 0,
            account: domain::OPERATOR_ACCOUNT,
            symbol,
            price_step,
            quantity_step,
            nonce: Some(inbox::new_nonce()),
            public_key: String::new(),
            signature: String::new(),
        };
        let body = operator_body(&key, &session, &message);
        publish_operator_or_exit(&feed_url, body, args.sign_only).await;
    } else if let Some(delist_args) = args.delist_symbol {
        // The --delist-symbol command.
        let symbol = delist_args[0].to_uppercase();
        let key = operator_signing_key_or_exit(&args.operator_key_file);
        let session = feed_session_or_exit(&feed_url).await;
        warn_about_the_symbol(&matcher_url, &symbol, false).await;
        let message = domain::OrderMessage::DelistSymbol {
            id: 0,
            timestamp: 0,
            account: domain::OPERATOR_ACCOUNT,
            symbol,
            nonce: Some(inbox::new_nonce()),
            public_key: String::new(),
            signature: String::new(),
        };
        let body = operator_body(&key, &session, &message);
        publish_operator_or_exit(&feed_url, body, args.sign_only).await;
    } else if let Some(rule_args) = args.engine_rule {
        // The --engine-rule command: the rule set the messages after it run
        // under.
        // This checks only that the value is a number the field can hold. Which
        // rule sets exist is the exchange's answer and not this binary's, and
        // `/market` below is where it is read.
        let version: u32 =
            arg_or_exit("--engine-rule", "rule set", &rule_args[0], "a whole number");
        let key = operator_signing_key_or_exit(&args.operator_key_file);
        let session = feed_session_or_exit(&feed_url).await;
        warn_about_the_rule_set(&matcher_url, version).await;
        let message = domain::OrderMessage::EngineRule {
            id: 0,
            timestamp: 0,
            account: domain::OPERATOR_ACCOUNT,
            version,
            nonce: Some(inbox::new_nonce()),
            public_key: String::new(),
            signature: String::new(),
        };
        let body = operator_body(&key, &session, &message);
        publish_operator_or_exit(&feed_url, body, args.sign_only).await;
    } else if args.operator_public_key {
        // The --operator-public-key command: it prints the value a sequencer
        // takes as --operator-key. This publishes nothing and creates no key.
        // The key file must exist already.
        let key = operator_signing_key_or_exit(&args.operator_key_file);
        println!("{}", logchain::to_hex(key.verifying_key().as_bytes()));
    } else if let Some(n_str) = args.orders {
        // The --orders command. It fetches the n newest messages from the
        // sequencer and prints them.
        let n: usize = arg_or_exit("--orders", "message count", &n_str, "a whole number");
        let client = reqwest::Client::new();
        let url = format!("{}/orders?n={}", feed_url, n);
        let res = match client.get(&url).send().await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("cannot reach the feed at {}: {}", url, reason(&e));
                std::process::exit(EXIT_CANNOT_RUN);
            }
        };
        if res.status().is_success() {
            // An address that answers 200 with something this binary cannot
            // read is not a sequencer, or not a sequencer of this version.
            // Either way nothing was fetched, so this is 2 and not 1. Status 3
            // is not used here. Status 3 is for a signed log this build checked
            // and could not fully read, and --orders checks nothing.
            let messages: Vec<domain::OrderMessage> = match res.json().await {
                Ok(messages) => messages,
                Err(e) => {
                    eprintln!("cannot read what {} served: {}", url, reason(&e));
                    std::process::exit(EXIT_CANNOT_RUN);
                }
            };
            println!("Most recent {} messages:", messages.len());
            println!("{:#?}", messages);
        } else {
            // 2 and not 1, for the same reason as the branch above: nothing
            // was fetched. --submit and --cancel answer a status that is not
            // 2xx with 1, because there the sequencer read a statement the
            // caller signed and said no to it. --orders sends no statement, and
            // a read holds nothing for the sequencer to refuse. So a status
            // here is a read that produced no messages. That is this command
            // failing to run, and not the sequencer turning the caller down.
            eprintln!("Failed to get messages. Status: {}", res.status());
            std::process::exit(EXIT_CANNOT_RUN);
        }
    } else if args.start_feed {
        // The --start-feed command. It starts the sequencer, which also
        // generates simulated orders.
        let feed_db = (!args.no_feed_db).then_some(args.feed_db);
        let ui_origins = ui_origins_or_exit(&args.ui_origin);
        let trusted_proxies = trusted_proxies_or_exit(&args.trusted_proxy);
        let bind = bind_addr_or_exit(&args.bind);
        let operator_key = operator_public_key_or_exit(args.operator_key.as_deref());
        feed::start_feed(
            bind,
            args.feed_port,
            args.num_accounts,
            args.rate,
            feed_db,
            args.inbox_url,
            ui_origins,
            trusted_proxies,
            operator_key,
        )
        .await;
    } else if args.start_inbox {
        // The --start-inbox command: the separate service that records orders
        // and that the sequencer empties.
        let trusted_proxies = trusted_proxies_or_exit(&args.trusted_proxy);
        let ui_origins = ui_origins_or_exit(&args.ui_origin);
        let bind = bind_addr_or_exit(&args.bind);
        services::inbox::start_inbox(
            bind,
            args.inbox_port,
            args.inbox_db,
            args.inbox_deadline_ms,
            args.feed_key,
            Some(feed_url),
            trusted_proxies,
            ui_origins,
        )
        .await;
    } else if args.start_validator {
        // The --start-validator command: one validator, which reads the log
        // and signs which messages it saw, in which order.
        let bind = bind_addr_or_exit(&args.bind);
        services::validator::start_validator(
            bind,
            args.validator_port,
            args.validator_db,
            feed_url,
            args.poll_ms,
        )
        .await;
    } else if args.start_matcher {
        // The --start-matcher command. It starts the exchange, which reads the
        // sequencer's messages.
        let bind = bind_addr_or_exit(&args.bind);
        matcher::start_matcher(matcher::MatcherOptions {
            public_feed_url: args.public_feed_url.unwrap_or_else(|| feed_url.clone()),
            // There is no fallback to a guessed address. --inbox-url is the
            // flag the operator already writes for a separate service they run.
            // With neither flag set, the page is told there is no separate
            // service, instead of being pointed at a port that may hold
            // nothing.
            public_inbox_url: args.public_inbox_url.or(args.inbox_url),
            feed_url,
            bind,
            port: args.matcher_port,
            poll_ms: args.poll_ms,
            state_db: (!args.no_state_db).then_some(args.state_db),
            reset_state: args.reset_state,
            validators: args.validators,
        })
        .await;
    } else if args.start_bot || args.backtest_bot.is_some() {
        // Both paths run the same strategy. Only the source of the messages
        // differs, so a backtest result is a claim about the running bot.
        let mut cfg = bot::BotConfig {
            account: args.bot_account,
            feed_url,
            poll_ms: args.bot_poll_ms,
            take_bps: args.bot_take_bps,
            quote_bps: args.bot_quote_bps,
            quote_units: args.bot_quote_units,
            ..Default::default()
        };
        if let Some(spec) = &args.bot_caps {
            // This replaces the defaults and does not merge with them. A
            // caller who names the caps chooses where the money goes. A default
            // left in place for a symbol they left out would be a position they
            // did not ask for.
            let mut caps = std::collections::HashMap::new();
            for entry in spec.split(',').filter(|e| !e.trim().is_empty()) {
                let Some((symbol, amount)) = entry.split_once('=') else {
                    eprintln!("--bot-caps: '{}' is not SYMBOL=AMOUNT", entry.trim());
                    std::process::exit(EXIT_CANNOT_RUN);
                };
                let symbol = symbol.trim().to_uppercase();
                if !domain::SYMBOLS.iter().any(|(s, _, _)| *s == symbol) {
                    eprintln!("--bot-caps: '{}' is not a valid symbol", symbol);
                    std::process::exit(EXIT_CANNOT_RUN);
                }
                match amount.trim().parse::<f64>() {
                    Ok(a) if a > 0.0 => {
                        caps.insert(symbol, a);
                    }
                    _ => {
                        eprintln!("--bot-caps: '{}' is not a positive amount", amount.trim());
                        std::process::exit(EXIT_CANNOT_RUN);
                    }
                }
            }
            cfg.caps = caps;
        }
        if let Some(messages) = args.backtest_bot {
            let result = bot::backtest(args.backtest_seed, messages, cfg);
            println!(
                "backtest: seed {}, {} feed messages, {} orders sent by the bot",
                args.backtest_seed, result.feed_messages, result.orders_sent
            );
            println!("  realized profit          {:>12.2}", result.realized);
            println!(
                "  total at the true mid    {:>12.2}   <- what it really made",
                result.total_at_true_mid
            );
            println!(
                "  total at last trade      {:>12.2}   <- what /positions would show",
                result.total_at_last_trade
            );
            println!(
                "  open position at the end {:>12.2} of notional",
                result.end_position_notional
            );
            // When this count is above zero, every number printed here is
            // measured against a market the simulated log does not describe. So
            // the run says so. Without this warning, a run with no profit would
            // look like a strategy that did not work.
            if result.orders_ignored > 0 {
                println!(
                    "  WARNING: the replica refused {} of the history's orders, so the books \
                     these numbers come from are not the books this history describes",
                    result.orders_ignored
                );
            }
            println!("  by symbol:");
            println!(
                "    {:<10}{:>12}{:>12}{:>10}{:>15}",
                "symbol", "total", "realized", "units", "open notional"
            );
            for s in &result.per_symbol {
                println!(
                    "    {:<10}{:>12.2}{:>12.2}{:>10.1}{:>15.0}",
                    s.symbol, s.total, s.realized, s.end_units, s.end_notional
                );
            }
        } else {
            let key = match logchain::load_or_create_key(&args.bot_key) {
                Ok(key) => key,
                Err(e) => {
                    eprintln!("cannot use bot key {}: {}", args.bot_key.display(), e);
                    std::process::exit(EXIT_CANNOT_RUN);
                }
            };
            bot::start_bot(cfg, key).await;
        }
    } else if let Some(target) = audit_target {
        // Both audits take the same optional anchor. It is read once, before
        // either audit runs, so a malformed address is a sentence and not a
        // check that failed halfway through running the log again.
        let anchor = match (&args.anchor_rpc, &args.anchor_contract) {
            (Some(rpc), Some(contract)) => {
                // The selector and the topic come first, for the same reason
                // the address is checked here: a mistyped one must be a
                // sentence before any request goes out. Neither gives an error
                // at the far end. A wrong selector answers empty, and a wrong
                // topic matches no logs, so an unchecked one would arrive as
                // "this contract holds no anchors".
                let abi = match services::anchor::AnchorAbi::from_flags_and_env(
                    args.anchored_topic.as_deref(),
                    args.latest_selector.as_deref(),
                ) {
                    Ok(abi) => abi,
                    Err(e) => {
                        eprintln!("cannot use that anchor: {}", e);
                        std::process::exit(EXIT_CANNOT_RUN);
                    }
                };
                // The warning comes before the audit, and not after it. A
                // value with the right shape and the wrong content is the case
                // nothing above catches, and the audit it produces looks like a
                // contract with no anchors.
                for warning in abi.warnings() {
                    eprintln!("{}", warning);
                }
                match services::anchor::AnchorSource::new(rpc, contract, args.anchor_from_block) {
                    Ok(source) => Some(source.with_abi(abi)),
                    Err(e) => {
                        eprintln!("cannot use that anchor: {}", e);
                        std::process::exit(EXIT_CANNOT_RUN);
                    }
                }
            }
            _ => None,
        };
        let root_anchor = root_anchor_source_or_exit(
            args.root_anchor_rpc.as_deref(),
            args.root_anchor_contract.as_deref(),
            args.root_anchor_from_block,
            args.anchored_root_topic.as_deref(),
            args.root_latest_selector.as_deref(),
        );
        let outcome = match target {
            // The --audit-url command: the same claim checks, against a
            // running exchange over HTTP, with no database in hand.
            //
            // This passes `args.feed_url` and not the resolved default. It is
            // the one command whose caller is not expected to know where the
            // sequencer is, so "not given" must reach it as `None` for it to
            // ask the exchange.
            AuditTarget::Live(matcher_url) => {
                services::prove::audit_url(
                    &matcher_url,
                    args.feed_url.as_deref(),
                    args.matcher_key.as_deref(),
                    anchor.as_ref(),
                    root_anchor.as_ref(),
                )
                .await
            }
            // The --audit command: run the log again and check every state
            // root claim the exchange wrote down.
            AuditTarget::Local(state_db) => {
                services::prove::audit_run(
                    &state_db,
                    &feed_url,
                    args.audit_run,
                    anchor.as_ref(),
                    root_anchor.as_ref(),
                )
                .await
            }
        };
        // Three answers and not two, and the exit status says which one.
        // `Verdict::exit_code` documents the numbers. 1 means the exchange's
        // records disagree with themselves. 3 means this binary is older than
        // the message format the sequencer publishes, while the sequencer's
        // signed log checked out. A script that treated those two as one number
        // would wake somebody up for a deploy.
        match outcome {
            Ok(verdict) if verdict.passed() => {}
            Ok(verdict) => std::process::exit(verdict.exit_code()),
            Err(e) => {
                eprintln!("audit could not run: {}", e);
                std::process::exit(EXIT_CANNOT_RUN);
            }
        }
    } else if let Some(state_db) = args.verify {
        // The --verify command. It builds every claim in the exchange's trade
        // record again from the sequencer's own log, and reports what fails.
        // The same three answers as an audit, and the same exit statuses.
        let root_anchor = root_anchor_source_or_exit(
            args.root_anchor_rpc.as_deref(),
            args.root_anchor_contract.as_deref(),
            args.root_anchor_from_block,
            args.anchored_root_topic.as_deref(),
            args.root_latest_selector.as_deref(),
        );
        match verify::verify_trades(&state_db, &feed_url, root_anchor.as_ref()).await {
            Ok(verdict) if verdict.passed() => {}
            Ok(verdict) => std::process::exit(verdict.exit_code()),
            Err(e) => {
                eprintln!("verification could not run: {}", e);
                std::process::exit(EXIT_CANNOT_RUN);
            }
        }
    } else if args.stdio_engine {
        // The --stdio-engine command. It runs the exchange behind the
        // market-harness stdio protocol, so a suite this repository did not
        // write can score this exchange. Standard output carries events and
        // nothing else, so every message to a person goes to standard error.
        if let Err(e) = stdio_engine::run(args.stdio_messages_per_second) {
            eprintln!("the stdio engine stopped: {}", e);
            std::process::exit(EXIT_CANNOT_RUN);
        }
    } else {
        // No command was given, so print what to do.
        println!("Please specify a command, e.g., --start-feed, --submit, --cancel, or --orders.");
    }
    Ok(())
}
