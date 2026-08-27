//! What the owner of the exchange signs to open a market, close one, or change
//! the rule set.
//!
//! `EngineRule`, `ListSymbol` and `DelistSymbol` are the three message kinds no
//! trader may publish. The command line signs one and the sequencer publishes
//! it on `POST /operator`. This module is the part that decides which bytes a
//! signature over one of them covers, so the program that publishes them and
//! the program that checks them read the same definition.
//!
//! # What the statement holds
//!
//! ```text
//! exchange-operator-list-v1\n<session>\n<symbol>\n<price_step_cents>\n<quantity_step_tenths>\n<nonce>
//! exchange-operator-delist-v1\n<session>\n<symbol>\n<nonce>
//! exchange-operator-rule-v1\n<session>\n<version>\n<nonce>
//! ```
//!
//! The same conventions as `inbox::submission_statement`. A versioned first
//! line, so a signature made here can never be read as the sequencer's signed
//! head, as a mark, or as an account submission. One field per line. No
//! trailing newline. Whole numbers, and not the decimals that appear on the
//! wire.
//!
//! The session is on the second line because a session names one log. The same
//! signed bytes therefore cannot be replayed into a different log, or into the
//! same log after it was emptied and got a new session.
//!
//! The nonce is on the last line, because the sequencer already refuses a
//! second message for an `(account, nonce)` pair it has published one for,
//! see `feed.rs`. Every operator message is under `domain::OPERATOR_ACCOUNT`,
//! so that map turns one signed statement into one message in one log.
//!
//! The id and the timestamp are not in the statement. The sequencer assigns
//! both, and the owner cannot know either one when signing.

use std::fs;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::domain::{OrderMessage, to_grid};
use crate::inbox::{PRICE_SCALE, QUANTITY_SCALE, canonical_nonce};
use crate::logchain;

/// The longest symbol this exchange accepts.
const MAX_SYMBOL_LENGTH: usize = 32;

/// Which of the three statements is being built.
///
/// Each one has its own prefix, so a signature over a listing can never be read
/// as a signature over a delisting of the same symbol in the same session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorKind {
    /// A symbol becomes tradable.
    List,
    /// A symbol stops being tradable.
    Delist,
    /// The rule set the later messages run under.
    Rule,
}

impl OperatorKind {
    /// The first line of the statement.
    pub fn prefix(&self) -> &'static str {
        match self {
            OperatorKind::List => "exchange-operator-list-v1",
            OperatorKind::Delist => "exchange-operator-delist-v1",
            OperatorKind::Rule => "exchange-operator-rule-v1",
        }
    }
}

/// Builds the bytes the operator's two fields cover.
///
/// `fields` holds the lines between the session and the end, already printed
/// as text. `kind_and_fields` is what turns a message into those lines, and it
/// is the only place that decides how a step or a version prints.
pub fn operator_statement(kind: OperatorKind, session: &str, fields: &[String]) -> Vec<u8> {
    let mut lines = Vec::with_capacity(fields.len() + 2);
    lines.push(kind.prefix().to_string());
    lines.push(session.to_string());
    lines.extend(fields.iter().cloned());
    lines.join("\n").into_bytes()
}

/// Splits an operator message into the kind and the field lines its statement
/// is built from.
///
/// This is where every value becomes text. The steps become whole cents and
/// whole tenths, the same units `matcher.rs` executes on, so a caller in
/// another language never has to answer "how does this language print 0.01".
/// The nonce is re-printed from its decoded bytes, so the statement commits to
/// the 128 bits and not to whichever spelling of them arrived.
///
/// `Err` names the one thing that is wrong. A `New` or a `Cancel` is an error
/// here rather than a kind with an empty statement, because a caller that
/// reaches this with a trader's message has asked the wrong question.
///
/// A rule set number becomes text here, and nothing here judges it. Which rule
/// sets exist is a fact about what the exchange implements, and not a fact
/// about the message. Neither this module nor the sequencer that calls it
/// executes messages. `--engine-rule` reads the number the exchange reports on
/// `/market` and warns. The exchange and the checker each decide for
/// themselves which rule sets they can run.
pub fn kind_and_fields(message: &OrderMessage) -> Result<(OperatorKind, Vec<String>), String> {
    let nonce = message
        .nonce()
        .ok_or_else(|| "an operator message must carry a nonce".to_string())?;
    let nonce = canonical_nonce(nonce)
        .ok_or_else(|| format!("nonce {} is not 32 lowercase hex characters", nonce))?;
    let nonce = logchain::to_hex(&nonce);

    match message {
        OrderMessage::ListSymbol {
            symbol,
            price_step,
            quantity_step,
            ..
        } => {
            valid_symbol(symbol)?;
            let price_step_cents = to_grid(*price_step, PRICE_SCALE).ok_or_else(|| {
                format!(
                    "price_step {} is not a whole number of cents the engine can hold",
                    price_step
                )
            })?;
            let quantity_step_tenths =
                to_grid(*quantity_step, QUANTITY_SCALE).ok_or_else(|| {
                    format!(
                        "quantity_step {} is not a whole number of tenths the engine can hold",
                        quantity_step
                    )
                })?;
            Ok((
                OperatorKind::List,
                vec![
                    symbol.clone(),
                    price_step_cents.to_string(),
                    quantity_step_tenths.to_string(),
                    nonce,
                ],
            ))
        }
        OrderMessage::DelistSymbol { symbol, .. } => {
            valid_symbol(symbol)?;
            Ok((OperatorKind::Delist, vec![symbol.clone(), nonce]))
        }
        OrderMessage::EngineRule { version, .. } => {
            Ok((OperatorKind::Rule, vec![version.to_string(), nonce]))
        }
        OrderMessage::New { .. } | OrderMessage::Cancel { .. } => {
            Err("this kind is published by a trader, not by the operator".to_string())
        }
    }
}

/// Signs a statement as the operator. Returns the 128 hex characters that go in
/// the message's `signature` field.
///
/// A caller in another language reproduces `operator_statement` and signs that.
pub fn sign(key: &SigningKey, kind: OperatorKind, session: &str, fields: &[String]) -> String {
    let statement = operator_statement(kind, session, fields);
    logchain::to_hex(&key.sign(&statement).to_bytes())
}

/// Checks that an operator message really was signed by `key` for this session.
///
/// `key` is the key the exchange trusts, and not the key the message names.
/// Both are checked. The message's `public_key` must be that same key, or the
/// field would be free to name anybody while the signature verified under the
/// trusted key.
///
/// `verify_strict` is the same call `inbox.rs` makes on an account signature.
/// Plain `verify` also accepts a few signatures that can be reshaped into
/// other valid signatures for the same message, and nothing here has a use for
/// that.
pub fn verify(message: &OrderMessage, session: &str, key: &VerifyingKey) -> Result<(), String> {
    let (public_key, signature) = fields_of(message)?;

    let Some(named) = logchain::from_hex::<32>(public_key.trim()) else {
        return Err(
            "public_key must be a 32-byte Ed25519 public key in hex (64 characters)".to_string(),
        );
    };
    if &named != key.as_bytes() {
        return Err(format!(
            "public_key {} is not the operator key this exchange trusts",
            public_key
        ));
    }
    let Some(signature_bytes) = logchain::from_hex::<64>(signature.trim()) else {
        return Err(
            "signature must be a 64-byte Ed25519 signature in hex (128 characters)".to_string(),
        );
    };

    let (kind, fields) = kind_and_fields(message)?;
    let statement = operator_statement(kind, session, &fields);
    key.verify_strict(&statement, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| {
            format!(
                "the signature does not verify under public_key {}; it must cover exactly: {}",
                public_key,
                String::from_utf8_lossy(&statement).replace('\n', " | ")
            )
        })
}

/// The key an operator message names, whoever signed it.
///
/// This function reads the field and nothing else. It says which key the
/// message claims to be from. It never says that the claim is good; `verify`
/// is what answers that. The exchange calls this for the first operator
/// message of a log, which is the one message with no earlier key to be
/// checked against.
pub fn named_key(message: &OrderMessage) -> Result<VerifyingKey, String> {
    let (public_key, _) = fields_of(message)?;
    let bytes = logchain::from_hex::<32>(public_key.trim()).ok_or_else(|| {
        "public_key must be a 32-byte Ed25519 public key in hex (64 characters)".to_string()
    })?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| {
        format!(
            "public_key {} is not a point on the curve",
            public_key.trim()
        )
    })
}

/// The two operator fields on a message, whichever of the three kinds it is.
fn fields_of(message: &OrderMessage) -> Result<(&str, &str), String> {
    match message {
        OrderMessage::EngineRule {
            public_key,
            signature,
            ..
        }
        | OrderMessage::ListSymbol {
            public_key,
            signature,
            ..
        }
        | OrderMessage::DelistSymbol {
            public_key,
            signature,
            ..
        } => Ok((public_key, signature)),
        OrderMessage::New { .. } | OrderMessage::Cancel { .. } => {
            Err("this kind is published by a trader, not by the operator".to_string())
        }
    }
}

/// Checks a symbol before it can be listed.
///
/// At most 32 characters, and only `A`-`Z`, `0`-`9` and `-`. The set is small
/// on purpose. A symbol is printed on the page, used as a map key in every
/// program that reads the log, and put in a signed statement. Lower case would
/// let `eth-usdc` and `ETH-USDC` be two markets that read as one.
///
/// An empty symbol is refused. It would name no market and it would print as
/// an empty line in the statement.
pub fn valid_symbol(symbol: &str) -> Result<(), String> {
    if symbol.is_empty() {
        return Err("a symbol cannot be empty".to_string());
    }
    if symbol.len() > MAX_SYMBOL_LENGTH {
        return Err(format!(
            "symbol {} is {} characters, and the limit is {}",
            symbol,
            symbol.len(),
            MAX_SYMBOL_LENGTH
        ));
    }
    if let Some(bad) = symbol
        .chars()
        .find(|c| !(c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '-'))
    {
        return Err(format!(
            "symbol {} holds {:?}, and a symbol holds only A-Z, 0-9 and -",
            symbol, bad
        ));
    }
    Ok(())
}

/// Loads the operator's signing key from `path`. The file holds 32 bytes in
/// hex, the same shape `logchain::load_or_create_key` reads.
///
/// This function never creates a key. `logchain::load_or_create_key` does, and
/// that is right for the sequencer. A sequencer with no key yet has nothing to
/// lose by making one, and its identity is whatever it published under. An
/// operator key is the opposite. It is the one key the exchange already
/// trusts. A mistyped path that created a fresh key would give a program that
/// starts, signs, and publishes messages nobody can verify, and nobody could
/// drive that program with the real key either.
pub fn load_key(path: &Path) -> Result<SigningKey, String> {
    if !path.exists() {
        return Err(format!(
            "{} does not exist; this is the operator key, so it is read and never created",
            path.display()
        ));
    }
    let hex =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let bytes: [u8; 32] = logchain::from_hex(hex.trim())
        .ok_or_else(|| format!("{} does not hold a 32-byte hex key", path.display()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Signs an operator message as `key` and names that key on it.
///
/// It is for a caller that holds a whole message and not a request body: the
/// bot's backtest, which invents a history and drives a real engine over it,
/// and the histories the tests build. Every one of those messages has to carry
/// a real signature now, ENGINE.md section 3.1, and one builder keeps them
/// from drifting into several slightly different ones. `main.rs` does not use
/// it. `main.rs` signs a body for `POST /operator`, where the sequencer
/// assigns the id and the timestamp.
///
/// This function states no rule. It calls `kind_and_fields` and `sign` above,
/// and what the exchange checks is `verify`.
///
/// A message with no statement comes back with an empty signature. A symbol
/// that breaks the name rule and a step no book can hold both have no
/// statement, so nobody can sign such a message, and the exchange ignores it
/// for exactly that reason.
pub fn signed_as(key: &SigningKey, session: &str, message: OrderMessage) -> OrderMessage {
    let named = logchain::to_hex(key.verifying_key().as_bytes());
    let made = kind_and_fields(&message)
        .map(|(kind, fields)| sign(key, kind, session, &fields))
        .unwrap_or_default();
    let mut message = message;
    match &mut message {
        OrderMessage::ListSymbol {
            public_key,
            signature,
            ..
        }
        | OrderMessage::DelistSymbol {
            public_key,
            signature,
            ..
        }
        | OrderMessage::EngineRule {
            public_key,
            signature,
            ..
        } => {
            *public_key = named;
            *signature = made;
        }
        OrderMessage::New { .. } | OrderMessage::Cancel { .. } => {
            panic!("a trader's message carries no operator signature")
        }
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::OPERATOR_ACCOUNT;

    const NONCE: &str = "0123456789abcdef0123456789abcdef";
    const SESSION: &str = "349d462ced25bb2b";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn listing(key: &SigningKey) -> OrderMessage {
        let fields = vec![
            "ALFA-USD".to_string(),
            "1".to_string(),
            "1".to_string(),
            NONCE.to_string(),
        ];
        OrderMessage::ListSymbol {
            id: 2,
            timestamp: 1786752446786,
            account: OPERATOR_ACCOUNT,
            symbol: "ALFA-USD".to_string(),
            price_step: 0.01,
            quantity_step: 0.1,
            nonce: Some(NONCE.to_string()),
            public_key: logchain::to_hex(key.verifying_key().as_bytes()),
            signature: sign(key, OperatorKind::List, SESSION, &fields),
        }
    }

    /// The exact bytes of the three statements the operator signs.
    ///
    /// The command line builds these bytes and the sequencer checks them, and
    /// both use this module, so nothing here would catch a field that moved.
    /// That is exactly why the bytes are written out. The second program to
    /// build them will be in another language, and a field that moves after
    /// that is a signature that stops verifying with no test to say so.
    #[test]
    fn the_operator_statements_are_exactly_these_bytes() {
        let text = |statement: Vec<u8>| String::from_utf8(statement).expect("statements are text");

        // 0.01 is 1 cent and 0.1 is 1 tenth. The statement carries the
        // engine's whole-number steps, and never the decimals that arrived on
        // the wire.
        let (kind, fields) = kind_and_fields(&OrderMessage::ListSymbol {
            id: 2,
            timestamp: 1786752446786,
            account: OPERATOR_ACCOUNT,
            symbol: "ALFA-USD".to_string(),
            price_step: 0.01,
            quantity_step: 0.1,
            nonce: Some(NONCE.to_string()),
            public_key: String::new(),
            signature: String::new(),
        })
        .expect("a listing has a statement");
        assert_eq!(kind, OperatorKind::List);
        assert_eq!(
            text(operator_statement(kind, SESSION, &fields)),
            "exchange-operator-list-v1\n\
             349d462ced25bb2b\n\
             ALFA-USD\n\
             1\n\
             1\n\
             0123456789abcdef0123456789abcdef"
        );

        let (kind, fields) = kind_and_fields(&OrderMessage::DelistSymbol {
            id: 3,
            timestamp: 1786752446786,
            account: OPERATOR_ACCOUNT,
            symbol: "ALFA-USD".to_string(),
            nonce: Some(NONCE.to_string()),
            public_key: String::new(),
            signature: String::new(),
        })
        .expect("a delisting has a statement");
        assert_eq!(kind, OperatorKind::Delist);
        assert_eq!(
            text(operator_statement(kind, SESSION, &fields)),
            "exchange-operator-delist-v1\n\
             349d462ced25bb2b\n\
             ALFA-USD\n\
             0123456789abcdef0123456789abcdef"
        );

        let (kind, fields) = kind_and_fields(&OrderMessage::EngineRule {
            id: 1,
            timestamp: 1786752446786,
            account: OPERATOR_ACCOUNT,
            version: 1,
            nonce: Some(NONCE.to_string()),
            public_key: String::new(),
            signature: String::new(),
        })
        .expect("a rule has a statement");
        assert_eq!(kind, OperatorKind::Rule);
        assert_eq!(
            text(operator_statement(kind, SESSION, &fields)),
            "exchange-operator-rule-v1\n\
             349d462ced25bb2b\n\
             1\n\
             0123456789abcdef0123456789abcdef"
        );
    }

    /// The three statements must never be readable as one another, and none of
    /// them as a head, a mark or an account submission.
    #[test]
    fn each_kind_has_its_own_statement_prefix() {
        let kinds = [OperatorKind::List, OperatorKind::Delist, OperatorKind::Rule];
        assert_eq!(kinds.len(), 3, "every kind the operator signs is here");

        let fields = vec!["ALFA-USD".to_string(), NONCE.to_string()];
        let mut prefixes = Vec::new();
        for kind in kinds {
            let statement = operator_statement(kind, SESSION, &fields);
            let text = String::from_utf8(statement).expect("statements are text");
            let prefix = text.lines().next().expect("a prefix line").to_string();
            assert!(
                prefix.starts_with("exchange-operator-") && prefix.ends_with(char::is_numeric),
                "{} is not a versioned, domain-separated prefix",
                prefix
            );
            assert!(
                !prefixes.contains(&prefix),
                "{} is used by two kinds",
                prefix
            );
            prefixes.push(prefix);
        }
    }

    /// The steps are in the statement as whole cents and whole tenths, so a
    /// caller in another language never prints a float.
    #[test]
    fn a_statement_commits_to_the_steps_as_integers() {
        let (kind, fields) = kind_and_fields(&OrderMessage::ListSymbol {
            id: 2,
            timestamp: 1,
            account: OPERATOR_ACCOUNT,
            symbol: "ALFA-USD".to_string(),
            price_step: 0.25,
            quantity_step: 2.5,
            nonce: Some(NONCE.to_string()),
            public_key: String::new(),
            signature: String::new(),
        })
        .expect("a listing has a statement");
        assert_eq!(fields[1], "25", "0.25 is 25 cents");
        assert_eq!(fields[2], "25", "2.5 is 25 tenths");

        let text = String::from_utf8(operator_statement(kind, SESSION, &fields))
            .expect("statements are text");
        assert!(
            !text.contains('.'),
            "the statement prints a decimal: {}",
            text
        );
    }

    /// A signature the operator made verifies, and it covers the session, the
    /// symbol, the steps and the nonce.
    #[test]
    fn a_signature_binds_every_field_of_the_statement() {
        let key = key();
        let public = key.verifying_key();
        let signed = listing(&key);
        assert!(verify(&signed, SESSION, &public).is_ok());

        // A different log.
        assert!(verify(&signed, "0000000000000000", &public).is_err());

        // A different symbol, step or nonce, with the same signature.
        let OrderMessage::ListSymbol {
            id,
            timestamp,
            account,
            public_key,
            signature,
            ..
        } = signed.clone()
        else {
            panic!("it is a listing");
        };
        for (symbol, price_step, quantity_step, nonce) in [
            ("BRAVO-USD", 0.01, 0.1, NONCE),
            ("ALFA-USD", 0.02, 0.1, NONCE),
            ("ALFA-USD", 0.01, 0.2, NONCE),
            ("ALFA-USD", 0.01, 0.1, "fedcba9876543210fedcba9876543210"),
        ] {
            let changed = OrderMessage::ListSymbol {
                id,
                timestamp,
                account,
                symbol: symbol.to_string(),
                price_step,
                quantity_step,
                nonce: Some(nonce.to_string()),
                public_key: public_key.clone(),
                signature: signature.clone(),
            };
            assert!(
                verify(&changed, SESSION, &public).is_err(),
                "a change to {} {} {} {} was not caught",
                symbol,
                price_step,
                quantity_step,
                nonce
            );
        }
    }

    /// A message that names a key other than the one the exchange trusts is
    /// refused, even when the signature under that named key is good.
    #[test]
    fn a_message_signed_by_a_stranger_is_refused() {
        let stranger = SigningKey::from_bytes(&[9u8; 32]);
        let signed = listing(&stranger);
        assert!(verify(&signed, SESSION, &stranger.verifying_key()).is_ok());

        let trusted = key().verifying_key();
        let refused = verify(&signed, SESSION, &trusted).expect_err("a stranger is refused");
        assert!(
            refused.contains("is not the operator key this exchange trusts"),
            "{}",
            refused
        );
    }

    /// Every symbol rule, with the value that breaks each one.
    #[test]
    fn a_symbol_holds_only_upper_case_letters_digits_and_dashes() {
        assert!(valid_symbol("ALFA-USD").is_ok());
        assert!(valid_symbol("BTC1-USDC").is_ok());
        assert!(valid_symbol(&"A".repeat(32)).is_ok());

        assert!(valid_symbol("").is_err(), "empty");
        assert!(valid_symbol(&"A".repeat(33)).is_err(), "33 characters");
        assert!(valid_symbol("alfa-usd").is_err(), "lower case");
        assert!(valid_symbol("ALFA_USD").is_err(), "underscore");
        assert!(valid_symbol("ALFA USD").is_err(), "space");
        assert!(valid_symbol("ALFA/USD").is_err(), "slash");
    }

    /// A missing key file is an error, and no file appears. A path typed wrong
    /// must stop the program, not give it a key nobody holds.
    #[test]
    fn load_key_refuses_a_missing_path_and_creates_nothing() {
        let dir = std::env::temp_dir().join(format!("operator-key-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("a directory for the test");
        let path = dir.join("operator.key");
        let _ = fs::remove_file(&path);

        let refused = load_key(&path).expect_err("a missing key file is an error");
        assert!(refused.contains("does not exist"), "{}", refused);
        assert!(!path.exists(), "load_key created {}", path.display());

        // And it reads one that is there.
        fs::write(&path, logchain::to_hex(&key().to_bytes())).expect("write a key");
        let loaded = load_key(&path).expect("it reads an existing key");
        assert_eq!(loaded.to_bytes(), key().to_bytes());

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    /// A trader's message has no operator statement. It is an error and not an
    /// empty statement, because a caller that gets here asked the wrong thing.
    #[test]
    fn a_traders_message_has_no_operator_statement() {
        let cancel = OrderMessage::Cancel {
            id: 1,
            timestamp: 1,
            account: 7,
            target_id: 2,
            nonce: Some(NONCE.to_string()),
        };
        assert!(kind_and_fields(&cancel).is_err());
        assert!(verify(&cancel, SESSION, &key().verifying_key()).is_err());
    }
}
