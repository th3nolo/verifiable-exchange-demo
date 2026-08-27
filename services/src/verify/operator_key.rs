//! The operator rule, worked out again from the log's own messages.
//!
//! ENGINE.md section 3.1: the log names its operator once. Every operator
//! message after that must name the same key and verify under it. A message
//! that does not verify changes nothing. No market opens, no market closes,
//! and the rule set stays where the log last put it. The first operator
//! message has nothing before it to be checked against, so the key the log
//! runs under is taken from that message. Its signature still has to verify
//! under the key it names.
//!
//! Nothing here shares a line of code with `matcher.rs`. The exchange keeps
//! the key on its state and asks `operator::verify` one question, "is this my
//! key, and did it sign this?", and gets one answer. This file keeps its own
//! key, compares the field itself, and calls Ed25519 itself, so the two can
//! disagree about a message.
//!
//! This file does import `crate::operator`, and only for the bytes one
//! signature covers. ENGINE.md section 5 allows that much and no more. Which
//! key is in force, and what a message that fails to verify does, are written
//! here.
//!
//! **The key never changes.** A message naming a second key is ignored,
//! whoever signed it. The signed statement covers the prefix, the session, the
//! fields and the nonce, and it never covers the `public_key` field. So such a
//! message shows nothing about the key it names. A log whose operator key has
//! to change is a new log.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::domain::{OrderId, OrderMessage};
use crate::logchain;
use crate::operator;
use crate::reporting::Check;

/// The operator key a walk of the log has reached, and what it made of the
/// operator messages it read.
///
/// Both walks keep one of these. They read the same messages in the same
/// order, so they reach the same answer about every message. That is what
/// makes the second walk ignore exactly the listings the first walk ignored.
/// Only the first walk's count is reported.
pub(super) struct Operator {
    /// The key this log named, once an operator message has named one. `None`
    /// before that: a log that has published no operator message has no
    /// operator, and it has opened no market either.
    in_force: Option<[u8; 32]>,
    /// The keys the log really ran under, in the order they appeared. A log
    /// under this rule holds one key. The report prints the whole list and not
    /// the count, so a reader can see whether the key ever changed.
    used: Vec<[u8; 32]>,
    check: Check,
}

impl Operator {
    pub(super) fn new() -> Self {
        Operator {
            in_force: None,
            used: Vec::new(),
            check: Check::new("every operator message is signed by the log's operator"),
        }
    }

    /// Whether this operator message may act.
    ///
    /// Three things have to hold, and a message that breaks any one of them
    /// fails the check. The message names a key that can be read. That key is
    /// the one the log named. And the signature on the message is one that key
    /// made over exactly the bytes this message says.
    ///
    /// The first operator message of a log has no key before it, so it is
    /// checked against the key it names. That is what decides which key the
    /// log runs under. It does not excuse the signature. A first message whose
    /// signature is wrong names no operator at all: the log has still not
    /// named one, and the next operator message becomes the first.
    pub(super) fn accepts(&mut self, id: OrderId, message: &OrderMessage, session: &str) -> bool {
        let (named, signature) = match key_and_signature(message) {
            Some(fields) => fields,
            // A trader's message. It carries no operator statement and this
            // rule says nothing about it.
            None => return true,
        };
        self.check.checked += 1;

        let Some(named) = logchain::from_hex::<32>(named.trim()) else {
            self.refuse(
                id,
                "it carries no readable public key, so nothing names who wrote it".to_string(),
            );
            return false;
        };
        let in_force = self.in_force.unwrap_or(named);
        if named != in_force {
            self.refuse(
                id,
                format!(
                    "it is written under key {}, and this log runs under {}. The signed bytes \
                     do not cover the key a message names, so a second key in the log is a \
                     claim nobody signed",
                    logchain::to_hex(&named),
                    logchain::to_hex(&in_force)
                ),
            );
            return false;
        }
        let Some(signature) = logchain::from_hex::<64>(signature.trim()) else {
            self.refuse(
                id,
                "it carries no readable signature, so nothing was checked".to_string(),
            );
            return false;
        };
        // The bytes one operator signature covers. `operator` is the one place
        // that states them, so the two programs sign and check the same
        // statement. It decides nothing else here.
        let statement = match operator::kind_and_fields(message) {
            Ok((kind, fields)) => operator::operator_statement(kind, session, &fields),
            Err(why) => {
                self.refuse(id, format!("there are no bytes to check: {}", why));
                return false;
            }
        };
        let verified = VerifyingKey::from_bytes(&in_force).is_ok_and(|key| {
            key.verify_strict(&statement, &Signature::from_bytes(&signature))
                .is_ok()
        });
        if !verified {
            self.refuse(
                id,
                format!(
                    "key {} did not sign it. What a signature on it has to cover is: {}",
                    logchain::to_hex(&in_force),
                    String::from_utf8_lossy(&statement).replace('\n', " | ")
                ),
            );
            return false;
        }
        if self.in_force.is_none() {
            self.in_force = Some(in_force);
            self.used.push(in_force);
        }
        true
    }

    /// Records one refused operator message. The message changed nothing, so
    /// the key in force does not move either. A message the log's operator did
    /// not write cannot decide who the operator is.
    fn refuse(&mut self, id: OrderId, why: String) {
        self.check.fail(format!(
            "operator message {} is not the operator's: {}",
            id, why
        ));
    }

    /// The keys the log ran under, oldest first, as the hex a reader compares
    /// against the key they hold.
    pub(super) fn keys_used(&self) -> Vec<String> {
        self.used.iter().map(|key| logchain::to_hex(key)).collect()
    }

    /// One line for the report: which key opened this log, and whether it is
    /// the only one.
    pub(super) fn line(&self) -> String {
        match self.keys_used().as_slice() {
            [] => {
                "          this log has named no operator, so it has opened no market".to_string()
            }
            [only] => format!("          operator key: {}", only),
            many => format!("          operator keys, oldest first: {}", many.join(", ")),
        }
    }

    /// The counts this walk built, for the report.
    pub(super) fn into_check(self) -> Check {
        self.check
    }
}

/// The two operator fields on a message, or `None` for a message a trader
/// published.
fn key_and_signature(message: &OrderMessage) -> Option<(&str, &str)> {
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
        } => Some((public_key, signature)),
        OrderMessage::New { .. } | OrderMessage::Cancel { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{OPERATOR_ACCOUNT, Side};
    use crate::verify::testkit::*;
    use crate::wire::Verdict;

    /// The first operator message names the key, and a listing under a second
    /// key opens nothing, even though that second key really signed it.
    ///
    /// This is the message a sequencer writing its own listings would publish:
    /// a key it made up, and a signature that verifies under that key. Nothing
    /// in the signed bytes covers which key a message names. So the only thing
    /// that makes a listing a real listing is the key the log already named.
    #[tokio::test]
    async fn a_listing_under_a_second_key_opens_no_market() {
        let theirs = by_stranger(OrderMessage::ListSymbol {
            id: 2,
            timestamp: 2000,
            account: OPERATOR_ACCOUNT,
            symbol: "BTC-USDC".to_string(),
            price_step: 0.01,
            quantity_step: 0.1,
            nonce: Some(format!("{:032x}", 2)),
            public_key: String::new(),
            signature: String::new(),
        });
        let messages = vec![list_eth(1), theirs, new_order(3, 5, Side::Sell, 100.0, 5.0)];
        let surveyed = survey(&messages).await;
        // Which markets the log had open is the second walk's answer now. It
        // is the walk that holds a book, so it is the walk that reads a
        // listing message.
        let open = replayed_history(&messages, &[]).await.open_symbols;

        assert_eq!(
            surveyed.operator.keys_used(),
            vec![operator_public_key()],
            "the log ran under the key its first operator message named"
        );
        assert!(
            open.admits("ETH-USDC", 10_000, 50),
            "the operator's own listing opened its market"
        );
        assert!(
            !open.admits("BTC-USDC", 10_000, 50),
            "a market opened by somebody the log never named"
        );
        let check = surveyed.operator.into_check();
        assert_eq!(check.checked, 2, "both operator messages were read");
        assert_eq!(check.failed, 1);
        assert!(
            check.failures[0].contains("this log runs under"),
            "{}",
            check.failures[0]
        );
    }

    /// A message that names the log's own key and carries a signature that key
    /// never made is refused too.
    ///
    /// The signature here is a real one the operator made, over a different
    /// symbol. Moving a signature onto another message is the cheapest forgery
    /// there is, so it is the one this test covers.
    #[tokio::test]
    async fn a_signature_moved_onto_another_message_is_refused() {
        let signed = list_on(2, "BTC-USDC", 0.01, 0.1);
        let OrderMessage::ListSymbol {
            public_key,
            signature,
            ..
        } = signed
        else {
            panic!("it is a listing");
        };
        let moved = OrderMessage::ListSymbol {
            id: 2,
            timestamp: 2000,
            account: OPERATOR_ACCOUNT,
            symbol: "ZULU-USD".to_string(),
            price_step: 0.01,
            quantity_step: 0.1,
            nonce: Some(format!("{:032x}", 2)),
            public_key,
            signature,
        };
        let messages = vec![list_eth(1), moved];
        let surveyed = survey(&messages).await;

        let open = replayed_history(&messages, &[]).await.open_symbols;
        assert!(!open.admits("ZULU-USD", 10_000, 50));
        let check = surveyed.operator.into_check();
        assert_eq!(check.failed, 1);
        assert!(
            check.failures[0].contains("did not sign it"),
            "{}",
            check.failures[0]
        );
    }

    /// A message with no nonce carries no statement, so there is nothing to
    /// check and it opens nothing.
    #[tokio::test]
    async fn a_message_with_no_nonce_opens_nothing() {
        let OrderMessage::ListSymbol {
            id,
            timestamp,
            account,
            symbol,
            price_step,
            quantity_step,
            ..
        } = unsigned_list_eth(1)
        else {
            panic!("it is a listing");
        };
        let no_nonce = OrderMessage::ListSymbol {
            id,
            timestamp,
            account,
            symbol,
            price_step,
            quantity_step,
            nonce: None,
            public_key: operator_public_key(),
            signature: "00".repeat(64),
        };
        let messages = vec![no_nonce];
        let surveyed = survey(&messages).await;

        let open = replayed_history(&messages, &[]).await.open_symbols;
        assert!(!open.admits("ETH-USDC", 10_000, 50));
        assert!(
            surveyed.operator.keys_used().is_empty(),
            "a message that did nothing names no operator"
        );
        let check = surveyed.operator.into_check();
        assert_eq!(check.failed, 1);
        assert!(
            check.failures[0].contains("no bytes to check"),
            "{}",
            check.failures[0]
        );
    }

    /// An operator message this checker cannot verify makes the run FAIL, and
    /// the process exits 1. It never exits 3, not even over a history the run
    /// could not read to the end.
    ///
    /// ENGINE.md section 6: a failed check outranks cannot-interpret. The two
    /// answers are about different people. Exit 3 says "this build is older
    /// than the log". A signature that does not verify is this build reading a
    /// message and finding it wrong. An operator who read 3 would go and
    /// upgrade a binary instead of asking who wrote that message.
    #[tokio::test]
    async fn an_unverifiable_operator_message_fails_rather_than_stopping_at_exit_3() {
        // Rule set 4,000 is one no build replays, so the walk also ends with
        // cannot-interpret. The operator really signed the `engine_rule`
        // message. The one failure below is the stranger's delist, and nothing
        // else.
        let theirs = by_stranger(OrderMessage::DelistSymbol {
            id: 2,
            timestamp: 2000,
            account: OPERATOR_ACCOUNT,
            symbol: "ETH-USDC".to_string(),
            nonce: Some(format!("{:032x}", 2)),
            public_key: String::new(),
            signature: String::new(),
        });
        let messages = vec![list_eth(1), theirs, engine_rule(3, 4_000)];
        let surveyed = survey(&messages).await;

        let too_old = surveyed.too_old.expect("rule set 4,000 stops this build");
        assert_eq!(too_old.id, 3);
        assert!(
            replayed_history(&messages, &[])
                .await
                .open_symbols
                .admits("ETH-USDC", 10_000, 50),
            "the stranger's delist closed nothing"
        );
        let check = surveyed.operator.into_check();
        assert_eq!(check.failed, 1);

        // The two answers, from the one function the report uses.
        assert_eq!(
            crate::verify::incomplete(check.passed(), &too_old),
            Verdict::Failed
        );
        assert_eq!(
            crate::verify::incomplete(check.passed(), &too_old).exit_code(),
            1,
            "a bad operator signature must not be reported as a stale binary"
        );
        assert_eq!(
            crate::verify::incomplete(true, &too_old).exit_code(),
            3,
            "and a history this build merely cannot read still reports 3"
        );
    }

    /// The report names the key the log ran under, so a reader can compare
    /// that key with the key they hold instead of taking "it verified" on
    /// trust.
    #[tokio::test]
    async fn the_report_names_the_key_the_log_ran_under() {
        let surveyed = survey(&[list_eth(1), delist(2, "ETH-USDC")]).await;
        let line = surveyed.operator.line();
        assert!(
            line.contains(&operator_public_key()),
            "the key is not in the line a reader gets: {}",
            line
        );

        // A log that has named no operator says so rather than printing an
        // empty list.
        let empty = survey(&[new_order(1, 5, Side::Sell, 100.0, 5.0)]).await;
        assert!(
            empty.operator.line().contains("named no operator"),
            "{}",
            empty.operator.line()
        );
    }
}
