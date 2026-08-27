//! The client for the separate order-submission service.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use super::{FeedState, InboxKey, NonceKey, with_state};
use crate::domain::{OrderId, OrderMessage};
use crate::fetch::read_bounded;
use crate::inbox::{self, Entry as InboxEntry};

/// Timeouts on the client that calls the separate service. `drain_inbox` is
/// awaited inline in the generator loop. So a separate service that accepts a
/// connection and never answers used to stop the sequencer publishing
/// anything. It stopped for as long as the service stayed that way, and
/// nothing in the log said so.
const INBOX_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const INBOX_TIMEOUT: Duration = Duration::from_secs(2);

/// The most bytes accepted from the separate service's `/pending`. The
/// sequencer signs what it takes from that service. So it trusts neither the
/// content of the answer nor its size.
const MAX_PENDING_BYTES: usize = 1024 * 1024;

/// How long a refused mark waits before the sequencer sends it again, and how
/// far that wait grows. A mark tells the separate service which message an
/// entry became. A mark that is refused every time used to be sent again on
/// every tick: ten error lines a second, forever, for one entry.
const MARK_RETRY_BASE: Duration = Duration::from_millis(500);
const MARK_RETRY_MAX: Duration = Duration::from_secs(30);

/// How many refusals of one mark before the sequencer stops sending it. The
/// entry then stays pending on the separate service, which reports it
/// overdue. That report is correct. The order is already sequenced and
/// trading, but the proof that links the order to the entry did not arrive,
/// and only an operator can find out why.
const MARK_REFUSAL_LIMIT: u32 = 8;

/// The most marks sent in one tick. The sequencer sends marks one after
/// another inside the generator's 100ms tick. Without a limit, a few hundred
/// stuck entries would spend the whole tick waiting for timeouts.
const MARK_BUDGET_PER_TICK: usize = 64;

/// What the sequencer remembers between drain ticks: the client for the
/// separate service, which database of that service it is talking to, and
/// which marks are in trouble.
pub(super) struct Drain {
    client: reqwest::Client,
    /// The epoch the separate service last announced. An epoch names one
    /// database. A new epoch means a new database, so nothing the sequencer
    /// remembers about entry ids applies any more.
    epoch: Option<String>,
    /// The marks that were refused, by entry id inside `epoch`.
    trouble: HashMap<i64, Trouble>,
    /// When this sequencer last wrote a line saying it cannot read the
    /// separate service.
    last_complaint: Option<Instant>,
}

/// How often the sequencer repeats that it cannot read the separate service.
/// See `Drain::complain`.
pub(super) const COMPLAIN_EVERY: Duration = Duration::from_secs(30);

/// One mark the separate service would not accept.
struct Trouble {
    /// Attempts since the last success. The wait before the next attempt
    /// grows with this count.
    attempts: u32,
    /// Of those attempts, how many were refusals rather than network
    /// failures. Only a refusal counts toward giving up. A separate service
    /// that cannot be reached comes back, and sending the mark again then is
    /// the right thing to do.
    refusals: u32,
    next_try: Instant,
    given_up: bool,
}

impl Drain {
    pub(super) fn new() -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .connect_timeout(INBOX_CONNECT_TIMEOUT)
            .timeout(INBOX_TIMEOUT)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Drain {
            client,
            epoch: None,
            trouble: HashMap::new(),
            last_complaint: None,
        })
    }

    /// Does the sequencer act on this entry in this tick?
    fn due(&self, inbox_id: i64, now: Instant) -> bool {
        match self.trouble.get(&inbox_id) {
            Some(trouble) => !trouble.given_up && trouble.next_try <= now,
            None => true,
        }
    }

    fn succeeded(&mut self, inbox_id: i64) {
        self.trouble.remove(&inbox_id);
    }

    /// Records a failed mark. Returns true when this attempt is the one that
    /// gives up, so the caller writes that line exactly once.
    fn failed(&mut self, inbox_id: i64, refused: bool, now: Instant) -> bool {
        let trouble = self.trouble.entry(inbox_id).or_insert(Trouble {
            attempts: 0,
            refusals: 0,
            next_try: now,
            given_up: false,
        });
        trouble.attempts += 1;
        if refused {
            trouble.refusals += 1;
        }
        let wait = MARK_RETRY_BASE
            .saturating_mul(1u32 << trouble.attempts.min(6))
            .min(MARK_RETRY_MAX);
        trouble.next_try = now + wait;
        if trouble.refusals >= MARK_REFUSAL_LIMIT && !trouble.given_up {
            trouble.given_up = true;
            return true;
        }
        false
    }
}

/// Sequences everything waiting in the separate service, then tells that
/// service what each entry became.
///
/// Each entry is sequenced once. The split between two records is what makes
/// that true. The pair (entry of the separate service -> message of the
/// sequencer) is written inside the sequencer's own transaction. The separate
/// service is told only after that transaction commits. A crash before the
/// commit sequences nothing. A crash after the commit but before the mark is
/// repaired on the next tick: the entry is still "pending" on the separate
/// service but is already in `inbox_sequenced`, so the next tick sends the
/// mark again instead of sequencing the entry again.
///
/// Every entry is checked first, against the same rules `POST /order`
/// applies. The sequencer is the party that signs the history, so the
/// sequencer itself has to be able to check what it signs. `--inbox-url` is a
/// plain flag that can point at any address. The checks that address says it
/// ran are not evidence to a service that has to stand behind the result.
pub(super) async fn drain_inbox(drain: &mut Drain, inbox_url: &str, state: &Arc<Mutex<FeedState>>) {
    let Some((epoch, pending)) = drain.pending(inbox_url).await else {
        return;
    };
    if drain.epoch.as_deref() != Some(epoch.as_str()) {
        if drain.epoch.is_some() {
            info!(
                "the inbox at {} announces epoch {}: it has a new database, so its entry ids \
                 start again and nothing recorded for the old one applies to them",
                inbox_url, epoch
            );
        }
        drain.epoch = Some(epoch.clone());
        drain.trouble.clear();
    }
    if pending.is_empty() {
        return;
    }

    let now = Instant::now();
    let due: Vec<InboxEntry> = pending
        .into_iter()
        .filter(|entry| drain.due(entry.inbox_id, now))
        .collect();
    if due.is_empty() {
        return;
    }

    // Sequencing and signing run under one lock. They run on a blocking
    // thread because the write ends in an fsync.
    let epoch_for_batch = epoch.clone();
    let Ok((marks, refused_at_intake)) = with_state(state, move |state| {
        sequence_drained(state, &epoch_for_batch, due)
    })
    .await
    else {
        return;
    };

    // An entry the sequencer will not sequence stays pending, and the
    // separate service goes on reporting it overdue. The reason for the
    // refusal goes no further than these two log lines. The sequencer does
    // not get to write its own excuse on the one interface a third party
    // reads. An alarm the sequencer cannot switch off is what that interface
    // is for.
    for (inbox_id, reason) in refused_at_intake {
        let now = Instant::now();
        let gave_up = drain.failed(inbox_id, true, now);
        if gave_up {
            error!(
                "giving up on inbox entry {}: {}. It stays pending and will be reported overdue; \
                 whatever is serving {} is not producing submissions this feed can sign",
                inbox_id, reason, inbox_url
            );
        } else {
            error!(
                "inbox entry {} cannot be sequenced: {}. The feed signs what it sequences, so it \
                 will not sign this",
                inbox_id, reason
            );
        }
    }

    // Entries sequenced in this tick go first. An entry whose mark keeps
    // being refused must not push newer entries past the tick's limit of 64
    // marks. The orders behind those newer entries are already trading. Only
    // the proof that names them is waiting.
    let mut marks = marks;
    marks.sort_by_key(|(_, fresh, _)| !*fresh);
    for (inbox_id, _, request) in marks.into_iter().take(MARK_BUDGET_PER_TICK) {
        let feed_id = request.feed_id;
        let outcome = client_mark(&drain.client, inbox_url, &request).await;
        let now = Instant::now();
        let transport_failure = matches!(outcome, Err((false, _)));
        match outcome {
            Ok(()) => drain.succeeded(inbox_id),
            // A refusal is not a lost packet. The separate service read this
            // mark and rejected it, for one of three reasons: one entry
            // sequenced twice, a message that is not what the user sent, or a
            // signature the service does not trust. The old code ignored
            // everything except a network error, which counted a refusal as a
            // success. That drops the one report which says the sequencer and
            // the separate service disagree about what happened.
            Err((refused, detail)) => {
                let gave_up = drain.failed(inbox_id, refused, now);
                if gave_up {
                    error!(
                        "giving up on marking inbox entry {} as message {} after {} refusals: {}. \
                         The message is sequenced and live; the entry stays pending on the inbox \
                         and will be reported overdue until an operator looks at why the two \
                         disagree",
                        inbox_id, feed_id, MARK_REFUSAL_LIMIT, detail
                    );
                } else if refused {
                    error!(
                        "inbox refused the mark for entry {} as message {}: {}",
                        inbox_id, feed_id, detail
                    );
                } else {
                    // The pair is written to disk on the sequencer's side.
                    // The separate service lists the entry as pending again,
                    // and a later tick sends the mark again.
                    warn!("could not mark inbox entry {}: {}", inbox_id, detail);
                }
            }
        }
        if transport_failure {
            // A separate service that accepts the connection and then does
            // not answer costs a full timeout for each mark. Sixty-four of
            // those is two minutes inside a 100ms tick, and the generator
            // publishes nothing for the whole two minutes. One timeout is
            // enough to know. A later tick sends the rest of the marks.
            break;
        }
    }
}

/// One entry's mark, and whether the message it names is one this pass is
/// writing. That flag decides two things: the order the marks are sent in,
/// and whether the mark may be sent at all when the write fails.
type PendingMark = (i64, bool, inbox::MarkRequest);

/// Sequences the entries this sequencer is the one to sequence, and signs a
/// mark for every entry whose pair it can prove.
///
/// Split out of `drain_inbox` for one reason. The decision made here for each
/// entry decides what the sequencer signs. This way a test can drive that
/// decision without a separate service on the other end of a socket.
///
/// Returns the marks to send, and the entries this sequencer refuses to
/// sequence at all, each with the reason for the refusal.
pub(super) fn sequence_drained(
    state: &mut FeedState,
    epoch: &str,
    due: Vec<InboxEntry>,
) -> (Vec<PendingMark>, Vec<(i64, String)>) {
    let mut batch: Vec<(Option<InboxKey>, OrderMessage)> = Vec::new();
    // (entry id, message id, does the mark wait on this batch's write)
    let mut pairs: Vec<(i64, OrderId, bool)> = Vec::new();
    // The entries this sequencer will not sequence, with the reason for each.
    let mut refused_at_intake: Vec<(i64, String)> = Vec::new();
    // The nonces this pass has given ids to. A nonce is a number the submitter
    // picks, and it names one submission. `state.nonces` is written only after
    // the batch commits. Without this map, a copy of a submission sitting next
    // to the original in one page of `/pending` would be sequenced beside it.
    let mut batch_nonces: HashMap<NonceKey, OrderId> = HashMap::new();
    for entry in due {
        let key = (epoch.to_string(), entry.inbox_id);
        // An earlier run of this sequencer already sequenced this entry. Only
        // the mark was lost, so only the mark is sent again.
        if let Some(feed_id) = state.inbox_sequenced.get(&key) {
            pairs.push((entry.inbox_id, *feed_id, false));
            continue;
        }
        if let Err(e) = inbox::validate_submission(&entry.submission) {
            // The separate service refuses a submission like this when it
            // arrives, so one that reaches here means the address is not the
            // service it claims to be. Skipping the entry leaves it pending,
            // so whatever answers that URL reports it overdue. That report is
            // correct. The wait before the next attempt grows the same way it
            // grows for a refused mark, because the problem has the same
            // shape: an entry nobody can act on, listed again on every tick.
            refused_at_intake.push((entry.inbox_id, e));
            continue;
        }
        // The account's own signature, checked again here against the keys
        // this sequencer has pinned. A pinned key is the first public key the
        // sequencer saw for an account, and every later message from that
        // account has to carry the same key. The separate service checked the
        // signature too, and that is not enough. `--inbox-url` is a plain flag
        // that can point at any address, and this sequencer is about to sign a
        // message that says account N asked for this. The sequencer has to be
        // able to show that itself.
        //
        // A refusal here is also the one case where the two services can
        // disagree and both be right: a different key reached each of them
        // first. So the reason is carried through to the log instead of being
        // reduced to "cannot sequence".
        let account = inbox::account_of(&entry.submission);
        let proved = inbox::verify_account_signature(&entry.signed())
            .and_then(|key| state.pin_or_check_account(account, &key));
        if let Err((_, why)) = proved {
            refused_at_intake.push((entry.inbox_id, why));
            continue;
        }
        // The log this submission was signed for, checked against the log this
        // sequencer is serving. `POST /order` makes the same call, so a
        // submission that arrives here and a submission that arrives there get
        // the same answer.
        //
        // The separate service does not make this call, and cannot: it would
        // have to ask this sequencer which session is current, and this
        // sequencer is the party it exists to distrust. See
        // `inbox::checked_session`. The cost of that is here: a submission
        // signed for a log that has gone is refused at this point, and the
        // entry stays pending and is reported overdue. That reads as
        // censorship and is not. It needs an operator who deleted `feed.db`
        // and kept `inbox.db`, because a reset renames the volume that holds
        // both.
        if let Err((_, why)) = inbox::check_session(&state.session, &entry.submission) {
            refused_at_intake.push((entry.inbox_id, why));
            continue;
        }
        // Read again from the submission, not assumed. Everything in this loop
        // came from a URL the operator passed on a flag. A panic here poisons
        // the sequencer's state lock, and a poisoned lock stops the process.
        let nonce = match inbox::checked_nonce(&entry.submission) {
            Ok(nonce) => nonce,
            Err(why) => {
                refused_at_intake.push((entry.inbox_id, why));
                continue;
            }
        };
        // The submission this entry holds may already be on the sequencer.
        // Somebody can read it off `GET /pending`, which serves the signature,
        // and send it to `POST /order`. Or the user can send the same signed
        // bytes to both.
        //
        // The entry is then not a problem to refuse. It is a question that is
        // already answered, because the message it asks for exists. So the
        // sequencer points the entry at that message and marks it, and the
        // separate service stops calling the entry pending. A check that only
        // asked "have I seen this signature" would refuse the entry instead.
        // That would leave a correct entry pending until it went overdue, and
        // the separate service would report censorship for an order that is
        // already trading. That failure is worse than the copied submission it
        // would stop, in a service whose product is evidence of censorship
        // that people can trust.
        let already = state
            .nonces
            .get(&(account, nonce))
            .map(|id| (*id, false))
            .or_else(|| batch_nonces.get(&(account, nonce)).map(|id| (*id, true)));
        if let Some((feed_id, in_this_batch)) = already {
            // The message has to be *this* submission before the sequencer
            // says the entry became it. It usually is, because the same signed
            // bytes reached both `POST /order` and the separate service. It is
            // not when one account signed two different submissions under one
            // nonce. Nothing stops an account doing that, because the
            // submitter chooses the nonce.
            //
            // Marking such an entry with the other message would write a
            // `content_mismatch` row in the rejection log of the separate
            // service. That log holds the marks the sequencer signed and the
            // service refused, so it is evidence about the *sequencer*. A
            // submitter that reuses its own nonce is not that, and it must not
            // be recorded as that. So the sequencer refuses the entry by name
            // instead, and the reason reaches the log.
            //
            // There are three answers here, not two. A message this build
            // cannot read is not a message that fails to match. It is a
            // message this sequencer cannot judge. The reason the sequencer
            // writes in its own log has to say which of the two happened. The
            // old code treated both the same and wrote "asks for something
            // else" about a message it had never read.
            let judged = if in_this_batch {
                Some(batch.iter().any(|(_, msg)| {
                    msg.id() == feed_id && inbox::message_matches(&entry.submission, msg)
                }))
            } else {
                state
                    .message(feed_id)
                    .map(|msg| inbox::message_matches(&entry.submission, &msg))
            };
            match judged {
                Some(true) => {}
                Some(false) => {
                    refused_at_intake.push((
                        entry.inbox_id,
                        format!(
                            "account {} already used this nonce for feed message {}, which asks \
                             for something else. A nonce names one submission; this one has to be \
                             signed again with a fresh nonce before it can be sequenced",
                            account, feed_id
                        ),
                    ));
                    continue;
                }
                // The entry stays pending and is reported overdue, so a
                // censorship alarm fires for something that is not
                // censorship. The case is narrow. It needs a message that a
                // newer build published through `POST /order` rather than
                // through the separate service, and then a sequencer that was
                // rolled back to an older build. Closing the case needs the
                // sequencer to say "this entry is that message, and I cannot
                // stand behind the content". The mark protocol carries no way
                // to say that.
                None => {
                    refused_at_intake.push((
                        entry.inbox_id,
                        format!(
                            "account {} already used this nonce for feed message {}, which this \
                             build cannot read, so it cannot tell whether that message is this \
                             submission. This is not the submitter's fault and it is not \
                             censorship: upgrade this sequencer",
                            account, feed_id
                        ),
                    ));
                    continue;
                }
            }
            info!(
                "inbox entry {} carries a submission already published as message {}; resolving \
                 the entry against it rather than sequencing it twice",
                entry.inbox_id, feed_id
            );
            // `in_this_batch` says whether that message is one this pass is
            // still trying to write. When it is, the mark waits on the same
            // commit the message waits on.
            pairs.push((entry.inbox_id, feed_id, in_this_batch));
            continue;
        }
        let id = state.next_id;
        state.next_id += 1;
        let timestamp = state.clock.now_ms();
        // The message is the submission field for field, with an id and a
        // timestamp added. The separate service compares the two exactly when
        // it checks the mark. `POST /order` calls the same function, so a
        // submission taken from the separate service becomes the same message
        // it would have become through `POST /order`.
        let msg = inbox::message_from(id, timestamp, &entry.submission);
        info!(
            "Sequencing inbox entry {} as message {}",
            entry.inbox_id, id
        );
        batch.push((Some(key), msg));
        batch_nonces.insert((account, nonce), id);
        pairs.push((entry.inbox_id, id, true));
    }
    let sequenced = state.sequence(batch).is_ok();
    if pairs.is_empty() {
        // There is nothing to prove, so no head is signed. A tick that refused
        // every entry must not cost an Ed25519 signature under the state lock.
        return (Vec::new(), refused_at_intake);
    }
    // The head is signed after sequencing, so the tree already holds every
    // leaf a mark can prove. One head covers the whole pass, not one head for
    // each mark. Every mark this pass sends is proved against the same tree.
    // Signing a head for each entry would cost one Ed25519 signature each,
    // under the state lock, for heads that all say the same thing.
    let head = match state.signed_tree_head() {
        Ok(head) => head,
        Err(e) => {
            // No head means no proof, so this pass sends no mark. The entries
            // stay pending on the separate service and are reported overdue.
            // That report is correct: the entries were sequenced, and this
            // sequencer cannot show it.
            error!(
                "this feed cannot read its own Merkle tree, so none of the {} entries it \
                 sequenced this pass can be marked: {}",
                pairs.len(),
                e
            );
            return (Vec::new(), refused_at_intake);
        }
    };
    let tree_head = inbox::TreeHead {
        session: head.session.clone(),
        timestamp: head.timestamp,
        tree_size: head.tree_size,
        root_hash: head.root_hash.clone(),
        signature: head.signature.clone(),
    };
    // The separate service accepts a mark only from this key, and only with
    // the message's stored bytes and a proof that those bytes are in the tree
    // this head covers. The service can then check the pair by hashing alone,
    // even for a kind of message neither service can read.
    let marks = pairs
        .into_iter()
        .filter_map(|(inbox_id, feed_id, fresh)| {
            if fresh && !sequenced {
                // The write failed, so this entry was not sequenced and
                // nothing was published. A mark that said otherwise is the
                // one thing that would make the failure impossible to recover
                // from.
                return None;
            }
            // The bytes as they were stored, not a message written out again
            // from a struct. Stored bytes are what makes this work for a kind
            // of message this build cannot read, and the leaf is the hash of
            // those bytes. Any other bytes would hash to something that is not
            // in the tree. The bytes are read back from the database when the
            // message has left the window of recent messages. That is the
            // ordinary case for an entry this sequencer sequenced in an
            // earlier run and has not been able to mark since.
            let Some(json) = state.stored_json(feed_id) else {
                // There is nothing to prove the pair with, so the sequencer
                // claims nothing. The entry stays pending on the separate
                // service and is reported overdue. That report is correct.
                warn!(
                    "inbox entry {} is recorded as message {}, which this feed no longer has; \
                     not marking it",
                    inbox_id, feed_id
                );
                return None;
            };
            // Leaf `n` is message `n + 1`. See `FeedState::tree`. The
            // separate service works the same index out from `feed_id`
            // instead of trusting an index sent to it, so it refuses a proof
            // for any other leaf.
            let Some(leaf_index) = feed_id.checked_sub(1) else {
                warn!("message 0 is not a feed message; not marking inbox entry {inbox_id}");
                return None;
            };
            let path = match state.inclusion_proof(leaf_index, tree_head.tree_size) {
                Ok(path) => path,
                Err(e) => {
                    // The head is this sequencer's own, and it covers
                    // everything the sequencer has published. So a failure
                    // here is a bug in this code, not a state the outside
                    // world can put the sequencer in. The sequencer still
                    // claims nothing: the entry stays pending.
                    error!(
                        "no inclusion proof for message {} against this feed's own head at size \
                         {}: {}. Inbox entry {} is not marked",
                        feed_id, tree_head.tree_size, e, inbox_id
                    );
                    return None;
                }
            };
            Some((
                inbox_id,
                fresh,
                inbox::signed_mark(
                    &state.signing_key,
                    epoch,
                    inbox_id,
                    feed_id,
                    &json,
                    tree_head.clone(),
                    path,
                ),
            ))
        })
        .collect();
    (marks, refused_at_intake)
}

/// Sends one mark. `Err((true, _))` is a refusal by the separate service.
/// `Err((false, _))` is a network failure.
async fn client_mark(
    client: &reqwest::Client,
    inbox_url: &str,
    request: &inbox::MarkRequest,
) -> Result<(), (bool, String)> {
    match client
        .post(format!("{}/mark", inbox_url))
        .json(request)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) => {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err((true, format!("{} {}", status, body.trim())))
        }
        Err(e) => Err((false, e.to_string())),
    }
}

impl Drain {
    /// Reads the pending entries of the separate service, and the epoch they
    /// belong to.
    ///
    /// None of what comes back is this sequencer's own data, so it is limited
    /// in three ways. A response bigger than `MAX_PENDING_BYTES` is refused
    /// before it is parsed. No more than one page of entries is taken from
    /// it. The epoch has to look like an epoch before it is used as part of a
    /// database key.
    async fn pending(&mut self, inbox_url: &str) -> Option<(String, Vec<InboxEntry>)> {
        let client = self.client.clone();
        let response = match client.get(format!("{}/pending", inbox_url)).send().await {
            Ok(response) => response,
            Err(e) => {
                self.complain(format_args!("inbox unreachable at {}: {}", inbox_url, e));
                return None;
            }
        };
        if !response.status().is_success() {
            self.complain(format_args!(
                "inbox at {} answered {}",
                inbox_url,
                response.status()
            ));
            return None;
        }
        let epoch = response
            .headers()
            .get(inbox::PENDING_EPOCH_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(String::from);
        let Some(epoch) = epoch.filter(|epoch| valid_epoch(epoch)) else {
            self.complain(format_args!(
                "the inbox at {} did not name its epoch on /pending, so its entry ids cannot be \
                 told apart from a previous database's; not draining it",
                inbox_url
            ));
            return None;
        };
        // The address is named inside `what`, not added around the error.
        // `read_bounded` builds one sentence, and this way that sentence holds
        // the whole message.
        let what = format!("/pending from {}", inbox_url);
        let body = match read_bounded(response, &what, MAX_PENDING_BYTES).await {
            Ok(body) => body,
            Err(e) => {
                self.complain(format_args!("{}", e));
                return None;
            }
        };
        match serde_json::from_slice::<Vec<InboxEntry>>(&body) {
            Ok(mut entries) => {
                self.last_complaint = None;
                entries.truncate(inbox::PAGE_LIMIT);
                Some((epoch, entries))
            }
            Err(e) => {
                self.complain(format_args!(
                    "could not parse the response from {}: {}",
                    inbox_url, e
                ));
                None
            }
        }
    }

    /// Writes one line saying the separate service cannot be read, then at
    /// most one more line every `COMPLAIN_EVERY`.
    ///
    /// The drain runs ten times a second. A separate service that is down, or
    /// that answers with something this sequencer will not use, made ten
    /// identical lines a second for as long as the fault lasted. Those lines
    /// pushed every other line out of the log, including the ones that
    /// matter.
    fn complain(&mut self, message: std::fmt::Arguments) {
        let now = Instant::now();
        let due = self
            .last_complaint
            .is_none_or(|last| now.duration_since(last) >= COMPLAIN_EVERY);
        if due {
            self.last_complaint = Some(now);
            warn!("{}", message);
        }
    }
}

/// The sequencer uses an epoch as part of a primary key, and prints it in
/// logs. So an epoch has to be short and plain, whatever address served it.
fn valid_epoch(epoch: &str) -> bool {
    !epoch.is_empty()
        && epoch.len() <= 64
        && epoch
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the sequencer does with a mark the separate service keeps
    /// refusing. It waits longer after each attempt, and then stops, instead
    /// of writing an error line on every tick forever.
    #[test]
    fn a_refused_mark_backs_off_and_gives_up() {
        let mut drain = Drain::new().expect("client");
        let now = Instant::now();
        assert!(drain.due(1, now), "a mark with no history is due");

        assert!(!drain.failed(1, true, now));
        assert!(!drain.due(1, now), "and waits before the next attempt");
        assert!(drain.due(1, now + MARK_RETRY_MAX));

        let mut gave_up = false;
        for _ in 1..MARK_REFUSAL_LIMIT {
            gave_up = drain.failed(1, true, now);
        }
        assert!(gave_up, "it says so exactly once");
        assert!(!drain.failed(1, true, now), "and not again");
        assert!(
            !drain.due(1, now + Duration::from_secs(86_400)),
            "a mark that was given up on is not retried again"
        );

        // None of that changed the record for a different entry.
        assert!(drain.due(2, now));
        drain.succeeded(1);
        assert!(drain.due(1, now), "a success clears the record");
    }

    #[test]
    fn an_epoch_has_to_look_like_an_epoch() {
        assert!(valid_epoch("0123456789abcdef"));
        assert!(valid_epoch("prod-inbox_2"));
        assert!(!valid_epoch(""));
        assert!(!valid_epoch("a".repeat(65).as_str()));
        assert!(!valid_epoch("has spaces"));
        assert!(!valid_epoch("../../etc/passwd"));
    }
}
