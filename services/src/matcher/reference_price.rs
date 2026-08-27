//! The price the protection collar is measured from.
//!
//! **This is not a step.** ENGINE.md section 4.0 says why it cannot be one.
//! Section 4.2 asks for a time-weighted mid price, and that is state which
//! lives across messages. Step 3 may only read the reference price. Step 5 is
//! what moves the book, and nobody may edit step 5. No step owns state that
//! outlives one message. So the window lives here, beside the steps, and
//! `MatcherState` holds one. `apply_new` and `apply_cancel` hand the window a
//! sample after they have finished with a book, and hand step 3 the number the
//! window returns.
//!
//! ENGINE.md section 4.2.1 writes out the rule this file implements. That text
//! is the specification `verify.rs` writes its own copy from, so a change here
//! is a change in ENGINE.md first.
//!
//! # Why the mid and not the last trade
//!
//! The mid is the price halfway between the best bid and the best ask.
//!
//! One trade moves the last trade price, and that trade can be an account
//! trading against its own resting order. Moving this average is much harder.
//! An account has to stand an order on one side of a real book and leave it
//! there. For the reference price to reach halfway to a price the account
//! chose, the account has to hold that order for half the window, and anybody
//! is free to fill it while it waits.
//!
//! The zero-weight rule is what makes that true. A sample that has held for
//! zero milliseconds counts for nothing. So placing an order and trading
//! against it inside one millisecond moves the reference price by exactly
//! nothing.
//!
//! # Why the sums are kept and not recomputed
//!
//! The exchange asks for the reference price on every new order, and it asks
//! before the book moves. Reading every sample each time costs more as the
//! sequencer runs faster. `observe` keeps one sample a millisecond, so a
//! sequencer at 1,000 messages a second fills the window with 30,000 samples,
//! and every order walks all 30,000.
//! `measures_matching_a_mix_of_orders_and_cancels` runs the same 200,000
//! messages four times and changes only the timestamps. The walk took the
//! exchange from 1,532,062 messages a second at 400 ms apart down to 183,801
//! at 1 ms apart. That is an eightfold fall, and 1 ms is the worst case,
//! because a timestamp is a whole millisecond.
//!
//! With the sums kept, the same four runs give 1,588,263 and 1,687,354. The
//! rate no longer changes the cost.
//!
//! So the sums are kept. A sample that is no longer the newest holds for a
//! fixed length of time. Its part of the average never changes again, so it
//! goes into `closed_weighted` and `closed_weight` once. A query then adds two
//! things to those sums. The first is the newest sample, which holds up to the
//! moment being asked about. The second is a correction for the window
//! opening, which has moved on since the last sample arrived.
//!
//! **The answer does not change.** Every term is an exact `i128` product of a
//! whole number of milliseconds and a whole number of cents, and there is one
//! division at the end. Adding the same whole numbers in a different order
//! gives the same total, so the kept sums and the walk give the same bytes.
//! `the_kept_sums_and_the_walk_agree_on_an_awkward_run` drives both over the
//! same samples and the same query times, and compares the two answers.
//!
//! `walked` is still here, and it is still the plain reading of the rule.
//! `walked` answers on its own whenever a message asks about a moment the
//! window has already moved past, because the kept sums cover samples that
//! reach beyond that moment.
//!
//! # What this deliberately does not do
//!
//! The window is not written to disk and it is not in the state root. An
//! engine resumed from the state database starts with an empty window. It has
//! no reference price, so it refuses market orders until it has watched a book
//! for long enough. That is a refusal, and never a wrong fill. It is still a
//! real difference between a resumed engine and `--audit`, which replays the
//! same history from message 1 and does have the window. Putting the window in
//! the state root instead would change the root's encoding, and every run has
//! already committed to that encoding.

use std::collections::{HashMap, VecDeque};

/// How far back the reference price is averaged over, in milliseconds.
///
/// Thirty seconds is long enough that holding the mid at a wrong price for
/// that whole time means leaving an order anybody can fill. It is short enough
/// that the reference price follows a market that has really moved. The
/// sequencer's generator moves a mid by up to 0.2% per message, so a run of
/// messages all going one way carries the reference price with it well inside
/// one window.
pub(super) const WINDOW_MS: u64 = 30_000;

/// The mid prices one engine has watched, per symbol.
#[derive(Debug, Default)]
pub(super) struct MidWindow {
    per_symbol: HashMap<String, SymbolWindow>,
}

/// One symbol's samples, and the running sums over the samples that are no
/// longer the newest.
///
/// Every entry of `samples` is `(timestamp, mid)`, and it holds from its own
/// timestamp until the next entry's timestamp. `None` is a book with one side
/// empty, which has no mid. A `None` entry ends the sample before it, instead
/// of letting a price that no longer exists keep its weight. Without that
/// rule, an account could place an order and cancel it, and the mid that order
/// produced would stay in the average until it left the window.
///
/// The timestamps always go up. `observe` replaces a sample rather than adding
/// a second one at the same millisecond.
#[derive(Debug, Default)]
struct SymbolWindow {
    /// The samples, oldest first.
    samples: VecDeque<(u64, Option<i64>)>,
    /// The sum of `mid * held` over every sample except the newest, in cents
    /// times milliseconds, counting only the part at or after `clip_ms`.
    ///
    /// The newest sample is left out because how long it holds depends on the
    /// moment a query asks about, and that moment is different every time.
    closed_weighted: i128,
    /// The sum of `held` over the same samples, in milliseconds. The sum is
    /// never negative and never more than `WINDOW_MS`, because the holds do
    /// not overlap and all of them lie between `clip_ms` and the newest
    /// sample.
    closed_weight: i128,
    /// The moment the two sums above start counting from. That moment is the
    /// window opening of the last `observe`.
    clip_ms: u64,
}

impl SymbolWindow {
    /// How many samples this symbol holds.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.samples.len()
    }

    /// What the kept sums lose when the window opening moves forward from
    /// `clip_ms` to `clip`, as `(weighted, weight)`.
    ///
    /// Only the oldest samples lose anything, and the walk stops at the first
    /// sample that still holds when the window opens. Every sample the walk
    /// passes is one `clip_to` then drops. So over the life of the window,
    /// this walk costs each sample one visit.
    ///
    /// The caller must pass a `clip` at or after `clip_ms`.
    fn loss_to(&self, clip: u64) -> (i128, i128) {
        let mut weighted: i128 = 0;
        let mut weight: i128 = 0;
        let mut index = 0;
        while index + 1 < self.samples.len() {
            let (from, mid) = self.samples[index];
            if from >= clip {
                break;
            }
            let to = self.samples[index + 1].0;
            if let Some(mid) = mid {
                // The part of this hold that lay between the old opening and
                // the new one. `saturating_sub` reads a hold that had already
                // ended before the old opening as nothing.
                let lost = to.min(clip).saturating_sub(from.max(self.clip_ms)) as i128;
                weight += lost;
                weighted += mid as i128 * lost;
            }
            if to > clip {
                break;
            }
            index += 1;
        }
        (weighted, weight)
    }

    /// Moves the moment the kept sums start counting from to `clip`, corrects
    /// the sums, and drops the samples that can no longer be read.
    fn clip_to(&mut self, clip: u64) {
        if clip >= self.clip_ms {
            let (weighted, weight) = self.loss_to(clip);
            self.closed_weighted -= weighted;
            self.closed_weight -= weight;
        } else if let Some(&(from, mid)) = self.samples.front() {
            // The window opens earlier than it did, so the oldest sample holds
            // for longer again. Only that one sample can reach back before the
            // old opening. `clip_to` drops every sample whose whole hold ends
            // at or before the opening, so the second sample always starts
            // after the old opening.
            if let (Some(mid), Some(&(to, _))) = (mid, self.samples.get(1)) {
                let gained = (to.min(self.clip_ms).max(from) - to.min(clip).max(from)) as i128;
                self.closed_weight += gained;
                self.closed_weighted += mid as i128 * gained;
            }
        }
        self.clip_ms = clip;

        // Every sample older than the window is out of reach of every future
        // question, because the window can only move forward. The one sample
        // that starts before the window opens stays, because that sample is
        // what held at the moment the window opens.
        while self.samples.len() >= 2 && self.samples[1].0 <= clip {
            self.samples.pop_front();
        }

        debug_assert!(
            self.closed_weight >= 0 && self.closed_weight <= WINDOW_MS as i128,
            "the kept weight is {} milliseconds, and a window holds at most {}",
            self.closed_weight,
            WINDOW_MS
        );
    }

    /// The `(weighted, weight)` pair the reference price divides, at `at_ms`,
    /// over a window that opens at `opens_at`.
    fn sums_at(&self, at_ms: u64, opens_at: u64) -> (i128, i128) {
        let Some(&(newest_at, newest_mid)) = self.samples.back() else {
            return (0, 0);
        };
        // A message carries its own timestamp, and nobody has checked that the
        // timestamp goes up. So the window can be asked about a moment it has
        // already moved past. The kept sums cannot answer that question. They
        // cover samples that reach beyond the moment asked about, and they
        // start at an opening later than the one this question wants.
        if at_ms < newest_at || opens_at < self.clip_ms {
            return self.walked(at_ms, opens_at);
        }

        // The window has moved on since the last sample arrived, so the oldest
        // holds have lost their earliest part.
        let (lost_weighted, lost_weight) = self.loss_to(opens_at);
        let mut weighted = self.closed_weighted - lost_weighted;
        let mut weight = self.closed_weight - lost_weight;

        // The newest sample holds up to the moment being asked about.
        if let Some(mid) = newest_mid {
            let held = at_ms.saturating_sub(newest_at.max(opens_at)) as i128;
            weight += held;
            weighted += mid as i128 * held;
        }
        (weighted, weight)
    }

    /// The same pair, read straight off every sample.
    ///
    /// This function is the plain statement of ENGINE.md 4.2.1, and it is what
    /// `sums_at` has to agree with. It also answers on its own whenever a
    /// message asks about a moment the window has already moved past.
    ///
    /// The arithmetic runs in `i128` so that a long window of large prices
    /// cannot wrap round. 30,000 milliseconds times the largest price this
    /// engine holds is 3e13, and every sample adds another number that size.
    fn walked(&self, at_ms: u64, opens_at: u64) -> (i128, i128) {
        let mut weighted: i128 = 0;
        let mut weight: i128 = 0;
        for (index, (from, mid)) in self.samples.iter().enumerate() {
            let Some(mid) = mid else { continue };
            // A sample holds until the next sample starts. The newest sample
            // holds until the moment being asked about.
            let until = self
                .samples
                .get(index + 1)
                .map_or(at_ms, |(next, _)| *next)
                .min(at_ms);
            let held_from = (*from).max(opens_at);
            if until <= held_from {
                continue;
            }
            let held = (until - held_from) as i128;
            weighted += *mid as i128 * held;
            weight += held;
        }
        (weighted, weight)
    }
}

impl MidWindow {
    /// Records what a symbol's mid became, at the millisecond on the message
    /// that moved its book.
    ///
    /// Three kinds of sample are not kept. None of them can change an answer,
    /// and all of them cost memory:
    ///
    /// - a sample at the same millisecond as the sample before it. The earlier
    ///   sample held for zero milliseconds and weighs nothing, so the new one
    ///   replaces it. That rule is also what limits the size of the window:
    ///   one entry per millisecond, so at most 30,000 per symbol however fast
    ///   messages arrive.
    /// - a sample repeating the mid the window already ends with. Cutting one
    ///   stretch of time into two stretches at the same price gives the same
    ///   average.
    /// - a sample older than the sample before it. A timestamp comes off the
    ///   message, and nobody has checked that it goes up, so the window reads
    ///   it as the last timestamp that did. A message cannot wind the window
    ///   back.
    pub(super) fn observe(&mut self, symbol: &str, at_ms: u64, mid_cents: Option<i64>) {
        let window = self.per_symbol.entry(symbol.to_string()).or_default();
        let newest = window.samples.back().copied();
        let at = match newest {
            Some((last, _)) => at_ms.max(last),
            None => at_ms,
        };
        match newest {
            Some((last, _)) if last == at => {
                // The newest sample is the one whose hold is still open. It is
                // not in the kept sums, so only its mid changes.
                if let Some(sample) = window.samples.back_mut() {
                    sample.1 = mid_cents;
                }
            }
            Some((_, mid)) if mid == mid_cents => {}
            _ => {
                // The sample that was newest stops here. Its hold now has a
                // fixed length, so it joins the kept sums.
                if let Some((from, Some(mid))) = newest {
                    let held = at.saturating_sub(from.max(window.clip_ms)) as i128;
                    window.closed_weight += held;
                    window.closed_weighted += mid as i128 * held;
                }
                window.samples.push_back((at, mid_cents));
            }
        }
        window.clip_to(at.saturating_sub(WINDOW_MS));
    }

    /// The reference price for `symbol` at `at_ms`, in cents, or `None` when
    /// there is none, see ENGINE.md 4.2.1. A caller that gets `None` has to
    /// refuse the order, not guess.
    pub(super) fn reference_cents(&self, symbol: &str, at_ms: u64) -> Option<i64> {
        let window = self.per_symbol.get(symbol)?;
        let opens_at = at_ms.saturating_sub(WINDOW_MS);
        let (weighted, weight) = window.sums_at(at_ms, opens_at);
        (weight > 0).then(|| (weighted / weight) as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::order_terms::MidHistory;

    /// The behaviour the whole design is for: a mid that held for no time at
    /// all moves the reference price by nothing. Placing an order and trading
    /// against it inside one millisecond is exactly that case.
    #[test]
    fn a_mid_that_held_for_no_time_moves_the_reference_by_nothing() {
        let mut window = MidWindow::default();
        window.observe("ETH-USDC", 1_000, Some(10_000));
        // The attacker's order, and the order it is meant to price, arrive in
        // the same millisecond.
        window.observe("ETH-USDC", 31_000, Some(90_000));
        assert_eq!(
            window.reference_cents("ETH-USDC", 31_000),
            Some(10_000),
            "the 90,000 mid has held for zero milliseconds"
        );
    }

    /// The other half of the rule: holding the mid at a wrong price does move
    /// the reference price, by as much as the time the price was held.
    #[test]
    fn moving_the_reference_costs_the_whole_window() {
        let mut window = MidWindow::default();
        window.observe("ETH-USDC", 0, Some(10_000));
        window.observe("ETH-USDC", 30_000, Some(20_000));
        // Half a window at each price, so the average sits halfway.
        assert_eq!(window.reference_cents("ETH-USDC", 45_000), Some(15_000));
        // A tenth of the window at the new price moves it a tenth of the way.
        assert_eq!(window.reference_cents("ETH-USDC", 33_000), Some(11_000));
    }

    /// A window with nothing in it, and a window whose samples all sit at one
    /// instant, both answer "there is no reference price" rather than a number.
    #[test]
    fn no_elapsed_time_is_no_reference_price() {
        let window = MidWindow::default();
        assert_eq!(window.reference_cents("ETH-USDC", 5_000), None);

        let mut window = MidWindow::default();
        window.observe("ETH-USDC", 7, Some(10_000));
        assert_eq!(window.reference_cents("ETH-USDC", 7), None);
        assert_eq!(window.reference_cents("ETH-USDC", 8), Some(10_000));
    }

    /// A book with one side empty has no mid, and the price that book used to
    /// show stops counting the moment the side goes away. Without that rule,
    /// an account could place an order and cancel it, and the mid that order
    /// produced would stay in the average for a whole window.
    #[test]
    fn a_cancelled_quote_stops_counting_when_it_is_cancelled() {
        let mut window = MidWindow::default();
        window.observe("ETH-USDC", 0, Some(10_000));
        window.observe("ETH-USDC", 1_000, Some(90_000));
        // The order that produced the 90,000 mid is taken off the book here.
        window.observe("ETH-USDC", 2_000, None);
        // One second at 10,000, one second at 90,000, and nothing after. The
        // average covers the two seconds that had a mid, and the gap after
        // them adds no weight.
        assert_eq!(window.reference_cents("ETH-USDC", 10_000), Some(50_000));
    }

    /// Only what is inside the window counts. A price from before the window
    /// is not in the average, but it is the price the window opens on when
    /// nothing newer has replaced it.
    #[test]
    fn the_window_forgets_what_is_older_than_it() {
        let mut window = MidWindow::default();
        window.observe("ETH-USDC", 0, Some(10_000));
        window.observe("ETH-USDC", 10_000, Some(20_000));
        // At 40,000 the window opens at 10,000, so only the second price is in
        // it at all.
        assert_eq!(window.reference_cents("ETH-USDC", 40_000), Some(20_000));
        // At 35,000 the window opens at 5,000: 5,000 ms of the first price and
        // 25,000 of the second.
        assert_eq!(
            window.reference_cents("ETH-USDC", 35_000),
            Some((10_000 * 5_000 + 20_000 * 25_000) / 30_000)
        );
    }

    /// A timestamp that goes backwards is read as the last one that did not, so
    /// a message cannot wind the window back and buy its own price more weight
    /// than the time it really held for.
    #[test]
    fn a_timestamp_that_goes_backwards_does_not_move_the_window() {
        let mut window = MidWindow::default();
        window.observe("ETH-USDC", 0, Some(10_000));
        window.observe("ETH-USDC", 10_000, Some(20_000));
        // Backdated by five seconds. The window reads the sample as arriving
        // at 10,000, where the window already stood.
        window.observe("ETH-USDC", 5_000, Some(90_000));
        assert_eq!(
            window.reference_cents("ETH-USDC", 20_000),
            Some((10_000 * 10_000 + 90_000 * 10_000) / 20_000),
            "10 seconds at 10,000 and 10 at 90,000"
        );
        // Had the backdating worked, 90,000 would have held for 15 seconds and
        // the answer would have been 70,000.
        assert_ne!(window.reference_cents("ETH-USDC", 20_000), Some(70_000));
    }

    /// Two symbols do not share a reference price.
    #[test]
    fn each_symbol_has_its_own_window() {
        let mut window = MidWindow::default();
        window.observe("ETH-USDC", 0, Some(10_000));
        window.observe("BTC-USDC", 0, Some(100_000));
        assert_eq!(window.reference_cents("ETH-USDC", 5_000), Some(10_000));
        assert_eq!(window.reference_cents("BTC-USDC", 5_000), Some(100_000));
        assert_eq!(window.reference_cents("MERKLE-USDC", 5_000), None);
    }

    /// However many messages arrive, one symbol keeps at most one sample per
    /// millisecond of the window. That limit is what stops a burst of messages
    /// at one price from growing `samples` without end.
    #[test]
    fn the_window_holds_one_sample_a_millisecond_however_many_arrive() {
        let mut window = MidWindow::default();
        for tick in 0..100_000u64 {
            // A different mid every time, so nothing is dropped as a repeat.
            window.observe("ETH-USDC", tick / 10, Some(10_000 + (tick as i64 % 7)));
        }
        let samples = window.per_symbol["ETH-USDC"].len();
        assert!(
            samples <= 10_001,
            "100,000 messages over 10,000 milliseconds left {} samples",
            samples
        );
    }

    /// A run of samples and query times that is hard on purpose, for the two
    /// tests below. It is a plain list, so both tests read the same numbers.
    ///
    /// The run holds: a mid that repeats, a mid that changes every
    /// millisecond, a book with a side missing, a long quiet gap, a second gap
    /// longer than the whole window, a sample at the same millisecond as the
    /// one before it, and a timestamp that goes backwards. Every step also
    /// asks the window for a price, and some of those questions are about a
    /// time long after the newest sample.
    ///
    /// The `at_ms` of each step never goes down. Both the exchange and the
    /// checker read the timestamps off the sequencer in the order the
    /// sequencer published them, so that is the order they are driven in here.
    fn awkward_run() -> Vec<(u64, Option<i64>, Vec<u64>)> {
        let mut run: Vec<(u64, Option<i64>, Vec<u64>)> = Vec::new();
        // A quiet start, one sample a second, and the same mid four times over.
        for second in 0..8u64 {
            let at = second * 1_000;
            run.push((
                at,
                Some(10_000 + (second as i64 / 4) * 25),
                vec![at, at + 1],
            ));
        }
        // A burst: one sample a millisecond for four seconds, with the mid
        // moving every time, and a query on every one of them.
        for tick in 0..4_000u64 {
            let at = 8_000 + tick;
            run.push((at, Some(10_050 + (tick as i64 % 37)), vec![at]));
        }
        // Two samples at the same millisecond. The second replaces the first.
        run.push((12_000, Some(9_000), vec![12_000]));
        run.push((12_000, Some(11_000), vec![12_000, 12_001]));
        // A side of the book goes away, and comes back nine seconds later.
        run.push((13_000, None, vec![13_000, 15_000, 20_000]));
        run.push((22_000, Some(12_500), vec![22_000, 25_000]));
        // A quiet gap that is longer than the window, so the window empties of
        // everything but the sample that holds across it.
        run.push((
            100_000,
            Some(12_600),
            vec![60_000, 100_000, 129_999, 130_001],
        ));
        // A backdated message. The exchange and the checker both read it as
        // arriving where the window stands.
        run.push((99_000, Some(15_000), vec![100_000, 101_000]));
        // A burst again, on top of a window that has just been emptied, with
        // queries far past the newest sample.
        for tick in 0..2_000u64 {
            let at = 101_000 + tick * 3;
            run.push((at, Some(15_000 - (tick as i64 % 53)), vec![at, at + 20_000]));
        }
        // A last long quiet stretch: every query here is past the whole window.
        run.push((
            200_000,
            Some(14_000),
            vec![200_000, 215_000, 230_000, 400_000],
        ));
        run
    }

    /// The kept sums and the plain walk answer the same on every question the
    /// awkward run asks.
    ///
    /// This is the test the whole change rests on. `sums_at` adds the same
    /// whole numbers of milliseconds and cents that `walked` adds, in a
    /// different order. So the two totals are equal, and the one division at
    /// the end gives the same cents. This test trusts none of that argument.
    /// It drives both functions and compares the answers.
    #[test]
    fn the_kept_sums_and_the_walk_agree_on_an_awkward_run() {
        let mut window = MidWindow::default();
        let mut asked = 0u32;
        let mut answered = 0u32;
        for (at_ms, mid, queries) in awkward_run() {
            window.observe("ETH-USDC", at_ms, mid);
            let symbol = &window.per_symbol["ETH-USDC"];
            for query in queries {
                let opens_at = query.saturating_sub(WINDOW_MS);
                let kept = symbol.sums_at(query, opens_at);
                let walk = symbol.walked(query, opens_at);
                assert_eq!(
                    kept, walk,
                    "at {}, the kept sums say {:?} and the walk says {:?}",
                    query, kept, walk
                );
                asked += 1;
                answered += u32::from(walk.1 > 0);
            }
        }
        // The run asks 8,034 questions. The check below is here so that a
        // later edit to `awkward_run` cannot shrink the run to nothing without
        // saying so.
        assert!(asked > 8_000, "only {} questions were asked", asked);
        assert!(
            answered > asked / 2,
            "only {} of {} questions had a price at all, so most of this test \
             compared nothing",
            answered,
            asked
        );
    }

    /// The same run, and backwards as well. The window is asked about moments
    /// it has already moved past.
    ///
    /// A message carries its own timestamp, and nobody has checked that the
    /// timestamp goes up, so a real sequencer can ask this question. `sums_at`
    /// hands the question to `walked`, and this test is what says so.
    #[test]
    fn a_question_about_a_moment_already_past_reads_the_same_as_the_walk() {
        let mut window = MidWindow::default();
        for (at_ms, mid, queries) in awkward_run() {
            window.observe("ETH-USDC", at_ms, mid);
            let symbol = &window.per_symbol["ETH-USDC"];
            for query in queries {
                // Every query the run makes, and the same moment 1 ms, 1 s and
                // 40 s earlier than the sample that has just arrived.
                for back in [0, 1, 1_000, 40_000, 200_000] {
                    let query = query.saturating_sub(back);
                    let opens_at = query.saturating_sub(WINDOW_MS);
                    assert_eq!(
                        symbol.sums_at(query, opens_at),
                        symbol.walked(query, opens_at),
                        "at {}, {} ms before the query the run makes",
                        query,
                        back
                    );
                }
            }
        }
    }

    /// The exchange's window and the checker's history answer the same price
    /// over the awkward run.
    ///
    /// The two hold different samples on purpose. The exchange drops a sample
    /// that repeats the mid before it. The checker keeps that sample and cuts
    /// one hold into two holds at the same price. ENGINE.md 4.2.1 says the
    /// average is the same either way, and this test checks that claim instead
    /// of repeating it.
    ///
    /// The checker keeps its plain walk. The walk is the second reading of one
    /// rule, and a second reading that shares the first one's code cannot
    /// disagree with it.
    #[test]
    fn the_exchange_and_the_checker_reach_the_same_reference_price() {
        let mut window = MidWindow::default();
        let mut history = MidHistory::default();
        let mut compared = 0u32;
        let mut priced = 0u32;
        for (at_ms, mid, queries) in awkward_run() {
            window.observe("ETH-USDC", at_ms, mid);
            history.showed("ETH-USDC", at_ms, mid);
            for query in queries {
                let exchange = window.reference_cents("ETH-USDC", query);
                let checker = history.reference_cents("ETH-USDC", query);
                assert_eq!(
                    exchange, checker,
                    "at {}, the exchange says {:?} and the checker says {:?}",
                    query, exchange, checker
                );
                compared += 1;
                priced += u32::from(exchange.is_some());
            }
        }
        assert!(compared > 8_000, "only {} prices were compared", compared);
        assert!(
            priced > compared / 2,
            "only {} of {} comparisons had a price at all",
            priced,
            compared
        );
        // Neither one has ever heard of this symbol.
        assert_eq!(window.reference_cents("BTC-USDC", 500_000), None);
        assert_eq!(history.reference_cents("BTC-USDC", 500_000), None);
    }

    /// The kept sums stay right when a burst fills the window and a long quiet
    /// stretch empties it again, twice over.
    ///
    /// This is the case the running sums are easiest to get wrong. `clip_to`
    /// has to take a whole window of samples out of the sums and drop them,
    /// and then build the sums up again from nothing.
    #[test]
    fn a_window_that_fills_and_empties_twice_keeps_its_sums() {
        let mut window = MidWindow::default();
        let mut at = 0u64;
        for round in 0..2 {
            for tick in 0..40_000u64 {
                at += 1;
                window.observe("ETH-USDC", at, Some(10_000 + (tick as i64 % 11) + round));
                let symbol = &window.per_symbol["ETH-USDC"];
                let opens_at = at.saturating_sub(WINDOW_MS);
                assert_eq!(symbol.sums_at(at, opens_at), symbol.walked(at, opens_at));
            }
            // A gap of two whole windows. Nothing arrives, and the one sample
            // that holds across it is the only thing left.
            at += 2 * WINDOW_MS;
            let symbol = &window.per_symbol["ETH-USDC"];
            let opens_at = at.saturating_sub(WINDOW_MS);
            assert_eq!(symbol.sums_at(at, opens_at), symbol.walked(at, opens_at));
        }
        assert_eq!(
            window.per_symbol["ETH-USDC"].len(),
            WINDOW_MS as usize + 1,
            "a window of one sample a millisecond holds a millisecond more \
             than the window is long"
        );
    }
}

/// The exchange's reference price against the checker's.
///
/// The rule is written twice on purpose, so the two copies can disagree and
/// catch each other. This module records where they disagree over a history in
/// which neither one is executing anything wrong. That is a different thing,
/// and it is worth writing down.
///
/// The two keep their samples differently. The exchange drops a sample that
/// repeats the mid the window already ends with, and keeps running sums beside
/// the samples it has left. The checker keeps the repeat and walks its list on
/// every question. Both are right for the question a replay asks: the
/// reference price at the timestamp of the message that just arrived, which is
/// never behind the newest sample.
///
/// Asked about a time behind the newest sample, the two do not agree at all.
/// The checker has dropped the samples that cover that time and answers "there
/// is no reference price", which is the answer that refuses a market order.
/// The exchange answers out of running sums it built for a later window.
///
/// Message timestamps come off `clock.now_ms()` at four places that publish,
/// and nothing makes them go up. So a wall clock stepping backwards is enough
/// to put a message in the log that asks this question.
#[cfg(test)]
mod differential {
    use super::*;
    use crate::verify::order_terms::MidHistory;

    /// Both readings, over one list of samples.
    fn both(samples: &[(u64, Option<i64>)]) -> (MidWindow, MidHistory) {
        let mut exchange = MidWindow::default();
        let mut checker = MidHistory::default();
        for (at, mid) in samples {
            exchange.observe("E", *at, *mid);
            checker.showed("E", *at, *mid);
        }
        (exchange, checker)
    }

    /// The question a replay asks: the reference price at the timestamp of the
    /// message that has just moved the book. Both walks reach the same sample
    /// list at the same message, so this is the same question on both sides.
    #[test]
    fn the_exchange_and_the_checker_agree_at_the_newest_sample() {
        let mut samples = Vec::new();
        let mut at = 0u64;
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..600 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            at += seed % 4_000;
            // A mid that repeats often, so the sample the exchange drops and
            // the checker keeps is the common case rather than a rarity.
            let mid = match seed % 10 {
                0 => None,
                1 => Some(10_000 + (seed % 50) as i64),
                _ => Some(10_000),
            };
            samples.push((at, mid));
            let (exchange, checker) = both(&samples);
            assert_eq!(
                exchange.reference_cents("E", at),
                checker.reference_cents("E", at),
                "the exchange and the checker price the sample at {} differently",
                at
            );
        }
    }

    /// And where the two do not agree. This test states today's behaviour, so
    /// on the day the two are made to agree the test fails and somebody
    /// deletes it.
    ///
    /// One sample, then another 45 seconds later. The test asks about a time
    /// 45 seconds behind the newest sample, which is inside the first sample's
    /// own window. The checker has already dropped that sample and answers
    /// `None`. The exchange answers 10,000, out of sums it built for the
    /// window around the second sample.
    #[test]
    fn the_two_disagree_about_a_time_behind_the_newest_sample() {
        let (exchange, checker) = both(&[
            (1_000, Some(10_000)),
            (10_000, Some(10_000)),
            (55_000, Some(10_000)),
        ]);
        assert_eq!(
            exchange.reference_cents("E", 10_000),
            Some(10_000),
            "the exchange still has sums covering that time"
        );
        assert_eq!(
            checker.reference_cents("E", 10_000),
            None,
            "the checker pruned the samples that covered it, and no reference price is \
             what refuses a market order"
        );
    }
}
