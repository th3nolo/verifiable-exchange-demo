//! The read budget.
//!
//! `RateLimiter` in `inbox.rs` counts submissions per caller over a fixed
//! period of time. It cannot be reused here, and the reason is worth writing
//! down. `RateLimiter` counts requests, and it reads `SUBMIT_BURST` and
//! `SUBMIT_WINDOW` straight out of module constants. There is no way to give
//! `RateLimiter` a second budget in a second unit without changing it for the
//! submission path too. The unit is the whole point on the read path, see
//! `READ_BURST`, so this is a second type, and not a parameter added to the
//! first one.
//!
//! `Caller` and `TrustedProxies` are reused, and must be. Which address a
//! request is charged to is the same decision here as it is for a submission. A
//! second copy of the right-to-left walk over the forwarded header is the kind
//! of code that ends up believing the leftmost entry.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// The read budget, in messages, that one caller may spend.
///
/// Counted in messages and not in requests, because the work is in the
/// messages. `?since=0&limit=1000` reads a thousand rows out of SQLite, parses
/// a thousand JSON documents and serializes them again, all while it holds the
/// state lock the generator needs to publish. `?limit=1` does one thousandth of
/// that work. A per-request counter would price the two the same. It would have
/// to be set low enough for the expensive one, and would then refuse the cheap
/// one for no reason.
///
/// `READ_BURST` is sized from the work this endpoint exists for. Checking the
/// first anchor on the live sequencer reads 13,774 messages in 14 pages. Each
/// page is charged `READ_REQUEST_COST` plus the messages it reserves:
/// 14 * (1000 + 10) = 14,140. The burst is three and a half times that, so a
/// visitor can check the first anchor three times over, reloading the page or
/// trying again after a network error, and is never refused. That work is the
/// point of the endpoint, and must never be the thing the budget refuses.
///
/// `READ_REFILL_PER_SEC` is what one caller may keep spending after the burst
/// is gone: five pages a second, about 615 KB/s of body, and a few tens of
/// milliseconds a second of locked CPU. Reading a longer history in full,
/// `--audit` against 500,000 messages, takes 500 pages, and so about 100
/// seconds at this rate. That is the same order as the 500 network round trips
/// it already costs. What the refill rate stops is the loop the rate limiter
/// was missing: one address that opens sockets as fast as it can and reads
/// `?since=0` on each of them.
///
/// `READ_REQUEST_COST` is the smallest amount every read pays, so a flood of
/// `?limit=1` or `/head` is bounded too. Ten messages is about right: a
/// response costs one Ed25519 signature over the head, about 25 microseconds,
/// and a message costs about 3 microseconds to read and serialize again.
pub(super) const READ_BURST: u64 = 50_000;
pub(super) const READ_REFILL_PER_SEC: u64 = 5_000;
pub(super) const READ_REQUEST_COST: u64 = 10;

/// What `/metrics` costs against the same budget. `/metrics` takes the state
/// lock and writes a few kilobytes for a request of a hundred bytes, so it is
/// the one read on this sequencer that answers with much more than it was asked
/// with. A cost of a hundred messages caps one address at fifty scrapes a
/// second, which is well under what the endpoint can produce and far under what
/// opening a socket costs.
pub(super) const METRICS_COST: u64 = 100;

/// One caller's remaining read budget.
///
/// Whole tokens rather than a float, so a bucket that is topped up a million
/// times does not drift. `last` only moves when at least one whole token was
/// added, so the part of a millisecond that added no token is kept and not
/// rounded away. At `READ_REFILL_PER_SEC` a millisecond is five tokens, so a
/// caller that waited one millisecond gets tokens back.
struct Bucket {
    tokens: u64,
    last: Instant,
}

/// Read cost per caller, refilled all the time. Kept in memory, like the
/// submission limiter. The purpose is to bound one burst, and a restart that
/// clears the map costs nothing.
pub(super) struct ReadLimiter {
    seen: HashMap<IpAddr, Bucket>,
}

impl ReadLimiter {
    pub(super) fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// Takes `cost` from this caller's bucket, or says how many seconds the
    /// bucket needs to hold that much again.
    ///
    /// Nothing is taken when the answer is a refusal. If a refused caller were
    /// charged as well, every retry would move that caller further from being
    /// allowed. A caller who is only early would then be refused for as long as
    /// they keep trying.
    pub(super) fn charge(&mut self, ip: IpAddr, cost: u64, now: Instant) -> Result<(), u64> {
        // Only prune when the map has grown, so the common path is one lookup.
        // A bucket back at `READ_BURST` holds no information: charging that
        // caller again would produce the same bucket. Dropping it is free.
        if self.seen.len() > 10_000 {
            let full = Duration::from_secs(READ_BURST.div_ceil(READ_REFILL_PER_SEC));
            self.seen
                .retain(|_, bucket| now.duration_since(bucket.last) < full);
        }
        let bucket = self.seen.entry(ip).or_insert(Bucket {
            tokens: READ_BURST,
            last: now,
        });
        let elapsed_ms = now.duration_since(bucket.last).as_millis() as u64;
        let refill = elapsed_ms.saturating_mul(READ_REFILL_PER_SEC) / 1000;
        if refill > 0 {
            bucket.tokens = bucket.tokens.saturating_add(refill).min(READ_BURST);
            bucket.last = now;
        }
        if bucket.tokens >= cost {
            bucket.tokens -= cost;
            return Ok(());
        }
        // Rounded up, and never zero. `Retry-After: 0` asks for an immediate
        // retry, and that retry would be refused again.
        let wait = (cost - bucket.tokens).div_ceil(READ_REFILL_PER_SEC);
        Err(wait.max(1))
    }

    /// Gives back what a read reserved and did not use.
    ///
    /// A page is charged for the messages it asked for, before the read, and
    /// not for the messages it returned. Charging after the read means the work
    /// is already done when the answer is "no". The reservation is then too big
    /// for every poll that is up to date: `/orders` always reserves
    /// `PAGE_LIMIT` and usually serves a few messages. The unused part comes
    /// back here, under the same lock, before the response leaves.
    pub(super) fn refund(&mut self, ip: IpAddr, amount: u64) {
        if amount == 0 {
            return;
        }
        if let Some(bucket) = self.seen.get_mut(&ip) {
            bucket.tokens = bucket.tokens.saturating_add(amount).min(READ_BURST);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bucket itself, on a clock this test owns: a burst, a refusal that
    /// names the wait, a refill, and a refund that cannot create tokens.
    #[test]
    fn a_read_budget_refills_and_refunds_what_a_page_did_not_use() {
        let mut limiter = ReadLimiter::new();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let start = Instant::now();

        assert!(limiter.charge(ip, READ_BURST, start).is_ok(), "the burst");
        let wait = limiter
            .charge(ip, READ_REFILL_PER_SEC * 2, start)
            .expect_err("the burst is spent");
        assert_eq!(wait, 2, "two seconds of refill is two seconds of waiting");

        // A refusal takes nothing, so a retry does not move the caller further
        // from being allowed.
        assert!(
            limiter
                .charge(ip, 1, start + Duration::from_millis(1))
                .is_ok(),
            "one millisecond refills {} tokens",
            READ_REFILL_PER_SEC / 1000
        );

        // Refilling stops at the burst. A caller that waits does not collect a
        // budget larger than the one they started with.
        assert!(
            limiter
                .charge(ip, READ_BURST, start + Duration::from_secs(3600))
                .is_ok()
        );
        assert!(
            limiter
                .charge(ip, 1, start + Duration::from_secs(3600))
                .is_err(),
            "an hour idle is still one burst, not an hour of refill"
        );

        // A refund cannot create tokens either.
        limiter.refund(ip, READ_BURST * 10);
        assert!(
            limiter
                .charge(ip, READ_BURST, start + Duration::from_secs(3600))
                .is_ok()
        );
        assert!(
            limiter
                .charge(ip, 1, start + Duration::from_secs(3600))
                .is_err(),
            "a refund tops the bucket up, it does not grow it"
        );
    }
}
