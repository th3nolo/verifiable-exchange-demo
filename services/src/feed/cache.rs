//! Which pages may be cached, and why a cached page may carry the signed head.

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::metrics::Metrics;
use crate::domain::OrderId;
use crate::logchain::{self, Chain};

/// What a closed page is cached as. 31,536,000 seconds is a year, which is the
/// longest value anything honours. `immutable` is on top of it, so a browser
/// does not ask again on a reload either.
///
/// `public` rather than `private` on purpose. The saving that matters is a
/// shared cache in front of the sequencer answering the second visitor without
/// the request reaching SQLite at all. `public` is safe because the
/// cross-origin layer appends `Vary: origin` to every response (see `cors.rs`).
/// A cache therefore keeps one entry for each origin, and cannot give one
/// origin's `Access-Control-Allow-Origin` to another.
///
/// See `Freshness` for what makes a page closed, and why a cached response may
/// carry the signed head.
const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// What a response that touches the head is allowed to be cached as: nothing.
///
/// Not a short `max-age`. The responses that land here are the polling path: an
/// empty page, or a page whose last message is the sequencer's newest. Both
/// carry the head of the *whole* history, and not a head standing inside the
/// body. A cache that holds one of those for even a second tells a consumer it
/// is up to date when it is not. It also makes a sequencer that stopped
/// publishing look like one that is still publishing, for as long as the cache
/// entry lives. `validator.rs` counts a poll it cannot check against a fresh
/// signed head as `Unchecked::NoAnswer`, and stalls after
/// `UNCHECKED_POLLS_BEFORE_STALL` of them. A cache that answered those polls
/// would hide the outage that `validator.rs` exists to report. There is nothing
/// to save either: a page that touches the head is served from the in-memory
/// window and never reads the disk.
pub(super) const OPEN_CACHE_CONTROL: &str = "no-store";

// A page is CLOSED when the range it names lies entirely below the head:
// `since + limit <= last_id`, which is the same thing as the page coming back
// full. Message ids only grow, and a published message never changes, because
// the hash chain covers it. A full page therefore returns the same bytes for
// that URL forever. A page that came back short is a page the next message
// makes longer, so it is not closed, and it never will be under that URL.
//
// THE HEAD HEADERS ON A CACHED RESPONSE
//
// The first worry is that `x-feed-last-id`, `x-feed-chain` and
// `x-feed-signature` describe the sequencer's current state. A cached copy
// would then give somebody a months-old head to mistake for a current one. On
// this sequencer those headers do not describe the current state. `page()`
// returns the head standing at the LAST MESSAGE IN THE BODY, and
// `head_headers_at` signs that position, see the note on
// `HEAD_LAST_ID_HEADER`, and `orders_are_paged_and_the_head_covers_
// exactly_what_is_served`. The signed statement is "history <session>, after
// message N, has chain C". The chain hashes every message up to N and nothing
// after it, so once that statement is true it stays true. Age does not make it
// wrong.
//
// So the three options are not equal:
//
//   (a) drop the head headers from cacheable responses. This breaks the two
//       consumers that exist. `parse_signed_head` in `matcher.rs` requires all
//       four headers together and refuses the whole batch without them, and
//       `validator.rs` counts such a response as `Unchecked::NoAnswer`. It does
//       worse than break them. It removes the only signature over the bytes
//       that were just cached: a visitor who reads 13,774 messages again out of
//       a browser cache would hold no sequencer signature over any of them.
//   (b) keep them and never mark anything immutable. That is today's behaviour,
//       and it gives up the whole saving.
//   (c) keep them, and mark immutable only where the head provably stands
//       inside the body. That is what this file does.
//
// The rule that makes (c) safe is in the structure of the code, and does not
// depend on care. A response is only ever marked immutable from the
// `Some(head)` branch of `page()`, and that head is the head at the last
// message served. The `unwrap_or((last_id, chain))` fallback does put the
// current head on a response, on an empty page. That fallback cannot reach
// `Freshness::Closed`, because an empty page is not a full page.
// `an_immutable_response_never_carries_a_head_past_its_body` fails if anybody
// changes that.
//
// Two things stay uncacheable, whatever the body holds:
//
//   - `?n=`, which names a range RELATIVE to the head. `?n=1000` on a long
//     history comes back full and passes every test above, and it answers with
//     different messages every second. A cacheable URL has to name an absolute
//     range, so a `?n=` request is refused caching from the request alone,
//     before the body is considered.
//   - any response whose head came from the current-head fallback above.

/// What a read may be cached as.
pub(super) enum Freshness {
    /// A closed range. The bytes, and every header beside them, are what this
    /// URL answers for as long as this session lasts.
    Closed { etag: String },
    /// The page touches the head, or names a range relative to the head.
    Open,
}

/// The ETag of a closed page: the session it belongs to, the range it covers,
/// and the chain standing at its last message.
///
/// A strong ETag, and it costs no hashing. The chain is already a SHA-256 hash
/// over every message up to that id, so the chain identifies the content of the
/// range that ends there. `since` fixes where the range starts, because two
/// different ranges can end at the same message. The session is in the ETag so
/// that a sequencer rebuilt from an empty database cannot match an ETag from
/// the history before it. That rebuild is the one case where message 5000 can
/// correctly become different bytes.
///
/// Hashing the body instead is the usual answer. It would read 123 KB through
/// SHA-256 on every response, to learn something the sequencer already knows.
pub(super) fn page_etag(session: &str, since: OrderId, last_id: OrderId, chain: &Chain) -> String {
    format!(
        "\"{}.{}.{}.{}\"",
        session,
        since,
        last_id,
        logchain::to_hex(chain)
    )
}

/// The ETag of a proof a cache may keep: the session, which of the two proofs
/// it is, and the two numbers that name the proof.
///
/// Nothing is hashed. A proof against a stated tree size is computed from the
/// leaves below that size and nothing else, and those leaves never change. The
/// parameters therefore identify the bytes exactly. The session is in the ETag
/// for the reason it is in `page_etag`: a sequencer rebuilt from an empty
/// database reaches tree size 1,000 again over entirely different messages.
pub(super) fn proof_etag(session: &str, proof: &str, first: u64, second: u64) -> String {
    format!("\"{}.{}.{}.{}\"", session, proof, first, second)
}

/// Whether `If-None-Match` on this request names the ETag the sequencer would
/// answer with.
///
/// The value is read as a list, because that is what the header is. `*` is a
/// match, because RFC 9110 gives `*` the meaning "any current representation",
/// and this URL has one. Weak comparison is the rule for `If-None-Match`, so a
/// `W/` prefix on the client's value is removed before the comparison. This
/// sequencer only ever issues strong ETags, so a `W/` prefix can only have come
/// from a cache that weakened one on the way.
pub(super) fn if_none_match(headers: &HeaderMap, etag: &str) -> bool {
    let Some(value) = headers.get(header::IF_NONE_MATCH) else {
        return false;
    };
    let Ok(text) = value.to_str() else {
        return false;
    };
    text.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
    })
}

/// Puts the cache headers for one read on a response, and counts the outcome.
pub(super) fn with_freshness(
    mut response: Response,
    freshness: &Freshness,
    metrics: &Metrics,
) -> Response {
    let headers = response.headers_mut();
    match freshness {
        Freshness::Closed { etag } => {
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static(IMMUTABLE_CACHE_CONTROL),
            );
            if let Ok(value) = HeaderValue::from_str(etag) {
                headers.insert(header::ETAG, value);
            }
            metrics.cache_immutable();
        }
        Freshness::Open => {
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static(OPEN_CACHE_CONTROL),
            );
            metrics.cache_uncacheable();
        }
    }
    response
}

/// The 304 for a closed page whose ETag the caller already holds.
///
/// The same `Cache-Control` and `ETag` as the 200 it stands in for, which RFC
/// 9111 requires. A cache updates its stored entry from those two headers. A
/// 304 that dropped them would tell the cache the entry is no longer cacheable,
/// and the next read would be a full page again. No body, and no head headers:
/// a 304 is not a representation, and a consumer that needs the signed head is
/// a consumer that did not have the page cached.
pub(super) fn not_modified(etag: &str, metrics: &Metrics) -> Response {
    let mut response = StatusCode::NOT_MODIFIED.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(IMMUTABLE_CACHE_CONTROL),
    );
    if let Ok(value) = HeaderValue::from_str(etag) {
        headers.insert(header::ETAG, value);
    }
    metrics.cache_not_modified();
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asked_with(value: &[u8]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_bytes(value).expect("a header value"),
        );
        headers
    }

    /// What a client sends back on the second visit, and what this sequencer
    /// does with it.
    ///
    /// Driven here and not through a handler, because a handler can only send
    /// one form. `a_matching_if_none_match_gets_a_304_with_no_body` sends back
    /// the exact ETag it was given, which is what a browser does. The list, the
    /// `W/` prefix and `*` are forms RFC 9110 allows and a cache in the middle
    /// can produce. No other test reaches those forms.
    #[test]
    fn an_etag_names_its_range_and_a_client_s_copy_is_matched_weakly() {
        let chain: Chain = [0xab; 32];
        let etag = page_etag("f00d", 0, 1000, &chain);
        assert_eq!(
            etag,
            format!("\"f00d.0.1000.{}\"", logchain::to_hex(&chain))
        );
        // `since` is in the ETag because two ranges can end at the same
        // message, and the chain alone would give both ranges the same ETag.
        assert_ne!(etag, page_etag("f00d", 1, 1000, &chain));
        // The session is in the ETag because a sequencer rebuilt from an empty
        // database can reach message 1000 with different bytes.
        assert_ne!(etag, page_etag("beef", 0, 1000, &chain));

        assert!(
            !if_none_match(&HeaderMap::new(), &etag),
            "no header is not a match"
        );
        assert!(if_none_match(&asked_with(etag.as_bytes()), &etag));
        assert!(
            !if_none_match(&asked_with(b"\"f00d.0.999.0000\""), &etag),
            "another range's validator is not this one"
        );

        // RFC 9110: `*` means any current representation, so a URL that has one
        // is a match.
        assert!(if_none_match(&asked_with(b"*"), &etag));

        // Weak comparison is the rule for If-None-Match. This sequencer only
        // issues strong ETags, so a `W/` can only have come from a cache that
        // weakened one on the way. Refusing it would make that cache ask for
        // the whole page every time.
        assert!(if_none_match(
            &asked_with(format!("W/{}", etag).as_bytes()),
            &etag
        ));

        // The header is a list, and a client that kept several pages sends
        // several.
        let list = format!("\"other\", W/{}, \"third\"", etag);
        assert!(if_none_match(&asked_with(list.as_bytes()), &etag));
        assert!(
            !if_none_match(&asked_with(b"\"other\", \"third\""), &etag),
            "a list this validator is not in is not a match"
        );

        assert!(
            !if_none_match(&asked_with(&[0xff, 0xfe]), &etag),
            "bytes that are not text cannot name an ETag"
        );
    }
}
