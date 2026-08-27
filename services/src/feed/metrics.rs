//! What `/metrics` counts.

use axum::http::StatusCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::domain::OrderId;

/// Writes the endpoint list once.
///
/// Each row names a variant, the path it answers and the label it counts under.
/// The enum, `ENDPOINTS`, `Endpoint::path`, `Endpoint::of` and `Endpoint::label`
/// all come out of the same rows. A row cannot be added to one of them and left
/// out of the others.
///
/// This used to be five lists written by hand, and two of them had to agree.
/// The counters are an array indexed by the variant. A variant left out of
/// `ENDPOINTS`, or given a row another variant already owned, reported one
/// endpoint's traffic under another endpoint's name. Nothing failed when that
/// happened. Adding an endpoint is now one row here.
macro_rules! endpoints {
    ($($variant:ident => $path:literal, $label:literal;)*) => {
        /// The endpoints counted separately. The list is fixed, and that
        /// decides whether `/metrics` can be public at all. A label taken from
        /// the request path would let anybody create series by asking for
        /// `/aaaa1`, `/aaaa2`, and so on, until the metrics response is larger
        /// than anything else this sequencer serves. Every path the list does
        /// not name shares one row.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(usize)]
        pub(super) enum Endpoint {
            $($variant,)*
            /// Every path the table above does not name.
            Other,
        }

        /// Every endpoint, in the order the table declares them, which is the
        /// order `/metrics` prints them in.
        const ENDPOINTS: [Endpoint; ENDPOINT_COUNT] = [
            $(Endpoint::$variant,)*
            Endpoint::Other,
        ];

        impl Endpoint {
            /// The path this endpoint answers. The router mounts its routes
            /// under this path, so the path is written once, and the route and
            /// its counter cannot name it differently. `Other` answers no path
            /// of its own, and the empty string matches no request.
            pub(super) const fn path(self) -> &'static str {
                match self {
                    $(Endpoint::$variant => $path,)*
                    Endpoint::Other => "",
                }
            }

            /// Which endpoint served one request path.
            pub(super) fn of(path: &str) -> Self {
                match path {
                    $($path => Endpoint::$variant,)*
                    _ => Endpoint::Other,
                }
            }

            /// The name this endpoint counts under in `/metrics`.
            fn label(self) -> &'static str {
                match self {
                    $(Endpoint::$variant => $label,)*
                    Endpoint::Other => "other",
                }
            }
        }
    };
}

endpoints! {
    Orders => "/orders", "orders";
    Messages => "/messages.ndjson", "messages_ndjson";
    Head => "/head", "head";
    Sth => "/sth", "sth";
    ProofInclusion => "/proof/inclusion", "proof_inclusion";
    ProofConsistency => "/proof/consistency", "proof_consistency";
    TreeNodes => "/tree/nodes", "tree_nodes";
    Symbols => "/symbols", "symbols";
    Metrics => "/metrics", "metrics";
    Order => "/order", "order";
    Cancel => "/cancel", "cancel";
}

/// How many rows the counter arrays hold. `Other` is the last variant the
/// table declares, so its own index plus one is the count, whatever the table
/// holds.
const ENDPOINT_COUNT: usize = Endpoint::Other as usize + 1;

/// Status classes, indexed by the first digit. Slot 0 exists so the index is
/// the digit itself and never needs a subtraction that could underflow.
const STATUS_CLASSES: [&str; 6] = ["0xx", "1xx", "2xx", "3xx", "4xx", "5xx"];

impl Endpoint {
    /// Which row of the counter arrays this endpoint owns.
    ///
    /// The enum is `repr(usize)`, and `ENDPOINTS` lists the same variants in
    /// the same order. The value is therefore the endpoint's position in
    /// `ENDPOINTS`, and cannot differ from it. Two endpoints sharing a row, or
    /// a row past the end of the arrays, are no longer things a person can
    /// write.
    fn index(self) -> usize {
        self as usize
    }
}

/// Counters behind `GET /metrics`.
///
/// Plain atomics rather than fields on `FeedState`, for two reasons. The
/// handlers increment them while they already hold the state lock, so those
/// increments wait for nothing. The counting layer around the router increments
/// them without taking that lock at all, which is what lets bytes be counted for
/// every response, including the responses a handler never builds, like a 404
/// or a refusal from an extractor. Nothing here allocates: the counters are a
/// fixed array indexed by endpoint, and the strings are only built when
/// `/metrics` is read.
pub(crate) struct Metrics {
    started: Instant,
    requests: [[AtomicU64; STATUS_CLASSES.len()]; ENDPOINTS.len()],
    response_bytes: [AtomicU64; ENDPOINTS.len()],
    /// Messages served out of the in-memory window, and out of SQLite. The two
    /// counts together say whether `MESSAGE_WINDOW` is the right size. A window
    /// that is too small appears here as messages read from disk, on a path
    /// that should never have needed the disk.
    messages_window: AtomicU64,
    messages_db: AtomicU64,
    /// Time spent inside the SQLite page read, as a sum and a count rather than
    /// a histogram. A histogram needs bucket boundaries chosen before anything
    /// has been measured, and twelve more counters to hold them. The sum and
    /// the count give the mean, and the mean answers the question this
    /// sequencer has: is the disk path expensive enough to care about. The max
    /// is kept beside them because the mean hides one slow read. The read
    /// happens under the state lock, so one slow page stops the generator, and
    /// only the max shows that it ever happened.
    db_page_micros: AtomicU64,
    db_pages: AtomicU64,
    db_page_max_micros: AtomicU64,
    cache_immutable: AtomicU64,
    cache_not_modified: AtomicU64,
    cache_uncacheable: AtomicU64,
    rate_limited: AtomicU64,
}

impl Metrics {
    pub(super) fn new() -> Self {
        Metrics {
            started: Instant::now(),
            requests: Default::default(),
            response_bytes: Default::default(),
            messages_window: AtomicU64::new(0),
            messages_db: AtomicU64::new(0),
            db_page_micros: AtomicU64::new(0),
            db_pages: AtomicU64::new(0),
            db_page_max_micros: AtomicU64::new(0),
            cache_immutable: AtomicU64::new(0),
            cache_not_modified: AtomicU64::new(0),
            cache_uncacheable: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
        }
    }

    /// One answered request. `Relaxed` throughout: `/metrics` only ever reads
    /// these counters as a snapshot, and no code branches on them, so there is
    /// no order between them to keep.
    pub(super) fn served(&self, endpoint: Endpoint, status: StatusCode, bytes: u64) {
        let class = (status.as_u16() / 100) as usize;
        let class = class.min(STATUS_CLASSES.len() - 1);
        self.requests[endpoint.index()][class].fetch_add(1, Ordering::Relaxed);
        self.response_bytes[endpoint.index()].fetch_add(bytes, Ordering::Relaxed);
    }

    pub(super) fn messages_served(&self, count: u64, from_db: bool) {
        let counter = if from_db {
            &self.messages_db
        } else {
            &self.messages_window
        };
        counter.fetch_add(count, Ordering::Relaxed);
    }

    pub(super) fn db_page(&self, took: Duration) {
        let micros = took.as_micros() as u64;
        self.db_page_micros.fetch_add(micros, Ordering::Relaxed);
        self.db_pages.fetch_add(1, Ordering::Relaxed);
        self.db_page_max_micros.fetch_max(micros, Ordering::Relaxed);
    }

    /// One read served as a closed page a cache may keep forever.
    pub(super) fn cache_immutable(&self) {
        self.cache_immutable.fetch_add(1, Ordering::Relaxed);
    }

    /// One read answered 304 against an ETag the caller already held.
    pub(super) fn cache_not_modified(&self) {
        self.cache_not_modified.fetch_add(1, Ordering::Relaxed);
    }

    /// One read no cache may keep, because it touches the head.
    pub(super) fn cache_uncacheable(&self) {
        self.cache_uncacheable.fetch_add(1, Ordering::Relaxed);
    }

    /// One read refused for exceeding the read budget.
    pub(super) fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }
}

/// The media type Prometheus expects. The version is part of the media type: a
/// scraper reads the format from here rather than guessing it.
pub(super) const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Writes the counters out. This is the only place in this file that allocates
/// for each metric. That is acceptable, because it runs once for each scrape
/// and not once for each request.
pub(super) fn render_metrics(metrics: &Metrics, last_id: OrderId, window: u64) -> String {
    let mut out = String::with_capacity(4096);
    let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);

    out.push_str("# HELP feed_requests_total Requests answered, by endpoint and status class.\n");
    out.push_str("# TYPE feed_requests_total counter\n");
    for endpoint in ENDPOINTS {
        for (class, name) in STATUS_CLASSES.iter().enumerate() {
            let count = load(&metrics.requests[endpoint.index()][class]);
            out.push_str(&format!(
                "feed_requests_total{{endpoint=\"{}\",status=\"{}\"}} {}\n",
                endpoint.label(),
                name,
                count
            ));
        }
    }

    out.push_str("# HELP feed_response_bytes_total Response body bytes served, by endpoint.\n");
    out.push_str("# TYPE feed_response_bytes_total counter\n");
    for endpoint in ENDPOINTS {
        out.push_str(&format!(
            "feed_response_bytes_total{{endpoint=\"{}\"}} {}\n",
            endpoint.label(),
            load(&metrics.response_bytes[endpoint.index()])
        ));
    }

    out.push_str(
        "# HELP feed_messages_served_total Messages served, by where they were read from.\n",
    );
    out.push_str("# TYPE feed_messages_served_total counter\n");
    out.push_str(&format!(
        "feed_messages_served_total{{source=\"window\"}} {}\n",
        load(&metrics.messages_window)
    ));
    out.push_str(&format!(
        "feed_messages_served_total{{source=\"database\"}} {}\n",
        load(&metrics.messages_db)
    ));

    out.push_str("# HELP feed_db_page_seconds_total Time spent in database page reads.\n");
    out.push_str("# TYPE feed_db_page_seconds_total counter\n");
    out.push_str(&format!(
        "feed_db_page_seconds_total {}\n",
        seconds(load(&metrics.db_page_micros))
    ));
    out.push_str(
        "# HELP feed_db_pages_total Database page reads. With the seconds above, the mean.\n",
    );
    out.push_str("# TYPE feed_db_pages_total counter\n");
    out.push_str(&format!(
        "feed_db_pages_total {}\n",
        load(&metrics.db_pages)
    ));
    out.push_str(
        "# HELP feed_db_page_seconds_max The slowest database page read since this feed started. \
         It runs under the state lock, so this is how long the generator was stalled.\n",
    );
    out.push_str("# TYPE feed_db_page_seconds_max gauge\n");
    out.push_str(&format!(
        "feed_db_page_seconds_max {}\n",
        seconds(load(&metrics.db_page_max_micros))
    ));

    out.push_str(
        "# HELP feed_cache_responses_total Read responses, by what a cache may do with them.\n",
    );
    out.push_str("# TYPE feed_cache_responses_total counter\n");
    out.push_str(&format!(
        "feed_cache_responses_total{{outcome=\"immutable\"}} {}\n",
        load(&metrics.cache_immutable)
    ));
    out.push_str(&format!(
        "feed_cache_responses_total{{outcome=\"not_modified\"}} {}\n",
        load(&metrics.cache_not_modified)
    ));
    out.push_str(&format!(
        "feed_cache_responses_total{{outcome=\"uncacheable\"}} {}\n",
        load(&metrics.cache_uncacheable)
    ));

    out.push_str("# HELP feed_reads_refused_total Reads refused for exceeding the read budget.\n");
    out.push_str("# TYPE feed_reads_refused_total counter\n");
    out.push_str(&format!(
        "feed_reads_refused_total {}\n",
        load(&metrics.rate_limited)
    ));

    out.push_str("# HELP feed_head_id The id of the newest message published.\n");
    out.push_str("# TYPE feed_head_id gauge\n");
    out.push_str(&format!("feed_head_id {}\n", last_id));
    out.push_str(
        "# HELP feed_window_messages Messages held in memory. Against \
         feed_messages_served_total{source=\"database\"}, this is whether the window is big \
         enough.\n",
    );
    out.push_str("# TYPE feed_window_messages gauge\n");
    out.push_str(&format!("feed_window_messages {}\n", window));
    out.push_str("# HELP feed_uptime_seconds Seconds since this feed process started.\n");
    out.push_str("# TYPE feed_uptime_seconds gauge\n");
    out.push_str(&format!(
        "feed_uptime_seconds {}\n",
        metrics.started.elapsed().as_secs()
    ));
    out
}

/// Microseconds as the decimal seconds Prometheus wants. The fraction is
/// written out and not divided as a float, so the value is exact and never
/// arrives as `1e-6`. Some scrapers read `1e-6` and some do not.
fn seconds(micros: u64) -> String {
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three numbers a page read leaves behind, and the format they are
    /// written in.
    ///
    /// Driven here and not through `/metrics`, because a handler cannot produce
    /// these values on demand. `metrics_are_prometheus_text_and_the_
    /// counters_move` proves the counters move. That test cannot time a page
    /// read to the microsecond, so until this test nothing read the sum, the
    /// max, or the decimal format they are written in.
    #[test]
    fn a_page_read_is_summed_counted_and_kept_at_its_max_in_decimal_seconds() {
        let metrics = Metrics::new();
        metrics.db_page(Duration::from_micros(1));
        metrics.db_page(Duration::from_micros(1_500_000));
        metrics.db_page(Duration::from_micros(2));

        let text = render_metrics(&metrics, 42, 7);
        assert!(text.contains("feed_db_pages_total 3\n"), "{}", text);
        assert!(
            text.contains("feed_db_page_seconds_total 1.500003\n"),
            "the sum of the three, in seconds: {}",
            text
        );
        assert!(
            text.contains("feed_db_page_seconds_max 1.500000\n"),
            "the slowest, not the last: {}",
            text
        );
        assert!(text.contains("feed_head_id 42\n"), "{}", text);
        assert!(text.contains("feed_window_messages 7\n"), "{}", text);

        // Why seconds() writes the fraction out by hand: one microsecond
        // divided as a float is 1e-6, and some scrapers read 1e-6 and some do
        // not.
        let one = Metrics::new();
        one.db_page(Duration::from_micros(1));
        let text = render_metrics(&one, 0, 0);
        assert!(
            text.contains("feed_db_page_seconds_total 0.000001\n"),
            "{}",
            text
        );
    }

    /// Every endpoint counts under its own name.
    ///
    /// Each endpoint is served a different number of requests and a different
    /// number of bytes. The test therefore reads which row a count landed in,
    /// and not only that some count moved. That is the failure this test holds
    /// down. The counters are an array indexed by the endpoint, and the array
    /// of endpoints and that index used to be two orders written by hand. Two
    /// rows were swapped in one of them, and every endpoint's traffic was
    /// reported under another endpoint's name, with nothing to report it.
    #[test]
    fn each_endpoint_counts_under_its_own_name() {
        let metrics = Metrics::new();
        for (position, endpoint) in ENDPOINTS.iter().enumerate() {
            for _ in 0..=position {
                metrics.served(*endpoint, StatusCode::OK, 7);
            }
        }

        let text = render_metrics(&metrics, 0, 0);
        for (position, endpoint) in ENDPOINTS.iter().enumerate() {
            let requests = position as u64 + 1;
            assert!(
                text.contains(&format!(
                    "feed_requests_total{{endpoint=\"{}\",status=\"2xx\"}} {}\n",
                    endpoint.label(),
                    requests
                )),
                "{} answered {} requests: {}",
                endpoint.label(),
                requests,
                text
            );
            assert!(
                text.contains(&format!(
                    "feed_response_bytes_total{{endpoint=\"{}\"}} {}\n",
                    endpoint.label(),
                    requests * 7
                )),
                "{} served {} bytes: {}",
                endpoint.label(),
                requests * 7,
                text
            );
        }
    }

    /// A path reaches its own endpoint, and every other path shares one row.
    ///
    /// The paths come out of the table, so this test repeats no list. The test
    /// says that the path a route is mounted under and the path the counter
    /// looks up are the same string, and that an unknown path adds no series.
    #[test]
    fn a_path_reaches_its_own_endpoint_and_every_other_path_shares_one_row() {
        for endpoint in ENDPOINTS {
            if endpoint == Endpoint::Other {
                continue;
            }
            assert_eq!(
                Endpoint::of(endpoint.path()),
                endpoint,
                "{}",
                endpoint.path()
            );
        }
        for path in ["", "/", "/aaaa1", "/orders/", "/Head", "/operator"] {
            assert_eq!(Endpoint::of(path), Endpoint::Other, "{}", path);
        }
    }

    /// The four counters that report what a cache and the read budget did.
    /// Each is one line of the text and nothing else reads them.
    #[test]
    fn the_cache_and_refusal_counters_each_reach_their_own_line() {
        let metrics = Metrics::new();
        metrics.cache_immutable();
        metrics.cache_immutable();
        metrics.cache_not_modified();
        metrics.cache_uncacheable();
        metrics.cache_uncacheable();
        metrics.cache_uncacheable();
        metrics.rate_limited();

        let text = render_metrics(&metrics, 0, 0);
        assert!(
            text.contains("feed_cache_responses_total{outcome=\"immutable\"} 2\n"),
            "{}",
            text
        );
        assert!(
            text.contains("feed_cache_responses_total{outcome=\"not_modified\"} 1\n"),
            "{}",
            text
        );
        assert!(
            text.contains("feed_cache_responses_total{outcome=\"uncacheable\"} 3\n"),
            "{}",
            text
        );
        assert!(text.contains("feed_reads_refused_total 1\n"), "{}", text);
    }
}
