//! The endpoints, and what each answer is allowed to say.

use axum::{
    Json, Router,
    body::HttpBody,
    extract::{Query, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{MethodRouter, get, post},
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{error, info, warn};

use super::cache::{
    Freshness, OPEN_CACHE_CONTROL, if_none_match, not_modified, page_etag, proof_etag,
    with_freshness,
};
use super::limit::{METRICS_COST, READ_BURST, READ_REFILL_PER_SEC, READ_REQUEST_COST};
use super::metrics::{Endpoint, METRICS_CONTENT_TYPE, Metrics, render_metrics};
use super::tree::{self, Unreadable};
use super::{
    ConsistencyProof, FeedState, InclusionProof, OPENING_MESSAGES, PAGE_LIMIT, Published,
    SignedHead, lock, with_state,
};
use crate::cors::{self, CorsPolicy};
use crate::domain::{
    AccountId, OPERATOR_ACCOUNT, OrderId, OrderMessage, OrderType, SYMBOLS, Side, TimeInForce,
};
use crate::inbox::{self, Caller, SUBMIT_BURST, SUBMIT_WINDOW, SignedSubmission, Submission};
use crate::logchain::{self, Chain};
use crate::merkle::TreeError;
use crate::operator;
use crate::wire;
use ed25519_dalek::VerifyingKey;

/// The list `/symbols` serves is fixed when the binary is built. An hour of
/// caching therefore costs nothing and saves one request for each visitor. The
/// value is not `immutable`, because the list changes when a new binary is
/// deployed. An hour is the longest an operator should wait to see that change.
const SYMBOLS_CACHE_CONTROL: &str = "public, max-age=3600";

// ---------------------------------------------------------------------------
// Cross-origin submissions
// ---------------------------------------------------------------------------

/// The paths a browser may ask about before it posts to this sequencer. Before
/// a browser sends a cross-origin POST, it first sends an OPTIONS request and
/// asks whether the path is allowed.
///
/// Only the two paths that take submissions are listed here. An OPTIONS request
/// for any other path is refused, so the permission cannot widen without being
/// noticed when a route is added.
///
/// The rules themselves are in `cors.rs`, shared with the separate service. One
/// implementation on purpose: the separate service has to be at least as
/// reachable by a browser as this sequencer's own `POST /order`, and two copies
/// of an allowlist parser are two things that can drift apart.
pub(super) const SUBMISSION_PATHS: [&str; 2] = [Endpoint::Order.path(), Endpoint::Cancel.path()];

// ---------------------------------------------------------------------------
// The routes, and what each one charges
// ---------------------------------------------------------------------------

/// `POST /operator` is the one route with no row in the metrics table, so its
/// requests count under `other`. That is what this sequencer serves today. A
/// row of its own would add series to `/metrics` that a scraper does not have
/// yet.
const OPERATOR_PATH: &str = "/operator";

/// What one request to a route costs, and which budget pays for it.
///
/// The charge is declared beside the route and not left to the handler. A route
/// that charged nothing served traffic that no budget limited and no counter
/// counted. Nothing failed when that happened: the endpoint answered, the
/// sequencer did the work, and the only sign was a counter that looked low.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Charge {
    /// The flat request cost, `READ_REQUEST_COST`, against the read budget.
    Read,
    /// The flat request cost, plus the messages the page reserves. What the page
    /// did not use is given back before the answer leaves; see
    /// `ReadLimiter::refund`.
    Page,
    /// `METRICS_COST`, against the same read budget. `/metrics` answers with
    /// more bytes than it was asked with, so it costs more than a plain read.
    Metrics,
    /// One submission against `state.limiter`, which counts requests in a time
    /// window and not messages.
    Submission,
    /// Charged nothing. `get_symbols` is the only route with this charge, and
    /// its own comment says why.
    Free,
}

/// The router being built, and what every route on it charges.
///
/// Two fields, because `routes` is the only way to ask `router` what it holds:
/// an axum `Router` does not list its own routes. `add` fills both fields from
/// one call, so the list is what was mounted and not a copy of it.
struct Mounted {
    router: Router<Arc<Mutex<FeedState>>>,
    routes: Vec<(&'static str, Charge)>,
}

impl Mounted {
    fn new() -> Self {
        Mounted {
            router: Router::new(),
            routes: Vec::new(),
        }
    }

    /// Mounts one route and records what it charges.
    ///
    /// `Mounted` has no `route` method. Inside `mount` below there is therefore
    /// no way to add a route without naming a charge for it, and no way to add
    /// one that the route test does not walk.
    fn add(
        mut self,
        path: &'static str,
        method: MethodRouter<Arc<Mutex<FeedState>>>,
        charge: Charge,
    ) -> Self {
        self.router = self.router.route(path, method);
        self.routes.push((path, charge));
        self
    }
}

/// Every route this sequencer serves.
///
/// The paths come from the metrics table, so a route and its counter cannot
/// name the path differently. `/operator` is the one exception, and the comment
/// on `OPERATOR_PATH` says why.
fn mount(operator_key: Option<VerifyingKey>) -> Mounted {
    let mut routes = Mounted::new()
        .add(Endpoint::Orders.path(), get(get_orders), Charge::Page)
        .add(
            Endpoint::Order.path(),
            post(submit_order),
            Charge::Submission,
        )
        .add(
            Endpoint::Cancel.path(),
            post(submit_cancel),
            Charge::Submission,
        )
        .add(Endpoint::Symbols.path(), get(get_symbols), Charge::Free)
        .add(Endpoint::Head.path(), get(get_head), Charge::Read)
        .add(Endpoint::Sth.path(), get(get_sth), Charge::Read)
        .add(
            Endpoint::ProofInclusion.path(),
            get(get_inclusion_proof),
            Charge::Read,
        )
        .add(
            Endpoint::ProofConsistency.path(),
            get(get_consistency_proof),
            Charge::Read,
        )
        .add(
            Endpoint::TreeNodes.path(),
            get(get_tree_nodes),
            Charge::Page,
        )
        .add(
            Endpoint::Messages.path(),
            get(get_messages_ndjson),
            Charge::Page,
        )
        .add(Endpoint::Metrics.path(), get(get_metrics), Charge::Metrics);
    if operator_key.is_some() {
        routes = routes.add(OPERATOR_PATH, post(submit_operator), Charge::Submission);
    }
    routes
}

/// Runs the API server that answers HTTP requests.
/// The server serves the log and takes order submissions. `start_feed` bound
/// the listener before the database was opened; see the note there.
///
/// `ui_origins` is the operator's allowlist of origins for browser submissions.
/// The exchange serves the user interface, on a different port here and on a
/// different hostname or path behind a reverse proxy. A browser therefore
/// treats every submission as cross-origin, and sends none until this sequencer
/// says which origins may send one.
///
/// `operator_key` decides whether `/operator` exists at all. A sequencer that
/// names no operator does not serve the route, so a post gets 404 and not 403.
/// There is nothing here to refuse with, and the caller learns that this
/// sequencer takes no operator message, rather than that their own message was
/// wrong. The route checks against the key on the state. This parameter only
/// says whether to mount the route, and `start_feed` sets both from one value.
pub(super) fn feed_router(
    shared_state: Arc<Mutex<FeedState>>,
    ui_origins: Vec<String>,
    operator_key: Option<VerifyingKey>,
) -> Router {
    let metrics = Arc::clone(&lock(&shared_state).metrics);
    let mounted = mount(operator_key);
    // Written once at startup, so an operator reads which routes this sequencer
    // serves, and what each one charges, without reading this file.
    info!(
        "serving {}",
        mounted
            .routes
            .iter()
            .map(|(path, charge)| format!("{} ({:?})", path, charge))
            .collect::<Vec<_>>()
            .join(", ")
    );
    crate::http_security::guard(
        cors::guard(
            mounted
                .router
                .with_state(shared_state)
                .layer(axum::middleware::from_fn(move |req, next| {
                    let metrics = Arc::clone(&metrics);
                    async move { account(metrics, req, next).await }
                })),
            CorsPolicy::new(ui_origins, &SUBMISSION_PATHS, "feed"),
        ),
        crate::http_security::api(),
    )
}

/// Counts one request and the bytes its answer carries.
///
/// The count is here and not in the handlers, because a handler does not see
/// every answer. A 404, a rejected extractor and a refusal from `parsed` all
/// leave without a handler running, and those are exactly the requests worth
/// counting when something is wrong.
///
/// The size comes from the body's own size hint, so nothing is buffered or
/// copied to learn it. Every response this sequencer builds has a known length.
/// One that did not would be counted as zero bytes, and not held in memory to
/// be measured.
///
/// This runs inside the cross-origin guard. The OPTIONS request a browser sends
/// first is answered before any handler and carries no body, so it is not
/// counted as a request served.
async fn account(metrics: Arc<Metrics>, req: axum::extract::Request, next: Next) -> Response {
    let endpoint = Endpoint::of(req.uri().path());
    let response = next.run(req).await;
    let bytes = response.body().size_hint().exact().unwrap_or(0);
    metrics.served(endpoint, response.status(), bytes);
    response
}

pub(super) async fn run_server(
    shared_state: Arc<Mutex<FeedState>>,
    listener: tokio::net::TcpListener,
    ui_origins: Vec<String>,
    operator_key: Option<VerifyingKey>,
) {
    let app = feed_router(shared_state, ui_origins, operator_key);

    if let Ok(addr) = listener.local_addr() {
        info!("listening on {}", addr);
    }
    // The connection information is passed in because the submission rate
    // limiter needs the caller's address.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("feed server stopped unexpectedly");
}

/// The refusal a spent read budget produces.
///
/// The text names the address that was charged, the size of the budget, and
/// what a full check costs against that budget. The caller most likely to read
/// this text is a person checking an anchor, who wants to know whether they did
/// something wrong. They did not: 14 pages is under a third of the burst.
fn read_refused(
    ip: IpAddr,
    cost: u64,
    retry_after: u64,
    metrics: &Metrics,
) -> (StatusCode, String) {
    metrics.rate_limited();
    warn!(
        "read from {} refused: {} messages more than the budget of {} plus {} a second",
        ip, cost, READ_BURST, READ_REFILL_PER_SEC
    );
    (
        StatusCode::TOO_MANY_REQUESTS,
        format!(
            "this read reserves {} messages and the read budget for {} is spent. One address may \
             read {} messages in a burst and {} messages a second after that. Retry in {} \
             second(s). For scale: verifying the first anchor is 14 pages and about 14,000 \
             messages, well inside one burst. This limit is on repeated whole-history reads, not \
             on verifying",
            cost, ip, READ_BURST, READ_REFILL_PER_SEC, retry_after
        ),
    )
}

/// Adds a `Retry-After` header to a refusal that has one. The value is a whole
/// number of seconds, which is the only form every cache and every client
/// agrees on.
fn with_retry_after(status: StatusCode, body: String, seconds: u64) -> Response {
    let mut response = (status, body).into_response();
    if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// One read that has already paid for itself.
///
/// The fields are what every read handler needs and cannot work out alone. The
/// address is the one the budget was charged to, so a page can give back what
/// it did not use. The counters are held separately, so reading them does not
/// borrow the state.
struct Read<'a> {
    state: &'a mut FeedState,
    ip: IpAddr,
    metrics: Arc<Metrics>,
}

/// Runs one read against the sequencer's state, and charges for it first.
///
/// Every read used to write out the same four steps again: name the caller,
/// take a reference to the counters, spend `cost`, and answer 429 with a
/// `Retry-After` header if the budget is spent. A handler that left the steps
/// out answered anyway, so its traffic was neither limited nor counted, and
/// nothing said so. The four steps are now in one place, and a read handler
/// reaches the state only through the `Read` this function hands it.
///
/// The caller passes the cost, because the cost is not the same for every
/// route. A page reserves the messages it may return, `/metrics` costs
/// `METRICS_COST`, and every other route pays the flat request cost. That is
/// also why this is not a layer around the router: a layer sees the request
/// before the cost is known, and would have to take the state lock a second
/// time to charge for it.
///
/// The refusal comes back as `Ok` and not as an error, because it is a response
/// this sequencer builds. The `(StatusCode, String)` error carries no header,
/// and this refusal has to carry `Retry-After`. The error is left for what the
/// work itself refuses, so each handler keeps the answer it gave before.
async fn charged<F>(
    state: &Arc<Mutex<FeedState>>,
    caller: Caller,
    cost: u64,
    work: F,
) -> Result<Response, (StatusCode, String)>
where
    F: FnOnce(Read<'_>) -> Result<Response, (StatusCode, String)> + Send + 'static,
{
    with_state(state, move |state| {
        // The address is worked out here, where the operator's trusted-proxy
        // list is. Behind a reverse proxy the socket peer is the proxy for
        // every request. Charging that address would give every visitor and the
        // bot one shared budget. See `Caller::client_ip` in `inbox.rs`.
        let ip = caller.client_ip(&state.trusted_proxies);
        let metrics = Arc::clone(&state.metrics);
        if let Err(wait) = state.charge_read(ip, cost, Instant::now()) {
            let (status, body) = read_refused(ip, cost, wait, &metrics);
            return Ok(with_retry_after(status, body, wait));
        }
        work(Read { state, ip, metrics })
    })
    .await?
}

/// The media type of `/orders`. Set here and not by `Json`, because the body is
/// built from the stored bytes and not serialized from a value.
const JSON_CONTENT_TYPE: &str = "application/json";

/// One page as a JSON array of the messages' stored bytes.
///
/// The result is byte for byte what `serde_json::to_vec` over the same messages
/// would write. A JSON array is its elements separated by commas, with no
/// spaces. The one difference is that these elements are the bytes the
/// sequencer published, and not this build's idea of them.
fn json_array(messages: &[Published]) -> Vec<u8> {
    let width = messages.iter().map(|msg| msg.json.len() + 1).sum::<usize>() + 1;
    let mut body = Vec::with_capacity(width);
    body.push(b'[');
    for (index, msg) in messages.iter().enumerate() {
        if index > 0 {
            body.push(b',');
        }
        body.extend_from_slice(msg.json.as_bytes());
    }
    body.push(b']');
    body
}

/// The query parameters of the `/orders` endpoint.
#[derive(Deserialize)]
pub(super) struct GetOrdersQuery {
    /// Return only messages with an ID greater than this value. A caller asking
    /// for new messages passes the highest ID it has seen so far.
    pub(super) since: Option<OrderId>,
    /// If set, return the last n messages instead.
    pub(super) n: Option<usize>,
}

/// Answers `GET /orders` with one page of messages.
/// With `since`, returns every message after the given ID. A caller asking for
/// new messages uses this. With `n`, returns the last n messages.
///
/// Both forms return at most `PAGE_LIMIT` messages in one response.
///
/// Every response carries the session and a signed head in its headers. That
/// head stands exactly at the last message in the body. A consumer that hashes
/// each message into the chain across successive `?since=` responses reaches,
/// each time, the chain the sequencer signed for what it just received.
///
/// `?n=` is the exception, and cannot be anything else. It returns the *end* of
/// the history, and the chain in the head covers every message from message 1
/// onwards, which the end of the history does not hold. The head is still true,
/// because it stands at the last message in the body. It cannot be computed
/// again from that body. Check with `?since=`, which is what every consumer in
/// this repository does. It is also why `?n=` is never cached: it names a range
/// that moves with the head.
///
/// The array is built from the stored bytes, and not serialized from parsed
/// messages. Element `i` here is therefore the same byte string that line `i`
/// of `/messages.ndjson` carries. If two endpoints over one history disagreed
/// about a message's bytes, one endpoint's chain would verify and the other
/// endpoint's chain would not.
pub(super) async fn get_orders(
    State(state): State<Arc<Mutex<FeedState>>>,
    caller: Caller,
    headers: HeaderMap,
    Query(params): Query<GetOrdersQuery>,
) -> Result<Response, (StatusCode, String)> {
    let relative = params.n.is_some();
    let reserved = READ_REQUEST_COST + PAGE_LIMIT as u64;
    charged(&state, caller, reserved, move |read| {
        let Read { state, ip, metrics } = read;
        // `?n=` asks for the end of the history, which is exactly what the
        // window holds. `n` is capped at `PAGE_LIMIT`, and the window is always
        // larger than `PAGE_LIMIT`, so this read never needs the disk.
        let since = match params.n {
            Some(n) => state.last_id().saturating_sub(n.min(PAGE_LIMIT) as OrderId),
            None => params.since.unwrap_or(0),
        };
        // The 304 is answered before the page is read, and that is the whole
        // saving. The ETag needs the chain at one message, not the thousand
        // messages the page would return.
        if !relative
            && let Some(fresh) = closed_etag(state, since, PAGE_LIMIT)
            && if_none_match(&headers, &fresh)
        {
            state.refund_read(ip, PAGE_LIMIT as u64);
            return Ok(not_modified(&fresh, &metrics));
        }
        let (messages, head) = match state.page(since, PAGE_LIMIT) {
            Ok(page) => page,
            Err(e) => {
                state.refund_read(ip, PAGE_LIMIT as u64);
                warn!("cannot serve /orders?since={}: {}", since, e);
                return Err((StatusCode::GONE, e));
            }
        };
        state.refund_read(ip, PAGE_LIMIT as u64 - messages.len() as u64);
        let freshness = freshness_of(state, since, PAGE_LIMIT, relative, &messages, head);
        // An empty page carries the head of the whole history. That head is
        // what tells a consumer it already has every message. It is also
        // exactly the response that must never be cached.
        let (last_id, chain) = head.unwrap_or((state.last_id(), state.chain));
        let response = (
            state.head_headers_at(last_id, chain),
            [(header::CONTENT_TYPE, JSON_CONTENT_TYPE)],
            json_array(&messages),
        )
            .into_response();
        Ok(with_freshness(response, &freshness, &metrics))
    })
    .await
}

/// The ETag a closed page would answer with. `None` when the range is not
/// closed, or when the chain at the end of the range cannot be read.
///
/// This is a function of its own because the same range asks for the ETag
/// twice: once before the page is read, to answer `If-None-Match`, and once
/// after, to label the 200. Both have to produce the same string, or a client
/// would ask again for ever.
fn closed_etag(state: &FeedState, since: OrderId, limit: usize) -> Option<String> {
    if limit == 0 {
        return None;
    }
    let end = since.checked_add(limit as OrderId)?;
    if end > state.last_id() {
        return None;
    }
    let chain = state.chain_at(end)?;
    Some(page_etag(&state.session, since, end, &chain))
}

/// What this page may be cached as.
///
/// Each test below is a way a page can look closed and not be. `?n=` names a
/// range that moves with the head. A short page is one the next message makes
/// longer. An empty page carries the current head, and not a head inside its
/// own body. The head comes from `page()`'s own `Some` branch. A response whose
/// head came from the current-head fallback therefore cannot reach `Closed`,
/// even if a later change made the other tests pass.
fn freshness_of(
    state: &FeedState,
    since: OrderId,
    limit: usize,
    relative: bool,
    messages: &[Published],
    head: Option<(OrderId, Chain)>,
) -> Freshness {
    if relative || messages.len() != limit {
        return Freshness::Open;
    }
    let Some((last_id, chain)) = head else {
        return Freshness::Open;
    };
    if Some(last_id) != messages.last().map(|msg| msg.id) {
        return Freshness::Open;
    }
    Freshness::Closed {
        etag: page_etag(&state.session, since, last_id, &chain),
    }
}

/// Answers `GET /head` with the signed head of the log, as a JSON document. It
/// is for anyone who wants to record the sequencer's claim about its own
/// history: a person checking the log, or a user keeping evidence.
///
/// The answer is `no-store`, and this is the endpoint where that matters most.
/// `/head` is the one place a caller asks where this sequencer stands right
/// now, so an answer out of a cache is the old head that the paged endpoints
/// are careful not to produce. Today `/head` sends no cache headers at all,
/// which is not the same as being uncacheable. RFC 9111 lets a shared cache
/// give a 200 with no `Cache-Control` a freshness lifetime of the cache's own
/// choosing. That risk therefore already exists on the live sequencer, and this
/// line ends it.
async fn get_head(
    State(state): State<Arc<Mutex<FeedState>>>,
    caller: Caller,
) -> Result<Response, (StatusCode, String)> {
    charged(&state, caller, READ_REQUEST_COST, |read| {
        let response = Json(read.state.signed_head()).into_response();
        Ok(with_freshness(response, &Freshness::Open, &read.metrics))
    })
    .await
}

// ---------------------------------------------------------------------------
// The Merkle log: the signed tree head and the two proofs
// ---------------------------------------------------------------------------

/// Answers `GET /sth` with the signed tree head, RFC 9162 `TreeHeadDataV2`.
/// STH is the short name for a signed tree head.
///
/// This is what a client keeps. Both proof endpoints below are checked against
/// the root in an STH the client already holds. `/sth` is therefore the only
/// one of the three that carries a signature, and the only one that has to be
/// fresh.
///
/// The answer is `no-store`, exactly like `/head` and for the same reason: this
/// is where a caller asks where the sequencer stands right now. RFC 9162 also
/// requires each timestamp to be later than the last one. A cache that handed
/// out an old copy would undo that rule from the client's side. The copy would
/// be a head this sequencer really signed, shown as the current one, and that
/// is what the rule exists to stop.
async fn get_sth(
    State(state): State<Arc<Mutex<FeedState>>>,
    caller: Caller,
) -> Result<Response, (StatusCode, String)> {
    charged(&state, caller, READ_REQUEST_COST, |read| {
        let head = match read.state.signed_tree_head() {
            Ok(head) => head,
            // The sequencer cannot read the tree it signs heads over. That is
            // this program's problem and not the caller's, so the answer is a
            // 500, and not a head over a size that no proof can support.
            Err(e) => return Ok(unreadable_tree(&e).into_response()),
        };
        let response = Json(head).into_response();
        Ok(with_freshness(response, &Freshness::Open, &read.metrics))
    })
    .await
}

/// Query parameters for `GET /proof/inclusion`.
#[derive(Deserialize)]
struct InclusionQuery {
    /// Which leaf, counted from 0 as RFC 9162 counts leaves. Message `n` is
    /// leaf `n - 1`, and the answer carries both numbers.
    leaf: u64,
    /// Which tree. Required, and on purpose it does not default to the newest
    /// tree: see the note on the handler.
    tree_size: u64,
}

/// Query parameters for `GET /proof/consistency`.
#[derive(Deserialize)]
struct ConsistencyQuery {
    first: u64,
    second: u64,
}

/// What a proof may be cached as.
///
/// A proof is computed from the leaves below the size it names, and those
/// leaves never change. One URL therefore answers with the same bytes for ever,
/// at any size. What decides the caching is not the answer but the number
/// inside it. A proof against the size the tree has reached right now carries
/// that size in its body, and this sequencer's rule (see `cache.rs`) is that no
/// response naming the current head may be cached: a copy served a year later
/// would tell its reader that the tree is still that size. It is also an answer
/// nobody asks for twice, because the next caller reads a newer STH and asks
/// about a newer size.
///
/// Below the head, the same URL is what every holder of one widely published
/// STH asks for. The anchored STH is the clearest case, and that case is what
/// caching is for.
fn proof_freshness(state: &FeedState, named: u64, etag: String) -> Freshness {
    if named < state.tree_size() {
        Freshness::Closed { etag }
    } else {
        Freshness::Open
    }
}

/// Turns a proof this sequencer did not produce into an answer that says whose
/// problem it is.
///
/// All three `ProofError`s answer 400. In all three the caller named something
/// that does not exist, and nothing here is wrong. That is what
/// `merkle::ProofError` says about itself.
///
/// The session and the size are in the text because the likeliest cause is a
/// client holding a head from a different history. Tree sizes restart at 0 when
/// a sequencer is given a new database, so an STH from before that names a size
/// this tree may never reach.
///
/// The other half answers 500. A node this sequencer cannot read back is not a
/// question the caller asked wrong, and answering 400 would send a client
/// looking for a mistake in numbers that were right.
fn proof_refused(
    session: &str,
    tree_size: u64,
    error: TreeError<Unreadable>,
) -> (StatusCode, String) {
    match error {
        TreeError::Proof(error) => (
            StatusCode::BAD_REQUEST,
            format!(
                "{}. This is feed history {}, and its tree holds {} messages. If your signed tree \
                 head names a different history, its proofs are not this feed's to produce",
                error, session, tree_size
            ),
        ),
        TreeError::Source(error) => unreadable_tree(&error),
    }
}

/// The answer when this sequencer cannot read its own tree, on any endpoint
/// that needs the tree.
///
/// The text is written by `error!` as well as returned, because a caller who
/// sees it can do nothing about it, and an operator has to.
fn unreadable_tree(error: &Unreadable) -> (StatusCode, String) {
    error!("this feed cannot read its own Merkle tree: {}", error);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("this feed cannot read its own Merkle tree: {}", error),
    )
}

/// Answers `GET /proof/inclusion?leaf=N&tree_size=M` with the node hashes that
/// compute the root of the tree of size M from leaf N, RFC 9162 section
/// 2.1.3.1.
///
/// **The caller names `tree_size`, and it is required.** A client checks a
/// proof against the root in an STH it holds, and that STH names the size the
/// tree had when it was signed. Answering only for the newest tree would make
/// every STH useless as soon as the next message is published, which on this
/// sequencer is within a second. The root of any earlier size can still be
/// computed from the tree in memory, and that is what `merkle::root_at` is for.
///
/// No root and no signature come back. The client already has the root, from
/// the STH. Serving an unsigned root beside the proof would invite a client to
/// check the proof against a root this sequencer never signed. That check
/// always succeeds and proves nothing.
async fn get_inclusion_proof(
    State(state): State<Arc<Mutex<FeedState>>>,
    caller: Caller,
    headers: HeaderMap,
    Query(params): Query<InclusionQuery>,
) -> Result<Response, (StatusCode, String)> {
    charged(&state, caller, READ_REQUEST_COST, move |read| {
        let Read { state, metrics, .. } = read;
        // The proof first, then the 304. `/orders` does it the other way round,
        // because its 304 saves reading a thousand rows out of SQLite. Here the
        // proof is a few hashes. Computing it first means a 304 can only stand
        // in for an answer this sequencer would really have given. A made-up
        // `If-None-Match` on a leaf that does not exist then gets a refusal,
        // and not "nothing has changed".
        let inclusion_path = state
            .inclusion_proof(params.leaf, params.tree_size)
            .map_err(|e| proof_refused(&state.session, state.tree_size(), e))?;
        let etag = proof_etag(&state.session, "inclusion", params.leaf, params.tree_size);
        let freshness = proof_freshness(state, params.tree_size, etag);
        if let Freshness::Closed { etag } = &freshness
            && if_none_match(&headers, etag)
        {
            return Ok(not_modified(etag, &metrics));
        }
        let response = Json(InclusionProof {
            session: state.session.clone(),
            leaf_index: params.leaf,
            // The proof was produced, so `leaf < tree_size`, and this addition
            // cannot overflow.
            message_id: params.leaf + 1,
            tree_size: params.tree_size,
            inclusion_path,
        })
        .into_response();
        Ok(with_freshness(response, &freshness, &metrics))
    })
    .await
}

/// Query parameters for `GET /tree/nodes`.
#[derive(Deserialize)]
struct TreeNodesQuery {
    /// The first leaf of the range, counted from 0. Message `n` is leaf
    /// `n - 1`.
    #[serde(default)]
    from: u64,
    /// How many leaves' worth of nodes to serve. Clamped to
    /// `tree::MAX_NODE_LEAVES`, the way `/orders` clamps its own limit: a
    /// caller cannot tell a clamped answer from a short one, and both mean the
    /// same thing, which is to ask again from where this answer ended.
    #[serde(default = "default_node_count")]
    count: u64,
}

fn default_node_count() -> u64 {
    tree::MAX_NODE_LEAVES
}

/// Answers `GET /tree/nodes?from=N&count=M` with the Merkle nodes this
/// sequencer stored when it appended leaves `N .. N + M`.
///
/// This is the one part of the log a stranger could not check. Everything else
/// is signed, or comes from something signed: each message is hashed into the
/// chain the head carries, the chain and the root carry a signature, and the
/// root is written to Base, a public blockchain. The nodes between the leaves
/// and the root are none of these. They are what every inclusion proof is built
/// out of, and until this route existed the only thing that ever compared them
/// against the messages was a test in this repository, with the database file
/// open.
///
/// A reader hashes the messages it was served into the same tree and compares
/// the nodes. A node that does not match is a node whose proofs reach a root
/// the sequencer did not sign, see `merkle::compare_nodes`.
///
/// Nothing here is signed and nothing needs to be. The reader checks the nodes
/// against the tree the reader built from the messages, so a sequencer that
/// serves made-up nodes fails that comparison. A signature over the nodes would
/// prove only that the sequencer said them, which is the thing the reader is
/// testing.
async fn get_tree_nodes(
    State(state): State<Arc<Mutex<FeedState>>>,
    caller: Caller,
    headers: HeaderMap,
    Query(params): Query<TreeNodesQuery>,
) -> Result<Response, (StatusCode, String)> {
    charged(&state, caller, READ_REQUEST_COST, move |read| {
        let Read { state, metrics, .. } = read;
        let count = params.count.min(tree::MAX_NODE_LEAVES);
        let tree_size = state.tree_size();
        let nodes = tree::window(&state.storage.nodes(), params.from, count)
            .map_err(|e| unreadable_tree(&e))?;
        // Cacheable exactly when the range is closed. A perfect subtree never
        // changes once it is complete, so the nodes below the head are the same
        // bytes for ever. A range that reaches the head is not cacheable, for
        // the reason on `proof_freshness`.
        let etag = proof_etag(&state.session, "nodes", params.from, count);
        let freshness = proof_freshness(state, params.from.saturating_add(count), etag);
        if let Freshness::Closed { etag } = &freshness
            && if_none_match(&headers, etag)
        {
            return Ok(not_modified(etag, &metrics));
        }
        let response = Json(wire::TreeNodes {
            session: state.session.clone(),
            tree_size,
            from: params.from,
            count,
            nodes: nodes
                .into_iter()
                .map(|(level, index, hash)| wire::TreeNode {
                    level,
                    index,
                    hash: logchain::to_hex(&hash),
                })
                .collect(),
        })
        .into_response();
        Ok(with_freshness(response, &freshness, &metrics))
    })
    .await
}

/// Answers `GET /proof/consistency?first=M&second=N` with proof that the tree
/// of size M is the start of the tree of size N, RFC 9162 section 2.1.4.1.
///
/// This proof is what replaces the chain. It says that messages were added and
/// never changed, removed or reordered, and it says that in `log2(N)` hashes,
/// where hashing the chain again says it in N messages.
///
/// The caller names both sizes. The pair that matters is two STHs the client
/// kept from two different moments, and neither has to be the newest.
async fn get_consistency_proof(
    State(state): State<Arc<Mutex<FeedState>>>,
    caller: Caller,
    headers: HeaderMap,
    Query(params): Query<ConsistencyQuery>,
) -> Result<Response, (StatusCode, String)> {
    charged(&state, caller, READ_REQUEST_COST, move |read| {
        let Read { state, metrics, .. } = read;
        // The proof before the 304, for the reason on `get_inclusion_proof`.
        let consistency_path = state
            .consistency_proof(params.first, params.second)
            .map_err(|e| proof_refused(&state.session, state.tree_size(), e))?;
        let etag = proof_etag(&state.session, "consistency", params.first, params.second);
        let freshness = proof_freshness(state, params.second, etag);
        if let Freshness::Closed { etag } = &freshness
            && if_none_match(&headers, etag)
        {
            return Ok(not_modified(etag, &metrics));
        }
        let response = Json(ConsistencyProof {
            session: state.session.clone(),
            first: params.first,
            second: params.second,
            consistency_path,
        })
        .into_response();
        Ok(with_freshness(response, &freshness, &metrics))
    })
    .await
}

/// The media type of `/messages.ndjson`. The body is one JSON document per
/// line, which is not itself a JSON document and must not be labelled as one.
const NDJSON_CONTENT_TYPE: &str = "application/x-ndjson";

/// Query parameters for `GET /messages.ndjson`. It serves the same page
/// `/orders?since=` serves, and the caller chooses the page size, up to
/// `PAGE_LIMIT`.
#[derive(Deserialize)]
pub(super) struct MessagesQuery {
    /// Return only messages with an ID greater than this value.
    pub(super) since: Option<OrderId>,
    /// How many messages to return, capped at `PAGE_LIMIT` like every other
    /// page.
    pub(super) limit: Option<usize>,
}

/// Answers `GET /messages.ndjson` with the same messages `/orders` serves. Each
/// line is the exact bytes that were hashed into the chain, one message per
/// line.
///
/// This endpoint exists because a browser cannot produce those bytes again. The
/// chain hashes `logchain::canonical_bytes`, which is `serde_json::to_vec`.
/// serde writes an f64 price of 100.0 as `100.0`, and JavaScript's
/// `JSON.stringify` writes `100`. Same number, different bytes, different
/// SHA-256 hash, so a page that parsed `/orders` and serialized it again
/// would compute a chain that disagrees with the head this sequencer signed,
/// and would report a correct sequencer as wrong. Served exactly as stored, a
/// page hashes each line as it arrived and serializes nothing.
///
/// The head headers are the same ones `/orders` carries and stand at the same
/// place, the last message in the body, so a page that hashes each message
/// into the chain across successive `?since=` responses checks every response
/// against a signature. That is also what lets a closed page be cached with its
/// head attached; see `Freshness`.
///
/// This is the endpoint the browser check runs on, and the one the cache
/// headers were added for. Checking the first anchor is `?since=0&limit=1000`
/// through `?since=13000&limit=774`: 14 URLs, every one of them a closed range,
/// every one of them answered from cache for the second visitor, and every one
/// answered with a 304 for a client that kept the ETag.
pub(super) async fn get_messages_ndjson(
    State(state): State<Arc<Mutex<FeedState>>>,
    caller: Caller,
    headers: HeaderMap,
    Query(params): Query<MessagesQuery>,
) -> Result<Response, (StatusCode, String)> {
    let since = params.since.unwrap_or(0);
    let limit = params.limit.unwrap_or(PAGE_LIMIT).min(PAGE_LIMIT);
    // The read is charged for what it asks for, before the work runs. What it
    // did not use is given back below. See `ReadLimiter::refund`.
    let reserved = READ_REQUEST_COST + limit as u64;
    charged(&state, caller, reserved, move |read| {
        let Read { state, ip, metrics } = read;
        if let Some(fresh) = closed_etag(state, since, limit)
            && if_none_match(&headers, &fresh)
        {
            state.refund_read(ip, limit as u64);
            return Ok(not_modified(&fresh, &metrics));
        }
        let (messages, head) = match state.page(since, limit) {
            Ok(page) => page,
            Err(e) => {
                state.refund_read(ip, limit as u64);
                warn!("cannot serve /messages.ndjson?since={}: {}", since, e);
                return Err((StatusCode::GONE, e));
            }
        };
        state.refund_read(ip, limit as u64 - messages.len() as u64);
        // One stored message and one 0x0A byte per line, and nothing else in
        // the body: what a line holds is exactly what was hashed.
        let mut body = Vec::new();
        for msg in &messages {
            body.extend_from_slice(msg.json.as_bytes());
            body.push(b'\n');
        }
        let freshness = freshness_of(state, since, limit, false, &messages, head);
        // An empty page carries the head of the whole history, exactly as
        // `/orders` does. That head is what tells a caller it already has every
        // message.
        let (last_id, chain) = head.unwrap_or((state.last_id(), state.chain));
        let response = (
            state.head_headers_at(last_id, chain),
            [(header::CONTENT_TYPE, NDJSON_CONTENT_TYPE)],
            body,
        )
            .into_response();
        Ok(with_freshness(response, &freshness, &metrics))
    })
    .await
}

/// The request body for submitting a new order.
///
/// Two fields were added when submissions started to be signed. `public_key` is
/// the account's Ed25519 key. `signature` covers `inbox::submission_statement`
/// for exactly these terms. They sit beside the order, and not in a header or a
/// wrapper, because that is how every other signed thing in this system
/// travels: `SignedHead` and `MarkRequest` both carry `public_key` and
/// `signature` as plain hex fields next to what they cover.
#[derive(Debug, Deserialize)]
pub(super) struct SubmitOrderRequest {
    pub(super) account: AccountId,
    pub(super) symbol: String,
    pub(super) side: Side,
    pub(super) price: f64,
    pub(super) quantity: f64,
    /// The submitter's nonce: 32 lowercase hex characters. A nonce is a value
    /// used once, so the same signed body cannot become two messages. The
    /// signature covers it, and the published message carries it. Required: a
    /// body without a nonce comes from a caller still signing the v1 statement,
    /// and the answer says so.
    pub(super) nonce: String,
    /// The session of the log this order is for, 16 lowercase hex characters,
    /// as `GET /head` and the `x-feed-session` header report it. The signature
    /// covers it, and `submit` refuses a session that is not this log's.
    /// Required: a body without a session comes from a caller still signing the
    /// v2 statement.
    pub(super) session: String,
    /// The three order terms, each absent when it holds its default, exactly as
    /// `OrderMessage::New` writes them. A body that names none of them is the
    /// plain limit order every body was before these existed.
    ///
    /// The signature covers all three whatever they hold, see
    /// `inbox::submission_statement`. Absent here means the default, and the
    /// default is what gets signed.
    #[serde(default)]
    pub(super) order_type: OrderType,
    #[serde(default)]
    pub(super) time_in_force: TimeInForce,
    #[serde(default)]
    pub(super) post_only: bool,
    pub(super) public_key: String,
    pub(super) signature: String,
}

/// The response returned when a message is accepted into the log.
///
/// The receipt is the submitter's proof that the message is in the log. A head
/// signed at the message's ID, or after it, commits to a history that holds
/// that message. If the sequencer later serves a history without the message,
/// hashing that history's messages again does not reach the receipt's chain,
/// and the receipt carries the sequencer's own signature on the claim it broke.
#[derive(Serialize)]
pub(super) struct SubmitResponse {
    pub(super) id: OrderId,
    pub(super) receipt: SignedHead,
}

/// Answers `POST /order` and puts one new order into the log.
/// The order is checked, given an ID, and published like any other message.
///
/// The check is `inbox.rs`'s `validate_submission`, called and not copied. The
/// two ways in must accept exactly the same orders, and the rules they both
/// need are the *matching engine's*: the exchange drops a price of 100.253
/// with no record, so accepting that price here answered 200 and a signed
/// receipt for an order that would never exist. A second copy of those rules in
/// this file would be a second thing to keep in step with `matcher.rs`.
pub(super) async fn submit_order(
    State(state): State<Arc<Mutex<FeedState>>>,
    caller: Caller,
    body: Result<Json<SubmitOrderRequest>, JsonRejection>,
) -> Result<Json<SubmitResponse>, (StatusCode, String)> {
    let req = parsed(
        body,
        "{\"account\": 1000, \"symbol\": \"ETH-USDC\", \"side\": \"Buy\", \"price\": 100.25, \
         \"quantity\": 5.0, \"nonce\": \"<32 hex>\", \"session\": \"<16 hex>\", \
         \"public_key\": \"<64 hex>\", \"signature\": \"<128 hex>\"}, and may also name \
         \"order_type\", \"time_in_force\" and \"post_only\"",
    )?;
    let signed = SignedSubmission {
        submission: Submission::Order {
            account: req.account,
            symbol: req.symbol,
            side: req.side,
            price: req.price,
            quantity: req.quantity,
            nonce: Some(req.nonce),
            session: Some(req.session),
            order_type: req.order_type,
            time_in_force: req.time_in_force,
            post_only: req.post_only,
        },
        public_key: req.public_key,
        signature: req.signature,
    };
    submit(state, caller, signed).await
}

/// The request body for submitting a cancel. `public_key` and `signature` are
/// as on `SubmitOrderRequest`. The statement a cancel's signature covers is the
/// account and the target id.
#[derive(Debug, Deserialize)]
pub(super) struct SubmitCancelRequest {
    pub(super) account: AccountId,
    pub(super) target_id: OrderId,
    /// As on `SubmitOrderRequest`. A new nonce for each cancel, and not one for
    /// each account: sending a cancel again until it takes effect is normal
    /// behaviour (the bot does exactly that), and each of those sends is its
    /// own submission.
    pub(super) nonce: String,
    /// As on `SubmitOrderRequest`: the session of the log this cancel is for.
    pub(super) session: String,
    pub(super) public_key: String,
    pub(super) signature: String,
}

/// Answers `POST /cancel` and puts one cancel into the log.
/// The sequencer does not check whether the target order is still waiting to
/// trade. Each consumer of the log decides what a cancel means for its own
/// book. The sequencer checks what can be checked here: that the account's own
/// key signed the cancel, and that `target_id` is not 0. Message ids start at
/// 1, so 0 names no message that can ever exist.
///
/// Proving who owns the account is what makes the exchange's ownership check
/// mean something. `apply_cancel` refuses a cancel whose account is not the
/// resting order's owner. Until the account field was proved, that check
/// compared a number the sender had chosen against a number the sender had
/// chosen earlier, and anyone could cancel anyone's order by writing their
/// number. The check in `matcher.rs` did not need to change. What changed is
/// that the number it reads can now only have come from the account it names.
pub(super) async fn submit_cancel(
    State(state): State<Arc<Mutex<FeedState>>>,
    caller: Caller,
    body: Result<Json<SubmitCancelRequest>, JsonRejection>,
) -> Result<Json<SubmitResponse>, (StatusCode, String)> {
    let req = parsed(
        body,
        "{\"account\": 1000, \"target_id\": 42, \"nonce\": \"<32 hex>\", \
         \"session\": \"<16 hex>\", \"public_key\": \"<64 hex>\", \"signature\": \"<128 hex>\"}",
    )?;
    let signed = SignedSubmission {
        submission: Submission::Cancel {
            account: req.account,
            target_id: req.target_id,
            nonce: Some(req.nonce),
            session: Some(req.session),
        },
        public_key: req.public_key,
        signature: req.signature,
    };
    submit(state, caller, signed).await
}

/// Turns a body axum could not deserialize into a refusal that shows the shape
/// this endpoint wants. The extractor's own answer is a 422 that says nothing
/// about that shape.
///
/// Both endpoints changed shape when submissions started to be signed. The
/// likeliest reason a body fails to parse is a caller still sending the
/// unsigned shape, and the answer says so.
fn parsed<T>(body: Result<Json<T>, JsonRejection>, shape: &str) -> Result<T, (StatusCode, String)> {
    match body {
        Ok(Json(req)) => Ok(req),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "this body is not a signed submission ({}). This endpoint takes {}: the \
                 signature covers the account's statement for these terms, see the README",
                e.body_text(),
                shape
            ),
        )),
    }
}

/// The part `POST /order` and `POST /cancel` share: check the terms, check that
/// the account named really asked for this, apply the rate limit, take an id,
/// publish, and answer with the receipt.
///
/// The checks run in this order on purpose. The terms are checked first,
/// because that step turns the price and the quantity into whole numbers of
/// steps, and those whole numbers are what the signature covers. The signature
/// is then checked with no lock and no database, so a made-up submission is
/// refused before it can touch either. Only a submission that passes both
/// reaches the state, where the rate limit, the account pin and the publish
/// happen together under one lock.
///
/// A submission that fails any of these is refused. It is not accepted and
/// marked. A marked message would still be in the log, still hashed into the
/// chain, still handed to the exchange, and the exchange's ownership rules
/// read the account field, not a mark beside it.
///
/// A publish that could not be written to disk answers 503 and no receipt. The
/// submitter is told their order did not go in, which is true and can be acted
/// on; the old code answered 200 with a signed receipt for a message the next
/// restart would not have.
async fn submit(
    state: Arc<Mutex<FeedState>>,
    caller: Caller,
    signed: SignedSubmission,
) -> Result<Json<SubmitResponse>, (StatusCode, String)> {
    inbox::validate_submission(&signed.submission).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let key = inbox::verify_account_signature(&signed)?;
    let account = inbox::account_of(&signed.submission);
    let submission = signed.submission;
    // Decoded here, so the state lock is not held while it runs, and decoded
    // again rather than assumed from the check above: an `expect` on this path
    // would let a request body panic the task and leave the sequencer's state
    // lock unusable for every request after it.
    let nonce = inbox::checked_nonce(&submission).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let nonce_text = logchain::to_hex(&nonce);

    with_state(&state, move |state| {
        // The address is worked out here, where the operator's trusted-proxy
        // list is. Behind a reverse proxy the socket peer is the proxy for
        // every request. Limiting on that address would give every visitor and
        // the bot one shared count. See `Caller::client_ip` in `inbox.rs`.
        let ip = caller.client_ip(&state.trusted_proxies);
        if !state.limiter.allow(ip, Instant::now()) {
            warn!(
                "submission from {} refused: more than {} in {:?}",
                ip, SUBMIT_BURST, SUBMIT_WINDOW
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "more than {} submissions from {} in {} seconds",
                    SUBMIT_BURST,
                    ip,
                    SUBMIT_WINDOW.as_secs()
                ),
            ));
        }
        // The opening defines the rule set and every compiled market. A user
        // order in one of those positions can make a listing arrive too late,
        // so every non-operator writer waits for the complete opening. This
        // check follows the request charge so the opening cannot be used to
        // bypass the submission budget.
        if !state.log_is_open() {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "the operator is still opening this log: {} of {} opening messages are \
                     published. Retry this signed submission after the opening completes",
                    state.last_id().min(OPENING_MESSAGES),
                    OPENING_MESSAGES
                ),
            ));
        }
        // The session names the log, and this is the only party that knows
        // which log is running. Checked here rather than at intake in the
        // separate service, which cannot learn the session without asking this
        // sequencer, see `inbox::checked_session`. `sequence_drained` makes
        // the same call, so both ways in answer one signed submission alike.
        inbox::check_session(&state.session, &submission)?;
        state.pin_or_check_account(account, &key)?;
        // This runs before an id is taken. A repeat of the same submission must
        // not use up a sequence number, and the answer has to name the message
        // this submission already became, instead of making a second message.
        //
        // This also settles a case that is older than the nonce check and was a
        // plain bug: a client whose connection dropped after the sequencer
        // published, and which sent the order again, used to get a second
        // identical order. The same signed bytes are now told which message
        // they are.
        if let Some(existing) = state.nonces.get(&(account, nonce)) {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "account {} already submitted nonce {}, and it is feed message {}. The same \
                     signed submission cannot become a second message; if this is a retry, that \
                     message is your order, and if you meant to send another one, sign it with a \
                     fresh nonce",
                    account, nonce_text, existing
                ),
            ));
        }
        let id = state.next_id;
        state.next_id += 1;
        let timestamp = state.clock.now_ms();
        // One conversion for both ways in. The drain in `drain.rs` calls the
        // same function, so the same signed submission becomes the same message
        // whichever way it arrives, and a new order term is one edit.
        let msg = inbox::message_from(id, timestamp, &submission);
        info!("Received submission: {:?}", msg);
        state
            .publish(msg)
            .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e))?;
        // The head is signed after publishing and still under the lock, so the
        // receipt's head stands exactly at this message's place in the history.
        Ok(SubmitResponse {
            id,
            receipt: state.signed_head(),
        })
    })
    .await?
    .map(Json)
}

// ---------------------------------------------------------------------------
// The operator's endpoint
// ---------------------------------------------------------------------------

/// The request body for `POST /operator`. It carries one of the three messages
/// that only the operator may publish.
///
/// One endpoint with a `kind` field, and not three endpoints. The three
/// messages carry different terms, but they carry the same key, the same
/// signature and the same nonce, and every check below is the same for all
/// three. Three routes would be three copies of those checks.
///
/// The variant names are the message names in `domain.rs`, so the body a caller
/// writes and the message it becomes read the same.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
pub(super) enum SubmitOperatorRequest {
    ListSymbol {
        symbol: String,
        price_step: f64,
        quantity_step: f64,
        nonce: String,
        public_key: String,
        signature: String,
    },
    DelistSymbol {
        symbol: String,
        nonce: String,
        public_key: String,
        signature: String,
    },
    EngineRule {
        version: u32,
        nonce: String,
        public_key: String,
        signature: String,
    },
}

impl SubmitOperatorRequest {
    /// The key this body names. `submit_operator` then asks whether that key is
    /// the key this exchange trusts.
    fn public_key(&self) -> &str {
        match self {
            SubmitOperatorRequest::ListSymbol { public_key, .. }
            | SubmitOperatorRequest::DelistSymbol { public_key, .. }
            | SubmitOperatorRequest::EngineRule { public_key, .. } => public_key,
        }
    }

    /// The nonce this body carries, as the caller wrote it.
    fn nonce(&self) -> &str {
        match self {
            SubmitOperatorRequest::ListSymbol { nonce, .. }
            | SubmitOperatorRequest::DelistSymbol { nonce, .. }
            | SubmitOperatorRequest::EngineRule { nonce, .. } => nonce,
        }
    }

    /// The message this body asks for, at the id and the timestamp the
    /// sequencer assigns.
    ///
    /// The signed statement covers neither the id nor the timestamp, because
    /// the operator cannot know either one when signing. The same body
    /// therefore builds both the message that is verified and the message that
    /// is published, and only these two fields differ between them.
    fn message(&self, id: OrderId, timestamp: u64) -> OrderMessage {
        match self {
            SubmitOperatorRequest::ListSymbol {
                symbol,
                price_step,
                quantity_step,
                nonce,
                public_key,
                signature,
            } => OrderMessage::ListSymbol {
                id,
                timestamp,
                account: OPERATOR_ACCOUNT,
                symbol: symbol.clone(),
                price_step: *price_step,
                quantity_step: *quantity_step,
                nonce: Some(nonce.clone()),
                public_key: public_key.clone(),
                signature: signature.clone(),
            },
            SubmitOperatorRequest::DelistSymbol {
                symbol,
                nonce,
                public_key,
                signature,
            } => OrderMessage::DelistSymbol {
                id,
                timestamp,
                account: OPERATOR_ACCOUNT,
                symbol: symbol.clone(),
                nonce: Some(nonce.clone()),
                public_key: public_key.clone(),
                signature: signature.clone(),
            },
            SubmitOperatorRequest::EngineRule {
                version,
                nonce,
                public_key,
                signature,
            } => OrderMessage::EngineRule {
                id,
                timestamp,
                account: OPERATOR_ACCOUNT,
                version: *version,
                nonce: Some(nonce.clone()),
                public_key: public_key.clone(),
                signature: signature.clone(),
            },
        }
    }
}

/// Answers `POST /operator` and publishes one message the operator signed.
///
/// The same steps as `submit`, in the same order and for the same reasons: the
/// shape of the message first, with no lock and no key, then who signed it,
/// then the rate limit, the nonce check and the publish together under one
/// lock.
///
/// Two things this route does not do, on purpose.
///
/// It is not in `SUBMISSION_PATHS`, so the cross-origin guard refuses the
/// OPTIONS request a browser sends first, and no page in a browser can call
/// this route. This route is for a command line that holds a key file. The key
/// that may publish here is the one key the exchange trusts for everything, and
/// a page that can be asked to send that key a body is one more way for the key
/// to be used by mistake.
///
/// It does not call `pin_or_check_account`. That function ties an account
/// number to a trader's key, both ways: the account can never be used by
/// another key, and the key is recorded as that account's key. An operator
/// message is published under `OPERATOR_ACCOUNT`, which names nobody, and the
/// operator key is not a trading account. Pinning it would make the two one
/// thing.
pub(super) async fn submit_operator(
    State(state): State<Arc<Mutex<FeedState>>>,
    caller: Caller,
    body: Result<Json<SubmitOperatorRequest>, JsonRejection>,
) -> Result<Json<SubmitResponse>, (StatusCode, String)> {
    let req = parsed(
        body,
        "{\"kind\": \"ListSymbol\", \"symbol\": \"ALFA-USD\", \"price_step\": 0.01, \
         \"quantity_step\": 0.1, \"nonce\": \"<32 hex>\", \"public_key\": \"<64 hex>\", \
         \"signature\": \"<128 hex>\"}: kind is ListSymbol, DelistSymbol or EngineRule",
    )?;
    // Nothing here checks which rule set an `EngineRule` names, and nothing
    // should. `version` is a `u32`, so `parsed` above already refused anything
    // that is not a number in range for the field, and that is the whole shape
    // of the message. Which rule sets exist is a fact about what the exchange
    // implements, not a fact about the message, and this sequencer does not run
    // messages, the same reason it holds no list of symbols. A number kept
    // here would be a third copy of a number the exchange and the checker each
    // hold, and on the day rule set 3 is added to those two and not to this
    // file, this endpoint would refuse a message the exchange would have run.
    // `--engine-rule` reads the exchange's own `/market` and warns instead.
    let nonce = inbox::canonical_nonce(req.nonce()).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "nonce {} is not 32 lowercase hex characters",
                req.nonce().trim()
            ),
        )
    })?;
    let nonce_text = logchain::to_hex(&nonce);
    // Id 0 and timestamp 0: the statement covers neither field, so this message
    // verifies exactly as the published one will. The published message is
    // built again below, with the id and the timestamp the sequencer assigns.
    let unsequenced = req.message(0, 0);
    // The symbol rule, and the steps being whole cents and whole tenths. A
    // message that fails one of these has no statement to verify, so the answer
    // is about the message, and not about who signed it.
    operator::kind_and_fields(&unsequenced).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    with_state(&state, move |state| {
        // The route exists only where a key is configured, so this is the same
        // answer a sequencer that names no operator gives: the endpoint is not
        // here.
        let Some(key) = state.operator_key else {
            return Err((
                StatusCode::NOT_FOUND,
                "this sequencer names no operator, so it publishes no operator message".to_string(),
            ));
        };
        // The named key is checked first, so a stranger is told their key is
        // not the one this exchange trusts, and not that their signature is
        // bad. `operator::verify` checks the key too, and has to: the checker
        // calls it when the checker runs the log again, and there no route
        // checked the key first.
        let named = logchain::from_hex::<32>(req.public_key().trim());
        if named.as_ref() != Some(key.as_bytes()) {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "public_key {} is not the operator key this sequencer publishes for, which \
                     is {}",
                    req.public_key().trim(),
                    logchain::to_hex(key.as_bytes())
                ),
            ));
        }
        // The session is this history's name, and the statement covers it. A
        // signature made for another log, or for this log before it was
        // emptied, does not verify here.
        operator::verify(&unsequenced, &state.session, &key)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
        let ip = caller.client_ip(&state.trusted_proxies);
        if !state.limiter.allow(ip, Instant::now()) {
            warn!(
                "operator message from {} refused: more than {} in {:?}",
                ip, SUBMIT_BURST, SUBMIT_WINDOW
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "more than {} submissions from {} in {} seconds",
                    SUBMIT_BURST,
                    ip,
                    SUBMIT_WINDOW.as_secs()
                ),
            ));
        }
        // This runs before an id is taken, as on `submit`: a repeat must not
        // use up a sequence number, and the answer names the message this
        // signed statement already became.
        if let Some(existing) = state.nonces.get(&(OPERATOR_ACCOUNT, nonce)) {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "the operator already published nonce {}, and it is feed message {}. The \
                     same signed message cannot become a second one; if this is a retry, that \
                     message is the one you signed, and if you meant to publish another one, \
                     sign it with a fresh nonce",
                    nonce_text, existing
                ),
            ));
        }
        let id = state.next_id;
        state.next_id += 1;
        let msg = req.message(id, state.clock.now_ms());
        info!("Received operator message: {:?}", msg);
        state
            .publish(msg)
            .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e))?;
        Ok(SubmitResponse {
            id,
            receipt: state.signed_head(),
        })
    })
    .await?
    .map(Json)
}

/// One market on `/symbols`: its name and the price step it opens with.
///
/// The step is served because `docker/open-the-log.sh` publishes the listings
/// and a shell script cannot read a Rust constant. Before this endpoint carried
/// the step, that script named the step itself, and the two places drifted
/// apart: every market was listed with a step of 0.01, while the middle prices
/// of those markets ran from 10 to 1000. The step is now named in
/// `domain::SYMBOLS` and nowhere else.
#[derive(Serialize)]
struct SymbolEntry {
    symbol: String,
    price_step: f64,
}

/// Answers `GET /symbols` with the list of markets and their steps.
///
/// This is the one read that is not charged against the read budget, and the
/// one that does not need to be: it takes no lock, reads no disk and answers
/// from a constant fixed when the binary is built. Charging it would mean
/// taking the state lock to reach the limiter, which would turn the cheapest
/// endpoint on this sequencer into a way to compete for the lock the generator
/// publishes under, the exact cost the budget exists to limit. If this route
/// ever costs something, it gets a budget at the same time.
async fn get_symbols() -> Response {
    let symbols: Vec<SymbolEntry> = SYMBOLS
        .iter()
        .map(|(symbol, _, price_step)| SymbolEntry {
            symbol: symbol.to_string(),
            price_step: *price_step,
        })
        .collect();
    let mut response = Json(symbols).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(SYMBOLS_CACHE_CONTROL),
    );
    response
}

/// Answers `GET /metrics` with what this sequencer has served, in Prometheus
/// text exposition format. The format is written by hand, because a client
/// library would be a thirteenth dependency for forty numbers.
///
/// # Public on purpose
///
/// Everything here is either already public or says nothing. The head id is
/// what `/head` answers with; the window size is `MESSAGE_WINDOW` unless the
/// sequencer is younger than that; the uptime is visible to anyone who watches
/// the sequencer for a day. The one new thing is the traffic volume: how many
/// people read this exchange and how much they read. This exchange argues that
/// outsiders can check it, so refusing to say how many outsiders do would be an
/// odd place to start keeping secrets, and the alternative is a credential this
/// project has nowhere to keep.
///
/// # A small request cannot pull a large answer
///
/// Two things stop that. The series are a fixed list: no label is ever taken
/// from a request, so nobody can make this response longer by asking for
/// `/aaaa1`, `/aaaa2`, which holds it near three kilobytes forever. And it is
/// charged `METRICS_COST` against the same read budget as everything else, so
/// one address cannot repeat it faster than fifty times a second.
async fn get_metrics(
    State(state): State<Arc<Mutex<FeedState>>>,
    caller: Caller,
) -> Result<Response, (StatusCode, String)> {
    charged(&state, caller, METRICS_COST, |read| {
        let Read { state, metrics, .. } = read;
        let body = render_metrics(&metrics, state.last_id(), state.messages.len() as u64);
        let mut response = body.into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(METRICS_CONTENT_TYPE),
        );
        // The body is a copy of counters that moved while the body was being
        // written. It must not be cached, not even for one second.
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(OPEN_CACHE_CONTROL),
        );
        Ok(response)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::{ConnectInfo, Request};
    use axum::http::Method;
    use ed25519_dalek::SigningKey;
    use std::time::Duration;
    use tower::ServiceExt;

    const WALL: u64 = 1_700_000_000_000;

    /// The address every request in these tests arrives from. It is not the
    /// loopback address: `charge_read` lets the loopback through so a local
    /// operator is never refused, and a test on that address would prove
    /// nothing.
    const CALLER: &str = "203.0.113.9:41000";

    /// Spends the whole budget the route's charge names.
    ///
    /// The read budget is spent at a time one hour ahead. A budget refills from
    /// the last charge and never goes backwards, so it stays empty for the rest
    /// of the test. The test therefore does not race the 5,000 tokens a second
    /// the caller earns back.
    fn spend(state: &Arc<Mutex<FeedState>>, ip: IpAddr, charge: Charge) {
        let mut held = lock(state);
        match charge {
            Charge::Submission => {
                for _ in 0..SUBMIT_BURST {
                    assert!(held.limiter.allow(ip, Instant::now()), "the burst itself");
                }
            }
            // Every other route is charged against the read budget, and a route
            // that charges nothing still has to answer after that budget is
            // gone. That is what makes it free, and not only cheap.
            Charge::Read | Charge::Page | Charge::Metrics | Charge::Free => {
                held.charge_read(ip, READ_BURST, Instant::now() + Duration::from_secs(3600))
                    .expect("a caller starts with the whole burst");
            }
        }
    }

    /// The session the bodies below are signed for. These tests drive the
    /// router and never reach the session check, which needs a sequencer's
    /// state; `feed.rs` covers that check.
    const TEST_SESSION: &str = "349d462ced25bb2b";

    /// A signed `POST /order` body, as a real caller sends one.
    fn order_body(key: &SigningKey) -> Body {
        let nonce = inbox::new_nonce();
        let submission = Submission::Order {
            account: 1000,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            price: 100.25,
            quantity: 5.0,
            nonce: Some(nonce.clone()),
            session: Some(TEST_SESSION.to_string()),
            order_type: OrderType::Limit,
            time_in_force: TimeInForce::GoodTillCancel,
            post_only: false,
        };
        let signed =
            inbox::sign_submission(key, &submission).expect("these terms have a statement");
        Body::from(
            serde_json::json!({
                "account": 1000,
                "symbol": "ETH-USDC",
                "side": "Buy",
                "price": 100.25,
                "quantity": 5.0,
                "nonce": nonce,
                "session": TEST_SESSION,
                "public_key": signed.public_key,
                "signature": signed.signature,
            })
            .to_string(),
        )
    }

    /// A signed `POST /cancel` body.
    fn cancel_body(key: &SigningKey) -> Body {
        let nonce = inbox::new_nonce();
        let submission = Submission::Cancel {
            account: 1000,
            target_id: 1,
            nonce: Some(nonce.clone()),
            session: Some(TEST_SESSION.to_string()),
        };
        let signed =
            inbox::sign_submission(key, &submission).expect("these terms have a statement");
        Body::from(
            serde_json::json!({
                "account": 1000,
                "target_id": 1,
                "nonce": nonce,
                "session": TEST_SESSION,
                "public_key": signed.public_key,
                "signature": signed.signature,
            })
            .to_string(),
        )
    }

    /// A `POST /operator` body signed for this session. The statement covers
    /// the session, so a body signed for another log does not verify here, and
    /// would never reach the limiter.
    fn operator_body(key: &SigningKey, session: &str) -> Body {
        let nonce = inbox::new_nonce();
        let message = operator::signed_as(
            key,
            session,
            OrderMessage::EngineRule {
                id: 0,
                timestamp: 0,
                account: OPERATOR_ACCOUNT,
                version: 2,
                nonce: Some(nonce.clone()),
                public_key: String::new(),
                signature: String::new(),
            },
        );
        let OrderMessage::EngineRule {
            public_key,
            signature,
            ..
        } = message
        else {
            unreachable!("signing keeps the kind it was given")
        };
        Body::from(
            serde_json::json!({
                "kind": "EngineRule",
                "version": 2,
                "nonce": nonce,
                "public_key": public_key,
                "signature": signature,
            })
            .to_string(),
        )
    }

    /// One request that reaches the handler behind `path`.
    ///
    /// Every part of the request has to be right. A request refused earlier,
    /// for a missing query parameter or for an unsigned body, never reaches
    /// the charge, and would pass this test for the wrong reason.
    fn request(path: &str, key: &SigningKey, session: &str) -> Request<Body> {
        let (method, uri, body) = match path {
            "/orders" | "/messages.ndjson" | "/head" | "/sth" | "/symbols" | "/metrics" => {
                (Method::GET, path.to_string(), Body::empty())
            }
            "/proof/inclusion" => (
                Method::GET,
                "/proof/inclusion?leaf=0&tree_size=1".to_string(),
                Body::empty(),
            ),
            "/proof/consistency" => (
                Method::GET,
                "/proof/consistency?first=1&second=2".to_string(),
                Body::empty(),
            ),
            "/tree/nodes" => (
                Method::GET,
                "/tree/nodes?from=0&count=1".to_string(),
                Body::empty(),
            ),
            "/order" => (Method::POST, path.to_string(), order_body(key)),
            "/cancel" => (Method::POST, path.to_string(), cancel_body(key)),
            "/operator" => (Method::POST, path.to_string(), operator_body(key, session)),
            other => panic!(
                "the router mounts {} and this test cannot call it. Add a request for it here, so \
                 what it charges is checked and not assumed",
                other
            ),
        };
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .body(body)
            .expect("a request");
        request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
            CALLER.parse().expect("a socket address"),
        ));
        request
    }

    /// Every route this sequencer mounts charges for itself.
    ///
    /// One sequencer is built for each route, with the budget that route names
    /// already spent, so the status says whether the route asked the limiter at
    /// all. A route that asked nothing answers 200 and fails here.
    ///
    /// What this test catches: a new route mounted without the charge, and a
    /// charge that stops working. `Mounted::add` records what it mounts, so the
    /// walk cannot miss a route, and a route with no request above stops the
    /// test and names itself rather than passing quietly.
    ///
    /// What this test does not catch: the wrong cost. A page charged the flat
    /// request cost and no reservation still refuses an empty budget, so it
    /// still passes here. The test also says nothing about a route added to the
    /// finished `Router` outside `mount`.
    #[tokio::test]
    async fn every_route_this_sequencer_mounts_charges_for_itself() {
        let operator = logchain::ephemeral_key();
        let trader = logchain::ephemeral_key();
        let ip: IpAddr = "203.0.113.9".parse().expect("an address");

        for (path, charge) in mount(Some(operator.verifying_key())).routes {
            let state = Arc::new(Mutex::new(FeedState::new(4, WALL)));
            let session = {
                let mut held = lock(&state);
                held.operator_key = Some(operator.verifying_key());
                held.session.clone()
            };
            spend(&state, ip, charge);
            let key = if path == OPERATOR_PATH {
                &operator
            } else {
                &trader
            };
            let answer = feed_router(
                Arc::clone(&state),
                Vec::new(),
                Some(operator.verifying_key()),
            )
            .oneshot(request(path, key, &session))
            .await
            .expect("the router answers");
            let expected = match charge {
                Charge::Free => StatusCode::OK,
                _ => StatusCode::TOO_MANY_REQUESTS,
            };
            assert_eq!(answer.status(), expected, "{} charges {:?}", path, charge);
        }
    }
}
