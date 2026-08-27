//! Cross-origin submissions, for the two services a browser posts to.
//!
//! An origin is a scheme, a host and a port together, such as
//! `http://127.0.0.1:3001`. A request is cross-origin when the page's origin
//! is not the origin it posts to. A preflight is the `OPTIONS` request a
//! browser sends first, to ask whether the real request is allowed.
//!
//! The sequencer's `POST /order` and `POST /cancel`, and the separate
//! service's `POST /submit`, all take submissions from the trading UI. The UI
//! is never on their origin. On one machine the exchange serves it on another
//! port, and behind a reverse proxy it comes from another hostname or path. A
//! browser will not send any of those requests until the receiving service
//! says which origins may send them.
//!
//! There is one copy of this rule and not one per service. The rule is the
//! same rule: an exact match against the operator's `--ui-origin`, nothing
//! echoed back, no wildcard, no credentials. The separate service exists so
//! that a user the sequencer is refusing can still submit through a service
//! the sequencer does not control. Two copies of a list parser are two things
//! that can drift apart, and a drift that let the separate service accept more
//! origins than the sequencer would open the cross-origin hole this rule
//! closes.
//!
//! Each service names two things for itself: the paths it will answer a
//! preflight for (`CorsPolicy::submission_paths`), and what it calls itself in
//! a refusal (`CorsPolicy::service`). Both live beside the router that grants
//! them, so the grant cannot widen without somebody seeing it when a route is
//! added.

use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tracing::{info, warn};

/// The origins allowed to submit when the operator names none.
///
/// Both spellings of the exchange's own address, because a browser reads them
/// as two different origins. A visitor who types `localhost:3001` and one who
/// types `127.0.0.1:3001` load the same page from the same process. If this
/// constant listed one spelling, only one of the two could trade.
pub const DEFAULT_UI_ORIGINS: &str = "http://127.0.0.1:3001,http://localhost:3001";

/// The methods and headers the preflight grants. `POST`, because that is what
/// the submission endpoints take. `content-type`, because a JSON body is what
/// makes the browser send a preflight at all. Nothing else is named.
/// `Access-Control-Allow-Credentials` is left out on purpose, so a browser
/// never attaches cookies to a submission, and the account key in the
/// signature stays the only thing that speaks for an account.
const ALLOWED_METHODS: &str = "POST";
const ALLOWED_HEADERS: &str = "content-type";
/// How long a browser may cache one preflight. Ten minutes is long enough that
/// a visitor placing orders does not pay for an extra round trip before each
/// one, and short enough that an operator who changes `--ui-origin` sees the
/// change take effect.
const PREFLIGHT_MAX_AGE: &str = "600";

/// The response headers a cross-origin page is allowed to read.
///
/// Without this header a browser hands JavaScript only the few headers the
/// CORS standard allows by default. `x-feed-session` and the rest of the
/// signed head then read back as `null`, even though the body arrives whole.
/// That is not a cosmetic limit. The UI is served from one hostname and the
/// sequencer from another, so these five headers are the only way a page can
/// check the sequencer's *own signature* over its head. Without them the page
/// can only fall back to the exchange's copy of the same values, which is the
/// operator reporting on the operator, and that is the one thing this project
/// exists to avoid.
///
/// Naming them gives nothing away. Every one of these values is already in the
/// body of a public endpoint.
const EXPOSED_HEADERS: &str =
    "x-feed-session, x-feed-last-id, x-feed-chain, x-feed-pubkey, x-feed-signature";

/// Reads one `--ui-origin` value into the exact string a browser will send in
/// its `Origin` header, or says why it is not an origin.
///
/// The comparison later is a byte-for-byte match against this string, and
/// nothing is echoed back. An origin that is not on the list is never returned
/// to its sender. That is the whole reason the value is checked here. A
/// wildcard is refused and not supported, because these are public submission
/// endpoints. The flag exists so an operator can name where their UI is served
/// from, and not so they can turn the check off.
///
/// A trailing slash is accepted and dropped, because that is how an operator
/// pastes a URL out of a browser bar. Anything with a path is refused, because
/// an origin has no path, and accepting one would match nothing without saying
/// so.
pub fn parse_ui_origin(spec: &str) -> Result<String, String> {
    let spec = spec.trim().trim_end_matches('/');
    if spec.is_empty() {
        return Err(
            "an empty --ui-origin names nothing. Pass the whole flag as an empty string \
             (--ui-origin '') to allow no browser at all"
                .to_string(),
        );
    }
    if spec.contains('*') {
        return Err(format!(
            "--ui-origin {} is a wildcard. These endpoints take submissions from the public \
             internet, so they answer a named origin or none; name the address the UI is served \
             from, for example {}",
            spec, DEFAULT_UI_ORIGINS
        ));
    }
    let Some((scheme, authority)) = spec.split_once("://") else {
        return Err(format!(
            "--ui-origin {} has no scheme: an origin is scheme://host[:port], for example \
             https://exchange.example.com",
            spec
        ));
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(format!(
            "--ui-origin {} is not http or https, and a browser will not send {} in an Origin \
             header these services could match",
            spec, scheme
        ));
    }
    if authority.is_empty() || authority.contains(['/', '?', '#', '@', ' ']) {
        return Err(format!(
            "--ui-origin {} is not an origin: an origin is scheme://host[:port] with no path, \
             no query and no credentials",
            spec
        ));
    }
    // A browser lowercases the scheme and host before it sends them, and keeps
    // the port as digits, so this is the exact string that will arrive.
    Ok(format!("{}://{}", scheme, authority.to_ascii_lowercase()))
}

/// Reads every `--ui-origin` value, and refuses the whole list if one of them
/// is not an origin. The service refuses to start rather than skipping the bad
/// entry. An operator who mistyped the address of their own UI would otherwise
/// learn it from a visitor whose order the browser refused to send.
///
/// `--ui-origin ''` is the one way to say "no browser at all", and it arrives
/// here as a single empty string, so an entry that is empty after trimming is
/// dropped rather than refused. Everything else has to be an origin.
pub fn parse_ui_origins(specs: &[String]) -> Result<Vec<String>, String> {
    specs
        .iter()
        .filter(|spec| !spec.trim().is_empty())
        .map(|spec| parse_ui_origin(spec))
        .collect()
}

/// One service's cross-origin rules: who may submit, where, and what to call
/// this service when refusing.
pub(crate) struct CorsPolicy {
    /// The operator's `--ui-origin` list, already parsed into the exact
    /// strings a browser will send.
    allowed: Vec<String>,
    /// The paths a browser is allowed to preflight: only the ones that take
    /// submissions. A preflight for anything else is answered with a refusal,
    /// so the grant cannot quietly widen when a route is added.
    submission_paths: &'static [&'static str],
    /// What this service calls itself in a refused preflight, so an operator
    /// reading the message knows which process to fix.
    service: &'static str,
}

impl CorsPolicy {
    pub(crate) fn new(
        allowed: Vec<String>,
        submission_paths: &'static [&'static str],
        service: &'static str,
    ) -> Self {
        CorsPolicy {
            allowed,
            submission_paths,
            service,
        }
    }
}

/// What the cross-origin rules say about one request.
///
/// The decision is taken apart from the response it produces. So the rule can
/// be tested without a server, and the code below stays small enough to read
/// on one screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cors {
    /// No `Origin` header, so no browser is asking for another page. The CLI,
    /// the bot, the sequencer's own drain and `curl` all land here, and
    /// nothing about their requests or answers changes.
    NotBrowser,
    /// A preflight for a submission from an origin on the list.
    PreflightAllowed,
    /// A preflight this service will not answer: an origin that is not on the
    /// list, or a path that takes no submissions.
    PreflightRefused,
    /// An ordinary request from an origin on the list. It runs, and the
    /// browser is allowed to read the answer.
    Allowed,
    /// An ordinary request from an origin that is not on the list. The request
    /// runs exactly as it always did, and the browser hides the answer.
    /// `Origin` does not prove who is calling, and nothing here treats it as
    /// though it did.
    Refused,
}

/// Decides what to do with one request, given the service's policy.
pub(crate) fn cors_for(
    policy: &CorsPolicy,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
) -> (Option<String>, Cors) {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
    else {
        return (None, Cors::NotBrowser);
    };
    let permitted = policy.allowed.iter().any(|listed| listed == &origin);
    // A preflight is an OPTIONS request carrying the method it asks about. An
    // OPTIONS without that header is not a preflight, so it is treated as an
    // ordinary request, which is what it is.
    if method == Method::OPTIONS && headers.contains_key(header::ACCESS_CONTROL_REQUEST_METHOD) {
        let decision = if permitted && policy.submission_paths.contains(&path) {
            Cors::PreflightAllowed
        } else {
            Cors::PreflightRefused
        };
        return (Some(origin), decision);
    }
    let decision = if permitted {
        Cors::Allowed
    } else {
        Cors::Refused
    };
    (Some(origin), decision)
}

/// Answers a preflight, or lets the request through and marks the answer
/// readable when the origin is one the operator named.
///
/// Only three things happen here. A request with no `Origin` passes through
/// untouched. A preflight is answered here and never reaches a handler. Every
/// other request runs exactly as it did before, and gains
/// `Access-Control-Allow-Origin` only when its origin is on the list.
///
/// Nothing is echoed back. The header carries the matching entry from the
/// operator's own list, so an origin the operator did not name cannot be sent
/// back to itself. There is no `Access-Control-Allow-Credentials` and no
/// wildcard.
async fn cors(policy: Arc<CorsPolicy>, req: Request, next: Next) -> Response {
    let (origin, decision) = cors_for(&policy, req.method(), req.uri().path(), req.headers());
    let Some(origin) = origin else {
        // No `Origin` header, and the answer still depends on that. A request
        // that sent an allowed origin gets `Access-Control-Allow-Origin` and
        // this one does not, so the two answers are different and a shared
        // cache has to key on the header to tell them apart.
        //
        // Without this line, a cache can store the copy made for a caller that
        // sent no origin, and hand that copy to a browser. Those callers are
        // `curl`, an audit, a health check. The body is right and the CORS
        // header is missing, so the browser refuses an answer from a sequencer
        // that is working. The UI shows that as the sequencer being
        // unreachable.
        //
        // It matters here and not in most middleware, because closed pages are
        // served `public, immutable`. Those answers really are stored, by
        // browsers and by anything between them and this process.
        let mut response = next.run(req).await;
        response
            .headers_mut()
            .append(header::VARY, HeaderValue::from_static("origin"));
        return response;
    };
    if let Cors::PreflightAllowed | Cors::PreflightRefused = decision {
        let allow = decision == Cors::PreflightAllowed;
        // A refused preflight says which origin was refused and which flag
        // decides it. The browser shows the caller only "CORS error", so
        // without this body the operator who mistyped `--ui-origin` has
        // nothing at all to read. The answer is not secret: whoever sent the
        // request already knows the origin they sent it from.
        let body = if allow {
            String::new()
        } else {
            format!(
                "origin {} may not submit to this {}. The operator lists the origins the UI is \
                 served from with --ui-origin; this {} allows: {}\n",
                origin,
                policy.service,
                policy.service,
                if policy.allowed.is_empty() {
                    "(none)".to_string()
                } else {
                    policy.allowed.join(", ")
                }
            )
        };
        let status = if allow {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::FORBIDDEN
        };
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = status;
        let headers = response.headers_mut();
        // Sent whether or not the preflight is granted. The answer depends on
        // the origin either way, and a cache that did not know that would hand
        // one origin's answer to another.
        headers.append(header::VARY, HeaderValue::from_static("origin"));
        if allow {
            if let Ok(value) = HeaderValue::from_str(&origin) {
                headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
            }
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static(ALLOWED_METHODS),
            );
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static(ALLOWED_HEADERS),
            );
            headers.insert(
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from_static(PREFLIGHT_MAX_AGE),
            );
        } else {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
        }
        return response;
    }
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.append(header::VARY, HeaderValue::from_static("origin"));
    if decision == Cors::Allowed {
        if let Ok(value) = HeaderValue::from_str(&origin) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        }
        headers.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static(EXPOSED_HEADERS),
        );
    }
    response
}

/// Says which browsers a service will accept submissions from, at startup.
///
/// The empty list is a warning and not an info line. The service starts either
/// way, and it still serves every caller that sends no `Origin` header. So an
/// operator who allowed nobody by accident would otherwise learn it from a
/// visitor whose browser refused to send an order.
pub fn log_ui_origins(service: &str, origins: &[String]) {
    match origins.len() {
        0 => warn!(
            "no --ui-origin: no browser can submit to this {}, because a page served from any \
             origin at all is cross-origin to it. Callers that send no Origin header are \
             unaffected: the CLI, the bot, the feed's own drain",
            service
        ),
        _ => info!(
            "this {} accepts browser submissions from: {}",
            service,
            origins.join(", ")
        ),
    }
}

/// Puts one service's routes behind its cross-origin rules.
///
/// It is applied as the outermost layer, after `with_state`, so a preflight is
/// answered before any handler, any extractor and any rate limiter sees it. A
/// preflight carries no body and no signature, and counting it against a
/// submission budget would let a browser lock its own visitor out.
pub(crate) fn guard(router: Router, policy: CorsPolicy) -> Router {
    let policy = Arc::new(policy);
    router.layer(axum::middleware::from_fn(move |req, next| {
        let policy = Arc::clone(&policy);
        async move { cors(policy, req, next).await }
    }))
}

/// The helpers the two services' own router tests share. Each service states
/// what it grants under these rules in its own module, and both need the same
/// default list and the same way to build request headers.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// The default list, as the CLI hands it over.
    pub(crate) fn default_origins() -> Vec<String> {
        parse_ui_origins(
            &DEFAULT_UI_ORIGINS
                .split(',')
                .map(str::to_string)
                .collect::<Vec<_>>(),
        )
        .expect("the default has to parse, or neither service can start")
    }

    pub(crate) fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }
}

#[cfg(test)]
mod tests {
    use super::testing::default_origins;
    use super::*;

    #[test]
    fn an_origin_is_read_as_a_browser_will_send_it() {
        // Case and a pasted trailing slash are the two ways an operator writes
        // the same origin, and a browser sends only one of them.
        assert_eq!(
            parse_ui_origin("HTTPS://Exchange.Example.COM/").unwrap(),
            "https://exchange.example.com"
        );
        assert_eq!(
            parse_ui_origin(" http://127.0.0.1:3001 ").unwrap(),
            "http://127.0.0.1:3001"
        );
    }

    #[test]
    fn what_is_not_an_origin_stops_the_service_starting() {
        // A wildcard is what an operator reaches for when the real origin is
        // inconvenient, and it is the one that must not work. These endpoints
        // take submissions from the public internet.
        for bad in [
            "*",
            "https://*.example.com",
            "",
            "exchange.example.com",
            "ftp://exchange.example.com",
            "https://exchange.example.com/ui",
            concat!("https://user:pass", "@exchange.example.com"),
        ] {
            assert!(
                parse_ui_origin(bad).is_err(),
                "{} is not an origin and must be refused at startup",
                bad
            );
        }
        // One bad entry refuses the whole list rather than being skipped.
        assert!(
            parse_ui_origins(&["http://127.0.0.1:3001".into(), "*".into()]).is_err(),
            "a list with a wildcard in it must not start a service that allows the rest"
        );
        // `--ui-origin ''` is how an operator says "no browser at all", and it
        // arrives as one empty string. It must allow nobody, not fail to start
        // and not allow everybody.
        assert_eq!(parse_ui_origins(&["".into()]), Ok(Vec::new()));
        assert_eq!(parse_ui_origins(&[]), Ok(Vec::new()));
    }

    /// The refusal names the origin and the flag, and says which of the two
    /// services refused. The operator has to know which process to fix, and a
    /// browser shows them only "CORS error".
    #[tokio::test]
    async fn a_refused_preflight_names_the_origin_the_flag_and_the_service() {
        use axum::routing::post;
        use tower::ServiceExt;

        for service in ["feed", "inbox"] {
            let router = guard(
                Router::new().route("/submit", post(|| async { "" })),
                CorsPolicy::new(default_origins(), &["/submit"], service),
            );
            let response = router
                .oneshot(
                    Request::builder()
                        .method(Method::OPTIONS)
                        .uri("/submit")
                        .header("origin", "https://evil.example")
                        .header("access-control-request-method", "POST")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("the router answers");
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .expect("a short refusal");
            let text = String::from_utf8_lossy(&body);
            assert!(text.contains("https://evil.example"), "{}", text);
            assert!(text.contains("--ui-origin"), "{}", text);
            assert!(text.contains(service), "{}", text);
        }
    }

    /// The signed head has to survive the trip to a page on another hostname.
    ///
    /// This is worth a test of its own, because nothing except a browser can
    /// see it break. `curl` prints `x-feed-session` whether or not this header
    /// is sent. Only a cross-origin page is denied the value, and it is denied
    /// without a word: `headers.get(...)` returns `null`, the body is whole,
    /// and there is no error anywhere. The UI then has no way to check the
    /// sequencer's signature over its own head, and it has to believe the
    /// exchange instead.
    #[tokio::test]
    async fn a_page_on_another_hostname_can_read_the_signed_head() {
        use axum::routing::get;
        use tower::ServiceExt;

        let router = guard(
            Router::new().route("/orders", get(|| async { "" })),
            CorsPolicy::new(default_origins(), &["/submit"], "feed"),
        );
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/orders")
                    .header("origin", "http://127.0.0.1:3001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("the router answers");

        let exposed = response
            .headers()
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .expect("an allowed origin is told which headers it may read")
            .to_str()
            .expect("ascii");
        for name in [
            crate::wire::SESSION_HEADER,
            crate::wire::HEAD_LAST_ID_HEADER,
            crate::wire::HEAD_CHAIN_HEADER,
            crate::wire::HEAD_PUBKEY_HEADER,
            crate::wire::HEAD_SIGNATURE_HEADER,
        ] {
            assert!(
                exposed.contains(name),
                "{} is part of the signed head and a browser cannot read it: {}",
                name,
                exposed
            );
        }
    }

    /// A cacheable answer says it depends on `Origin`, whichever kind of
    /// caller asked for it.
    ///
    /// The failure needs a shared cache to show itself, which is why it gets a
    /// test and not a comment. `curl` and an audit send no `Origin` and get an
    /// answer with no `Access-Control-Allow-Origin`. A browser sends one and
    /// gets the header back. That is two different answers at one URL. Without
    /// `Vary` on both, a cache can store the first and serve it to the second.
    /// The browser then refuses an answer from a sequencer that is working,
    /// and the UI reports that as the sequencer being unreachable.
    ///
    /// It became possible when the sequencer started serving closed pages as
    /// `public, immutable`, so those answers really are stored.
    #[tokio::test]
    async fn an_answer_varies_on_origin_even_when_none_was_sent() {
        use axum::routing::get;
        use tower::ServiceExt;

        for origin in [Some("http://127.0.0.1:3001"), None] {
            let router = guard(
                Router::new().route("/orders", get(|| async { "" })),
                CorsPolicy::new(default_origins(), &["/submit"], "feed"),
            );
            let mut request = Request::builder().uri("/orders");
            if let Some(value) = origin {
                request = request.header("origin", value);
            }
            let response = router
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .expect("the router answers");

            let varies = response
                .headers()
                .get_all(header::VARY)
                .iter()
                .any(|value| value.to_str().is_ok_and(|v| v.contains("origin")));
            assert!(
                varies,
                "a request with origin {:?} got an answer that does not say it varies on Origin",
                origin
            );
        }
    }

    /// An origin that was refused is told nothing, including this.
    #[tokio::test]
    async fn a_refused_origin_is_not_told_what_it_may_read() {
        use axum::routing::get;
        use tower::ServiceExt;

        let router = guard(
            Router::new().route("/orders", get(|| async { "" })),
            CorsPolicy::new(default_origins(), &["/submit"], "feed"),
        );
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/orders")
                    .header("origin", "https://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("the router answers");
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
                .is_none()
        );
    }
}
