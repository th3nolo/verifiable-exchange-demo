//! Response headers shared by the three public HTTP services.
//!
//! The reverse proxy sets the same policy. Keeping it here too means a missing
//! proxy label cannot silently remove the browser boundary from a service that
//! is otherwise healthy.

use axum::{
    Router,
    extract::Request,
    http::{HeaderMap, HeaderName, HeaderValue, header},
    middleware::Next,
    response::Response,
};
use std::collections::BTreeSet;

const HSTS: HeaderName = HeaderName::from_static("strict-transport-security");
const CSP: HeaderName = HeaderName::from_static("content-security-policy");
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
const X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
const PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");

#[derive(Clone)]
pub(crate) struct SecurityHeaders {
    csp: HeaderValue,
}

/// A strict policy for the matcher page.
///
/// `connect_urls` are reduced to origins. Paths, credentials and fragments do
/// not enter the header. Only HTTP and HTTPS are useful to `fetch` here.
pub(crate) fn browser(connect_urls: &[String]) -> SecurityHeaders {
    let mut origins = BTreeSet::from(["'self'".to_string()]);
    for raw in connect_urls {
        let Ok(url) = reqwest::Url::parse(raw) else {
            continue;
        };
        if matches!(url.scheme(), "http" | "https") {
            origins.insert(url.origin().ascii_serialization());
        }
    }
    let value = format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src {}; \
         img-src 'self' data:; base-uri 'none'; form-action 'none'; \
         object-src 'none'; frame-ancestors 'none'",
        origins.into_iter().collect::<Vec<_>>().join(" ")
    );
    SecurityHeaders {
        csp: HeaderValue::from_str(&value).expect("URL origins make a valid CSP header"),
    }
}

/// A JSON service loads no browser resource and needs no source allowlist.
pub(crate) fn api() -> SecurityHeaders {
    SecurityHeaders {
        csp: HeaderValue::from_static(
            "default-src 'none'; base-uri 'none'; form-action 'none'; \
             object-src 'none'; frame-ancestors 'none'",
        ),
    }
}

/// Applies the policy to every response, including extractor failures and 404s.
pub(crate) fn guard(router: Router, policy: SecurityHeaders) -> Router {
    router.layer(axum::middleware::from_fn(move |request, next| {
        let policy = policy.clone();
        async move { add_headers(policy, request, next).await }
    }))
}

async fn add_headers(policy: SecurityHeaders, request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    insert(headers, HSTS, "max-age=63072000; includeSubDomains");
    headers.insert(CSP, policy.csp);
    insert(headers, X_CONTENT_TYPE_OPTIONS, "nosniff");
    insert(headers, X_FRAME_OPTIONS, "DENY");
    insert(headers, REFERRER_POLICY, "no-referrer");
    insert(
        headers,
        PERMISSIONS_POLICY,
        "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    );
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

fn insert(headers: &mut HeaderMap, name: HeaderName, value: &'static str) {
    headers.insert(name, HeaderValue::from_static(value));
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request as HttpRequest, routing::get};
    use tower::ServiceExt;

    #[tokio::test]
    async fn the_browser_policy_has_no_inline_script_or_style_escape() {
        let router = guard(
            Router::new().route("/", get(|| async { "page" })),
            browser(&[
                "https://feed.example.test/order".to_string(),
                "https://feed.example.test/other".to_string(),
            ]),
        );
        let response = router
            .oneshot(HttpRequest::new(Body::empty()))
            .await
            .expect("the router answers");
        let headers = response.headers();
        let csp = headers.get(CSP).unwrap().to_str().unwrap();
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("style-src 'self'"));
        assert!(csp.contains("https://feed.example.test"));
        assert_eq!(csp.matches("https://feed.example.test").count(), 1);
        assert!(!csp.contains("unsafe-inline"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert_eq!(headers.get(X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    }

    #[tokio::test]
    async fn an_explicit_cache_policy_is_not_overwritten() {
        let router = guard(
            Router::new().route(
                "/proof",
                get(|| async { ([(header::CACHE_CONTROL, "public, immutable")], "proof") }),
            ),
            api(),
        );
        let response = router
            .oneshot(
                HttpRequest::builder()
                    .uri("/proof")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("the router answers");
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, immutable"
        );
        assert_eq!(
            response.headers().get(X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
    }
}
