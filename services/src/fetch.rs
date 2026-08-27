//! The HTTP code the checker, the audit, the sequencer and the binary share.
//!
//! This module says how to read a body of a bounded size over HTTP. It holds
//! the timeouts a request runs under, the client that carries it, the sentence
//! an error turns into, and the size cap a body is read against. It holds no
//! rule about what the body means.
//!
//! The independence this repository keeps is between the engine and the
//! checker, over matching rules, and none of that is here. A second copy of
//! this code would catch nothing either. A body this module cut short hashes
//! again to a chain that does not match the signed head, so the checker and
//! the audit both fail on it and say so, instead of agreeing on a wrong
//! answer. ENGINE.md section 5 lists what the checker may import.

use std::time::Duration;

/// How long to wait for a service to answer at all. A service that is not
/// listening must end the run with a message, not hang it forever.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one request may take in total, body included. One page, not a
/// whole history, so this does not have to be generous.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The most bytes one page of anything may occupy.
///
/// `/messages.ndjson` answers with at most `feed::PAGE_LIMIT` messages, which
/// is under 200 KB, so anything past this cap is not a page. `read_bounded`
/// measures the body while it arrives, and not after the whole body is in
/// memory. A body refused after it is in memory has already cost the memory it
/// was refused for.
pub const MAX_PAGE_BYTES: usize = 16 * 1024 * 1024;

/// The client the checker and the audit fetch with. One client is built and
/// reused. A history is read one page per request, and a fresh client per page
/// would open a fresh connection for every thousand messages. The timeouts are
/// why this function exists: a service that stops answering ends the run with
/// a message instead of hanging it.
pub fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| format!("cannot build an HTTP client: {}", e))
}

/// Why an HTTP call failed, in the words of the thing that actually failed.
///
/// `reqwest::Error`'s own `Display` says only "error sending request for url
/// (...)", and it leaves the reason in `source()`, one or two levels down. The
/// reason is the part the caller acts on. "Connection refused" means the
/// service is not running at that address. "Name or service not known" means
/// the address is wrong. So this function walks the chain to its end and
/// returns the deepest cause.
pub fn reason(error: &(dyn std::error::Error + 'static)) -> String {
    let mut deepest = error;
    while let Some(cause) = deepest.source() {
        deepest = cause;
    }
    deepest.to_string()
}

/// Reads a response body, refusing one larger than `max`.
///
/// `content_length` is checked first because it costs nothing and refuses
/// before a single byte of the body is read. The body is then read in chunks
/// against a running total, because a chunked response sends no length at all
/// and the header alone would bound nothing.
///
/// `max` is a parameter and not a constant here. The checker and the audit
/// read pages of `MAX_PAGE_BYTES`, and the sequencer reads the separate
/// service against its own smaller cap.
///
/// `what` names the thing being read, so a caller that does not add context
/// of its own still says which fetch failed.
pub async fn read_bounded(
    mut response: reqwest::Response,
    what: &str,
    max: usize,
) -> Result<Vec<u8>, String> {
    if let Some(length) = response.content_length()
        && length > max as u64
    {
        return Err(format!(
            "{} offers {} bytes, more than the {} bytes read at once",
            what, length, max
        ));
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("cannot read {}: {}", what, e))?
    {
        if body.len() + chunk.len() > max {
            return Err(format!(
                "{} sent more than {} bytes for one page, which is not a page",
                what, max
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Answers one request with exactly `raw`, then holds the connection open
    /// for a while. It is written against a socket and not a router, because
    /// the thing under test is the shape of the response: chunked, or a
    /// `Content-Length` that is never satisfied. A router picks that shape
    /// itself.
    async fn serve_raw(raw: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
        let address = format!("http://{}", listener.local_addr().expect("an address"));
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("a connection");
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await;
            let _ = socket.write_all(&raw).await;
            let _ = socket.flush().await;
            // Held open, so a body that never arrives stays a body that never
            // arrives instead of becoming a closed connection.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        address
    }

    /// A chunked response carries no length, so the cap has to hold while the
    /// body arrives. The refusal names the cap, because the number is what
    /// tells an operator whether the cap is wrong or the server is.
    #[tokio::test]
    async fn a_body_over_the_cap_is_refused_and_the_refusal_names_the_size() {
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..4 {
            raw.extend_from_slice(b"3e8\r\n");
            raw.extend_from_slice(&[b'x'; 1000]);
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"0\r\n\r\n");
        let address = serve_raw(raw).await;

        let client = client().expect("a client");
        let response = client.get(&address).send().await.expect("an answer");
        assert_eq!(
            response.content_length(),
            None,
            "a chunked response has no length to check, which is why the loop has to count"
        );
        let refusal = read_bounded(response, "a page of feed history", 2000)
            .await
            .expect_err("4000 bytes is more than the 2000 asked for");
        assert!(
            refusal.contains("2000"),
            "the refusal has to name the cap: {}",
            refusal
        );
        assert!(
            refusal.contains("sent more than"),
            "and has to say the body went past it: {}",
            refusal
        );
    }

    /// A response that announces a length over the cap is refused on the
    /// header, before any of the body is read. The server here sends the
    /// header and then nothing at all. A reader that started on the body would
    /// wait for bytes that never come.
    #[tokio::test]
    async fn an_announced_length_over_the_cap_is_refused_before_the_body_is_read() {
        let address =
            serve_raw(b"HTTP/1.1 200 OK\r\nContent-Length: 5000000\r\n\r\n".to_vec()).await;

        let client = client().expect("a client");
        let response = client.get(&address).send().await.expect("an answer");
        assert_eq!(
            response.content_length(),
            Some(5_000_000),
            "the announced length is what the check reads"
        );
        let refusal = tokio::time::timeout(
            Duration::from_secs(2),
            read_bounded(response, "the inbox's pending entries", 1024),
        )
        .await
        .expect("the check answers on the header, so it cannot wait for the body")
        .expect_err("5000000 bytes is more than the 1024 asked for");
        assert!(
            refusal.contains("5000000") && refusal.contains("1024"),
            "the refusal has to name what was offered and what is allowed: {}",
            refusal
        );
        assert!(
            refusal.contains("offers"),
            "and has to be the refusal made before reading: {}",
            refusal
        );
    }
}
