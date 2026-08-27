package main

// ---------------------------------------------------------------------------
// Reaching the chain when an endpoint is down
// ---------------------------------------------------------------------------
//
// Public testnet endpoints stop answering. On 18 August 2026
// https://sepolia.base.org answered 503 to ten requests out of ten, while
// https://base-sepolia-rpc.publicnode.com answered all ten. This sender had
// that first URL compiled into it as its only endpoint, so for as long as the
// outage lasted it wrote no anchors at all: every tick reached `latest()`,
// got a 503, logged FAILED, and waited five minutes to fail the same way.
//
// The browser reading the anchor already tries each endpoint in turn. This is
// the same behaviour for the program that writes them, put one layer lower so
// that every call gets it: `latest()`, the gas estimate, the send, and the
// receipt poll all travel through this transport without knowing about it.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// The endpoint used when neither the flag nor the deployment record names one.
// It is the endpoint Base documents, kept as the last resort so that a sender
// run with no configuration at all still reaches the right chain.
const defaultRPC = "https://sepolia.base.org"

// How long one endpoint gets to answer one request. Per attempt, not per call:
// a first endpoint that hangs must not spend the time the second one needs.
// Three endpoints therefore bound a call at 60 seconds, against an anchor
// interval of five minutes.
const rpcAttemptTimeout = 20 * time.Second

// failover sends each request to the first endpoint that answers it.
//
// The endpoints are an ordered preference, but once a call moves to a later
// one, later calls start there too. Going back to the front on every call
// would pay the dead endpoint's 20 seconds on every call, which is the cost
// this exists to avoid. A restart is what returns to the front of the list.
type failover struct {
	urls []*url.URL
	next http.RoundTripper
	at   atomic.Int64
	// attempt is how long one endpoint gets. A field so a test can make it
	// short enough to measure without waiting the real 20 seconds.
	attempt time.Duration
	// note is called once per endpoint that fails, so an outage shows up in
	// the log as the reason a call was slow rather than as nothing at all.
	note func(format string, args ...any)
}

func newFailover(endpoints []string, note func(string, ...any)) (*failover, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no RPC endpoint to talk to")
	}
	f := &failover{next: http.DefaultTransport, note: note, attempt: rpcAttemptTimeout}
	for _, raw := range endpoints {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, fmt.Errorf("%q is not an http or https RPC endpoint", raw)
		}
		f.urls = append(f.urls, parsed)
	}
	return f, nil
}

// answering names the endpoint the next call will be sent to first.
func (f *failover) answering() string {
	return f.urls[f.at.Load()].String()
}

// down reports whether a status code means "this endpoint could not answer",
// as opposed to "this endpoint answered, and the answer is a refusal".
//
// Only these three. A 400 is a request this sender built wrong, and every
// endpoint would reject it identically, so trying the rest only makes the
// error message longer. Everything a chain says about a transaction, a revert
// included, arrives as 200 with a JSON-RPC error inside it, and that is an
// answer: failing over on it would send the same doomed call to every
// endpoint in the list.
func down(code int) bool {
	return code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500
}

// bodyCancel releases the per-attempt timeout when the caller is finished
// reading. Cancelling any earlier truncates the response that was asked for.
type bodyCancel struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b bodyCancel) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

func (f *failover) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := replayable(req)
	if err != nil {
		return nil, err
	}

	// Rebroadcasting a transaction is safe, which is what makes retrying a
	// send safe: it is already signed, and it carries a nonce. A second
	// endpoint either accepts the identical transaction or rejects it as one
	// it already knows. Neither outcome writes two anchors.
	start := int(f.at.Load())
	var first error
	for tried := range f.urls {
		at := (start + tried) % len(f.urls)
		endpoint := f.urls[at]

		ctx, cancel := context.WithTimeout(req.Context(), f.attempt)
		out := req.Clone(ctx)
		// A copy: the transport is free to touch the URL it is given, and the
		// one in f.urls is read by every later call.
		target := *endpoint
		out.URL = &target
		out.Host = "" // taken from the new URL
		if body != nil {
			out.Body = io.NopCloser(bytes.NewReader(body))
			out.ContentLength = int64(len(body))
			out.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(body)), nil
			}
		}

		resp, err := f.next.RoundTrip(out)
		switch {
		case err != nil:
			cancel()
			if first == nil {
				first = fmt.Errorf("%s: %w", endpoint.Host, err)
			}
			f.noteFailure(endpoint, err.Error())
		case down(resp.StatusCode):
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			cancel()
			if first == nil {
				first = fmt.Errorf("%s: %s", endpoint.Host, resp.Status)
			}
			f.noteFailure(endpoint, resp.Status)
		default:
			resp.Body = bodyCancel{ReadCloser: resp.Body, cancel: cancel}
			f.at.Store(int64(at))
			return resp, nil
		}
	}
	if len(f.urls) == 1 {
		return nil, first
	}
	return nil, fmt.Errorf("%w (%d endpoints tried, none answered)", first, len(f.urls))
}

func (f *failover) noteFailure(endpoint *url.URL, reason string) {
	if f.note != nil {
		f.note("  RPC %s did not answer: %s", endpoint.Host, reason)
	}
}

// replayable returns the request body, which every attempt needs its own
// reader over. go-ethereum sets GetBody on the requests it makes, so this is
// normally free; reading the body is the path for anything that does not.
func replayable(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	if req.GetBody != nil {
		rc, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	defer req.Body.Close()
	return io.ReadAll(req.Body)
}

// rpcEndpoints decides which endpoints to try, in order.
//
// The flag wins when it is set, because it is how an operator swaps a
// rate-limited public endpoint for a paid one without a rebuild. Otherwise
// the deployment record decides, which is the file that already says which
// chain and which contract, and is therefore the one place where "this
// deployment lives here" is written down once. The built-in default is what
// is left when neither names anything.
func rpcEndpoints(flag string, record deployment) []string {
	if named := split(flag); len(named) > 0 {
		return named
	}
	named := append(split(record.RPC), record.RPCFallbacks...)
	if endpoints := dedupe(named); len(endpoints) > 0 {
		return endpoints
	}
	return []string{defaultRPC}
}

// split reads a comma or whitespace separated list, so that one environment
// variable can carry a primary and its fallbacks.
func split(list string) []string {
	fields := strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	return dedupe(fields)
}

// dedupe keeps the first mention of each endpoint. A record that repeats its
// primary in its fallback list must not make this sender wait for the same
// dead host twice.
func dedupe(items []string) []string {
	seen := make(map[string]bool, len(items))
	kept := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		kept = append(kept, item)
	}
	return kept
}

// endpointHosts names the endpoints in preference order, for the startup log.
// Hosts only: an endpoint URL can carry an API key in its path.
func endpointHosts(f *failover) []string {
	hosts := make([]string, 0, len(f.urls))
	for _, u := range f.urls {
		hosts = append(hosts, u.Host)
	}
	return hosts
}
