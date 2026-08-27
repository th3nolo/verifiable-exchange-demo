package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// ---------------------------------------------------------------------------
// Reaching the chain through more than one endpoint
// ---------------------------------------------------------------------------

// chainIDHex is 84532, Base Sepolia, as an endpoint would answer it.
const chainIDHex = "0x14a34"

// endpoint is a stand-in RPC server that counts what it was asked.
type endpoint struct {
	*httptest.Server
	calls atomic.Int64
}

// answering serves a JSON-RPC result to every request.
func answering(t *testing.T, result string) *endpoint {
	t.Helper()
	return serving(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%q}`, result)
	})
}

// unavailable is an endpoint in the state sepolia.base.org was in on
// 18 August 2026: reachable, and answering 503 to everything.
func unavailable(t *testing.T) *endpoint {
	t.Helper()
	return serving(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	})
}

func serving(t *testing.T, handle http.HandlerFunc) *endpoint {
	t.Helper()
	e := &endpoint{}
	e.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.calls.Add(1)
		handle(w, r)
	}))
	t.Cleanup(e.Close)
	return e
}

// dial builds the client the sender builds, over the endpoints given.
func dial(t *testing.T, urls ...string) (*ethclient.Client, *failover) {
	t.Helper()
	f, err := newFailover(urls, nil)
	if err != nil {
		t.Fatalf("newFailover: %v", err)
	}
	f.attempt = 2 * time.Second
	chain, err := rpc.DialOptions(context.Background(), f.answering(),
		rpc.WithHTTPClient(&http.Client{Transport: f}))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(chain.Close)
	return ethclient.NewClient(chain), f
}

// The outage this was written for: the first endpoint is up and refusing, and
// the call has to reach the chain anyway.
func TestACallReachesTheChainThroughTheEndpointThatAnswers(t *testing.T) {
	down, up := unavailable(t), answering(t, chainIDHex)
	client, _ := dial(t, down.URL, up.URL)

	id, err := client.ChainID(context.Background())
	if err != nil {
		t.Fatalf("the chain id came back as an error: %v", err)
	}
	if id.Int64() != 84532 {
		t.Fatalf("chain id %s, want 84532", id)
	}
	if down.calls.Load() != 1 || up.calls.Load() != 1 {
		t.Fatalf("the call was tried %d times on the endpoint that is down and %d times on "+
			"the one that is up; want one each", down.calls.Load(), up.calls.Load())
	}
}

// Having moved, it stays moved. Starting at the front of the list again would
// pay the dead endpoint's timeout on every anchor for as long as the outage
// lasts, which is the cost this exists to avoid.
func TestTheEndpointThatAnsweredIsWhereTheNextCallStarts(t *testing.T) {
	down, up := unavailable(t), answering(t, chainIDHex)
	client, f := dial(t, down.URL, up.URL)

	for i := 0; i < 3; i++ {
		if _, err := client.ChainID(context.Background()); err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
	}
	if down.calls.Load() != 1 {
		t.Fatalf("the endpoint that is down was asked %d times; want 1, the first call only",
			down.calls.Load())
	}
	if up.calls.Load() != 3 {
		t.Fatalf("the endpoint that answers was asked %d times; want 3", up.calls.Load())
	}
	if f.answering() != up.URL {
		t.Fatalf("answering() is %s; want %s", f.answering(), up.URL)
	}
}

// A chain that refuses is a chain that answered. A revert, an underpriced
// transaction and a nonce that is already used all arrive as 200 with a
// JSON-RPC error inside. Sending those to every endpoint in turn would take a
// call that is doomed and make it slow as well.
func TestARefusalIsAnAnswerAndNotAReasonToTryTheNextEndpoint(t *testing.T) {
	refusing := serving(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution reverted"}}`)
	})
	spare := answering(t, chainIDHex)
	client, _ := dial(t, refusing.URL, spare.URL)

	_, err := client.ChainID(context.Background())
	if err == nil || !strings.Contains(err.Error(), "execution reverted") {
		t.Fatalf("error is %v; want the endpoint's own refusal", err)
	}
	if spare.calls.Load() != 0 {
		t.Fatalf("the second endpoint was asked %d times; a refusal is an answer and it should "+
			"never have been asked", spare.calls.Load())
	}
}

// When every endpoint is down, the error has to say that every endpoint is
// down. The failure that gets logged is the first one, because the first
// endpoint is the one an operator configured on purpose.
func TestEveryEndpointDownSaysHowManyWereTried(t *testing.T) {
	first, second := unavailable(t), unavailable(t)
	client, _ := dial(t, first.URL, second.URL)

	_, err := client.ChainID(context.Background())
	if err == nil {
		t.Fatal("two endpoints answering 503 produced no error")
	}
	if !strings.Contains(err.Error(), "2 endpoints tried") {
		t.Fatalf("error is %q; it should say how many endpoints were tried", err)
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("error is %q; it should carry what the first endpoint said", err)
	}
}

// One endpoint is the old behaviour, and its error should read like the old
// error: no count, because there is nothing to count.
func TestOneEndpointReportsItsOwnFailurePlainly(t *testing.T) {
	only := unavailable(t)
	client, _ := dial(t, only.URL)

	_, err := client.ChainID(context.Background())
	if err == nil {
		t.Fatal("an endpoint answering 503 produced no error")
	}
	if strings.Contains(err.Error(), "endpoints tried") {
		t.Fatalf("error is %q; with one endpoint there is no list to report", err)
	}
}

// An endpoint that accepts the connection and then says nothing is the case a
// per-call timeout does not cover: the anchor loop would sit there until the
// process is killed. Each endpoint gets its own clock.
func TestAnEndpointThatNeverAnswersDoesNotHoldUpTheNextOne(t *testing.T) {
	// The handler waits for the client to give up. It also waits on a channel
	// the test closes, because a server does not always notice a client that
	// went away, and httptest.Server.Close waits for its handlers to return:
	// without this, a regression here hangs the run instead of failing it.
	release := make(chan struct{})
	hanging := serving(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	// Registered after serving(), so it runs before the server is closed.
	t.Cleanup(func() { close(release) })
	up := answering(t, chainIDHex)
	client, f := dial(t, hanging.URL, up.URL)
	f.attempt = 300 * time.Millisecond

	started := time.Now()
	id, err := client.ChainID(context.Background())
	if err != nil {
		t.Fatalf("the call did not get past the endpoint that hangs: %v", err)
	}
	if id.Int64() != 84532 {
		t.Fatalf("chain id %s, want 84532", id)
	}
	if took := time.Since(started); took > 3*time.Second {
		t.Fatalf("the call took %s; the endpoint that hangs should have been given up on "+
			"after 300ms", took)
	}
}

// ---------------------------------------------------------------------------
// Which endpoints get tried
// ---------------------------------------------------------------------------

func TestTheDeploymentRecordNamesTheEndpoints(t *testing.T) {
	record := deployment{
		RPC:          "https://sepolia.base.org",
		RPCFallbacks: []string{"https://base-sepolia-rpc.publicnode.com"},
	}
	got := rpcEndpoints("", record)
	want := []string{"https://sepolia.base.org", "https://base-sepolia-rpc.publicnode.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("endpoints %v; want %v", got, want)
	}
}

// The reason the flag exists: swapping a rate-limited public endpoint for a
// paid one is a deploy variable, not a rebuild.
func TestTheFlagWinsOverTheRecord(t *testing.T) {
	record := deployment{RPC: "https://sepolia.base.org"}
	got := rpcEndpoints("https://paid.example/key, https://spare.example", record)
	want := []string{"https://paid.example/key", "https://spare.example"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("endpoints %v; want %v", got, want)
	}
}

func TestARecordThatNamesNoEndpointFallsBackToTheDocumentedOne(t *testing.T) {
	got := rpcEndpoints("", deployment{})
	if len(got) != 1 || got[0] != defaultRPC {
		t.Fatalf("endpoints %v; want just %s", got, defaultRPC)
	}
}

// A record that repeats its primary among its fallbacks must not make the
// sender wait for the same dead host twice.
func TestAnEndpointNamedTwiceIsTriedOnce(t *testing.T) {
	record := deployment{
		RPC:          "https://sepolia.base.org",
		RPCFallbacks: []string{"https://sepolia.base.org", "https://spare.example"},
	}
	got := rpcEndpoints("", record)
	want := []string{"https://sepolia.base.org", "https://spare.example"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("endpoints %v; want %v", got, want)
	}
}

func TestSomethingThatIsNotAnEndpointIsRefusedAtStartup(t *testing.T) {
	for _, bad := range []string{"sepolia.base.org", "ws://sepolia.base.org", "", "://x"} {
		if _, err := newFailover([]string{bad}, nil); err == nil {
			t.Fatalf("%q was accepted as an RPC endpoint", bad)
		}
	}
	if _, err := newFailover(nil, nil); err == nil {
		t.Fatal("an empty endpoint list was accepted")
	}
}
