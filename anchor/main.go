// Command anchor-sender writes one exchange's history commitment to an
// ExchangeAnchor contract, on a timer.
//
// It is deliberately a separate program from the exchange. Everything it reads
// is a public endpoint, so anyone can run one against any exchange. A third
// party's anchor is stronger evidence than the operator's own, because
// an anchor written by the operator's own process is still the operator. See
// README.md.
//
//	anchor-sender -once
//	anchor-sender -interval 5m
package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// ---------------------------------------------------------------------------
// Configuration: flags, with an environment variable behind each one
// ---------------------------------------------------------------------------

// Config holds every configuration field. Every field has an environment
// variable so the container running this needs no command line at all, and
// swapping a rate-limited public RPC for a provider endpoint is one variable.
type Config struct {
	RPC        string
	Contract   string
	KeyPath    string
	Exchange   string
	FeedURL    string
	Interval   time.Duration
	Deployment string
	Once       bool
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s=%q is not a duration like 5m; using %s\n", name, value, fallback)
		return fallback
	}
	return parsed
}

func parseFlags() Config {
	var c Config
	flag.StringVar(&c.RPC, "rpc", env("ANCHOR_RPC", ""),
		"JSON-RPC endpoints of the chain the anchors go on, most preferred first, "+
			"comma separated (ANCHOR_RPC). Each call goes to the first one that answers, "+
			"because a public testnet endpoint that is down must not stop the anchors. "+
			"Read from the deployment record when unset")
	flag.StringVar(&c.Contract, "contract", env("ANCHOR_CONTRACT", ""),
		"ExchangeAnchor address; read from the deployment record when unset (ANCHOR_CONTRACT)")
	flag.StringVar(&c.KeyPath, "key", env("ANCHOR_KEY_FILE", "/run/secrets/anchor_key"),
		"path to the file holding the 64-hex-character private key that writes anchors "+
			"(ANCHOR_KEY_FILE). A path only. This program never takes key material from the "+
			"environment, because an environment variable is readable through docker inspect, "+
			"/proc/<pid>/environ and the deployment UI")
	flag.StringVar(&c.Exchange, "exchange-url", env("ANCHOR_EXCHANGE_URL", "https://exchange.th3nolo.com"),
		"the matcher's base URL (ANCHOR_EXCHANGE_URL)")
	flag.StringVar(&c.FeedURL, "feed-url", env("ANCHOR_FEED_URL", ""),
		"the feed's base URL; asked for on GET /config when unset (ANCHOR_FEED_URL)")
	flag.DurationVar(&c.Interval, "interval", envDuration("ANCHOR_INTERVAL", 5*time.Minute),
		"how often to anchor (ANCHOR_INTERVAL). A tuning decision, not a protocol one: "+
			"it bounds how much recent history a rewind could reach without contradicting an anchor")
	flag.StringVar(&c.Deployment, "deployment", env("ANCHOR_DEPLOYMENT", "root-deployment.json"),
		"deployment record to take the contract address from when -contract is unset")
	flag.BoolVar(&c.Once, "once", false, "write one anchor and exit")
	flag.Parse()
	return c
}

// ---------------------------------------------------------------------------
// The signing key
// ---------------------------------------------------------------------------

// Signer holds the key that writes anchors. Nothing on it exposes the private
// half: it can produce an address and it can sign, and that is all. The key is
// never logged, never written anywhere, and never included in an error.
type Signer struct {
	key     *ecdsa.PrivateKey
	address common.Address
}

// LoadSigner reads the key from a file and refuses everything else.
//
// A path, never a value. A key in an environment variable is readable through
// `docker inspect`, through /proc/<pid>/environ for anything running as the
// same user, and through the deployment UI that set it, three places it is
// visible to people who were never meant to hold it. A path names a file that
// Docker mounts read-only at 0400 and that nothing else can see.
//
// Every way the path can be wrong is checked here, at startup, before a single
// transaction is built, and each one names the path and what was wrong with
// it. The directory case is the one worth calling out: when Docker
// bind-mounts a file that does not exist on the host, it silently creates a
// *directory* at the target. Without this check the sender starts happily,
// fails at signing time with something about a read, and the operator is left
// believing anchoring is running when nothing has been written for a week.
func LoadSigner(path string) (*Signer, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf(
			"the anchor key file %s does not exist. It must hold 64 hex characters and nothing "+
				"else; in the container it is the secret mounted at /run/secrets/anchor_key",
			path)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot look at the anchor key file %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf(
			"the anchor key path %s is a directory, not a file. Docker creates a directory there "+
				"when it is told to bind-mount a file that does not exist on the host, so the "+
				"secret almost certainly never reached this container",
			path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the anchor key file %s: %w", path, err)
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, fmt.Errorf("the anchor key file %s is empty", path)
	}
	text = strings.TrimPrefix(text, "0x")
	if len(text) != 64 {
		return nil, fmt.Errorf(
			"the anchor key file %s holds %d characters, not the 64 hex characters a private "+
				"key is (its contents are not shown here on purpose)",
			path, len(text))
	}
	if _, err := hex.DecodeString(text); err != nil {
		// Deliberately not wrapping: the library's message quotes the input.
		return nil, fmt.Errorf("the anchor key file %s is not hexadecimal", path)
	}
	key, err := crypto.HexToECDSA(text)
	if err != nil {
		return nil, fmt.Errorf("the anchor key file %s does not hold a usable secp256k1 key", path)
	}
	return &Signer{key: key, address: crypto.PubkeyToAddress(key.PublicKey)}, nil
}

func (s *Signer) Address() common.Address { return s.address }

func (s *Signer) Sign(tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), s.key)
	if err != nil {
		return nil, fmt.Errorf("cannot sign the anchor transaction: %w", err)
	}
	return signed, nil
}

// ---------------------------------------------------------------------------
// Logging, and the "nothing to do" case
// ---------------------------------------------------------------------------

func logf(format string, args ...interface{}) {
	fmt.Printf("%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
}

// errSkip marks a tick with nothing to write. Not a failure: an exchange that
// has not committed a new message since the last anchor is behaving normally,
// and sending a transaction for it would only be refused by the contract.
type errSkip struct{ reason string }

func (e errSkip) Error() string { return e.reason }

func skipf(format string, args ...interface{}) error {
	return errSkip{reason: fmt.Sprintf(format, args...)}
}

// ---------------------------------------------------------------------------
// One tick
// ---------------------------------------------------------------------------

// tick reads the contract, reads the exchange, and writes one anchor when
// there is a newer tree to commit to.
//
// The contract's own newest anchor goes *into* `Collect` rather than being
// compared with its answer afterwards. It is not only the "is there anything
// new" test: it is the value the feed's freshly signed tree head is checked
// against, by a consistency proof, and three of the ways the two can
// contradict each other stop the write. Nothing is anchored that was not
// checked against both a signature and the commitment already on chain.
//
// There is no resume file any more. The old sender kept one so each tick could
// fold the hash chain forward from the last anchored message instead of from
// message 1; there is no fold left to resume, and what a resume file used to
// hold, where this sender last stood in this history, is on chain, where the
// operator cannot edit it.
func tick(ctx context.Context, anchorer *Anchorer, exchange *Exchange) error {
	onChain, err := anchorer.Latest(ctx)
	if err != nil {
		return err
	}

	facts, err := exchange.Collect(onChain)
	if err != nil {
		return err
	}

	if facts.TreeSize <= onChain.TreeSize {
		return skipf("nothing new to anchor: on chain over %d messages, the feed's tree holds %d",
			onChain.TreeSize, facts.TreeSize)
	}

	logf("  anchoring session %s over %d messages, tree head signed %s",
		facts.Session, facts.TreeSize,
		time.UnixMilli(int64(facts.Timestamp)).UTC().Format(time.RFC3339))
	logf("    root       %s", hex.EncodeToString(facts.Root[:]))
	logf("    state root %s after message %d", hex.EncodeToString(facts.StateRoot[:]), facts.LastID)

	receipt, err := anchorer.Send(ctx, facts)
	if err != nil {
		return err
	}
	logf("  anchored in block %d, tx %s", receipt.BlockNumber, receipt.TxHash)
	logf("    %d gas, %s wei L2 + %s wei L1 data = %s ETH",
		receipt.GasUsed,
		new(big.Int).Mul(new(big.Int).SetUint64(receipt.GasUsed), receipt.GasPrice),
		orZero(receipt.L1Fee),
		formatEther(receipt.Total()))
	return nil
}

func orZero(value *big.Int) *big.Int {
	if value == nil {
		return big.NewInt(0)
	}
	return value
}

// formatEther prints wei as ETH with all 18 decimals, trimmed. An anchor costs
// well under a millionth of an ETH and a rounded figure would print as zero.
func formatEther(wei *big.Int) string {
	whole := new(big.Int)
	frac := new(big.Int)
	whole.QuoRem(wei, big.NewInt(1e18), frac)
	text := fmt.Sprintf("%d.%018d", whole, frac)
	text = strings.TrimRight(text, "0")
	return strings.TrimSuffix(text, ".")
}

// ---------------------------------------------------------------------------

// deployment is the part of the deployment record this sender reads: where the
// contract is, and where to reach the chain it is on. The record holds a great
// deal more, and none of the rest is this program's business.
type deployment struct {
	Address      string   `json:"address"`
	RPC          string   `json:"rpc"`
	RPCFallbacks []string `json:"rpc_fallbacks"`
}

// readDeployment returns the record, and whether the file could be read at
// all. An unreadable record is not by itself a failure: -contract and -rpc can
// supply everything it would have said. It is only a failure when nothing else
// says where the contract is, and then the caller reports it as that.
func readDeployment(path string) (deployment, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return deployment{}, err
	}
	var record deployment
	if err := json.Unmarshal(raw, &record); err != nil {
		return deployment{}, nil // a file that is there and is not a record
	}
	return record, nil
}

func run(c Config) error {
	record, recordErr := readDeployment(c.Deployment)
	address := c.Contract
	if address == "" {
		if recordErr != nil {
			return fmt.Errorf("no contract address: pass -contract, set ANCHOR_CONTRACT, or run "+
				"where %s is readable", c.Deployment)
		}
		if record.Address == "" {
			return fmt.Errorf("%s names no contract address", c.Deployment)
		}
		address = record.Address
	}
	if !common.IsHexAddress(address) {
		return fmt.Errorf("%q is not a contract address", address)
	}

	// The one variable name somebody might reach for to pass the key itself.
	// Refusing to start is the only way to make sure a key that was put there
	// gets moved rather than quietly used from a place it can be read.
	if os.Getenv("ANCHOR_KEY") != "" {
		return fmt.Errorf(
			"ANCHOR_KEY is set. This program never takes key material from the environment: " +
				"put the key in a file and name the file in ANCHOR_KEY_FILE (or -key). Unset " +
				"ANCHOR_KEY, and rotate that key if it was ever a real one. Anything that can " +
				"run docker inspect has already seen it")
	}
	signer, err := LoadSigner(c.KeyPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	endpoints, err := newFailover(rpcEndpoints(c.RPC, record), logf)
	if err != nil {
		return err
	}
	// The URL given here is only the one the first call uses; the transport
	// chooses per request. Timeout is left to the transport, which bounds each
	// endpoint separately rather than making them share one budget.
	chain, err := rpc.DialOptions(ctx, endpoints.answering(),
		rpc.WithHTTPClient(&http.Client{Transport: endpoints}))
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", endpoints.answering(), err)
	}
	client := ethclient.NewClient(chain)
	defer client.Close()

	anchorer, err := NewAnchorer(ctx, client, common.HexToAddress(address), signer)
	if err != nil {
		return err
	}
	exchange, err := NewExchange(c.Exchange, c.FeedURL)
	if err != nil {
		return err
	}

	// The address answering with the wrong number of words is the one startup
	// failure worth exiting on, because it never gets better by itself: it is
	// this sender pointed at something that is not an ExchangeRootAnchor,
	// most likely the closed chain-hash contract, which declares the same
	// `latest()` and so answers the same selector with six words instead of
	// seven. Every other reason `latest()` can fail is a chain that is busy,
	// and the loop below is what answers those.
	var wrongContract errWrongContract
	if _, err := anchorer.Latest(ctx); errors.As(err, &wrongContract) {
		return wrongContract
	}

	logf("anchor sender: %s -> %s on chain %s", exchange.Matcher, address, anchorer.ChainID())
	logf("  feed     %s", exchange.Feed)
	logf("  rpc      %s", strings.Join(endpointHosts(endpoints), ", "))
	logf("  writer   %s", signer.Address())
	logf("  interval %s", c.Interval)
	if writer, err := anchorer.Writer(ctx); err == nil && writer != signer.Address() {
		logf("  WARNING  %s only accepts anchors from %s; every transaction this sender makes will revert",
			address, writer)
	}

	for {
		started := time.Now()
		err := tick(ctx, anchorer, exchange)
		var skip errSkip
		switch {
		case err == nil:
		case errors.As(err, &skip):
			logf("  %s", skip.reason)
			err = nil // nothing new to anchor is not a failure
		default:
			// One bad tick must not end the *loop*: an exchange that is down,
			// an RPC that refused, a transaction that did not land. All of
			// them are answered by trying again on the next tick.
			logf("  FAILED: %v", err)
		}
		if c.Once {
			// A single run is somebody or something asking whether an anchor
			// was written, so the exit status has to answer that. Logging the
			// failure and exiting 0 makes a skipped anchor indistinguishable
			// from a written one to cron, to CI, and to a health check.
			return err
		}
		wait := c.Interval - time.Since(started)
		if wait < time.Second {
			wait = time.Second
		}
		select {
		case <-ctx.Done():
			logf("stopping")
			return nil
		case <-time.After(wait):
		}
	}
}

func main() {
	if err := run(parseFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "anchor-sender: %v\n", err)
		os.Exit(1)
	}
}
