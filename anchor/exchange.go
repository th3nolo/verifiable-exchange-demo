package main

// Reading the exchange, and checking every signature the anchor will rest on.
//
// Nothing in this file needs the operator's cooperation beyond the endpoints
// they already serve to a browser: /config and /claims on the matcher, /sth
// and /proof/consistency on the feed.
//
// This used to fold the whole hash chain here, from /messages.ndjson, message
// by message, every tick. It does not any more. The feed publishes an RFC 9162
// Merkle tree and signs its root in a tree head, so the value this sender
// anchors is one the feed put its own signature on rather than one the sender
// worked out alone. Proving the new root extends the one already on chain
// takes a consistency proof of about 17 hashes instead of 100,000 messages.
// That is both less work and a stronger statement. See README.md.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The feed and the matcher both page at 1000 rows.
const pageLimit = 1000

// Exchange is the set of public endpoints one anchor is read from.
type Exchange struct {
	Matcher string
	Feed    string
	client  *http.Client
}

// NewExchange resolves the feed address, asking the matcher for it when the
// caller did not name one. The claims are on the matcher and the history they
// are claims about is on the feed, which is a different service at a different
// address.
func NewExchange(matcherURL, feedURL string) (*Exchange, error) {
	e := &Exchange{
		Matcher: strings.TrimRight(matcherURL, "/"),
		client:  &http.Client{Timeout: 60 * time.Second},
	}
	if feedURL != "" {
		e.Feed = strings.TrimRight(feedURL, "/")
		return e, nil
	}
	var config struct {
		FeedURL string `json:"feed_url"`
	}
	if err := e.getJSON(e.Matcher+"/config", &config); err != nil {
		return nil, err
	}
	if config.FeedURL == "" {
		return nil, fmt.Errorf(
			"%s advertises no feed_url on /config, and the tree to anchor is on the feed; pass -feed-url",
			e.Matcher)
	}
	e.Feed = strings.TrimRight(config.FeedURL, "/")
	return e, nil
}

func (e *Exchange) getBytes(url string) ([]byte, error) {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "exchange-anchor-sender/2")
	response, err := e.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", url, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", url, err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s: %s", url, response.Status,
			strings.TrimSpace(string(body)))
	}
	return body, nil
}

func (e *Exchange) getJSON(url string, into interface{}) error {
	body, err := e.getBytes(url)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("cannot read what %s served: %w", url, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// The documents the exchange serves
// ---------------------------------------------------------------------------

// Claim is one execution claim, exactly as /claims serves it.
type Claim struct {
	FromMsg     uint64 `json:"from_msg"`
	ToMsg       uint64 `json:"to_msg"`
	RootBefore  string `json:"root_before"`
	RootAfter   string `json:"root_after"`
	TradesTotal uint64 `json:"trades_total"`
	Signature   string `json:"signature"`
}

// ClaimsPage is the /claims envelope: the page, plus everything needed to
// check it. The session, the key and the cursor travel with the page on
// purpose, so one response either verifies or does not.
type ClaimsPage struct {
	RunID            int64   `json:"run_id"`
	Session          string  `json:"session"`
	Cursor           uint64  `json:"cursor"`
	MatcherPublicKey string  `json:"matcher_public_key"`
	FeedPublicKey    string  `json:"feed_public_key"`
	Claims           []Claim `json:"claims"`
}

// SignedTreeHead is the feed's signed tree head, as GET /sth serves it.
//
// `timestamp`, `tree_size` and `root_hash` are RFC 9162 `TreeHeadDataV2`. The
// root is the whole reason this program changed: it is the value that lets a
// visitor prove one trade is inside the anchored commitment with about 17
// hashes.
type SignedTreeHead struct {
	Session   string `json:"session"`
	Timestamp uint64 `json:"timestamp"`
	TreeSize  uint64 `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// ConsistencyProof is the answer to GET /proof/consistency.
//
// No roots come back with it, and that is deliberate on the feed's side: both
// roots have to come from heads the caller already holds, here one from the
// tree head just checked and one off the chain, because a proof checked
// against a root the feed handed over beside it always succeeds and proves
// nothing.
type ConsistencyProof struct {
	Session         string   `json:"session"`
	First           uint64   `json:"first"`
	Second          uint64   `json:"second"`
	ConsistencyPath []string `json:"consistency_path"`
}

// treeHeadStatement is what a tree head signature covers. Byte for byte what
// logchain.rs signs, including the newlines.
//
// The prefix is not the head's. The feed serves a chain head and a tree head
// under one key, and both statements start with a session and a count, so
// without separate prefixes a chain head at message 500 and a tree head over
// 500 leaves would be two signatures a verifier could substitute for each
// other.
func treeHeadStatement(session string, timestampMs, treeSize uint64, rootHex string) string {
	return fmt.Sprintf("exchange-feed-sth-v1\n%s\n%d\n%d\n%s", session, timestampMs, treeSize, rootHex)
}

// claimStatement is what an execution claim's signature covers.
func claimStatement(session string, c Claim) string {
	return fmt.Sprintf("exchange-claim-v1\n%s\n%d\n%d\n%s\n%s\n%d",
		session, c.FromMsg, c.ToMsg, c.RootBefore, c.RootAfter, c.TradesTotal)
}

func checkEd25519(publicKeyHex, statement, signatureHex, what string) error {
	key, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("%s names %q, which is not a 32-byte hex public key", what, publicKeyHex)
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%s carries no 64-byte hex signature", what)
	}
	if !ed25519.Verify(ed25519.PublicKey(key), []byte(statement), signature) {
		return fmt.Errorf("%s does not verify under key %s", what, publicKeyHex)
	}
	return nil
}

// ---------------------------------------------------------------------------
// The tree head, and the proof that it extends what is already anchored
// ---------------------------------------------------------------------------

// treeHead reads GET /sth and refuses it unless its own signature verifies.
//
// This is the check that replaces folding the chain. The old sender proved to
// itself that the value it was about to anchor was the value the feed had
// signed, by recomputing it from every message. Here the value it is about to
// anchor *is* the value the feed signed, and this is where that is
// established, before any transaction is built, and with a refusal if it does
// not hold.
func (e *Exchange) treeHead(session, pinnedKey string) (*SignedTreeHead, error) {
	var sth SignedTreeHead
	if err := e.getJSON(e.Feed+"/sth", &sth); err != nil {
		return nil, err
	}
	if sth.Session != session {
		return nil, fmt.Errorf(
			"the matcher is executing history %s and the feed's tree head names %s: these are two different histories",
			session, sth.Session)
	}
	if pinnedKey != "" && sth.PublicKey != pinnedKey {
		return nil, fmt.Errorf("this run pinned feed key %s, the tree head is signed by %s",
			pinnedKey, sth.PublicKey)
	}
	if _, err := hex32(sth.RootHash); err != nil {
		return nil, fmt.Errorf("the feed's tree head names root %q, which is not a 32-byte hex value", sth.RootHash)
	}
	if err := checkEd25519(
		sth.PublicKey,
		treeHeadStatement(sth.Session, sth.Timestamp, sth.TreeSize, sth.RootHash),
		sth.Signature,
		"the feed's signed tree head",
	); err != nil {
		return nil, err
	}
	return &sth, nil
}

// extends checks that the tree the feed has just signed contains, unchanged,
// the tree whose root is already on chain.
//
// One request and about 17 hashes. The old sender established the same thing
// by folding every message from the last anchored position to the feed's head
// and comparing against a signature; this asks the feed for the log(n) node
// hashes that prove it and checks them here.
//
// A proof that does not verify is not a network problem to retry past. It says
// the feed's current tree is not an extension of the tree this contract holds,
// which is the fork an anchor exists to expose, so it is returned as an error
// and nothing is written.
func (e *Exchange) extends(anchored [32]byte, at uint64, sth *SignedTreeHead) error {
	var proof ConsistencyProof
	url := fmt.Sprintf("%s/proof/consistency?first=%d&second=%d", e.Feed, at, sth.TreeSize)
	if err := e.getJSON(url, &proof); err != nil {
		return err
	}
	if proof.First != at || proof.Second != sth.TreeSize {
		return fmt.Errorf("asked for a consistency proof from %d to %d and was answered for %d to %d",
			at, sth.TreeSize, proof.First, proof.Second)
	}
	path := make([][32]byte, 0, len(proof.ConsistencyPath))
	for i, node := range proof.ConsistencyPath {
		decoded, err := hex32(node)
		if err != nil {
			return fmt.Errorf("node %d of the consistency proof from %d to %d: %w", i, at, sth.TreeSize, err)
		}
		path = append(path, decoded)
	}
	root, err := hex32(sth.RootHash)
	if err != nil {
		return err
	}
	if !verifyConsistency(at, sth.TreeSize, anchored, root, path) {
		return fmt.Errorf(
			"the tree of %d messages under root %s is on chain, and the feed's proof does not show it is a "+
				"prefix of the tree of %d messages under root %s that it has just signed. Entries this "+
				"contract already committed to have been changed, removed or reordered",
			at, hex.EncodeToString(anchored[:]), sth.TreeSize, sth.RootHash)
	}
	return nil
}

// ---------------------------------------------------------------------------
// One coherent tuple
// ---------------------------------------------------------------------------

// Facts is what one anchor commits to, with the position every value stands
// at.
//
// Two positions, not one, and they are both here because a signature covers
// each of them separately: `Root` stands at `TreeSize` under the feed's tree
// head signature, and `StateRoot` stands at `LastID` under the matcher's claim
// signature. The old anchor forced all four values to one position and paid
// for it by folding the whole history every tick, because the feed only ever
// signs its chain at its own head and a tree head cannot be re-derived at an
// earlier size either. `LastID <= TreeSize`, so the messages the execution
// claims to have applied are always inside the tree being anchored. The
// contract refuses anything else.
type Facts struct {
	Session   string
	TreeSize  uint64
	Root      [32]byte
	LastID    uint64
	StateRoot [32]byte
	// When the feed signed the tree head this root came from, in milliseconds
	// since the epoch. Not anchored, because the block's own timestamp is what
	// dates the anchor. Logged anyway, because a root signed an hour ago
	// written into a block now is worth seeing.
	Timestamp uint64
}

// Collect reads one coherent (treeSize, lastId, session, root, stateRoot) from
// the exchange, checking every signature it rests on before returning it.
//
// `onChain` is what the contract already holds. It is an input rather than
// something the caller compares afterwards because three of the refusals below
// need both sides: a tree that has shrunk past an anchored size, a different
// root signed for a size already anchored, and a new root that does not extend
// the anchored one. Each of those is the feed contradicting a commitment
// nobody can edit, and each stops the write.
func (e *Exchange) Collect(onChain AnchorState) (*Facts, error) {
	var envelope ClaimsPage
	if err := e.getJSON(e.Matcher+"/claims?since=0", &envelope); err != nil {
		return nil, err
	}
	session := envelope.Session
	if !isSessionHex(session) {
		return nil, skipf("this exchange names no feed session (%q), so an anchored tree size would name nothing", session)
	}
	// The contract uses a zero bytes8 to mean "no anchor has been written
	// here yet", so it refuses this value. Astronomically unlikely from a
	// random 64-bit session, and worth one line rather than a contract that
	// reverts every five minutes with nothing saying why.
	if session == "0000000000000000" {
		return nil, fmt.Errorf(
			"this exchange's feed session is all zeroes, which the contract reserves for " +
				"'nothing anchored yet' and will refuse. Restart the feed to get a new session")
	}
	if envelope.Cursor == 0 {
		return nil, skipf("this exchange has committed no messages yet")
	}
	cursor := envelope.Cursor

	// The claim whose to_msg is exactly the cursor. Claims are keyed by
	// from_msg and one claim covers at most a page of messages, so a page
	// starting a page below the cursor always contains it.
	since := uint64(0)
	if cursor > pageLimit {
		since = cursor - pageLimit
	}
	var page ClaimsPage
	if err := e.getJSON(fmt.Sprintf("%s/claims?since=%d", e.Matcher, since), &page); err != nil {
		return nil, err
	}
	var claim *Claim
	for i := range page.Claims {
		if page.Claims[i].ToMsg == cursor {
			claim = &page.Claims[i]
			break
		}
	}
	if claim == nil {
		return nil, fmt.Errorf(
			"%s has no claim ending at its own cursor %d: its execution up to there was never committed to",
			e.Matcher, cursor)
	}
	if err := checkEd25519(envelope.MatcherPublicKey, claimStatement(session, *claim), claim.Signature,
		fmt.Sprintf("the claim for messages %d..%d", claim.FromMsg, claim.ToMsg)); err != nil {
		return nil, err
	}
	stateRoot, err := hex32(claim.RootAfter)
	if err != nil {
		return nil, fmt.Errorf("the claim ending at message %d: %w", cursor, err)
	}

	sth, err := e.treeHead(session, envelope.FeedPublicKey)
	if err != nil {
		return nil, err
	}
	// Message n is leaf n-1, so a tree of `tree_size` messages holds messages
	// 1..tree_size. A cursor past that is an execution claim about messages
	// the anchored tree does not cover, and the contract refuses it too.
	if sth.TreeSize < cursor {
		return nil, fmt.Errorf(
			"the feed's tree holds %d messages and the matcher has committed up to message %d: the state "+
				"root would stand outside the tree being anchored",
			sth.TreeSize, cursor)
	}
	root, err := hex32(sth.RootHash)
	if err != nil {
		return nil, err
	}

	if !onChain.Empty() {
		if err := checkAgainstChain(onChain, sth, root, cursor); err != nil {
			return nil, err
		}
		if sth.TreeSize > onChain.TreeSize {
			if err := e.extends(onChain.Root, onChain.TreeSize, sth); err != nil {
				return nil, err
			}
		}
	}

	return &Facts{
		Session:   session,
		TreeSize:  sth.TreeSize,
		Root:      root,
		LastID:    cursor,
		StateRoot: stateRoot,
		Timestamp: sth.Timestamp,
	}, nil
}

// checkAgainstChain compares a freshly signed tree head against the anchor
// already on chain, and names each way they can contradict each other.
//
// All four are the feed disagreeing with a value nobody, not even the
// operator, can edit, which is the whole reason the anchor exists. None of
// them is a reason to try again in five minutes, so each one stops the tick
// with a sentence saying which two values disagree.
func checkAgainstChain(onChain AnchorState, sth *SignedTreeHead, root [32]byte, cursor uint64) error {
	// The session first. Everything below compares sizes and roots, and
	// comparing them across two histories would report a replaced history as
	// a lost entry, which is the wrong sentence for the one event this
	// contract exists to expose.
	session, err := sessionBytes8(sth.Session)
	if err != nil {
		return err
	}
	if session != onChain.Session {
		return fmt.Errorf(
			"this contract anchors history %s and the exchange now serves %s: the history it records has "+
				"been replaced. Deploy a second contract for the new history and publish its address; "+
				"this one keeps the record of the old one",
			hex.EncodeToString(onChain.Session[:]), sth.Session)
	}
	if sth.TreeSize < onChain.TreeSize {
		return fmt.Errorf(
			"this contract holds a tree of %d messages and the feed has just signed one of %d for the same "+
				"history: the log has lost entries it was already committed to",
			onChain.TreeSize, sth.TreeSize)
	}
	if sth.TreeSize == onChain.TreeSize && root != onChain.Root {
		return fmt.Errorf(
			"this contract holds root %s over %d messages and the feed has just signed %s over the same %d "+
				"of the same history: the entries under that root have been rewritten",
			hex.EncodeToString(onChain.Root[:]), onChain.TreeSize, sth.RootHash, sth.TreeSize)
	}
	if cursor < onChain.LastID {
		return fmt.Errorf(
			"this contract holds the state after message %d and the matcher has now committed only up to %d: "+
				"the execution has been rewound past what was anchored",
			onChain.LastID, cursor)
	}
	return nil
}

// isSessionHex reports whether a session is the 16 lowercase hex characters
// the feed writes. It becomes a bytes8 on chain, so anything else would be
// silently truncated or padded into a different history's name.
func isSessionHex(session string) bool {
	if len(session) != 16 {
		return false
	}
	for _, c := range session {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func hex32(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return out, fmt.Errorf("%q is not a 32-byte hex value", s)
	}
	copy(out[:], raw)
	return out, nil
}
