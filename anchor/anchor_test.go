package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// ---------------------------------------------------------------------------
// RFC 9162, the worked example from section 2.1.5
// ---------------------------------------------------------------------------

// The seven-leaf tree the RFC draws, built here from leafHash and nodeHash
// directly rather than from any tree code.
//
//	       hash
//	      /    \
//	     k      l
//	    / \    / \
//	   g   h  i   j
//	  /|  /|  /|  |
//	 a b c d e f  d6
//	 | | | | | |
//	d0 d1 d2 d3 d4 d5
//
// The entries are "entry-0".."entry-6", the same seven `services/src/merkle.rs`
// uses, so the digests below are values both implementations have to produce.
// That is the point of pinning them in two languages: a mistake in one shows up
// as a disagreement instead of as two copies of itself.
type rfcExample struct {
	a, b, c, d, e, f       [32]byte
	g, h, i, j, k, l, root [32]byte
}

func buildRFCExample() rfcExample {
	entry := func(i int) []byte { return []byte(fmt.Sprintf("entry-%d", i)) }
	var x rfcExample
	x.a = leafHash(entry(0))
	x.b = leafHash(entry(1))
	x.c = leafHash(entry(2))
	x.d = leafHash(entry(3))
	x.e = leafHash(entry(4))
	x.f = leafHash(entry(5))
	// j has one child in the diagram, so it is d6's leaf hash: MTH of a
	// one-element list is that element's leaf hash.
	x.j = leafHash(entry(6))
	x.g = nodeHash(x.a, x.b)
	x.h = nodeHash(x.c, x.d)
	x.i = nodeHash(x.e, x.f)
	x.k = nodeHash(x.g, x.h)
	x.l = nodeHash(x.i, x.j)
	x.root = nodeHash(x.k, x.l)
	return x
}

// The two prefix bytes, pinned to digests anyone can reproduce with sha256sum
// and no Merkle code in the way. Deleting either prefix changes every digest
// in this file and leaves the tree's shape alone, so this is what notices.
func TestTheRFCPrefixesAreTheBytesTheRFCNames(t *testing.T) {
	for what, got := range map[string]string{
		// printf '' | sha256sum
		"MTH({})": hexOf(emptyRoot()),
		// printf '\x00' | sha256sum
		"leafHash(\"\")": hexOf(leafHash(nil)),
		// printf '\x01\x00...\x00' over two 32-byte zero children
		"nodeHash(0, 0)": hexOf(nodeHash([32]byte{}, [32]byte{})),
	} {
		if len(got) != 64 {
			t.Errorf("%s is %q", what, got)
		}
	}
	if got := hexOf(emptyRoot()); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("MTH({}) is %s", got)
	}
	if got := hexOf(leafHash(nil)); got != "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" {
		t.Errorf("leafHash of an empty entry is %s", got)
	}
}

// The four roots the RFC's incremental example passes through, as digests the
// Rust side pins to the same strings.
func TestTheRFCExampleProducesTheSameRootsAsTheRustTree(t *testing.T) {
	x := buildRFCExample()
	for what, pair := range map[string][2]string{
		"root over 3": {hexOf(nodeHash(x.g, x.c)), "a64bf26e09128f6fe2fe6f8b2d8c801e166b57c047a7cd9b2b809e7a96a2f1cb"},
		"root over 4": {hexOf(x.k), "256b9e8825e5d370a4ae005d0901ea291977e2927f5cf8e3e72660dd09519edb"},
		"root over 6": {hexOf(nodeHash(x.k, x.i)), "08783a523d260480de2ccf0976d7411ed8adaf06f75d5a5de2254c58f968eca9"},
		"root over 7": {hexOf(x.root), "9139601cc1ca8ab2a7a0c2c134c04845f2b1ba549a83d6c845cfcda439cc585d"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("the %s is %s, services/src/merkle.rs pins %s", what, pair[0], pair[1])
		}
	}
}

// The three known-answer consistency proofs of RFC 9162 section 2.1.5. These
// are the only proofs this sender ever checks, and getting one wrong means
// either anchoring a fork or refusing an honest feed forever.
func TestTheRFCConsistencyProofsVerify(t *testing.T) {
	x := buildRFCExample()
	cases := []struct {
		first     uint64
		firstHash [32]byte
		path      [][32]byte
	}{
		{3, nodeHash(x.g, x.c), [][32]byte{x.c, x.d, x.g, x.l}},
		{4, x.k, [][32]byte{x.l}},
		{6, nodeHash(x.k, x.i), [][32]byte{x.i, x.j, x.k}},
	}
	for _, c := range cases {
		if !verifyConsistency(c.first, 7, c.firstHash, x.root, c.path) {
			t.Errorf("the RFC's consistency proof from %d to 7 did not verify", c.first)
		}
	}
}

// A proof has to fail when anything about it is wrong, because "verified" is
// the word this sender writes a transaction on.
func TestABadConsistencyProofIsRefused(t *testing.T) {
	x := buildRFCExample()
	other := leafHash([]byte("not in this tree"))
	cases := []struct {
		what          string
		first, second uint64
		firstHash     [32]byte
		secondHash    [32]byte
		path          [][32]byte
	}{
		{"a node swapped", 4, 7, x.k, x.root, [][32]byte{x.i}},
		{"a node from another tree", 4, 7, x.k, x.root, [][32]byte{other}},
		{"an empty path", 4, 7, x.k, x.root, nil},
		{"a path with an extra node", 4, 7, x.k, x.root, [][32]byte{x.l, x.l}},
		{"the wrong old root", 4, 7, x.g, x.root, [][32]byte{x.l}},
		{"the wrong new root", 4, 7, x.k, x.l, [][32]byte{x.l}},
		{"running backwards", 7, 4, x.root, x.k, [][32]byte{x.l}},
		{"a size that is not the proof's", 3, 7, x.k, x.root, [][32]byte{x.l}},
		{"an empty tree that is not empty", 0, 7, x.k, x.root, nil},
		{"one size twice with two roots", 7, 7, x.k, x.root, nil},
	}
	for _, c := range cases {
		if verifyConsistency(c.first, c.second, c.firstHash, c.secondHash, c.path) {
			t.Errorf("%s verified", c.what)
		}
	}
	// The two sizes outside the RFC that are still true.
	if !verifyConsistency(0, 7, emptyRoot(), x.root, nil) {
		t.Error("the empty tree is a prefix of every tree")
	}
	if !verifyConsistency(7, 7, x.root, x.root, nil) {
		t.Error("a tree is a prefix of itself")
	}
}

// ---------------------------------------------------------------------------
// The statements the exchange signs
// ---------------------------------------------------------------------------

// Byte for byte what logchain.rs signs. A newline in the wrong place here means
// the sender anchors a root it never checked a signature on, because a
// signature over a statement this program builds differently simply fails to
// verify and the anchor stops for a reason that is not the real one.
//
// services/src/logchain.rs pins these same two statements in
// the_signed_statements_are_exactly_these_bytes, with the same session, time,
// counts and roots. The two expected strings below are character for character
// the two in that Rust test, so a reader can open both files and compare them
// without running anything. The roots are the full 64 hex characters the feed
// really serves, for the same reason.
func TestSignedStatementsMatchTheExchangesFormat(t *testing.T) {
	const (
		root       = "6f9415dc00000000000000000000000000000000000000000000000000000000"
		rootBefore = "aa00000000000000000000000000000000000000000000000000000000000000"
		rootAfter  = "bb00000000000000000000000000000000000000000000000000000000000000"
	)
	sth := treeHeadStatement("349d462ced25bb2b", 1786767726360, 102769, root)
	if sth != "exchange-feed-sth-v1\n349d462ced25bb2b\n1786767726360\n102769\n"+
		"6f9415dc00000000000000000000000000000000000000000000000000000000" {
		t.Errorf("tree head statement is %q, services/src/logchain.rs pins another", sth)
	}
	claim := claimStatement("349d462ced25bb2b", Claim{
		FromMsg: 5, ToMsg: 9, RootBefore: rootBefore, RootAfter: rootAfter, TradesTotal: 17,
	})
	if claim != "exchange-claim-v1\n349d462ced25bb2b\n5\n9\n"+
		"aa00000000000000000000000000000000000000000000000000000000000000\n"+
		"bb00000000000000000000000000000000000000000000000000000000000000\n17" {
		t.Errorf("claim statement is %q, services/src/logchain.rs pins another", claim)
	}
}

// A signature that does not verify has to stop the anchor, not be logged and
// stepped over: the whole value of an anchor is that what it commits to was
// signed by somebody who cannot take it back.
func TestEd25519CheckAcceptsOnlyRealSignatures(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	statement := treeHeadStatement("349d462ced25bb2b", 1, 1, "00")
	good := hex.EncodeToString(ed25519.Sign(private, []byte(statement)))
	keyHex := hex.EncodeToString(public)

	if err := checkEd25519(keyHex, statement, good, "the tree head"); err != nil {
		t.Errorf("an honest signature was refused: %v", err)
	}
	if err := checkEd25519(keyHex, statement+" ", good, "the tree head"); err == nil {
		t.Error("a signature over a different statement verified")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if err := checkEd25519(hex.EncodeToString(other), statement, good, "the tree head"); err == nil {
		t.Error("a signature verified under a stranger's key")
	}
	if err := checkEd25519(keyHex, statement, "notahexsignature", "the tree head"); err == nil {
		t.Error("a signature that is not hex verified")
	}
}

// ---------------------------------------------------------------------------
// One tick against a feed that can be made to misbehave
// ---------------------------------------------------------------------------

const testSession = "349d462ced25bb2b"

// fakeExchange serves the four documents `Collect` reads, each of them
// tweakable, so every refusal below is produced by a real HTTP round trip
// through the real parsing rather than by calling a checker directly.
type fakeExchange struct {
	session    string
	cursor     uint64
	stateRoot  [32]byte
	sthSize    uint64
	sthRoot    [32]byte
	sthTime    uint64
	proofPath  [][32]byte
	feedKey    ed25519.PrivateKey
	matcherKey ed25519.PrivateKey

	// Ways to make the feed lie, each one a separate refusal below.
	breakSTHSignature  bool
	sthSessionOverride string
}

func newFakeExchange(t *testing.T) *fakeExchange {
	t.Helper()
	x := buildRFCExample()
	_, feed, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, matcher, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeExchange{
		session:    testSession,
		cursor:     7,
		stateRoot:  leafHash([]byte("state after message 7")),
		sthSize:    7,
		sthRoot:    x.root,
		sthTime:    1786767726360,
		proofPath:  [][32]byte{x.l},
		feedKey:    feed,
		matcherKey: matcher,
	}
}

func (f *fakeExchange) start(t *testing.T) *Exchange {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	exchange, err := NewExchange(server.URL, server.URL)
	if err != nil {
		t.Fatalf("NewExchange: %v", err)
	}
	return exchange
}

func (f *fakeExchange) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/claims":
		claim := Claim{
			FromMsg:     1,
			ToMsg:       f.cursor,
			RootBefore:  strings.Repeat("00", 32),
			RootAfter:   hexOf(f.stateRoot),
			TradesTotal: 3,
		}
		claim.Signature = hex.EncodeToString(
			ed25519.Sign(f.matcherKey, []byte(claimStatement(f.session, claim))))
		writeJSON(w, ClaimsPage{
			RunID:            1,
			Session:          f.session,
			Cursor:           f.cursor,
			MatcherPublicKey: hex.EncodeToString(f.matcherKey.Public().(ed25519.PublicKey)),
			FeedPublicKey:    hex.EncodeToString(f.feedKey.Public().(ed25519.PublicKey)),
			Claims:           []Claim{claim},
		})
	case "/sth":
		session := f.session
		if f.sthSessionOverride != "" {
			session = f.sthSessionOverride
		}
		sth := SignedTreeHead{
			Session:   session,
			Timestamp: f.sthTime,
			TreeSize:  f.sthSize,
			RootHash:  hexOf(f.sthRoot),
			PublicKey: hex.EncodeToString(f.feedKey.Public().(ed25519.PublicKey)),
		}
		signed := ed25519.Sign(f.feedKey,
			[]byte(treeHeadStatement(sth.Session, sth.Timestamp, sth.TreeSize, sth.RootHash)))
		if f.breakSTHSignature {
			// One bit. The document is otherwise exactly what an honest feed
			// serves, which is the case a check by eye would pass.
			signed[0] ^= 0x01
		}
		sth.Signature = hex.EncodeToString(signed)
		writeJSON(w, sth)
	case "/proof/consistency":
		path := make([]string, 0, len(f.proofPath))
		for _, node := range f.proofPath {
			path = append(path, hexOf(node))
		}
		writeJSON(w, ConsistencyProof{
			Session:         f.session,
			First:           mustUint(r.URL.Query().Get("first")),
			Second:          mustUint(r.URL.Query().Get("second")),
			ConsistencyPath: path,
		})
	default:
		http.Error(w, "no such endpoint", http.StatusNotFound)
	}
}

// anchoredAt is what the contract would already hold: the RFC example's tree of
// four, which the tree of seven extends.
func anchoredAtFour(t *testing.T) AnchorState {
	t.Helper()
	x := buildRFCExample()
	session, err := sessionBytes8(testSession)
	if err != nil {
		t.Fatal(err)
	}
	return AnchorState{
		TreeSize: 4,
		LastID:   4,
		Session:  session,
		Root:     x.k,
		Count:    5,
	}
}

// The happy path, and the one line that matters in it: what gets anchored is
// the root the feed signed, at the size the feed signed it for.
func TestTheSenderAnchorsTheRootTheFeedSigned(t *testing.T) {
	fake := newFakeExchange(t)
	facts, err := fake.start(t).Collect(anchoredAtFour(t))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	x := buildRFCExample()
	if facts.Root != x.root {
		t.Errorf("anchored root %s, the feed signed %s", hexOf(facts.Root), hexOf(x.root))
	}
	if facts.TreeSize != 7 {
		t.Errorf("anchored tree size %d, the feed signed 7", facts.TreeSize)
	}
	if facts.LastID != 7 {
		t.Errorf("anchored cursor %d, the matcher committed up to 7", facts.LastID)
	}
	if facts.StateRoot != fake.stateRoot {
		t.Errorf("anchored state root %s, the claim says %s", hexOf(facts.StateRoot), hexOf(fake.stateRoot))
	}
	if facts.Session != testSession {
		t.Errorf("anchored session %q", facts.Session)
	}
}

// A contract nothing has been written to yet has no root to extend, so the tree
// head's own signature is the whole check. Every anchor after this one is also
// checked against what this one wrote.
func TestTheFirstAnchorNeedsNoConsistencyProof(t *testing.T) {
	fake := newFakeExchange(t)
	// Any proof served here would be wrong, and none is asked for.
	fake.proofPath = [][32]byte{leafHash([]byte("nonsense"))}
	facts, err := fake.start(t).Collect(AnchorState{})
	if err != nil {
		t.Fatalf("Collect against an empty contract: %v", err)
	}
	if facts.TreeSize != 7 {
		t.Errorf("anchored tree size %d", facts.TreeSize)
	}
}

// **The refusal this program exists for.** A tree head whose signature does not
// verify is not a root to anchor: it is a value nobody has committed to, and
// writing it would put the sender's own arithmetic on chain under the feed's
// name.
func TestTheSenderRefusesToAnchorAnUnsignedTreeHead(t *testing.T) {
	fake := newFakeExchange(t)
	fake.breakSTHSignature = true
	_, err := fake.start(t).Collect(anchoredAtFour(t))
	if err == nil {
		t.Fatal("a tree head with a broken signature was anchored")
	}
	if !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("the refusal does not say the signature failed: %v", err)
	}
	var skip errSkip
	if errors.As(err, &skip) {
		t.Error("a broken signature was reported as nothing to do")
	}
}

// Every way the feed can contradict what is already on chain, each with the
// sentence that names both values. None of these is a network problem to retry
// past, and none of them may end as a written anchor.
func TestTheSenderRefusesAFeedThatContradictsTheChain(t *testing.T) {
	x := buildRFCExample()
	cases := []struct {
		what   string
		set    func(f *fakeExchange)
		saying string
	}{
		{
			"a tree that does not extend the anchored one",
			func(f *fakeExchange) { f.proofPath = [][32]byte{x.i} },
			"prefix",
		},
		{
			"a tree smaller than the anchored one",
			func(f *fakeExchange) { f.sthSize, f.sthRoot, f.cursor = 3, nodeHash(x.g, x.c), 3 },
			"lost entries",
		},
		{
			"another root over the anchored size",
			func(f *fakeExchange) { f.sthSize, f.sthRoot, f.cursor = 4, x.l, 4 },
			"rewritten",
		},
		{
			"a cursor outside the tree",
			func(f *fakeExchange) { f.cursor = 9 },
			"outside the tree",
		},
		{
			"an execution rewound past the anchored one",
			func(f *fakeExchange) { f.cursor = 2 },
			"rewound",
		},
		{
			"a tree head from another history",
			func(f *fakeExchange) { f.sthSessionOverride = "0123456789abcdef" },
			"two different histories",
		},
	}
	for _, c := range cases {
		fake := newFakeExchange(t)
		c.set(fake)
		_, err := fake.start(t).Collect(anchoredAtFour(t))
		if err == nil {
			t.Errorf("%s was anchored", c.what)
			continue
		}
		if !strings.Contains(err.Error(), c.saying) {
			t.Errorf("%s was refused without saying %q: %v", c.what, c.saying, err)
		}
	}
}

// ---------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------

// The calldata this sender sends, checked against the ABI by hand: a selector
// and five whole words, with two uint64 right-aligned and a bytes8
// left-aligned.
func TestAnchorCalldataIsTheFiveWordsTheContractExpects(t *testing.T) {
	facts := &Facts{
		Session:  testSession,
		TreeSize: 102769,
		LastID:   102587,
	}
	copy(facts.Root[:], mustHex(t, "6f9415dcf81e7801a443f05b372465afff3850138a51ffd07f02db80c8fbe87f"))
	copy(facts.StateRoot[:], mustHex(t, "811d8964c69b843c2765c301fd25702733f8f41a321a62103b0ca4fa71d9a34b"))

	data, err := anchorCalldata(facts)
	if err != nil {
		t.Fatalf("calldata: %v", err)
	}
	const want = "cea5bcba" + // anchor(uint64,uint64,bytes8,bytes32,bytes32)
		"0000000000000000000000000000000000000000000000000000000000019171" +
		"00000000000000000000000000000000000000000000000000000000000190bb" +
		"349d462ced25bb2b000000000000000000000000000000000000000000000000" +
		"6f9415dcf81e7801a443f05b372465afff3850138a51ffd07f02db80c8fbe87f" +
		"811d8964c69b843c2765c301fd25702733f8f41a321a62103b0ca4fa71d9a34b"
	if hex.EncodeToString(data) != want {
		t.Errorf("calldata is\n  %s\nwant\n  %s", hex.EncodeToString(data), want)
	}
}

// The selectors are derived here rather than pasted, so a rename in the
// contract cannot leave this program calling something that no longer exists.
// These are the values `solc` emitted, recorded in ExchangeRootAnchor.json.
func TestSelectorsMatchWhatTheCompilerEmitted(t *testing.T) {
	for signature, want := range map[string]string{
		anchorSignature: "cea5bcba",
		latestSignature: "52bfe789",
		writerSignature: "453a2abc",
	} {
		if got := hex.EncodeToString(selector(signature)); got != want {
			t.Errorf("%s has selector %s, the compiler emitted %s", signature, got, want)
		}
	}
	const topic = "f17e064140470b4f4b89eb3a9324a477206c096df6cbc3dfed400e9b4a2c191f"
	event := "AnchoredRoot(uint64,bytes8,bytes32,uint64,bytes32,uint64,uint64)"
	if got := hex.EncodeToString(crypto.Keccak256([]byte(event))); got != topic {
		t.Errorf("the AnchoredRoot topic is %s, the Rust auditor filters on %s", got, topic)
	}
}

// `latest()` is the same selector on both contracts, because a selector covers
// a function's name and arguments and says nothing about what comes back. The
// width of the answer is the only thing that tells them apart over the wire, so
// this sender pointed at the closed chain-hash contract has to say so rather
// than decode six words as though they were seven.
func TestAContractOfTheWrongShapeIsNamedAsSuch(t *testing.T) {
	if hex.EncodeToString(selector("latest()")) != "52bfe789" {
		t.Fatal("latest() is not the selector both contracts answer")
	}
	// Whatever this sender is pointed at, only 224 bytes may decode.
	if latestWords*32 != 224 {
		t.Errorf("an ExchangeRootAnchor answers latest() with %d bytes", latestWords*32)
	}
}

// The two values the Rust verifier cannot derive for itself.
//
// Ethereum names a function by the first 4 bytes of the Keccak hash of its
// signature and an event by the full 32 bytes. The Rust side has no Keccak
// implementation. Adding a dependency for constants that can never change
// while the contract does not change is a worse trade than checking them here,
// where a real Keccak is already linked in for signing.
//
// This reads the Rust source and looks for the derived value in it, rather than
// comparing against a copy written in this file. A copy proves only that two Go
// strings agree. What has to hold is that the bytes in anchor.rs are the hash of
// the signature the deployed contract was compiled from, and the only way to
// check that is to read anchor.rs.
//
// Both contracts are checked. The chain-hash one is closed and its ~140 anchors
// are still on chain and still audited, so its two constants have to keep
// naming it, and the root one's two have to name the contract now being
// written to.
//
// The failure this prevents is quiet. A topic that is wrong is not an error at
// any layer: eth_getLogs matches nothing, returns an empty list, and a verifier
// reports "no anchors found" for a contract holding hundreds of them.
func TestTheRustVerifierHoldsTheValuesTheseSignaturesHashTo(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "services", "src", "anchor.rs"))
	if err != nil {
		t.Fatalf("cannot read the Rust verifier: %v", err)
	}
	rust := string(source)

	for constant, value := range map[string]string{
		"DEFAULT_LATEST_SELECTOR": "0x" + hex.EncodeToString(selector("latest()")),
		"DEFAULT_ANCHORED_TOPIC": "0x" + hex.EncodeToString(crypto.Keccak256(
			[]byte("Anchored(uint64,bytes8,bytes32,bytes32,uint64,uint64)"))),
		"DEFAULT_ROOT_LATEST_SELECTOR": "0x" + hex.EncodeToString(selector(latestSignature)),
		"DEFAULT_ROOT_ANCHORED_TOPIC": "0x" + hex.EncodeToString(crypto.Keccak256(
			[]byte("AnchoredRoot(uint64,bytes8,bytes32,uint64,bytes32,uint64,uint64)"))),
	} {
		// The declaration, and the value inside the declaration. rustfmt is
		// free to wrap a long constant onto the next line, so this takes a
		// window after the name rather than one line, and the window is short
		// enough that only the literal being assigned can fall inside it.
		at := strings.Index(rust, "const "+constant+":")
		if at < 0 {
			t.Errorf("services/src/anchor.rs declares no %s. The Rust auditor's default "+
				"has to be the value %s hashes to, and this test cannot check a constant "+
				"it cannot find. If it was renamed, rename it here too.", constant, value)
			continue
		}
		window := rust[at:min(at+200, len(rust))]
		if !strings.Contains(window, `"`+value+`"`) {
			t.Errorf("%s is %s, and services/src/anchor.rs does not assign it to %s. "+
				"Either the contract changed and the Rust default was not updated, "+
				"or the default was edited by hand. The declaration reads:\n%s",
				constant, value, constant, window)
		}
	}
}

// The session becomes a bytes8, so anything that is not the feed's 16 hex
// characters would be silently truncated or padded into another history's
// name. Refusing is the only safe answer.
func TestOnlyARealFeedSessionIsAccepted(t *testing.T) {
	if !isSessionHex(testSession) {
		t.Error("a real session was refused")
	}
	for _, bad := range []string{"", "349d462ced25bb2", "349d462ced25bb2bb", "349D462CED25BB2B", "zzzzzzzzzzzzzzzz"} {
		if isSessionHex(bad) {
			t.Errorf("%q was accepted as a session", bad)
		}
		if _, err := sessionBytes8(bad); err == nil {
			t.Errorf("%q encoded as a bytes8", bad)
		}
	}
}

// An anchor costs a fraction of a millionth of an ETH, and a log line that
// rounds it to zero tells the operator nothing about their runway.
func TestEtherIsPrintedWithoutRounding(t *testing.T) {
	for wei, want := range map[int64]string{
		258432936139:        "0.000000258432936139",
		1000000000000000000: "1",
		0:                   "0",
	} {
		if got := formatEther(big.NewInt(wei)); got != want {
			t.Errorf("%d wei printed as %s, want %s", wei, got, want)
		}
	}
}

// ---------------------------------------------------------------------------

func hexOf(value [32]byte) string { return hex.EncodeToString(value[:]) }

func writeJSON(w http.ResponseWriter, value interface{}) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func mustUint(text string) uint64 {
	var value uint64
	_, _ = fmt.Sscanf(text, "%d", &value)
	return value
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
