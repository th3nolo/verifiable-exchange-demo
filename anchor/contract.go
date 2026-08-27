package main

// Talking to the ExchangeRootAnchor contract.
//
// The ABI work here is hand-rolled rather than generated with abigen, and the
// reason is that there is nothing to generate: `anchor` takes five fixed-width
// arguments and `latest` returns seven, so the calldata is a 4-byte selector
// followed by whole 32-byte words with no offsets, no dynamic types and no
// tails. A code generator and a checked-in generated file would be more
// machinery than the twenty lines it replaces, and it would hide the one thing
// worth reading, that this wire format is simple enough to check by eye. The
// Rust auditor decodes the same 224 bytes with no Ethereum library at all.
//
// What is *not* hand-rolled is anything cryptographic: the key handling,
// keccak, the RLP of an EIP-1559 transaction and the secp256k1 signature all
// come from go-ethereum. Those are exactly the parts nobody should reimplement.

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	anchorSignature = "anchor(uint64,uint64,bytes8,bytes32,bytes32)"
	latestSignature = "latest()"
	writerSignature = "writer()"

	// How wide `latest()`'s answer is: seven fixed-width values, so seven
	// whole words.
	//
	// This width is the only thing that tells an ExchangeRootAnchor apart from
	// the closed chain-hash ExchangeAnchor over the wire. Both declare
	// `latest()`, so both answer the same selector. A selector covers the
	// name and the arguments and says nothing about what comes back. The old
	// contract returns six words. Pointing this sender at it therefore fails
	// here, saying so, rather than sending a transaction that reverts.
	latestWords = 7

	// How long to wait for one anchor to be mined, and how often to ask.
	// Base produces a block every two seconds.
	receiptTimeout = 3 * time.Minute
	receiptPoll    = 2 * time.Second
)

func selector(signature string) []byte {
	return crypto.Keccak256([]byte(signature))[:4]
}

// AnchorState is what `latest()` returns.
type AnchorState struct {
	TreeSize   uint64
	LastID     uint64
	Session    [8]byte
	Root       [32]byte
	StateRoot  [32]byte
	AnchoredAt uint64
	Count      uint64
}

// Empty reports whether this contract has never been written to.
func (a AnchorState) Empty() bool { return a.Count == 0 }

// errWrongContract is what `latest()` answering the wrong width means: the
// address holds something that is not an ExchangeRootAnchor. It is a separate
// type because it is the one contract error that never gets better by itself,
// so startup exits on it while every other RPC failure is left to the next
// tick.
type errWrongContract struct{ reason string }

func (e errWrongContract) Error() string { return e.reason }

// Anchorer sends anchors to one contract with one key.
type Anchorer struct {
	client   *ethclient.Client
	address  common.Address
	chainID  *big.Int
	key      *Signer
	gasLimit uint64
}

func NewAnchorer(ctx context.Context, client *ethclient.Client, address common.Address, key *Signer) (*Anchorer, error) {
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot read the chain id: %w", err)
	}
	return &Anchorer{client: client, address: address, chainID: chainID, key: key}, nil
}

func (a *Anchorer) ChainID() *big.Int { return a.chainID }

// Latest reads the newest anchor in one eth_call.
func (a *Anchorer) Latest(ctx context.Context) (AnchorState, error) {
	var state AnchorState
	data := selector(latestSignature)
	out, err := a.client.CallContract(ctx, ethereum.CallMsg{To: &a.address, Data: data}, nil)
	if err != nil {
		return state, fmt.Errorf("cannot read %s: %w", a.address, err)
	}
	if len(out) != latestWords*32 {
		return state, errWrongContract{reason: fmt.Sprintf(
			"%s answered latest() with %d bytes, not the %d an ExchangeRootAnchor returns. The closed "+
				"chain-hash ExchangeAnchor answers the same selector with 192 bytes; this sender writes "+
				"Merkle roots and cannot write to it. Point -contract, ANCHOR_CONTRACT or the deployment "+
				"record at the root anchor",
			a.address, len(out), latestWords*32)}
	}
	// Seven static words. A uint64 is right-aligned in its word, a bytes8 is
	// left-aligned, a bytes32 fills one.
	state.TreeSize = binary.BigEndian.Uint64(out[24:32])
	state.LastID = binary.BigEndian.Uint64(out[56:64])
	copy(state.Session[:], out[64:72])
	copy(state.Root[:], out[96:128])
	copy(state.StateRoot[:], out[128:160])
	state.AnchoredAt = binary.BigEndian.Uint64(out[184:192])
	state.Count = binary.BigEndian.Uint64(out[216:224])
	return state, nil
}

// Writer is the only account the contract accepts anchors from.
func (a *Anchorer) Writer(ctx context.Context) (common.Address, error) {
	out, err := a.client.CallContract(ctx, ethereum.CallMsg{To: &a.address, Data: selector(writerSignature)}, nil)
	if err != nil {
		return common.Address{}, err
	}
	if len(out) != 32 {
		return common.Address{}, fmt.Errorf("%s answered writer() with %d bytes", a.address, len(out))
	}
	return common.BytesToAddress(out[12:32]), nil
}

// anchorCalldata is the selector followed by five 32-byte words: two uint64
// right-aligned, a bytes8 left-aligned, and two bytes32 as they are.
func anchorCalldata(f *Facts) ([]byte, error) {
	session, err := sessionBytes8(f.Session)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 4+5*32)
	data = append(data, selector(anchorSignature)...)
	var word [32]byte
	binary.BigEndian.PutUint64(word[24:32], f.TreeSize)
	data = append(data, word[:]...)
	word = [32]byte{}
	binary.BigEndian.PutUint64(word[24:32], f.LastID)
	data = append(data, word[:]...)
	word = [32]byte{}
	copy(word[:8], session[:]) // bytes8 is left-aligned in its word
	data = append(data, word[:]...)
	data = append(data, f.Root[:]...)
	data = append(data, f.StateRoot[:]...)
	return data, nil
}

// sessionBytes8 is the feed's 16 hex characters as the 8 bytes the contract
// stores. Anything else would be silently truncated or padded into a different
// history's name, so it is refused instead.
func sessionBytes8(session string) ([8]byte, error) {
	var out [8]byte
	if !isSessionHex(session) {
		return out, fmt.Errorf("%q is not a 16-character feed session", session)
	}
	raw, err := hex.DecodeString(session)
	if err != nil {
		return out, fmt.Errorf("%q is not hex: %w", session, err)
	}
	copy(out[:], raw)
	return out, nil
}

// Receipt is what one landed anchor cost, including the L1 data fee that an
// L2-only estimate misses.
type Receipt struct {
	TxHash      common.Hash
	BlockNumber uint64
	GasUsed     uint64
	GasPrice    *big.Int
	L1Fee       *big.Int
}

// Total is the whole cost in wei: L2 execution plus L1 data.
func (r Receipt) Total() *big.Int {
	total := new(big.Int).Mul(new(big.Int).SetUint64(r.GasUsed), r.GasPrice)
	if r.L1Fee != nil {
		total.Add(total, r.L1Fee)
	}
	return total
}

// Send builds, signs and sends one anchor, then waits for it to land.
func (a *Anchorer) Send(ctx context.Context, f *Facts) (*Receipt, error) {
	data, err := anchorCalldata(f)
	if err != nil {
		return nil, err
	}
	from := a.key.Address()
	nonce, err := a.client.PendingNonceAt(ctx, from)
	if err != nil {
		return nil, fmt.Errorf("cannot read the nonce for %s: %w", from, err)
	}
	tip, err := a.client.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot read a gas tip: %w", err)
	}
	header, err := a.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot read the latest block: %w", err)
	}
	baseFee := header.BaseFee
	if baseFee == nil {
		baseFee = big.NewInt(0)
	}
	// Room for the base fee to double before this lands, which is the usual
	// headroom and still costs only what the block charges.
	feeCap := new(big.Int).Add(tip, new(big.Int).Mul(baseFee, big.NewInt(2)))

	gas, err := a.client.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &a.address, Data: data})
	if err != nil {
		return nil, fmt.Errorf("the anchor call would revert: %w", err)
	}
	tx, err := a.key.Sign(types.NewTx(&types.DynamicFeeTx{
		ChainID:   a.chainID,
		Nonce:     nonce,
		GasTipCap: tip,
		GasFeeCap: feeCap,
		Gas:       gas + gas/5,
		To:        &a.address,
		Data:      data,
	}), a.chainID)
	if err != nil {
		return nil, err
	}
	if err := a.client.SendTransaction(ctx, tx); err != nil {
		return nil, fmt.Errorf("cannot send the anchor: %w", err)
	}
	return a.wait(ctx, tx.Hash())
}

// wait polls for the receipt and reads the L1 data fee off the raw JSON, which
// is an OP-stack field the typed receipt does not carry.
func (a *Anchorer) wait(ctx context.Context, hash common.Hash) (*Receipt, error) {
	deadline, cancel := context.WithTimeout(ctx, receiptTimeout)
	defer cancel()
	for {
		receipt, err := a.client.TransactionReceipt(deadline, hash)
		if err == nil {
			if receipt.Status != types.ReceiptStatusSuccessful {
				return nil, fmt.Errorf("anchor transaction %s reverted", hash)
			}
			out := &Receipt{
				TxHash:      hash,
				BlockNumber: receipt.BlockNumber.Uint64(),
				GasUsed:     receipt.GasUsed,
				GasPrice:    receipt.EffectiveGasPrice,
				L1Fee:       a.l1Fee(deadline, hash),
			}
			if out.GasPrice == nil {
				out.GasPrice = big.NewInt(0)
			}
			return out, nil
		}
		select {
		case <-deadline.Done():
			return nil, fmt.Errorf("anchor transaction %s did not land in %s", hash, receiptTimeout)
		case <-time.After(receiptPoll):
		}
	}
}

func (a *Anchorer) l1Fee(ctx context.Context, hash common.Hash) *big.Int {
	var raw struct {
		L1Fee string `json:"l1Fee"`
	}
	if err := a.client.Client().CallContext(ctx, &raw, "eth_getTransactionReceipt", hash); err != nil {
		return nil
	}
	if raw.L1Fee == "" {
		return nil
	}
	fee, ok := new(big.Int).SetString(trimHexPrefix(raw.L1Fee), 16)
	if !ok {
		return nil
	}
	return fee
}

func trimHexPrefix(s string) string {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return s[2:]
	}
	return s
}
