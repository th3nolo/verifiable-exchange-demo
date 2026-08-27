package main

// RFC 9162 hashing, and the one proof this sender has to check.
//
// The feed signs a tree head: a size and a root. The sender's job is to write
// that root to a contract only when it extends the root already there, and a
// consistency proof is what says so in about 17 hashes where re-folding the
// history says it in 100,000 messages.
//
// Only verification lives here. Building proofs is the feed's job, and the
// sender never needs a root it was not given: the root comes from the signed
// tree head, and the earlier root comes off the chain.
//
// `services/src/merkle.rs` is the same RFC on the Rust side. The two are
// separate transcriptions on purpose: `anchor_test.go` runs both against the
// worked example in RFC 9162 section 2.1.5, so a mistake in one shows up as a
// disagreement rather than as two copies of itself.

import "crypto/sha256"

// The two prefix bytes of RFC 9162 section 2.1.1.
//
// They are not decoration. Without them an internal node can be presented as a
// leaf, and a proof can be produced for data nobody submitted. See
// docs/ENGINE.md section 1.1.
const (
	leafPrefix byte = 0x00
	nodePrefix byte = 0x01
)

// leafHash is MTH({d}) = HASH(0x00 || d).
func leafHash(entry []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(entry)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// nodeHash is HASH(0x01 || left || right).
func nodeHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// emptyRoot is MTH({}) = HASH(), the hash of nothing at all.
func emptyRoot() [32]byte {
	return sha256.Sum256(nil)
}

// verifyConsistency reports whether the tree of size `first` with root
// `firstHash` is a prefix of the tree of size `second` with root `secondHash`.
// RFC 9162 section 2.1.4.2, step by step.
//
// "Prefix" is the whole point: it says entries were appended, and never
// changed, removed or reordered. That is the property the hash chain used to
// carry, at the cost of reading every message to check it.
//
// The RFC covers 0 < first < second. The three sizes outside that range are
// decided before the RFC's steps begin and are marked below.
func verifyConsistency(first, second uint64, firstHash, secondHash [32]byte, path [][32]byte) bool {
	// Outside the RFC. A consistency proof only runs forwards.
	if first > second {
		return false
	}
	// Outside the RFC. The empty tree is a prefix of every tree, so there is
	// nothing to prove; but firstHash must really be the empty tree's root, or
	// the caller is claiming something else is empty. secondHash is not
	// checked, because nothing here can check it: "the empty tree is a prefix
	// of X" is true whatever X is.
	if first == 0 {
		return len(path) == 0 && firstHash == emptyRoot()
	}
	// Outside the RFC. The same tree twice: nothing to prove, but the two
	// heads must be the same head.
	if first == second {
		return len(path) == 0 && firstHash == secondHash
	}

	// Step 1.
	if len(path) == 0 {
		return false
	}
	// Step 2. A `first` that is a power of two means D[0:first] is itself a
	// perfect subtree of the second tree, so the log does not send that node:
	// the verifier already holds it as firstHash.
	full := make([][32]byte, 0, len(path)+1)
	if first&(first-1) == 0 {
		full = append(full, firstHash)
	}
	full = append(full, path...)

	// Step 3.
	fnode := first - 1
	snode := second - 1
	// Step 4. Climb out of the first tree's own right edge before comparing
	// the two trees.
	for fnode&1 == 1 {
		fnode >>= 1
		snode >>= 1
	}
	// Step 5. fr rebuilds the old root and sr the new one, and both start from
	// the same node. That shared start is what makes this one proof about two
	// trees rather than two unrelated climbs.
	fr := full[0]
	sr := full[0]
	// Step 6.
	for _, c := range full[1:] {
		// Step 6(a). A proof longer than the climb to the root is refused here
		// rather than folding extra nodes into the answer.
		if snode == 0 {
			return false
		}
		if fnode&1 == 1 || fnode == snode {
			// Step 6(b)(i) and 6(b)(ii). This node is in both trees, so it
			// feeds both rebuilds.
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			// Step 6(b)(iii).
			for fnode&1 == 0 && fnode != 0 {
				fnode >>= 1
				snode >>= 1
			}
		} else {
			// Step 6(b), "Otherwise", (i). This node covers entries the first
			// tree did not have, so it feeds the new root only.
			sr = nodeHash(sr, c)
		}
		// Step 6(c).
		fnode >>= 1
		snode >>= 1
	}
	// Step 7. snode != 0 means the proof ran out before the root, so a short
	// proof is refused as well as a long one.
	return snode == 0 && fr == firstHash && sr == secondHash
}
