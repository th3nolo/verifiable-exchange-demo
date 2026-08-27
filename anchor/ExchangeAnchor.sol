// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// A periodic, external commitment to one exchange's history.
///
/// The exchange already signs its history (a hash chain over the feed's
/// messages) and its execution (state roots inside signed claims), and anyone
/// can re-execute both. What none of that gives is a record outside the
/// operator's own machine. An operator can stop, delete the databases, replay
/// a different history, re-sign every statement consistently, restart, and an
/// auditor arriving afterwards sees a coherent exchange that passes every
/// check.
///
/// This contract is that outside record. Every 30 minutes the sender writes
/// one tuple:
///
///   lastId     the feed message the exchange had committed up to,
///   session    the feed history those ids belong to,
///   chainHash  SHA-256 chain over feed messages 1..lastId,
///   stateRoot  the matcher's own signed state root after message lastId.
///
/// Both hashes are for the same position in the same history, so "at 14:00
/// message 12859 of history 349d46... hashed to X and left the engine in state
/// Y" becomes a fact with a block number on it. Re-running that history
/// afterwards either reproduces both values or does not.
///
/// What it does not do: it says nothing about whether the exchange was honest
/// at the moment it was written. An operator who is dishonest from the start
/// anchors their dishonest history quite happily. What it removes is the
/// ability to change the answer *later*.
contract ExchangeAnchor {
    /// The only account that may write, fixed at deployment.
    ///
    /// Without a guard, anyone could write into this contract and `latest()`
    /// would mean "whatever the last stranger said", which is both a way to
    /// fail an honest exchange's audit and a way to bury a real anchor under
    /// noise. With it, every entry here is the deployer's own commitment,
    /// which is exactly the thing they cannot take back later.
    ///
    /// Immutable rather than an owner that can be transferred: this is one
    /// history's record, and the guarantee is stronger when nothing about it
    /// can be reassigned. Anyone else who wants to anchor this same exchange
    /// deploys their own copy and publishes the address. A third party's
    /// anchor is better evidence than the operator's own, because the
    /// operator's sender is still the operator. The auditor's flag takes any
    /// address.
    address public immutable writer;

    /// The newest anchor. These four share one 32-byte storage slot, so
    /// writing them costs one SSTORE rather than four.
    uint64 public lastId;
    uint64 public anchoredAt;
    uint64 public count;
    bytes8 public session;

    bytes32 public chainHash;
    bytes32 public stateRoot;

    /// The full history, readable by anyone from the logs. `lastId` and
    /// `session` are indexed so a reader can ask for one history, or for the
    /// anchor covering a particular message, without reading every entry.
    event Anchored(
        uint64 indexed lastId,
        bytes8 indexed session,
        bytes32 chainHash,
        bytes32 stateRoot,
        uint64 anchoredAt,
        uint64 count
    );

    error NotWriter();
    error NoSession();
    error SessionChanged();
    error NotNewer();

    constructor() {
        writer = msg.sender;
    }

    /// Records one anchor.
    ///
    /// Two rules, and both exist to stop this contract from being used to
    /// undo what it already recorded:
    ///
    /// - the session is fixed by the first anchor. A new feed history means
    ///   the ids restart at 1 and the chain restarts from zero, so an anchor
    ///   for a different history is not a later entry in this record, it is a
    ///   different record. Wiping the feed and starting again is the exact
    ///   event this contract exists to expose, so it is refused here and the
    ///   operator has to deploy a second contract and publish that address,
    ///   in public, permanently, where an auditor pointed at the old one still
    ///   sees the anchor for the history that was thrown away.
    /// - `lastId` only moves forward. A rewound exchange cannot overwrite the
    ///   state slot with a lower position, so a single `eth_call` for
    ///   `latest()` is always the furthest-forward commitment ever made, and a
    ///   verifier that reads nothing but state loses nothing.
    function anchor(uint64 _lastId, bytes8 _session, bytes32 _chainHash, bytes32 _stateRoot)
        external
    {
        if (msg.sender != writer) revert NotWriter();
        if (_session == bytes8(0)) revert NoSession();
        if (session == bytes8(0)) {
            session = _session;
        } else if (_session != session) {
            revert SessionChanged();
        }
        if (_lastId <= lastId) revert NotNewer();

        lastId = _lastId;
        chainHash = _chainHash;
        stateRoot = _stateRoot;
        anchoredAt = uint64(block.timestamp);
        count += 1;

        emit Anchored(_lastId, _session, _chainHash, _stateRoot, uint64(block.timestamp), count);
    }

    /// The newest anchor in one call, so a verifier needs one JSON-RPC request
    /// and no log scanning. Six fixed-width values, which is a fixed 192-byte
    /// return: readable without an ABI decoder, which is what lets the Rust
    /// auditor check this over plain HTTP with no Ethereum library.
    function latest()
        external
        view
        returns (
            uint64 _lastId,
            bytes8 _session,
            bytes32 _chainHash,
            bytes32 _stateRoot,
            uint64 _anchoredAt,
            uint64 _count
        )
    {
        return (lastId, session, chainHash, stateRoot, anchoredAt, count);
    }
}
