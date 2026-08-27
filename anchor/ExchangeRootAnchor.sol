// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// A periodic, external commitment to one exchange's history, as a Merkle
/// root.
///
/// This is `ExchangeAnchor` with one value replaced and one added, and it is a
/// separate contract rather than an edit for a reason that is not bookkeeping.
/// `ExchangeAnchor` commits `chainHash`: SHA-256 folded over every message from
/// the first to `lastId`. Proving one trade sits inside that value needs every
/// message in the window, 1.7 MB, measured. This contract commits `rootHash`:
/// the RFC 9162 Merkle root the feed signs in its tree head. Proving one trade
/// sits inside *that* needs about 17 node hashes, 544 bytes, and runs in a
/// browser.
///
/// # Why the old contract is not reused
///
/// A root is 32 bytes and so is a chain hash, so a root would fit in
/// `ExchangeAnchor`'s `chainHash` slot and every transaction would succeed.
/// Two things make that wrong, and only the second is unfixable:
///
/// - the field would be named `chainHash` forever, in the ABI, in the event,
///   and in every block explorer that decodes it. A contract is what a stranger
///   reads when they do not believe the documentation.
/// - **nothing on chain would say which anchors are which.** Both values are 32
///   bytes of hash. A verifier reading the log would need a rule from outside
///   the log, "entries after the 143rd are roots", held in a binary or a
///   configuration file, which is exactly what `docs/ENGINE.md` section 3
///   forbids. Here the event signature settles it: `Anchored(...)` and
///   `AnchoredRoot(...)` hash to different topics, so one `eth_getLogs` filter
///   returns chain anchors and the other returns root anchors, and neither can
///   return the other kind. The old contract keeps its anchors, still readable,
///   still checkable, and closed.
///
/// # The five values, and why two positions rather than one
///
/// ```text
/// treeSize   how many messages were in the Merkle tree, from the feed's own
///            signed tree head. The tree holds messages 1..treeSize.
/// lastId     the matcher's durable cursor: the last message it has committed
///            to its state database.
/// session    the feed history both numbers belong to. Sizes and ids restart
///            at 1 when a history is replaced, so either without a session
///            names nothing.
/// rootHash   the RFC 9162 root over messages 1..treeSize, copied from the
///            signed tree head. The sender checks that Ed25519 signature
///            before it builds this transaction and writes nothing if it does
///            not verify.
/// stateRoot  the root_after of the matcher's own signed claim whose to_msg is
///            exactly lastId.
/// ```
///
/// `ExchangeAnchor` forced all four of its values to one position, and paid
/// for it: the sender had to fold the whole history itself to get the chain at
/// the cursor, because the feed only ever signs the chain at its own head. A
/// tree head cannot be re-derived at an earlier size either, so this contract
/// stops pretending and carries both positions. Each value now stands at a
/// number that a signature covers: `rootHash` at `treeSize` under the feed's
/// tree-head signature, `stateRoot` at `lastId` under the matcher's claim
/// signature. `lastId <= treeSize` is enforced below, so the messages the
/// execution claims to have applied are always inside the tree that was
/// anchored.
contract ExchangeRootAnchor {
    /// The only account that may write, fixed at deployment.
    ///
    /// Without a guard, anyone could write here and `latest()` would mean
    /// "whatever the last stranger said", which is both a way to fail an
    /// honest exchange's audit and a way to bury a real anchor under noise.
    /// With it, every entry is the deployer's own commitment, which is exactly
    /// the thing they cannot take back later.
    ///
    /// Immutable rather than transferable: this is one history's record, and
    /// the guarantee is stronger when nothing about it can be reassigned.
    /// Anyone else who wants to anchor this same exchange deploys their own
    /// copy and publishes the address. A third party's anchor is better
    /// evidence than the operator's own, because the operator's sender is
    /// still the operator.
    address public immutable writer;

    /// The newest anchor. These four are 8 bytes each and share one 32-byte
    /// storage slot, so they cost one SSTORE between them.
    uint64 public treeSize;
    uint64 public lastId;
    uint64 public anchoredAt;
    uint64 public count;

    bytes8 public session;
    bytes32 public rootHash;
    bytes32 public stateRoot;

    /// The full history, readable by anyone from the logs, and what the
    /// auditor actually checks. `treeSize` and `session` are indexed so a
    /// reader can ask for one history, or for the anchor covering a particular
    /// leaf, without reading every entry.
    ///
    /// The signature of this event is what tells a reader they are looking at
    /// a root and not a chain. Renaming it, or reordering its arguments,
    /// changes the topic and makes every anchor written before the change
    /// invisible to a filter built for the new one.
    event AnchoredRoot(
        uint64 indexed treeSize,
        bytes8 indexed session,
        bytes32 rootHash,
        uint64 lastId,
        bytes32 stateRoot,
        uint64 anchoredAt,
        uint64 count
    );

    error NotWriter();
    error NoSession();
    error SessionChanged();
    error NotNewer();
    error CursorOutsideTree();
    error CursorWentBack();

    constructor() {
        writer = msg.sender;
    }

    /// Records one anchor.
    ///
    /// Four rules, all of them there to stop this contract being used to undo
    /// what it already recorded:
    ///
    /// - the session is fixed by the first anchor. A new feed history means
    ///   the sizes restart at 0 and the root restarts from the empty tree, so
    ///   an anchor for a different history is not a later entry in this
    ///   record, it is a different record. Wiping the feed and starting again
    ///   is the exact event this contract exists to expose, so it is refused
    ///   here and the operator has to deploy a second contract and publish
    ///   that address, in public, permanently, where an auditor pointed at
    ///   the old one still sees the anchor for the history that was thrown
    ///   away.
    /// - `treeSize` only moves forward. A rewound feed cannot overwrite the
    ///   state slot with a smaller tree, so `latest()` is always the furthest
    ///   commitment ever made.
    /// - `lastId` only moves forward, for the same reason applied to
    ///   execution: a matcher replaying less than it had already committed to
    ///   cannot quietly replace the state root that was anchored.
    /// - `lastId <= treeSize`. The state root stands after message `lastId`
    ///   and the anchored tree holds messages 1..`treeSize`. A cursor past the
    ///   tree would be an execution claim about messages this anchor does not
    ///   commit to, which is a tuple nobody can check.
    function anchor(
        uint64 _treeSize,
        uint64 _lastId,
        bytes8 _session,
        bytes32 _rootHash,
        bytes32 _stateRoot
    ) external {
        if (msg.sender != writer) revert NotWriter();
        if (_session == bytes8(0)) revert NoSession();
        if (session == bytes8(0)) {
            session = _session;
        } else if (_session != session) {
            revert SessionChanged();
        }
        if (_treeSize <= treeSize) revert NotNewer();
        if (_lastId > _treeSize) revert CursorOutsideTree();
        if (_lastId < lastId) revert CursorWentBack();

        treeSize = _treeSize;
        lastId = _lastId;
        rootHash = _rootHash;
        stateRoot = _stateRoot;
        anchoredAt = uint64(block.timestamp);
        count += 1;

        emit AnchoredRoot(
            _treeSize, _session, _rootHash, _lastId, _stateRoot, uint64(block.timestamp), count
        );
    }

    /// The newest anchor in one call, so a verifier needs one JSON-RPC request
    /// and no log scanning. Seven fixed-width values, which is a fixed
    /// 224-byte return: readable by slicing, with no ABI decoder, which is
    /// what lets the Rust auditor check this over plain HTTP with no Ethereum
    /// library.
    function latest()
        external
        view
        returns (
            uint64 _treeSize,
            uint64 _lastId,
            bytes8 _session,
            bytes32 _rootHash,
            bytes32 _stateRoot,
            uint64 _anchoredAt,
            uint64 _count
        )
    {
        return (treeSize, lastId, session, rootHash, stateRoot, anchoredAt, count);
    }
}
