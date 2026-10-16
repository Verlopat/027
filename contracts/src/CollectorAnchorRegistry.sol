// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice Minimal experiment-local registry and immutable anchor ledger.
/// Ed25519 signature checking is done off-chain. The contract authorizes the
/// transaction sender and commits only hashes. Never use this contract to prove
/// that the logged event was truthful or complete at its real-world source.
contract CollectorAnchorRegistry {
    address public immutable owner;

    struct Epoch {
        bytes32 publicKey;
        address submitter;
        uint64 revokedBlock;
        bool exists;
        bytes32 recoveryCommitment;
    }
    struct Anchor {
        bytes32 manifestHash;
        bytes32 merkleRoot;
        bytes32 lastChain;
        uint64 firstSequence;
        uint64 lastSequence;
        uint64 blockNumber;
        uint64 blockTimestamp;
    }

    mapping(bytes32 => mapping(uint64 => Epoch)) private epochs;
    mapping(bytes32 => mapping(uint64 => mapping(uint64 => Anchor))) private anchors;
    mapping(bytes32 => mapping(uint64 => uint64)) public latestBatch;
    mapping(bytes32 => mapping(uint64 => uint64)) public latestSequence;

    event Registered(bytes32 indexed collector, uint64 indexed epoch, bytes32 publicKey, bytes32 recoveryCommitment);
    event Revoked(bytes32 indexed collector, uint64 indexed epoch, uint64 revocationBlock);
    event Anchored(bytes32 indexed collector, uint64 indexed epoch, uint64 indexed batchNumber, bytes32 manifestHash, bytes32 root);

    error Unauthorized();
    error InvalidEpoch();
    error InvalidAnchor();

    constructor() { owner = msg.sender; }

    function register(bytes32 collector, uint64 epoch, bytes32 publicKey, address submitter, bytes32 recoveryCommitment) external {
        if (msg.sender != owner) revert Unauthorized();
        if (collector == 0 || publicKey == 0 || submitter == address(0) || epoch == 0 || epochs[collector][epoch].exists) revert InvalidEpoch();
        if (epoch > 1 && (epoch == 0 || !epochs[collector][epoch - 1].exists || epochs[collector][epoch - 1].revokedBlock == 0)) revert InvalidEpoch();
        epochs[collector][epoch] = Epoch(publicKey, submitter, 0, true, recoveryCommitment);
        emit Registered(collector, epoch, publicKey, recoveryCommitment);
    }

    function revoke(bytes32 collector, uint64 epoch) external {
        if (msg.sender != owner) revert Unauthorized();
        Epoch storage entry = epochs[collector][epoch];
        if (!entry.exists || entry.revokedBlock != 0) revert InvalidEpoch();
        entry.revokedBlock = uint64(block.number);
        emit Revoked(collector, epoch, entry.revokedBlock);
    }

    function anchor(
        bytes32 collector, uint64 epoch, uint64 batchNumber, bytes32 manifestHash,
        bytes32 merkleRoot, bytes32 lastChain, uint64 firstSequence,
        uint64 lastSequence, bytes32 previousManifestHash
    ) external {
        Epoch storage entry = epochs[collector][epoch];
        if (!entry.exists || msg.sender != entry.submitter || entry.revokedBlock != 0) revert Unauthorized();
        if (manifestHash == 0 || merkleRoot == 0 || batchNumber == 0 || lastSequence < firstSequence) revert InvalidAnchor();
        if (batchNumber != latestBatch[collector][epoch] + 1) revert InvalidAnchor();
        if (firstSequence != latestSequence[collector][epoch] + 1) revert InvalidAnchor();
        if (anchors[collector][epoch][batchNumber].blockNumber != 0) revert InvalidAnchor();
        if (batchNumber == 1 && previousManifestHash != bytes32(0)) revert InvalidAnchor();
        if (batchNumber > 1 && previousManifestHash != bytes32(0) &&
            previousManifestHash != anchors[collector][epoch][batchNumber-1].manifestHash) revert InvalidAnchor();
        anchors[collector][epoch][batchNumber] = Anchor(manifestHash, merkleRoot, lastChain, firstSequence, lastSequence, uint64(block.number), uint64(block.timestamp));
        latestBatch[collector][epoch] = batchNumber;
        latestSequence[collector][epoch] = lastSequence;
        emit Anchored(collector, epoch, batchNumber, manifestHash, merkleRoot);
    }

    function getEpoch(bytes32 collector, uint64 epoch) external view returns (bytes32, address, uint64, bool, bytes32) {
        Epoch memory e = epochs[collector][epoch];
        return (e.publicKey, e.submitter, e.revokedBlock, e.exists, e.recoveryCommitment);
    }
    function getAnchor(bytes32 collector, uint64 epoch, uint64 batchNumber)
        external view returns (bytes32, bytes32, bytes32, uint64, uint64, uint64, uint64) {
        Anchor memory a = anchors[collector][epoch][batchNumber];
        return (a.manifestHash, a.merkleRoot, a.lastChain, a.firstSequence, a.lastSequence, a.blockNumber, a.blockTimestamp);
    }
}
