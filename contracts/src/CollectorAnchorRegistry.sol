// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice Minimal experiment-local registry and immutable anchor ledger.
/// Ed25519 signature checking is done off-chain. The contract authorizes the
/// transaction sender and commits only hashes. Never use this contract to prove
/// that the logged event was truthful or complete at its real-world source.
contract CollectorAnchorRegistry {
    address public immutable owner;
    bytes32 internal constant POLICY_P1 = hex"c0af4ce3b96e055e3f5e99bcc34ce9098ffacc2ed890c6ff8ebb8ea8b0c9a582";
    bytes32 internal constant POLICY_A1 = hex"4d32f9ec53cfa81adc0e879a7b5f5841036c4a1b3f6551e512406a5c65f98743";
    bytes32 internal constant POLICY_A4 = hex"1bb2fb697184ac1f11ebfeb084082c50000be06b967443c1f9ad5b657832237f";
    bytes32 internal constant POLICY_A5 = hex"81ad195a9708677a41db9f0d385dd6f3a9c391082e4b6864869ed26cbc8857d7";

    struct Epoch {
        bytes32 publicKey;
        address submitter;
        uint64 revokedBlock;
        bool exists;
        bytes32 recoveryCommitment;
        bytes32 policyId;
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

    event Registered(bytes32 indexed collector, uint64 indexed epoch, bytes32 publicKey, bytes32 recoveryCommitment, bytes32 policyId);
    event Revoked(bytes32 indexed collector, uint64 indexed epoch, uint64 revocationBlock);
    event Anchored(bytes32 indexed collector, uint64 indexed epoch, uint64 indexed batchNumber, bytes32 manifestHash, bytes32 root);

    error Unauthorized();
    error InvalidEpoch();
    error InvalidAnchor();

    constructor() { owner = msg.sender; }

    function register(bytes32 collector, uint64 epoch, bytes32 publicKey, address submitter, bytes32 recoveryCommitment, bytes32 policyId) external {
        if (msg.sender != owner) revert Unauthorized();
        if (collector == 0 || publicKey == 0 || submitter == address(0) || policyId == 0 || epoch == 0 || epochs[collector][epoch].exists) revert InvalidEpoch();
        if (epoch > 1 && (epoch == 0 || !epochs[collector][epoch - 1].exists || epochs[collector][epoch - 1].revokedBlock == 0)) revert InvalidEpoch();
        epochs[collector][epoch] = Epoch(publicKey, submitter, 0, true, recoveryCommitment, policyId);
        emit Registered(collector, epoch, publicKey, recoveryCommitment, policyId);
    }

    function revoke(bytes32 collector, uint64 epoch) external {
        if (msg.sender != owner) revert Unauthorized();
        Epoch storage entry = epochs[collector][epoch];
        if (!entry.exists || entry.revokedBlock != 0) revert InvalidEpoch();
        // Become effective from the *following* block for unambiguous same-block audit evidence.
        entry.revokedBlock = uint64(block.number + 1);
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
        if (batchNumber > 1) {
            // Policy identifiers computed by SHA-256 framed hashing off-chain and passed at registration.
            // For all policies, a nonzero link must match; the mandatory-link policies
            // are additionally guarded by policyId supplied on registration.
            if (previousManifestHash != bytes32(0) &&
                previousManifestHash != anchors[collector][epoch][batchNumber-1].manifestHash) revert InvalidAnchor();
            // These values are the pinned digest("PABLA-POLICY-v1", name) test vectors.
            if (entry.policyId == POLICY_P1 || entry.policyId == POLICY_A1 ||
                entry.policyId == POLICY_A4 || entry.policyId == POLICY_A5) {
                if (previousManifestHash != anchors[collector][epoch][batchNumber-1].manifestHash) revert InvalidAnchor();
            }
        }
        anchors[collector][epoch][batchNumber] = Anchor(manifestHash, merkleRoot, lastChain, firstSequence, lastSequence, uint64(block.number), uint64(block.timestamp));
        latestBatch[collector][epoch] = batchNumber;
        latestSequence[collector][epoch] = lastSequence;
        emit Anchored(collector, epoch, batchNumber, manifestHash, merkleRoot);
    }

    function getEpoch(bytes32 collector, uint64 epoch) external view returns (bytes32, address, uint64, bool, bytes32, bytes32) {
        Epoch memory e = epochs[collector][epoch];
        return (e.publicKey, e.submitter, e.revokedBlock, e.exists, e.recoveryCommitment, e.policyId);
    }
    function getAnchor(bytes32 collector, uint64 epoch, uint64 batchNumber)
        external view returns (bytes32, bytes32, bytes32, uint64, uint64, uint64, uint64) {
        Anchor memory a = anchors[collector][epoch][batchNumber];
        return (a.manifestHash, a.merkleRoot, a.lastChain, a.firstSequence, a.lastSequence, a.blockNumber, a.blockTimestamp);
    }
}
