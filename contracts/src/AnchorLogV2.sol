// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice PABLA-v2 reference: permissionless signed checkpoints, schedule
/// inclusion and public same-period equivocation proofs. No user log data held.
/// @dev Exact digest and key-leaf codecs shared with pabla/v2/checkpoint.py.
contract AnchorLogV2 {
    address public immutable owner;
    bytes32 public constant CHECKPOINT_DOMAIN = hex"513061a742a200981b26ea7a8466fe0f13df827f381bdd18bc20d8c100a43933";
    bytes32 public constant KEY_TAG = hex"45dbd9d81df6ed4be02c7ce15e54ef47201d7989a5aac515c0be73f08466ab8a";
    uint256 internal constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct Checkpoint {
        bytes32 domain;
        bytes32 collector;
        uint64 epoch;
        uint64 period;
        uint64 size;
        bytes32 root;
        bytes32 prev;
        uint64 wallMs;
        bytes32 scheduleRoot;
    }
    struct Schedule { bytes32 root; uint64 first; uint8 height; }
    struct Head {uint64 period; uint64 size; bytes32 digest; bytes32 root;}

    mapping(bytes32 => mapping(uint64 => Schedule[])) private schedules;
    mapping(bytes32 => mapping(uint64 => Head)) public heads;
    mapping(bytes32 => mapping(uint64 => uint64)) public revokedAt;
    mapping(bytes32 => mapping(uint64 => mapping(uint64 => bytes32))) public anchoredDigest;

    event Registered(bytes32 indexed collector, uint64 indexed epoch, uint64 first, uint8 height, bytes32 root);
    event Anchored(bytes32 indexed collector, uint64 indexed epoch, uint64 indexed period, bytes32 digest, bytes32 root, uint64 size);
    event Equivocation(bytes32 indexed collector, uint64 indexed epoch, uint64 indexed period, bytes32 a, bytes32 b);
    event Revoked(bytes32 indexed collector, uint64 indexed epoch, uint64 blockNumber);
    error Unauthorized();
    error InvalidSchedule();
    error InvalidCheckpoint();
    error InvalidSignature();
    error InvalidProof();

    constructor() { owner = msg.sender; }

    function register(bytes32 collector, uint64 epoch, uint64 first, uint8 height, bytes32 root) external {
        if (msg.sender != owner) revert Unauthorized();
        if (collector == 0 || epoch == 0 || first != 1 || height == 0 || height > 24 || root == 0 || schedules[collector][epoch].length != 0) revert InvalidSchedule();
        schedules[collector][epoch].push(Schedule(root,first,height));
        emit Registered(collector,epoch,first,height,root);
    }

    function renew(bytes32 collector, uint64 epoch, uint64 first, uint8 height, bytes32 root) external {
        if (msg.sender != owner) revert Unauthorized();
        if (revokedAt[collector][epoch] != 0 || schedules[collector][epoch].length == 0 ||
            first != heads[collector][epoch].period+1 || root == 0 || height == 0 || height > 24) revert InvalidSchedule();
        schedules[collector][epoch].push(Schedule(root,first,height));
        emit Registered(collector,epoch,first,height,root);
    }

    function scheduleAt(bytes32 collector,uint64 epoch,uint64 period) public view returns (Schedule memory) {
        Schedule[] storage ss = schedules[collector][epoch];
        for (uint256 i=ss.length;i>0;--i) {
            Schedule memory s = ss[i-1];
            if (period >= s.first && uint256(period)-s.first < (uint256(1)<<s.height)) return s;
        }
        revert InvalidSchedule();
    }

    function checkpointDigest(Checkpoint memory cp) public pure returns (bytes32) {
        return sha256(abi.encode(cp.domain, cp.collector, cp.epoch, cp.period, cp.size,
                                 cp.root, cp.prev, cp.wallMs, cp.scheduleRoot));
    }
    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) revert InvalidSignature();
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset,32))
            v := byte(0,calldataload(add(signature.offset,64)))
        }
        if (v != 27 && v != 28 || uint256(s)==0 || uint256(s)>HALF_ORDER || uint256(r)==0) revert InvalidSignature();
        address signer = ecrecover(digest,v,r,s);
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }
    function _checkKey(Checkpoint memory cp,address signer,bytes32[] calldata proof) internal view {
        Schedule memory s = scheduleAt(cp.collector,cp.epoch,cp.period);
        if (cp.scheduleRoot != s.root || proof.length!=s.height) revert InvalidProof();
        uint256 index = cp.period-s.first;
        bytes32 current = sha256(abi.encode(KEY_TAG,cp.period,signer));
        for (uint256 j=0;j<proof.length;++j) {
            if ((index & 1) == 1) current=sha256(abi.encodePacked(bytes1(0x01),proof[j],current));
            else current=sha256(abi.encodePacked(bytes1(0x01),current,proof[j]));
            index >>= 1;
        }
        if (current != s.root) revert InvalidProof();
    }
    function _verify(Checkpoint memory cp,bytes calldata signature,bytes32[] calldata proof) internal view returns (bytes32) {
        if (cp.domain!=CHECKPOINT_DOMAIN || cp.collector==bytes32(0) || cp.epoch==0 || cp.period==0) revert InvalidCheckpoint();
        bytes32 digest=checkpointDigest(cp);
        _checkKey(cp,_recover(digest,signature),proof);
        return digest;
    }

    function anchor(Checkpoint calldata cp,bytes calldata signature,bytes32[] calldata proof) external {
        if (revokedAt[cp.collector][cp.epoch] != 0) revert Unauthorized();
        bytes32 digest = _verify(cp,signature,proof);
        Head storage h = heads[cp.collector][cp.epoch];
        if (cp.period!=h.period+1 || cp.size<h.size || cp.prev != h.digest || anchoredDigest[cp.collector][cp.epoch][cp.period]!=0) revert InvalidCheckpoint();
        h.period=cp.period;h.size=cp.size;h.digest=digest;h.root=cp.root;
        anchoredDigest[cp.collector][cp.epoch][cp.period]=digest;
        emit Anchored(cp.collector,cp.epoch,cp.period,digest,cp.root,cp.size);
    }

    function revoke(bytes32 collector,uint64 epoch) external {
        if (msg.sender!=owner) revert Unauthorized();
        if (schedules[collector][epoch].length==0 || revokedAt[collector][epoch]!=0) revert InvalidSchedule();
        revokedAt[collector][epoch]=uint64(block.number);
        emit Revoked(collector,epoch,uint64(block.number));
    }

    function proveEquivocation(
        Checkpoint calldata a,bytes calldata sigA,Checkpoint calldata b,bytes calldata sigB,
        bytes32[] calldata keyProof
    ) external {
        if (a.collector!=b.collector || a.epoch!=b.epoch || a.period!=b.period) revert InvalidCheckpoint();
        bytes32 da=_verify(a,sigA,keyProof);
        bytes32 db=_verify(b,sigB,keyProof);
        if (da==db) revert InvalidCheckpoint();
        if (revokedAt[a.collector][a.epoch]!=0) revert InvalidCheckpoint();
        revokedAt[a.collector][a.epoch]=uint64(block.number);
        emit Equivocation(a.collector,a.epoch,a.period,da,db);
        emit Revoked(a.collector,a.epoch,uint64(block.number));
    }
}
