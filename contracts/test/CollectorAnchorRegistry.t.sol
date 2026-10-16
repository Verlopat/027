// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;
import "../src/CollectorAnchorRegistry.sol";

contract Outsider {
    function submit(CollectorAnchorRegistry target, bytes32 collector) external returns (bool, bytes memory) {
        return address(target).call(abi.encodeWithSelector(target.anchor.selector,
            collector,uint64(1),uint64(1),bytes32(uint256(2)),bytes32(uint256(3)),
            bytes32(uint256(4)),uint64(1),uint64(2),bytes32(0)));
    }
}

contract RegistryTest {
    function testRegistrationAndAnchor() public {
        CollectorAnchorRegistry r = new CollectorAnchorRegistry();
        bytes32 c = keccak256("collector-a");
        r.register(c,1,bytes32(uint256(5)),address(this),0,bytes32(uint256(1)));
        r.anchor(c,1,1,bytes32(uint256(10)),bytes32(uint256(20)),bytes32(uint256(30)),1,2,0);
        (, , ,uint64 first,uint64 last,uint64 blk,) = r.getAnchor(c,1,1);
        require(first == 1 && last == 2 && blk > 0,"anchor mismatch");
        (bool duplicate,) = address(r).call(abi.encodeWithSelector(r.anchor.selector,
            c,uint64(1),uint64(1),bytes32(uint256(10)),bytes32(uint256(20)),
            bytes32(uint256(30)),uint64(1),uint64(2),bytes32(0)));
        require(!duplicate, "duplicate anchor accepted");
        r.anchor(c,1,2,bytes32(uint256(11)),bytes32(uint256(21)),bytes32(uint256(31)),3,4,bytes32(uint256(10)));
        (bool gap,) = address(r).call(abi.encodeWithSelector(r.anchor.selector,
            c,uint64(1),uint64(3),bytes32(uint256(12)),bytes32(uint256(22)),
            bytes32(uint256(32)),uint64(6),uint64(7),bytes32(uint256(11))));
        require(!gap,"sequence gap accepted");
    }
    function testRevocationAndRotation() public {
        CollectorAnchorRegistry r = new CollectorAnchorRegistry();
        bytes32 c=keccak256("collector-b");
        r.register(c,1,bytes32(uint256(5)),address(this),0,bytes32(uint256(1)));
        Outsider attacker = new Outsider();
        (bool outsiderAccepted, bytes memory revertData) = attacker.submit(r,c);
        require(!outsiderAccepted, "unauthorized sender accepted under active epoch");
        require(revertData.length >= 4, "missing unauthorized selector");
        bytes4 selector;
        assembly { selector := mload(add(revertData, 32)) }
        require(selector == CollectorAnchorRegistry.Unauthorized.selector, "wrong revert reason");
        r.revoke(c,1);
        (bool accepted,) = address(r).call(abi.encodeWithSelector(r.anchor.selector,
            c,uint64(1),uint64(1),bytes32(uint256(10)),bytes32(uint256(20)),
            bytes32(uint256(30)),uint64(1),uint64(2),bytes32(0)));
        require(!accepted,"revoked epoch accepted");
        r.register(c,2,bytes32(uint256(6)),address(this),bytes32(uint256(99)),bytes32(uint256(1)));
        r.anchor(c,2,1,bytes32(uint256(41)),bytes32(uint256(42)),bytes32(uint256(43)),1,1,0);

    }
}

contract StrictLinkTest {
    function testMandatoryLink() public {
        CollectorAnchorRegistry r = new CollectorAnchorRegistry();
        bytes32 c = keccak256("strict-link");
        bytes32 strictPolicy = hex"c0af4ce3b96e055e3f5e99bcc34ce9098ffacc2ed890c6ff8ebb8ea8b0c9a582";
        r.register(c,1,bytes32(uint256(5)),address(this),0,strictPolicy);
        r.anchor(c,1,1,bytes32(uint256(10)),bytes32(uint256(20)),bytes32(uint256(30)),1,2,0);
        (bool accepted,) = address(r).call(abi.encodeWithSelector(r.anchor.selector,
            c,uint64(1),uint64(2),bytes32(uint256(11)),bytes32(uint256(21)),
            bytes32(uint256(31)),uint64(3),uint64(4),bytes32(0)));
        require(!accepted,"missing manifest link accepted");
    }
}

contract SameBlockRevocationTest {
    function testAnchorBeforeRevocationSameBlockRemainsValid() public {
        CollectorAnchorRegistry r = new CollectorAnchorRegistry();
        bytes32 c = keccak256("same-block-revocation");
        bytes32 policy = hex"c0af4ce3b96e055e3f5e99bcc34ce9098ffacc2ed890c6ff8ebb8ea8b0c9a582";
        r.register(c, 1, bytes32(uint256(5)), address(this), 0, policy);
        r.anchor(c, 1, 1, bytes32(uint256(11)), bytes32(uint256(12)),
                 bytes32(uint256(13)), 1, 1, 0);
        (, , , , , uint64 anchorBlock, ) = r.getAnchor(c, 1, 1);
        r.revoke(c, 1);
        (, , uint64 effectiveRevocationBlock, , , ) = r.getEpoch(c, 1);
        require(anchorBlock == uint64(block.number), "different block");
        require(effectiveRevocationBlock == uint64(block.number+1), "same-block valid anchor could be rejected");
    }
}
