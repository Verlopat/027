// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;
import "../src/CollectorAnchorRegistry.sol";

contract Outsider {
    function submit(CollectorAnchorRegistry target, bytes32 collector) external returns (bool) {
        (bool ok,) = address(target).call(abi.encodeWithSelector(target.anchor.selector,
            collector,uint64(1),uint64(1),bytes32(uint256(2)),bytes32(uint256(3)),
            bytes32(uint256(4)),uint64(1),uint64(2),bytes32(0)));
        return ok;
    }
}

contract RegistryTest {
    function testRegistrationAndAnchor() public {
        CollectorAnchorRegistry r = new CollectorAnchorRegistry();
        bytes32 c = keccak256("collector-a");
        r.register(c,1,bytes32(uint256(5)),address(this),0);
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
        r.register(c,1,bytes32(uint256(5)),address(this),0);
        r.revoke(c,1);
        (bool accepted,) = address(r).call(abi.encodeWithSelector(r.anchor.selector,
            c,uint64(1),uint64(1),bytes32(uint256(10)),bytes32(uint256(20)),
            bytes32(uint256(30)),uint64(1),uint64(2),bytes32(0)));
        require(!accepted,"revoked epoch accepted");
        r.register(c,2,bytes32(uint256(6)),address(this),bytes32(uint256(99)));
        r.anchor(c,2,1,bytes32(uint256(41)),bytes32(uint256(42)),bytes32(uint256(43)),1,1,0);
        Outsider attacker = new Outsider();
        require(!attacker.submit(r,c),"unauthorized sender accepted");
    }
}
