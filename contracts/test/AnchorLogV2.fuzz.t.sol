// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;
import './AnchorLogV2.t.sol';

/// @notice Negative mutation tests using the audited reference vectors.
/// The permitted signature and schedule must still pass the original test.
/// This file is an executable Foundry target; it has NOT been run locally.
contract AnchorLogV2FuzzTest is AnchorLogV2Test {
    function testFuzzRejectInvalidRecoveryId(uint8 recoveryId) public {
        if (recoveryId == 27 || recoveryId == 28) return;
        AnchorLogV2 r = new AnchorLogV2();
        r.register(COLLECTOR,1,1,1,ROOT);
        bytes memory corrupted = sigA();
        corrupted[64] = bytes1(recoveryId);
        (bool ok,) = address(r).call(abi.encodeWithSelector(
            r.anchor.selector, honest(), corrupted, proof1()));
        require(!ok,'accepted invalid recovery id');
    }

    function testFuzzRejectMutatedProof(bytes32 sibling) public {
        bytes32[] memory validProof=proof1();
        if (sibling==validProof[0]) return;
        AnchorLogV2 r = new AnchorLogV2();
        r.register(COLLECTOR,1,1,1,ROOT);
        bytes32[] memory wrong = new bytes32[](1);
        wrong[0]=sibling;
        (bool ok,) = address(r).call(abi.encodeWithSelector(
            r.anchor.selector, honest(), sigA(), wrong));
        require(!ok,'accepted invalid key proof');
    }

    function testFuzzRejectTamperedCheckpointSize(uint64 size) public {
        if (size==1) return;
        AnchorLogV2 r = new AnchorLogV2();
        r.register(COLLECTOR,1,1,1,ROOT);
        AnchorLogV2.Checkpoint memory cp = honest();
        cp.size = size;
        (bool ok,) = address(r).call(abi.encodeWithSelector(
            r.anchor.selector,cp,sigA(),proof1()));
        require(!ok,'accepted forged checkpoint');
    }

    function testRevokeBlocksSubsequentAnchors() public {
        AnchorLogV2 r = new AnchorLogV2();
        r.register(COLLECTOR,1,1,1,ROOT);
        r.anchor(honest(),sigA(),proof1());
        r.revoke(COLLECTOR,1);
        (bool ok,) = address(r).call(abi.encodeWithSelector(
            r.anchor.selector,second(),sigC(),proof2()));
        require(!ok,'accepted anchor after revocation');
    }
}
