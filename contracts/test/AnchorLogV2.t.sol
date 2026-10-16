// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;
import "../src/AnchorLogV2.sol";
contract AnchorLogV2Test {
bytes32 internal constant COLLECTOR=hex"ec2c9050f47dc88e74785d48dea610398d21803da56f0ddd3df7f0d861e653e5";
bytes32 internal constant ROOT=hex"a2a5a5e45aa69cda419b858e1c0deb4bb84e1f7c1a1cbba9f55483b1a7c7cfe8";
function honest() internal pure returns (AnchorLogV2.Checkpoint memory) {return AnchorLogV2.Checkpoint({domain: bytes32(hex"513061a742a200981b26ea7a8466fe0f13df827f381bdd18bc20d8c100a43933"), collector: COLLECTOR, epoch: uint64(1), period: uint64(1), size: uint64(1), root: bytes32(hex"ce36863f51b6baf9d16397ffb3e9af506b284a816f72d487e55943c1fd974d6d"), prev: bytes32(hex"0000000000000000000000000000000000000000000000000000000000000000"), wallMs: uint64(10), scheduleRoot: ROOT});}
function forked() internal pure returns (AnchorLogV2.Checkpoint memory) {return AnchorLogV2.Checkpoint({domain: bytes32(hex"513061a742a200981b26ea7a8466fe0f13df827f381bdd18bc20d8c100a43933"), collector: COLLECTOR, epoch: uint64(1), period: uint64(1), size: uint64(2), root: bytes32(hex"147cfdd0a3c699db55251949ea436dc273504eb0cb6573c89cc8362c5f7de65f"), prev: bytes32(hex"0000000000000000000000000000000000000000000000000000000000000000"), wallMs: uint64(11), scheduleRoot: ROOT});}
function second() internal pure returns (AnchorLogV2.Checkpoint memory) {return AnchorLogV2.Checkpoint({domain: bytes32(hex"513061a742a200981b26ea7a8466fe0f13df827f381bdd18bc20d8c100a43933"), collector: COLLECTOR, epoch: uint64(1), period: uint64(2), size: uint64(2), root: bytes32(hex"b4e3d14e7519279e6a352f776d75a905a9de9a27efdb6d802fe4e700224ade2e"), prev: bytes32(hex"cbc819a302e380e1700b395fb1bf72e6e1f56d9f02ec20f20c20a6e5002e6098"), wallMs: uint64(20), scheduleRoot: ROOT});}
function sigA() internal pure returns(bytes memory) {return hex"fc5b51f2129d96a30d7561ca30418bad413a2fa82bd72850d2e8cc71aea7eef840b709ee4ac17072b4de7ee8ae82a06b9499c94e38e94c13594e1984626ae85e1b";}
function sigB() internal pure returns(bytes memory) {return hex"2a9c0c06d7a2d1966adf88822f961dfa4d6ba799622c17ffed0350812698cdf07a1ccb7cdf72e8645c7e5f2c4a9d1bf3c6690031345f621b78be23543978bd5c1c";}
function sigC() internal pure returns(bytes memory) {return hex"a193e0421855ae742fe0efa465a93f81e3c9610d1036addedf042992e8f6e90a0f8df349d4719c9cb2432479f4ecd91aa8f80b1f0c13622871fcf8a6e548fae21b";}
function proof1() internal pure returns(bytes32[] memory p) {p=new bytes32[](1);p[0]=bytes32(hex"725c4c427a083de6887e713b162dfc9e89fd8c9c591dc24f6cb58100b27aed73");}
function proof2() internal pure returns(bytes32[] memory p) {p=new bytes32[](1);p[0]=bytes32(hex"200dbb4bc606eefcd040121e4811511beb49fed461c24d1a30e8933b2557c917");}
function testSignedAnchorsAndPublicFraudProof() public {
   AnchorLogV2 r=new AnchorLogV2();r.register(COLLECTOR,1,1,1,ROOT);
   r.anchor(honest(),sigA(),proof1());
   require(r.anchoredDigest(COLLECTOR,1,1)==r.checkpointDigest(honest()),"wrong digest");
   r.anchor(second(),sigC(),proof2());
   (uint64 latest,,,)=r.heads(COLLECTOR,1);require(latest==2,"bad tip");
   r.proveEquivocation(honest(),sigA(),forked(),sigB(),proof1());
   require(r.revokedAt(COLLECTOR,1)!=0,"no equivocation revocation");
 }
 function testRejectWrongKeyAndRepeatedPeriod() public {
   AnchorLogV2 r=new AnchorLogV2();r.register(COLLECTOR,1,1,1,ROOT);
   (bool bad,) = address(r).call(abi.encodeWithSelector(r.anchor.selector, honest(),sigB(),proof1()));
   // A fork signature is valid for the forged checkpoint but invalid for the honest checkpoint
   require(!bad,"accepted invalid signature");
   r.anchor(honest(),sigA(),proof1());
   (bool repeated,) = address(r).call(abi.encodeWithSelector(r.anchor.selector,honest(),sigA(),proof1()));
   require(!repeated,"accepted replay");
 }
}