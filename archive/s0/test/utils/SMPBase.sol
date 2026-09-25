// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SealedMandateGate} from "../../src/SealedMandateGate.sol";
import {PublicPredicateVerifier} from "../../src/verifiers/PublicPredicateVerifier.sol";
import {MerkleHelper} from "./MerkleHelper.sol";

contract MockToken is ERC20 {
    constructor() ERC20("Mock", "MCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

abstract contract SMPBase is Test {
    uint8 internal constant S0 = 0;

    SealedMandateGate internal gate;
    PublicPredicateVerifier internal verifier;
    MockToken internal token;

    address internal principal = makeAddr("principal");
    address internal guardian = makeAddr("guardian");
    address internal stranger = makeAddr("stranger");
    uint256 internal agentPk = 0xA11CE;
    uint256 internal subAgentPk = 0xB0B;
    address internal agent;
    address internal subAgent;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");
    address internal dave = makeAddr("dave"); // never in the root's D

    bytes32 internal VIS;

    function setUp() public virtual {
        agent = vm.addr(agentPk);
        subAgent = vm.addr(subAgentPk);
        verifier = new PublicPredicateVerifier();
        address[] memory vs = new address[](1);
        vs[0] = address(verifier);
        gate = new SealedMandateGate(vs, guardian);
        token = new MockToken();
        token.mint(principal, 1_000_000e18);
        vm.prank(principal);
        token.approve(address(gate), type(uint256).max);
        VIS = verifier.VIS_PUBLIC();
        vm.warp(1_800_000_000);
    }

    // ───────────── builders ─────────────

    function _set(address a, address b, address c) internal pure returns (address[] memory s) {
        s = new address[](3);
        (s[0], s[1], s[2]) = (a, b, c);
    }

    function _set1(address a) internal pure returns (address[] memory s) {
        s = new address[](1);
        s[0] = a;
    }

    function _rootSet() internal view returns (address[] memory) {
        return _set(alice, bob, carol);
    }

    function _pred(address who, uint256 cap, bool mayDelegate)
        internal
        pure
        returns (PublicPredicateVerifier.Predicate memory)
    {
        return PublicPredicateVerifier.Predicate({agent: who, perActCap: cap, mayDelegate: mayDelegate});
    }

    /// @dev Local mirror of PublicPredicateVerifier.commitOf, so helpers make no external call
    ///      that would consume a pending vm.expectRevert. _issue still uses the contract's
    ///      version, which cross-checks the two.
    function _commit(PublicPredicateVerifier.Predicate memory p, bytes32 destRoot) internal view returns (bytes32) {
        return keccak256(
            abi.encode(keccak256("SMP/S0/PublicPredicate/v1"), p.agent, p.perActCap, p.mayDelegate, destRoot, VIS)
        );
    }

    function _issue(PublicPredicateVerifier.Predicate memory p, address[] memory d, uint256 budget, uint64 ttl)
        internal
        returns (bytes32 id)
    {
        bytes32 destRoot = MerkleHelper.root(d);
        bytes32 commit = verifier.commitOf(p, destRoot, VIS);
        vm.prank(principal);
        id = gate.issueMandate(commit, destRoot, budget, uint64(block.timestamp) + ttl, VIS, address(token), "");
    }

    function _delegate(
        address caller,
        bytes32 parentId,
        PublicPredicateVerifier.Predicate memory parentP,
        PublicPredicateVerifier.Predicate memory childP,
        address[] memory childD,
        uint256 budget,
        uint64 expiry
    ) internal returns (bytes32) {
        bytes32 destRoot = MerkleHelper.root(childD);
        bytes32 commit = _commit(childP, destRoot);
        vm.prank(caller);
        return gate.delegate(parentId, commit, destRoot, budget, expiry, VIS, S0, abi.encode(parentP, childP));
    }

    function _act(bytes32 mandateId, address dest, uint256 cost, bytes32 nonce)
        internal
        view
        returns (SealedMandateGate.Act memory)
    {
        return SealedMandateGate.Act({
            mandateId: mandateId,
            dest: dest,
            cost: cost,
            epoch: gate.currentEpoch(mandateId),
            deadline: uint64(block.timestamp) + 1 hours,
            nonce: nonce,
            visProjection: abi.encode("route-hint", dest, cost)
        });
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, MessageHashUtils.toEthSignedMessageHash(digest));
        return abi.encodePacked(r, s, v);
    }

    /// @dev Gate proof for a path given leaf-first D sets.
    function _proof(
        address[][] memory pathSets,
        address dest,
        PublicPredicateVerifier.Predicate memory p,
        bytes memory sig
    ) internal pure returns (bytes memory) {
        bytes32[][] memory dp = new bytes32[][](pathSets.length);
        for (uint256 i; i < pathSets.length; ++i) {
            dp[i] = MerkleHelper.proof(pathSets[i], dest);
        }
        return abi.encode(dp, abi.encode(p, sig));
    }

    function _path1(address[] memory a) internal pure returns (address[][] memory s) {
        s = new address[][](1);
        s[0] = a;
    }

    function _path2(address[] memory leafSet, address[] memory rootSet) internal pure returns (address[][] memory s) {
        s = new address[][](2);
        (s[0], s[1]) = (leafSet, rootSet);
    }

    /// @dev Signs with `pk` and submits. Returns the candidate id.
    function _submit(
        SealedMandateGate.Act memory act,
        address[][] memory pathSets,
        PublicPredicateVerifier.Predicate memory p,
        uint256 pk
    ) internal returns (bytes32) {
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(pathSets, act.dest, p, _sign(pk, digest));
        return gate.submitCandidate(act, digest, S0, proof);
    }
}
