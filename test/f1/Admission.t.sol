// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AgentGate} from "../../src/AgentGate.sol";
import {GateSettlement} from "../../src/GateSettlement.sol";
import {ILivenessSource} from "../../src/interfaces/IGateExternal.sol";
import "../../src/GateTypes.sol";
import "../../src/GateErrors.sol";
import {MerkleHelper} from "../utils/MerkleHelper.sol";
import {MockRouter, MockAccount, Sink} from "../mocks/Mocks.sol";
import {F1Base} from "./F1Base.sol";

/// @notice SPEC.md §7.1 admission rejects (A1–A17) and the SMP V-vectors that map onto them.
contract AdmissionTest is F1Base {
    function _rootId() internal view returns (bytes32) {
        return gate.rootCapId(MANDATE, _epoch());
    }

    // ═════════════════════════ happy path (SMP V1) ═════════════════════════

    function test_V1_legalAct_reservesThenDebitsMeasuredOutflow() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 40e18);
        bytes32 root = _rootId();
        assertEq(gate.capHash(root), keccak256(abi.encode(_rootNode())), "fixture rebuilds the root preimage");

        (bytes32 th, TicketPreimage memory t) = gate.admit(a);
        assertEq(gate.capRemaining(root, address(usdc)), 460e18, "reserved at admit");
        assertEq(t.windowLen, 1 hours + 40 * 36, "window grows with the reservation");
        assertTrue(gate.ticketLive(th));

        vm.warp(t.windowEnd);
        vm.prank(stranger); // executor identity is irrelevant
        (uint256[] memory outs,) = settle.execute(_exec(a, t));

        assertEq(outs[0], 40e18);
        assertEq(usdc.balanceOf(alice), 40e18);
        assertEq(gate.capRemaining(root, address(usdc)), 460e18);
        assertEq(gate.consumed(MANDATE, 1, address(usdc)), 40e18);
        assertFalse(gate.ticketLive(th));
    }

    // ═════════════════════════ A1 ═════════════════════════

    function test_A1_wrongEpoch() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        a.proposal.epoch += 1;
        _sign(a, agentPk);
        vm.expectRevert(A1_MandateNotLive.selector);
        gate.admit(a);
    }

    function test_A1_suspendedMandate() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        _asPrincipal(abi.encodeCall(AgentGate.suspend, (MANDATE, a.commit, new bytes32[](0))));
        vm.expectRevert(A1_MandateNotLive.selector);
        gate.admit(a);
    }

    function test_A1_expiredMandate() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        vm.warp(expiry);
        vm.expectRevert(A1_MandateNotLive.selector);
        gate.admit(a);
    }

    // ═════════════════════════ A2 ═════════════════════════

    function test_A2_forgedNodePreimage() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        a.path[0].allotment[0].amount = 10_000e18;
        vm.expectRevert(A2_BadCapPath.selector);
        gate.admit(a);
    }

    function test_A2_revokedNode() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        vm.prank(agent);
        settle.revokeCap(a.path, 0);
        vm.expectRevert(A2_BadCapPath.selector);
        gate.admit(a);
    }

    // ═════════════════════════ A3 (SMP V2) ═════════════════════════

    function test_A3_V2_leafOutsideScope_rejected() public {
        AdmitInput memory a = _payInput(L_PAY_DAVE, dave, 1e18);
        // Reuse a real member's proof: still cannot place dave's leaf under the root.
        a.scopeProofs[0] = _scopeProof(_rootSet(), L_PAY_ALICE);
        vm.expectRevert(A3_OutOfScope.selector);
        gate.admit(a);
    }

    // ═════════════════════════ A4 ═════════════════════════

    function test_A4_paramsPreimageMismatch() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        a.params.windowBase = 0; // looser window, not what was committed
        vm.expectRevert(A4_PreimageMismatch.selector);
        gate.admit(a);
    }

    function test_A4_attestorNotInSet() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        uint256 outsiderPk = 0xFFFF1;
        Attestation memory x = a.attestations[1];
        x.attestor = bytes32(uint256(uint160(vm.addr(outsiderPk))));
        x.blob = "";
        x.blob = _sig(outsiderPk, gate.attestationHash(x));
        if (uint256(x.attestor) > uint256(a.attestations[0].attestor)) {
            a.attestations[1] = x;
        } else {
            (a.attestations[0], a.attestations[1]) = (x, a.attestations[0]);
            (a.attestorProofs[0], a.attestorProofs[1]) = (a.attestorProofs[1], a.attestorProofs[0]);
        }
        vm.expectRevert(A4_NotAttestor.selector);
        gate.admit(a);
    }

    // ═════════════════════════ A5 (SMP V7) ═════════════════════════

    function test_A5_belowThreshold() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        Attestation[] memory one = new Attestation[](1);
        one[0] = a.attestations[0];
        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = a.attestorProofs[0];
        (a.attestations, a.attestorProofs) = (one, proofs);
        vm.expectRevert(A5_BelowThreshold.selector);
        gate.admit(a);
    }

    function test_A5_sameAttestorTwice() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        a.attestations[1] = a.attestations[0];
        a.attestorProofs[1] = a.attestorProofs[0];
        vm.expectRevert(A5_DuplicateAttestor.selector);
        gate.admit(a);
    }

    function test_A5_attestationForAnotherProposal() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        AdmitInput memory b = _payInput(L_PAY_BOB, bob, 1e18);
        a.attestations = b.attestations;
        vm.expectRevert(A5_AttestationMismatch.selector);
        gate.admit(a);
    }

    function test_A5_expiredAttestation() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        vm.warp(vm.getBlockTimestamp() + 2 days + 1);
        vm.expectRevert(A5_AttestationMismatch.selector);
        gate.admit(a);
    }

    /// SPEC §17 F-3: the attestation hash covers expiresAt, so a relayer cannot extend it.
    function test_A5_tamperedExpiry_breaksSignature() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        a.attestations[0].expiresAt += 30 days;
        vm.expectRevert(A5_BadAttestation.selector);
        gate.admit(a);
    }

    function test_A5_V7_unregisteredScheme() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        a.attestations[0].scheme = keccak256("SMP/scheme/zk-unbound");
        vm.expectRevert(A5_SchemeNotAllowed.selector);
        gate.admit(a);
    }

    function test_A5_V7_noAttestations() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        a.attestations = new Attestation[](0);
        a.attestorProofs = new bytes32[][](0);
        vm.expectRevert(A5_BelowThreshold.selector);
        gate.admit(a);
    }

    // ═════════════════════════ A6 ═════════════════════════

    /// A valid signature from a key that is not the node's delegatee (session key ≠ mandate).
    function test_A6_validSignatureFromWrongKey() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        a.agentSig = _sig(subAgentPk, gate.proposalHash(a.proposal));
        vm.expectRevert(A6_BadAgentSig.selector);
        gate.admit(a);
    }

    // ═════════════════════════ A7 (SMP V8) ═════════════════════════

    function test_A7_V8_nonceReplay() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        gate.admit(a);
        vm.expectRevert(A7_NonceUsed.selector);
        gate.admit(a);
    }

    function test_A7_identicalPaymentsWithFreshNonces_bothAdmit() public {
        gate.admit(_payInput(L_PAY_ALICE, alice, 10e18));
        gate.admit(_payInput(L_PAY_ALICE, alice, 10e18));
        assertEq(gate.capRemaining(_rootId(), address(usdc)), 480e18);
    }

    // ═════════════════════════ A8 ═════════════════════════

    function test_A8_afterValidUntil() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        vm.warp(a.proposal.validUntil + 1);
        vm.expectRevert(A8_OutsideValidity.selector);
        gate.admit(a);
    }

    function test_A8_staleStateRef() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        vm.roll(vm.getBlockNumber() + 65);
        vm.expectRevert(A8_StaleState.selector);
        gate.admit(a);
    }

    function test_A8_forgedStateRef() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        a.proposal.stateRef.blockHash = keccak256("not the chain");
        _sign(a, agentPk);
        vm.expectRevert(A8_StaleState.selector);
        gate.admit(a);
    }

    // ═════════════════════════ A9 (SMP V3) ═════════════════════════

    function test_A9_V3_declaredAboveLeafCap() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 50e18);
        a.proposal.declaredOut[0].amount = 101e18;
        _sign(a, agentPk);
        vm.expectRevert(A9_ExceedsBudget.selector);
        gate.admit(a);
    }

    function test_A9_V3_periodCap() public {
        for (uint256 i; i < 3; ++i) {
            gate.admit(_payInput(L_PAY_ALICE, alice, 100e18));
        }
        AdmitInput memory a = _payInput(L_PAY_BOB, bob, 1e18);
        vm.expectRevert(A9_ExceedsBudget.selector);
        gate.admit(a);

        vm.warp(vm.getBlockTimestamp() + 1 days); // next period
        gate.admit(_payInput(L_PAY_BOB, bob, 1e18));
    }

    function test_A9_V3_epochCap() public {
        for (uint256 i; i < 3; ++i) {
            _settle(_payInput(L_PAY_ALICE, alice, 100e18));
        }
        vm.warp(vm.getBlockTimestamp() + 1 days);
        _settle(_payInput(L_PAY_ALICE, alice, 100e18));
        _settle(_payInput(L_PAY_ALICE, alice, 100e18));
        assertEq(gate.capRemaining(_rootId(), address(usdc)), 0);
        AdmitInput memory a = _payInput(L_PAY_BOB, bob, 1);
        vm.expectRevert(A9_ExceedsBudget.selector);
        gate.admit(a);
    }

    // ═════════════════════════ A10 ═════════════════════════

    function test_A10_declaredAssetsOutOfOrder() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _pathRoot();
        AdmitInput memory a = _input(L_SWAP, _swapData(50e18), _u2(50e18, 0), path, sets, agentPk);
        (a.proposal.declaredOut[0], a.proposal.declaredOut[1]) = (a.proposal.declaredOut[1], a.proposal.declaredOut[0]);
        _sign(a, agentPk);
        vm.expectRevert(A10_AssetMismatch.selector);
        gate.admit(a);
    }

    function test_A10_minInOnUnlistedAsset() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        a.proposal.declaredMinIn = new AssetAmount[](1);
        a.proposal.declaredMinIn[0] = AssetAmount(address(weth), 1);
        _sign(a, agentPk);
        vm.expectRevert(A10_AssetMismatch.selector);
        gate.admit(a);
    }

    // ═════════════════════════ A11 ═════════════════════════

    function test_A11_capPathDisagreesWithNodes() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        a.proposal.capPath[0] = keccak256("elsewhere");
        _sign(a, agentPk);
        vm.expectRevert(A11_PathMismatch.selector);
        gate.admit(a);
    }

    // ═════════════════════════ A12, A13, A17 ═════════════════════════

    function test_A12_unknownLeafType() public {
        AdmitInput memory a = _payInput(L_BAD_TYPE, alice, 0);
        vm.expectRevert(A12_BadLeafType.selector);
        gate.admit(a);
    }

    function test_A13_targetIsGate() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _pathRoot();
        AdmitInput memory a = _input(
            L_TARGET_GATE, abi.encodeCall(AgentGate.cancelCommit, (MANDATE)), _u1(0), path, sets, agentPk
        );
        vm.expectRevert(A13_ForbiddenTarget.selector);
        gate.admit(a);
    }

    function test_A13_targetIsPrincipalAccount() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _pathRoot();
        AdmitInput memory a = _input(
            L_TARGET_ACCOUNT, abi.encodeCall(MockAccount.installModule, (bytes32("backdoor"))), _u1(0), path, sets, agentPk
        );
        vm.expectRevert(A13_ForbiddenTarget.selector);
        gate.admit(a);
    }

    function test_A17_proxyImplementationUnsupported() public {
        AdmitInput memory a = _payInput(L_PROXY, alice, 1e18);
        vm.expectRevert(A17_ImplementationUnsupported.selector);
        gate.admit(a);
    }

    // ═════════════════════════ A14 (SMP V6) ═════════════════════════

    function test_A14_V6_calldataSwappedAfterSigning() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        a.data = abi.encodeCall(IERC20.transfer, (alice, 2e18));
        vm.expectRevert(A14_PreimageMismatch.selector);
        gate.admit(a);
    }

    function test_A14_V6_receiverOutsideArgRule() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, bob, 1e18); // alice's leaf, bob as receiver
        vm.expectRevert(A14_ArgRuleViolated.selector);
        gate.admit(a);
    }

    function test_A14_amountAboveArgRule() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 101e18);
        a.proposal.declaredOut[0].amount = 100e18;
        _sign(a, agentPk);
        vm.expectRevert(A14_ArgRuleViolated.selector);
        gate.admit(a);
    }

    function test_A14_swapMustPayTheAccount() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _pathRoot();
        bytes memory data =
            abi.encodeCall(MockRouter.swap, (address(usdc), 50e18, address(weth), 0, evil));
        AdmitInput memory a = _input(L_SWAP, data, _u2(50e18, 0), path, sets, agentPk);
        vm.expectRevert(A14_ArgRuleViolated.selector);
        gate.admit(a);
    }

    // ═════════════════════════ A15 ═════════════════════════

    function test_A15_accountModuleAddedAfterCommit() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        vm.prank(owner);
        account.installModule(keccak256("second executor"));
        vm.expectRevert(A15_AccountConfig.selector);
        gate.admit(a);
    }

    function test_A15_agentHasAnotherPath() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        vm.prank(owner);
        account.setOtherAuthority(agent, true);
        vm.expectRevert(A15_AccountConfig.selector);
        gate.admit(a);
    }

    // ═════════════════════════ A16 ═════════════════════════

    function test_A16_valueAboveDeclaredNative() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _pathRoot();
        AdmitInput memory a =
            _input(L_NATIVE, abi.encodeCall(Sink.ping, ()), _u1(0.5 ether), path, sets, agentPk);
        a.proposal.value = 0.6 ether;
        _sign(a, agentPk);
        vm.expectRevert(A16_ValueExceedsDeclared.selector);
        gate.admit(a);
    }

    function test_A16_valueOnErc20Leaf() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        a.proposal.value = 1;
        _sign(a, agentPk);
        vm.expectRevert(A16_ValueExceedsDeclared.selector);
        gate.admit(a);
    }

    // ═════════════════════════ domain separation ═════════════════════════

    /// SPEC §12.2: the same proposal hashes differently under another gate on the same chain.
    function test_proposalHashBoundToGate() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        GateSettlement impl2 = new GateSettlement(ILivenessSource(address(live)));
        bytes32[] memory schemes = new bytes32[](1);
        schemes[0] = ECDSA_SCHEME;
        address[] memory vs = new address[](1);
        vs[0] = address(verifier);
        AgentGate gate2 = new AgentGate(schemes, vs, ILivenessSource(address(live)), address(impl2));
        assertTrue(gate2.proposalHash(a.proposal) != gate.proposalHash(a.proposal));
    }

    // ═════════════════════════ helpers ═════════════════════════

    function _swapData(uint256 amountIn) internal view returns (bytes memory) {
        return abi.encodeCall(MockRouter.swap, (address(usdc), amountIn, address(weth), 0, address(account)));
    }
}
