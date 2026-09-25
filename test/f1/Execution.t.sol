// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {AgentGate} from "../../src/AgentGate.sol";
import "../../src/GateTypes.sol";
import "../../src/GateErrors.sol";
import {MockRouter, ReentrantTarget, Sink} from "../mocks/Mocks.sol";
import {F1Base} from "./F1Base.sol";

/// @notice SPEC.md §7.2 execution rejects (X1–X10), measured settlement, and ticket drops.
contract ExecutionTest is F1Base {
    function _rootId() internal view returns (bytes32) {
        return gate.rootCapId(MANDATE, _epoch());
    }

    function _swapInput(uint256 amountIn, uint256 declaredOut) internal returns (AdmitInput memory) {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _pathRoot();
        bytes memory data =
            abi.encodeCall(MockRouter.swap, (address(usdc), amountIn, address(weth), 0, address(account)));
        return _input(L_SWAP, data, _u2(declaredOut, 0), path, sets, agentPk);
    }

    function _noProof() internal pure returns (bytes32[] memory) {
        return new bytes32[](0);
    }

    // ═════════════════════════ measured settlement ═════════════════════════

    function test_measured_underSpendReleasesDifference() public {
        AdmitInput memory a = _swapInput(100e18, 150e18);
        (, TicketPreimage memory t) = gate.admit(a);
        assertEq(gate.capRemaining(_rootId(), address(usdc)), 350e18);
        vm.warp(t.windowEnd);
        (uint256[] memory outs, uint256[] memory ins) = settle.execute(_exec(a, t));
        assertEq(outs[0], 100e18, "measured, not declared");
        assertEq(ins[1], 0.1e18);
        assertEq(gate.capRemaining(_rootId(), address(usdc)), 400e18, "50 released back");
        assertEq(gate.consumed(MANDATE, 1, address(usdc)), 100e18);
        assertEq(weth.balanceOf(address(account)), 0.1e18);
    }

    function test_measured_nativeValue() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _pathRoot();
        AdmitInput memory a = _input(L_NATIVE, abi.encodeCall(Sink.ping, ()), _u1(0.5 ether), path, sets, agentPk);
        a.proposal.value = 0.5 ether;
        _sign(a, agentPk);
        _settle(a);
        assertEq(address(sink).balance, 0.5 ether);
        assertEq(gate.consumed(MANDATE, 1, NATIVE), 0.5 ether);
    }

    // ═════════════════════════ X1 / X3 ═════════════════════════

    function test_X1_calldataSwappedAtExecute() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 10e18);
        (, TicketPreimage memory t) = gate.admit(a);
        vm.warp(t.windowEnd);
        ExecuteInput memory x = _exec(a, t);
        x.data = abi.encodeCall(IERC20.transfer, (evil, 10e18));
        vm.expectRevert(X1_TicketMismatch.selector);
        settle.execute(x);
    }

    /// A tampered ticket preimage hashes to a ticket that does not exist.
    function test_X1_X3_tamperedTicketPreimage() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 10e18);
        (, TicketPreimage memory t) = gate.admit(a);
        t.windowEnd = uint64(vm.getBlockTimestamp()); // try to skip the window
        vm.expectRevert(X3_NoTicket.selector);
        settle.execute(_exec(a, t));
    }

    function test_X3_executeTwice() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 10e18);
        (, TicketPreimage memory t) = gate.admit(a);
        vm.warp(t.windowEnd);
        settle.execute(_exec(a, t));
        vm.expectRevert(X3_NoTicket.selector);
        settle.execute(_exec(a, t));
    }

    // ═════════════════════════ X2 / X10 ═════════════════════════

    function test_X2_windowNotElapsed() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 10e18);
        (, TicketPreimage memory t) = gate.admit(a);
        vm.warp(t.windowEnd - 1);
        vm.expectRevert(X2_WindowNotElapsed.selector);
        settle.execute(_exec(a, t));
    }

    function test_X2_principalCoSignShortensWindow() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 100e18);
        a.coSig = _sig(ownerPk, gate.coSignHash(gate.proposalHash(a.proposal)));
        (, TicketPreimage memory t) = gate.admit(a);
        assertEq(t.windowLen, 5 minutes);
        vm.warp(vm.getBlockTimestamp() + 5 minutes);
        settle.execute(_exec(a, t));
    }

    function test_X2_forgedCoSign() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 100e18);
        a.coSig = _sig(agentPk, gate.coSignHash(gate.proposalHash(a.proposal)));
        vm.expectRevert(CoSigInvalid.selector);
        gate.admit(a);
    }

    /// X10: an outage during the window restarts it from recovery + grace.
    function test_X10_outageRestartsWindow() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 10e18);
        (, TicketPreimage memory t) = gate.admit(a);

        vm.warp(vm.getBlockTimestamp() + 10 minutes);
        live.set(false, uint64(vm.getBlockTimestamp()));
        vm.warp(t.windowEnd);
        vm.expectRevert(X6_SequencerDown.selector);
        settle.execute(_exec(a, t));

        live.set(true, uint64(vm.getBlockTimestamp()));
        uint256 restartEnd = vm.getBlockTimestamp() + 30 minutes + t.windowLen;
        vm.warp(restartEnd - 1);
        vm.expectRevert(X2_WindowNotElapsed.selector);
        settle.execute(_exec(a, t));
        vm.warp(restartEnd);
        settle.execute(_exec(a, t));
    }

    // ═════════════════════════ X4 (SMP V4) ═════════════════════════

    function test_X4_V4_suspendAfterAdmit() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 10e18);
        (, TicketPreimage memory t) = gate.admit(a);
        vm.prank(guardian);
        gate.suspend(MANDATE, a.commit, _noProof());
        vm.warp(t.windowEnd);
        vm.expectRevert(X4_StaleTicket.selector);
        settle.execute(_exec(a, t));
    }

    function test_X4_nodeRevokedAfterAdmit() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 10e18);
        (, TicketPreimage memory t) = gate.admit(a);
        vm.prank(agent);
        settle.revokeCap(a.path, 0);
        vm.warp(t.windowEnd);
        vm.expectRevert(X4_StaleTicket.selector);
        settle.execute(_exec(a, t));
    }

    function test_X4_validUntilPassed() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 10e18);
        (, TicketPreimage memory t) = gate.admit(a);
        vm.warp(t.validUntil + 1);
        vm.expectRevert(X4_StaleTicket.selector);
        settle.execute(_exec(a, t));
    }

    // ═════════════════════════ X5 ═════════════════════════

    function test_X5_targetCodeChanged() public {
        AdmitInput memory a = _swapInput(50e18, 50e18);
        (, TicketPreimage memory t) = gate.admit(a);
        vm.etch(address(router), hex"00"); // counterparty upgraded or self-destructed-and-redeployed
        vm.warp(t.windowEnd);
        vm.expectRevert(X5_CodeHashChanged.selector);
        settle.execute(_exec(a, t));
    }

    // ═════════════════════════ X6 ═════════════════════════

    function test_X6_accountConfigChangedAfterAdmit() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 10e18);
        (, TicketPreimage memory t) = gate.admit(a);
        vm.prank(owner);
        account.installModule(keccak256("second executor"));
        vm.warp(t.windowEnd);
        vm.expectRevert(X6_AccountConfig.selector);
        settle.execute(_exec(a, t));
    }

    // ═════════════════════════ X7 ═════════════════════════

    function test_X7_counterpartyPullsMoreThanDeclared() public {
        AdmitInput memory a = _swapInput(100e18, 100e18);
        (, TicketPreimage memory t) = gate.admit(a);
        router.configure(1e18, 0); // pulls 101
        vm.warp(t.windowEnd);
        vm.expectRevert(X7_OutflowExceeded.selector);
        settle.execute(_exec(a, t));
    }

    function test_X7_inflowBelowDeclaredMinimum() public {
        AdmitInput memory a = _swapInput(100e18, 100e18);
        a.proposal.declaredMinIn = new AssetAmount[](1);
        a.proposal.declaredMinIn[0] = AssetAmount(address(weth), 0.1e18);
        _sign(a, agentPk);
        (, TicketPreimage memory t) = gate.admit(a);
        router.configure(0, 1); // pays 1 wei short
        vm.warp(t.windowEnd);
        vm.expectRevert(X7_InflowShort.selector);
        settle.execute(_exec(a, t));
    }

    // ═════════════════════════ X8 / X9 ═════════════════════════

    function test_X8_allowanceLeftToNonAllowlistedSpender() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _pathRoot();
        AdmitInput memory a = _input(
            L_APPROVE_EVIL, abi.encodeCall(IERC20.approve, (evil, type(uint256).max)), _u1(0), path, sets, agentPk
        );
        (, TicketPreimage memory t) = gate.admit(a);
        vm.warp(t.windowEnd);
        vm.expectRevert(X8_AllowanceIncreased.selector);
        settle.execute(_exec(a, t));
    }

    function test_X9_targetReentersGate() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _pathRoot();
        AdmitInput memory a = _input(L_REENTER, abi.encodeCall(ReentrantTarget.poke, ()), _u1(0), path, sets, agentPk);
        (, TicketPreimage memory t) = gate.admit(a);
        vm.warp(t.windowEnd);
        vm.expectRevert(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        settle.execute(_exec(a, t));
    }

    /// Failure rolls back whole; the ticket stays executable until it expires (SPEC §4.3).
    function test_failedExecution_ticketStaysLive() public {
        AdmitInput memory a = _swapInput(100e18, 100e18);
        (bytes32 th, TicketPreimage memory t) = gate.admit(a);
        router.configure(1e18, 0);
        vm.warp(t.windowEnd);
        vm.expectRevert(X7_OutflowExceeded.selector);
        settle.execute(_exec(a, t));
        assertTrue(gate.ticketLive(th));
        router.configure(0, 0);
        settle.execute(_exec(a, t));
        assertFalse(gate.ticketLive(th));
    }

    // ═════════════════════════ drops ═════════════════════════

    function test_veto_byGuardian_releasesReservation() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 60e18);
        (, TicketPreimage memory t) = gate.admit(a);
        vm.prank(guardian);
        settle.veto(t, a.commit, _noProof());
        assertEq(gate.capRemaining(_rootId(), address(usdc)), 500e18);
        assertEq(gate.periodUsed(MANDATE, 1, address(usdc), t.periodIdx[0]), 0);
        vm.warp(t.windowEnd);
        vm.expectRevert(X3_NoTicket.selector);
        settle.execute(_exec(a, t));
    }

    function test_veto_strangerRejected() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 60e18);
        (, TicketPreimage memory t) = gate.admit(a);
        vm.prank(stranger);
        vm.expectRevert(NotAuthorized.selector);
        settle.veto(t, a.commit, _noProof());
    }

    function test_withdrawAttestation_actsAsVeto() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 60e18);
        (, TicketPreimage memory t) = gate.admit(a);
        bytes32[] memory counted = new bytes32[](2);
        (counted[0], counted[1]) = (a.attestations[0].attestor, a.attestations[1].attestor);

        vm.prank(att[2]); // not counted
        vm.expectRevert(NotAuthorized.selector);
        settle.withdrawAttestation(t, counted, 0);

        vm.prank(att[1]);
        settle.withdrawAttestation(t, counted, 1);
        assertEq(gate.capRemaining(_rootId(), address(usdc)), 500e18);
    }

    function test_cancel_onlyByAgent() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 60e18);
        (, TicketPreimage memory t) = gate.admit(a);
        vm.prank(stranger);
        vm.expectRevert(NotAuthorized.selector);
        settle.cancel(t);
        vm.prank(agent);
        settle.cancel(t);
        assertEq(gate.capRemaining(_rootId(), address(usdc)), 500e18);
    }

    function test_release_onlyWhenDead() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 60e18);
        (, TicketPreimage memory t) = gate.admit(a);
        vm.expectRevert(TicketStillLive.selector);
        settle.release(t, a.proposal.capPath);
        vm.warp(t.validUntil + 1);
        vm.prank(stranger);
        settle.release(t, a.proposal.capPath);
        assertEq(gate.capRemaining(_rootId(), address(usdc)), 500e18);
    }

    /// Epoch change voids the node reservation but must still free the period budget.
    function test_release_afterEpochChange_freesPeriodOnly() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 100e18);
        (, TicketPreimage memory t) = gate.admit(a);
        uint64 idx = t.periodIdx[0];
        _asPrincipal(abi.encodeCall(AgentGate.suspend, (MANDATE, a.commit, _noProof())));
        settle.release(t, a.proposal.capPath);
        assertEq(gate.periodUsed(MANDATE, 1, address(usdc), idx), 0);
    }
}
