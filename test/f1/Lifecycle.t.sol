// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AgentGate} from "../../src/AgentGate.sol";
import "../../src/GateTypes.sol";
import "../../src/GateErrors.sol";
import {MockRouter} from "../mocks/Mocks.sol";
import {F1Base} from "./F1Base.sol";

/// @notice SPEC.md §4.1 mandate lifecycle, §11 trip, and the §17 fixes to spec B.
contract LifecycleTest is F1Base {
    bytes32[] internal none;

    // ═════════════════════════ helpers ═════════════════════════

    function _proposeAs(MandateCommit memory c, Params memory p) internal {
        (Attestation[] memory r, bytes32[][] memory rp) = _ready(c);
        _asPrincipal(abi.encodeCall(AgentGate.proposeCommit, (c, p, r, rp)));
    }

    /// Builds a commit with a later activateAfter while keeping _commit() equal to the active one.
    function _replacement(Params memory p, BudgetSpec memory b, uint64 after_)
        internal
        returns (MandateCommit memory c)
    {
        uint64 saved = activateAfter;
        activateAfter = after_;
        c = _commitWith(p, b, expiry);
        activateAfter = saved;
    }

    function _budgetCap(uint256 epochCap) internal view returns (BudgetSpec memory b) {
        b = _budget();
        b.assets[0].epochCap = epochCap;
    }

    /// Admission input against an arbitrary active commit (after shrink or replacement).
    function _payUnder(MandateCommit memory c, Params memory p, BudgetSpec memory b, uint256 amt)
        internal
        returns (AdmitInput memory a)
    {
        CapabilityNode[] memory path = new CapabilityNode[](1);
        path[0] = _rootNodeFor(c, p, b);
        uint256[][] memory sets = new uint256[][](1);
        sets[0] = _rootSet();
        a = _input(L_PAY_ALICE, abi.encodeCall(IERC20.transfer, (alice, amt)), _u1(amt), path, sets, agentPk);
        (a.commit, a.params, a.budget) = (c, p, b);
    }

    function _rootId() internal view returns (bytes32) {
        return gate.rootCapId(MANDATE, _epoch());
    }

    // ═════════════════════════ propose / activate ═════════════════════════

    function test_activated_fixtureState() public view {
        AgentGate.MandateState memory s = gate.getMandate(MANDATE);
        assertEq(s.status, STATUS_ACTIVE);
        assertEq(s.epoch, 1);
        assertEq(s.era, 1);
        assertEq(s.principal, address(account));
        assertEq(gate.capRemaining(_rootId(), address(usdc)), 500e18);
    }

    function test_propose_requiresReadinessThreshold() public {
        activateAfter = uint64(vm.getBlockTimestamp() + 2 days);
        MandateCommit memory c = _commitWith(_params(), _budgetCap(400e18), expiry);
        (Attestation[] memory r, bytes32[][] memory rp) = _ready(c);
        Attestation[] memory one = new Attestation[](1);
        one[0] = r[0];
        bytes32[][] memory p1 = new bytes32[][](1);
        p1[0] = rp[0];
        vm.prank(owner);
        vm.expectRevert(A5_BelowThreshold.selector);
        account.execute(address(gate), 0, abi.encodeCall(AgentGate.proposeCommit, (c, _params(), one, p1)));
    }

    function test_propose_onlyByPrincipalAccount() public {
        MandateCommit memory c = _commit();
        (Attestation[] memory r, bytes32[][] memory rp) = _ready(c);
        vm.prank(owner); // the owner EOA is not the principal; the account is
        vm.expectRevert(NotPrincipal.selector);
        gate.proposeCommit(c, _params(), r, rp);
    }

    function test_propose_refusesAccountWithAgentBackdoor() public {
        vm.prank(owner);
        account.setOtherAuthority(agent, true);
        activateAfter = uint64(vm.getBlockTimestamp() + 2 days);
        MandateCommit memory c = _commit();
        (Attestation[] memory r, bytes32[][] memory rp) = _ready(c);
        vm.prank(owner);
        vm.expectRevert(A15_AccountConfig.selector);
        account.execute(address(gate), 0, abi.encodeCall(AgentGate.proposeCommit, (c, _params(), r, rp)));
    }

    function test_activate_notBeforeDelay() public {
        activateAfter = uint64(vm.getBlockTimestamp() + 1 days);
        MandateCommit memory c = _commitWith(_params(), _budgetCap(400e18), expiry);
        _proposeAs(c, _params());
        vm.warp(activateAfter - 1);
        vm.expectRevert(TooEarly.selector);
        gate.activate(c, _params(), _budgetCap(400e18));
    }

    /// SPEC §17 F-8: a replacement cannot shorten its own delay below the active one.
    function test_F8_replacementWaitsForTheLongerDelay() public {
        Params memory fast = _params();
        fast.activationDelay = 0;
        activateAfter = uint64(vm.getBlockTimestamp() + 1 hours);
        MandateCommit memory c = _commitWith(fast, _budget(), expiry);
        (Attestation[] memory r, bytes32[][] memory rp) = _ready(c);
        vm.prank(owner);
        vm.expectRevert(DelayTooShort.selector);
        account.execute(address(gate), 0, abi.encodeCall(AgentGate.proposeCommit, (c, fast, r, rp)));
    }

    function test_guardianVetoesPendingExpansion() public {
        MandateCommit memory active = _commit();
        MandateCommit memory c = _replacement(_params(), _budgetCap(900e18), uint64(vm.getBlockTimestamp() + 1 days));
        _proposeAs(c, _params());
        vm.prank(guardian);
        gate.vetoCommit(MANDATE, active, none); // guardian of the active commit
        vm.warp(c.activateAfter);
        vm.expectRevert(NothingPending.selector);
        gate.activate(c, _params(), _budgetCap(900e18));
    }

    /// Replacement is an expansion: old commit keeps working during the delay; activation
    /// bumps epoch and era, kills old tickets, and opens a fresh consumption ledger.
    function test_replacement_activatesAsNewEra() public {
        _settle(_payInput(L_PAY_ALICE, alice, 100e18));
        BudgetSpec memory bigger = _budgetCap(800e18);
        MandateCommit memory c = _replacement(_params(), bigger, uint64(vm.getBlockTimestamp() + 1 days));
        _proposeAs(c, _params());

        AdmitInput memory old = _payInput(L_PAY_ALICE, alice, 10e18); // still admissible
        (, TicketPreimage memory t) = gate.admit(old);

        vm.warp(c.activateAfter);
        gate.activate(c, _params(), bigger);
        AgentGate.MandateState memory s = gate.getMandate(MANDATE);
        assertEq(s.epoch, 2);
        assertEq(s.era, 2);
        assertEq(gate.capRemaining(_rootId(), address(usdc)), 800e18);

        vm.expectRevert(X4_StaleTicket.selector);
        settle.execute(_exec(old, t));
    }

    // ═════════════════════════ shrink ═════════════════════════

    /// SPEC §17 F-1: under spec B's wording, shrink re-initialises the root from epochCap and
    /// refunds what was already spent. Here the root gets cap − consumed.
    function test_F1_shrinkNeverRefundsConsumption() public {
        _settle(_payInput(L_PAY_ALICE, alice, 100e18));
        _settle(_payInput(L_PAY_ALICE, alice, 100e18));
        _settle(_payInput(L_PAY_ALICE, alice, 50e18));
        assertEq(gate.consumed(MANDATE, 1, address(usdc)), 250e18);

        AdmitInput memory pending = _payInput(L_PAY_ALICE, alice, 10e18);
        (, TicketPreimage memory t) = gate.admit(pending);

        BudgetSpec memory lower = _budgetCap(300e18);
        MandateCommit memory nc = _commitWith(_params(), lower, expiry);
        ShrinkInput memory x = ShrinkInput(_commit(), nc, _params(), _params(), _budget(), lower);
        _asPrincipal(abi.encodeCall(AgentGate.shrink, (x)));

        assertEq(gate.getMandate(MANDATE).epoch, 2);
        assertEq(gate.getMandate(MANDATE).era, 1, "shrink keeps the ledger");
        assertEq(gate.capRemaining(_rootId(), address(usdc)), 50e18, "300 cap - 250 consumed, not 300");

        vm.warp(t.windowEnd);
        vm.expectRevert(X4_StaleTicket.selector);
        settle.execute(_exec(pending, t));

        // The dead ticket's node reservation died with the epoch; its period reservation did not.
        settle.release(t, pending.proposal.capPath);

        AdmitInput memory tooMuch = _payUnder(nc, _params(), lower, 51e18);
        vm.expectRevert(A9_ExceedsBudget.selector);
        gate.admit(tooMuch);
        _settle(_payUnder(nc, _params(), lower, 50e18));
    }

    function test_shrink_rejectsLargerCap() public {
        BudgetSpec memory higher = _budgetCap(501e18);
        ShrinkInput memory x =
            ShrinkInput(_commit(), _commitWith(_params(), higher, expiry), _params(), _params(), _budget(), higher);
        vm.prank(owner);
        vm.expectRevert(NotShrink.selector);
        account.execute(address(gate), 0, abi.encodeCall(AgentGate.shrink, (x)));
    }

    function test_shrink_rejectsLowerThreshold() public {
        Params memory looser = _params();
        looser.attestThreshold = 1;
        ShrinkInput memory x =
            ShrinkInput(_commit(), _commitWith(looser, _budget(), expiry), _params(), looser, _budget(), _budget());
        vm.prank(owner);
        vm.expectRevert(NotShrink.selector);
        account.execute(address(gate), 0, abi.encodeCall(AgentGate.shrink, (x)));
    }

    function test_shrink_rejectsScopeChange() public {
        MandateCommit memory nc = _commit();
        nc.scopeRoot = keccak256("a smaller tree, allegedly");
        ShrinkInput memory x = ShrinkInput(_commit(), nc, _params(), _params(), _budget(), _budget());
        vm.prank(owner);
        vm.expectRevert(NotShrink.selector);
        account.execute(address(gate), 0, abi.encodeCall(AgentGate.shrink, (x)));
    }

    function test_shrink_earlierExpiryAndLongerWindow() public {
        Params memory slower = _params();
        slower.windowBase = 2 hours;
        uint64 sooner = expiry - 30 days;
        MandateCommit memory nc = _commitWith(slower, _budget(), sooner);
        ShrinkInput memory x = ShrinkInput(_commit(), nc, _params(), slower, _budget(), _budget());
        _asPrincipal(abi.encodeCall(AgentGate.shrink, (x)));
        (, TicketPreimage memory t) = gate.admit(_payUnder(nc, slower, _budget(), 10e18));
        assertEq(t.windowLen, 2 hours + 360);
        assertEq(t.pathMinExpiry, sooner);
    }

    // ═════════════════════════ suspend / revoke ═════════════════════════

    /// SPEC §17 F-7: a replacement proposed before a suspension must not resume the mandate.
    function test_F7_suspendClearsPendingReplacement() public {
        MandateCommit memory active = _commit();
        MandateCommit memory c = _replacement(_params(), _budgetCap(400e18), uint64(vm.getBlockTimestamp() + 1 days));
        _proposeAs(c, _params());
        vm.prank(guardian);
        gate.suspend(MANDATE, active, none);
        vm.warp(c.activateAfter);
        vm.expectRevert(NothingPending.selector);
        gate.activate(c, _params(), _budgetCap(400e18));
    }

    function test_suspend_thenResumeThroughFullDelay() public {
        MandateCommit memory active = _commit();
        vm.prank(guardian);
        gate.suspend(MANDATE, active, none);
        assertEq(gate.getMandate(MANDATE).status, STATUS_SUSPENDED);

        activateAfter = uint64(vm.getBlockTimestamp() + 1 days);
        MandateCommit memory c = _commitWith(_params(), _budget(), expiry);
        _proposeAs(c, _params());
        vm.warp(activateAfter);
        gate.activate(c, _params(), _budget());
        assertEq(gate.getMandate(MANDATE).status, STATUS_ACTIVE);
        assertEq(gate.getMandate(MANDATE).epoch, 3);
        _settle(_payUnder(c, _params(), _budget(), 1e18));
    }

    function test_suspend_strangerRejected() public {
        MandateCommit memory active = _commit();
        vm.prank(stranger);
        vm.expectRevert(NotAuthorized.selector);
        gate.suspend(MANDATE, active, none);
    }

    function test_revoke_isTerminal() public {
        vm.prank(guardian);
        vm.expectRevert(NotPrincipal.selector); // guardians may only suspend
        gate.revoke(MANDATE);

        _asPrincipal(abi.encodeCall(AgentGate.revoke, (MANDATE)));
        assertEq(gate.getMandate(MANDATE).status, STATUS_REVOKED);

        activateAfter = uint64(vm.getBlockTimestamp() + 1 days);
        MandateCommit memory c = _commit();
        (Attestation[] memory r, bytes32[][] memory rp) = _ready(c);
        vm.prank(owner);
        vm.expectRevert(Terminal.selector);
        account.execute(address(gate), 0, abi.encodeCall(AgentGate.proposeCommit, (c, _params(), r, rp)));
    }

    // ═════════════════════════ trip ═════════════════════════

    function test_trip_accountConfigDrift() public {
        MandateCommit memory c = _commit();
        ActionLeaf memory unused;
        vm.expectRevert(ConditionNotMet.selector);
        gate.trip(TRIP_ACCOUNT_CONFIG, c, unused, none);

        vm.prank(owner);
        account.installModule(keccak256("second executor"));
        vm.prank(stranger);
        gate.trip(TRIP_ACCOUNT_CONFIG, c, unused, none);
        assertEq(gate.getMandate(MANDATE).status, STATUS_SUSPENDED);
    }

    function test_trip_targetCodeDrift() public {
        MandateCommit memory c = _commit();
        ActionLeaf memory swapLeaf = _leaf(L_SWAP);
        bytes32[] memory proof = _scopeProof(_rootSet(), L_SWAP);
        vm.expectRevert(ConditionNotMet.selector);
        gate.trip(TRIP_CODE_DRIFT, c, swapLeaf, proof);

        vm.etch(address(router), hex"00");
        gate.trip(TRIP_CODE_DRIFT, c, swapLeaf, proof);
        assertEq(gate.getMandate(MANDATE).status, STATUS_SUSPENDED);
    }
}
