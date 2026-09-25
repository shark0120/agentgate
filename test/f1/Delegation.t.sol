// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AgentGate} from "../../src/AgentGate.sol";
import {GateSettlement} from "../../src/GateSettlement.sol";
import "../../src/GateTypes.sol";
import "../../src/GateErrors.sol";
import {F1Base} from "./F1Base.sol";

/// @notice SPEC.md §9: delegation as an action (D1), use-time scope intersection (D2),
///         allotment carving (D3), reclaim (D4), node epochs (D6), role separation (D10), G1–G4.
contract DelegationTest is F1Base {
    uint256[] internal childSet; // scope of the default child: pay alice, pay dave, delegate

    function setUp() public override {
        super.setUp();
        childSet.push(L_PAY_ALICE);
        childSet.push(L_PAY_DAVE);
        childSet.push(L_DELEGATE);
    }

    // ═════════════════════════ builders ═════════════════════════

    function _childNode(
        CapabilityNode memory parent,
        address delegatee,
        uint256[] memory scope,
        uint256 allot,
        uint64 exp,
        bool canDelegate
    ) internal view returns (CapabilityNode memory c) {
        c.capId = gate.childCapId(MANDATE, nonceCounter + 1); // the nonce _input will use
        c.mandateId = MANDATE;
        c.mandateEpoch = _epoch();
        c.parentCapId = parent.capId;
        c.parentNodeEpoch = 0;
        c.delegatee = delegatee;
        c.scopeRoot = _scopeRootOf(scope);
        c.depth = parent.depth + 1;
        c.expiry = exp;
        c.canDelegate = canDelegate;
        c.allotment = new AssetAmount[](1);
        c.allotment[0] = AssetAmount(address(usdc), allot);
    }

    function _delegateInput(
        CapabilityNode[] memory path,
        uint256[][] memory sets,
        uint256 signerPk,
        CapabilityNode memory child
    ) internal returns (AdmitInput memory) {
        bytes memory data = abi.encodeWithSelector(DELEGATE_SEL, child);
        return _input(L_DELEGATE, data, _u1(child.allotment[0].amount), path, sets, signerPk);
    }

    /// @notice root → child(subAgent, childSet, 150 USDC), settled.
    function _makeChild() internal returns (CapabilityNode[] memory path, uint256[][] memory sets) {
        (CapabilityNode[] memory rp, uint256[][] memory rs) = _pathRoot();
        CapabilityNode memory child = _childNode(rp[0], subAgent, childSet, 150e18, uint64(vm.getBlockTimestamp() + 20 days), true);
        _settle(_delegateInput(rp, rs, agentPk, child));
        path = new CapabilityNode[](2);
        (path[0], path[1]) = (rp[0], child);
        sets = new uint256[][](2);
        (sets[0], sets[1]) = (rs[0], childSet);
    }

    function _childPay(CapabilityNode[] memory path, uint256[][] memory sets, uint256 leafIdx, address to, uint256 amt)
        internal
        returns (AdmitInput memory)
    {
        return _input(leafIdx, abi.encodeCall(IERC20.transfer, (to, amt)), _u1(amt), path, sets, subAgentPk);
    }

    // ═════════════════════════ D1 / D3 ═════════════════════════

    function test_D1_D3_delegationCarvesThenChildSpends() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _makeChild();
        bytes32 rootId = path[0].capId;
        bytes32 childId = path[1].capId;
        assertEq(gate.capHash(childId), keccak256(abi.encode(path[1])));
        assertEq(gate.capRemaining(rootId, address(usdc)), 350e18);
        assertEq(gate.capRemaining(childId, address(usdc)), 150e18);
        assertEq(gate.consumed(MANDATE, 1, address(usdc)), 0, "carving is not spending");

        _settle(_childPay(path, sets, L_PAY_ALICE, alice, 50e18));
        assertEq(usdc.balanceOf(alice), 50e18);
        assertEq(gate.capRemaining(childId, address(usdc)), 100e18);
        assertEq(gate.capRemaining(rootId, address(usdc)), 350e18);
        assertEq(gate.consumed(MANDATE, 1, address(usdc)), 50e18);
    }

    function test_D1_parentAgentCannotSpendChildAllotment() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _makeChild();
        AdmitInput memory a = _input(
            L_PAY_ALICE, abi.encodeCall(IERC20.transfer, (alice, 1e18)), _u1(1e18), path, sets, agentPk
        );
        vm.expectRevert(A6_BadAgentSig.selector);
        gate.admit(a);
    }

    // ═════════════════════════ D2 ═════════════════════════

    /// The child committed to a scope with dave in it; the root never did. Never usable.
    function test_D2_childScopeWiderThanParent_neverUsable() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _makeChild();
        AdmitInput memory a = _childPay(path, sets, L_PAY_DAVE, dave, 1e18);
        vm.expectRevert(A3_OutOfScope.selector);
        gate.admit(a);
    }

    // ═════════════════════════ V5 / A9 ═════════════════════════

    function test_V5_childCannotExceedItsAllotment() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _makeChild();
        _settle(_childPay(path, sets, L_PAY_ALICE, alice, 100e18));
        AdmitInput memory a = _childPay(path, sets, L_PAY_ALICE, alice, 51e18);
        vm.expectRevert(A9_ExceedsBudget.selector);
        gate.admit(a);
    }

    function test_G3_siblingsCannotOversubscribe() public {
        (CapabilityNode[] memory rp, uint256[][] memory rs) = _pathRoot();
        uint64 exp = uint64(vm.getBlockTimestamp() + 20 days);
        gate.admit(_delegateInput(rp, rs, agentPk, _childNode(rp[0], subAgent, childSet, 300e18, exp, false)));
        AdmitInput memory a = _delegateInput(rp, rs, agentPk, _childNode(rp[0], subAgent, childSet, 201e18, exp, false));
        vm.expectRevert(A9_ExceedsBudget.selector);
        gate.admit(a);
    }

    // ═════════════════════════ G1–G4 ═════════════════════════

    function test_G1_nodeWithoutDelegateRight() public {
        (CapabilityNode[] memory rp, uint256[][] memory rs) = _pathRoot();
        CapabilityNode memory child =
            _childNode(rp[0], subAgent, childSet, 150e18, uint64(vm.getBlockTimestamp() + 20 days), false);
        _settle(_delegateInput(rp, rs, agentPk, child));
        CapabilityNode[] memory path = new CapabilityNode[](2);
        (path[0], path[1]) = (rp[0], child);
        uint256[][] memory sets = new uint256[][](2);
        (sets[0], sets[1]) = (rs[0], childSet);

        AdmitInput memory a = _delegateInput(
            path, sets, subAgentPk, _childNode(child, agent, childSet, 10e18, child.expiry, false)
        );
        vm.expectRevert(G1_CannotDelegate.selector);
        gate.admit(a);
    }

    function test_G1_depthLimit() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _makeChild(); // depth 1
        CapabilityNode memory grand = _childNode(path[1], agent, childSet, 50e18, path[1].expiry, true);
        _settle(_delegateInput(path, sets, subAgentPk, grand)); // depth 2 == maxDepth

        CapabilityNode[] memory p3 = new CapabilityNode[](3);
        (p3[0], p3[1], p3[2]) = (path[0], path[1], grand);
        uint256[][] memory s3 = new uint256[][](3);
        (s3[0], s3[1], s3[2]) = (sets[0], childSet, childSet);
        AdmitInput memory a = _delegateInput(p3, s3, agentPk, _childNode(grand, subAgent, childSet, 1e18, grand.expiry, false));
        vm.expectRevert(G1_CannotDelegate.selector);
        gate.admit(a);
    }

    function test_G2_childOutlivesParent() public {
        (CapabilityNode[] memory rp, uint256[][] memory rs) = _pathRoot();
        AdmitInput memory a =
            _delegateInput(rp, rs, agentPk, _childNode(rp[0], subAgent, childSet, 10e18, rp[0].expiry + 1, false));
        vm.expectRevert(G2_ExpiryWidens.selector);
        gate.admit(a);
    }

    function test_G3_allotmentDiffersFromDeclared() public {
        (CapabilityNode[] memory rp, uint256[][] memory rs) = _pathRoot();
        CapabilityNode memory child =
            _childNode(rp[0], subAgent, childSet, 150e18, uint64(vm.getBlockTimestamp() + 1 days), false);
        bytes memory data = abi.encodeWithSelector(DELEGATE_SEL, child);
        AdmitInput memory a = _input(L_DELEGATE, data, _u1(100e18), rp, rs, agentPk); // reserve only 100
        vm.expectRevert(G3_AllotmentMismatch.selector);
        gate.admit(a);
    }

    function test_G4_childIdNotDerivedFromNonce() public {
        (CapabilityNode[] memory rp, uint256[][] memory rs) = _pathRoot();
        CapabilityNode memory child =
            _childNode(rp[0], subAgent, childSet, 10e18, uint64(vm.getBlockTimestamp() + 1 days), false);
        child.capId = keccak256("squat");
        AdmitInput memory a = _delegateInput(rp, rs, agentPk, child);
        vm.expectRevert(G4_BadChildBinding.selector);
        gate.admit(a);
    }

    function test_G4_childBoundToStaleEpoch() public {
        (CapabilityNode[] memory rp, uint256[][] memory rs) = _pathRoot();
        CapabilityNode memory child =
            _childNode(rp[0], subAgent, childSet, 10e18, uint64(vm.getBlockTimestamp() + 1 days), false);
        child.mandateEpoch -= 1;
        AdmitInput memory a = _delegateInput(rp, rs, agentPk, child);
        vm.expectRevert(G4_BadChildBinding.selector);
        gate.admit(a);
    }

    // ═════════════════════════ D10 ═════════════════════════

    function test_D10_delegateeCannotAttestForItsOwnPath() public {
        (CapabilityNode[] memory rp, uint256[][] memory rs) = _pathRoot();
        uint256 attesterAsAgentPk = attPk[0];
        CapabilityNode memory child =
            _childNode(rp[0], att[0], childSet, 50e18, uint64(vm.getBlockTimestamp() + 20 days), false);
        _settle(_delegateInput(rp, rs, agentPk, child));
        CapabilityNode[] memory path = new CapabilityNode[](2);
        (path[0], path[1]) = (rp[0], child);
        uint256[][] memory sets = new uint256[][](2);
        (sets[0], sets[1]) = (rs[0], childSet);

        AdmitInput memory a =
            _input(L_PAY_ALICE, abi.encodeCall(IERC20.transfer, (alice, 1e18)), _u1(1e18), path, sets, attesterAsAgentPk);
        vm.expectRevert(A5_RoleConflict.selector); // att[0] signs as agent and attests
        gate.admit(a);

        // Two attestors off the path suffice.
        bytes32 ph = gate.proposalHash(a.proposal);
        a.attestations[0] = _attest(1, ph, a.proposal.epoch, a.proposal.stateRef);
        a.attestations[1] = _attest(2, ph, a.proposal.epoch, a.proposal.stateRef);
        (a.attestorProofs[0], a.attestorProofs[1]) = (_attestorProof(1), _attestorProof(2));
        gate.admit(a);
    }

    // ═════════════════════════ D6 / D4 ═════════════════════════

    function test_D6_parentHolderRevokesChild_thenReclaim() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _makeChild();
        _settle(_childPay(path, sets, L_PAY_ALICE, alice, 30e18));
        AdmitInput memory pending = _childPay(path, sets, L_PAY_ALICE, alice, 20e18);
        (, TicketPreimage memory t) = gate.admit(pending);

        vm.prank(stranger);
        vm.expectRevert(NotAuthorized.selector);
        settle.revokeCap(path, 1);

        vm.prank(agent); // holder of the parent
        settle.revokeCap(path, 1);

        AdmitInput memory a = _childPay(path, sets, L_PAY_ALICE, alice, 1e18);
        vm.expectRevert(A2_BadCapPath.selector);
        gate.admit(a);

        vm.warp(t.windowEnd);
        vm.expectRevert(X4_StaleTicket.selector);
        settle.execute(_exec(pending, t));

        settle.release(t, pending.proposal.capPath); // reservation back to the dead child
        settle.reclaim(path); // and from there to the root
        assertEq(gate.capRemaining(path[1].capId, address(usdc)), 0);
        assertEq(gate.capRemaining(path[0].capId, address(usdc)), 350e18 + 120e18);
    }

    function test_D4_reclaimRefusesLiveNode() public {
        (CapabilityNode[] memory path,) = _makeChild();
        vm.expectRevert(NodeStillLive.selector);
        settle.reclaim(path);
    }

    function test_D4_expiredChildFlowsBack() public {
        (CapabilityNode[] memory path,) = _makeChild();
        vm.warp(path[1].expiry);
        settle.reclaim(path);
        assertEq(gate.capRemaining(path[0].capId, address(usdc)), 500e18);
    }

    function test_D4_D5_mandateEpochChange_noReflow() public {
        (CapabilityNode[] memory path,) = _makeChild();
        _asPrincipal(abi.encodeCall(AgentGate.suspend, (MANDATE, _commit(), new bytes32[](0))));
        vm.expectRevert(NoLiveAncestor.selector);
        settle.reclaim(path);
    }

    function test_D6_grandchildDiesWithRevokedChild() public {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _makeChild();
        CapabilityNode memory grand = _childNode(path[1], agent, childSet, 50e18, path[1].expiry, false);
        _settle(_delegateInput(path, sets, subAgentPk, grand));
        vm.prank(owner);
        account.execute(address(gate), 0, abi.encodeCall(GateSettlement.revokeCap, (path, 1)));

        CapabilityNode[] memory p3 = new CapabilityNode[](3);
        (p3[0], p3[1], p3[2]) = (path[0], path[1], grand);
        uint256[][] memory s3 = new uint256[][](3);
        (s3[0], s3[1], s3[2]) = (sets[0], childSet, childSet);
        AdmitInput memory a =
            _input(L_PAY_ALICE, abi.encodeCall(IERC20.transfer, (alice, 1e18)), _u1(1e18), p3, s3, agentPk);
        vm.expectRevert(A2_BadCapPath.selector);
        gate.admit(a);

        settle.reclaim(p3); // nearest live ancestor of the grandchild is the root
        assertEq(gate.capRemaining(path[0].capId, address(usdc)), 350e18 + 50e18);
    }
}
