// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgentGate} from "../../src/AgentGate.sol";
import {Sink} from "../mocks/Mocks.sol";
import "../../src/GateTypes.sol";
import "../../src/GateErrors.sol";
import {F1Base} from "./F1Base.sol";

/// @notice Shrink and suspend across USDC and native, not only the single-asset invariant.
contract MultiAssetTest is F1Base {
    function test_shrinkNeverRefundsUsdcOrNative() public {
        _settle(_payInput(L_PAY_ALICE, alice, 40e18));
        (CapabilityNode[] memory path, uint256[][] memory sets) = _pathRoot();
        AdmitInput memory nativePay = _input(L_NATIVE, abi.encodeCall(Sink.ping, ()), _u1(0.4 ether), path, sets, agentPk);
        nativePay.proposal.value = 0.4 ether;
        _sign(nativePay, agentPk);
        _settle(nativePay);
        assertEq(gate.consumed(MANDATE, 1, address(usdc)), 40e18);
        assertEq(gate.consumed(MANDATE, 1, NATIVE), 0.4 ether);

        BudgetSpec memory lower = _budget();
        lower.assets[0].epochCap = 50e18;
        lower.assets[1].epochCap = 0.5 ether;
        MandateCommit memory nc = _commitWith(_params(), lower, expiry);
        _asPrincipal(abi.encodeCall(AgentGate.shrink, (ShrinkInput(_commit(), nc, _params(), _params(), _budget(), lower))));

        assertEq(gate.getMandate(MANDATE).era, 1);
        assertEq(gate.consumed(MANDATE, 1, address(usdc)), 40e18, "USDC consumption is not refunded");
        assertEq(gate.consumed(MANDATE, 1, NATIVE), 0.4 ether, "native consumption is not refunded");
        assertEq(gate.capRemaining(gate.rootCapId(MANDATE, 2), address(usdc)), 10e18);
        assertEq(gate.capRemaining(gate.rootCapId(MANDATE, 2), NATIVE), 0.1 ether);
    }

    function test_suspendBlocksTheNextAdmission() public {
        MandateCommit memory c = _commit();
        _asPrincipal(abi.encodeCall(AgentGate.suspend, (MANDATE, c, new bytes32[](0))));
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 1e18);
        vm.expectRevert(A1_MandateNotLive.selector);
        gate.admit(a);
    }
}