// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgentGate} from "../../src/AgentGate.sol";
import "../../src/GateTypes.sol";
import "../../src/GateErrors.sol";
import {F1Base} from "./F1Base.sol";

contract AdapterFieldTest is F1Base {
    function test_zeroAdapterRejected() public {
        MandateCommit memory c = _commit();
        c.adapter = address(0);
        Attestation[] memory none;
        bytes32[][] memory proofs;
        vm.expectRevert(InvalidCommit.selector);
        _asPrincipal(abi.encodeCall(AgentGate.proposeCommit, (c, _params(), none, proofs)));
    }

    function test_changingAdapterIsNotAShrink() public {
        MandateCommit memory oldC = _commit();
        MandateCommit memory newC = _commit();
        newC.adapter = address(0xBEEF);
        ShrinkInput memory x = ShrinkInput(oldC, newC, _params(), _params(), _budget(), _budget());
        vm.expectRevert(NotShrink.selector);
        _asPrincipal(abi.encodeCall(AgentGate.shrink, (x)));
    }
}