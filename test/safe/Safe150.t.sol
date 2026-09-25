// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PermissiveGuard, SafeIntegrationTest} from "./SafeIntegration.sol";

/// @notice AgentGate against Safe v1.5.0 creation bytecode compiled from the tagged source.
contract Safe150Test is SafeIntegrationTest {
    function _singletonPath() internal pure override returns (string memory) {
        return "test/safe/bytecode/safe-1.5.0.bin";
    }

    function _factoryPath() internal pure override returns (string memory) {
        return "test/safe/bytecode/factory-1.5.0.bin";
    }

    function _handlerPath() internal pure override returns (string memory) {
        return "test/safe/bytecode/handler-1.5.0.bin";
    }

    function test_setModuleGuardBlocksExecutionAndTrips() public {
        _blocksAndTrips(abi.encodeWithSignature("setModuleGuard(address)", address(new PermissiveGuard())));
    }
}