// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SafeIntegrationTest} from "./SafeIntegration.sol";

/// @notice AgentGate against Safe v1.4.1 creation bytecode compiled from the tagged source.
contract Safe141Test is SafeIntegrationTest {
    function _singletonPath() internal pure override returns (string memory) {
        return "test/safe/bytecode/safe-1.4.1.bin";
    }

    function _factoryPath() internal pure override returns (string memory) {
        return "test/safe/bytecode/factory-1.4.1.bin";
    }

    function _handlerPath() internal pure override returns (string memory) {
        return "test/safe/bytecode/handler-1.4.1.bin";
    }
}