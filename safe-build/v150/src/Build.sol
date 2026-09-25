// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import "safe/Safe.sol";
import "safe/proxies/SafeProxyFactory.sol";
import "safe/handler/CompatibilityFallbackHandler.sol";

contract Build {
    function names() external pure returns (string memory) {
        return type(Safe).name;
    }
}