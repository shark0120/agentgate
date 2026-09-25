// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccountAdapter} from "./interfaces/IGateExternal.sol";

/// @title SafeAgentGateAdapter — the only module an AgentGate mandate should enable on a Safe.
/// @notice Binds one Safe to one gate. executeFromGate performs exactly one CALL through
///         execTransactionFromModule. No function on this contract requests DELEGATECALL.
/// @dev The same bytecode talks to Safe v1.4.1 and v1.5.0. The module-guard slot is part of the
///      digest on both; v1.4.1 leaves it zero. A truncated module list reverts rather than hiding a path.
contract SafeAgentGateAdapter is IAccountAdapter {
    uint8 internal constant OP_CALL = 0;
    address internal constant SENTINEL = address(0x1);
    uint256 internal constant PAGE = 8;
    uint256 internal constant MAX_MODULES = 256;

    // Safe storage slots. Identical in v1.4.1 and v1.5.0.
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    address public immutable gate;
    address public immutable safe;

    error ZeroAddress();
    error NotGate();
    error DelegateCallRefused();
    error ExecutionFailed();
    error ModuleListTooLong();

    constructor(address gate_, address safe_) {
        if (gate_ == address(0) || safe_ == address(0)) revert ZeroAddress();
        gate = gate_;
        safe = safe_;
    }

    function account() external view returns (address) {
        return safe;
    }

    function executeFromGate(address target, uint256 value, bytes calldata data) external returns (bytes memory ret) {
        if (msg.sender != gate) revert NotGate();
        (bool ok, bytes memory raw) =
            ISafeModule(safe).execTransactionFromModuleReturnData(target, value, data, OP_CALL);
        if (!ok) {
            if (raw.length == 0) revert ExecutionFailed();
            assembly ("memory-safe") {
                revert(add(raw, 0x20), mload(raw))
            }
        }
        return raw;
    }

    /// @notice Explicit refusal. The CALL entry point above is the only execution path.
    function executeDelegateFromGate(address, uint256, bytes calldata) external pure returns (bytes memory) {
        revert DelegateCallRefused();
    }

    function configDigest() public view returns (bytes32) {
        ISafeModule s = ISafeModule(safe);
        return keccak256(
            abi.encode(s.getOwners(), s.getThreshold(), moduleList(), _slot(GUARD_SLOT), _slot(FALLBACK_SLOT), _slot(MODULE_GUARD_SLOT))
        );
    }

    function agentAuthority(address agent) external view returns (bool) {
        if (agent == address(0) || agent == SENTINEL) return false;
        ISafeModule s = ISafeModule(safe);
        return s.isOwner(agent) || s.isModuleEnabled(agent);
    }

    /// @notice Every enabled module, or a revert. A partial list would hide a path from the digest.
    function moduleList() public view returns (address[] memory all) {
        address[] memory buf = new address[](MAX_MODULES);
        uint256 n;
        address start = SENTINEL;
        for (uint256 page; page < MAX_MODULES / PAGE; ++page) {
            (address[] memory batch, address next) = ISafeModule(safe).getModulesPaginated(start, PAGE);
            for (uint256 i; i < batch.length; ++i) {
                if (n == MAX_MODULES) revert ModuleListTooLong();
                buf[n++] = batch[i];
            }
            if (next == SENTINEL || next == address(0)) {
                assembly ("memory-safe") {
                    mstore(buf, n)
                }
                return buf;
            }
            if (next == start) revert ModuleListTooLong();
            start = next;
        }
        revert ModuleListTooLong();
    }

    function _slot(bytes32 slot) internal view returns (address a) {
        bytes memory raw = ISafeModule(safe).getStorageAt(uint256(slot), 1);
        if (raw.length < 32) return address(0);
        assembly ("memory-safe") {
            a := and(mload(add(raw, 0x20)), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }
}

interface ISafeModule {
    function execTransactionFromModuleReturnData(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool success, bytes memory returnData);

    function isOwner(address owner) external view returns (bool);

    function getThreshold() external view returns (uint256);

    function getOwners() external view returns (address[] memory);

    function isModuleEnabled(address module) external view returns (bool);

    function getModulesPaginated(address start, uint256 pageSize)
        external
        view
        returns (address[] memory array, address next);

    function getStorageAt(uint256 offset, uint256 length) external view returns (bytes memory);
}