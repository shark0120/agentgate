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
    uint256 internal constant FIRST_PAGE = 1;
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

    function configDigest() public view returns (bytes32 digest) {
        (digest,) = _read(address(0));
    }

    /// @notice Bound account, config digest, and whether `agent` has another path. One Safe walk.
    function accountSnapshot(address agent) external view returns (address bound, bytes32 digest, bool otherAuthority) {
        bound = safe;
        (digest, otherAuthority) = _read(agent);
    }

    /// @dev Independent of `_read`. Tests compare this with the snapshot so the two cannot silently diverge.
    function agentAuthority(address agent) external view returns (bool) {
        if (agent == address(0) || agent == SENTINEL) return false;
        ISafeModule s = ISafeModule(safe);
        return s.isOwner(agent) || s.isModuleEnabled(agent);
    }

    /// @notice Every enabled module, or a revert. A partial list would hide a path from the digest.
    /// @dev The first page asks for one module. A one-module Safe is the common case and should not
    ///      allocate a 256-word buffer. Later pages are 8. A page that would pass the cap reverts
    ///      instead of being truncated.
    function moduleList() public view returns (address[] memory all) {
        address[] memory buf = new address[](FIRST_PAGE);
        uint256 n;
        address start = SENTINEL;
        uint256 pageSize = FIRST_PAGE;
        for (uint256 page; page < MAX_MODULES; ++page) {
            (address[] memory batch, address next) = ISafeModule(safe).getModulesPaginated(start, pageSize);
            uint256 add = batch.length;
            if (add > MAX_MODULES || n > MAX_MODULES - add) revert ModuleListTooLong();
            if (n + add > buf.length) {
                address[] memory grown = new address[](n + add);
                for (uint256 i; i < n; ++i) grown[i] = buf[i];
                buf = grown;
            }
            for (uint256 i; i < add; ++i) buf[n++] = batch[i];
            if (next == SENTINEL || next == address(0)) {
                assembly ("memory-safe") {
                    mstore(buf, n)
                }
                return buf;
            }
            if (next == start) revert ModuleListTooLong();
            start = next;
            pageSize = PAGE;
        }
        revert ModuleListTooLong();
    }

    /// @dev Digest encoding is unchanged. Authority is derived from the lists just read, so the hot
    ///      path does not also call `isOwner` and `isModuleEnabled`.
    function _read(address agent) internal view returns (bytes32 digest, bool other) {
        ISafeModule s = ISafeModule(safe);
        address[] memory owners = s.getOwners();
        address[] memory modules = moduleList();
        digest = keccak256(
            abi.encode(owners, s.getThreshold(), modules, _slot(GUARD_SLOT), _slot(FALLBACK_SLOT), _slot(MODULE_GUARD_SLOT))
        );
        if (agent == address(0) || agent == SENTINEL) return (digest, false);
        other = _listed(owners, agent) || _listed(modules, agent);
    }

    function _listed(address[] memory xs, address x) internal pure returns (bool) {
        for (uint256 i; i < xs.length; ++i) {
            if (xs[i] == x) return true;
        }
        return false;
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