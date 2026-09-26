// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Attestation scheme adapter (SPEC.md §10). One deployment per scheme id.
/// @dev attestationHash already commits to every attestation field and the gate's EIP-712
///      domain. An implementation only decides whether `blob` proves that `attestor` signed it.
interface IAttestationVerifier {
    function verify(bytes32 scheme, bytes32 attestationHash, bytes32 attestor, bytes calldata blob)
        external
        view
        returns (bool);
}

/// @notice Smart-account module surface the gate relies on (SPEC.md §5 帳戶層, T7).
interface IAccountAdapter {
    /// @dev Must only accept calls from the installed gate and perform exactly one CALL.
    function executeFromGate(address target, uint256 value, bytes calldata data) external returns (bytes memory);

    /// @dev One read of the three facts below. The gate calls this, not the three functions.
    ///      A revert is a failed check. The three functions stay so a reviewer can compare them.
    function accountSnapshot(address agent)
        external
        view
        returns (address account, bytes32 digest, bool otherAuthority);

    /// @dev Digest of the account's owners, threshold, modules, guard, fallback handler, and module guard.
    function configDigest() external view returns (bytes32);

    /// @dev True if `agent` can act on the account through any path other than the gate.
    function agentAuthority(address agent) external view returns (bool);

    /// @dev Account whose funds this adapter moves. The gate rejects a commit that names a different principal.
    function account() external view returns (address);
}

/// @notice Sequencer liveness feed (T1).
interface ILivenessSource {
    function isUp() external view returns (bool);

    function lastChangeAt() external view returns (uint64);
}
