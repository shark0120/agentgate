// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Proof-system adapter for the Finality Gate (spec §9, §16.3 verifyProof).
/// @dev Each proof type owns its commitment format. A commitment produced for one
///      type must never verify under another (domain-tag the preimage).
///      Implementations must be stateless views: the gate relies on a proof that
///      verified at submit time staying valid until finalize.
interface IRefinementVerifier {
    /// @notice refine_ok ∧ vis_ok for a candidate act (spec π).
    /// @dev dest ∈ D, budget, window and epoch are checked by the gate, not here.
    function verifyAct(
        bytes32 commit,
        bytes32 destRoot,
        bytes32 visHash,
        bytes32 actDigest,
        address dest,
        uint256 cost,
        bytes calldata proof
    ) external view returns (bool);

    /// @notice P′ ⇒ P ∧ V′ not weaker than V ∧ caller may delegate under P (spec §2.4, §8.1).
    /// @dev D′ ⊆ D is not checked here: the gate enforces dest ∈ D at every level of
    ///      the delegation path when an act is spent.
    function verifyDelegation(
        bytes32 parentCommit,
        bytes32 parentDestRoot,
        bytes32 parentVisHash,
        bytes32 childCommit,
        bytes32 childDestRoot,
        bytes32 childVisHash,
        address caller,
        bool callerIsParentPrincipal,
        bytes calldata proof
    ) external view returns (bool);
}
