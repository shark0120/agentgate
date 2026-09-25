// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IRefinementVerifier} from "../interfaces/IRefinementVerifier.sol";

/// @title PublicPredicateVerifier — S0 proof type (spec §15 S0)
/// @notice P is a publicly checkable restricted predicate revealed inside the proof.
///         There is nothing sealed here: the verifier only accepts V = PUBLIC so that
///         no S0 mandate can be mistaken for a confidential one.
/// @dev With P public, knowing P is not a capability. Anyone could build "A ⊑ P" for
///      any dest ∈ D. The committed `agent` key therefore attests which refinement
///      the evaluator actually chose. That signature is a necessary conjunct of π,
///      never sufficient on its own (spec §3: session key ≠ mandate).
contract PublicPredicateVerifier is IRefinementVerifier {
    bytes32 public constant COMMIT_TAG = keccak256("SMP/S0/PublicPredicate/v1");
    bytes32 public constant VIS_PUBLIC = keccak256("SMP/V/PUBLIC");

    struct Predicate {
        address agent; // evaluator key that signs the chosen act digest
        uint256 perActCap; // A ⊑ P: cost(A) ≤ perActCap
        bool mayDelegate; // agent may issue strictly tighter sub-mandates
    }

    /// @notice Commit(M) = H(tag, P, D, V) for this proof type.
    function commitOf(Predicate memory p, bytes32 destRoot, bytes32 visHash) public pure returns (bytes32) {
        return keccak256(abi.encode(COMMIT_TAG, p.agent, p.perActCap, p.mayDelegate, destRoot, visHash));
    }

    /// @param proof abi.encode(Predicate p, bytes agentSignature)
    function verifyAct(
        bytes32 commit,
        bytes32 destRoot,
        bytes32 visHash,
        bytes32 actDigest,
        address, /* dest: membership is enforced by the gate on every path level */
        uint256 cost,
        bytes calldata proof
    ) external view returns (bool) {
        if (visHash != VIS_PUBLIC) return false;
        (Predicate memory p, bytes memory sig) = abi.decode(proof, (Predicate, bytes));
        if (p.agent == address(0)) return false;
        if (commitOf(p, destRoot, visHash) != commit) return false;
        if (cost > p.perActCap) return false;
        return SignatureChecker.isValidSignatureNow(p.agent, MessageHashUtils.toEthSignedMessageHash(actDigest), sig);
    }

    /// @param proof abi.encode(Predicate parentP, Predicate childP)
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
    ) external pure returns (bool) {
        // S0 can only compare opaque V hashes by equality; "not weaker" collapses to "same".
        if (parentVisHash != VIS_PUBLIC || childVisHash != VIS_PUBLIC) return false;
        (Predicate memory pp, Predicate memory cp) = abi.decode(proof, (Predicate, Predicate));
        if (commitOf(pp, parentDestRoot, parentVisHash) != parentCommit) return false;
        if (commitOf(cp, childDestRoot, childVisHash) != childCommit) return false;
        if (!callerIsParentPrincipal && !(pp.mayDelegate && caller == pp.agent)) return false;
        if (cp.agent == address(0)) return false;
        // P′ ⇒ P
        if (cp.perActCap > pp.perActCap) return false;
        if (cp.mayDelegate && !pp.mayDelegate) return false;
        return true;
    }
}
