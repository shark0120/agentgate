// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IAttestationVerifier, ILivenessSource} from "./interfaces/IGateExternal.sol";
import {GateBase} from "./GateBase.sol";
import {GateSettlement} from "./GateSettlement.sol";
import {GateChecks} from "./libraries/GateChecks.sol";
import "./GateTypes.sol";
import "./GateErrors.sol";

/// @title AgentGate — fused SMP × settlement-gate spec, stage F1 (SPEC.md)
/// @notice Registry and admission for agent actions executed through a principal's smart account.
///         The gate never holds assets: budgets are counters, and the account performs the single
///         CALL the gate hands it at settlement.
/// @dev No owner, no upgrade path, no global switch. Attestation verifiers and the settlement
///      extension are fixed at construction. Settlement functions (execute, veto,
///      withdrawAttestation, cancel, release, revokeCap, reclaim) live in GateSettlement and are
///      reached through the fallback with the caller's calldata untouched.
contract AgentGate is GateBase {
    address public immutable settlement;

    constructor(bytes32[] memory schemes, address[] memory verifiers, ILivenessSource liveness_, address settlement_)
        GateBase(liveness_)
    {
        if (schemes.length != verifiers.length) revert InvalidParams();
        if (GateSettlement(settlement_).liveness() != liveness_) revert InvalidParams();
        for (uint256 i; i < schemes.length; ++i) {
            if (schemeVerifier[schemes[i]] != address(0) || verifiers[i] == address(0)) revert InvalidParams();
            schemeVerifier[schemes[i]] = verifiers[i];
        }
        settlement = settlement_;
    }

    fallback() external {
        address impl = settlement;
        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }

    // ═══════════════════════════════ Registry ═══════════════════════════════

    function proposeCommit(
        MandateCommit calldata c,
        Params calldata p,
        Attestation[] calldata ready,
        bytes32[][] calldata readyProofs
    ) external nonReentrant {
        if (msg.sender != c.principalAccount) revert NotPrincipal();
        MandateState storage s = _mandates[c.mandateId];
        if (s.status == STATUS_NONE) {
            s.principal = c.principalAccount;
            s.status = STATUS_INACTIVE;
        } else if (s.principal != c.principalAccount) {
            revert NotPrincipal();
        } else if (s.status == STATUS_REVOKED) {
            revert Terminal();
        }
        if (keccak256(abi.encode(p)) != c.paramsHash) revert A4_PreimageMismatch();
        if (
            c.rootDelegatee == address(0) || c.rootDelegatee == c.principalAccount || c.adapter == address(0)
                || c.expiry <= c.activateAfter
        ) {
            revert InvalidCommit();
        }
        if (p.attestThreshold == 0 || p.maxStateAge == 0 || p.maxStateAge > 256) revert InvalidParams();
        uint256 delay = p.activationDelay > s.activationDelay ? p.activationDelay : s.activationDelay;
        if (c.activateAfter < block.timestamp + delay) revert DelayTooShort();
        if (!_accountOk(c.principalAccount, c.adapter, c.accountConfigDigest, c.rootDelegatee)) revert A15_AccountConfig();

        bytes32 ch = keccak256(abi.encode(c));
        address[] memory forbidden = new address[](1);
        forbidden[0] = c.rootDelegatee;
        uint256 n = _countAttestations(
            ready, readyProofs, readyHash(ch), c.policyHash, 0, StateRef(0, 0), p, c.attestorSetRoot, forbidden
        );
        if (n < p.attestThreshold) revert A5_BelowThreshold();

        s.pendingCommitHash = ch;
        emit CommitProposed(c.mandateId, ch);
    }

    function cancelCommit(bytes32 mandateId) external nonReentrant {
        MandateState storage s = _mandates[mandateId];
        if (msg.sender != s.principal) revert NotPrincipal();
        if (s.pendingCommitHash == 0) revert NothingPending();
        s.pendingCommitHash = 0;
        emit CommitCleared(mandateId, msg.sender);
    }

    /// @notice A guardian of the active or the pending commit blocks a pending expansion.
    function vetoCommit(bytes32 mandateId, MandateCommit calldata source, bytes32[] calldata guardianProof)
        external
        nonReentrant
    {
        MandateState storage s = _mandates[mandateId];
        if (s.pendingCommitHash == 0) revert NothingPending();
        bytes32 h = keccak256(abi.encode(source));
        if (h != s.commitHash && h != s.pendingCommitHash) revert A4_PreimageMismatch();
        if (!_isGuardian(source.guardianSetRoot, msg.sender, guardianProof)) revert NotAuthorized();
        s.pendingCommitHash = 0;
        emit CommitCleared(mandateId, msg.sender);
    }

    function activate(MandateCommit calldata c, Params calldata p, BudgetSpec calldata b) external nonReentrant {
        MandateState storage s = _mandates[c.mandateId];
        bytes32 ch = keccak256(abi.encode(c));
        if (s.pendingCommitHash == 0 || ch != s.pendingCommitHash) revert NothingPending();
        if (block.timestamp < c.activateAfter) revert TooEarly();
        if (block.timestamp >= c.expiry) revert A1_MandateNotLive();
        if (keccak256(abi.encode(p)) != c.paramsHash || keccak256(abi.encode(b)) != c.budgetHash) {
            revert A4_PreimageMismatch();
        }
        if (!_accountOk(c.principalAccount, c.adapter, c.accountConfigDigest, c.rootDelegatee)) revert A15_AccountConfig();

        s.commitHash = ch;
        s.pendingCommitHash = 0;
        s.status = STATUS_ACTIVE;
        s.activationDelay = p.activationDelay;
        s.epoch += 1;
        s.era += 1;
        CapabilityNode memory root = _initRoot(c, p, b, s);
        emit Activated(c.mandateId, s.epoch, s.era, root);
    }

    /// @notice Numeric-only contraction, effective immediately. Keeps the era, so consumption
    ///         already recorded is never refunded (SPEC §17 F-1).
    function shrink(ShrinkInput calldata x) external nonReentrant {
        MandateState storage s = _mandates[x.oldCommit.mandateId];
        if (msg.sender != s.principal) revert NotPrincipal();
        if (s.status != STATUS_ACTIVE) revert A1_MandateNotLive();
        if (keccak256(abi.encode(x.oldCommit)) != s.commitHash) revert A4_PreimageMismatch();
        if (
            keccak256(abi.encode(x.oldParams)) != x.oldCommit.paramsHash
                || keccak256(abi.encode(x.oldBudget)) != x.oldCommit.budgetHash
                || keccak256(abi.encode(x.newParams)) != x.newCommit.paramsHash
                || keccak256(abi.encode(x.newBudget)) != x.newCommit.budgetHash
        ) revert A4_PreimageMismatch();
        GateChecks.requireShrink(x);

        s.commitHash = keccak256(abi.encode(x.newCommit));
        s.activationDelay = x.newParams.activationDelay;
        s.epoch += 1;
        CapabilityNode memory root = _initRoot(x.newCommit, x.newParams, x.newBudget, s);
        emit Shrunk(x.oldCommit.mandateId, s.epoch, root);
    }

    function suspend(bytes32 mandateId, MandateCommit calldata c, bytes32[] calldata guardianProof)
        external
        nonReentrant
    {
        MandateState storage s = _mandates[mandateId];
        if (s.status != STATUS_ACTIVE) revert A1_MandateNotLive();
        if (msg.sender != s.principal) {
            if (keccak256(abi.encode(c)) != s.commitHash) revert A4_PreimageMismatch();
            if (!_isGuardian(c.guardianSetRoot, msg.sender, guardianProof)) revert NotAuthorized();
        }
        _halt(mandateId, s, STATUS_SUSPENDED);
    }

    function revoke(bytes32 mandateId) external nonReentrant {
        MandateState storage s = _mandates[mandateId];
        if (msg.sender != s.principal) revert NotPrincipal();
        if (s.status == STATUS_REVOKED) revert Terminal();
        _halt(mandateId, s, STATUS_REVOKED);
    }

    /// @notice Anyone may suspend a mandate whose objective precondition is broken (T6, T7).
    function trip(uint8 code, MandateCommit calldata c, ActionLeaf calldata leaf, bytes32[] calldata scopeProof)
        external
        nonReentrant
    {
        MandateState storage s = _mandates[c.mandateId];
        if (s.status != STATUS_ACTIVE) revert A1_MandateNotLive();
        if (keccak256(abi.encode(c)) != s.commitHash) revert A4_PreimageMismatch();
        bool broken;
        if (code == TRIP_ACCOUNT_CONFIG) {
            broken = !_accountOk(c.principalAccount, c.adapter, c.accountConfigDigest, c.rootDelegatee);
        } else if (code == TRIP_CODE_DRIFT) {
            bytes32 member = keccak256(bytes.concat(keccak256(abi.encode(leaf))));
            if (!MerkleProof.verifyCalldata(scopeProof, c.scopeRoot, member)) revert A3_OutOfScope();
            broken = leaf.leafType == LEAF_CALL && leaf.target.codehash != leaf.codeHash;
        }
        if (!broken) revert ConditionNotMet();
        emit Tripped(c.mandateId, code);
        _halt(c.mandateId, s, STATUS_SUSPENDED);
    }

    // ═══════════════════════════════ Admission ═══════════════════════════════

    function admit(AdmitInput calldata a) external nonReentrant returns (bytes32 ticketHash, TicketPreimage memory t) {
        Proposal calldata p = a.proposal;
        MandateState storage s = _mandates[p.mandateId];

        // A1, A4
        if (s.status != STATUS_ACTIVE || p.epoch != s.epoch) revert A1_MandateNotLive();
        if (keccak256(abi.encode(a.commit)) != s.commitHash) revert A4_PreimageMismatch();
        if (block.timestamp >= a.commit.expiry) revert A1_MandateNotLive();
        if (
            keccak256(abi.encode(a.params)) != a.commit.paramsHash
                || keccak256(abi.encode(a.budget)) != a.commit.budgetHash
        ) revert A4_PreimageMismatch();

        bytes32 ph = _proposalHash(p);
        // A2, A3, A11
        (address[] memory delegatees, uint64 minExpiry) = _checkPath(a, s.epoch);
        address agent = delegatees[delegatees.length - 1];
        // A10, A12, A13, A14, A16, A17
        GateChecks.checkLeafAndCalldata(a.leaf, p, a.data, a.commit.principalAccount);
        // A6, A15
        if (!SignatureChecker.isValidSignatureNow(agent, ph, a.agentSig)) revert A6_BadAgentSig();
        if (!_accountOk(a.commit.principalAccount, a.commit.adapter, a.commit.accountConfigDigest, agent)) revert A15_AccountConfig();
        // A7, A8
        _useNonce(p.mandateId, p.nonce);
        _checkValidity(p, a.params.maxStateAge);
        // A5, D10
        if (
            _countAttestations(
                a.attestations,
                a.attestorProofs,
                ph,
                a.commit.policyHash,
                p.epoch,
                p.stateRef,
                a.params,
                a.commit.attestorSetRoot,
                delegatees
            ) < a.params.attestThreshold
        ) revert A5_BelowThreshold();
        // G1–G4
        if (a.leaf.leafType == LEAF_DELEGATE) {
            CapabilityNode calldata parent = a.path[a.path.length - 1];
            bytes32 childId = childCapId(p.mandateId, p.nonce);
            GateChecks.checkDelegationShape(
                a.data, parent, p, a.params.maxDepth, s.epoch, nodeEpoch[parent.capId], childId
            );
            if (capHash[childId] != 0) revert G4_BadChildBinding();
        }

        bytes32 usedCap = p.capPath[p.capPath.length - 1];
        t.periodIdx = _reserve(a, usedCap, s.era); // A9
        t.proposalHash = ph;
        t.mandateId = p.mandateId;
        t.capId = usedCap;
        t.capPathHash = keccak256(abi.encode(p.capPath));
        t.agent = agent;
        t.leafType = a.leaf.leafType;
        t.epoch = s.epoch;
        t.era = s.era;
        t.admitTime = uint64(block.timestamp);
        t.windowLen = _windowLen(a, ph);
        t.outageGrace = a.params.outageGrace;
        t.windowEnd = uint64(block.timestamp) + t.windowLen;
        t.validUntil = p.validUntil;
        t.pathMinExpiry = minExpiry < a.commit.expiry ? minExpiry : a.commit.expiry;
        t.attestorsDigest = _attestorsDigest(a.attestations);
        t.reserved = p.declaredOut;

        ticketHash = keccak256(abi.encode(t));
        ticketLive[ticketHash] = true;
        emit Admitted(ticketHash, p.mandateId, t);
    }

    // ═══════════════════════════════ Views ═══════════════════════════════

    function getMandate(bytes32 mandateId) external view returns (MandateState memory) {
        return _mandates[mandateId];
    }

    function nonceUsed(bytes32 mandateId, uint256 nonce) external view returns (bool) {
        return _nonceBits[mandateId][nonce >> 8] & (1 << (nonce & 0xff)) != 0;
    }

    function proposalHash(Proposal calldata p) external view returns (bytes32) {
        return _proposalHash(p);
    }

    function attestationHash(Attestation calldata a) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    ATTEST_TAG,
                    a.proposalHash,
                    a.policyHash,
                    a.epoch,
                    a.stateRef.blockNumber,
                    a.stateRef.blockHash,
                    a.attestor,
                    a.scheme,
                    a.verdict,
                    a.expiresAt
                )
            )
        );
    }

    function readyHash(bytes32 commitHash) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(READY_TAG, commitHash)));
    }

    function coSignHash(bytes32 proposalHash_) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(COSIGN_TAG, proposalHash_)));
    }

    function rootCapId(bytes32 mandateId, uint64 epoch) public pure returns (bytes32) {
        return keccak256(abi.encode(ROOT_TAG, mandateId, epoch));
    }

    /// @dev Derived from the proposal nonce, not the proposal hash: the child preimage sits
    ///      inside the calldata the proposal hash commits to. Nonces are single-use per mandate.
    function childCapId(bytes32 mandateId, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encode(CHILD_TAG, mandateId, nonce));
    }

    // ═══════════════════════════════ Internals ═══════════════════════════════

    function _halt(bytes32 mandateId, MandateState storage s, uint8 status) internal {
        s.status = status;
        s.epoch += 1;
        s.pendingCommitHash = 0; // SPEC §17 F-7
        emit EpochBumped(mandateId, s.epoch, status);
    }

    /// @dev Root allotment = cap − consumed in the current era, so a shrink cannot refill.
    function _initRoot(MandateCommit calldata c, Params calldata p, BudgetSpec calldata b, MandateState storage s)
        internal
        returns (CapabilityNode memory root)
    {
        uint256 k = b.assets.length;
        root.capId = rootCapId(c.mandateId, s.epoch);
        root.mandateId = c.mandateId;
        root.mandateEpoch = s.epoch;
        root.delegatee = c.rootDelegatee;
        root.scopeRoot = c.scopeRoot;
        root.expiry = c.expiry;
        root.canDelegate = p.maxDepth > 0;
        root.allotment = new AssetAmount[](k);
        for (uint256 i; i < k; ++i) {
            AssetBudget calldata ab = b.assets[i];
            if (ab.periodLength == 0 || ab.asset == address(0)) revert InvalidParams();
            for (uint256 j; j < i; ++j) {
                if (b.assets[j].asset == ab.asset) revert InvalidParams();
            }
            uint256 used = consumed[c.mandateId][s.era][ab.asset];
            capRemaining[root.capId][ab.asset] = ab.epochCap > used ? ab.epochCap - used : 0;
            root.allotment[i] = AssetAmount(ab.asset, ab.epochCap);
        }
        capHash[root.capId] = keccak256(abi.encode(root));
    }

    function _checkPath(AdmitInput calldata a, uint64 epoch)
        internal
        view
        returns (address[] memory delegatees, uint64 minExpiry)
    {
        Proposal calldata p = a.proposal;
        uint256 n = a.path.length;
        if (n == 0 || n != p.capPath.length || n != a.scopeProofs.length) revert A11_PathMismatch();
        bytes32 leafHash = keccak256(abi.encode(a.leaf));
        if (leafHash != p.leafHash) revert A14_PreimageMismatch();
        bytes32 scopeLeaf = keccak256(bytes.concat(leafHash));
        delegatees = new address[](n);
        minExpiry = type(uint64).max;
        for (uint256 i; i < n; ++i) {
            CapabilityNode calldata node = a.path[i];
            if (p.capPath[i] != node.capId) revert A11_PathMismatch();
            if (
                capHash[node.capId] != keccak256(abi.encode(node)) || node.mandateId != p.mandateId
                    || node.mandateEpoch != epoch || nodeEpoch[node.capId] != 0 || block.timestamp >= node.expiry
            ) revert A2_BadCapPath();
            if (i == 0) {
                if (node.parentCapId != 0) revert A2_BadCapPath();
            } else if (
                node.parentCapId != a.path[i - 1].capId || node.parentNodeEpoch != nodeEpoch[a.path[i - 1].capId]
            ) {
                revert A2_BadCapPath();
            }
            if (!MerkleProof.verifyCalldata(a.scopeProofs[i], node.scopeRoot, scopeLeaf)) revert A3_OutOfScope();
            if (node.expiry < minExpiry) minExpiry = node.expiry;
            delegatees[i] = node.delegatee;
        }
    }

    function _useNonce(bytes32 mandateId, uint256 nonce) internal {
        uint256 bit = 1 << (nonce & 0xff);
        uint256 word = _nonceBits[mandateId][nonce >> 8];
        if (word & bit != 0) revert A7_NonceUsed();
        _nonceBits[mandateId][nonce >> 8] = word | bit;
    }

    function _checkValidity(Proposal calldata p, uint32 maxStateAge) internal view {
        if (block.timestamp < p.validAfter || block.timestamp > p.validUntil) revert A8_OutsideValidity();
        StateRef calldata sr = p.stateRef;
        if (
            sr.blockNumber >= block.number || block.number - sr.blockNumber > maxStateAge || sr.blockHash == 0
                || blockhash(sr.blockNumber) != sr.blockHash
        ) revert A8_StaleState();
    }

    /// @return count Number of valid attestations. Any malformed attestation reverts the call,
    ///               so a relayer learns exactly which one is wrong.
    function _countAttestations(
        Attestation[] calldata atts,
        bytes32[][] calldata proofs,
        bytes32 expectedProposal,
        bytes32 policyHash,
        uint64 epoch,
        StateRef memory stateRef,
        Params calldata params,
        bytes32 attestorSetRoot,
        address[] memory forbidden
    ) internal view returns (uint256 count) {
        if (atts.length != proofs.length) revert A5_AttestationMismatch();
        bytes32 prev;
        for (uint256 i; i < atts.length; ++i) {
            Attestation calldata at = atts[i];
            if (
                at.proposalHash != expectedProposal || at.policyHash != policyHash || at.epoch != epoch
                    || at.stateRef.blockNumber != stateRef.blockNumber || at.stateRef.blockHash != stateRef.blockHash
                    || at.verdict != VERDICT_ALLOW || at.expiresAt < block.timestamp
            ) revert A5_AttestationMismatch();
            if (uint256(at.attestor) <= uint256(prev)) revert A5_DuplicateAttestor();
            prev = at.attestor;
            address verifier = schemeVerifier[at.scheme];
            if (verifier == address(0) || !_containsScheme(params.attestSchemes, at.scheme)) {
                revert A5_SchemeNotAllowed();
            }
            for (uint256 j; j < forbidden.length; ++j) {
                if (at.attestor == bytes32(uint256(uint160(forbidden[j])))) revert A5_RoleConflict();
            }
            bytes32 member = keccak256(bytes.concat(keccak256(abi.encode(at.attestor, at.scheme))));
            if (!MerkleProof.verifyCalldata(proofs[i], attestorSetRoot, member)) revert A4_NotAttestor();
            if (!IAttestationVerifier(verifier).verify(at.scheme, attestationHash(at), at.attestor, at.blob)) {
                revert A5_BadAttestation();
            }
            ++count;
        }
    }

    function _attestorsDigest(Attestation[] calldata atts) internal pure returns (bytes32) {
        bytes32[] memory ids = new bytes32[](atts.length);
        for (uint256 i; i < atts.length; ++i) {
            ids[i] = atts[i].attestor;
        }
        return keccak256(abi.encode(ids));
    }

    function _reserve(AdmitInput calldata a, bytes32 usedCap, uint64 era) internal returns (uint64[] memory periodIdx) {
        ActionLeaf calldata l = a.leaf;
        AssetAmount[] calldata out = a.proposal.declaredOut;
        bytes32 mandateId = a.proposal.mandateId;
        periodIdx = new uint64[](out.length);
        for (uint256 i; i < out.length; ++i) {
            uint256 amt = out[i].amount;
            if (amt > l.maxOutPerCall[i]) revert A9_ExceedsBudget();
            if (amt == 0) continue;
            address asset = out[i].asset;
            uint256 rem = capRemaining[usedCap][asset];
            if (amt > rem) revert A9_ExceedsBudget();
            capRemaining[usedCap][asset] = rem - amt;
            if (l.leafType != LEAF_CALL) continue; // carving is not spending
            AssetBudget calldata ab = _budgetOf(a.budget, asset);
            uint64 idx = uint64(block.timestamp / ab.periodLength);
            uint256 used = periodUsed[mandateId][era][asset][idx];
            if (used + amt > ab.periodCap) revert A9_ExceedsBudget();
            periodUsed[mandateId][era][asset][idx] = used + amt;
            periodIdx[i] = idx;
        }
    }

    function _windowLen(AdmitInput calldata a, bytes32 ph) internal view returns (uint32) {
        Params calldata params = a.params;
        uint256 w = params.windowBase;
        AssetAmount[] calldata out = a.proposal.declaredOut;
        for (uint256 i; i < out.length; ++i) {
            for (uint256 j; j < params.windowRate.length; ++j) {
                if (params.windowRate[j].asset == out[i].asset) {
                    w += params.windowRate[j].amount * out[i].amount / 1e18;
                }
            }
        }
        if (w < params.windowMin) w = params.windowMin;
        if (a.coSig.length != 0) {
            if (!SignatureChecker.isValidSignatureNow(a.commit.principalAccount, coSignHash(ph), a.coSig)) {
                revert CoSigInvalid();
            }
            if (w > params.coSignWindowMin) w = params.coSignWindowMin;
        }
        return w > type(uint32).max ? type(uint32).max : uint32(w);
    }

    function _budgetOf(BudgetSpec calldata b, address asset) internal pure returns (AssetBudget calldata) {
        for (uint256 i; i < b.assets.length; ++i) {
            if (b.assets[i].asset == asset) return b.assets[i];
        }
        revert A9_ExceedsBudget();
    }

    function _containsScheme(bytes32[] calldata list, bytes32 x) internal pure returns (bool) {
        for (uint256 i; i < list.length; ++i) {
            if (list[i] == x) return true;
        }
        return false;
    }
}
