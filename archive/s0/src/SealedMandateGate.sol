// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IRefinementVerifier} from "./interfaces/IRefinementVerifier.sol";

/// @title SealedMandateGate — SMP S0
/// @notice Mandate Registry (L2) + Capability Graph (L3) + Finality Gate (L7) in one contract,
///         so escrowed assets never sit behind a cross-contract trust boundary.
/// @dev Asset exits, exhaustively:
///        - finalize(): the gate proper. Live mandate, verified π, reserved budget.
///        - reclaim():  principal refund of a *dead* root (revoked or expired). No candidate
///                      under that root can finalize any more, so this cannot race the gate.
///      There is no owner, no upgrade path, and no verifier setter. The guardian can only
///      disable proof types, which removes liveness and never adds an exit.
///
///      Budget accounting per node (all in the root's asset):
///        remain   = unspent budget of this subtree
///        locked   = Σ remain of live children
///        reserved = Σ cost of pending candidates on this node
///        available = remain − locked − reserved
///      Invariant: for every root r that is not closed, the gate holds r.remain of r.asset.
contract SealedMandateGate is ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint8 public constant MAX_DEPTH = 4;
    bytes32 public constant ACT_TAG = keccak256("SMP/S0/Act/v1");

    struct Mandate {
        address principal;
        uint64 expiry;
        uint64 epoch;
        uint64 parentEpoch; // parent's epoch at delegation; parent advancing kills this subtree
        uint8 depth;
        bool revoked;
        bool closed; // child: released to parent. root: reclaimed.
        address asset;
        bytes32 commit;
        bytes32 destRoot;
        bytes32 visHash;
        bytes32 parent;
        bytes32 root;
        uint256 remain;
        uint256 locked;
        uint256 reserved;
    }

    /// @notice Candidate Act A. S0 effects are fixed to `asset.transfer(dest, cost)`.
    struct Act {
        bytes32 mandateId;
        address dest;
        uint256 cost;
        uint64 epoch;
        uint64 deadline; // quote window: no finalize after this
        bytes32 nonce; // lets two identical payments coexist without colliding on actDigest
        bytes visProjection; // bound into actDigest so a relayer cannot swap it
    }

    enum Status {
        None,
        Pending,
        Finalized,
        Cancelled
    }

    struct Candidate {
        bytes32 mandateId;
        address dest;
        uint64 epoch;
        uint64 deadline;
        uint8 proofType;
        Status status;
        uint256 cost;
    }

    address public immutable guardian;
    address[] private _verifiers;
    mapping(uint8 => bool) public proofTypeDisabled;

    uint256 private _idNonce;
    mapping(bytes32 => Mandate) private _mandates;
    mapping(bytes32 => Candidate) private _candidates;

    error UnknownMandate();
    error NotAuthorized();
    error InvalidParams();
    error AlreadyRevoked();
    error MandateRevoked();
    error MandateExpired();
    error MandateClosed();
    error ParentEpochAdvanced();
    error StaleEpoch();
    error DeadlinePassed();
    error ActDigestMismatch();
    error DuplicateAct();
    error DestNotInSet();
    error InsufficientBudget();
    error UnsupportedProofType();
    error ProofTypeDisabled();
    error EmptyProof();
    error MalformedProof();
    error InvalidProof();
    error DepthExceeded();
    error WidensWindow();
    error NotPending();
    error StillLive();
    error TransferAmountMismatch();

    event MandateIssued(
        bytes32 indexed id,
        address indexed principal,
        address asset,
        bytes32 commit,
        bytes32 destRoot,
        bytes32 visHash,
        uint256 budget,
        uint64 expiry,
        bytes meta
    );
    event Delegated(
        bytes32 indexed childId,
        bytes32 indexed parentId,
        address indexed delegator,
        bytes32 commit,
        bytes32 destRoot,
        bytes32 visHash,
        uint256 budget,
        uint64 expiry
    );
    event Revoked(bytes32 indexed id, address indexed by, uint64 newEpoch);
    event Released(bytes32 indexed id, bytes32 indexed parentId, uint256 amount);
    event Reclaimed(bytes32 indexed rootId, address indexed principal, uint256 amount);
    event CandidateSubmitted(
        bytes32 indexed candidateId,
        bytes32 indexed mandateId,
        address dest,
        uint256 cost,
        uint8 proofType,
        bytes visProjection
    );
    event CandidateFinalized(bytes32 indexed candidateId, bytes32 indexed mandateId, address dest, uint256 cost);
    event CandidateCancelled(bytes32 indexed candidateId);
    event ProofTypeDisabledByGuardian(uint8 indexed proofType);

    constructor(address[] memory verifiers, address guardian_) {
        _verifiers = verifiers;
        guardian = guardian_;
    }

    // ───────────────────────────── L2 Registry ─────────────────────────────

    /// @notice Issue a root mandate and escrow its budget. Spec §16.1 plus `asset`.
    function issueMandate(
        bytes32 commit,
        bytes32 destRoot,
        uint256 budget,
        uint64 expiry,
        bytes32 visHash,
        address asset,
        bytes calldata meta
    ) external nonReentrant returns (bytes32 id) {
        if (commit == 0 || destRoot == 0 || budget == 0 || expiry <= block.timestamp || asset == address(0)) {
            revert InvalidParams();
        }
        id = _newId();
        Mandate storage m = _mandates[id];
        m.principal = msg.sender;
        m.expiry = expiry;
        m.asset = asset;
        m.commit = commit;
        m.destRoot = destRoot;
        m.visHash = visHash;
        m.root = id;
        m.remain = budget;

        uint256 before = IERC20(asset).balanceOf(address(this));
        IERC20(asset).safeTransferFrom(msg.sender, address(this), budget);
        if (IERC20(asset).balanceOf(address(this)) - before != budget) revert TransferAmountMismatch();

        emit MandateIssued(id, msg.sender, asset, commit, destRoot, visHash, budget, expiry, meta);
    }

    /// @notice Terminal revocation: sets the bit and advances the epoch (spec §5.4).
    ///         Callable by this mandate's principal or any ancestor's principal.
    function revoke(bytes32 id) external returns (uint64 newEpoch) {
        Mandate storage m = _mandates[id];
        if (m.principal == address(0)) revert UnknownMandate();
        if (m.revoked) revert AlreadyRevoked();
        if (!_isPrincipalOnPath(id, msg.sender)) revert NotAuthorized();
        m.revoked = true;
        newEpoch = ++m.epoch;
        emit Revoked(id, msg.sender, newEpoch);
    }

    // ─────────────────────────── L3 Capability Graph ───────────────────────────

    /// @notice Create M′ under `parentId`. Enforces T′ ⊆ T and B′ ≤ available(B) here;
    ///         P′ ⇒ P and V′ ⊒ V through the verifier; D′ ⊆ D at spend time along the path.
    /// @dev Spec §16.1 has no proof argument, but with P sealed the registry cannot check
    ///      P′ ⇒ P or the delegator's right to delegate without one.
    function delegate(
        bytes32 parentId,
        bytes32 childCommit,
        bytes32 destRoot,
        uint256 budget,
        uint64 expiry,
        bytes32 visHash,
        uint8 proofType,
        bytes calldata delegationProof
    ) external returns (bytes32 childId) {
        Mandate storage p = _mandates[parentId];
        if (p.principal == address(0)) revert UnknownMandate();
        bytes4 err = _checkPath(parentId);
        if (err != 0) _revertWith(err);
        if (p.depth >= MAX_DEPTH) revert DepthExceeded();
        if (childCommit == 0 || destRoot == 0 || budget == 0 || expiry <= block.timestamp) revert InvalidParams();
        if (expiry > p.expiry) revert WidensWindow();
        if (budget > _available(p)) revert InsufficientBudget();
        address verifier = _verifierOf(proofType);
        if (verifier == address(0)) revert UnsupportedProofType();
        if (proofTypeDisabled[proofType]) revert ProofTypeDisabled();
        if (
            !IRefinementVerifier(verifier).verifyDelegation(
                p.commit,
                p.destRoot,
                p.visHash,
                childCommit,
                destRoot,
                visHash,
                msg.sender,
                msg.sender == p.principal,
                delegationProof
            )
        ) revert InvalidProof();

        childId = _newId();
        p.locked += budget;
        Mandate storage c = _mandates[childId];
        c.principal = msg.sender;
        c.expiry = expiry;
        c.parentEpoch = p.epoch;
        c.depth = p.depth + 1;
        c.asset = p.asset;
        c.commit = childCommit;
        c.destRoot = destRoot;
        c.visHash = visHash;
        c.parent = parentId;
        c.root = p.root;
        c.remain = budget;

        emit Delegated(childId, parentId, msg.sender, childCommit, destRoot, visHash, budget, expiry);
    }

    /// @notice Return a dead child's unspent budget to its parent (spec §8.3).
    ///         Dead = revoked, expired, parent epoch advanced, or exhausted.
    function release(bytes32 id) external {
        Mandate storage m = _mandates[id];
        if (m.principal == address(0)) revert UnknownMandate();
        if (m.parent == 0) revert InvalidParams();
        if (m.closed) revert MandateClosed();
        Mandate storage p = _mandates[m.parent];
        bool dead = m.revoked || block.timestamp >= m.expiry || m.parentEpoch != p.epoch || m.remain == 0;
        if (!dead) revert StillLive();

        uint256 amount = m.remain;
        m.closed = true;
        m.remain = 0;
        m.locked = 0;
        m.reserved = 0;
        // A closed parent already moved its whole subtree's remain upward.
        if (!p.closed) p.locked -= amount;
        emit Released(id, m.parent, amount);
    }

    /// @notice Refund a dead root's unspent escrow to its principal.
    function reclaim(bytes32 rootId) external nonReentrant returns (uint256 amount) {
        Mandate storage m = _mandates[rootId];
        if (m.principal == address(0)) revert UnknownMandate();
        if (m.parent != 0) revert InvalidParams();
        if (m.closed) revert MandateClosed();
        if (!m.revoked && block.timestamp < m.expiry) revert StillLive();

        amount = m.remain;
        m.closed = true;
        m.remain = 0;
        m.locked = 0;
        m.reserved = 0;
        emit Reclaimed(rootId, m.principal, amount);
        IERC20(m.asset).safeTransfer(m.principal, amount);
    }

    // ───────────────────────────── L7 Finality Gate ─────────────────────────────

    /// @param proof abi.encode(bytes32[][] destProofs, bytes verifierProof).
    ///        destProofs[i] proves dest ∈ D at path level i (0 = act's mandate, last = root).
    function submitCandidate(Act calldata act, bytes32 actDigest, uint8 proofType, bytes calldata proof)
        external
        returns (bytes32 candidateId)
    {
        bytes4 err = _checkAct(act, actDigest, proofType, proof);
        if (err != 0) _revertWith(err);

        candidateId = actDigest;
        _mandates[act.mandateId].reserved += act.cost;
        _candidates[candidateId] = Candidate({
            mandateId: act.mandateId,
            dest: act.dest,
            epoch: act.epoch,
            deadline: act.deadline,
            proofType: proofType,
            status: Status.Pending,
            cost: act.cost
        });
        emit CandidateSubmitted(candidateId, act.mandateId, act.dest, act.cost, proofType, act.visProjection);
    }

    /// @notice The only live-mandate asset exit. Re-checks everything that can change after
    ///         submit (epoch, liveness along the path, deadline, proof type status), then
    ///         consumes the reservation and transfers in one transaction.
    function finalize(bytes32 candidateId) external nonReentrant returns (bool) {
        Candidate storage c = _candidates[candidateId];
        if (c.status != Status.Pending) revert NotPending();
        bytes4 err = _checkFinalizable(c);
        if (err != 0) _revertWith(err);

        c.status = Status.Finalized;
        uint256 cost = c.cost;
        Mandate storage m = _mandates[c.mandateId];
        m.reserved -= cost;
        m.remain -= cost;
        for (bytes32 pid = m.parent; pid != 0;) {
            Mandate storage p = _mandates[pid];
            p.locked -= cost;
            p.remain -= cost;
            pid = p.parent;
        }

        emit CandidateFinalized(candidateId, c.mandateId, c.dest, cost);
        IERC20(m.asset).safeTransfer(c.dest, cost);
        return true;
    }

    /// @notice Drop a pending candidate and free its reservation. The mandate's principal may
    ///         cancel any time; anyone may cancel once the candidate can no longer finalize.
    function cancelCandidate(bytes32 candidateId) external {
        Candidate storage c = _candidates[candidateId];
        if (c.status != Status.Pending) revert NotPending();
        Mandate storage m = _mandates[c.mandateId];
        if (msg.sender != m.principal && _checkFinalizable(c) == 0) revert StillLive();
        c.status = Status.Cancelled;
        if (!m.closed) m.reserved -= c.cost;
        emit CandidateCancelled(candidateId);
    }

    /// @notice One-way kill switch for an unsound proof system (spec §11, §13).
    function disableProofType(uint8 proofType) external {
        if (msg.sender != guardian) revert NotAuthorized();
        proofTypeDisabled[proofType] = true;
        emit ProofTypeDisabledByGuardian(proofType);
    }

    // ───────────────────────────────── Views ─────────────────────────────────

    /// @notice actDigest = H(tag, chainId, gate, mandateId, epoch, asset, selector, dest, cost,
    ///         deadline, nonce, H(visProjection)). Spec §16.2 plus gate address, deadline,
    ///         nonce and projection.
    function computeActDigest(Act calldata act) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                ACT_TAG,
                block.chainid,
                address(this),
                act.mandateId,
                act.epoch,
                _mandates[act.mandateId].asset,
                IERC20.transfer.selector,
                act.dest,
                act.cost,
                act.deadline,
                act.nonce,
                keccak256(act.visProjection)
            )
        );
    }

    /// @notice Dry-run of submitCandidate. Never reverts; reason is the error selector.
    function previewVerify(Act calldata act, bytes32 actDigest, uint8 proofType, bytes calldata proof)
        external
        view
        returns (bool ok, bytes4 reason)
    {
        try this.checkAct(act, actDigest, proofType, proof) returns (bytes4 e) {
            return (e == 0, e);
        } catch {
            return (false, MalformedProof.selector);
        }
    }

    /// @dev External only so previewVerify can catch ABI-decoding reverts.
    function checkAct(Act calldata act, bytes32 actDigest, uint8 proofType, bytes calldata proof)
        external
        view
        returns (bytes4)
    {
        return _checkAct(act, actDigest, proofType, proof);
    }

    function getMandate(bytes32 id) external view returns (Mandate memory) {
        return _mandates[id];
    }

    function getCandidate(bytes32 id) external view returns (Candidate memory) {
        return _candidates[id];
    }

    /// @notice Budget this mandate can still spend or delegate right now.
    function remainingBudget(bytes32 id) external view returns (uint256) {
        Mandate storage m = _mandates[id];
        return m.closed ? 0 : _available(m);
    }

    function currentEpoch(bytes32 id) external view returns (uint64) {
        return _mandates[id].epoch;
    }

    function verifierOf(uint8 proofType) external view returns (address) {
        return _verifierOf(proofType);
    }

    // ─────────────────────────────── Internals ───────────────────────────────

    function _checkAct(Act calldata act, bytes32 actDigest, uint8 proofType, bytes calldata proof)
        internal
        view
        returns (bytes4)
    {
        Mandate storage m = _mandates[act.mandateId];
        if (m.principal == address(0)) return UnknownMandate.selector;
        if (actDigest != computeActDigest(act)) return ActDigestMismatch.selector;
        if (_candidates[actDigest].status != Status.None) return DuplicateAct.selector;
        if (act.epoch != m.epoch) return StaleEpoch.selector;
        if (block.timestamp > act.deadline) return DeadlinePassed.selector;
        bytes4 err = _checkPath(act.mandateId);
        if (err != 0) return err;
        if (act.cost == 0 || act.dest == address(0)) return InvalidParams.selector;
        if (act.cost > _available(m)) return InsufficientBudget.selector;

        address verifier = _verifierOf(proofType);
        if (verifier == address(0)) return UnsupportedProofType.selector;
        if (proofTypeDisabled[proofType]) return ProofTypeDisabled.selector;
        if (proof.length == 0) return EmptyProof.selector;
        (bytes32[][] memory destProofs, bytes memory verifierProof) = abi.decode(proof, (bytes32[][], bytes));

        err = _checkDestAlongPath(act.mandateId, act.dest, destProofs);
        if (err != 0) return err;

        try IRefinementVerifier(verifier).verifyAct(
            m.commit, m.destRoot, m.visHash, actDigest, act.dest, act.cost, verifierProof
        ) returns (bool ok) {
            if (!ok) return InvalidProof.selector;
        } catch {
            return InvalidProof.selector;
        }
        return 0;
    }

    function _checkFinalizable(Candidate storage c) internal view returns (bytes4) {
        if (proofTypeDisabled[c.proofType]) return ProofTypeDisabled.selector;
        if (block.timestamp > c.deadline) return DeadlinePassed.selector;
        if (c.epoch != _mandates[c.mandateId].epoch) return StaleEpoch.selector;
        return _checkPath(c.mandateId);
    }

    /// @dev Every node from `id` to the root must be open, unrevoked, unexpired, and bound to
    ///      its parent's current epoch. Bounded by MAX_DEPTH.
    function _checkPath(bytes32 id) internal view returns (bytes4) {
        Mandate storage m = _mandates[id];
        while (true) {
            if (m.closed) return MandateClosed.selector;
            if (m.revoked) return MandateRevoked.selector;
            if (block.timestamp >= m.expiry) return MandateExpired.selector;
            if (m.parent == 0) return 0;
            Mandate storage p = _mandates[m.parent];
            if (m.parentEpoch != p.epoch) return ParentEpochAdvanced.selector;
            m = p;
        }
    }

    /// @dev Effective D of a delegated mandate is the intersection of D along its path.
    ///      This makes D′ ⊆ D hold by construction; no subset proof is needed at delegate time.
    function _checkDestAlongPath(bytes32 id, address dest, bytes32[][] memory destProofs)
        internal
        view
        returns (bytes4)
    {
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(dest))));
        uint256 i;
        while (true) {
            if (i >= destProofs.length) return MalformedProof.selector;
            Mandate storage m = _mandates[id];
            if (!MerkleProof.verify(destProofs[i], m.destRoot, leaf)) return DestNotInSet.selector;
            if (m.parent == 0) break;
            id = m.parent;
            ++i;
        }
        if (destProofs.length != i + 1) return MalformedProof.selector;
        return 0;
    }

    function _isPrincipalOnPath(bytes32 id, address who) internal view returns (bool) {
        while (id != 0) {
            Mandate storage m = _mandates[id];
            if (m.principal == who) return true;
            id = m.parent;
        }
        return false;
    }

    function _available(Mandate storage m) internal view returns (uint256) {
        return m.remain - m.locked - m.reserved;
    }

    function _verifierOf(uint8 proofType) internal view returns (address) {
        return proofType < _verifiers.length ? _verifiers[proofType] : address(0);
    }

    function _newId() internal returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), ++_idNonce));
    }

    function _revertWith(bytes4 selector) internal pure {
        assembly ("memory-safe") {
            mstore(0, selector)
            revert(0, 4)
        }
    }
}
