// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAccountAdapter, ILivenessSource} from "./interfaces/IGateExternal.sol";
import {GateBase} from "./GateBase.sol";
import "./GateTypes.sol";
import "./GateErrors.sol";

/// @title GateSettlement — execution, ticket drops and capability upkeep for AgentGate.
/// @notice Only reachable through AgentGate's fallback (DELEGATECALL into an address fixed at
///         AgentGate's construction). Called directly it refuses, and it would only see its own
///         empty storage anyway. Split out to keep both contracts under EIP-170.
contract GateSettlement is GateBase {
    bytes4 internal constant APPROVE_SELECTOR = 0x095ea7b3;
    bytes4 internal constant INCREASE_ALLOWANCE_SELECTOR = 0x39509351;

    address private immutable _self;

    constructor(ILivenessSource liveness_) GateBase(liveness_) {
        _self = address(this);
    }

    modifier viaGate() {
        if (address(this) == _self) revert NotAuthorized();
        _;
    }

    // ═══════════════════════════════ Settlement ═══════════════════════════════

    function execute(ExecuteInput calldata x)
        external
        viaGate
        nonReentrant
        returns (uint256[] memory outs, uint256[] memory ins)
    {
        TicketPreimage calldata t = x.ticket;
        bytes32 th = keccak256(abi.encode(t));
        if (!ticketLive[th]) revert X3_NoTicket();
        Proposal calldata p = x.proposal;
        if (
            _proposalHash(p) != t.proposalHash || keccak256(x.data) != p.calldataHash
                || keccak256(abi.encode(x.leaf)) != p.leafHash
        ) revert X1_TicketMismatch();

        MandateState storage s = _mandates[t.mandateId];
        if (s.status != STATUS_ACTIVE || s.epoch != t.epoch || keccak256(abi.encode(x.commit)) != s.commitHash) {
            revert X4_StaleTicket();
        }
        if (block.timestamp >= t.pathMinExpiry || block.timestamp > t.validUntil) revert X4_StaleTicket();
        for (uint256 i; i < p.capPath.length; ++i) {
            if (nodeEpoch[p.capPath[i]] != 0) revert X4_StaleTicket();
        }
        _checkWindow(t);
        if (!_accountOk(x.commit.principalAccount, x.commit.accountConfigDigest, t.agent)) revert X6_AccountConfig();

        delete ticketLive[th];
        if (t.leafType == LEAF_DELEGATE) {
            _settleDelegation(x);
            outs = new uint256[](t.reserved.length);
            ins = new uint256[](t.reserved.length);
        } else {
            (outs, ins) = _settleCall(x);
        }
        emit Settled(th, t.mandateId, outs, ins);
    }

    function veto(TicketPreimage calldata t, MandateCommit calldata c, bytes32[] calldata guardianProof)
        external
        viaGate
        nonReentrant
    {
        bytes32 th = _requireLive(t);
        MandateState storage s = _mandates[t.mandateId];
        if (msg.sender != s.principal) {
            if (keccak256(abi.encode(c)) != s.commitHash) revert A4_PreimageMismatch();
            if (!_isGuardian(c.guardianSetRoot, msg.sender, guardianProof)) revert NotAuthorized();
        }
        _drop(th, t, s);
    }

    /// @notice A counted attestor retracting its attestation is a veto (SPEC §4.3).
    function withdrawAttestation(TicketPreimage calldata t, bytes32[] calldata counted, uint256 idx)
        external
        viaGate
        nonReentrant
    {
        bytes32 th = _requireLive(t);
        if (keccak256(abi.encode(counted)) != t.attestorsDigest) revert A4_PreimageMismatch();
        if (counted[idx] != bytes32(uint256(uint160(msg.sender)))) revert NotAuthorized();
        _drop(th, t, _mandates[t.mandateId]);
    }

    function cancel(TicketPreimage calldata t) external viaGate nonReentrant {
        bytes32 th = _requireLive(t);
        if (msg.sender != t.agent) revert NotAuthorized();
        _drop(th, t, _mandates[t.mandateId]);
    }

    /// @notice Anyone frees the reservation of an expired or invalidated ticket.
    function release(TicketPreimage calldata t, bytes32[] calldata capPath) external viaGate nonReentrant {
        bytes32 th = _requireLive(t);
        if (keccak256(abi.encode(capPath)) != t.capPathHash) revert A4_PreimageMismatch();
        MandateState storage s = _mandates[t.mandateId];
        bool dead = block.timestamp > t.validUntil || block.timestamp >= t.pathMinExpiry
            || s.status != STATUS_ACTIVE || s.epoch != t.epoch;
        for (uint256 i; !dead && i < capPath.length; ++i) {
            dead = nodeEpoch[capPath[i]] != 0;
        }
        if (!dead) revert TicketStillLive();
        _drop(th, t, s);
    }

    // ═══════════════════════════ Capability upkeep ═══════════════════════════

    /// @param path Authentic chain ending at the node to revoke; any holder on it may revoke.
    function revokeCap(CapabilityNode[] calldata path, uint256 idx) external viaGate nonReentrant {
        _verifyChain(path);
        CapabilityNode calldata node = path[idx];
        bool ok = msg.sender == _mandates[node.mandateId].principal;
        for (uint256 j; !ok && j <= idx; ++j) {
            ok = path[j].delegatee == msg.sender;
        }
        if (!ok) revert NotAuthorized();
        uint64 e = ++nodeEpoch[node.capId];
        emit CapRevoked(node.capId, e);
    }

    /// @notice Move a dead node's unused allotment to its nearest live ancestor (D4).
    /// @param path Root-first chain ending at the dead node.
    function reclaim(CapabilityNode[] calldata path) external viaGate nonReentrant {
        _verifyChain(path);
        uint256 n = path.length;
        if (n < 2 || path[0].parentCapId != 0) revert A2_BadCapPath();
        MandateState storage s = _mandates[path[0].mandateId];
        bool valid = s.status == STATUS_ACTIVE && path[0].mandateEpoch == s.epoch;
        uint256 live = type(uint256).max;
        for (uint256 i; i < n; ++i) {
            valid = valid && nodeEpoch[path[i].capId] == 0 && block.timestamp < path[i].expiry;
            if (i == n - 1) {
                if (valid) revert NodeStillLive();
            } else if (valid) {
                live = i;
            }
        }
        if (live == type(uint256).max) revert NoLiveAncestor();

        CapabilityNode calldata src = path[n - 1];
        bytes32 to = path[live].capId;
        for (uint256 i; i < src.allotment.length; ++i) {
            address asset = src.allotment[i].asset;
            uint256 amt = capRemaining[src.capId][asset];
            if (amt == 0) continue;
            capRemaining[src.capId][asset] = 0;
            capRemaining[to][asset] += amt;
        }
        emit CapReclaimed(src.capId, to);
    }

    // ═══════════════════════════════ Internals ═══════════════════════════════

    /// @dev X2, X6 (sequencer), X10: any liveness change after admission restarts the whole
    ///      window from the last change plus the grace period.
    function _checkWindow(TicketPreimage calldata t) internal view {
        uint256 end = t.windowEnd;
        if (address(liveness) != address(0)) {
            if (!liveness.isUp()) revert X6_SequencerDown();
            uint64 lc = liveness.lastChangeAt();
            if (lc > t.admitTime) {
                uint256 restart = uint256(lc) + t.outageGrace + t.windowLen;
                if (restart > end) end = restart;
            }
        }
        if (block.timestamp < end) revert X2_WindowNotElapsed();
    }

    function _settleDelegation(ExecuteInput calldata x) internal {
        CapabilityNode memory child = abi.decode(x.data[4:], (CapabilityNode));
        if (capHash[child.capId] != 0) revert G4_BadChildBinding();
        capHash[child.capId] = keccak256(abi.encode(child));
        for (uint256 i; i < child.allotment.length; ++i) {
            capRemaining[child.capId][child.allotment[i].asset] += child.allotment[i].amount;
        }
        emit Delegated(x.ticket.capId, child.capId, child);
    }

    function _settleCall(ExecuteInput calldata x) internal returns (uint256[] memory outs, uint256[] memory ins) {
        ActionLeaf calldata l = x.leaf;
        TicketPreimage calldata t = x.ticket;
        address account = x.commit.principalAccount;
        if (l.target.codehash != l.codeHash) revert X5_CodeHashChanged();

        uint256 k = l.assets.length;
        uint256[] memory pre = new uint256[](k);
        for (uint256 i; i < k; ++i) {
            pre[i] = _balanceOf(l.assets[i], account);
        }
        address[] memory spenders = _checkedSpenders(l, x.data);
        uint256[] memory preAllow = _allowances(l.assets, account, spenders);

        IAccountAdapter(account).executeFromGate(l.target, x.proposal.value, x.data);

        outs = new uint256[](k);
        ins = new uint256[](k);
        for (uint256 i; i < k; ++i) {
            uint256 post = _balanceOf(l.assets[i], account);
            if (post < pre[i]) outs[i] = pre[i] - post;
            else ins[i] = post - pre[i];
            if (outs[i] > t.reserved[i].amount) revert X7_OutflowExceeded();
        }
        AssetAmount[] calldata minIn = x.proposal.declaredMinIn;
        for (uint256 i; i < minIn.length; ++i) {
            if (ins[_indexOf(l.assets, minIn[i].asset)] < minIn[i].amount) revert X7_InflowShort();
        }
        uint256[] memory postAllow = _allowances(l.assets, account, spenders);
        for (uint256 i; i < postAllow.length; ++i) {
            if (postAllow[i] > preAllow[i]) revert X8_AllowanceIncreased();
        }

        for (uint256 i; i < k; ++i) {
            uint256 reserved = t.reserved[i].amount;
            if (reserved == 0) continue; // outs[i] ≤ reserved, so nothing left the account either
            address asset = l.assets[i];
            capRemaining[t.capId][asset] += reserved - outs[i];
            consumed[t.mandateId][t.era][asset] += outs[i];
            periodUsed[t.mandateId][t.era][asset][t.periodIdx[i]] -= reserved - outs[i];
        }
    }

    /// @dev EVM cannot enumerate spenders. Checked: the call target, and the spender argument of
    ///      approve/increaseAllowance. Allowlisted spenders are skipped (SPEC §7.2 X8, §17 F-4).
    function _checkedSpenders(ActionLeaf calldata l, bytes calldata data) internal pure returns (address[] memory s) {
        s = new address[](2);
        uint256 n;
        if (_indexOf(l.spenderAllowlist, l.target) == type(uint256).max) s[n++] = l.target;
        bytes4 sel = bytes4(data[:4]);
        if ((sel == APPROVE_SELECTOR || sel == INCREASE_ALLOWANCE_SELECTOR) && data.length >= 36) {
            address sp = address(uint160(uint256(bytes32(data[4:36]))));
            if (sp != l.target && _indexOf(l.spenderAllowlist, sp) == type(uint256).max) s[n++] = sp;
        }
        assembly ("memory-safe") {
            mstore(s, n)
        }
    }

    function _allowances(address[] calldata assets, address account, address[] memory spenders)
        internal
        view
        returns (uint256[] memory out)
    {
        out = new uint256[](assets.length * spenders.length);
        uint256 n;
        for (uint256 i; i < assets.length; ++i) {
            if (assets[i] == NATIVE) {
                n += spenders.length;
                continue;
            }
            for (uint256 j; j < spenders.length; ++j) {
                out[n++] = IERC20(assets[i]).allowance(account, spenders[j]);
            }
        }
    }

    function _drop(bytes32 th, TicketPreimage calldata t, MandateState storage s) internal {
        delete ticketLive[th];
        bool sameEpoch = s.epoch == t.epoch; // a changed mandate epoch voids the node reservation
        for (uint256 i; i < t.reserved.length; ++i) {
            uint256 amt = t.reserved[i].amount;
            if (amt == 0) continue;
            address asset = t.reserved[i].asset;
            if (sameEpoch) capRemaining[t.capId][asset] += amt;
            if (t.leafType == LEAF_CALL) periodUsed[t.mandateId][t.era][asset][t.periodIdx[i]] -= amt;
        }
        emit TicketDropped(th, msg.sender);
    }

    function _requireLive(TicketPreimage calldata t) internal view returns (bytes32 th) {
        th = keccak256(abi.encode(t));
        if (!ticketLive[th]) revert X3_NoTicket();
    }

    function _verifyChain(CapabilityNode[] calldata path) internal view {
        if (path.length == 0) revert A2_BadCapPath();
        for (uint256 i; i < path.length; ++i) {
            if (capHash[path[i].capId] != keccak256(abi.encode(path[i]))) revert A2_BadCapPath();
            if (i > 0 && path[i].parentCapId != path[i - 1].capId) revert A2_BadCapPath();
        }
    }

    function _balanceOf(address asset, address account) internal view returns (uint256) {
        return asset == NATIVE ? account.balance : IERC20(asset).balanceOf(account);
    }
}
