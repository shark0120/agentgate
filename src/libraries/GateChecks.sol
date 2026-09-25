// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../GateTypes.sol";
import "../GateErrors.sol";

/// @title GateChecks — stateless validation split out of AgentGate to stay under EIP-170.
/// @dev External library: runs by DELEGATECALL, so `address(this)` is the gate.
library GateChecks {
    /// @notice A10, A12, A13, A14, A16, A17.
    function checkLeafAndCalldata(ActionLeaf calldata l, Proposal calldata p, bytes calldata data, address account)
        external
        view
    {
        if (l.leafType != LEAF_CALL && l.leafType != LEAF_DELEGATE) revert A12_BadLeafType();
        if (l.implementation != address(0)) revert A17_ImplementationUnsupported();
        if (l.leafType == LEAF_CALL && (l.target == address(this) || l.target == account)) revert A13_ForbiddenTarget();
        if (keccak256(data) != p.calldataHash) revert A14_PreimageMismatch();
        if (data.length < 4 || bytes4(data[:4]) != l.selector) revert A14_ArgRuleViolated();
        _checkArgRules(l.argRules, data, account);

        uint256 k = l.assets.length;
        if (p.declaredOut.length != k || l.maxOutPerCall.length != k) revert A10_AssetMismatch();
        for (uint256 i; i < k; ++i) {
            if (p.declaredOut[i].asset != l.assets[i]) revert A10_AssetMismatch();
            for (uint256 j; j < i; ++j) {
                if (l.assets[j] == l.assets[i]) revert A10_AssetMismatch();
            }
        }
        for (uint256 i; i < p.declaredMinIn.length; ++i) {
            if (_indexOf(l.assets, p.declaredMinIn[i].asset) == type(uint256).max) revert A10_AssetMismatch();
        }
        if (p.value != 0) {
            uint256 idx = _indexOf(l.assets, NATIVE);
            if (l.leafType != LEAF_CALL || idx == type(uint256).max || p.value > p.declaredOut[idx].amount) {
                revert A16_ValueExceedsDeclared();
            }
        }
    }

    /// @notice G1–G4 shape checks; the gate still checks that the child id is unused.
    function checkDelegationShape(
        bytes calldata data,
        CapabilityNode calldata parent,
        Proposal calldata p,
        uint8 maxDepth,
        uint64 epoch,
        uint64 parentNodeEpoch,
        bytes32 expectedChildId
    ) external view {
        CapabilityNode memory child = abi.decode(data[4:], (CapabilityNode));
        if (!parent.canDelegate || child.depth != parent.depth + 1 || child.depth > maxDepth) {
            revert G1_CannotDelegate();
        }
        if (child.expiry > parent.expiry || child.expiry <= block.timestamp) revert G2_ExpiryWidens();
        AssetAmount[] calldata out = p.declaredOut;
        if (child.allotment.length != out.length) revert G3_AllotmentMismatch();
        for (uint256 i; i < out.length; ++i) {
            if (child.allotment[i].asset != out[i].asset || child.allotment[i].amount != out[i].amount) {
                revert G3_AllotmentMismatch();
            }
        }
        if (
            child.mandateId != p.mandateId || child.mandateEpoch != epoch || child.parentCapId != parent.capId
                || child.parentNodeEpoch != parentNodeEpoch || child.capId != expectedChildId
                || child.delegatee == address(0)
        ) revert G4_BadChildBinding();
    }

    /// @notice Numeric-only contraction (SPEC §4.1): every bound tightens or stays; nothing else moves.
    function requireShrink(ShrinkInput calldata x) external view {
        _requireCommitShrink(x.oldCommit, x.newCommit);
        _requireParamsShrink(x.oldParams, x.newParams);
        _requireBudgetShrink(x.oldBudget, x.newBudget);
    }

    function _checkArgRules(ArgRule[] calldata rules, bytes calldata data, address account) private pure {
        for (uint256 i; i < rules.length; ++i) {
            ArgRule calldata r = rules[i];
            uint256 start = 4 + uint256(r.offset);
            if (start + 32 > data.length) revert A14_ArgRuleViolated();
            bytes32 w = bytes32(data[start:start + 32]);
            bool ok;
            if (r.op == OP_EQ) ok = w == r.operand;
            else if (r.op == OP_LTE) ok = uint256(w) <= uint256(r.operand);
            else if (r.op == OP_GTE) ok = uint256(w) >= uint256(r.operand);
            else if (r.op == OP_EQ_ACCOUNT) ok = w == bytes32(uint256(uint160(account)));
            if (!ok) revert A14_ArgRuleViolated();
        }
    }

    function _requireCommitShrink(MandateCommit calldata o, MandateCommit calldata n) private view {
        if (
            n.mandateId != o.mandateId || n.principalAccount != o.principalAccount || n.rootDelegatee != o.rootDelegatee
                || n.adapter != o.adapter || n.scopeRoot != o.scopeRoot || n.policyHash != o.policyHash
                || n.attestorSetRoot != o.attestorSetRoot || n.guardianSetRoot != o.guardianSetRoot
                || n.accountConfigDigest != o.accountConfigDigest || n.activateAfter != o.activateAfter
                || n.expiry > o.expiry || n.expiry <= block.timestamp
        ) revert NotShrink();
    }

    function _requireParamsShrink(Params calldata o, Params calldata n) private pure {
        if (
            n.attestThreshold < o.attestThreshold || n.windowMin < o.windowMin || n.windowBase < o.windowBase
                || n.coSignWindowMin < o.coSignWindowMin || n.activationDelay < o.activationDelay
                || n.maxDepth > o.maxDepth || n.maxStateAge > o.maxStateAge || n.maxStateAge == 0
                || n.outageGrace < o.outageGrace || n.attestSchemes.length == 0
        ) revert NotShrink();
        for (uint256 i; i < n.attestSchemes.length; ++i) {
            if (!_contains(o.attestSchemes, n.attestSchemes[i])) revert NotShrink();
        }
        for (uint256 i; i < o.windowRate.length; ++i) {
            bool covered;
            for (uint256 j; j < n.windowRate.length; ++j) {
                if (n.windowRate[j].asset == o.windowRate[i].asset && n.windowRate[j].amount >= o.windowRate[i].amount)
                {
                    covered = true;
                }
            }
            if (!covered) revert NotShrink();
        }
    }

    function _requireBudgetShrink(BudgetSpec calldata o, BudgetSpec calldata n) private pure {
        if (n.assets.length != o.assets.length) revert NotShrink();
        for (uint256 i; i < n.assets.length; ++i) {
            AssetBudget calldata a = o.assets[i];
            AssetBudget calldata b = n.assets[i];
            if (
                b.asset != a.asset || b.periodLength != a.periodLength || b.epochCap > a.epochCap
                    || b.periodCap > a.periodCap
            ) revert NotShrink();
        }
    }

    function _indexOf(address[] calldata list, address x) private pure returns (uint256) {
        for (uint256 i; i < list.length; ++i) {
            if (list[i] == x) return i;
        }
        return type(uint256).max;
    }

    function _contains(bytes32[] calldata list, bytes32 x) private pure returns (bool) {
        for (uint256 i; i < list.length; ++i) {
            if (list[i] == x) return true;
        }
        return false;
    }
}
