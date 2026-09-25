// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Data structures of the fused spec (SPEC.md §12). Only hashes of these live in storage.

address constant NATIVE = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

uint8 constant LEAF_CALL = 0;
uint8 constant LEAF_DELEGATE = 1;

uint8 constant OP_EQ = 0;
uint8 constant OP_LTE = 1;
uint8 constant OP_GTE = 2;
uint8 constant OP_EQ_ACCOUNT = 3;

uint8 constant VERDICT_ALLOW = 1;

uint8 constant STATUS_NONE = 0;
uint8 constant STATUS_INACTIVE = 1; // proposed, never activated
uint8 constant STATUS_ACTIVE = 2;
uint8 constant STATUS_SUSPENDED = 3;
uint8 constant STATUS_REVOKED = 4;

uint8 constant TRIP_ACCOUNT_CONFIG = 1;
uint8 constant TRIP_CODE_DRIFT = 2;

struct AssetAmount {
    address asset;
    uint256 amount;
}

struct MandateCommit {
    bytes32 mandateId;
    address principalAccount;
    address rootDelegatee;
    bytes32 scopeRoot;
    bytes32 policyHash;
    bytes32 attestorSetRoot;
    bytes32 guardianSetRoot;
    bytes32 paramsHash;
    bytes32 budgetHash;
    bytes32 accountConfigDigest;
    uint64 expiry;
    uint64 activateAfter;
    address adapter; // module the gate calls; equals principalAccount on the mock
}

struct Params {
    uint8 attestThreshold;
    bytes32[] attestSchemes;
    uint32 windowMin;
    uint32 windowBase;
    AssetAmount[] windowRate; // seconds added per 1e18 units reserved
    uint32 coSignWindowMin;
    uint32 activationDelay;
    uint8 maxDepth;
    uint32 maxStateAge; // blocks; must be ≤ 256 while stateRef uses blockhash
    uint32 outageGrace;
}

struct AssetBudget {
    address asset;
    uint256 epochCap;
    uint256 periodCap;
    uint32 periodLength;
}

struct BudgetSpec {
    AssetBudget[] assets;
}

struct ArgRule {
    uint16 offset; // byte offset into calldata after the 4-byte selector
    uint8 op;
    bytes32 operand;
}

struct ActionLeaf {
    uint8 leafType;
    address target;
    bytes32 codeHash;
    address implementation;
    bytes4 selector;
    ArgRule[] argRules;
    address[] assets;
    uint256[] maxOutPerCall;
    address[] spenderAllowlist;
}

struct CapabilityNode {
    bytes32 capId;
    bytes32 mandateId;
    uint64 mandateEpoch;
    bytes32 parentCapId;
    uint64 parentNodeEpoch;
    address delegatee;
    bytes32 scopeRoot;
    uint8 depth;
    uint64 expiry;
    bool canDelegate;
    AssetAmount[] allotment;
}

struct StateRef {
    uint64 blockNumber;
    bytes32 blockHash;
}

struct Proposal {
    bytes32 mandateId;
    uint64 epoch;
    bytes32[] capPath; // root first; the last entry is the node being used
    bytes32 leafHash;
    bytes32 calldataHash;
    uint256 value;
    AssetAmount[] declaredOut; // aligned with leaf.assets
    AssetAmount[] declaredMinIn;
    uint256 nonce;
    uint64 validAfter;
    uint64 validUntil;
    StateRef stateRef;
}

struct Attestation {
    bytes32 proposalHash;
    bytes32 policyHash;
    uint64 epoch;
    StateRef stateRef;
    bytes32 attestor;
    bytes32 scheme;
    uint8 verdict;
    uint64 expiresAt;
    bytes blob;
}

struct TicketPreimage {
    bytes32 proposalHash;
    bytes32 mandateId;
    bytes32 capId;
    bytes32 capPathHash;
    address agent;
    uint8 leafType;
    uint64 epoch;
    uint64 era;
    uint64 admitTime;
    uint32 windowLen;
    uint32 outageGrace;
    uint64 windowEnd;
    uint64 validUntil;
    uint64 pathMinExpiry;
    bytes32 attestorsDigest;
    AssetAmount[] reserved;
    uint64[] periodIdx; // aligned with reserved; unused for DELEGATE
}

struct AdmitInput {
    MandateCommit commit;
    Params params;
    BudgetSpec budget;
    Proposal proposal;
    bytes agentSig;
    bytes coSig; // optional principal co-signature; shortens the window to coSignWindowMin
    ActionLeaf leaf;
    CapabilityNode[] path; // root first
    bytes32[][] scopeProofs; // per path node
    Attestation[] attestations; // strictly increasing attestor ids
    bytes32[][] attestorProofs;
    bytes data;
}

struct ExecuteInput {
    TicketPreimage ticket;
    MandateCommit commit;
    Proposal proposal;
    ActionLeaf leaf;
    bytes data;
}

struct ShrinkInput {
    MandateCommit oldCommit;
    MandateCommit newCommit;
    Params oldParams;
    Params newParams;
    BudgetSpec oldBudget;
    BudgetSpec newBudget;
}
