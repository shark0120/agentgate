// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IAccountAdapter, ILivenessSource} from "./interfaces/IGateExternal.sol";
import "./GateTypes.sol";
import "./GateErrors.sol";

/// @title GateBase — storage layout, events and helpers shared by AgentGate and GateSettlement.
/// @dev Both contracts inherit this base unchanged, so their storage layouts are identical and
///      AgentGate can DELEGATECALL into GateSettlement. Never add state outside this contract.
abstract contract GateBase is EIP712, ReentrancyGuardTransient {
    bytes32 internal constant PROPOSAL_TAG = keccak256("SMP/F1/Proposal");
    bytes32 internal constant ATTEST_TAG = keccak256("SMP/F1/Attestation");
    bytes32 internal constant READY_TAG = keccak256("SMP/F1/Ready");
    bytes32 internal constant COSIGN_TAG = keccak256("SMP/F1/CoSign");
    bytes32 internal constant ROOT_TAG = keccak256("SMP/F1/RootCap");
    bytes32 internal constant CHILD_TAG = keccak256("SMP/F1/ChildCap");

    struct MandateState {
        address principal;
        uint8 status;
        uint32 activationDelay; // of the active commit; replacements wait max(old, new)
        uint64 epoch;
        uint64 era; // consumption ledger generation; only activate advances it
        bytes32 commitHash;
        bytes32 pendingCommitHash;
    }

    ILivenessSource public immutable liveness;

    mapping(bytes32 scheme => address) public schemeVerifier;
    mapping(bytes32 => MandateState) internal _mandates;
    mapping(bytes32 => mapping(uint256 => uint256)) internal _nonceBits;
    mapping(bytes32 => mapping(uint64 => mapping(address => uint256))) public consumed;
    mapping(bytes32 => mapping(uint64 => mapping(address => mapping(uint64 => uint256)))) public periodUsed;
    mapping(bytes32 => bytes32) public capHash;
    mapping(bytes32 => uint64) public nodeEpoch;
    mapping(bytes32 => mapping(address => uint256)) public capRemaining;
    mapping(bytes32 => bool) public ticketLive;

    event CommitProposed(bytes32 indexed mandateId, bytes32 commitHash);
    event CommitCleared(bytes32 indexed mandateId, address indexed by);
    event Activated(bytes32 indexed mandateId, uint64 epoch, uint64 era, CapabilityNode root);
    event Shrunk(bytes32 indexed mandateId, uint64 epoch, CapabilityNode root);
    event EpochBumped(bytes32 indexed mandateId, uint64 epoch, uint8 status);
    event Tripped(bytes32 indexed mandateId, uint8 code);
    event Admitted(bytes32 indexed ticketHash, bytes32 indexed mandateId, TicketPreimage ticket);
    event TicketDropped(bytes32 indexed ticketHash, address indexed by);
    event Settled(bytes32 indexed ticketHash, bytes32 indexed mandateId, uint256[] outflows, uint256[] inflows);
    event Delegated(bytes32 indexed parentCapId, bytes32 indexed childCapId, CapabilityNode child);
    event CapRevoked(bytes32 indexed capId, uint64 nodeEpoch);
    event CapReclaimed(bytes32 indexed fromCapId, bytes32 indexed toCapId);

    constructor(ILivenessSource liveness_) EIP712("SMP-AgentGate", "1") {
        liveness = liveness_;
    }

    function _proposalHash(Proposal calldata p) internal view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(PROPOSAL_TAG, keccak256(abi.encode(p)))));
    }

    /// @dev Fail closed. One snapshot: bound account, config digest, and no other authority path.
    ///      A revert is a failed check. Reject codes are unchanged.
    function _accountOk(address principal, address adapter, bytes32 digest, address agent) internal view returns (bool) {
        if (adapter == address(0) || adapter.code.length == 0) return false;
        try IAccountAdapter(adapter).accountSnapshot(agent) returns (address bound, bytes32 d, bool other) {
            return bound == principal && d == digest && !other;
        } catch {
            return false;
        }
    }

    function _isGuardian(bytes32 root, address who, bytes32[] calldata proof) internal pure returns (bool) {
        return MerkleProof.verifyCalldata(proof, root, keccak256(bytes.concat(keccak256(abi.encode(who)))));
    }

    function _indexOf(address[] calldata list, address x) internal pure returns (uint256) {
        for (uint256 i; i < list.length; ++i) {
            if (list[i] == x) return i;
        }
        return type(uint256).max;
    }
}
