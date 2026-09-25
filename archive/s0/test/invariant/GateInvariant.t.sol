// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SealedMandateGate} from "../../src/SealedMandateGate.sol";
import {PublicPredicateVerifier} from "../../src/verifiers/PublicPredicateVerifier.sol";
import {MockToken} from "../utils/SMPBase.sol";
import {MerkleHelper} from "../utils/MerkleHelper.sol";

contract GateHandler is Test {
    SealedMandateGate internal gate;
    PublicPredicateVerifier internal verifier;
    MockToken internal token;

    address internal principal = makeAddr("inv-principal");
    uint256 internal agentPk = 0xA11CE;
    address internal agent;
    address public outsider = makeAddr("inv-outsider");
    address[] internal d;
    bytes32 internal destRoot;
    bytes32 internal vis;
    bytes32 internal commit;
    PublicPredicateVerifier.Predicate internal p;

    bytes32[] public ids;
    bytes32[] public roots;
    bytes32[] public candidates;
    uint256 public totalIssued;
    uint256 public totalPaid;
    uint256 public totalReclaimed;
    bool public outsiderAccepted;
    uint256 internal nonce;
    uint256 public nDelegated;
    uint256 public nFinalized;
    uint256 public nCancelled;
    uint256 public nReleased;
    uint256 public nReclaimed;
    uint256 public nRevoked;

    constructor(SealedMandateGate gate_, PublicPredicateVerifier verifier_, MockToken token_) {
        (gate, verifier, token) = (gate_, verifier_, token_);
        agent = vm.addr(agentPk);
        d.push(makeAddr("inv-alice"));
        d.push(makeAddr("inv-bob"));
        d.push(makeAddr("inv-carol"));
        destRoot = MerkleHelper.root(d);
        vis = verifier.VIS_PUBLIC();
        p = PublicPredicateVerifier.Predicate({agent: agent, perActCap: type(uint128).max, mayDelegate: true});
        commit = verifier.commitOf(p, destRoot, vis);
        token.mint(principal, type(uint128).max);
        vm.prank(principal);
        token.approve(address(gate), type(uint256).max);
    }

    function members() external view returns (address[] memory) {
        return d;
    }

    function idsLength() external view returns (uint256) {
        return ids.length;
    }

    function rootsLength() external view returns (uint256) {
        return roots.length;
    }

    function candidatesLength() external view returns (uint256) {
        return candidates.length;
    }

    // ───────────── actions ─────────────

    function issue(uint256 budget, uint256 ttl) external {
        budget = bound(budget, 1e18, 1_000e18);
        ttl = bound(ttl, 1 hours, 10 days);
        vm.prank(principal);
        bytes32 id = gate.issueMandate(commit, destRoot, budget, uint64(block.timestamp + ttl), vis, address(token), "");
        ids.push(id);
        roots.push(id);
        totalIssued += budget;
    }

    function delegate(uint256 parentSeed, uint256 budget, uint256 ttl) external {
        if (ids.length == 0) return;
        bytes32 parentId = ids[parentSeed % ids.length];
        SealedMandateGate.Mandate memory m = gate.getMandate(parentId);
        if (m.expiry <= block.timestamp + 1) return;
        uint256 avail = gate.remainingBudget(parentId);
        budget = bound(budget, 1, avail + 1); // +1 keeps over-budget attempts in the mix
        uint64 expiry = uint64(bound(ttl, block.timestamp + 1, m.expiry));
        vm.prank(agent);
        try gate.delegate(parentId, commit, destRoot, budget, expiry, vis, 0, abi.encode(p, p)) returns (bytes32 c) {
            ids.push(c);
            ++nDelegated;
        } catch {}
    }

    function spend(uint256 idSeed, uint256 destSeed, uint256 cost, bool finalizeNow) external {
        if (ids.length == 0) return;
        bool toOutsider = destSeed % 8 == 0;
        bytes32 id = ids[idSeed % ids.length];
        address dest = toOutsider ? outsider : d[destSeed % d.length];
        uint256 avail = gate.remainingBudget(id);
        cost = bound(cost, 1, avail + avail / 10 + 1);

        SealedMandateGate.Act memory act = SealedMandateGate.Act({
            mandateId: id,
            dest: dest,
            cost: cost,
            epoch: gate.currentEpoch(id),
            deadline: uint64(block.timestamp + 12 hours),
            nonce: bytes32(++nonce),
            visProjection: ""
        });
        bytes32 digest = gate.computeActDigest(act);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentPk, MessageHashUtils.toEthSignedMessageHash(digest));

        uint256 levels = uint256(gate.getMandate(id).depth) + 1;
        bytes32[][] memory dp = new bytes32[][](levels);
        bytes32[] memory memberProof = MerkleHelper.proof(d, toOutsider ? d[0] : dest);
        for (uint256 i; i < levels; ++i) {
            dp[i] = memberProof;
        }
        bytes memory proof = abi.encode(dp, abi.encode(p, abi.encodePacked(r, s, v)));

        try gate.submitCandidate(act, digest, 0, proof) returns (bytes32 cid) {
            if (toOutsider) outsiderAccepted = true;
            candidates.push(cid);
            if (finalizeNow) _finalize(cid);
        } catch {}
    }

    function finalizePending(uint256 seed) external {
        if (candidates.length == 0) return;
        _finalize(candidates[seed % candidates.length]);
    }

    function cancelPending(uint256 seed, bool asPrincipal) external {
        if (candidates.length == 0) return;
        bytes32 cid = candidates[seed % candidates.length];
        address caller = asPrincipal ? gate.getMandate(gate.getCandidate(cid).mandateId).principal : outsider;
        vm.prank(caller);
        try gate.cancelCandidate(cid) {
            ++nCancelled;
        } catch {}
    }

    function revoke(uint256 seed) external {
        if (ids.length == 0) return;
        vm.prank(principal);
        try gate.revoke(ids[seed % ids.length]) {
            ++nRevoked;
        } catch {}
    }

    function release(uint256 seed) external {
        if (ids.length == 0) return;
        try gate.release(ids[seed % ids.length]) {
            ++nReleased;
        } catch {}
    }

    function reclaim(uint256 seed) external {
        if (roots.length == 0) return;
        try gate.reclaim(roots[seed % roots.length]) returns (uint256 amount) {
            totalReclaimed += amount;
            ++nReclaimed;
        } catch {}
    }

    function warp(uint256 dt) external {
        vm.warp(block.timestamp + bound(dt, 1, 6 hours));
    }

    function _finalize(bytes32 cid) internal {
        uint256 cost = gate.getCandidate(cid).cost;
        try gate.finalize(cid) {
            totalPaid += cost;
            ++nFinalized;
        } catch {}
    }
}

/// @notice Budget conservation and capability-graph accounting under random interleavings.
contract GateInvariantTest is Test {
    SealedMandateGate internal gate;
    MockToken internal token;
    GateHandler internal handler;

    function setUp() public {
        vm.warp(1_800_000_000);
        PublicPredicateVerifier verifier = new PublicPredicateVerifier();
        address[] memory vs = new address[](1);
        vs[0] = address(verifier);
        gate = new SealedMandateGate(vs, address(0));
        token = new MockToken();
        handler = new GateHandler(gate, verifier, token);
        handler.issue(500e18, 5 days);
        targetContract(address(handler));
        bytes4[] memory actions = new bytes4[](10);
        actions[0] = GateHandler.issue.selector;
        actions[1] = GateHandler.delegate.selector;
        actions[2] = GateHandler.spend.selector;
        actions[3] = GateHandler.spend.selector; // weight the main path
        actions[4] = GateHandler.finalizePending.selector;
        actions[5] = GateHandler.cancelPending.selector;
        actions[6] = GateHandler.revoke.selector;
        actions[7] = GateHandler.release.selector;
        actions[8] = GateHandler.reclaim.selector;
        actions[9] = GateHandler.warp.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: actions}));
    }

    /// Handler swallows reverts, so show that runs actually reach each state transition.
    function afterInvariant() public view {
        console.log(
            string.concat(
                "roots=", vm.toString(handler.rootsLength()),
                " delegated=", vm.toString(handler.nDelegated()),
                " finalized=", vm.toString(handler.nFinalized()),
                " cancelled=", vm.toString(handler.nCancelled())
            )
        );
        console.log(
            string.concat(
                "revoked=", vm.toString(handler.nRevoked()),
                " released=", vm.toString(handler.nReleased()),
                " reclaimed=", vm.toString(handler.nReclaimed())
            )
        );
    }

    /// Escrow = Σ remain of open roots.
    function invariant_escrowEqualsOpenRootRemain() public view {
        uint256 sum;
        for (uint256 i; i < handler.rootsLength(); ++i) {
            SealedMandateGate.Mandate memory r = gate.getMandate(handler.roots(i));
            if (!r.closed) sum += r.remain;
        }
        assertEq(token.balanceOf(address(gate)), sum);
    }

    /// Issued = escrow + paid out through the gate + refunded to principals. Nothing else leaves.
    function invariant_conservation() public view {
        assertEq(
            token.balanceOf(address(gate)) + handler.totalPaid() + handler.totalReclaimed(), handler.totalIssued()
        );
        address[] memory d = handler.members();
        uint256 received;
        for (uint256 i; i < d.length; ++i) {
            received += token.balanceOf(d[i]);
        }
        assertEq(received, handler.totalPaid());
    }

    function invariant_outsiderNeverPaid() public view {
        assertFalse(handler.outsiderAccepted());
        assertEq(token.balanceOf(handler.outsider()), 0);
    }

    /// Per open node: locked + reserved ≤ remain; locked = Σ remain of open children;
    /// reserved = Σ cost of its pending candidates.
    function invariant_graphAccounting() public view {
        uint256 n = handler.idsLength();
        uint256 m = handler.candidatesLength();
        for (uint256 i; i < n; ++i) {
            bytes32 id = handler.ids(i);
            SealedMandateGate.Mandate memory node = gate.getMandate(id);
            if (node.closed) continue;
            assertLe(node.locked + node.reserved, node.remain, "overcommitted");

            uint256 childSum;
            for (uint256 j; j < n; ++j) {
                SealedMandateGate.Mandate memory c = gate.getMandate(handler.ids(j));
                if (c.parent == id && !c.closed) childSum += c.remain;
            }
            assertEq(node.locked, childSum, "locked != open children");

            uint256 pendingSum;
            for (uint256 k; k < m; ++k) {
                SealedMandateGate.Candidate memory cand = gate.getCandidate(handler.candidates(k));
                if (cand.mandateId == id && cand.status == SealedMandateGate.Status.Pending) pendingSum += cand.cost;
            }
            assertEq(node.reserved, pendingSum, "reserved != pending");
        }
    }
}
