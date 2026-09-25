// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SMPBase} from "./utils/SMPBase.sol";
import {MerkleHelper} from "./utils/MerkleHelper.sol";
import {SealedMandateGate} from "../src/SealedMandateGate.sol";
import {PublicPredicateVerifier} from "../src/verifiers/PublicPredicateVerifier.sol";

/// @notice Spec §16.4 minimal vectors (V1–V8) and §15 S0 falsifiable milestones.
contract SealedMandateGateTest is SMPBase {
    PublicPredicateVerifier.Predicate internal P;
    bytes32 internal root;

    function setUp() public override {
        super.setUp();
        P = _pred(agent, 60e18, true);
        root = _issue(P, _rootSet(), 100e18, 1 days);
    }

    // ═════════════════════════ §16.4 vectors ═════════════════════════

    /// V1 合法精煉 → 過閘，預算減少。
    function test_V1_legalRefinement_passes_budgetDecreases() public {
        bytes32 cid = _submit(_act(root, bob, 40e18, "n1"), _path1(_rootSet()), P, agentPk);
        assertEq(gate.remainingBudget(root), 60e18, "reserved at submit");
        vm.prank(stranger); // executor identity is irrelevant
        assertTrue(gate.finalize(cid));
        assertEq(token.balanceOf(bob), 40e18);
        assertEq(gate.remainingBudget(root), 60e18);
        assertEq(gate.getMandate(root).remain, 60e18);
        assertEq(token.balanceOf(address(gate)), 60e18);
    }

    /// V2 合法簽章、非法目標 → 拒絕。
    function test_V2_validSig_destOutsideD_rejected() public {
        SealedMandateGate.Act memory act = _act(root, dave, 10e18, "n1");
        bytes32 digest = gate.computeActDigest(act);
        // Best an attacker can do: a valid proof for some real member, reused for dave.
        bytes32[][] memory dp = new bytes32[][](1);
        dp[0] = MerkleHelper.proof(_rootSet(), alice);
        bytes memory proof = abi.encode(dp, abi.encode(P, _sign(agentPk, digest)));
        vm.expectRevert(SealedMandateGate.DestNotInSet.selector);
        gate.submitCandidate(act, digest, S0, proof);
    }

    /// V3 合法簽章、超預算 → 拒絕（剩餘預算與單筆上限兩條）。
    function test_V3_validSig_overBudget_rejected() public {
        gate.finalize(_submit(_act(root, alice, 60e18, "n1"), _path1(_rootSet()), P, agentPk));

        SealedMandateGate.Act memory act = _act(root, alice, 41e18, "n2");
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(_path1(_rootSet()), alice, P, _sign(agentPk, digest));
        vm.expectRevert(SealedMandateGate.InsufficientBudget.selector);
        gate.submitCandidate(act, digest, S0, proof);
    }

    function test_V3b_validSig_overPerActCap_isNotARefinement() public {
        SealedMandateGate.Act memory act = _act(root, alice, 61e18, "n1");
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(_path1(_rootSet()), alice, P, _sign(agentPk, digest));
        vm.expectRevert(SealedMandateGate.InvalidProof.selector);
        gate.submitCandidate(act, digest, S0, proof);
    }

    /// V4 撤銷後重放同一 π → 拒絕。
    function test_V4_revoke_thenReplaySameProof_rejected() public {
        SealedMandateGate.Act memory act = _act(root, alice, 10e18, "n1");
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(_path1(_rootSet()), alice, P, _sign(agentPk, digest));
        (bool ok,) = gate.previewVerify(act, digest, S0, proof);
        assertTrue(ok, "valid before revoke");

        vm.prank(principal);
        assertEq(gate.revoke(root), 1);

        vm.expectRevert(SealedMandateGate.StaleEpoch.selector);
        gate.submitCandidate(act, digest, S0, proof);

        // Fresh proof at the new epoch still fails: revocation is terminal.
        SealedMandateGate.Act memory act2 = _act(root, alice, 10e18, "n1");
        bytes32 d2 = gate.computeActDigest(act2);
        bytes memory p2 = _proof(_path1(_rootSet()), alice, P, _sign(agentPk, d2));
        vm.expectRevert(SealedMandateGate.MandateRevoked.selector);
        gate.submitCandidate(act2, d2, S0, p2);
    }

    function test_V4b_revoke_blocksAlreadyPendingCandidate() public {
        bytes32 cid = _submit(_act(root, alice, 10e18, "n1"), _path1(_rootSet()), P, agentPk);
        vm.prank(principal);
        gate.revoke(root);
        vm.expectRevert(SealedMandateGate.StaleEpoch.selector);
        gate.finalize(cid);
    }

    /// V5 子授權花費超過鎖定份額 → 拒絕。
    function test_V5_childSpendAboveLockedShare_rejected() public {
        PublicPredicateVerifier.Predicate memory cp = _pred(subAgent, 60e18, false);
        bytes32 child = _delegate(agent, root, P, cp, _rootSet(), 30e18, uint64(block.timestamp + 1 hours));
        assertEq(gate.remainingBudget(root), 70e18, "parent share locked");

        SealedMandateGate.Act memory act = _act(child, alice, 31e18, "c1");
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(_path2(_rootSet(), _rootSet()), alice, cp, _sign(subAgentPk, digest));
        vm.expectRevert(SealedMandateGate.InsufficientBudget.selector);
        gate.submitCandidate(act, digest, S0, proof);

        // Within share: passes, and the spend is debited from every ancestor.
        gate.finalize(_submit(_act(child, alice, 30e18, "c2"), _path2(_rootSet(), _rootSet()), cp, subAgentPk));
        assertEq(gate.getMandate(root).remain, 70e18);
        assertEq(gate.getMandate(root).locked, 0);
        assertEq(gate.remainingBudget(root), 70e18);
        assertEq(gate.remainingBudget(child), 0);
    }

    /// V6 actDigest 與實際呼叫不一致 → 拒絕。
    function test_V6_actDigestMismatch_rejected() public {
        SealedMandateGate.Act memory signed = _act(root, alice, 10e18, "n1");
        bytes32 signedDigest = gate.computeActDigest(signed);
        bytes memory sig = _sign(agentPk, signedDigest);

        // (a) Relayer swaps the receiver but keeps the signed digest.
        SealedMandateGate.Act memory swapped = _act(root, bob, 10e18, "n1");
        bytes memory proofBob = _proof(_path1(_rootSet()), bob, P, sig);
        vm.expectRevert(SealedMandateGate.ActDigestMismatch.selector);
        gate.submitCandidate(swapped, signedDigest, S0, proofBob);

        // (b) Relayer recomputes the digest honestly: the signature no longer matches.
        bytes32 honestDigest = gate.computeActDigest(swapped);
        vm.expectRevert(SealedMandateGate.InvalidProof.selector);
        gate.submitCandidate(swapped, honestDigest, S0, proofBob);

        // (c) Relayer swaps only the projection handed to solvers.
        SealedMandateGate.Act memory reprojected = _act(root, alice, 10e18, "n1");
        reprojected.visProjection = "tampered";
        vm.expectRevert(SealedMandateGate.ActDigestMismatch.selector);
        gate.submitCandidate(reprojected, signedDigest, S0, _proof(_path1(_rootSet()), alice, P, sig));
    }

    /// V7 錯誤證明類型或空證明 → 拒絕。
    function test_V7_wrongProofTypeOrEmptyProof_rejected() public {
        SealedMandateGate.Act memory act = _act(root, alice, 10e18, "n1");
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(_path1(_rootSet()), alice, P, _sign(agentPk, digest));

        vm.expectRevert(SealedMandateGate.UnsupportedProofType.selector);
        gate.submitCandidate(act, digest, 1, proof);

        vm.expectRevert(SealedMandateGate.EmptyProof.selector);
        gate.submitCandidate(act, digest, S0, "");

        vm.expectRevert();
        gate.submitCandidate(act, digest, S0, hex"deadbeef");

        (bool ok, bytes4 why) = gate.previewVerify(act, digest, S0, hex"deadbeef");
        assertFalse(ok);
        assertEq(why, SealedMandateGate.MalformedProof.selector);
    }

    /// V8 重複 actDigest → 第二次拒絕（pending 與已終局兩種）。
    function test_V8_duplicateActDigest_secondRejected() public {
        SealedMandateGate.Act memory act = _act(root, alice, 10e18, "n1");
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(_path1(_rootSet()), alice, P, _sign(agentPk, digest));
        gate.submitCandidate(act, digest, S0, proof);

        vm.expectRevert(SealedMandateGate.DuplicateAct.selector);
        gate.submitCandidate(act, digest, S0, proof);

        gate.finalize(digest);
        vm.expectRevert(SealedMandateGate.NotPending.selector);
        gate.finalize(digest);
        vm.expectRevert(SealedMandateGate.DuplicateAct.selector);
        gate.submitCandidate(act, digest, S0, proof);
    }

    // ═════════════════════ §15 S0 milestones & §2.2 forbidden transitions ═════════════════════

    /// 選擇器合法、簽章有效、但簽的人不是被承諾的 agent（session key ≠ 授權）。
    function test_S0_validSignatureFromUncommittedKey_rejected() public {
        SealedMandateGate.Act memory act = _act(root, alice, 10e18, "n1");
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(_path1(_rootSet()), alice, P, _sign(subAgentPk, digest));
        vm.expectRevert(SealedMandateGate.InvalidProof.selector);
        gate.submitCandidate(act, digest, S0, proof);
    }

    /// 證明內揭示的 P 被放寬（cap 調高）→ 對不上承諾。
    function test_S0_widenedPredicate_doesNotMatchCommit() public {
        PublicPredicateVerifier.Predicate memory wide = _pred(agent, 100e18, true);
        SealedMandateGate.Act memory act = _act(root, alice, 90e18, "n1");
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(_path1(_rootSet()), alice, wide, _sign(agentPk, digest));
        vm.expectRevert(SealedMandateGate.InvalidProof.selector);
        gate.submitCandidate(act, digest, S0, proof);
    }

    /// 同一 agent 簽的 π 不可搬到另一份 Mandate（同 P、同 D）。
    function test_S0_proofForOneMandate_rejectedOnAnother() public {
        bytes32 other = _issue(P, _rootSet(), 100e18, 1 days);
        SealedMandateGate.Act memory act = _act(root, alice, 10e18, "n1");
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(_path1(_rootSet()), alice, P, _sign(agentPk, digest));
        act.mandateId = other;
        vm.expectRevert(SealedMandateGate.ActDigestMismatch.selector);
        gate.submitCandidate(act, digest, S0, proof);
    }

    /// 同鏈另一個閘門實例：digest 綁 address(this)，不可重放。
    function test_S0_crossGateReplay_rejected() public {
        address[] memory vs = new address[](1);
        vs[0] = address(verifier);
        SealedMandateGate gate2 = new SealedMandateGate(vs, guardian);
        SealedMandateGate.Act memory act = _act(root, alice, 10e18, "n1");
        assertTrue(gate2.computeActDigest(act) != gate.computeActDigest(act));
    }

    /// 兩筆完全相同的合法付款：nonce 不同即可並存（規格 §16.2 的 digest 會讓第二筆永遠撞號）。
    function test_S0_identicalPaymentsWithDistinctNonce_bothPass() public {
        gate.finalize(_submit(_act(root, alice, 10e18, "n1"), _path1(_rootSet()), P, agentPk));
        gate.finalize(_submit(_act(root, alice, 10e18, "n2"), _path1(_rootSet()), P, agentPk));
        assertEq(token.balanceOf(alice), 20e18);
    }

    function test_S0_expiry_blocksFinalize() public {
        SealedMandateGate.Act memory act = _act(root, alice, 10e18, "n1");
        act.deadline = gate.getMandate(root).expiry + 1 days; // quote outlives the mandate
        bytes32 cid = _submit(act, _path1(_rootSet()), P, agentPk);
        vm.warp(gate.getMandate(root).expiry);
        vm.expectRevert(SealedMandateGate.MandateExpired.selector);
        gate.finalize(cid);
    }

    function test_S0_quoteDeadline_blocksFinalize_thenAnyoneCanCancel() public {
        bytes32 cid = _submit(_act(root, alice, 10e18, "n1"), _path1(_rootSet()), P, agentPk);
        vm.prank(stranger);
        vm.expectRevert(SealedMandateGate.StillLive.selector);
        gate.cancelCandidate(cid);

        vm.warp(block.timestamp + 1 hours + 1);
        vm.expectRevert(SealedMandateGate.DeadlinePassed.selector);
        gate.finalize(cid);

        vm.prank(stranger);
        gate.cancelCandidate(cid);
        assertEq(gate.remainingBudget(root), 100e18, "reservation freed");
    }

    function test_S0_principalCanCancelLiveCandidate() public {
        bytes32 cid = _submit(_act(root, alice, 10e18, "n1"), _path1(_rootSet()), P, agentPk);
        vm.prank(principal);
        gate.cancelCandidate(cid);
        vm.expectRevert(SealedMandateGate.NotPending.selector);
        gate.finalize(cid);
    }

    function test_S0_onlyPrincipalOnPathCanRevoke() public {
        vm.prank(agent);
        vm.expectRevert(SealedMandateGate.NotAuthorized.selector);
        gate.revoke(root);
    }

    // ═════════════════════════ §2.4 / §8 delegation ═════════════════════════

    function test_delegate_widerCap_rejected() public {
        vm.expectRevert(SealedMandateGate.InvalidProof.selector);
        _delegate(agent, root, P, _pred(subAgent, 61e18, false), _rootSet(), 10e18, uint64(block.timestamp + 1 hours));
    }

    function test_delegate_widerWindow_rejected() public {
        uint64 tooLate = gate.getMandate(root).expiry + 1;
        vm.expectRevert(SealedMandateGate.WidensWindow.selector);
        _delegate(agent, root, P, _pred(subAgent, 10e18, false), _rootSet(), 10e18, tooLate);
    }

    function test_delegate_budgetAboveAvailable_rejected() public {
        vm.expectRevert(SealedMandateGate.InsufficientBudget.selector);
        _delegate(agent, root, P, _pred(subAgent, 10e18, false), _rootSet(), 101e18, uint64(block.timestamp + 1 hours));
    }

    function test_delegate_siblingsCannotOversubscribeRoot() public {
        uint64 exp = uint64(block.timestamp + 1 hours);
        _delegate(agent, root, P, _pred(subAgent, 10e18, false), _rootSet(), 60e18, exp);
        vm.expectRevert(SealedMandateGate.InsufficientBudget.selector);
        _delegate(agent, root, P, _pred(subAgent, 10e18, false), _rootSet(), 41e18, exp);
    }

    function test_delegate_strangerCannotDelegate() public {
        vm.expectRevert(SealedMandateGate.InvalidProof.selector);
        _delegate(stranger, root, P, _pred(subAgent, 10e18, false), _rootSet(), 10e18, uint64(block.timestamp + 1 hours));
    }

    function test_delegate_agentBlockedWhenParentForbidsRedelegation() public {
        PublicPredicateVerifier.Predicate memory noDelegate = _pred(agent, 60e18, false);
        bytes32 r2 = _issue(noDelegate, _rootSet(), 100e18, 1 days);
        vm.expectRevert(SealedMandateGate.InvalidProof.selector);
        _delegate(agent, r2, noDelegate, _pred(subAgent, 10e18, false), _rootSet(), 10e18, uint64(block.timestamp + 1 hours));
    }

    function test_delegate_childCannotGainRedelegationRight() public {
        PublicPredicateVerifier.Predicate memory noDelegate = _pred(agent, 60e18, false);
        bytes32 r2 = _issue(noDelegate, _rootSet(), 100e18, 1 days);
        // Even the principal cannot mint a child that is looser than its parent.
        vm.expectRevert(SealedMandateGate.InvalidProof.selector);
        _delegate(principal, r2, noDelegate, _pred(subAgent, 10e18, true), _rootSet(), 10e18, uint64(block.timestamp + 1 hours));
    }

    /// D′ ⊄ D: child commits to a set containing dave; the root level still rejects dave.
    function test_delegate_childDestOutsideParentD_rejectedAtSpend() public {
        PublicPredicateVerifier.Predicate memory cp = _pred(subAgent, 60e18, false);
        address[] memory wider = _set(alice, bob, dave);
        bytes32 child = _delegate(agent, root, P, cp, wider, 30e18, uint64(block.timestamp + 1 hours));

        SealedMandateGate.Act memory act = _act(child, dave, 10e18, "c1");
        bytes32 digest = gate.computeActDigest(act);
        bytes32[][] memory dp = new bytes32[][](2);
        dp[0] = MerkleHelper.proof(wider, dave);
        dp[1] = MerkleHelper.proof(_rootSet(), alice); // no honest proof exists for dave
        bytes memory proof = abi.encode(dp, abi.encode(cp, _sign(subAgentPk, digest)));
        vm.expectRevert(SealedMandateGate.DestNotInSet.selector);
        gate.submitCandidate(act, digest, S0, proof);

        // Omitting the root level is also rejected.
        dp = new bytes32[][](1);
        dp[0] = MerkleHelper.proof(wider, dave);
        proof = abi.encode(dp, abi.encode(cp, _sign(subAgentPk, digest)));
        vm.expectRevert(SealedMandateGate.MalformedProof.selector);
        gate.submitCandidate(act, digest, S0, proof);
    }

    function test_delegate_parentAgentCannotSpendChildBudget() public {
        PublicPredicateVerifier.Predicate memory cp = _pred(subAgent, 60e18, false);
        bytes32 child = _delegate(agent, root, P, cp, _rootSet(), 30e18, uint64(block.timestamp + 1 hours));
        SealedMandateGate.Act memory act = _act(child, alice, 10e18, "c1");
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(_path2(_rootSet(), _rootSet()), alice, cp, _sign(agentPk, digest));
        vm.expectRevert(SealedMandateGate.InvalidProof.selector);
        gate.submitCandidate(act, digest, S0, proof);
    }

    /// §5.4 / §8.4 父撤銷使子樹未終局候選失效。
    function test_parentRevoke_killsChildPendingAndNew() public {
        PublicPredicateVerifier.Predicate memory cp = _pred(subAgent, 60e18, false);
        bytes32 child = _delegate(agent, root, P, cp, _rootSet(), 30e18, uint64(block.timestamp + 1 hours));
        bytes32 cid = _submit(_act(child, alice, 10e18, "c1"), _path2(_rootSet(), _rootSet()), cp, subAgentPk);

        vm.prank(principal);
        gate.revoke(root);

        vm.expectRevert(SealedMandateGate.ParentEpochAdvanced.selector);
        gate.finalize(cid);

        SealedMandateGate.Act memory act = _act(child, alice, 10e18, "c2");
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(_path2(_rootSet(), _rootSet()), alice, cp, _sign(subAgentPk, digest));
        vm.expectRevert(SealedMandateGate.ParentEpochAdvanced.selector);
        gate.submitCandidate(act, digest, S0, proof);
    }

    function test_rootPrincipalCanRevokeGrandchild_andDelegatorCanRevokeOwnChild() public {
        PublicPredicateVerifier.Predicate memory cp = _pred(subAgent, 60e18, true);
        uint64 exp = uint64(block.timestamp + 1 hours);
        bytes32 child = _delegate(agent, root, P, cp, _rootSet(), 30e18, exp);
        bytes32 grand = _delegate(subAgent, child, cp, _pred(agent, 5e18, false), _rootSet(), 10e18, exp);

        vm.prank(principal);
        gate.revoke(grand);

        vm.prank(stranger);
        vm.expectRevert(SealedMandateGate.NotAuthorized.selector);
        gate.revoke(child);

        vm.prank(agent); // delegator of `child`
        gate.revoke(child);
    }

    function test_release_returnsUnspentShareToParent() public {
        PublicPredicateVerifier.Predicate memory cp = _pred(subAgent, 60e18, false);
        bytes32 child = _delegate(agent, root, P, cp, _rootSet(), 30e18, uint64(block.timestamp + 1 hours));
        gate.finalize(_submit(_act(child, alice, 10e18, "c1"), _path2(_rootSet(), _rootSet()), cp, subAgentPk));

        vm.expectRevert(SealedMandateGate.StillLive.selector);
        gate.release(child);

        vm.warp(block.timestamp + 1 hours);
        gate.release(child);
        assertEq(gate.remainingBudget(root), 90e18);
        assertEq(gate.getMandate(root).locked, 0);
    }

    function test_depthLimit() public {
        uint64 exp = uint64(block.timestamp + 1 hours);
        PublicPredicateVerifier.Predicate memory p = _pred(agent, 60e18, true);
        bytes32 id = root;
        for (uint256 i; i < gate.MAX_DEPTH(); ++i) {
            id = _delegate(agent, id, p, p, _rootSet(), 10e18, exp);
        }
        vm.expectRevert(SealedMandateGate.DepthExceeded.selector);
        _delegate(agent, id, p, p, _rootSet(), 1e18, exp);
    }

    // ═════════════════════════ exits & guardian ═════════════════════════

    function test_reclaim_onlyAfterRootIsDead() public {
        vm.expectRevert(SealedMandateGate.StillLive.selector);
        gate.reclaim(root);

        gate.finalize(_submit(_act(root, alice, 25e18, "n1"), _path1(_rootSet()), P, agentPk));
        bytes32 pending = _submit(_act(root, alice, 5e18, "n2"), _path1(_rootSet()), P, agentPk);

        vm.prank(principal);
        gate.revoke(root);
        uint256 before = token.balanceOf(principal);
        vm.prank(stranger); // anyone may trigger; funds only go to the principal
        assertEq(gate.reclaim(root), 75e18);
        assertEq(token.balanceOf(principal) - before, 75e18);
        assertEq(token.balanceOf(address(gate)), 0);

        vm.expectRevert(SealedMandateGate.MandateClosed.selector);
        gate.reclaim(root);
        vm.expectRevert(SealedMandateGate.StaleEpoch.selector);
        gate.finalize(pending);
    }

    function test_reclaim_afterExpiry_includesDelegatedShares() public {
        PublicPredicateVerifier.Predicate memory cp = _pred(subAgent, 60e18, false);
        bytes32 child = _delegate(agent, root, P, cp, _rootSet(), 30e18, uint64(block.timestamp + 1 hours));
        bytes32 pending = _submit(_act(child, alice, 10e18, "c1"), _path2(_rootSet(), _rootSet()), cp, subAgentPk);
        vm.warp(gate.getMandate(root).expiry);
        assertEq(gate.reclaim(root), 100e18);
        vm.expectRevert(SealedMandateGate.DeadlinePassed.selector);
        gate.finalize(pending);
        gate.release(child); // bookkeeping only; parent already closed
    }

    function test_guardian_canOnlyDisable_andDisabledTypeCannotFinalize() public {
        bytes32 cid = _submit(_act(root, alice, 10e18, "n1"), _path1(_rootSet()), P, agentPk);

        vm.expectRevert(SealedMandateGate.NotAuthorized.selector);
        gate.disableProofType(S0);

        vm.prank(guardian);
        gate.disableProofType(S0);

        vm.expectRevert(SealedMandateGate.ProofTypeDisabled.selector);
        gate.finalize(cid);

        SealedMandateGate.Act memory act = _act(root, alice, 10e18, "n2");
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(_path1(_rootSet()), alice, P, _sign(agentPk, digest));
        vm.expectRevert(SealedMandateGate.ProofTypeDisabled.selector);
        gate.submitCandidate(act, digest, S0, proof);

        // Principal's exit does not depend on any proof system.
        vm.prank(principal);
        gate.revoke(root);
        gate.reclaim(root);
        assertEq(token.balanceOf(address(gate)), 0);
    }

    function test_issue_rejectsNonPublicVisibilityAtSpend() public {
        bytes32 destRoot = MerkleHelper.root(_rootSet());
        bytes32 fakeSealed = keccak256("SMP/V/SEALED");
        bytes32 commit = verifier.commitOf(P, destRoot, fakeSealed);
        vm.prank(principal);
        bytes32 id = gate.issueMandate(commit, destRoot, 10e18, uint64(block.timestamp + 1 hours), fakeSealed, address(token), "");
        SealedMandateGate.Act memory act = _act(id, alice, 1e18, "n1");
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(_path1(_rootSet()), alice, P, _sign(agentPk, digest));
        vm.expectRevert(SealedMandateGate.InvalidProof.selector);
        gate.submitCandidate(act, digest, S0, proof);
    }

    // ═════════════════════════ fuzz ═════════════════════════

    /// Any cost within cap and budget passes; anything above either is rejected.
    function testFuzz_costBounds(uint256 cost) public {
        cost = bound(cost, 1, 200e18);
        SealedMandateGate.Act memory act = _act(root, carol, cost, "f");
        bytes32 digest = gate.computeActDigest(act);
        bytes memory proof = _proof(_path1(_rootSet()), carol, P, _sign(agentPk, digest));
        (bool ok, bytes4 why) = gate.previewVerify(act, digest, S0, proof);
        if (cost <= 60e18) {
            assertTrue(ok);
        } else if (cost <= 100e18) {
            assertEq(why, SealedMandateGate.InvalidProof.selector);
        } else {
            assertEq(why, SealedMandateGate.InsufficientBudget.selector);
        }
    }

    /// Any receiver outside D is rejected no matter which member's proof is reused.
    function testFuzz_outsiderNeverPasses(address outsider, uint8 which) public {
        vm.assume(outsider != alice && outsider != bob && outsider != carol && outsider != address(0));
        address[] memory d = _rootSet();
        SealedMandateGate.Act memory act = _act(root, outsider, 1e18, "f");
        bytes32 digest = gate.computeActDigest(act);
        bytes32[][] memory dp = new bytes32[][](1);
        dp[0] = MerkleHelper.proof(d, d[which % 3]);
        bytes memory proof = abi.encode(dp, abi.encode(P, _sign(agentPk, digest)));
        (bool ok, bytes4 why) = gate.previewVerify(act, digest, S0, proof);
        assertFalse(ok);
        assertEq(why, SealedMandateGate.DestNotInSet.selector);
    }
}
