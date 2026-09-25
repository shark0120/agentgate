// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AgentGate} from "../../src/AgentGate.sol";
import {GateSettlement} from "../../src/GateSettlement.sol";
import {EcdsaAttestationVerifier} from "../../src/verifiers/EcdsaAttestationVerifier.sol";
import {ILivenessSource} from "../../src/interfaces/IGateExternal.sol";
import "../../src/GateTypes.sol";
import "../../src/GateErrors.sol";
import {MerkleHelper} from "../utils/MerkleHelper.sol";
import {MockToken, MockAccount, MockLiveness, MockRouter, ReentrantTarget, Sink} from "../mocks/Mocks.sol";

/// @notice Fixture: one smart account, one active mandate whose root scope holds leaves 0–6.
abstract contract F1Base is Test {
    bytes32 internal constant ECDSA_SCHEME = keccak256("SMP/scheme/ecdsa");
    bytes32 internal constant POLICY = keccak256("policy text v1: pay vendors, rebalance USDC->WETH");
    bytes32 internal constant MANDATE = keccak256("mandate-1");
    bytes4 internal constant DELEGATE_SEL = bytes4(keccak256("delegate(CapabilityNode)"));

    uint256 internal constant L_PAY_ALICE = 0;
    uint256 internal constant L_PAY_BOB = 1;
    uint256 internal constant L_SWAP = 2;
    uint256 internal constant L_DELEGATE = 3;
    uint256 internal constant L_APPROVE_EVIL = 4;
    uint256 internal constant L_REENTER = 5;
    uint256 internal constant L_NATIVE = 6;
    // In the root scope on purpose: the gate itself must refuse these (A12, A13, A17).
    uint256 internal constant L_BAD_TYPE = 7;
    uint256 internal constant L_TARGET_GATE = 8;
    uint256 internal constant L_TARGET_ACCOUNT = 9;
    uint256 internal constant L_PROXY = 10;
    uint256 internal constant ROOT_LEAF_COUNT = 11;
    uint256 internal constant L_PAY_DAVE = 11; // never in the root scope

    AgentGate internal gate;
    GateSettlement internal settle; // settlement ABI at the gate's address
    EcdsaAttestationVerifier internal verifier;
    MockLiveness internal live;
    MockToken internal usdc;
    MockToken internal weth;
    MockAccount internal account;
    MockRouter internal router;
    ReentrantTarget internal reenter;
    Sink internal sink;

    uint256 internal ownerPk = 0x0111;
    uint256 internal agentPk = 0xA6E;
    uint256 internal subAgentPk = 0xB6E;
    uint256 internal guardianPk = 0x6A2D;
    uint256[3] internal attPk;
    address[3] internal att;
    address internal owner;
    address internal agent;
    address internal subAgent;
    address internal guardian;
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal dave = makeAddr("dave");
    address internal evil = makeAddr("evil");
    address internal stranger = makeAddr("stranger");

    uint64 internal activateAfter;
    uint64 internal expiry;
    uint256 internal nonceCounter;

    function setUp() public virtual {
        vm.warp(1_800_000_000);
        vm.roll(1_000);
        owner = vm.addr(ownerPk);
        agent = vm.addr(agentPk);
        subAgent = vm.addr(subAgentPk);
        guardian = vm.addr(guardianPk);
        _makeAttestors();

        usdc = new MockToken("USDC");
        weth = new MockToken("WETH");
        live = new MockLiveness();
        verifier = new EcdsaAttestationVerifier();
        GateSettlement impl = new GateSettlement(ILivenessSource(address(live)));
        bytes32[] memory schemes = new bytes32[](1);
        schemes[0] = ECDSA_SCHEME;
        address[] memory vs = new address[](1);
        vs[0] = address(verifier);
        gate = new AgentGate(schemes, vs, ILivenessSource(address(live)), address(impl));
        settle = GateSettlement(address(gate));

        account = new MockAccount(owner);
        vm.prank(owner);
        account.installGate(address(gate));
        router = new MockRouter();
        reenter = new ReentrantTarget(address(gate));
        sink = new Sink();

        usdc.mint(address(account), 1_000e18);
        weth.mint(address(router), 100e18);
        vm.deal(address(account), 10 ether);
        vm.prank(owner);
        account.execute(address(usdc), 0, abi.encodeCall(IERC20.approve, (address(router), type(uint256).max)));

        _proposeAndActivate();
    }

    // ═══════════════════════════ fixture builders ═══════════════════════════

    function _makeAttestors() internal {
        uint256[3] memory pks = [uint256(0xA771), uint256(0xA772), uint256(0xA773)];
        // Attestations must be sorted by attestor id.
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (vm.addr(pks[j]) < vm.addr(pks[i])) (pks[i], pks[j]) = (pks[j], pks[i]);
            }
        }
        for (uint256 i; i < 3; ++i) {
            attPk[i] = pks[i];
            att[i] = vm.addr(pks[i]);
        }
    }

    function _leaf(uint256 i) internal view returns (ActionLeaf memory l) {
        l.argRules = new ArgRule[](0);
        l.spenderAllowlist = new address[](0);
        l.leafType = LEAF_CALL;
        if (i == L_PAY_ALICE || i == L_PAY_BOB || i == L_PAY_DAVE) {
            address to = i == L_PAY_ALICE ? alice : i == L_PAY_BOB ? bob : dave;
            l.target = address(usdc);
            l.selector = IERC20.transfer.selector;
            l.argRules = new ArgRule[](2);
            l.argRules[0] = ArgRule(0, OP_EQ, bytes32(uint256(uint160(to))));
            l.argRules[1] = ArgRule(32, OP_LTE, bytes32(uint256(100e18)));
            l.assets = _a1(address(usdc));
            l.maxOutPerCall = _u1(100e18);
        } else if (i == L_SWAP) {
            l.target = address(router);
            l.selector = MockRouter.swap.selector;
            l.argRules = new ArgRule[](3);
            l.argRules[0] = ArgRule(0, OP_EQ, bytes32(uint256(uint160(address(usdc)))));
            l.argRules[1] = ArgRule(64, OP_EQ, bytes32(uint256(uint160(address(weth)))));
            l.argRules[2] = ArgRule(128, OP_EQ_ACCOUNT, 0);
            l.assets = new address[](2);
            (l.assets[0], l.assets[1]) = (address(usdc), address(weth));
            l.maxOutPerCall = new uint256[](2);
            l.maxOutPerCall[0] = 200e18;
            l.spenderAllowlist = _a1(address(router));
        } else if (i == L_DELEGATE) {
            l.leafType = LEAF_DELEGATE;
            l.selector = DELEGATE_SEL;
            l.assets = _a1(address(usdc));
            l.maxOutPerCall = _u1(300e18);
            return l; // no target, no code hash
        } else if (i == L_APPROVE_EVIL) {
            l.target = address(usdc);
            l.selector = IERC20.approve.selector;
            l.argRules = new ArgRule[](1);
            l.argRules[0] = ArgRule(0, OP_EQ, bytes32(uint256(uint160(evil))));
            l.assets = _a1(address(usdc));
            l.maxOutPerCall = _u1(0);
        } else if (i == L_REENTER) {
            l.target = address(reenter);
            l.selector = ReentrantTarget.poke.selector;
            l.assets = _a1(address(usdc));
            l.maxOutPerCall = _u1(0);
        } else if (i == L_NATIVE) {
            l.target = address(sink);
            l.selector = Sink.ping.selector;
            l.assets = _a1(NATIVE);
            l.maxOutPerCall = _u1(1 ether);
        } else if (i == L_BAD_TYPE) {
            l.leafType = 2;
            l.target = address(usdc);
            l.selector = IERC20.transfer.selector;
            l.assets = _a1(address(usdc));
            l.maxOutPerCall = _u1(0);
        } else if (i == L_TARGET_GATE) {
            l.target = address(gate);
            l.selector = AgentGate.cancelCommit.selector;
            l.assets = _a1(address(usdc));
            l.maxOutPerCall = _u1(0);
        } else if (i == L_TARGET_ACCOUNT) {
            l.target = address(account);
            l.selector = MockAccount.installModule.selector;
            l.assets = _a1(address(usdc));
            l.maxOutPerCall = _u1(0);
        } else if (i == L_PROXY) {
            l.target = address(usdc);
            l.implementation = address(0xBEEF);
            l.selector = IERC20.transfer.selector;
            l.assets = _a1(address(usdc));
            l.maxOutPerCall = _u1(100e18);
        }
        l.codeHash = l.target.codehash;
    }

    function _params() internal view returns (Params memory p) {
        p.attestThreshold = 2;
        p.attestSchemes = new bytes32[](1);
        p.attestSchemes[0] = ECDSA_SCHEME;
        p.windowMin = 10 minutes;
        p.windowBase = 1 hours;
        p.windowRate = new AssetAmount[](1);
        p.windowRate[0] = AssetAmount(address(usdc), 36); // +36 s per 1e18 reserved
        p.coSignWindowMin = 5 minutes;
        p.activationDelay = 1 days;
        p.maxDepth = 2;
        p.maxStateAge = 64;
        p.outageGrace = 30 minutes;
    }

    function _budget() internal view returns (BudgetSpec memory b) {
        b.assets = new AssetBudget[](2);
        b.assets[0] = AssetBudget(address(usdc), 500e18, 300e18, 1 days);
        b.assets[1] = AssetBudget(NATIVE, 2 ether, 2 ether, 1 days);
    }

    function _commit() internal view returns (MandateCommit memory) {
        return _commitWith(_params(), _budget(), expiry);
    }

    function _commitWith(Params memory p, BudgetSpec memory b, uint64 exp)
        internal
        view
        returns (MandateCommit memory c)
    {
        c.mandateId = MANDATE;
        c.principalAccount = address(account);
        c.rootDelegatee = agent;
        c.scopeRoot = MerkleHelper.rootOf(_scopeLeaves(_rootSet()));
        c.policyHash = POLICY;
        c.attestorSetRoot = MerkleHelper.rootOf(_attestorLeaves());
        c.guardianSetRoot = MerkleHelper.root(_one(guardian));
        c.paramsHash = keccak256(abi.encode(p));
        c.budgetHash = keccak256(abi.encode(b));
        c.accountConfigDigest = account.configDigest();
        c.expiry = exp;
        c.activateAfter = activateAfter;
    }

    function _proposeAndActivate() internal {
        activateAfter = uint64(vm.getBlockTimestamp() + 1 days);
        expiry = uint64(vm.getBlockTimestamp() + 60 days);
        MandateCommit memory c = _commit();
        (Attestation[] memory r, bytes32[][] memory rp) = _ready(c);
        _asPrincipal(abi.encodeCall(AgentGate.proposeCommit, (c, _params(), r, rp)));
        vm.warp(activateAfter);
        gate.activate(c, _params(), _budget());
    }

    // ═══════════════════════════ scope & sets ═══════════════════════════

    function _rootSet() internal pure returns (uint256[] memory s) {
        s = new uint256[](ROOT_LEAF_COUNT);
        for (uint256 i; i < ROOT_LEAF_COUNT; ++i) {
            s[i] = i;
        }
    }

    function _scopeLeaves(uint256[] memory set) internal view returns (bytes32[] memory out) {
        out = new bytes32[](set.length);
        for (uint256 i; i < set.length; ++i) {
            out[i] = keccak256(bytes.concat(keccak256(abi.encode(_leaf(set[i])))));
        }
    }

    function _scopeRootOf(uint256[] memory set) internal view returns (bytes32) {
        return MerkleHelper.rootOf(_scopeLeaves(set));
    }

    function _scopeProof(uint256[] memory set, uint256 leafIdx) internal view returns (bytes32[] memory) {
        uint256 pos = type(uint256).max;
        for (uint256 i; i < set.length; ++i) {
            if (set[i] == leafIdx) pos = i;
        }
        if (pos == type(uint256).max) return new bytes32[](0); // caller wants a failing proof
        return MerkleHelper.proofOf(_scopeLeaves(set), pos);
    }

    function _attestorLeaves() internal view returns (bytes32[] memory out) {
        out = new bytes32[](3);
        for (uint256 i; i < 3; ++i) {
            out[i] = keccak256(bytes.concat(keccak256(abi.encode(bytes32(uint256(uint160(att[i]))), ECDSA_SCHEME))));
        }
    }

    function _attestorProof(uint256 i) internal view returns (bytes32[] memory) {
        return MerkleHelper.proofOf(_attestorLeaves(), i);
    }

    // ═══════════════════════════ signatures ═══════════════════════════

    function _sig(uint256 pk, bytes32 h) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        return abi.encodePacked(r, s, v);
    }

    function _attest(uint256 who, bytes32 ph, uint64 ep, StateRef memory sr)
        internal
        view
        returns (Attestation memory a)
    {
        a = Attestation({
            proposalHash: ph,
            policyHash: POLICY,
            epoch: ep,
            stateRef: sr,
            attestor: bytes32(uint256(uint160(att[who]))),
            scheme: ECDSA_SCHEME,
            verdict: VERDICT_ALLOW,
            expiresAt: uint64(vm.getBlockTimestamp() + 2 days),
            blob: ""
        });
        a.blob = _sig(attPk[who], gate.attestationHash(a));
    }

    function _ready(MandateCommit memory c) internal view returns (Attestation[] memory a, bytes32[][] memory p) {
        bytes32 rh = gate.readyHash(keccak256(abi.encode(c)));
        a = new Attestation[](2);
        p = new bytes32[][](2);
        for (uint256 i; i < 2; ++i) {
            a[i] = _attest(i, rh, 0, StateRef(0, 0));
            p[i] = _attestorProof(i);
        }
    }

    // ═══════════════════════════ proposals ═══════════════════════════

    function _epoch() internal view returns (uint64) {
        return gate.getMandate(MANDATE).epoch;
    }

    function _rootNode() internal view returns (CapabilityNode memory) {
        return _rootNodeFor(_commit(), _params(), _budget());
    }

    function _rootNodeFor(MandateCommit memory c, Params memory p, BudgetSpec memory b)
        internal
        view
        returns (CapabilityNode memory n)
    {
        uint64 e = _epoch();
        n.capId = gate.rootCapId(MANDATE, e);
        n.mandateId = MANDATE;
        n.mandateEpoch = e;
        n.delegatee = c.rootDelegatee;
        n.scopeRoot = c.scopeRoot;
        n.expiry = c.expiry;
        n.canDelegate = p.maxDepth > 0;
        n.allotment = new AssetAmount[](b.assets.length);
        for (uint256 i; i < b.assets.length; ++i) {
            n.allotment[i] = AssetAmount(b.assets[i].asset, b.assets[i].epochCap);
        }
    }

    function _stateRef() internal returns (StateRef memory sr) {
        uint256 bn = vm.getBlockNumber() - 1;
        bytes32 h = keccak256(abi.encode("blockhash", bn));
        vm.setBlockhash(bn, h);
        sr = StateRef(uint64(bn), h);
    }

    function _pathRoot() internal view returns (CapabilityNode[] memory path, uint256[][] memory sets) {
        path = new CapabilityNode[](1);
        path[0] = _rootNode();
        sets = new uint256[][](1);
        sets[0] = _rootSet();
    }

    /// @notice Complete, valid admission input for leaf `leafIdx` with calldata `data`.
    function _input(
        uint256 leafIdx,
        bytes memory data,
        uint256[] memory outs,
        CapabilityNode[] memory path,
        uint256[][] memory sets,
        uint256 signerPk
    ) internal returns (AdmitInput memory a) {
        ActionLeaf memory l = _leaf(leafIdx);
        Proposal memory p;
        p.mandateId = MANDATE;
        p.epoch = _epoch();
        p.capPath = new bytes32[](path.length);
        for (uint256 i; i < path.length; ++i) {
            p.capPath[i] = path[i].capId;
        }
        p.leafHash = keccak256(abi.encode(l));
        p.calldataHash = keccak256(data);
        p.declaredOut = new AssetAmount[](l.assets.length);
        for (uint256 i; i < l.assets.length; ++i) {
            p.declaredOut[i] = AssetAmount(l.assets[i], outs[i]);
        }
        p.declaredMinIn = new AssetAmount[](0);
        p.nonce = ++nonceCounter;
        p.validAfter = uint64(vm.getBlockTimestamp());
        p.validUntil = uint64(vm.getBlockTimestamp() + 3 days);
        p.stateRef = _stateRef();

        a.commit = _commit();
        a.params = _params();
        a.budget = _budget();
        a.proposal = p;
        a.leaf = l;
        a.path = path;
        a.scopeProofs = new bytes32[][](path.length);
        for (uint256 i; i < path.length; ++i) {
            a.scopeProofs[i] = _scopeProof(sets[i], leafIdx);
        }
        a.data = data;
        _sign(a, signerPk);
    }

    /// @notice (Re)sign a possibly edited input: agent signature plus two attestations.
    function _sign(AdmitInput memory a, uint256 signerPk) internal view {
        bytes32 ph = gate.proposalHash(a.proposal);
        a.agentSig = _sig(signerPk, ph);
        a.attestations = new Attestation[](2);
        a.attestorProofs = new bytes32[][](2);
        for (uint256 i; i < 2; ++i) {
            a.attestations[i] = _attest(i, ph, a.proposal.epoch, a.proposal.stateRef);
            a.attestorProofs[i] = _attestorProof(i);
        }
    }

    function _payInput(uint256 leafIdx, address to, uint256 amt) internal returns (AdmitInput memory) {
        (CapabilityNode[] memory path, uint256[][] memory sets) = _pathRoot();
        return _input(leafIdx, abi.encodeCall(IERC20.transfer, (to, amt)), _u1(amt), path, sets, agentPk);
    }

    function _exec(AdmitInput memory a, TicketPreimage memory t) internal pure returns (ExecuteInput memory x) {
        x = ExecuteInput({ticket: t, commit: a.commit, proposal: a.proposal, leaf: a.leaf, data: a.data});
    }

    /// @notice Admit, wait out the window, execute. Returns measured outflows.
    function _settle(AdmitInput memory a) internal returns (uint256[] memory outs) {
        (, TicketPreimage memory t) = gate.admit(a);
        vm.warp(t.windowEnd);
        (outs,) = settle.execute(_exec(a, t));
    }

    function _asPrincipal(bytes memory call) internal {
        vm.prank(owner);
        account.execute(address(gate), 0, call);
    }

    // ═══════════════════════════ small arrays ═══════════════════════════

    function _a1(address x) internal pure returns (address[] memory a) {
        a = new address[](1);
        a[0] = x;
    }

    function _u1(uint256 x) internal pure returns (uint256[] memory a) {
        a = new uint256[](1);
        a[0] = x;
    }

    function _u2(uint256 x, uint256 y) internal pure returns (uint256[] memory a) {
        a = new uint256[](2);
        (a[0], a[1]) = (x, y);
    }

    function _one(address x) internal pure returns (address[] memory a) {
        a = new address[](1);
        a[0] = x;
    }
}
