// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AgentGate} from "../../src/AgentGate.sol";
import {GateSettlement} from "../../src/GateSettlement.sol";
import {SafeAgentGateAdapter} from "../../src/SafeAgentGateAdapter.sol";
import "../../src/GateTypes.sol";
import "../../src/GateErrors.sol";
import {F1Base} from "../f1/F1Base.sol";

interface ISafeFactory {
    function createProxyWithNonce(address singleton, bytes memory initializer, uint256 saltNonce)
        external
        returns (address proxy);
}

interface ISafeSetup {
    function setup(
        address[] calldata owners,
        uint256 threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;
}

interface ISafeTx {
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool);

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 nonce_
    ) external view returns (bytes32);

    function nonce() external view returns (uint256);

    function domainSeparator() external view returns (bytes32);
}

contract CallSpy {
    address public lastCaller;
    address public lastSelf;

    function poke() external {
        lastCaller = msg.sender;
        lastSelf = address(this);
    }
}

/// @dev Returns true for every interface id so both Safe versions accept it as a guard.
contract PermissiveGuard {
    function supportsInterface(bytes4) external pure returns (bool) {
        return true;
    }

    function checkTransaction(
        address,
        uint256,
        bytes calldata,
        uint8,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes calldata,
        address
    ) external pure {}

    function checkAfterExecution(bytes32, bool) external pure {}

    function checkModuleTransaction(address, uint256, bytes calldata, uint8, address) external pure returns (bytes32) {
        return bytes32(0);
    }

    function checkAfterModuleExecution(bytes32, bool) external pure {}
}

/// @notice Shared Safe integration. Version files deploy the real v1.4.1 or v1.5.0 singleton.
abstract contract SafeIntegrationTest is F1Base {
    bytes32 internal constant SAFE_MSG_TYPEHASH = 0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca;

    address internal safe;
    SafeAgentGateAdapter internal adapter;

    function _singletonPath() internal pure virtual returns (string memory);
    function _factoryPath() internal pure virtual returns (string memory);
    function _handlerPath() internal pure virtual returns (string memory);

    function _deployCreation(string memory path) internal returns (address deployed) {
        bytes memory code = vm.parseBytes(vm.readFile(path));
        assembly ("memory-safe") {
            deployed := create(0, add(code, 0x20), mload(code))
        }
        require(deployed != address(0), "safe creation failed");
    }

    function _deploySafeStack() internal returns (address singleton, address factory, address handler) {
        singleton = _deployCreation(_singletonPath());
        factory = _deployCreation(_factoryPath());
        handler = _deployCreation(_handlerPath());
    }

    function _principal() internal view override returns (address) {
        return safe;
    }

    function _adapterAddr() internal view override returns (address) {
        return address(adapter);
    }

    function _configDigest() internal view override returns (bytes32) {
        return adapter.configDigest();
    }

    function _asPrincipal(bytes memory call) internal override {
        _safeExec(address(gate), 0, call);
    }

    function setUp() public override {
        _initFixture();
        _bootSafe(1);
        _proposeAndActivate();
    }

    function _bootSafe(uint256 saltNonce) internal {
        (address singleton, address factory, address handler) = _deploySafeStack();
        address[] memory owners = new address[](1);
        owners[0] = owner;
        bytes memory init = abi.encodeCall(
            ISafeSetup.setup, (owners, 1, address(0), "", handler, address(0), 0, payable(address(0)))
        );
        safe = ISafeFactory(factory).createProxyWithNonce(singleton, init, saltNonce);
        adapter = new SafeAgentGateAdapter(address(gate), safe);
        _safeExec(safe, 0, abi.encodeWithSignature("enableModule(address)", address(adapter)));
        usdc.mint(safe, 1_000e18);
        vm.deal(safe, 10 ether);
        _safeExec(address(usdc), 0, abi.encodeCall(IERC20.approve, (address(router), type(uint256).max)));
    }

    function _safeExec(address to, uint256 value, bytes memory data) internal {
        ISafeTx s = ISafeTx(safe);
        bytes32 hash = s.getTransactionHash(to, value, data, 0, 0, 0, 0, address(0), address(0), s.nonce());
        (uint8 v, bytes32 r, bytes32 sigS) = vm.sign(ownerPk, hash);
        bool ok = s.execTransaction(
            to, value, data, 0, 0, 0, 0, address(0), payable(address(0)), abi.encodePacked(r, sigS, v)
        );
        require(ok, "safe exec failed");
    }

    function _safeCoSig(bytes32 coHash) internal view returns (bytes memory) {
        bytes32 inner = keccak256(abi.encode(SAFE_MSG_TYPEHASH, keccak256(abi.encode(coHash))));
        bytes32 messageHash =
            keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), ISafeTx(safe).domainSeparator(), inner));
        return _sig(ownerPk, messageHash);
    }

    function _blocksAndTrips(bytes memory mutation) internal {
        MandateCommit memory committed = _commit();
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 10e18);
        (, TicketPreimage memory t) = gate.admit(a);
        _safeExec(safe, 0, mutation);
        vm.warp(t.windowEnd);
        vm.expectRevert(X6_AccountConfig.selector);
        settle.execute(_exec(a, t));
        ActionLeaf memory unused;
        bytes32[] memory none;
        gate.trip(TRIP_ACCOUNT_CONFIG, committed, unused, none);
        assertEq(uint256(gate.getMandate(MANDATE).status), uint256(STATUS_SUSPENDED));
    }

    function test_settlesUsdcFromTheSafe() public {
        uint256 beforeSafe = usdc.balanceOf(safe);
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 25e18);
        uint256[] memory outs = _settle(a);
        assertEq(outs[0], 25e18);
        assertEq(usdc.balanceOf(safe), beforeSafe - 25e18);
        assertEq(usdc.balanceOf(alice), 25e18);
        assertEq(usdc.balanceOf(address(adapter)), 0);
        assertEq(gate.consumed(MANDATE, 1, address(usdc)), 25e18);
    }

    function test_demoSettledVetoedSuspended() public {
        _settle(_payInput(L_PAY_ALICE, alice, 4e18));
        assertEq(usdc.balanceOf(alice), 4e18);

        AdmitInput memory vetoed = _payInput(L_PAY_BOB, bob, 3e18);
        (, TicketPreimage memory vt) = gate.admit(vetoed);
        _asPrincipal(abi.encodeCall(GateSettlement.veto, (vt, vetoed.commit, new bytes32[](0))));
        assertFalse(gate.ticketLive(keccak256(abi.encode(vt))));
        assertEq(usdc.balanceOf(bob), 0);

        _asPrincipal(abi.encodeCall(AgentGate.suspend, (MANDATE, vetoed.commit, new bytes32[](0))));
        AdmitInput memory blocked = _payInput(L_PAY_ALICE, alice, 1e18);
        vm.expectRevert(A1_MandateNotLive.selector);
        gate.admit(blocked);
    }

    function test_onlyGateMayCallTheAdapter() public {
        vm.expectRevert(SafeAgentGateAdapter.NotGate.selector);
        adapter.executeFromGate(address(usdc), 0, abi.encodeCall(IERC20.transfer, (alice, 1)));
    }

    function test_executeIsCallAndDelegateCallIsRefused() public {
        CallSpy spy = new CallSpy();
        vm.prank(address(gate));
        adapter.executeFromGate(address(spy), 0, abi.encodeCall(CallSpy.poke, ()));
        assertEq(spy.lastCaller(), safe);
        assertEq(spy.lastSelf(), address(spy));
        vm.expectRevert(SafeAgentGateAdapter.DelegateCallRefused.selector);
        adapter.executeDelegateFromGate(address(spy), 0, "");
    }

    function test_enableModuleBlocksExecutionAndTrips() public {
        _blocksAndTrips(abi.encodeWithSignature("enableModule(address)", address(new CallSpy())));
    }

    function test_addOwnerBlocksExecutionAndTrips() public {
        _blocksAndTrips(abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", makeAddr("extra"), 1));
    }

    function test_setGuardBlocksExecutionAndTrips() public {
        _blocksAndTrips(abi.encodeWithSignature("setGuard(address)", address(new PermissiveGuard())));
    }

    function test_setFallbackHandlerBlocksExecutionAndTrips() public {
        _blocksAndTrips(abi.encodeWithSignature("setFallbackHandler(address)", address(new PermissiveGuard())));
    }

    function test_tripDoesNotFireWhileConfigMatches() public {
        MandateCommit memory committed = _commit();
        ActionLeaf memory unused;
        bytes32[] memory none;
        vm.expectRevert(ConditionNotMet.selector);
        gate.trip(TRIP_ACCOUNT_CONFIG, committed, unused, none);
    }

    function test_agentAsOwnerIsAnotherPath() public {
        assertFalse(adapter.agentAuthority(agent));
        _safeExec(safe, 0, abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", agent, 1));
        assertTrue(adapter.agentAuthority(agent));
    }

    function test_agentAsModuleIsAnotherPath() public {
        assertFalse(adapter.agentAuthority(agent));
        _safeExec(safe, 0, abi.encodeWithSignature("enableModule(address)", agent));
        assertTrue(adapter.agentAuthority(agent));
    }

    function test_coSignGoesThroughSafeERC1271() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 100e18);
        a.coSig = _safeCoSig(gate.coSignHash(gate.proposalHash(a.proposal)));
        (, TicketPreimage memory t) = gate.admit(a);
        assertEq(t.windowLen, 5 minutes);
        vm.warp(vm.getBlockTimestamp() + 5 minutes);
        settle.execute(_exec(a, t));
        assertEq(usdc.balanceOf(alice), 100e18);
    }

    function test_rawOwnerSignatureIsNotASafeCoSign() public {
        AdmitInput memory a = _payInput(L_PAY_ALICE, alice, 100e18);
        a.coSig = _sig(ownerPk, gate.coSignHash(gate.proposalHash(a.proposal)));
        vm.expectRevert(CoSigInvalid.selector);
        gate.admit(a);
    }

    function test_adapterBoundToAnotherSafeIsRejected() public {
        (address singleton, address factory, address handler) = _deploySafeStack();
        address[] memory owners = new address[](1);
        owners[0] = owner;
        bytes memory init = abi.encodeCall(
            ISafeSetup.setup, (owners, 1, address(0), "", handler, address(0), 0, payable(address(0)))
        );
        address other = ISafeFactory(factory).createProxyWithNonce(singleton, init, 99);
        SafeAgentGateAdapter foreign = new SafeAgentGateAdapter(address(gate), other);
        assertTrue(other != safe, "second safe collided");
        assertEq(foreign.account(), other);
        MandateCommit memory c = _commit();
        c.adapter = address(foreign);
        c.accountConfigDigest = foreign.configDigest();
        c.activateAfter = uint64(vm.getBlockTimestamp() + 2 days);
        assertEq(c.adapter, address(foreign), "commit adapter did not stick");
        assertTrue(c.principalAccount != foreign.account(), "principal matches foreign safe");
        (Attestation[] memory ready, bytes32[][] memory proofs) = _ready(c);
        // Prank the Safe rather than execTransaction: expectRevert would bind to the
        // preceding getTransactionHash, and Safe v1.4.1 reports an inner failure as GS013.
        vm.prank(safe);
        vm.expectRevert(A15_AccountConfig.selector);
        gate.proposeCommit(c, _params(), ready, proofs);
    }

    function test_digestIncludesTheModulePastTheFirstPage() public {
        for (uint256 i; i < 10; ++i) {
            _safeExec(safe, 0, abi.encodeWithSignature("enableModule(address)", address(uint160(0xA000 + i))));
        }
        address[] memory mods = adapter.moduleList();
        assertEq(mods.length, 11);
        assertEq(mods[mods.length - 1], address(adapter));
        bytes32 before = adapter.configDigest();
        _safeExec(
            safe, 0, abi.encodeWithSignature("disableModule(address,address)", mods[mods.length - 2], address(adapter))
        );
        assertTrue(adapter.configDigest() != before);
        assertEq(adapter.moduleList().length, 10);
        _assertSnapshot(address(uint160(0xA000)), true);
        _assertModuleListMatchesSafe();
    }

    function test_accountSnapshotMatchesTheThreeReads() public {
        _assertSnapshot(agent, false);
        _assertSnapshot(owner, true);
        _assertSnapshot(address(adapter), true);
        _assertSnapshot(address(0), false);
        _assertSnapshot(address(0x1), false);
        _assertModuleListMatchesSafe();
        _safeExec(safe, 0, abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", agent, 1));
        _assertSnapshot(agent, true);
    }

    function _assertSnapshot(address who, bool other) internal view {
        (address bound, bytes32 digest, bool got) = adapter.accountSnapshot(who);
        assertEq(bound, safe);
        assertEq(bound, adapter.account());
        assertEq(digest, adapter.configDigest());
        assertEq(got, other);
        assertEq(got, adapter.agentAuthority(who));
    }

    function _assertModuleListMatchesSafe() internal view {
        address[] memory got = adapter.moduleList();
        address start = address(0x1);
        uint256 n;
        for (uint256 page; page < 40; ++page) {
            (address[] memory batch, address next) = ISafePages(safe).getModulesPaginated(start, 8);
            for (uint256 i; i < batch.length; ++i) {
                assertLt(n, got.length);
                assertEq(got[n], batch[i]);
                ++n;
            }
            if (next == address(0x1) || next == address(0)) break;
            start = next;
        }
        assertEq(n, got.length);
    }

    function test_thresholdChangeChangesDigest() public {
        _safeExec(safe, 0, abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", makeAddr("extra-owner"), 1));
        bytes32 before = adapter.configDigest();
        _safeExec(safe, 0, abi.encodeWithSignature("changeThreshold(uint256)", 2));
        assertTrue(adapter.configDigest() != before);
    }
}

interface ISafePages {
    function getModulesPaginated(address start, uint256 pageSize)
        external
        view
        returns (address[] memory array, address next);
}
