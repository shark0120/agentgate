// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AgentGate} from "../../src/AgentGate.sol";
import {GateSettlement} from "../../src/GateSettlement.sol";
import "../../src/GateTypes.sol";
import {F1Base} from "./F1Base.sol";

/// @dev Drives one mandate (no epoch changes) through random interleavings. Complex inputs are
///      kept abi-encoded in storage.
contract F1Handler is F1Base {
    uint256[] internal childSet;

    bytes[] internal nodePaths; // abi.encode(CapabilityNode[] path, uint256[][] sets); [0] = root
    bytes[] internal tickets; // abi.encode(ExecuteInput)
    bytes32[] public ticketHashes;
    mapping(uint256 => bool) internal done;

    uint256 public nAdmitted;
    uint256 public nExecuted;
    uint256 public nDelegated;
    uint256 public nDropped;
    uint256 public nRevoked;
    uint256 public nReclaimed;
    bool public daveAdmitted;

    constructor() {
        setUp();
        childSet.push(L_PAY_ALICE);
        childSet.push(L_PAY_DAVE);
        (CapabilityNode[] memory rp, uint256[][] memory rs) = _pathRoot();
        nodePaths.push(abi.encode(rp, rs));
    }

    // ───────────── getters for the invariant contract ─────────────

    function gateAddr() external view returns (address) {
        return address(gate);
    }

    function token() external view returns (address) {
        return address(usdc);
    }

    function accountAddr() external view returns (address) {
        return address(account);
    }

    function recipients() external view returns (address, address, address) {
        return (alice, bob, dave);
    }

    function nodeCount() external view returns (uint256) {
        return nodePaths.length;
    }

    function nodeId(uint256 i) external view returns (bytes32) {
        (CapabilityNode[] memory path,) = abi.decode(nodePaths[i], (CapabilityNode[], uint256[][]));
        return path[path.length - 1].capId;
    }

    function ticketCount() external view returns (uint256) {
        return tickets.length;
    }

    function ticketReserved(uint256 i) external view returns (uint256) {
        ExecuteInput memory x = abi.decode(tickets[i], (ExecuteInput));
        return x.ticket.reserved[0].amount;
    }

    // ───────────── actions ─────────────

    function pay(uint256 nodeSeed, uint256 who, uint256 amt) external {
        uint256 n = nodeSeed % nodePaths.length;
        (CapabilityNode[] memory path, uint256[][] memory sets) = abi.decode(nodePaths[n], (CapabilityNode[], uint256[][]));
        amt = bound(amt, 1, 100e18);
        uint256 leafIdx;
        address to;
        if (n == 0) (leafIdx, to) = who % 2 == 0 ? (L_PAY_ALICE, alice) : (L_PAY_BOB, bob);
        else (leafIdx, to) = who % 4 == 0 ? (L_PAY_DAVE, dave) : (L_PAY_ALICE, alice);
        uint256 pk = n == 0 ? agentPk : subAgentPk;
        AdmitInput memory a = _input(leafIdx, abi.encodeCall(IERC20.transfer, (to, amt)), _u1(amt), path, sets, pk);
        _admit(a);
    }

    function delegate(uint256 amt, uint256 ttl) external {
        (CapabilityNode[] memory rp, uint256[][] memory rs) = abi.decode(nodePaths[0], (CapabilityNode[], uint256[][]));
        amt = bound(amt, 1, 200e18);
        CapabilityNode memory c;
        c.capId = gate.childCapId(MANDATE, nonceCounter + 1);
        c.mandateId = MANDATE;
        c.mandateEpoch = _epoch();
        c.parentCapId = rp[0].capId;
        c.delegatee = subAgent;
        c.scopeRoot = _scopeRootOf(childSet);
        c.depth = 1;
        c.expiry = uint64(bound(ttl, vm.getBlockTimestamp() + 1 hours, rp[0].expiry));
        c.allotment = new AssetAmount[](1);
        c.allotment[0] = AssetAmount(address(usdc), amt);
        AdmitInput memory a = _input(L_DELEGATE, abi.encodeWithSelector(DELEGATE_SEL, c), _u1(amt), rp, rs, agentPk);
        _admit(a);
    }

    function execute(uint256 seed, bool waitWindow) external {
        if (tickets.length == 0) return;
        uint256 i = seed % tickets.length;
        if (done[i]) return;
        ExecuteInput memory x = abi.decode(tickets[i], (ExecuteInput));
        if (waitWindow && vm.getBlockTimestamp() < x.ticket.windowEnd) vm.warp(x.ticket.windowEnd);
        try settle.execute(x) {
            done[i] = true;
            ++nExecuted;
            if (x.ticket.leafType == LEAF_DELEGATE) {
                CapabilityNode memory child = abi.decode(_tail(x.data), (CapabilityNode));
                (CapabilityNode[] memory rp, uint256[][] memory rs) =
                    abi.decode(nodePaths[0], (CapabilityNode[], uint256[][]));
                CapabilityNode[] memory path = new CapabilityNode[](2);
                (path[0], path[1]) = (rp[0], child);
                uint256[][] memory sets = new uint256[][](2);
                (sets[0], sets[1]) = (rs[0], childSet);
                nodePaths.push(abi.encode(path, sets));
                ++nDelegated;
            }
        } catch {}
    }

    function drop(uint256 seed, uint8 kind) external {
        if (tickets.length == 0) return;
        uint256 i = seed % tickets.length;
        if (done[i]) return;
        ExecuteInput memory x = abi.decode(tickets[i], (ExecuteInput));
        bool ok;
        if (kind % 3 == 0) {
            vm.prank(owner);
            try account.execute(address(gate), 0, abi.encodeCall(GateSettlement.veto, (x.ticket, x.commit, new bytes32[](0)))) {
                ok = true;
            } catch {}
        } else if (kind % 3 == 1) {
            vm.prank(x.ticket.agent);
            try settle.cancel(x.ticket) {
                ok = true;
            } catch {}
        } else {
            try settle.release(x.ticket, x.proposal.capPath) {
                ok = true;
            } catch {}
        }
        if (ok) {
            done[i] = true;
            ++nDropped;
        }
    }

    function revokeChild(uint256 seed) external {
        if (nodePaths.length < 2) return;
        uint256 n = 1 + seed % (nodePaths.length - 1);
        (CapabilityNode[] memory path,) = abi.decode(nodePaths[n], (CapabilityNode[], uint256[][]));
        vm.prank(agent);
        try settle.revokeCap(path, 1) {
            ++nRevoked;
        } catch {}
    }

    function reclaim(uint256 seed) external {
        if (nodePaths.length < 2) return;
        uint256 n = 1 + seed % (nodePaths.length - 1);
        (CapabilityNode[] memory path,) = abi.decode(nodePaths[n], (CapabilityNode[], uint256[][]));
        try settle.reclaim(path) {
            ++nReclaimed;
        } catch {}
    }

    function warp(uint256 dt) external {
        vm.warp(vm.getBlockTimestamp() + bound(dt, 1 minutes, 6 hours));
        vm.roll(vm.getBlockNumber() + 1);
    }

    function _admit(AdmitInput memory a) internal {
        try gate.admit(a) returns (bytes32 th, TicketPreimage memory t) {
            tickets.push(abi.encode(_exec(a, t)));
            ticketHashes.push(th);
            ++nAdmitted;
            if (a.leaf.argRules.length > 0 && a.leaf.argRules[0].operand == bytes32(uint256(uint160(dave)))) {
                daveAdmitted = true;
            }
        } catch {}
    }

    function _tail(bytes memory data) internal pure returns (bytes memory out) {
        out = new bytes(data.length - 4);
        for (uint256 i; i < out.length; ++i) {
            out[i] = data[i + 4];
        }
    }
}

/// @notice Conservation of the capability tree and use-time scope intersection (D2).
contract F1InvariantTest is Test {
    F1Handler internal h;
    AgentGate internal gate;
    IERC20 internal usdc;
    uint256 internal startBalance;
    bytes32 internal constant MANDATE = keccak256("mandate-1");

    function setUp() public {
        h = new F1Handler();
        gate = AgentGate(h.gateAddr());
        usdc = IERC20(h.token());
        startBalance = usdc.balanceOf(h.accountAddr());
        targetContract(address(h));
        bytes4[] memory sel = new bytes4[](9);
        sel[0] = F1Handler.pay.selector;
        sel[1] = F1Handler.pay.selector;
        sel[2] = F1Handler.delegate.selector;
        sel[3] = F1Handler.execute.selector;
        sel[4] = F1Handler.execute.selector;
        sel[5] = F1Handler.drop.selector;
        sel[6] = F1Handler.revokeChild.selector;
        sel[7] = F1Handler.reclaim.selector;
        sel[8] = F1Handler.warp.selector;
        targetSelector(FuzzSelector({addr: address(h), selectors: sel}));
    }

    /// epochCap = Σ node remaining + Σ live reservations + consumed.
    function invariant_budgetConserved() public view {
        uint256 sum = gate.consumed(MANDATE, 1, address(usdc));
        for (uint256 i; i < h.nodeCount(); ++i) {
            sum += gate.capRemaining(h.nodeId(i), address(usdc));
        }
        for (uint256 i; i < h.ticketCount(); ++i) {
            if (gate.ticketLive(h.ticketHashes(i))) sum += h.ticketReserved(i);
        }
        assertEq(sum, 500e18);
    }

    /// Only the gate moves the account's USDC, and every unit it moved is recorded as consumed.
    function invariant_outflowEqualsConsumed() public view {
        uint256 outflow = startBalance - usdc.balanceOf(h.accountAddr());
        assertEq(outflow, gate.consumed(MANDATE, 1, address(usdc)));
        (address alice, address bob,) = h.recipients();
        assertEq(usdc.balanceOf(alice) + usdc.balanceOf(bob), outflow);
    }

    /// D2: dave sits in the child's scope but never in the root's, so no act paying dave admits.
    function invariant_scopeIntersection() public view {
        (,, address dave) = h.recipients();
        assertFalse(h.daveAdmitted());
        assertEq(usdc.balanceOf(dave), 0);
    }

    function afterInvariant() public view {
        console.log(
            string.concat(
                "admitted=", vm.toString(h.nAdmitted()),
                " executed=", vm.toString(h.nExecuted()),
                " delegated=", vm.toString(h.nDelegated()),
                " dropped=", vm.toString(h.nDropped()),
                " revoked=", vm.toString(h.nRevoked()),
                " reclaimed=", vm.toString(h.nReclaimed())
            )
        );
    }
}
