// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AgentGate} from "../../src/AgentGate.sol";
import {GateSettlement} from "../../src/GateSettlement.sol";
import {ILivenessSource} from "../../src/interfaces/IGateExternal.sol";
import {MockLiveness} from "../mocks/Mocks.sol";
import "../../src/GateTypes.sol";

/// @notice Writes the encoding vectors the TypeScript SDK must match.
contract SdkVectorsTest is Test {
    function test_exportSdkVectors() public {
        MockLiveness live = new MockLiveness();
        GateSettlement impl = new GateSettlement(ILivenessSource(address(live)));
        bytes32 scheme = keccak256("SMP/scheme/ecdsa");
        bytes32[] memory schemes = new bytes32[](1);
        schemes[0] = scheme;
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(0xBEEF);
        AgentGate gate = new AgentGate(schemes, verifiers, ILivenessSource(address(live)), address(impl));

        ActionLeaf memory leaf;
        leaf.leafType = LEAF_CALL;
        leaf.target = address(0x1111);
        leaf.codeHash = keccak256("code");
        leaf.selector = bytes4(keccak256("transfer(address,uint256)"));
        leaf.argRules = new ArgRule[](1);
        leaf.argRules[0] = ArgRule(0, OP_EQ, bytes32(uint256(uint160(address(0x2222)))));
        leaf.assets = new address[](1);
        leaf.assets[0] = address(0x3333);
        leaf.maxOutPerCall = new uint256[](1);
        leaf.maxOutPerCall[0] = 5 ether;

        Proposal memory p;
        p.mandateId = keccak256("mandate-sdk");
        p.epoch = 1;
        p.capPath = new bytes32[](1);
        p.capPath[0] = keccak256("root");
        p.leafHash = keccak256(abi.encode(leaf));
        p.calldataHash = keccak256(hex"a9059cbb");
        p.value = 0;
        p.declaredOut = new AssetAmount[](1);
        p.declaredOut[0] = AssetAmount(address(0x3333), 1 ether);
        p.declaredMinIn = new AssetAmount[](0);
        p.nonce = 7;
        p.validAfter = 1_800_000_000;
        p.validUntil = 1_800_086_400;
        p.stateRef = StateRef(1000, keccak256("block"));

        Attestation memory a;
        a.proposalHash = gate.proposalHash(p);
        a.policyHash = keccak256("pay listed vendors");
        a.epoch = 1;
        a.stateRef = p.stateRef;
        a.attestor = bytes32(uint256(uint160(address(0x4444))));
        a.scheme = scheme;
        a.verdict = VERDICT_ALLOW;
        a.expiresAt = 1_800_172_800;

        bytes32[] memory scopeLeaves = new bytes32[](3);
        scopeLeaves[0] = keccak256(bytes.concat(keccak256(abi.encode(leaf))));
        scopeLeaves[1] = keccak256("leaf-b");
        scopeLeaves[2] = keccak256("leaf-c");

        string memory head = string.concat(
            '{"chainId":"', vm.toString(block.chainid),
            '","gate":"', vm.toString(address(gate)),
            '","ecdsaScheme":"', vm.toString(scheme),
            '","leafEncoded":"', vm.toString(abi.encode(leaf)),
            '","scopeLeaf":"', vm.toString(scopeLeaves[0]),
            '","proposalHash":"', vm.toString(a.proposalHash),
            '"'
        );
        string memory tail = string.concat(
            ',"proposalEncoded":"', vm.toString(abi.encode(p)),
            '","attestationHash":"', vm.toString(gate.attestationHash(a)),
            '","readyHash":"', vm.toString(gate.readyHash(keccak256("commit"))),
            '","coSignHash":"', vm.toString(gate.coSignHash(a.proposalHash)),
            '","rootCapId":"', vm.toString(gate.rootCapId(p.mandateId, 1)),
            '","childCapId":"', vm.toString(gate.childCapId(p.mandateId, 7)),
            '","leafHash":"', vm.toString(p.leafHash),
            '","policyHash":"', vm.toString(a.policyHash),
            '","attestor":"', vm.toString(a.attestor),
            '"}'
        );
        vm.writeFile("sdk/test/fixtures/vectors.json", string.concat(head, tail));
    }
}