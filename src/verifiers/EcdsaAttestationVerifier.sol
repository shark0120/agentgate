// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IAttestationVerifier} from "../interfaces/IGateExternal.sol";

/// @title EcdsaAttestationVerifier — attestor id is the signer address (ECDSA or ERC-1271).
contract EcdsaAttestationVerifier is IAttestationVerifier {
    function verify(bytes32, bytes32 attestationHash, bytes32 attestor, bytes calldata blob)
        external
        view
        returns (bool)
    {
        if (uint256(attestor) >> 160 != 0 || attestor == 0) return false;
        return SignatureChecker.isValidSignatureNow(address(uint160(uint256(attestor))), attestationHash, blob);
    }
}
