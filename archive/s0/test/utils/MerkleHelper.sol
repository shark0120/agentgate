// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Sorted-pair Merkle tree matching OpenZeppelin MerkleProof. Odd nodes carry up.
library MerkleHelper {
    function leaf(address a) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(a))));
    }

    function leaves(address[] memory set) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](set.length);
        for (uint256 i; i < set.length; ++i) {
            out[i] = leaf(set[i]);
        }
    }

    function root(address[] memory set) internal pure returns (bytes32) {
        bytes32[] memory layer = leaves(set);
        uint256 n = layer.length;
        while (n > 1) {
            layer = _next(layer, n);
            n = (n + 1) / 2;
        }
        return layer[0];
    }

    function proof(address[] memory set, address member) internal pure returns (bytes32[] memory out) {
        bytes32[] memory layer = leaves(set);
        uint256 idx = type(uint256).max;
        for (uint256 i; i < set.length; ++i) {
            if (set[i] == member) idx = i;
        }
        require(idx != type(uint256).max, "not a member");
        out = new bytes32[](256);
        uint256 len;
        uint256 n = layer.length;
        while (n > 1) {
            uint256 sib = idx ^ 1;
            if (sib < n) out[len++] = layer[sib];
            layer = _next(layer, n);
            n = (n + 1) / 2;
            idx /= 2;
        }
        assembly ("memory-safe") {
            mstore(out, len)
        }
    }

    function _next(bytes32[] memory layer, uint256 n) private pure returns (bytes32[] memory next) {
        next = new bytes32[]((n + 1) / 2);
        for (uint256 i; i < n; i += 2) {
            next[i / 2] = i + 1 < n ? _hashPair(layer[i], layer[i + 1]) : layer[i];
        }
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }
}
