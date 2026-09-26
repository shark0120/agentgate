// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IAccountAdapter, ILivenessSource} from "../../src/interfaces/IGateExternal.sol";

contract MockToken is ERC20 {
    constructor(string memory name) ERC20(name, name) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev Minimal smart account with the gate installed as an executor module.
///      configDigest covers the gate, the owner and any extra module; ERC-1271 by the owner.
contract MockAccount is IAccountAdapter {
    address public owner;
    address public gate;
    bytes32 public extraModule;
    mapping(address => bool) public otherAuthority;

    constructor(address owner_) {
        owner = owner_;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function installGate(address g) external onlyOwner {
        gate = g;
    }

    function installModule(bytes32 m) external onlyOwner {
        extraModule = m;
    }

    function setOtherAuthority(address a, bool v) external onlyOwner {
        otherAuthority[a] = v;
    }

    /// @dev The principal acting directly, outside the gate.
    function execute(address target, uint256 value, bytes calldata data) external onlyOwner returns (bytes memory) {
        return _call(target, value, data);
    }

    function executeFromGate(address target, uint256 value, bytes calldata data) external returns (bytes memory) {
        require(msg.sender == gate, "not gate");
        return _call(target, value, data);
    }

    function configDigest() public view returns (bytes32) {
        return keccak256(abi.encode(gate, owner, extraModule));
    }

    function agentAuthority(address agent) public view returns (bool) {
        return otherAuthority[agent];
    }

    function account() public view returns (address) {
        return address(this);
    }

    /// @dev Same three facts, one call. Composes the functions above so they cannot drift.
    function accountSnapshot(address agent) external view returns (address, bytes32, bool) {
        return (account(), configDigest(), agentAuthority(agent));
    }

    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, sig);
        return err == ECDSA.RecoverError.NoError && signer == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    receive() external payable {}

    function _call(address target, uint256 value, bytes calldata data) internal returns (bytes memory ret) {
        bool ok;
        (ok, ret) = target.call{value: value}(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }
}

contract MockLiveness is ILivenessSource {
    bool public up = true;
    uint64 public changedAt;

    function set(bool up_, uint64 at) external {
        up = up_;
        changedAt = at;
    }

    function isUp() external view returns (bool) {
        return up;
    }

    function lastChangeAt() external view returns (uint64) {
        return changedAt;
    }
}

/// @dev Pulls tokenIn from the caller and pays tokenOut at a fixed rate. `overcharge` and
///      `shortfall` let tests model a malicious or degraded counterparty.
contract MockRouter {
    uint256 public rate = 1e15; // tokenOut per 1e18 tokenIn
    uint256 public overcharge;
    uint256 public shortfall;

    function configure(uint256 overcharge_, uint256 shortfall_) external {
        overcharge = overcharge_;
        shortfall = shortfall_;
    }

    function swap(address tokenIn, uint256 amountIn, address tokenOut, uint256 minOut, address to)
        external
        returns (uint256 out)
    {
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn + overcharge);
        out = amountIn * rate / 1e18 - shortfall;
        minOut; // the gate enforces declaredMinIn by measurement, not the router
        IERC20(tokenOut).transfer(to, out);
    }
}

/// @dev Calls back into the gate during settlement (X9).
contract ReentrantTarget {
    address public gate;

    constructor(address gate_) {
        gate = gate_;
    }

    function poke() external {
        (bool ok, bytes memory ret) = gate.call(abi.encodeWithSignature("cancelCommit(bytes32)", bytes32(0)));
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }
}

contract Sink {
    function ping() external payable {}
}
