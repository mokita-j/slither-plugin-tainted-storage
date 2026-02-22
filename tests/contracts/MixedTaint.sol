// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Deployer {
    uint256 public val;
    constructor(uint256 _v) {
        val = _v;
    }
}

/// Complex scenarios mixing multiple taint sources.
contract MixedTaint {
    uint256 public combined;        // TAINTED: gasleft + balance
    address public cleanAddr;       // CLEAN: constant address
    uint256 public bitwiseTaint;    // TAINTED: bitwise on gasleft
    uint256 public abiEncodeTaint;  // TAINTED: abi.encode of balance
    uint256 public nestedBranch;    // TAINTED: nested control flow

    function combineSources() external {
        uint256 g = gasleft();
        uint256 b = msg.sender.balance;
        combined = g ^ b;
    }

    function storeConstant() external {
        cleanAddr = address(0xdead);
    }

    function bitwiseOps() external {
        uint256 g = gasleft();
        uint256 shifted = g << 3;
        uint256 masked = shifted & 0xFF;
        bitwiseTaint = masked;
    }

    function abiEncodeFlow() external {
        uint256 b = msg.sender.balance;
        bytes memory encoded = abi.encode(b, uint256(1));
        bytes32 h = keccak256(encoded);
        abiEncodeTaint = uint256(h);
    }

    function nestedControlFlow() external {
        uint256 g = gasleft();
        if (g > 5000) {
            if (g > 10000) {
                nestedBranch = 1;
            }
        }
    }
}
