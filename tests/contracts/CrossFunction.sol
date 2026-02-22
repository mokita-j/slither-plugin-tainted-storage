// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Tests for taint propagation across function calls.
contract CrossFunction {
    uint256 public storedResult;     // TAINTED: via internal call
    uint256 public indirectResult;   // TAINTED: multi-hop
    uint256 public cleanResult;      // CLEAN: no taint source

    function _getGas() internal view returns (uint256) {
        return gasleft();
    }

    function _double(uint256 x) internal pure returns (uint256) {
        return x * 2;
    }

    function _pureCalc(
        uint256 x
    ) internal pure returns (uint256) {
        return x + 10;
    }

    function storeViaCall() external {
        uint256 g = _getGas();
        storedResult = g;
    }

    function multiHop() external {
        uint256 g = _getGas();
        uint256 d = _double(g);
        indirectResult = d;
    }

    function cleanCall() external {
        uint256 r = _pureCalc(42);
        cleanResult = r;
    }
}
