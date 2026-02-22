// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Tests for gasleft() taint propagation to storage.
contract GasleftTaint {
    uint256 public storedGas;          // TAINTED: direct gasleft
    uint256 public gasBasedCalc;       // TAINTED: arithmetic on gasleft
    uint256 public cleanVar;           // CLEAN: no taint
    uint256 public hashedGas;          // TAINTED: keccak of gasleft
    uint256 public conditionalStore;   // TAINTED: control-flow taint
    mapping(uint256 => uint256) public gasMap; // TAINTED: mapping with gas key

    function directGasleft() external {
        storedGas = gasleft();
    }

    function arithmeticGasleft() external {
        uint256 g = gasleft();
        uint256 calc = g * 2 + 1;
        gasBasedCalc = calc;
    }

    function cleanFunction() external {
        cleanVar = 42;
    }

    function hashedGasleft() external {
        uint256 g = gasleft();
        bytes32 h = keccak256(abi.encodePacked(g));
        hashedGas = uint256(h);
    }

    function controlFlowGasleft() external {
        uint256 g = gasleft();
        if (g > 1000) {
            conditionalStore = 1;
        }
    }

    function mappingKeyGasleft() external {
        uint256 g = gasleft();
        gasMap[g] = 100;
    }
}
