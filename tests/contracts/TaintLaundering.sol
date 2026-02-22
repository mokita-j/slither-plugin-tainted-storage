// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Patterns where taint may be "laundered" or propagation is subtle.
contract TaintLaundering {
    uint256 public storedGas;            // TAINTED: gasleft
    uint256 public copiedFromState;      // FN-candidate: reads storedGas (tainted in another function)
    uint256 public viaExternalReturn;    // CLEAN: external call return value not tracked as taint source
    uint256 public balanceViaAlias;      // TAINTED: msg.sender.balance through alias
    bool public flagFromGas;             // TAINTED: bool derived from gasleft comparison
    uint256 public fromTernary;          // TAINTED: ternary branches both use gas
    uint256 public cleanAfterBranch;     // CLEAN: written outside tainted branch
    uint256 public mappingValueRead;     // CLEAN: reading a mapping value is clean

    mapping(uint256 => uint256) public data;

    function storeGas() external {
        storedGas = gasleft();
    }

    /// Cross-function state read: taint should flow
    /// storedGas -> copiedFromState
    function copyFromState() external {
        copiedFromState = storedGas;
    }

    /// Balance through an alias for msg.sender
    function balanceThroughAlias() external {
        address sender = msg.sender;
        uint256 b = sender.balance;
        balanceViaAlias = b;
    }

    /// Bool from tainted comparison
    function boolFromGas() external {
        uint256 g = gasleft();
        flagFromGas = g > 50000;
    }

    /// Ternary where both branches depend on gas
    function ternaryBothTainted() external {
        uint256 g = gasleft();
        fromTernary = g > 1000 ? g * 2 : g / 2;
    }

    /// Write AFTER a tainted branch -- should NOT be tainted
    function writeAfterBranch() external {
        uint256 g = gasleft();
        if (g > 5000) {
            // state write inside branch is tainted
            storedGas = g;
        }
        // This write is AFTER the branch, not inside it
        cleanAfterBranch = 100;
    }

    /// Reading a mapping value that was written cleanly
    function readCleanMapping() external {
        data[1] = 42;
        mappingValueRead = data[1];
    }
}
