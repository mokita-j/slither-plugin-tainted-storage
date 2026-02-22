// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Tests for intra-transaction taint through internal calls.
/// When f() calls g() and g() taints a state variable,
/// f() should see that state variable as tainted.
contract IntraCallTaint {
    uint256 public taintedVar;        // TAINTED: gasleft in _taint()
    uint256 public copiedVar;         // TAINTED: reads taintedVar after _taint()
    uint256 public derivedVar;        // TAINTED: arithmetic on taintedVar after _taint()
    uint256 public cleanVar;          // CLEAN: no taint source
    uint256 public multiHopCopy;      // TAINTED: chain _taint() -> _copy() -> read
    uint256 public conditionalCopy;   // TAINTED: reads taintedVar in branch after _taint()

    function _taint() internal {
        taintedVar = gasleft();
    }

    function _copy() internal {
        copiedVar = taintedVar;
    }

    /// Direct: call _taint(), then read taintedVar
    function directCopy() external {
        _taint();
        copiedVar = taintedVar;
    }

    /// Derived: call _taint(), then compute from taintedVar
    function derivedCopy() external {
        _taint();
        derivedVar = taintedVar * 2 + 1;
    }

    /// Clean: no taint involved
    function cleanWrite() external {
        cleanVar = 42;
    }

    /// Multi-hop: _taint() writes taintedVar, _copy() reads it
    function multiHop() external {
        _taint();
        _copy();
        multiHopCopy = copiedVar;
    }

    /// Conditional: taint then branch on tainted value
    function conditionalAfterTaint() external {
        _taint();
        if (taintedVar > 1000) {
            conditionalCopy = 1;
        }
    }
}
