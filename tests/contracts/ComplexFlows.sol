// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Complex taint flow patterns: structs, arrays, multi-return,
/// storage-to-storage within same function, and event boundaries.
contract ComplexFlows {
    struct Metrics {
        uint256 gasUsed;
        uint256 blockNum;
    }

    Metrics public metrics;              // metrics.gasUsed TAINTED, metrics.blockNum CLEAN
    uint256[] public gasHistory;         // TAINTED: array push of gasleft
    uint256 public fromMultiReturn;      // TAINTED: via multi-return
    uint256 public cleanFromMultiReturn; // TAINTED (FP): tuple-level taint taints all unpacked values
    uint256 public stateToState;         // TAINTED: reads gasHistory.length (tainted via push with gas key?) Actually: just reads length -- CLEAN
    uint256 public rewrittenClean;       // CLEAN: tainted then overwritten with clean

    /// Write to struct members
    function updateMetrics() external {
        metrics.gasUsed = gasleft();
        metrics.blockNum = block.number;
    }

    /// Push tainted value to array
    function recordGas() external {
        gasHistory.push(gasleft());
    }

    /// Multi-return: only first value tainted
    function _gasAndBlock() internal view returns (uint256, uint256) {
        return (gasleft(), block.number);
    }

    function storeMultiReturn() external {
        (uint256 g, uint256 b) = _gasAndBlock();
        fromMultiReturn = g;
        cleanFromMultiReturn = b;
    }

    /// Overwrite: first tainted, then overwritten with clean value
    function overwriteFlow() external {
        rewrittenClean = gasleft();
        rewrittenClean = 42;
    }

    /// State-to-state within same function:
    /// Read gasHistory length (clean: length is just a count),
    /// store to stateToState.
    function readStateLength() external {
        stateToState = gasHistory.length;
    }
}
