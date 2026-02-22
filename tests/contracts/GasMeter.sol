// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Gas metering patterns found in real protocols.
contract GasMeter {
    uint256 public gasPerUnit;           // TAINTED: gasleft diff / count
    uint256 public cachedGasPrice;       // CLEAN: tx.gasprice not a source
    uint256 public executionCount;       // CLEAN: just a counter
    uint256 public lastExecGas;          // TAINTED: gasleft diff

    mapping(address => uint256) public userGasUsed; // TAINTED: gasleft

    /// Gas metering: measure how much gas an operation uses
    function measureExecution(uint256 iterations) external {
        uint256 gasBefore = gasleft();

        uint256 acc = 0;
        for (uint256 i = 0; i < iterations; i++) {
            acc += i;
        }

        uint256 gasUsed = gasBefore - gasleft();
        lastExecGas = gasUsed;
        gasPerUnit = gasUsed / (iterations > 0 ? iterations : 1);
        userGasUsed[msg.sender] = gasUsed;
        executionCount += 1;
    }

    /// Clean: tx.gasprice is NOT one of our taint sources
    function cacheGasPrice() external {
        cachedGasPrice = tx.gasprice;
    }

    /// gasleft used in require -- the require itself doesn't write
    /// state, but state written after the require is NOT tainted
    /// (the require is a guard, not a branch body)
    function guardedWrite(uint256 val) external {
        require(gasleft() > 10000, "not enough gas");
        // This write is AFTER the require, not inside a branch
        // In Slither IR, require is not an IF branch, so this
        // should NOT be tainted by control flow.
        executionCount = val;
    }
}
