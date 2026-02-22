// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Edge cases: false positive / false negative tests.
contract EdgeCases {
    uint256 public blockNum;        // CLEAN: block.number is not a source
    uint256 public timestamp;       // CLEAN: block.timestamp is not a source
    uint256 public txGasPrice;      // CLEAN: tx.gasprice is not a source
    uint256 public msgValue;        // CLEAN: msg.value is not a source
    uint256 public otherBalance;    // CLEAN: non-sender balance (literal addr)
    uint256 public gasInLoop;       // TAINTED: gasleft in loop body
    uint256 public ternaryGas;      // TAINTED: ternary with gasleft
    uint256 public multiAssign;     // TAINTED: reassigned from tainted

    function storeBlockNum() external {
        blockNum = block.number;
    }

    function storeTimestamp() external {
        timestamp = block.timestamp;
    }

    function storeTxGasPrice() external {
        txGasPrice = tx.gasprice;
    }

    function storeMsgValue() external payable {
        msgValue = msg.value;
    }

    function storeLiteralBalance() external {
        otherBalance = address(0xdead).balance;
    }

    function gasInLoopBody() external {
        for (uint256 i = 0; i < 10; i++) {
            gasInLoop = gasleft();
        }
    }

    function ternaryWithGas() external {
        uint256 g = gasleft();
        ternaryGas = g > 1000 ? g : 0;
    }

    function reassignedTaint() external {
        uint256 a = gasleft();
        uint256 b = a;
        uint256 c = b;
        multiAssign = c;
    }
}
