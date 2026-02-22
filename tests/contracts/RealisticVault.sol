// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Realistic DeFi vault that exercises inheritance, structs,
/// balance-via-variable, and modifier patterns.

abstract contract Ownable {
    address public owner;
    uint256 public lastGasUsed;       // TAINTED: inherited, gasleft

    modifier trackGas() {
        uint256 start = gasleft();
        _;
        lastGasUsed = start - gasleft();
    }

    constructor() {
        owner = msg.sender;
    }
}

contract RealisticVault is Ownable {
    struct DepositInfo {
        uint256 amount;
        uint256 senderBalance;    // stored in struct
        uint256 timestamp;
    }

    mapping(address => DepositInfo) public deposits;
    uint256 public totalDeposits;             // CLEAN
    uint256 public lastSenderBalance;         // TAINTED: msg.sender.balance via alias
    uint256 public gasRefund;                 // TAINTED: gasleft via modifier

    /// balance read through a local variable (not directly msg.sender)
    function depositWithBalanceCheck() external payable {
        address user = msg.sender;
        uint256 bal = user.balance;
        lastSenderBalance = bal;

        deposits[msg.sender] = DepositInfo({
            amount: msg.value,
            senderBalance: bal,
            timestamp: block.timestamp
        });
        totalDeposits += msg.value;
    }

    /// Uses the trackGas modifier from parent -- gasleft in modifier
    function withdrawAll() external trackGas {
        DepositInfo storage info = deposits[msg.sender];
        uint256 amt = info.amount;
        info.amount = 0;
        totalDeposits -= amt;
        payable(msg.sender).transfer(amt);
    }

    /// gasleft difference stored as a refund metric
    function complexGasCalc() external {
        uint256 g1 = gasleft();
        // simulate work
        uint256 dummy = uint256(keccak256(abi.encode(g1)));
        uint256 g2 = gasleft();
        gasRefund = g1 - g2;
    }

    /// Clean: only reads msg.value (not a taint source)
    function simpleDeposit() external payable {
        totalDeposits += msg.value;
    }
}
