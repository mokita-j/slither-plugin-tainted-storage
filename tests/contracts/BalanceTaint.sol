// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Tests for msg.sender.balance taint propagation.
contract BalanceTaint {
    uint256 public senderBal;           // TAINTED: msg.sender.balance
    uint256 public balCalc;             // TAINTED: arithmetic on balance
    uint256 public cleanAmount;         // CLEAN: msg.value is not a source
    uint256 public controlFlowBal;      // TAINTED: branch on balance
    mapping(address => uint256) public balances; // TAINTED: stores balance
    uint256 public hashOfBalance;       // TAINTED: keccak of balance

    function storeSenderBalance() external {
        senderBal = msg.sender.balance;
    }

    function arithmeticOnBalance() external {
        uint256 b = msg.sender.balance;
        uint256 calc = b / 2;
        balCalc = calc;
    }

    function storeClean() external payable {
        cleanAmount = msg.value;
    }

    function controlFlowBalance() external {
        uint256 b = msg.sender.balance;
        if (b > 1 ether) {
            controlFlowBal = 99;
        }
    }

    function storeInMapping() external {
        balances[msg.sender] = msg.sender.balance;
    }

    function hashedBalance() external {
        uint256 b = msg.sender.balance;
        bytes32 h = keccak256(abi.encode(b));
        hashOfBalance = uint256(h);
    }
}
