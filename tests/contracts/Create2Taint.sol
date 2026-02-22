// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Child {
    uint256 public value;
    constructor(uint256 _v) {
        value = _v;
    }
}

/// Tests for CREATE2 result taint propagation to storage.
contract Create2Taint {
    address public deployedAddr;        // TAINTED: CREATE2 result
    uint256 public derivedFromAddr;     // TAINTED: cast of CREATE2 addr
    address public cleanDeployed;       // CLEAN: regular CREATE (no salt)
    uint256 public addrBalance;         // TAINTED: balance of CREATE2 addr

    function deployWithSalt(
        bytes32 salt
    ) external {
        Child c = new Child{salt: salt}(42);
        deployedAddr = address(c);
    }

    function deployAndCast(bytes32 salt) external {
        Child c = new Child{salt: salt}(10);
        derivedFromAddr = uint256(uint160(address(c)));
    }

    function deployNoSalt() external {
        Child c = new Child(10);
        cleanDeployed = address(c);
    }

    function deployAndCheckBalance(
        bytes32 salt
    ) external {
        Child c = new Child{salt: salt}(0);
        addrBalance = address(c).balance;
    }
}
