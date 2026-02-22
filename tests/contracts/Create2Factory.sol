// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Widget {
    uint256 public val;
    constructor(uint256 _v) { val = _v; }
}

/// Realistic factory exercising CREATE2 taint through mappings,
/// cross-function state reads, and array storage.
contract Create2Factory {
    address[] public deployedAddrs;           // TAINTED: CREATE2 result stored in array
    mapping(bytes32 => address) public saltToAddr; // TAINTED: CREATE2
    address public lastDeployed;              // TAINTED: CREATE2
    uint256 public lastDeployedAsUint;        // TAINTED: derived from CREATE2 addr
    uint256 public deployCount;               // CLEAN: just a counter
    address public lastCleanDeploy;           // CLEAN: regular CREATE

    /// Deploy via CREATE2 and store results in multiple places
    function deploy(bytes32 salt, uint256 val) external returns (address) {
        Widget w = new Widget{salt: salt}(val);
        address addr = address(w);

        lastDeployed = addr;
        saltToAddr[salt] = addr;
        deployedAddrs.push(addr);
        lastDeployedAsUint = uint256(uint160(addr));
        deployCount += 1;

        return addr;
    }

    /// Cross-function: reads lastDeployed (tainted state) and
    /// stores derived value. Should be tainted but detector
    /// analyzes per-function without tracking state taint.
    function derivedFromState() external {
        // This reads a state variable that was tainted in deploy()
        address addr = lastDeployed;
        // Stores it elsewhere -- cross-function state taint
        saltToAddr[bytes32(uint256(1))] = addr;
    }

    /// Clean: regular CREATE (no salt)
    function deployClean(uint256 val) external {
        Widget w = new Widget(val);
        lastCleanDeploy = address(w);
        deployCount += 1;
    }
}
