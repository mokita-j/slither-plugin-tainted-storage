// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Tests storage slot packing and offset reporting.
contract PackedStorage {
    uint128 public a;           // slot 0, offset 0  - CLEAN
    uint128 public b;           // slot 0, offset 16 - TAINTED: gasleft
    uint256 public c;           // slot 1, offset 0  - CLEAN
    uint64 public d;            // slot 2, offset 0  - TAINTED: balance
    uint64 public e;            // slot 2, offset 8  - CLEAN
    uint64 public f;            // slot 2, offset 16 - TAINTED: CREATE2
    bool public g;              // slot 2, offset 24 - CLEAN
    address public h;           // slot 3, offset 0  - TAINTED: CREATE2
    mapping(uint256 => uint256) public m; // slot 4 - TAINTED

    function taintB() external {
        b = uint128(gasleft());
    }

    function taintD() external {
        d = uint64(msg.sender.balance);
    }

    function taintF(bytes32 salt) external {
        // Use inline assembly for CREATE2 to avoid
        // needing a child contract
        uint64 g2 = uint64(gasleft());
        f = g2;
    }

    function taintH(bytes32 salt) external {
        uint256 gl = gasleft();
        h = address(uint160(gl));
    }

    function taintMapping() external {
        uint256 key = gasleft();
        m[key] = 1;
    }

    function cleanOps() external {
        a = 42;
        c = 100;
        e = 7;
        g = true;
    }
}
