# storage-drift

A [Slither](https://github.com/crytic/slither) plugin that detects storage slots whose values will diverge across execution environments (e.g. Ethereum vs Polkadot/revive). Useful for cross-chain storage comparison tooling where deterministic storage is expected.

## What it detects

State variables written from chain-specific values that differ between execution environments:

| Drift source | Why it diverges |
|---|---|
| `gasleft()` | Gas mechanics differ across chains; remaining gas varies per call |
| `tx.gasprice` | Set by the transaction sender; pricing models differ across chains |
| `block.basefee` | EIP-1559 specific; changes every block, absent on some chains |
| `block.blobbasefee` | EIP-4844 specific; absent on non-Ethereum chains |
| `block.gaslimit` | Differs across chains and changes across blocks |
| CREATE2 result | Deployed address depends on chain-specific deployer mechanics |
| `msg.sender.balance` | Sender balance is externally mutable and differs across chains |

For each finding the detector reports the **storage slot number**, **byte offset** (for packed variables), and the **drift source** that flows into the write.

### Drift propagation

**Data flow** -- drift propagates through:
- Assignments, arithmetic (`+` `-` `*` `/` `%`), bitwise ops (`&` `|` `^` `<<` `>>`)
- Hashing (`keccak256`, `sha256`, `sha3`, `ripemd160`)
- ABI encoding (`abi.encode`, `abi.encodePacked`, `abi.encodeWithSelector`, ...)
- Type conversions, mapping index keys
- Internal function arguments and return values (inter-procedural)
- Intra-transaction internal calls: when `f()` calls `g()` and `g()` drifts a state variable, `f()` sees that variable as drifting (including multi-hop chains like `f()` → `g()` → `h()`)

**Control flow** -- if a drifting value appears in a branch condition (`if`, loop guard), every state variable written inside that branch is considered drifting.

## Installation

Requires Python >= 3.9 and a working Slither installation.

```bash
# From the plugin directory
pip install -e .
```

This registers the `storage-drift` detector with Slither via the `slither_analyzer.plugin` entry point.
No changes to Slither itself are needed.

Verify it loaded:

```bash
slither --list-detectors | grep storage-drift
```

### Solidity compiler

A `solc` binary compatible with your contracts must be on `$PATH`.
For Solidity 0.8.x contracts install it with [solc-select](https://github.com/crytic/solc-select):

```bash
pip install solc-select
solc-select install 0.8.28
solc-select use 0.8.28
```

## Quick start

### Analyze a contract

```bash
slither MyContract.sol --detect storage-drift
```

Human-readable output:

```
MyContract.storedGas (MyContract.sol#5) (slot: 0, offset: 0) is tainted by gasleft() in MyContract.save() (MyContract.sol#8-10)
        storedGas = gasleft()() (MyContract.sol#9)
```

### JSON output

```bash
slither MyContract.sol --detect storage-drift --json output.json
```

Each finding includes an `additional_fields.storage_drift` object:

```json
{
  "variable": "MyContract.storedGas",
  "contract": "MyContract",
  "slot": 0,
  "slot_hex": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "offset": 0,
  "taint_source": "gasleft()",
  "function": "MyContract.save()"
}
```

| Field | Type | Description |
|---|---|---|
| `variable` | string | Canonical name (`Contract.varName`) |
| `contract` | string | Contract that owns the variable |
| `slot` | int | EVM storage slot number |
| `slot_hex` | string | Slot as 32-byte zero-padded hex (`0x...`, 66 chars) |
| `offset` | int | Byte offset within the slot (non-zero for packed variables) |
| `taint_source` | string | Comma-separated list of sources (e.g. `"gasleft(), msg.sender.balance"`) |
| `function` | string | Function where the drifting write occurs |

### JSON to stdout

```bash
slither MyContract.sol --detect storage-drift --json -
```

### Extract just the drifting slots with jq

```bash
slither MyContract.sol --detect storage-drift --json - 2>/dev/null \
  | jq '.results.detectors[].additional_fields.storage_drift'
```

## Run the test suite

The test contracts are in `tests/contracts/`.
Each contract has annotated `// TAINTED` and `// CLEAN` comments showing expected results.

```bash
# Install test dependencies
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v
```

### Test contracts

| Contract | Scenarios |
|---|---|
| `GasleftTaint.sol` | Direct `gasleft()`, arithmetic, keccak256, control-flow branch, mapping key |
| `BalanceTaint.sol` | Direct `msg.sender.balance`, arithmetic, control-flow, mapping value, keccak256 |
| `Create2Taint.sol` | `new Contract{salt: ...}()`, type cast, balance of deployed address, regular CREATE (clean) |
| `CrossFunction.sol` | Drift through internal call, multi-hop call chain, clean internal call |
| `MixedTaint.sol` | Combined sources (`gasleft ^ balance`), bitwise chain, ABI encode flow, nested branches |
| `EdgeCases.sol` | False-positive guards: `block.number`, `block.timestamp`, `msg.value`, literal-address balance. True positives: loop body, ternary, multi-assignment chain, `tx.gasprice` |
| `PackedStorage.sol` | Storage packing: `uint128`+`uint128` in one slot, three `uint64`+`bool` in one slot, verifies correct slot numbers and byte offsets |
| `RealisticVault.sol` | DeFi vault with inheritance, structs, modifiers, balance-via-alias |
| `Create2Factory.sol` | Factory pattern with CREATE2, array push, cross-function state |
| `GasMeter.sol` | Gas metering, require guard (clean), `tx.gasprice` (drifting), `block.basefee`, `block.blobbasefee`, `block.gaslimit` |
| `ComplexFlows.sol` | Struct member drift, array push, multi-return, overwrite elimination, state length |
| `TaintLaundering.sol` | Balance alias, bool from gas, ternary, write after branch (clean), clean mapping read |
| `IntraCallTaint.sol` | Intra-transaction drift: `_taint()` then read, derived values, multi-hop chain, conditional after call |

#### Real-world contracts (false-positive validation)

| Contract | Scenarios |
|---|---|
| `tokens/tether.sol` | Tether (USDT) -- zero findings expected: all writes use explicit parameters, no drift sources |
| `tokens/weth.sol` | Wrapped Ether (WETH9) -- zero findings: `address(this).balance` in view function only, no drifting state writes |
| `uniswap-v3/UniswapV3Factory.sol` | Uniswap V3 factory -- `getPool` drifts via CREATE2 deployment; `owner`, `feeAmountTickSpacing` clean |
| `uniswap-v3/UniswapV3Pool.sol` | Uniswap V3 pool (869 lines, 18 functions) -- zero findings: `block.timestamp` not a tracked drift source |

### Run against the included test contracts directly

```bash
# Analyze a single test contract
slither tests/contracts/GasleftTaint.sol --detect storage-drift

# JSON output for packed storage (see slot offsets)
slither tests/contracts/PackedStorage.sol --detect storage-drift --json - 2>/dev/null \
  | jq '.results.detectors[].additional_fields.storage_drift | {variable, slot, offset, taint_source}'
```

Expected output for PackedStorage:

```json
{ "variable": "PackedStorage.b", "slot": 0, "offset": 16, "taint_source": "gasleft()" }
{ "variable": "PackedStorage.d", "slot": 2, "offset": 0,  "taint_source": "msg.sender.balance" }
{ "variable": "PackedStorage.f", "slot": 2, "offset": 16, "taint_source": "gasleft()" }
{ "variable": "PackedStorage.h", "slot": 3, "offset": 0,  "taint_source": "gasleft()" }
{ "variable": "PackedStorage.m", "slot": 4, "offset": 0,  "taint_source": "gasleft()" }
```

## Project structure

```
storage-drift/
  pyproject.toml                                  # Package config + Slither entry point
  README.md
  storage_drift/
    __init__.py                                   # make_plugin() for Slither registration
    detectors/
      __init__.py
      drift_detector.py                           # Detector implementation
  tests/
    helpers.py                                    # Shared test utilities (caching, helpers)
    test_storage_drift.py                         # 46 core tests
    test_complex_contracts.py                     # 34 complex/realistic tests
    test_real_contracts.py                        # 27 real-world contract tests
    contracts/
      GasleftTaint.sol                            # gasleft() scenarios
      BalanceTaint.sol                            # msg.sender.balance scenarios
      Create2Taint.sol                            # CREATE2 scenarios
      CrossFunction.sol                           # Inter-procedural drift
      MixedTaint.sol                              # Multiple sources, complex flows
      EdgeCases.sol                               # False-positive / edge-case tests
      PackedStorage.sol                           # Storage packing + offset tests
      RealisticVault.sol                          # DeFi vault, inheritance, modifiers
      Create2Factory.sol                          # Factory pattern, array storage
      GasMeter.sol                                # Gas metering, require guard
      ComplexFlows.sol                            # Structs, arrays, multi-return
      TaintLaundering.sol                         # Alias tracking, laundering patterns
      IntraCallTaint.sol                          # Intra-transaction call drift
      tokens/
        tether.sol                                # Tether (USDT) production contract
        weth.sol                                  # WETH9 production contract
      uniswap-v3/                                 # Uniswap V3 core (solc 0.7.6)
        UniswapV3Factory.sol                      # Factory with CREATE2 deployment
        UniswapV3Pool.sol                         # Pool with oracle, swaps, positions
        UniswapV3PoolDeployer.sol                 # CREATE2 deployer base
        NoDelegateCall.sol                        # Delegate call guard
        interfaces/                               # IUniswapV3*.sol interfaces
        libraries/                                # Oracle, Tick, Position, math libs
```

## Limitations

- **Cross-transaction state drift** is not tracked. If `f()` drifts a state variable in transaction 1 and `g()` reads it in transaction 2, `g()` will not see it as drifting. Intra-transaction drift (internal calls within the same function) *is* tracked.
- **External calls** (cross-contract) are not tracked; only internal/private calls are followed.
- `address.balance` where the address is not `msg.sender` is reported as `address.balance`, but only `msg.sender.balance` is treated as a drift source for direct balance reads. An indirect balance read (e.g. reading the balance of a CREATE2-deployed address) is still caught because the address variable itself is drifting.
- **Tuple-level drift**: when a multi-return function has any drifting return value, all unpacked values are marked drifting (known false positive).
- Storage slot numbers are the **base slot** for mappings and dynamic arrays. The actual EVM slot for a specific key requires `keccak256(abi.encode(key, slot))` which depends on runtime values.
- Assembly (`SSTORE`) writes are not tracked.

## License

AGPL-3.0-only (same as Slither).
