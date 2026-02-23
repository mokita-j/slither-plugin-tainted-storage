"""Tests for the storage-drift detector plugin."""

from __future__ import annotations

from helpers import (
    drifting_vars as _drifting_vars,
)
from helpers import (
    run_detector as _run_detector,
)
from helpers import (
    storage_drift_fields as _drift_fields,
)

# ── GasleftTaint ────────────────────────────────────────────────


def test_gasleft_direct():
    results = _run_detector("GasleftTaint.sol")
    drifting = _drifting_vars(results)
    assert "storedGas" in drifting


def test_gasleft_arithmetic():
    results = _run_detector("GasleftTaint.sol")
    drifting = _drifting_vars(results)
    assert "gasBasedCalc" in drifting


def test_gasleft_hashed():
    results = _run_detector("GasleftTaint.sol")
    drifting = _drifting_vars(results)
    assert "hashedGas" in drifting


def test_gasleft_control_flow():
    results = _run_detector("GasleftTaint.sol")
    drifting = _drifting_vars(results)
    assert "conditionalStore" in drifting


def test_gasleft_mapping_key():
    results = _run_detector("GasleftTaint.sol")
    drifting = _drifting_vars(results)
    assert "gasMap" in drifting


def test_gasleft_clean():
    results = _run_detector("GasleftTaint.sol")
    drifting = _drifting_vars(results)
    assert "cleanVar" not in drifting


def test_gasleft_slots():
    results = _run_detector("GasleftTaint.sol")
    fields = _drift_fields(results)
    assert fields["GasleftTaint.storedGas"]["slot"] == 0
    assert fields["GasleftTaint.gasBasedCalc"]["slot"] == 1
    # cleanVar at slot 2 is not tainted
    assert fields["GasleftTaint.hashedGas"]["slot"] == 3
    assert fields["GasleftTaint.conditionalStore"]["slot"] == 4
    assert fields["GasleftTaint.gasMap"]["slot"] == 5


def test_gasleft_json_taint_source():
    results = _run_detector("GasleftTaint.sol")
    fields = _drift_fields(results)
    for var_name, ts in fields.items():
        assert ts["taint_source"] == "gasleft()"
        assert ts["slot_hex"].startswith("0x")
        assert len(ts["slot_hex"]) == 66  # 0x + 64 hex chars
        assert ts["contract"] == "GasleftTaint"


# ── BalanceTaint ────────────────────────────────────────────────


def test_balance_direct():
    results = _run_detector("BalanceTaint.sol")
    drifting = _drifting_vars(results)
    assert "senderBal" in drifting


def test_balance_arithmetic():
    results = _run_detector("BalanceTaint.sol")
    drifting = _drifting_vars(results)
    assert "balCalc" in drifting


def test_balance_control_flow():
    results = _run_detector("BalanceTaint.sol")
    drifting = _drifting_vars(results)
    assert "controlFlowBal" in drifting


def test_balance_mapping():
    results = _run_detector("BalanceTaint.sol")
    drifting = _drifting_vars(results)
    assert "balances" in drifting


def test_balance_hashed():
    results = _run_detector("BalanceTaint.sol")
    drifting = _drifting_vars(results)
    assert "hashOfBalance" in drifting


def test_balance_clean():
    results = _run_detector("BalanceTaint.sol")
    drifting = _drifting_vars(results)
    assert "cleanAmount" not in drifting


def test_balance_json_taint_source():
    results = _run_detector("BalanceTaint.sol")
    fields = _drift_fields(results)
    for ts in fields.values():
        assert "msg.sender.balance" in ts["taint_source"]


def test_balance_slots():
    results = _run_detector("BalanceTaint.sol")
    fields = _drift_fields(results)
    assert fields["BalanceTaint.senderBal"]["slot"] == 0
    assert fields["BalanceTaint.balCalc"]["slot"] == 1
    # cleanAmount at slot 2
    assert fields["BalanceTaint.controlFlowBal"]["slot"] == 3
    assert fields["BalanceTaint.balances"]["slot"] == 4
    assert fields["BalanceTaint.hashOfBalance"]["slot"] == 5


# ── Create2Taint ────────────────────────────────────────────────


def test_create2_direct():
    results = _run_detector("Create2Taint.sol")
    drifting = _drifting_vars(results)
    assert "deployedAddr" in drifting


def test_create2_cast():
    results = _run_detector("Create2Taint.sol")
    drifting = _drifting_vars(results)
    assert "derivedFromAddr" in drifting


def test_create2_balance():
    results = _run_detector("Create2Taint.sol")
    drifting = _drifting_vars(results)
    assert "addrBalance" in drifting


def test_create2_no_salt_clean():
    results = _run_detector("Create2Taint.sol")
    drifting = _drifting_vars(results)
    assert "cleanDeployed" not in drifting


def test_create2_json_taint_source():
    results = _run_detector("Create2Taint.sol")
    fields = _drift_fields(results)
    for ts in fields.values():
        assert "CREATE2" in ts["taint_source"]


def test_create2_slots():
    results = _run_detector("Create2Taint.sol")
    fields = _drift_fields(results)
    assert fields["Create2Taint.deployedAddr"]["slot"] == 0
    assert fields["Create2Taint.derivedFromAddr"]["slot"] == 1
    # cleanDeployed at slot 2
    assert fields["Create2Taint.addrBalance"]["slot"] == 3


# ── CrossFunction ───────────────────────────────────────────────


def test_cross_function_internal_call():
    results = _run_detector("CrossFunction.sol")
    drifting = _drifting_vars(results)
    assert "storedResult" in drifting


def test_cross_function_multi_hop():
    results = _run_detector("CrossFunction.sol")
    drifting = _drifting_vars(results)
    assert "indirectResult" in drifting


def test_cross_function_clean():
    results = _run_detector("CrossFunction.sol")
    drifting = _drifting_vars(results)
    assert "cleanResult" not in drifting


def test_cross_function_json():
    results = _run_detector("CrossFunction.sol")
    fields = _drift_fields(results)
    assert fields["CrossFunction.storedResult"]["slot"] == 0
    assert fields["CrossFunction.indirectResult"]["slot"] == 1
    for ts in fields.values():
        assert ts["taint_source"] == "gasleft()"


# ── MixedTaint ──────────────────────────────────────────────────


def test_mixed_combined_sources():
    results = _run_detector("MixedTaint.sol")
    drifting = _drifting_vars(results)
    assert "combined" in drifting


def test_mixed_bitwise():
    results = _run_detector("MixedTaint.sol")
    drifting = _drifting_vars(results)
    assert "bitwiseTaint" in drifting


def test_mixed_abi_encode():
    results = _run_detector("MixedTaint.sol")
    drifting = _drifting_vars(results)
    assert "abiEncodeTaint" in drifting


def test_mixed_nested_branch():
    results = _run_detector("MixedTaint.sol")
    drifting = _drifting_vars(results)
    assert "nestedBranch" in drifting


def test_mixed_clean():
    results = _run_detector("MixedTaint.sol")
    drifting = _drifting_vars(results)
    assert "cleanAddr" not in drifting


def test_mixed_combined_json():
    results = _run_detector("MixedTaint.sol")
    fields = _drift_fields(results)
    src = fields["MixedTaint.combined"]["taint_source"]
    assert "gasleft()" in src
    assert "msg.sender.balance" in src


# ── EdgeCases ───────────────────────────────────────────────────


def test_edge_no_false_positives():
    results = _run_detector("EdgeCases.sol")
    drifting = _drifting_vars(results)
    for clean_var in [
        "blockNum",
        "timestamp",
        "msgValue",
        "otherBalance",
    ]:
        assert clean_var not in drifting, f"{clean_var} should not drift"


def test_edge_gas_in_loop():
    results = _run_detector("EdgeCases.sol")
    drifting = _drifting_vars(results)
    assert "gasInLoop" in drifting


def test_edge_ternary():
    results = _run_detector("EdgeCases.sol")
    drifting = _drifting_vars(results)
    assert "ternaryGas" in drifting


def test_edge_multi_assign():
    results = _run_detector("EdgeCases.sol")
    drifting = _drifting_vars(results)
    assert "multiAssign" in drifting


def test_edge_tx_gasprice():
    results = _run_detector("EdgeCases.sol")
    drifting = _drifting_vars(results)
    assert "txGasPrice" in drifting


def test_edge_block_basefee():
    results = _run_detector("EdgeCases.sol")
    drifting = _drifting_vars(results)
    assert "baseFee" in drifting


def test_edge_block_blobbasefee():
    results = _run_detector("EdgeCases.sol")
    drifting = _drifting_vars(results)
    assert "blobBaseFee" in drifting


def test_edge_block_gaslimit():
    results = _run_detector("EdgeCases.sol")
    drifting = _drifting_vars(results)
    assert "gasLimit" in drifting


def test_edge_gas_sources_reasons():
    results = _run_detector("EdgeCases.sol")
    fields = _drift_fields(results)
    assert fields["EdgeCases.txGasPrice"]["taint_source"] == ("tx.gasprice")
    assert fields["EdgeCases.baseFee"]["taint_source"] == ("block.basefee")
    blob = fields["EdgeCases.blobBaseFee"]["taint_source"]
    assert blob == "block.blobbasefee"
    assert fields["EdgeCases.gasLimit"]["taint_source"] == ("block.gaslimit")


# ── PackedStorage (slot packing + offset) ───────────────────────


def test_packed_tainted_vars():
    results = _run_detector("PackedStorage.sol")
    drifting = _drifting_vars(results)
    for var in ["b", "d", "f", "h", "m"]:
        assert var in drifting, f"{var} should drift"
    for var in ["a", "c", "e", "g"]:
        assert var not in drifting, f"{var} should NOT drift"


def test_packed_slot_offsets():
    results = _run_detector("PackedStorage.sol")
    fields = _drift_fields(results)

    b = fields["PackedStorage.b"]
    assert b["slot"] == 0
    assert b["offset"] == 16  # uint128 a takes 16 bytes

    d = fields["PackedStorage.d"]
    assert d["slot"] == 2
    assert d["offset"] == 0

    f = fields["PackedStorage.f"]
    assert f["slot"] == 2
    assert f["offset"] == 16  # d=8 bytes + e=8 bytes

    h = fields["PackedStorage.h"]
    assert h["slot"] == 3
    assert h["offset"] == 0

    m = fields["PackedStorage.m"]
    assert m["slot"] == 4
    assert m["offset"] == 0


def test_packed_slot_hex_format():
    results = _run_detector("PackedStorage.sol")
    fields = _drift_fields(results)
    for ts in fields.values():
        slot_hex = ts["slot_hex"]
        assert slot_hex.startswith("0x")
        assert len(slot_hex) == 66
        assert int(slot_hex, 16) == ts["slot"]


def test_packed_json_completeness():
    """Every result has all required storage_drift fields."""
    results = _run_detector("PackedStorage.sol")
    required_keys = {
        "variable",
        "contract",
        "slot",
        "slot_hex",
        "offset",
        "taint_source",
        "function",
    }
    for r in results:
        ts = r.get("additional_fields", {}).get("storage_drift", {})
        assert ts, "missing storage_drift in additional_fields"
        assert required_keys <= set(ts.keys()), (
            f"missing keys: {required_keys - set(ts.keys())}"
        )


def test_packed_taint_sources():
    results = _run_detector("PackedStorage.sol")
    fields = _drift_fields(results)
    assert fields["PackedStorage.b"]["taint_source"] == "gasleft()"
    assert "msg.sender.balance" in (fields["PackedStorage.d"]["taint_source"])
    assert fields["PackedStorage.f"]["taint_source"] == "gasleft()"
    assert fields["PackedStorage.h"]["taint_source"] == "gasleft()"
    assert fields["PackedStorage.m"]["taint_source"] == "gasleft()"
