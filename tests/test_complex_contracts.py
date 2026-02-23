"""Tests for complex/realistic contracts."""

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

# ── RealisticVault ──────────────────────────────────────────────


def test_vault_balance_via_alias():
    """msg.sender.balance through a local variable alias."""
    results = _run_detector("RealisticVault.sol")
    drifting = _drifting_vars(results)
    assert "lastSenderBalance" in drifting


def test_vault_struct_taint():
    """Struct field tainted via balance alias."""
    results = _run_detector("RealisticVault.sol")
    drifting = _drifting_vars(results)
    assert "deposits" in drifting


def test_vault_modifier_gasleft():
    """gasleft() in inherited modifier taints state variable."""
    results = _run_detector("RealisticVault.sol")
    drifting = _drifting_vars(results)
    assert "lastGasUsed" in drifting


def test_vault_gasleft_diff():
    """gasleft difference stored as gasRefund."""
    results = _run_detector("RealisticVault.sol")
    drifting = _drifting_vars(results)
    assert "gasRefund" in drifting


def test_vault_clean_total():
    """totalDeposits only uses msg.value (not a source)."""
    results = _run_detector("RealisticVault.sol")
    drifting = _drifting_vars(results)
    assert "totalDeposits" not in drifting


def test_vault_balance_label():
    """Balance via alias labeled as msg.sender.balance."""
    results = _run_detector("RealisticVault.sol")
    fields = _drift_fields(results)
    ts = fields["RealisticVault.lastSenderBalance"]
    assert "msg.sender.balance" in ts["taint_source"]


def test_vault_modifier_slot():
    """Inherited lastGasUsed at slot 1 (after owner at slot 0)."""
    results = _run_detector("RealisticVault.sol")
    fields = _drift_fields(results)
    ts = fields["Ownable.lastGasUsed"]
    assert ts["slot"] == 1


# ── Create2Factory ──────────────────────────────────────────────


def test_factory_all_create2_vars():
    """All variables written from CREATE2 result are tainted."""
    results = _run_detector("Create2Factory.sol")
    drifting = _drifting_vars(results)
    for var in [
        "lastDeployed",
        "saltToAddr",
        "deployedAddrs",
        "lastDeployedAsUint",
    ]:
        assert var in drifting, f"{var} should drift"


def test_factory_clean_vars():
    """Counter and regular CREATE are clean."""
    results = _run_detector("Create2Factory.sol")
    drifting = _drifting_vars(results)
    assert "deployCount" not in drifting
    assert "lastCleanDeploy" not in drifting


def test_factory_json():
    results = _run_detector("Create2Factory.sol")
    fields = _drift_fields(results)
    for ts in fields.values():
        assert "CREATE2" in ts["taint_source"]
        assert ts["contract"] == "Create2Factory"


# ── GasMeter ────────────────────────────────────────────────────


def test_gasmeter_tainted():
    results = _run_detector("GasMeter.sol")
    drifting = _drifting_vars(results)
    for var in ["gasPerUnit", "lastExecGas", "userGasUsed"]:
        assert var in drifting, f"{var} should drift"


def test_gasmeter_gasprice_tainted():
    results = _run_detector("GasMeter.sol")
    drifting = _drifting_vars(results)
    assert "cachedGasPrice" in drifting


def test_gasmeter_gasprice_reason():
    results = _run_detector("GasMeter.sol")
    fields = _drift_fields(results)
    ts = fields["GasMeter.cachedGasPrice"]
    assert ts["taint_source"] == "tx.gasprice"


def test_gasmeter_clean():
    results = _run_detector("GasMeter.sol")
    drifting = _drifting_vars(results)
    assert "executionCount" not in drifting


def test_gasmeter_guarded_write():
    """require(gasleft() > X) is not an IF branch, so state
    written after it should NOT be tainted by control flow."""
    results = _run_detector("GasMeter.sol")
    drifting = _drifting_vars(results)
    # executionCount is written in guardedWrite but gasleft
    # is only in a require, not an if-branch
    assert "executionCount" not in drifting


# ── ComplexFlows ────────────────────────────────────────────────


def test_complex_struct_member():
    """Writing gasleft() to struct member taints the struct."""
    results = _run_detector("ComplexFlows.sol")
    drifting = _drifting_vars(results)
    assert "metrics" in drifting


def test_complex_array_push():
    """push(gasleft()) taints the array."""
    results = _run_detector("ComplexFlows.sol")
    drifting = _drifting_vars(results)
    assert "gasHistory" in drifting


def test_complex_multi_return_tainted():
    """First value from multi-return (gasleft) is tainted."""
    results = _run_detector("ComplexFlows.sol")
    drifting = _drifting_vars(results)
    assert "fromMultiReturn" in drifting


def test_complex_multi_return_tuple_taint():
    """Tuple-level taint: second value also tainted (known FP)."""
    results = _run_detector("ComplexFlows.sol")
    drifting = _drifting_vars(results)
    # This is a known limitation: entire tuple is tainted
    assert "cleanFromMultiReturn" in drifting


def test_complex_overwrite_clean():
    """Variable first tainted then overwritten with clean value."""
    results = _run_detector("ComplexFlows.sol")
    drifting = _drifting_vars(results)
    assert "rewrittenClean" not in drifting


def test_complex_state_length_clean():
    """Reading array length is clean (length is a count)."""
    results = _run_detector("ComplexFlows.sol")
    drifting = _drifting_vars(results)
    assert "stateToState" not in drifting


# ── TaintLaundering ─────────────────────────────────────────────


def test_laundering_balance_via_alias():
    """Balance through msg.sender alias is tainted."""
    results = _run_detector("TaintLaundering.sol")
    drifting = _drifting_vars(results)
    assert "balanceViaAlias" in drifting


def test_laundering_bool_from_gas():
    """Bool derived from gasleft comparison is tainted."""
    results = _run_detector("TaintLaundering.sol")
    drifting = _drifting_vars(results)
    assert "flagFromGas" in drifting


def test_laundering_ternary():
    results = _run_detector("TaintLaundering.sol")
    drifting = _drifting_vars(results)
    assert "fromTernary" in drifting


def test_laundering_write_after_branch_clean():
    """State written AFTER a tainted branch is NOT tainted."""
    results = _run_detector("TaintLaundering.sol")
    drifting = _drifting_vars(results)
    assert "cleanAfterBranch" not in drifting


def test_laundering_clean_mapping_read():
    """Reading a cleanly-written mapping value is clean."""
    results = _run_detector("TaintLaundering.sol")
    drifting = _drifting_vars(results)
    assert "mappingValueRead" not in drifting


def test_laundering_cross_function_known_fn():
    """Cross-function state taint: known limitation (FN).
    copiedFromState reads storedGas (tainted in another function)
    but per-function analysis cannot track this."""
    results = _run_detector("TaintLaundering.sol")
    drifting = _drifting_vars(results)
    # Known FN: cross-function state taint not tracked
    assert "copiedFromState" not in drifting


def test_laundering_balance_alias_label():
    """Balance through alias labeled as msg.sender.balance."""
    results = _run_detector("TaintLaundering.sol")
    fields = _drift_fields(results)
    ts = fields["TaintLaundering.balanceViaAlias"]
    assert "msg.sender.balance" in ts["taint_source"]


# ── IntraCallTaint ─────────────────────────────────────────────


def test_intracall_direct_taint():
    """_taint() writes gasleft to taintedVar directly."""
    results = _run_detector("IntraCallTaint.sol")
    drifting = _drifting_vars(results)
    assert "taintedVar" in drifting


def test_intracall_copied_after_call():
    """copiedVar = taintedVar after _taint() is tainted."""
    results = _run_detector("IntraCallTaint.sol")
    drifting = _drifting_vars(results)
    assert "copiedVar" in drifting


def test_intracall_derived_after_call():
    """derivedVar = taintedVar * 2 + 1 after _taint()."""
    results = _run_detector("IntraCallTaint.sol")
    drifting = _drifting_vars(results)
    assert "derivedVar" in drifting


def test_intracall_clean():
    """cleanVar = 42 has no taint source."""
    results = _run_detector("IntraCallTaint.sol")
    drifting = _drifting_vars(results)
    assert "cleanVar" not in drifting


def test_intracall_multi_hop():
    """_taint() -> _copy() -> multiHopCopy chain."""
    results = _run_detector("IntraCallTaint.sol")
    drifting = _drifting_vars(results)
    assert "multiHopCopy" in drifting


def test_intracall_conditional():
    """if (taintedVar > 1000) after _taint() taints branch."""
    results = _run_detector("IntraCallTaint.sol")
    drifting = _drifting_vars(results)
    assert "conditionalCopy" in drifting
