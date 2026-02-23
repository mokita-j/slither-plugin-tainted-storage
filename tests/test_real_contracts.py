"""Tests against real-world contracts (tokens and Uniswap V3).

These contracts are unmodified production code used to validate that
the detector produces no false positives on clean contracts and
correctly identifies real drift patterns.
"""

from __future__ import annotations

import pytest
from helpers import (
    drifting_vars as _drifting_vars,
)
from helpers import (
    find_solc,
)
from helpers import (
    run_detector as _run_detector,
)
from helpers import (
    storage_drift_fields as _drift_fields,
)

_SOLC_07 = find_solc("0.7.6")


# ── Tether (USDT) ─────────────────────────────────────────────


class TestTether:
    """Tether (USDT) -- no drift sources, all writes are clean."""

    @pytest.fixture(scope="class")
    def results(self):
        return _run_detector("tokens/tether.sol")

    def test_no_findings(self, results):
        """Production USDT contract has zero drifting storage."""
        assert len(results) == 0

    def test_clean_balances(self, results):
        drifting = _drifting_vars(results)
        assert "balances" not in drifting

    def test_clean_owner(self, results):
        drifting = _drifting_vars(results)
        assert "owner" not in drifting

    def test_clean_totalSupply(self, results):
        drifting = _drifting_vars(results)
        assert "_totalSupply" not in drifting

    def test_clean_paused(self, results):
        drifting = _drifting_vars(results)
        assert "paused" not in drifting

    def test_clean_blacklist(self, results):
        drifting = _drifting_vars(results)
        assert "isBlackListed" not in drifting

    def test_clean_fee_params(self, results):
        drifting = _drifting_vars(results)
        assert "basisPointsRate" not in drifting
        assert "maximumFee" not in drifting


# ── WETH ───────────────────────────────────────────────────────


class TestWETH:
    """Wrapped Ether -- address(this).balance in view function
    only; no state writes depend on drift sources."""

    @pytest.fixture(scope="class")
    def results(self):
        return _run_detector("tokens/weth.sol")

    def test_no_findings(self, results):
        """WETH contract has zero drifting storage."""
        assert len(results) == 0

    def test_clean_balanceOf(self, results):
        drifting = _drifting_vars(results)
        assert "balanceOf" not in drifting

    def test_clean_allowance(self, results):
        drifting = _drifting_vars(results)
        assert "allowance" not in drifting


# ── Uniswap V3 Factory ────────────────────────────────────────


_skip_no_solc07 = pytest.mark.skipif(
    _SOLC_07 is None,
    reason="solc 0.7.6 not installed",
)


@_skip_no_solc07
class TestUniswapV3Factory:
    """UniswapV3Factory -- CREATE2 deployment taints getPool."""

    @pytest.fixture(scope="class")
    def results(self):
        return _run_detector("uniswap-v3/UniswapV3Factory.sol", solc=_SOLC_07)

    def test_getPool_tainted(self, results):
        """getPool mapping stores CREATE2-deployed address."""
        drifting = _drifting_vars(results)
        assert "getPool" in drifting

    def test_getPool_source_is_create2(self, results):
        fields = _drift_fields(results)
        ts = fields["UniswapV3Factory.getPool"]
        assert ts["taint_source"] == "CREATE2"

    def test_getPool_function(self, results):
        fields = _drift_fields(results)
        ts = fields["UniswapV3Factory.getPool"]
        assert "createPool" in ts["function"]

    def test_getPool_slot(self, results):
        fields = _drift_fields(results)
        ts = fields["UniswapV3Factory.getPool"]
        assert ts["slot"] == 5

    def test_only_one_finding(self, results):
        """Only getPool drifts, not owner or feeAmountTickSpacing."""
        assert len(results) == 1

    def test_owner_clean(self, results):
        drifting = _drifting_vars(results)
        assert "owner" not in drifting

    def test_feeAmountTickSpacing_clean(self, results):
        drifting = _drifting_vars(results)
        assert "feeAmountTickSpacing" not in drifting

    def test_parameters_clean(self, results):
        drifting = _drifting_vars(results)
        assert "parameters" not in drifting

    def test_json_completeness(self, results):
        """JSON output includes all required fields."""
        fields = _drift_fields(results)
        ts = fields["UniswapV3Factory.getPool"]
        for key in (
            "variable",
            "contract",
            "slot",
            "slot_hex",
            "offset",
            "taint_source",
            "function",
        ):
            assert key in ts, f"missing {key}"
        assert ts["contract"] == "UniswapV3Factory"
        assert ts["slot_hex"].startswith("0x")
        assert len(ts["slot_hex"]) == 66


# ── Uniswap V3 Pool ───────────────────────────────────────────


@_skip_no_solc07
class TestUniswapV3Pool:
    """UniswapV3Pool -- no gasleft/gasprice/basefee/CREATE2.
    block.timestamp is not a tracked drift source."""

    @pytest.fixture(scope="class")
    def results(self):
        return _run_detector("uniswap-v3/UniswapV3Pool.sol", solc=_SOLC_07)

    def test_no_findings(self, results):
        """Pool has no drifting storage (block.timestamp not tracked)."""
        assert len(results) == 0

    def test_slot0_clean(self, results):
        drifting = _drifting_vars(results)
        assert "slot0" not in drifting

    def test_liquidity_clean(self, results):
        drifting = _drifting_vars(results)
        assert "liquidity" not in drifting

    def test_feeGrowth_clean(self, results):
        drifting = _drifting_vars(results)
        assert "feeGrowthGlobal0X128" not in drifting
        assert "feeGrowthGlobal1X128" not in drifting

    def test_protocolFees_clean(self, results):
        drifting = _drifting_vars(results)
        assert "protocolFees" not in drifting

    def test_observations_clean(self, results):
        drifting = _drifting_vars(results)
        assert "observations" not in drifting

    def test_ticks_clean(self, results):
        drifting = _drifting_vars(results)
        assert "ticks" not in drifting

    def test_positions_clean(self, results):
        drifting = _drifting_vars(results)
        assert "positions" not in drifting
