"""Shared test utilities for the tainted-storage detector."""

from __future__ import annotations

from pathlib import Path

from slither import Slither
from slither_tainted_storage.detectors.tainted_storage import (
    TaintedStorage,
)

CONTRACTS_DIR = Path(__file__).parent / "contracts"

# ── result cache ──────────────────────────────────────────────

_cache: dict[tuple[str, str | None], list[dict]] = {}


def run_detector(
    filename: str, *, solc: str | None = None
) -> list[dict]:
    """Run tainted-storage on a contract and return JSON results.

    Results are cached by (filename, solc) so the same contract
    is compiled at most once per test session.
    """
    key = (filename, solc)
    if key not in _cache:
        sol_path = str(CONTRACTS_DIR / filename)
        kwargs: dict = {}
        if solc is not None:
            kwargs["solc"] = solc
        sl = Slither(sol_path, **kwargs)
        sl.register_detector(TaintedStorage)
        results = sl.run_detectors()
        _cache[key] = [
            item for sublist in results for item in sublist
        ]
    return _cache[key]


def tainted_vars(results: list[dict]) -> set[str]:
    """Extract the set of tainted variable names from results."""
    names: set[str] = set()
    for r in results:
        elems = r.get("elements", [])
        if elems:
            name = elems[0].get("name", "")
            if name:
                names.add(name)
    return names


def tainted_storage_fields(
    results: list[dict],
) -> dict[str, dict]:
    """Map variable canonical name to its tainted_storage JSON."""
    out: dict[str, dict] = {}
    for r in results:
        ts = r.get("additional_fields", {}).get(
            "tainted_storage", {}
        )
        if ts:
            out[ts["variable"]] = ts
    return out


def find_solc(version: str) -> str | None:
    """Find a solc binary for a specific version.

    Uses solc-select's artifacts directory.  Returns the path
    string or None if not installed.
    """
    try:
        from solc_select.constants import ARTIFACTS_DIR

        path = Path(ARTIFACTS_DIR) / f"solc-{version}" / f"solc-{version}"
        if path.exists():
            return str(path)
    except ImportError:
        pass
    return None
