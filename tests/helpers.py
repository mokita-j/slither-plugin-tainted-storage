"""Shared test utilities for the storage-drift detector."""

from __future__ import annotations

from pathlib import Path

from slither import Slither

from storage_drift.detectors.drift_detector import (
    StorageDrift,
)

CONTRACTS_DIR = Path(__file__).parent / "contracts"

# ── result cache ──────────────────────────────────────────────

_cache: dict[tuple[str, str | None], list[dict]] = {}


def run_detector(filename: str, *, solc: str | None = None) -> list[dict]:
    """Run storage-drift on a contract and return JSON results.

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
        sl.register_detector(StorageDrift)
        results = sl.run_detectors()
        _cache[key] = [item for sublist in results for item in sublist]
    return _cache[key]


def drifting_vars(results: list[dict]) -> set[str]:
    """Extract the set of drifting variable names from results."""
    names: set[str] = set()
    for r in results:
        elems = r.get("elements", [])
        if elems:
            name = elems[0].get("name", "")
            if name:
                names.add(name)
    return names


def storage_drift_fields(
    results: list[dict],
) -> dict[str, dict]:
    """Map variable canonical name to its storage_drift JSON."""
    out: dict[str, dict] = {}
    for r in results:
        ts = r.get("additional_fields", {}).get("storage_drift", {})
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
