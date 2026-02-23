from slither.detectors.abstract_detector import AbstractDetector
from slither.printers.abstract_printer import AbstractPrinter

from storage_drift.detectors.drift_detector import (
    StorageDrift,
)


def make_plugin() -> tuple[
    list[type[AbstractDetector]], list[type[AbstractPrinter]]
]:
    plugin_detectors: list[type[AbstractDetector]] = [StorageDrift]
    plugin_printers: list[type[AbstractPrinter]] = []
    return plugin_detectors, plugin_printers
