from slither_tainted_storage.detectors.tainted_storage import (
    TaintedStorage,
)

from slither.detectors.abstract_detector import AbstractDetector
from slither.printers.abstract_printer import AbstractPrinter


def make_plugin() -> (
    tuple[list[type[AbstractDetector]], list[type[AbstractPrinter]]]
):
    plugin_detectors: list[type[AbstractDetector]] = [TaintedStorage]
    plugin_printers: list[type[AbstractPrinter]] = []
    return plugin_detectors, plugin_printers
