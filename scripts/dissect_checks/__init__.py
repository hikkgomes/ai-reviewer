"""Deterministic, evidence-first checks used by Dissect."""

import sys

if sys.version_info < (3, 11):
    raise RuntimeError("Dissect requires Python 3.11 or newer.")

from .engine import ScanOptions, ScanReport, scan_paths, scan_report
from .model import Finding

__all__ = ["Finding", "ScanOptions", "ScanReport", "scan_paths", "scan_report"]
