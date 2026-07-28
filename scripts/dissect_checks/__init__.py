"""Deterministic, evidence-first checks used by Dissect."""

from .engine import ScanOptions, ScanReport, scan_paths, scan_report
from .model import Finding

__all__ = ["Finding", "ScanOptions", "ScanReport", "scan_paths", "scan_report"]
