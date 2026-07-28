"""Deterministic, evidence-first checks used by Dissect."""

from .engine import ScanOptions, scan_paths
from .model import Finding

__all__ = ["Finding", "ScanOptions", "scan_paths"]
