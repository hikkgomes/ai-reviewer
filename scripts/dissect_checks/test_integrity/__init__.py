"""Test-integrity evidence collection and approval-bound verification."""

from .model import (
    MutationResult,
    TestArtifact,
    TestChange,
    TestRunResult,
    TestSubject,
)
from .inventory import InventoryResult, build_inventory
from .orchestrator import TestIntegrityResult, analyse
from .evidence_matrix import EvidenceMatrix, execute_approved_matrix, flakiness_evidence, interpret_matrix, reachability_candidates

__all__ = [
    "MutationResult",
    "TestArtifact",
    "TestChange",
    "TestRunResult",
    "TestSubject",
    "InventoryResult",
    "TestIntegrityResult",
    "EvidenceMatrix",
    "build_inventory",
    "analyse",
    "execute_approved_matrix",
    "flakiness_evidence",
    "interpret_matrix",
    "reachability_candidates",
]
