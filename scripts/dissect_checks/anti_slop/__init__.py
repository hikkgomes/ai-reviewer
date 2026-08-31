"""Backend-aware structural anti-slop analysis."""

from .model import AnalysisTarget, BackendDiagnostic, BackendResult, LoadedAnalysisTarget, canonical_diagnostic_identity, load_target
from .orchestrator import analyse, build_targets

__all__ = [
    "AnalysisTarget", "LoadedAnalysisTarget", "BackendDiagnostic", "BackendResult",
    "canonical_diagnostic_identity", "load_target", "analyse", "build_targets",
]
