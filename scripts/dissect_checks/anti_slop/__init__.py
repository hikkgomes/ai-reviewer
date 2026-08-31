"""Backend-aware structural anti-slop analysis."""

from .model import AnalysisTarget, BackendDiagnostic, BackendResult
from .orchestrator import analyse, build_targets

__all__ = ["AnalysisTarget", "BackendDiagnostic", "BackendResult", "analyse", "build_targets"]
