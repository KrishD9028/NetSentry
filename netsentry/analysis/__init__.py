"""Rule-based, non-exploitative security analysis for NetSentry scan results."""

from .engine import SecurityAnalyzer, assess_scan_result, assess_scan_results
from .checks import ConfirmedFindingCheck, CompletedNoFindingCheck, ServiceCheck
from .correlation import CorrelationStatus, SoftwareEvidence, VulnerabilityCorrelation
from .fingerprinting import identify_service, merge_fingerprints
from .models import (
    AssessmentCoverage,
    AssessmentStatus,
    AttackSurfaceObservation,
    CheckStatus,
    Confidence,
    Finding,
    HostAssessment,
    RiskLevel,
    SecurityCheckResult,
    Severity,
)

__all__ = [
    "Confidence",
    "CorrelationStatus",
    "AssessmentCoverage",
    "AssessmentStatus",
    "AttackSurfaceObservation",
    "CheckStatus",
    "CompletedNoFindingCheck",
    "ConfirmedFindingCheck",
    "Finding",
    "HostAssessment",
    "RiskLevel",
    "SecurityCheckResult",
    "SecurityAnalyzer",
    "ServiceCheck",
    "SoftwareEvidence",
    "VulnerabilityCorrelation",
    "identify_service",
    "merge_fingerprints",
    "Severity",
    "assess_scan_result",
    "assess_scan_results",
]
