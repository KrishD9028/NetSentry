"""Rule-based, non-exploitative security analysis for NetSentry scan results."""

from .engine import SecurityAnalyzer, assess_scan_result, assess_scan_results
from .checks import ConfirmedFindingCheck, CompletedNoFindingCheck, ServiceCheck
from .correlation import CorrelationStatus, SoftwareEvidence, VulnerabilityCorrelation, VulnerabilityDefinition, StaticVulnerabilityProvider
from .versions import AffectedVersionRange, MatchStatus, match_version
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
    "VulnerabilityDefinition",
    "StaticVulnerabilityProvider",
    "AffectedVersionRange",
    "MatchStatus",
    "match_version",
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
