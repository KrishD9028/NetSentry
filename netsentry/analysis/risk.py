"""Deterministic risk policy v1.

Severity scores retain compatibility: INFO=0, LOW=2, MEDIUM=5, HIGH=8,
CRITICAL=10. Host observed risk is the maximum accepted finding, or INFO/0
after a completed check, otherwise UNKNOWN/null. Overall risk is unavailable
unless coverage status is COMPLETE. Correlations are never inputs.

Confidence and evidenced context influence action priority, not severity:
critical/high/medium/low/info map to immediate/high/normal/low/informational.
A critical finding requires HIGH confidence plus a demonstrated configuration
or vulnerability for IMMEDIATE; otherwise it is HIGH. Evidenced external
reachability or critical service importance promotes NORMAL to HIGH (only
with HIGH confidence). Private/local scope never discounts a finding.
Within a priority, order by severity, confidence, evidence quality, supported
exposure/importance, then stable endpoint/rule identifiers. No IP inference.
"""
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Finding, HostAssessment

SEVERITY_SCORES = {"INFO": 0, "LOW": 2, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}
CONFIDENCE_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
EVIDENCE_ORDER = {None: 0, "observation": 1, "configuration": 2, "demonstrated_vulnerability": 3}


class RemediationPriority(str, Enum):
    IMMEDIATE = "IMMEDIATE"
    HIGH = "HIGH"
    NORMAL = "NORMAL"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


PRIORITY_ORDER = {value.value: index for index, value in enumerate(RemediationPriority)}


def score_finding(finding: "Finding") -> int:
    return SEVERITY_SCORES[finding.severity.value]


def score_assessment(assessment: "HostAssessment", *, overall=False) -> tuple[str, int | None]:
    if overall and assessment.status.value != "COMPLETE":
        return "UNKNOWN", None
    if assessment.findings:
        highest = max(assessment.findings, key=score_finding)
        return highest.severity.value, score_finding(highest)
    if overall or any(check.status.value == "COMPLETED" for check in assessment.checks):
        return "INFO", 0
    return "UNKNOWN", None


def supported_context(finding: "Finding") -> dict:
    return {
        "exposure": finding.exposure if finding.exposure_evidence else None,
        "exposure_evidence": finding.exposure_evidence,
        "service_importance": finding.service_importance if finding.service_importance_evidence else None,
        "service_importance_evidence": finding.service_importance_evidence,
        "evidence_kind": finding.evidence_kind,
    }


def remediation_priority(finding: "Finding") -> RemediationPriority:
    severity = finding.severity.value
    high_confidence = finding.confidence.value == "HIGH"
    direct = finding.evidence_kind in {"configuration", "demonstrated_vulnerability"}
    context = supported_context(finding)
    if severity == "CRITICAL":
        return RemediationPriority.IMMEDIATE if high_confidence and direct else RemediationPriority.HIGH
    if severity == "HIGH":
        return RemediationPriority.HIGH
    if severity == "MEDIUM":
        elevated = context["exposure"] == "external" or context["service_importance"] == "critical"
        return RemediationPriority.HIGH if high_confidence and elevated else RemediationPriority.NORMAL
    return RemediationPriority.LOW if severity == "LOW" else RemediationPriority.INFORMATIONAL


def finding_order(finding: "Finding") -> tuple:
    context = supported_context(finding)
    return (PRIORITY_ORDER[remediation_priority(finding).value], -score_finding(finding),
            -CONFIDENCE_ORDER[finding.confidence.value], -EVIDENCE_ORDER[finding.evidence_kind],
            -(context["exposure"] == "external"), -(context["service_importance"] == "critical"),
            finding.host, finding.port or 0, finding.protocol or "", finding.rule_id, finding.finding_id)


def host_order(assessment: "HostAssessment") -> tuple:
    # UNKNOWN sorts after known evidence for action triage, never as a zero score.
    score = assessment.observed_risk_score
    best = min((finding_order(item)[:6] for item in assessment.findings), default=(5, 0, 0, 0, 0, 0))
    return (score is None, -(score or 0), best, assessment.host)


def risk_explanation(assessment: "HostAssessment") -> dict:
    return {
        "policy": "netsentry-risk-v1",
        "observed_basis": "Highest accepted finding severity" if assessment.findings else (
            "Completed checks produced no accepted findings" if assessment.coverage.checks_completed else "No completed security checks"),
        "overall_basis": "Observed scan coverage is complete" if assessment.status.value == "COMPLETE" else assessment.status_reason or "Assessment coverage is incomplete",
        "excluded": ["potential CVE correlations", "service hints", "port state alone", "coverage percentage"],
        "confidence_policy": "Confidence affects action priority and ordering; severity is not discounted.",
        "exposure_policy": "Only explicit exposure/importance evidence affects priority; IP address class is not proof.",
    }
