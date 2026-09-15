from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..ip import ip_visibility
from .risk import SEVERITY_SCORES, score_finding, score_assessment, risk_explanation, remediation_priority, supported_context
from .remediation import remediation_details, priority_actions, correlation_validation


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def score(self) -> int:
        return SEVERITY_SCORES[self.value]


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AssessmentStatus(str, Enum):
    COMPLETE = "COMPLETE"
    LIMITED = "LIMITED"
    UNREACHABLE = "UNREACHABLE"
    ERROR = "ERROR"


class CheckStatus(str, Enum):
    COMPLETED = "COMPLETED"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class RiskLevel(str, Enum):
    UNKNOWN = "UNKNOWN"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class AttackSurfaceObservation:
    host: str
    port: int
    protocol: str
    service: str | None
    product: str | None
    version: str | None
    evidence: str
    identification_confidence: Confidence = Confidence.LOW
    identification_source: str | None = None
    transport: str = "tcp"
    tls: bool | None = None
    state: str = "unknown"
    state_reason: str = ""
    scan_observed: bool = True
    scanner_state: str | None = None
    scanner_reason: str | None = None
    scanner_source: str | None = None
    scanner_service: dict | None = None
    service_hint: str | None = None
    identification_status: str = "UNKNOWN"
    identities: tuple[dict, ...] = ()
    identification_attempts: tuple[dict, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "evidence": self.evidence,
            "identification_confidence": self.identification_confidence.value,
            "identification_source": self.identification_source,
            "transport": self.transport,
            "tls": self.tls,
            "state": self.state,
            "state_reason": self.state_reason,
            "scan_observed": self.scan_observed,
            "scanner_state": self.scanner_state,
            "scanner_reason": self.scanner_reason,
            "scanner_source": self.scanner_source,
            "scanner_service": self.scanner_service,
            "service_hint": self.service_hint,
            "identification_status": self.identification_status,
            "identities": list(self.identities),
            "identification_attempts": list(self.identification_attempts),
        }


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    host: str
    evidence: str
    remediation: str
    rule_id: str
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    references: tuple[str, ...] = ()

    evidence_kind: str | None = None
    exposure: str | None = None
    exposure_evidence: str | None = None
    service_importance: str | None = None
    service_importance_evidence: str | None = None
    remediation_key: str | None = None

    def __post_init__(self):
        if self.evidence_kind not in {None, "observation", "configuration", "demonstrated_vulnerability"}:
            raise ValueError("Unsupported finding evidence kind")
        if self.exposure not in {None, "external", "private", "local"}:
            raise ValueError("Unsupported exposure scope")
        if self.service_importance not in {None, "standard", "critical"}:
            raise ValueError("Unsupported service importance")

    @property
    def remediation_details(self) -> dict:
        return remediation_details(self)

    @property
    def score(self) -> int:
        return score_finding(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": list(self.references),
            "rule_id": self.rule_id,
            "score": self.score,
            "remediation_priority": remediation_priority(self).value,
            "remediation_details": self.remediation_details,
            "risk_context": supported_context(self),
        }


@dataclass(frozen=True, slots=True)
class SecurityCheckResult:
    check_id: str
    title: str
    status: CheckStatus
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    reason: str = ""
    findings: tuple[Finding, ...] = ()
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status.value,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "reason": self.reason,
            "details": self.details or {},
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True, slots=True)
class AssessmentCoverage:
    """Endpoint and check counts; services_discovered is a deprecated open_ports alias.

    Retain the legacy constructor field for existing Python callers.
    """

    services_discovered: int
    checks_attempted: int
    checks_completed: int
    checks_unavailable_or_failed: int
    confirmed_services: int = 0

    @property
    def open_ports(self) -> int:
        return self.services_discovered

    @property
    def unconfirmed_open_ports(self) -> int:
        return self.open_ports - self.confirmed_services

    def to_dict(self) -> dict[str, int]:
        return {
            "services_discovered": self.open_ports,
            "open_ports": self.open_ports,
            "confirmed_services": self.confirmed_services,
            "unconfirmed_open_ports": self.unconfirmed_open_ports,
            "checks_attempted": self.checks_attempted,
            "checks_completed": self.checks_completed,
            "checks_unavailable_or_failed": self.checks_unavailable_or_failed,
        }


@dataclass(frozen=True, slots=True)
class HostAssessment:
    host: str
    observations: tuple[AttackSurfaceObservation, ...] = ()
    checks: tuple[SecurityCheckResult, ...] = ()
    findings: tuple[Finding, ...] = ()
    status: AssessmentStatus = AssessmentStatus.LIMITED
    status_reason: str = ""
    scan_profile: str = "unspecified"
    requested_ports: tuple[int, ...] = ()
    reachability: bool | None = None
    probe_status: str = "unknown"
    unimplemented_services: int = 0
    potential_correlations: tuple[dict[str, Any], ...] = ()
    raw_xml: str | None = None
    port_summary: tuple[dict, ...] = ()
    software_evidence: tuple[dict, ...] = ()
    correlation_diagnostics: tuple[dict, ...] = ()
    host_identity: dict | None = None

    @property
    def risk_score(self) -> int | None:
        return score_assessment(self, overall=True)[1]

    @property
    def risk_severity(self) -> RiskLevel:
        return RiskLevel(score_assessment(self, overall=True)[0])

    @property
    def risk_level(self) -> RiskLevel:
        return self.risk_severity

    @property
    def observed_risk_level(self) -> RiskLevel:
        return RiskLevel(score_assessment(self)[0])

    @property
    def observed_risk_score(self) -> int | None:
        return score_assessment(self)[1]

    @property
    def priority_actions(self) -> list[dict]:
        return priority_actions(self.findings)

    @property
    def overall_risk(self) -> dict:
        return {"severity": self.risk_level.value, "score": self.risk_score}

    @property
    def observed_risk(self) -> dict[str, Any]:
        return {
            "severity": self.observed_risk_level.value,
            "score": self.observed_risk_score,
            "scope": "assessed_evidence",
        }

    @property
    def coverage(self) -> AssessmentCoverage:
        completed = sum(check.status is CheckStatus.COMPLETED for check in self.checks)
        unavailable = sum(
            check.status in {CheckStatus.UNAVAILABLE, CheckStatus.FAILED, CheckStatus.INCONCLUSIVE}
            for check in self.checks
        )
        open_endpoints = {
            (item.host, item.protocol, item.port)
            for item in self.observations if item.state == "open"
        }
        confirmed_endpoints = {
            (item.host, item.protocol, item.port)
            for item in self.observations
            if item.state == "open" and item.identification_status == "CONFIRMED" and item.service
        }
        return AssessmentCoverage(
            services_discovered=len(open_endpoints), checks_attempted=len(self.checks),
            checks_completed=completed, checks_unavailable_or_failed=unavailable,
            confirmed_services=len(confirmed_endpoints),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "host_label": ip_visibility(self.host),
            **({"host_identity": self.host_identity} if self.host_identity is not None else {}),
            "assessment_status": self.status.value,
            "status_reason": self.status_reason,
            "scan_profile": self.scan_profile,
            "requested_ports": list(self.requested_ports),
            "reachability": self.reachability,
            "probe_status": self.probe_status,
            "scan_evidence": {"raw_xml": self.raw_xml, "port_summary": list(self.port_summary)},
            "unimplemented_services": self.unimplemented_services,
            "potential_vulnerability_correlations": list(self.potential_correlations),
            "software_evidence": list(self.software_evidence),
            "correlation_diagnostics": list(self.correlation_diagnostics),
            "risk": {
                "severity": self.risk_level.value,
                "score": self.risk_score,
            },
            "observed_risk": self.observed_risk,
            "overall_risk": self.overall_risk,
            "risk_explanation": risk_explanation(self),
            "priority_actions": self.priority_actions,
            "correlation_validation_actions": sorted(
                (correlation_validation(item) for item in self.potential_correlations),
                key=lambda item: (-SEVERITY_SCORES.get(item["advisory_severity"], 0), item["cve_id"] or "")),
            "attack_surface": [observation.to_dict() for observation in self.observations],
            "security_checks": [check.to_dict() for check in self.checks],
            "coverage": self.coverage.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
        }
