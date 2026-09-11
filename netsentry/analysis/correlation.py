from dataclasses import dataclass
from enum import Enum

from .models import Confidence, Severity


class CorrelationStatus(str, Enum):
    POTENTIAL = "POTENTIAL"
    CONFIRMED = "CONFIRMED"


@dataclass(frozen=True, slots=True)
class SoftwareEvidence:
    product: str
    version: str | None
    protocol: str
    confidence: Confidence
    source: str


@dataclass(frozen=True, slots=True)
class VulnerabilityCorrelation:
    cve_id: str
    product: str
    affected_range: str
    evidence: SoftwareEvidence
    status: CorrelationStatus
    confidence: Confidence
    severity: Severity | None = None
    cvss: float | None = None
    reference: str | None = None

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "product": self.product,
            "affected_range": self.affected_range,
            "evidence": {
                "product": self.evidence.product,
                "version": self.evidence.version,
                "protocol": self.evidence.protocol,
                "confidence": self.evidence.confidence.value,
                "source": self.evidence.source,
            },
            "status": self.status.value,
            "confidence": self.confidence.value,
            "severity": self.severity.value if self.severity else None,
            "cvss": self.cvss,
            "reference": self.reference,
        }


class VulnerabilityProvider:
    def correlate(self, evidence: SoftwareEvidence) -> tuple[VulnerabilityCorrelation, ...]:
        raise NotImplementedError


class StaticVulnerabilityProvider(VulnerabilityProvider):
    """Opt-in provider for caller-supplied metadata; no network lookups occur."""

    def __init__(self, correlations: tuple[VulnerabilityCorrelation, ...] = ()) -> None:
        self.correlations = correlations

    def correlate(self, evidence: SoftwareEvidence) -> tuple[VulnerabilityCorrelation, ...]:
        return tuple(item for item in self.correlations if item.product.lower() == evidence.product.lower())
