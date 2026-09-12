from dataclasses import asdict, dataclass
from enum import Enum

from .models import Confidence, Severity
from .versions import AffectedVersionRange, MatchStatus, match_version


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
    vendor: str | None = None
    variant: str | None = None
    raw_version: str | None = None
    host: str | None = None
    port: int | None = None


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
    vendor: str | None = None
    variant: str | None = None
    correlation_source: str | None = None
    matched_range: AffectedVersionRange | None = None
    match_reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "product": self.product,
            "affected_range": self.affected_range,
            "evidence": {**asdict(self.evidence), "confidence": self.evidence.confidence.value},
            "vendor": self.vendor,
            "variant": self.variant,
            "correlation_source": self.correlation_source,
            "matched_range": asdict(self.matched_range) if self.matched_range else None,
            "match_reason": self.match_reason,
            "status": self.status.value,
            "confidence": self.confidence.value,
            "severity": self.severity.value if self.severity else None,
            "cvss": self.cvss,
            "reference": self.reference,
        }


class VulnerabilityProvider:
    def correlate(self, evidence: SoftwareEvidence) -> tuple[VulnerabilityCorrelation, ...]:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class VulnerabilityDefinition:
    cve_id: str
    product: str
    ranges: tuple[AffectedVersionRange, ...]
    source: str
    reference: str | None = None
    vendor: str | None = None
    variant: str | None = None
    severity: Severity | None = None
    cvss: float | None = None


class StaticVulnerabilityProvider(VulnerabilityProvider):
    """Offline definitions with explicit applicability; legacy result records cannot match."""

    def __init__(self, definitions=(), *, correlations=None) -> None:
        self.definitions = tuple(definitions if correlations is None else correlations)

    def evaluate(self, evidence: SoftwareEvidence):
        results, diagnostics = [], []
        for definition in self.definitions:
            if not isinstance(definition, VulnerabilityDefinition):
                diagnostics.append({"status": "INDETERMINATE", "reason": "Legacy correlation result requires a structured vulnerability definition."})
                continue
            if definition.product.casefold() != evidence.product.casefold():
                continue
            constraint_error = None
            for field in ("vendor", "variant"):
                required = getattr(definition, field)
                actual = getattr(evidence, field)
                if required is not None and (actual is None or required.casefold() != actual.casefold()):
                    constraint_error = {"cve_id": definition.cve_id, "status": "INDETERMINATE" if actual is None else "NO_MATCH", "reason": f"{field} constraint not satisfied"}
                    break
            if constraint_error:
                diagnostics.append(constraint_error)
                continue
            if not definition.ranges:
                diagnostics.append({"cve_id": definition.cve_id, "status": "INDETERMINATE", "reason": "No explicit affected ranges"})
            for affected in definition.ranges:
                if not isinstance(affected, AffectedVersionRange):
                    diagnostics.append({"cve_id": definition.cve_id, "status": "INDETERMINATE", "reason": "A structured affected-version range is required"})
                    continue
                # OpenSSH ranges must be scoped to a specific variant.
                if affected.scheme == "openssh" and definition.variant is None:
                    diagnostics.append({"cve_id": definition.cve_id, "status": "INDETERMINATE", "reason": "OpenSSH definition requires an explicit variant"})
                    continue
                match = match_version(evidence.version, affected, variant=evidence.variant)
                diagnostics.append({"cve_id": definition.cve_id, "status": match.status.value, "reason": match.reason, "range": asdict(affected)})
                if match.status is MatchStatus.MATCH:
                    # Fresh evidence binding and unconditional POTENTIAL status.
                    results.append(VulnerabilityCorrelation(
                        definition.cve_id, definition.product, str(asdict(affected)), evidence,
                        CorrelationStatus.POTENTIAL, evidence.confidence,
                        definition.severity, definition.cvss, definition.reference,
                        definition.vendor, definition.variant, definition.source, affected, match.reason,
                    ))
                    break
        return tuple(results), tuple(diagnostics)

    def correlate(self, evidence: SoftwareEvidence) -> tuple[VulnerabilityCorrelation, ...]:
        return self.evaluate(evidence)[0]


def bind_correlation(candidate, evidence):
    """Validate provider applicability at the engine boundary and bind fresh evidence."""
    from dataclasses import replace
    if not isinstance(candidate, VulnerabilityCorrelation) or not isinstance(candidate.matched_range, AffectedVersionRange):
        return None
    if candidate.product.casefold() != evidence.product.casefold():
        return None
    for field in ("vendor", "variant"):
        required, observed = getattr(candidate, field), getattr(evidence, field)
        if required is not None and (observed is None or required.casefold() != observed.casefold()):
            return None
    if candidate.matched_range.scheme == "openssh" and candidate.variant is None:
        return None
    if match_version(evidence.version, candidate.matched_range, variant=evidence.variant).status is not MatchStatus.MATCH:
        return None
    rank = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
    confidence = min((candidate.confidence, evidence.confidence), key=rank.get)
    return replace(candidate, evidence=evidence, status=CorrelationStatus.POTENTIAL, confidence=confidence)
