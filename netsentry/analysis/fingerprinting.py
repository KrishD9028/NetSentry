from dataclasses import dataclass

from ..scanning.models import PortService
from .correlation import SoftwareEvidence
from .models import Confidence


@dataclass(frozen=True, slots=True)
class FingerprintEvidence:
    service: str | None
    product: str | None
    version: str | None
    confidence: Confidence
    source: str


def identify_service(service: PortService) -> SoftwareEvidence | None:
    """Convert strong scan metadata into correlation-ready software evidence."""
    if not service.product:
        return None
    confidence = Confidence.HIGH if service.version and service.product else Confidence.MEDIUM
    source = "Nmap fingerprint"
    if service.extra:
        source = "Nmap fingerprint and service metadata"
    return SoftwareEvidence(
        product=service.product,
        version=service.version,
        protocol=service.protocol,
        confidence=confidence,
        source=source,
    )


def merge_fingerprints(candidates: tuple[SoftwareEvidence, ...]) -> SoftwareEvidence | None:
    """Prefer exact version evidence and never silently merge conflicting products."""
    if not candidates:
        return None
    products = {candidate.product.lower() for candidate in candidates}
    if len(products) != 1:
        return None
    versions = [candidate for candidate in candidates if candidate.version]
    return max(versions or list(candidates), key=lambda candidate: candidate.confidence.value)
