from dataclasses import dataclass
import re

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
    if not service.confirmed_protocols:
        return None
    if service.product and service.service_method == "probed" and service.service_confidence == "10":
        return SoftwareEvidence(
            product=service.product, version=service.version, protocol=service.protocol,
            confidence=Confidence.HIGH if service.version else Confidence.MEDIUM,
            source="Nmap fingerprint",
        )
    for identity in service.identities:
        if identity.protocol == "ssh":
            banner = identity.evidence.get("banner", "")
            match = re.match(r"SSH-[^-]+-(OpenSSH)_for_Windows_([0-9][^\s]*)", banner)
            if match is None:
                match = re.match(r"SSH-[^-]+-([A-Za-z][A-Za-z0-9.-]*)_([0-9][^\s]*)", banner)
            if match:
                return SoftwareEvidence(match[1], match[2], "ssh", Confidence.MEDIUM, identity.source)
    return None


def merge_fingerprints(candidates: tuple[SoftwareEvidence, ...]) -> SoftwareEvidence | None:
    """Prefer exact version evidence and never silently merge conflicting products."""
    if not candidates:
        return None
    products = {candidate.product.lower() for candidate in candidates}
    if len(products) != 1:
        return None
    versions = [candidate for candidate in candidates if candidate.version]
    return max(versions or list(candidates), key=lambda candidate: {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}[candidate.confidence])
