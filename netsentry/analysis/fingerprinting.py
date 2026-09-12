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
    if len(products) != 1 or any(len({getattr(candidate, field) for candidate in candidates if getattr(candidate, field) is not None}) > 1 for field in ("version", "vendor", "variant")):
        return None
    versions = [candidate for candidate in candidates if candidate.version]
    return max(versions or list(candidates), key=lambda candidate: {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}[candidate.confidence])


def collect_software_evidence(service: PortService, checks=(), *, host=None) -> tuple[SoftwareEvidence, ...]:
    """Keep distinct observations, including conflicts, after endpoint checks finish."""
    from dataclasses import replace
    observations = []
    if not service.confirmed_protocols:
        return ()
    if service.product and service.service_method == "probed" and service.service_confidence == "10":
        observations.append(SoftwareEvidence(service.product, service.version, service.protocol,
                                            Confidence.HIGH if service.version else Confidence.MEDIUM,
                                            "Nmap fingerprint", raw_version=service.version))
    banners = [(item.evidence.get("banner"), item.source) for item in service.identities if item.protocol == "ssh"]
    banners.extend((check.details.get("banner"), "NetSentry SSH probe") for check in checks if check.check_id == "NS-CHECK-SSH" and check.details)
    for banner, source in banners:
        if not banner:
            continue
        match = re.match(r"SSH-[^-]+-(OpenSSH)_for_Windows_([^\s]+)", banner)
        variant = "windows" if match else None
        if match is None:
            match = re.match(r"SSH-[^-]+-([A-Za-z][A-Za-z0-9.-]*)_([^\s]+)", banner)
            if match and match[1] == "OpenSSH":
                variant = "portable" if re.fullmatch(r"[0-9]+\.[0-9]+p[0-9]+", match[2]) else "upstream" if re.fullmatch(r"[0-9]+\.[0-9]+", match[2]) else None
        if match:
            observations.append(SoftwareEvidence(match[1], match[2], "ssh", Confidence.MEDIUM, source,
                                                variant=variant, raw_version=match[2]))
    for check in checks:
        if check.check_id != "NS-CHECK-HTTP" or check.status.value != "COMPLETED" or not check.details:
            continue
        server = check.details.get("server")
        if not isinstance(server, str):
            continue
        for token in server[:16384].split()[:64]:
            match = re.fullmatch(r"([^/\s]+)/([^/\s]+)", token)
            if match:
                observations.append(SoftwareEvidence(match[1], match[2], "http", Confidence.MEDIUM,
                                                    "HTTP Server header", raw_version=match[2]))
    unique = {}
    for item in observations:
        item = replace(item, host=host, port=service.port)
        key = (item.product, item.version, item.protocol, item.vendor, item.variant, item.source)
        unique.setdefault(key, item)
    return tuple(unique.values())
