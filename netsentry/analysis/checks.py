from abc import ABC, abstractmethod
from collections.abc import Iterable

from ..scanning.models import HostScanResult, PortService
from .models import CheckStatus, Finding, SecurityCheckResult


class ServiceCheck(ABC):
    """A safe, service-specific check that may produce confirmed findings."""

    check_id: str
    title: str

    @abstractmethod
    def matches(self, service: PortService) -> bool:
        """Return whether this check applies to the observed service."""

    @abstractmethod
    def run(self, result: HostScanResult, service: PortService) -> SecurityCheckResult:
        """Run a non-destructive check and return explicit coverage status."""


class UnavailableServiceCheck(ServiceCheck):
    def __init__(self, check_id: str, title: str, reason: str, matcher=None) -> None:
        self.check_id = check_id
        self.title = title
        self.reason = reason
        self.matcher = matcher

    def matches(self, service: PortService) -> bool:
        return self.matcher(service) if self.matcher is not None else True

    def run(self, result: HostScanResult, service: PortService) -> SecurityCheckResult:
        return SecurityCheckResult(
            check_id=self.check_id,
            title=self.title,
            status=CheckStatus.UNAVAILABLE,
            port=service.port,
            protocol=service.protocol,
            service=service.service,
            reason=self.reason,
        )


class CompletedNoFindingCheck(ServiceCheck):
    """Small reusable check implementation for safe checks with no finding."""

    def __init__(self, check_id: str, title: str, matcher) -> None:
        self.check_id = check_id
        self.title = title
        self.matcher = matcher

    def matches(self, service: PortService) -> bool:
        return self.matcher(service)

    def run(self, result: HostScanResult, service: PortService) -> SecurityCheckResult:
        return SecurityCheckResult(
            check_id=self.check_id,
            title=self.title,
            status=CheckStatus.COMPLETED,
            port=service.port,
            protocol=service.protocol,
            service=service.service,
            reason="Check completed; no confirmed security finding was generated.",
        )


class ConfirmedFindingCheck(ServiceCheck):
    """Adapter for tests or future safe checks that return confirmed evidence."""

    def __init__(self, check_id: str, title: str, matcher, finding_factory) -> None:
        self.check_id = check_id
        self.title = title
        self.matcher = matcher
        self.finding_factory = finding_factory

    def matches(self, service: PortService) -> bool:
        return self.matcher(service)

    def run(self, result: HostScanResult, service: PortService) -> SecurityCheckResult:
        finding: Finding = self.finding_factory(result, service)
        return SecurityCheckResult(
            check_id=self.check_id,
            title=self.title,
            status=CheckStatus.COMPLETED,
            port=service.port,
            protocol=service.protocol,
            service=service.service,
            findings=(finding,),
            reason="Check completed with confirmed evidence.",
        )


def _service_name(service: PortService) -> str:
    return (service.service or "").lower()


def _port_or_name(port: int, names: set[str]):
    return lambda service: service.protocol == "tcp" and (service.port == port or _service_name(service) in names)


def default_service_checks() -> tuple[ServiceCheck, ...]:
    unavailable = "No safe protocol-specific probe is configured in this milestone; the Nmap observation is preserved without claiming a vulnerability."
    return (
        UnavailableServiceCheck("NS-CHECK-SMB", "SMB configuration", unavailable, lambda service: default_check_matcher("NS-CHECK-SMB", service)),
        UnavailableServiceCheck("NS-CHECK-TLS", "TLS configuration", unavailable, lambda service: default_check_matcher("NS-CHECK-TLS", service)),
        UnavailableServiceCheck("NS-CHECK-HTTP", "HTTP security configuration", unavailable, lambda service: default_check_matcher("NS-CHECK-HTTP", service)),
        UnavailableServiceCheck("NS-CHECK-DNS", "DNS configuration", unavailable, lambda service: default_check_matcher("NS-CHECK-DNS", service)),
    )


def default_check_matcher(check_id: str, service: PortService) -> bool:
    name = _service_name(service)
    if check_id == "NS-CHECK-SMB":
        return service.protocol == "tcp" and (service.port == 445 or name in {"smb", "microsoft-ds"})
    if check_id == "NS-CHECK-TLS":
        return service.protocol == "tcp" and (service.port in {443, 8443} or name in {"https", "ssl", "https-alt"})
    if check_id == "NS-CHECK-HTTP":
        return service.protocol == "tcp" and (service.port == 80 or name == "http")
    if check_id == "NS-CHECK-DNS":
        return service.protocol == "tcp" and (service.port == 53 or name in {"dns", "domain"})
    return True


def dispatch_service_check(checks: Iterable[ServiceCheck], result: HostScanResult, service: PortService) -> ServiceCheck:
    for check in checks:
        if check.matches(service):
            return check
    return UnavailableServiceCheck(
        "NS-CHECK-UNSUPPORTED",
        "Service-specific configuration",
        "No applicable safe check is registered for this service.",
    )
