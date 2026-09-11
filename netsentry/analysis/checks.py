from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
import re

from ..scanning.models import HostScanResult, PortService
from .models import CheckStatus, Confidence, Finding, SecurityCheckResult, Severity
from .probes import ProbeError, SMBProbeData, TLSProbeData, probe_smb, probe_tls
from .service_probes import DNSProbeData, HTTPProbeData, RDPProbeData, SSHProbeData, probe_dns, probe_http, probe_rdp, probe_ssh


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


class SMBConfigurationCheck(ServiceCheck):
    check_id = "NS-CHECK-SMB"
    title = "SMB configuration"

    def __init__(self, probe: Callable[..., SMBProbeData] = probe_smb) -> None:
        self.probe = probe

    def matches(self, service: PortService) -> bool:
        return service.protocol == "tcp" and (service.port == 445 or _service_name(service) in {"smb", "microsoft-ds"})

    def run(self, result: HostScanResult, service: PortService) -> SecurityCheckResult:
        try:
            data = self.probe(result.target, port=service.port)
        except ProbeError as exc:
            return SecurityCheckResult(self.check_id, self.title, CheckStatus.FAILED, service.port, service.protocol, service.service, str(exc))

        findings: list[Finding] = []
        if data.smb1_supported is True:
            findings.append(Finding(
                finding_id=f"{self.check_id}:SMB1:{result.target}:{service.port}",
                title="SMBv1 supported",
                description="The SMB probe reported support for the obsolete SMBv1 dialect.",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                host=result.target,
                port=service.port,
                protocol=service.protocol,
                service=service.service,
                evidence="Unauthenticated SMB negotiation reported SMBv1 support.",
                remediation="Disable SMBv1 and require a current SMB dialect where compatibility permits.",
                rule_id=self.check_id,
            ))
        if data.signing_required is False:
            findings.append(Finding(
                finding_id=f"{self.check_id}:SIGNING:{result.target}:{service.port}",
                title="SMB signing is not required",
                description="The SMB negotiate response did not require message signing.",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                host=result.target,
                port=service.port,
                protocol=service.protocol,
                service=service.service,
                evidence="Unauthenticated SMB negotiate response reported signing as supported but not required.",
                remediation="Require SMB signing where operationally appropriate and restrict SMB exposure.",
                rule_id=self.check_id,
            ))
        return SecurityCheckResult(
            self.check_id,
            self.title,
            CheckStatus.COMPLETED,
            service.port,
            service.protocol,
            service.service,
            (
                "SMB negotiate completed without authentication. "
                f"Dialect: {data.dialect or 'unknown'}; "
                f"SMBv1 supported: {_yes_no_unknown(data.smb1_supported)}; "
                f"Signing supported: {_yes_no_unknown(data.signing_supported)}; "
                f"Signing required: {_yes_no_unknown(data.signing_required)}; "
                f"Authentication: {data.authentication_status}."
            ),
            tuple(findings),
            {"dialect": data.dialect, "smb1_supported": data.smb1_supported, "signing_supported": data.signing_supported, "signing_required": data.signing_required, "identity": data.identity, "authentication_status": data.authentication_status},
        )


class TLSConfigurationCheck(ServiceCheck):
    check_id = "NS-CHECK-TLS"
    title = "TLS configuration"

    def __init__(self, probe: Callable[..., TLSProbeData] = probe_tls) -> None:
        self.probe = probe

    def matches(self, service: PortService) -> bool:
        return service.protocol == "tcp" and (service.port in {443, 8443} or _service_name(service) in {"https", "ssl", "https-alt"})

    def run(self, result: HostScanResult, service: PortService) -> SecurityCheckResult:
        try:
            data = self.probe(result.target, port=service.port)
        except ProbeError as exc:
            message = str(exc)
            status = CheckStatus.INCONCLUSIVE if "TLS" in message or "tls" in message else CheckStatus.FAILED
            return SecurityCheckResult(self.check_id, self.title, status, service.port, service.protocol, service.service, message)

        findings: list[Finding] = []
        if data.expired is True:
            findings.append(_tls_finding(result, service, "Expired TLS certificate", "The TLS certificate was expired when probed.", "Replace the certificate with a current certificate before relying on TLS for trust.", data))
        if data.not_yet_valid is True:
            findings.append(_tls_finding(result, service, "TLS certificate is not yet valid", "The TLS certificate validity window has not started.", "Install a certificate whose validity period includes the current time.", data))
        return SecurityCheckResult(
            self.check_id,
            self.title,
            CheckStatus.COMPLETED,
            service.port,
            service.protocol,
            service.service,
            (
                f"TLS handshake completed: version={data.tls_version or 'unknown'}, "
                f"cipher={data.cipher or 'unknown'}, subject={data.subject or 'unknown'}, "
                f"issuer={data.issuer or 'unknown'}, valid_until={data.not_after or 'unknown'}, "
                f"verification={data.verification_result}."
            ),
            tuple(findings),
            {"tls_version": data.tls_version, "cipher": data.cipher, "subject": data.subject, "issuer": data.issuer, "not_before": data.not_before, "not_after": data.not_after, "expired": data.expired, "not_yet_valid": data.not_yet_valid, "verification_result": data.verification_result, "http_status": data.http_status, "security_headers": data.security_headers or {}},
        )


class SSHConfigurationCheck(ServiceCheck):
    check_id = "NS-CHECK-SSH"
    title = "SSH configuration"

    def __init__(self, probe=probe_ssh) -> None:
        self.probe = probe

    def matches(self, service: PortService) -> bool:
        return service.protocol == "tcp" and (service.port == 22 or _service_name(service) == "ssh")

    def run(self, result: HostScanResult, service: PortService) -> SecurityCheckResult:
        try:
            data: SSHProbeData = self.probe(result.target, port=service.port)
        except ProbeError as exc:
            return SecurityCheckResult(self.check_id, self.title, CheckStatus.FAILED, service.port, service.protocol, service.service, str(exc))
        return SecurityCheckResult(self.check_id, self.title, CheckStatus.COMPLETED, service.port, service.protocol, service.service, f"SSH banner: {data.banner or 'unavailable'}", (), {"banner": data.banner, "protocol": data.protocol, "algorithms": data.algorithms})


class HTTPConfigurationCheck(ServiceCheck):
    check_id = "NS-CHECK-HTTP"
    title = "HTTP security configuration"

    def __init__(self, probe=probe_http) -> None:
        self.probe = probe

    def matches(self, service: PortService) -> bool:
        name = _service_name(service)
        return service.protocol == "tcp" and (
            service.port == 80
            or service.port in {443, 8443}
            or name in {"http", "http-proxy", "http-alt", "http-api"}
            or name in {"https", "https-alt", "ssl"}
            or name.startswith("http-")
        )

    def run(self, result: HostScanResult, service: PortService) -> SecurityCheckResult:
        try:
            is_tls = service.port in {443, 8443} or _service_name(service) in {"https", "https-alt", "ssl"}
            try:
                data: HTTPProbeData = self.probe(result.target, port=service.port, tls=is_tls)
            except TypeError:
                data = self.probe(result.target, port=service.port)
        except ProbeError as exc:
            return SecurityCheckResult(self.check_id, self.title, CheckStatus.FAILED, service.port, service.protocol, service.service, str(exc))
        missing = [header for header in ("x-content-type-options", "content-security-policy", "referrer-policy") if header not in data.headers]
        selected_headers = {
            name: data.headers[name]
            for name in (
                "server",
                "location",
                "content-type",
                "strict-transport-security",
                "content-security-policy",
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
            )
            if name in data.headers
        }
        server_product, server_version = _server_fingerprint(data.server)
        return SecurityCheckResult(
            self.check_id,
            self.title,
            CheckStatus.COMPLETED,
            service.port,
            service.protocol,
            service.service,
            f"Transport: {'TLS' if data.tls else 'plaintext TCP'}; HTTP response: Valid; status={data.status}; Server={data.server or 'unreported'}",
            (),
            {
                "status": data.status,
                "transport": data.transport,
                "tls": data.tls,
                "headers": data.headers,
                "selected_headers": selected_headers,
                "redirect": data.redirect,
                "server": data.server,
                "fingerprint": {
                    "product": server_product,
                    "version": server_version,
                    "source": "HTTP Server header",
                    "confidence": "HIGH" if server_product and server_version else "MEDIUM" if server_product else "LOW",
                },
                "methods": data.methods,
                "missing_security_headers": missing,
            },
        )


class DNSConfigurationCheck(ServiceCheck):
    check_id = "NS-CHECK-DNS"
    title = "DNS configuration"

    def __init__(self, probe=probe_dns) -> None:
        self.probe = probe

    def matches(self, service: PortService) -> bool:
        return service.protocol == "tcp" and (service.port == 53 or _service_name(service) in {"dns", "domain"})

    def run(self, result: HostScanResult, service: PortService) -> SecurityCheckResult:
        try:
            try:
                data: DNSProbeData = self.probe(result.target, port=service.port, transport=service.protocol)
            except TypeError:
                # Keep compatibility with injected probes written before transport was explicit.
                data = self.probe(result.target, port=service.port)
        except ProbeError as exc:
            return SecurityCheckResult(self.check_id, self.title, CheckStatus.FAILED, service.port, service.protocol, service.service, str(exc))
        findings = ()
        if data.recursion_available is True:
            findings = (Finding(f"{self.check_id}:RECURSION:{result.target}:{service.port}", "Open DNS recursion confirmed", "The DNS response indicated recursion is available.", Severity.MEDIUM, Confidence.MEDIUM, result.target, "DNS response set the recursion-available flag.", "Restrict recursion to authorized clients and trusted networks.", self.check_id, service.port, service.protocol, service.service),)
        return SecurityCheckResult(
            self.check_id,
            self.title,
            CheckStatus.COMPLETED,
            service.port,
            service.protocol,
            service.service,
            (
                f"Transport tested: {data.transport}; DNS response: Valid; "
                f"recursion requested: {'Yes' if data.recursion_requested else 'No'}; "
                f"recursion available: {_yes_no_unknown(data.recursion_available)}; "
                f"response code: {data.response_code or 'Unknown'}."
            ),
            findings,
            {
                "responded": data.responded,
                "transport": data.transport,
                "recursion_requested": data.recursion_requested,
                "recursion_available": data.recursion_available,
                "authoritative": data.authoritative,
                "response_code": data.response_code,
            },
        )


class RDPConfigurationCheck(ServiceCheck):
    check_id = "NS-CHECK-RDP"
    title = "RDP security negotiation"

    def __init__(self, probe=probe_rdp) -> None:
        self.probe = probe

    def matches(self, service: PortService) -> bool:
        return service.protocol == "tcp" and (service.port == 3389 or _service_name(service) in {"rdp", "ms-wbt-server"})

    def run(self, result: HostScanResult, service: PortService) -> SecurityCheckResult:
        try:
            data: RDPProbeData = self.probe(result.target, port=service.port)
        except ProbeError as exc:
            return SecurityCheckResult(self.check_id, self.title, CheckStatus.FAILED, service.port, service.protocol, service.service, str(exc))
        return SecurityCheckResult(self.check_id, self.title, CheckStatus.COMPLETED, service.port, service.protocol, service.service, "RDP negotiation response received without authentication.", (), {"protocol_response": data.protocol_response, "security_layer": data.security_layer, "nla": data.nla})


def _tls_finding(result: HostScanResult, service: PortService, title: str, description: str, remediation: str, data: TLSProbeData) -> Finding:
    return Finding(
        finding_id=f"NS-CHECK-TLS:{title}:{result.target}:{service.port}",
        title=title,
        description=description,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        host=result.target,
        port=service.port,
        protocol=service.protocol,
        service=service.service,
        evidence=f"TLS handshake succeeded on TCP/{service.port}; certificate validity was evaluated.",
        remediation=remediation,
        rule_id="NS-CHECK-TLS",
    )


def _service_name(service: PortService) -> str:
    return (service.service or "").lower()


def _yes_no_unknown(value: bool | None) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unknown"


def _server_fingerprint(server: str | None) -> tuple[str | None, str | None]:
    if not server:
        return None, None
    products = []
    for token in server.split():
        match = re.match(r"([^/\s]+)/([^/\s]+)$", token)
        if match:
            products.append((match.group(1), match.group(2)))
    if not products:
        return server, None
    return ", ".join(product for product, _ in products), ", ".join(version for _, version in products)


def _port_or_name(port: int, names: set[str]):
    return lambda service: service.protocol == "tcp" and (service.port == port or _service_name(service) in names)


def default_service_checks() -> tuple[ServiceCheck, ...]:
    return (
        SMBConfigurationCheck(),
        TLSConfigurationCheck(),
        SSHConfigurationCheck(),
        HTTPConfigurationCheck(),
        DNSConfigurationCheck(),
        RDPConfigurationCheck(),
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


def dispatch_service_check(checks: Iterable[ServiceCheck], result: HostScanResult, service: PortService) -> tuple[ServiceCheck, ...]:
    """Return every applicable check so layered protocols can be assessed together."""
    return tuple(check for check in checks if check.matches(service))
