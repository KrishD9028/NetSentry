from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
import re
import inspect
from dataclasses import asdict, replace

from ..scanning.models import HostScanResult, PortService, ServiceIdentity, PORT_HINTS
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
            service=service.confirmed_service,
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
            service=service.confirmed_service,
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
            service=service.confirmed_service,
            findings=(finding,),
            reason="Check completed with confirmed evidence.",
        )


class ProtocolServiceCheck(ServiceCheck):
    """Collect protocol evidence separately from evaluating security settings."""

    protocol_name: str
    hint_ports: frozenset[int] = frozenset()
    hint_names: frozenset[str] = frozenset()

    def matches(self, service: PortService) -> bool:
        return service.protocol == "tcp" and self.protocol_name in service.confirmed_protocols

    def candidate(self, service: PortService) -> bool:
        if service.state != "open" or service.protocol != "tcp":
            return False
        if self.matches(service):
            return False  # Existing protocol evidence already permits dispatch.
        if service.confirmed_protocols:
            return self.protocol_name == "http" and service.confirmed_protocols == ("tls",)
        hint = (service.service_hint or "").lower()
        if hint in self.hint_names or (self.protocol_name == "http" and hint.startswith("http-")):
            return True
        known_hints = set(PORT_HINTS.values()) | {"dns", "smb", "rdp", "tls", "ssl", "http", "https"}
        if hint in known_hints:
            return False  # A known service hint takes precedence over the port.
        if service.port in self.hint_ports:
            return True
        # Ambiguous endpoints get one bounded SSH banner fallback, not a sweep
        # through all supported protocols. Failed known hints stay unconfirmed.
        return self.protocol_name == "ssh"

    def collect(self, result: HostScanResult, service: PortService):
        options = {"port": service.port}
        if self.protocol_name == "http":
            options["tls"] = "tls" in service.confirmed_protocols or (
                not service.confirmed_protocols and (
                    service.port in {443, 8443} or service.service_hint in {"https", "https-alt", "ssl"}
                )
            )
        elif self.protocol_name == "dns":
            options["transport"] = service.protocol
        elif self.protocol_name == "ssh" and service.port != 22 and service.service_hint != "ssh":
            options["timeout"] = 1.0
        if self.protocol_name in {"ssh", "rdp"}:
            options["enumerate_security"] = True
        # Compatibility with injected probes, without retrying after TypeError.
        parameters = inspect.signature(self.probe).parameters
        if not any(p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values()):
            options = {key: value for key, value in options.items() if key in parameters}
        return self.probe(result.target, **options)

    @abstractmethod
    def protocol_demonstrated(self, data) -> bool:
        """Only positive protocol responses can establish identity."""


def identify_for_checks(checks, result: HostScanResult, service: PortService):
    """Prepare evidence and cache successful probe data for subsequent checks."""
    collected = {}
    attempts = list(service.identification_attempts)
    ordered = sorted(checks, key=lambda check: (
        0 if getattr(check, "protocol_name", None) == "tls" else
        2 if getattr(check, "protocol_name", None) == "ssh" and service.service_hint != "ssh" else 1
    ))
    for check in ordered:
        if not isinstance(check, ProtocolServiceCheck) or not check.candidate(service):
            continue
        try:
            data = check.collect(result, service)
            if not check.protocol_demonstrated(data):
                attempts.append({"protocol": check.protocol_name, "status": "INCONCLUSIVE",
                                 "reason": "Response did not demonstrate the expected protocol.", "evidence": asdict(data)})
                continue
            identity = ServiceIdentity(check.protocol_name, f"NetSentry {check.protocol_name.upper()} probe", asdict(data))
            identities = service.identities + (identity,)
            if check.protocol_name == "http" and data.tls and "tls" not in service.confirmed_protocols:
                identities += (ServiceIdentity("tls", "NetSentry HTTP TLS handshake", {"tls": True}),)
            service = replace(service, identities=identities)
            collected[check] = data
            attempts.append({"protocol": check.protocol_name, "status": "CONFIRMED", "source": identity.source})
        except Exception as exc:
            attempts.append({"protocol": check.protocol_name, "status": "INCONCLUSIVE", "reason": str(exc)})
    return replace(service, identification_attempts=tuple(attempts)), collected


class SMBConfigurationCheck(ProtocolServiceCheck):
    protocol_name = "smb"
    hint_ports = frozenset({445, 139})
    hint_names = frozenset({"smb", "microsoft-ds", "netbios-ssn"})

    def protocol_demonstrated(self, data) -> bool:
        return bool(data.dialect)

    check_id = "NS-CHECK-SMB"
    title = "SMB configuration"

    def __init__(self, probe: Callable[..., SMBProbeData] = probe_smb) -> None:
        self.probe = probe

    def run(self, result: HostScanResult, service: PortService, *, data=None) -> SecurityCheckResult:
        try:
            data = data if data is not None else self.collect(result, service)
        except ProbeError as exc:
            return SecurityCheckResult(self.check_id, self.title, CheckStatus.FAILED, service.port, service.protocol, service.confirmed_service, str(exc))

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
                service=service.confirmed_service,
                evidence="Unauthenticated SMB negotiation reported SMBv1 support.",
                remediation="Disable SMBv1 and require a current SMB dialect where compatibility permits.",
                rule_id=self.check_id,
                evidence_kind="configuration",
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
                service=service.confirmed_service,
                evidence="Unauthenticated SMB negotiate response reported signing as supported but not required.",
                remediation="Require SMB signing where operationally appropriate and restrict SMB exposure.",
                rule_id=self.check_id,
                evidence_kind="configuration",
            ))
        return SecurityCheckResult(
            self.check_id,
            self.title,
            CheckStatus.COMPLETED,
            service.port,
            service.protocol,
            service.confirmed_service,
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


class TLSConfigurationCheck(ProtocolServiceCheck):
    protocol_name = "tls"
    hint_ports = frozenset({443, 8443})
    hint_names = frozenset({"https", "https-alt", "ssl", "tls"})

    def protocol_demonstrated(self, data) -> bool:
        return bool(data.tls_version)

    check_id = "NS-CHECK-TLS"
    title = "TLS configuration"

    def __init__(self, probe: Callable[..., TLSProbeData] = probe_tls) -> None:
        self.probe = probe

    def run(self, result: HostScanResult, service: PortService, *, data=None) -> SecurityCheckResult:
        try:
            data = data if data is not None else self.collect(result, service)
        except ProbeError as exc:
            message = str(exc)
            status = CheckStatus.INCONCLUSIVE if "TLS" in message or "tls" in message else CheckStatus.FAILED
            return SecurityCheckResult(self.check_id, self.title, status, service.port, service.protocol, service.confirmed_service, message)

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
            service.confirmed_service,
            (
                f"TLS handshake completed: version={data.tls_version or 'unknown'}, "
                f"cipher={data.cipher or 'unknown'}, subject={data.subject or 'unknown'}, "
                f"issuer={data.issuer or 'unknown'}, valid_until={data.not_after or 'unknown'}, "
                f"verification={data.verification_result}."
            ),
            tuple(findings),
            {"tls_version": data.tls_version, "cipher": data.cipher, "subject": data.subject, "issuer": data.issuer, "not_before": data.not_before, "not_after": data.not_after, "expired": data.expired, "not_yet_valid": data.not_yet_valid, "verification_result": data.verification_result, "http_status": data.http_status, "security_headers": data.security_headers or {}},
        )


class SSHConfigurationCheck(ProtocolServiceCheck):
    protocol_name = "ssh"
    hint_ports = frozenset({22})
    hint_names = frozenset({"ssh"})

    def protocol_demonstrated(self, data) -> bool:
        return bool(data.banner and re.fullmatch(r"SSH-(?:2\.0|1\.99|1\.5)-[^\s]+(?: [^\r\n]*)?", data.banner))

    check_id = "NS-CHECK-SSH"
    title = "SSH configuration"

    def __init__(self, probe=probe_ssh) -> None:
        self.probe = probe

    def run(self, result: HostScanResult, service: PortService, *, data=None) -> SecurityCheckResult:
        try:
            data = data if data is not None else self.collect(result, service)
        except ProbeError as exc:
            return SecurityCheckResult(self.check_id, self.title, CheckStatus.FAILED, service.port, service.protocol, service.confirmed_service, str(exc))
        findings = []
        policies = (
            ("kex", "diffie-hellman-group1-sha1", "https://www.rfc-editor.org/rfc/rfc9142.html"),
            ("kex", "rsa1024-sha1", "https://www.rfc-editor.org/rfc/rfc9142.html"),
            ("cipher_client_to_server", "arcfour", "https://www.rfc-editor.org/rfc/rfc8758.html"),
            ("cipher_server_to_client", "arcfour", "https://www.rfc-editor.org/rfc/rfc8758.html"),
        )
        policies += tuple((category, algorithm, "https://www.rfc-editor.org/rfc/rfc8758.html")
                          for category in ("cipher_client_to_server", "cipher_server_to_client")
                          for algorithm in ("arcfour128", "arcfour256"))
        if data.enumeration_status == "completed":
            for category, algorithm, reference in policies:
                if algorithm not in data.algorithms.get(category, ()):
                    continue
                findings.append(Finding(
                    f"{self.check_id}:{category}:{algorithm}:{result.target}:{service.port}",
                    f"Obsolete SSH algorithm advertised: {algorithm} ({category})",
                    "The server advertised an obsolete algorithm; this does not establish that a session used it.",
                    Severity.MEDIUM, Confidence.HIGH, result.target,
                    f"Server SSH_MSG_KEXINIT {category} list includes {algorithm}.",
                    "Remove the obsolete algorithm from the server configuration and repeat enumeration.",
                    self.check_id, service.port, service.protocol, service.confirmed_service, (reference,),
                    evidence_kind="configuration", remediation_key="ssh_obsolete_algorithm",
                ))
        complete = data.enumeration_status == "completed" and all(data.algorithms.get(key) for key in (
            "kex", "host_key", "cipher_client_to_server", "cipher_server_to_client", "mac_client_to_server", "mac_server_to_client"))
        return SecurityCheckResult(
            self.check_id, self.title, CheckStatus.COMPLETED if complete else CheckStatus.INCONCLUSIVE,
            service.port, service.protocol, service.confirmed_service,
            data.enumeration_reason, tuple(findings), asdict(data),
        )


class HTTPConfigurationCheck(ProtocolServiceCheck):
    protocol_name = "http"
    hint_ports = frozenset({80, 443, 8080, 8443})
    hint_names = frozenset({"http", "https", "https-alt", "ssl"})

    def protocol_demonstrated(self, data) -> bool:
        return isinstance(data.status, int) and 100 <= data.status <= 599

    check_id = "NS-CHECK-HTTP"
    title = "HTTP security configuration"

    def __init__(self, probe=probe_http) -> None:
        self.probe = probe

    def run(self, result: HostScanResult, service: PortService, *, data=None) -> SecurityCheckResult:
        try:
            data = data if data is not None else self.collect(result, service)
        except ProbeError as exc:
            return SecurityCheckResult(self.check_id, self.title, CheckStatus.FAILED, service.port, service.protocol, service.confirmed_service, str(exc))
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
            service.confirmed_service,
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


class DNSConfigurationCheck(ProtocolServiceCheck):
    protocol_name = "dns"
    hint_ports = frozenset({53})
    hint_names = frozenset({"dns", "domain"})

    def protocol_demonstrated(self, data) -> bool:
        return data.responded is True

    check_id = "NS-CHECK-DNS"
    title = "DNS configuration"

    def __init__(self, probe=probe_dns) -> None:
        self.probe = probe

    def run(self, result: HostScanResult, service: PortService, *, data=None) -> SecurityCheckResult:
        try:
            data = data if data is not None else self.collect(result, service)
        except ProbeError as exc:
            return SecurityCheckResult(self.check_id, self.title, CheckStatus.FAILED, service.port, service.protocol, service.confirmed_service, str(exc))
        advertised = _yes_no_unknown(data.recursion_available).lower()
        return SecurityCheckResult(
            self.check_id, self.title, CheckStatus.INCONCLUSIVE,
            service.port, service.protocol, service.confirmed_service,
            f"Recursion advertised: {advertised}; open recursion not established.",
            (), asdict(data),
        )


class RDPConfigurationCheck(ProtocolServiceCheck):
    protocol_name = "rdp"
    hint_ports = frozenset({3389})
    hint_names = frozenset({"rdp", "ms-wbt-server"})

    def protocol_demonstrated(self, data) -> bool:
        return data.protocol_response is True

    check_id = "NS-CHECK-RDP"
    title = "RDP security negotiation"

    def __init__(self, probe=probe_rdp) -> None:
        self.probe = probe

    def run(self, result: HostScanResult, service: PortService, *, data=None) -> SecurityCheckResult:
        try:
            data = data if data is not None else self.collect(result, service)
        except ProbeError as exc:
            return SecurityCheckResult(self.check_id, self.title, CheckStatus.FAILED, service.port, service.protocol, service.confirmed_service, str(exc))
        return SecurityCheckResult(
            self.check_id, self.title,
            CheckStatus.COMPLETED if data.enumeration_status == "completed" else CheckStatus.INCONCLUSIVE,
            service.port, service.protocol, service.confirmed_service,
            "RDP negotiation evidence collected without authentication; selected protocols describe individual attempts.",
            (), asdict(data),
        )


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
        service=service.confirmed_service,
        evidence=f"TLS handshake succeeded on TCP/{service.port}; certificate validity was evaluated.",
        remediation=remediation,
        rule_id="NS-CHECK-TLS",
        evidence_kind="configuration",
    )


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


def default_service_checks() -> tuple[ServiceCheck, ...]:
    return (
        SSHConfigurationCheck(),
        SMBConfigurationCheck(),
        TLSConfigurationCheck(),
        HTTPConfigurationCheck(),
        DNSConfigurationCheck(),
        RDPConfigurationCheck(),
    )


def default_check_matcher(check_id: str, service: PortService) -> bool:
    return any(check.check_id == check_id and check.matches(service) for check in default_service_checks())


def dispatch_service_check(checks: Iterable[ServiceCheck], result: HostScanResult, service: PortService) -> tuple[ServiceCheck, ...]:
    """Return every applicable check so layered protocols can be assessed together."""
    if service.state != "open" or not service.confirmed_protocols:
        return ()
    return tuple(check for check in checks if check.matches(service))
