from collections.abc import Iterable

from ...scanning.models import HostScanResult, PortService
from ..models import Confidence, Finding, Severity
from .base import SecurityRule


def _service_name(service: PortService) -> str:
    return (service.service or "").strip().lower()


def _finding_id(rule_id: str, result: HostScanResult, service: PortService) -> str:
    return f"{rule_id}:{result.target}:{service.protocol}:{service.port}"


def _evidence(service: PortService) -> str:
    identified = f"; service identified as {service.service}" if service.service else "; service was not identified"
    return f"TCP/{service.port} reported open by Nmap{identified}."


def _confidence(service: PortService) -> Confidence:
    return Confidence.HIGH if service.service else Confidence.MEDIUM


def _finding(
    rule_id: str,
    result: HostScanResult,
    service: PortService,
    *,
    title: str,
    description: str,
    severity: Severity,
    remediation: str,
) -> Finding:
    return Finding(
        finding_id=_finding_id(rule_id, result, service),
        title=title,
        description=description,
        severity=severity,
        confidence=_confidence(service),
        host=result.target,
        port=service.port,
        protocol=service.protocol,
        service=service.service,
        evidence=_evidence(service),
        remediation=remediation,
        rule_id=rule_id,
    )


class TelnetRule(SecurityRule):
    rule_id = "NS-001"

    def evaluate(self, result: HostScanResult) -> Iterable[Finding]:
        for service in result.services:
            if service.protocol == "tcp" and (service.port == 23 or _service_name(service) == "telnet"):
                yield _finding(
                    self.rule_id,
                    result,
                    service,
                    title="Telnet service exposed",
                    description="Telnet normally transmits session data without encryption.",
                    severity=Severity.HIGH,
                    remediation="Disable Telnet if unnecessary and use SSH for remote administration.",
                )


class FtpRule(SecurityRule):
    rule_id = "NS-002"

    def evaluate(self, result: HostScanResult) -> Iterable[Finding]:
        for service in result.services:
            if service.protocol == "tcp" and (service.port == 21 or _service_name(service) == "ftp"):
                yield _finding(
                    self.rule_id,
                    result,
                    service,
                    title="FTP service exposed",
                    description="Traditional FTP is unencrypted; this observation does not prove that credentials were exposed.",
                    severity=Severity.MEDIUM,
                    remediation="Use SFTP or FTPS where file transfer is required and restrict access to trusted networks.",
                )


class SmbRule(SecurityRule):
    rule_id = "NS-003"

    def evaluate(self, result: HostScanResult) -> Iterable[Finding]:
        for service in result.services:
            if service.protocol == "tcp" and (service.port == 445 or _service_name(service) in {"microsoft-ds", "smb"}):
                yield _finding(
                    self.rule_id,
                    result,
                    service,
                    title="SMB service exposed",
                    description="SMB exposure increases the host's attack surface and should be reviewed.",
                    severity=Severity.MEDIUM,
                    remediation="Restrict SMB to trusted networks and disable it where it is not required.",
                )


class RdpRule(SecurityRule):
    rule_id = "NS-004"

    def evaluate(self, result: HostScanResult) -> Iterable[Finding]:
        for service in result.services:
            if service.protocol == "tcp" and (service.port == 3389 or _service_name(service) in {"rdp", "ms-wbt-server"}):
                yield _finding(
                    self.rule_id,
                    result,
                    service,
                    title="RDP service exposed",
                    description="Externally or unnecessarily exposed RDP is a high-value attack surface; this does not establish that the host is vulnerable.",
                    severity=Severity.MEDIUM,
                    remediation="Restrict RDP to trusted networks or a VPN, require strong access controls, and disable it when unnecessary.",
                )


DATABASE_SERVICES = {
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "Microsoft SQL Server",
    27017: "MongoDB",
    6379: "Redis",
}


class DatabaseRule(SecurityRule):
    rule_id = "NS-005"

    def evaluate(self, result: HostScanResult) -> Iterable[Finding]:
        for service in result.services:
            database = DATABASE_SERVICES.get(service.port)
            if database is None or service.protocol != "tcp":
                continue
            yield _finding(
                self.rule_id,
                result,
                service,
                title=f"{database} database service exposed",
                description="Database services generally should not be broadly reachable unless explicitly required.",
                severity=Severity.MEDIUM,
                remediation="Restrict database access to approved application hosts and trusted networks.",
            )


class HttpRule(SecurityRule):
    rule_id = "NS-006"

    def evaluate(self, result: HostScanResult) -> Iterable[Finding]:
        for service in result.services:
            name = _service_name(service)
            if service.protocol == "tcp" and name != "https" and (service.port == 80 or name == "http"):
                yield _finding(
                    self.rule_id,
                    result,
                    service,
                    title="Unencrypted HTTP service observed",
                    description="NetSentry observed an HTTP service; it cannot automatically prove that sensitive data is transmitted over it.",
                    severity=Severity.LOW,
                    remediation="Prefer HTTPS with valid TLS configuration for sensitive or authenticated web traffic.",
                )


class UnknownServiceRule(SecurityRule):
    rule_id = "NS-007"

    def evaluate(self, result: HostScanResult) -> Iterable[Finding]:
        for service in result.services:
            if service.protocol == "tcp" and not service.service:
                yield _finding(
                    self.rule_id,
                    result,
                    service,
                    title="Unknown open service",
                    description="An open TCP port was observed, but Nmap did not identify the service.",
                    severity=Severity.INFO,
                    remediation="Identify the service, confirm that it is required, and restrict or disable it when appropriate.",
                )


DEFAULT_RULES = (TelnetRule, FtpRule, SmbRule, RdpRule, DatabaseRule, HttpRule, UnknownServiceRule)
