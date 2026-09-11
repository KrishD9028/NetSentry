from dataclasses import dataclass, field

from ..ip import ip_visibility


PORT_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1723: "pptp", 3306: "mysql", 3389: "ms-wbt-server", 5900: "vnc",
    8080: "http-alt", 8443: "https-alt",
}


def service_protocols(name: str | None, tunnel: str | None = None) -> tuple[str, ...]:
    """Normalize an identified name, never a port number, into protocol layers."""
    name = (name or "").lower()
    if not name or name == "unknown":
        return ()
    if name in {"https", "https-alt"}:
        return ("tls", "http")
    if name in {"ssl", "tls"}:
        return ("tls",)
    aliases = {"microsoft-ds": "smb", "domain": "dns", "ms-wbt-server": "rdp"}
    protocol = "http" if name.startswith("http-") else aliases.get(name, name)
    return ("tls", protocol) if tunnel == "ssl" else (protocol,)


@dataclass(frozen=True, slots=True)
class ServiceIdentity:
    protocol: str
    source: str
    evidence: dict
    confidence: str = "HIGH"


@dataclass(frozen=True, slots=True)
class PortService:
    """Port evidence; the legacy service field is a label, not proof of identity."""

    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra: str | None = None
    scanner_state: str | None = None
    scanner_reason: str | None = None
    scanner_source: str | None = None
    state_reason: str = ""
    scan_observed: bool = True
    service_method: str | None = None
    service_confidence: str | None = None
    service_tunnel: str | None = None
    identities: tuple[ServiceIdentity, ...] = ()
    identification_attempts: tuple[dict, ...] = ()

    @property
    def service_hint(self) -> str | None:
        return (self.service if self.service and self.service != "unknown" else None) or (PORT_HINTS.get(self.port) if self.protocol == "tcp" else None)

    @property
    def confirmed_protocols(self) -> tuple[str, ...]:
        if self.state != "open":
            return ()
        return tuple(dict.fromkeys(item.protocol for item in self.identities if item.confidence == "HIGH" and item.source and item.evidence))

    @property
    def confirmed_service(self) -> str | None:
        protocols = self.confirmed_protocols
        if "http" in protocols and "tls" in protocols:
            return "https"
        return next((name for name in protocols if name != "tls"), "tls" if protocols else None)

    @property
    def identification_status(self) -> str:
        return "CONFIRMED" if self.confirmed_service else "HINT" if self.service_hint else "UNKNOWN"


@dataclass(frozen=True, slots=True)
class HostScanResult:
    """Structured results for an individual host scan."""

    target: str
    hostname: str | None = None
    services: list[PortService] = field(default_factory=list)
    raw_xml: str | None = None
    scan_profile: str = "unspecified"
    requested_ports: tuple[int, ...] = ()
    reachability: bool | None = None
    probe_status: str = "completed"
    port_summary: tuple[dict, ...] = ()

    @property
    def target_label(self) -> str:
        return ip_visibility(self.target)

    @property
    def open_ports(self) -> int:
        return sum(service.state == "open" for service in self.services)


@dataclass(frozen=True, slots=True)
class ScanSummary:
    """Summary information for one or more scanned hosts."""

    hosts_scanned: int
    open_ports: int
    duration_seconds: float
