from dataclasses import dataclass, field

from ..ip import ip_visibility


@dataclass(frozen=True, slots=True)
class PortService:
    """A single TCP/UDP service result returned by a scanner."""

    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra: str | None = None


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

    @property
    def target_label(self) -> str:
        return ip_visibility(self.target)

    @property
    def open_ports(self) -> int:
        return len(self.services)


@dataclass(frozen=True, slots=True)
class ScanSummary:
    """Summary information for one or more scanned hosts."""

    hosts_scanned: int
    open_ports: int
    duration_seconds: float
