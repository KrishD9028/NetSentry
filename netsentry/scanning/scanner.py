import time
from dataclasses import replace

from .models import HostScanResult, ScanSummary
from .nmap import NmapClient, NmapScanError
from .profiles import resolve_ports


def scan_target(target: str, *, profile: str = "quick", port_spec: str | None = None, timeout: float = 20.0) -> HostScanResult:
    """Scan a single IPv4 target using a named scan profile or explicit port list."""
    ports = resolve_ports(profile, port_spec)
    result = NmapClient().scan(target, ports, timeout=timeout)
    return replace(result, target=result.target or target, scan_profile=profile, requested_ports=tuple(ports))


def scan_targets(targets: list[str], *, profile: str = "quick", port_spec: str | None = None, timeout: float = 20.0) -> tuple[list[HostScanResult], ScanSummary]:
    """Scan multiple targets and return host results plus a summary."""
    results: list[HostScanResult] = []
    started = time.monotonic()
    for target in targets:
        try:
            result = scan_target(target, profile=profile, port_spec=port_spec, timeout=timeout)
            results.append(result)
        except NmapScanError:
            continue
    duration = time.monotonic() - started
    summary = ScanSummary(
        hosts_scanned=len(results),
        open_ports=sum(host.open_ports for host in results),
        duration_seconds=duration,
    )
    return results, summary
