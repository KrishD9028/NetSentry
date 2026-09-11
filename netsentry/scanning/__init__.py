"""Service discovery and TCP port scanning support for NetSentry."""

from .models import HostScanResult, PortService, ServiceIdentity
from .nmap import NmapClient, NmapNotInstalledError, NmapScanError, parse_nmap_xml
from .profiles import parse_port_spec, resolve_ports
from .scanner import scan_target, scan_targets

__all__ = [
    "HostScanResult",
    "NmapClient",
    "NmapNotInstalledError",
    "NmapScanError",
    "PortService",
    "ServiceIdentity",
    "parse_nmap_xml",
    "parse_port_spec",
    "resolve_ports",
    "scan_target",
    "scan_targets",
]
