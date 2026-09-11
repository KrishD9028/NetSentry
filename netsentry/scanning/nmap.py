import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET

from .models import HostScanResult, PortService


class NmapScanError(RuntimeError):
    """Raised when the Nmap command fails or times out."""


class NmapNotInstalledError(NmapScanError):
    """Raised when the nmap binary is not available on the system path."""


def parse_nmap_xml(xml_text: str) -> HostScanResult:
    """Parse Nmap XML output into a structured host result."""
    root = ET.fromstring(xml_text)
    hosts = root.findall("./host")
    if not hosts:
        return HostScanResult(target="", services=[], raw_xml=xml_text)

    host = hosts[0]
    address = host.find("./address")
    target = address.attrib.get("addr") if address is not None else ""

    hostname = None
    hostnames = host.find("./hostnames")
    if hostnames is not None:
        hostname_tag = hostnames.find("./hostname")
        if hostname_tag is not None:
            hostname = hostname_tag.attrib.get("name")

    services: list[PortService] = []
    for port in host.findall("./ports/port"):
        state = port.find("./state")
        if state is None or state.attrib.get("state") != "open":
            continue

        protocol = port.attrib.get("protocol", "tcp")
        port_number = int(port.attrib.get("portid", "0"))
        service_tag = port.find("./service")
        service_name = service_tag.attrib.get("name") if service_tag is not None else None
        product = service_tag.attrib.get("product") if service_tag is not None else None
        version = service_tag.attrib.get("version") if service_tag is not None else None
        extra = service_tag.attrib.get("extrainfo") if service_tag is not None else None

        services.append(
            PortService(
                port=port_number,
                protocol=protocol,
                state="open",
                service=service_name,
                product=product,
                version=version,
                extra=extra,
            )
        )

    return HostScanResult(target=target, hostname=hostname, services=services, raw_xml=xml_text)


class NmapClient:
    """Small wrapper around the system-installed Nmap binary."""

    def __init__(self, binary: str = "nmap") -> None:
        self.binary = binary

    def build_command(self, target: str, ports: list[int], timeout: float = 30.0) -> list[str]:
        try:
            ipaddress.ip_address(target)
        except ValueError as exc:
            raise ValueError(f"Unsupported target {target!r}. Only IPv4 addresses are supported for service scanning.") from exc

        if not ports:
            raise ValueError("Nmap requires at least one port to scan.")

        port_value = ",".join(str(port) for port in ports)
        host_timeout_ms = max(1000, int(timeout * 1000))
        return [
            self.binary,
            "-Pn",
            "-n",
            "-T4",
            "-sT",
            "--host-timeout",
            f"{host_timeout_ms}ms",
            "-oX",
            "-",
            "-p",
            port_value,
            target,
        ]

    def scan(self, target: str, ports: list[int], timeout: float = 30.0) -> HostScanResult:
        if shutil.which(self.binary) is None:
            raise NmapNotInstalledError("Nmap is not installed or not on PATH. Install Nmap to perform service scanning.")

        command = self.build_command(target, ports, timeout=timeout)
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise NmapScanError(f"Nmap timed out while scanning {target!r}.") from exc
        except subprocess.CalledProcessError as exc:
            details = exc.stderr.strip() or exc.stdout.strip() or str(exc)
            raise NmapScanError(f"Nmap failed for {target!r}: {details}") from exc
        except OSError as exc:
            raise NmapScanError(f"Could not execute nmap for target {target!r}.") from exc

        stdout = completed.stdout.strip()
        stderr = completed.stderr.strip()
        if completed.returncode != 0:
            details = stderr or stdout or "unknown nmap failure"
            raise NmapScanError(f"Nmap failed for {target!r}: {details}")

        if not stdout:
            raise NmapScanError(f"Nmap returned no XML output for {target!r}.")

        try:
            return parse_nmap_xml(stdout)
        except ET.ParseError as exc:
            raise NmapScanError(f"Could not parse Nmap XML for {target!r}: {exc}") from exc
