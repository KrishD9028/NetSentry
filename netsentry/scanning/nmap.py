from dataclasses import replace
import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET

from .models import HostScanResult, PortService, ServiceIdentity, service_protocols
from .profiles import parse_port_spec


class NmapScanError(RuntimeError):
    """Raised when the Nmap command fails or times out."""


class NmapNotInstalledError(NmapScanError):
    """Raised when the nmap binary is not available on the system path."""


def normalize_port_state(state: str | None, reason: str | None) -> tuple[str, str]:
    """Interpret TCP evidence conservatively while keeping Nmap's values intact."""
    if state in {"open", "closed"}:
        return state, f"Nmap reported {state}" + (f" ({reason})." if reason else ".")
    if state == "filtered" and reason in {"admin-prohibited", "host-prohibited", "net-prohibited"}:
        return "filtered", f"Nmap reported explicit traffic prohibition ({reason})."
    return "unknown", f"Nmap reported {state or 'no state'} ({reason or 'no reason'}); insufficient evidence to determine port state."


def _port_result(number: int, protocol: str, state: dict, service: dict | None = None, *, source: str = "Nmap XML port") -> PortService:
    service = service or {}
    raw_state, raw_reason = state.get("state"), state.get("reason")
    normalized, explanation = normalize_port_state(raw_state, raw_reason)
    identities = ()
    # Nmap table lookups (normally conf=3) and missing provenance stay hints.
    if normalized == "open" and service.get("method") == "probed" and service.get("conf") == "10":
        identities = tuple(
            ServiceIdentity(name, "Nmap service probe", dict(service))
            for name in service_protocols(service.get("name"), service.get("tunnel"))
        )
    return PortService(
        port=number, protocol=protocol, state=normalized,
        service=service.get("name"), product=service.get("product"),
        version=service.get("version"), extra=service.get("extrainfo"),
        scanner_state=raw_state, scanner_reason=raw_reason, scanner_source=source,
        state_reason=explanation, service_method=service.get("method"),
        service_confidence=service.get("conf"), service_tunnel=service.get("tunnel"),
        identities=identities,
    )


def _unknown_port(number: int, reason: str) -> PortService:
    return PortService(number, "tcp", "unknown", state_reason=reason, scan_observed=False)


def parse_nmap_xml(xml_text: str, requested_ports: tuple[int, ...] = ()) -> HostScanResult:
    """Preserve explicit and unambiguously attributable grouped TCP evidence."""
    root = ET.fromstring(xml_text)
    if not requested_ports:
        scaninfo = root.find("./scaninfo[@protocol='tcp']")
        if scaninfo is not None and scaninfo.get("services"):
            requested_ports = tuple(parse_port_spec(scaninfo.attrib["services"]))
    host = root.find("./host")
    if host is None:
        return HostScanResult(
            target="", services=[_unknown_port(p, "No host/port result was returned; testing is unverified.") for p in requested_ports],
            raw_xml=xml_text, requested_ports=requested_ports, probe_status="incomplete",
        )
    address = host.find("./address[@addrtype='ipv4']")
    if address is None:
        address = host.find("./address")
    target = address.get("addr", "") if address is not None else ""
    hostname_tag = host.find("./hostnames/hostname")
    hostname = hostname_tag.get("name") if hostname_tag is not None else None
    services = []
    for port in host.findall("./ports/port"):
        state = port.find("./state")
        service = port.find("./service")
        services.append(_port_result(
            int(port.attrib["portid"]), port.get("protocol", "tcp"),
            dict(state.attrib) if state is not None else {},
            dict(service.attrib) if service is not None else {},
        ))

    summaries = tuple(
        {**group.attrib, "reasons": [dict(item.attrib) for item in group.findall("./extrareasons")]}
        for group in host.findall("./ports/extraports")
    )
    explicit = {item.port for item in services if item.protocol == "tcp"}
    remaining = set(requested_ports) - explicit
    attributed: dict[int, list[PortService]] = {}
    for group in summaries:
        if sum(int(reason.get("count", "0")) for reason in group["reasons"]) != int(group.get("count", "0")):
            continue
        for reason in group["reasons"]:
            if not reason.get("ports") or reason.get("proto") != "tcp":
                continue
            numbers = parse_port_spec(reason["ports"])
            if len(numbers) != int(reason.get("count", "0")):
                continue
            if requested_ports and not set(numbers) <= set(requested_ports):
                continue
            for number in numbers:
                attributed.setdefault(number, []).append(_port_result(
                    number, "tcp", {"state": group.get("state"), "reason": reason.get("reason")},
                    source="Nmap XML extrareasons ports",
                ))
    for number, candidates in attributed.items():
        if number not in explicit and len(candidates) == 1:
            services.append(candidates[0])
            remaining.discard(number)

    # Older Nmap versions omit the ranges. Infer only one group covering exactly
    # the remainder, with no mixed protocols or competing group membership.
    tcp_only = all(item.protocol == "tcp" for item in services) and all(
        item.get("protocol") == "tcp" for item in root.findall("./scaninfo")
    )
    if (len(summaries) == 1 and not attributed and remaining and tcp_only
            and all(not reason.get("ports") and reason.get("proto") in {None, "tcp"} for reason in summaries[0]["reasons"])):
        group = summaries[0]
        if int(group.get("count", "0")) == len(remaining):
            reasons = group["reasons"]
            raw_reason = None
            if len(reasons) == 1 and int(reasons[0].get("count", "0")) == len(remaining):
                raw_reason = reasons[0].get("reason")
            # A mixed set of reasons cannot be assigned to particular ports.
            for number in sorted(remaining):
                services.append(_port_result(number, "tcp", {"state": group.get("state"), "reason": raw_reason}, source="Nmap XML extraports remainder"))
            remaining.clear()

    services.extend(_unknown_port(p, "No attributable port result; the requested port may not have been tested.") for p in sorted(remaining))
    status = host.find("./status")
    reachability = None
    if any(item.state in {"open", "closed"} for item in services):
        reachability = True
    elif status is not None and status.get("state") == "up" and status.get("reason") not in {None, "user-set"}:
        reachability = True
    finished = root.find("./runstats/finished")
    incomplete = bool(remaining) or host.get("timedout") == "true" or (finished is not None and finished.get("exit") == "error")
    return HostScanResult(
        target=target, hostname=hostname, services=sorted(services, key=lambda item: (item.port, item.protocol)),
        raw_xml=xml_text, requested_ports=requested_ports, reachability=reachability,
        probe_status="incomplete" if incomplete else "completed", port_summary=summaries,
    )


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
            raw = exc.stdout or ""
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            try:
                result = parse_nmap_xml(raw, tuple(ports))
            except ET.ParseError:
                result = HostScanResult(
                    target=target, raw_xml=raw or None, requested_ports=tuple(ports),
                    services=[_unknown_port(p, "Scanner timed out; no complete per-port evidence is available.") for p in ports],
                )
            return replace(result, target=result.target or target, probe_status="timeout")
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
            return parse_nmap_xml(stdout, tuple(ports))
        except ET.ParseError as exc:
            raise NmapScanError(f"Could not parse Nmap XML for {target!r}: {exc}") from exc
