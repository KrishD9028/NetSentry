import ipaddress
import re
import socket
import subprocess
from ipaddress import IPv4Network

from .models import Device, NetworkTarget


class DiscoveryError(RuntimeError):
    """Raised when local network discovery cannot be completed."""


def _parse_netmask(value: str) -> str:
    if value.startswith("0x"):
        return str(ipaddress.IPv4Address(int(value, 16)))
    return value


def _network_from_address(address: str, netmask: str) -> IPv4Network:
    return ipaddress.IPv4Network(f"{address}/{_parse_netmask(netmask)}", strict=False)


def _default_interface() -> str:
    try:
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise DiscoveryError("Could not determine the default network interface.") from exc

    match = re.search(r"^\s*interface:\s*(\S+)", result.stdout, re.MULTILINE)
    if not match:
        raise DiscoveryError("The default network interface was not reported by route.")
    return match.group(1)


def _available_interfaces() -> list[str]:
    try:
        result = subprocess.run(
            ["ifconfig", "-a"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise DiscoveryError("Could not enumerate available network interfaces.") from exc

    interfaces: list[str] = []
    for line in result.stdout.splitlines():
        match = re.match(r"^(\S+):", line)
        if match:
            interfaces.append(match.group(1))
    return interfaces


def _interface_address(interface: str) -> tuple[str, str]:
    try:
        result = subprocess.run(
            ["ifconfig", interface],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise DiscoveryError(f"Could not inspect interface {interface!r}.") from exc

    match = re.search(
        r"^\s*inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\S+)",
        result.stdout,
        re.MULTILINE,
    )
    if not match:
        raise DiscoveryError(f"Interface {interface!r} has no usable IPv4 address.")
    return match.group(1), _parse_netmask(match.group(2))


def _network_for_interface(interface: str) -> NetworkTarget:
    address, netmask = _interface_address(interface)
    parsed_address = ipaddress.IPv4Address(address)
    if parsed_address.is_loopback:
        raise DiscoveryError(
            f"Interface {interface!r} is a loopback interface ({address}) and cannot be used for LAN discovery."
        )
    return NetworkTarget(
        interface=interface,
        address=address,
        network=_network_from_address(address, netmask),
    )


def get_local_network(interface: str | None = None) -> NetworkTarget:
    if interface:
        return _network_for_interface(interface)

    candidates = [_default_interface()]
    try:
        candidates.extend(_available_interfaces())
    except DiscoveryError:
        pass

    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            return _network_for_interface(candidate)
        except (DiscoveryError, ValueError):
            continue

    raise DiscoveryError("No usable IPv4 network interface was found. Specify --interface manually, for example --interface en0.")


def _hostname_for(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None


def _vendor_for(mac: str) -> str | None:
    locally_administered = _is_locally_administered_mac(mac)
    normalized_mac = mac.lower().replace("-", ":")
    try:
        from scapy.config import conf

        lookup_result = conf.manufdb.lookup(mac)
    except Exception:
        lookup_result = None

    candidates = lookup_result if isinstance(lookup_result, (tuple, list)) else (lookup_result,)
    vendor_names = [
        value.strip()
        for value in candidates
        if isinstance(value, str)
        and value.strip()
        and value.strip().lower().replace("-", ":") != normalized_mac
    ]
    if vendor_names:
        return vendor_names[-1]
    if locally_administered:
        return "Unknown (Private/Randomized MAC)"
    return "Unknown"


def _is_locally_administered_mac(mac: str) -> bool:
    """Return whether the MAC's locally administered bit is set."""
    try:
        first_octet = int(mac.replace("-", ":").split(":", 1)[0], 16)
    except (AttributeError, ValueError):
        return False
    return bool(first_octet & 0x02)


def discover_devices(
    network: IPv4Network,
    interface: str,
    timeout: float = 2.0,
) -> list[Device]:
    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
    except ImportError as exc:
        raise DiscoveryError("Scapy is required for ARP discovery. Install the project dependencies first.") from exc

    try:
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
            iface=interface,
            timeout=timeout,
            verbose=False,
        )
    except (PermissionError, OSError) as exc:
        raise DiscoveryError(
            "ARP discovery requires packet access. On macOS, grant the terminal network permission "
            "or rerun the command with the required privileges."
        ) from exc

    devices = []
    for _, response in answered:
        ip = response.psrc
        mac = response.hwsrc.lower()
        devices.append(
            Device(
                ip=ip,
                mac=mac,
                hostname=_hostname_for(ip),
                vendor=_vendor_for(mac),
            )
        )
    return sorted(devices, key=lambda device: ipaddress.IPv4Address(device.ip))
