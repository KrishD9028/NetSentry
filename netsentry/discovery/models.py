from dataclasses import dataclass
from ipaddress import IPv4Network

from ..ip import ip_visibility


@dataclass(frozen=True, slots=True)
class NetworkTarget:
    interface: str
    address: str
    network: IPv4Network


@dataclass(frozen=True, slots=True)
class Device:
    ip: str
    mac: str | None
    hostname: str | None
    vendor: str | None

    @property
    def ip_label(self) -> str:
        return ip_visibility(self.ip)
