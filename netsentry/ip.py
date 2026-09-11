import ipaddress
from enum import Enum


class IPClassification(str, Enum):
    PRIVATE = "Private"
    SHARED_CGNAT = "Shared/CGNAT"
    LOOPBACK = "Loopback"
    LINK_LOCAL = "Link-local"
    MULTICAST = "Multicast"
    RESERVED = "Reserved/Special-use"
    PUBLIC = "Public"


RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
SHARED_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


def classify_ip(address: str) -> IPClassification:
    """Classify an IP address without treating every non-private address as public."""
    parsed = ipaddress.ip_address(address)
    if any(parsed in network for network in RFC1918_NETWORKS):
        return IPClassification.PRIVATE
    if parsed in SHARED_CGNAT_NETWORK:
        return IPClassification.SHARED_CGNAT
    if parsed.is_loopback:
        return IPClassification.LOOPBACK
    if parsed.is_link_local:
        return IPClassification.LINK_LOCAL
    if parsed.is_multicast:
        return IPClassification.MULTICAST
    if parsed.is_reserved or parsed.is_unspecified or not parsed.is_global:
        return IPClassification.RESERVED
    return IPClassification.PUBLIC


def ip_visibility(address: str) -> str:
    """Return a display label for an IP address classification."""
    classification = classify_ip(address)
    if classification is IPClassification.PRIVATE:
        return "Private IP"
    if classification is IPClassification.SHARED_CGNAT:
        return "Shared/CGNAT IP"
    if classification is IPClassification.PUBLIC:
        return "Public IP"
    return f"{classification.value} IP"


def labeled_ip(address: str) -> str:
    """Return an IPv4 address with its private/public classification."""
    return f"{ip_visibility(address)}: {address}"