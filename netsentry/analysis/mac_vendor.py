"""Deterministic local OUI lookup; never perform a network request."""
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class VendorResult:
    mac: str | None
    vendor: str | None
    status: str
    reason: str


def normalize_mac(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not (re.fullmatch(r'(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', value) or
            re.fullmatch(r'[0-9a-fA-F]{12}', value) or re.fullmatch(r'(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}', value)):
        return None
    compact = re.sub(r'[:.\-]', '', value).lower()
    return ':'.join(compact[i:i + 2] for i in range(0, 12, 2))


def lookup_vendor(value, database=None):
    mac = normalize_mac(value)
    if mac is None:
        return VendorResult(None, None, 'INCONCLUSIVE', 'Malformed MAC address; no lookup performed.')
    first = int(mac[:2], 16)
    if first & 1 or mac == '00:00:00:00:00:00':
        return VendorResult(mac, None, 'INCONCLUSIVE', 'Multicast/broadcast or unspecified address is not a device OUI.')
    if first & 2:
        return VendorResult(mac, None, 'INCONCLUSIVE', 'Locally administered address; a manufacturer cannot be inferred from its prefix.')
    if database is None:
        try:
            from scapy.config import conf
            database = conf.manufdb
        except ImportError:
            return VendorResult(mac, None, 'UNSUPPORTED', 'Local Scapy OUI database is unavailable.')
    if database is None:
        return VendorResult(mac, None, 'UNSUPPORTED', 'Local OUI database is unavailable.')
    result = database.lookup(mac)
    values = result if isinstance(result, (tuple, list)) else (result,)
    names = [name.strip() for name in values if isinstance(name, str) and name.strip() and normalize_mac(name) is None and name != 'Unknown']
    vendor = names[-1] if names else None
    if vendor is None:
        return VendorResult(mac, None, 'INCONCLUSIVE', 'Prefix absent from the installed local OUI database; no external lookup performed.')
    return VendorResult(mac, vendor.strip(), 'COMPLETED', 'Installed local OUI database; interface manufacturer does not establish OS identity.')
