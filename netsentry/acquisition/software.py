"""Canonical software normalization for acquisition, without fuzzy aliases or CPEs."""
from dataclasses import replace
import re

from ..analysis.correlation import SoftwareEvidence


def normalize_software(item: SoftwareEvidence, *, action_id, source_key, raw_value):
    # Explicit product names only; this table supplies vendors, not product aliases.
    vendors = {'Apache': 'Apache', 'OpenSSH': 'OpenBSD', 'Microsoft-IIS': 'Microsoft', 'Python': 'Python Software Foundation'}
    valid = isinstance(item.version, str) and bool(re.fullmatch(r'[0-9]+(?:\.[0-9]+)*(?:p[0-9]+)?', item.version))
    return replace(item, vendor=item.vendor or vendors.get(item.product), raw_version=item.raw_version or item.version,
                   version=item.version if valid else None, action_id=action_id, raw_value=raw_value,
                   normalization_status='VERSION_OBSERVED' if valid else 'INDETERMINATE', independence_key=source_key,
                   limitations='Self-reported software metadata; installed build, downstream fixes and vulnerable configuration are unverified. No CPE inferred.')
