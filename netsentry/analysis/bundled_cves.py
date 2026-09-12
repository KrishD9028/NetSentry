"""Load the small reviewed offline catalog; invalid data is never an empty success."""
from datetime import date
from importlib import resources
import json
import re
from urllib.parse import urlsplit

from .correlation import StaticVulnerabilityProvider, VulnerabilityDefinition
from .models import Severity
from .versions import AffectedVersionRange, MatchStatus, match_version

MAX_BYTES = 262144


class DatasetError(ValueError):
    pass


def _object(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise DatasetError("Missing or unsupported dataset fields")
    return value


def _text(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 2048 or any(not c.isprintable() for c in value):
        raise DatasetError("Expected nonempty bounded text")
    return value


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DatasetError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_dataset(text):
    """Return a provider and metadata, validating every definition before use."""
    try:
        if len(text.encode("utf-8")) > MAX_BYTES:
            raise DatasetError("Dataset exceeds size limit")
        data = json.loads(text, object_pairs_hook=_unique_keys)
        _object(data, ("schema_version", "revision", "reviewed", "definition_count", "coverage_notes", "definitions"))
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise DatasetError("Unsupported dataset schema")
        for field in ("revision", "reviewed", "coverage_notes"):
            _text(data[field])
        if date.fromisoformat(data["reviewed"]).isoformat() != data["reviewed"]:
            raise DatasetError("Reviewed date must be YYYY-MM-DD")
        rows = data["definitions"]
        if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
            raise DatasetError("Dataset must contain 1 to 100 definitions")
        if type(data["definition_count"]) is not int or data["definition_count"] != len(rows):
            raise DatasetError("Definition count does not match dataset")
        definitions, seen = [], set()
        for row in rows:
            _object(row, ("cve_id", "product", "source", "reference", "severity", "ranges", "limitations"),
                    ("vendor", "variant"))
            for field in ("cve_id", "product", "source", "reference", "limitations"):
                _text(row[field])
            if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", row["cve_id"]):
                raise DatasetError("Invalid CVE identifier")
            url = urlsplit(row["reference"])
            if url.scheme != "https" or not url.hostname or url.username or url.password:
                raise DatasetError("Reference must be an HTTPS advisory URL")
            for field in ("vendor", "variant"):
                if field in row:
                    _text(row[field])
            key = (row["cve_id"], row["product"].casefold(),
                   row.get("vendor", "").casefold(), row.get("variant", "").casefold())
            if key in seen:
                raise DatasetError("Duplicate vulnerability definition")
            seen.add(key)
            if not isinstance(row["ranges"], list) or not 1 <= len(row["ranges"]) <= 16:
                raise DatasetError("Expected 1 to 16 explicit affected ranges")
            ranges = []
            for raw in row["ranges"]:
                _object(raw, ("scheme",), ("exact", "lower", "upper", "lower_inclusive", "upper_inclusive"))
                for field in ("scheme", "exact", "lower", "upper"):
                    if field in raw:
                        _text(raw[field])
                affected = AffectedVersionRange(**raw)
                sample = affected.exact or affected.lower or affected.upper
                validation = match_version(sample, affected, variant=row.get("variant"))
                if validation.status is MatchStatus.INDETERMINATE:
                    raise DatasetError(f"Invalid range for {row['cve_id']}: {validation.reason}")
                if affected in ranges:
                    raise DatasetError("Duplicate affected range")
                ranges.append(affected)
            definitions.append(VulnerabilityDefinition(
                row["cve_id"], row["product"], tuple(ranges), row["source"],
                reference=row["reference"], vendor=row.get("vendor"), variant=row.get("variant"),
                severity=Severity(row["severity"]), limitations=row["limitations"],
            ))
        return StaticVulnerabilityProvider(definitions), {key: value for key, value in data.items() if key != "definitions"}
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise DatasetError(f"Invalid bundled CVE dataset: {exc}") from exc


def load_bundled_provider():
    try:
        resource = resources.files("netsentry").joinpath("data", "cves.json")
        with resource.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise DatasetError("Dataset exceeds size limit")
        return parse_dataset(raw.decode("utf-8"))
    except (OSError, UnicodeError) as exc:
        raise DatasetError(f"Cannot load bundled CVE dataset: {exc}") from exc
