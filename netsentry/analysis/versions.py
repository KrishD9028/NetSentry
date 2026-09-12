"""Explicit bounded version schemes. Unsupported inputs never match positively."""
from dataclasses import dataclass
from enum import Enum
import re


class MatchStatus(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True)
class VersionMatch:
    status: MatchStatus
    reason: str


@dataclass(frozen=True, slots=True)
class AffectedVersionRange:
    scheme: str
    exact: str | None = None
    lower: str | None = None
    lower_inclusive: bool = True
    upper: str | None = None
    upper_inclusive: bool = False


def _text(value):
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError("Missing, malformed, or oversized version")
    return value


def _numbers(value):
    parts = value.split(".")
    if len(parts) > 16 or any(not re.fullmatch(r"0|[1-9][0-9]{0,15}", item) for item in parts):
        raise ValueError("Unsupported numeric version")
    numbers = tuple(int(item) for item in parts)
    return numbers + (0,) * (16 - len(numbers))


def _parse(value, scheme, variant):
    value = _text(value)
    if scheme == "numeric":
        return _numbers(value)
    if scheme == "semver":
        match = re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?", value)
        if not match:
            raise ValueError("Not strict SemVer")
        release = _numbers(".".join(match.group(i) for i in (1, 2, 3)))
        prerelease = []
        for section in (match[4], match[5]):
            if section is not None and (len(section.split(".")) > 16 or any(not item for item in section.split("."))):
                raise ValueError("Invalid SemVer identifiers")
        if match[4]:
            for item in match[4].split("."):
                if item.isdigit():
                    if len(item) > 16 or (len(item) > 1 and item[0] == "0"):
                        raise ValueError("Invalid SemVer numeric prerelease")
                    prerelease.append((0, int(item)))
                else:
                    prerelease.append((1, item))
        # Build metadata is preserved by the caller but ignored in precedence.
        return release, (0, tuple(prerelease)) if prerelease else (1, ())
    if scheme == "openssh":
        if variant not in {"upstream", "portable", "windows"}:
            raise ValueError("OpenSSH variant must be explicit")
        match = re.fullmatch(r"(0|[1-9][0-9]{0,15})\.(0|[1-9][0-9]{0,15})(?:p(0|[1-9][0-9]{0,15}))?", value)
        if not match or (variant == "portable") != (match[3] is not None):
            raise ValueError("Version is incompatible with the specified OpenSSH variant")
        return int(match[1]), int(match[2]), int(match[3] or 0)
    if scheme == "opaque":
        return value
    raise ValueError("Unsupported version scheme")


def match_version(observed, affected: AffectedVersionRange, *, variant=None):
    try:
        if not isinstance(affected, AffectedVersionRange):
            raise ValueError("A structured affected-version range is required")
        if not isinstance(affected.lower_inclusive, bool) or not isinstance(affected.upper_inclusive, bool):
            raise ValueError("Range inclusivity flags must be booleans")
        actual = _parse(observed, affected.scheme, variant)
        if affected.exact is not None:
            if affected.lower is not None or affected.upper is not None:
                raise ValueError("Exact version cannot be combined with bounds")
            expected = _parse(affected.exact, affected.scheme, variant)
            matches = actual == expected
        else:
            if affected.scheme == "opaque":
                raise ValueError("Opaque versions only support explicit exact matching")
            if affected.lower is None and affected.upper is None:
                raise ValueError("At least one explicit version bound is required")
            lower = _parse(affected.lower, affected.scheme, variant) if affected.lower is not None else None
            upper = _parse(affected.upper, affected.scheme, variant) if affected.upper is not None else None
            if lower is not None and upper is not None and (lower > upper or (lower == upper and not (affected.lower_inclusive and affected.upper_inclusive))):
                raise ValueError("Invalid or empty version interval")
            matches = (lower is None or actual > lower or (affected.lower_inclusive and actual == lower)) and (
                upper is None or actual < upper or (affected.upper_inclusive and actual == upper))
        return VersionMatch(MatchStatus.MATCH if matches else MatchStatus.NO_MATCH, "Version satisfies the explicit range." if matches else "Version is outside the explicit range.")
    except (ValueError, TypeError) as exc:
        return VersionMatch(MatchStatus.INDETERMINATE, str(exc))
