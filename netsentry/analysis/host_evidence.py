"""Identity observations are independent of findings, port states, and risk."""
from dataclasses import asdict, dataclass, field
from enum import Enum

from .models import Confidence


class ResolutionState(str, Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    UNRESOLVED = "UNRESOLVED"
    CONTRADICTORY = "CONTRADICTORY"


ATTRIBUTES = ("hostname", "dns_name", "netbios_name", "netbios_domain", "dns_domain",
              "workgroup", "operating_system", "os_version", "os_edition",
              "candidate_cpe", "mac_address", "mac_vendor")


@dataclass(frozen=True)
class HostObservation:
    attribute: str
    value: str
    source: str
    probe: str
    independence_key: str
    confidence: Confidence = Confidence.MEDIUM
    endpoint: str | None = None
    observed_at: str | None = None
    authoritative: bool = False
    hypothesis: bool = False
    support: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()
    limitations: str | None = None

    def to_dict(self):
        return {**asdict(self), "confidence": self.confidence.value}


@dataclass(frozen=True)
class IdentityProbeResult:
    status: str
    reason: str
    observations: tuple[HostObservation, ...] = ()


@dataclass
class HostEvidence:
    observations: list[HostObservation] = field(default_factory=list)
    attempts: list[dict] = field(default_factory=list)

    def add(self, item):
        if not isinstance(item.value, str) or not item.value.strip() or len(item.value) > 2048:
            return
        key = (item.attribute, item.value, item.source, item.probe, item.endpoint)
        if any((old.attribute, old.value, old.source, old.probe, old.endpoint) == key for old in self.observations):
            return
        self.observations.append(item)

    def resolve(self, attribute):
        items = [item for item in self.observations if item.attribute == attribute]
        values = {}
        for item in items:
            normalized = item.value.rstrip(".").casefold()
            values.setdefault(normalized, []).append(item)
        attempts = [item for item in self.attempts if attribute in item.get("attributes", ())]
        reason = next((item["reason"] for item in attempts if item.get("kind") == "unresolved_goal"),
                      "No unauthenticated source exposed this attribute.")
        state, value, confidence = ResolutionState.UNRESOLVED, None, None
        confirmations = 0
        if len(values) > 1:
            state = ResolutionState.CONTRADICTORY
            reason = "Sources disagree; conflicting observations were retained."
        elif values:
            agreeing = next(iter(values.values()))
            value = agreeing[0].value
            confirmations = len({item.independence_key for item in agreeing if not item.hypothesis})
            reliable_sources = {item.independence_key for item in agreeing
                                if not item.hypothesis and item.confidence in {Confidence.MEDIUM, Confidence.HIGH}}
            proven = any(item.authoritative and not item.hypothesis for item in agreeing) or len(reliable_sources) >= 2
            state = ResolutionState.CONFIRMED if proven else ResolutionState.PROBABLE
            confidence = "HIGH" if proven else "MEDIUM" if any(item.confidence != Confidence.LOW for item in agreeing) else "LOW"
            reason = ("Authoritative observation." if any(item.authoritative and not item.hypothesis for item in agreeing) else "Independent sources agree.") if proven else "Reported identity or hypothesis lacks independent confirmation."
        return {"state": state.value, "value": value, "confidence": confidence,
                "independent_confirmations": confirmations, "reason": reason,
                "observations": [item.to_dict() for item in items],
                "attempts": attempts}

    def to_dict(self):
        return {"attributes": {name: self.resolve(name) for name in ATTRIBUTES},
                "observations": [item.to_dict() for item in self.observations],
                "attempts": list(self.attempts)}


def observation(attribute, value, source, probe, family, endpoint=None, **kwargs):
    return HostObservation(attribute, value, source, probe, family,
                           endpoint=endpoint, **kwargs)


def ntlm_observations(fields, probe, endpoint):
    result = []
    mapping = {"netbios_computer_name": "netbios_name", "dns_computer_name": "dns_name",
               "netbios_domain_name": "netbios_domain", "dns_domain_name": "dns_domain",
               "target_name": "ntlm_target_name", "product_version": "os_version"}
    # Multiple AV pairs in one NTLM challenge are one source, never many votes.
    for key, attribute in mapping.items():
        if fields.get(key):
            result.append(observation(attribute, fields[key], f"NTLM {key}", probe, "rdp_ntlm", endpoint))
            if attribute in {"dns_name", "netbios_name"}:
                result.append(observation("hostname", fields[key].split(".")[0], f"NTLM {key}", probe, "rdp_ntlm", endpoint))
    if fields.get("product_version"):
        result.append(observation("operating_system", "Microsoft Windows", "RDP NTLM reported version (compatible implementations may emulate it)",
                                  probe, "rdp_ntlm", endpoint, hypothesis=True))
        result.append(observation("candidate_cpe", "cpe:/o:microsoft:windows", "Candidate from RDP NTLM version; edition and patch status unverified",
                                  probe, "rdp_ntlm", endpoint, hypothesis=True))
    return tuple(result)
