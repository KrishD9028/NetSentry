"""Bounded RDP negotiation evidence; never enters CredSSP or desktop sessions."""
from dataclasses import dataclass, field
import socket
import ssl
import time

from .probes import ProbeError, certificate_metadata

PROTOCOLS = {0: "RDP", 1: "TLS", 2: "CredSSP", 8: "CredSSP_EX"}
FAILURES = {1: "SSL_REQUIRED_BY_SERVER", 2: "SSL_NOT_ALLOWED_BY_SERVER", 3: "SSL_CERT_NOT_ON_SERVER",
            4: "INCONSISTENT_FLAGS", 5: "HYBRID_REQUIRED_BY_SERVER", 6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"}


@dataclass(frozen=True, slots=True)
class RDPNegotiationAttempt:
    requested_protocols: int
    raw_response: str = ""
    response_type: int | None = None
    flags: int | None = None
    selected_protocol: int | None = None
    failure_code: int | None = None
    status: str = "inconclusive"
    reason: str = ""
    tls_used: bool | None = None
    certificate: dict | None = None
    tls_error: str | None = None
    source: str = "RDP X.224 negotiation"


@dataclass(frozen=True, slots=True)
class RDPProbeData:
    protocol_response: bool
    security_layer: str | None = None
    nla: bool | None = None  # Deprecated; intentionally not assigned new semantics.
    attempts: tuple[RDPNegotiationAttempt, ...] = ()
    nla_available: bool | None = None
    nla_required: bool | None = None
    legacy_accepted: bool | None = None
    tls_used: bool | None = None
    enumeration_status: str = "unavailable"
    contradictions: tuple[str, ...] = ()


def parse_response(requested, response):
    raw = response.hex()
    if len(response) < 11 or len(response) > 4096 or response[:2] != b"\x03\x00" or int.from_bytes(response[2:4], "big") != len(response):
        raise ProbeError("Invalid RDP TPKT framing")
    if response[4] != len(response) - 5 or response[5] != 0xD0:
        raise ProbeError("Invalid RDP X.224 connection confirm")
    if len(response) == 11:
        return RDPNegotiationAttempt(requested, raw, selected_protocol=0, status="completed", reason="Legacy X.224 response without negotiation extension.")
    if len(response) != 19 or response[11] not in {2, 3} or response[13:15] != b"\x08\x00":
        raise ProbeError("Invalid RDP negotiation structure")
    kind, flags, value = response[11], response[12], int.from_bytes(response[15:19], "little")
    if kind == 3:
        return RDPNegotiationAttempt(requested, raw, kind, flags, failure_code=value,
                                     status="completed" if value in FAILURES else "inconclusive",
                                     reason=FAILURES.get(value, "Unknown negotiation failure code"))
    if value not in PROTOCOLS:
        return RDPNegotiationAttempt(requested, raw, kind, flags, value, reason="Unsupported selected protocol value")
    if value and not requested & value:
        return RDPNegotiationAttempt(requested, raw, kind, flags, value, reason="Server selected a protocol not offered by this request")
    return RDPNegotiationAttempt(requested, raw, kind, flags, value, status="completed", reason=f"Selected {PROTOCOLS[value]} for this connection.")


def summarize(attempts):
    valid = [item for item in attempts if item.status == "completed"]
    selected = {item.selected_protocol for item in valid if item.selected_protocol is not None}
    required = any(item.failure_code == 5 for item in valid)
    contradictions = ()
    if required and selected & {0, 1}:
        contradictions = ("CredSSP requirement conflicts with accepted non-CredSSP negotiation.",)
    has_response = any(item.raw_response and (item.response_type in {2, 3} or item.selected_protocol == 0) for item in attempts)
    return RDPProbeData(
        has_response,
        security_layer=PROTOCOLS[next(iter(selected))] if len(selected) == 1 else None,
        attempts=tuple(attempts), nla_available=True if selected & {2, 8} else None,
        nla_required=True if required and not contradictions else None,
        legacy_accepted=True if 0 in selected else None,
        tls_used=True if any(item.tls_used is True for item in attempts) else None,
        enumeration_status="completed" if valid and len(valid) == len(attempts) and not contradictions and not any(item.tls_error for item in attempts) else "inconclusive",
        contradictions=contradictions,
    )


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProbeError("RDP negotiation deadline reached")
    return remaining


def _read(connection, size, deadline):
    if not 0 <= size <= 4096:
        raise ProbeError("RDP read exceeds size limit")
    result = bytearray()
    while len(result) < size:
        connection.settimeout(_remaining(deadline))
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise ProbeError("RDP response ended prematurely")
        result.extend(chunk)
    return bytes(result)


def probe_rdp(host, *, port=3389, timeout=3.0, socket_factory=socket.create_connection,
              enumerate_security=False, context_factory=ssl.create_default_context):
    from dataclasses import replace
    deadline = time.monotonic() + timeout
    attempts = []
    requested = 3
    for _ in range(3):
        raw = b""
        try:
            with socket_factory((host, port), timeout=_remaining(deadline)) as connection:
                connection.settimeout(_remaining(deadline))
                connection.sendall(bytes.fromhex("030000130ee0000000000001000800") + requested.to_bytes(4, "little"))
                raw = _read(connection, 4, deadline)
                length = int.from_bytes(raw[2:4], "big")
                if raw[:2] != b"\x03\x00" or not 11 <= length <= 4096:
                    raise ProbeError("Invalid RDP TPKT header")
                raw += _read(connection, length - 4, deadline)
                attempt = parse_response(requested, raw)
                if enumerate_security and attempt.status == "completed" and attempt.selected_protocol in {1, 2, 8}:
                    try:
                        context = context_factory()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        connection.settimeout(_remaining(deadline))
                        with context.wrap_socket(connection, server_hostname=host) as secure:
                            metadata = certificate_metadata(secure)
                            attempt = replace(attempt, tls_used=True, certificate=metadata,
                                              tls_error=None if metadata.get("subject") else "TLS certificate metadata unavailable")
                    except (OSError, ValueError, ProbeError) as exc:
                        attempt = replace(attempt, tls_error=str(exc))
                attempts.append(attempt)
        except (OSError, ProbeError) as exc:
            attempts.append(RDPNegotiationAttempt(requested, raw.hex(), reason=str(exc)))
        if not enumerate_security:
            if not summarize(attempts).protocol_response:
                raise ProbeError(attempts[-1].reason)
            break
        last = attempts[-1]
        if last.status != "completed":
            break
        if requested == 3 and last.selected_protocol in {2, 8}:
            requested = 1
        elif last.failure_code == 2 and requested != 0:
            requested = 0
        else:
            break
    return summarize(attempts)
