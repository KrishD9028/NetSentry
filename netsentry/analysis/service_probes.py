import socket
import secrets
import re
import time
from dataclasses import dataclass
from typing import Callable

from .probes import ProbeError


from .ssh import SSHProbeData, probe_ssh


@dataclass(frozen=True, slots=True)
class HTTPProbeData:
    status: int | None
    headers: dict[str, str]
    redirect: str | None
    server: str | None
    methods: tuple[str, ...]
    body_prefix: str = ""
    transport: str = "TCP"
    tls: bool = False


@dataclass(frozen=True, slots=True)
class DNSProbeData:
    responded: bool
    recursion_available: bool | None
    authoritative: bool | None
    transport: str = "UDP"
    response_code: str | None = None
    recursion_requested: bool = True
    recursion_demonstrated: bool | None = None
    open_recursion_confirmed: bool | None = None
    query_name: str | None = None
    query_type: int | None = None
    query_class: int | None = None
    answer_count: int = 0
    answers: tuple[dict, ...] = ()
    truncated: bool = False
    raw_response: str | None = None


from .rdp import RDPProbeData, probe_rdp


def _connect(host: str, port: int, timeout: float, socket_factory):
    try:
        return socket_factory((host, port), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        raise ProbeError(f"connection failed: {exc}") from exc


def probe_http(
    host: str,
    *,
    port: int,
    timeout: float = 3.0,
    tls: bool = False,
    socket_factory=socket.create_connection,
    context_factory=__import__("ssl").create_default_context,
) -> HTTPProbeData:
    with _connect(host, port, timeout, socket_factory) as connection:
        connection.settimeout(timeout)
        if tls:
            context = context_factory()
            context.check_hostname = False
            context.verify_mode = __import__("ssl").CERT_NONE
            with context.wrap_socket(connection, server_hostname=host) as secure_connection:
                secure_connection.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                response = secure_connection.recv(16384).decode("iso-8859-1", errors="replace")
        else:
            connection.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            response = connection.recv(16384).decode("iso-8859-1", errors="replace")
    head, _, body = response.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status_line = re.fullmatch(r"HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\r\n]*)?", lines[0]) if lines else None
    if status_line is None:
        raise ProbeError("response was not a valid HTTP status line")
    status = int(status_line[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.lower()] = value.strip()
    methods = ()
    allow_header = headers.get("allow", "")
    methods = tuple(method.strip().upper() for method in allow_header.split(",") if method.strip())
    return HTTPProbeData(
        status,
        headers,
        headers.get("location"),
        headers.get("server"),
        methods,
        body[:256],
        transport="TLS" if tls else "TCP",
        tls=tls,
    )


def probe_dns(
    host: str,
    *,
    port: int = 53,
    timeout: float = 3.0,
    transport: str = "tcp",
    socket_factory=socket.socket,
) -> DNSProbeData:
    """Send a low-impact DNS query using the transport observed by Nmap."""
    query = _dns_query()
    deadline = time.monotonic() + timeout
    normalized_transport = transport.lower()
    if normalized_transport == "tcp":
        sock = socket_factory(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(len(query).to_bytes(2, "big") + query)
            prefix = _recv_exact(sock, 2, deadline=deadline)
            length = int.from_bytes(prefix, "big")
            if not 12 <= length <= 16384:
                raise ProbeError("DNS TCP response length is outside bounds")
            response = _recv_exact(sock, length, deadline=deadline)
        except TimeoutError as exc:
            raise ProbeError(f"DNS TCP query timed out: {exc}") from exc
        except ConnectionResetError as exc:
            raise ProbeError(f"DNS TCP connection reset: {exc}") from exc
        except OSError as exc:
            raise ProbeError(f"DNS TCP connection failed: {exc}") from exc
        finally:
            sock.close()
    elif normalized_transport == "udp":
        sock = socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(query, (host, port))
            response, peer = sock.recvfrom(4096)
            if peer != (host, port):
                raise ProbeError("DNS UDP response came from an unexpected endpoint")
        except TimeoutError as exc:
            raise ProbeError(f"DNS UDP query timed out: {exc}") from exc
        except OSError as exc:
            raise ProbeError(f"DNS UDP query failed: {exc}") from exc
        finally:
            sock.close()
    else:
        raise ProbeError(f"Unsupported DNS transport: {transport}")
    return _parse_dns_response(query, response, normalized_transport.upper())


def _dns_query() -> bytes:
    name = b"\x07example\x03com\x00"
    # RD=1 requests recursion; the query is read-only and has no side effects.
    return secrets.token_bytes(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x01\x00\x01"


def _recv_exact(sock, size: int, protocol: str = "DNS TCP", deadline: float | None = None) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeError(f"{protocol} response timed out")
            sock.settimeout(remaining)
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ProbeError(f"{protocol} connection closed before a complete response was received")
        chunks.extend(chunk)
    return bytes(chunks)


def _dns_name(message: bytes, offset: int):
    """Decode bounded labels/compression; reject cycles and oversized names."""
    labels, visited = [], set()
    end = None
    wire_length = 1
    for _ in range(128):
        if offset >= len(message) or offset in visited:
            raise ProbeError("DNS name is truncated or has a compression loop")
        visited.add(offset)
        size = message[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ProbeError("DNS compression pointer is truncated")
            pointer = ((size & 0x3F) << 8) | message[offset + 1]
            if pointer < 12 or pointer >= offset:
                raise ProbeError("DNS compression pointer is invalid")
            end = end if end is not None else offset + 2
            offset = pointer
            continue
        if size & 0xC0 or offset + 1 + size > len(message):
            raise ProbeError("DNS label is malformed")
        offset += 1
        if size == 0:
            return tuple(labels), end if end is not None else offset
        wire_length += size + 1
        if wire_length > 255:
            raise ProbeError("DNS name exceeds size limit")
        labels.append(message[offset:offset + size].lower())
        offset += size
    raise ProbeError("DNS name exceeds decoding limit")


def _dns_question(message: bytes):
    name, offset = _dns_name(message, 12)
    if offset + 4 > len(message):
        raise ProbeError("DNS question is truncated")
    return (name, int.from_bytes(message[offset:offset + 2], "big"),
            int.from_bytes(message[offset + 2:offset + 4], "big")), offset + 4


def _parse_dns_response(query: bytes, response: bytes, transport: str) -> DNSProbeData:
    if not 12 <= len(response) <= 16384:
        raise ProbeError("DNS response was malformed")
    flags = int.from_bytes(response[2:4], "big")
    if response[:2] != query[:2] or not flags & 0x8000 or flags & 0x7800:
        raise ProbeError("DNS response was not a valid response to the query")
    counts = [int.from_bytes(response[i:i + 2], "big") for i in (4, 6, 8, 10)]
    if counts[0] != 1 or sum(counts[1:]) > 128:
        raise ProbeError("DNS section counts are outside bounds")
    expected, _ = _dns_question(query)
    question, offset = _dns_question(response)
    if question != expected:
        raise ProbeError("DNS response question does not match query")
    answers = []
    for section, count in enumerate(counts[1:]):
        for _ in range(count):
            name, offset = _dns_name(response, offset)
            if offset + 10 > len(response):
                raise ProbeError("DNS resource record is truncated")
            kind = int.from_bytes(response[offset:offset + 2], "big")
            record_class = int.from_bytes(response[offset + 2:offset + 4], "big")
            ttl = int.from_bytes(response[offset + 4:offset + 8], "big")
            length = int.from_bytes(response[offset + 8:offset + 10], "big")
            offset += 10
            if offset + length > len(response):
                raise ProbeError("DNS record data is truncated")
            raw = response[offset:offset + length]
            if kind in {1, 28} and length != (4 if kind == 1 else 16):
                raise ProbeError("DNS address record has invalid length")
            if section == 0:
                answers.append({"name": b".".join(name).decode("ascii", "backslashreplace") + ".",
                                "type": kind, "class": record_class, "ttl": ttl, "rdata_hex": raw.hex()})
            offset += length
    if offset != len(response):
        raise ProbeError("DNS response has unexpected trailing data")
    response_code = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}.get(flags & 0x000F, f"RCODE-{flags & 0x000F}")
    return DNSProbeData(
        responded=True,
        recursion_available=bool(flags & 0x0080),
        authoritative=bool(flags & 0x0400),
        transport=transport,
        response_code=response_code,
        recursion_requested=bool(query[2] & 0x01),
        query_name=b".".join(question[0]).decode("ascii") + ".",
        query_type=question[1], query_class=question[2],
        answer_count=counts[1], answers=tuple(answers),
        truncated=bool(flags & 0x0200), raw_response=response.hex(),
    )
