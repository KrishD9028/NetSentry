import socket
import re
import time
from dataclasses import dataclass
from typing import Callable

from .probes import ProbeError


@dataclass(frozen=True, slots=True)
class SSHProbeData:
    banner: str | None
    protocol: str | None
    algorithms: dict[str, tuple[str, ...]]


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


@dataclass(frozen=True, slots=True)
class RDPProbeData:
    protocol_response: bool
    security_layer: str | None = None
    nla: bool | None = None


def _connect(host: str, port: int, timeout: float, socket_factory):
    try:
        return socket_factory((host, port), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        raise ProbeError(f"connection failed: {exc}") from exc


def probe_ssh(host: str, *, port: int = 22, timeout: float = 3.0, socket_factory=socket.create_connection) -> SSHProbeData:
    deadline = time.monotonic() + timeout
    with _connect(host, port, timeout, socket_factory) as connection:
        received = bytearray()
        while len(received) < 4096:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeError("SSH identification timed out")
            connection.settimeout(remaining)
            chunk = connection.recv(4096 - len(received))
            if not chunk:
                break
            received.extend(chunk)
            for line in bytes(received).split(b"\n")[:-1]:
                banner = line.rstrip(b"\r").decode("ascii", errors="replace")
                if re.fullmatch(r"SSH-(?:2\.0|1\.99|1\.5)-[^\s]+(?: [^\r\n]*)?", banner) and len(line) <= 255:
                    return SSHProbeData(banner, banner.split("-", 2)[1], {})
    raise ProbeError("service did not provide a complete SSH identification string")


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
    normalized_transport = transport.lower()
    if normalized_transport == "tcp":
        sock = socket_factory(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(len(query).to_bytes(2, "big") + query)
            prefix = _recv_exact(sock, 2)
            response = _recv_exact(sock, int.from_bytes(prefix, "big"))
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
            response, _ = sock.recvfrom(4096)
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
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x01\x00\x01"


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


def _parse_dns_response(query: bytes, response: bytes, transport: str) -> DNSProbeData:
    if len(response) < 12:
        raise ProbeError("DNS response was malformed")
    if response[0:2] != query[0:2] or not (response[2] & 0x80):
        raise ProbeError("DNS response was not a valid response to the query")
    flags = int.from_bytes(response[2:4], "big")
    response_code = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}.get(flags & 0x000F, f"RCODE-{flags & 0x000F}")
    return DNSProbeData(
        responded=True,
        recursion_available=bool(flags & 0x0080),
        authoritative=bool(flags & 0x0400),
        transport=transport,
        response_code=response_code,
        recursion_requested=bool(query[2] & 0x01),
    )


def probe_rdp(host: str, *, port: int = 3389, timeout: float = 3.0, socket_factory=socket.create_connection) -> RDPProbeData:
    request = bytes.fromhex("030000130ee000000000000100080003000000")
    deadline = time.monotonic() + timeout
    with _connect(host, port, timeout, socket_factory) as connection:
        connection.settimeout(timeout)
        connection.sendall(request)
        header = _recv_exact(connection, 4, "RDP", deadline)
        size = int.from_bytes(header[2:4], "big")
        if header[:2] != b"\x03\x00" or not 11 <= size <= 4096:
            raise ProbeError("service did not provide a valid RDP TPKT header")
        response = header + _recv_exact(connection, size - 4, "RDP", deadline)
    if response[4] != size - 5 or response[5] != 0xD0:
        raise ProbeError("service did not provide an RDP X.224 connection confirm")
    if size > 11 and (size != 19 or response[11] not in {2, 3} or response[13:15] != b"\x08\x00"):
        raise ProbeError("service did not provide a valid RDP negotiation response")
    return RDPProbeData(True)
