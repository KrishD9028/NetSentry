"""Bounded SSH identification and pre-authentication KEXINIT enumeration."""
from dataclasses import dataclass
import os
import re
import socket
import struct
import time

from .probes import ProbeError

MAX_PACKET = 35000
MAX_EXCHANGE = 65536
FIELDS = (
    "kex", "host_key", "cipher_client_to_server", "cipher_server_to_client",
    "mac_client_to_server", "mac_server_to_client", "compression_client_to_server",
    "compression_server_to_client", "languages_client_to_server", "languages_server_to_client",
)
EXTENSIONS = {"ext-info-s", "ext-info-c", "kex-strict-s-v00@openssh.com", "kex-strict-c-v00@openssh.com"}


@dataclass(frozen=True, slots=True)
class SSHProbeData:
    banner: str | None
    protocol: str | None
    algorithms: dict[str, tuple[str, ...]]
    enumeration_status: str = "unavailable"
    enumeration_reason: str = "Algorithm enumeration was not performed."
    extensions: tuple[str, ...] = ()
    raw_kexinit: str | None = None
    source: str = "SSH identification and KEXINIT"


class Reader:
    def __init__(self, connection, deadline):
        self.connection = connection
        self.deadline = deadline
        self.buffer = bytearray()
        self.received = 0

    def read(self, size):
        if not 0 <= size <= MAX_PACKET:
            raise ProbeError("SSH read exceeds packet limit")
        while len(self.buffer) < size:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeError("SSH exchange timed out")
            self.connection.settimeout(remaining)
            chunk = self.connection.recv(min(4096, MAX_EXCHANGE - self.received))
            if not chunk:
                raise ProbeError("SSH exchange ended before complete evidence")
            self.received += len(chunk)
            if self.received > MAX_EXCHANGE:
                raise ProbeError("SSH exchange exceeds byte limit")
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def send(self, payload):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("SSH exchange timed out")
        self.connection.settimeout(remaining)
        self.connection.sendall(payload)


def parse_kexinit(payload):
    if len(payload) > MAX_PACKET or len(payload) < 17 or payload[0] != 20:
        raise ProbeError("Invalid SSH KEXINIT message")
    offset = 17
    result = {}
    for field in FIELDS:
        if offset + 4 > len(payload):
            raise ProbeError("Truncated SSH name-list length")
        size = int.from_bytes(payload[offset:offset + 4], "big")
        offset += 4
        if size > 8192 or offset + size > len(payload):
            raise ProbeError("Invalid SSH name-list length")
        raw = payload[offset:offset + size]
        offset += size
        if not raw and not field.startswith("languages"):
            raise ProbeError("Required SSH algorithm list is empty")
        names = raw.split(b",") if raw else []
        if len(names) > 256 or any(not name or len(name) > 256 or any(c < 33 or c > 126 for c in name) for name in names):
            raise ProbeError("Invalid SSH algorithm names")
        result[field] = tuple(name.decode("ascii") for name in names)
    if len(payload) != offset + 5 or payload[offset] not in {0, 1} or payload[offset + 1:] != b"\0" * 4:
        raise ProbeError("Invalid SSH KEXINIT trailer")
    extensions = tuple(name for name in result["kex"] if name in EXTENSIONS)
    result["kex"] = tuple(name for name in result["kex"] if name not in EXTENSIONS)
    if not result["kex"]:
        raise ProbeError("No actual SSH KEX algorithms advertised")
    return result, extensions


def _client_kexinit():
    lists = ("curve25519-sha256", "ssh-ed25519", "aes128-ctr", "aes128-ctr",
             "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", "")
    payload = b"\x14" + os.urandom(16)
    for value in lists:
        encoded = value.encode("ascii")
        payload += struct.pack(">I", len(encoded)) + encoded
    payload += b"\0" * 5
    padding = 8 - ((len(payload) + 5) % 8)
    if padding < 4:
        padding += 8
    return struct.pack(">IB", len(payload) + padding + 1, padding) + payload + os.urandom(padding)


def _enumerate(reader):
    reader.send(b"SSH-2.0-NetSentry\r\n")
    reader.send(_client_kexinit())
    for _ in range(16):
        header = reader.read(5)
        length = int.from_bytes(header[:4], "big")
        padding = header[4]
        if not 12 <= length <= MAX_PACKET or (length + 4) % 8 or padding < 4 or padding >= length - 1:
            raise ProbeError("Invalid SSH packet length or padding")
        body = reader.read(length - 1)
        payload = body[:-padding]
        if payload[0] == 20:
            algorithms, extensions = parse_kexinit(payload)
            return algorithms, extensions, payload.hex()
        if payload[0] not in {2, 4}:  # Only skip bounded IGNORE/DEBUG messages.
            raise ProbeError("SSH exchange ended without KEXINIT")
    raise ProbeError("SSH packet count limit reached")


def probe_ssh(host, *, port=22, timeout=3.0, socket_factory=socket.create_connection, enumerate_security=False):
    deadline = time.monotonic() + timeout
    try:
        with socket_factory((host, port), timeout=timeout) as connection:
            reader = Reader(connection, deadline)
            line = bytearray()
            banner = None
            for _ in range(4096):
                byte = reader.read(1)
                line.extend(byte)
                if byte == b"\n":
                    text = bytes(line).rstrip(b"\r\n").decode("ascii", errors="replace")
                    if len(line) <= 255 and re.fullmatch(r"SSH-(?:2\.0|1\.99|1\.5)-[^\s]+(?: [^\r\n]*)?", text):
                        banner = text
                        break
                    line.clear()
            if banner is None:
                raise ProbeError("service did not provide a complete SSH identification string")
            protocol = banner.split("-", 2)[1]
            if not enumerate_security:
                return SSHProbeData(banner, protocol, {})
            if protocol == "1.5":
                return SSHProbeData(banner, protocol, {}, "inconclusive", "SSH-1.5 advertised; SSHv2 KEXINIT cannot be collected.")
            try:
                algorithms, extensions, raw = _enumerate(reader)
                return SSHProbeData(banner, protocol, algorithms, "completed", "Server KEXINIT advertisements collected; no authentication performed.", extensions, raw)
            except (ProbeError, OSError) as exc:
                return SSHProbeData(banner, protocol, {}, "inconclusive", str(exc))
    except (OSError, TimeoutError) as exc:
        raise ProbeError(f"SSH transport failed: {exc}") from exc
