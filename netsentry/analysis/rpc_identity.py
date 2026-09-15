"""One bounded unauthenticated endpoint-mapper page, using NDR32 only."""
import socket
import struct
import time
from uuid import UUID

from .host_evidence import IdentityProbeResult, observation
from .identity_probes import read_exact, remaining
from .probes import ProbeError

EPM = UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa").bytes_le + struct.pack("<HH", 3, 0)
NDR = UUID("8a885d04-1ceb-11c9-9fe8-08002b104860").bytes_le + struct.pack("<I", 2)


def pdu(kind, call, body):
    return bytes([5, 0, kind, 3, 0x10, 0, 0, 0]) + struct.pack("<HHI", len(body) + 16, 0, call) + body


def receive(sock, call, kind, deadline):
    header = read_exact(sock, 16, deadline)
    length, auth, returned_call = struct.unpack_from("<HHI", header, 8)
    if header[:2] != b"\x05\0" or header[4:8] != b"\x10\0\0\0" or not 16 <= length <= 16384 or auth or returned_call != call:
        raise ProbeError("Unsupported or malformed RPC header")
    if header[2] != kind or header[3] & 3 != 3:
        raise ProbeError("RPC fault, rejection, or fragmented result; no interface claims made")
    return read_exact(sock, length - 16, deadline)


def bind_accepted(body):
    if len(body) < 10:
        raise ProbeError("Truncated RPC bind acknowledgement")
    secondary_length = int.from_bytes(body[8:10], "little")
    offset = (10 + secondary_length + 3) & ~3
    if offset + 28 != len(body) or body[offset] != 1:
        raise ProbeError("Unsupported RPC bind context results")
    result, reason = struct.unpack_from("<HH", body, offset + 4)
    if result or body[offset + 8:offset + 28] != NDR:
        raise ProbeError("RPC endpoint mapper NDR32 binding rejected")


def parse_tower(data):
    if len(data) < 2:
        raise ProbeError("Truncated endpoint tower")
    count = int.from_bytes(data[:2], "little")
    if not 1 <= count <= 8:
        raise ProbeError("Endpoint tower floor count outside bounds")
    offset, floors = 2, []
    for _ in range(count):
        parts = []
        for _ in range(2):
            if offset + 2 > len(data):
                raise ProbeError("Truncated tower floor length")
            size = int.from_bytes(data[offset:offset + 2], "little")
            offset += 2
            if offset + size > len(data):
                raise ProbeError("Truncated tower floor")
            parts.append(data[offset:offset + size])
            offset += size
        floors.append(parts)
    if offset != len(data):
        raise ProbeError("Trailing tower data")
    left, right = floors[0]
    if len(left) != 19 or left[0] != 13 or len(right) != 2:
        raise ProbeError("Unsupported interface floor")
    interface = str(UUID(bytes_le=left[1:17]))
    version = f"{int.from_bytes(left[17:19], 'little')}.{int.from_bytes(right, 'little')}"
    return interface + " v" + version


def parse_lookup(body):
    if len(body) < 36:
        raise ProbeError("Truncated endpoint lookup response")
    handle = body[:20]
    count, maximum, offset, actual = struct.unpack_from("<IIII", body, 20)
    if count != actual or offset or not 0 <= actual <= maximum <= 8:
        raise ProbeError("Endpoint array exceeds bounds")
    pos, entries = 36, []
    for _ in range(actual):
        if pos + 28 > len(body):
            raise ProbeError("Truncated endpoint entry")
        tower_pointer = int.from_bytes(body[pos + 16:pos + 20], "little")
        annotation_offset, annotation_size = struct.unpack_from("<II", body, pos + 20)
        pos += 28
        if not tower_pointer or annotation_offset or annotation_size > 256 or pos + annotation_size > len(body):
            raise ProbeError("Unsupported endpoint annotation")
        annotation = body[pos:pos + annotation_size].rstrip(b"\0").decode("utf-8", "replace")
        pos = (pos + annotation_size + 3) & ~3
        entries.append({"annotation": annotation})
    for entry in entries:
        if pos + 8 > len(body):
            raise ProbeError("Truncated deferred endpoint tower")
        maximum, size = struct.unpack_from("<II", body, pos)
        pos += 8
        if size != maximum or not 1 <= size <= 4096 or pos + size > len(body):
            raise ProbeError("Endpoint tower exceeds bounds")
        entry["interface"] = parse_tower(body[pos:pos + size])
        pos = (pos + size + 3) & ~3
    if pos + 4 != len(body) or int.from_bytes(body[pos:], "little") not in {0, 0x16C9A0D6}:
        raise ProbeError("Endpoint lookup failed or has unsupported trailing data")
    return handle, entries


def probe_rpc_identity(host, port=135, timeout=3.0, socket_factory=socket.create_connection):
    deadline, items = time.monotonic() + timeout, []
    endpoint = f"{host}:{port}/tcp"
    try:
        with socket_factory((host, port), timeout=remaining(deadline)) as sock:
            sock.settimeout(remaining(deadline))
            bind = struct.pack("<HHI", 4280, 4280, 0) + b"\x01\0\0\0" + b"\0\0\x01\0" + EPM + NDR
            sock.sendall(pdu(11, 1, bind))
            bind_accepted(receive(sock, 1, 12, deadline))
            items.append(observation("confirmed_service", "DCE/RPC endpoint mapper", "Accepted endpoint-mapper bind",
                                     "rpc_identity", "rpc", endpoint))
            stub = struct.pack("<IIII", 0, 0, 0, 1) + bytes(20) + struct.pack("<I", 8)
            sock.settimeout(remaining(deadline))
            sock.sendall(pdu(0, 2, struct.pack("<IHH", len(stub), 0, 2) + stub))
            response = receive(sock, 2, 2, deadline)
            if len(response) < 8 or response[4:6] != bytes(2):
                raise ProbeError("Invalid RPC response context")
            handle, entries = parse_lookup(response[8:])
            for entry in entries:
                items.append(observation("rpc_interface", entry["interface"], "Endpoint mapper tower",
                                         "rpc_identity", "rpc", endpoint))
                if entry["annotation"]:
                    items.append(observation("rpc_annotation", entry["annotation"], "Endpoint mapper annotation",
                                             "rpc_identity", "rpc", endpoint))
            if handle != bytes(20):
                # Release enumeration context; never walk an unbounded inventory.
                sock.settimeout(remaining(deadline))
                sock.sendall(pdu(0, 3, struct.pack("<IHH", 20, 0, 4) + handle))
                receive(sock, 3, 2, deadline)
        return IdentityProbeResult("COMPLETED", "One endpoint-mapper page (at most 8 entries); no OS edition inferred.", tuple(items))
    except (OSError, ProbeError) as exc:
        return IdentityProbeResult("INCONCLUSIVE", str(exc), tuple(items))
