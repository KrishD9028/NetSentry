"""Bounded unauthenticated identity requests; no credential response is sent."""
import secrets
import socket
import ssl
import struct
import time

from .host_evidence import IdentityProbeResult, observation, ntlm_observations
from .probes import ProbeError, certificate_metadata
from .rdp import parse_response
from .service_probes import _dns_name


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise ProbeError("Identity probe deadline reached")
    return value


def read_exact(sock, count, deadline):
    if not 0 <= count <= 16384:
        raise ProbeError("Identity response exceeds read limit")
    data = bytearray()
    while len(data) < count:
        sock.settimeout(remaining(deadline))
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ProbeError("Identity response ended prematurely")
        data.extend(chunk)
    return bytes(data)


def der(tag, value):
    size = len(value)
    length = bytes([size]) if size < 128 else b"\x82" + size.to_bytes(2, "big")
    return bytes([tag]) + length + value


def read_der(sock, deadline):
    header = read_exact(sock, 2, deadline)
    size = header[1]
    if size & 128:
        count = size & 127
        if count not in {1, 2}:
            raise ProbeError("Unsupported ASN.1 length")
        header += read_exact(sock, count, deadline)
        size = int.from_bytes(header[2:], "big")
    if header[0] != 0x30 or size > 8192:
        raise ProbeError("Invalid CredSSP frame")
    return header + read_exact(sock, size, deadline)


def ntlm_token(frame):
    """Find an NTLM OCTET STRING through bounded ASN.1 containers."""
    if len(frame) > 8196:
        raise ProbeError("CredSSP frame exceeds limit")
    def walk(data, depth):
        if depth > 8:
            raise ProbeError("CredSSP nesting exceeds limit")
        offset, token = 0, None
        while offset < len(data):
            if offset + 2 > len(data):
                raise ProbeError("Truncated ASN.1 field")
            tag, size = data[offset:offset + 2]
            offset += 2
            if size & 128:
                count = size & 127
                if count not in {1, 2} or offset + count > len(data):
                    raise ProbeError("Invalid ASN.1 length")
                size = int.from_bytes(data[offset:offset + count], "big")
                offset += count
            if offset + size > len(data):
                raise ProbeError("Truncated ASN.1 payload")
            payload = data[offset:offset + size]
            offset += size
            if tag == 4 and payload.startswith(b"NTLMSSP\0"):
                if token is not None:
                    raise ProbeError("Multiple NTLM tokens")
                token = payload
            if tag & 0x20:
                found = walk(payload, depth + 1)
                if found is not None:
                    if token is not None:
                        raise ProbeError("Multiple NTLM tokens")
                    token = found
        return token
    token = walk(frame, 0)
    if token is None:
        raise ProbeError("No NTLM challenge returned")
    return token


def parse_ntlm_challenge(data):
    if not 48 <= len(data) <= 8192 or data[:12] != b"NTLMSSP\0\x02\0\0\0":
        raise ProbeError("Invalid NTLM challenge")
    flags = int.from_bytes(data[20:24], "little")
    if not flags & 1:
        raise ProbeError("Non-Unicode NTLM identity unsupported")
    header = 56 if flags & 0x02000000 else 48
    if len(data) < header:
        raise ProbeError("NTLM version field is truncated")
    def buffer(offset):
        size, maximum, start = struct.unpack_from("<HHI", data, offset)
        if size > maximum or size > 4096 or (size and (start < header or start + size > len(data))):
            raise ProbeError("NTLM security buffer is outside bounds")
        return data[start:start + size] if size else b""
    def decode(value):
        if len(value) % 2:
            raise ProbeError("Invalid NTLM Unicode length")
        try:
            return value.decode("utf-16-le").rstrip("\0")
        except UnicodeError as exc:
            raise ProbeError("Invalid NTLM Unicode") from exc
    result = {"target_name": decode(buffer(12))}
    if flags & 0x02000000:
        result["product_version"] = f"{data[48]}.{data[49]}.{int.from_bytes(data[50:52], 'little')}"
    av = buffer(40)
    offset = 0
    names = {1: "netbios_computer_name", 2: "netbios_domain_name", 3: "dns_computer_name", 4: "dns_domain_name", 5: "dns_tree_name"}
    for _ in range(64):
        if offset == len(av) and not av:
            break
        if offset + 4 > len(av):
            raise ProbeError("Truncated NTLM target information")
        kind, length = struct.unpack_from("<HH", av, offset)
        offset += 4
        if offset + length > len(av):
            raise ProbeError("Truncated NTLM AV pair")
        if kind == 0:
            if length or offset != len(av):
                raise ProbeError("Invalid NTLM target information terminator")
            break
        if kind in names:
            name, value = names[kind], decode(av[offset:offset + length])
            if name in result and result[name] != value:
                raise ProbeError("Contradictory duplicate NTLM AV pair")
            result[name] = value
        offset += length
    else:
        raise ProbeError("Too many NTLM AV pairs")
    return result


def certificate_observations(metadata, endpoint, probe):
    subject = metadata.get("subject")
    if not subject:
        return ()
    items = [observation("tls_certificate_identity", subject, "TLS certificate subject", probe, "tls_certificate", endpoint)]
    # A CN is a reported identity, not a verified host name or OS.
    import re
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", subject):
        items.append(observation("hostname", subject.rstrip(".").split(".")[0], "TLS certificate CN", probe, "tls_certificate", endpoint))
    return tuple(items)


def probe_rdp_identity(host, port=3389, timeout=3.0, socket_factory=socket.create_connection, context_factory=ssl.create_default_context):
    deadline = time.monotonic() + timeout
    observations = []
    certificate_reason = None
    endpoint = f"{host}:{port}/tcp"
    try:
        with socket_factory((host, port), timeout=remaining(deadline)) as sock:
            sock.settimeout(remaining(deadline))
            sock.sendall(bytes.fromhex("030000130ee0000000000001000800") + (11).to_bytes(4, "little"))
            header = read_exact(sock, 4, deadline)
            length = int.from_bytes(header[2:], "big")
            if not 11 <= length <= 4096:
                raise ProbeError("Invalid RDP identity negotiation length")
            attempt = parse_response(11, header + read_exact(sock, length - 4, deadline))
            if attempt.status != "completed" or attempt.selected_protocol not in {2, 8}:
                return IdentityProbeResult("UNSUPPORTED", "Server did not select CredSSP; NTLM identity not requested.")
            context = context_factory()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock.settimeout(remaining(deadline))
            with context.wrap_socket(sock, server_hostname=host) as secure:
                try:
                    observations.extend(certificate_observations(certificate_metadata(secure), endpoint, "rdp_identity"))
                except (OSError, ValueError) as exc:
                    # Certificate extraction must not discard the NTLM opportunity.
                    certificate_reason = str(exc)
                flags = 0xA2888207  # Unicode, target info, NTLM, extended security; no credentials.
                negotiate = b"NTLMSSP\0" + struct.pack("<II", 1, flags) + bytes(16) + bytes([10, 0, 0, 0, 0, 0, 0, 15])
                request = der(0x30, der(0xA0, der(2, b"\x06")) +
                              der(0xA1, der(0x30, der(0x30, der(0xA0, der(4, negotiate))))))
                secure.settimeout(remaining(deadline))
                secure.sendall(request)
                fields = parse_ntlm_challenge(ntlm_token(read_der(secure, deadline)))
                observations.extend(ntlm_observations(fields, "rdp_identity", endpoint))
        return IdentityProbeResult("INCONCLUSIVE" if certificate_reason else "COMPLETED",
                                   "NTLM challenge collected; no AUTHENTICATE message or credentials sent." +
                                   (f" Certificate metadata unavailable: {certificate_reason}" if certificate_reason else ""), tuple(observations))
    except (OSError, ProbeError) as exc:
        return IdentityProbeResult("INCONCLUSIVE", str(exc), tuple(observations))


def parse_node_status(query, response):
    if len(response) < 12 or response[:2] != query[:2]:
        raise ProbeError("NetBIOS transaction does not match")
    flags, qcount, answers = struct.unpack_from(">HHH", response, 2)
    if not flags & 0x8000 or flags & 0x020F or flags & 0x7800 or qcount > 1 or answers != 1 or response[8:12] != bytes(4):
        raise ProbeError("Invalid NetBIOS node-status response")
    offset = 12
    if qcount:
        name, offset = _dns_name(response, offset)
        expected, _ = _dns_name(query, 12)
        if name != expected or response[offset:offset + 4] != b"\x00\x21\x00\x01":
            raise ProbeError("NetBIOS question mismatch")
        offset += 4
    answer_name, offset = _dns_name(response, offset)
    expected, _ = _dns_name(query, 12)
    if (answer_name != expected or not answer_name or len(answer_name[0]) != 32
            or any(byte not in b"abcdefghijklmnop" for byte in answer_name[0])):
        raise ProbeError("Invalid NetBIOS encoded answer name")
    if offset + 10 > len(response):
        raise ProbeError("Truncated NetBIOS record")
    kind, cls, ttl, size = struct.unpack_from(">HHIH", response, offset)
    offset += 10
    if kind != 0x21 or cls != 1 or size < 7 or offset + size != len(response):
        raise ProbeError("Invalid NetBIOS node-status record")
    data = response[offset:]
    count = data[0]
    if count > 64 or 1 + count * 18 + 6 > len(data):
        raise ProbeError("NetBIOS names exceed record bounds")
    names = []
    for index in range(count):
        entry = data[1 + index * 18:1 + (index + 1) * 18]
        try:
            name = entry[:15].decode("ascii", "strict").rstrip(" \0")
        except UnicodeError as exc:
            raise ProbeError("Invalid NetBIOS name encoding") from exc
        names.append((name, entry[15], bool(int.from_bytes(entry[16:], "big") & 0x8000)))
    mac = data[1 + count * 18:7 + count * 18]
    return names, ":".join(f"{byte:02x}" for byte in mac) if mac not in {bytes(6), b"\xff" * 6} else None


def probe_netbios_identity(host, port=137, timeout=2.0, socket_factory=socket.socket):
    deadline = time.monotonic() + timeout
    name = b"*" + bytes(15)
    encoded = bytes(65 + nibble for byte in name for nibble in (byte >> 4, byte & 15))
    query = secrets.token_bytes(2) + b"\x00\x00\x00\x01" + bytes(6) + b"\x20" + encoded + b"\x00\x00\x21\x00\x01"
    with socket_factory(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(remaining(deadline))
        sock.sendto(query, (host, port))
        sock.settimeout(remaining(deadline))
        response, peer = sock.recvfrom(4096)
    if peer != (host, port):
        raise ProbeError("NetBIOS response came from unexpected endpoint")
    names, mac = parse_node_status(query, response)
    items = []
    endpoint = f"{host}:{port}/udp"
    for value, suffix, group in names:
        if not value:
            continue
        if group and suffix == 0:
            items.append(observation("workgroup", value, "NetBIOS group name", "netbios_identity", "netbios", endpoint))
        elif not group and suffix in {0, 0x20}:
            for attribute in ("netbios_name", "hostname"):
                items.append(observation(attribute, value, "NetBIOS node status", "netbios_identity", "netbios", endpoint))
    if mac:
        items.append(observation("mac_address", mac, "NetBIOS node-status unit ID (may be virtual)", "netbios_identity", "netbios", endpoint))
    return IdentityProbeResult("COMPLETED", "Node status collected over UDP/137; TCP/139 state was not reinterpreted.", tuple(items))
