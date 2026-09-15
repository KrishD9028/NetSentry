"""Bounded wire fixtures; all transports are in memory, with no live targets."""
import struct
from unittest.mock import patch

import pytest

from netsentry.analysis import identity_probes as ip
from netsentry.analysis.probes import ProbeError


class Stream:
    def __init__(self, data=b""):
        self.data = data
        self.sent = []
        self.timeouts = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, value):
        self.timeouts.append(value)

    def recv(self, count):
        value, self.data = self.data[:count], self.data[count:]
        return value

    def sendall(self, data):
        self.sent.append(data)


def av(kind, value):
    raw = value.encode('utf-16-le') if isinstance(value, str) else value
    return struct.pack('<HH', kind, len(raw)) + raw


def challenge(pairs=None, target='LAB', version=True):
    pairs = pairs if pairs is not None else av(1, 'HOST') + av(2, 'LAB') + av(3, 'host.lab.test') + av(4, 'lab.test') + bytes(4)
    raw_target = target.encode('utf-16-le')
    size = 56 if version else 48
    header = bytearray(size)
    header[:12] = b'NTLMSSP\0\x02\0\0\0'
    struct.pack_into('<HHI', header, 12, len(raw_target), len(raw_target), size)
    struct.pack_into('<I', header, 20, 1 | (0x02000000 if version else 0))
    struct.pack_into('<HHI', header, 40, len(pairs), len(pairs), size + len(raw_target))
    if version:
        header[48:56] = bytes([10, 0]) + struct.pack('<H', 19045) + bytes(3) + b'\x0f'
    return bytes(header) + raw_target + pairs


def overwrite(data, offset, value):
    return data[:offset] + value + data[offset + len(value):]


def test_ntlm_names_version_and_same_response_independence():
    fields = ip.parse_ntlm_challenge(challenge())
    assert fields == dict(target_name='LAB', product_version='10.0.19045', netbios_computer_name='HOST', netbios_domain_name='LAB', dns_computer_name='host.lab.test', dns_domain_name='lab.test')
    observations = ip.ntlm_observations(fields, 'rdp_identity', '192.0.2.1:3389/tcp')
    assert {item.independence_key for item in observations} == {'rdp_ntlm'}
    assert sum(item.attribute == 'hostname' for item in observations) == 2


def test_ntlm_identical_duplicates_and_absent_version():
    fields = ip.parse_ntlm_challenge(challenge(av(1, 'HOST') * 2 + bytes(4), version=False))
    assert fields['netbios_computer_name'] == 'HOST'
    assert 'product_version' not in fields


@pytest.mark.parametrize('data', [
    b'', challenge()[:47], overwrite(challenge(), 0, b'BAD'),
    overwrite(challenge(), 8, struct.pack('<I', 3)),
    overwrite(challenge(), 20, bytes(4)), challenge()[:50],
    overwrite(challenge(), 12, struct.pack('<HHI', 4, 2, 56)),
    overwrite(challenge(), 12, struct.pack('<HHI', 4, 4, 55)),
    overwrite(challenge(), 12, struct.pack('<HHI', 4, 4, 9999)),
    overwrite(challenge(), 12, struct.pack('<HHI', 4097, 4097, 56)),
    overwrite(challenge(), 12, struct.pack('<HHI', 3, 3, 56)),
    challenge(av(1, b'\x00\xd8') + bytes(4)),
    challenge(av(1, b'x') + bytes(4)),
    challenge(av(1, 'ONE') + av(1, 'TWO') + bytes(4)),
    challenge(b'\x01\x00\xff\x00a'), challenge(av(1, 'HOST')),
    challenge(b'\x00\x00\x01\x00x'), challenge(bytes(8)),
    challenge(av(99, b'') * 64 + bytes(4)), challenge() + bytes(8193),
])
def test_ntlm_rejects_invalid_packets(data):
    with pytest.raises(ProbeError):
        ip.parse_ntlm_challenge(data)


def test_every_ntlm_truncation_is_bounded():
    data = challenge()
    for length in range(len(data)):
        with pytest.raises(ProbeError):
            ip.parse_ntlm_challenge(data[:length])


def frame(token):
    return ip.der(0x30, ip.der(0xA1, ip.der(0x30, ip.der(0x30, ip.der(0xA0, ip.der(4, token))))))


def test_nested_credssp_token():
    data = frame(challenge())
    assert ip.ntlm_token(data) == challenge()
    assert ip.read_der(Stream(data), float('inf')) == data


@pytest.mark.parametrize('data', [b'0', b'0\x80', b'0\x83\x00\x00\x01a', b'0\x82\x01', b'0\x05x', ip.der(0x30, b'\x02\x01\x06'), b'0\x82\x20\x01' + bytes(8193), ip.der(0x30, ip.der(4, challenge()) + b'\x01')])
def test_der_rejects_malformed_missing_or_oversized_token(data):
    with pytest.raises(ProbeError):
        ip.ntlm_token(data)


def test_der_excessive_nesting_and_duplicate_tokens():
    data = ip.der(4, challenge())
    for _ in range(10):
        data = ip.der(0x30, data)
    with pytest.raises(ProbeError, match='nesting'):
        ip.ntlm_token(data)
    with pytest.raises(ProbeError, match='Multiple'):
        ip.ntlm_token(ip.der(0x30, ip.der(4, challenge()) * 2))


@pytest.mark.parametrize('data', [b'', b'0', b'0\x80', b'0\x83\0\0\x01x', b'0\x82\x20\x01', b'\x04\x01a', b'0\x02a'])
def test_read_der_rejects_bad_frames(data):
    with pytest.raises(ProbeError):
        ip.read_der(Stream(data), float('inf'))


def node_query():
    name = b'*' + bytes(15)
    encoded = bytes(65 + nibble for byte in name for nibble in (byte >> 4, byte & 15))
    return b'\x12\x34\0\0\0\x01' + bytes(6) + b'\x20' + encoded + b'\0\0\x21\0\x01'


def node_response(query=None, mac=b'\x00\x11\x22\x33\x44\x55', count=2):
    query = query or node_query()
    names = b'HOST'.ljust(15, b' ') + b'\x20\0\0' + b'WORKGROUP'.ljust(15, b' ') + b'\0\x80\0'
    data = bytes([count]) + names + mac
    return query[:2] + b'\x84\x00\0\x01\0\x01' + bytes(4) + query[12:] + b'\xc0\x0c' + struct.pack('>HHIH', 0x21, 1, 0, len(data)) + data


def test_node_status_names_workgroup_mac():
    names, mac = ip.parse_node_status(node_query(), node_response())
    assert names == [('HOST', 0x20, False), ('WORKGROUP', 0, True)]
    assert mac == '00:11:22:33:44:55'


@pytest.mark.parametrize('mac', [bytes(6), b'\xff' * 6])
def test_node_status_ignores_placeholder_mac(mac):
    assert ip.parse_node_status(node_query(), node_response(mac=mac))[1] is None


@pytest.mark.parametrize('data', [
    overwrite(node_response(), 0, b'\xff\xff'), overwrite(node_response(), 2, b'\0\0'),
    overwrite(node_response(), 2, b'\x84\x02'), overwrite(node_response(), 8, b'\0\x01'),
    overwrite(node_response(), 12, b'\xff'), overwrite(node_response(), 13, b'Z'),
    overwrite(node_response(), len(node_query()), b'\xc0\xff'),
    overwrite(node_response(), len(node_query()) + 2, b'\0\x20'),
    overwrite(node_response(), len(node_query()) + 4, b'\0\x02'),
    overwrite(node_response(), len(node_query()) + 10, b'\xff\xff'),
    node_response(count=65), node_response()[:-1],
])
def test_node_status_rejects_invalid(data):
    with pytest.raises(ProbeError):
        ip.parse_node_status(node_query(), data)


def test_node_status_all_truncations():
    for length in range(len(node_response())):
        with pytest.raises(ProbeError):
            ip.parse_node_status(node_query(), node_response()[:length])


class Datagram(Stream):
    peer = ('192.0.2.1', 137)

    def sendto(self, data, peer):
        self.query = data
        self.sent.append(peer)

    def recvfrom(self, limit):
        assert limit == 4096
        return node_response(self.query), self.peer


def test_netbios_probe_observations_and_ipv4_transport():
    sock = Datagram()
    def factory(family, kind):
        assert family == ip.socket.AF_INET and kind == ip.socket.SOCK_DGRAM
        return sock
    result = ip.probe_netbios_identity('192.0.2.1', socket_factory=factory)
    assert result.status == 'COMPLETED'
    assert {item.attribute for item in result.observations} == {'hostname', 'netbios_name', 'workgroup', 'mac_address'}
    assert {item.independence_key for item in result.observations} == {'netbios'}


def test_netbios_rejects_unexpected_source():
    sock = Datagram()
    sock.peer = ('192.0.2.2', 137)
    with pytest.raises(ProbeError, match='unexpected endpoint'):
        ip.probe_netbios_identity('192.0.2.1', socket_factory=lambda *args: sock)


class TLSContext:
    def __init__(self, stream):
        self.stream = stream
    def wrap_socket(self, sock, server_hostname):
        return self.stream


def rdp_negotiation():
    return bytes.fromhex('030000130ed000000000000200080002000000')


@pytest.mark.parametrize('certificate_error', [False, True])
def test_rdp_stops_after_challenge_and_retains_ntlm_when_certificate_fails(certificate_error):
    plain, secure = Stream(rdp_negotiation()), Stream(frame(challenge()))
    with patch.object(ip, 'certificate_metadata', side_effect=ValueError('bad certificate') if certificate_error else None, return_value={'subject': 'HOST'}):
        result = ip.probe_rdp_identity('192.0.2.1', socket_factory=lambda *args, **kwargs: plain, context_factory=lambda: TLSContext(secure))
    assert result.status == ('INCONCLUSIVE' if certificate_error else 'COMPLETED')
    assert any(item.attribute == 'os_version' and item.value == '10.0.19045' for item in result.observations)
    assert len(plain.sent) == len(secure.sent) == 1
    sent = ip.ntlm_token(secure.sent[0])
    assert sent[:12] == b'NTLMSSP\0\x01\0\0\0'  # NEGOTIATE only, never AUTHENTICATE.
    assert sent[16:32] == bytes(16)  # No supplied domain or workstation.
    assert all(0 < value <= 3 for value in plain.timeouts + secure.timeouts)


def test_rdp_preserves_certificate_after_malformed_challenge():
    plain, secure = Stream(rdp_negotiation()), Stream(frame(b'NTLMSSP\0bad'))
    with patch.object(ip, 'certificate_metadata', return_value={'subject': 'HOST'}):
        result = ip.probe_rdp_identity('192.0.2.1', socket_factory=lambda *args, **kwargs: plain, context_factory=lambda: TLSContext(secure))
    assert result.status == 'INCONCLUSIVE'
    assert any(item.attribute == 'hostname' for item in result.observations)


def test_rdp_transport_failure_and_deadline_are_structured():
    def timeout(*args, **kwargs):
        raise TimeoutError('remote timeout')
    assert ip.probe_rdp_identity('192.0.2.1', socket_factory=timeout).status == 'INCONCLUSIVE'
    assert ip.probe_rdp_identity('192.0.2.1', timeout=0, socket_factory=timeout).status == 'INCONCLUSIVE'


def test_netbios_deadline_includes_send_time():
    sock = Datagram()
    with patch.object(ip.time, 'monotonic', side_effect=[10, 11, 12]):
        with pytest.raises(ProbeError, match='deadline'):
            ip.probe_netbios_identity('192.0.2.1', timeout=2, socket_factory=lambda *args: sock)
    assert len(sock.sent) == 1


@pytest.mark.parametrize('probe', [ip.probe_rdp_identity, ip.probe_netbios_identity])
def test_transport_factory_programmer_errors_are_not_hidden(probe):
    def broken(*args, **kwargs):
        raise ValueError('programmer error')
    with pytest.raises(ValueError, match='programmer error'):
        probe('192.0.2.1', socket_factory=broken)
