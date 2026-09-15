"""DCE/RPC NDR32 fixtures exercise the single-page endpoint mapper boundary."""
import struct
from uuid import UUID

import pytest

from netsentry.analysis import rpc_identity as rpc
from netsentry.analysis.probes import ProbeError
from tests.test_identity_parsers import Stream, overwrite


def bind_ack(result=0):
    # frag lengths, association, empty secondary address, alignment, one result.
    return struct.pack('<HHIH', 4280, 4280, 0, 0) + bytes(2) + b'\x01\0\0\0' + struct.pack('<HH', result, 0) + rpc.NDR


def tower():
    left = b'\x0d' + UUID('12345678-1234-abcd-ef00-0123456789ab').bytes_le + struct.pack('<H', 1)
    return b'\x01\0' + struct.pack('<H', len(left)) + left + b'\x02\0\x00\0'


def lookup(annotation=b'test interface\0', handle=bytes(20)):
    result = handle + struct.pack('<IIII', 1, 8, 0, 1)
    result += bytes(16) + struct.pack('<III', 0x20000, 0, len(annotation)) + annotation
    result += bytes(-len(result) % 4)
    result += struct.pack('<II', len(tower()), len(tower())) + tower()
    result += bytes(-len(result) % 4)
    return result + bytes(4)


def test_rpc_valid_bind_and_receive():
    assert rpc.bind_accepted(bind_ack()) is None
    assert rpc.receive(Stream(rpc.pdu(12, 1, bind_ack())), 1, 12, float('inf')) == bind_ack()


@pytest.mark.parametrize('body', [b'', bind_ack(2), bind_ack()[:-1], overwrite(bind_ack(), 8, b'\xff\xff'), overwrite(bind_ack(), 12, b'\x02'), bind_ack()[:-20] + bytes(20)])
def test_rpc_rejects_bind(body):
    with pytest.raises(ProbeError):
        rpc.bind_accepted(body)


@pytest.mark.parametrize('data', [
    b'', rpc.pdu(12, 1, bind_ack())[:15],
    overwrite(rpc.pdu(12, 1, bind_ack()), 0, b'\x04'),
    overwrite(rpc.pdu(12, 1, bind_ack()), 4, b'\0'),
    rpc.pdu(12, 2, bind_ack()), rpc.pdu(3, 1, b''),
    overwrite(rpc.pdu(12, 1, bind_ack()), 3, b'\x01'),
    overwrite(rpc.pdu(12, 1, bind_ack()), 10, b'\x01\0'),
    overwrite(rpc.pdu(12, 1, bind_ack()), 8, b'\xff\xff'),
    overwrite(rpc.pdu(12, 1, bind_ack()), 8, b'\x0f\0'),
])
def test_rpc_rejects_header_call_fragment_auth_and_size(data):
    with pytest.raises(ProbeError):
        rpc.receive(Stream(data), 1, 12, float('inf'))


def test_tower_interface_is_only_protocol_evidence():
    assert rpc.parse_tower(tower()) == '12345678-1234-abcd-ef00-0123456789ab v1.0'


@pytest.mark.parametrize('data', [b'', b'\0\0', b'\x09\0', tower()[:-1], overwrite(tower(), 2, b'\xff\xff'), overwrite(tower(), 4, b'\x0f'), tower() + b'x'])
def test_tower_rejects_malformed(data):
    with pytest.raises(ProbeError):
        rpc.parse_tower(data)


def test_lookup_valid_page():
    handle, entries = rpc.parse_lookup(lookup())
    assert handle == bytes(20)
    assert entries == [{'annotation': 'test interface', 'interface': '12345678-1234-abcd-ef00-0123456789ab v1.0'}]
    assert rpc.parse_lookup(bytes(20) + struct.pack('<IIII', 0, 8, 0, 0) + bytes(4))[1] == []


@pytest.mark.parametrize('data', [
    b'', lookup()[:35], overwrite(lookup(), 20, struct.pack('<IIII', 9, 9, 0, 9)),
    overwrite(lookup(), 20, struct.pack('<I', 2)), overwrite(lookup(), 28, struct.pack('<I', 1)),
    overwrite(lookup(), 52, bytes(4)), overwrite(lookup(), 56, b'\x01\0\0\0'),
    overwrite(lookup(), 60, struct.pack('<I', 257)), lookup(annotation=b'a' * 257),
    lookup()[:65], lookup()[:84], overwrite(lookup(), 80, struct.pack('<I', 9000)),
    lookup()[:-5], lookup()[:-4] + struct.pack('<I', 5), lookup() + bytes(4),
])
def test_lookup_rejects_invalid_arrays_annotations_towers_and_status(data):
    with pytest.raises(ProbeError):
        rpc.parse_lookup(data)


def test_all_tower_and_lookup_truncations_are_bounded():
    for parser, data in ((rpc.parse_tower, tower()), (rpc.parse_lookup, lookup())):
        for length in range(len(data)):
            with pytest.raises(ProbeError):
                parser(data[:length])


def test_probe_reads_one_page_and_releases_context():
    handle = b'\x01' + bytes(19)
    stream = Stream(rpc.pdu(12, 1, bind_ack()) + rpc.pdu(2, 2, bytes(8) + lookup(handle=handle)) + rpc.pdu(2, 3, bytes(8) + bytes(24)))
    result = rpc.probe_rpc_identity('192.0.2.1', socket_factory=lambda *args, **kwargs: stream)
    assert result.status == 'COMPLETED'
    assert len(stream.sent) == 3
    assert int.from_bytes(stream.sent[1][22:24], 'little') == 2  # ept_lookup
    assert int.from_bytes(stream.sent[2][22:24], 'little') == 4  # handle_free, not another lookup
    assert int.from_bytes(stream.sent[1][-4:], 'little') == 8
    assert {item.independence_key for item in result.observations} == {'rpc'}
    assert {item.attribute for item in result.observations} == {'confirmed_service', 'rpc_interface', 'rpc_annotation'}


def test_successful_rpc_evidence_retained_after_cleanup_failure():
    stream = Stream(rpc.pdu(12, 1, bind_ack()) + rpc.pdu(2, 2, bytes(8) + lookup(handle=b'\x01' + bytes(19))))
    result = rpc.probe_rpc_identity('192.0.2.1', socket_factory=lambda *args, **kwargs: stream)
    assert result.status == 'INCONCLUSIVE'
    assert any(item.attribute == 'rpc_interface' for item in result.observations)


def test_successful_bind_retained_after_lookup_failure():
    stream = Stream(rpc.pdu(12, 1, bind_ack()))
    result = rpc.probe_rpc_identity('192.0.2.1', socket_factory=lambda *args, **kwargs: stream)
    assert result.status == 'INCONCLUSIVE'
    assert len(result.observations) == 1


def test_rpc_internal_error_propagates():
    def broken(*args, **kwargs):
        raise ValueError('programmer error')
    with pytest.raises(ValueError, match='programmer error'):
        rpc.probe_rpc_identity('192.0.2.1', socket_factory=broken)
