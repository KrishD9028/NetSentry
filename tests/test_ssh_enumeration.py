import struct
import unittest
from dataclasses import replace
from unittest.mock import Mock

from netsentry.analysis.ssh import FIELDS, SSHProbeData, parse_kexinit, probe_ssh
from netsentry.analysis.probes import ProbeError
from netsentry.analysis.checks import SSHConfigurationCheck
from netsentry.analysis.engine import assess_scan_result
from netsentry.analysis.models import CheckStatus
from netsentry.scanning.models import HostScanResult, PortService


def payload(overrides=None):
    values = dict(zip(FIELDS, ("curve25519-sha256,ext-info-s", "ssh-ed25519", "aes128-ctr", "aes128-ctr",
                               "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", "")))
    values.update(overrides or {})
    output = b"\x14" + b"x" * 16
    for field in FIELDS:
        raw = values[field].encode()
        output += struct.pack(">I", len(raw)) + raw
    return output + b"\0" * 5


def packet(value):
    padding = 8 - (len(value) + 5) % 8
    if padding < 4:
        padding += 8
    return struct.pack(">IB", len(value) + padding + 1, padding) + value + b"\0" * padding


class Socket:
    def __init__(self, data):
        self.data = data
        self.sent = []
        self.reads = []
        self.closed = False
    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.closed = True
    def settimeout(self, value):
        pass
    def recv(self, size):
        self.reads.append(size)
        chunk, self.data = self.data[:min(size, 7)], self.data[min(size, 7):]
        return chunk
    def sendall(self, data):
        self.sent.append(data)


class SSHEnumerationTests(unittest.TestCase):
    def test_complete_exchange_without_authentication(self):
        sock = Socket(b"SSH-2.0-OpenSSH_9.6\r\n" + packet(payload()))
        data = probe_ssh("test", socket_factory=lambda *a, **k: sock, enumerate_security=True)
        self.assertEqual(data.enumeration_status, "completed")
        self.assertEqual(data.algorithms["host_key"], ("ssh-ed25519",))
        self.assertEqual(data.extensions, ("ext-info-s",))
        self.assertEqual(len(sock.sent), 2)
        self.assertTrue(sock.sent[0].startswith(b"SSH-2.0-"))
        self.assertEqual(sock.sent[1][5], 20)
        self.assertTrue(sock.closed)

    def test_identity_survives_failed_enumeration(self):
        sock = Socket(b"SSH-2.0-OpenSSH_9.6\r\n")
        probe = lambda host, **kwargs: probe_ssh(host, socket_factory=lambda *a, **k: sock, **kwargs)
        result = assess_scan_result(HostScanResult("10.0.0.1", services=[PortService(22, "tcp", "open")]), checks=[SSHConfigurationCheck(probe)])
        self.assertEqual(result.observations[0].service, "ssh")
        self.assertEqual(result.checks[0].status, CheckStatus.INCONCLUSIVE)
        self.assertEqual(result.findings, ())

    def test_directional_weak_algorithm_and_duplicates(self):
        algorithms, extensions = parse_kexinit(payload({"cipher_server_to_client": "arcfour,arcfour"}))
        data = SSHProbeData("SSH-2.0-test", "2.0", algorithms, "completed", "test", extensions)
        check = SSHConfigurationCheck(Mock(return_value=data))
        result = check.run(HostScanResult("10.0.0.1"), PortService(22, "tcp", "open"))
        self.assertEqual(len(result.findings), 1)
        self.assertIn("cipher_server_to_client", result.findings[0].evidence)
        self.assertNotIn("cipher_client_to_server", result.findings[0].evidence)

    def test_unknown_algorithms_are_observations(self):
        algorithms, _ = parse_kexinit(payload({"host_key": "unknown@example.test"}))
        result = SSHConfigurationCheck().run(HostScanResult("10.0.0.1"), PortService(22, "tcp", "open"), data=SSHProbeData("SSH-2.0-test", "2.0", algorithms, "completed"))
        self.assertEqual(result.findings, ())

    def test_empty_enumeration_is_not_complete(self):
        result = SSHConfigurationCheck().run(HostScanResult("10.0.0.1"), PortService(22, "tcp", "open"), data=SSHProbeData("SSH-2.0-test", "2.0", {}))
        self.assertEqual(result.status, CheckStatus.INCONCLUSIVE)

    def test_malformed_packet_length_does_not_request_large_read(self):
        sock = Socket(b"SSH-2.0-test\r\n" + struct.pack(">IB", 0xffffffff, 4))
        data = probe_ssh("test", socket_factory=lambda *a, **k: sock, enumerate_security=True)
        self.assertEqual(data.enumeration_status, "inconclusive")
        self.assertLessEqual(max(sock.reads), 4096)
        self.assertEqual(data.banner, "SSH-2.0-test")

    def test_malformed_name_length_is_rejected(self):
        with self.assertRaises(ProbeError):
            parse_kexinit(b"\x14" + b"x" * 16 + b"\xff" * 4)

    def test_truncated_or_empty_required_lists_are_rejected(self):
        for value in (payload()[:-1], payload({"host_key": ""})):
            with self.assertRaises(ProbeError):
                parse_kexinit(value)

    def test_legacy_banner_does_not_trigger_ssh2_exchange(self):
        sock = Socket(b"SSH-1.5-test\r\n")
        data = probe_ssh("test", socket_factory=lambda *a, **k: sock, enumerate_security=True)
        self.assertEqual(sock.sent, [])
        self.assertEqual(data.enumeration_status, "inconclusive")

    def test_199_uses_ssh2_enumeration(self):
        sock = Socket(b"SSH-1.99-test\r\n" + packet(payload()))
        data = probe_ssh("test", socket_factory=lambda *a, **k: sock, enumerate_security=True)
        self.assertEqual(data.enumeration_status, "completed")

    def test_invalid_banner_never_sends_protocol_messages(self):
        sock = Socket(b"SMTP 220 test\r\n")
        with self.assertRaises(ProbeError):
            probe_ssh("test", socket_factory=lambda *a, **k: sock, enumerate_security=True)
        self.assertEqual(sock.sent, [])

    def test_kex_finding_has_reference(self):
        algorithms, _ = parse_kexinit(payload({"kex": "diffie-hellman-group1-sha1"}))
        result = SSHConfigurationCheck().run(HostScanResult("10.0.0.1"), PortService(22, "tcp", "open"), data=SSHProbeData("SSH-2.0-test", "2.0", algorithms, "completed"))
        self.assertEqual(len(result.findings), 1)
        self.assertIn("rfc9142", result.findings[0].references[0])

    def test_overall_deadline_survives_banner_but_stops_enumeration(self):
        from unittest.mock import patch
        clock = [0.0]
        sock = Socket(b"SSH-2.0-test\r\n" + packet(payload()))
        original_send = sock.sendall
        def send(data):
            original_send(data)
            clock[0] = 2.0
        sock.sendall = send
        with patch("netsentry.analysis.ssh.time.monotonic", side_effect=lambda: clock[0]):
            data = probe_ssh("test", timeout=1, socket_factory=lambda *a, **k: sock, enumerate_security=True)
        self.assertEqual(data.banner, "SSH-2.0-test")
        self.assertEqual(data.enumeration_status, "inconclusive")
        self.assertEqual(len(sock.sent), 1)
