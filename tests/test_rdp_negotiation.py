import unittest
from unittest.mock import Mock
from netsentry.analysis.rdp import RDPNegotiationAttempt, parse_response, probe_rdp, summarize
from netsentry.analysis.checks import RDPConfigurationCheck, HTTPConfigurationCheck, TLSConfigurationCheck
from netsentry.analysis.engine import assess_scan_result
from netsentry.analysis.models import CheckStatus
from netsentry.analysis.probes import ProbeError
from netsentry.scanning.models import HostScanResult, PortService
from tests.test_ssh_enumeration import Socket


def response(value=1, kind=2):
    return bytes.fromhex("030000130ed00000000000") + bytes([kind, 0, 8, 0]) + value.to_bytes(4, "little")


class RDPNegotiationTests(unittest.TestCase):
    def test_selection_is_not_supported_protocol_inventory(self):
        data = summarize((parse_response(3, response(2)),))
        self.assertTrue(data.nla_available)
        self.assertIsNone(data.nla_required)
        self.assertEqual(data.attempts[0].selected_protocol, 2)
        self.assertEqual(data.attempts[0].raw_response, response(2).hex())

    def test_explicit_credssp_requirement(self):
        data = summarize((parse_response(1, response(5, 3)),))
        self.assertTrue(data.nla_required)
        self.assertIsNone(data.nla_available)

    def test_timeout_is_not_proof_of_unsupported_feature(self):
        data = probe_rdp("test", socket_factory=Mock(side_effect=TimeoutError()), enumerate_security=True)
        self.assertFalse(data.protocol_response)
        self.assertIsNone(data.nla_available)
        self.assertIsNone(data.nla_required)
        self.assertIsNone(data.legacy_accepted)
        self.assertEqual(len(data.attempts), 1)

    def test_contradictions_are_preserved(self):
        attempts = (parse_response(1, response(5, 3)), parse_response(1, response(1)))
        data = summarize(attempts)
        self.assertEqual(data.attempts, attempts)
        self.assertTrue(data.contradictions)
        self.assertIsNone(data.nla_required)
        self.assertEqual(data.enumeration_status, "inconclusive")

    def test_unknown_protocol_value_is_raw_inconclusive_evidence(self):
        data = summarize((parse_response(3, response(99)),))
        self.assertTrue(data.protocol_response)
        self.assertEqual(data.attempts[0].selected_protocol, 99)
        self.assertEqual(data.enumeration_status, "inconclusive")

    def test_protocol_not_requested_is_inconclusive(self):
        self.assertEqual(parse_response(1, response(2)).status, "inconclusive")

    def test_certificate_failure_preserves_rdp_identity(self):
        sock = Socket(response(1))
        context = Mock()
        context.wrap_socket.side_effect = OSError("certificate handshake failure")
        probe = lambda host, **kw: probe_rdp(host, socket_factory=lambda *a, **k: sock, context_factory=lambda: context, **kw)
        result = assess_scan_result(HostScanResult("10.0.0.1", services=[PortService(3389, "tcp", "open")]), checks=[RDPConfigurationCheck(probe)])
        self.assertEqual(result.observations[0].service, "rdp")
        self.assertEqual(result.checks[0].status, CheckStatus.INCONCLUSIVE)
        self.assertIn("certificate", result.checks[0].details["attempts"][0]["tls_error"])

    def test_nested_tls_never_dispatches_generic_http_or_tls(self):
        rdp = summarize((parse_response(3, response(1)),))
        http_probe, tls_probe = Mock(), Mock()
        result = assess_scan_result(HostScanResult("10.0.0.1", services=[PortService(3389, "tcp", "open")]), checks=[RDPConfigurationCheck(Mock(return_value=rdp)), TLSConfigurationCheck(tls_probe), HTTPConfigurationCheck(http_probe)])
        http_probe.assert_not_called()
        tls_probe.assert_not_called()
        self.assertEqual(len(result.checks), 1)

    def test_three_attempt_limit_and_no_authentication(self):
        sockets = [Socket(response(2)), Socket(response(2, 3)), Socket(response(0))]
        factory = Mock(side_effect=sockets)
        context = Mock()
        context.wrap_socket.side_effect = OSError("TLS unavailable")
        result = probe_rdp("test", socket_factory=factory, enumerate_security=True, context_factory=lambda: context)
        self.assertEqual(len(result.attempts), 3)
        self.assertEqual([a.requested_protocols for a in result.attempts], [3, 1, 0])
        for sock in sockets:
            self.assertEqual(len(sock.sent), 1)
            self.assertEqual(len(sock.sent[0]), 19)
            self.assertTrue(sock.closed)

    def test_tls_metadata_uses_negotiated_connection_only(self):
        sock = Socket(response(1))
        secure = Mock()
        secure.getpeercert.return_value = {"subject": ((('commonName', 'test'),),), "issuer": ((('organizationName', 'test'),),)}
        secure.version.return_value = "TLSv1.3"
        secure.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        wrapped = Mock()
        wrapped.__enter__ = Mock(return_value=secure)
        wrapped.__exit__ = Mock(return_value=False)
        context = Mock()
        context.wrap_socket.return_value = wrapped
        result = probe_rdp("test", socket_factory=lambda *a, **k: sock, enumerate_security=True, context_factory=lambda: context)
        context.wrap_socket.assert_called_once_with(sock, server_hostname="test")
        secure.sendall.assert_not_called()
        self.assertTrue(result.tls_used)
        self.assertEqual(result.attempts[0].certificate["subject"], "test")

    def test_malformed_length_is_bounded(self):
        sock = Socket(b"\x03\x00\xff\xff")
        result = probe_rdp("test", socket_factory=lambda *a, **k: sock, enumerate_security=True)
        self.assertLessEqual(max(sock.reads), 4)
        self.assertFalse(result.protocol_response)

    def test_unknown_failure_code_remains_inconclusive(self):
        item = parse_response(3, response(100, 3))
        self.assertEqual(item.failure_code, 100)
        self.assertEqual(item.status, "inconclusive")

    def test_deadline_prevents_further_negotiation_after_slow_connect(self):
        from unittest.mock import patch
        clock = [0.0]
        sock = Socket(response())
        def connect(*args, **kwargs):
            clock[0] = 2.0
            return sock
        with patch("netsentry.analysis.rdp.time.monotonic", side_effect=lambda: clock[0]):
            result = probe_rdp("test", timeout=1, socket_factory=connect, enumerate_security=True)
        self.assertEqual(sock.sent, [])
        self.assertEqual(len(result.attempts), 1)
        self.assertEqual(result.enumeration_status, "inconclusive")
