"""DNS capability and answer evidence never imply open recursion."""
from contextlib import redirect_stdout
from dataclasses import replace
from io import StringIO
import unittest
from unittest.mock import patch

from netsentry.analysis.checks import DNSConfigurationCheck
from netsentry.analysis.engine import assess_scan_result
from netsentry.analysis.service_probes import _dns_query, _parse_dns_response, probe_dns, ProbeError
from netsentry.main import _print_assessment
from netsentry.scanning.models import HostScanResult, PortService

HOST = "100.100.201.193"


def reply(query, flags=0x8180, answer=False):
    header = query[:2] + flags.to_bytes(2, "big") + b"\x00\x01" + int(answer).to_bytes(2, "big") + b"\x00\x00\x00\x00"
    record = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22"
    return header + query[12:] + (record if answer else b"")


def assessment(data):
    return assess_scan_result(HostScanResult(HOST, services=[PortService(53, "tcp", "open")]),
                              checks=[DNSConfigurationCheck(lambda *a, **kw: data)])


class DNSEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.query = _dns_query()

    def test_ra_noerror_never_finding(self):
        data = _parse_dns_response(self.query, reply(self.query), "TCP")
        result = assessment(data)
        self.assertEqual(result.findings, ())
        self.assertTrue(result.checks[0].details["recursion_available"])
        self.assertIsNone(result.checks[0].details["recursion_demonstrated"])
        self.assertIsNone(result.checks[0].details["open_recursion_confirmed"])
        self.assertEqual(result.checks[0].status.value, "INCONCLUSIVE")

    def test_empty_answer_is_observed_not_resolution(self):
        data = _parse_dns_response(self.query, reply(self.query), "TCP")
        self.assertEqual(data.answer_count, 0)
        self.assertEqual(data.answers, ())
        self.assertEqual(assessment(data).findings, ())

    def test_refused_and_servfail_with_ra_never_finding(self):
        for flags, code in ((0x8185, "REFUSED"), (0x8182, "SERVFAIL")):
            with self.subTest(code=code):
                data = _parse_dns_response(self.query, reply(self.query, flags), "TCP")
                self.assertEqual(data.response_code, code)
                self.assertTrue(data.recursion_available)
                self.assertEqual(assessment(data).findings, ())

    def test_authoritative_answer_never_finding(self):
        data = _parse_dns_response(self.query, reply(self.query, 0x8580, True), "TCP")
        self.assertTrue(data.authoritative)
        self.assertEqual(assessment(data).findings, ())

    def test_cached_public_looking_answer_never_proves_recursion(self):
        data = _parse_dns_response(self.query, reply(self.query, answer=True), "TCP")
        self.assertFalse(data.authoritative)
        self.assertEqual(data.answer_count, 1)
        self.assertEqual(data.answers[0]["name"], "example.com.")
        self.assertEqual(data.answers[0]["rdata_hex"], "5db8d822")
        self.assertIsNone(data.recursion_demonstrated)
        self.assertIsNone(data.open_recursion_confirmed)
        self.assertEqual(assessment(data).findings, ())

    def test_ra_does_not_change_observed_or_overall_risk(self):
        data = _parse_dns_response(self.query, reply(self.query), "TCP")
        advertised, unavailable = assessment(data), assessment(replace(data, recursion_available=False))
        self.assertEqual(advertised.observed_risk, unavailable.observed_risk)
        self.assertEqual(advertised.to_dict()["risk"], unavailable.to_dict()["risk"])
        self.assertIsNone(advertised.observed_risk_score)

    def test_valid_dns_identity_survives_inconclusive_assessment(self):
        data = _parse_dns_response(self.query, reply(self.query), "TCP")
        result = assessment(data)
        self.assertEqual(result.observations[0].service, "dns")
        self.assertEqual(result.observations[0].identification_status, "CONFIRMED")
        output = StringIO()
        with redirect_stdout(output):
            _print_assessment(result)
        self.assertIn("DNS", output.getvalue())
        self.assertIn("Recursion advertised: yes; open recursion not established.", output.getvalue())
        self.assertNotIn("Open DNS recursion confirmed", output.getvalue())

    def test_query_transaction_id_uses_random_bytes(self):
        with patch("netsentry.analysis.service_probes.secrets.token_bytes", side_effect=[b"\x00\x01", b"\x00\x02"]) as random:
            first, second = _dns_query(), _dns_query()
        self.assertNotEqual(first[:2], second[:2])
        self.assertEqual(first[2:], second[2:])
        self.assertEqual(random.call_count, 2)

    def test_id_qr_opcode_validation(self):
        valid = reply(self.query)
        invalid = [bytes([valid[0] ^ 1]) + valid[1:], reply(self.query, 0x0180), reply(self.query, 0x8980)]
        for response in invalid:
            with self.assertRaises(ProbeError):
                _parse_dns_response(self.query, response, "TCP")

    def test_matching_question_required(self):
        valid = reply(self.query)
        invalid = [valid[:13] + b"X" + valid[14:], valid[:-4] + b"\x00\x1c\x00\x01",
                   valid[:-2] + b"\x00\x03", valid[:4] + b"\x00\x00" + valid[6:],
                   valid[:12]]
        for response in invalid:
            with self.assertRaises(ProbeError):
                _parse_dns_response(self.query, response, "TCP")

    def test_record_bounds_and_compression_validation(self):
        valid = reply(self.query, answer=True)
        start = len(self.query)
        invalid = [valid[:-1], valid[:start] + b"\xff\xff" + valid[start + 2:],
                   valid[:start] + b"\xc0" + bytes([start]) + valid[start + 2:],
                   valid + b"extra", valid[:6] + b"\xff\xff" + valid[8:]]
        for response in invalid:
            with self.assertRaises(ProbeError):
                _parse_dns_response(self.query, response, "TCP")

    def test_raw_evidence_query_and_truncation_preserved(self):
        response = reply(self.query, 0x8380)
        data = _parse_dns_response(self.query, response, "TCP")
        self.assertTrue(data.truncated)
        self.assertEqual(data.raw_response, response.hex())
        self.assertEqual((data.query_name, data.query_type, data.query_class), ("example.com.", 1, 1))
        self.assertTrue(data.recursion_requested)
        self.assertEqual(data.transport, "TCP")
        self.assertEqual(assessment(data).findings, ())

    def test_udp_sender_validation(self):
        class Socket:
            peer = (HOST, 53)
            def __init__(self, *args): pass
            def settimeout(self, timeout): pass
            def sendto(self, query, address): self.query = query
            def recvfrom(self, size): return reply(self.query), self.peer
            def close(self): pass
        self.assertEqual(probe_dns(HOST, transport="udp", socket_factory=Socket).transport, "UDP")
        Socket.peer = ("192.0.2.2", 53)
        with self.assertRaisesRegex(ProbeError, "unexpected endpoint"):
            probe_dns(HOST, transport="udp", socket_factory=Socket)

    def test_tcp_oversized_prefix_rejected_before_body_read(self):
        calls = []
        class Socket:
            def __init__(self, *args): pass
            def settimeout(self, timeout): pass
            def connect(self, address): pass
            def sendall(self, query): pass
            def recv(self, size):
                calls.append(size)
                return b"\xff\xff"
            def close(self): pass
        with self.assertRaisesRegex(ProbeError, "outside bounds"):
            probe_dns(HOST, socket_factory=Socket)
        self.assertEqual(calls, [2])
