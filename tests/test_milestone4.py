import unittest

from netsentry.analysis.checks import DNSConfigurationCheck, HTTPConfigurationCheck, RDPConfigurationCheck, SSHConfigurationCheck
from netsentry.analysis.correlation import CorrelationStatus, StaticVulnerabilityProvider, SoftwareEvidence, VulnerabilityCorrelation
from netsentry.analysis.engine import assess_scan_result
from netsentry.analysis.fingerprinting import identify_service, merge_fingerprints
from netsentry.analysis.models import AssessmentStatus, CheckStatus, Confidence, Severity
from netsentry.analysis.service_probes import DNSProbeData, HTTPProbeData, RDPProbeData, SSHProbeData, ProbeError, probe_dns
from netsentry.scanning.models import HostScanResult, PortService, ServiceIdentity, service_protocols


def svc(port, name, protocol="tcp"):
    return PortService(
        port=port, protocol=protocol, state="open", service=name, product="ExampleServer", version="1.2.3",
        service_method="probed", service_confidence="10",
        identities=tuple(ServiceIdentity(item, "Nmap service probe", {"name": name}) for item in service_protocols(name)),
    )


class ServiceModuleTests(unittest.TestCase):
    def test_ssh_banner_is_preserved(self):
        result = SSHConfigurationCheck(lambda host, port: SSHProbeData("SSH-2.0-OpenSSH_9.6", "2.0", {})).run(HostScanResult("10.0.0.1"), svc(22, "ssh"))
        self.assertEqual(result.status, CheckStatus.COMPLETED)
        self.assertEqual(result.details["banner"], "SSH-2.0-OpenSSH_9.6")

    def test_http_headers_are_observations(self):
        result = HTTPConfigurationCheck(lambda host, port: HTTPProbeData(200, {"server": "Example", "content-type": "text/plain", "strict-transport-security": "max-age=1", "allow": "GET, HEAD"}, None, "Example", ())).run(HostScanResult("10.0.0.1"), svc(80, "http"))
        self.assertEqual(result.status, CheckStatus.COMPLETED)
        self.assertEqual(result.details["status"], 200)
        self.assertEqual(result.details["selected_headers"]["content-type"], "text/plain")
        self.assertEqual(result.details["methods"], ())
        self.assertIn("content-security-policy", result.details["missing_security_headers"])

    def test_http_proxy_label_on_nonstandard_port_is_assessed(self):
        check = HTTPConfigurationCheck(lambda host, port: HTTPProbeData(200, {"server": "SimpleHTTP/0.6 Python/3.14.6"}, None, "SimpleHTTP/0.6 Python/3.14.6", ()))
        result = check.run(HostScanResult("10.0.0.1"), svc(8080, "http-proxy"))
        self.assertEqual(result.status, CheckStatus.COMPLETED)
        self.assertEqual(result.details["status"], 200)
        self.assertEqual(result.details["transport"], "TCP")
        self.assertFalse(result.details["tls"])
        self.assertEqual(result.details["fingerprint"]["product"], "SimpleHTTP, Python")
        self.assertEqual(result.details["fingerprint"]["version"], "0.6, 3.14.6")
        self.assertEqual(result.details["fingerprint"]["source"], "HTTP Server header")

    def test_http_redirect_and_error_statuses_are_completed(self):
        for status in (301, 404, 500):
            result = HTTPConfigurationCheck(
                lambda host, port, status=status: HTTPProbeData(status, {"location": "/next"} if status == 301 else {}, "/next" if status == 301 else None, None, ())
            ).run(HostScanResult("10.0.0.1"), svc(8080, "http-proxy"))
            self.assertEqual(result.status, CheckStatus.COMPLETED)
            self.assertEqual(result.details["status"], status)

    def test_non_http_service_on_http_labeled_port_fails_protocol_check(self):
        def non_http_probe(host, port, **kwargs):
            raise ProbeError("response was not a valid HTTP status line")

        result = HTTPConfigurationCheck(non_http_probe).run(
            HostScanResult("10.0.0.1"), svc(8080, "http-proxy")
        )
        self.assertEqual(result.status, CheckStatus.FAILED)

    def test_http_check_and_tls_check_can_both_apply(self):
        from netsentry.analysis.checks import TLSConfigurationCheck

        result = assess_scan_result(
            HostScanResult("10.0.0.1", services=[svc(8443, "https-alt")], scan_profile="full"),
            checks=[
                TLSConfigurationCheck(lambda host, port: __import__("netsentry.analysis.probes", fromlist=["TLSProbeData"]).TLSProbeData("TLSv1.3", "cipher", "subject", "issuer", None, None, False, False)),
                HTTPConfigurationCheck(lambda host, port: HTTPProbeData(200, {"server": "app"}, None, "app", ())),
            ],
        )
        self.assertEqual({check.title for check in result.checks}, {"TLS configuration", "HTTP security configuration"})

    def test_dns_recursion_requires_observed_flag(self):
        result = DNSConfigurationCheck(lambda host, port: DNSProbeData(True, True, False)).run(HostScanResult("10.0.0.1"), svc(53, "domain"))
        self.assertEqual(result.status, CheckStatus.COMPLETED)
        self.assertEqual(result.findings[0].title, "Open DNS recursion confirmed")

    def test_dns_tcp_response_preserves_transport_and_refusal(self):
        response = b"\x12\x34\x81\x05\x00\x01\x00\x00\x00\x00\x00\x00"

        class FakeTcpSocket:
            def __init__(self, *args):
                self.sent = b""
                self.remaining = len(response).to_bytes(2, "big") + response

            def settimeout(self, value):
                pass

            def connect(self, address):
                pass

            def sendall(self, data):
                self.sent = data

            def recv(self, size):
                result = self.remaining[:size]
                self.remaining = self.remaining[size:]
                return result

            def close(self):
                pass

        data = probe_dns("10.0.0.1", transport="tcp", socket_factory=FakeTcpSocket)
        self.assertEqual(data.transport, "TCP")
        self.assertEqual(data.response_code, "REFUSED")
        self.assertFalse(data.recursion_available)

    def test_dns_tcp_timeout_is_a_probe_failure(self):
        class TimeoutSocket:
            def __init__(self, *args):
                pass
            def settimeout(self, value):
                pass
            def connect(self, address):
                pass
            def sendall(self, data):
                pass
            def recv(self, size):
                raise TimeoutError("timed out")
            def close(self):
                pass

        with self.assertRaisesRegex(ProbeError, "TCP query timed out"):
            probe_dns("10.0.0.1", transport="tcp", socket_factory=TimeoutSocket)

    def test_dns_tcp_nxdomain_is_valid_protocol_evidence(self):
        response = b"\x12\x34\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00"

        class NxDomainSocket:
            def __init__(self, *args):
                self.remaining = len(response).to_bytes(2, "big") + response
            def settimeout(self, value):
                pass
            def connect(self, address):
                pass
            def sendall(self, data):
                pass
            def recv(self, size):
                result = self.remaining[:size]
                self.remaining = self.remaining[size:]
                return result
            def close(self):
                pass

        data = probe_dns("10.0.0.1", transport="tcp", socket_factory=NxDomainSocket)
        self.assertEqual(data.response_code, "NXDOMAIN")
        self.assertTrue(data.responded)

    def test_dns_tcp_connection_reset_is_distinguished(self):
        class ResetSocket:
            def __init__(self, *args):
                pass
            def settimeout(self, value):
                pass
            def connect(self, address):
                pass
            def sendall(self, data):
                raise ConnectionResetError("reset")
            def close(self):
                pass

        with self.assertRaisesRegex(ProbeError, "connection reset"):
            probe_dns("10.0.0.1", transport="tcp", socket_factory=ResetSocket)

    def test_successful_tcp_dns_evidence_is_not_invalidated_by_udp_failure(self):
        tcp_data = DNSProbeData(True, False, False, "TCP", "REFUSED", True)
        result = DNSConfigurationCheck(lambda host, port: tcp_data).run(
            HostScanResult("10.0.0.1"), svc(53, "domain")
        )
        self.assertEqual(result.status, CheckStatus.COMPLETED)
        self.assertEqual(result.details["transport"], "TCP")
        self.assertEqual(result.details["response_code"], "REFUSED")

    def test_rdp_protocol_response_is_not_a_vulnerability(self):
        result = RDPConfigurationCheck(lambda host, port: RDPProbeData(True)).run(HostScanResult("10.0.0.1"), svc(3389, "ms-wbt-server"))
        self.assertEqual(result.status, CheckStatus.COMPLETED)
        self.assertEqual(result.findings, ())


class FingerprintAndCorrelationTests(unittest.TestCase):
    def test_product_version_becomes_high_confidence_evidence(self):
        evidence = identify_service(svc(8080, "http"))
        self.assertEqual(evidence.product, "ExampleServer")
        self.assertEqual(evidence.version, "1.2.3")
        self.assertEqual(evidence.confidence, Confidence.HIGH)

    def test_conflicting_products_are_not_merged(self):
        first = SoftwareEvidence("A", "1.0", "tcp", Confidence.HIGH, "banner")
        second = SoftwareEvidence("B", "1.0", "tcp", Confidence.HIGH, "nmap")
        self.assertIsNone(merge_fingerprints((first, second)))

    def test_potential_correlation_is_not_a_finding_or_risk(self):
        evidence = SoftwareEvidence("ExampleServer", "1.2.3", "tcp", Confidence.HIGH, "Nmap fingerprint")
        correlation = VulnerabilityCorrelation("CVE-2099-0001", "ExampleServer", "<1.3.0", evidence, CorrelationStatus.POTENTIAL, Confidence.HIGH, Severity.HIGH)
        assessment = assess_scan_result(HostScanResult("10.0.0.1", services=[svc(135, "msrpc")], scan_profile="full"), vulnerability_provider=StaticVulnerabilityProvider((correlation,)))
        self.assertEqual(assessment.status, AssessmentStatus.COMPLETE)
        self.assertEqual(assessment.risk_score, 0)
        self.assertEqual(assessment.potential_correlations[0]["status"], "POTENTIAL")
        self.assertIsNone(assessment.observed_risk_score)
        self.assertEqual(assessment.observed_risk_level.value, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
