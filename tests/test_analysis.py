import json
import logging
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from netsentry.analysis import (
    AssessmentStatus,
    CompletedNoFindingCheck,
    ConfirmedFindingCheck,
    Confidence,
    Finding,
    RiskLevel,
    SecurityAnalyzer,
    Severity,
    assess_scan_result,
)
from netsentry.analysis.checks import SMBConfigurationCheck, ServiceCheck, TLSConfigurationCheck
from netsentry.analysis.models import CheckStatus, SecurityCheckResult
from netsentry.analysis.probes import ProbeError, SMBProbeData, TLSProbeData, _decode_peer_certificate, probe_smb
from netsentry.main import _print_assessment
from netsentry.scanning.models import HostScanResult, PortService, ServiceIdentity, service_protocols


def service(port: int, name: str | None, protocol: str = "tcp") -> PortService:
    return PortService(
        port=port, protocol=protocol, state="open", service=name,
        identities=tuple(ServiceIdentity(item, "fixture protocol evidence", {"service": name}) for item in service_protocols(name)),
    )


def finding_factory(severity: Severity):
    def build(result: HostScanResult, observed: PortService) -> Finding:
        return Finding(
            finding_id=f"test:{observed.port}",
            title="Confirmed test finding",
            description="A test check confirmed evidence.",
            severity=severity,
            confidence=Confidence.HIGH,
            host=result.target,
            port=observed.port,
            protocol=observed.protocol,
            service=observed.service,
            evidence="Test evidence.",
            remediation="Test remediation.",
            rule_id="TEST",
        )
    return build


class FailingCheck(ServiceCheck):
    check_id = "TEST-FAILED"
    title = "Failed service check"

    def matches(self, service: PortService) -> bool:
        return True

    def run(self, result: HostScanResult, service: PortService) -> SecurityCheckResult:
        raise RuntimeError("probe unavailable")


class SecurityRuleTests(unittest.TestCase):
    def setUp(self):
        # Unit tests never connect to the illustrative host addresses.
        probe = patch("netsentry.analysis.checks.ProtocolServiceCheck.collect", side_effect=ProbeError("fixture unavailable"))
        probe.start()
        self.addCleanup(probe.stop)

    def test_empty_common_scan_is_limited_not_clean(self) -> None:
        assessment = assess_scan_result(
            HostScanResult(
                target="192.168.1.20",
                scan_profile="common",
                requested_ports=(22, 80, 443),
            )
        )
        self.assertEqual(assessment.status, AssessmentStatus.LIMITED)
        self.assertIsNone(assessment.risk_score)
        self.assertIn("common scan profile", assessment.status_reason)

    def test_empty_full_scan_without_evidence_is_limited(self) -> None:
        assessment = assess_scan_result(
            HostScanResult(target="192.168.1.20", scan_profile="full", requested_ports=tuple(range(1, 65536)))
        )
        self.assertEqual(assessment.status, AssessmentStatus.LIMITED)
        self.assertIsNone(assessment.risk_score)
        self.assertEqual(assessment.risk_level, RiskLevel.UNKNOWN)

    def test_telnet_rule_has_high_confidence_and_score(self) -> None:
        assessment = assess_scan_result(
            HostScanResult(target="192.168.1.20", services=[service(23, "telnet")]),
            checks=[ConfirmedFindingCheck("TEST-TELNET", "Telnet check", lambda item: item.port == 23, finding_factory(Severity.HIGH))],
        )
        self.assertEqual(len(assessment.findings), 1)
        finding = assessment.findings[0]
        self.assertEqual(finding.rule_id, "TEST")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.confidence, Confidence.HIGH)
        self.assertEqual(assessment.risk_score, 8)

    def test_port_rules_work_when_service_names_are_missing(self) -> None:
        result = HostScanResult(
            target="192.168.1.20",
            services=[service(21, None), service(445, None), service(3389, None)],
        )
        assessment = assess_scan_result(result)
        self.assertEqual(assessment.findings, ())
        self.assertEqual({observation.port for observation in assessment.observations}, {21, 445, 3389})
        self.assertEqual(assessment.status, AssessmentStatus.LIMITED)

    def test_database_services_are_detected(self) -> None:
        result = HostScanResult(
            target="192.168.1.20",
            services=[service(3306, "mysql"), service(5432, "postgresql"), service(1433, "ms-sql-s"), service(27017, "mongodb"), service(6379, "redis")],
        )
        assessment = assess_scan_result(result)
        self.assertEqual(len(assessment.observations), 5)
        self.assertEqual(assessment.findings, ())
        self.assertEqual(assessment.status, AssessmentStatus.COMPLETE)

    def test_http_and_unknown_services_are_detected(self) -> None:
        result = HostScanResult(
            target="192.168.1.20",
            services=[service(80, "http"), service(8080, None)],
        )
        assessment = assess_scan_result(result)
        self.assertEqual(assessment.findings, ())
        self.assertEqual(len(assessment.observations), 2)
        self.assertEqual(assessment.coverage.checks_attempted, 1)
        self.assertEqual(assessment.risk_level, RiskLevel.UNKNOWN)

    def test_tls_service_does_not_trigger_http_rule(self) -> None:
        def failing_tls_probe(host, port):
            raise ProbeError("TLS handshake failed")

        assessment = assess_scan_result(
            HostScanResult(target="192.168.1.20", services=[service(443, "https")]),
            checks=[TLSConfigurationCheck(failing_tls_probe)],
        )
        self.assertEqual(assessment.findings, ())
        self.assertEqual(assessment.risk_level, RiskLevel.UNKNOWN)
        self.assertEqual(assessment.status, AssessmentStatus.LIMITED)

    def test_clean_host_has_no_findings(self) -> None:
        assessment = assess_scan_result(
            HostScanResult(target="192.168.1.20", services=[service(22, "ssh")], scan_profile="full"),
            checks=[CompletedNoFindingCheck("TEST-SSH", "SSH check", lambda item: item.port == 22)],
        )
        self.assertEqual(assessment.findings, ())
        self.assertEqual(assessment.risk_score, 0)
        self.assertEqual(assessment.risk_level, RiskLevel.INFO)
        self.assertEqual(assessment.status, AssessmentStatus.COMPLETE)

    def test_multiple_findings_use_highest_risk_not_info_count(self) -> None:
        services = [service(23, "telnet"), service(80, "http")]
        checks = [
            ConfirmedFindingCheck("TEST-HIGH", "High check", lambda item: item.port == 23, finding_factory(Severity.HIGH)),
            ConfirmedFindingCheck("TEST-LOW", "Low check", lambda item: item.port == 80, finding_factory(Severity.LOW)),
        ]
        assessment = assess_scan_result(HostScanResult(target="192.168.1.20", services=services), checks=checks)
        self.assertEqual(assessment.risk_score, 8)
        self.assertEqual(assessment.risk_severity, Severity.HIGH)

    def test_findings_are_sorted_by_severity(self) -> None:
        result = HostScanResult(target="192.168.1.20", services=[service(80, "http"), service(23, "telnet"), service(445, "smb")])
        checks = [
            ConfirmedFindingCheck("TEST-HIGH", "High check", lambda item: item.port == 23, finding_factory(Severity.HIGH)),
            ConfirmedFindingCheck("TEST-MEDIUM", "Medium check", lambda item: item.port == 445, finding_factory(Severity.MEDIUM)),
            ConfirmedFindingCheck("TEST-LOW", "Low check", lambda item: item.port == 80, finding_factory(Severity.LOW)),
        ]
        findings = assess_scan_result(result, checks=checks).findings
        self.assertEqual([finding.severity for finding in findings], [Severity.HIGH, Severity.MEDIUM, Severity.LOW])


class AssessmentSerializationTests(unittest.TestCase):
    def test_smb_probe_success_reports_signing_and_dialect(self) -> None:
        check = SMBConfigurationCheck(lambda host, port: SMBProbeData("SMB 3.1.1", False, True, False, "WORKGROUP", "Not required for protocol negotiation"))
        result = check.run(HostScanResult(target="192.0.2.1"), service(445, "microsoft-ds"))
        self.assertEqual(result.status, CheckStatus.COMPLETED)
        self.assertEqual(result.details["dialect"], "SMB 3.1.1")
        self.assertEqual(result.details["signing_required"], False)
        self.assertEqual(result.details["authentication_status"], "Not required for protocol negotiation")
        self.assertIn("Dialect: SMB 3.1.1", result.reason)
        self.assertIn("Signing required: No", result.reason)

        output = StringIO()
        with redirect_stdout(output):
            _print_assessment(assess_scan_result(
                HostScanResult(target="192.0.2.1", services=[service(445, "smb")], scan_profile="full"),
                checks=[check],
            ))
        self.assertIn("SMB 3.1.1, signing not required", output.getvalue())
        self.assertIn("COMPLETED", output.getvalue())
        self.assertEqual(result.findings[0].title, "SMB signing is not required")

    def test_smb_signing_required_and_smbv1_disabled_have_no_findings(self) -> None:
        check = SMBConfigurationCheck(lambda host, port: SMBProbeData("SMB 3.1.1", False, True, True, "server", "Not required for protocol negotiation"))
        result = check.run(HostScanResult(target="192.0.2.1"), service(445, "smb"))
        self.assertEqual(result.status, CheckStatus.COMPLETED)
        self.assertEqual(result.findings, ())
        self.assertFalse(result.details["smb1_supported"])
        self.assertTrue(result.details["signing_required"])

    def test_smb_probe_failure_is_explicit(self) -> None:
        def failing_probe(host, port):
            raise ProbeError("SMB probe failed")

        result = SMBConfigurationCheck(failing_probe).run(
            HostScanResult(target="192.0.2.1"), service(445, "smb")
        )
        self.assertEqual(result.status, CheckStatus.FAILED)

    def test_tls_probe_success_and_certificate_findings(self) -> None:
        valid = TLSProbeData("TLSv1.3", "TLS_AES_256_GCM_SHA384", "service.local", "Test CA", "Jan 01 00:00:00 2025 GMT", "Jan 01 00:00:00 2099 GMT", False, False, 200, {"strict-transport-security": "max-age=1"}, "not performed (certificate verification disabled for observation)")
        result = TLSConfigurationCheck(lambda host, port: valid).run(
            HostScanResult(target="192.0.2.2"), service(8443, "https-alt")
        )
        self.assertEqual(result.status, CheckStatus.COMPLETED)
        self.assertEqual(result.details["tls_version"], "TLSv1.3")
        self.assertEqual(result.details["subject"], "service.local")
        self.assertEqual(result.details["issuer"], "Test CA")
        self.assertEqual(result.details["not_before"], "Jan 01 00:00:00 2025 GMT")
        self.assertIn("certificate verification disabled", result.details["verification_result"])
        self.assertEqual(result.findings, ())

    def test_undecodable_tls_certificate_is_explicit(self) -> None:
        self.assertEqual(_decode_peer_certificate(b"not-a-certificate"), {})

    @patch("netsentry.analysis.probes.logging.getLogger")
    @patch("smbprotocol.connection.Connection")
    def test_smbprobe_suppresses_library_logs(self, mock_connection, mock_get_logger) -> None:
        connection = mock_connection.return_value
        connection.dialect = 0x0311
        connection.server_security_mode = 3
        connection.server_guid = "server-guid"
        data = probe_smb("192.0.2.1")
        self.assertEqual(data.dialect, "SMB 3.1.1")
        mock_get_logger.assert_any_call("smbprotocol")
        self.assertTrue(mock_get_logger.return_value.setLevel.called)

    def test_unimplemented_observed_service_does_not_limit_complete_assessment(self) -> None:
        check = SMBConfigurationCheck(lambda host, port: SMBProbeData("SMB 3.1.1", False, True, True))
        assessment = assess_scan_result(
            HostScanResult(
                target="192.0.2.1",
                services=[service(445, "smb"), service(135, "msrpc")],
                scan_profile="full",
            ),
            checks=[check],
        )
        self.assertEqual(assessment.status, AssessmentStatus.COMPLETE)
        self.assertEqual(assessment.unimplemented_services, 1)
        self.assertEqual(assessment.coverage.checks_unavailable_or_failed, 0)

    def test_expired_tls_certificate_is_reported(self) -> None:
        expired = TLSProbeData("TLSv1.2", "AES256", "old.local", "Old CA", "Jan 01 00:00:00 2020 GMT", "Jan 01 00:00:00 2021 GMT", True, False)
        result = TLSConfigurationCheck(lambda host, port: expired).run(
            HostScanResult(target="192.0.2.2"), service(443, "https")
        )
        self.assertEqual(result.status, CheckStatus.COMPLETED)
        self.assertEqual(result.findings[0].title, "Expired TLS certificate")

    def test_non_tls_service_on_8443_is_inconclusive(self) -> None:
        def non_tls_probe(host, port):
            raise ProbeError("TLS handshake failed: server does not speak TLS")

        result = TLSConfigurationCheck(non_tls_probe).run(
            HostScanResult(target="192.0.2.2"), service(8443, "https-alt")
        )
        self.assertEqual(result.status, CheckStatus.INCONCLUSIVE)

    def test_tls_connection_failure_is_failed(self) -> None:
        def failed_tls_probe(host, port):
            raise ProbeError("connection refused")

        result = TLSConfigurationCheck(failed_tls_probe).run(
            HostScanResult(target="192.0.2.2"), service(8443, "https-alt")
        )
        self.assertEqual(result.status, CheckStatus.FAILED)

    def test_failed_service_probe_produces_limited_assessment(self) -> None:
        assessment = assess_scan_result(
            HostScanResult(target="192.168.1.20", services=[service(445, "smb")]),
            checks=[FailingCheck()],
        )
        self.assertEqual(assessment.status, AssessmentStatus.LIMITED)
        self.assertEqual(assessment.coverage.checks_unavailable_or_failed, 1)
        self.assertEqual(assessment.checks[0].status, CheckStatus.FAILED)
        self.assertIsNone(assessment.risk_score)

    def test_json_serialization_contains_structured_assessment(self) -> None:
        assessment = assess_scan_result(
            HostScanResult(target="8.8.8.8", services=[service(23, "telnet")]),
            checks=[ConfirmedFindingCheck("TEST-TELNET", "Telnet check", lambda item: item.port == 23, finding_factory(Severity.HIGH))],
        )
        payload = assessment.to_dict()
        encoded = json.dumps(payload)
        decoded = json.loads(encoded)
        self.assertEqual(decoded["host"], "8.8.8.8")
        self.assertEqual(decoded["risk"], {"severity": "HIGH", "score": 8})
        self.assertEqual(decoded["findings"][0]["rule_id"], "TEST")
        self.assertEqual(decoded["findings"][0]["port"], 23)

    def test_custom_rule_can_be_injected(self) -> None:
        analyzer = SecurityAnalyzer(rules=[])
        assessment = analyzer.assess(HostScanResult(target="192.168.1.20"))
        self.assertEqual(assessment.findings, ())


if __name__ == "__main__":
    unittest.main()
