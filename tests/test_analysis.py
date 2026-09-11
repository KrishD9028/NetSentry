import json
import unittest

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
from netsentry.analysis.checks import ServiceCheck
from netsentry.analysis.models import CheckStatus, SecurityCheckResult
from netsentry.scanning.models import HostScanResult, PortService


def service(port: int, name: str | None, protocol: str = "tcp") -> PortService:
    return PortService(port=port, protocol=protocol, state="open", service=name)


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

    def test_empty_full_scan_can_complete_with_zero_risk(self) -> None:
        assessment = assess_scan_result(
            HostScanResult(target="192.168.1.20", scan_profile="full", requested_ports=tuple(range(1, 65536)))
        )
        self.assertEqual(assessment.status, AssessmentStatus.COMPLETE)
        self.assertEqual(assessment.risk_score, 0)
        self.assertEqual(assessment.risk_level, RiskLevel.INFO)

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
        self.assertEqual(assessment.status, AssessmentStatus.LIMITED)

    def test_http_and_unknown_services_are_detected(self) -> None:
        result = HostScanResult(
            target="192.168.1.20",
            services=[service(80, "http"), service(8080, None)],
        )
        assessment = assess_scan_result(result)
        self.assertEqual(assessment.findings, ())
        self.assertEqual(len(assessment.observations), 2)
        self.assertEqual(assessment.coverage.checks_attempted, 2)
        self.assertEqual(assessment.risk_level, RiskLevel.UNKNOWN)

    def test_tls_service_does_not_trigger_http_rule(self) -> None:
        assessment = assess_scan_result(
            HostScanResult(target="192.168.1.20", services=[service(443, "https")])
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
