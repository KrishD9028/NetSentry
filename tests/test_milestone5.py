"""Risk, evidence-scoped priorities, remediation, and reporting contracts."""
from contextlib import redirect_stdout
from dataclasses import replace
from io import StringIO
import json
import unittest

from netsentry.analysis.models import (
    Finding, Severity, Confidence, HostAssessment, AssessmentStatus,
    CheckStatus, SecurityCheckResult,
)
from netsentry.analysis.risk import finding_order, host_order, remediation_priority
from netsentry.analysis.remediation import remediation_details
from netsentry.analysis.checks import SMBConfigurationCheck, SSHConfigurationCheck
from netsentry.analysis.probes import SMBProbeData
from netsentry.analysis.ssh import SSHProbeData
from netsentry.main import _print_assessment, _network_assessment_payload, _print_network_assessment_summary, _build_parser
from netsentry.scanning.models import HostScanResult, PortService
from netsentry.analysis.engine import assess_scan_result
from tests.test_dns_evidence import _dns_query, reply, _parse_dns_response, assessment as dns_assessment
from tests.test_bundled_cves import cli as apache_cli


def finding(severity=Severity.HIGH, confidence=Confidence.HIGH, **kwargs):
    return Finding("fixture", "Observed issue", "Recorded weakness", severity, confidence,
                   "192.0.2.1", "Direct fixture evidence", "Correct the recorded control", "fixture",
                   port=445, protocol="tcp", service="smb", **kwargs)


def completed():
    return SecurityCheckResult("fixture", "Fixture check", CheckStatus.COMPLETED)


def host(findings=(), status=AssessmentStatus.COMPLETE, checks=None):
    return HostAssessment("192.0.2.1", findings=findings, status=status,
                          checks=(completed(),) if checks is None else checks)


def render(value, verbose=False):
    result = StringIO()
    with redirect_stdout(result):
        _print_assessment(value, verbose=verbose)
    return result.getvalue()


class RiskPolicyTests(unittest.TestCase):
    def test_critical_confirmed_above_high(self):
        critical = finding(Severity.CRITICAL, evidence_kind="configuration")
        high = finding()
        self.assertLess(finding_order(critical), finding_order(high))
        self.assertGreater(critical.score, high.score)
        self.assertEqual(remediation_priority(critical).value, "IMMEDIATE")

    def test_confidence_prioritizes_without_disguising_severity(self):
        certain, weak = finding(), finding(confidence=Confidence.LOW)
        self.assertLess(finding_order(certain), finding_order(weak))
        self.assertEqual(certain.score, weak.score)
        self.assertEqual(remediation_priority(finding(Severity.CRITICAL, Confidence.LOW)).value, "HIGH")

    def test_evidence_quality_breaks_ties(self):
        self.assertLess(finding_order(finding(evidence_kind="configuration")),
                        finding_order(finding(evidence_kind="observation")))
        self.assertEqual(remediation_priority(finding(Severity.CRITICAL)).value, "HIGH")

    def test_info_is_zero_and_informational(self):
        item = finding(Severity.INFO)
        self.assertEqual(item.score, 0)
        self.assertEqual(remediation_priority(item).value, "INFORMATIONAL")
        self.assertEqual(host((item,)).observed_risk_level.value, "INFO")

    def test_severity_scores_deterministic_bounded(self):
        for severity, score in ((Severity.INFO, 0), (Severity.LOW, 2), (Severity.MEDIUM, 5),
                                (Severity.HIGH, 8), (Severity.CRITICAL, 10)):
            for confidence in Confidence:
                item = finding(severity, confidence)
                self.assertEqual(item.score, score)
                self.assertEqual(item.score, item.score)
                self.assertLessEqual(item.score, 10)
                self.assertGreaterEqual(item.score, 0)

    def test_clean_complete_and_no_checks(self):
        self.assertEqual(host().overall_risk, {"severity": "INFO", "score": 0})
        self.assertEqual(host().observed_risk_score, 0)
        self.assertIsNone(host(checks=()).observed_risk_score)

    def test_limited_clean_and_known_finding(self):
        limited = host(status=AssessmentStatus.LIMITED)
        self.assertIsNone(limited.risk_score)
        self.assertEqual(limited.observed_risk_score, 0)
        known = replace(limited, findings=(finding(),))
        self.assertEqual(known.observed_risk_score, 8)
        self.assertIsNone(known.risk_score)

    def test_all_incomplete_statuses_keep_overall_unknown(self):
        for status in (AssessmentStatus.LIMITED, AssessmentStatus.ERROR, AssessmentStatus.UNREACHABLE):
            value = host((finding(),), status=status)
            self.assertEqual(value.overall_risk, {"severity": "UNKNOWN", "score": None})

    def test_explicit_exposure_promotes_action_only(self):
        item = finding(Severity.MEDIUM, exposure="external", exposure_evidence="Approved external vantage report")
        self.assertEqual(remediation_priority(item).value, "HIGH")
        self.assertEqual(item.score, 5)
        self.assertEqual(remediation_priority(replace(item, exposure_evidence=None)).value, "NORMAL")
        self.assertEqual(remediation_priority(replace(item, confidence=Confidence.LOW)).value, "NORMAL")

    def test_critical_service_requires_evidence(self):
        item = finding(Severity.MEDIUM, service_importance="critical")
        self.assertEqual(remediation_priority(item).value, "NORMAL")
        self.assertEqual(remediation_priority(replace(item, service_importance_evidence="Operator inventory")).value, "HIGH")

    def test_ip_class_never_implies_exposure(self):
        for address in ("8.8.8.8", "192.168.1.1", "100.100.201.193"):
            item = replace(finding(Severity.MEDIUM), host=address)
            self.assertEqual(remediation_priority(item).value, "NORMAL")
            self.assertIsNone(item.to_dict()["risk_context"]["exposure"])

    def test_private_scope_never_discounts(self):
        item = finding(exposure="private", exposure_evidence="Local test scope")
        self.assertEqual(item.score, 8)
        self.assertEqual(remediation_priority(item).value, "HIGH")

    def test_context_validation(self):
        for values in ({"exposure": "probably public"}, {"service_importance": "maybe"},
                       {"evidence_kind": "correlated"}):
            with self.assertRaises(ValueError):
                finding(**values)


class RemediationTests(unittest.TestCase):
    def test_actual_smb_findings_receive_specific_guidance(self):
        def probe(host: str, port: int) -> SMBProbeData:
            return SMBProbeData("SMB 3.1.1", True, True, False)

        result = assess_scan_result(HostScanResult("192.0.2.1", services=[PortService(445, "tcp", "open")]),
                                    checks=[SMBConfigurationCheck(probe)])
        self.assertEqual(len(result.findings), 2)
        for item in result.findings:
            data = item.remediation_details
            self.assertIn("SMB", data["summary"])
            self.assertIn("negotiation", data["validation"])
            self.assertEqual(data["applicability_confidence"], "HIGH")
            self.assertIsNone(data["without_service_disruption"])
            self.assertEqual(item.evidence_kind, "configuration")

    def test_tls_remediation_validity_and_chain(self):
        for title in ("Expired TLS certificate", "TLS certificate is not yet valid"):
            item = replace(finding(Severity.MEDIUM), title=title, rule_id="NS-CHECK-TLS", service="tls", port=443)
            data = remediation_details(item)
            self.assertIn("chain", data["validation"])
            self.assertIn("hostname", data["validation"])
            self.assertIn("certificate", data["summary"])
            self.assertTrue(data["references"])

    def test_ssh_exact_algorithm_and_direction_guidance(self):
        data = SSHProbeData("SSH-2.0-example", "2.0", {
            "kex": ("curve25519-sha256",), "host_key": ("ssh-ed25519",),
            "cipher_client_to_server": ("aes128-ctr",), "cipher_server_to_client": ("arcfour",),
            "mac_client_to_server": ("hmac-sha2-256",), "mac_server_to_client": ("hmac-sha2-256",)
        }, enumeration_status="completed")
        result = assess_scan_result(HostScanResult("192.0.2.1", services=[PortService(22, "tcp", "open")]),
                                    checks=[SSHConfigurationCheck(lambda *a, **kw: data)])
        item = result.findings[0]
        self.assertIn("arcfour", item.evidence)
        self.assertIn("cipher_server_to_client", item.evidence)
        self.assertIn("affected category", item.remediation_details["validation"])
        self.assertTrue(item.remediation_details["references"])

    def test_fallback_retains_custom_guidance_and_uncertainty(self):
        item = finding()
        self.assertEqual(item.remediation_details["summary"], item.remediation)
        self.assertEqual(item.remediation_details["applicability_confidence"], "LOW")
        self.assertIn(item.rule_id, item.remediation_details["validation"])
        self.assertIsNone(item.remediation_details["without_service_disruption"])

    def test_no_mistaken_template_by_title_alone(self):
        item = replace(finding(), title="SMB signing is not required")
        self.assertEqual(item.remediation_details["applicability_confidence"], "LOW")

    def test_actions_deterministic(self):
        items = (finding(Severity.LOW), finding(Severity.HIGH))
        self.assertEqual(host(items).priority_actions, host(tuple(reversed(items))).priority_actions)

    def test_real_cves_only_create_validation_work(self):
        code, output = apache_cli(flags=("--json",))
        value = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(value["priority_actions"], [])
        self.assertEqual(value["observed_risk"]["score"], 0)
        actions = value["correlation_validation_actions"]
        self.assertEqual(len(actions), 2)
        for item in actions:
            self.assertEqual(item["status"], "POTENTIAL")
            self.assertIsNone(item["remediation_applicable"])
            self.assertIn("before deciding", item["action"])
            self.assertEqual(item["advisory_severity"], "CRITICAL")


class Milestone5EvidenceTests(unittest.TestCase):
    def test_hint_produces_no_actions(self):
        value = assess_scan_result(HostScanResult("192.0.2.1", services=[PortService(22, "tcp", "open", "ssh")]), checks=[])
        self.assertEqual(value.priority_actions, [])
        self.assertIsNone(value.observed_risk_score)

    def test_inconclusive_check_no_actions(self):
        value = host(checks=(replace(completed(), status=CheckStatus.INCONCLUSIVE),), status=AssessmentStatus.LIMITED)
        self.assertEqual(value.priority_actions, [])
        self.assertIsNone(value.observed_risk_score)

    def test_dns_ra_still_no_finding_or_actions(self):
        query = _dns_query()
        value = dns_assessment(_parse_dns_response(query, reply(query), "TCP"))
        self.assertEqual(value.findings, ())
        self.assertEqual(value.priority_actions, [])
        self.assertIsNone(value.observed_risk_score)


class Milestone5ReportingTests(unittest.TestCase):
    def test_legacy_and_extended_json(self):
        value = host((finding(),), status=AssessmentStatus.LIMITED).to_dict()
        self.assertEqual(value["risk"], value["overall_risk"])
        self.assertIsNone(value["overall_risk"]["score"])
        item = value["findings"][0]
        self.assertEqual(item["remediation"], "Correct the recorded control")
        self.assertEqual(item["remediation_priority"], "HIGH")
        self.assertIn("validation", item["remediation_details"])
        self.assertIsNone(item["risk_context"]["exposure"])
        self.assertIn("policy", value["risk_explanation"])
        self.assertEqual(len(value["priority_actions"]), 1)

    def test_rendering_does_not_mutate(self):
        value = host((finding(),))
        before = json.dumps(value.to_dict())
        render(value)
        render(value, True)
        self.assertEqual(before, json.dumps(value.to_dict()))

    def test_clean_compact(self):
        output = render(host())
        self.assertIn("Observed Risk: INFO (0/10)", output)
        self.assertIn("No security findings.", output)
        self.assertNotIn("Coverage incomplete", output)
        self.assertNotIn("PRIORITY ACTIONS", output)

    def test_vulnerable_compact_actions_near_top(self):
        output = render(host((finding(),)))
        self.assertLess(output.index("PRIORITY ACTIONS"), output.index("PORT "))
        self.assertIn("[Priority: HIGH]", output)
        self.assertIn("Confidence: HIGH", output)

    def test_incomplete_compact_unknown(self):
        output = render(host(status=AssessmentStatus.LIMITED, checks=()))
        self.assertIn("Observed Risk: UNKNOWN", output)
        self.assertIn("Coverage incomplete", output)
        self.assertNotIn("(0/10)", output)

    def test_actions_bounded(self):
        items = tuple(replace(finding(), finding_id=str(i), port=i + 1) for i in range(8))
        output = render(host(items))
        self.assertIn("3 more actions in verbose/JSON output.", output)
        self.assertEqual(len(host(items).priority_actions), 8)

    def test_verbose_guidance_and_unknowns(self):
        output = render(host((finding(),)), True)
        self.assertIn("Remediation:", output)
        self.assertIn("Without service disruption: Unknown", output)
        self.assertIn("Risk scope:", output)

    def test_network_ranking_and_actions(self):
        high = host((finding(),), status=AssessmentStatus.LIMITED)
        clean = replace(host(), host="192.0.2.2")
        unknown = replace(host(status=AssessmentStatus.LIMITED, checks=()), host="192.0.2.3")
        values = [clean, unknown, high]
        self.assertEqual(sorted(values, key=host_order)[0], high)
        summary = _network_assessment_payload(values)["network_summary"]
        self.assertEqual(summary["hosts_with_findings"], 1)
        self.assertEqual(summary["incomplete_assessments"], 2)
        self.assertEqual(summary["unknown_observed_risk_hosts"], 1)
        self.assertEqual(summary["highest_risk_hosts"][0]["host"], high.host)
        self.assertEqual(len(summary["priority_actions"]), 1)
        output = StringIO()
        with redirect_stdout(output):
            _print_network_assessment_summary(values)
        self.assertIn("Incomplete assessments: 2", output.getvalue())
        self.assertIn("NETWORK PRIORITY ACTIONS", output.getvalue())

    def test_network_confidence_tiebreak(self):
        weak = host((finding(confidence=Confidence.LOW),))
        strong = replace(host((finding(),)), host="192.0.2.2")
        self.assertEqual(sorted([weak, strong], key=host_order)[0], strong)

    def test_compatible_commands_parse(self):
        for args in (["discover"], ["scan", "192.0.2.1"], ["scan", "--discovered"],
                     ["assess", "192.0.2.1"], ["assess", "--discovered"],
                     ["assess", "192.0.2.1", "--json"], ["assess", "192.0.2.1", "--verbose"]):
            self.assertIsNotNone(_build_parser().parse_args(args))
