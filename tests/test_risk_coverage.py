"""Observed risk remains independent of port evidence and assessment completeness."""
import json
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from io import StringIO

from netsentry.analysis.models import (
    AssessmentCoverage, AssessmentStatus, AttackSurfaceObservation, CheckStatus,
    Confidence, Finding, HostAssessment, RiskLevel, SecurityCheckResult, Severity,
)
from netsentry.main import _network_assessment_payload, _print_assessment, _print_network_assessment_summary


def retest_fixture():
    host = "192.0.2.1"
    observations = tuple(
        AttackSurfaceObservation(
            host, port, "tcp", service, None, None, "Fixture evidence",
            state=state, identification_status="CONFIRMED" if service else "HINT",
            service_hint=hint,
        )
        for port, state, service, hint in (
            (22, "unknown", None, "ssh"), (135, "open", None, "msrpc"),
            (139, "open", None, "netbios-ssn"), (445, "open", "smb", "microsoft-ds"),
            (8443, "open", "https", "https-alt"),
        )
    )
    checks = tuple(SecurityCheckResult(name, name, CheckStatus.COMPLETED, port=port, protocol="tcp")
                   for name, port in (("SMB", 445), ("TLS", 8443), ("HTTP", 8443)))
    return HostAssessment(
        host, observations=observations, checks=checks, status=AssessmentStatus.LIMITED,
        status_reason="Port-state evidence is incomplete or traffic filtering prevents assessment.",
    )


def finding(severity):
    return Finding("fixture", "Accepted test finding", "Fixture", severity, Confidence.HIGH,
                   "192.0.2.1", "Accepted fixture evidence", "Fixture remediation", "fixture")


class CoverageTests(unittest.TestCase):
    def test_four_open_endpoints_two_confirmed_services(self):
        coverage = retest_fixture().coverage
        self.assertEqual((coverage.open_ports, coverage.confirmed_services, coverage.unconfirmed_open_ports), (4, 2, 2))
        self.assertEqual((coverage.checks_attempted, coverage.checks_completed), (3, 3))
        self.assertEqual(coverage.checks_unavailable_or_failed, 0)

    def test_https_counts_once_despite_two_checks_and_duplicate_observations(self):
        base = retest_fixture()
        https = base.observations[-1]
        result = replace(base, observations=(https, https), checks=base.checks[1:])
        self.assertEqual(result.coverage.open_ports, 1)
        self.assertEqual(result.coverage.confirmed_services, 1)
        self.assertEqual(result.coverage.checks_completed, 2)

    def test_nonopen_endpoints_do_not_count_even_with_stale_identity(self):
        base = retest_fixture()
        for state in ("closed", "filtered", "unknown"):
            result = replace(base, observations=(replace(base.observations[-1], state=state),))
            self.assertEqual(result.coverage.open_ports, 0)
            self.assertEqual(result.coverage.confirmed_services, 0)

    def test_endpoint_key_includes_host_and_transport(self):
        base = retest_fixture()
        observation = base.observations[-1]
        result = replace(base, observations=(observation, replace(observation, protocol="udp"), replace(observation, host="192.0.2.2")))
        self.assertEqual(result.coverage.open_ports, 3)
        self.assertEqual(result.coverage.confirmed_services, 3)

    def test_hint_or_missing_service_never_counts_as_confirmed(self):
        base = retest_fixture()
        item = base.observations[-1]
        for observation in (replace(item, identification_status="HINT"), replace(item, service=None)):
            coverage = replace(base, observations=(observation,)).coverage
            self.assertEqual(coverage.confirmed_services, 0)
            self.assertEqual(coverage.unconfirmed_open_ports, 1)

    def test_legacy_alias_and_constructor_keep_open_port_meaning(self):
        coverage = retest_fixture().coverage
        self.assertEqual(coverage.services_discovered, 4)
        self.assertEqual(coverage.to_dict()["services_discovered"], coverage.to_dict()["open_ports"])
        legacy = AssessmentCoverage(4, 3, 3, 0)
        self.assertEqual(legacy.open_ports, 4)
        self.assertEqual(AssessmentCoverage(services_discovered=4, checks_attempted=3, checks_completed=3, checks_unavailable_or_failed=0), legacy)

    def test_inconclusive_is_in_existing_combined_counter(self):
        result = replace(retest_fixture(), checks=tuple(SecurityCheckResult(str(status), str(status), status) for status in CheckStatus))
        self.assertEqual(result.coverage.checks_completed, 1)
        self.assertEqual(result.coverage.checks_unavailable_or_failed, 3)


class ObservedRiskTests(unittest.TestCase):
    def test_limited_completed_checks_without_findings(self):
        result = retest_fixture()
        self.assertEqual(result.observed_risk_level, RiskLevel.INFO)
        self.assertEqual(result.observed_risk_score, 0)
        self.assertEqual(result.risk_level, RiskLevel.UNKNOWN)
        self.assertIsNone(result.risk_score)

    def test_limited_high_and_critical_findings_remain_visible(self):
        for severity in (Severity.HIGH, Severity.CRITICAL):
            result = replace(retest_fixture(), findings=(finding(Severity.LOW), finding(severity)))
            self.assertEqual(result.observed_risk_level.value, severity.value)
            self.assertEqual(result.observed_risk_score, severity.score)
            self.assertEqual(result.risk_level, RiskLevel.UNKNOWN)
            self.assertIsNone(result.risk_score)

    def test_accepted_finding_does_not_require_completed_check_count(self):
        result = replace(retest_fixture(), checks=(), findings=(finding(Severity.HIGH),))
        self.assertEqual(result.observed_risk_score, 8)

    def test_no_completed_checks_yields_unknown_for_every_assessment_status(self):
        for status in AssessmentStatus:
            result = replace(retest_fixture(), checks=(), status=status)
            self.assertEqual(result.observed_risk_level, RiskLevel.UNKNOWN)
            self.assertIsNone(result.observed_risk_score)

    def test_failed_unavailable_and_inconclusive_checks_do_not_establish_zero(self):
        for status in (CheckStatus.FAILED, CheckStatus.UNAVAILABLE, CheckStatus.INCONCLUSIVE):
            result = replace(retest_fixture(), checks=(SecurityCheckResult("test", "test", status),))
            self.assertIsNone(result.observed_risk_score)

    def test_one_completed_check_is_sufficient_for_scoped_zero(self):
        base = retest_fixture()
        result = replace(base, checks=(base.checks[0], SecurityCheckResult("failed", "failed", CheckStatus.FAILED)))
        self.assertEqual(result.observed_risk_score, 0)
        self.assertIsNone(result.risk_score)

    def test_potential_cves_do_not_affect_observed_risk(self):
        base = replace(retest_fixture(), potential_correlations=({"cve_id": "CVE-2099-0001", "status": "POTENTIAL", "severity": "CRITICAL", "cvss": 10},))
        self.assertEqual(base.observed_risk_score, 0)
        self.assertIsNone(replace(base, checks=()).observed_risk_score)

    def test_port_states_and_identification_attempts_do_not_affect_observed_risk(self):
        base = retest_fixture()
        for state in ("open", "closed", "filtered", "unknown"):
            item = replace(base.observations[0], state=state, identification_attempts=({"status": "INCONCLUSIVE"},))
            result = replace(base, observations=(item,), checks=())
            self.assertIsNone(result.observed_risk_score)

    def test_complete_overall_risk_keeps_existing_behavior(self):
        for findings, score in (((), 0), ((finding(Severity.HIGH),), 8)):
            result = replace(retest_fixture(), status=AssessmentStatus.COMPLETE, findings=findings)
            self.assertEqual(result.risk_score, score)
            self.assertEqual(result.observed_risk_score, score)

    def test_legacy_json_risk_is_unchanged_with_scoped_addition(self):
        data = json.loads(json.dumps(retest_fixture().to_dict()))
        self.assertEqual(data["risk"], {"severity": "UNKNOWN", "score": None})
        self.assertEqual(data["observed_risk"], {"severity": "INFO", "score": 0, "scope": "assessed_evidence"})
        self.assertEqual(data["coverage"]["services_discovered"], 4)
        self.assertEqual(data["coverage"]["confirmed_services"], 2)


class RiskReportingTests(unittest.TestCase):
    def render(self, printer, value):
        output = StringIO()
        with redirect_stdout(output):
            printer(value)
        return output.getvalue()

    def test_retest_terminal_scope_and_coverage(self):
        output = self.render(_print_assessment, retest_fixture())
        for text in ("Status: LIMITED", "Observed Risk: INFO (0/10)",
                     "Coverage incomplete; overall target risk is unknown.",
                     "4 open ports | 2 confirmed services | 3/3 checks completed"):
            self.assertIn(text, output)
        self.assertNotIn("Services discovered:", output)

    def test_high_finding_prominent_in_limited_terminal(self):
        output = self.render(_print_assessment, replace(retest_fixture(), findings=(finding(Severity.HIGH),)))
        self.assertIn("Observed Risk: HIGH", output)
        self.assertIn("Observed Risk: HIGH (8/10)", output)
        self.assertIn("[HIGH] Accepted test finding", output)
        self.assertIn("overall target risk is unknown.", output)

    def test_no_completed_checks_terminal_does_not_claim_zero(self):
        output = self.render(_print_assessment, replace(retest_fixture(), checks=()))
        self.assertIn("Observed Risk: UNKNOWN", output)
        self.assertIn("No security checks completed", output)

    def test_network_ranks_known_observed_risk_ahead_of_complete_zero(self):
        high = replace(retest_fixture(), findings=(finding(Severity.HIGH),))
        clean = replace(retest_fixture(), host="192.0.2.2", status=AssessmentStatus.COMPLETE)
        unknown = replace(retest_fixture(), host="192.0.2.3", checks=())
        assessments = [clean, unknown, high]
        ranked = _network_assessment_payload(assessments)["network_summary"]["highest_risk_hosts"]
        self.assertEqual([row["host"] for row in ranked], [high.host, clean.host, unknown.host])
        self.assertEqual(ranked[0]["severity"], "UNKNOWN")
        self.assertIsNone(ranked[0]["score"])
        self.assertEqual(ranked[0]["observed_risk"]["score"], 8)
        self.assertEqual(ranked[0]["assessment_status"], "LIMITED")
        self.assertEqual(ranked[0]["coverage"]["confirmed_services"], 2)
        output = self.render(_print_network_assessment_summary, assessments)
        self.assertLess(output.index(high.host), output.index(clean.host))
        self.assertIn("Observed: HIGH 8/10; Assessment: LIMITED; Overall: UNKNOWN", output)

    def test_network_critical_findings_are_counted_and_ranked_first(self):
        critical = replace(retest_fixture(), findings=(finding(Severity.CRITICAL),))
        high = replace(retest_fixture(), host="192.0.2.2", findings=(finding(Severity.HIGH),))
        output = self.render(_print_network_assessment_summary, [high, critical])
        self.assertIn("CRITICAL: 1", output)
        self.assertLess(output.index(critical.host), output.index(high.host))
