"""Presentation must preserve the assessment and scanner evidence."""
import json
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from io import StringIO
from unittest.mock import patch

from netsentry.analysis.models import (
    AttackSurfaceObservation, HostAssessment, SecurityCheckResult,
    CheckStatus, AssessmentStatus, Finding, Severity, Confidence,
)
from netsentry.main import _print_assessment, _build_parser, _run_assess

HOST = "100.100.201.201"


def observation(port, state="unknown", scanner=None, service=None, hint=None):
    return AttackSurfaceObservation(
        HOST, port, "tcp", service, None, None, "fixture",
        state=state, scanner_state=scanner, scanner_reason="no-response",
        scanner_source="Nmap XML port", service_hint=hint,
        identification_status="CONFIRMED" if service else "HINT" if hint else "UNKNOWN",
    )


def windows_fixture():
    observations = (
        observation(22, scanner="filtered", hint="ssh"),
        observation(135, "open", "open", hint="msrpc"),
        observation(139, "open", "open", hint="netbios-ssn"),
        observation(445, "open", "open", "smb"),
        replace(observation(8443, "open", "open", "https"),
                identities=({"protocol": "tls", "source": "TLS handshake", "evidence": {"version": "TLSv1.3"}},),
                identification_attempts=({"protocol": "http", "status": "confirmed"},)),
    ) + tuple(observation(port) for port in range(9000, 9018))
    checks = (
        SecurityCheckResult("smb", "SMB configuration", CheckStatus.COMPLETED, 445, "tcp", "smb",
                            details={"dialect": "SMB 3.1.1", "signing_required": True}),
        SecurityCheckResult("tls", "TLS configuration", CheckStatus.COMPLETED, 8443, "tcp", "tls",
                            details={"tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                                     "subject": "CN=fixture", "issuer": "CN=fixture CA"}),
        SecurityCheckResult("http", "HTTP security configuration", CheckStatus.COMPLETED, 8443, "tcp", "http",
                            details={"status": 401, "server": "SecureWindowsFileServer/1.0"}),
    )
    return HostAssessment(HOST, observations=observations, checks=checks,
                          status_reason="Incomplete port-state evidence.")


def render(assessment, verbose=False):
    output = StringIO()
    with redirect_stdout(output):
        _print_assessment(assessment, verbose=verbose)
    return output.getvalue()


class ReportingTests(unittest.TestCase):
    def test_filtered_is_display_only(self):
        assessment = windows_fixture()
        before = json.dumps(assessment.to_dict())
        self.assertIn("Filtered: 22/tcp (ssh)", render(assessment))
        self.assertEqual(assessment.observations[0].state, "unknown")
        self.assertEqual(before, json.dumps(assessment.to_dict()))

    def test_ambiguous_and_missing_raw_states_never_filtered(self):
        for raw in ("open|filtered", "unsupported", "unknown", None):
            with self.subTest(raw=raw):
                output = render(HostAssessment(HOST, observations=(observation(22, scanner=raw),)))
                self.assertNotIn("Filtered:", output)
                self.assertIn("1 inconclusive ports", output)

    def test_normalized_filtered_without_scanner_evidence_not_displayed_filtered(self):
        self.assertNotIn("Filtered:", render(HostAssessment(HOST, observations=(observation(22, "filtered"),))))

    def test_hints_and_confirmed_services(self):
        output = render(windows_fixture())
        self.assertRegex(output, r"445/tcp\s+open\s+smb")
        self.assertRegex(output, r"135/tcp\s+open\s+\(msrpc\)")
        self.assertRegex(output, r"8443/tcp\s+open\s+https")
        self.assertNotIn("hint:", output)

    def test_closed_omitted(self):
        output = render(HostAssessment(HOST, observations=(observation(22, "closed", "closed"),)))
        self.assertNotIn("22/tcp", output)
        self.assertIn("Not shown: 1 closed ports", output)

    def test_large_lists_bounded_and_exclusive(self):
        items = tuple(observation(p, scanner="filtered") for p in range(1, 1001))
        items += tuple(observation(p) for p in range(1001, 2001))
        output = render(HostAssessment(HOST, observations=tuple(reversed(items))))
        self.assertIn("992 more filtered ports not shown", output)
        self.assertIn("Not shown: 1000 inconclusive ports", output)
        self.assertNotIn("1001/tcp", output)
        self.assertLess(len(output.splitlines()), 30)
        self.assertEqual(output, render(HostAssessment(HOST, observations=items)))

    def test_verbose_contains_complete_evidence_without_mutation(self):
        assessment = replace(windows_fixture(), software_evidence=({"product": "example"},),
                             correlation_diagnostics=({"status": "INDETERMINATE"},))
        before = json.dumps(assessment.to_dict())
        output = render(assessment, True)
        for token in ('"state": "unknown"', '"scanner_state": "filtered"', '"scanner_reason": "no-response"',
                      '"scanner_source": "Nmap XML port"', '"identities"', '"identification_attempts"',
                      'CN=fixture CA', 'SOFTWARE OBSERVATIONS', 'INDETERMINATE', 'COVERAGE EVIDENCE'):
            self.assertIn(token, output)
        self.assertEqual(before, json.dumps(assessment.to_dict()))

    def test_complete_and_limited_risk(self):
        self.assertIn("Coverage incomplete", render(windows_fixture()))
        output = render(replace(windows_fixture(), status=AssessmentStatus.COMPLETE))
        self.assertNotIn("Coverage incomplete", output)
        self.assertIn("Observed Risk: INFO (0/10)", output)

    def test_zero_checks_unknown(self):
        output = render(replace(windows_fixture(), checks=()))
        self.assertIn("Observed Risk: UNKNOWN\n", output)
        self.assertNotIn("(0/10)", output)

    def test_all_check_statuses_visible_and_single_line(self):
        checks = tuple(SecurityCheckResult(s.value, "Example check", s, reason="first\nsecond") for s in CheckStatus)
        output = render(HostAssessment(HOST, checks=checks))
        for status in CheckStatus:
            self.assertIn(status.value, output)
        self.assertIn("1 unavailable | 1 failed | 1 inconclusive", output)
        self.assertNotIn("PASS", output)
        self.assertIn("first second", output)

    def test_findings_sorted_and_prominent_potentials_separate(self):
        findings = tuple(Finding(s.value, s.value + " issue", "description", s, Confidence.HIGH,
                                 HOST, "brief evidence", "remediation", "rule", 445, "tcp", "smb")
                         for s in (Severity.LOW, Severity.CRITICAL, Severity.HIGH))
        correlation = {"cve_id": "CVE-fixture", "product": "example", "evidence": {"version": "1"}}
        output = render(replace(windows_fixture(), findings=findings, potential_correlations=(correlation,)))
        self.assertLess(output.index("FINDINGS"), output.index("PORT "))
        self.assertLess(output.index("[CRITICAL]"), output.index("[HIGH]"))
        self.assertLess(output.index("[HIGH]"), output.index("[LOW]"))
        self.assertIn(HOST + ":445/tcp (smb)", output)
        self.assertIn("POTENTIAL CVE CORRELATIONS (not confirmed findings)", output)

    @patch("netsentry.main.assess_scan_result")
    @patch("netsentry.main.scan_target")
    def test_json_verbose_exact_bytes(self, scan, assess):
        assessment = windows_fixture()
        assess.return_value = assessment
        outputs = []
        for flags in (["--json"], ["--json", "--verbose"]):
            output = StringIO()
            with redirect_stdout(output):
                code = _run_assess(_build_parser().parse_args(["assess", HOST] + flags))
            self.assertEqual(code, 0)
            outputs.append(output.getvalue())
        self.assertEqual(outputs[0], json.dumps(assessment.to_dict(), indent=2) + "\n")
        self.assertEqual(outputs[0], outputs[1])

    @patch("netsentry.main.load_current_snapshot")
    @patch("netsentry.main.assess_scan_result")
    @patch("netsentry.main.scan_target")
    def test_discovered_modes_consistent(self, scan, assess, snapshot):
        from netsentry.discovery.models import Device
        snapshot.return_value = [Device(HOST, None, None, "Unknown"), Device("100.100.201.202", None, None, "Unknown")]
        assess.return_value = windows_fixture()
        for flags, verbose in (([], False), (["-v"], True)):
            output = StringIO()
            with redirect_stdout(output):
                _run_assess(_build_parser().parse_args(["assess", "--discovered"] + flags))
            text = output.getvalue()
            self.assertEqual(text.count("NetSentry Security Assessment"), 2)
            self.assertEqual(text.count("PORT EVIDENCE"), 2 if verbose else 0)
            self.assertEqual(text.count("Filtered: 22/tcp (ssh)"), 0 if verbose else 2)
            self.assertIn("NETWORK ASSESSMENT SUMMARY", text)
