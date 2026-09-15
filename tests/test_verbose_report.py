"""Verbose expands user-facing evidence, not internal serialization."""
from dataclasses import replace
import json
import unittest

from tests.test_reporting import windows_fixture, render
from tests.test_milestone5 import finding
from netsentry.analysis.models import SecurityCheckResult, CheckStatus


class VerboseReportTests(unittest.TestCase):
    def test_normal_information_is_preserved(self):
        value = windows_fixture()
        normal, verbose = render(value), render(value, True)
        for line in normal.splitlines():
            if line.strip():
                self.assertIn(line, verbose)
        self.assertIn("Signing required: Yes", verbose)
        self.assertIn("Certificate issuer: CN=fixture CA", verbose)
        self.assertIn("Requested ports:", verbose)

    def test_raw_models_and_unknown_details_never_dumped(self):
        raw = '<nmaprun><host>RAW_SECRET_MARKER</host></nmaprun>'
        value = windows_fixture()
        checks = tuple(replace(c, details={**c.details, "raw_xml": raw, "raw_response": "BLOB_MARKER",
                                          "debug": {"nested": ["SERIALIZED_MARKER"]}}) for c in value.checks)
        value = replace(value, checks=checks, raw_xml=raw, port_summary=({"raw": "SCANNER_BLOB"},),
                        findings=(finding(),))
        before = json.dumps(value.to_dict())
        output = render(value, True)
        for marker in ("raw_xml", "<nmaprun", "RAW_SECRET_MARKER", "BLOB_MARKER", "SERIALIZED_MARKER",
                       "SCANNER_BLOB", '"attack_surface"', "'nested':", '"checks_attempted":',
                       "None", "{", "}"):
            self.assertNotIn(marker, output)
        self.assertIn("RAW_SECRET_MARKER", before)
        self.assertEqual(json.dumps(value.to_dict()), before)

    def test_check_unknown_container_is_not_repr(self):
        value = windows_fixture()
        check = replace(value.checks[0], details={"dialect": {"internal": ["do not render"]}})
        output = render(replace(value, checks=(check,)), True)
        self.assertNotIn("'internal'", output)
        self.assertNotIn("do not render", output)

    def test_rdp_properties_contradictions_and_failures(self):
        check = SecurityCheckResult("NS-CHECK-RDP", "RDP security negotiation", CheckStatus.INCONCLUSIVE,
                                    3389, "tcp", "rdp", "Conflicting negotiation responses",
                                    details={"nla_available": True, "nla_required": None,
                                             "legacy_accepted": None, "tls_used": True,
                                             "contradictions": ["TLS accepted after a requirement rejection"],
                                             "attempts": [{"requested_protocols": 3, "selected_protocol": 2,
                                                           "status": "inconclusive", "tls_error": "Certificate unavailable",
                                                           "raw_response": "RAW_RDP",
                                                           "certificate": {"subject": "example.test"}}]})
        output = render(replace(windows_fixture(), checks=(check,)), True)
        for text in ("NLA available: Yes", "NLA required: Unknown", "TLS used: Yes",
                     "Legacy security accepted: Unknown", "Contradiction:", "TLS failure: Certificate unavailable",
                     "Selected security: CredSSP", "Certificate subject: example.test"):
            self.assertIn(text, output)
        self.assertNotIn("RAW_RDP", output)

    def test_remediation_and_validation_are_readable(self):
        output = render(replace(windows_fixture(), findings=(finding(),)), True)
        for label in ("FINDINGS", "Remediation:", "Validation:", "Applicability reasoning:",
                      "Disruption considerations:", "Without service disruption: Unknown"):
            self.assertIn(label, output)

    def test_cve_range_and_reasoning_no_dictionary(self):
        correlation = {"cve_id": "CVE-example", "product": "Example", "evidence": {"version": "1.5"},
                       "severity": "HIGH", "matched_range": {"scheme": "numeric", "lower": "1.0",
                       "lower_inclusive": True, "upper": "2.0", "upper_inclusive": False},
                       "match_reason": "Version satisfies the explicit range.", "confidence": "MEDIUM"}
        output = render(replace(windows_fixture(), potential_correlations=(correlation,)), True)
        self.assertIn("Affected range: >=1.0 and <2.0", output)
        self.assertIn("Match reasoning: Version satisfies", output)
        self.assertIn("Validation: Verify installed version", output)
        self.assertNotIn("'scheme':", output)

    def test_tls_layer_is_expanded_when_service_is_https(self):
        check = replace(windows_fixture().checks[1], check_id="NS-CHECK-TLS", service="https")
        output = render(replace(windows_fixture(), checks=(check,)), True)
        self.assertIn("Certificate issuer: CN=fixture CA", output)
