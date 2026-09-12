import unittest
from dataclasses import replace
from unittest.mock import Mock
from netsentry.analysis.versions import AffectedVersionRange as Range, MatchStatus, match_version
from netsentry.analysis.correlation import (
    SoftwareEvidence, VulnerabilityDefinition, StaticVulnerabilityProvider,
    VulnerabilityCorrelation, CorrelationStatus, bind_correlation,
)
from netsentry.analysis.fingerprinting import collect_software_evidence
from netsentry.analysis.models import Confidence, Severity, CheckStatus
from netsentry.analysis.checks import HTTPConfigurationCheck
from netsentry.analysis.service_probes import HTTPProbeData
from netsentry.analysis.engine import assess_scan_result
from netsentry.scanning.models import HostScanResult, PortService, ServiceIdentity


def evidence(version="1.2.3", **kwargs):
    return SoftwareEvidence("Example", version, "http", Confidence.MEDIUM, "fixture", **kwargs)


def definition(**kwargs):
    return VulnerabilityDefinition("CVE-2099-0001", "Example", (Range("numeric", lower="1.0", upper="2.0"),), "fixture provider", **kwargs)


class VersionTests(unittest.TestCase):
    def test_every_inclusive_exclusive_boundary(self):
        for lower_inclusive in (True, False):
            for upper_inclusive in (True, False):
                interval = Range("numeric", lower="1.0", lower_inclusive=lower_inclusive, upper="2.0", upper_inclusive=upper_inclusive)
                for version, expected in (("0.9", False), ("1.0", lower_inclusive), ("1.5", True), ("2.0", upper_inclusive), ("2.1", False)):
                    with self.subTest(version=version, lower=lower_inclusive, upper=upper_inclusive):
                        self.assertEqual(match_version(version, interval).status, MatchStatus.MATCH if expected else MatchStatus.NO_MATCH)

    def test_numeric_order_is_not_lexical(self):
        self.assertEqual(match_version("1.10", Range("numeric", lower="1.9")).status, MatchStatus.MATCH)
        self.assertEqual(match_version("1.2", Range("numeric", exact="1.2.0")).status, MatchStatus.MATCH)

    def test_exact_and_open_ended_ranges(self):
        for interval in (Range("numeric", exact="1.2.3"), Range("numeric", lower="1.2.3"), Range("numeric", upper="1.2.3", upper_inclusive=True)):
            self.assertEqual(match_version("1.2.3", interval).status, MatchStatus.MATCH)

    def test_invalid_ranges_are_indeterminate(self):
        for interval in (Range("numeric"), Range("numeric", lower="2", upper="1"), Range("numeric", lower="1", upper="1"), Range("numeric", exact="1", lower="1"), Range("unknown", exact="1")):
            self.assertEqual(match_version("1", interval).status, MatchStatus.INDETERMINATE)

    def test_missing_malformed_and_oversized_versions_are_indeterminate(self):
        for version in (None, "", "foo", "1..2", "01.2", " 1.2", "1.2-ubuntu", "9" * 1000):
            self.assertEqual(match_version(version, Range("numeric", upper="2")).status, MatchStatus.INDETERMINATE)

    def test_semver_prerelease_precedence(self):
        ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]
        for first, second in zip(ordered, ordered[1:]):
            self.assertEqual(match_version(first, Range("semver", upper=second)).status, MatchStatus.MATCH)
            self.assertEqual(match_version(second, Range("semver", upper=first)).status, MatchStatus.NO_MATCH)

    def test_semver_build_metadata_ignored(self):
        self.assertEqual(match_version("1.2.3+build.1", Range("semver", exact="1.2.3+other")).status, MatchStatus.MATCH)

    def test_non_strict_semver_is_indeterminate(self):
        for value in ("1.2", "1.2.3-01", "v1.2.3", "1.2.3+", "1.2.3-alpha..1"):
            self.assertEqual(match_version(value, Range("semver", upper="2.0.0")).status, MatchStatus.INDETERMINATE)

    def test_openssh_variants_are_distinct(self):
        self.assertEqual(match_version("9.6p2", Range("openssh", lower="9.6p1"), variant="portable").status, MatchStatus.MATCH)
        for variant in (None, "windows", "upstream"):
            self.assertEqual(match_version("9.6p1", Range("openssh", exact="9.6p1"), variant=variant).status, MatchStatus.INDETERMINATE)
        self.assertEqual(match_version("9.6", Range("openssh", exact="9.6"), variant="windows").status, MatchStatus.MATCH)

    def test_opaque_only_supports_exact_literal(self):
        self.assertEqual(match_version("vendor_build-r7", Range("opaque", exact="vendor_build-r7")).status, MatchStatus.MATCH)
        self.assertEqual(match_version("vendor_build-r8", Range("opaque", exact="vendor_build-r7")).status, MatchStatus.NO_MATCH)
        self.assertEqual(match_version("vendor_build-r7", Range("opaque", lower="vendor_build-r1")).status, MatchStatus.INDETERMINATE)


class CorrelationTests(unittest.TestCase):
    def test_fresh_current_evidence_forced_potential(self):
        provider = StaticVulnerabilityProvider((definition(severity=Severity.HIGH, cvss=8.0, reference="https://example.test/advisory"),))
        first, second = evidence("1.1", host="10.0.0.1", port=80), evidence("1.9", host="10.0.0.2", port=8080)
        first_match, second_match = provider.correlate(first)[0], provider.correlate(second)[0]
        self.assertIsNot(first_match, second_match)
        self.assertEqual(second_match.evidence, second)
        self.assertEqual(second_match.status, CorrelationStatus.POTENTIAL)
        self.assertEqual(second_match.correlation_source, "fixture provider")

    def test_product_and_version_required(self):
        provider = StaticVulnerabilityProvider((definition(),))
        for item in (evidence(None), evidence("invalid"), evidence("3.0"), replace(evidence(), product="ExampleExtra")):
            self.assertEqual(provider.correlate(item), ())

    def test_vendor_and_variant_constraints_enforced(self):
        provider = StaticVulnerabilityProvider((definition(vendor="Vendor", variant="windows"),))
        for item in (evidence(), evidence(vendor="Other", variant="windows"), evidence(vendor="Vendor", variant="portable")):
            self.assertEqual(provider.correlate(item), ())
        self.assertEqual(len(provider.correlate(evidence(vendor="Vendor", variant="windows"))), 1)

    def test_openssh_definition_requires_variant_scope(self):
        record = replace(definition(), ranges=(Range("openssh", exact="9.6"),))
        self.assertEqual(StaticVulnerabilityProvider((record,)).correlate(evidence("9.6", variant="upstream")), ())

    def test_legacy_results_never_become_product_only_matches(self):
        legacy = VulnerabilityCorrelation("CVE-2099-0001", "Example", "<2.0", evidence("0.1"), CorrelationStatus.CONFIRMED, Confidence.HIGH)
        results, diagnostics = StaticVulnerabilityProvider(correlations=(legacy,)).evaluate(evidence())
        self.assertEqual(results, ())
        self.assertEqual(diagnostics[0]["status"], "INDETERMINATE")

    def test_provider_boundary_rebinds_status_and_caps_confidence(self):
        stale = VulnerabilityCorrelation("CVE-2099-0001", "Example", "<2.0", evidence("0.1"), CorrelationStatus.CONFIRMED, Confidence.HIGH, matched_range=Range("numeric", upper="2.0"))
        bound = bind_correlation(stale, evidence())
        self.assertEqual(bound.evidence.version, "1.2.3")
        self.assertEqual(bound.status, CorrelationStatus.POTENTIAL)
        self.assertEqual(bound.confidence, Confidence.MEDIUM)
        self.assertIsNone(bind_correlation(replace(stale, matched_range=None), evidence()))

    def test_indeterminate_diagnostic_has_no_positive(self):
        results, diagnostics = StaticVulnerabilityProvider((definition(),)).evaluate(evidence("1.2-vendor"))
        self.assertEqual(results, ())
        self.assertEqual(diagnostics[0]["status"], "INDETERMINATE")

    def test_http_products_are_correlated_after_checks_as_distinct_observations(self):
        records = (definition(), replace(definition(), product="Python", ranges=(Range("numeric", exact="3.14.6"),)))
        check = HTTPConfigurationCheck(Mock(return_value=HTTPProbeData(200, {}, None, "Example/1.2.3 Python/3.14.6", ())))
        result = assess_scan_result(HostScanResult("10.0.0.1", services=[PortService(80, "tcp", "open")]), checks=[check], vulnerability_provider=StaticVulnerabilityProvider(records))
        self.assertEqual({item["product"] for item in result.software_evidence}, {"Example", "Python"})
        self.assertEqual(len(result.potential_correlations), 2)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.observed_risk_score, 0)
        self.assertEqual(result.risk_score, 0)
        self.assertTrue(all(item["status"] == "POTENTIAL" for item in result.potential_correlations))

    def test_conflicting_versions_preserved_and_positive_withheld(self):
        item = PortService(80, "tcp", "open", service="http", product="Example", version="1.0", service_method="probed", service_confidence="10", identities=(ServiceIdentity("http", "Nmap", {"service": "http"}),))
        check = HTTPConfigurationCheck(Mock(return_value=HTTPProbeData(200, {}, None, "Example/1.9", ())))
        result = assess_scan_result(HostScanResult("10.0.0.1", services=[item]), checks=[check], vulnerability_provider=StaticVulnerabilityProvider((definition(),)))
        self.assertEqual({record["version"] for record in result.software_evidence}, {"1.0", "1.9"})
        self.assertEqual(result.potential_correlations, ())
        self.assertTrue(all(diagnostic["status"] == "INDETERMINATE" for diagnostic in result.correlation_diagnostics))

    def test_ssh_variant_evidence_is_preserved(self):
        for banner, variant in (("OpenSSH_for_Windows_9.5", "windows"), ("OpenSSH_9.6p1", "portable"), ("OpenSSH_9.6", "upstream")):
            item = PortService(22, "tcp", "open", identities=(ServiceIdentity("ssh", "SSH banner", {"banner": "SSH-2.0-" + banner}),))
            observations = collect_software_evidence(item)
            self.assertEqual(observations[0].variant, variant)

    def test_conflicting_merge_never_silently_selects_a_version(self):
        from netsentry.analysis.fingerprinting import merge_fingerprints
        self.assertIsNone(merge_fingerprints((evidence("1.0"), evidence("1.9"))))

    def test_legacy_range_string_is_indeterminate(self):
        self.assertEqual(match_version("1.0", "<2.0").status, MatchStatus.INDETERMINATE)
        record = replace(definition(), ranges=("<2.0",))
        matches, diagnostics = StaticVulnerabilityProvider((record,)).evaluate(evidence())
        self.assertEqual(matches, ())
        self.assertEqual(diagnostics[0]["status"], "INDETERMINATE")
