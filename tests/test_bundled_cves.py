"""Real offline advisories reach the normal CLI without injected providers."""
from contextlib import redirect_stdout
from copy import deepcopy
from dataclasses import replace
from importlib import resources
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from netsentry.analysis.bundled_cves import DatasetError, load_bundled_provider, parse_dataset
from netsentry.analysis.checks import HTTPConfigurationCheck
from netsentry.analysis.correlation import SoftwareEvidence
from netsentry.analysis.engine import assess_scan_result
from netsentry.analysis.models import Confidence
from netsentry.planning import Budget
from netsentry.analysis.service_probes import HTTPProbeData
from netsentry.discovery.models import Device
from netsentry.main import _build_parser, _run_assess
from netsentry.scanning.models import HostScanResult, PortService

HOST = "192.0.2.1"


def evidence(version="2.4.49", **kwargs):
    return SoftwareEvidence("Apache", version, "http", Confidence.MEDIUM, "HTTP Server header", **kwargs)


def http_check(version):
    data = HTTPProbeData(200, {"server": f"Apache/{version}"}, None, f"Apache/{version}", ())
    return HTTPConfigurationCheck(lambda *args, **kwargs: data)


def cli(version="2.4.49", flags=()):
    # Network acquisition and elapsed time are controlled. The CLI, evidence collection, bundled
    # loader, version matcher, and correlation binding all run normally.
    scan = HostScanResult(HOST, services=[PortService(80, "tcp", "open")], scan_profile="common")
    output = StringIO()
    with patch("netsentry.main.scan_target", return_value=scan), patch(
        "netsentry.analysis.engine.default_service_checks", return_value=(http_check(version),)
    ), patch("netsentry.planning.loop.Budget", side_effect=lambda limits: Budget(limits, clock=lambda: 0)), redirect_stdout(output):
        result = _run_assess(_build_parser().parse_args(["assess", HOST, "--profile", "common", *flags]))
    return result, output.getvalue()


class BundledDatasetTests(unittest.TestCase):
    def setUp(self):
        self.raw = json.loads(resources.files("netsentry").joinpath("data", "cves.json").read_text())
        self.provider, self.metadata = load_bundled_provider()

    def test_load_real_definitions(self):
        self.assertEqual(self.metadata["definition_count"], 2)
        self.assertEqual(len(self.provider.definitions), 2)
        self.assertEqual({d.cve_id for d in self.provider.definitions}, {"CVE-2021-41773", "CVE-2021-42013"})

    def test_exact_affected_versions_and_boundaries(self):
        expected = {"2.4.48": set(), "2.4.49": {"CVE-2021-41773", "CVE-2021-42013"},
                    "2.4.50": {"CVE-2021-42013"}, "2.4.51": set()}
        for version, ids in expected.items():
            with self.subTest(version=version):
                self.assertEqual({m.cve_id for m in self.provider.correlate(evidence(version))}, ids)

    def test_missing_indeterminate_and_wrong_products(self):
        for version in (None, "", "unknown", "2.4.49-vendor", "2.4.49 (patched)"):
            self.assertEqual(self.provider.correlate(evidence(version)), ())
        for product in ("Apache Tomcat", "NotApache", "Apache httpd"):
            self.assertEqual(self.provider.correlate(replace(evidence(), product=product)), ())

    def test_fresh_potential_source_reference_limitations(self):
        current = evidence(host=HOST, port=80)
        matches = self.provider.correlate(current)
        for match in matches:
            self.assertEqual(match.status.value, "POTENTIAL")
            self.assertIs(match.evidence, current)
            self.assertEqual(match.correlation_source, "Apache HTTP Server Project")
            self.assertTrue(match.reference.endswith("#" + match.cve_id))
            self.assertIn("exploitability have not been verified", match.to_dict()["limitations"])
        self.assertIsNot(matches[0], self.provider.correlate(current)[0])

    def test_vendor_variant_constraints_not_relaxed_by_loader(self):
        self.raw["definitions"][0].update(vendor="Apache Software Foundation", variant="upstream")
        provider, _ = parse_dataset(json.dumps(self.raw))
        def matches(item):
            return any(m.cve_id == "CVE-2021-41773" for m in provider.correlate(item))
        self.assertFalse(matches(evidence()))
        self.assertFalse(matches(evidence(vendor="Other", variant="upstream")))
        self.assertFalse(matches(evidence(vendor="Apache Software Foundation", variant="windows")))
        self.assertTrue(matches(evidence(vendor="Apache Software Foundation", variant="upstream")))

    def test_malformed_documents(self):
        for raw in ("{", "[]", "null", '{"a": 1, "a": 2}', " " * 262145):
            with self.subTest(raw=raw[:20]), self.assertRaises(DatasetError):
                parse_dataset(raw)

    def test_invalid_metadata(self):
        for key, value in (("schema_version", 2), ("schema_version", True), ("revision", ""),
                           ("reviewed", "2026-13-01"), ("definition_count", 3), ("definition_count", True),
                           ("coverage_notes", ""), ("definitions", [])):
            raw = deepcopy(self.raw)
            raw[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(DatasetError):
                parse_dataset(json.dumps(raw))

    def test_invalid_entries(self):
        for key, value in (("cve_id", "CVE-fixture"), ("source", ""), ("reference", "file:///tmp/a"),
                           ("reference", "https://user:password@example.org/"), ("product", ""),
                           ("severity", "SEVERE"), ("limitations", ""), ("vendor", None)):
            raw = deepcopy(self.raw)
            raw["definitions"][0][key] = value
            with self.subTest(key=key), self.assertRaises(DatasetError):
                parse_dataset(json.dumps(raw))
        del self.raw["definitions"][0]["reference"]
        with self.assertRaises(DatasetError):
            parse_dataset(json.dumps(self.raw))

    def test_invalid_bounds_and_schemes(self):
        for value in ({"scheme": "bogus", "exact": "1"},
                      {"scheme": "numeric", "lower": "2", "upper": "1"},
                      {"scheme": "numeric", "lower": "2", "upper": "2"},
                      {"scheme": "numeric", "exact": "1", "upper": "2"},
                      {"scheme": "numeric", "lower": "1", "lower_inclusive": 1},
                      {"scheme": "numeric"},
                      {"scheme": "numeric", "exact": "broken"},
                      {"scheme": "openssh", "exact": "9.6p1"},
                      {"scheme": "opaque", "lower": "abc"}):
            raw = deepcopy(self.raw)
            raw["definitions"][0]["ranges"] = [value]
            with self.subTest(value=value), self.assertRaises(DatasetError):
                parse_dataset(json.dumps(raw))

    def test_duplicate_definitions_and_ranges(self):
        raw = deepcopy(self.raw)
        raw["definitions"].append(deepcopy(raw["definitions"][0]))
        raw["definition_count"] += 1
        with self.assertRaisesRegex(DatasetError, "Duplicate vulnerability"):
            parse_dataset(json.dumps(raw))
        self.raw["definitions"][0]["ranges"] *= 2
        with self.assertRaisesRegex(DatasetError, "Duplicate affected range"):
            parse_dataset(json.dumps(self.raw))

    def test_cli_uses_real_provider(self):
        code, output = cli(flags=("--json",))
        self.assertEqual(code, 0)
        result = json.loads(output)
        ids = {m["cve_id"] for m in result["potential_vulnerability_correlations"]}
        self.assertIn("CVE-2021-41773", ids)
        self.assertTrue(all(m["status"] == "POTENTIAL" for m in result["potential_vulnerability_correlations"]))

    def test_cli_nonmatch_and_terminal_separation(self):
        code, output = cli()
        self.assertEqual(code, 0)
        self.assertIn("POTENTIAL CVE CORRELATIONS (not confirmed findings)", output)
        self.assertIn("CVE-2021-41773", output)
        self.assertIn("exploitability have not been verified", output)
        self.assertIn("No security findings.", output)
        _, output = cli("2.4.51", ("--json",))
        self.assertEqual(json.loads(output)["potential_vulnerability_correlations"], [])

    def test_cli_verbose_metadata_and_json_precedence(self):
        _, output = cli(flags=("--verbose",))
        self.assertIn("CVE CORRELATION", output)
        self.assertNotIn("BUNDLED CVE DATASET", output)
        self.assertIn(self.metadata["revision"], output)
        self.assertEqual(cli(flags=("--json",))[1], cli(flags=("--json", "--verbose"))[1])

    def test_library_none_and_risk_unchanged(self):
        scan = HostScanResult(HOST, services=[PortService(80, "tcp", "open")])
        baseline = assess_scan_result(scan, checks=[http_check("2.4.49")], vulnerability_provider=None)
        correlated = assess_scan_result(scan, checks=[http_check("2.4.49")], vulnerability_provider=self.provider)
        self.assertEqual(baseline.potential_correlations, ())
        self.assertEqual(len(correlated.potential_correlations), 2)
        self.assertEqual(baseline.observed_risk, correlated.observed_risk)
        self.assertEqual(baseline.to_dict()["risk"], correlated.to_dict()["risk"])

    def test_discovered_mode_real_provider(self):
        output = StringIO()
        devices = [Device(HOST, None, None, "Unknown"), Device("192.0.2.2", None, None, "Unknown")]
        with patch("netsentry.main.load_current_snapshot", return_value=devices), patch(
            "netsentry.main.scan_target", side_effect=lambda host, **kw: HostScanResult(host, services=[PortService(80, "tcp", "open")])
        ), patch("netsentry.analysis.engine.default_service_checks", return_value=(http_check("2.4.49"),)), redirect_stdout(output):
            code = _run_assess(_build_parser().parse_args(["assess", "--discovered", "--json"]))
        self.assertEqual(code, 0)
        results = json.loads(output.getvalue())["assessments"]
        self.assertEqual(len(results), 2)
        for result in results:
            matches = result["potential_vulnerability_correlations"]
            self.assertEqual(len(matches), 2)
            self.assertEqual(matches[0]["evidence"]["host"], result["host"])

    def test_failed_load_visible_and_does_not_scan(self):
        for flags in ((), ("--json",)):
            output = StringIO()
            with patch("netsentry.main.load_bundled_provider", side_effect=DatasetError("broken data")), patch(
                "netsentry.main.scan_target"
            ) as scan, redirect_stdout(output):
                code = _run_assess(_build_parser().parse_args(["assess", HOST, *flags]))
            self.assertEqual(code, 1)
            scan.assert_not_called()
            self.assertIn("CVE dataset load failed", output.getvalue())
            if flags:
                self.assertIn("error", json.loads(output.getvalue()))

    def test_packaged_resource_without_source_directory(self):
        root = Path(__file__).resolve().parents[1]
        config = tomllib.loads((root / "pyproject.toml").read_text())
        self.assertIn("data/*.json", config["tool"]["setuptools"]["package-data"]["netsentry"])
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "netsentry.zip"
            with ZipFile(archive, "w") as bundle:
                for path in (root / "netsentry").rglob("*"):
                    if path.suffix in {".py", ".json"}:
                        bundle.write(path, path.relative_to(root))
            script = (
                "import sys; sys.path.insert(0, sys.argv[1]); "
                "from netsentry.analysis.bundled_cves import load_bundled_provider; "
                "provider, metadata = load_bundled_provider(); "
                "assert len(provider.definitions) == metadata['definition_count'] == 2"
            )
            result = subprocess.run([sys.executable, "-B", "-c", script, str(archive)],
                                    cwd=temp, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
