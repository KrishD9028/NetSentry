"""Keep worker failures as NetSentry evidence and metadata below results."""
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import replace
from io import StringIO
import logging
import threading
import unittest
from unittest.mock import patch

from netsentry.analysis.checks import SMBConfigurationCheck
from netsentry.analysis.identity_resolution import IdentityResolver
from netsentry.main import _build_parser, _run_assess
from netsentry.scanning.models import HostScanResult, PortService
from tests.test_reporting import windows_fixture, observation, render
from tests.test_bundled_cves import cli


class VerboseCleanupTests(unittest.TestCase):
    @patch("netsentry.main.IdentityResolver", lambda: IdentityResolver(probes={}))
    def test_smb_worker_log_suppressed_but_probe_failure_visible(self):
        worker_logger = logging.getLogger("smbprotocol.connection")
        original_filters = list(worker_logger.filters)
        original_levels = {name: logging.getLogger(name).level for name in ("smbprotocol", "smbprotocol.connection")}
        logs, stdout, stderr = StringIO(), StringIO(), StringIO()
        handler = logging.StreamHandler(logs)
        logging.getLogger().addHandler(handler)
        failure = OSError(22, "Invalid argument")

        class Connection:
            def __init__(self, *args, **kwargs): pass
            def connect(self, **kwargs):
                def worker():
                    try:
                        raise failure
                    except OSError:
                        worker_logger.exception("SMB receive worker died (outstanding=%d)", 1)
                thread = threading.Thread(target=worker)
                thread.start()
                thread.join()
                raise failure
            def disconnect(self): pass

        try:
            for flags in ([], ["--verbose"]):
                with patch("smbprotocol.connection.Connection", Connection), patch(
                    "netsentry.main.scan_target", return_value=HostScanResult(
                        "192.0.2.1", services=[PortService(445, "tcp", "open")])
                ), patch("netsentry.analysis.engine.default_service_checks", return_value=(SMBConfigurationCheck(),)), redirect_stdout(stdout), redirect_stderr(stderr):
                    self.assertEqual(_run_assess(_build_parser().parse_args(["assess", "192.0.2.1", *flags])), 0)
            combined = stdout.getvalue() + stderr.getvalue() + logs.getvalue()
            self.assertNotIn("SMB receive worker died", combined)
            self.assertNotIn("Traceback (most recent call last)", combined)
            self.assertIn("Identification attempt: smb", stdout.getvalue())
            self.assertIn("Result: INCONCLUSIVE", stdout.getvalue())
            self.assertIn("SMB transport error during negotiation: [Errno 22] Invalid argument", stdout.getvalue())
            self.assertEqual(worker_logger.filters, original_filters)
            logging.getLogger("netsentry.test").error("Unexpected NetSentry error stays visible")
            self.assertIn("Unexpected NetSentry error stays visible", logs.getvalue())
        finally:
            logging.getLogger().removeHandler(handler)
            for name, level in original_levels.items():
                logging.getLogger(name).setLevel(level)

    def test_filter_does_not_hide_other_library_errors(self):
        from netsentry.analysis.probes import _quiet_smb_worker
        logger = logging.getLogger("smbprotocol.connection")
        stream = StringIO()
        handler = logging.StreamHandler(stream)
        logger.addHandler(handler)
        try:
            with _quiet_smb_worker():
                logger.error("Unrelated library error")
            self.assertIn("Unrelated library error", stream.getvalue())
        finally:
            logger.removeHandler(handler)

    def test_filtered_and_unknown_explained_without_zero_counter_confusion(self):
        value = replace(windows_fixture(), observations=tuple(observation(p, scanner="filtered") for p in range(1, 20)))
        output = render(value, True)
        self.assertIn("Scanner-reported filtered/no-response: 19 ports", output)
        self.assertIn("NetSentry interpretation: UNKNOWN", output)
        self.assertIn("No response is insufficient to distinguish filtering from other causes.", output)
        self.assertNotIn("Normalized filtered ports: 0", output)
        self.assertEqual(value.observations[0].state, "unknown")
        self.assertEqual(value.observations[0].scanner_state, "filtered")

    def test_dataset_metadata_follows_results_and_no_match_is_scoped(self):
        code, output = cli("2.4.51", ("--verbose",))
        self.assertEqual(code, 0)
        self.assertTrue(output.startswith("NetSentry Security Assessment"))
        self.assertNotIn("BUNDLED CVE DATASET", output)
        self.assertGreater(output.index("CVE CORRELATION"), output.index("SECURITY CHECKS"))
        self.assertIn("Dataset: bundled revision", output)
        self.assertIn("Definitions: 2", output)
        self.assertIn("Applicable matches: 0", output)
        self.assertIn("absence of a match does not establish absence of vulnerabilities", output)
