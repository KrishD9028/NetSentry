import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from netsentry.main import _build_parser, _run_assess
from netsentry.discovery.models import Device, NetworkTarget
from netsentry.scanning.models import HostScanResult, PortService
from ipaddress import IPv4Network


class AssessmentCliTests(unittest.TestCase):
    def test_assess_help_parser_accepts_json(self) -> None:
        args = _build_parser().parse_args(["assess", "192.168.1.20", "--json"])
        self.assertTrue(args.json)
        self.assertEqual(args.profile, "common")

    @patch("netsentry.main.scan_target")
    def test_single_assessment_json_is_valid(self, mock_scan) -> None:
        mock_scan.return_value = HostScanResult(
            target="192.168.1.20",
            services=[PortService(port=23, protocol="tcp", state="open", service="telnet")],
        )
        args = _build_parser().parse_args(["assess", "192.168.1.20", "--json"])
        output = StringIO()
        with redirect_stdout(output):
            exit_code = _run_assess(args)

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["risk"]["severity"], "UNKNOWN")
        self.assertEqual(payload["assessment_status"], "LIMITED")
        self.assertEqual(payload["attack_surface"][0]["port"], 23)
        mock_scan.assert_called_once_with("192.168.1.20", profile="common", port_spec=None, timeout=20.0)

    @patch("netsentry.main.discover_devices")
    @patch("netsentry.main.get_local_network")
    @patch("netsentry.main.scan_target")
    def test_discovered_assessment_respects_explicit_limit(self, mock_scan, mock_network, mock_discover) -> None:
        mock_network.return_value = NetworkTarget("en0", "192.168.1.2", IPv4Network("192.168.1.0/24"))
        mock_discover.return_value = [
            Device("192.168.1.10", None, None, "Unknown"),
            Device("192.168.1.11", None, None, "Unknown"),
            Device("192.168.1.12", None, None, "Unknown"),
        ]
        mock_scan.side_effect = lambda target, **kwargs: HostScanResult(target=target)
        args = _build_parser().parse_args(["assess", "--discovered", "--limit", "2", "--json"])
        output = StringIO()
        with redirect_stdout(output):
            exit_code = _run_assess(args)

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["network_summary"]["hosts_assessed"], 2)
        self.assertEqual([call.args[0] for call in mock_scan.call_args_list], ["192.168.1.10", "192.168.1.11"])


if __name__ == "__main__":
    unittest.main()
