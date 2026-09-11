import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from netsentry.main import _build_parser, _run_assess, _run_discovery, _run_scan
from netsentry.discovery.models import Device, NetworkTarget
from netsentry.scanning.models import HostScanResult, PortService
from ipaddress import IPv4Network


class AssessmentCliTests(unittest.TestCase):
    @patch("netsentry.main.save_current_snapshot")
    @patch("netsentry.main.discover_devices")
    @patch("netsentry.main.get_local_network")
    def test_discover_replaces_current_snapshot(self, mock_network, mock_discover, mock_save) -> None:
        mock_network.return_value = NetworkTarget("en0", "100.100.201.2", IPv4Network("100.100.201.0/24"))
        devices = [Device("100.100.201.201", None, None, "Unknown")]
        mock_discover.return_value = devices
        args = _build_parser().parse_args(["discover", "--interface", "en0"])
        with redirect_stdout(StringIO()):
            exit_code = _run_discovery(args)
        self.assertEqual(exit_code, 0)
        mock_save.assert_called_once_with(devices)

    @patch("netsentry.main.discover_devices")
    @patch("netsentry.main.load_current_snapshot")
    @patch("netsentry.main.scan_target")
    def test_discovered_scan_uses_only_current_snapshot(self, mock_scan, mock_snapshot, mock_discover) -> None:
        mock_snapshot.return_value = [Device("100.100.201.201", None, None, "Unknown")]
        args = _build_parser().parse_args(["scan", "--discovered", "--profile", "common"])
        with redirect_stdout(StringIO()):
            _run_scan(args)
        mock_scan.assert_called_once()
        self.assertEqual(mock_scan.call_args.args[0], "100.100.201.201")
        mock_discover.assert_not_called()

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
        self.assertEqual(payload["risk"]["severity"], "INFO")
        self.assertEqual(payload["assessment_status"], "COMPLETE")
        self.assertEqual(payload["attack_surface"][0]["port"], 23)
        mock_scan.assert_called_once_with("192.168.1.20", profile="common", port_spec=None, timeout=20.0)

    @patch("netsentry.main.load_current_snapshot")
    @patch("netsentry.main.scan_target")
    def test_discovered_assessment_respects_explicit_limit(self, mock_scan, mock_snapshot) -> None:
        mock_snapshot.return_value = [
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
