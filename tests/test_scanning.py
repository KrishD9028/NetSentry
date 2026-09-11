import subprocess
import unittest
from unittest.mock import patch

from netsentry.scanning.models import HostScanResult, PortService
from netsentry.scanning.nmap import NmapClient, NmapNotInstalledError, NmapScanError, parse_nmap_xml
from netsentry.scanning.profiles import parse_port_spec, resolve_ports


class PortSpecificationTests(unittest.TestCase):
    def test_parse_port_spec_supports_mixed_ports_and_ranges(self) -> None:
        self.assertEqual(parse_port_spec("22,80,443,8000-8100"), [22, 80, 443, *range(8000, 8101)])

    def test_parse_port_spec_rejects_reversed_ranges(self) -> None:
        with self.assertRaises(ValueError):
            parse_port_spec("8080-8000")

    def test_parse_port_spec_rejects_empty_values(self) -> None:
        with self.assertRaises(ValueError):
            parse_port_spec("22,,80")

    def test_parse_port_spec_rejects_invalid_ports(self) -> None:
        with self.assertRaises(ValueError):
            parse_port_spec("0,80")


class NmapCommandAndParsingTests(unittest.TestCase):
    def test_scan_result_labels_public_target(self) -> None:
        result = HostScanResult(target="8.8.8.8")
        self.assertEqual(result.target_label, "Public IP")

    def test_build_command_uses_port_list(self) -> None:
        command = NmapClient().build_command("192.168.1.20", [22, 80, 443], timeout=5.0)
        self.assertIn("nmap", command)
        self.assertIn("-p", command)
        self.assertIn("22,80,443", command)
        self.assertIn("192.168.1.20", command)

    def test_parse_nmap_xml_handles_no_open_ports(self) -> None:
        xml = '''
        <nmaprun>
            <host>
                <address addr="192.168.1.10" addrtype="ipv4"/>
                <hostnames><hostname name="host.local" type="PTR"/></hostnames>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="closed"/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        '''
        result = parse_nmap_xml(xml)
        self.assertEqual(result.target, "192.168.1.10")
        self.assertEqual(result.hostname, "host.local")
        self.assertEqual(result.services, [])

    def test_parse_nmap_xml_handles_multiple_services(self) -> None:
        xml = '''
        <nmaprun>
            <host>
                <address addr="192.168.1.20" addrtype="ipv4"/>
                <hostnames><hostname name="desktop.local" type="PTR"/></hostnames>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh" product="OpenSSH" version="9.6" extrainfo="protocol 2.0"/>
                    </port>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" product="nginx" version="1.25.4"/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        '''
        result = parse_nmap_xml(xml)
        self.assertEqual(len(result.services), 2)
        self.assertEqual(result.services[0], PortService(port=22, protocol="tcp", state="open", service="ssh", product="OpenSSH", version="9.6", extra="protocol 2.0"))
        self.assertEqual(result.services[1].service, "http")

    def test_parse_nmap_xml_handles_missing_version_and_product(self) -> None:
        xml = '''
        <nmaprun>
            <host>
                <address addr="192.168.1.30" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="443">
                        <state state="open"/>
                        <service name="https"/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        '''
        result = parse_nmap_xml(xml)
        self.assertEqual(result.services[0].product, None)
        self.assertEqual(result.services[0].version, None)

    @patch("netsentry.scanning.nmap.shutil.which", return_value=None)
    def test_missing_nmap_raises_clear_error(self, _mock_which) -> None:
        with self.assertRaises(NmapNotInstalledError):
            NmapClient().scan("127.0.0.1", [80])

    @patch("netsentry.scanning.nmap.shutil.which", return_value="/usr/local/bin/nmap")
    @patch("netsentry.scanning.nmap.subprocess.run", side_effect=subprocess.CalledProcessError(1, ["nmap"], stderr="boom"))
    def test_nmap_failure_raises_scan_error(self, _mock_run, _mock_which) -> None:
        import subprocess

        with self.assertRaises(NmapScanError):
            NmapClient().scan("127.0.0.1", [80])

    @patch("netsentry.scanning.nmap.shutil.which", return_value="/usr/local/bin/nmap")
    @patch("netsentry.scanning.nmap.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["nmap"], timeout=5.0))
    def test_nmap_timeout_raises_scan_error(self, _mock_run, _mock_which) -> None:
        with self.assertRaises(NmapScanError):
            NmapClient().scan("127.0.0.1", [80], timeout=5.0)


class ProfileResolutionTests(unittest.TestCase):
    def test_quick_and_common_profile_ports_are_resolved(self) -> None:
        quick = resolve_ports("quick")
        common = resolve_ports("common")
        self.assertTrue(quick)
        self.assertTrue(common)
        self.assertIn(22, quick)
        self.assertIn(80, common)

    def test_full_profile_requires_explicit_selection(self) -> None:
        with self.assertRaises(ValueError):
            resolve_ports("full")


class ScanLimitParserTests(unittest.TestCase):
    def test_limit_is_optional_and_default_is_none(self) -> None:
        args = __import__("netsentry.main", fromlist=["_build_parser"])._build_parser().parse_args(["scan", "--discovered"])
        self.assertIsNone(args.limit)

    def test_limit_can_be_set_explicitly(self) -> None:
        args = __import__("netsentry.main", fromlist=["_build_parser"])._build_parser().parse_args(["scan", "--discovered", "--limit", "10"])
        self.assertEqual(args.limit, 10)


if __name__ == "__main__":
    unittest.main()
