import unittest
from unittest.mock import patch

from netsentry.discovery.network import (
    _is_locally_administered_mac,
    _network_from_address,
    _parse_netmask,
    _vendor_for,
    get_local_network,
)
from netsentry.discovery.snapshot import load_current_snapshot, save_current_snapshot
from netsentry.discovery.models import Device
from netsentry.ip import IPClassification, classify_ip, ip_visibility, labeled_ip


class NetworkParsingTests(unittest.TestCase):
    def test_current_snapshot_replaces_previous_devices(self) -> None:
        with self.subTest("snapshot replacement"):
            from tempfile import TemporaryDirectory

            with TemporaryDirectory() as directory:
                from pathlib import Path

                path = Path(directory) / "current.json"
                save_current_snapshot([Device("100.100.201.202", None, None, "Unknown")], path)
                save_current_snapshot([Device("100.100.201.201", None, None, "Unknown")], path)
                devices = load_current_snapshot(path)

        self.assertEqual([device.ip for device in devices], ["100.100.201.201"])
    def test_rfc1918_private_ranges_and_boundaries(self) -> None:
        for address in ("10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254", "192.168.0.1", "192.168.255.254"):
            self.assertEqual(classify_ip(address), IPClassification.PRIVATE)
        self.assertEqual(classify_ip("172.15.255.255"), IPClassification.PUBLIC)
        self.assertEqual(classify_ip("172.32.0.0"), IPClassification.PUBLIC)

    def test_shared_cgnat_range_and_boundaries(self) -> None:
        self.assertEqual(classify_ip("100.64.0.0"), IPClassification.SHARED_CGNAT)
        self.assertEqual(classify_ip("100.100.201.201"), IPClassification.SHARED_CGNAT)
        self.assertEqual(classify_ip("100.127.255.255"), IPClassification.SHARED_CGNAT)
        self.assertEqual(classify_ip("100.63.255.255"), IPClassification.PUBLIC)
        self.assertEqual(classify_ip("100.128.0.0"), IPClassification.PUBLIC)

    def test_special_use_addresses_are_not_public(self) -> None:
        self.assertEqual(classify_ip("127.0.0.1"), IPClassification.LOOPBACK)
        self.assertEqual(classify_ip("169.254.1.1"), IPClassification.LINK_LOCAL)
        self.assertEqual(classify_ip("224.0.0.1"), IPClassification.MULTICAST)
        self.assertEqual(classify_ip("8.8.8.8"), IPClassification.PUBLIC)
        self.assertEqual(ip_visibility("100.100.201.201"), "Shared/CGNAT IP")

    def test_locally_administered_mac_is_detected(self) -> None:
        self.assertTrue(_is_locally_administered_mac("ae:0a:9e:e0:c0:95"))
        self.assertFalse(_is_locally_administered_mac("ac:de:48:00:11:22"))

    def test_vendor_lookup_uses_useful_name_from_tuple(self) -> None:
        with patch("scapy.config.conf") as mock_conf:
            mock_conf.manufdb.lookup.return_value = ("Apple", "Apple, Inc.")
            self.assertEqual(_vendor_for("ac:de:48:00:11:22"), "Apple, Inc.")

    def test_locally_administered_unknown_vendor_is_labeled(self) -> None:
        with patch("scapy.config.conf") as mock_conf:
            mock_conf.manufdb.lookup.return_value = ("ae:0a:9e:e0:c0:95", "ae:0a:9e:e0:c0:95")
            self.assertEqual(_vendor_for("ae:0a:9e:e0:c0:95"), "Unknown (Private/Randomized MAC)")

    def test_globally_administered_unknown_vendor_is_labeled(self) -> None:
        with patch("scapy.config.conf") as mock_conf:
            mock_conf.manufdb.lookup.return_value = None
            self.assertEqual(_vendor_for("ac:de:48:00:11:22"), "Unknown")

    def test_private_ipv4_is_labeled_private(self) -> None:
        self.assertEqual(ip_visibility("192.168.1.20"), "Private IP")
        self.assertEqual(labeled_ip("192.168.1.20"), "Private IP: 192.168.1.20")

    def test_public_ipv4_is_labeled_public(self) -> None:
        self.assertEqual(ip_visibility("8.8.8.8"), "Public IP")
        self.assertEqual(labeled_ip("8.8.8.8"), "Public IP: 8.8.8.8")

    def test_hex_netmask_is_converted(self) -> None:
        self.assertEqual(_parse_netmask("0xffff8000"), "255.255.128.0")

    def test_dotted_netmask_is_preserved(self) -> None:
        self.assertEqual(_parse_netmask("0xffffff00"), "255.255.255.0")

    def test_local_network_is_derived_from_address(self) -> None:
        self.assertEqual(str(_network_from_address("10.130.102.215", "255.255.128.0")), "10.130.0.0/17")

    @patch("netsentry.discovery.network._default_interface", return_value="utun6")
    @patch("netsentry.discovery.network._available_interfaces", return_value=["utun6", "en0"]) 
    @patch("netsentry.discovery.network._interface_address")
    def test_get_local_network_falls_back_to_valid_interface(self, mock_interface_address, _mock_available, _mock_default) -> None:
        mock_interface_address.side_effect = [
            ValueError("bad"),
            ("192.168.1.20", "255.255.255.0"),
        ]

        target = get_local_network()
        self.assertEqual(target.interface, "en0")
        self.assertEqual(str(target.network), "192.168.1.0/24")


if __name__ == "__main__":
    unittest.main()
