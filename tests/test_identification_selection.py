"""Target likely protocols and summarize routine state evidence."""
from dataclasses import replace
import json
import unittest
from unittest.mock import Mock

from netsentry.analysis.checks import (
    SSHConfigurationCheck, SMBConfigurationCheck, RDPConfigurationCheck,
    TLSConfigurationCheck, HTTPConfigurationCheck, identify_for_checks,
)
from netsentry.analysis.probes import ProbeError, SMBProbeData
from netsentry.analysis.service_probes import SSHProbeData, RDPProbeData, HTTPProbeData
from netsentry.scanning.models import HostScanResult, PortService
from tests.test_reporting import windows_fixture, observation, render
from tests.test_port_evidence import TLS


class IdentificationSelectionTests(unittest.TestCase):
    def test_unrelated_windows_ports_do_not_probe_ssh(self):
        for port in (135, 139, 445, 3389):
            ssh = Mock(side_effect=ProbeError("unexpected"))
            smb = Mock(return_value=SMBProbeData("SMB 3.1.1", False, True, True))
            rdp = Mock(return_value=RDPProbeData(True))
            service, _ = identify_for_checks(
                [SSHConfigurationCheck(ssh), SMBConfigurationCheck(smb), RDPConfigurationCheck(rdp)],
                HostScanResult("192.0.2.1"), PortService(port, "tcp", "open"))
            ssh.assert_not_called()
            self.assertEqual(smb.call_count, int(port in (139, 445)))
            self.assertEqual(rdp.call_count, int(port == 3389))
            if port == 135:
                self.assertIsNone(service.confirmed_service)

    def test_expected_web_and_ssh_probes(self):
        for port in (22, 80, 8080, 443, 8443):
            ssh = Mock(return_value=SSHProbeData("SSH-2.0-test", "2.0", {}))
            tls = Mock(return_value=TLS)
            http = Mock(return_value=HTTPProbeData(200, {}, None, None, (), tls=port in (443, 8443)))
            service, _ = identify_for_checks(
                [SSHConfigurationCheck(ssh), HTTPConfigurationCheck(http), TLSConfigurationCheck(tls)],
                HostScanResult("192.0.2.1"), PortService(port, "tcp", "open"))
            self.assertEqual(ssh.call_count, int(port == 22))
            self.assertEqual(tls.call_count, int(port in (443, 8443)))
            self.assertEqual(http.call_count, int(port != 22))
            self.assertIsNotNone(service.confirmed_service)

    def test_ambiguous_port_uses_single_fallback(self):
        ssh = Mock(return_value=SSHProbeData("SSH-2.0-test", "2.0", {}))
        smb, rdp = Mock(), Mock()
        service, _ = identify_for_checks(
            [SMBConfigurationCheck(smb), RDPConfigurationCheck(rdp), SSHConfigurationCheck(ssh)],
            HostScanResult("192.0.2.1"), PortService(2222, "tcp", "open"))
        ssh.assert_called_once()
        smb.assert_not_called()
        rdp.assert_not_called()
        self.assertEqual(service.confirmed_service, "ssh")

    def test_failed_known_hint_does_not_trigger_unrelated_sweep(self):
        ssh = Mock()
        smb = Mock(side_effect=ProbeError("SMB timeout"))
        service, _ = identify_for_checks(
            [SSHConfigurationCheck(ssh), SMBConfigurationCheck(smb)],
            HostScanResult("192.0.2.1"), PortService(445, "tcp", "open"))
        ssh.assert_not_called()
        self.assertIsNone(service.confirmed_service)
        self.assertIn("SMB timeout", service.identification_attempts[0]["reason"])

    def test_explicit_ssh_hint_overrides_https_port(self):
        ssh = Mock(return_value=SSHProbeData("SSH-2.0-test", "2.0", {}))
        tls = Mock()
        service, _ = identify_for_checks(
            [TLSConfigurationCheck(tls), SSHConfigurationCheck(ssh)],
            HostScanResult("192.0.2.1"), PortService(443, "tcp", "open", "ssh"))
        tls.assert_not_called()
        self.assertEqual(service.confirmed_service, "ssh")


class StateSummaryTests(unittest.TestCase):
    def test_open_state_has_concise_evidence(self):
        item = replace(observation(445, "open", "open", "smb"), scanner_reason="syn-ack",
                       state_reason="Nmap reported open (syn-ack).")
        output = render(replace(windows_fixture(), observations=(item,)), True)
        self.assertIn("State: open", output)
        self.assertIn("Evidence: Nmap SYN-ACK", output)
        self.assertNotIn("Scanner state:", output)
        self.assertNotIn("Normalized state:", output)

    def test_routine_filtering_grouped_without_losing_json(self):
        items = tuple(observation(port, scanner="filtered") for port in range(1, 501))
        value = replace(windows_fixture(), observations=items)
        before = json.dumps(value.to_dict())
        output = render(value, True)
        self.assertIn("500 tcp ports with shared evidence: filtered", output)
        self.assertNotIn("service identification:", output)
        self.assertEqual(before, json.dumps(value.to_dict()))

    def test_unusual_and_failures_retained_after_large_filtered_run(self):
        items = tuple(observation(port, scanner="filtered") for port in range(1, 101))
        unusual = observation(1001, scanner="open|filtered")
        failure = replace(observation(1002, scanner="filtered"),
                          identification_attempts=({"protocol": "ssh", "status": "INCONCLUSIVE", "reason": "Probe timeout"},))
        contradiction = observation(1003, "open", "closed")
        output = render(replace(windows_fixture(), observations=items + (unusual, failure, contradiction)), True)
        for token in ("100 tcp ports with shared evidence", "1001/tcp —", "1002/tcp —",
                      "Probe timeout", "1003/tcp —", "NetSentry interpretation: open"):
            self.assertIn(token, output)
