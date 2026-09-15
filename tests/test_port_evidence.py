"""Port evidence, identification, and dispatch regressions; no network access."""
import json
import subprocess
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from io import StringIO
from unittest.mock import Mock, patch

from netsentry.analysis.checks import (
    CompletedNoFindingCheck, DNSConfigurationCheck, HTTPConfigurationCheck,
    RDPConfigurationCheck, SMBConfigurationCheck, SSHConfigurationCheck,
    TLSConfigurationCheck, default_service_checks, dispatch_service_check,
)
from netsentry.analysis.engine import assess_scan_result
from netsentry.analysis.fingerprinting import identify_service, merge_fingerprints
from netsentry.analysis.correlation import SoftwareEvidence
from netsentry.analysis.models import AssessmentStatus, Confidence
from netsentry.analysis.probes import ProbeError, SMBProbeData, TLSProbeData
from netsentry.analysis.service_probes import (
    DNSProbeData, HTTPProbeData, RDPProbeData, SSHProbeData, probe_http, probe_rdp, probe_ssh,
)
from netsentry.main import _build_parser, _print_assessment, _print_scan_result, _run_assess
from netsentry.scanning.models import HostScanResult, PortService, ServiceIdentity
from netsentry.scanning.nmap import NmapClient, parse_nmap_xml
from netsentry.scanning.scanner import scan_target, scan_targets


HOST = "100.100.201.201"
SSH = SSHProbeData("SSH-2.0-OpenSSH_9.6", "2.0", {})
TLS = TLSProbeData("TLSv1.3", "TLS_AES_256_GCM_SHA384", "test", "test", None, None, False, False)


def xml(ports="", *, requested="22,80,443", groups="", status='state="up" reason="user-set"', host_extra=""):
    return f'''<nmaprun>
      <scaninfo type="connect" protocol="tcp" services="{requested}"/>
      <host {host_extra}><status {status}/><address addr="{HOST}" addrtype="ipv4"/>
      <ports>{groups}{ports}</ports></host><runstats><finished exit="success"/></runstats>
    </nmaprun>'''


def port(number, state="open", reason="syn-ack", service=""):
    return f'<port protocol="tcp" portid="{number}"><state state="{state}" reason="{reason}"/>{service}</port>'


def confirmed(number, name):
    return PortService(number, "tcp", "open", service=name, identities=(ServiceIdentity(name, "test response", {"protocol": name}),))


class PortStateTests(unittest.TestCase):
    def test_explicit_states_and_raw_evidence(self):
        source = xml(port(22) + port(80, "closed", "conn-refused") + port(443, "filtered", "admin-prohibited"))
        result = parse_nmap_xml(source)
        self.assertEqual([item.state for item in result.services], ["open", "closed", "filtered"])
        self.assertEqual(result.open_ports, 1)
        self.assertEqual(result.raw_xml, source)
        self.assertEqual(result.services[2].scanner_reason, "admin-prohibited")
        self.assertEqual(result.services[2].scanner_source, "Nmap XML port")
        self.assertTrue(result.reachability)

    def test_no_response_is_unknown_with_raw_filtered_preserved(self):
        result = parse_nmap_xml(xml(port(22, "filtered", "no-response"), requested="22"))
        item = result.services[0]
        self.assertEqual(item.state, "unknown")
        self.assertEqual(item.scanner_state, "filtered")
        self.assertEqual(item.scanner_reason, "no-response")
        self.assertTrue(item.scan_observed)
        self.assertIsNone(result.reachability)

    def test_indeterminate_states_and_unreachable_reasons_remain_unknown(self):
        for state, reason in (("open|filtered", "no-response"), ("closed|filtered", "no-response"),
                              ("unfiltered", "reset"), ("filtered", "host-unreach"),
                              ("filtered", "net-unreach"), ("filtered", "port-unreach"),
                              ("filtered", "unknown"), ("filtered", "no-route")):
            with self.subTest(state=state, reason=reason):
                item = parse_nmap_xml(xml(port(22, state, reason), requested="22")).services[0]
                self.assertEqual(item.state, "unknown")
                self.assertEqual(item.scanner_state, state)
                self.assertEqual(item.scanner_reason, reason)

    def test_explicit_prohibition_reasons_support_filtered(self):
        for reason in ("admin-prohibited", "host-prohibited", "net-prohibited"):
            item = parse_nmap_xml(xml(port(22, "filtered", reason), requested="22")).services[0]
            self.assertEqual(item.state, "filtered")

    def test_missing_state_is_preserved_as_unknown(self):
        item = parse_nmap_xml(xml('<port protocol="tcp" portid="22"/>', requested="22")).services[0]
        self.assertEqual(item.state, "unknown")
        self.assertIsNone(item.scanner_state)

    def test_missing_requested_port_is_not_claimed_tested(self):
        result = parse_nmap_xml(xml(port(80)))
        self.assertEqual(result.probe_status, "incomplete")
        self.assertEqual(result.requested_ports, (22, 80, 443))
        for item in (result.services[0], result.services[2]):
            self.assertEqual(item.state, "unknown")
            self.assertFalse(item.scan_observed)
            self.assertIsNone(item.scanner_state)

    def test_no_host_result_is_incomplete(self):
        result = parse_nmap_xml('<nmaprun/>', (22,))
        self.assertEqual(result.probe_status, "incomplete")
        self.assertEqual(result.services[0].state, "unknown")
        self.assertIsNone(result.reachability)

    def test_user_set_up_does_not_prove_reachability(self):
        result = parse_nmap_xml(xml(port(22, "filtered", "no-response"), requested="22"))
        self.assertIsNone(result.reachability)

    def test_grouped_explicit_ranges_preserve_each_reason(self):
        groups = '''<extraports state="closed" count="2"><extrareasons reason="resets" count="2" proto="tcp" ports="22,80"/></extraports>
                    <extraports state="filtered" count="1"><extrareasons reason="admin-prohibited" count="1" proto="tcp" ports="443"/></extraports>'''
        result = parse_nmap_xml(xml(groups=groups))
        self.assertEqual([item.state for item in result.services], ["closed", "closed", "filtered"])
        self.assertEqual(result.services[0].scanner_reason, "resets")
        self.assertEqual(result.services[0].scanner_source, "Nmap XML extrareasons ports")
        self.assertEqual(len(result.port_summary), 2)

    def test_legacy_group_maps_only_exact_remainder(self):
        groups = '<extraports state="closed" count="2"><extrareasons reason="resets" count="2"/></extraports>'
        result = parse_nmap_xml(xml(port(80), groups=groups))
        self.assertEqual([item.state for item in result.services], ["closed", "open", "closed"])
        self.assertEqual(result.services[0].scanner_source, "Nmap XML extraports remainder")

    def test_ambiguous_groups_remain_unattributed(self):
        groups = '<extraports state="closed" count="1"/><extraports state="filtered" count="2"/>'
        result = parse_nmap_xml(xml(groups=groups))
        self.assertTrue(all(item.state == "unknown" and not item.scan_observed for item in result.services))
        self.assertEqual(len(result.port_summary), 2)

    def test_mixed_group_reasons_are_not_arbitrarily_assigned(self):
        groups = '''<extraports state="filtered" count="3"><extrareasons reason="admin-prohibited" count="1"/>
                    <extrareasons reason="no-response" count="2"/></extraports>'''
        result = parse_nmap_xml(xml(groups=groups))
        self.assertTrue(all(item.state == "unknown" and item.scanner_reason is None for item in result.services))
        self.assertEqual(len(result.port_summary[0]["reasons"]), 2)

    def test_overlapping_group_ranges_are_not_guessed(self):
        groups = '''<extraports state="closed" count="1"><extrareasons reason="resets" count="1" proto="tcp" ports="22"/></extraports>
                    <extraports state="filtered" count="1"><extrareasons reason="admin-prohibited" count="1" proto="tcp" ports="22"/></extraports>'''
        item = parse_nmap_xml(xml(groups=groups, requested="22")).services[0]
        self.assertEqual(item.state, "unknown")
        self.assertFalse(item.scan_observed)

    def test_host_timeout_is_not_complete_even_with_open_port(self):
        result = parse_nmap_xml(xml(port(22), requested="22", host_extra='timedout="true"'))
        self.assertEqual(result.services[0].state, "open")
        self.assertEqual(result.probe_status, "incomplete")

    @patch("netsentry.scanning.nmap.shutil.which", return_value="nmap")
    @patch("netsentry.scanning.nmap.subprocess.run")
    def test_subprocess_timeout_keeps_raw_partial_xml(self, run, which):
        raw = b'<nmaprun><host>'
        run.side_effect = subprocess.TimeoutExpired(["nmap"], 3, output=raw)
        result = NmapClient().scan(HOST, [22, 443], 3)
        self.assertEqual(result.raw_xml, raw.decode())
        self.assertEqual(result.probe_status, "timeout")
        self.assertTrue(all(item.state == "unknown" and not item.scan_observed for item in result.services))

    @patch("netsentry.scanning.nmap.shutil.which", return_value="nmap")
    @patch("netsentry.scanning.nmap.subprocess.run")
    def test_timeout_can_preserve_complete_xml_evidence(self, run, which):
        run.side_effect = subprocess.TimeoutExpired(["nmap"], 3, output=xml(port(22), requested="22"))
        result = NmapClient().scan(HOST, [22], 3)
        self.assertEqual(result.open_ports, 1)
        self.assertEqual(result.probe_status, "timeout")

    @patch("netsentry.scanning.scanner.NmapClient.scan")
    def test_wrapper_preserves_states_metadata_and_uncertainty(self, scan):
        parsed = parse_nmap_xml(xml(port(22, "filtered", "no-response"), requested="22"))
        scan.return_value = replace(parsed, probe_status="timeout")
        result = scan_target(HOST, profile="custom", port_spec="22")
        self.assertEqual(result.services, parsed.services)
        self.assertEqual(result.raw_xml, parsed.raw_xml)
        self.assertIsNone(result.reachability)
        self.assertEqual(result.probe_status, "timeout")
        self.assertEqual(result.requested_ports, (22,))

    @patch("netsentry.scanning.scanner.scan_target")
    def test_scan_summary_counts_only_open(self, scan):
        scan.return_value = parse_nmap_xml(xml(port(22) + port(80, "closed", "reset") + port(443, "filtered", "no-response")))
        results, summary = scan_targets([HOST])
        self.assertEqual(summary.open_ports, 1)
        self.assertEqual(len(results[0].services), 3)

    def test_command_remains_bounded_connect_scan_without_version_scan(self):
        command = NmapClient().build_command(HOST, [22, 443], 5)
        self.assertIn("-sT", command)
        self.assertIn("5000ms", command)
        self.assertNotIn("-sV", command)
        self.assertNotIn("-A", command)


class IdentificationDispatchTests(unittest.TestCase):
    def test_table_label_is_hint_even_on_open_port(self):
        source = xml(port(22, service='<service name="ssh" method="table" conf="3"/>'), requested="22")
        item = parse_nmap_xml(source).services[0]
        self.assertEqual(item.identification_status, "HINT")
        self.assertEqual(item.service_hint, "ssh")
        self.assertEqual(dispatch_service_check(default_service_checks(), HostScanResult(HOST), item), ())

    def test_filtered_ssh_label_never_confirms_identity_or_runs_probes(self):
        source = xml(port(22, "filtered", "admin-prohibited", '<service name="ssh" method="probed" conf="10" product="OpenSSH"/>'), requested="22")
        probe = Mock(return_value=SSH)
        assessment = assess_scan_result(parse_nmap_xml(source), checks=[SSHConfigurationCheck(probe)])
        probe.assert_not_called()
        self.assertEqual(assessment.observations[0].identification_status, "HINT")
        self.assertIsNone(assessment.observations[0].service)
        self.assertEqual(assessment.checks, ())

    def test_nonopen_ports_skip_all_checks_even_with_stale_identity(self):
        for state in ("closed", "filtered", "unknown"):
            probe = Mock(return_value=SSH)
            check = CompletedNoFindingCheck("test", "test", lambda item: True)
            check.run = Mock(wraps=check.run)
            item = replace(confirmed(22, "ssh"), state=state)
            result = assess_scan_result(HostScanResult(HOST, services=[item]), checks=[SSHConfigurationCheck(probe), check])
            probe.assert_not_called()
            check.run.assert_not_called()
            self.assertEqual(result.checks, ())
            self.assertEqual(result.coverage.services_discovered, 0)
            self.assertEqual(result.unimplemented_services, 0)

    def test_open_22_without_protocol_evidence_remains_hint(self):
        probe = Mock(side_effect=ProbeError("no identification banner"))
        check = SSHConfigurationCheck(probe)
        check.run = Mock(wraps=check.run)
        result = assess_scan_result(HostScanResult(HOST, services=[PortService(22, "tcp", "open")]), checks=[check])
        check.run.assert_not_called()
        self.assertEqual(result.observations[0].service_hint, "ssh")
        self.assertIsNone(result.observations[0].service)
        self.assertEqual(result.status, AssessmentStatus.LIMITED)
        self.assertEqual(result.coverage.checks_attempted, 0)
        self.assertIn("no identification banner", result.observations[0].identification_attempts[0]["reason"])

    def test_confirmed_ssh_on_standard_and_unusual_ports_reuses_probe(self):
        for number in (22, 2222, 443):
            probe = Mock(return_value=SSH)
            check = SSHConfigurationCheck(probe)
            check.run = Mock(wraps=check.run)
            result = assess_scan_result(HostScanResult(HOST, services=[PortService(number, "tcp", "open", "ssh" if number == 443 else None)]), checks=[check])
            probe.assert_called_once()
            check.run.assert_called_once()
            self.assertEqual(result.observations[0].service, "ssh")
            self.assertEqual(result.observations[0].identification_status, "CONFIRMED")
            self.assertEqual(result.observations[0].identities[0]["evidence"]["banner"], SSH.banner)
            self.assertEqual(result.findings, ())

    def test_unusual_ssh_banner_probe_has_one_second_timeout(self):
        probe = Mock(return_value=SSH)
        assess_scan_result(HostScanResult(HOST, services=[PortService(2222, "tcp", "open")]), checks=[SSHConfigurationCheck(probe)])
        probe.assert_called_once_with(HOST, port=2222, timeout=1.0, enumerate_security=True)

    def test_nmap_probed_identity_on_unusual_port(self):
        result = parse_nmap_xml(xml(port(2222, service='<service name="ssh" method="probed" conf="10" product="OpenSSH" version="9.6"/>'), requested="2222"))
        item = result.services[0]
        self.assertEqual(item.confirmed_service, "ssh")
        self.assertEqual(len(dispatch_service_check([SSHConfigurationCheck()], result, item)), 1)
        self.assertEqual(identify_service(item).version, "9.6")

    def test_low_confidence_or_missing_method_stays_hint(self):
        for attributes in ('method="probed" conf="3"', 'conf="10"', 'method="table" conf="10"'):
            item = parse_nmap_xml(xml(port(22, service=f'<service name="ssh" product="OpenSSH" version="9.6" {attributes}/>'), requested="22")).services[0]
            self.assertEqual(item.identification_status, "HINT")
            self.assertIsNone(identify_service(item))

    def test_generic_open_port_cannot_reach_injected_check(self):
        check = CompletedNoFindingCheck("test", "test", lambda item: True)
        check.run = Mock(wraps=check.run)
        result = assess_scan_result(HostScanResult(HOST, services=[PortService(22, "tcp", "open")]), checks=[check])
        check.run.assert_not_called()
        self.assertEqual(result.findings, ())

    def test_confirmed_protocol_overrides_conventional_port_dispatch(self):
        item = confirmed(443, "ssh")
        selected = dispatch_service_check(default_service_checks(), HostScanResult(HOST), item)
        self.assertEqual([check.check_id for check in selected], ["NS-CHECK-SSH"])

    def test_https_layers_are_independently_demonstrated_and_cached(self):
        tls_probe = Mock(return_value=TLS)
        http_probe = Mock(return_value=HTTPProbeData(401, {"server": "test"}, None, "test", (), tls=True))
        result = assess_scan_result(HostScanResult(HOST, services=[PortService(8443, "tcp", "open")]), checks=[TLSConfigurationCheck(tls_probe), HTTPConfigurationCheck(http_probe)])
        tls_probe.assert_called_once()
        http_probe.assert_called_once_with(HOST, port=8443, tls=True)
        self.assertEqual({check.check_id for check in result.checks}, {"NS-CHECK-TLS", "NS-CHECK-HTTP"})
        self.assertEqual(result.observations[0].service, "https")
        self.assertTrue(result.observations[0].tls)
        self.assertEqual(result.findings, ())

    def test_tls_success_without_http_does_not_dispatch_http(self):
        http_check = HTTPConfigurationCheck(Mock(side_effect=ProbeError("not HTTP")))
        http_check.run = Mock(wraps=http_check.run)
        result = assess_scan_result(HostScanResult(HOST, services=[PortService(8443, "tcp", "open")]), checks=[TLSConfigurationCheck(Mock(return_value=TLS)), http_check])
        http_check.run.assert_not_called()
        self.assertEqual(result.observations[0].service, "tls")
        self.assertEqual([check.check_id for check in result.checks], ["NS-CHECK-TLS"])
        self.assertEqual(result.status, AssessmentStatus.LIMITED)

    def test_plain_http_on_443_does_not_use_tls_from_port(self):
        http_probe = Mock(return_value=HTTPProbeData(200, {}, None, None, ()))
        result = assess_scan_result(HostScanResult(HOST, services=[confirmed(443, "http")]), checks=[HTTPConfigurationCheck(http_probe), TLSConfigurationCheck(Mock())])
        http_probe.assert_called_once_with(HOST, port=443, tls=False)
        self.assertEqual([check.check_id for check in result.checks], ["NS-CHECK-HTTP"])

    def test_nmap_ssl_tunnel_preserves_both_protocol_layers(self):
        item = parse_nmap_xml(xml(port(9443, service='<service name="http" tunnel="ssl" method="probed" conf="10"/>'), requested="9443")).services[0]
        self.assertEqual(item.confirmed_service, "https")
        self.assertEqual(item.confirmed_protocols, ("tls", "http"))
        selected = dispatch_service_check(default_service_checks(), HostScanResult(HOST), item)
        self.assertEqual({check.check_id for check in selected}, {"NS-CHECK-TLS", "NS-CHECK-HTTP"})

    def test_existing_smb_dns_rdp_probes_confirm_then_assess(self):
        cases = ((445, SMBConfigurationCheck, SMBProbeData("SMB 3.1.1", False, True, True), "smb"),
                 (53, DNSConfigurationCheck, DNSProbeData(True, False, False, "TCP"), "dns"),
                 (3389, RDPConfigurationCheck, RDPProbeData(True), "rdp"))
        for number, cls, data, name in cases:
            probe = Mock(return_value=data)
            result = assess_scan_result(HostScanResult(HOST, services=[PortService(number, "tcp", "open")]), checks=[cls(probe)])
            probe.assert_called_once()
            self.assertEqual(result.observations[0].service, name)
            self.assertEqual(len(result.checks), 1)
            self.assertEqual(result.findings, ())

    def test_state_alone_never_produces_findings(self):
        for state in ("open", "closed", "filtered", "unknown"):
            result = assess_scan_result(HostScanResult(HOST, services=[PortService(22, "tcp", state)]), checks=[])
            self.assertEqual(result.findings, ())
            self.assertIsNone(result.risk_score)

    def test_closed_full_range_can_complete_but_unobserved_full_range_cannot(self):
        requested = tuple(range(1, 65536))
        result = parse_nmap_xml(xml(groups='<extraports state="closed" count="65535"><extrareasons reason="resets" count="65535"/></extraports>', requested="1-65535"))
        assessment = assess_scan_result(replace(result, scan_profile="full"), checks=[])
        self.assertEqual(assessment.status, AssessmentStatus.COMPLETE)
        self.assertEqual(assessment.risk_score, 0)
        self.assertEqual(assessment.coverage.services_discovered, 0)
        missing = assess_scan_result(HostScanResult(HOST, scan_profile="full", requested_ports=requested), checks=[])
        self.assertEqual(missing.status, AssessmentStatus.LIMITED)

    def test_confidence_merge_uses_rank_not_alphabetical_order(self):
        items = tuple(SoftwareEvidence("server", "1.0", "tcp", confidence, "test") for confidence in (Confidence.HIGH, Confidence.LOW, Confidence.MEDIUM))
        self.assertEqual(merge_fingerprints(items).confidence, Confidence.HIGH)

    def test_windows_openssh_banner_preserves_actual_version(self):
        item = PortService(22, "tcp", "open", identities=(ServiceIdentity(
            "ssh", "NetSentry SSH probe", {"banner": "SSH-2.0-OpenSSH_for_Windows_9.5"},
        ),))
        evidence = identify_service(item)
        self.assertEqual((evidence.product, evidence.version), ("OpenSSH", "9.5"))
        self.assertEqual(evidence.confidence, Confidence.MEDIUM)

    def test_ambiguous_ssh_software_token_does_not_invent_version(self):
        item = PortService(22, "tcp", "open", identities=(ServiceIdentity(
            "ssh", "NetSentry SSH probe", {"banner": "SSH-2.0-Example_custom_build"},
        ),))
        self.assertIsNone(identify_service(item))


class PortReportingTests(unittest.TestCase):
    def sample(self):
        return parse_nmap_xml(xml(
            port(22, "filtered", "admin-prohibited", '<service name="ssh" method="table" conf="3"/>')
            + port(80, "filtered", "no-response")
            + port(443, service='<service name="http" tunnel="ssl" method="probed" conf="10"/>')
        ))

    def test_json_preserves_open_filtered_unknown_and_raw_evidence(self):
        scan = self.sample()
        data = json.loads(json.dumps(assess_scan_result(scan, checks=[]).to_dict()))
        self.assertEqual([item["state"] for item in data["attack_surface"]], ["filtered", "unknown", "open"])
        self.assertEqual(data["attack_surface"][0]["service_hint"], "ssh")
        self.assertIsNone(data["attack_surface"][0]["service"])
        self.assertEqual(data["attack_surface"][1]["scanner_state"], "filtered")
        self.assertEqual(data["attack_surface"][1]["scanner_reason"], "no-response")
        self.assertEqual(data["attack_surface"][2]["service"], "https")
        self.assertEqual(data["scan_evidence"]["raw_xml"], scan.raw_xml)
        self.assertEqual(data["coverage"]["services_discovered"], 1)

    def test_terminal_assessment_and_scan_show_states_and_hints(self):
        scan = self.sample()
        for printer, result in ((_print_assessment, assess_scan_result(scan, checks=[])), (_print_scan_result, scan)):
            output = StringIO()
            with redirect_stdout(output):
                printer(result)
            rendered = output.getvalue()
            if printer is _print_assessment:
                self.assertIn("Filtered: 22/tcp (ssh), 80/tcp (http)", rendered)
            else:
                self.assertRegex(rendered, r"22/tcp\s+filtered\s+unknown \(hint: ssh\)")
                self.assertRegex(rendered, r"80/tcp\s+unknown")
            self.assertRegex(rendered, r"443/tcp\s+open\s+https")

    def test_closed_only_scan_still_prints_ports_and_zero_open(self):
        scan = parse_nmap_xml(xml(port(22, "closed", "conn-refused"), requested="22"))
        output = StringIO()
        with redirect_stdout(output):
            _print_scan_result(scan)
        self.assertRegex(output.getvalue(), r"22/tcp\s+closed")
        self.assertIn("Open ports: 0", output.getvalue())

    def test_large_closed_range_is_compact_without_losing_json_evidence(self):
        scan = HostScanResult(HOST, services=[PortService(p, "tcp", "closed") for p in range(1, 501)])
        assessment = assess_scan_result(scan, checks=[])
        output = StringIO()
        with redirect_stdout(output):
            _print_assessment(assessment)
        self.assertLess(len(output.getvalue().splitlines()), 60)
        self.assertEqual(len(assessment.to_dict()["attack_surface"]), 500)

    @patch("netsentry.main.scan_target")
    def test_cli_timeout_json_is_a_limited_assessment(self, scan):
        scan.return_value = HostScanResult(HOST, services=[PortService(22, "tcp", "unknown", scan_observed=False)], probe_status="timeout")
        output = StringIO()
        with redirect_stdout(output):
            code = _run_assess(_build_parser().parse_args(["assess", HOST, "--json"]))
        self.assertEqual(code, 0)
        data = json.loads(output.getvalue())
        self.assertEqual(data["assessment_status"], "LIMITED")
        self.assertEqual(data["probe_status"], "timeout")
        self.assertEqual(data["attack_surface"][0]["state"], "unknown")


class ProtocolEvidenceValidationTests(unittest.TestCase):
    def connection(self, chunks):
        connection = Mock()
        connection.recv.side_effect = chunks
        context = Mock()
        context.__enter__ = Mock(return_value=connection)
        context.__exit__ = Mock(return_value=False)
        return connection, Mock(return_value=context)

    def test_ssh_fragmented_banner_and_pre_banner_lines(self):
        connection, factory = self.connection([b"hello\r\nSS", b"H-2.0-OpenSSH_9.6\r\n"])
        result = probe_ssh(HOST, port=2222, socket_factory=factory)
        self.assertEqual(result.banner, SSH.banner)
        connection.sendall.assert_not_called()

    def test_ssh_incomplete_or_invalid_banner_is_not_confirmation(self):
        for banner in (b"SSH-", b"SSH-2.0-\r\n", b"hello\r\n"):
            _, factory = self.connection([banner, b""])
            with self.assertRaises(ProbeError):
                probe_ssh(HOST, socket_factory=factory)

    def test_non_http_numeric_response_is_rejected(self):
        _, factory = self.connection([b"SMTP 220 ready\r\n"])
        with self.assertRaisesRegex(ProbeError, "HTTP status line"):
            probe_http(HOST, port=80, socket_factory=factory)

    def test_valid_http_error_response_is_protocol_evidence(self):
        _, factory = self.connection([b"HTTP/1.1 401 Unauthorized\r\nServer: test\r\n\r\n"])
        data = probe_http(HOST, port=80, socket_factory=factory)
        self.assertEqual(data.status, 401)

    def test_rdp_single_magic_byte_is_not_confirmation(self):
        _, factory = self.connection([b"\x03\x00\x00\x02"])
        with self.assertRaises(ProbeError):
            probe_rdp(HOST, socket_factory=factory)

    def test_rdp_valid_tpkt_and_connection_confirm(self):
        _, factory = self.connection([bytes.fromhex("03000013"), bytes.fromhex("0ed000000000000200080001000000")])
        self.assertTrue(probe_rdp(HOST, socket_factory=factory).protocol_response)
