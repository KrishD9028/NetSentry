"""Acquisition through approved capabilities; in-memory transports only."""
from dataclasses import asdict, replace
from io import StringIO
from contextlib import redirect_stdout
import json
from unittest.mock import Mock, patch

import pytest

from netsentry.acquisition.adapters import acquire_http, acquire_ssh, AcquisitionResult, DeadlineSocket
from netsentry.acquisition.hypotheses import refresh_hypotheses
from netsentry.acquisition.software import normalize_software
from netsentry.analysis.host_evidence import HostEvidence, observation
from netsentry.analysis.identity_resolution import collect_existing, enrich_identity
from netsentry.analysis.correlation import SoftwareEvidence
from netsentry.analysis.bundled_cves import load_bundled_provider
from netsentry.analysis.mac_vendor import lookup_vendor, normalize_mac
from netsentry.analysis.models import Confidence, SecurityCheckResult, CheckStatus
from netsentry.analysis.probes import probe_smb, ProbeError
from netsentry.analysis.ssh import SSHProbeData
from netsentry.planning import ActionRegistry, AdaptiveIdentityResolver, BudgetLimits, Policy, ProposedAction
from netsentry.planning.models import ActionContext
from netsentry.planning.executor import execute
from netsentry.planning.registry import identity_registry
from netsentry.planning.planner import candidates
from netsentry.terminal_details import planning_details
from tests.test_planning import knowledge, budget
from tests.test_host_identity import assessment, scan
from tests.test_reporting import HOST, observation as port


class Socket:
    def __init__(self, payload):
        self.payload = payload
        self.sent = []
        self.timeouts = []
    def sendall(self, data):
        self.sent.append(data)
    def recv(self, count):
        assert count <= 16384
        return self.payload[:count]
    def settimeout(self, value):
        self.timeouts.append(value)
    def close(self):
        pass
    def getpeercert(self, **kwargs):
        return {'subjectAltName': (('DNS', 'host.test'),)}


def http_result(server='Apache/2.4.49', tls=False):
    sock = Socket(f'HTTP/1.1 200 OK\r\nServer: {server}\r\n\r\n'.encode())
    class Context:
        def wrap_socket(self, raw, **kwargs):
            return sock
    with patch('netsentry.acquisition.adapters.certificate_metadata', return_value={'subject': 'host.test', 'issuer': 'CA', 'tls_version': 'TLSv1.3', 'cipher': 'cipher'}):
        result = acquire_http(ActionContext(HOST, 8443 if tls else 80, 3), tls=tls,
                              socket_factory=lambda *args, **kwargs: sock, context_factory=Context)
    return result, sock


def registry_with_http(server='Apache/2.4.49'):
    action = identity_registry().get('http_fingerprint')
    def handler(context):
        return http_result(server)[0]
    return ActionRegistry([replace(action, handler=handler)])


@pytest.mark.parametrize('raw', ['00:00:0c:11:22:33', '00-00-0C-11-22-33', '0000.0c11.2233', '00000C112233'])
def test_oui_normalization_and_known_prefix(raw):
    database = Mock()
    database.lookup.return_value = ('Cisco', 'Cisco Systems, Inc')
    result = lookup_vendor(raw, database)
    assert result.mac == '00:00:0c:11:22:33'
    assert result.vendor == 'Cisco Systems, Inc'
    database.lookup.assert_called_once_with(result.mac)


@pytest.mark.parametrize('raw', ['xyz', '00:12', '00:11:22:33:44:gg', None, '00112233445566'])
def test_malformed_mac_never_looks_up(raw):
    database = Mock()
    assert lookup_vendor(raw, database).status == 'INCONCLUSIVE'
    database.lookup.assert_not_called()


@pytest.mark.parametrize('raw', ['02:11:22:33:44:55', 'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'])
def test_local_multicast_and_unspecified_not_vendor_claims(raw):
    database = Mock()
    assert lookup_vendor(raw, database).vendor is None
    database.lookup.assert_not_called()


def test_unknown_oui_is_distinguished_from_malformed():
    database = Mock()
    database.lookup.return_value = ('c4:ff:99:b1:a2:c9', 'c4:ff:99:b1:a2:c9')
    result = lookup_vendor('C4:FF:99:B1:A2:C9', database)
    assert 'Prefix absent' in result.reason
    assert result.vendor is None and result.mac


def test_smb_139_does_not_start_direct_tcp_negotiation():
    with patch('smbprotocol.connection.Connection') as connection:
        with pytest.raises(ProbeError, match='NetBIOS session establishment'):
            probe_smb(HOST, port=139)
        connection.assert_not_called()


def test_smb_139_remains_unconfirmed_without_invalid_io():
    from netsentry.analysis.checks import SMBConfigurationCheck, identify_for_checks
    from netsentry.scanning.models import HostScanResult, PortService
    with patch('smbprotocol.connection.Connection') as connection:
        service, _ = identify_for_checks((SMBConfigurationCheck(),), HostScanResult(HOST), PortService(139, 'tcp', 'open'))
    assert service.state == 'open'
    assert not service.confirmed_protocols
    assert 'unsupported' in service.identification_attempts[-1]['reason']
    connection.assert_not_called()


@pytest.mark.parametrize('version,expected', [('2.4.49', '2.4.49'), ('9.0p1', '9.0p1'), ('latest', None), ('2.4.x', None), (None, None)])
def test_software_normalization_preserves_raw_and_uncertainty(version, expected):
    item = SoftwareEvidence('Apache', version, 'http', Confidence.MEDIUM, 'HTTP Server header', host=HOST, port=80)
    result = normalize_software(item, action_id='http_fingerprint', source_key='http', raw_value=f'Apache/{version}')
    assert result.version == expected
    assert result.raw_version == version
    assert result.action_id and result.independence_key and result.limitations
    assert 'No CPE' in result.limitations
    assert result.normalization_status == ('VERSION_OBSERVED' if expected else 'INDETERMINATE')


def test_exact_product_identity_no_fuzzy_alias():
    item = SoftwareEvidence('AlmostApache', '2.4.49', 'http', Confidence.MEDIUM, 'HTTP header')
    result = normalize_software(item, action_id='http_fingerprint', source_key='http', raw_value='AlmostApache/2.4.49')
    assert result.product == 'AlmostApache' and result.vendor is None
    assert load_bundled_provider()[0].correlate(result) == ()


def test_http_acquisition_provenance_and_bounded_request():
    result, sock = http_result('Apache/2.4.49 Python/3.14.6')
    assert result.status == 'COMPLETED'
    assert len(sock.sent) == 1 and b'GET / HTTP/1.0' in sock.sent[0]
    assert all(0 < t <= 3 for t in sock.timeouts)
    assert [s.product for s in result.software] == ['Apache', 'Python']
    assert all(s.host == HOST and s.port == 80 and s.action_id == 'http_fingerprint' for s in result.software)
    assert all(s.raw_value == 'Apache/2.4.49 Python/3.14.6' for s in result.software)
    assert result.logical_requests == 1


def test_https_keeps_tls_http_layers_and_certificate_sources_separate():
    result, sock = http_result(tls=True)
    assert result.logical_requests == 2
    assert any(o.attribute == 'confirmed_protocol' and o.value == 'tls' for o in result.observations)
    assert any(o.attribute == 'confirmed_service' and o.value == 'https' for o in result.observations)
    assert any(o.value == 'SAN DNS: host.test' for o in result.observations)
    assert {o.independence_key for o in result.observations if o.attribute == 'hostname'} == {'tls_certificate'}
    assert result.software[0].independence_key == 'http'


def test_tls_success_survives_invalid_http_response():
    sock = Socket(b'not http')
    class Context:
        def wrap_socket(self, raw, **kwargs):
            return sock
    with patch('netsentry.acquisition.adapters.certificate_metadata', return_value={'subject': 'host.test'}):
        result = acquire_http(ActionContext(HOST, 443, 3), tls=True, socket_factory=lambda *a, **k: sock, context_factory=Context)
    assert result.status == 'INCONCLUSIVE'
    assert any(o.value == 'tls' for o in result.observations)
    assert not result.software


def test_http_timeout_is_structured():
    result = acquire_http(ActionContext(HOST, 80, 3), socket_factory=Mock(side_effect=TimeoutError('deadline')))
    assert result.status == 'INCONCLUSIVE'
    assert not result.software


def test_deadline_socket_rejects_expired_deadline():
    sock = Socket(b'')
    with pytest.raises(ProbeError, match='deadline'):
        DeadlineSocket(sock, -1).recv(100)
    assert not sock.timeouts


def test_ssh_acquisition_reuses_pre_auth_probe_and_retains_partial_banner():
    probe = Mock(return_value=SSHProbeData('SSH-2.0-OpenSSH_for_Windows_9.0', '2.0', {}, 'inconclusive', 'KEX timed out'))
    result = acquire_ssh(ActionContext(HOST, 22, 1), probe=probe)
    assert result.status == 'INCONCLUSIVE'
    assert result.software[0].variant == 'windows'
    assert result.software[0].version == '9.0'
    probe.assert_called_once_with(HOST, port=22, timeout=1, enumerate_security=True)


def test_hypotheses_support_and_conflicts_never_vote_as_os_confirmation():
    evidence = HostEvidence()
    for value, source in [('SSH-2.0-OpenSSH_for_Windows_9.0', 'ssh'), ('SSH-2.0-OpenSSH_9.0p1 Ubuntu', 'other_ssh')]:
        evidence.add(observation('software_banner', value, 'Banner', 'ssh_fingerprint', source, HOST + ':22/tcp'))
    refresh_hypotheses(evidence)
    result = evidence.resolve('operating_system')
    assert result['state'] == 'CONTRADICTORY'
    assert all(o['hypothesis'] and o['support'] and o['contradictions'] for o in result['observations'])
    assert result['independent_confirmations'] == 0
    assert evidence.resolve('candidate_cpe')['state'] == 'UNRESOLVED'
    refresh_hypotheses(evidence)
    assert len(evidence.resolve('operating_system')['observations']) == 2


def test_windows_compatible_services_are_hypothesis_not_confirmation():
    evidence = HostEvidence()
    for attr, value, action, source in [('protocol_version', 'SMB 3.1.1', 'smb_metadata', 'smb'), ('netbios_name', 'KRISH', 'netbios_identity', 'netbios'), ('rpc_interface', 'uuid v1.0', 'rpc_identity', 'rpc')]:
        evidence.add(observation(attr, value, source, action, source))
    refresh_hypotheses(evidence)
    result = evidence.resolve('operating_system')
    assert result['state'] == 'PROBABLE'
    assert result['independent_confirmations'] == 0
    assert len(result['observations'][0]['support']) == 3
    assert evidence.resolve('os_version')['state'] == evidence.resolve('os_edition')['state'] == 'UNRESOLVED'


def test_existing_nmap_os_metadata_is_reused_as_reported_hypothesis():
    result = scan()
    result.raw_xml = f'<nmaprun><host><address addr="{HOST}"/><os><osmatch><osclass osfamily="Linux"/></osmatch></os></host></nmaprun>'
    evidence = collect_existing(assessment(), result)
    refresh_hypotheses(evidence)
    assert evidence.resolve('operating_system')['state'] == 'PROBABLE'
    assert evidence.resolve('operating_system')['independent_confirmations'] == 0


def test_acquired_version_replans_and_reaches_real_cve_provider_without_risk_change():
    original = replace(assessment(port(80, 'open', service='http')), software_evidence=({'product': 'Apache', 'version': None, 'port': 80, 'source': 'Initial product only'},))
    resolver = AdaptiveIdentityResolver(registry=registry_with_http())
    result = enrich_identity(original, scan(), resolver, vulnerability_provider=load_bundled_provider()[0])
    assert any(c['cve_id'] == 'CVE-2021-41773' and c['status'] == 'POTENTIAL' for c in result.potential_correlations)
    assert result.software_evidence[-1]['version'] == '2.4.49'
    assert any('version:80:Apache' in s.get('goals_resolved', []) for s in result.planning_trace['steps'])
    assert sum(bool(s['selected']) for s in result.planning_trace['steps']) == 1
    assert result.observations is original.observations and result.findings is original.findings
    assert result.risk_score == original.risk_score and result.observed_risk_score == original.observed_risk_score
    assert result.planning_trace['steps'][0]['result']['accounting']['logical_units_reported'] == 1


def test_ambiguous_acquired_version_cannot_match_cve():
    result = enrich_identity(assessment(port(80, 'open', service='http')), scan(),
                             AdaptiveIdentityResolver(registry=registry_with_http('Apache/2.4.x')), vulnerability_provider=load_bundled_provider()[0])
    assert result.software_evidence[-1]['version'] is None
    assert result.software_evidence[-1]['raw_version'] == '2.4.x'
    assert not result.potential_correlations


def test_malformed_software_or_accounting_rejected_at_executor_boundary():
    valid, _ = http_result()
    for result in [replace(valid, logical_requests=99), replace(valid, software=(replace(valid.software[0], host='192.0.2.2'),)), replace(valid, software=('dictionary instead of software',))]:
        action = replace(identity_registry().get('http_fingerprint'), handler=lambda ctx: result)
        outcome = execute(ProposedAction(action.action_id, 80, 'test'), knowledge(assessment(port(80, 'open', service='http'))), ActionRegistry([action]), Policy(), budget())
        assert outcome.status == 'INVALID_RESULT'
        assert not outcome.software


def test_acquisition_obeys_policy_and_budget():
    registry = registry_with_http()
    state = knowledge(assessment(port(80, 'open', service='http')))
    for policy, remaining in [(Policy(frozenset()), budget()), (Policy(), budget(network_requests=0))]:
        assert execute(ProposedAction('http_fingerprint', 80, ''), state, registry, policy, remaining).status == 'REJECTED'


def test_initial_evidence_is_reused_without_network_repetition():
    target = replace(assessment(port(80, 'open', service='http')), checks=(SecurityCheckResult('NS-CHECK-HTTP', 'HTTP', CheckStatus.COMPLETED, 80),))
    option = next(c for c in candidates(knowledge(target), identity_registry(), Policy(), budget()) if c.proposal.action_id == 'http_fingerprint')
    assert 'already collected' in option.rejection


def test_discriminating_capability_gets_explainable_bonus():
    evidence = HostEvidence()
    evidence.add(observation('operating_system', 'Windows', 'clue', 'clue', 'clue', hypothesis=True))
    target = assessment(port(80, 'open', service='http'))
    action = identity_registry().get('http_fingerprint')
    options = candidates(knowledge(target, evidence), ActionRegistry([action, replace(action, action_id='nondiscriminating', discriminates=())]), Policy(), budget())
    assert options[0].proposal.action_id == 'http_fingerprint'
    assert 'discrimination bonus 8' in options[0].proposal.reason


def test_verbose_rejection_dedup_keeps_full_json_trace():
    result = enrich_identity(assessment(port(80, 'open', service='http')), scan(), AdaptiveIdentityResolver(registry=registry_with_http()))
    trace = result.planning_trace
    rejection = {'proposal': {'action_id': 'rdp_identity', 'port': None}, 'rejection': 'No applicable endpoint'}
    for step in trace['steps']:
        step['candidates'].append(rejection)
    before = json.dumps(trace)
    output = StringIO()
    with redirect_stdout(output):
        planning_details(trace)
    assert output.getvalue().count('rdp_identity: No applicable endpoint') == 1
    assert json.dumps(trace) == before
    assert before.count('No applicable endpoint') == len(trace['steps'])


@pytest.mark.parametrize('field,value', [('raw_version', b'2.4.49'), ('vendor', {'name': 'Apache'}), ('variant', ['bad']), ('protocol', object())])
def test_software_field_types_cannot_break_json(field, value):
    result, _ = http_result()
    result = replace(result, software=(replace(result.software[0], **{field: value}),))
    action = replace(identity_registry().get('http_fingerprint'), handler=lambda ctx: result)
    outcome = execute(ProposedAction(action.action_id, 80, ''), knowledge(assessment(port(80, 'open', service='http'))), ActionRegistry([action]), Policy(), budget())
    assert outcome.status == 'INVALID_RESULT'


def test_conflicting_new_version_withholds_prior_match_but_retains_evidence():
    initial, _ = http_result()
    provider = load_bundled_provider()[0]
    prior = provider.correlate(initial.software[0])[0].to_dict()
    # Distinct initial source permits a discriminating protocol acquisition.
    software = {**asdict(initial.software[0]), 'source': 'Nmap fingerprint', 'confidence': 'MEDIUM'}
    original = replace(assessment(port(80, 'open', service='http')), software_evidence=(software,), potential_correlations=(prior,))
    result = enrich_identity(original, scan(), AdaptiveIdentityResolver(registry=registry_with_http('Apache/2.4.51')), vulnerability_provider=provider)
    assert {s['version'] for s in result.software_evidence} == {'2.4.49', '2.4.51'}
    assert not result.potential_correlations
    assert any(d.get('prior_candidate') == prior for d in result.correlation_diagnostics)
    assert original.potential_correlations == (prior,)


def test_http_nonaffected_boundary_does_not_match():
    result = enrich_identity(assessment(port(80, 'open', service='http')), scan(),
                             AdaptiveIdentityResolver(registry=registry_with_http('Apache/2.4.51')), vulnerability_provider=load_bundled_provider()[0])
    assert not result.potential_correlations


def test_acquisition_prerequisite_and_repeat_guards():
    action = replace(identity_registry().get('http_fingerprint'), prerequisites=('hostname',))
    state = knowledge(assessment(port(80, 'open', service='http')))
    assert 'prerequisite' in candidates(state, ActionRegistry([action]), Policy(), budget())[0].rejection
    result = enrich_identity(assessment(port(80, 'open', service='http')), scan(), AdaptiveIdentityResolver(registry=registry_with_http()))
    assert any('repeat suppressed' in (c['rejection'] or '') for c in result.planning_trace['steps'][-1]['candidates'])


def test_ssh_timeout_stays_inconclusive_without_software():
    result = acquire_ssh(ActionContext(HOST, 22, 1), probe=Mock(side_effect=ProbeError('deadline')))
    assert result.status == 'INCONCLUSIVE' and not result.software


def test_ssh_banner_os_hypothesis_does_not_claim_os_build():
    data = SSHProbeData('SSH-2.0-OpenSSH_for_Windows_9.0', '2.0', {'kex': ('curve25519-sha256',)}, 'completed', 'Bounded KEXINIT')
    result = acquire_ssh(ActionContext(HOST, 22, 1), probe=lambda *a, **k: data)
    evidence = HostEvidence(list(result.observations))
    refresh_hypotheses(evidence)
    assert evidence.resolve('operating_system')['value'] == 'Microsoft Windows'
    assert evidence.resolve('operating_system')['independent_confirmations'] == 0
    assert evidence.resolve('os_version')['state'] == 'UNRESOLVED'
    assert result.software[0].version == '9.0'  # OpenSSH product version, not Windows version.


def test_packet_failure_accounting_does_not_refund_reserved_budget():
    action = replace(identity_registry().get('http_fingerprint'), handler=Mock(side_effect=ProbeError('timeout')))
    remaining = budget()
    result = execute(ProposedAction(action.action_id, 80, ''), knowledge(assessment(port(80, 'open', service='http'))), ActionRegistry([action]), Policy(), remaining)
    assert result.status == 'FAILED'
    assert result.accounting['logical_units_reserved'] == 1
    assert remaining.requests == 1


def test_smb_139_security_check_is_unavailable_not_transport_failure():
    from netsentry.analysis.checks import SMBConfigurationCheck
    from netsentry.scanning.models import HostScanResult, PortService
    result = SMBConfigurationCheck().run(HostScanResult(HOST), PortService(139, 'tcp', 'open'))
    assert result.status == CheckStatus.UNAVAILABLE
    assert not result.findings
