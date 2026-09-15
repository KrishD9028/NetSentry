"""Identity evidence and follow-ups must not change the security assessment."""
import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from netsentry.analysis.host_evidence import HostEvidence, HostObservation, IdentityProbeResult, observation, ntlm_observations, ATTRIBUTES
from netsentry.analysis.identity_resolution import IdentityResolver, collect_existing, enrich_identity, GOALS
from netsentry.analysis.models import HostAssessment, SecurityCheckResult, CheckStatus
from netsentry.analysis.probes import ProbeError
from tests.test_reporting import observation as port_observation, windows_fixture, render, HOST


def item(value='HOST', family='one', **kwargs):
    return observation('hostname', value, family, family, family, **kwargs)


def evidence(*items):
    result = HostEvidence()
    for current in items:
        result.add(current)
    return result


@pytest.mark.parametrize('items,state,votes', [
    ((item(),), 'PROBABLE', 1),
    ((item(authoritative=True),), 'CONFIRMED', 1),
    ((item(), item('host.', 'two')), 'CONFIRMED', 2),
    ((item(), replace(item(), source='another AV field')), 'PROBABLE', 1),
    ((item(hypothesis=True), item(family='two', hypothesis=True)), 'PROBABLE', 0),
    ((item(hypothesis=True, authoritative=True),), 'PROBABLE', 0),
    ((item(), item(family='two', hypothesis=True)), 'PROBABLE', 1),
    ((item(), item('other', 'two')), 'CONTRADICTORY', 0),
    ((), 'UNRESOLVED', 0),
])
def test_resolution_states_and_independence(items, state, votes):
    result = evidence(*items).resolve('hostname')
    assert result['state'] == state
    assert result['independent_confirmations'] == votes
    assert result['reason']
    assert len(result['observations']) == len(items)


@pytest.mark.parametrize('value', ['', '  ', 'x' * 2049, None, 42])
def test_invalid_observations_rejected(value):
    result = evidence(replace(item(), value=value))
    assert not result.observations


def test_normalization_keeps_different_hostnames_and_conflicts():
    result = evidence(item('HOST.'), item('host', 'two'), item('host.other.test', 'three'))
    assert result.resolve('hostname')['state'] == 'CONTRADICTORY'
    assert len(result.to_dict()['observations']) == 3


def test_attempt_attribute_association_and_raw_observations():
    result = evidence(observation('rpc_annotation', 'Remote interface', 'RPC', 'rpc_identity', 'rpc'))
    attempt = {'probe': 'rdp_identity', 'status': 'INCONCLUSIVE', 'reason': 'Timeout', 'attributes': ['hostname']}
    result.attempts.append(attempt)
    assert result.resolve('hostname')['attempts'] == [attempt]
    assert result.resolve('os_edition')['attempts'] == []
    assert result.to_dict()['observations'][0]['attribute'] == 'rpc_annotation'
    assert 'rpc_annotation' not in result.to_dict()['attributes']


def test_one_ntlm_challenge_never_votes_for_itself():
    fields = dict(netbios_computer_name='HOST', dns_computer_name='host.lab.test', product_version='10.0.19045')
    result = evidence(*ntlm_observations(fields, 'rdp_identity', HOST + ':3389/tcp'))
    assert result.resolve('hostname')['state'] == 'PROBABLE'
    assert result.resolve('hostname')['independent_confirmations'] == 1
    assert result.resolve('operating_system')['state'] == 'PROBABLE'
    assert result.resolve('operating_system')['independent_confirmations'] == 0
    assert result.resolve('os_edition')['state'] == 'UNRESOLVED'


def scan(hostname=None):
    return SimpleNamespace(hostname=hostname, raw_xml=None)


def assessment(*ports):
    return HostAssessment(HOST, observations=tuple(ports))


def test_discovery_dns_does_not_count_again_as_independent():
    result = collect_existing(assessment(), scan('HOST'), SimpleNamespace(hostname='HOST', mac=None, vendor=None))
    assert result.resolve('hostname')['state'] == 'PROBABLE'


@pytest.mark.parametrize('port,service,hint,expected', [
    (3389, None, None, [('rdp_identity', 3389)]),
    (135, None, None, [('rpc_identity', 135)]),
    (139, None, None, [('netbios_identity', 137)]),
    (445, None, None, [('netbios_identity', 137)]),
    (8443, 'rdp', None, [('rdp_identity', 8443)]),
    (80, 'http', None, []), (3389, 'http', None, []),
    (111, None, 'rpcbind', []), (135, 'http', 'msrpc', []),
    (445, None, 'http', []), (12345, None, None, []),
])
def test_planner_protocol_aware_fallback(port, service, hint, expected):
    target = assessment(port_observation(port, 'open', service=service, hint=hint))
    assert IdentityResolver().plan(target, HostEvidence()) == expected


@pytest.mark.parametrize('state', ['closed', 'filtered', 'unknown', 'open|filtered'])
def test_nonopen_ports_never_trigger_probes(state):
    target = assessment(*(port_observation(port, state) for port in [135, 139, 445, 3389]))
    assert IdentityResolver().plan(target, HostEvidence()) == []


def test_planner_no_duplicate_nbns_and_no_udp_tcp_confusion():
    target = assessment(port_observation(139, 'open'), port_observation(445, 'open'), replace(port_observation(3389, 'open'), protocol='udp'))
    assert IdentityResolver().plan(target, HostEvidence()) == [('netbios_identity', 137)]


def test_satisfied_goals_skip_probe():
    result = HostEvidence()
    for attribute in GOALS['netbios_identity']:
        result.add(observation(attribute, 'value', 'trusted', 'trusted', 'trusted', authoritative=True))
    assert IdentityResolver().plan(assessment(port_observation(445, 'open')), result) == []


@pytest.mark.parametrize('observations', [(), (item(),), (item(), item('OTHER', 'two'))])
def test_unresolved_probable_conflicting_identity_can_be_corroborated(observations):
    assert IdentityResolver().plan(assessment(port_observation(445, 'open')), evidence(*observations))


def test_probe_count_budget_and_no_repeat():
    probe = Mock(return_value=IdentityProbeResult('COMPLETED', 'bounded evidence'))
    resolver = IdentityResolver({name: probe for name in GOALS}, max_probes=1)
    target = assessment(*(port_observation(port, 'open') for port in [135, 445, 3389]))
    result = resolver.resolve(target, HostEvidence())
    assert probe.call_count == 1
    assert len(result.attempts) == 3
    assert all('budget exhausted' in a['reason'] for a in result.attempts[1:])
    resolver.resolve(target, result)
    assert probe.call_count == 1
    assert len(result.attempts) == 3


def test_global_deadline_and_remaining_timeout():
    probe = Mock(return_value=IdentityProbeResult('COMPLETED', 'done'))
    resolver = IdentityResolver({name: probe for name in GOALS}, timeout=2)
    target = assessment(port_observation(135, 'open'), port_observation(445, 'open'))
    with patch('netsentry.analysis.identity_resolution.time.monotonic', side_effect=[10, 11, 12]):
        result = resolver.resolve(target, HostEvidence())
    assert probe.call_count == 1
    assert probe.call_args.kwargs['timeout'] == 1
    assert 'budget exhausted' in result.attempts[-1]['reason']


@pytest.mark.parametrize('exc', [OSError('transport'), ProbeError('malformed remote packet')])
def test_expected_probe_failures_are_structured(exc):
    probe = Mock(side_effect=exc)
    result = IdentityResolver({'rdp_identity': probe}).resolve(assessment(port_observation(3389, 'open')), HostEvidence())
    assert result.attempts[0]['status'] == 'FAILED'
    assert str(exc) in result.attempts[0]['reason']


@pytest.mark.parametrize('exc', [RuntimeError('bug'), TypeError('bug'), ValueError('bug'), AttributeError('bug')])
def test_programmer_errors_propagate(exc):
    with pytest.raises(type(exc), match='bug'):
        IdentityResolver({'rdp_identity': Mock(side_effect=exc)}).resolve(assessment(port_observation(3389, 'open')), HostEvidence())


def test_metadata_reuse_and_preservation_without_smb_negotiation():
    checks = (
        SecurityCheckResult('NS-CHECK-SMB', 'SMB', CheckStatus.COMPLETED, 445, 'tcp', 'smb', details={'dialect': 'SMB 3.1.1', 'identity': 'guid-123'}),
        SecurityCheckResult('NS-CHECK-TLS', 'TLS', CheckStatus.COMPLETED, 443, 'tcp', 'tls', details={'subject': 'HOST'}),
        SecurityCheckResult('NS-CHECK-RDP', 'RDP', CheckStatus.COMPLETED, 3389, 'tcp', 'rdp', details={'attempts': [{'certificate': {'subject': 'HOST'}}]}),
    )
    original = replace(windows_fixture(), checks=checks)
    with patch('netsentry.analysis.probes.probe_smb', side_effect=AssertionError('Must reuse negotiation')):
        result = collect_existing(original, scan())
    assert result.resolve('hostname')['state'] == 'PROBABLE'  # TLS/RDP copies of certificate are one source.
    assert result.resolve('os_version')['state'] == 'UNRESOLVED'
    assert result.resolve('os_edition')['state'] == 'UNRESOLVED'
    assert any(o.attribute == 'smb_server_guid' for o in result.observations)
    assert any(a['probe'] == 'smb_metadata' and a['reused'] for a in result.attempts)


def test_identity_enrichment_preserves_assessment_and_success_after_failure():
    original = windows_fixture()
    before = json.dumps(original.to_dict(), sort_keys=True)
    success = IdentityProbeResult('COMPLETED', 'Node status', (item('HOST', 'netbios'),))
    resolver = IdentityResolver({'rpc_identity': Mock(side_effect=OSError('RPC failed')), 'netbios_identity': Mock(return_value=success)})
    enriched = enrich_identity(original, scan(), resolver)
    assert enriched.host_identity['attributes']['hostname']['value'] == 'HOST'
    assert any(a['status'] == 'FAILED' for a in enriched.host_identity['attempts'])
    assert json.dumps(original.to_dict(), sort_keys=True) == before
    result = enriched.to_dict()
    result.pop('host_identity')
    assert result == original.to_dict()
    assert enriched.findings == original.findings
    assert enriched.observations == original.observations
    assert enriched.risk_score == original.risk_score
    assert enriched.observed_risk_score == original.observed_risk_score


def test_contradictory_os_versions_retained_and_never_correlated():
    original = assessment(port_observation(3389, 'open'), port_observation(3390, 'open', service='rdp'))
    def probe(host, port, timeout):
        return IdentityProbeResult('COMPLETED', 'NTLM version reported', ntlm_observations({'product_version': '10.0.19045' if port == 3389 else '6.1.7601'}, 'rdp_identity', f'{host}:{port}/tcp'))
    provider = Mock()
    result = enrich_identity(original, scan(), IdentityResolver({'rdp_identity': probe}), vulnerability_provider=provider)
    assert result.host_identity['attributes']['os_version']['state'] == 'CONTRADICTORY'
    assert {e['raw_version'] for e in result.software_evidence} == {'10.0.19045', '6.1.7601'}
    assert len(result.correlation_diagnostics) == 2
    assert not provider.mock_calls
    assert not result.potential_correlations


def test_report_has_explanations_evidence_attempts_without_compact_noise():
    original = assessment(port_observation(445, 'open'))
    def probe(*args, **kwargs):
        return IdentityProbeResult('COMPLETED', 'Node status collected', (item('SECOND', 'netbios', endpoint=HOST + ':137/udp'),))
    result = enrich_identity(original, scan('FIRST'), IdentityResolver({'netbios_identity': probe}))
    verbose, compact = render(result, True), render(result)
    assert 'HOST IDENTITY' not in compact
    for word in ['HOST IDENTITY', 'Resolved attributes:', 'Evidence:', 'Follow-up attempts:', 'CONTRADICTORY', 'FIRST', 'SECOND', 'UNRESOLVED', 'Explanation:', 'Source:', 'probe netbios', ':137/udp', '(new)']:
        assert word in verbose
    assert 'raw_xml' not in verbose
    assert "'attributes':" not in verbose
    assert set(result.host_identity) == {'attributes', 'observations', 'attempts'}
    assert 'host_identity' not in original.to_dict()


def test_low_quality_agreement_is_not_high_confidence_os_identity():
    from netsentry.analysis.models import Confidence
    result = evidence(*(observation('operating_system', 'Microsoft Windows', name, name, name, confidence=Confidence.LOW) for name in ['one', 'two']))
    assert result.resolve('operating_system')['state'] == 'PROBABLE'
    result = evidence(*(observation('operating_system', 'Microsoft Windows', name, name, name, confidence=Confidence.HIGH) for name in ['one', 'two']))
    assert result.resolve('operating_system')['state'] == 'CONFIRMED'


def test_missing_value_helper_does_not_fabricate_identity():
    assert evidence(observation('hostname', None, 'source', 'probe', 'family')).resolve('hostname')['state'] == 'UNRESOLVED'


@pytest.mark.parametrize('confirm_os', [False, True])
def test_ntlm_correlation_requires_product_identity_and_preserves_potential_semantics(confirm_os):
    from netsentry.analysis.correlation import StaticVulnerabilityProvider, VulnerabilityDefinition
    from netsentry.analysis.versions import AffectedVersionRange
    from netsentry.analysis.models import Severity
    # Synthetic definition is a provider-boundary test, never shipped as intelligence.
    provider = StaticVulnerabilityProvider((VulnerabilityDefinition('CVE-2099-0001', 'Microsoft Windows', (AffectedVersionRange('numeric', exact='10.0.19045'),), 'test-only', variant='ntlm_reported', severity=Severity.CRITICAL),))
    def probe(host, port, timeout):
        items = ntlm_observations({'product_version': '10.0.19045'}, 'rdp_identity', f'{host}:{port}/tcp')
        if confirm_os:
            items += (observation('operating_system', 'Microsoft Windows', 'Explicit trusted fixture', 'trusted', 'trusted', authoritative=True),)
        return IdentityProbeResult('COMPLETED', 'NTLM version observed', items)
    original = replace(windows_fixture(), observations=(port_observation(3389, 'open'),))
    result = enrich_identity(original, scan(), IdentityResolver({'rdp_identity': probe}), vulnerability_provider=provider)
    assert result.software_evidence[-1]['version'] == '10.0.19045'
    assert result.software_evidence[-1]['raw_version'] == '10.0.19045'
    assert result.software_evidence[-1]['variant'] == 'ntlm_reported'
    assert len(result.potential_correlations) == int(confirm_os)
    if confirm_os:
        assert result.potential_correlations[-1]['status'] == 'POTENTIAL'
    else:
        assert 'does not establish Windows' in result.correlation_diagnostics[-1]['reason']
    assert result.observed_risk_score == original.observed_risk_score
    assert result.risk_score == original.risk_score
    assert result.findings == original.findings


def test_existing_findings_are_preserved_exactly():
    from netsentry.analysis.models import Finding, Severity, Confidence
    finding = Finding('TEST-HIGH', 'Known configuration finding', 'Description', Severity.HIGH, Confidence.HIGH, HOST, 'Observed security evidence', 'Fix configuration', 'TEST-HIGH', port=445, protocol='tcp', service='smb')
    original = replace(windows_fixture(), findings=(finding,))
    result = enrich_identity(original, scan('HOST'), IdentityResolver(probes={}))
    assert result.findings is original.findings
    assert result.risk_score == original.risk_score
    assert result.observed_risk_score == original.observed_risk_score == 8


def test_cli_identity_single_and_discovered_json_integration():
    from contextlib import redirect_stdout
    from io import StringIO
    from netsentry.main import _build_parser, _run_assess
    from netsentry.discovery.models import Device
    from netsentry.scanning.models import HostScanResult
    target = HostScanResult(HOST)
    original = assessment(port_observation(3389, 'open'))
    for discovered in [False, True]:
        output = StringIO()
        probe = Mock(return_value=IdentityProbeResult('COMPLETED', 'Identity collected', (item('HOST', 'rdp_ntlm'),)))
        flags = ['--discovered'] if discovered else [HOST]
        with patch('netsentry.main.scan_target', return_value=target), patch('netsentry.main.assess_scan_result', return_value=original), patch('netsentry.main.load_current_snapshot', return_value=[Device(HOST, 'Unknown', 'Unknown', 'Unknown')]), patch('netsentry.main.IdentityResolver', return_value=IdentityResolver({'rdp_identity': probe})), redirect_stdout(output):
            assert _run_assess(_build_parser().parse_args(['assess', *flags, '--json', '--verbose'])) == 0
        payload = json.loads(output.getvalue())
        host = payload['assessments'][0] if discovered else payload
        assert host['host_identity']['attributes']['hostname']['value'] == 'HOST'
        assert probe.call_count == 1
