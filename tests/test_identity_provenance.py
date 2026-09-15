"""Live-report regressions: provenance is retained without new identity claims."""
from dataclasses import asdict, replace
import json

import pytest

from netsentry.analysis.fingerprinting import collect_software_evidence
from netsentry.analysis.host_evidence import HostEvidence, IdentityProbeResult, observation
from netsentry.analysis.identity_resolution import collect_existing, enrich_identity, IdentityResolver
from netsentry.analysis.models import SecurityCheckResult, CheckStatus
from netsentry.scanning.models import PortService, ServiceIdentity
from tests.test_host_identity import scan, assessment
from tests.test_reporting import HOST, observation as port, render, windows_fixture


def test_unavailable_goals_render_under_attributes_not_as_fake_probes():
    result = enrich_identity(assessment(), scan())
    output = render(result, True)
    assert 'Probe: planner' not in output
    for attribute, label in [('operating_system', 'Operating system'), ('os_version', 'OS version/build')]:
        goal = result.host_identity['attributes'][attribute]
        assert goal['state'] == 'UNRESOLVED'
        assert 'No applicable unauthenticated identity probe' in goal['reason']
        assert goal['attempts'][0]['attributes'] == [attribute]
        assert goal['attempts'][0]['kind'] == 'unresolved_goal'
        assert f'{label}: Not established — UNRESOLVED' in output
    assert 'Endpoint: Unknown' not in output
    attempts = result.host_identity['attempts']
    assert len({tuple(a['attributes']) for a in attempts}) == len(attempts)
    assert json.loads(json.dumps(result.to_dict()))['host_identity'] == result.host_identity


def test_legacy_planner_json_is_still_interpreted_with_attribute_context():
    original = enrich_identity(assessment(), scan())
    legacy = json.loads(json.dumps(original.host_identity))
    for attempt in legacy['attempts']:
        attempt.pop('kind', None)
    for attribute in legacy['attributes'].values():
        for attempt in attribute['attempts']:
            attempt.pop('kind', None)
    result = replace(original, host_identity=legacy)
    before = json.dumps(result.to_dict())
    output = render(result, True)
    assert 'Probe: planner' not in output
    assert 'Goal limitation: No applicable' in output
    assert 'OS version/build: Not established — UNRESOLVED' in output
    assert json.dumps(result.to_dict()) == before


def software_identity(service, checks=()):
    software = collect_software_evidence(service, checks, host=HOST)
    target = replace(assessment(), software_evidence=tuple({**asdict(s), 'confidence': s.confidence.value} for s in software))
    return collect_existing(target, scan())


def assert_shared_provenance(evidence, expected_port, products):
    for product in products:
        product_item = next(o for o in evidence.observations if o.attribute == 'software_product' and o.value == product)
        version_item = next(o for o in evidence.observations if o.attribute == 'software_version' and o.value.startswith(product + ' '))
        for field in ['endpoint', 'source', 'probe', 'independence_key']:
            assert getattr(product_item, field) == getattr(version_item, field)
        assert product_item.endpoint == f'{HOST}:{expected_port}'


def test_http_response_products_and_versions_keep_identical_provenance():
    service = PortService(8443, 'tcp', 'open', identities=(ServiceIdentity('http', 'HTTP response', {'status': 200}), ServiceIdentity('tls', 'TLS handshake', {'version': 'TLSv1.3'})))
    check = SecurityCheckResult('NS-CHECK-HTTP', 'HTTP', CheckStatus.COMPLETED, 8443, 'tcp', 'http', details={'server': 'SecureWindowsFileServer/1.0 Python/3.14.6'})
    assert_shared_provenance(software_identity(service, (check,)), 8443, ['SecureWindowsFileServer', 'Python'])


@pytest.mark.parametrize('service,product', [
    (PortService(22, 'tcp', 'open', identities=(ServiceIdentity('ssh', 'SSH banner', {'banner': 'SSH-2.0-OpenSSH_9.0p1'}),)), 'OpenSSH'),
    (PortService(8080, 'tcp', 'open', product='Apache', version='2.4.49', service_method='probed', service_confidence='10', identities=(ServiceIdentity('http', 'Nmap', {'product': 'Apache'}),)), 'Apache'),
])
def test_ssh_and_nmap_software_provenance(service, product):
    assert_shared_provenance(software_identity(service), service.port, [product])


@pytest.mark.parametrize('location', [{}, {'host': HOST}, {'port': 8443}, {'host': None, 'port': None}])
def test_missing_endpoint_is_not_fabricated(location):
    target = replace(assessment(), software_evidence=({'product': 'Python', 'version': '3.14.6', 'source': 'imported evidence', **location},))
    items = collect_existing(target, scan()).observations
    assert len(items) == 2
    assert all(o.endpoint is None for o in items)


def test_https_stack_and_layers_do_not_multiply_host_identity_votes():
    target = assessment(replace(port(8443, 'open', service='https'), identities=({'protocol': 'tls', 'source': 'TLS handshake', 'evidence': {'version': 'TLSv1.3'}}, {'protocol': 'http', 'source': 'HTTP response', 'evidence': {'status': 200}})))
    target = replace(target, checks=(SecurityCheckResult('NS-CHECK-TLS', 'TLS', CheckStatus.COMPLETED, 8443, 'tcp', 'tls', details={'subject': 'HOST'}),))
    result = enrich_identity(target, scan())
    evidence = result.host_identity
    assert [(o['attribute'], o['value']) for o in evidence['observations'] if o['attribute'] == 'confirmed_service'] == [('confirmed_service', 'https')]
    assert evidence['attributes']['hostname']['independent_confirmations'] == 1
    assert evidence['attributes']['hostname']['state'] == 'PROBABLE'
    assert evidence['attributes']['operating_system']['state'] == 'UNRESOLVED'
    assert result.coverage.confirmed_services == 1
    output = render(result, True)
    for phrase in ['Confirmed service stack: HTTPS (HTTP over TLS)', 'Confirmed protocol: tls', 'Protocol role: Transport/security layer', 'Confirmed protocol: http', 'Protocol role: Application layer']:
        assert phrase in output
    assert result.observations == target.observations


def test_coverage_wording_identifies_service_scope():
    target = windows_fixture()
    output = render(target, True)
    assert f'Open ports without confirmed service identity: {target.coverage.unconfirmed_open_ports}' in output
    assert 'Open ports without confirmed identity:' not in output


def test_live_windows_associated_clues_remain_unresolved_without_os_evidence():
    checks = (SecurityCheckResult('NS-CHECK-SMB', 'SMB', CheckStatus.COMPLETED, 445, 'tcp', 'smb', details={'dialect': 'SMB 3.1.1'}),)
    target = replace(windows_fixture(), checks=checks, software_evidence=({'product': 'SecureWindowsFileServer', 'version': '1.0', 'source': 'HTTP Server header', 'host': HOST, 'port': 8443}, {'product': 'Python', 'version': '3.14.6', 'source': 'HTTP Server header', 'host': HOST, 'port': 8443}))
    def netbios(*args, **kwargs):
        return IdentityProbeResult('COMPLETED', 'Node status collected', (observation('hostname', 'HOST', 'NetBIOS node status', 'netbios_identity', 'netbios'), observation('workgroup', 'WORKGROUP', 'NetBIOS group', 'netbios_identity', 'netbios')))
    def rpc(*args, **kwargs):
        return IdentityProbeResult('COMPLETED', 'One bounded page', (observation('rpc_annotation', 'Ngc Pop Key Service', 'RPC annotation', 'rpc_identity', 'rpc'),))
    before = json.dumps(target.to_dict())
    result = enrich_identity(target, scan(), IdentityResolver({'netbios_identity': netbios, 'rpc_identity': rpc}))
    for attribute in ['operating_system', 'os_version', 'os_edition', 'candidate_cpe']:
        assert result.host_identity['attributes'][attribute]['state'] == 'UNRESOLVED'
    assert any(o['value'] == 'Ngc Pop Key Service' for o in result.host_identity['observations'])
    assert json.dumps(target.to_dict()) == before
    payload = result.to_dict()
    payload.pop('host_identity')
    assert payload == target.to_dict()  # Includes findings, risk, coverage, raw states and correlations.
    assert result.observations is target.observations
    assert result.findings is target.findings
