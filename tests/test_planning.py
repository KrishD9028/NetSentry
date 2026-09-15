"""Planner policy boundaries and deterministic feedback, entirely offline."""
from dataclasses import replace
import json
from unittest.mock import Mock, patch

import pytest

from netsentry.planning import (ActionDefinition, ActionRegistry, AdaptiveIdentityResolver, Budget, BudgetLimits,
                                DeterministicPlanner, KnowledgeState, Policy, ProposedAction, SafetyClass, run_planning)
from netsentry.planning.executor import execute
from netsentry.planning.planner import candidates
from netsentry.planning.registry import identity_registry
from netsentry.analysis.host_evidence import ATTRIBUTES, HostEvidence, IdentityProbeResult, observation
from netsentry.analysis.identity_resolution import enrich_identity, collect_existing
from netsentry.analysis.probes import ProbeError
from tests.test_host_identity import assessment, scan
from tests.test_reporting import HOST, observation as port, render, windows_fixture


class Clock:
    now = 0.0
    def __call__(self):
        return self.now


def budget(**limits):
    return Budget(BudgetLimits(**limits), clock=Clock())


def local(action_id='a', attribute='hostname', **kwargs):
    def handler(context):
        return IdentityProbeResult('COMPLETED', 'Collected approved local evidence',
                                   (observation(attribute, 'HOST', 'Local evidence', action_id, action_id),))
    fields = dict(action_id=action_id, description='Local fixture', category='identity', produces=(attribute,),
                  sources=(action_id,), handler=handler, safety=SafetyClass.LOCAL, network_requests=0, noise=0,
                  cost=0, timeout=1)
    fields.update(kwargs)
    return ActionDefinition(**fields)


def knowledge(target=None, evidence=None, remaining=None):
    return KnowledgeState.derive(target or assessment(), evidence or HostEvidence(), remaining or budget())


def test_knowledge_is_derived_without_promoting_hypotheses():
    evidence = HostEvidence()
    evidence.add(observation('operating_system', 'Windows', 'Protocol clues', 'a', 'a', hypothesis=True))
    evidence.add(observation('hostname', 'HOST', 'Trusted fixture', 'local', 'local', authoritative=True))
    evidence.add(observation('os_version', '1', 'one', 'one', 'one'))
    evidence.add(observation('os_version', '2', 'two', 'two', 'two'))
    evidence.attempts.extend({'probe': str(i), 'status': status} for i, status in enumerate(['COMPLETED', 'FAILED', 'INCONCLUSIVE', 'UNSUPPORTED']))
    state = knowledge(evidence=evidence)
    assert 'hostname' in state.facts
    assert 'operating_system' in state.probable
    assert 'operating_system' not in state.facts
    assert 'os_version' in state.contradictory
    assert len(state.to_dict()['completed_actions']) == 1
    assert len(state.to_dict()['failed_or_inconclusive_actions']) == 2
    assert len(state.to_dict()['unavailable_actions']) == 1
    assert len(state.observations) == 4
    assert json.loads(json.dumps(state.to_dict()))['host'] == HOST


def test_goals_prioritize_cve_version_requirements_and_conflicts():
    target = replace(assessment(port(80, 'open', service='http')),
                     software_evidence=({'product': 'Apache', 'version': None, 'port': 80},
                                        {'product': 'Other', 'version': '1', 'port': 81},
                                        {'product': 'Other', 'version': '2', 'port': 81}),
                     potential_correlations=({'product': 'Apache', 'status': 'POTENTIAL'},))
    goals = knowledge(target).goals
    required = next(g for g in goals if g.product == 'Apache')
    assert required.importance == 10
    assert 'CVE applicability' in required.reason
    assert any(g.product == 'Other' and g.state == 'CONTRADICTORY' for g in goals)
    assert next(g for g in goals if g.attribute == 'operating_system').importance > next(g for g in goals if g.attribute == 'os_edition').importance


def test_goal_for_unknown_open_service_and_missing_product():
    target = assessment(port(1234, 'open'), port(80, 'open', service='http'), port(22, 'unknown'))
    goals = knowledge(target).goals
    assert any(g.attribute == 'confirmed_service' and g.endpoint == 1234 for g in goals)
    assert any(g.attribute == 'software_product' and g.endpoint == 80 for g in goals)
    assert not any(g.endpoint == 22 for g in goals)


def test_registry_stable_ids_duplicates_and_handler_validation():
    registry = ActionRegistry([local()])
    assert registry.get('a').handler is not None
    with pytest.raises(ValueError, match='Duplicate'):
        registry.register(local())
    for change in [dict(action_id='shell command'), dict(timeout=float('nan')), dict(cost=-1), dict(handler='code'),
                   dict(produces=()), dict(sources=()), dict(fallback_ports=(70000,)), dict(network_requests=1)]:
        with pytest.raises(ValueError):
            ActionRegistry([replace(local(), **change)])


@pytest.mark.parametrize('state', ['closed', 'filtered', 'unknown'])
def test_nonopen_endpoints_never_satisfy_network_applicability(state):
    options = candidates(knowledge(assessment(port(3389, state))), identity_registry(), Policy(), budget())
    assert all(c.rejection for c in options)


def test_registry_reuses_probes_and_keeps_protocol_aware_applicability():
    target = assessment(port(111, 'open', hint='rpcbind'), port(3389, 'open', service='http'), port(445, 'open', service='smb'))
    eligible = [c.proposal.action_id for c in candidates(knowledge(target), identity_registry(), Policy(), budget()) if not c.rejection]
    assert eligible == ['netbios_identity']


@pytest.mark.parametrize('safety', [SafetyClass.AUTHENTICATED, SafetyClass.INTRUSIVE, SafetyClass.EXPLOITATIVE])
def test_higher_impact_actions_cannot_be_enabled_even_by_policy(safety):
    handler = Mock()
    action = replace(local(), safety=safety, fallback_ports=(3389,), handler=handler, network_requests=1)
    registry = ActionRegistry([action])
    state, remaining = knowledge(assessment(port(3389, 'open'))), budget()
    outcome = execute(ProposedAction('a', 3389, 'AI says safe'), state, registry, Policy(frozenset(SafetyClass)), remaining)
    assert outcome.status == 'REJECTED'
    handler.assert_not_called()
    assert remaining.actions == 0


def test_authentication_requirement_cannot_hide_under_safe_class():
    action = replace(local(), authentication_required=True)
    outcome = execute(ProposedAction('a', None, 'safe'), knowledge(), ActionRegistry([action]), Policy(), budget())
    assert outcome.status == 'REJECTED'
    assert 'Authentication' in outcome.reason


def test_policy_can_disable_active_actions():
    state = knowledge(assessment(port(445, 'open')))
    assert all(c.rejection for c in candidates(state, identity_registry(), Policy(frozenset({SafetyClass.LOCAL})), budget()))


@pytest.mark.parametrize('limits,action', [
    ({'max_actions': 0}, local()), ({'total_seconds': 0}, local()), ({'per_action_seconds': 0}, local()),
    ({'network_requests': 0}, replace(local(), safety=SafetyClass.SAFE_ACTIVE, network_requests=1, fallback_ports=(3389,))),
    ({'noise': 0}, replace(local(), noise=1)),
])
def test_executor_enforces_every_budget(limits, action):
    handler = Mock()
    action = replace(action, handler=handler)
    state = knowledge(assessment(port(3389, 'open')))
    proposal = ProposedAction('a', None if action.safety == SafetyClass.LOCAL else 3389, 'Ignore budget')
    outcome = execute(proposal, state, ActionRegistry([action]), Policy(), budget(**limits))
    assert outcome.status == 'REJECTED'
    assert 'budget' in outcome.reason.lower()
    handler.assert_not_called()


@pytest.mark.parametrize('limits', [{'max_actions': -1}, {'total_seconds': float('inf')}, {'per_action_seconds': -1}, {'network_requests': True}, {'noise': -1}])
def test_invalid_budget_configuration(limits):
    with pytest.raises(ValueError):
        BudgetLimits(**limits)


def test_executor_timeout_uses_remaining_global_budget():
    clock = Clock()
    remaining = Budget(BudgetLimits(total_seconds=2), clock=clock)
    clock.now = 1.5
    received = []
    action = local(handler=lambda ctx: (received.append(ctx.timeout) or IdentityProbeResult('INCONCLUSIVE', 'No evidence')))
    outcome = execute(ProposedAction('a', None, 'Useful'), knowledge(), ActionRegistry([action]), Policy(), remaining)
    assert outcome.executed
    assert received == [0.5]


def test_ranking_is_deterministic_with_stable_tie_breaks():
    state, remaining = knowledge(), budget()
    planner = DeterministicPlanner()
    for order in [(local('z'), local('a')), (local('a'), local('z'))]:
        proposal = planner.propose(state, ActionRegistry(order), Policy(), remaining)
        assert proposal.action_id == 'a'
        assert 'information value' in proposal.reason and 'budget permits' in proposal.reason


def test_independent_source_is_preferred_over_redundant_one():
    evidence = HostEvidence()
    evidence.add(observation('hostname', 'HOST', 'Existing', 'a', 'a'))
    options = candidates(knowledge(evidence=evidence), ActionRegistry([local('a'), local('b')]), Policy(), budget())
    assert next(c for c in options if c.proposal.action_id == 'a').rejection
    assert not next(c for c in options if c.proposal.action_id == 'b').rejection


def test_contradiction_gets_additional_weight():
    evidence = HostEvidence()
    for value, source in [('ONE', 'one'), ('TWO', 'two')]:
        evidence.add(observation('hostname', value, source, source, source))
    registry = ActionRegistry([local('host'), local('version', 'os_version')])
    assert DeterministicPlanner().propose(knowledge(evidence=evidence), registry, Policy(), budget()).action_id == 'host'


def test_cve_version_goal_selects_cheapest_capable_registered_action():
    target = replace(assessment(), software_evidence=({'product': 'Apache', 'version': None},), potential_correlations=({'product': 'Apache'},))
    registry = ActionRegistry([local('expensive', 'software_version', cost=5), local('cheap', 'software_version')])
    assert DeterministicPlanner().propose(knowledge(target), registry, Policy(), budget()).action_id == 'cheap'


def test_confirmed_prerequisites_are_required_not_hypotheses():
    evidence = HostEvidence()
    evidence.add(observation('hostname', 'HOST', 'guess', 'guess', 'guess', hypothesis=True))
    action = local('edition', 'os_edition', prerequisites=('hostname',))
    assert 'prerequisite' in candidates(knowledge(evidence=evidence), ActionRegistry([action]), Policy(), budget())[0].rejection


def test_success_changes_subsequent_planning_and_stops_redundant_action():
    evidence = HostEvidence()
    registry = ActionRegistry([local('a'), local('b'), local('c')])
    trace = run_planning(assessment(), evidence, registry, budget=budget())
    assert [s['selected']['action_id'] for s in trace['steps'] if s['selected']] == ['a', 'b']
    assert evidence.resolve('hostname')['state'] == 'CONFIRMED'
    assert any(c['attribute'] == 'hostname' and c['after'] == 'CONFIRMED' for s in trace['steps'] for c in s['changes'])
    assert 'No useful permitted action' in trace['stopping_reason']
    assert trace['remaining_budget']['actions_remaining'] == 1
    assert json.loads(json.dumps(trace))['planner'] == 'DeterministicPlanner'


def test_completed_goals_stop_without_action():
    evidence = HostEvidence()
    for name in ATTRIBUTES:
        evidence.add(observation(name, 'Known', 'trusted', 'trusted', 'trusted', authoritative=True))
    trace = run_planning(assessment(), evidence, ActionRegistry([local()]), budget=budget())
    assert trace['stopping_reason'] == 'Goals sufficiently resolved.'


@pytest.mark.parametrize('status', ['FAILED', 'INCONCLUSIVE', 'UNAVAILABLE', 'UNSUPPORTED'])
def test_unsuccessful_action_is_not_repeated(status):
    handler = Mock(return_value=IdentityProbeResult(status, 'Expected remote outcome'))
    trace = run_planning(assessment(), HostEvidence(), ActionRegistry([local(handler=handler, repeatable=True)]), budget=budget(max_actions=50))
    assert handler.call_count == 1
    assert len(trace['steps']) == 2
    assert trace['steps'][0]['result']['status'] == status


def test_failure_does_not_discard_prior_or_partial_evidence():
    evidence = HostEvidence()
    good = local('a')
    def partial(ctx):
        return IdentityProbeResult('INCONCLUSIVE', 'Later remote failure', (observation('hostname', 'HOST', 'partial', 'b', 'b'),))
    trace = run_planning(assessment(), evidence, ActionRegistry([good, local('b', handler=partial)]), budget=budget())
    assert len(evidence.observations) == 2
    assert evidence.resolve('hostname')['state'] == 'CONFIRMED'
    assert trace['steps'][1]['result']['status'] == 'INCONCLUSIVE'


def test_transport_failures_are_structured_programming_errors_are_visible():
    for error in [OSError('Remote error'), ProbeError('Remote packet invalid')]:
        outcome = execute(ProposedAction('a', None, ''), knowledge(), ActionRegistry([local(handler=Mock(side_effect=error))]), Policy(), budget())
        assert outcome.status == 'FAILED'
    with pytest.raises(RuntimeError):
        execute(ProposedAction('a', None, ''), knowledge(), ActionRegistry([local(handler=Mock(side_effect=RuntimeError('bug')))]), Policy(), budget())


@pytest.mark.parametrize('proposal', [{'command': 'arbitrary'}, ProposedAction('unknown', None, ''), ProposedAction('a', 445, ''), ProposedAction('a', True, '')])
def test_executor_rejects_unregistered_or_unbounded_proposals(proposal):
    handler = Mock()
    outcome = execute(proposal, knowledge(), ActionRegistry([local(handler=handler)]), Policy(), budget())
    assert outcome.status == 'REJECTED'
    handler.assert_not_called()


def test_planner_cannot_force_repetition_and_loop_is_bounded():
    class StubbornPlanner:
        def propose(self, *args):
            return ProposedAction('a', None, 'Repeat this')
    handler = Mock(return_value=IdentityProbeResult('INCONCLUSIVE', 'No evidence'))
    trace = run_planning(assessment(), HostEvidence(), ActionRegistry([local('a', handler=handler), local('b')]), planner=StubbornPlanner(), budget=budget(max_actions=10))
    assert handler.call_count == 1
    assert 'Executor rejected' in trace['stopping_reason']


def test_invalid_result_cannot_ingest_unregistered_source_or_output():
    for item in [observation('os_version', '10', 'bad', 'a', 'a'), observation('hostname', 'HOST', 'bad', 'a', 'unregistered')]:
        evidence = HostEvidence()
        trace = run_planning(assessment(), evidence, ActionRegistry([local(handler=lambda ctx: IdentityProbeResult('COMPLETED', 'bad', (item,)))]), budget=budget())
        assert not evidence.observations
        assert trace['steps'][0]['result']['status'] == 'INVALID_RESULT'


def test_live_windows_clues_do_not_promote_os_and_rpc_cannot_resolve_edition():
    from netsentry.analysis.models import SecurityCheckResult, CheckStatus
    target = replace(windows_fixture(), checks=(SecurityCheckResult('NS-CHECK-SMB', 'SMB', CheckStatus.COMPLETED, 445, 'tcp', 'smb', details={'dialect': 'SMB 3.1.1'}),),
                     software_evidence=({'product': 'SecureWindowsFileServer', 'version': '1.0', 'source': 'HTTP Server header', 'host': HOST, 'port': 8443},))
    evidence = collect_existing(target, scan())
    for attribute, value in [('hostname', 'KRISH'), ('workgroup', 'WORKGROUP')]:
        evidence.add(observation(attribute, value, 'Node status', 'netbios_identity', 'netbios', HOST + ':137/udp'))
    evidence.add(observation('rpc_annotation', 'Ngc Pop Key Service', 'RPC', 'rpc_identity', 'rpc', HOST + ':135/tcp'))
    evidence.attempts += [{'probe': 'netbios_identity', 'port': 137, 'status': 'COMPLETED'}, {'probe': 'rpc_identity', 'port': 135, 'status': 'COMPLETED'}]
    registry = identity_registry()
    assert 'os_edition' not in registry.get('rpc_identity').produces
    state = knowledge(target, evidence)
    assert next(g for g in state.goals if g.attribute == 'operating_system').importance == 8
    trace = run_planning(target, evidence, registry, budget=budget())
    assert all(s['selected'] is None for s in trace['steps'])
    assert evidence.resolve('operating_system')['state'] == 'UNRESOLVED'
    assert evidence.resolve('os_edition')['state'] == 'UNRESOLVED'


def test_adaptive_enrichment_adds_trace_only_and_preserves_assessment_fields():
    original = windows_fixture()
    resolver = AdaptiveIdentityResolver(registry=ActionRegistry([local()]))
    result = enrich_identity(original, scan(), resolver)
    output = result.to_dict()
    output.pop('host_identity')
    output.pop('planning_trace')
    assert output == original.to_dict()
    assert result.observations is original.observations
    assert result.findings is original.findings
    assert 'ENUMERATION PLANNING' not in render(result)
    assert 'ENUMERATION PLANNING' in render(result, True)
    assert "'candidates':" not in render(result, True)
    assert json.loads(json.dumps(result.to_dict()))['planning_trace']['steps']
    assert original.planning_trace is None


def test_catalog_is_json_safe_and_never_exposes_handler():
    catalog = identity_registry().catalog()
    assert all('handler' not in a for a in catalog)
    assert json.loads(json.dumps(catalog))[0]['safety'] == 'SAFE_ACTIVE'


def test_global_deadline_stops_loop_after_slow_action():
    clock = Clock()
    remaining = Budget(BudgetLimits(total_seconds=1), clock=clock)
    def slow(context):
        clock.now = 2
        return IdentityProbeResult('INCONCLUSIVE', 'Time budget consumed')
    trace = run_planning(assessment(), HostEvidence(), ActionRegistry([local('a', handler=slow), local('b')]), budget=remaining)
    assert len([s for s in trace['steps'] if s['selected']]) == 1
    assert 'Budget exhausted' in trace['stopping_reason']


def test_unavailable_capability_and_policy_stop_are_explicit():
    trace = run_planning(assessment(), HostEvidence(), ActionRegistry([local(handler=None)]), budget=budget())
    assert 'unavailable' in trace['steps'][0]['candidates'][0]['rejection']
    trace = run_planning(assessment(), HostEvidence(), ActionRegistry([local(safety=SafetyClass.INTRUSIVE)]), budget=budget())
    assert trace['stopping_reason'] == 'Policy prohibits remaining actions.'


def test_network_result_cannot_forge_endpoint_or_authority():
    def action_for(item):
        return replace(local(), safety=SafetyClass.SAFE_ACTIVE, network_requests=1, fallback_ports=(3389,),
                       handler=lambda context: IdentityProbeResult('COMPLETED', 'bad provenance', (item,)))
    for item in [observation('hostname', 'HOST', 'response', 'a', 'a', '192.0.2.99:3389/tcp'),
                 observation('hostname', 'HOST', 'response', 'a', 'a', HOST + ':3389/tcp', authoritative=True)]:
        result = execute(ProposedAction('a', 3389, ''), knowledge(assessment(port(3389, 'open'))), ActionRegistry([action_for(item)]), Policy(), budget())
        assert result.status == 'INVALID_RESULT'
        assert result.observations == ()


def test_udp_action_can_register_applicability_without_planner_changes():
    action = replace(local(), safety=SafetyClass.SAFE_ACTIVE, network_requests=1, observed_transport='udp', transport='udp', fallback_ports=(53,))
    target = assessment(replace(port(53, 'open'), protocol='udp'))
    proposal = DeterministicPlanner().propose(knowledge(target), ActionRegistry([action]), Policy(), budget())
    assert proposal.port == 53


def test_netbios_does_not_claim_ipv6_support():
    target = replace(assessment(port(445, 'open', service='smb')), host='2001:db8::1')
    choices = candidates(knowledge(target), identity_registry(), Policy(), budget())
    assert next(c for c in choices if c.proposal.action_id == 'netbios_identity').rejection


def test_planner_mutated_snapshot_cannot_satisfy_executor_prerequisite():
    class MutatingPlanner:
        def propose(self, state, *args):
            state.facts['hostname'] = {'state': 'CONFIRMED'}
            return ProposedAction('edition', None, 'Forged prerequisite')
    handler = Mock()
    registry = ActionRegistry([local('a'), local('edition', 'os_edition', handler=handler, prerequisites=('hostname',))])
    trace = run_planning(assessment(), HostEvidence(), registry, planner=MutatingPlanner(), budget=budget())
    handler.assert_not_called()
    assert 'Executor rejected' in trace['stopping_reason']


def test_loop_reserves_worst_case_network_allowance_and_count_before_execution():
    state = assessment(port(3389, 'open'))
    received = []
    action = replace(local(), safety=SafetyClass.SAFE_ACTIVE, fallback_ports=(3389,), network_requests=2,
                     handler=lambda ctx: received.append(ctx) or IdentityProbeResult('INCONCLUSIVE', 'No response'))
    remaining = budget(network_requests=2)
    trace = run_planning(state, HostEvidence(), ActionRegistry([action]), budget=remaining)
    assert len(received) == 1
    assert trace['remaining_budget']['network_requests_remaining'] == 0
    assert remaining.actions == 1


@pytest.mark.parametrize('discovered', [False, True])
def test_normal_cli_and_discovered_hosts_use_adaptive_planning(discovered):
    from contextlib import redirect_stdout
    from io import StringIO
    from netsentry.main import _build_parser, _run_assess
    from netsentry.discovery.models import Device
    from netsentry.scanning.models import HostScanResult
    target = assessment(port(445, 'open', service='smb'))
    def probe(host, port, timeout):
        return IdentityProbeResult('COMPLETED', 'Node status collected',
                                   (observation('hostname', 'KRISH', 'NetBIOS node status', 'netbios_identity', 'netbios', f'{host}:{port}/udp'),))
    mock_probe = Mock(side_effect=probe)
    output = StringIO()
    flags = ['--discovered'] if discovered else [HOST]
    with patch('netsentry.main.scan_target', return_value=HostScanResult(HOST)), patch('netsentry.main.assess_scan_result', return_value=target), patch('netsentry.main.load_current_snapshot', return_value=[Device(HOST, None, None, None)]), patch('netsentry.analysis.identity_probes.probe_netbios_identity', mock_probe), redirect_stdout(output):
        assert _run_assess(_build_parser().parse_args(['assess', *flags, '--json', '--verbose'])) == 0
    payload = json.loads(output.getvalue())
    host = payload['assessments'][0] if discovered else payload
    assert host['planning_trace']['planner'] == 'DeterministicPlanner'
    assert host['host_identity']['attributes']['hostname']['value'] == 'KRISH'
    assert mock_probe.call_count == 1


def test_new_service_evidence_resolves_knowledge_goal_without_changing_scan_state():
    target = assessment(port(135, 'open', hint='msrpc'))
    evidence = HostEvidence()
    assert any(g.attribute == 'confirmed_service' for g in knowledge(target, evidence).goals)
    evidence.add(observation('confirmed_service', 'DCE/RPC endpoint mapper', 'RPC bind', 'rpc_identity', 'rpc', HOST + ':135/tcp'))
    rebuilt = knowledge(target, evidence)
    assert rebuilt.endpoints[0]['service'] == 'DCE/RPC endpoint mapper'
    assert not any(g.attribute == 'confirmed_service' for g in rebuilt.goals)
    assert target.observations[0].service is None


def test_registered_contract_and_proposal_types_are_validated():
    with pytest.raises(ValueError):
        ActionRegistry([local(produces='hostname')])
    result = execute(ProposedAction('a', None, {'command': 'anything'}), knowledge(), ActionRegistry([local()]), Policy(), budget())
    assert result.status == 'REJECTED'


def test_known_high_finding_is_unchanged_by_adaptive_planning():
    from netsentry.analysis.models import Finding, Severity, Confidence
    finding = Finding('TEST-HIGH', 'Existing finding', 'Description', Severity.HIGH, Confidence.HIGH,
                      HOST, 'Observed configuration', 'Remediate', 'TEST-HIGH', port=445)
    original = replace(windows_fixture(), findings=(finding,))
    result = enrich_identity(original, scan(), AdaptiveIdentityResolver(registry=ActionRegistry([local()])))
    assert result.findings is original.findings
    assert result.observed_risk_score == original.observed_risk_score == 8
    assert result.risk_score == original.risk_score
    assert result.observations is original.observations


def test_rpc_can_resolve_an_unknown_open_service_but_not_os_edition():
    target = assessment(port(135, 'open', hint='msrpc'))
    selected = DeterministicPlanner().propose(knowledge(target), identity_registry(), Policy(), budget())
    assert selected.action_id == 'rpc_identity'
    assert 'service:tcp:135' in selected.reason
    assert 'os_edition' not in selected.reason


def test_budget_stop_remains_visible_in_unresolved_identity_reason():
    result = enrich_identity(assessment(port(3389, 'open')), scan(),
                             AdaptiveIdentityResolver(limits=BudgetLimits(max_actions=0)))
    assert 'budget' in result.host_identity['attributes']['hostname']['reason'].lower()
    assert 'Budget exhausted' in result.planning_trace['stopping_reason']


def test_tls_is_not_an_independent_source_for_ntlm_os_version():
    target = assessment(port(3389, 'open'))
    evidence = HostEvidence()
    evidence.add(observation('os_version', '10.0.19045', 'NTLM version', 'rdp_identity', 'rdp_ntlm', HOST + ':3389/tcp'))
    option = next(c for c in candidates(knowledge(target, evidence), identity_registry(), Policy(), budget()) if c.proposal.action_id == 'rdp_identity')
    assert 'os_version' not in option.goals
    assert identity_registry().get('rdp_identity').sources_for('hostname') == ('rdp_ntlm', 'tls_certificate')
