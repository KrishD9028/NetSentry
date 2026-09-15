"""Bounded feedback loop; evidence stays in the existing HostEvidence store."""
from dataclasses import asdict

from .executor import execute
from .knowledge import KnowledgeState
from .models import Budget, BudgetLimits, Policy, ProposedAction
from .planner import DeterministicPlanner, candidates
from .registry import identity_registry


def run_planning(assessment, evidence, registry, *, planner=None, policy=None, budget=None):
    planner = planner if planner is not None else DeterministicPlanner()
    policy = policy if policy is not None else Policy()
    budget = budget if budget is not None else Budget()
    trace = {'planner': type(planner).__name__, 'steps': [], 'stopping_reason': None}
    # Explicit iteration ceiling also bounds faulty/adversarial replacement planners.
    for _ in range(budget.limits.max_actions + 1):
        knowledge = KnowledgeState.derive(assessment, evidence, budget)
        options = candidates(knowledge, registry, policy, budget)
        step = {'goals': [asdict(g) for g in knowledge.goals],
                'candidates': [c.to_dict() for c in options], 'budget_before': budget.snapshot(),
                'selected': None, 'policy_decision': None, 'result': None, 'changes': []}
        trace['steps'].append(step)
        if not any(c.rejection is None for c in options):
            if not knowledge.goals:
                reason = 'Goals sufficiently resolved.'
            elif any(c.rejection and 'budget' in c.rejection.lower() for c in options):
                reason = 'Budget exhausted for remaining useful actions.'
            elif options and all(c.rejection and ('policy' in c.rejection or 'Authentication' in c.rejection) for c in options):
                reason = 'Policy prohibits remaining actions.'
            else:
                reason = 'No useful permitted action remains (unavailable, inapplicable, redundant, or already attempted).'
            trace['stopping_reason'] = reason
            break
        proposal = planner.propose(knowledge, registry, policy, budget)
        if proposal is None:
            trace['stopping_reason'] = 'Planner declined remaining actions.'
            break
        if type(proposal) is ProposedAction:
            # Only schema-approved scalar fields enter the machine-readable trace.
            step['selected'] = {'action_id': proposal.action_id if isinstance(proposal.action_id, str) else None,
                                'port': proposal.port if type(proposal.port) is int else None,
                                'reason': proposal.reason[:2000] if isinstance(proposal.reason, str) else 'Invalid explanation'}
        # Rebuild from canonical evidence after proposal generation; the executor
        # does not trust a planner-mutated/stale knowledge snapshot.
        execution = execute(proposal, KnowledgeState.derive(assessment, evidence, budget), registry, policy, budget)
        step['policy_decision'] = 'ALLOWED' if execution.executed else 'REJECTED'
        step['result'] = {'status': execution.status, 'reason': execution.reason, 'evidence_count': len(execution.observations)}
        if not execution.executed:
            trace['stopping_reason'] = 'Executor rejected proposal: ' + execution.reason
            break
        previous = evidence.to_dict()['attributes']
        count = len(evidence.observations)
        for observation in execution.observations:
            evidence.add(observation)
        action = registry.get(proposal.action_id)
        evidence.attempts.append({'probe': action.action_id, 'port': proposal.port,
                                  'endpoint': f'{assessment.host}:{proposal.port}/{action.transport}' if proposal.port is not None else None,
                                  'status': execution.status, 'reason': execution.reason,
                                  'attributes': list(action.produces), 'reused': False})
        after = evidence.to_dict()['attributes']
        step['changes'] = [{'attribute': name, 'before': previous[name]['state'], 'after': result['state']}
                           for name, result in after.items() if any(result[key] != previous[name][key] for key in ('state', 'value', 'independent_confirmations'))]
        rebuilt = KnowledgeState.derive(assessment, evidence, budget)
        step['goals_resolved'] = sorted({g.goal_id for g in knowledge.goals} - {g.goal_id for g in rebuilt.goals})
        step['observations_added'] = len(evidence.observations) - count
        step['budget_after'] = budget.snapshot()
    else:
        trace['stopping_reason'] = 'Planning iteration limit reached.'
    trace['remaining_budget'] = budget.snapshot()
    return trace


class AdaptiveIdentityResolver:
    """CLI adapter preserving the existing resolve(assessment, evidence) boundary."""
    def __init__(self, probes=None, *, registry=None, planner=None, policy=None, limits=BudgetLimits()):
        self.registry = registry if registry is not None else identity_registry(probes)
        self.planner, self.policy, self.limits = planner, policy, limits
        self.trace = None

    def resolve(self, assessment, evidence):
        remaining = Budget(self.limits)
        self.trace = run_planning(assessment, evidence, self.registry, planner=self.planner,
                                  policy=self.policy, budget=remaining)
        for goal in KnowledgeState.derive(assessment, evidence, remaining).goals:
            if goal.state != 'UNRESOLVED' or any(goal.attribute in a.get('attributes', ()) for a in evidence.attempts):
                continue
            rejected = [f"{c['proposal']['action_id']}: {c['rejection']}" for c in self.trace['steps'][-1]['candidates']
                        if goal.attribute in c['expected_evidence'] and c['rejection']]
            evidence.attempts.append({'probe': 'planner', 'kind': 'unresolved_goal', 'status': 'UNSUPPORTED',
                                      'attributes': [goal.attribute],
                                      'reason': '; '.join(rejected) if rejected else self.trace['stopping_reason']})
        return evidence
