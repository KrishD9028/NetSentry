"""Explainable integer heuristics, not probabilities or risk scores."""
from ipaddress import ip_address

from .models import Candidate, ProposedAction, SafetyClass


def applicable_ports(action, knowledge):
    if action.safety in {SafetyClass.LOCAL, SafetyClass.PASSIVE}:
        return (None,)
    if ip_address(knowledge.host).version not in action.ip_versions:
        return ()
    ports = set()
    for item in knowledge.endpoints:
        # Identity follow-ups originate in observed open TCP services; NetBIOS
        # explicitly redirects to UDP/137 without changing the original port state.
        if item['state'] != 'open' or item['transport'] != action.observed_transport:
            continue
        service = item['service'] or item['hint']
        if service in action.services or (not service and item['port'] in action.fallback_ports):
            ports.add(action.target_port if action.target_port is not None else item['port'])
    return tuple(sorted(ports))


def previous_attempt(action, port, knowledge):
    endpoint = f'{knowledge.host}:{port}/{action.transport}'
    return any(a.get('probe') == action.action_id and
               (a.get('port') == port or a.get('endpoint') == endpoint)
               for a in knowledge.attempts)


def candidates(knowledge, registry, policy, budget):
    results = []
    for action in registry:
        ports = applicable_ports(action, knowledge)
        for port in ports or (None,):
            rejection = policy.rejection(action)
            if rejection is None and not ports:
                rejection = 'No applicable observed open endpoint/service.'
            if rejection is None and action.handler is None:
                rejection = 'Action implementation is unavailable.'
            if rejection is None and any(name not in knowledge.facts for name in action.prerequisites):
                rejection = 'Confirmed prerequisite facts are missing.'
            # Even a repeatable registration cannot opt out of this milestone's
            # one-attempt-per-action/endpoint ceiling.
            if rejection is None and previous_attempt(action, port, knowledge):
                rejection = 'Action/endpoint already attempted; repeat suppressed.'
            relevant = [g for g in knowledge.goals if g.attribute in action.produces and
                        (g.endpoint is None or g.endpoint == port)]
            useful = [g for g in relevant if not g.sources or set(action.sources_for(g.attribute)) - set(g.sources)]
            if rejection is None and not useful:
                rejection = 'No unresolved goal can gain new independent evidence; action is redundant.'
            if rejection is None:
                rejection = budget.rejection(action)
            gain = sum(g.importance * (2 if g.state == 'CONTRADICTORY' else 1) for g in useful)
            penalty = action.cost + action.network_requests + action.noise + int(action.timeout)
            score = gain * action.information_value - penalty
            reason = (f"Goals: {', '.join(g.goal_id for g in useful) or 'none'}; "
                      f"independent evidence sources: {', '.join(action.sources)}; "
                      f"information value {gain} × {action.information_value}, cost penalty {penalty}; "
                      f"{action.safety.value}; " + (rejection or 'applicable, prerequisites satisfied, budget permits execution.'))
            if score <= 0 and rejection is None:
                rejection = 'Expected information value does not outweigh declared cost.'
                reason += ' ' + rejection
            results.append(Candidate(ProposedAction(action.action_id, port, reason), tuple(g.goal_id for g in useful),
                                     score, rejection, action.produces,
                                     {'cost': action.cost, 'timeout': action.timeout, 'network_requests': action.network_requests, 'noise': action.noise}))
    return tuple(sorted(results, key=lambda c: (-c.score, c.proposal.action_id, c.proposal.port or 0)))


class DeterministicPlanner:
    def propose(self, knowledge, registry, policy, budget):
        return next((item.proposal for item in candidates(knowledge, registry, policy, budget) if item.rejection is None), None)
