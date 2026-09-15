"""Mandatory executor boundary: recompute eligibility, then invoke trusted code."""
from dataclasses import dataclass

from ..analysis.host_evidence import HostObservation, IdentityProbeResult
from ..analysis.models import Confidence
from ..analysis.probes import ProbeError
from .models import ActionContext, ProposedAction, SafetyClass
from .planner import candidates


@dataclass(frozen=True)
class Execution:
    status: str
    reason: str
    observations: tuple[HostObservation, ...] = ()
    executed: bool = False


def execute(proposal, knowledge, registry, policy, budget):
    if type(proposal) is not ProposedAction or type(proposal.action_id) is not str or type(proposal.reason) is not str or len(proposal.reason) > 2000 or (proposal.port is not None and type(proposal.port) is not int):
        return Execution('REJECTED', 'Invalid proposed-action schema.')
    action = registry.get(proposal.action_id)
    if action is None:
        return Execution('REJECTED', 'Unregistered action ID.')
    # Never trust the planner's explanation, score, parameters or safety decision.
    candidate = next((c for c in candidates(knowledge, registry, policy, budget)
                      if c.proposal.action_id == proposal.action_id and c.proposal.port == proposal.port), None)
    if candidate is None or candidate.rejection:
        return Execution('REJECTED', candidate.rejection if candidate else 'Endpoint is not applicable.')
    rejection = budget.rejection(action)
    if rejection:
        return Execution('REJECTED', rejection)
    timeout = budget.reserve(action)
    if timeout <= 0:
        return Execution('REJECTED', 'Deadline expired before execution.')
    try:
        result = action.handler(ActionContext(knowledge.host, proposal.port, timeout))
    except (OSError, ProbeError) as exc:
        return Execution('FAILED', str(exc), executed=True)
    if not isinstance(result, IdentityProbeResult) or result.status not in {'COMPLETED', 'FAILED', 'INCONCLUSIVE', 'UNSUPPORTED', 'UNAVAILABLE'} or not isinstance(result.reason, str):
        return Execution('INVALID_RESULT', 'Handler returned an invalid structured result.', executed=True)
    if not isinstance(result.observations, tuple) or len(result.observations) > 128:
        return Execution('INVALID_RESULT', 'Evidence count or container is invalid.', executed=True)
    expected_endpoint = f'{knowledge.host}:{proposal.port}/{action.transport}' if proposal.port is not None else None
    for item in result.observations:
        if (not isinstance(item, HostObservation) or item.attribute not in action.produces or
                item.independence_key not in action.sources_for(item.attribute) or not isinstance(item.value, str) or
                not item.value.strip() or len(item.value) > 2048 or not isinstance(item.confidence, Confidence) or
                item.probe != action.action_id or item.endpoint != expected_endpoint or
                (action.safety == SafetyClass.SAFE_ACTIVE and item.authoritative)):
            return Execution('INVALID_RESULT', 'Evidence violates the registered output/source contract.', executed=True)
    return Execution(result.status, result.reason, result.observations, True)
