"""Typed planning contracts. Proposals name capabilities, never executable code."""
from dataclasses import asdict, dataclass, field
from enum import Enum
import math
import time
from typing import Callable, Protocol

from ..analysis.host_evidence import IdentityProbeResult


class SafetyClass(str, Enum):
    LOCAL = 'LOCAL'
    PASSIVE = 'PASSIVE'
    SAFE_ACTIVE = 'SAFE_ACTIVE'
    AUTHENTICATED = 'AUTHENTICATED'
    INTRUSIVE = 'INTRUSIVE'
    EXPLOITATIVE = 'EXPLOITATIVE'


AUTOMATIC_CLASSES = frozenset({SafetyClass.LOCAL, SafetyClass.PASSIVE, SafetyClass.SAFE_ACTIVE})


@dataclass(frozen=True)
class Policy:
    allowed: frozenset[SafetyClass] = AUTOMATIC_CLASSES

    def rejection(self, action):
        # A configurable policy can narrow this milestone's ceiling, never raise it.
        if action.safety not in AUTOMATIC_CLASSES or action.safety not in self.allowed:
            return 'Safety class is prohibited by the automatic-execution policy.'
        if action.authentication_required:
            return 'Authentication is not enabled for automatic planning.'
        return None


@dataclass(frozen=True)
class Goal:
    goal_id: str
    attribute: str
    state: str
    importance: int
    reason: str
    endpoint: int | None = None
    product: str | None = None
    sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class BudgetLimits:
    max_actions: int = 3
    total_seconds: float = 8.0
    per_action_seconds: float = 3.0
    network_requests: int = 12
    noise: int | None = None

    def __post_init__(self):
        for value in (self.max_actions, self.network_requests):
            if type(value) is not int or value < 0:
                raise ValueError('Budget counts must be nonnegative integers')
        for value in (self.total_seconds, self.per_action_seconds):
            if not math.isfinite(value) or value < 0:
                raise ValueError('Budget times must be finite and nonnegative')
        if self.noise is not None and (type(self.noise) is not int or self.noise < 0):
            raise ValueError('Noise budget must be a nonnegative integer')


class Budget:
    def __init__(self, limits=BudgetLimits(), clock=time.monotonic):
        self.limits, self.clock = limits, clock
        self.deadline = clock() + limits.total_seconds
        self.actions = self.requests = self.noise = 0

    def snapshot(self):
        return {'actions_remaining': max(0, self.limits.max_actions - self.actions),
                'seconds_remaining': max(0.0, self.deadline - self.clock()),
                'network_requests_remaining': max(0, self.limits.network_requests - self.requests),
                'noise_remaining': None if self.limits.noise is None else max(0, self.limits.noise - self.noise)}

    def rejection(self, action):
        budget = self.snapshot()
        if not budget['actions_remaining']:
            return 'Action budget exhausted.'
        if budget['seconds_remaining'] <= 0 or self.limits.per_action_seconds <= 0:
            return 'Wall-clock or per-action time budget exhausted.'
        if action.network_requests > budget['network_requests_remaining']:
            return 'Insufficient network-request budget.'
        if budget['noise_remaining'] is not None and action.noise > budget['noise_remaining']:
            return 'Insufficient noise budget.'
        return None

    def reserve(self, action):
        self.actions += 1
        self.requests += action.network_requests
        self.noise += action.noise
        return min(action.timeout, self.limits.per_action_seconds, max(0, self.deadline - self.clock()))


@dataclass(frozen=True)
class ActionContext:
    host: str
    port: int | None
    timeout: float


@dataclass(frozen=True)
class ActionDefinition:
    action_id: str
    description: str
    category: str
    produces: tuple[str, ...]
    sources: tuple[str, ...]
    handler: Callable[[ActionContext], IdentityProbeResult] | None = field(repr=False, compare=False)
    services: tuple[str, ...] = ()
    fallback_ports: tuple[int, ...] = ()
    transport: str = 'tcp'
    observed_transport: str = 'tcp'
    ip_versions: tuple[int, ...] = (4, 6)
    target_port: int | None = None
    prerequisites: tuple[str, ...] = ()
    information_value: int = 1
    cost: int = 1
    timeout: float = 3.0
    network_requests: int = 1
    noise: int = 1
    safety: SafetyClass = SafetyClass.SAFE_ACTIVE
    authentication_required: bool = False
    repeatable: bool = False
    discriminates: tuple[str, ...] = ()
    reuse_checks: tuple[str, ...] = ()
    reuse_sources: tuple[str, ...] = ()
    source_outputs: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def sources_for(self, attribute):
        return next((sources for name, sources in self.source_outputs if name == attribute), self.sources)


@dataclass(frozen=True)
class ProposedAction:
    action_id: str
    port: int | None
    reason: str

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class Candidate:
    proposal: ProposedAction
    goals: tuple[str, ...]
    score: int
    rejection: str | None
    expected_evidence: tuple[str, ...]
    costs: dict

    def to_dict(self):
        return {**asdict(self), 'proposal': self.proposal.to_dict()}


class Planner(Protocol):
    def propose(self, knowledge, registry, policy: Policy, budget: Budget) -> ProposedAction | None: ...
