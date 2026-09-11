from abc import ABC, abstractmethod
from collections.abc import Iterable

from ...scanning.models import HostScanResult
from ..models import Finding


class SecurityRule(ABC):
    """A single independently testable rule over one host scan result."""

    rule_id: str

    @abstractmethod
    def evaluate(self, result: HostScanResult) -> Iterable[Finding]:
        """Return findings supported by the observed scan data."""
