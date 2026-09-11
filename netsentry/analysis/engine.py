from collections.abc import Iterable, Sequence

from ..scanning.models import HostScanResult
from .checks import ServiceCheck, default_service_checks, dispatch_service_check
from .models import (
    AssessmentStatus,
    AttackSurfaceObservation,
    CheckStatus,
    Finding,
    HostAssessment,
    SecurityCheckResult,
)
from .rules import SecurityRule


class SecurityAnalyzer:
    """Evaluate a scan result with an ordered, extensible set of rules."""

    def __init__(
        self,
        rules: Sequence[SecurityRule] | None = None,
        checks: Sequence[ServiceCheck] | None = None,
    ) -> None:
        self.rules = tuple(rules or ())
        self.checks = tuple(checks) if checks is not None else default_service_checks()

    def assess(self, result: HostScanResult) -> HostAssessment:
        observations = tuple(
            AttackSurfaceObservation(
                host=result.target,
                port=service.port,
                protocol=service.protocol,
                service=service.service,
                product=service.product,
                version=service.version,
                evidence=(
                    f"{service.port}/{service.protocol} reported {service.state} by Nmap"
                    f"; service identified as {service.service}."
                    if service.service
                    else f"{service.port}/{service.protocol} reported {service.state} by Nmap; service was not identified."
                ),
            )
            for service in result.services
        )
        checks: list[SecurityCheckResult] = []
        findings: list[Finding] = []
        for service in result.services:
            check = dispatch_service_check(self.checks, result, service)
            try:
                check_result = check.run(result, service)
            except Exception as exc:
                check_result = SecurityCheckResult(
                    check_id=check.check_id,
                    title=check.title,
                    status=CheckStatus.FAILED,
                    port=service.port,
                    protocol=service.protocol,
                    service=service.service,
                    reason=f"Safe check failed: {exc}",
                )
            checks.append(check_result)
            findings.extend(check_result.findings)
        for rule in self.rules:
            findings.extend(rule.evaluate(result))
        findings.sort(key=lambda finding: (-finding.score, finding.rule_id, finding.port or 0))
        if result.reachability is False:
            status = AssessmentStatus.UNREACHABLE
            reason = "The target was not reachable during enumeration."
        elif any(check.status in {CheckStatus.UNAVAILABLE, CheckStatus.FAILED} for check in checks):
            status = AssessmentStatus.LIMITED
            reason = "One or more service-specific security checks were unavailable or failed."
        elif not result.services and result.scan_profile != "full":
            status = AssessmentStatus.LIMITED
            profile = result.scan_profile or "selected"
            reason = f"No open TCP ports were detected within the ports covered by the {profile} scan profile."
        else:
            status = AssessmentStatus.COMPLETE
            reason = "All applicable security checks completed for the observed scan evidence."
        return HostAssessment(
            host=result.target,
            observations=observations,
            checks=tuple(checks),
            findings=tuple(findings),
            status=status,
            status_reason=reason,
            scan_profile=result.scan_profile,
            requested_ports=result.requested_ports,
            reachability=result.reachability,
            probe_status=result.probe_status,
        )


def assess_scan_result(
    result: HostScanResult,
    rules: Sequence[SecurityRule] | None = None,
    checks: Sequence[ServiceCheck] | None = None,
) -> HostAssessment:
    """Analyze one scan result using the default or supplied rules."""
    return SecurityAnalyzer(rules, checks).assess(result)


def assess_scan_results(
    results: Iterable[HostScanResult],
    rules: Sequence[SecurityRule] | None = None,
    checks: Sequence[ServiceCheck] | None = None,
) -> tuple[HostAssessment, ...]:
    """Analyze each host exactly once and return deterministic host assessments."""
    analyzer = SecurityAnalyzer(rules, checks)
    return tuple(analyzer.assess(result) for result in results)
