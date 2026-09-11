from collections.abc import Iterable, Sequence

from ..scanning.models import HostScanResult
from .checks import ServiceCheck, default_service_checks, dispatch_service_check
from .correlation import VulnerabilityProvider
from .fingerprinting import identify_service
from .models import (
    AssessmentStatus,
    AttackSurfaceObservation,
    CheckStatus,
    Confidence,
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
        vulnerability_provider: VulnerabilityProvider | None = None,
    ) -> None:
        self.rules = tuple(rules or ())
        self.checks = tuple(checks) if checks is not None else default_service_checks()
        self.vulnerability_provider = vulnerability_provider

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
                identification_confidence=(identify_service(service).confidence if identify_service(service) else Confidence.LOW),
                identification_source=(identify_service(service).source if identify_service(service) else "port/service observation"),
                transport=service.protocol,
                tls=(service.port in {443, 8443} or (service.service or "").lower() in {"https", "https-alt", "ssl"}) if service.protocol == "tcp" else None,
            )
            for service in result.services
        )
        checks: list[SecurityCheckResult] = []
        findings: list[Finding] = []
        unimplemented_services = 0
        correlations: list[dict] = []
        for service in result.services:
            evidence = identify_service(service)
            if evidence is not None and self.vulnerability_provider is not None:
                correlations.extend(item.to_dict() for item in self.vulnerability_provider.correlate(evidence))
            applicable_checks = dispatch_service_check(self.checks, result, service)
            if not applicable_checks:
                unimplemented_services += 1
                continue
            for check in applicable_checks:
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
        elif any(check.status in {CheckStatus.UNAVAILABLE, CheckStatus.FAILED, CheckStatus.INCONCLUSIVE} for check in checks):
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
            unimplemented_services=unimplemented_services,
            potential_correlations=tuple(correlations),
        )


def assess_scan_result(
    result: HostScanResult,
    rules: Sequence[SecurityRule] | None = None,
    checks: Sequence[ServiceCheck] | None = None,
    vulnerability_provider: VulnerabilityProvider | None = None,
) -> HostAssessment:
    """Analyze one scan result using the default or supplied rules."""
    return SecurityAnalyzer(rules, checks, vulnerability_provider).assess(result)


def assess_scan_results(
    results: Iterable[HostScanResult],
    rules: Sequence[SecurityRule] | None = None,
    checks: Sequence[ServiceCheck] | None = None,
) -> tuple[HostAssessment, ...]:
    """Analyze each host exactly once and return deterministic host assessments."""
    analyzer = SecurityAnalyzer(rules, checks)
    return tuple(analyzer.assess(result) for result in results)
