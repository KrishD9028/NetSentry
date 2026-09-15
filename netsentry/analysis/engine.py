from collections.abc import Iterable, Sequence
from dataclasses import asdict, replace

from ..scanning.models import HostScanResult
from .checks import ServiceCheck, default_service_checks, dispatch_service_check, identify_for_checks
from .correlation import VulnerabilityProvider, bind_correlation
from .fingerprinting import identify_service, collect_software_evidence
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
from .risk import finding_order


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
        observations = []
        prepared_services = []
        checks: list[SecurityCheckResult] = []
        findings: list[Finding] = []
        unimplemented_services = 0
        correlations: list[dict] = []
        software_observations = []
        correlation_diagnostics = []
        for original_service in result.services:
            service, collected = identify_for_checks(self.checks, result, original_service)
            prepared_services.append(service)
            evidence = identify_service(service)
            observations.append(AttackSurfaceObservation(
                host=result.target, port=service.port, protocol=service.protocol,
                state=service.state, state_reason=service.state_reason,
                scan_observed=service.scan_observed, scanner_state=service.scanner_state,
                scanner_reason=service.scanner_reason, scanner_source=service.scanner_source,
                service=service.confirmed_service, service_hint=service.service_hint,
                scanner_service={"name": service.service, "product": service.product,
                                 "version": service.version, "extra": service.extra,
                                 "method": service.service_method, "confidence": service.service_confidence,
                                 "tunnel": service.service_tunnel},
                product=evidence.product if evidence else None,
                version=evidence.version if evidence else None,
                evidence=service.state_reason or f"{service.port}/{service.protocol} reported {service.state}.",
                identification_status=service.identification_status,
                identification_confidence=Confidence.HIGH if service.confirmed_protocols else Confidence.LOW,
                identification_source=", ".join(dict.fromkeys(item.source for item in service.identities)) or None,
                identities=tuple(asdict(item) for item in service.identities),
                identification_attempts=service.identification_attempts,
                transport=service.protocol, tls=True if "tls" in service.confirmed_protocols else None,
            ))
            applicable_checks = dispatch_service_check(self.checks, result, service)
            if not applicable_checks and service.state == "open" and service.confirmed_protocols:
                unimplemented_services += 1
            endpoint_checks = []
            for check in applicable_checks:
                try:
                    if check in collected:
                        check_result = check.run(result, service, data=collected[check])
                    else:
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
                endpoint_checks.append(check_result)
                findings.extend(check_result.findings)
            endpoint_software = collect_software_evidence(service, endpoint_checks, host=result.target)
            software_observations.extend({**asdict(item), "confidence": item.confidence.value} for item in endpoint_software)
            for item in endpoint_software:
                competing = {other.version for other in endpoint_software if other.product.casefold() == item.product.casefold() and other.version is not None}
                context = {"host": result.target, "port": service.port, "product": item.product, "version": item.version, "source": item.source}
                if len(competing) > 1:
                    correlation_diagnostics.append({**context, "status": "INDETERMINATE", "reason": "Conflicting observed versions; automatic correlation withheld."})
                    continue
                if self.vulnerability_provider is not None:
                    if hasattr(self.vulnerability_provider, "evaluate"):
                        matches, diagnostics = self.vulnerability_provider.evaluate(item)
                        correlation_diagnostics.extend({**context, **diagnostic} for diagnostic in diagnostics)
                    else:
                        matches = self.vulnerability_provider.correlate(item)
                    for match in matches:
                        bound = bind_correlation(match, item)
                        if bound is not None:
                            correlations.append(bound.to_dict())
                        else:
                            correlation_diagnostics.append({**context, "status": "INDETERMINATE", "reason": "Provider result lacks valid structured applicability."})
        # Legacy injected rules receive only reachable, identified services.
        rule_result = replace(result, services=[item for item in prepared_services if item.confirmed_protocols])
        for rule in self.rules:
            findings.extend(rule.evaluate(rule_result))
        findings.sort(key=finding_order)
        if result.reachability is False:
            status = AssessmentStatus.UNREACHABLE
            reason = "The target was not reachable during enumeration."
        elif any(check.status in {CheckStatus.UNAVAILABLE, CheckStatus.FAILED, CheckStatus.INCONCLUSIVE} for check in checks):
            status = AssessmentStatus.LIMITED
            reason = "One or more service-specific security checks were unavailable or failed."
        elif result.probe_status != "completed" or any(item.state in {"unknown", "filtered"} for item in prepared_services):
            status = AssessmentStatus.LIMITED
            reason = "Port-state evidence is incomplete or traffic filtering prevents assessment."
        elif any(
            item.confirmed_protocols == ("tls",)
            and any(attempt["protocol"] == "http" and attempt["status"] == "INCONCLUSIVE" for attempt in item.identification_attempts)
            for item in prepared_services
        ):
            status = AssessmentStatus.LIMITED
            reason = "TLS was demonstrated, but HTTP identification was inconclusive."
        elif any(item.state == "open" and not item.confirmed_protocols for item in prepared_services):
            status = AssessmentStatus.LIMITED
            reason = "One or more open ports lack confirmed service identity."
        elif not result.open_ports and not (
            result.scan_profile == "full"
            and set(result.requested_ports) == set(range(1, 65536))
            and {item.port for item in prepared_services if item.protocol == "tcp" and item.state == "closed"} == set(result.requested_ports)
        ):
            status = AssessmentStatus.LIMITED
            profile = result.scan_profile or "selected"
            reason = f"No open TCP ports were detected within the ports covered by the {profile} scan profile."
        else:
            status = AssessmentStatus.COMPLETE
            reason = "All applicable security checks completed for the observed scan evidence."
        return HostAssessment(
            host=result.target,
            observations=tuple(observations),
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
            raw_xml=result.raw_xml,
            port_summary=result.port_summary,
            software_evidence=tuple(software_observations),
            correlation_diagnostics=tuple(correlation_diagnostics),
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
