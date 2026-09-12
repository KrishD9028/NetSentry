import argparse
import ipaddress
import json
import logging
import time
from collections import Counter

from .analysis.bundled_cves import DatasetError, load_bundled_provider
from .analysis import Severity, assess_scan_result
from .discovery import (
    DiscoveryError,
    discover_devices,
    get_local_network,
    load_current_snapshot,
    save_current_snapshot,
)
from .ip import ip_visibility
from .scanning import NmapNotInstalledError, NmapScanError, scan_target

logger = logging.getLogger(__name__)


def _yes_no_unknown(value: bool | None) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unknown"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetSentry: authorized discovery and service scanning.")
    parser.add_argument("--interface", help="Interface to scan, for example en0.")
    parser.add_argument("--network", help="Override the detected IPv4 network, for example 192.168.1.0/24.")
    parser.add_argument("--timeout", type=float, default=2.0, help="ARP response timeout in seconds.")

    subparsers = parser.add_subparsers(dest="command")

    discover_parser = subparsers.add_parser("discover", help="Discover devices on the local network.")
    discover_parser.add_argument("--interface", help="Interface to scan, for example en0.")
    discover_parser.add_argument("--network", help="Override the detected IPv4 network, for example 192.168.1.0/24.")
    discover_parser.add_argument("--timeout", type=float, default=2.0, help="ARP response timeout in seconds.")

    scan_parser = subparsers.add_parser("scan", help="Scan a host for exposed TCP services.")
    scan_parser.add_argument("target", nargs="?", help="IPv4 target to scan.")
    scan_parser.add_argument("--discovered", action="store_true", help="Scan all devices previously discovered on the local network.")
    scan_parser.add_argument("--profile", choices=["quick", "common", "custom", "full"], default="quick", help="Port scan profile to use.")
    scan_parser.add_argument("--ports", help="Comma-separated ports or ranges, for example 22,80,443 or 8000-8100.")
    scan_parser.add_argument("--timeout", type=float, default=20.0, help="Nmap scan timeout in seconds.")
    scan_parser.add_argument("--interface", help="Interface used to discover devices when --discovered is set.")
    scan_parser.add_argument("--network", help="Override the detected network for discovery when --discovered is set.")
    scan_parser.add_argument("--limit", type=int, default=None, help="Optional maximum number of discovered devices to scan when --discovered is used.")

    assess_parser = subparsers.add_parser("assess", help="Analyze a host scan for non-exploitative security findings.")
    assess_parser.add_argument("target", nargs="?", help="IPv4 target to assess.")
    assess_parser.add_argument("--discovered", action="store_true", help="Assess all devices discovered on the local network.")
    assess_parser.add_argument("--profile", choices=["quick", "common", "custom", "full"], default="common", help="Port scan profile to use.")
    assess_parser.add_argument("--ports", help="Comma-separated ports or ranges, for example 22,80,443 or 8000-8100.")
    assess_parser.add_argument("--timeout", type=float, default=20.0, help="Nmap scan timeout in seconds.")
    assess_parser.add_argument("--interface", help="Interface used to discover devices when --discovered is set.")
    assess_parser.add_argument("--network", help="Override the detected network for discovery when --discovered is set.")
    assess_parser.add_argument("--limit", type=int, default=None, help="Optional maximum number of discovered devices to assess.")
    assess_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of terminal formatting.")

    assess_parser.add_argument("-v", "--verbose", action="store_true", help="Show full assessment evidence (JSON takes precedence).")

    return parser


def _print_discovery_results(devices: list) -> None:
    for device in devices:
        print("\nDEVICE FOUND")
        print(f"{device.ip_label}: {device.ip}")
        print(f"MAC:      {device.mac or 'Unknown'}")
        print(f"Hostname: {device.hostname or 'Unknown'}")
        print(f"Vendor:   {device.vendor or 'Unknown'}")

    print(f"\n{len(devices)} device{'s' if len(devices) != 1 else ''} discovered.")


def _port_ranges(ports) -> str:
    ranges = []
    start = previous = None
    for port in sorted(set(ports)):
        if previous is not None and port != previous + 1:
            ranges.append(str(start) if start == previous else f"{start}-{previous}")
            start = None
        if start is None:
            start = port
        previous = port
    if start is not None:
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


def _print_port_table(items) -> None:
    print(f"{'PORT':<11} {'STATE':<9} SERVICE")
    grouped = {}
    for item in items:
        # Keep hints and open services visible; compact large unlabelled ranges.
        if len(items) > 64 and item.state != "open" and not item.service_hint:
            grouped.setdefault((item.protocol, item.state), []).append(item.port)
            continue
        confirmed = item.confirmed_service if hasattr(item, "confirmed_service") else item.service
        label = confirmed or "unknown"
        if not confirmed and item.service_hint:
            label += f" (hint: {item.service_hint})"
        if confirmed and item.product:
            label += f" {item.product}" + (f" {item.version}" if item.version else "")
        print(f"{str(item.port) + '/' + item.protocol:<11} {item.state:<9} {label}")
    for (protocol, state), ports in grouped.items():
        ranges = _port_ranges(ports)
        if len(ranges) > 100:
            ranges = ranges[:97] + "..."
        print(f"{len(ports)} additional {protocol} ports: {state} ({ranges})")


def _print_scan_result(result) -> None:
    print(f"{result.target_label}: {result.target}")
    if result.hostname:
        print(f"Hostname: {result.hostname}")
    print()
    if result.services:
        _print_port_table(result.services)
    if not result.open_ports:
        print(f"No open TCP ports were detected within the ports covered by the {result.scan_profile or 'selected'} scan profile.")
    if result.probe_status != "completed":
        print(f"Scan status: {result.probe_status}; port testing may be incomplete.")
    print()
    print("Scan summary:")
    print("Hosts scanned: 1")
    print(f"Open ports: {result.open_ports}")


def _print_assessment_details(assessment) -> None:
    print("NetSentry Security Assessment")
    print("==============================")
    print()
    print(f"Host: {ip_visibility(assessment.host)}: {assessment.host}")
    print(f"Assessment Status: {assessment.status.value}")
    print(f"Status Reason: {assessment.status_reason}")
    qualifier = " (limited coverage)" if assessment.status.value == "LIMITED" else ""
    print(f"Overall Risk: {assessment.risk_level.value}{qualifier}")
    score = f"{assessment.risk_score}/10" if assessment.risk_score is not None else "UNKNOWN"
    print(f"Overall Risk Score: {score}")
    print(f"Observed Risk: {assessment.observed_risk_level.value}")
    observed_score = f"{assessment.observed_risk_score}/10" if assessment.observed_risk_score is not None else "UNKNOWN"
    print(f"Observed Risk Score: {observed_score} (assessed evidence only)")
    if not assessment.findings:
        if assessment.coverage.checks_completed:
            print(f"No findings were identified by the {assessment.coverage.checks_completed} completed security checks.")
        else:
            print("No security checks completed; observed risk cannot be determined.")
    if assessment.status.value != "COMPLETE":
        print("Incomplete assessment prevents a complete target-risk determination.")
    print()
    print("Attack Surface")
    if assessment.observations:
        _print_port_table(assessment.observations)
    else:
        print("No port-state evidence was returned within scan coverage.")
    print()
    print("Security Checks")
    if not assessment.checks:
        print("No applicable service-specific checks were available.")
    for check in assessment.checks:
        print(f"{check.title}: {check.status.value}")
        if check.reason:
            print(f"  {check.reason}")
        if check.details:
            if check.title == "SSH configuration":
                print(f"  Banner: {check.details.get('banner') or 'Unavailable'}")
                print(f"  Enumeration: {check.details.get('enumeration_status', 'unavailable')}")
                for category, algorithms in check.details.get("algorithms", {}).items():
                    if algorithms:
                        print(f"  {category}: {', '.join(algorithms)}")
            elif check.title == "RDP security negotiation":
                details = check.details
                for name in ("nla_available", "nla_required", "legacy_accepted", "tls_used"):
                    print(f"  {name}: {_yes_no_unknown(details.get(name))}")
                for attempt in details.get("attempts", ()):
                    print(f"  Requested={attempt['requested_protocols']} selected={attempt.get('selected_protocol')} "
                          f"failure={attempt.get('failure_code')}: {attempt['status']} - {attempt['reason']}")
                    if attempt.get("tls_error"):
                        print(f"    TLS: {attempt['tls_error']}")
            elif check.title == "SMB configuration":
                details = check.details
                print(f"  Negotiated dialect: {details.get('dialect') or 'Unknown'}")
                print(f"  SMBv1 supported: {_yes_no_unknown(details.get('smb1_supported'))}")
                print(f"  Signing supported: {_yes_no_unknown(details.get('signing_supported'))}")
                print(f"  Signing required: {_yes_no_unknown(details.get('signing_required'))}")
                print(f"  Authentication: {details.get('authentication_status', 'Unknown')}")
                if details.get("identity"):
                    print(f"  Server identity: {details['identity']}")
            elif check.title == "TLS configuration":
                details = check.details
                print(f"  TLS version: {details.get('tls_version') or 'Unavailable'}")
                print(f"  Cipher: {details.get('cipher') or 'Unavailable'}")
                print(f"  Subject: {details.get('subject') or 'Unavailable'}")
                print(f"  Issuer: {details.get('issuer') or 'Unavailable'}")
                print(f"  Valid from: {details.get('not_before') or 'Unavailable'}")
                print(f"  Valid until: {details.get('not_after') or 'Unavailable'}")
                print(f"  Verification: {details.get('verification_result') or 'Unavailable'}")
                print(f"  Expired: {_yes_no_unknown(details.get('expired'))}")
                print(f"  Not yet valid: {_yes_no_unknown(details.get('not_yet_valid'))}")
            elif check.title == "HTTP security configuration":
                details = check.details
                print(f"  Transport: {'TLS' if details.get('tls') else 'plaintext TCP'}")
                print(f"  HTTP response: {'Valid' if details.get('status') is not None else 'Unavailable'}")
                print(f"  Status: {details.get('status') or 'Unavailable'}")
                print(f"  Server: {details.get('server') or 'Unreported'}")
                print(f"  Redirect: {details.get('redirect') or 'None'}")
                print(f"  Advertised methods: {', '.join(details.get('methods', ())) or 'Unreported'}")
                for header, value in details.get('selected_headers', {}).items():
                    print(f"  {header}: {value}")
    print()
    print("Assessment Coverage")
    coverage = assessment.coverage
    print(f"Open ports: {coverage.open_ports}")
    print(f"Confirmed services: {coverage.confirmed_services}")
    print(f"Open ports without confirmed service identity: {coverage.unconfirmed_open_ports}")
    print(f"Security checks attempted: {coverage.checks_attempted}")
    print(f"Checks completed: {coverage.checks_completed}")
    print(f"Checks unavailable/failed/inconclusive: {coverage.checks_unavailable_or_failed}")
    if assessment.unimplemented_services:
        print(f"{assessment.unimplemented_services} observed services currently have no registered assessment module.")
    print()
    indeterminate = sum(item.get("status") == "INDETERMINATE" for item in assessment.correlation_diagnostics)
    if indeterminate:
        print(f"CVE correlation: {indeterminate} indeterminate evaluations; details are preserved in JSON.")
    print(f"Findings: {len(assessment.findings)}")
    if not assessment.findings:
        print("No security findings were generated by the current NetSentry ruleset.")
    if assessment.potential_correlations:
        print()
        print("Potential Vulnerability Correlations")
        for correlation in assessment.potential_correlations:
            print(f"{correlation['cve_id']}: {correlation['product']} {correlation['evidence'].get('version') or 'unknown version'}")
            print(f"  Affected range: {correlation.get('matched_range') or correlation['affected_range']}")
            print(f"  Source: {correlation.get('correlation_source') or 'Unspecified'}")
            if correlation.get("reference"):
                print(f"  Reference: {correlation['reference']}")
            if correlation.get("limitations"):
                print(f"  Limitations: {correlation['limitations']}")
            print(f"  Confidence: {correlation['confidence']}")
            print(f"  Status: {correlation['status']} - additional validation required")
        if not assessment.findings:
            return
    elif not assessment.findings:
        return

    for finding in assessment.findings:
        print()
        print(f"[{finding.severity.value}] {finding.title}")
        print(f"Rule: {finding.rule_id}")
        if finding.port is not None:
            print(f"Port: {finding.port}/{finding.protocol or 'tcp'}")
        print(f"Confidence: {finding.confidence.value}")
        print()
        print("Evidence:")
        print(finding.evidence)
        print()
        print("Why this matters:")
        print(finding.description)
        print()
        print("Remediation:")
        print(finding.remediation)
        print("-" * 48)



def _compact_text(value, limit=160) -> str:
    # Evidence may contain line breaks or terminal control characters.
    text = " ".join("".join(char if char.isprintable() else " " for char in str(value)).split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _display_state(observation) -> str:
    raw = observation.scanner_state
    if raw in {"open", "closed", "filtered"}:
        return raw
    if raw is not None:
        return "inconclusive"
    return observation.state if observation.state in {"open", "closed"} else "inconclusive"


def _service_label(observation) -> str:
    if observation.identification_status == "CONFIRMED" and observation.service:
        return _compact_text(observation.service, 60)
    if observation.service_hint:
        return "(" + _compact_text(observation.service_hint, 60) + ")"
    return "unknown"


def _check_summary(check) -> str:
    details = check.details or {}
    if check.status.value != "COMPLETED":
        return _compact_text(check.reason or "No completed assessment evidence.")
    service = (check.service or check.title.split()[0]).lower()
    if service == "smb":
        signing_required = details.get("signing_required")
        if signing_required is True:
            signing = "signing required"
        elif signing_required is False:
            signing = "signing not required"
        else:
            signing = "signing requirement unknown"
        values = [details.get("dialect"), signing]
    elif service == "tls":
        values = [details.get("tls_version"), details.get("cipher")]
    elif service in {"http", "https"}:
        values = [details.get("status"), details.get("server")]
    elif service == "ssh":
        values = [details.get("banner"), "algorithm enumeration " + str(details.get("enumeration_status", "unavailable"))]
    elif service == "rdp":
        values = ["NLA required: " + _yes_no_unknown(details.get("nla_required")),
                  "TLS used: " + _yes_no_unknown(details.get("tls_used"))]
    else:
        values = []
    return _compact_text(", ".join(str(value) for value in values if value is not None) or check.reason or "Check completed.")


def _print_compact_findings(assessment) -> None:
    print("FINDINGS")
    if not assessment.findings:
        print("No security findings.")
    for finding in sorted(assessment.findings, key=lambda item: (-item.score, item.port or 0, item.title)):
        endpoint = f"{finding.host}:{finding.port}/{finding.protocol or 'tcp'}" if finding.port is not None else finding.host
        service = f" ({_compact_text(finding.service, 60)})" if finding.service else ""
        print(f"[{finding.severity.value}] {_compact_text(finding.title)}")
        print(f"  {endpoint}{service} — {_compact_text(finding.evidence)}")
    print()


def _print_assessment(assessment, *, verbose=False) -> None:
    if verbose:
        _print_assessment_details(assessment)
        # Render all structured fields, including evidence not covered by the
        # explanatory report above. This is a read-only view of the same payload.
        payload = assessment.to_dict()
        for title, value in (
            ("PORT EVIDENCE (state = normalized NetSentry state)", payload["attack_surface"]),
            ("FULL CHECK EVIDENCE", payload["security_checks"]),
            ("SOFTWARE OBSERVATIONS", payload["software_evidence"]),
            ("POTENTIAL CVE CORRELATIONS (not confirmed findings)", payload["potential_vulnerability_correlations"]),
            ("CORRELATION DIAGNOSTICS", payload["correlation_diagnostics"]),
            ("COVERAGE EVIDENCE", {key: payload[key] for key in (
                "coverage", "status_reason", "scan_profile", "requested_ports", "reachability",
                "probe_status", "unimplemented_services", "scan_evidence")}),
        ):
            print("\n" + title)
            print(json.dumps(value, indent=2))
        return

    print("NetSentry Security Assessment")
    print("==============================\n")
    print(f"Target: {assessment.host}")
    print(f"Status: {assessment.status.value}")
    score = assessment.observed_risk_score
    print(f"Observed Risk: {assessment.observed_risk_level.value}" + (f" ({score}/10)" if score is not None else ""))
    if assessment.status.value != "COMPLETE":
        print("Coverage incomplete; overall target risk is unknown.")
    print()
    if assessment.findings:
        _print_compact_findings(assessment)

    observations = sorted(assessment.observations, key=lambda item: (item.port, item.protocol))
    groups = {state: [] for state in ("open", "closed", "filtered", "inconclusive")}
    for item in observations:
        groups[_display_state(item)].append(item)
    print(f"{'PORT':<11} {'STATE':<10} SERVICE")
    for item in groups["open"]:
        print(f"{str(item.port) + '/' + item.protocol:<11} {'open':<10} {_service_label(item)}")
    if not groups["open"]:
        print("No open ports reported.")
    if groups["filtered"]:
        shown = groups["filtered"][:8]
        labels = [f"{item.port}/{item.protocol} {_service_label(item)}" for item in shown]
        omitted = len(groups["filtered"]) - len(shown)
        print("Filtered: " + ", ".join(labels) + (f"; {omitted} more filtered ports not shown" if omitted else ""))
    hidden = [f"{len(groups[state])} {state} ports" for state in ("closed", "inconclusive") if groups[state]]
    if hidden:
        print("Not shown: " + " | ".join(hidden))
    if any(item.service_hint and item.identification_status != "CONFIRMED" for item in groups["open"] + groups["filtered"][:8]):
        print("Parentheses indicate service hints.")
    print("\nSECURITY CHECKS")
    for check in sorted(assessment.checks, key=lambda item: (item.port or 0, item.check_id)):
        name = _compact_text(check.service or check.title.split()[0], 20).upper()
        endpoint = f"{check.port}/{check.protocol or 'tcp'}" if check.port is not None else "-"
        print(f"{name:<8} {endpoint:<11} {check.status.value:<12} {_check_summary(check)}")
    if not assessment.checks:
        print("No security checks completed; no applicable checks were available.")
    print()
    if not assessment.findings:
        _print_compact_findings(assessment)
    if assessment.potential_correlations:
        print("POTENTIAL CVE CORRELATIONS (not confirmed findings)")
        for item in assessment.potential_correlations:
            evidence = item.get("evidence", {})
            print(_compact_text(item.get("cve_id")))
            print(f"  Product: {_compact_text(item.get('product'))}")
            print(f"  Observed version: {_compact_text(evidence.get('version') or 'unknown')}")
            matched_range = item.get("matched_range") or {}
            range_label = (f"exactly {matched_range['exact']} ({matched_range['scheme']})"
                           if matched_range.get("exact") else matched_range or item.get("affected_range") or "unavailable")
            print(f"  Affected range: {_compact_text(range_label)}")
            print(f"  Severity: {_compact_text(item.get('severity') or 'Unspecified')} (advisory)")
            print("  Status: POTENTIAL — additional validation required.")
            print(f"  Source: {_compact_text(item.get('correlation_source') or 'Unspecified')}")
            if item.get("reference"):
                print(f"  Reference: {_compact_text(item['reference'], 300)}")
            if item.get("limitations"):
                print(f"  Limitations: {_compact_text(item['limitations'], 600)}")
        print()
    coverage = assessment.coverage
    print("COVERAGE")
    print(f"{coverage.open_ports} open ports | {coverage.confirmed_services} confirmed services | "
          f"{coverage.checks_completed}/{coverage.checks_attempted} checks completed")
    counts = Counter(check.status.value for check in assessment.checks)
    incomplete = [f"{counts[status]} {status.lower()}" for status in ("UNAVAILABLE", "FAILED", "INCONCLUSIVE") if counts[status]]
    if incomplete:
        print("Checks: " + " | ".join(incomplete))

def _print_network_assessment_summary(assessments: list) -> None:
    counts = Counter(finding.severity for assessment in assessments for finding in assessment.findings)
    print("NETWORK ASSESSMENT SUMMARY")
    print()
    print(f"Hosts assessed: {len(assessments)}")
    print(f"Total findings: {sum(counts.values())}")
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        print(f"{severity.value}: {counts.get(severity, 0)}")
    print()
    print("Highest observed-risk hosts (assessed evidence only):")
    ranked_assessments = sorted(
        assessments,
        key=lambda item: (item.observed_risk_score is None, -(item.observed_risk_score or 0), item.host),
    )
    for index, assessment in enumerate(ranked_assessments[:5], start=1):
        host_display = f"{ip_visibility(assessment.host)}: {assessment.host}"
        score = f"{assessment.risk_score}/10" if assessment.risk_score is not None else "UNKNOWN"
        observed_score = f"{assessment.observed_risk_score}/10" if assessment.observed_risk_score is not None else "UNKNOWN"
        overall = "UNKNOWN" if assessment.risk_score is None else f"{assessment.risk_level.value} {score}"
        print(f"{index}. {host_display}  Observed: {assessment.observed_risk_level.value} {observed_score}; "
              f"Assessment: {assessment.status.value}; Overall: {overall}")


def _network_assessment_payload(assessments: list) -> dict:
    counts = Counter(finding.severity.value for assessment in assessments for finding in assessment.findings)
    ranked_assessments = sorted(
        assessments,
        key=lambda item: (item.observed_risk_score is None, -(item.observed_risk_score or 0), item.host),
    )
    return {
        "assessments": [assessment.to_dict() for assessment in assessments],
        "network_summary": {
            "hosts_assessed": len(assessments),
            "total_findings": sum(counts.values()),
            "severity_counts": {severity.value: counts.get(severity.value, 0) for severity in Severity},
            "highest_risk_hosts": [
                {
                    "host": assessment.host,
                    "host_label": ip_visibility(assessment.host),
                    "severity": assessment.risk_severity.value,
                    "score": assessment.risk_score,
                    "observed_risk": assessment.observed_risk,
                    "assessment_status": assessment.status.value,
                    "coverage": assessment.coverage.to_dict(),
                }
                for assessment in ranked_assessments[:5]
            ],
        },
    }


def _run_discovery(args: argparse.Namespace) -> int:
    try:
        interface = args.interface or None
        target = get_local_network(interface)
        network = ipaddress.IPv4Network(args.network) if args.network else target.network
        logging.info("Starting discovery on %s via %s", network, target.interface)
        devices = discover_devices(network, target.interface, timeout=args.timeout)
        save_current_snapshot(devices)
    except (DiscoveryError, OSError, ValueError) as exc:
        print(f"Discovery failed: {exc}")
        return 1

    _print_discovery_results(devices)
    return 0


def _run_scan(args: argparse.Namespace) -> int:
    if args.discovered:
        try:
            devices = load_current_snapshot()
            targets = [device.ip for device in devices]
        except (DiscoveryError, FileNotFoundError, ValueError) as exc:
            print(f"Discovery failed: {exc}")
            return 1

        if args.limit is not None:
            if args.limit <= 0:
                print("The discovered-device limit must be greater than zero.")
                return 2
            targets = targets[: args.limit]
            print(f"Scanning first {len(targets)} of {len(devices)} discovered devices.")

        if not targets:
            print("No devices were discovered on the local network.")
            return 0
    elif args.target:
        targets = [args.target]
    else:
        print("A target IP address is required for service scanning.")
        return 2

    print("Authorization notice: only scan systems you own or are explicitly authorized to assess.")
    start = time.monotonic()
    open_port_count = 0
    host_count = 0
    for target in targets:
        try:
            logger.info("Scanning %s %s using profile %s", ip_visibility(target), target, args.profile)
            result = scan_target(target, profile=args.profile, port_spec=args.ports, timeout=args.timeout)
            host_count += 1
            open_port_count += result.open_ports
            _print_scan_result(result)
        except (NmapNotInstalledError, NmapScanError, ValueError) as exc:
            try:
                target_display = f"{ip_visibility(target)}: {target}"
            except ValueError:
                target_display = target
            print(f"Scan failed for {target_display}: {exc}")
            continue

    print("Scan summary:")
    print(f"Hosts scanned: {host_count}")
    print(f"Open ports: {open_port_count}")
    print(f"Duration: {time.monotonic() - start:.1f}s")
    return 0


def _run_assess(args: argparse.Namespace) -> int:
    if args.discovered:
        try:
            devices = load_current_snapshot()
            targets = [device.ip for device in devices]
        except (DiscoveryError, FileNotFoundError, ValueError) as exc:
            if args.json:
                print(json.dumps({"error": str(exc)}))
            else:
                print(f"Discovery failed: {exc}")
            return 1

        if args.limit is not None:
            if args.limit <= 0:
                message = "The discovered-device limit must be greater than zero."
                if args.json:
                    print(json.dumps({"error": message}))
                else:
                    print(message)
                return 2
            targets = targets[: args.limit]
            if not args.json:
                print(f"Assessing first {len(targets)} of {len(devices)} discovered devices.")

        if not targets:
            payload = {"assessments": [], "network_summary": {"hosts_assessed": 0, "total_findings": 0}}
            print(json.dumps(payload) if args.json else "No devices were discovered on the local network.")
            return 0
    elif args.target:
        targets = [args.target]
    else:
        message = "A target IP address is required for security assessment."
        if args.json:
            print(json.dumps({"error": message}))
        else:
            print(message)
        return 2

    try:
        vulnerability_provider, dataset_metadata = load_bundled_provider()
    except DatasetError as exc:
        message = f"CVE dataset load failed: {exc}"
        print(json.dumps({"error": message}) if args.json else message)
        return 1

    assessments = []
    errors = []
    for target in targets:
        try:
            if not args.json:
                logger.info("Assessing %s %s using profile %s", ip_visibility(target), target, args.profile)
            result = scan_target(target, profile=args.profile, port_spec=args.ports, timeout=args.timeout)
            assessments.append(assess_scan_result(result, vulnerability_provider=vulnerability_provider))
        except (NmapNotInstalledError, NmapScanError, ValueError) as exc:
            errors.append({"target": target, "error": str(exc)})
            if not args.json:
                try:
                    target_display = f"{ip_visibility(target)}: {target}"
                except ValueError:
                    target_display = target
                print(f"Assessment failed for {target_display}: {exc}")

    if args.json:
        if args.discovered:
            payload = _network_assessment_payload(assessments)
            if errors:
                payload["errors"] = errors
        elif assessments:
            payload = assessments[0].to_dict()
            if errors:
                payload["errors"] = errors
        else:
            payload = {"host": targets[0], "error": errors[0]["error"] if errors else "Assessment failed."}
        print(json.dumps(payload, indent=2))
        return 1 if errors and not assessments else 0

    if args.verbose:
        print("BUNDLED CVE DATASET")
        print(json.dumps(dataset_metadata, indent=2))
    for assessment in assessments:
        _print_assessment(assessment, verbose=args.verbose)
        print()
    if args.discovered:
        _print_network_assessment_summary(assessments)
    return 1 if errors and not assessments else 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = _build_parser().parse_args()

    if args.command == "scan":
        return _run_scan(args)
    if args.command == "assess":
        return _run_assess(args)
    return _run_discovery(args)


if __name__ == "__main__":
    raise SystemExit(main())
