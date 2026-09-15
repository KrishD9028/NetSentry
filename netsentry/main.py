import argparse
import ipaddress
import json
import logging
import time
from collections import Counter

from .analysis.bundled_cves import DatasetError, load_bundled_provider
from .analysis.identity_resolution import IdentityResolver, enrich_identity
from .analysis import Severity, assess_scan_result
from .analysis.risk import finding_order, host_order
from .analysis.remediation import priority_actions
from .terminal_details import (
    text as interpreted_text, detail, check_details, port_evidence_summary, finding_details, coverage_details,
    correlation_details, correlation_range,
)
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


def _check_summary(check, *, verbose=False) -> str:
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
    return _compact_text(", ".join(interpreted_text(value) if verbose else str(value) for value in values if value is not None) or check.reason or "Check completed.")


def _print_compact_findings(assessment, *, verbose=False) -> None:
    print("FINDINGS")
    if not assessment.findings:
        print("No security findings.")
    for finding in sorted(assessment.findings, key=finding_order):
        endpoint = f"{finding.host}:{finding.port}/{finding.protocol or 'tcp'}" if finding.port is not None else finding.host
        service = f" ({_compact_text(finding.service, 60)})" if finding.service else ""
        print(f"[{finding.severity.value}] {_compact_text(finding.title)}")
        print(f"  {endpoint}{service} — {_compact_text(finding.evidence)}")
        print(f"  Confidence: {finding.confidence.value}; remediation priority: {finding.to_dict()['remediation_priority']}")
        if verbose:
            finding_details(finding)
    print()


def _print_assessment(assessment, *, verbose=False, dataset_metadata=None) -> None:
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
        print("PRIORITY ACTIONS")
        _print_priority_actions(assessment.priority_actions)
        print()
        _print_compact_findings(assessment, verbose=verbose)

    if verbose and assessment.host_identity:
        from .terminal_details import host_identity_details
        host_identity_details(assessment.host_identity)
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
    if verbose:
        port_evidence_summary(observations)
    print("\nSECURITY CHECKS")
    for check in sorted(assessment.checks, key=lambda item: (item.port or 0, item.check_id)):
        name = _compact_text(check.service or check.title.split()[0], 20).upper()
        endpoint = f"{check.port}/{check.protocol or 'tcp'}" if check.port is not None else "-"
        print(f"{name:<8} {endpoint:<11} {check.status.value:<12} {_check_summary(check, verbose=verbose)}")
        if verbose:
            check_details(check)
    if not assessment.checks:
        print("No security checks completed; no applicable checks were available.")
    print()
    if not assessment.findings:
        _print_compact_findings(assessment, verbose=verbose)
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
            print(f"  Affected range: {correlation_range(item) if verbose else _compact_text(range_label)}")
            print(f"  Severity: {_compact_text(item.get('severity') or 'Unspecified')} (advisory)")
            print("  Status: POTENTIAL — additional validation required.")
            print(f"  Source: {_compact_text(item.get('correlation_source') or 'Unspecified')}")
            if item.get("reference"):
                print(f"  Reference: {_compact_text(item['reference'], 300)}")
            if item.get("limitations"):
                print(f"  Limitations: {_compact_text(item['limitations'], 600)}")
            if verbose:
                detail("Match reasoning", item.get("match_reason"))
                detail("Evidence confidence", item.get("confidence"))
                detail("Validation", "Verify installed version, vendor/variant, downstream fixes and advisory conditions before deciding whether remediation applies.")
        print()
    if verbose and dataset_metadata is not None:
        print("CVE CORRELATION")
        detail("Dataset", f"bundled revision {dataset_metadata['revision']}")
        detail("Definitions", dataset_metadata["definition_count"])
        detail("Applicable matches", len(assessment.potential_correlations))
        detail("Coverage", "Limited curated dataset; absence of a match does not establish absence of vulnerabilities.")
    if verbose and (assessment.software_evidence or assessment.correlation_diagnostics):
        if not assessment.potential_correlations:
            print("POTENTIAL CVE CORRELATIONS (not confirmed findings)")
            print("No potential matches reported; this does not establish absence of vulnerabilities.")
        correlation_details(assessment)
        print()
    coverage = assessment.coverage
    print("COVERAGE")
    print(f"{coverage.open_ports} open ports | {coverage.confirmed_services} confirmed services | "
          f"{coverage.checks_completed}/{coverage.checks_attempted} checks completed")
    counts = Counter(check.status.value for check in assessment.checks)
    incomplete = [f"{counts[status]} {status.lower()}" for status in ("UNAVAILABLE", "FAILED", "INCONCLUSIVE") if counts[status]]
    if incomplete:
        print("Checks: " + " | ".join(incomplete))
    if verbose:
        coverage_details(assessment)

def _print_network_assessment_summary(assessments: list) -> None:
    counts = Counter(finding.severity for assessment in assessments for finding in assessment.findings)
    print("NETWORK ASSESSMENT SUMMARY")
    print()
    print(f"Hosts assessed: {len(assessments)}")
    print(f"Hosts with findings: {sum(bool(item.findings) for item in assessments)}")
    print(f"Incomplete assessments: {sum(item.status.value != 'COMPLETE' for item in assessments)}")
    print(f"Hosts with unknown observed risk: {sum(item.observed_risk_score is None for item in assessments)}")
    print(f"Total findings: {sum(counts.values())}")
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        print(f"{severity.value}: {counts.get(severity, 0)}")
    print()
    print("Highest observed-risk hosts (assessed evidence only):")
    ranked_assessments = sorted(
        assessments,
        key=host_order,
    )
    for index, assessment in enumerate(ranked_assessments[:5], start=1):
        host_display = f"{ip_visibility(assessment.host)}: {assessment.host}"
        score = f"{assessment.risk_score}/10" if assessment.risk_score is not None else "UNKNOWN"
        observed_score = f"{assessment.observed_risk_score}/10" if assessment.observed_risk_score is not None else "UNKNOWN"
        overall = "UNKNOWN" if assessment.risk_score is None else f"{assessment.risk_level.value} {score}"
        observed = "UNKNOWN" if assessment.observed_risk_score is None else f"{assessment.observed_risk_level.value} {observed_score}"
        print(f"{index}. {host_display}  Observed: {observed}; "
              f"Assessment: {assessment.status.value}; Overall: {overall}")

    print("\nNETWORK PRIORITY ACTIONS")
    actions = priority_actions(tuple(finding for assessment in assessments for finding in assessment.findings))
    if actions:
        _print_priority_actions(actions, include_host=True)
    else:
        print("No finding-based actions; incomplete assessments may require further evidence.")


def _print_priority_actions(actions, *, include_host=False):
    for index, action in enumerate(actions[:5], 1):
        endpoint = action["endpoint"]
        address = f"{endpoint['port']}/{endpoint['protocol'] or 'tcp'}" if endpoint["port"] is not None else "host"
        if include_host:
            address = f"{endpoint['host']}:{address}"
        print(f"{index}. [Priority: {action['priority']}] {_compact_text(action['action'], 100)} — {address}")
    if len(actions) > 5:
        print(f"{len(actions) - 5} more actions in verbose/JSON output.")


def _network_assessment_payload(assessments: list) -> dict:
    counts = Counter(finding.severity.value for assessment in assessments for finding in assessment.findings)
    ranked_assessments = sorted(
        assessments,
        key=host_order,
    )
    return {
        "assessments": [assessment.to_dict() for assessment in assessments],
        "network_summary": {
            "hosts_assessed": len(assessments),
            "hosts_with_findings": sum(bool(item.findings) for item in assessments),
            "incomplete_assessments": sum(item.status.value != "COMPLETE" for item in assessments),
            "unknown_observed_risk_hosts": sum(item.observed_risk_score is None for item in assessments),
            "priority_actions": priority_actions(tuple(finding for item in assessments for finding in item.findings)),
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
            assessment = assess_scan_result(result, vulnerability_provider=vulnerability_provider)
            device = next((item for item in devices if item.ip == target), None) if args.discovered else None
            assessments.append(enrich_identity(assessment, result, IdentityResolver(), device, vulnerability_provider))
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

    for assessment in assessments:
        _print_assessment(assessment, verbose=args.verbose, dataset_metadata=dataset_metadata)
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
