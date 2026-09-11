import argparse
import ipaddress
import json
import logging
import time
from collections import Counter

from .analysis import Severity, assess_scan_result
from .discovery import DiscoveryError, discover_devices, get_local_network
from .ip import ip_visibility
from .scanning import NmapNotInstalledError, NmapScanError, scan_target

logger = logging.getLogger(__name__)


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

    return parser


def _print_discovery_results(devices: list) -> None:
    for device in devices:
        print("\nDEVICE FOUND")
        print(f"{device.ip_label}: {device.ip}")
        print(f"MAC:      {device.mac or 'Unknown'}")
        print(f"Hostname: {device.hostname or 'Unknown'}")
        print(f"Vendor:   {device.vendor or 'Unknown'}")

    print(f"\n{len(devices)} device{'s' if len(devices) != 1 else ''} discovered.")


def _print_scan_result(result) -> None:
    print(f"{result.target_label}: {result.target}")
    if result.hostname:
        print(f"Hostname: {result.hostname}")
    print()

    if not result.services:
        if result.scan_profile == "full":
            print("No open TCP ports were detected across the full TCP range.")
        else:
            profile = result.scan_profile or "selected"
            print(f"No open TCP ports were detected within the ports covered by the {profile} scan profile.")
        print()
        print("Scan summary:")
        print(f"Hosts scanned: 1")
        print(f"Open ports: 0")
        return

    print(f"{'PORT':<8} {'STATE':<6} {'SERVICE':<12} PRODUCT")
    for service in result.services:
        product_text = service.product or ""
        if service.version:
            product_text = f"{product_text} {service.version}".strip()
        print(f"{service.port}/{service.protocol:<4} {service.state:<6} {service.service or 'unknown':<12} {product_text or '-'}")

    print()
    print("Scan summary:")
    print(f"Hosts scanned: 1")
    print(f"Open ports: {result.open_ports}")


def _print_assessment(assessment) -> None:
    print("NetSentry Security Assessment")
    print("==============================")
    print()
    print(f"Host: {ip_visibility(assessment.host)}: {assessment.host}")
    print(f"Assessment Status: {assessment.status.value}")
    print(f"Status Reason: {assessment.status_reason}")
    print(f"Risk: {assessment.risk_level.value}")
    score = f"{assessment.risk_score}/10" if assessment.risk_score is not None else "UNKNOWN"
    print(f"Risk Score: {score}")
    print()
    print("Attack Surface")
    for observation in assessment.observations:
        service = observation.service or "unknown"
        product = f" {observation.product}" if observation.product else ""
        version = f" {observation.version}" if observation.version else ""
        print(f"{observation.port}/{observation.protocol:<4} {service}{product}{version}")
    if not assessment.observations:
        print("No open TCP services were detected within scan coverage.")
    print()
    print("Security Checks")
    for check in assessment.checks:
        print(f"{check.title}: {check.status.value}")
        if check.reason:
            print(f"  {check.reason}")
    print()
    print("Assessment Coverage")
    coverage = assessment.coverage
    print(f"Services discovered: {coverage.services_discovered}")
    print(f"Security checks attempted: {coverage.checks_attempted}")
    print(f"Checks completed: {coverage.checks_completed}")
    print(f"Checks unavailable/failed: {coverage.checks_unavailable_or_failed}")
    print()
    print(f"Findings: {len(assessment.findings)}")
    if not assessment.findings:
        print("No security findings were generated by the current NetSentry ruleset.")
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


def _print_network_assessment_summary(assessments: list) -> None:
    counts = Counter(finding.severity for assessment in assessments for finding in assessment.findings)
    print("NETWORK ASSESSMENT SUMMARY")
    print()
    print(f"Hosts assessed: {len(assessments)}")
    print(f"Total findings: {sum(counts.values())}")
    for severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        print(f"{severity.value}: {counts.get(severity, 0)}")
    print()
    print("Highest-risk hosts:")
    ranked_assessments = sorted(
        assessments,
        key=lambda item: (item.risk_score is None, -(item.risk_score or 0), item.host),
    )
    for index, assessment in enumerate(ranked_assessments[:5], start=1):
        host_display = f"{ip_visibility(assessment.host)}: {assessment.host}"
        score = f"{assessment.risk_score}/10" if assessment.risk_score is not None else "UNKNOWN"
        print(f"{index}. {host_display:<28} {assessment.risk_level.value:<8} {score}")


def _network_assessment_payload(assessments: list) -> dict:
    counts = Counter(finding.severity.value for assessment in assessments for finding in assessment.findings)
    ranked_assessments = sorted(
        assessments,
        key=lambda item: (item.risk_score is None, -(item.risk_score or 0), item.host),
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
    except (DiscoveryError, ValueError) as exc:
        print(f"Discovery failed: {exc}")
        return 1

    _print_discovery_results(devices)
    return 0


def _run_scan(args: argparse.Namespace) -> int:
    if args.discovered:
        try:
            target = get_local_network(args.interface)
            network = ipaddress.IPv4Network(args.network) if args.network else target.network
            devices = discover_devices(network, target.interface, timeout=args.timeout)
            targets = [device.ip for device in devices]
        except (DiscoveryError, ValueError) as exc:
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
            target = get_local_network(args.interface)
            network = ipaddress.IPv4Network(args.network) if args.network else target.network
            devices = discover_devices(network, target.interface, timeout=args.timeout)
            targets = [device.ip for device in devices]
        except (DiscoveryError, ValueError) as exc:
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

    assessments = []
    errors = []
    for target in targets:
        try:
            if not args.json:
                logger.info("Assessing %s %s using profile %s", ip_visibility(target), target, args.profile)
            result = scan_target(target, profile=args.profile, port_spec=args.ports, timeout=args.timeout)
            assessments.append(assess_scan_result(result))
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
        _print_assessment(assessment)
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
