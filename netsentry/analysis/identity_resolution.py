"""Targeted host-identity planner. Failures never erase successful evidence."""
from dataclasses import asdict, replace
import time

from .host_evidence import ATTRIBUTES, HostEvidence, IdentityProbeResult, observation
from .identity_probes import probe_rdp_identity, probe_netbios_identity, certificate_observations
from .rpc_identity import probe_rpc_identity
from .correlation import SoftwareEvidence, bind_correlation
from .probes import ProbeError

GOALS = {
    "rdp_identity": ("hostname", "dns_name", "netbios_name", "dns_domain", "netbios_domain", "operating_system", "os_version", "os_edition"),
    "netbios_identity": ("hostname", "netbios_name", "workgroup", "mac_address"),
    "rpc_identity": ("operating_system", "os_edition"),
}


def collect_existing(assessment, scan, discovery=None):
    evidence = HostEvidence()
    if isinstance(scan.hostname, str) and scan.hostname:
        evidence.add(observation("hostname", scan.hostname.split(".")[0], "Scanner hostname", "initial_scan", "dns"))
        evidence.add(observation("dns_name", scan.hostname, "Scanner hostname", "initial_scan", "dns"))
    if discovery:
        for field, attribute in (("hostname", "hostname"), ("mac", "mac_address"), ("vendor", "mac_vendor")):
            value = getattr(discovery, field, None)
            if value and value != "Unknown":
                evidence.add(observation(attribute, value, "Local discovery", "discovery", "dns" if field == "hostname" else "oui_database" if field == "vendor" else "local_discovery"))
    if isinstance(scan.raw_xml, str) and len(scan.raw_xml) <= 2_000_000 and "<!DOCTYPE" not in scan.raw_xml and "<!ENTITY" not in scan.raw_xml:
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(scan.raw_xml)
            for scanned in root.findall("host"):
                if not any(address.get("addr") == assessment.host for address in scanned.findall("address")):
                    continue
                for address in scanned.findall("address[@addrtype='mac']"):
                    if address.get("addr"):
                        evidence.add(observation("mac_address", address.get("addr"), "Nmap link-layer observation", "initial_scan", "local_discovery"))
                    if address.get("vendor"):
                        evidence.add(observation("mac_vendor", address.get("vendor"), "Nmap local vendor lookup", "initial_scan", "oui_database"))
        except ET.ParseError:
            pass  # Scanner parsing already owns errors; identity never alters scan state.
    protocols = set()
    for item in assessment.observations:
        endpoint = f"{assessment.host}:{item.port}/{item.protocol}"
        if item.identification_status == "CONFIRMED" and item.service:
            evidence.add(observation("confirmed_service", item.service, "Protocol identification", "initial_checks", item.service, endpoint))
            protocols.add(item.service)
        for attempt in item.identification_attempts:
            evidence.attempts.append({"probe": f"{attempt['protocol']}_identification", "endpoint": endpoint,
                                      "status": attempt["status"], "reason": attempt.get("reason", "Protocol identity established"),
                                      "attributes": ["confirmed_service"], "reused": True})
    for check in assessment.checks:
        data = check.details or {}
        endpoint = f"{assessment.host}:{check.port}/{check.protocol or 'tcp'}"
        if check.check_id == "NS-CHECK-SMB":
            if data.get("dialect"):
                evidence.add(observation("protocol_version", data["dialect"], "SMB dialect negotiation", "smb_metadata", "smb", endpoint))
            # Server GUID is not a hostname. Preserve it without mislabeling.
            if data.get("identity"):
                evidence.add(observation("smb_server_guid", data["identity"], "SMB server GUID", "smb_metadata", "smb", endpoint))
            evidence.attempts.append({"probe": "smb_metadata", "endpoint": endpoint, "status": "COMPLETED" if data else "INCONCLUSIVE",
                                      "reason": "Existing negotiation reused; no hostname, domain, build, or edition exposed by this negotiation.",
                                      "attributes": ["hostname", "workgroup", "os_version", "os_edition"], "reused": True})
        if check.check_id == "NS-CHECK-TLS":
            for item in certificate_observations(data, endpoint, "tls_certificate"):
                evidence.add(item)
        if check.check_id == "NS-CHECK-RDP":
            for attempt in data.get("attempts", ()):
                if attempt.get("certificate"):
                    for item in certificate_observations(attempt["certificate"], endpoint, "rdp_certificate"):
                        evidence.add(item)
        for field in ("tls_version", "banner"):
            if data.get(field):
                evidence.add(observation("protocol_version" if field == "tls_version" else "software_banner",
                                         data[field], check.title, check.check_id, check.service or check.title, endpoint))
    for item in assessment.software_evidence:
        # Product and version originate in the same response. Copy provenance
        # together; a missing endpoint must remain absent rather than host:None.
        host, port = item.get("host"), item.get("port")
        endpoint = f"{host}:{port}" if host is not None and port is not None else None
        evidence.add(observation("software_product", item["product"], item["source"], "initial_checks", item["source"],
                                 endpoint))
        if item.get("version"):
            evidence.add(observation("software_version", f"{item['product']} {item['version']}", item["source"], "initial_checks", item["source"], endpoint))
    if "rdp" in protocols and "smb" in protocols:
        evidence.add(observation("operating_system", "Microsoft Windows", "Confirmed RDP and SMB are Windows-compatible, not Windows-exclusive",
                                 "cross_service", "protocol_hypothesis", hypothesis=True))
    return evidence


class IdentityResolver:
    def __init__(self, probes=None, *, timeout=8.0, max_probes=3):
        self.probes = dict(probes) if probes is not None else {
            "rdp_identity": probe_rdp_identity, "netbios_identity": probe_netbios_identity,
            "rpc_identity": probe_rpc_identity}
        self.timeout = min(max(timeout, 0), 8.0)
        self.max_probes = min(max(max_probes, 0), 3)

    def plan(self, assessment, evidence):
        tasks = []
        for item in sorted(assessment.observations, key=lambda row: row.port):
            if item.state != "open" or item.protocol != "tcp":
                continue
            name = item.service if item.identification_status == "CONFIRMED" else item.service_hint
            if name in {"rdp", "ms-wbt-server"} or (not name and item.port == 3389):
                tasks.append(("rdp_identity", item.port))
            if name in {"smb", "microsoft-ds", "netbios-ssn"} or (not name and item.port in {139, 445}):
                tasks.append(("netbios_identity", 137))
            if name in {"msrpc"} or (not name and item.port == 135):
                tasks.append(("rpc_identity", item.port))
        seen = {(item["probe"], item.get("port")) for item in evidence.attempts}
        planned = []
        for probe, port in tasks:
            if (probe, port) in seen:
                continue
            seen.add((probe, port))
            if any(evidence.resolve(attribute)["state"] in {"UNRESOLVED", "PROBABLE", "CONTRADICTORY"} for attribute in GOALS[probe]):
                planned.append((probe, port))
        return planned

    def resolve(self, assessment, evidence):
        deadline = time.monotonic() + self.timeout
        for index, (name, port) in enumerate(self.plan(assessment, evidence)):
            remaining = deadline - time.monotonic()
            if index >= self.max_probes or remaining <= 0:
                result = IdentityProbeResult("UNSUPPORTED", "Host identity probe budget exhausted; not attempted.")
            elif name not in self.probes:
                result = IdentityProbeResult("UNSUPPORTED", "No implementation configured for this identity probe.")
            else:
                try:
                    result = self.probes[name](assessment.host, port=port, timeout=min(3.0, remaining))
                except (OSError, ProbeError) as exc:
                    result = IdentityProbeResult("FAILED", str(exc))
            for item in result.observations:
                evidence.add(item)
            evidence.attempts.append({"probe": name, "port": port, "endpoint": f"{assessment.host}:{port}/{'udp' if name == 'netbios_identity' else 'tcp'}",
                                      "status": result.status, "reason": result.reason, "attributes": list(GOALS[name]), "reused": False})
        return evidence


def enrich_identity(assessment, scan, resolver=None, discovery=None, vulnerability_provider=None):
    evidence = collect_existing(assessment, scan, discovery)
    if resolver is not None:
        resolver.resolve(assessment, evidence)
    if not evidence.resolve("mac_vendor")["value"] and evidence.resolve("mac_address")["state"] != "CONTRADICTORY":
        mac = evidence.resolve("mac_address")["value"]
        if mac:
            try:
                from scapy.config import conf
                vendor = conf.manufdb._get_manuf(mac) if conf.manufdb is not None else mac
                if vendor and vendor != mac and vendor != "Unknown":
                    evidence.add(observation("mac_vendor", vendor, "Local Scapy OUI database; interface vendor is not OS identity",
                                             "mac_vendor_lookup", "oui_database"))
                evidence.attempts.append({"probe": "mac_vendor_lookup", "status": "COMPLETED" if vendor != mac else "INCONCLUSIVE",
                                          "reason": "Local OUI lookup only; no network request.", "attributes": ["mac_vendor"]})
            except (ImportError, OSError) as exc:
                evidence.attempts.append({"probe": "mac_vendor_lookup", "status": "UNSUPPORTED", "reason": str(exc), "attributes": ["mac_vendor"]})
    for attribute in ATTRIBUTES:
        if not any(attribute in attempt.get("attributes", ()) for attempt in evidence.attempts) and evidence.resolve(attribute)["state"] == "UNRESOLVED":
            evidence.attempts.append({"probe": "planner", "kind": "unresolved_goal", "status": "UNSUPPORTED",
                                      "reason": "No applicable unauthenticated identity probe is available from the observed services.",
                                      "attributes": [attribute]})
    software = list(assessment.software_evidence)
    correlations = list(assessment.potential_correlations)
    diagnostics = list(assessment.correlation_diagnostics)
    # OS evidence is available for provider evaluation, but never fabricated
    # from SMB dialects. Retain all versions, withholding contradictory matches.
    versions = [item for item in evidence.observations if item.attribute == "os_version" and item.probe == "rdp_identity"]
    for item in versions:
        current = SoftwareEvidence("Microsoft Windows", item.value, "rdp", item.confidence, item.source,
                                   vendor=None, variant="ntlm_reported", raw_version=item.value,
                                   host=assessment.host, port=int(item.endpoint.rsplit(":", 1)[1].split("/")[0]) if item.endpoint else None)
        software.append({**asdict(current), "confidence": current.confidence.value})
        if evidence.resolve("os_version")["state"] == "CONTRADICTORY":
            diagnostics.append({"product": current.product, "status": "INDETERMINATE", "reason": "Conflicting OS build observations; automatic correlation withheld."})
        elif evidence.resolve("operating_system")["state"] != "CONFIRMED":
            diagnostics.append({"product": current.product, "status": "INDETERMINATE", "reason": "NTLM version alone does not establish Windows product identity; automatic correlation withheld."})
        elif vulnerability_provider is not None:
            if hasattr(vulnerability_provider, "evaluate"):
                matches, reasons = vulnerability_provider.evaluate(current)
                diagnostics.extend({**reason, "host": assessment.host, "product": current.product} for reason in reasons)
            else:
                matches = vulnerability_provider.correlate(current)
            for candidate in matches:
                bound = bind_correlation(candidate, current)
                if bound is not None:
                    correlations.append(bound.to_dict())
    return replace(assessment, host_identity=evidence.to_dict(), planning_trace=getattr(resolver, "trace", assessment.planning_trace), software_evidence=tuple(software),
                   potential_correlations=tuple(correlations), correlation_diagnostics=tuple(diagnostics))
