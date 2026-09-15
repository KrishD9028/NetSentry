"""Human-oriented evidence expansion. Deliberate field selection, never model dumps."""


def text(value):
    if value is None:
        return "Unknown"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if not isinstance(value, (str, int, float)):
        return "Not available as interpreted evidence"
    value = " ".join(str(value).split())
    value = "".join(c for c in value if c.isprintable())
    return value[:800] + ("…" if len(value) > 800 else "")


def detail(label, value):
    print(f"  {label}: {text(value)}")


def fields(data, labels):
    for key, label in labels:
        if key in data:
            detail(label, data[key])


CERTIFICATE = (
    ("tls_version", "TLS version"), ("cipher", "Cipher"), ("subject", "Certificate subject"),
    ("issuer", "Certificate issuer"), ("not_before", "Valid from"),
    ("not_after", "Valid until"), ("expired", "Expired"), ("not_yet_valid", "Not yet valid"),
    ("verification_result", "Certificate verification"),
)


def check_details(check):
    data = check.details or {}
    if check.reason:
        detail("Assessment reasoning", check.reason)
    protocol = (check.service or check.title.split()[0]).lower()
    protocol = {"NS-CHECK-HTTP": "http", "NS-CHECK-TLS": "tls",
                "NS-CHECK-SMB": "smb", "NS-CHECK-SSH": "ssh",
                "NS-CHECK-RDP": "rdp", "NS-CHECK-DNS": "dns"}.get(check.check_id, protocol)
    if protocol == "smb":
        fields(data, (("dialect", "Dialect"), ("smb1_supported", "SMBv1 supported"),
                      ("signing_supported", "Signing supported"), ("signing_required", "Signing required"),
                      ("authentication_status", "Negotiation authentication"), ("identity", "Server identity")))
    elif protocol == "rdp":
        fields(data, (("nla_available", "NLA available"), ("nla_required", "NLA required"),
                      ("tls_used", "TLS used"), ("legacy_accepted", "Legacy security accepted")))
        protocols = {0: "Legacy RDP", 1: "TLS", 2: "CredSSP", 8: "CredSSP extended"}
        for index, attempt in enumerate(data.get("attempts", ())[:3], 1):
            selected = attempt.get("selected_protocol")
            detail(f"Negotiation attempt {index}", attempt.get("status"))
            requested = attempt.get("requested_protocols")
            if isinstance(requested, int):
                names = [name for bit, name in protocols.items() if bit and requested & bit]
                detail("Requested security", ", ".join(names) if names else "Legacy RDP" if requested == 0 else "Unsupported selection")
            detail("Selected security", protocols.get(selected, "Unknown" if selected is None else f"Unsupported protocol {selected}"))
            fields(attempt, (("reason", "Result"), ("failure_code", "Negotiation failure code"),
                             ("tls_error", "TLS failure")))
            if isinstance(attempt.get("certificate"), dict):
                fields(attempt["certificate"], CERTIFICATE)
    elif protocol == "tls":
        fields(data, CERTIFICATE)
    elif protocol in {"http", "https"}:
        fields(data, (("status", "HTTP status"), ("server", "Server software"),
                      ("tls", "TLS transport"), ("redirect", "Redirect")))
        for name in ("content-type", "strict-transport-security", "content-security-policy",
                     "x-content-type-options", "x-frame-options", "referrer-policy"):
            if name in data.get("selected_headers", {}):
                detail(name, data["selected_headers"][name])
        if data.get("methods"):
            detail("Advertised methods", ", ".join(text(item) for item in data["methods"][:20]))
    elif protocol == "ssh":
        fields(data, (("banner", "SSH banner"), ("enumeration_status", "Algorithm enumeration"),
                      ("enumeration_reason", "Enumeration reasoning")))
        labels = {"kex": "Key exchange", "host_key": "Host-key algorithms",
                  "cipher_client_to_server": "Ciphers client to server",
                  "cipher_server_to_client": "Ciphers server to client",
                  "mac_client_to_server": "MACs client to server",
                  "mac_server_to_client": "MACs server to client",
                  "compression_client_to_server": "Compression client to server",
                  "compression_server_to_client": "Compression server to client"}
        for key, label in labels.items():
            values = data.get("algorithms", {}).get(key, ())
            if values:
                detail(label, ", ".join(text(value) for value in values[:20]))
                if len(values) > 20:
                    detail("Additional algorithms", len(values) - 20)
    elif protocol == "dns":
        fields(data, (("transport", "DNS transport"), ("query_name", "Query name"),
                      ("response_code", "Response code"), ("authoritative", "Authoritative answer"),
                      ("answer_count", "Answer records"), ("recursion_available", "Recursion advertised"),
                      ("recursion_demonstrated", "Recursion demonstrated"),
                      ("open_recursion_confirmed", "Open recursion confirmed")))
    for contradiction in data.get("contradictions", ())[:10]:
        detail("Contradiction", contradiction)


def port_details(observation):
    print(f"  {observation.port}/{observation.protocol} — service identification: {text(observation.identification_status)}")
    raw = observation.scanner_state
    state = raw or observation.state
    detail("State", state)
    source = observation.scanner_source or "Scanner"
    reason = {"syn-ack": "SYN-ACK", "conn-refused": "connection refused",
              "no-response": "no response", "reset": "RST"}.get(observation.scanner_reason, observation.scanner_reason)
    if source.startswith("Nmap"):
        source = "Nmap"
    detail("Evidence", f"{source} {reason}" if reason else observation.state_reason or source)
    if raw and raw != observation.state:
        detail("NetSentry interpretation", f"{observation.state}; {observation.state_reason or 'scanner state is not independently established'}")
    for identity in observation.identities[:8]:
        detail("Confirmed protocol", identity.get("protocol"))
        role = {"tls": "Transport/security layer", "http": "Application layer"}.get(identity.get("protocol"))
        if role:
            detail("Protocol role", role)
        detail("Identification source", identity.get("source"))
        fields(identity.get("evidence", {}), (("banner", "Banner"), ("tls_version", "TLS version"),
                                              ("status", "HTTP status"), ("dialect", "SMB dialect")))
    for attempt in observation.identification_attempts[:8]:
        detail("Identification attempt", attempt.get("protocol"))
        fields(attempt, (("status", "Result"), ("reason", "Reason")))



def port_evidence_summary(observations):
    """Group routine silence/closed evidence; keep exceptions and open details."""
    grouped = {}
    detailed = []
    for item in observations:
        raw, state = item.scanner_state, item.state
        routine = (
            (raw == "filtered" and state in {"unknown", "filtered"} and item.scanner_reason in {None, "no-response"}) or
            (raw in {None, "unknown"} and state == "unknown" and item.scanner_reason in {None, "no-response"}) or
            (raw in {None, "closed"} and state == "closed" and item.scanner_reason in {None, "reset", "conn-refused"})
        )
        if routine and not item.identities and not item.identification_attempts and item.identification_status != "CONFIRMED":
            key = (item.protocol, raw, state, item.scanner_reason, item.scanner_source, item.state_reason)
            grouped.setdefault(key, []).append(item)
        else:
            detailed.append(item)
    for items in grouped.values():
        first = items[0]
        state = "filtered" if first.scanner_state == "filtered" else first.state
        detail(f"{len(items)} {first.protocol} ports with shared evidence",
               f"{state}; {first.scanner_source or 'scanner result'}; {first.scanner_reason or 'no further response evidence'}")
        if first.scanner_state != first.state and first.scanner_state:
            detail("NetSentry interpretation", first.state)
        if first.state_reason:
            detail("Reasoning", first.state_reason)
    # Caller supplies deterministic port order. Exceptions are never hidden
    # behind long runs of routine filtered ports.
    for item in detailed:
        port_details(item)

def finding_details(finding):
    data = finding.remediation_details
    detail("Evidence", finding.evidence)
    detail("Why this matters", finding.description)
    detail("Remediation", finding.remediation)
    detail("Technical guidance", data["technical_explanation"])
    detail("Validation", data["validation"])
    detail("Remediation applicability confidence", data["applicability_confidence"])
    detail("Applicability reasoning", data["applicability_reason"])
    detail("Without service disruption", data["without_service_disruption"])
    detail("Disruption considerations", data["disruption_notes"])
    for reference in data["references"]:
        detail("Reference", reference)


def coverage_details(assessment):
    detail("Scan profile", assessment.scan_profile)
    detail("Requested ports", len(assessment.requested_ports))
    no_response = sum(item.scanner_state == "filtered" and item.scanner_reason == "no-response"
                      and item.state == "unknown" for item in assessment.observations)
    if no_response:
        detail("Scanner-reported filtered/no-response", f"{no_response} ports")
        detail("NetSentry interpretation", "UNKNOWN")
        detail("Reason", "No response is insufficient to distinguish filtering from other causes.")
    confirmed_filtered = sum(item.state == "filtered" for item in assessment.observations)
    if confirmed_filtered:
        detail("Ports with normalized FILTERED evidence", confirmed_filtered)
    other_unknown = sum(item.state == "unknown" for item in assessment.observations) - no_response
    if other_unknown:
        detail("Other ports with UNKNOWN state", other_unknown)
    detail("Open ports without confirmed service identity", assessment.coverage.unconfirmed_open_ports)
    detail("Checks attempted", assessment.coverage.checks_attempted)
    detail("Checks completed", assessment.coverage.checks_completed)
    detail("Scan completion", assessment.probe_status)
    detail("Assessment reasoning", assessment.status_reason or None)
    detail("Services without assessment modules", assessment.unimplemented_services)
    detail("Risk scope", "Observed risk uses accepted findings only; potential CVEs and incomplete coverage do not add risk.")
    detail("Overall risk", assessment.risk_level.value)


def correlation_range(item):
    value = item.get("matched_range") or {}
    if value.get("exact"):
        return f"exactly {text(value['exact'])} ({text(value.get('scheme'))})"
    bounds = []
    for key, comparison in (("lower", ">"), ("upper", "<")):
        if value.get(key) is not None:
            bounds.append(comparison + ("=" if value.get(key + "_inclusive") else "") + text(value[key]))
    return " and ".join(bounds) if bounds else text(item.get("affected_range"))


def correlation_details(assessment):
    for observation in assessment.software_evidence[:30]:
        detail("Software observation", f"{text(observation.get('product'))} {text(observation.get('version'))}")
        fields(observation, (("port", "Port"), ("source", "Software evidence source"),
                             ("confidence", "Confidence"), ("variant", "Variant"), ("vendor", "Vendor")))
    for item in assessment.correlation_diagnostics[:30]:
        detail("CVE evaluation", f"{text(item.get('cve_id'))}: {text(item.get('status'))}")
        fields(item, (("product", "Product"), ("port", "Port"), ("reason", "Correlation reasoning")))
    omitted = max(0, len(assessment.software_evidence) - 30) + max(0, len(assessment.correlation_diagnostics) - 30)
    if omitted:
        detail("Additional software/correlation entries in JSON", omitted)


def host_identity_details(identity):
    print("HOST IDENTITY")
    labels = {"hostname": "Hostname", "dns_name": "DNS name", "netbios_name": "NetBIOS name",
              "netbios_domain": "NetBIOS domain", "dns_domain": "DNS domain", "workgroup": "Workgroup",
              "operating_system": "Operating system", "os_version": "OS version/build", "os_edition": "OS edition",
              "candidate_cpe": "Candidate CPE", "mac_address": "MAC address", "mac_vendor": "MAC vendor"}
    print("  Resolved attributes:")
    for name, result in identity["attributes"].items():
        value = result["value"] or ("Conflicting values" if result["state"] == "CONTRADICTORY" else "Not established")
        detail(labels.get(name, name), f"{text(value)} — {result['state']}")
        if result["confidence"]:
            detail("Confidence", result["confidence"])
        detail("Independent confirmations", result["independent_confirmations"])
        detail("Explanation", result["reason"])
        # Preserve explanations from older JSON lacking unresolved_goal kinds.
        for attempt in result.get("attempts", ()):
            if attempt.get("probe") == "planner" and attempt.get("kind") != "unresolved_goal":
                detail("Goal limitation", attempt["reason"])
    print("  Evidence:")
    for item in identity["observations"]:
        if item["attribute"] == "confirmed_service" and item["value"] == "https":
            detail("Confirmed service stack", "HTTPS (HTTP over TLS)")
        else:
            detail(labels.get(item["attribute"], item["attribute"].replace("_", " ").capitalize()), item["value"])
        detail("Source", f"{text(item['source'])}; probe {text(item['probe'])}; endpoint {text(item['endpoint'])}")
    print("  Follow-up attempts:")
    for attempt in identity["attempts"]:
        # Legacy planner records also describe unresolved goals, not traffic.
        if attempt.get("kind") == "unresolved_goal" or attempt.get("probe") == "planner":
            continue
        origin = "reused" if attempt.get("reused") else "new"
        detail("Probe", f"{text(attempt['probe'])} — {text(attempt['status'])} ({origin})")
        detail("Endpoint", attempt.get("endpoint"))
        detail("Reason", attempt["reason"])
    print()


def planning_details(trace):
    print('ENUMERATION PLANNING')
    detail('Planner', trace['planner'])
    for index, step in enumerate(trace['steps'], 1):
        selected = step['selected']
        if selected:
            detail(f'Step {index}', f"{selected['action_id']} at port {selected['port']}")
            detail('Selection reasoning', selected['reason'])
            detail('Policy', step['policy_decision'])
            if step['result']:
                detail('Result', f"{step['result']['status']}: {step['result']['reason']}")
            for change in step['changes']:
                detail('Knowledge change', f"{change['attribute']}: {change['before']} → {change['after']}")
        for candidate in step['candidates']:
            if candidate['rejection']:
                detail('Not selected', f"{candidate['proposal']['action_id']}: {candidate['rejection']}")
    detail('Stopped', trace['stopping_reason'])
    detail('Actions remaining', trace['remaining_budget']['actions_remaining'])
    detail('Network requests remaining', trace['remaining_budget']['network_requests_remaining'])
    print()
