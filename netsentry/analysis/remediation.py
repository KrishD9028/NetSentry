"""Evidence-specific administrator guidance; no automated changes or exploit tests."""
from .risk import finding_order, remediation_priority, supported_context

# Exact rule/title keys avoid matching unrelated custom findings by words.
GUIDANCE = {
    ("NS-CHECK-SMB", "SMBv1 supported"): (
        "Disable SMBv1", "Check legacy client dependencies, then disable the SMBv1 server dialect.",
        "Repeat unauthenticated SMB negotiation on this endpoint; confirm SMBv1 is no longer accepted and required clients still work.",
        "Legacy SMBv1 clients can lose connectivity; plan a maintenance window."),
    ("NS-CHECK-SMB", "SMB signing is not required"): (
        "Require SMB signing", "After verifying client compatibility, require server-side SMB message signing. Signing protects message integrity; this finding does not demonstrate a relay attack.",
        "Repeat SMB negotiation on this endpoint and confirm signing_required is true; verify approved clients can connect.",
        "Clients without signing support can lose access; rollout or restart requirements depend on the server."),
    ("NS-CHECK-TLS", "Expired TLS certificate"): (
        "Replace expired TLS certificate", "Renew or replace the certificate served by this endpoint and configure its required intermediate chain.",
        "Repeat the TLS handshake using the intended hostname; verify the served certificate validity dates, hostname, and chain trust with the administrator's trust store.",
        "Certificate reload/restart behavior depends on the service; uninterrupted replacement is not established."),
    ("NS-CHECK-TLS", "TLS certificate is not yet valid"): (
        "Correct TLS certificate validity", "Check the server and scanner clocks and deploy a certificate valid at the verified current time.",
        "Repeat the TLS handshake; verify not_before and not_after against a trusted clock, then check hostname and chain trust.",
        "A certificate reload or service restart may be required; confirm the deployment procedure."),
}


def remediation_details(finding) -> dict:
    guide = GUIDANCE.get((finding.rule_id, finding.title))
    if finding.remediation_key == "ssh_obsolete_algorithm":
        guide = (
            "Remove advertised obsolete SSH algorithm",
            finding.remediation + " Apply this to the exact algorithm and direction listed in the evidence; first check client compatibility.",
            "Repeat SSH KEXINIT enumeration on this endpoint and confirm the listed algorithm is absent from the affected category. Check approved clients still connect.",
            "Older SSH clients may lose access; preserve an approved administrative recovery path.")
    specific = guide is not None
    if not guide:
        guide = (
            finding.remediation or "Review the recorded finding",
            finding.description,
            f"Review rule {finding.rule_id} and the recorded evidence on this endpoint; apply the stated remediation and repeat the same check. Verify the underlying condition is corrected, not merely that the endpoint stopped responding.",
            "Service-disruption requirements have not been established.")
    references = list(finding.references)
    if (finding.rule_id, finding.title) == ("NS-CHECK-SMB", "SMB signing is not required"):
        references.append("https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview")
    if finding.rule_id == "NS-CHECK-TLS" and specific:
        references.append("https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5")
    return {
        "summary": guide[0], "technical_explanation": guide[1],
        "priority": remediation_priority(finding).value,
        "validation": guide[2],
        "without_service_disruption": None,
        "disruption_notes": guide[3],
        "applicability_confidence": finding.confidence.value if specific else "LOW",
        "applicability_reason": "Guidance corresponds to the observed control; deployment compatibility remains unverified." if specific else "Generic fallback preserves the finding's own guidance; an administrator must confirm applicability.",
        "affected_endpoint": {"host": finding.host, "port": finding.port, "protocol": finding.protocol, "service": finding.service},
        "references": list(dict.fromkeys(references)),
    }


def priority_actions(findings) -> list[dict]:
    actions = []
    for finding in sorted(findings, key=finding_order):
        guidance = remediation_details(finding)
        actions.append({
            "finding_id": finding.finding_id, "rule_id": finding.rule_id,
            "severity": finding.severity.value, "confidence": finding.confidence.value,
            "score": finding.score, "priority": guidance["priority"],
            "action": guidance["summary"], "endpoint": guidance["affected_endpoint"],
            "validation": guidance["validation"], "applicability_confidence": guidance["applicability_confidence"],
            "context": supported_context(finding),
        })
    return actions


def correlation_validation(correlation) -> dict:
    """Advisory severity orders validation work only, never remediation findings."""
    evidence = correlation.get("evidence", {})
    return {
        "cve_id": correlation.get("cve_id"), "status": "POTENTIAL",
        "advisory_severity": correlation.get("severity"), "advisory_cvss": correlation.get("cvss"),
        "action": "Validate the observed product/version against the authoritative advisory and deployment context before deciding whether remediation applies.",
        "validation": "Verify the installed version, vendor/variant, downstream fixes, and advisory configuration requirements. A banner correlation does not establish vulnerability or compromise.",
        "endpoint": {"host": evidence.get("host"), "port": evidence.get("port"), "protocol": evidence.get("protocol")},
        "reference": correlation.get("reference"), "limitations": correlation.get("limitations"),
        "remediation_applicable": None,
    }
