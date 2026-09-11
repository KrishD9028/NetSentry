# NetSentry

NetSentry is an authorized network security assessment tool. It discovers local devices, enumerates TCP services, and produces non-exploitative security analysis from observable evidence.

## Authorization and limitations

Only assess systems and networks you own or have explicit permission to test. NetSentry does not exploit vulnerabilities, execute payloads, brute-force credentials, authenticate to services, modify remote systems, or download exploit code.

An open port is an attack-surface observation, not proof of a vulnerability. A security finding is emitted only by a completed security check with supporting evidence. If checks are unavailable or fail, NetSentry reports `LIMITED` and `Risk: UNKNOWN` rather than claiming the host is clean.

## Setup

```sh
cd ~/NetSentry
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

Scapy is used for local ARP discovery. Service scanning and assessment require the system-installed `nmap` binary. NetSentry checks for Nmap and does not install it automatically.

## Commands

Show help:

```sh
netsentry --help
netsentry discover --help
netsentry scan --help
netsentry assess --help
```

Discover devices:

```sh
netsentry discover
netsentry discover --interface en0
netsentry discover --network 192.168.1.0/24
netsentry discover --timeout 5
```

Discovery displays classified addresses such as `Private IP`, `Shared/CGNAT IP`, or `Public IP`, plus MAC, hostname, and best-effort vendor information.

Each successful `discover` run atomically replaces `~/.netsentry/current_discovery.json`. The `--discovered` forms of `scan` and `assess` read only that current snapshot; they do not perform a new discovery and do not merge historical hosts. Run `netsentry discover` again to refresh it.

Scan one authorized host:

```sh
netsentry scan 192.168.1.20
netsentry scan 192.168.1.20 --profile quick
netsentry scan 192.168.1.20 --profile common
netsentry scan 192.168.1.20 --profile custom --ports 22,80,443,8000-8100
netsentry scan 192.168.1.20 --profile full --ports 1-65535
```

Scan discovered devices:

```sh
netsentry scan --discovered
netsentry scan --discovered --interface en0 --limit 10
```

Without `--limit`, all discovered devices are scanned. If a scan profile reports no open ports, the output is scoped to that profile, for example: `No open TCP ports were detected within the ports covered by the common scan profile.`

Assess one host:

```sh
netsentry assess 192.168.1.20 --profile common
netsentry assess 192.168.1.20 --profile custom --ports 53,135,139,445,8443
```

Assess discovered devices:

```sh
netsentry assess --discovered --profile common
netsentry assess --discovered --interface en0 --limit 10 --profile common
```

Emit structured JSON:

```sh
netsentry assess 192.168.1.20 --profile common --json
netsentry assess --discovered --limit 10 --profile common --json
```

Assessment JSON preserves the host classification, scan profile, requested ports, reachability, probe status, port-state and service-identity evidence, security-check results, coverage, findings, and risk. Original XML and grouped port summaries are retained in `scan_evidence`.

## Assessment states

- `COMPLETE`: all applicable checks for the available evidence completed.
- `LIMITED`: checks were unavailable or failed, or the scan profile found no ports without proving the host has none.
- `UNREACHABLE`: the target could not be reached.
- `ERROR`: reserved for assessment errors that prevent meaningful analysis.

`Overall Risk: UNKNOWN` is used for limited assessments. The legacy overall `0/10` result is reserved for completed assessments with no findings. Observed risk is reported separately and is scoped to assessed evidence; see below.

## Analysis architecture

The pipeline is:

```text
Discovery -> Nmap enumeration -> port-state evidence -> bounded protocol identification
          -> attack-surface observations -> service-aware defensive checks -> findings -> risk
```

The analysis package uses independently testable checks for SMB, TLS, SSH, HTTP, DNS, and RDP. Bounded protocol identification precedes security-check dispatch. Successful identification data is reused by the corresponding check; failed identification remains explicit evidence without becoming a vulnerability.

Future service/version normalization, CPE matching, CVE intelligence, and CVSS data can feed the same structured finding model without coupling those concerns to the scanner.

## Risk scoring

Finding scores are transparent:

```text
INFO     0
LOW      2
MEDIUM   5
HIGH     8
CRITICAL 10
```

The host score is the highest score among confirmed findings. Informational observations do not inflate risk. A finding represents something supported by a completed check and deserves review; it does not prove exploitability.

## Testing

```sh
. .venv/bin/activate
python -m unittest discover -s tests -v
```

Tests use constructed scan results and mocked discovery/subprocess boundaries. They do not scan random Internet hosts.

## Milestone 4 capabilities

The assessment layer also includes safe, modular checks for:

- SSH banners and protocol evidence
- HTTP response status, redirects, server metadata, and security-header observations
- DNS response and recursion flags
- RDP negotiation response
- SMB and TLS checks from Milestone 3

Services without a registered module remain attack-surface observations. Their presence alone does not create a vulnerability finding or increase risk.

Software evidence can be passed to provider-based potential vulnerability correlation. Correlations are reported as `POTENTIAL` and never promoted to confirmed findings or risk without direct evidence.

## TCP state and service evidence

TCP scanning still uses Nmap `-sT -Pn` with the existing profile ports, timing,
process timeout, and host timeout. This change does not enable `-sV` or NSE scripts.

- `open`: Nmap reports the port open.
- `closed`: Nmap reports the port closed.
- `filtered`: Nmap reports filtering with an explicit `admin-prohibited`,
  `host-prohibited`, or `net-prohibited` reason.
- `unknown`: missing evidence, ambiguous states, no response, or insufficient
  evidence to distinguish filtering from other causes.

For example, raw Nmap `filtered` with `reason="no-response"` becomes NetSentry
`unknown`. The original `scanner_state`, `scanner_reason`, and `scanner_source`
remain available alongside the normalized `state` and `state_reason`. See Nmap's
[port-state semantics](https://nmap.org/book/port-scanning.html) and
[XML service-identification metadata](https://nmap.org/book/output-formats-xml-output.html).

Grouped Nmap results are assigned to individual ports only when explicit ranges
or one exact remaining group establish membership. Mixed reasons are never
arbitrarily assigned to individual ports. Unattributed requested ports have
`scan_observed: false`: they may not have been tested, and are not described as
confirmed closed or filtered. A process timeout returns a `timeout` scan result;
complete available XML is parsed, while incomplete XML is retained without
inventing per-port evidence. `-Pn`'s `up/user-set` does not establish reachability.

`PortService.service` preserves the scanner's original label for compatibility.
Use `service_hint`, `confirmed_service`, and `confirmed_protocols` to interpret it:

- `HINT`: a conventional port or scanner table label, such as SSH on TCP/22.
- `CONFIRMED`: protocol evidence from a successful bounded NetSentry probe, or
  Nmap `method="probed"` with `conf="10"`. Each protocol identity retains its
  source, confidence, and evidence. Missing/low-confidence provenance stays a hint.
- `UNKNOWN`: neither an identified service nor a useful hint is available.

In assessment JSON, `service` is the confirmed service, `service_hint` is separate,
and `scanner_service` preserves the original label and metadata. A confirmed
service is not a confirmed vulnerability or verified software authenticity.

Only open ports can undergo identification. Hints select the existing safe
protocol probes; a passive SSH banner read also recognizes SSH on other open
ports (one-second budget when SSH is not hinted). This can add up to one second
per unidentified open port to assessment time. Active protocol identification
is limited to the registered modules and applicable hints. It is not a universal
service detector. `scan` itself does not perform these extra identification probes.
TLS and HTTP are demonstrated independently; TLS alone does not prove HTTPS.

Closed, filtered, and unknown ports never reach service-specific checks. Open
ports also need confirmed protocol identity. Identification attempts appear
separately from security checks in JSON. Port state alone creates no finding.
Uncertain port state or unidentified open services produce `LIMITED`/unknown
risk; adding closed ports does not inflate service counts. Even a `full` profile
cannot claim a completed empty assessment without evidence for the full range.

Terminal output includes state and labels hints explicitly. Large unlabelled
non-open ranges are compacted; JSON retains every port record. The legacy
`services` list now includes non-open records, and `open_ports` counts only open
records. Consumers must use state and identity guards rather than list length or
port number. Assessment JSON may be larger because it preserves raw XML.

Example (illustrative, not a live measurement):

```text
Attack Surface
PORT        STATE     SERVICE
22/tcp      filtered  unknown (hint: ssh)
135/tcp     unknown   unknown (hint: msrpc)
445/tcp     open      smb
8443/tcp    open      https
```

For the owner's Windows test host, compare:

```sh
netsentry scan 100.100.201.201 --profile common
netsentry assess 100.100.201.201 --profile common
netsentry assess 100.100.201.201 --profile common --json
```

TCP/22 should remain visible. A no-response result should show `unknown`, preserve
Nmap's raw `filtered/no-response` evidence in JSON, and cause no SSH security check.
After connectivity is restored, an SSH identification banner should permit the
SSH check. SMB on 445 and demonstrated TLS/HTTP on 8443 should continue working.

## Observed risk and coverage

Overall `risk` remains conservative and backward compatible: non-`COMPLETE`
assessments retain `UNKNOWN` severity and a null score. A separate
`observed_risk` object has `scope: "assessed_evidence"` and is derived as follows:

- Accepted findings exist: highest finding severity and score.
- No findings and at least one completed security check: `INFO`, score `0`.
- No findings and no completed security checks: `UNKNOWN`, score `null`.

Port state, hints, incomplete identification, potential CVE correlations, and
coverage counts never contribute to observed risk. A limited assessment can
therefore retain an observed HIGH finding while overall risk remains unknown.
An observed zero means completed checks generated no findings; it does not mean
the target is secure. Existing confidence remains attached to evidence/findings.
`COMPLETE` refers to applicable checks within the assessment scope, not exhaustive
knowledge of target risk.

Coverage distinguishes `open_ports`, `confirmed_services`, and
`unconfirmed_open_ports`. These count unique endpoints by host, transport, and
port. Only open endpoints with confirmed identity count as confirmed services.
HTTPS on one port counts once even when TLS and HTTP each have a security check.
Identification attempts remain separate from security-check counts. The existing
`checks_unavailable_or_failed` field includes inconclusive checks as well.

**Deprecated:** `coverage.services_discovered` and the Python attribute of that
name remain compatibility aliases for `open_ports`, never for
`confirmed_services`. The legacy Python constructor remains supported; callers
that construct coverage directly should supply `confirmed_services` when known
(the default is zero). New consumers should use the explicit count names.

JSON retains the existing `risk` object and adds `observed_risk`. Network
`highest_risk_hosts` entries retain their legacy overall `severity` and `score`
fields and add `observed_risk`, `assessment_status`, and `coverage`. Ranking now
uses descending observed score, with unassessed/unknown scores last and host as
the deterministic tie-breaker. Terminal summaries show observed risk, assessment
status, and overall risk together. This is an ordering change; strict JSON
consumers must also accommodate the added fields. Unknown ranking position is
not an assertion of lower actual risk.
