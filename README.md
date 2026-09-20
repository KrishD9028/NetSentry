# NetSentry

[![Tests](https://github.com/KrishD9028/NetSentry/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/KrishD9028/NetSentry/actions/workflows/tests.yml)

NetSentry is an evidence-driven network security assessment and enumeration framework.

It discovers hosts, enumerates services, performs bounded protocol-specific security
checks, gathers additional evidence adaptively, and resolves host and service identity.
It can correlate observed software with potential CVEs, while explicitly separating
confirmed observations, hypotheses, limitations, and unknowns.

## Key Features

- Local IPv4 host discovery with address, MAC, hostname, and best-effort vendor evidence.
- Profile-based TCP service enumeration through Nmap, with raw and normalized state evidence.
- Bounded, non-exploitative checks for SMB, TLS, SSH, HTTP, DNS, and RDP.
- Deterministic adaptive evidence acquisition under explicit time, action, and request budgets.
- Conservative host and service identity resolution with provenance and conflict handling.
- Offline, version-aware potential CVE correlation that never becomes a confirmed finding
  or changes risk without direct evidence.
- Human-readable compact and verbose reports plus structured JSON for automation.
- Explicit assessment status, coverage, observed risk, confidence, limitations, and unknowns.

## Example Assessment

```sh
netsentry assess 192.0.2.20 --profile common --verbose
netsentry assess 192.0.2.20 --profile common --json
```

Example output is intentionally not presented as a live measurement. NetSentry keeps
potential CVE correlations separate from confirmed findings and reports incomplete
checks as limited or unknown.

<!-- TODO(public-release): Add a sanitized terminal screenshot from an authorized lab. -->

## Architecture

```text
Discovery -> Nmap enumeration -> port-state evidence -> bounded protocol identification
          -> adaptive evidence acquisition and identity resolution
          -> service-aware defensive checks -> findings -> risk
          -> potential CVE correlation (reported separately)
```

The implementation separates discovery, scanning, analysis, deterministic planning,
and acquisition into independently testable packages. Registered capabilities are
bounded by policy; service hints guide probes but do not establish identity, and an
open port alone is not treated as a vulnerability.

## Installation

NetSentry requires Python 3.11 or newer. Create a virtual environment and install the
project and its declared dependencies from the existing `pyproject.toml` configuration:

```sh
git clone https://github.com/KrishD9028/NetSentry.git
cd NetSentry
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Scapy is used for local ARP discovery. Service scanning and assessment require the
system-installed `nmap` binary. NetSentry checks for Nmap and does not install it.
On Debian or Ubuntu, install it with `sudo apt-get install nmap`.

## Usage

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
netsentry discover --network 192.0.2.0/24
netsentry discover --timeout 5
```

Discovery displays classified addresses such as `Private IP`, `Shared/CGNAT IP`, or `Public IP`, plus MAC, hostname, and best-effort vendor information.

Each successful `discover` run atomically replaces `~/.netsentry/current_discovery.json`. The `--discovered` forms of `scan` and `assess` read only that current snapshot; they do not perform a new discovery and do not merge historical hosts. Run `netsentry discover` again to refresh it.

Scan one authorized host:

```sh
netsentry scan 192.0.2.20
netsentry scan 192.0.2.20 --profile quick
netsentry scan 192.0.2.20 --profile common
netsentry scan 192.0.2.20 --profile custom --ports 22,80,443,8000-8100
netsentry scan 192.0.2.20 --profile full --ports 1-65535
```

Scan discovered devices:

```sh
netsentry scan --discovered
netsentry scan --discovered --interface en0 --limit 10
```

Without `--limit`, all discovered devices are scanned. If a scan profile reports no open ports, the output is scoped to that profile, for example: `No open TCP ports were detected within the ports covered by the common scan profile.`

Assess one host:

```sh
netsentry assess 192.0.2.20 --profile common
netsentry assess 192.0.2.20 --profile custom --ports 53,135,139,445,8443
```

Assess discovered devices:

```sh
netsentry assess --discovered --profile common
netsentry assess --discovered --interface en0 --limit 10 --profile common
```

Emit structured JSON:

```sh
netsentry assess 192.0.2.20 --profile common --json
netsentry assess --discovered --limit 10 --profile common --json
```

Assessment JSON preserves the host classification, scan profile, requested ports, reachability, probe status, port-state and service-identity evidence, security-check results, coverage, findings, and risk. Original XML and grouped port summaries are retained in `scan_evidence`.

## Testing

The test suite uses Python's standard-library test runner, so the editable installation
above supplies all declared runtime and test requirements:

```sh
python -m unittest discover -s tests -v
```

Tests use constructed scan results and mocked discovery and subprocess boundaries.
They do not scan random Internet hosts.

## Evidence and Confidence Model

An open port is an attack-surface observation, not proof of a vulnerability. A security
finding is emitted only by a completed security check with supporting evidence. If
checks are unavailable or fail, NetSentry reports `LIMITED` and `Risk: UNKNOWN` rather
than claiming the host is clean. Potential CVE correlations remain potential until
their applicability is independently established.

### Assessment states

- `COMPLETE`: all applicable checks for the available evidence completed.
- `LIMITED`: checks were unavailable or failed, or the scan profile found no ports without proving the host has none.
- `UNREACHABLE`: the target could not be reached.
- `ERROR`: reserved for assessment errors that prevent meaningful analysis.

`Overall Risk: UNKNOWN` is used for limited assessments. The legacy overall `0/10` result is reserved for completed assessments with no findings. Observed risk is reported separately and is scoped to assessed evidence; see below.

### Analysis details

The pipeline is:

```text
Discovery -> Nmap enumeration -> port-state evidence -> bounded protocol identification
          -> attack-surface observations -> service-aware defensive checks -> findings -> risk
```

The analysis package uses independently testable checks for SMB, TLS, SSH, HTTP, DNS, and RDP. Bounded protocol identification precedes security-check dispatch. Successful identification data is reused by the corresponding check; failed identification remains explicit evidence without becoming a vulnerability.

Future service/version normalization, CPE matching, CVE intelligence, and CVSS data can feed the same structured finding model without coupling those concerns to the scanner.

### Risk scoring

Finding scores are transparent:

```text
INFO     0
LOW      2
MEDIUM   5
HIGH     8
CRITICAL 10
```

The host score is the highest score among confirmed findings. Informational observations do not inflate risk. A finding represents something supported by a completed check and deserves review; it does not prove exploitability.

### Protocol-check capabilities

The assessment layer also includes safe, modular checks for:

- SSH banners and protocol evidence
- HTTP response status, redirects, server metadata, and security-header observations
- DNS response and recursion flags
- RDP negotiation response
- SMB and TLS checks from Milestone 3

Services without a registered module remain attack-surface observations. Their presence alone does not create a vulnerability finding or increase risk.

Software evidence can be passed to provider-based potential vulnerability correlation. Correlations are reported as `POTENTIAL` and never promoted to confirmed findings or risk without direct evidence.

### TCP state and service evidence

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

For an authorized test host, compare:

```sh
netsentry scan 192.0.2.201 --profile common
netsentry assess 192.0.2.201 --profile common
netsentry assess 192.0.2.201 --profile common --json
```

TCP/22 should remain visible. A no-response result should show `unknown`, preserve
Nmap's raw `filtered/no-response` evidence in JSON, and cause no SSH security check.
After connectivity is restored, an SSH identification banner should permit the
SSH check. SMB on 445 and demonstrated TLS/HTTP on 8443 should continue working.

### Observed risk and coverage

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

### SSH algorithms, RDP negotiation, and version ranges

SSH banner identity and security enumeration are independent facts. The SSH
check exchanges identification and KEXINIT messages only after a valid SSH banner
has been received. It collects advertised KEX and host-key algorithms, directional
ciphers/MACs, compression lists, and extension markers without completing key
exchange or authenticating. Advertised algorithms do not prove a particular
session used them or reveal host-key size. Banner-only and failed enumeration
results retain SSH identity but make configuration assessment `INCONCLUSIVE`.
The direct `probe_ssh` API defaults to banner-only behavior for compatibility;
checks request `enumerate_security=True` and reuse that collected result.

The intentionally small finding policy covers `diffie-hellman-group1-sha1` and
`rsa1024-sha1` ([RFC 9142](https://www.rfc-editor.org/rfc/rfc9142.html)), and
`arcfour`, `arcfour128`, `arcfour256` in either cipher direction
([RFC 8758](https://www.rfc-editor.org/rfc/rfc8758.html)). Unknown algorithms are
observations. Duplicate names do not duplicate a finding within a category.
Other host-key, cipher, and MAC policies remain outside this initial rule set.

RDP retains each requested mask, selected protocol or failure code, flags, raw
response, interpretation, and optional TLS certificate metadata. It uses at most
three connections under one deadline: the existing TLS/CredSSP offer, a TLS-only
attempt when CredSSP was selected, and a legacy attempt only after explicit
SSL-not-allowed evidence. Selection is specific to an attempt, not an inventory.
An explicit HYBRID_REQUIRED_BY_SERVER failure supports `nla_required: true`;
CredSSP selection supports `nla_available: true`. TLS-only acceptance does not
become an "NLA disabled" finding. Unknown/reset/timeout results leave capability
fields unknown. Contradictions retain their attempts and produce an inconclusive
summary. The old `nla` field is deprecated and remains unset. Raw selected values
outside the implemented set remain visible with an inconclusive interpretation.

TLS metadata is collected on the negotiated RDP connection, with certificate
verification explicitly disabled for observation. No HTTP request, CredSSP
message, or desktop session follows. Certificate/handshake failure does not erase
RDP identity. Nested TLS is recorded inside RDP evidence and does not dispatch
standalone HTTPS checks. RDP negotiation produces observations in this chunk.
The [Microsoft negotiation specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817)
defines selections and their scope.

Network exchanges use a single per-probe deadline (existing three-second default;
one second for the unhinted SSH fallback). SSH is capped at a 4 KiB banner read,
16 packets, 35,000-byte packet lengths, 64 KiB total received, and bounded algorithm
lists/names. RDP frames are capped at 4 KiB. A slow response can legitimately
remain inconclusive rather than trigger unbounded retries.

#### Offline affected-version definitions

`StaticVulnerabilityProvider` now accepts `VulnerabilityDefinition` records rather
than preconstructed correlation results. Each definition supplies product,
optional vendor/variant, one or more explicit `AffectedVersionRange` records,
source/reference, and optional severity/CVSS. Use `exact`, or `lower`/`upper` with
explicit inclusivity flags. Multiple ranges are alternatives. Unbounded,
malformed, or legacy string ranges produce an `INDETERMINATE` diagnostic, never a
product-only positive. The supported schemes are intentionally limited:

- `numeric`: dotted nonnegative integers, at most 16 components, each at most
  16 digits; trailing zero components compare equally. Leading zero components
  are rejected except for zero itself.
- `semver`: strict three-component SemVer, prerelease precedence, and ignored
  build metadata for ordering/equality. No coercion of vendor suffixes.
- `openssh`: explicit `upstream`, `portable`, or `windows` variant required on
  the definition and evidence. Portable versions require a `p` suffix; upstream
  and Windows versions use the two-component upstream version within their own
  variant. These variants are never automatically equated.
- `opaque`: explicit exact literal matching only, no range ordering.

Version strings are bounded to 256 printable ASCII characters. Numeric/SemVer
comparators are not universal distribution/package comparators. Unknown vendor
information cannot satisfy a vendor-specific definition. OpenSSH banner shape
provides variant evidence, not a Windows OS build number or patch assurance.

Each positive result binds the current software observation to a matching range
and is always `POTENTIAL`; provider-boundary checks enforce structured applicability
and never reuse a stale observation or CONFIRMED status. No correlation contributes
to observed or overall risk. `affected_range` is retained as a display string;
`matched_range` is the machine-readable range, with source, reason, vendor/variant,
and evidence retained in JSON.

Correlation runs after endpoint checks. `software_evidence` preserves each distinct
software observation, including separate HTTP Server header products and versions.
The legacy combined HTTP fingerprint display remains for compatibility but is not
used as correlation input. Conflicting versions for the same product remain in
JSON and suppress automatic correlations, with an `INDETERMINATE` explanation in
`correlation_diagnostics`. Distribution backports and undisclosed vendor patches
cannot be established from a banner. No live vulnerability service or production
CVE dataset is bundled; providers remain explicitly injected by callers.

Existing port-state, dispatch, endpoint-count, and risk semantics are preserved.
No new dependency or global Nmap version-detection flag is introduced.

#### Assessment terminal modes

`netsentry assess TARGET` now defaults to a compact scanner-oriented report.
Use `-v` or `--verbose` for interpreted analyst details, including scanner-reported
and normalized port states, identification attempts, protocol/certificate properties,
software observations, correlation diagnostics, and coverage evidence.

Plain service names indicate confirmed identities. Parenthesized names such as
`(ssh)` are service hints only. Displayed filtered ports require explicit scanner
`filtered` evidence; the internal JSON `state` may still be `unknown` when the
scanner reason is `no-response`. Ambiguous scanner states stay inconclusive.
Closed and inconclusive ports are counted rather than individually listed;
filtered lists show at most eight endpoints plus an omitted count.

Check statuses describe completion, not a security pass. Findings appear first
when present; potential CVEs remain separately labeled and do not affect risk.
Observed risk describes assessed evidence only. Incomplete coverage remains visible.

Terminal formatting has intentionally changed. JSON is the stable automation
interface: `--json` retains its schema and semantics and takes precedence over
`--verbose`. Rendering does not alter assessment evidence. The `scan` and
`discover` terminal formats are unchanged.

#### Bundled real CVE correlations

Normal `netsentry assess TARGET --profile common` and `--discovered` assessments
load a small offline dataset automatically. Library callers still choose their
own provider; `None` continues to disable correlation.

Dataset revision **2026-09-11.1**, reviewed **2026-09-11**, contains **2 real CVE
definitions** for Apache HTTP Server:

| CVE | Affected versions | Authoritative source |
| --- | --- | --- |
| CVE-2021-41773 | 2.4.49 only | [Apache advisory](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773) |
| CVE-2021-42013 | 2.4.49 and 2.4.50 only | [Apache advisory](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-42013) |

The exact product token `Apache` emitted by HTTP Server headers is supported,
with case-insensitive equality. No aliases were added: other product labels,
including a scanner's `Apache httpd`, are not silently rewritten.
Severity is Apache's advisory classification; no numeric CVSS is invented.

These are version-based POTENTIAL correlations, not findings or exploitability
claims. File disclosure depends on directory access controls; code execution
also depends on CGI configuration. Each result retains these limitations and
its advisory reference. Banner accuracy, configuration, and downstream patch
status are unverified. Unknown versions and unsupported version suffixes do not
match. Potential correlations never change observed or overall risk.

Coverage is deliberately limited to these two advisories. There are no OpenSSH
definitions in this revision: server/client, OS, and configuration applicability
must be reviewed before adding any. No matches does not mean a host is free of
vulnerabilities. No live CVE queries, downloads, or automatic updates occur.

Metadata is available in `--verbose` output and in the packaged
`netsentry/data/cves.json`. Maintainers update this file through reviewed changes:
verify authoritative affected versions and limitations, increment the revision,
update the review date/count, and add boundary regressions. Invalid or missing
bundled data fails assessment visibly before scanning; it is never replaced
with an empty provider. JSON correlations add a `limitations` field when supplied;
existing fields and risk semantics are preserved.

#### DNS recursion evidence

DNS `recursion_available` is retained for compatibility and means **recursion
advertised** (RA), not demonstrated. The current bounded probe queries
`example.com. IN A`, validates the response/question and record boundaries, and
preserves flags, transport, answer records, and raw response bytes. It does not
establish whether an answer was cached, local, forwarded, or recursively fetched.

`recursion_demonstrated` and `open_recursion_confirmed` remain null. The DNS
configuration assessment is INCONCLUSIVE even when DNS identity is confirmed.
RA, NOERROR, authoritative answers, and public-looking answers generate no
open-recursion finding and make no risk contribution. A DNS-only assessment can
therefore have UNKNOWN observed risk because no security check completed.
Controlled recursion and client-access-policy validation are deferred.

### Risk and actionable remediation

The centralized policy in `analysis/risk.py` preserves severity scores:
INFO **0**, LOW **2**, MEDIUM **5**, HIGH **8**, CRITICAL **10**. Observed risk is
the maximum accepted finding; without findings it is INFO/0 only if a security
check completed, otherwise UNKNOWN/null. Overall risk is UNKNOWN/null unless
assessment status is COMPLETE. COMPLETE describes the assessed scan coverage,
not a guarantee that every possible vulnerability was checked.

Confidence is the existing LOW/MEDIUM/HIGH evidence confidence, not a probability.
It affects action priority and tie-breaking, not severity or numeric score.
Base priorities are INFORMATIONAL, LOW, NORMAL, HIGH, and IMMEDIATE respectively.
IMMEDIATE requires a CRITICAL finding with HIGH confidence and direct
configuration or demonstrated-vulnerability evidence; otherwise CRITICAL remains
HIGH priority. A HIGH-confidence MEDIUM finding becomes HIGH priority only when
explicit evidence establishes external reachability or critical service importance.
Private/local exposure never discounts severity. Within a priority, severity,
confidence, evidence kind, supported exposure and importance determine ordering;
endpoint and rule identifiers break ties deterministically.

The scanner currently cannot establish Internet reachability or business importance.
Those nullable finding fields can be supplied by integrations with explicit
supporting evidence; an IP address or conventional port number is never used to
infer them. Configuration evidence is not evidence of exploitation. Potential
CVE severity orders separate advisory-validation work and never enters finding
scores, remediation actions, or host risk.

Each finding preserves its legacy remediation string and adds structured
`remediation_details`, `remediation_priority`, and `risk_context`.
SMBv1/signing, TLS validity, and obsolete SSH algorithm findings have specific
guidance and safe verification steps. Unknown/custom rules retain their original
guidance with an explicitly LOW-applicability fallback. Applicability confidence
describes how well guidance fits the observation, not proof that a rollout is
safe. Disruption-free changes remain null because deployment compatibility and
restart behavior have not been established.

Host JSON adds `overall_risk` (same values as legacy `risk`),
`risk_explanation`, `priority_actions`, and `correlation_validation_actions`.
Existing risk/coverage keys and null semantics remain unchanged. Correlation
validation instructs the operator to confirm installed version, vendor/variant,
downstream patches and advisory conditions before deciding whether to remediate.

Compact reports show at most five priority actions near the top. Full guidance
and all actions are in verbose/JSON. Network summaries show hosts with findings,
incomplete assessments, unknown observed risk, and the highest-priority actions.
Hosts rank primarily by observed score, then finding priority/confidence; unknown
hosts remain explicitly unknown and are counted separately, never labeled safe.
No scanner behavior, protocol requests, dependencies, or automated remediation
actions were added.

### Human-readable verbose reports

Verbose expands the normal report sections with interpreted protocol properties,
service/check evidence, remediation and validation guidance, status reasoning,
and coverage statistics. Nullable properties display as Unknown. Probe failures
and contradictions remain visible; long detail lists are bounded with omitted
counts pointing to JSON.

Raw XML, packet hex, scanner blobs, and full serialized models are available
through `--json`, not verbose terminal output. Unknown/custom check detail objects
are not dumped; check status and reason remain visible. JSON continues to take
precedence over `--verbose`. No debug mode was added.

Identification now follows recognized service hints before conventional ports.
SSH is selected for SSH hints, SMB for 445/139, RDP for 3389, HTTP for 80/8080,
and TLS followed by HTTP for 443/8443. Existing confirmed identities still govern
security-check dispatch. Known unsupported hints such as MSRPC do not trigger
an unrelated probe sweep. Ambiguous endpoints retain one bounded SSH banner
fallback; failure of a known hinted protocol does not trigger exhaustive probing.
A misleading hint can therefore leave identity unconfirmed. Hints never establish
identity or findings by themselves.

Verbose port evidence uses concise state/reason descriptions and groups routine
filtered/no-response or closed results sharing the same evidence. Open ports,
confirmed identities, unusual states, contradictory state evidence and identification
attempts retain individual details. Full raw/normalized fields remain in JSON.

Verbose cleanup: the bundled dataset revision/count and applicable-match count
appear in a lower-priority CVE CORRELATION section. Full catalog metadata remains
in the packaged dataset. Scanner filtered/no-response counts explicitly explain
why NetSentry retains UNKNOWN; normalized state fields are unchanged.

During SMB probing, the specific smbprotocol receive-worker exception log is
suppressed through disconnect because the same exception is returned to NetSentry
and preserved as structured probe-failure evidence. The temporary logger filter
is removed afterward. Other library errors and NetSentry exceptions are not
suppressed; application stderr is not redirected.

### Bounded host identity follow-ups

The assessment CLI (including discovered-host and JSON modes) reuses scanner,
SMB, TLS, RDP, and software observations before scheduling identity follow-ups.
This identity layer does not change port normalization, security checks, accepted
findings, coverage, or risk. Library `HostAssessment.host_identity` remains optional;
`enrich_identity` can collect passive evidence with no resolver, or use an injected
`IdentityResolver`. Existing assessment JSON fields are preserved. The optional
`host_identity` object adds `attributes`, raw `observations`, and `attempts`.

Identity follow-ups are selected only for observed open TCP endpoints with relevant
service evidence or conventional hints, with at most three probes and an eight-second
host budget. Each active TCP probe uses the remaining budget capped at three seconds.
No endpoint is retried during the same resolution. Missing implementations and
exhausted budgets have explicit reasons. Built-in probe reads and writes use the
remaining deadline; injected probes must honor the supplied timeout.

- RDP follows a CredSSP selection with TLS and an NTLM NEGOTIATE request. It stops
  after reading the challenge; no credentials or AUTHENTICATE message are sent.
  Certificate and NTLM observations survive a subsequent failure independently.
- NetBIOS node status uses **IPv4 UDP/137**, prompted by relevant open SMB/NetBIOS
  endpoints. This is not IPv6 NetBIOS support and does not reinterpret TCP/139 state.
- DCE/RPC requests one NDR32 endpoint-mapper page of at most eight entries. It
  attempts to release a returned enumeration context, never follows further pages,
  and preserves interface UUID/version and annotation evidence. Fragmented,
  authenticated, oversized, or unsupported replies remain inconclusive. ONC RPC
  (`rpcbind`) does not select this DCE/RPC probe.

Identity states are CONFIRMED, PROBABLE, UNRESOLVED, or CONTRADICTORY. Confirmation
requires an explicitly authoritative observation or agreeing independent sources
of at least medium confidence. Multiple NTLM fields share one source, certificate
subjects share one certificate source, NetBIOS names share one node-status source,
and RPC entries share one mapper source. Scanner/discovery DNS names do not count
as independent votes. Source grouping is deliberately conservative: certificates
on multiple services and repeated NTLM responses do not multiply confirmations.
Conflicts retain every observation; unresolved fields carry explanations and attempts.

SMB dialects are protocol versions, never Windows versions. Windows-compatible
protocols and NTLM version data support OS hypotheses, not edition or patch-state
claims. NTLM build values are retained verbatim. Automatic OS correlation is withheld
when builds conflict or Windows product identity is unconfirmed. No Windows release
mapping or new CVE definitions were added; provider applicability rules and POTENTIAL
status remain unchanged. The bundled curated dataset has no Windows coverage, and
absence of a match does not establish absence of vulnerabilities.

Verbose HOST IDENTITY output separates resolved attributes, source/probe/endpoint
observations, and reused/new attempts. Compact reports do not display these diagnostics.
Raw identity observations that are not resolved attributes (GUIDs, banners, protocol
versions, RPC interfaces) remain available in JSON and interpreted verbose evidence.
Unauthenticated names may be configured, shared, or emulated; OS edition and patch
state commonly remain unresolved. No live-host interoperability retest is implied
by the in-memory protocol fixtures.

The RPC fixtures use the NDR32 endpoint-entry and tower layouts described in the
[Impacket endpoint-mapper implementation](https://github.com/fortra/impacket/blob/master/impacket/dcerpc/v5/epm.py).
Pytest collection is restricted to `tests/` to keep unrelated workspace projects
outside NetSentry validation.

Host-identity reporting distinguishes unresolved goals from network activity.
When no applicable identity probe exists, the explanation appears under the
specific unresolved attribute. JSON retains the legacy `probe: "planner"`,
`status`, `attributes`, and `reason` fields for compatibility and adds
`kind: "unresolved_goal"`; these records do not represent network requests.
Older planner records remain readable by the verbose renderer.

Software product and version observations from the same response share endpoint,
source, probe, and independence key. HTTP (including every product token in a
Server header), SSH, and Nmap software evidence keep their collected provenance.
When source host/port information is missing, the identity endpoint stays null;
no `host:None` endpoint is manufactured.

HTTPS denotes the service stack **HTTP over TLS**. HTTP is the application layer;
TLS supplies the transport/security layer. Verbose output labels these roles,
while JSON keeps existing `service: "https"`, `confirmed_service`, and individual
HTTP/TLS identity evidence. The stack and its layers are not three independent
host-identity confirmations. No source-independence or resolution rules change.
Coverage's “open ports without confirmed service identity” refers to endpoint
protocol/service identification, not unresolved hostnames or operating systems.
Windows-associated banners, SMB dialects, and RPC annotations do not establish
Windows identity, edition, patch state, or CPE merely by appearing together.

### Deterministic adaptive enumeration foundation

`netsentry assess` now selects identity follow-ups through a deterministic planning
loop in `netsentry/planning/`, including discovered-host assessment. The original
`IdentityResolver` remains available to library callers. Initial scanning, protocol
security checks, findings, scoring, remediation, and CVE policy remain separate.
No LLM, API client, command runner, authentication, or exploitation was added.

The loop derives `KnowledgeState` from the current assessment and `HostEvidence`:
confirmed/probable/conflicting facts, endpoints and protocol layers, software
observations, potential CVE candidates, attempts, unresolved goals, source keys,
and remaining planning budget. It does not promote hypotheses. It rebuilds this
view after each result. Goals distinguish hostname, OS family/build, service and
product identification, software version conflicts, and CPE candidates. Missing
versions associated with potential CVE candidates have higher priority; this goal
weight has no effect on vulnerability applicability or risk.

`ActionRegistry` holds trusted `ActionDefinition` objects with stable IDs, evidence
outputs/source keys, service/port/address-family requirements, prerequisites,
heuristic information value, costs, timeout, network allowance, safety class,
authentication requirement, repeatability metadata, and a handler. Its `catalog()`
exports JSON-safe descriptors without handler references. A future AI adapter can
receive this catalog and a knowledge snapshot, never implementation handles.

The initial adapters reuse existing probes:

| Action | Applicability | Evidence and limits |
| --- | --- | --- |
| `netbios_identity` | Open SMB/NetBIOS endpoint; IPv4 only | One UDP/137 node-status request; hostname/workgroup/MAC |
| `rdp_identity` | Open RDP endpoint | Existing bounded TLS/CredSSP probe; stops after NTLM challenge |
| `rpc_identity` | Open MSRPC endpoint | Existing single NDR32 mapper page, at most eight entries; interface/annotation evidence |

The registry deliberately does **not** advertise RPC as an OS-edition probe. RPC
may help identify an unknown open service, but already-known RPC inventory can be
too low-value to justify another request. Existing SMB/TLS/RDP metadata is collected
before planning. No additional SMB negotiation is introduced.

Both future planners and `DeterministicPlanner` implement the `Planner` protocol,
returning only `ProposedAction(action_id, port, reason)`. The target host comes from
the assessment; timeout and transport come from policy/registered capabilities.
A separate executor independently rechecks applicability, prerequisites, policy,
usefulness, previous attempts, and budget. It rejects unregistered IDs and invalid
parameters. Result ingestion validates the structured result, output attributes,
source keys per output attribute, endpoint, probe identity, and evidence bounds.
TLS certificate evidence cannot act as an independent vote for an NTLM OS version. Network observations
cannot claim authoritative status at this boundary. Partial valid evidence from
inconclusive results is retained. Unexpected programming exceptions remain visible.

Ranking is a transparent integer heuristic: sum useful goal importance, double
contradiction weight, multiply by the action's information-value weight, then
subtract declared cost, network allowance, noise, and timeout penalties. Evidence
from already-used sources is treated as redundant. Actions with no positive net
value are not selected. Ties use action ID then port, independent of registry
insertion order. These weights are neither confidence percentages nor risk scores.

Automatic execution is restricted to LOCAL, PASSIVE, and SAFE_ACTIVE actions that
require no authentication. AUTHENTICATED, INTRUSIVE, and EXPLOITATIVE are metadata
placeholders; even an expanded policy allowlist cannot enable them. Registry code
is trusted application code, not a sandbox for arbitrary plugins or generated code.

Default planning limits are three actions, eight seconds total, three seconds per
action, and twelve logical network-request units. An optional noise budget can
further restrict execution. Requests are conservatively reserved **before** a
handler runs, including failed attempts: NetBIOS reserves one unit, RDP four, RPC
three. These units represent bounded protocol exchanges, not an IP-packet counter;
TCP/TLS implementation packets are not counted individually. Built-in handlers
honor the supplied deadline. Custom trusted handlers must honor the same contract;
there is no process-isolation watchdog to forcibly terminate arbitrary Python code.
Repeatable metadata cannot override the current one-attempt-per-action/endpoint
limit. A separate iteration ceiling prevents a faulty replacement planner looping.
The budget applies to this follow-up phase, not the preceding scanner/check phase.

Optional assessment JSON field `planning_trace` records goals, all candidates and
rejections, selection/explanation, expected outputs, declared costs, budget snapshots,
executor decision, result, evidence/goal changes, and stopping reason. Existing
assessment fields remain intact. Actual elapsed-time values naturally differ across
runs. Verbose `ENUMERATION PLANNING` interprets the trace; compact output does not
print it. Goals can remain unresolved when no useful permitted capability exists.

This remains a bounded capability catalog. Acquisition adapters now ingest host
observations and canonical SoftwareEvidence; see the acquisition milestone below.
Future CPE and CVE-investigation adapters must use those canonical pipelines rather
than add a competing fact store. Registering a goal does not implement its capability. Before adding
an AI planner, live-test selection/deadlines, review capability costs and provenance
contracts, implement needed evidence adapters, and validate an untrusted JSON proposal
decoder plus adversarial policy-boundary tests. The executor and policy ceiling must
remain outside the AI adapter's control.

### Evidence acquisition and active fingerprinting

The existing registry now includes `http_fingerprint`, `https_fingerprint`, and
`ssh_fingerprint`. These are SAFE_ACTIVE capabilities with declared endpoints,
outputs, source categories, prerequisites, costs, reuse constraints and discrimination
metadata. Selection and validation stay in the generic planner/executor; main.py has
no protocol-specific acquisition logic. Completed HTTP/SSH checks and equivalent
software-source evidence suppress redundant acquisition.

HTTP reads one response of at most 16 KiB from `GET /`, without redirects, crawling,
credentials or arbitrary paths. HTTPS uses the same bounded HTTP parser over TLS,
retaining handshake, cipher, subject, issuer and bounded SAN observations. A shared
absolute deadline clamps connection, handshake, send and receive operations. A
successful TLS observation survives a later HTTP failure. SSH reuses the existing
bounded identification/KEXINIT probe and stops before authentication; a usable banner
survives incomplete algorithm enumeration. No new SMB/RPC authentication exchange,
aggressive OS scan, external callback or exploit validation was added.

`AcquisitionResult` extends the existing identity-probe result with a tuple of
`SoftwareEvidence` and optional logical-request accounting. It is not another software
model. Canonical software evidence has additive action ID, raw value, normalization
status, independence key and limitations fields alongside existing vendor, product,
version, variant, protocol and endpoint fields. Exact product names are retained;
there are no fuzzy aliases. Ambiguous version strings keep `raw_version` and yield
`version: null`. Product vendors describe the software project, not a proven downstream
package vendor. No CPE is manufactured from these observations.

The executor validates bounded text fields, endpoint/action provenance, registered
source categories, result sizes and declared request allowances before ingestion.
Validated software updates the planning view, so an acquired version can resolve a
version goal and stop further acquisition. At enrichment completion it enters the
existing version-aware provider and fresh POTENTIAL binding. Conflicting versions
withhold automatic matches; a superseded candidate is preserved in diagnostics with
the original observations. None of this creates security findings or risk scores.
Acquisition does not rerun security checks or rewrite the initial port-state snapshot;
new service demonstrations remain available in host evidence and planner knowledge.

OS hypotheses reuse HostObservation with `hypothesis: true`, explicit supporting
records, contradictory candidates, confidence and limitations. Existing Nmap OS
metadata, explicit SSH OS-flavored banners, and exact Microsoft-IIS headers may supply
reported clues. SMB dialect + NetBIOS name + RPC interface evidence supports only a
Windows-compatible hypothesis. RPC annotations, GUIDs, port numbers, generic software
names and protocol versions never establish Windows edition/build or patch state.
All derived hypotheses contribute zero independent confirmations. Genuine conflicting
observations remain retained. The planner awards a transparent discrimination bonus
to eligible capabilities offering a new source for an unresolved OS hypothesis or
conflict; repeating the same correlated source earns no bonus.

TCP/139 is explicitly UNAVAILABLE for SMB negotiation. The installed `smbprotocol`
transport implements Direct TCP, while 139 requires NetBIOS session establishment.
NetSentry rejects this unsupported transport before opening a connection rather than
sending an invalid Direct TCP negotiate. TCP/445 security assessment is unchanged.
See Microsoft's [SMB transport documentation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/f906c680-330c-43ae-9a71-f854e24aeee6)
and [Direct SMB hosting overview](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/direct-hosting-of-smb-over-tcpip).

Discovery and identity enrichment share a local MAC/OUI lookup. Colon, hyphen,
compact and dotted forms normalize to lowercase colon-separated MACs. Malformed,
multicast, unspecified and locally administered addresses do not produce manufacturer
claims. Missing local prefixes are distinguished from unavailable databases. The
installed Scapy database in this development environment resolves a known Cisco OUI
but has no entry for `c4:ff:99`; the supplied MAC remains unresolved locally. No lookup
service, dataset download, or runtime network dependency was added. Database versions
on other installations may differ. An interface manufacturer never proves an OS.

Budgets still reserve the full declared allowance before execution. HTTP reserves one
logical exchange, HTTPS two, SSH two; these are exchanges, not literal packets.
Acquisition results report attempted logical units where available, elapsed execution
time and the supplied timeout. Existing adapters may report unknown actual units;
there is no fabricated packet count or refund for failures. All existing action-count,
wall-clock, repetition, safety and authentication gates remain enforced.

JSON retains the complete planning history and additive evidence/accounting fields.
Verbose output deduplicates identical action/endpoint/rejection messages while keeping
changed reasons, selections and results. Compact output remains concise. There is no
LLM integration. OS family/build can still remain unresolved on a host exposing only
SMB/NetBIOS/RPC: this milestone does not manufacture facts to close a capability gap.

## Current Limitations

- NetSentry requires a local Nmap installation for scanning and assessment.
- Active identification is limited to registered bounded probes; it is not universal
  service detection, and ambiguous or failed evidence remains inconclusive.
- The bundled offline CVE dataset is intentionally small. Correlations are potential,
  version-based leads and do not prove applicability, exploitability, or patch state.
- DNS probing does not demonstrate open recursion, and the scanner cannot establish
  Internet reachability or business importance by itself.
- Identity evidence may remain probable, unresolved, or contradictory. Protocol and
  banner clues do not establish an operating-system edition or patch state.
- NetSentry does not exploit vulnerabilities, execute payloads, attack credentials,
  crack Wi-Fi, establish persistence, evade defenses, or modify remote systems.

## Roadmap

Future work may expand reviewed evidence adapters, protocol coverage, identity
resolution, vulnerability intelligence, and planner integrations. Any such work must
preserve the existing provenance, bounded-execution, policy, and conservative
correlation model. Roadmap items are not current capabilities.

## Authorized Use

NetSentry is intended for systems owned by the operator, systems for which the
operator has explicit authorization to test, and legitimate security research or
defensive assessment conducted within an approved scope. Operators are responsible
for understanding the environment, obtaining permission, and respecting applicable
policies and law.

## License

No license file is currently included. Until the project owner selects and adds a
license, the repository's source remains subject to the default protections of
copyright law; public visibility alone does not grant reuse rights.

For a permissive open-source release, common choices include:

- **MIT:** a short permissive license allowing use, modification, and redistribution
  with preservation of the copyright and license notice and a warranty disclaimer.
- **Apache License 2.0:** similarly permissive, with an explicit patent license,
  patent-termination terms, and notice requirements.

The project owner should choose the license that matches the intended contribution,
redistribution, and patent policy before the public release.
