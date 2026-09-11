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

Assessment JSON preserves the host classification, scan profile, requested ports, reachability, probe status, attack-surface observations, security-check results, coverage, findings, and risk.

## Assessment states

- `COMPLETE`: all applicable checks for the available evidence completed.
- `LIMITED`: checks were unavailable or failed, or the scan profile found no ports without proving the host has none.
- `UNREACHABLE`: the target could not be reached.
- `ERROR`: reserved for assessment errors that prevent meaningful analysis.

`Risk: UNKNOWN` is used for limited assessments. A clean `0/10` result is reserved for a completed assessment with sufficient coverage and no confirmed findings.

## Analysis architecture

The pipeline is:

```text
Discovery -> Nmap enumeration -> scan evidence -> attack-surface observations
          -> service-aware defensive checks -> confirmed findings -> risk
```

The analysis package uses stable, independently testable checks. Current default checks identify applicable SMB, TLS, HTTP, and DNS checks, but report them as unavailable when no safe protocol-specific probe is configured. This preserves uncertainty instead of turning service exposure into an unsupported vulnerability claim.

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
