# deadband

Read-only OT, intralogistics/ASRS, HVAC/cold-chain, and CNC vulnerability scanner. Discovers industrial controllers, fingerprints firmware, matches against [CISA ICS Advisories](https://www.cisa.gov/news-events/ics-advisories), OASIS CSAF 2.0 ROLIE feeds (CERT@VDE, Beckhoff, SICK, Pilz, WAGO, Festo, Phoenix Contact, Weidmüller, TURCK, Lenze, Pepperl+Fuchs), and targeted NVD 2.0 OEM advisories, and produces a self-contained HTML report.

No agent. No cloud. No telemetry. No writes to OT devices.

## Install

```bash
make deadband           # CLI only
make deadband-web       # CLI + embedded web UI
```

## Quick Start

```bash
# Refresh the advisory database (one-time)
bin/deadband --update

# Scan a network — auto runs every protocol concurrently
bin/deadband --cidr 10.0.1.0/24

# Single-protocol scan
bin/deadband --cidr 10.0.1.0/24 --mode haas

# Check a pre-collected inventory
bin/deadband -i devices.csv --min-cvss 7.0 --prioritize

# Export an HTML report for a customer engagement
bin/deadband -i devices.csv \
  --site-name "Acme Manufacturing" \
  --out-format html -o acme.html

# CI gate: exit 1 if anything HIGH-confidence matches
bin/deadband -i devices.csv --min-confidence high
```

## Discovery

### Targeted asset enrichment

The local web Assets page supports **Enrich missing details** and **Verify firmware update** for selected known EtherNet/IP endpoint assets. Preview the exact targets, requested fields, and traffic limits before execution. Results retain observations, identity conflicts, execution metrics, and before/after advisory assessments on the existing asset IDs. Subnet posture scanning is a separate, explicit discovery option.

The first bounded query profile is `enip-identity-tcp-v1`: one unicast TCP/44818 ListIdentity per endpoint, with no session registration, backplane enumeration, broadcast, or protocol fallback. Chassis-slot assets require a component-specific profile and are excluded from this identity workflow.

```bash
bin/deadband query plan --targets targets.json --purpose enrich -o plan.json
bin/deadband query run --plan plan.json --dry-run
bin/deadband query run --plan plan.json -o observations.json
```

See [targeted enrichment](docs/targeted-enrichment.md) for the target format, API, limits, and rollout details, and [platform cohesion](docs/platform-cohesion.md) for the remaining product improvements.

Every probe is read-only by construction. None require authentication. Tests assert no unexpected bytes hit the wire.

| Mode | Port | Vendors |
|---|---|---|
| `cip` | UDP/TCP 44818 | Rockwell, Beckhoff, SICK, SEW-EURODRIVE, Festo, Pilz, Cognex, Keyence, Danfoss, WAGO, ABB, Moxa |
| `s7` | TCP 102 (+ HTTPS/SNMP fallback) | Siemens (S7-300/400/1200/1500/ET200SP, incl. PUT/GET-disabled TIA Portal CPUs) |
| `modbus` | TCP 502 (Units 1, 255, 0) | Schneider, ABB, Danfoss, CAREL, Copeland, Vertiv, Interroll, Pulseroller, SEW-EURODRIVE, WAGO, Moxa |
| `bacnet` | UDP 47808 (+ routed MS/TP) | Johnson Controls, Trane, Carrier/Automated Logic, Siemens, Honeywell, Tridium, Danfoss, CAREL, Copeland, Vertiv/Liebert, Distech, Delta Controls, LOYTEC, SAUTER |
| `opcua` | TCP 4840 | KNAPP KiSoft, Swisslog, Dematic, Vanderlande, TGW, SSI Schaefer, AutoStore, Siemens, Beckhoff, B&R |
| `ads` | UDP 48899 / TCP 48898 | Beckhoff TwinCAT 2/3 IPCs & CX/C6xxx/CPxxxx shuttle controllers |
| `sick` | TCP 2111, 2112, 2122 | SICK SOPAS CoLa-A, CoLa-B, and CoLa-2 barcode scanners & LiDARs (`CLV6xx`, `MSC800`, `Lector`, `TiM`, `LMS`) |
| `fox` | TCP 1911 / TLS 4911 | Tridium Niagara Framework (`JACE-8000/9000`, Honeywell `WEBs-N4`, JCI `FX`, Distech `EC-Net 4`, Alerton, Vykon) |
| `ancillary` | HTTP/S 80, 443, 8080, 8443 | KNAPP KiSoft, Swisslog SynQ, Dematic, Interroll, Pulseroller, Danfoss `AK-SM`, Copeland `XWEB`, CAREL `Boss`/`pCOWeb`, Metasys, Tracer SC+, WebCTRL, Desigo CC, Vaisala `viewLinc`, Testo `Saveris`, ELPRO, APC `InRow`/`NetBotz`, Vertiv `Liebert`, Zebra `Link-OS` (HTTP only — never probes `TCP/9100`) |
| `melsec` | TCP 5007 | Mitsubishi (iQ-R/F, Q, L, FX5) |
| `fins` | UDP 9600 | Omron (CJ, CP, CS, NJ, NX) |
| `srtp` | TCP 18245 | Emerson / GE (PACSystems, Series 90, VersaMax) |
| `haas` | TCP 5051 | Haas Automation NGC controllers |
| `fanuc` | TCP 21 / 8193 | Fanuc CNC + R-30iB robots (FTP banner + FOCAS2) |
| `mazak` | HTTP 5000 / 80 / 8080 | Mazak Smooth CNC (MTConnect read-only `/probe`) |

`--mode auto` (default) runs all of the above concurrently and merges results, preserving multi-slot CIP chassis modules and routed BACnet MS/TP field controllers behind BACnet/IP routers.

## HTML Report

`--out-format html` produces a single-file report with no external resources. Everything is inline — open it on an air-gapped laptop, print it from a browser, attach it to an email.

Contents:

- Cover with site name (`--site-name`), generation timestamp, advisory DB version
- Executive summary (vulnerable / potential / OK / no-match) with a stacked bar
- Top risk items sorted by KEV + CVSS + EPSS
- Device assessment table with status badges
- Per-device vulnerability detail with CVEs, KEV/ransomware flags, remediation links
- Optional compliance mapping with `--compliance iec62443,nist-csf,nerc-cip`
- Print stylesheet — browser Print → Save as PDF gives a clean light-mode export

A regression test (`pkg/output/html_test.go`) asserts the rendered template carries zero external references.

## Web UI

```bash
bin/deadband serve         # API + UI on :8484
```

Four panes:

- **Dashboard** — exposure summary, site risk overview, top findings, Export Report button
- **Scan** — kick off discovery against a CIDR with any mode
- **Report** — sidebar action that downloads the HTML report
- **Settings** — advisory DB status + Update Now

Development with hot reload:

```bash
go run ./cmd/deadband serve   # API on :8484
cd web && npm run dev          # Frontend with /api/* proxy
```

## Advisory Database

`--update` resolves its source like this:

| `--source` value | Behavior |
|---|---|
| empty (default) | Fetch deadband-hosted CISA snapshot (falling back to `cisagov/CSAF`), plus live TLP:WHITE OASIS CSAF 2.0 ROLIE feeds (CERT@VDE, Beckhoff, SICK, Pilz, WAGO, Festo, TURCK, Lenze, Pepperl+Fuchs, Phoenix Contact, Weidmüller) and targeted NVD 2.0 OEM lookups (KNAPP, Dematic, Swisslog, Vaisala, Testo, ELPRO, Sensaphone, Distech, Belimo) |
| `github` | Force per-file fetch from `cisagov/CSAF`, plus OASIS CSAF ROLIE and targeted NVD 2.0 feeds |
| `https://...` | Specific snapshot URL with `.sha256` verification only (no external ROLIE/NVD calls) |
| `/local/path/` | Local CSAF mirror only (full air-gap isolation — zero outbound network calls) |

Set `DEADBAND_NVD_API_KEY` (optional) to increase NVD 2.0 rate limits during `--update`.

```bash
bin/deadband --update                                # default: snapshot + fallback
bin/deadband --update --source github                # force per-file
bin/deadband --update --source ./local-csaf-mirror   # air-gapped
```

For air-gap, copy the resulting database between hosts:

```bash
scp ~/.deadband/advisories.json analyst@isolated:~/.deadband/
```

## Input Formats

**CSV**:
```
Scanned IP,Device Name,Ethernet Address (MAC),IP Address,Product Revision,Serial Number,Status,Uptime
172.16.12.21,1756-EN2T/D,5C:88:16:C4:26:3C,172.16.12.21,11.002,D060925B,Run,"206 days, 03h:12m:20s"
```

**JSON**:
```json
[{"scanned_ip":"172.16.12.21","device_name":"1756-EN2T/D","product_revision":"11.002"}]
```

## Flags

### Discovery
| Flag | Default | Description |
|---|---|---|
| `--cidr` | | CIDR range |
| `--mode` | `auto` | See discovery table above |
| `--timeout` | `2s` | TCP/UDP scan timeout |
| `--http-timeout` | `5s` | HTTP scrape timeout |
| `--concurrency` | `50` | Concurrent workers |

### Check
| Flag | Default | Description |
|---|---|---|
| `--inventory` / `-i` | | Inventory file |
| `--format` | auto-detect | `csv`, `json`, `flat` |
| `--db` | `~/.deadband/advisories.json` | Advisory database |
| `--output` / `-o` | stdout | Output path |
| `--out-format` | `text` | `text`, `csv`, `json`, `html`, `sarif` |
| `--site-name` | | Site label for the HTML report cover |
| `--min-confidence` | `low` | `low`, `medium`, `high` |
| `--min-cvss` | `0.0` | Minimum CVSS v3 score |
| `--vendor` | | Filter to a specific vendor |
| `--prioritize` | `false` | Sort by risk score (KEV + EPSS + CVSS) |
| `--compliance` | | `iec62443,nist-csf,nerc-cip,all` |

### Update
| Flag | Default | Description |
|---|---|---|
| `--update` | | Refresh advisory database |
| `--source` | | See updater table above |
| `--since` | | Only fetch advisories after `YYYY-MM-DD` |
| `--skip-enrichment` | `false` | Skip KEV/EPSS fetch |

### Server
| Flag | Default | Description |
|---|---|---|
| `--serve` | `false` | Start the web UI + API |
| `--addr` | `:8484` | Listen address |

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No vulnerabilities matched |
| `1` | Matches found |
| `2` | Error (missing DB, bad input, parse failure) |

## Confidence Levels

| Level | Meaning |
|---|---|
| HIGH | Vendor + model exact match, firmware in advisory range (clean semver) |
| MEDIUM | Vendor + model match, version comparison ambiguous |
| LOW | Vendor match only, model is partial / wildcard |

## Safety

- Read-only probes — only documented identification reads or banner grabs
- No runtime internet calls — advisory data is fetched ahead of time via `--update`
- No authentication, no credential storage, no writes
- Safety banner on every entry point
- Public CISA data only (TLP:WHITE)

## Project Structure

```
cmd/deadband/main.go       CLI entrypoint
pkg/advisory/              Advisory DB load/save
pkg/asset/                 Asset inventory + vulnerability state
pkg/cli/banner.go          Safety banner
pkg/discover/              Active read-only discovery (CIP, S7, Modbus, BACnet, OPC UA, ADS, SICK, Niagara Fox, Ancillary WCS/BMS, MELSEC, FINS, SRTP, Haas, Fanuc, Mazak)
pkg/inventory/             CSV / JSON / flat parsing
pkg/matcher/               Vendor, model, version matching
pkg/output/                Text, CSV, JSON, HTML, SARIF writers
pkg/pcap/                  Passive Ethernet/VLAN PCAP dissection
pkg/posture/               Two-phase OT-safe subnet posture & IEC 62443 / NIST CSF / NERC CIP rules
pkg/server/                HTTP API + report export
pkg/updater/               CISA CSAF + OASIS ROLIE + targeted NVD 2.0 advisory ingestion
web/                       Next.js frontend
```

## License

MIT
