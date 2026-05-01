# deadband

Read-only OT vulnerability scanner. Discovers industrial controllers, fingerprints firmware, matches against the [CISA ICS Advisory](https://www.cisa.gov/news-events/ics-advisories) feed (3,600+ advisories), and produces a self-contained HTML report.

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

Every probe is read-only by construction. None require authentication. Tests assert no unexpected bytes hit the wire.

| Mode | Port | Vendors |
|---|---|---|
| `cip` | UDP 44818 | Rockwell Automation |
| `s7` | TCP 102 | Siemens (S7-300/400/1200/1500) |
| `modbus` | TCP 502 | Schneider, ABB, Delta, Moxa, Phoenix Contact, WAGO, Emerson, Yokogawa, Eaton |
| `melsec` | TCP 5007 | Mitsubishi (iQ-R/F, Q, L, FX5) |
| `fins` | UDP 9600 | Omron (CJ, CP, CS, NJ, NX) |
| `srtp` | TCP 18245 | Emerson / GE (PACSystems, Series 90, VersaMax) |
| `opcua` | TCP 4840 | cross-vendor industrial servers |
| `haas` | TCP 5051 | Haas Automation NGC controllers |
| `fanuc` | TCP 21 | Fanuc CNC + R-30iB robots (FTP banner) |

`--mode auto` (default) runs all of the above concurrently and merges results.

**BACnet/IP** lives behind a build tag — `go build -tags bacnet ./cmd/deadband` — and is excluded from default builds.

**Fanuc FOCAS2** (TCP/8193) is stubbed pending live-device access; the FTP banner-grab handles common fingerprinting today.

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
| empty (default) | Try the deadband-hosted snapshot, fall back to per-file CSAF |
| `github` | Force per-file fetch from `cisagov/CSAF` |
| `https://...` | Specific snapshot URL with `.sha256` verification |
| `/local/path/` | Local CSAF mirror (full air-gap) |

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
pkg/discover/              Active discovery (CIP, S7, Modbus, MELSEC, FINS, SRTP, OPC UA, Haas, Fanuc)
pkg/inventory/             CSV / JSON / flat parsing
pkg/matcher/               Vendor, model, version matching
pkg/output/                Text, CSV, JSON, HTML, SARIF writers
pkg/server/                HTTP API + report export
pkg/updater/               CISA CSAF fetch (snapshot + per-file)
web/                       Next.js frontend
```

## License

MIT
