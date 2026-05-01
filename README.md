# deadband

**Read-only OT vulnerability scanning and reporting for mid-market manufacturers.**

deadband discovers industrial controllers on a network, fingerprints their firmware, and matches them against the [CISA ICS Advisory](https://www.cisa.gov/news-events/ics-advisories) feed (3,600+ advisories). It produces a self-contained HTML report you can hand to a customer at the end of an engagement. No agent, no cloud, no telemetry, no writes to OT devices.

v0.5 focuses on the job-shop / CNC market — sites that are too small for Dragos, Claroty, or Nozomi but now face CMMC 2.0 pressure. New in this release: **Haas Q-command** discovery, **Fanuc FTP-banner** fingerprinting, a polished HTML report, and a snapshot-based advisory updater that survives shop-floor egress filtering.

## Why deadband

There is no lightweight, offline-capable tool that says "here are the open CVEs against your machine tools" without a six-figure platform contract. deadband does it from a terminal, in a browser, or as a one-shot HTML deliverable, with full air-gap support and zero phone-home behavior.

## Safety

- **Read-only by construction.** Every probe issues only documented identification reads or banner grabs. Unit tests assert no unexpected bytes are written to fixture servers.
- **No external runtime calls.** Advisory data is fetched/cached separately via `--update`. The check pipeline runs offline.
- **No writes, no auth, no credential storage.** Refuses to log into anything.
- **Transparent.** Prints a safety banner at every entry point. Uses only public CISA data (TLP:WHITE).

## Quick Start

```bash
# Build
make deadband

# Fetch advisory database (one-time)
bin/deadband --update

# Auto-discover everything (CIP + S7 + Modbus + MELSEC + FINS + SRTP + OPC UA + Haas + Fanuc)
bin/deadband --cidr 10.0.1.0/24

# CNC-only modes (new in v0.5)
bin/deadband --cidr 10.0.1.0/24 --mode haas    # Haas NGC, TCP/5051
bin/deadband --cidr 10.0.1.0/24 --mode fanuc   # Fanuc FTP banner, TCP/21

# Existing PLC modes
bin/deadband --cidr 10.0.1.0/24 --mode cip     # Rockwell EtherNet/IP
bin/deadband --cidr 10.0.1.0/24 --mode s7      # Siemens S7comm
bin/deadband --cidr 10.0.1.0/24 --mode modbus  # Schneider, ABB, Delta, Moxa, etc.
bin/deadband --cidr 10.0.1.0/24 --mode melsec  # Mitsubishi
bin/deadband --cidr 10.0.1.0/24 --mode fins    # Omron
bin/deadband --cidr 10.0.1.0/24 --mode srtp    # Emerson/GE PACSystems

# Check a pre-collected inventory file
bin/deadband -i devices.csv --min-cvss 7.0 --prioritize

# Generate a client-deliverable HTML report
bin/deadband -i devices.csv \
  --site-name "Acme Job Shop" \
  --out-format html -o acme-report.html

# Fail CI if any HIGH-confidence vulns are found
bin/deadband -i devices.csv --min-confidence high
echo $?  # 1 = found, 0 = clean, 2 = error
```

## HTML Report (the deliverable)

The `--out-format html` writer produces a single-file, self-contained report — no CDN, no external fonts, no remote stylesheets. Hand it to a customer; open it on an air-gapped laptop; print to PDF from any browser.

What's in it:

- **Cover** with site name (`--site-name`), generation timestamp, advisory DB version
- **Executive summary** — counts of vulnerable / potential / OK / no-match with a stacked bar
- **Top risk items** — KEV + CVSS + risk-score sorted, top 5
- **Device assessment table** — one row per device with status badges
- **Vulnerability details** — per-device advisories with CVSS, KEV/ransomware flags, CVEs, remediation links
- **Compliance mapping** (optional, with `--compliance iec62443,nist-csf,nerc-cip`)
- **Print stylesheet** — browser Print → Save as PDF produces a clean light-mode report

A regression test in `pkg/output/html_test.go` enforces self-containedness — no external references can sneak into the template.

## Web UI

Run the bundled web app for an interactive flow:

```bash
make deadband-web
bin/deadband serve
# http://localhost:8484
```

Four panes, intentionally small:

- **Dashboard** — exposure summary, site risk overview, top findings, **Export Report** button
- **Scan** — kick off a discovery run against a CIDR (Haas / Fanuc / CIP / S7 / Modbus / etc.)
- **Report** — sidebar action that downloads the HTML report
- **Settings** — advisory DB status + Update Now

For development with hot reload:

```bash
go run ./cmd/deadband serve   # API on :8484
cd web && npm run dev          # Frontend with /api/* proxy
```

## Advisory Database

`--update` fetches the latest CISA CSAF feed. Source resolution is layered:

| `--source` value | Behavior |
|---|---|
| empty (default) | Fetch deadband.org snapshot, fall back to per-file CSAF on failure |
| `github` | Force per-file fetch from `cisagov/CSAF` (slow, ~3,600 files) |
| `https://...` | Fetch a specific snapshot URL with `.sha256` verification |
| `/local/path/` | Use a local CSAF mirror (full air-gap) |

The default snapshot path is fast (one HTTP request), survives corporate egress filtering, and gracefully falls back to per-file fetch when unreachable. Air-gapped sites point `--source` at a copied CSAF mirror.

```bash
# Fast default path
bin/deadband --update

# Force per-file (when snapshot is stale or you want fresh-from-source)
bin/deadband --update --source github

# Air-gapped
scp ~/.deadband/advisories.json analyst@isolated:~/.deadband/
# or
bin/deadband --update --source ./local-csaf-mirror/
```

## Active Discovery Protocols

All probes are read-only. None require authentication.

| Protocol | Port | Vendors covered |
|---|---|---|
| **Haas Q-commands** | TCP 5051 | Haas Automation (NGC controllers) — *new in v0.5* |
| **Fanuc FTP banner** | TCP 21 | Fanuc CNC + R-30iB robot controllers — *new in v0.5* |
| CIP/EIP ListIdentity | UDP 44818 | Rockwell Automation |
| S7comm SZL Read | TCP 102 | Siemens (S7-300/400/1200/1500) |
| Modbus TCP Device ID | TCP 502 | Schneider, ABB, Delta, Moxa, Phoenix Contact, WAGO, Emerson, Yokogawa, Eaton |
| MELSEC/SLMP | TCP 5007 | Mitsubishi Electric (iQ-R/F, Q, L, FX5) |
| FINS | UDP 9600 | Omron (CJ, CP, CS, NJ, NX) |
| GE-SRTP | TCP 18245 | Emerson / GE (PACSystems, Series 90, VersaMax) |
| OPC UA | TCP 4840 | Cross-vendor industrial servers |

Auto mode (`--mode auto`, default) runs all of the above concurrently and merges results.

**BACnet/IP** is available behind a build tag for users who specifically need building automation:

```bash
go build -tags bacnet ./cmd/deadband
bin/deadband --mode bacnet --cidr 10.0.1.0/24
```

It was moved out of the default scope because it serves the building-automation market rather than manufacturing OT — different positioning, different buyers.

**Fanuc FOCAS2** (TCP/8193) is stubbed pending live-device access. Banner-grab fingerprinting handles the common cases today.

## Input Formats

**CSV** (default):
```
Scanned IP,Device Name,Ethernet Address (MAC),IP Address,Product Revision,Serial Number,Status,Uptime
172.16.12.21,1756-EN2T/D,5C:88:16:C4:26:3C,172.16.12.21,11.002,D060925B,Run,"206 days, 03h:12m:20s"
```

**JSON**:
```json
[{"scanned_ip":"172.16.12.21","device_name":"1756-EN2T/D","product_revision":"11.002"}]
```

**Flat text** (frozen as of v0.5 — no further extensions):
```
172.16.12.21,Rockwell,1756-EN2T,11.002
172.16.12.22,Haas,VF-2,100.21.000.1037
```

## Flags

### Discovery
| Flag | Default | Description |
|---|---|---|
| `--cidr` | | CIDR range (e.g. `10.0.1.0/24`) |
| `--mode` | `auto` | `auto`, `cip`, `s7`, `modbus`, `melsec`, `fins`, `srtp`, `opcua`, `haas`, `fanuc`, `http` (`bacnet` available with `-tags bacnet`) |
| `--timeout` | `2s` | TCP/UDP scan timeout |
| `--http-timeout` | `5s` | HTTP scrape timeout |
| `--concurrency` | `50` | Concurrent workers |

### Check
| Flag | Default | Description |
|---|---|---|
| `--inventory` / `-i` | | Path to device inventory file |
| `--format` | auto-detect | `csv`, `json`, `flat` |
| `--db` | `~/.deadband/advisories.json` | Advisory database |
| `--output` / `-o` | stdout | Output file path |
| `--out-format` | `text` | `text`, `csv`, `json`, **`html`**, `sarif` |
| `--site-name` | | Site label for the HTML report cover |
| `--min-confidence` | `low` | `low`, `medium`, `high` |
| `--min-cvss` | `0.0` | Minimum CVSS v3 score |
| `--vendor` | | Filter to a specific vendor |
| `--prioritize` | `false` | Sort by risk score (KEV + EPSS + CVSS) |
| `--compliance` | | Include mappings: `iec62443,nist-csf,nerc-cip,all` |

### Update
| Flag | Default | Description |
|---|---|---|
| `--update` | | Refresh advisory database |
| `--source` | | empty / `github` / URL / local path (see above) |
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
| `1` | One or more matches found |
| `2` | Error (missing DB, bad input, parse failure) |

## Confidence Levels

| Level | Meaning |
|---|---|
| HIGH | Vendor + model exact match, firmware in advisory range (clean semver) |
| MEDIUM | Vendor + model match, version comparison ambiguous |
| LOW | Vendor match only, model is partial / wildcard |

## Vendor Coverage

The advisory database covers 3,600+ CISA ICS advisories across 500+ vendors. Recently expanded for the CNC market: **Fanuc**, **Haas Automation**, **Heidenhain**, **Okuma**, **Yamazaki Mazak**, plus extended Mitsubishi Electric aliases for the M700/M800/M80/E80 CNC series.

## Project Structure

```
cmd/deadband/main.go       # CLI entrypoint
pkg/advisory/              # Advisory DB load/save
pkg/asset/                 # Asset inventory + vulnerability state
pkg/cli/banner.go          # Safety banner
pkg/discover/              # Active discovery (CIP, S7, Modbus, MELSEC, FINS, SRTP, OPC UA, Haas, Fanuc; BACnet behind build tag)
pkg/inventory/             # CSV / JSON / flat parsing
pkg/matcher/               # Vendor, model, version matching
pkg/output/                # Text, CSV, JSON, HTML, SARIF writers
pkg/server/                # HTTP API + report export endpoint
pkg/updater/               # CISA CSAF fetch (snapshot + per-file)
web/                       # Next.js frontend (Dashboard, Scan, Settings)
```

Routes for `/acl`, `/posture`, `/sites`, `/assets`, `/advisories` remain on disk but are hidden from the v0.5 sidebar pending decisions about the enterprise market.

## License

MIT
