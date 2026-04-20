# deadband

**Offline OT asset inventory, vulnerability matching, and network posture analysis** — Release 0.30

deadband discovers industrial devices on your network, cross-references firmware versions against 3,600+ CISA ICS advisories, and analyzes network posture (segmentation, ACL gaps, IT/OT boundary) — all from a single Go binary with an optional embedded web UI.

It actively scans for Rockwell Automation (CIP/EIP), Siemens (S7comm), Schneider Electric / ABB / Delta (Modbus TCP), Mitsubishi Electric (MELSEC/SLMP), Omron (FINS), BACnet/IP (Trane, Honeywell, Johnson Controls), Emerson/GE (SRTP), and OPC UA. It also passively extracts devices from pcap captures and accepts pre-collected inventory files (CSV/JSON).

## Why

No lightweight, offline-capable tool accepts "here are my PLCs and their firmware versions" and outputs "here are the open CVEs against them, mapped to IEC 62443 controls, enriched with CISA KEV / EPSS, and a posture report showing segmentation gaps." deadband does it in a terminal or browser, with no agent or sensor.

## Safety

- **Read-only by construction** — discovery uses identity reads and port probes only (no CIP writes, no S7 writes, no ACL pushes)
- **Sensitivity-ordered posture scanning** — hosts identified as OT are excluded from IT port scans, SMB probes, and banner grabs (see `pkg/posture/doc.go`)
- **No runtime internet calls** — advisory, KEV, and EPSS data are fetched/cached ahead of time
- **Transparent** — prints a safety banner on startup, uses only public CISA/first.org data
- **Scriptable** — structured output, meaningful exit codes

## Quick Start

```bash
# Build (CLI only)
make deadband

# Build with embedded web UI
make deadband-web

# Fetch advisory + enrichment database (one-time, requires internet)
bin/deadband --update

# Discover and check (auto mode: all 8 OT protocols in parallel)
bin/deadband --cidr 10.0.1.0/24

# Target a single protocol
bin/deadband --cidr 10.0.1.0/24 --mode s7
bin/deadband --cidr 10.0.1.0/24 --mode modbus

# Check a pre-collected inventory file
bin/deadband --inventory devices.csv

# Passive extraction from pcap
bin/deadband pcap capture.pcap

# Start the web UI + API
bin/deadband serve           # http://localhost:8484

# JSON/HTML/SARIF output with filters, compliance mappings, risk prioritization
bin/deadband -i devices.json \
  --min-cvss 7.0 --prioritize \
  --compliance iec62443,nist-csf \
  --out-format sarif -o report.sarif
```

## Input Formats

**CSV** (default, matches `rockwell-discover` output):
```
Scanned IP,Device Name,Ethernet Address (MAC),IP Address,Product Revision,Serial Number,Status,Uptime
172.16.12.21,1756-EN2T/D,5C:88:16:C4:26:3C,172.16.12.21,11.002,D060925B,Run,"206 days, 03h:12m:20s"
```

**JSON** (matches `rockwell-discover --format json`):
```json
[{"scanned_ip":"172.16.12.21","device_name":"1756-EN2T/D","product_revision":"11.002",...}]
```

**Flat text** (manual/ad-hoc):
```
172.16.12.21,Rockwell,1756-EN2T,11.002
172.16.12.22,ABB,AC500,3.4.1
```

## Output Formats

| Format | Use case |
|--------|----------|
| `text` | Terminal, human review (default) |
| `csv` | Spreadsheet import |
| `json` | Scripting / pipeline integration |
| `html` | Standalone shareable report |
| `sarif` | CI/CD (GitHub Code Scanning, Azure DevOps) |

## Flags

### Discovery

| Flag | Default | Description |
|------|---------|-------------|
| `--cidr` | | CIDR range to scan (e.g. `10.0.1.0/24`) |
| `--mode` | `auto` | `auto`, `cip`, `s7`, `modbus`, `melsec`, `bacnet`, `fins`, `srtp`, `opcua`, `http` |
| `--timeout` | `2s` | TCP/UDP scan timeout |
| `--http-timeout` | `5s` | HTTP scrape timeout |
| `--concurrency` | `50` | Concurrent scan workers |

### Check

| Flag | Default | Description |
|------|---------|-------------|
| `--inventory` / `-i` | | Path to device inventory file |
| `--compare` | | Second inventory file (diff mode) |
| `--format` | `auto` | Input format: `csv`, `json`, `flat`, `auto` |
| `--db` | `~/.deadband/advisories.json` | Path to advisory database |
| `--output` / `-o` | stdout | Output file path |
| `--out-format` | `text` | `text`, `csv`, `json`, `html`, `sarif` |
| `--min-confidence` | `low` | `low`, `medium`, `high` |
| `--min-cvss` | `0.0` | Minimum CVSS v3 score |
| `--vendor` | (all) | Filter to a specific vendor |
| `--prioritize` | `false` | Sort results by risk (KEV > EPSS > CVSS) |
| `--compliance` | | `iec62443`, `nist-csf`, `nerc-cip`, `all` (comma-separated) |
| `--dry-run` | `false` | Parse only, emit counts |

### Baseline & Asset Inventory

| Flag | Default | Description |
|------|---------|-------------|
| `--save-baseline` | `false` | Save current device list as baseline after scan |
| `--compare-baseline` | `false` | Compare current scan against saved baseline |
| `--baseline` | `~/.deadband/baseline.json` | Baseline file path |
| `--auto-save-assets` | `false` | Auto-import discovered devices into asset inventory |
| `--asset-store` | `~/.deadband/assets.json` | Asset inventory file path |

### Update

| Flag | Default | Description |
|------|---------|-------------|
| `--update` | | Fetch advisories + KEV + EPSS |
| `--skip-enrichment` | `false` | Skip KEV/EPSS fetch during update |
| `--since` | (all) | Only fetch after date (`YYYY-MM-DD`) |
| `--source` | | Local CSAF mirror path (air-gapped) |

### Server

| Flag | Default | Description |
|------|---------|-------------|
| `--serve` | `false` | Start the web UI and API server |
| `--addr` | `:8484` | Listen address |

The `serve` subcommand is also accepted (`deadband serve [--addr :8484] [--db <path>]`).

### Other

| Flag | Description |
|------|-------------|
| `--stats` | Show advisory DB metadata (counts, staleness, vendor coverage) |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No vulnerabilities found |
| `1` | One or more matches found |
| `2` | Error (missing DB, bad input, etc.) |

## Confidence Levels

| Level | Meaning |
|-------|---------|
| `HIGH` | Vendor + model exact match, firmware in advisory range (clean semver) |
| `MEDIUM` | Vendor + model match, version comparison ambiguous |
| `LOW` | Vendor match only, model is partial/wildcard match |

## Enrichment

On `--update`, deadband also fetches:

- **CISA KEV** — Known Exploited Vulnerabilities catalog (flags CVEs with `ransomware_use`)
- **FIRST EPSS** — Exploit Prediction Scoring System (probability of exploitation in next 30 days)

Risk scoring combines these signals (KEV > EPSS > CVSS) so `--prioritize` surfaces the advisories that matter most. All enrichment data is cached alongside the advisory DB for offline use.

## Compliance Mappings

Results can be annotated with controls from three frameworks:

| Framework | Controls mapped |
|-----------|-----------------|
| IEC 62443-3-3 | SR (System Requirements) and RE (Requirement Enhancements) |
| NIST CSF 2.0 | ID, PR, DE, RS, RC functions |
| NERC CIP | CIP-002 through CIP-013 |

Pass `--compliance iec62443,nist-csf,nerc-cip` (or `all`) to include mappings in any output format. The web UI exposes the same mappings under **Posture → Frameworks**.

## Air-Gap Support

deadband works with zero internet at check-time. Run `--update` on a connected host, then copy the DB folder:

```bash
scp -r ~/.deadband/ assessor@isolated-host:~/
ssh assessor@isolated-host "bin/deadband -i /tmp/devices.csv"
```

For fully air-gapped environments, point `--source` at a local CSAF mirror:

```bash
bin/deadband --update --source ./local-csaf-mirror/
```

## Web UI

The embedded web UI is a Next.js static export served from the Go binary.

```bash
make deadband-web
bin/deadband serve          # http://localhost:8484
```

The sidebar has five top-level areas:

| Area | Contents |
|------|----------|
| **Dashboard** | Summary tiles, getting-started checklist (first run), recent discovery |
| **Assets** | Tabs: Inventory, Discover, History, Compare (diff two snapshots) |
| **Network** | Collapsible group: Sites (CIDR zones) and ACL Policies (zone-to-zone rules) |
| **Posture** | Tabs: Findings (subnet posture), Frameworks (IEC 62443 / NIST CSF / NERC CIP) |
| **Advisories** | Searchable advisory browser; row click opens a detail drawer |
| **Settings** | Tabs: Database (advisory updates, stats), Integrations (Sentinel, ASA) |

Advisory detail uses a URL-driven drawer (`/advisories?advisory=ICSA-XX-YYY-ZZ`), so deep links survive refresh and browser back.

For frontend development:

```bash
# Terminal 1: API server
go run ./cmd/deadband serve

# Terminal 2: Next.js dev server (proxies /api/* to :8484)
cd web && npm run dev
```

## Sites

Sites define named network locations with CIDR subnets and optional zones (IT, DMZ, OT, Safety, etc.). When a site is defined, discovered or imported assets are automatically assigned based on IP matching.

```bash
# Create a site
curl -X POST http://localhost:8484/api/sites \
  -H 'Content-Type: application/json' \
  -d '{"name":"Plant A","cidrs":["10.0.1.0/24","10.0.2.0/24"],"location":"Chicago, IL"}'

# List sites
curl http://localhost:8484/api/sites

# Reassign all assets to sites based on CIDR matching
curl -X POST http://localhost:8484/api/sites/reassign
```

Sites and zones are managed through the web UI's **Network → Sites** page or the HTTP API.

## ACL Policies

ACL policies define allow/deny rules between zones (e.g., `IT → OT` denied except TCP 44818 for CIP). deadband compares policies against observed ASA configuration or Sentinel flow data to surface gaps — rules that exist but have no matching traffic, or observed traffic that no rule allows.

Managed at **Network → ACL Policies** in the web UI. Gap analysis is purely analytical — deadband never pushes rules to any device.

## Posture Analysis

The Posture page walks a subnet with a sensitivity-ordered scanner that protects OT controllers from any intrusive probing. See `pkg/posture/doc.go` for the full protocol; the short version:

1. Pre-tag known OT hosts from the asset store
2. Scan 8 OT ports on every host
3. Scan 12 IT/network ports only on non-OT hosts
4. Classify (OT / IT / Network / Unknown)
5. SMB/NTLMSSP probe on Windows hosts (RDP open, non-OT)
6. Protocol banner grabs (SSH, HTTP, SNMP, Telnet) on non-OT hosts only
7. Presumption enrichment (no packets sent)

Output surfaces subnet posture (host classes, unknowns), control recommendations (compensating controls per host class), and a risk simulation panel that models the impact of adding specific compensating controls.

## Change Simulator

The change simulator answers the question that gates a controls-engineer signoff: **"if I add, remove, or edit this rule, what newly breaks or newly opens?"** It evaluates a planned policy against current traffic plus posture-implied traffic and returns a three-bucket diff: newly denied, newly allowed, unchanged.

Inputs:

- A current policy baseline (selected by `policy_id`)
- A planned policy (full rule set, server never persists it)
- `flow_window`: `24h`, `7d` (default), or `30d`
- Toggles: `include_observed` (Sentinel flows, default on), `include_implied` (synthesized from the latest posture scan, default on)

**Observed flows** come from the site's Sentinel snapshot within the window. **Implied flows** are synthesized from posture: for each allow rule, deadband enumerates `(srcHost, dstHost, port)` tuples where `srcHost` is any posture-scanned host in the rule's source zone, `dstHost` has `port` open in the destination zone, and `port` matches the rule's port list. Zone pairs with more than 1,000 possible tuples collapse to a single representative record tagged `enrichment.collapsed=true`.

Both flow sets feed a top-to-bottom rule-match evaluator that returns a `FlowVerdict` per flow (matched rule ID, action, human reason). The diff keys on `(src, dst, port, protocol)` and buckets by whether the verdict flipped.

Use it from the web UI at `/acl` → **Plan Change** → edit the right pane's rules → **Simulate**. Rows in the result view are grouped by zone pair, badged `OBSERVED` or `IMPLIED`, and flagged when the destination zone is OT or safety-purposed. Click a row to see the full verdict and enrichment in a side drawer.

Endpoint:

```
POST /api/acl/simulate
{ site_id, policy_id, planned_policy, flow_window, include_observed, include_implied }
→ { current: DiffSummary, planned: DiffSummary, diff: { newly_denied, newly_allowed, unchanged } }
```

Pluggable flow sources (Splunk, Elastic, Palo Alto, etc.) with a preview-driven column mapping UI are planned for 0.31 — see `INTEGRATIONS.md`.

## Integrations

deadband can ingest data from existing enterprise security tools to enrich its picture of the environment:

| Integration | Purpose |
|-------------|---------|
| **Microsoft Sentinel** (Azure Log Analytics) | Pull flow telemetry to validate ACL policies |
| **Cisco ASA** | Parse `show` command output to extract ACLs, interfaces, connections, routes; detect drift between snapshots |

Credentials are stored locally (not committed) and configured via **Settings → Integrations**. All reads are unauthenticated to the OT side — integrations only contact IT/network systems that expect API access.

## .dbd Export/Import

deadband exports and imports complete asset inventories (including site metadata) using the `.dbd` file format — CSV with site metadata encoded as comment headers:

```
# deadband export v1
# exported: 2026-04-14T21:30:00Z
# site: Plant-A|10.0.1.0/24,10.0.2.0/24|Building 7|Chicago IL|ops@example.com
# site: Plant-B|10.0.3.0/24|Building 12|Detroit MI|
ID,IP,Vendor,Model,Firmware,Name,Site,Zone,Criticality,Status,...
```

```bash
# Export
curl http://localhost:8484/api/assets/export?format=dbd -o assets.dbd

# Import into another instance
curl -X POST http://other-host:8484/api/assets/import/dbd \
  --data-binary @assets.dbd -H 'Content-Type: text/csv'
```

Also available in the web UI on the Assets page.

## Active Scanning Protocols

| Protocol | Port | Vendor(s) | Method |
|----------|------|-----------|--------|
| CIP/EIP ListIdentity | UDP 44818 | Rockwell Automation | Broadcast + unicast, extracts ProductName + firmware revision |
| S7comm SZL Read | TCP 102 | Siemens (S7-300/400/1200/1500) | 3-phase handshake (COTP + S7 Setup + SZL 0x001C), extracts module name + firmware |
| Modbus TCP Device ID | TCP 502 | Schneider, ABB, Delta, Moxa, Phoenix Contact, WAGO, Emerson, Yokogawa, Eaton | FC 43 / MEI 14 Read Device Identification |
| MELSEC/SLMP | TCP 5007 | Mitsubishi Electric (iQ-R, iQ-F, Q, L, FX5) | Read Type Name (0x0101), extracts CPU model |
| BACnet/IP | UDP 47808 | Trane, Honeywell, Johnson Controls, Carrier, Daikin | Who-Is + ReadProperty, extracts vendor ID + model + firmware |
| FINS | UDP 9600 | Omron (CJ, CP, CS, NJ, NX) | Controller Data Read (0501), extracts CPU model + firmware |
| GE-SRTP | TCP 18245 | Emerson / GE (PACSystems, Series 90, VersaMax) | INIT handshake + Controller Type Read (0x43) |
| OPC UA | TCP 4840 | Siemens, Kepware, Prosys, Unified Automation | Hello + GetEndpoints, extracts application URI + product name |

Auto mode (`--mode auto`, default) runs all protocols concurrently and merges results.

## Passive PCAP Analysis

```bash
bin/deadband pcap capture.pcap --out-format json -o devices.json
```

Extracts device identity from CIP, S7comm, Modbus, and HTTP traffic in a packet capture. Useful when active scanning is prohibited. Accepts the same `--compliance`, `--prioritize`, and output flags as inventory check mode.

## Vendor Coverage

deadband's advisory database covers 3,600+ CISA ICS advisories across 500+ vendors. Top vendors by advisory count:

| Vendor | Advisories | Protocol |
|--------|-----------|----------|
| Siemens | 979 | S7comm + OPC UA |
| Rockwell Automation | 229 | CIP/EIP |
| Schneider Electric | 224 | Modbus TCP |
| Hitachi Energy / ABB | 167 | Modbus TCP |
| Mitsubishi Electric | 115 | MELSEC/SLMP |
| Delta Electronics | 94 | Modbus TCP |
| Advantech | 78 | Modbus TCP / HTTP |
| Emerson / GE | 62 | Modbus TCP + GE-SRTP |
| Moxa | 48 | Modbus TCP / HTTP |
| Honeywell | 35 | BACnet/IP |
| Yokogawa | 30 | Modbus TCP |
| Omron | 28 | FINS |
| Phoenix Contact | 23 | Modbus TCP |
| WAGO | 11 | Modbus TCP |

## Project Structure

```
cmd/deadband/main.go       # CLI entrypoint
pkg/acl/                   # Zone-to-zone ACL policies + gap analysis
pkg/advisory/              # Advisory DB load/save/query
pkg/asa/                   # Cisco ASA config ingestion + drift detection
pkg/asset/                 # Asset inventory store + vulnerability state
pkg/baseline/              # Snapshot save/compare
pkg/cli/                   # Safety banner
pkg/compliance/            # IEC 62443, NIST CSF, NERC CIP mappings
pkg/diff/                  # Inventory snapshot diff
pkg/discover/              # Multi-protocol active discovery + scheduler
pkg/enrichment/            # CISA KEV + FIRST EPSS
pkg/integration/           # External integration configs (Sentinel, ASA)
pkg/inventory/             # Multi-format inventory parsing
pkg/matcher/               # Vendor, model, version matching
pkg/output/                # Text, CSV, JSON, HTML, SARIF, .dbd formatters
pkg/pcap/                  # Passive device extraction from captures
pkg/posture/               # Sensitivity-ordered subnet posture scanner
pkg/sentinel/              # Azure Sentinel / Log Analytics client
pkg/server/                # HTTP API + embedded web UI
pkg/site/                  # Site management (CIDR zone grouping)
pkg/updater/               # CISA CSAF fetch and cache
web/                       # Next.js 16 frontend (static export)
```

## License

MIT
