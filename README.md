# deadband

**Firmware vulnerability gap detector for ICS/OT assets**

deadband discovers industrial devices on your network and cross-references their firmware versions against the [CISA ICS Advisory](https://www.cisa.gov/news-events/ics-advisories) feed to surface known CVEs. It actively scans for Rockwell Automation (CIP/EIP) and Siemens (S7comm) devices, and can also accept pre-collected inventory files (CSV/JSON) from any vendor.

## Why

There is no lightweight, offline-capable CLI tool that accepts "here are my PLCs and their firmware versions" and outputs "here are the open CVEs against them." Tenable and Dragos do this inside licensed platforms. deadband does it for free, in a terminal, with no agent or sensor necessary.

## Safety

- **Read-only by construction** - discovery uses only identity reads and port probes (no CIP writes, no S7 writes)
- **Conservative and safe** - no external API calls at runtime; advisory data is fetched/cached separately
- **Transparent** - prints a safety banner on startup, uses only public CISA data (TLP:WHITE)
- **Scriptable** - structured output, meaningful exit codes

## Quick Start

```bash
# Build
make deadband

# Fetch advisory database (one-time, requires internet)
bin/deadband --update

# Discover and check (auto mode: scans CIP + S7 in parallel)
bin/deadband --cidr 10.0.1.0/24

# Scan for Siemens PLCs only
bin/deadband --cidr 10.0.1.0/24 --mode s7

# Scan Modbus TCP devices (Schneider, ABB, Delta, etc.)
bin/deadband --cidr 10.0.1.0/24 --mode modbus

# Or check a pre-collected inventory file
bin/deadband --inventory devices.csv

# JSON output with filters
bin/deadband -i devices.json --min-cvss 7.0 --out-format json -o report.json

# Fail CI if any HIGH-confidence vulns found
bin/deadband -i devices.csv --min-confidence high
echo $?  # 1 = found, 0 = clean
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

## Flags

### Discovery Mode

| Flag | Default | Description |
|------|---------|-------------|
| `--cidr` | | CIDR range to scan (e.g. `10.0.1.0/24`) |
| `--mode` | `auto` | Discovery mode: `auto`, `cip`, `s7`, `modbus`, `http` |
| `--timeout` | `2s` | TCP/UDP scan timeout |
| `--http-timeout` | `5s` | HTTP scrape timeout |
| `--concurrency` | `50` | Concurrent scan workers |

### Check Mode

| Flag | Default | Description |
|------|---------|-------------|
| `--inventory` / `-i` | | Path to device inventory file |
| `--format` | auto-detect | Input format: `csv`, `json`, `flat` |
| `--db` | `~/.deadband/advisories.json` | Path to advisory database |
| `--output` / `-o` | stdout | Output file path |
| `--out-format` | `text` | Output format: `text`, `csv`, `json` |
| `--min-confidence` | `low` | Filter: `low`, `medium`, `high` |
| `--min-cvss` | `0.0` | Minimum CVSS v3 score |
| `--vendor` | (all) | Filter to specific vendor |
| `--dry-run` | `false` | Parse only, emit counts |

### Update Mode

| Flag | Default | Description |
|------|---------|-------------|
| `--update` | | Fetch advisories from CISA CSAF repo |
| `--since` | (all) | Only fetch after date (`YYYY-MM-DD`) |
| `--source` | | Local CSAF mirror path (air-gapped) |

### Other

| Flag | Description |
|------|-------------|
| `--stats` | Show advisory DB metadata |

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

## Air-Gap Support

deadband works with zero internet at check-time. Run `--update` on a connected host, then copy the DB file:

```bash
scp ~/.deadband/advisories.json assessor@isolated-host:~/.deadband/
ssh assessor@isolated-host "bin/deadband -i /tmp/devices.csv"
```

For fully air-gapped environments, point `--source` at a local CSAF mirror:

```bash
bin/deadband --update --source ./local-csaf-mirror/
```

## Web UI

deadband includes an optional web frontend built with Next.js (embedded in the Go binary):

```bash
# Build with embedded frontend
make deadband-web

# Serve API + UI on http://localhost:8484
bin/deadband serve
```

The UI provides a dashboard, advisory browser, vulnerability check, network discovery, inventory diff, and database management — all with a dark industrial aesthetic.

For development, run the Go API and Next.js dev server separately:

```bash
# Terminal 1: API server
go run ./cmd/deadband serve

# Terminal 2: Frontend with hot reload (proxies /api/* to :8484)
cd web && npm run dev
```

## Active Scanning Protocols

| Protocol | Port | Vendor(s) | Method |
|----------|------|-----------|--------|
| CIP/EIP ListIdentity | UDP 44818 | Rockwell Automation | Broadcast + unicast, extracts ProductName + firmware revision |
| S7comm SZL Read | TCP 102 | Siemens (S7-300/400/1200/1500) | 3-phase handshake (COTP + S7 Setup + SZL 0x001C), extracts module name + firmware |
| Modbus TCP Device ID | TCP 502 | Schneider Electric, ABB, Delta, Moxa, Phoenix Contact, WAGO, Emerson, Yokogawa, Eaton | FC 43 / MEI 14 Read Device Identification, extracts vendor + model + firmware |

Auto mode (`--mode auto`, the default) runs all three protocols concurrently and merges results.

## Scanning Roadmap

deadband's advisory database covers 3,600+ CISA ICS advisories across 500+ vendors. The top vendors by advisory count and their scanning status:

| Vendor | Advisories | Protocol | Status |
|--------|-----------|----------|--------|
| Siemens | 979 | S7comm (TCP 102) | Implemented |
| Rockwell Automation | 229 | CIP/EIP (UDP 44818) | Implemented |
| Schneider Electric | 224 | Modbus TCP (TCP 502) | Implemented |
| Hitachi Energy / ABB | 167 | Modbus TCP (TCP 502) | Implemented |
| Mitsubishi Electric | 115 | MELSEC/SLMP (TCP 5007) | Planned |
| Delta Electronics | 94 | Modbus TCP (TCP 502) | Implemented |
| Advantech | 78 | Modbus TCP / HTTP | Implemented |
| Moxa | 48 | Modbus TCP / HTTP | Implemented |
| Honeywell | 35 | BACnet/IP (UDP 47808) | Planned |
| Emerson | 34 | Modbus TCP (TCP 502) | Implemented |
| Yokogawa | 30 | Modbus TCP (TCP 502) | Implemented |
| Omron | 28 | FINS (UDP 9600) | Planned |
| GE / GE Vernova | 28 | GE-SRTP (TCP 18245) | Planned |
| Phoenix Contact | 23 | Modbus TCP (TCP 502) | Implemented |
| WAGO | 11 | Modbus TCP (TCP 502) | Implemented |

### Protocol priority

1. **Modbus TCP Device ID** (Function 43/14) — single implementation covers Schneider, ABB, Delta, Moxa, Phoenix Contact, WAGO, Emerson, Yokogawa, Eaton (~600 advisories)
2. **MELSEC/SLMP** — Mitsubishi Electric (~115 advisories)
3. **HTTP fingerprinting** — extensible regex scraper for web-exposed devices across all vendors
4. **FINS** — Omron (~28 advisories)
5. **BACnet/IP** — building automation (Johnson Controls, Honeywell, ~75 advisories)
6. **GE-SRTP** — GE Vernova (~28 advisories)

## Project Structure

```
cmd/deadband/main.go       # CLI entrypoint
pkg/advisory/advisory.go   # Advisory DB load/save/query
pkg/cli/banner.go          # Safety banner
pkg/discover/              # Multi-protocol device discovery (CIP, S7comm, Modbus TCP)
pkg/inventory/inventory.go # Multi-format inventory parsing
pkg/matcher/               # Vendor, model, version matching
pkg/output/                # Text, CSV, JSON formatters
pkg/server/                # HTTP API + embedded frontend
pkg/updater/               # CISA CSAF fetch and cache
web/                       # Next.js frontend (static export)
```

## License

MIT
