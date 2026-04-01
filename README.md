# deadband

**Firmware vulnerability gap detector for ICS/OT assets**

deadband discovers Rockwell Automation devices on your network and cross-references their firmware versions against the [CISA ICS Advisory](https://www.cisa.gov/news-events/ics-advisories) feed to surface known CVEs. It can also accept pre-collected inventory files (CSV/JSON) from [trics/rockwell-discover](https://github.com/jmeltz/trics) or other sources.

## Why

There is no lightweight, offline-capable CLI tool that accepts "here are my PLCs and their firmware versions" and outputs "here are the open CVEs against them." Tenable and Dragos do this inside licensed platforms. deadband does it for free, in a terminal, with no agent.

## Safety

- **Read-only by construction** - discovery uses only TCP port probes and HTTP GET (no CIP writes)
- **Conservative and safe** - no external API calls at runtime; advisory data is fetched/cached separately
- **Transparent** - prints a safety banner on startup, uses only public CISA data (TLP:WHITE)
- **Scriptable** - structured output, meaningful exit codes

## Quick Start

```bash
# Build
make deadband

# Fetch advisory database (one-time, requires internet)
bin/deadband --update

# Discover and check in one shot
bin/deadband --cidr 10.0.1.0/24

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
| `--timeout` | `2s` | TCP port scan timeout |
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

## Project Structure

```
cmd/deadband/main.go       # CLI entrypoint
pkg/advisory/advisory.go   # Advisory DB load/save/query
pkg/cli/banner.go          # Safety banner
pkg/discover/              # Rockwell EtherNet/IP device discovery
pkg/inventory/inventory.go # Multi-format inventory parsing
pkg/matcher/               # Vendor, model, version matching
pkg/output/                # Text, CSV, JSON formatters
pkg/updater/               # CISA CSAF fetch and cache
```

## License

MIT
