# deadband — Project Requirements Document

**trics/deadband** — Firmware vulnerability gap detector for ICS/OT assets  
**Status:** Pre-implementation  
**Target:** Claude Code implementation handoff  
**Repo context:** https://github.com/jmeltz/trics

---

## 1. Purpose

`deadband` takes a list of discovered OT devices (from `trics/rockwell-discover`, `trics/cip-banner`, or a manually-supplied CSV/JSON) and cross-references firmware versions against the CISA ICS Advisory feed to surface devices running firmware with known CVEs.

**The gap it fills:** There is no lightweight, offline-capable CLI tool that accepts "here are my PLCs and their firmware versions" and outputs "here are the open CVEs against them." Tenable and Dragos do this inside licensed platforms. `deadband` does it for free, in a terminal, with no agent.

---

## 2. Positioning

Consistent with the trics framework:

- **Read-only by construction** — no packets sent to OT devices (operates entirely on previously-collected inventory data)
- **Conservative and safe** — no external API calls required at runtime; advisory data is fetched/cached separately
- **Transparent** — prints a safety banner on startup, uses only public CISA data (TLP:WHITE)
- **Scriptable** — structured output, meaningful exit codes

---

## 3. Inputs

### 3a. Device inventory (required)

Accepts output from other trics tools or a manually-crafted file. Supported formats:

**CSV** (default, matches `rockwell-discover` output schema):
```
Scanned IP,Device Name,Ethernet Address (MAC),IP Address,Product Revision,Serial Number,Status,Uptime
172.16.12.21,1756-EN2T/D,5C:88:16:C4:26:3C,172.16.12.21,11.002,D060925B,Run,"206 days, 03h:12m:20s"
```

**JSON** (matches `rockwell-discover --format json` output):
```json
[
  {
    "scanned_ip": "172.16.12.21",
    "device_name": "1756-EN2T/D",
    "mac": "5C:88:16:C4:26:3C",
    "ip": "172.16.12.21",
    "product_revision": "11.002",
    "serial": "D060925B",
    "status": "Run",
    "uptime": "206 days, 03h:12m:20s"
  }
]
```

**Flat text** (one `IP,vendor,model,firmware` per line, for manual/ad-hoc use):
```
172.16.12.21,Rockwell,1756-EN2T,11.002
172.16.12.22,ABB,AC500,3.4.1
```

### 3b. Advisory database (required, separate fetch step)

Advisory data is NOT fetched at check-time. It is fetched once and cached locally via a separate `--update` command (see §5). This keeps `deadband` usable in air-gapped environments — copy the cached advisory DB to the air-gapped host manually.

**Primary source:** CISA CSAF repository (public GitHub, TLP:WHITE)
- Index: `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/index.txt`
- Individual advisories: `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/{year}/{advisory-id}.json`

**Secondary/fallback source:** CISA ICS Advisory RSS feed
- `https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml`

**Cache format:** A single local file, `~/.trics/deadband-advisories.json` (path configurable via `--db`), containing a flattened advisory index:

```json
{
  "updated": "2026-03-31T00:00:00Z",
  "source": "cisagov/CSAF",
  "advisories": [
    {
      "id": "ICSA-24-179-01",
      "title": "Rockwell Automation ControlLogix 5580",
      "vendor": "Rockwell Automation",
      "products": ["ControlLogix 5580", "1756-L8*"],
      "affected_versions": ["v33 and prior", "v34.011 and prior"],
      "cvss_v3_max": 9.8,
      "cves": ["CVE-2024-6242"],
      "url": "https://www.cisa.gov/news-events/ics-advisories/icsa-24-179-01",
      "published": "2024-06-27"
    }
  ]
}
```

---

## 4. Matching Logic

Matching is intentionally fuzzy — firmware version strings from the field are messy and CISA advisory version ranges are often expressed in prose ("v33 and prior", "all versions before 3.4.2"). 

### 4a. Vendor normalization

Build a static vendor alias map (compiled into the binary):

```
"Rockwell Automation" → ["Rockwell", "Allen-Bradley", "A-B", "RA"]
"ABB" → ["ABB", "ABB Ltd"]
"Siemens" → ["Siemens", "Siemens AG"]
"Schneider Electric" → ["Schneider", "Schneider Electric", "SE"]
```

### 4b. Model matching

Attempt substring match between device model string (from inventory) and `products` field in advisory. Normalize both sides: strip spaces, lowercase, collapse special chars.

Example: `1756-EN2T/D` from inventory → match against `1756-EN2T` in advisory `products`.

Wildcard patterns in advisory products (e.g. `1756-L8*`) should be treated as glob patterns.

### 4c. Firmware version comparison

CVSS ranges in CISA advisories are not machine-parseable in a consistent way. Implement a two-tier approach:

**Tier 1 — Semantic version comparison** (when version strings are clean semver-like):  
Parse both the inventory firmware string and the advisory version boundary. Flag if inventory version ≤ advisory boundary version.

**Tier 2 — Regex extraction + heuristic** (when version strings are prose):  
Extract version numbers from advisory prose with regex. Apply best-effort comparison. When comparison is ambiguous, **flag conservatively** (report as potential match) and note the confidence level in output.

### 4d. Confidence levels

Each match is tagged with a confidence level:

| Level | Meaning |
|-------|---------|
| `HIGH` | Vendor + model exact match, firmware version falls within advisory range (clean semver) |
| `MEDIUM` | Vendor + model match, firmware comparison ambiguous or advisory uses prose version range |
| `LOW` | Vendor match only, model is partial/wildcard match |

Output always shows confidence. Users can filter by `--min-confidence high`.

---

## 5. CLI Interface

### 5a. Commands

```
deadband [flags]                   Run a check against a device inventory
deadband --update                  Fetch/refresh the advisory database cache
deadband --stats                   Show advisory DB metadata (count, last updated, coverage)
```

### 5b. Primary check flags

| Flag | Default | Description |
|------|---------|-------------|
| `--inventory` / `-i` | (required) | Path to device inventory file (CSV or JSON) |
| `--format` | auto-detect | Input format: `csv`, `json`, `flat` |
| `--db` | `~/.trics/deadband-advisories.json` | Path to advisory database cache |
| `--output` / `-o` | stdout | Output file path (`-` for stdout) |
| `--out-format` | `text` | Output format: `text`, `csv`, `json` |
| `--min-confidence` | `low` | Filter results: `low`, `medium`, `high` |
| `--min-cvss` | `0.0` | Filter results by minimum CVSS v3 score (e.g. `7.0`) |
| `--vendor` | (all) | Filter to a specific vendor (e.g. `Rockwell`) |
| `--dry-run` | `false` | Parse inventory and DB, report match counts, emit no results |

### 5c. Update flags

| Flag | Default | Description |
|------|---------|-------------|
| `--update` | `false` | Fetch latest advisories from CISA CSAF repo and refresh local DB |
| `--db` | `~/.trics/deadband-advisories.json` | Path to write advisory DB |
| `--since` | (all) | Only fetch advisories published after this date (`YYYY-MM-DD`) |

---

## 6. Output

### 6a. Text output (default)

```
[trics] deadband v0.1.0 — ICS firmware vulnerability gap detector
[trics] Advisory DB: 847 advisories, last updated 2026-03-28
[trics] Checking 14 devices against advisory database...

  172.16.12.21  1756-EN2T/D   fw 11.002   VULNERABLE  [HIGH]
    ICSA-24-179-01  CVE-2024-6242  CVSS 9.8  Rockwell ControlLogix/Ethernet Adapter RCE
    https://www.cisa.gov/news-events/ics-advisories/icsa-24-179-01

  172.16.12.22  1756-EN2T/D   fw 11.002   VULNERABLE  [HIGH]
    ICSA-24-179-01  CVE-2024-6242  CVSS 9.8  (same as above)

  172.16.12.30  1756-L83E/B   fw 28.011   POTENTIAL   [MEDIUM]
    ICSA-23-297-01  CVE-2023-46290  CVSS 8.1  Version range comparison ambiguous
    https://www.cisa.gov/news-events/ics-advisories/icsa-23-297-01

  172.16.12.50  1756-L82E/A   fw 32.014   OK
  172.16.12.51  1756-L81E/B   fw 32.014   OK

[trics] Summary: 2 VULNERABLE, 1 POTENTIAL, 2 OK (of 14 checked; 9 no advisory match)
```

Exit code `0` = no vulnerabilities found at or above `--min-confidence`  
Exit code `1` = one or more matches found  
Exit code `2` = error (missing DB, unreadable inventory, etc.)

### 6b. JSON output (`--out-format json`)

```json
{
  "checked_at": "2026-03-31T14:22:00Z",
  "db_updated": "2026-03-28T00:00:00Z",
  "devices_checked": 14,
  "results": [
    {
      "ip": "172.16.12.21",
      "device_name": "1756-EN2T/D",
      "firmware": "11.002",
      "status": "VULNERABLE",
      "confidence": "HIGH",
      "advisories": [
        {
          "id": "ICSA-24-179-01",
          "cves": ["CVE-2024-6242"],
          "cvss_v3": 9.8,
          "title": "Rockwell Automation ControlLogix/Ethernet Adapter RCE",
          "url": "https://www.cisa.gov/news-events/ics-advisories/icsa-24-179-01"
        }
      ]
    }
  ],
  "summary": {
    "vulnerable": 2,
    "potential": 1,
    "ok": 2,
    "no_match": 9
  }
}
```

### 6c. CSV output (`--out-format csv`)

```
IP,Device Name,Firmware,Status,Confidence,Advisory ID,CVEs,CVSS,URL
172.16.12.21,1756-EN2T/D,11.002,VULNERABLE,HIGH,ICSA-24-179-01,"CVE-2024-6242",9.8,https://...
172.16.12.30,1756-L83E/B,28.011,POTENTIAL,MEDIUM,ICSA-23-297-01,"CVE-2023-46290",8.1,https://...
```

---

## 7. Package Structure

Follow existing trics conventions:

```
trics/
  cmd/
    deadband/
      main.go          # CLI entrypoint, flag parsing, safety banner
  pkg/
    deadband/
      advisor.go       # Advisory DB load, parse, and query logic
      inventory.go     # Inventory file parsing (CSV, JSON, flat)
      matcher.go       # Vendor normalization, model matching, version comparison
      updater.go       # CISA CSAF fetch, cache write logic
      output.go        # Text, CSV, JSON formatters
```

Reuse from existing trics packages where applicable:
- `pkg/scan` — CIDR/host utilities (if piping from rockwell-discover)
- `pkg/output` — CSV/JSON output helpers
- `pkg/cli` — Safety banner, common flag conventions

---

## 8. Advisory DB Update Implementation Notes

- Fetch the CSAF index from `cisagov/CSAF` on GitHub (raw content, no auth required)
- Parse each OT advisory JSON file (CSAF 2.0 format)
- Extract: `document.title`, `product_tree`, `vulnerabilities[].cve`, `vulnerabilities[].scores[].cvss_v3.baseScore`, `document.references`
- Flatten into the local `deadband-advisories.json` schema
- On update, merge rather than replace — preserve any local overrides
- Print progress during update: `Fetching ICSA-24-XXX-XX... (N of M)`
- On failure mid-update, preserve the previous DB and report the error

---

## 9. Air-Gap Support

`deadband` must work with zero internet access at check-time:

- All advisory data must be pre-loaded into the local DB file
- The DB file is a single portable JSON — can be sneakernet'd to an isolated assessment host
- `--update` is the only command that requires internet access
- Optionally, `--update --source ./local-csaf-mirror/` allows pointing at a local CSAF mirror directory (for environments where even the update host has no internet)

---

## 10. Explicit Non-Goals

- No packet generation — `deadband` never touches the network at check time
- No authentication — does not log into any device or platform
- No write operations of any kind
- No Tenable/Dragos/Claroty API integration (keep it dependency-free and vendor-neutral)
- No CVE scoring beyond what CISA provides — do not fetch NVD or enrich further
- No GUI

---

## 11. Acceptance Criteria

- [ ] `deadband --update` fetches and caches CISA ICS advisories successfully
- [ ] `deadband -i devices.csv` runs against `rockwell-discover` CSV output with no modification
- [ ] `deadband -i devices.json` runs against `rockwell-discover --format json` output
- [ ] Matches are correctly identified for at least 3 known Rockwell advisories against test firmware strings
- [ ] `--min-cvss 7.0` filters results correctly
- [ ] `--min-confidence high` filters results correctly
- [ ] Exit code `1` when any match found, `0` when clean
- [ ] JSON output is valid and matches schema in §6b
- [ ] Works fully offline after `--update` has been run (no network calls at check time)
- [ ] `--dry-run` sends zero packets and emits no results, only counts
- [ ] Safety banner prints on every invocation
- [ ] `make deadband` builds a static binary with no CGO dependencies

---

## 12. Example End-to-End Workflow

```bash
# One-time: fetch advisory database
bin/deadband --update

# Check devices discovered by rockwell-discover
bin/rockwell-discover --cidr 10.0.1.0/24 --format json --output devices.json
bin/deadband --inventory devices.json --min-cvss 7.0 --out-format json --output report.json

# Scripted: fail CI/pipeline if any HIGH-confidence vulns found
bin/deadband --inventory devices.json --min-confidence high
echo $?  # 1 = found, 0 = clean

# Air-gapped: copy DB to isolated host, run check
scp ~/.trics/deadband-advisories.json assessor@isolated-host:~/.trics/
ssh assessor@isolated-host "bin/deadband --inventory /tmp/devices.csv"
```
