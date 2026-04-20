# Integrations Roadmap

deadband's integration layer pulls data from enterprise security and network tools to enrich its picture of an OT environment — validating ACL policies against observed flow, detecting configuration drift on edge firewalls, and correlating IT-side telemetry with OT assets discovered by native scanning.

This document lays out the current state and planned direction. It is intentionally opinionated about which integrations matter most for OT sites; pull requests that reshuffle the priority are welcome if they come with a concrete customer need.

## Design principles

Every integration deadband ships must follow these rules. PRs that violate them will be rejected.

1. **Read-only by construction.** Integrations never push rules, acknowledge alarms, or mutate configuration. Drift is surfaced for humans to act on.
2. **IT-side only.** Integrations talk to SIEMs, firewalls, cloud APIs, and CMDBs — never directly to PLCs, RTUs, or HMIs. OT traffic goes through `pkg/discover/` and `pkg/posture/`, which enforce their own safety gates.
3. **Per-site scoping.** All integration configs carry a `SiteID` and only operate on assets/CIDRs in that site. Credentials never leak across site boundaries.
4. **Credentials at rest only.** `integrations.json` is written with mode `0600`. Tokens live in memory for the duration of a request, never on disk outside the config, never in logs.
5. **Offline-tolerant.** Integration failures must never block native discovery or inventory checks. A dead Sentinel workspace should surface as a warning badge in the UI, not a stack trace in the CLI.
6. **Config is data.** Every integration is a row in `pkg/integration/store.go` and a panel in `settings/_tabs/IntegrationsTab.tsx`. Adding one means extending both — no custom config files, no env var sprawl.

## Current state (shipped)

| Integration | Purpose | Transport | Status |
|-------------|---------|-----------|--------|
| Microsoft Sentinel (Log Analytics) | Pull firewall flow telemetry via KQL to validate ACL policies | OAuth2 client credentials → REST API | Shipped |
| Cisco ASA | Parse `show` output (ACLs, interfaces, connections, routes); detect drift between snapshots | SSH + PTY | Shipped |

Shipped integrations feed two downstream features:
- **ACL gap analysis** (`pkg/acl/gaps.go`) — cross-references policy rules against observed flow and firewall config
- **Posture findings** — IT-side hosts discovered via Sentinel flow show up in posture classification

## Phase 1 — Complete the firewall/flow picture (near-term)

Goal: every site running a modern edge firewall can be analyzed without Sentinel as a dependency. Today, `pkg/acl/gaps.go` only knows about ASA snapshots and Sentinel KQL; expanding here unblocks sites on other vendors.

| # | Integration | Why it matters | Transport | Notes |
|---|-------------|----------------|-----------|-------|
| 1.1 | **Palo Alto PAN-OS** | Second most-deployed edge firewall at OT sites after ASA. XML API is stable and well-documented. | HTTPS + API key | Parse `show config` + `show session all`. Same drift model as ASA. |
| 1.2 | **Fortinet FortiGate** | Widely deployed at Purdue Level 3.5 / DMZ boundaries. | REST API + token | Policy + flow via `/api/v2/monitor/firewall/session`. |
| 1.3 | **Cisco Firepower / FTD (FMC)** | Upgrade path from ASA; many plants are mid-migration. | REST API + token | Centralized via FMC rather than per-device SSH. |
| 1.4 | **Syslog receiver** | Catch-all for firewalls without an API: Check Point, Juniper, pfSense, plus older ASA where API access is refused. | UDP/TCP 514 listener | Parses Cisco ASA, PAN-OS, and FortiGate syslog formats. Lands flow data equivalent to Sentinel. |
| 1.5 | **Zeek / Corelight logs** | Passive flow source for sites that tap their IT/OT boundary. | File ingest (conn.log) | Same parsing model as `pkg/pcap`. Zero-touch; no remote connection. |

Exit criteria for Phase 1: a site can validate ACL policy without requiring Azure. All five sources populate the same `FlowRecord` shape consumed by `pkg/acl/gaps.go`.

## Phase 2 — SIEM breadth and OT-native platforms (mid-term)

Goal: meet OT security teams where they already have data. Splunk and Elastic each have meaningful on-prem deployments that Sentinel does not reach; OT-native platforms (Claroty, Nozomi, Dragos, Defender for IoT) carry asset data that complements deadband's active scans.

| # | Integration | Why it matters | Transport | Notes |
|---|-------------|----------------|-----------|-------|
| 2.1 | **Splunk** | Dominant on-prem SIEM; equivalent to Sentinel role. | HEC token + SPL search API | Parallel implementation of `pkg/sentinel`. |
| 2.2 | **Elastic / OpenSearch** | Common where Splunk licensing is untenable. | REST API + API key | Same role as Splunk. |
| 2.3 | **Microsoft Defender for IoT** | Azure-native OT sensor; emits asset + alert data via Log Analytics and Defender APIs. | OAuth2 + REST | Complements posture findings with passive-collected OT asset telemetry. |
| 2.4 | **Claroty xDome / CTD** | Dominant OT asset discovery platform. One-way sync: pull assets into deadband, never push. | REST API + token | Merge into `pkg/asset` with `source: claroty`. |
| 2.5 | **Nozomi Networks** | Second major OT asset discovery platform. | REST API + token | Same model as Claroty integration. |
| 2.6 | **Tenable.ot** | Vulnerability scanner; complements CISA advisory matching with active scan results. | REST API + API key | Feeds `asset.VulnState` as a secondary source. |

Exit criteria for Phase 2: deadband can operate as a **consolidator** — a site running Claroty, Splunk, and PAN-OS can see unified posture, ACL gaps, and vulnerability state in one UI.

## Phase 3 — Identity, endpoint, and OT platform depth (long-term)

Goal: close the gap between "which device is this" and "what does the business know about this device." Integrations at this tier are lower-priority individually but collectively turn deadband from an OT scanner into an OT asset system of record.

| # | Integration | Why it matters | Transport |
|---|-------------|----------------|-----------|
| 3.1 | **Active Directory (LDAP)** | Resolve IT-side host identity on the OT boundary (domain, OU, last logon). | LDAPS |
| 3.2 | **CrowdStrike Falcon / SentinelOne / Defender for Endpoint** | EDR visibility on IT hosts that touch OT networks (jump boxes, engineering workstations). | REST API + token |
| 3.3 | **ServiceNow CMDB** | Sync asset inventory bidirectionally (read CIs, write OT-discovered assets back as a tagged class). | REST API + OAuth |
| 3.4 | **Rockwell FactoryTalk AssetCentre** | Native asset source for Rockwell-heavy sites. | ODBC / REST |
| 3.5 | **Siemens SIMATIC Inventory Server / TIA** | Native asset source for Siemens-heavy sites. | REST API |
| 3.6 | **Schneider EcoStruxure** | Native asset source for Schneider-heavy sites. | REST API |
| 3.7 | **Cloud VPC flow logs** (AWS / Azure NSG / GCP) | Required for sites where part of the OT estate runs in cloud (SCADA historians, analytics). | Native SDK |
| 3.8 | **Industrial switch APIs** (Cisco IE, Hirschmann, Moxa EDS) | MAC/port mapping, PoE state, topology. | SNMPv3 + REST |

No exit criteria for Phase 3 — this tier is driven by specific customer asks rather than a coverage goal.

## What belongs outside the roadmap

These are explicitly **not** on deadband's path:

- **Writing to OT devices.** Not now, not later. This is the load-bearing product promise.
- **Writing to firewalls.** Drift detection lives in deadband; remediation lives in the customer's CI/CD or change-management system. A human always closes the loop.
- **Running agents on OT endpoints.** deadband is agentless by design. Integrations that require an agent (some EDR deployments) pull via the central console, never directly.
- **Pushing to SIEMs.** deadband consumes SIEM data to enrich its own view. Shipping alerts back belongs in the SIEM's own alerting pipeline.
- **Real-time streaming.** All integrations are pull-on-demand or scheduled poll. Stream processing is a different product.

## How to propose a new integration

Before writing code:

1. Which design principle does it respect? If it requires a write path to OT or a persistent agent, it's out.
2. Which Phase does it fit in, and who is asking for it? Concrete customer use cases move integrations up the list.
3. What is the minimal data contract? Every integration produces one of: flow records, config snapshots, assets, vulnerabilities, or identities. New data shapes need a core-package discussion first.
4. What happens when it breaks? Integration failures must degrade gracefully — the UI shows a warning, native scans keep working, the CLI exits with the same code it would have without the integration.

Open an issue describing the above before starting implementation. New integrations land as:

- A new file under `pkg/<vendor>/` (e.g., `pkg/panos/`, `pkg/splunk/`)
- A config struct and store methods in `pkg/integration/`
- A handler group in `pkg/server/integrations.go`
- A panel component under `web/src/app/settings/_tabs/IntegrationsTab.tsx` with matching hook in `web/src/lib/hooks/`

All four pieces ship together in one PR. Partial integrations that work only in the CLI or only in the UI are not accepted.
