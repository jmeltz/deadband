# Targeted asset enrichment

Implemented across the standalone scanner/web UI, Cloud agent, Cloud application, Ops, and a local protocol responder harness. The initial executable query profile is **ENIP TCP identity-only**. Broader native-protocol discovery remains available through its existing modes; those modes do not inherit the bounded identity profile's guarantees.

## User workflows

On the local Assets page, select known EtherNet/IP endpoints and choose **Enrich missing details** or **Verify firmware update**. A preview records the exact selection, identity expectations, requested fields, profile, limits, and expiry. **Run query** executes that saved preview once. Results retain device observations, conflicts, metrics, access requirements, and advisory assessments. The asset detail page exposes recent field evidence. **Recheck advisories** uses stored identity and the advisory database without contacting devices.

Cloud offers the same two asset actions through a capable enrolled agent. Agent capability advertisement gates dispatch; legacy agents are not sent an unfamiliar enrichment mode. Cloud uses a smaller initial policy cap of 16 targets to bound result ingestion and projection work in one D1 transaction. The standalone engine accepts at most 256 targets. Both consume the same hashed plan schema. The agent imports the standalone stdlib query package at a pinned public release, verified by Go module checksums; it has no copied engine or sibling checkout dependency.

From a reviewed Cloud verification preview, schedule a recurring revision refresh with a fixed asset selection, freshness threshold, daily maintenance window, and IANA timezone. The existing hourly dispatcher selects stale revision evidence inside that window and generates a fresh plan for each execution, clipping plan expiry to the window close. Missing firmware observations mean unknown revision age, even when host liveness was recently observed. The policy rechecks agent capabilities and current component eligibility and never expands its pinned asset set. Daylight-saving transitions are covered by tests. Schedules appear in the existing schedule list with their window, timezone, and pinned-target count.

The first profile queries endpoint identity. CPU modules, routed devices, and chassis slots are excluded from these asset actions: an adapter revision must not become a CPU firmware observation. Query responses remain unauthenticated device claims with provenance. Conflicting or concurrently changed identities retain evidence for review and do not overwrite the asset projection.

## CLI

Create a target file containing explicit asset references and endpoints:

```json
[
  {
    "asset_id": "sensor-01",
    "ip": "192.0.2.10",
    "port": 44818,
    "requested_fields": ["firmware"],
    "expected": {"vendor": "SICK", "model": "CLV650", "serial": ""}
  }
]
```

```sh
deadband query plan --targets targets.json --purpose verify -o plan.json
deadband query run --plan plan.json --dry-run
deadband query run --plan plan.json -o observations.json
```

Planning and dry-run validation send no device traffic. The CLI emits observations as JSON; it does not silently import those results or start a discovery/posture scan. Local web execution applies eligible observations to existing asset IDs and retains its full job record under `~/.deadband/query-jobs/`. Restarted incomplete jobs are marked interrupted in the viewer and do not resume device work automatically.

## Execution contract

Schema version 1 supports profile `enip-identity-tcp-v1`, purposes `enrich` and `verify`, explicit IPv4 unicast literals on port 44818, and requested vendor/model/firmware/serial fields. The plan hash is SHA-256 over compact JSON with recursively sorted object keys, preserving array order and timestamp spelling, excluding the root `plan_hash`. Go and TypeScript golden fixtures verify ASCII and Unicode parity.

The profile permits one connection attempt and one 24-byte application request per target, with a bounded framed response of at most 4,096 bytes. There is no RegisterSession, broadcast, backplane traversal, retry, HTTP redirect, or alternate protocol. Global limits separately cover connection attempts, application requests, payload bytes sent/received, concurrency, start rate, timeout, and duration. Transport headers and TCP retransmissions are not included in application-byte metrics.

Standalone defaults are one target at a time, two starts per second, two-second per-target timeout, and five-minute maximum duration. Cloud applies its explicit reviewed policy, currently one target at a time and one start per second. A valid plan returns an outcome for every target, including unstarted/canceled/budget-exhausted targets. Invalid plans fail before I/O. Agent jobs are serialized process-wide and use the complete authoritative claimed plan.

## Local API

| Endpoint | Purpose |
|---|---|
| `POST /api/queries/preview` | `{ids: string[], purpose: "enrich" \| "verify"}` → stored preview, targets, exclusions, limits |
| `POST /api/queries/{id}/execute` | `{plan_hash: string}` → start the unchanged saved preview once |
| `GET /api/queries/{id}` | Progress state, observations, outcomes, metrics, assessment snapshots |
| `POST /api/queries/{id}/cancel` | Cancel in-flight execution and prevent new work |
| `GET /api/queries` | Recent query history |
| `GET /api/queries/{id}/access.csv` | Exact destination/transport/port/operation requirements |

Cloud stores plans in scan job params and accepts agent results through `POST /api/v1/agents/jobs/{id}/enrichment`. Results must match the job owner, plan/hash, target set, timestamps, operations, profile, and aggregate/per-target budgets. Exact duplicate delivery is idempotent. Evidence, observations, projection, audit, and per-execution assessments commit together, using snapshot checks to preserve newer asset data. Canceling jobs can retain partial evidence; terminal jobs cannot accept a new execution.

## Advisory interpretation

Local automatic and manual assessment now supersede old state for every targeted component, including zero-match outcomes. Missing identity/version or an unavailable catalog yields `UNKNOWN`; no applicable local catalog match yields `NO_MATCH`. Both preserve previous assessments. Same-model chassis slots are assessed independently.

Cloud matching evaluates conservative numeric version comparisons and associated affected-version ranges. A comparable known affected version is `VULNERABLE`; unknown syntax, missing revision, or ambiguous product/version association stays `POTENTIAL`. An excluded range or absent applicable catalog match does not establish that every vulnerability has been remediated. Newly parsed CSAF retains product-specific known-affected scopes where IDs resolve; unresolved scopes remain uncertain. Manual overrides use the same effective identity across ingest and advisory refresh.

## Operations and validation

Ops shows query-capable agents, execution outcomes, conflicts, payload totals, evidence coverage, and assessment snapshot counts. Before the additive migration is applied, unavailable summary queries render unavailable values rather than zero coverage.

The Cloud release includes an additive migration for agent capabilities, `asset_observations`, and `enrichment_results`; it does not backfill or rewrite existing fingerprints. Apply the reviewed migration through the Cloud deployment process before releasing the matching application code and advertising the capable agent.

The migration also adds a database uniqueness constraint on workspace and query-plan identity so repeated submissions cannot dispatch the same reviewed plan twice. The generated expression-index quoting was corrected after reviewing the SQL; fresh-database tests exercise the final migration.

The local responder harness frames fragmented/coalesced Modbus MBAP, ENIP encapsulation, and S7 TPKT requests with explicit size and assembly-time limits. Go passive analysis accepts Ethernet, loopback, and supported raw capture formats; Cloud accepts loopback captures too. Both the standalone scanner and agent use corrected S7 framing and component/version mapping, with independent synthetic fixtures and bounded same-session module reads. Passive packet analysis still requires complete protocol frames and does not reassemble arbitrary TCP streams or IP fragments.

Wire-contract and loopback tests establish declared behavior. Real-device tolerance under representative production load remains a separate validation step. Additional bounded Modbus/S7/BACnet/ADS/SOPAS profiles should be enabled only after their own interaction contracts and device-family validation are established.
