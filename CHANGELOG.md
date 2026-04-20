# Changelog

All notable changes to deadband are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [0.30.0] — 2026-04-20

### Added
- **Change simulator** — `POST /api/acl/simulate` plus the web "Plan Change" flow. Evaluates a planned policy against current and posture-implied traffic and returns a three-bucket diff (newly denied, newly allowed, unchanged). Backed by `pkg/acl/simulate` (`Evaluate`, `Diff`) with unit tests covering rule ordering, default-action fallthrough, and bucketing. UI components: `web/src/app/acl/_components/PolicyPlanner.tsx`, `SimulationResult.tsx`.
- **Canonical `pkg/flow.FlowRecord`** — single flow shape consumed by Sentinel ingestion, ACL gap analysis, scoping, and simulation. Carries source/dest address and zone, connection count, action, kind (`observed`/`implied`), source ID/hash, and an arbitrary enrichment map.
- **Implied-flow synthesis** (`pkg/flow/implied.go`) — for each allow rule, enumerates `(srcHost, dstHost, port)` tuples from the latest posture scan. Zone pairs exceeding 1,000 tuples collapse to a single representative record tagged `enrichment.collapsed=true`.
- **INTEGRATIONS.md** — read-only integration roadmap documenting what ships today (Sentinel, Cisco ASA) and what's queued (Palo Alto, Fortinet, Firepower, Syslog, Zeek, Splunk, Elastic, Defender for IoT, Claroty, Nozomi, Tenable.ot, and further out).

### Changed
- `pkg/acl/gaps.go` now consumes `[]flow.FlowRecord` instead of sentinel-specific types. `AnalyzeGaps` signature unchanged for external callers.
- `pkg/sentinel/client.go` converts vendor output to `FlowRecord` at the ingestion boundary; tags each record with `SourceID = "sentinel:<cfgID>"` and `SourceHash = sha256(query)`.
- Moved `pkg/sentinel/scoping.go` → `pkg/acl/scoping.go`; extracted CIDR→zone resolution into `pkg/flow/zoneresolve.go` so it is source-agnostic.
- CLI version constant `pkg/cli.Version` bumped to `0.30.0`; `web/package.json` version bumped to `0.30.0`.
- Simulator result drawer labels corrected: the **Source** row no longer appends `dest_port`, and the second **Source** row (which shows the ingestion source identifier) is now labeled **Source ID**.

### Removed
- Go-side `SentinelFlow` struct. The TypeScript deprecation alias (`export type SentinelFlow = FlowRecord`) is retained in `web/src/lib/types.ts` for one release.

### Deferred to 0.31
- **Pluggable flow sources** — `pkg/flowsource/`, `POST /api/flowsources/preview`, Splunk/Elastic/generic runners, and a preview-driven column-mapping UI (Integrations → Flow Sources sub-tab).
- **Test coverage** for `pkg/posture`, `pkg/sentinel`, `pkg/asa`.

## [0.1.0] — 2025-12-XX

Initial public release: CLI-only OT discovery across CIP/EIP, S7comm, Modbus TCP, MELSEC/SLMP, FINS, BACnet/IP, SRTP, and OPC UA; offline CISA ICS advisory matching; text/CSV/JSON/HTML/SARIF output; .dbd asset export/import; embedded web UI with inventory, compliance, PCAP, posture, baseline, enrichment, ACL policy, ASA drift, and Sentinel integration views.
