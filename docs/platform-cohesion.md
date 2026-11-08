# Deadband platform cohesion

The shared product loop should be **collect → enrich → assess → act → verify**. Each screen should expose its current evidence, explain the next useful action, and preserve history across the CLI, agent, Cloud, and Ops.

## Changes implemented with targeted enrichment

- The local and hosted asset workflows use the same **Enrich missing details** and **Verify firmware update** language. Offline advisory rechecks remain distinct from device queries.
- Bounded queries have an explicit target/operation preview and retain evidence, traffic metrics, conflicts, and assessment snapshots. Capability gating prevents old agents from interpreting a new query as broad discovery.
- Local posture scans are separately selected and share the scan execution slot. Empty discovery results no longer prove a Cloud topology path is blocked.
- The agent and CLI query engine use identical source and cross-language hash fixtures. Ops mirrors the additive evidence schema and exposes operational coverage. Public copy distinguishes the hosted agent and local CLI implementations.
- Recurring Cloud revision refresh pins its target set, uses field observation age, and generates a fresh plan within a timezone-aware maintenance window. The local asset layout now remains usable on narrow screens, with accessible navigation and horizontally scrollable evidence tables.
- Incomplete inventory imports preserve enrichment candidates. S7 and capture-format compatibility now have independent fixtures, and the responder harness frames TCP requests correctly.

## Recommended next product work

| Priority | Improvement | Why it matters / completion criterion |
|---|---|---|
| 1 | Introduce explicit endpoint/component hierarchy in inventory. | Keep a root ENIP endpoint separate from its CPU/backplane cards and routed children. Expose the correct query action for each component and version kind. |
| 1 | Migrate legacy discovery identity conservatively. | Targeted enrichment uses stable asset IDs, but legacy Cloud discovery fingerprints still depend on mutable identity and omit network/slot context. Add network-scoped endpoint IDs and component IDs with previewable reconciliation and history-preserving adoption; do not blanket-rehash existing records. |
| 1 | Share the Cloud/Ops schema and plan types as one versioned package. | Replace hand-maintained table copies with a single reviewed contract. Retain cross-version migration and Go/TypeScript conformance tests. |
| 2 | Make assessment explanations consistent across reports and dashboards. | Use explicit “insufficient identity,” “version uncertain,” “known affected,” and “no applicable catalog match” language. Separate exploit severity from confidence that this exact component is affected. |
| 2 | Unify readiness evidence with topology. | Start from imported switch/firewall facts. Display policy inference, firewall lookup, and observed transport evidence separately, with timestamps and incomplete-data states. Access exports should describe only the selected plan. |
| 2 | Add bounded protocol profiles by demonstrated customer value. | Follow ENIP with known-unit Modbus, known-TSAP S7, known-instance BACnet, route-less ADS, and selected SOPAS reads. Every profile needs endpoint/operation tests, stopping rules, negative assertions, and device-family lab evidence. |
| 3 | Provide one job timeline across collection, assessment, and verification. | Show why work ran, what it sought, whether scope/limits were reached, fields changed, and advisory decisions changed. Link individual observations back to their execution and source capture. |
| 3 | Publish a capability matrix generated from shipped contracts. | Align CLI help, agent doctor, Cloud agent picker, Ops compatibility, and site documentation. Avoid marketing claims that imply parity beyond tested shared profiles. |

The strongest customer outcomes to measure are fresh useful revision evidence, resolved advisory uncertainty, successful verification, and fewer unnecessary queries. Raw discovered-device counts are supporting metrics. Preserve unresolved and conflicting results so apparent coverage does not hide uncertainty.
