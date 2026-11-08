# Deadband platform cohesion

The shared product loop should be **collect → enrich → assess → act → verify**. Each screen should expose its current evidence, explain the next useful action, and preserve history across the CLI, agent, Cloud, and Ops.

## Changes implemented with targeted enrichment

- The local and hosted asset workflows use the same **Enrich missing details** and **Verify firmware update** language. Offline advisory rechecks remain distinct from device queries.
- Bounded queries have an explicit target/operation preview and retain evidence, traffic metrics, conflicts, and assessment snapshots. Capability gating prevents old agents from interpreting a new query as broad discovery.
- Local posture scans are separately selected and share the scan execution slot. Empty discovery results no longer prove a Cloud topology path is blocked.
- The agent imports the CLI’s query package at an exact public Go module version and verifies it with module checksums. Cross-language hash fixtures remain shared. Cloud and Ops consume the same versioned, integrity-checked contract package, while dispatch policy and tenant authorization stay in each app.
- Recurring Cloud revision refresh pins its target set, uses field observation age, and generates a fresh plan within a timezone-aware maintenance window. The local asset layout now remains usable on narrow screens, with accessible navigation and horizontally scrollable evidence tables.
- Incomplete inventory imports preserve enrichment candidates. S7 and capture-format compatibility now have independent fixtures, and the responder harness frames TCP requests correctly.

## Platform validation and identity foundation

- Cloud’s **Scans → Lab validation** starts with normal agent enrollment and one declared endpoint in a saved network. It stores independent baselines and expectations, previews the exact query, dispatches an ordinary agent job, and exports linked evidence and user observations. The user’s physical-device test requires no separate responder or scanner command.
- Endpoint scopes and component bindings preserve stable asset IDs. Overlapping address spaces and equal cards in different slots remain distinct. Unique, consistently scoped legacy identities can be adopted without changing their fingerprints or history; ambiguous or conflicting records stay visible for review.
- Immutable events retain raw ordinary scan and capture identities before inventory rollup. Root ENIP identities remain alongside chassis modules. BACnet instance/routed-address metadata and application versus firmware versions remain separate.
- Query application checks both asset and binding context. Expected-value comparisons and user-reported operational impact are separate results. Ops exposes pending observations and reported impact without equating query success with device tolerance.
- A generated capability registry feeds the shared contract and public targeted-query matrix. Planned protocol profiles have no executable profile IDs. Readiness normalization keeps configuration inference, policy lookup, route lookup and transport observations as distinct evidence layers.

## Recommended next product work

| Priority | Improvement | Why it matters / completion criterion |
|---|---|---|
| 1 | Complete legacy reconciliation review. | The new scope/binding foundation preserves IDs and adopts only unambiguous scoped candidates. Next add explicit preview/apply decisions for unresolved duplicates and replacements; historical identities lost by earlier rollup cannot be reconstructed. |
| 1 | Complete independent platform lab runs. | The enrolled-machine test flow is implemented. Physical-device tolerance and observed firmware accuracy remain pending independent lab reports for each device family. |
| 2 | Make assessment explanations consistent across reports and dashboards. | Use explicit “insufficient identity,” “version uncertain,” “known affected,” and “no applicable catalog match” language. Separate exploit severity from confidence that this exact component is affected. |
| 2 | Connect readiness imports to topology. | The normalized evidence model and exact-flow ACL adapter are implemented. Next add reviewed import and display of provenance-bearing facts; retain incomplete and stale states. |
| 2 | Add bounded protocol profiles by demonstrated customer value. | Follow ENIP with known-unit Modbus, known-TSAP S7, known-instance BACnet, route-less ADS, and selected SOPAS reads. Every profile needs endpoint/operation tests, stopping rules, negative assertions, and device-family lab evidence. |
| 3 | Provide one job timeline across collection, assessment, and verification. | Show why work ran, what it sought, whether scope/limits were reached, fields changed, and advisory decisions changed. Link individual observations back to their execution and source capture. |
| 3 | Extend generated capability coverage. | Targeted query metadata now shares one generated source. Extend that registry to legacy discovery operations, CLI help and agent diagnostics; retain explicit differences between implementations. |
| 3 | Reassemble fragmented passive streams. | Preserve bounded per-flow framing and ambiguity instead of relying on arbitrary packet payload slices. Validate truncated, reordered and overlapping traffic before broadening parsers. |

The strongest customer outcomes to measure are fresh useful revision evidence, resolved advisory uncertainty, successful verification, and fewer unnecessary queries. Raw discovered-device counts are supporting metrics. Preserve unresolved and conflicting results so apparent coverage does not hide uncertainty.
