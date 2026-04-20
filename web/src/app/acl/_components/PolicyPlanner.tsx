"use client";

import { useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { SideDrawer } from "@/components/ui/SideDrawer";
import { useSimulatePolicy } from "@/lib/hooks/useACL";
import type {
  Policy,
  PolicyRule,
  SimulationResponse,
  Zone,
} from "@/lib/types";
import { SimulationResult } from "./SimulationResult";

type DraftRule = PolicyRule & { _tempId: string };

interface PolicyPlannerProps {
  open: boolean;
  onClose: () => void;
  policy: Policy;
  zones: Zone[];
}

function cloneRule(r: PolicyRule, i: number): DraftRule {
  return { ...r, ports: [...(r.ports ?? [])], _tempId: r.id || `new-${i}` };
}

function emptyRule(zones: Zone[], i: number): DraftRule {
  return {
    id: "",
    source_zone: zones[0]?.name ?? "",
    dest_zone: zones[1]?.name ?? zones[0]?.name ?? "",
    ports: [],
    action: "deny",
    description: "",
    _tempId: `new-${i}`,
  };
}

function parsePorts(input: string): number[] {
  return input
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => Number(p))
    .filter((p) => Number.isFinite(p) && p > 0 && p < 65536);
}

export function PolicyPlanner({ open, onClose, policy, zones }: PolicyPlannerProps) {
  const [draftRules, setDraftRules] = useState<DraftRule[]>(() =>
    (policy.rules ?? []).map(cloneRule),
  );
  const [defaultAction, setDefaultAction] = useState<"allow" | "deny">(policy.default_action);
  const [flowWindow, setFlowWindow] = useState<"24h" | "7d" | "30d">("7d");
  const [includeObserved, setIncludeObserved] = useState(true);
  const [includeImplied, setIncludeImplied] = useState(true);
  const [result, setResult] = useState<SimulationResponse | null>(null);

  const simulate = useSimulatePolicy();

  const plannedPolicy: Policy = useMemo(
    () => ({
      ...policy,
      rules: draftRules.map(({ _tempId, ...r }) => r),
      default_action: defaultAction,
    }),
    [policy, draftRules, defaultAction],
  );

  const run = () => {
    simulate.mutate(
      {
        site_id: policy.site_id,
        policy_id: policy.id,
        planned_policy: plannedPolicy,
        flow_window: flowWindow,
        include_observed: includeObserved,
        include_implied: includeImplied,
      },
      { onSuccess: setResult },
    );
  };

  const addRule = () => {
    setDraftRules((rs) => [...rs, emptyRule(zones, rs.length)]);
  };
  const removeRule = (tempId: string) => {
    setDraftRules((rs) => rs.filter((r) => r._tempId !== tempId));
    if (result) setResult(null);
  };
  const updateRule = (tempId: string, patch: Partial<DraftRule>) => {
    setDraftRules((rs) => rs.map((r) => (r._tempId === tempId ? { ...r, ...patch } : r)));
    if (result) setResult(null);
  };

  const dirty = useMemo(() => {
    if (defaultAction !== policy.default_action) return true;
    const originalRules = policy.rules ?? [];
    if (draftRules.length !== originalRules.length) return true;
    for (let i = 0; i < draftRules.length; i++) {
      const a = draftRules[i];
      const b = originalRules[i];
      if (
        a.source_zone !== b.source_zone ||
        a.dest_zone !== b.dest_zone ||
        a.action !== b.action ||
        (a.description ?? "") !== (b.description ?? "") ||
        (a.ports ?? []).join(",") !== (b.ports ?? []).join(",")
      ) {
        return true;
      }
    }
    return false;
  }, [draftRules, defaultAction, policy]);

  return (
    <SideDrawer
      open={open}
      onClose={onClose}
      width={900}
      title={
        <div>
          <h3 className="font-heading text-sm font-semibold text-db-text">
            Plan Change &mdash; {policy.name}
          </h3>
          <p className="text-[10px] text-db-muted mt-0.5">
            Edit rules on the right, then simulate to see which flows would be
            newly denied or newly allowed before you commit.
          </p>
        </div>
      }
    >
      <div className="p-4 space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <PolicyPane title="Current Policy" rules={policy.rules ?? []} defaultAction={policy.default_action} />
          <DraftPane
            rules={draftRules}
            zones={zones}
            defaultAction={defaultAction}
            onAdd={addRule}
            onRemove={removeRule}
            onUpdate={updateRule}
            onDefaultAction={setDefaultAction}
          />
        </div>

        <Card className="p-0 overflow-hidden">
          <div className="px-4 py-3 border-b border-db-border flex items-center gap-4 flex-wrap">
            <label className="flex items-center gap-1.5 text-xs text-db-text">
              <input
                type="checkbox"
                checked={includeObserved}
                onChange={(e) => setIncludeObserved(e.target.checked)}
              />
              Include observed flows
            </label>
            <label className="flex items-center gap-1.5 text-xs text-db-text">
              <input
                type="checkbox"
                checked={includeImplied}
                onChange={(e) => setIncludeImplied(e.target.checked)}
              />
              Include implied flows
            </label>
            <label className="flex items-center gap-1.5 text-xs text-db-text">
              Flow window:
              <select
                value={flowWindow}
                onChange={(e) => setFlowWindow(e.target.value as "24h" | "7d" | "30d")}
                className="bg-db-surface border border-db-border px-2 py-1 text-xs text-db-text focus:outline-none"
              >
                <option value="24h">24h</option>
                <option value="7d">7d</option>
                <option value="30d">30d</option>
              </select>
            </label>
            <div className="flex-1" />
            <Button size="sm" onClick={run} disabled={simulate.isPending || (!dirty && !result)}>
              {simulate.isPending ? "Simulating..." : result ? "Re-run" : "Simulate"}
            </Button>
          </div>

          {simulate.isError && (
            <div className="px-4 py-3 text-xs text-red-400">
              {(simulate.error as Error).message}
            </div>
          )}

          {result && <SimulationResult result={result} zones={zones} />}

          {!result && !simulate.isPending && !simulate.isError && (
            <div className="px-4 py-6 text-xs text-db-muted text-center">
              Edit rules above, then click Simulate to preview impact.
            </div>
          )}
        </Card>
      </div>
    </SideDrawer>
  );
}

function PolicyPane({
  title,
  rules,
  defaultAction,
}: {
  title: string;
  rules: PolicyRule[];
  defaultAction: string;
}) {
  return (
    <Card className="p-0 overflow-hidden">
      <div className="px-4 py-2.5 border-b border-db-border bg-db-bg">
        <h4 className="text-xs font-semibold text-db-text">{title}</h4>
        <p className="text-[10px] text-db-muted mt-0.5">
          {rules.length} rules &middot; default{" "}
          <span className="font-mono uppercase">{defaultAction}</span>
        </p>
      </div>
      <div className="divide-y divide-db-border/40 max-h-96 overflow-y-auto">
        {rules.length === 0 ? (
          <div className="px-4 py-6 text-center text-xs text-db-muted">No rules.</div>
        ) : (
          rules.map((r, i) => (
            <div key={r.id || i} className="px-3 py-2 text-xs space-y-0.5">
              <div className="flex items-center gap-2">
                <span
                  className={`text-[9px] font-mono px-1.5 py-0.5 border uppercase ${
                    r.action === "allow"
                      ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/40"
                      : "bg-red-500/10 text-red-400 border-red-500/40"
                  }`}
                >
                  {r.action}
                </span>
                <span className="text-db-text">
                  {r.source_zone} &rarr; {r.dest_zone}
                </span>
                <span className="font-mono text-db-muted text-[10px] ml-auto">
                  {(r.ports ?? []).length === 0 ? "all ports" : r.ports.join(",")}
                </span>
              </div>
              {r.description && (
                <div className="text-[10px] text-db-muted truncate">{r.description}</div>
              )}
            </div>
          ))
        )}
      </div>
    </Card>
  );
}

function DraftPane({
  rules,
  zones,
  defaultAction,
  onAdd,
  onRemove,
  onUpdate,
  onDefaultAction,
}: {
  rules: DraftRule[];
  zones: Zone[];
  defaultAction: "allow" | "deny";
  onAdd: () => void;
  onRemove: (tempId: string) => void;
  onUpdate: (tempId: string, patch: Partial<DraftRule>) => void;
  onDefaultAction: (a: "allow" | "deny") => void;
}) {
  return (
    <Card className="p-0 overflow-hidden">
      <div className="px-4 py-2.5 border-b border-db-border bg-db-bg flex items-center gap-2">
        <div className="flex-1 min-w-0">
          <h4 className="text-xs font-semibold text-db-text">Planned Policy</h4>
          <p className="text-[10px] text-db-muted mt-0.5 flex items-center gap-1">
            default
            <select
              value={defaultAction}
              onChange={(e) => onDefaultAction(e.target.value as "allow" | "deny")}
              className="bg-db-surface border border-db-border px-1 py-0.5 text-[10px] font-mono uppercase text-db-text focus:outline-none"
            >
              <option value="deny">DENY</option>
              <option value="allow">ALLOW</option>
            </select>
          </p>
        </div>
        <Button size="sm" variant="secondary" onClick={onAdd}>
          + Rule
        </Button>
      </div>
      <div className="divide-y divide-db-border/40 max-h-96 overflow-y-auto">
        {rules.length === 0 && (
          <div className="px-4 py-6 text-center text-xs text-db-muted">
            No rules. Click &quot;+ Rule&quot; to add one.
          </div>
        )}
        {rules.map((r) => (
          <div key={r._tempId} className="px-3 py-2 space-y-1.5 text-xs">
            <div className="flex items-center gap-1.5">
              <select
                value={r.action}
                onChange={(e) => onUpdate(r._tempId, { action: e.target.value as "allow" | "deny" })}
                className={`bg-db-surface border border-db-border px-1.5 py-0.5 text-[10px] font-mono uppercase focus:outline-none ${
                  r.action === "allow" ? "text-emerald-400" : "text-red-400"
                }`}
              >
                <option value="allow">ALLOW</option>
                <option value="deny">DENY</option>
              </select>
              <select
                value={r.source_zone}
                onChange={(e) => onUpdate(r._tempId, { source_zone: e.target.value })}
                className="bg-db-surface border border-db-border px-1.5 py-0.5 text-xs text-db-text focus:outline-none"
              >
                {zones.map((z) => (
                  <option key={z.id} value={z.name}>
                    {z.name}
                  </option>
                ))}
              </select>
              <span className="text-db-muted">&rarr;</span>
              <select
                value={r.dest_zone}
                onChange={(e) => onUpdate(r._tempId, { dest_zone: e.target.value })}
                className="bg-db-surface border border-db-border px-1.5 py-0.5 text-xs text-db-text focus:outline-none"
              >
                {zones.map((z) => (
                  <option key={z.id} value={z.name}>
                    {z.name}
                  </option>
                ))}
              </select>
              <button
                onClick={() => onRemove(r._tempId)}
                className="ml-auto text-db-muted hover:text-red-400 text-sm"
                aria-label="Remove rule"
              >
                &times;
              </button>
            </div>
            <input
              type="text"
              value={(r.ports ?? []).join(", ")}
              onChange={(e) => onUpdate(r._tempId, { ports: parsePorts(e.target.value) })}
              placeholder="ports (comma-separated, empty = all)"
              className="w-full bg-db-surface border border-db-border px-2 py-1 text-xs font-mono text-db-text focus:outline-none"
            />
            <input
              type="text"
              value={r.description ?? ""}
              onChange={(e) => onUpdate(r._tempId, { description: e.target.value })}
              placeholder="description (optional)"
              className="w-full bg-db-surface border border-db-border px-2 py-1 text-[11px] text-db-text focus:outline-none"
            />
          </div>
        ))}
      </div>
    </Card>
  );
}
