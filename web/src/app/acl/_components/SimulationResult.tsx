"use client";

import { useState } from "react";
import type { FlowVerdict, SimulationResponse, Zone } from "@/lib/types";

interface SimulationResultProps {
  result: SimulationResponse;
  zones: Zone[];
}

type Tab = "newly_denied" | "newly_allowed" | "unchanged";

export function SimulationResult({ result, zones }: SimulationResultProps) {
  const [tab, setTab] = useState<Tab>(
    result.diff.newly_denied.length > 0
      ? "newly_denied"
      : result.diff.newly_allowed.length > 0
        ? "newly_allowed"
        : "unchanged",
  );

  const sensitiveZones = new Set(
    zones.filter((z) => z.purpose === "ot" || z.purpose === "safety").map((z) => z.name),
  );

  const tabs: { key: Tab; label: string; count: number; tone: string }[] = [
    {
      key: "newly_denied",
      label: "Newly Denied",
      count: result.diff.newly_denied.length,
      tone: "text-red-400",
    },
    {
      key: "newly_allowed",
      label: "Newly Allowed",
      count: result.diff.newly_allowed.length,
      tone: "text-emerald-400",
    },
    {
      key: "unchanged",
      label: "Unchanged",
      count: result.diff.unchanged.count,
      tone: "text-db-muted",
    },
  ];

  return (
    <div>
      <SummaryBar current={result.current} planned={result.planned} />
      <div className="flex border-b border-db-border bg-db-surface">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`px-4 py-2.5 text-xs font-medium transition-colors ${
              tab === t.key
                ? "border-b-2 border-db-teal text-db-teal-light"
                : "text-db-muted hover:text-db-text"
            }`}
          >
            <span className={tab === t.key ? "" : t.tone}>{t.label}</span>
            <span className="ml-1.5 text-[10px] font-mono">({t.count})</span>
          </button>
        ))}
      </div>

      {tab === "newly_denied" && (
        <VerdictList verdicts={result.diff.newly_denied} sensitiveZones={sensitiveZones} tone="deny" />
      )}
      {tab === "newly_allowed" && (
        <VerdictList verdicts={result.diff.newly_allowed} sensitiveZones={sensitiveZones} tone="allow" />
      )}
      {tab === "unchanged" && <UnchangedView result={result} />}
    </div>
  );
}

function SummaryBar({
  current,
  planned,
}: {
  current: SimulationResponse["current"];
  planned: SimulationResponse["planned"];
}) {
  const delta = (a: number, b: number) => {
    const d = b - a;
    if (d === 0) return "";
    const sign = d > 0 ? "+" : "";
    return ` (${sign}${d})`;
  };
  return (
    <div className="px-4 py-2 bg-db-bg border-b border-db-border flex items-center gap-4 text-[10px] font-mono">
      <span className="text-db-muted uppercase">Flows evaluated</span>
      <span className="text-db-text">
        {current.total}
        <span className="text-db-muted"> total</span>
      </span>
      <span className="text-emerald-400">
        {planned.permit} permit<span className="text-db-muted">{delta(current.permit, planned.permit)}</span>
      </span>
      <span className="text-red-400">
        {planned.deny} deny<span className="text-db-muted">{delta(current.deny, planned.deny)}</span>
      </span>
      {planned.implied > 0 && (
        <span className="text-db-muted">{planned.implied} implied</span>
      )}
    </div>
  );
}

function VerdictList({
  verdicts,
  sensitiveZones,
  tone,
}: {
  verdicts: FlowVerdict[];
  sensitiveZones: Set<string>;
  tone: "allow" | "deny";
}) {
  const [selected, setSelected] = useState<FlowVerdict | null>(null);

  if (verdicts.length === 0) {
    return (
      <div className="px-4 py-8 text-center text-xs text-db-muted">
        No flows in this bucket.
      </div>
    );
  }

  // Group by (srcZone, dstZone)
  const groups = new Map<string, FlowVerdict[]>();
  for (const v of verdicts) {
    const key = `${v.flow.source_zone || "?"}|${v.flow.dest_zone || "?"}`;
    const arr = groups.get(key) ?? [];
    arr.push(v);
    groups.set(key, arr);
  }

  return (
    <>
      <div className="divide-y divide-db-border/50">
        {[...groups.entries()].map(([key, vs]) => {
          const [src, dst] = key.split("|");
          const dstSensitive = sensitiveZones.has(dst);
          return (
            <div key={key}>
              <div
                className={`px-4 py-2 bg-db-bg flex items-center gap-2 text-[11px] ${
                  dstSensitive ? "border-l-2 border-l-red-500" : ""
                }`}
              >
                <span className="text-db-text font-medium">
                  {src} &rarr; {dst}
                </span>
                {dstSensitive && (
                  <span className="text-[9px] font-mono px-1 py-0.5 border bg-red-500/10 text-red-400 border-red-500/40 uppercase">
                    {dst === "safety" ? "safety" : "ot"}
                  </span>
                )}
                <span className="text-db-muted font-mono ml-auto">
                  {vs.length} flow{vs.length !== 1 ? "s" : ""}
                </span>
              </div>
              {vs.map((v, i) => (
                <VerdictRow
                  key={`${key}-${i}`}
                  verdict={v}
                  tone={tone}
                  onSelect={() => setSelected(v)}
                />
              ))}
            </div>
          );
        })}
      </div>
      {selected && (
        <VerdictDetail verdict={selected} onClose={() => setSelected(null)} />
      )}
    </>
  );
}

function VerdictRow({
  verdict,
  tone,
  onSelect,
}: {
  verdict: FlowVerdict;
  tone: "allow" | "deny";
  onSelect: () => void;
}) {
  const f = verdict.flow;
  const user = f.enrichment?.UserName || f.enrichment?.user_name;
  const dept = f.enrichment?.Department || f.enrichment?.department;
  return (
    <div
      onClick={onSelect}
      className="px-4 py-2 cursor-pointer table-row-hover flex items-center gap-2 text-xs"
    >
      <span
        className={`text-[9px] font-mono px-1.5 py-0.5 border uppercase ${
          f.kind === "implied"
            ? "bg-db-surface text-db-muted border-db-border"
            : "bg-db-teal-dim/30 text-db-teal-light border-db-teal/40"
        }`}
      >
        {f.kind}
      </span>
      <span className="font-mono text-db-text">
        {f.source_addr} &rarr; {f.dest_addr}:{f.dest_port}
      </span>
      <span className="text-[10px] font-mono text-db-muted">{f.protocol}</span>
      {user && (
        <span className="text-[10px] text-db-muted truncate max-w-[180px]">
          {user}
          {dept ? ` / ${dept}` : ""}
        </span>
      )}
      <span className="flex-1" />
      {f.kind === "observed" && (
        <span className="text-[10px] font-mono text-db-muted">
          {f.connection_count} conn
        </span>
      )}
      {f.enrichment?.tuple_count && (
        <span className="text-[10px] font-mono text-db-muted">
          {f.enrichment.tuple_count} tuples (collapsed)
        </span>
      )}
      <span
        className={`text-[10px] font-mono uppercase ${
          tone === "deny" ? "text-red-400" : "text-emerald-400"
        }`}
      >
        {verdict.action}
      </span>
    </div>
  );
}

function VerdictDetail({
  verdict,
  onClose,
}: {
  verdict: FlowVerdict;
  onClose: () => void;
}) {
  const f = verdict.flow;
  const entries = Object.entries(f.enrichment ?? {});
  return (
    <div className="fixed inset-0 z-[60] flex justify-end" onClick={(e) => {
      if (e.target === e.currentTarget) onClose();
    }}>
      <div className="absolute inset-0 bg-black/50" />
      <div className="relative h-full w-[480px] max-w-full bg-db-bg border-l border-db-border overflow-y-auto">
        <div className="sticky top-0 bg-db-bg border-b border-db-border px-4 py-3 flex items-center justify-between">
          <h4 className="text-sm font-semibold text-db-text">Flow verdict</h4>
          <button onClick={onClose} className="text-db-muted hover:text-db-text text-lg">
            &times;
          </button>
        </div>
        <div className="p-4 space-y-3 text-xs">
          <DetailRow label="Action" value={verdict.action.toUpperCase()} mono />
          <DetailRow label="Reason" value={verdict.reason} />
          <DetailRow label="Matched rule" value={verdict.matched_rule_id || "default"} mono />
          <DetailRow label="Source" value={`${f.source_addr} (${f.source_zone || "?"})`} mono />
          <DetailRow label="Dest" value={`${f.dest_addr}:${f.dest_port} (${f.dest_zone || "?"})`} mono />
          <DetailRow label="Protocol" value={f.protocol} mono />
          <DetailRow label="Kind" value={f.kind} mono />
          <DetailRow label="Connection count" value={String(f.connection_count)} mono />
          <DetailRow label="Observed at" value={f.observed_at || "\u2014"} mono />
          <DetailRow label="Source ID" value={f.source_id || "\u2014"} mono />
          {entries.length > 0 && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-db-muted mb-1">
                Enrichment
              </div>
              <dl className="divide-y divide-db-border/40 border border-db-border/40">
                {entries.map(([k, v]) => (
                  <div key={k} className="grid grid-cols-[140px_1fr] px-2 py-1">
                    <dt className="text-db-muted text-[10px] font-mono">{k}</dt>
                    <dd className="text-db-text text-[11px] font-mono break-all">{v}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-2">
      <span className="text-[10px] uppercase tracking-wider text-db-muted pt-0.5">
        {label}
      </span>
      <span className={`text-db-text ${mono ? "font-mono text-[11px] break-all" : ""}`}>
        {value}
      </span>
    </div>
  );
}

function UnchangedView({ result }: { result: SimulationResponse }) {
  const byZone = result.diff.unchanged.by_zone ?? [];
  if (byZone.length === 0) {
    return (
      <div className="px-4 py-8 text-center text-xs text-db-muted">
        No unchanged flows in this run.
      </div>
    );
  }
  const sorted = [...byZone].sort((a, b) => b.count - a.count);
  return (
    <div className="divide-y divide-db-border/40">
      {sorted.map((z) => (
        <div
          key={`${z.source_zone}|${z.dest_zone}`}
          className="px-4 py-2 flex items-center gap-2 text-xs"
        >
          <span className="text-db-text">
            {z.source_zone || "?"} &rarr; {z.dest_zone || "?"}
          </span>
          <span className="flex-1" />
          <span className="text-[10px] font-mono text-db-muted">
            {z.count} flow{z.count !== 1 ? "s" : ""}
          </span>
        </div>
      ))}
    </div>
  );
}
