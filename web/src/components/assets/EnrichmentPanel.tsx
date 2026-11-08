"use client";

import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import type { QueryRecord } from "@/lib/types";

export function EnrichmentPanel({ ids }: { ids: string[] }) {
  const [record, setRecord] = useState<QueryRecord | null>(null);
  const [history, setHistory] = useState<QueryRecord[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const qc = useQueryClient();
  const running = record?.status === "running" || record?.status === "applying";
  const queryId=record?.plan.id;

  useEffect(() => { api.queryHistory().then(setHistory).catch(() => {}); }, []);
  useEffect(() => {
    if (!running || !queryId) return;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const next = await api.queryStatus(queryId);
        if (disposed) return;
        setRecord(next);
        if (next.status === "running" || next.status === "applying") timer = setTimeout(poll, 1000);
        else {
          qc.invalidateQueries({ queryKey: ["assets"] });
          qc.invalidateQueries({ queryKey: ["asset"] });
          qc.invalidateQueries({ queryKey: ["asset-summary"] });
          api.queryHistory().then(setHistory).catch(() => {});
        }
      } catch (e) { if (!disposed) { setError(e instanceof Error ? e.message : "Could not refresh query"); timer = setTimeout(poll, 3000); } }
    };
    timer = setTimeout(poll, 500);
    return () => { disposed = true; clearTimeout(timer); };
  }, [running, queryId, qc]);

  const preview = async (purpose: "enrich" | "verify") => {
    setBusy(true); setError("");
    try { setRecord(await api.previewQuery({ ids, purpose })); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not preview query"); }
    finally { setBusy(false); }
  };
  const execute = async () => {
    if (!record) return;
    setBusy(true); setError("");
    try { const next=await api.executeQuery(record.plan.id, record.plan.plan_hash);setRecord(next);if(next.status!=="running"&&next.status!=="applying"){qc.invalidateQueries({queryKey:["assets"]});qc.invalidateQueries({queryKey:["asset"]});qc.invalidateQueries({queryKey:["asset-summary"]});} }
    catch (e) { setError(e instanceof Error ? e.message : "Could not start query"); }
    finally { setBusy(false); }
  };
  const download = () => {
    if (!record) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(record, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = `deadband-query-${record.plan.id}.json`; link.click(); URL.revokeObjectURL(url);
  };

  return <Card>
    <h3 className="font-heading text-sm font-semibold">Asset enrichment</h3>
    <p className="text-xs text-db-muted mt-1">Query selected assets to complete identity details or read their current revision. Advisory rechecks use the local database and send no device queries.</p>
    <div className="flex flex-wrap items-center gap-2 mt-3">
      <Button size="sm" onClick={() => preview("enrich")} disabled={!ids.length || ids.length > 256 || busy || running}>Enrich missing details</Button>
      <Button size="sm" onClick={() => preview("verify")} disabled={!ids.length || ids.length > 256 || busy || running}>Verify firmware update</Button>
      <span className="text-xs text-db-muted">{ids.length ? `${ids.length} selected` : "Select assets below to preview a query"}</span>
      {history.length > 0 && <select aria-label="Previous enrichment queries" value="" disabled={running} onChange={async e => { const id=e.target.value; if (id) { try { setRecord(await api.queryStatus(id)); } catch { setError("Could not load query"); } } }} className="bg-db-bg border border-db-border p-1 text-xs text-db-text">
        <option value="">Previous queries…</option>
        {history.map(h => <option key={h.plan.id} value={h.plan.id}>{new Date(h.plan.created_at).toLocaleString()} · {h.plan.purpose} · {h.status}</option>)}
      </select>}
    </div>
    {error && <p role="alert" className="text-xs text-status-critical mt-3">{error}</p>}
    {record && <div className="mt-4 space-y-3">
      <div className="text-xs text-db-text">{record.plan.purpose === "verify" ? "Read current revision" : "Complete missing details"} · {record.plan.targets.length} target{record.plan.targets.length===1 ? "" : "s"} · <span className="font-mono">{record.status}</span></div>
      <p className="text-xs text-db-muted">One ENIP ListIdentity request per target on TCP/44818. Maximum {record.plan.budget.max_connections} connection{record.plan.budget.max_connections===1 ? "" : "s"} and {record.plan.budget.max_requests} request{record.plan.budget.max_requests===1 ? "" : "s"}, {record.plan.budget.requests_per_second} starts/second, {record.plan.budget.timeout_ms / 1000}s per target. Preview expires {new Date(record.plan.expires_at).toLocaleTimeString()}.</p>
      <div className="overflow-x-auto max-h-64 border border-db-border"><table className="w-full text-xs text-left"><thead className="text-db-muted"><tr><th className="p-2">Target</th><th className="p-2">Expected model</th><th className="p-2">Fields requested</th></tr></thead><tbody>{record.plan.targets.map(t => <tr key={t.asset_id} className="border-t border-db-border"><td className="p-2 font-mono">{t.ip}:44818</td><td className="p-2">{t.expected.model || "Unknown"}</td><td className="p-2">{t.requested_fields.join(", ")}</td></tr>)}</tbody></table></div>
      {record.excluded.length > 0 && <details className="text-xs text-db-muted"><summary>{record.excluded.length} selected assets excluded</summary><ul className="mt-2 space-y-1">{record.excluded.map(e => <li key={e.asset_id}>{e.asset_id}: {e.reason}</li>)}</ul></details>}
      <div className="flex flex-wrap gap-3 items-center">
        {record.status === "preview" && <Button size="sm" disabled={busy} onClick={execute}>Run query</Button>}
        {running && <Button size="sm" onClick={async () => { try { await api.cancelQuery(record.plan.id); } catch (e) { setError(e instanceof Error ? e.message : "Could not cancel"); } }}>Cancel query</Button>}
        <a className="text-xs text-db-teal-light underline" href={`/api/queries/${encodeURIComponent(record.plan.id)}/access.csv`}>Download access requirements</a>
        <button className="text-xs text-db-teal-light underline" onClick={download}>Download evidence</button>
      </div>
      {record.error && <p role="alert" className="text-xs text-status-critical">{record.error}</p>}
      {record.result && <div className="space-y-2">{record.result.outcomes.map(o => <details key={o.asset_id} className="border border-db-border p-2 text-xs" open={o.status === "identity_conflict"}>
        <summary><span className="font-mono">{o.ip}</span> · {o.status.replaceAll("_", " ")} · {o.metrics.connections} connection{o.metrics.connections===1 ? "" : "s"} / {o.metrics.requests} request{o.metrics.requests===1 ? "" : "s"}</summary>
        {o.error && <p className="mt-2 text-db-muted">{o.error}</p>}
        <p className="mt-2 text-db-muted">Observed {new Date(o.observed_at).toLocaleString()}; application payload {o.metrics.bytes_sent} bytes sent / {o.metrics.bytes_received} received.</p>
        <ul className="mt-2 space-y-1">{o.observations.map((v,i) => <li key={i}>{v.field}: <span className="font-mono">{v.value}</span>{v.version_kind && ` (${v.version_kind.replaceAll("_", " ")})`}</li>)}</ul>
        {record.assessments?.filter(a => a.asset_id===o.asset_id).map(a => <div key={a.asset_id} className="mt-2 text-db-muted"><p>Advisory assessment: {a.previous?.status || "Unchecked"} → {a.current.status.replaceAll("_"," ")}; revision {a.firmware_before || "unknown"} → {a.firmware_after || "unknown"}.</p>{a.current.reason && <p>{a.current.reason}</p>}</div>)}
      </details>)}<p className="text-xs text-db-muted">Revision evidence is specific to the responding identity component. No advisory match alone does not establish remediation.</p></div>}
    </div>}
  </Card>;
}
