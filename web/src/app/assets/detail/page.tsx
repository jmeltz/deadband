"use client";

import { useSearchParams } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, StatCard } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { formatDateTime } from "@/lib/utils/format";
import { useState, Suspense } from "react";
import Link from "next/link";
import type { Asset, Criticality } from "@/lib/types";

function AssetDetailContent() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") ?? "";
  const qc = useQueryClient();

  const { data: asset, isLoading } = useQuery({
    queryKey: ["asset", id],
    queryFn: () => api.getAsset(id),
    enabled: !!id,
  });

  const updateAsset = useMutation({
    mutationFn: (patch: Partial<Asset>) => api.updateAsset(id, patch),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asset", id] });
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
  });

  const checkAssets = useMutation({
    mutationFn: () => api.checkAssets({ ids: [id] }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asset", id] });
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
  });

  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({
    name: "",
    site: "",
    zone: "",
    criticality: "" as Criticality,
    tags: "",
    notes: "",
    status: "",
    hostname: "",
  });

  if (isLoading) {
    return <div className="text-db-muted text-sm p-8">Loading...</div>;
  }

  if (!asset) {
    return <div className="text-db-muted text-sm p-8">Asset not found.</div>;
  }

  const startEdit = () => {
    setForm({
      name: asset.name,
      site: asset.site,
      zone: asset.zone,
      criticality: (asset.criticality || "") as Criticality,
      tags: asset.tags?.join(", ") ?? "",
      notes: asset.notes,
      status: asset.status,
      hostname: asset.hostname ?? "",
    });
    setEditing(true);
  };

  const saveEdit = () => {
    updateAsset.mutate(
      {
        name: form.name,
        site: form.site,
        zone: form.zone,
        criticality: form.criticality,
        tags: form.tags.split(",").map((t) => t.trim()).filter(Boolean),
        notes: form.notes,
        status: form.status,
        hostname: form.hostname,
      },
      { onSuccess: () => setEditing(false) },
    );
  };

  const vs = asset.vuln_state;
  const statusColors: Record<string, string> = {
    VULNERABLE: "bg-status-critical/20 text-status-critical border-status-critical/30",
    POTENTIAL: "bg-status-medium/20 text-status-medium border-status-medium/30",
    OK: "bg-status-ok/20 text-status-ok border-status-ok/30",
  };

  return (
    <div className="max-w-5xl space-y-6">
      {/* Back link */}
      <Link href="/assets" className="text-xs text-db-teal-light hover:text-db-text transition-colors">
        &larr; Back to Assets
      </Link>

      {/* Header */}
      <Card>
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <h2 className="text-lg font-heading font-semibold text-db-text">
              {asset.name || asset.model || asset.ip}
            </h2>
            <div className="flex items-center gap-3 text-xs text-db-muted">
              <span className="font-mono">{asset.ip}</span>
              <span>{asset.vendor}</span>
              <span className="font-mono">{asset.model}</span>
              <span className="font-mono">fw {asset.firmware}</span>
            </div>
            <div className="flex items-center gap-2 mt-2">
              {asset.protocol && (
                <span className="px-1.5 py-0.5 text-[10px] rounded-sm border border-db-teal/30 bg-db-teal-dim text-db-teal-light uppercase">
                  {asset.protocol}
                </span>
              )}
              {asset.port ? (
                <span className="text-[10px] font-mono text-db-muted">:{asset.port}</span>
              ) : null}
              {asset.status && (
                <span className={`px-1.5 py-0.5 text-[10px] rounded-sm border ${
                  asset.status === "active"
                    ? "border-status-ok/30 bg-status-ok/10 text-status-ok"
                    : asset.status === "quarantined"
                      ? "border-status-critical/30 bg-status-critical/10 text-status-critical"
                      : "border-db-border bg-db-surface text-db-muted"
                }`}>
                  {asset.status}
                </span>
              )}
              {asset.criticality && (
                <CritBadge value={asset.criticality} />
              )}
            </div>
          </div>
          <div className="flex gap-2">
            <Button
              size="sm"
              onClick={() => checkAssets.mutate()}
              disabled={checkAssets.isPending}
            >
              {checkAssets.isPending ? "Checking..." : "Re-check"}
            </Button>
            {!editing && (
              <Button size="sm" variant="ghost" onClick={startEdit}>
                Edit
              </Button>
            )}
          </div>
        </div>
      </Card>

      {/* Hardware identity */}
      <div className="grid grid-cols-4 gap-4">
        <MiniStat label="Serial" value={asset.serial} />
        <MiniStat label="MAC" value={asset.mac} />
        <MiniStat label="Hostname" value={asset.hostname} />
        <MiniStat label="Order Number" value={asset.order_number} />
      </div>

      {/* Metadata edit form */}
      {editing && (
        <Card>
          <h3 className="font-heading text-sm font-semibold mb-3">Edit Metadata</h3>
          <div className="grid grid-cols-3 gap-3">
            <Field label="Name" value={form.name} onChange={(v) => setForm({ ...form, name: v })} />
            <Field label="Site" value={form.site} onChange={(v) => setForm({ ...form, site: v })} />
            <Field label="Zone" value={form.zone} onChange={(v) => setForm({ ...form, zone: v })} />
            <Field label="Hostname" value={form.hostname} onChange={(v) => setForm({ ...form, hostname: v })} />
            <div>
              <label className="block text-[10px] text-db-muted mb-1">Criticality</label>
              <select
                value={form.criticality}
                onChange={(e) => setForm({ ...form, criticality: e.target.value as Criticality })}
                className="w-full bg-db-bg border border-db-border px-2 py-1 text-xs text-db-text focus:outline-none input-industrial"
              >
                <option value="">None</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label className="block text-[10px] text-db-muted mb-1">Status</label>
              <select
                value={form.status}
                onChange={(e) => setForm({ ...form, status: e.target.value })}
                className="w-full bg-db-bg border border-db-border px-2 py-1 text-xs text-db-text focus:outline-none input-industrial"
              >
                <option value="active">Active</option>
                <option value="retired">Retired</option>
                <option value="quarantined">Quarantined</option>
              </select>
            </div>
            <Field label="Tags (comma-separated)" value={form.tags} onChange={(v) => setForm({ ...form, tags: v })} />
            <Field label="Notes" value={form.notes} onChange={(v) => setForm({ ...form, notes: v })} />
          </div>
          <div className="flex gap-2 mt-3">
            <Button size="sm" onClick={saveEdit} disabled={updateAsset.isPending}>
              {updateAsset.isPending ? "Saving..." : "Save"}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>
              Cancel
            </Button>
          </div>
        </Card>
      )}

      {/* Metadata display (when not editing) */}
      {!editing && (
        <Card>
          <h3 className="font-heading text-sm font-semibold mb-3">Metadata</h3>
          <div className="grid grid-cols-4 gap-y-3 gap-x-6 text-xs">
            <MetaRow label="Site" value={asset.site} />
            <MetaRow label="Zone" value={asset.zone} />
            <MetaRow label="Source" value={asset.source} />
            <MetaRow label="First Seen" value={asset.first_seen ? formatDateTime(asset.first_seen) : ""} />
            <MetaRow label="Last Seen" value={asset.last_seen ? formatDateTime(asset.last_seen) : ""} />
            <MetaRow label="Notes" value={asset.notes} />
            <div className="col-span-2">
              <span className="text-db-muted">Tags: </span>
              {asset.tags?.length > 0 ? (
                <span className="space-x-1">
                  {asset.tags.map((t) => (
                    <span key={t} className="px-1.5 py-0.5 text-[10px] bg-db-teal-dim text-db-teal-light rounded-sm">
                      {t}
                    </span>
                  ))}
                </span>
              ) : (
                <span className="text-db-muted/50 italic">none</span>
              )}
            </div>
          </div>
        </Card>
      )}

      {/* Vulnerability state */}
      <Card>
        <h3 className="font-heading text-sm font-semibold mb-3">Vulnerability Assessment</h3>
        {vs ? (
          <>
            <div className="grid grid-cols-4 gap-4 mb-4">
              <div className="space-y-1">
                <span className="text-[10px] text-db-muted uppercase tracking-wider">Status</span>
                <div>
                  <span className={`px-2 py-1 text-xs rounded-sm border ${statusColors[vs.status] ?? "bg-db-surface text-db-muted border-db-border"}`}>
                    {vs.status}
                  </span>
                </div>
              </div>
              <div className="space-y-1">
                <span className="text-[10px] text-db-muted uppercase tracking-wider">Risk Score</span>
                <div className="text-lg font-heading font-semibold text-db-text">{vs.risk_score.toFixed(1)}</div>
              </div>
              <div className="space-y-1">
                <span className="text-[10px] text-db-muted uppercase tracking-wider">CVEs</span>
                <div className="text-lg font-heading font-semibold text-db-text">{vs.cve_count}</div>
              </div>
              <div className="space-y-1">
                <span className="text-[10px] text-db-muted uppercase tracking-wider">Checked</span>
                <div className="text-xs text-db-muted">{formatDateTime(vs.checked_at)}</div>
              </div>
            </div>

            {vs.kev_count > 0 && (
              <div className="mb-4 px-3 py-2 rounded-sm border border-status-critical/30 bg-status-critical/5">
                <span className="text-xs text-status-critical font-bold">KEV</span>
                <span className="text-xs text-db-muted ml-2">
                  {vs.kev_count} advisory{vs.kev_count !== 1 ? "ies" : "y"} in CISA Known Exploited Vulnerabilities catalog
                </span>
              </div>
            )}

            {/* Advisory list */}
            {vs.advisories && vs.advisories.length > 0 && (
              <div className="space-y-1">
                <h4 className="text-xs font-medium text-db-muted mb-2">Matched Advisories</h4>
                {vs.advisories.map((adv) => (
                  <Link
                    key={adv.id}
                    href={`/advisories?advisory=${adv.id}`}
                    className="flex items-center gap-3 py-2 px-3 -mx-3 rounded table-row-hover transition-colors"
                  >
                    <CvssBadge score={adv.cvss_v3} />
                    <span className="text-xs font-mono text-db-muted w-36 shrink-0">{adv.id}</span>
                    <span className="text-xs text-db-text truncate flex-1">{adv.title}</span>
                    {adv.kev && <span className="text-[10px] text-status-critical font-bold shrink-0">KEV</span>}
                    <span className="text-[10px] text-db-muted font-mono shrink-0">
                      risk {adv.risk_score.toFixed(0)}
                    </span>
                  </Link>
                ))}
              </div>
            )}
          </>
        ) : (
          <div className="text-center py-6">
            <p className="text-xs text-db-muted mb-3">This asset has not been checked for vulnerabilities yet.</p>
            <Button
              size="sm"
              onClick={() => checkAssets.mutate()}
              disabled={checkAssets.isPending}
            >
              {checkAssets.isPending ? "Checking..." : "Check Now"}
            </Button>
          </div>
        )}
      </Card>
    </div>
  );
}

export default function AssetDetailPage() {
  return (
    <Suspense fallback={<div className="text-db-muted text-sm p-8">Loading...</div>}>
      <AssetDetailContent />
    </Suspense>
  );
}

function MiniStat({ label, value }: { label: string; value?: string }) {
  return (
    <Card className="flex flex-col gap-0.5 p-3">
      <span className="text-[10px] text-db-muted uppercase tracking-wider">{label}</span>
      <span className="text-xs font-mono text-db-text">
        {value || <span className="text-db-muted/40 italic">---</span>}
      </span>
    </Card>
  );
}

function MetaRow({ label, value }: { label: string; value?: string }) {
  return (
    <div>
      <span className="text-db-muted">{label}: </span>
      <span className="text-db-text">{value || <span className="text-db-muted/50 italic">---</span>}</span>
    </div>
  );
}

function Field({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <div>
      <label className="block text-[10px] text-db-muted mb-1">{label}</label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full bg-db-bg border border-db-border px-2 py-1 text-xs text-db-text focus:outline-none input-industrial"
      />
    </div>
  );
}

function CritBadge({ value }: { value: string }) {
  const colors: Record<string, string> = {
    critical: "bg-status-critical/20 text-status-critical border-status-critical/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-status-medium/20 text-status-medium border-status-medium/30",
    low: "bg-status-ok/20 text-status-ok border-status-ok/30",
  };
  return (
    <span className={`px-1.5 py-0.5 text-[10px] rounded-sm border ${colors[value] ?? "bg-db-surface text-db-muted border-db-border"}`}>
      {value}
    </span>
  );
}

function CvssBadge({ score }: { score: number }) {
  let color = "bg-db-surface text-db-muted border-db-border";
  if (score >= 9) color = "bg-status-critical/20 text-status-critical border-status-critical/30";
  else if (score >= 7) color = "bg-orange-500/20 text-orange-400 border-orange-500/30";
  else if (score >= 4) color = "bg-status-medium/20 text-status-medium border-status-medium/30";
  else if (score > 0) color = "bg-status-ok/20 text-status-ok border-status-ok/30";
  return (
    <span className={`px-1.5 py-0.5 text-[10px] font-mono rounded-sm border shrink-0 ${color}`}>
      {score.toFixed(1)}
    </span>
  );
}
