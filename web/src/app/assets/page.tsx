"use client";

import { useMemo, useRef, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { useAssets, useDeleteAsset, useCheckAssets } from "@/lib/hooks/useAssets";
import { api } from "@/lib/api";
import { useQueryClient } from "@tanstack/react-query";
import { formatDate, relativeTime } from "@/lib/utils/format";
import type { Asset } from "@/lib/types";

const VULN_STATUSES = ["VULNERABLE", "POTENTIAL", "OK"] as const;

export default function AssetsPage() {
  const [search, setSearch] = useState("");
  const [vendorFilter, setVendorFilter] = useState("");
  const [vulnFilter, setVulnFilter] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [importing, setImporting] = useState(false);
  const [importMessage, setImportMessage] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const { data, isLoading } = useAssets({
    q: search || undefined,
    vendor: vendorFilter || undefined,
    vuln_status: vulnFilter || undefined,
    sort: "last_seen:desc",
  });
  const deleteAsset = useDeleteAsset();
  const checkAssets = useCheckAssets();
  const qc = useQueryClient();

  const assets = data?.assets ?? [];
  const total = data?.total ?? 0;

  const vendors = useMemo(() => {
    const set = new Set<string>();
    for (const a of assets) if (a.vendor) set.add(a.vendor);
    return Array.from(set).sort();
  }, [assets]);

  const selectedCount = selected.size;
  const allVisibleSelected =
    assets.length > 0 && assets.every((a) => selected.has(a.id));

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (allVisibleSelected) {
      setSelected(new Set());
    } else {
      setSelected(new Set(assets.map((a) => a.id)));
    }
  };

  const handleBulkDelete = async () => {
    if (selectedCount === 0) return;
    if (
      !confirm(
        `Remove ${selectedCount} asset${selectedCount === 1 ? "" : "s"} from the inventory? They won't appear in scans or reports.`,
      )
    )
      return;
    const ids = Array.from(selected);
    for (const id of ids) {
      try {
        await deleteAsset.mutateAsync(id);
      } catch {
        // best-effort across the batch
      }
    }
    setSelected(new Set());
  };

  const handleRecheck = () => {
    const ids = selectedCount > 0 ? Array.from(selected) : undefined;
    checkAssets.mutate({ ids });
  };

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImporting(true);
    setImportMessage(null);
    try {
      const text = await file.text();
      const ext = file.name.toLowerCase().endsWith(".json") ? "json" : "csv";
      const res = await fetch(`/api/check/upload?format=${ext}`, {
        method: "POST",
        body: text,
        headers: {
          "Content-Type": ext === "json" ? "application/json" : "text/csv",
        },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || res.statusText);
      }
      const result = await res.json();
      const devices = result?.devices ?? [];
      if (devices.length > 0) {
        await api.importAssets({ devices, source: `import:${file.name}` });
      }
      setImportMessage(
        `Imported ${devices.length} device${devices.length === 1 ? "" : "s"} from ${file.name}.`,
      );
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["asset-summary"] });
    } catch (err) {
      setImportMessage(
        `Import failed: ${err instanceof Error ? err.message : "unknown error"}`,
      );
    } finally {
      setImporting(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  return (
    <div className="space-y-4 max-w-7xl">
      <Card>
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div>
            <h3 className="font-heading text-sm font-semibold">Assets</h3>
            <p className="text-xs text-db-muted mt-0.5">
              Devices currently in scope for scans and reports. Remove anything
              you don&apos;t want included.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv,.json,text/csv,application/json"
              onChange={handleImport}
              className="hidden"
            />
            <Button
              size="sm"
              onClick={() => fileInputRef.current?.click()}
              disabled={importing}
            >
              {importing ? "Importing..." : "Import CSV / JSON"}
            </Button>
            <Button
              size="sm"
              onClick={handleRecheck}
              disabled={checkAssets.isPending || total === 0}
            >
              {checkAssets.isPending
                ? "Checking..."
                : selectedCount > 0
                  ? `Recheck ${selectedCount}`
                  : "Recheck All"}
            </Button>
          </div>
        </div>
        {importMessage && (
          <p
            className={`mt-3 text-[11px] font-mono ${
              importMessage.startsWith("Import failed")
                ? "text-status-critical"
                : "text-status-ok"
            }`}
          >
            {importMessage}
          </p>
        )}
      </Card>

      <Card className="p-0 overflow-hidden">
        <div className="px-4 py-3 border-b border-db-border flex flex-wrap items-end gap-3">
          <div className="flex flex-col">
            <label className="text-[10px] text-db-muted uppercase tracking-wider mb-1">
              Search
            </label>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="IP, model, hostname..."
              className="bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text font-mono focus:outline-none w-56"
            />
          </div>
          <div className="flex flex-col">
            <label className="text-[10px] text-db-muted uppercase tracking-wider mb-1">
              Vendor
            </label>
            <select
              value={vendorFilter}
              onChange={(e) => setVendorFilter(e.target.value)}
              className="bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none w-48"
            >
              <option value="">All vendors</option>
              {vendors.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-col">
            <label className="text-[10px] text-db-muted uppercase tracking-wider mb-1">
              Vuln status
            </label>
            <select
              value={vulnFilter}
              onChange={(e) => setVulnFilter(e.target.value)}
              className="bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none w-44"
            >
              <option value="">Any</option>
              {VULN_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <span className="text-[11px] font-mono text-db-muted">
              {selectedCount > 0 ? `${selectedCount} selected` : `${total} total`}
            </span>
            {selectedCount > 0 && (
              <Button size="sm" onClick={handleBulkDelete}>
                Remove Selected
              </Button>
            )}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-db-muted bg-db-bg">
                <th className="py-2 px-2 w-8">
                  <input
                    type="checkbox"
                    checked={allVisibleSelected}
                    onChange={toggleAll}
                    aria-label="Select all"
                  />
                </th>
                <th className="py-2 px-2 font-medium">IP</th>
                <th className="py-2 px-2 font-medium">Vendor</th>
                <th className="py-2 px-2 font-medium">Model</th>
                <th className="py-2 px-2 font-medium">Firmware</th>
                <th className="py-2 px-2 font-medium">Status</th>
                <th className="py-2 px-2 font-medium">Risk</th>
                <th className="py-2 px-2 font-medium">Last seen</th>
                <th className="py-2 px-2 w-12"></th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr>
                  <td colSpan={9} className="py-6 px-3 text-center text-db-muted">
                    Loading...
                  </td>
                </tr>
              )}
              {!isLoading && assets.length === 0 && (
                <tr>
                  <td colSpan={9} className="py-6 px-3 text-center text-db-muted">
                    {search || vendorFilter || vulnFilter
                      ? "No assets match the current filters."
                      : "No assets yet. Run a scan or import a CSV / JSON inventory."}
                  </td>
                </tr>
              )}
              {assets.map((a) => (
                <AssetRow
                  key={a.id}
                  asset={a}
                  selected={selected.has(a.id)}
                  onToggle={() => toggle(a.id)}
                  onDelete={() => deleteAsset.mutate(a.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

const statusColors: Record<string, string> = {
  VULNERABLE:
    "bg-status-critical/20 text-status-critical border-status-critical/40",
  POTENTIAL: "bg-orange-500/20 text-orange-400 border-orange-500/40",
  OK: "bg-status-ok/20 text-status-ok border-status-ok/40",
};

function AssetRow({
  asset,
  selected,
  onToggle,
  onDelete,
}: {
  asset: Asset;
  selected: boolean;
  onToggle: () => void;
  onDelete: () => void;
}) {
  const vs = asset.vuln_state;
  const status = vs?.status;
  const risk = vs?.risk_score;

  return (
    <tr className="border-t border-db-border/50 table-row-hover">
      <td className="py-2 px-2">
        <input
          type="checkbox"
          checked={selected}
          onChange={onToggle}
          aria-label={`Select ${asset.ip}`}
        />
      </td>
      <td className="py-2 px-2 font-mono text-db-text">{asset.ip}</td>
      <td className="py-2 px-2 text-db-text">{asset.vendor || "—"}</td>
      <td className="py-2 px-2 font-mono text-db-text">{asset.model || "—"}</td>
      <td className="py-2 px-2 font-mono text-db-muted">
        {asset.firmware || "—"}
      </td>
      <td className="py-2 px-2">
        {status ? (
          <span
            className={`text-[9px] font-mono uppercase px-1.5 py-0.5 border ${
              statusColors[status] || "text-db-muted border-db-border"
            }`}
          >
            {status}
          </span>
        ) : (
          <span className="text-[10px] text-db-muted">unchecked</span>
        )}
      </td>
      <td className="py-2 px-2 font-mono text-db-text">
        {risk != null ? Math.round(risk) : "—"}
        {vs?.kev_count ? (
          <span className="ml-1 text-[9px] font-mono px-1 py-0.5 border border-status-critical/40 text-status-critical">
            KEV
          </span>
        ) : null}
      </td>
      <td className="py-2 px-2 font-mono text-db-muted text-[11px]">
        {asset.last_seen ? (
          <span title={formatDate(asset.last_seen)}>
            {relativeTime(asset.last_seen)}
          </span>
        ) : (
          "—"
        )}
      </td>
      <td className="py-2 px-2 text-right">
        <button
          onClick={() => {
            if (confirm(`Remove ${asset.ip} from inventory?`)) onDelete();
          }}
          className="text-db-muted hover:text-status-critical text-xs"
          aria-label={`Remove ${asset.ip}`}
          title="Remove from inventory"
        >
          ×
        </button>
      </td>
    </tr>
  );
}
