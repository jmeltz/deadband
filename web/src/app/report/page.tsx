"use client";

import { useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { useAssets } from "@/lib/hooks/useAssets";
import { api } from "@/lib/api";

const VULN_STATUSES = ["VULNERABLE", "POTENTIAL", "OK"] as const;

const COMPLIANCE_FRAMEWORKS: { value: string; label: string; sub: string }[] = [
  {
    value: "iec62443",
    label: "IEC 62443",
    sub: "Industrial Automation and Control Systems",
  },
  {
    value: "nist-csf",
    label: "NIST CSF",
    sub: "Cybersecurity Framework",
  },
  {
    value: "nerc-cip",
    label: "NERC CIP",
    sub: "Critical Infrastructure Protection",
  },
];

export default function ReportPage() {
  const [siteName, setSiteName] = useState("");
  const [vendorFilter, setVendorFilter] = useState("");
  const [vulnFilter, setVulnFilter] = useState("");
  const [compliance, setCompliance] = useState<Set<string>>(new Set());
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Always fetch the full asset list so we can show the unfiltered total
  // alongside the scoped count. Filtered fetch drives the actual export.
  const { data: allAssets } = useAssets({ sort: "ip:asc" });
  const { data: filtered } = useAssets({
    vendor: vendorFilter || undefined,
    vuln_status: vulnFilter || undefined,
    sort: "ip:asc",
  });

  const totalAssets = allAssets?.total ?? 0;
  const scopedAssets = filtered?.assets ?? [];
  const scopedCount = filtered?.total ?? 0;

  const vendors = useMemo(() => {
    const set = new Set<string>();
    for (const a of allAssets?.assets ?? []) if (a.vendor) set.add(a.vendor);
    return Array.from(set).sort();
  }, [allAssets]);

  const isFiltered = vendorFilter !== "" || vulnFilter !== "";

  const toggleCompliance = (value: string) => {
    setCompliance((prev) => {
      const next = new Set(prev);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      return next;
    });
  };

  const handleGenerate = async () => {
    if (scopedCount === 0) {
      setError("Scope is empty — adjust filters or import assets first.");
      return;
    }
    setGenerating(true);
    setError(null);
    try {
      const body: Parameters<typeof api.exportHTMLReport>[0] = {};
      if (siteName.trim()) body.site_name = siteName.trim();
      if (compliance.size > 0) body.compliance = Array.from(compliance);
      // Only constrain IDs when filters are active. Empty/no filter → server
      // includes the entire inventory.
      if (isFiltered) body.ids = scopedAssets.map((a) => a.id);

      const { blob, filename } = await api.exportHTMLReport(body);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Report generation failed");
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="space-y-4 max-w-3xl">
      <Card>
        <h3 className="font-heading text-sm font-semibold">Generate Report</h3>
        <p className="text-xs text-db-muted mt-0.5">
          Configure what gets included and download a self-contained HTML
          report. The same content is what gets emailed or printed.
        </p>
      </Card>

      <Card>
        <h4 className="text-[10px] text-db-muted uppercase tracking-wider mb-2">
          Cover
        </h4>
        <div className="flex flex-col">
          <label className="text-xs text-db-text mb-1">Site name</label>
          <input
            value={siteName}
            onChange={(e) => setSiteName(e.target.value)}
            placeholder='e.g. "Acme Manufacturing - Plant 3"'
            className="bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none w-full max-w-md"
          />
          <p className="text-[10px] text-db-muted mt-1">
            Renders on the report cover. Leave blank for an unbranded report.
          </p>
        </div>
      </Card>

      <Card>
        <h4 className="text-[10px] text-db-muted uppercase tracking-wider mb-2">
          Asset Scope
        </h4>
        <div className="grid grid-cols-2 gap-3 max-w-xl">
          <div className="flex flex-col">
            <label className="text-xs text-db-text mb-1">Vendor</label>
            <select
              value={vendorFilter}
              onChange={(e) => setVendorFilter(e.target.value)}
              className="bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none"
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
            <label className="text-xs text-db-text mb-1">Vuln status</label>
            <select
              value={vulnFilter}
              onChange={(e) => setVulnFilter(e.target.value)}
              className="bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none"
            >
              <option value="">Any status</option>
              {VULN_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
        </div>
        <p className="text-[11px] font-mono text-db-muted mt-3">
          {isFiltered ? (
            <>
              <span className="text-db-text">{scopedCount}</span> of{" "}
              {totalAssets} asset{totalAssets === 1 ? "" : "s"} match — only
              these will be included.
            </>
          ) : (
            <>
              All <span className="text-db-text">{totalAssets}</span> asset
              {totalAssets === 1 ? "" : "s"} will be included.
            </>
          )}
        </p>
      </Card>

      <Card>
        <h4 className="text-[10px] text-db-muted uppercase tracking-wider mb-2">
          Compliance Mappings
        </h4>
        <p className="text-[11px] text-db-muted mb-3">
          Optional. Adds a controls table to the report citing which advisories
          map into each framework.
        </p>
        <div className="space-y-2">
          {COMPLIANCE_FRAMEWORKS.map((f) => (
            <label
              key={f.value}
              className="flex items-start gap-2 cursor-pointer"
            >
              <input
                type="checkbox"
                checked={compliance.has(f.value)}
                onChange={() => toggleCompliance(f.value)}
                className="mt-0.5"
              />
              <div>
                <div className="text-xs text-db-text">{f.label}</div>
                <div className="text-[10px] text-db-muted">{f.sub}</div>
              </div>
            </label>
          ))}
        </div>
      </Card>

      <Card>
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="text-[11px] text-db-muted">
            {scopedCount === 0 && totalAssets === 0
              ? "No assets in inventory — import or scan first."
              : scopedCount === 0
                ? "Current filters match zero assets."
                : `Ready to export ${scopedCount} asset${scopedCount === 1 ? "" : "s"}.`}
          </div>
          <div className="flex items-center gap-2">
            {error && (
              <span className="text-[11px] text-status-critical font-mono">
                {error}
              </span>
            )}
            <Button
              size="sm"
              onClick={handleGenerate}
              disabled={generating || scopedCount === 0}
            >
              {generating ? "Generating..." : "Generate Report"}
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
