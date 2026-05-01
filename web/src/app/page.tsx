"use client";

import { useState, useSyncExternalStore } from "react";
import { useDbStats } from "@/lib/hooks/useDbStats";
import { useAdvisories } from "@/lib/hooks/useAdvisories";
import { useEnrichmentStats } from "@/lib/hooks/useEnrichment";
import { useAssetSummary } from "@/lib/hooks/useAssetSummary";
import { useDiscoverHistory } from "@/lib/hooks/useDiscoverHistory";
import { usePosture } from "@/lib/hooks/usePosture";
import { StatCard, Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { CvssBadge } from "@/components/advisory/CvssBadge";
import { formatDate, relativeTime, formatDateTime } from "@/lib/utils/format";
import { api } from "@/lib/api";
import Link from "next/link";

const GETTING_STARTED_KEY = "deadband.gettingStarted";
const GETTING_STARTED_EVENT = "deadband.gettingStarted.change";

function subscribeGettingStarted(onChange: () => void) {
  window.addEventListener(GETTING_STARTED_EVENT, onChange);
  return () => window.removeEventListener(GETTING_STARTED_EVENT, onChange);
}

function readGettingStarted() {
  try {
    return localStorage.getItem(GETTING_STARTED_KEY) === "dismissed";
  } catch {
    return false;
  }
}

export default function Dashboard() {
  const { data: stats, isLoading } = useDbStats();
  const { data: advisories } = useAdvisories({ page: 1, per_page: 10, sort: "published" });
  const { data: enrichment } = useEnrichmentStats();
  const { data: summary } = useAssetSummary();
  const { data: history } = useDiscoverHistory();
  const { data: postureData } = usePosture();

  const gettingStartedDismissed = useSyncExternalStore(
    subscribeGettingStarted,
    readGettingStarted,
    () => false,
  );
  const dismissGettingStarted = () => {
    try {
      localStorage.setItem(GETTING_STARTED_KEY, "dismissed");
    } catch {
      // localStorage unavailable
    }
    window.dispatchEvent(new Event(GETTING_STARTED_EVENT));
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-db-muted text-sm">Loading...</div>
      </div>
    );
  }

  const vendors = stats?.vendors || {};
  const topVendors = Object.entries(vendors)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 8);
  const maxVendorCount = topVendors[0]?.[1] || 1;

  const lastJob = (history ?? [])[0];
  const showGettingStarted =
    !gettingStartedDismissed && summary && summary.total_assets === 0;

  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const handleExportReport = async () => {
    setExporting(true);
    setExportError(null);
    try {
      const { blob, filename } = await api.exportHTMLReport({});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : "export failed");
    } finally {
      setExporting(false);
    }
  };

  const canExport = !!summary && summary.total_assets > 0;

  return (
    <div className="space-y-6 max-w-6xl">
      {/* Getting Started (empty state) */}
      {showGettingStarted && (
        <Card>
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1">
              <h3 className="font-heading text-sm font-semibold">
                Getting Started
              </h3>
              <p className="text-xs text-db-muted mt-0.5">
                Four steps to go from empty to a full OT posture picture.
              </p>
              <ol className="mt-4 space-y-2.5">
                <GettingStartedStep
                  n={1}
                  href="/sites"
                  label="Create a site"
                  sub="Group CIDRs and zones by physical location"
                />
                <GettingStartedStep
                  n={2}
                  href="/assets?tab=discover"
                  label="Run your first discovery"
                  sub="Scan a CIDR to enumerate OT devices"
                />
                <GettingStartedStep
                  n={3}
                  href="/assets"
                  label="Review assets"
                  sub="Inspect what was found and match against advisories"
                />
                <GettingStartedStep
                  n={4}
                  href="/posture"
                  label="Run posture analysis"
                  sub="Classify subnets and surface compensating controls"
                />
              </ol>
            </div>
            <button
              onClick={dismissGettingStarted}
              aria-label="Dismiss"
              className="text-db-muted hover:text-db-text text-lg leading-none"
            >
              &times;
            </button>
          </div>
        </Card>
      )}

      {/* Action bar */}
      {canExport && (
        <div className="flex items-center justify-end gap-3">
          {exportError && (
            <span className="text-[11px] text-status-critical font-mono">{exportError}</span>
          )}
          <Button size="sm" onClick={handleExportReport} disabled={exporting}>
            {exporting ? "Exporting..." : "Export Report"}
          </Button>
        </div>
      )}

      {/* Row 1: Asset + Vuln stat cards */}
      {summary && summary.total_assets > 0 && (
        <div className="grid grid-cols-4 gap-4">
          <StatCard label="Total Assets" value={summary.total_assets} sub={`${summary.by_status?.active ?? 0} active`} />
          <StatCard
            label="Vulnerable"
            value={summary.by_vuln_status?.VULNERABLE ?? 0}
            sub={`${summary.by_vuln_status?.POTENTIAL ?? 0} potential`}
            className={
              (summary.by_vuln_status?.VULNERABLE ?? 0) > 0
                ? "border-status-critical/40"
                : undefined
            }
          />
          <StatCard
            label="KEV Affected"
            value={summary.kev_affected_assets}
            sub="known exploited"
            className={
              summary.kev_affected_assets > 0
                ? "border-status-critical/40"
                : undefined
            }
          />
          <StatCard
            label="Stale Assets"
            value={summary.stale_assets}
            sub="not seen in 7+ days"
            className={
              summary.stale_assets > 0
                ? "border-status-medium/40"
                : undefined
            }
          />
        </div>
      )}

      {/* Row 2: Risk heatmap (site x vuln status) */}
      {summary && Object.keys(summary.by_site).length > 0 && (
        <Card>
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-heading text-sm font-semibold">Site Risk Overview</h3>
            <Link href="/assets" className="text-xs text-db-teal-light hover:text-db-text transition-colors">
              View assets
            </Link>
          </div>
          <div className="space-y-2">
            {Object.entries(summary.by_site)
              .sort(([, a], [, b]) => b.vulnerable - a.vulnerable || b.total - a.total)
              .map(([site, s]) => (
                <div key={site} className="flex items-center gap-3">
                  <span className="text-xs text-db-text w-32 truncate">{site}</span>
                  <div className="flex-1 flex h-5 rounded-sm overflow-hidden bg-db-bg">
                    {s.vulnerable > 0 && (
                      <div
                        className="bg-status-critical/80 flex items-center justify-center"
                        style={{ width: `${(s.vulnerable / s.total) * 100}%` }}
                      >
                        {s.vulnerable > 0 && (
                          <span className="text-[9px] text-white font-mono">{s.vulnerable}</span>
                        )}
                      </div>
                    )}
                    <div
                      className="bg-status-ok/40"
                      style={{ width: `${((s.total - s.vulnerable) / s.total) * 100}%` }}
                    />
                  </div>
                  <span className="text-[10px] text-db-muted font-mono w-8 text-right">{s.total}</span>
                </div>
              ))}
          </div>
        </Card>
      )}

      {/* Row 2.5: Network posture summary */}
      {postureData && "id" in postureData && postureData.summary && (
        <Card>
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-heading text-sm font-semibold">Network Posture</h3>
            <Link href="/posture" className="text-xs text-db-teal-light hover:text-db-text transition-colors">
              View analysis
            </Link>
          </div>
          <div className="grid grid-cols-5 gap-4">
            <div className="text-center">
              <div className="text-lg font-heading font-semibold text-db-text">{postureData.summary.total_hosts}</div>
              <div className="text-[10px] text-db-muted">Hosts Scanned</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-heading font-semibold text-db-teal-light">{postureData.summary.ot_hosts}</div>
              <div className="text-[10px] text-db-muted">OT Devices</div>
            </div>
            <div className="text-center">
              <div className={`text-lg font-heading font-semibold ${postureData.summary.mixed_subnets > 0 ? "text-status-critical" : "text-status-ok"}`}>
                {postureData.summary.mixed_subnets}
              </div>
              <div className="text-[10px] text-db-muted">Mixed Subnets</div>
            </div>
            <div className="text-center">
              <div className={`text-lg font-heading font-semibold ${postureData.summary.critical_count > 0 ? "text-status-critical" : "text-status-ok"}`}>
                {postureData.summary.finding_count}
              </div>
              <div className="text-[10px] text-db-muted">Findings ({postureData.summary.critical_count} crit)</div>
            </div>
            <div className="text-center">
              <div className={`text-lg font-heading font-semibold ${
                postureData.summary.overall_score >= 7 ? "text-status-critical" :
                postureData.summary.overall_score >= 4 ? "text-orange-400" :
                "text-status-ok"
              }`}>
                {postureData.summary.overall_score.toFixed(1)}
              </div>
              <div className="text-[10px] text-db-muted">Risk Score</div>
            </div>
          </div>
        </Card>
      )}

      {/* Row 3: Two columns — assets needing attention + recent activity */}
      <div className="grid grid-cols-2 gap-6">
        {/* Top CVEs */}
        {summary && summary.top_cves && summary.top_cves.length > 0 && (
          <Card>
            <h3 className="font-heading text-sm font-semibold mb-3">Top CVEs by Affected Assets</h3>
            <div className="space-y-1.5">
              {summary.top_cves.map((c) => (
                <div key={c.cve} className="flex items-center justify-between py-1 px-2 -mx-2 rounded table-row-hover">
                  <Link
                    href={`/assets?cve=${c.cve}`}
                    className="text-xs font-mono text-db-teal-light hover:text-db-text transition-colors"
                  >
                    {c.cve}
                  </Link>
                  <span className="text-xs text-db-muted">
                    {c.affected_assets} asset{c.affected_assets !== 1 ? "s" : ""}
                  </span>
                </div>
              ))}
            </div>
          </Card>
        )}

        {/* Recent discovery (compact summary) */}
        <Card>
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-heading text-sm font-semibold">Recent Discovery</h3>
            <Link href="/assets?tab=history" className="text-xs text-db-teal-light hover:text-db-text transition-colors">
              View all
            </Link>
          </div>
          {lastJob ? (
            <div className="space-y-1.5 text-xs">
              <div className="flex items-center gap-2">
                <span
                  className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                    lastJob.status === "complete" ? "bg-status-ok" : "bg-status-critical"
                  }`}
                />
                <span className="font-mono text-db-text">{lastJob.cidr}</span>
              </div>
              <div className="text-db-muted">
                {lastJob.device_count} device{lastJob.device_count !== 1 ? "s" : ""}
                {lastJob.new_count > 0 && (
                  <span className="text-status-ok ml-1">+{lastJob.new_count} new</span>
                )}
                {lastJob.duration ? (
                  <span className="font-mono ml-2">&middot; {lastJob.duration}</span>
                ) : null}
              </div>
              <div className="text-[10px] text-db-muted font-mono">
                {lastJob.started_at
                  ? `${formatDateTime(lastJob.started_at)} (${relativeTime(lastJob.started_at)})`
                  : ""}
              </div>
            </div>
          ) : (
            <p className="text-xs text-db-muted py-4 text-center">
              No discovery scans yet.
            </p>
          )}
        </Card>
      </div>

      {/* Row 4: Advisory DB stats */}
      <div className="grid grid-cols-3 gap-4">
        <StatCard
          label="Advisories"
          value={stats?.advisory_count ?? "---"}
          sub={stats?.source}
        />
        <StatCard
          label="DB Updated"
          value={stats ? relativeTime(stats.updated) : "---"}
          sub={stats ? formatDate(stats.updated) : undefined}
        />
        <StatCard
          label="Added Since Last"
          value={
            stats?.added_since_last != null && stats.added_since_last >= 0
              ? stats.added_since_last
              : "---"
          }
          sub="new advisories"
        />
      </div>
      <div className="grid grid-cols-3 gap-4">
        <StatCard
          label="Chronic (>6mo)"
          value={stats?.chronic_count ?? "---"}
          sub="long-standing advisories"
        />
        <StatCard
          label="KEV Entries"
          value={enrichment?.kev_count ?? "---"}
          sub={enrichment?.kev_date ? `Released ${enrichment.kev_date}` : "CISA Known Exploited"}
        />
        <StatCard
          label="EPSS Scores"
          value={enrichment?.epss_count ?? "---"}
          sub={enrichment?.epss_version ? `Model ${enrichment.epss_version}` : "Exploit Prediction"}
        />
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Recent advisories */}
        <Card>
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-heading text-sm font-semibold">Recent Advisories</h3>
            <Link href="/advisories" className="text-xs text-db-teal-light hover:text-db-text transition-colors">
              View all
            </Link>
          </div>
          <div className="space-y-1">
            {advisories?.advisories.map((a) => (
              <Link
                key={a.id}
                href={`/advisories?advisory=${a.id}`}
                className="flex items-center gap-3 py-1.5 px-2 -mx-2 rounded table-row-hover transition-colors"
              >
                <CvssBadge score={a.cvss_v3_max} />
                <span className="text-xs font-mono text-db-muted w-32 shrink-0">{a.id}</span>
                <span className="text-xs text-db-text truncate flex-1">{a.title}</span>
                <span className="text-[10px] text-db-muted font-mono shrink-0">{a.published}</span>
              </Link>
            ))}
            {!advisories?.advisories.length && (
              <p className="text-xs text-db-muted py-4 text-center">
                No advisories loaded. Run <code className="font-mono">deadband --update</code> first.
              </p>
            )}
          </div>
        </Card>

        {/* Vendor coverage */}
        <Card>
          <h3 className="font-heading text-sm font-semibold mb-3">Vendor Coverage</h3>
          <div className="space-y-2">
            {topVendors.map(([vendor, count]) => (
              <div key={vendor} className="space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-db-text">{vendor}</span>
                  <span className="text-[10px] font-mono text-db-muted">{count}</span>
                </div>
                <div className="h-1.5 bg-db-bg rounded-sm overflow-hidden">
                  <div
                    className="h-full bg-db-teal rounded-sm bar-fill bar-fill-glow"
                    style={{ width: `${(count / maxVendorCount) * 100}%` }}
                  />
                </div>
              </div>
            ))}
            {topVendors.length === 0 && (
              <p className="text-xs text-db-muted py-4 text-center">No vendor data available.</p>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}

function GettingStartedStep({
  n,
  href,
  label,
  sub,
}: {
  n: number;
  href: string;
  label: string;
  sub: string;
}) {
  return (
    <li>
      <Link
        href={href}
        className="flex items-start gap-3 py-1.5 px-2 -mx-2 rounded table-row-hover transition-colors"
      >
        <span className="w-5 h-5 rounded-sm bg-db-teal-dim text-db-teal-light text-[10px] font-mono font-semibold flex items-center justify-center shrink-0 mt-0.5">
          {n}
        </span>
        <div className="flex-1 min-w-0">
          <span className="text-xs text-db-text font-medium">{label}</span>
          <span className="block text-[10px] text-db-muted">{sub}</span>
        </div>
        <span className="text-db-teal-light text-xs shrink-0">&rarr;</span>
      </Link>
    </li>
  );
}
