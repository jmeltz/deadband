"use client";

import { useDbStats } from "@/lib/hooks/useDbStats";
import { useAdvisories } from "@/lib/hooks/useAdvisories";
import { useEnrichmentStats } from "@/lib/hooks/useEnrichment";
import { useQueryClient } from "@tanstack/react-query";
import { StatCard, Card } from "@/components/ui/Card";
import { CvssBadge } from "@/components/advisory/CvssBadge";
import { formatDate, relativeTime } from "@/lib/utils/format";
import type { CheckResponse } from "@/lib/types";
import Link from "next/link";

export default function Dashboard() {
  const { data: stats, isLoading } = useDbStats();
  const { data: advisories } = useAdvisories({
    page: 1,
    per_page: 10,
    sort: "published",
  });
  const { data: enrichment } = useEnrichmentStats();
  const qc = useQueryClient();
  const checkResults = qc.getQueryData<CheckResponse>(["check-results"]);

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

  return (
    <div className="space-y-6 max-w-6xl">
      {/* Stat cards */}
      <div className="grid grid-cols-3 gap-4">
        <StatCard
          label="Advisories"
          value={stats?.advisory_count ?? "—"}
          sub={stats?.source}
        />
        <StatCard
          label="DB Updated"
          value={stats ? relativeTime(stats.updated) : "—"}
          sub={stats ? formatDate(stats.updated) : undefined}
        />
        <StatCard
          label="Added Since Last"
          value={
            stats?.added_since_last != null && stats.added_since_last >= 0
              ? stats.added_since_last
              : "—"
          }
          sub="new advisories"
        />
      </div>
      <div className="grid grid-cols-3 gap-4">
        <StatCard
          label="Chronic (>6mo)"
          value={stats?.chronic_count ?? "—"}
          sub="long-standing advisories"
        />
        <StatCard
          label="KEV Entries"
          value={enrichment?.kev_count ?? "—"}
          sub={enrichment?.kev_date ? `Released ${enrichment.kev_date}` : "CISA Known Exploited"}
        />
        <StatCard
          label="EPSS Scores"
          value={enrichment?.epss_count ?? "—"}
          sub={enrichment?.epss_version ? `Model ${enrichment.epss_version}` : "Exploit Prediction"}
        />
      </div>

      {/* Check summary if available */}
      {checkResults && (
        <Card>
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-heading text-sm font-semibold">
              Last Check Results
            </h3>
            <Link href="/devices" className="text-xs text-db-teal-light hover:text-db-text transition-colors">
              View details
            </Link>
          </div>
          <div className="flex gap-4">
            <SummaryBlock label="Vulnerable" value={checkResults.summary.vulnerable} color="bg-status-critical" />
            <SummaryBlock label="Potential" value={checkResults.summary.potential} color="bg-status-medium" />
            <SummaryBlock label="OK" value={checkResults.summary.ok} color="bg-status-ok" />
            <SummaryBlock label="No Match" value={checkResults.summary.no_match} color="bg-db-border" />
          </div>
          <div className="mt-3 flex h-2 rounded-sm overflow-hidden bg-db-bg">
            <BarSegment count={checkResults.summary.vulnerable} total={checkResults.devices_checked} color="bg-status-critical" />
            <BarSegment count={checkResults.summary.potential} total={checkResults.devices_checked} color="bg-status-medium" />
            <BarSegment count={checkResults.summary.ok} total={checkResults.devices_checked} color="bg-status-ok" />
            <BarSegment count={checkResults.summary.no_match} total={checkResults.devices_checked} color="bg-db-muted/30" />
          </div>
        </Card>
      )}

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
                href={`/advisories/detail?id=${a.id}`}
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

function SummaryBlock({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className={`w-2.5 h-2.5 rounded-sm ${color}`} />
      <span className="text-lg font-heading font-semibold text-db-text">{value}</span>
      <span className="text-xs text-db-muted">{label}</span>
    </div>
  );
}

function BarSegment({ count, total, color }: { count: number; total: number; color: string }) {
  if (count === 0 || total === 0) return null;
  return <div className={`${color} transition-all`} style={{ width: `${(count / total) * 100}%` }} />;
}
