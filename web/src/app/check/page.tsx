"use client";

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { FileUpload } from "@/components/ui/FileUpload";
import { StatusBadge, ConfidenceBadge } from "@/components/ui/Badge";
import { CvssBadge } from "@/components/advisory/CvssBadge";
import { CveBadge } from "@/components/advisory/CveBadge";
import { EmptyState } from "@/components/ui/EmptyState";
import { useCheckUpload } from "@/lib/hooks/useCheck";
import type { CheckResponse, CheckDeviceResult } from "@/lib/types";
import Link from "next/link";

export default function CheckPage() {
  const qc = useQueryClient();
  const checkResults = qc.getQueryData<CheckResponse>(["check-results"]);
  const checkUpload = useCheckUpload();
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggleExpand = (key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const handleFile = (file: File) => {
    checkUpload.mutate({ file });
  };

  const results = checkResults?.results || [];
  const sorted = [...results].sort((a, b) => {
    const order: Record<string, number> = { VULNERABLE: 0, POTENTIAL: 1, OK: 2 };
    const diff = (order[a.status] ?? 3) - (order[b.status] ?? 3);
    if (diff !== 0) return diff;
    const maxA = Math.max(...(a.advisories?.map((x) => x.cvss_v3) || [0]));
    const maxB = Math.max(...(b.advisories?.map((x) => x.cvss_v3) || [0]));
    return maxB - maxA;
  });

  return (
    <div className="max-w-6xl space-y-4">
      {!checkResults && (
        <>
          <FileUpload
            onFile={handleFile}
            label="Drop an inventory file to run a vulnerability check"
          />
          {checkUpload.isPending && (
            <div className="text-sm text-db-muted text-center py-4">Running check...</div>
          )}
          {!checkUpload.isPending && (
            <EmptyState
              title="No check results"
              description="Upload an inventory file above, or go to Devices to load and check your inventory."
            >
              <Link href="/devices">
                <Button variant="secondary" size="sm">Go to Devices</Button>
              </Link>
            </EmptyState>
          )}
        </>
      )}

      {checkResults && (
        <>
          {/* Summary bar */}
          <Card>
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-heading text-sm font-semibold">
                Check Results — {checkResults.devices_checked} devices
              </h3>
              <span className="text-[10px] text-db-muted font-mono">
                {checkResults.checked_at}
              </span>
            </div>
            <div className="flex gap-6 mb-3">
              <SummaryBlock label="Vulnerable" value={checkResults.summary.vulnerable} color="bg-status-critical" />
              <SummaryBlock label="Potential" value={checkResults.summary.potential} color="bg-status-medium" />
              <SummaryBlock label="OK" value={checkResults.summary.ok} color="bg-status-ok" />
              <SummaryBlock label="No Match" value={checkResults.summary.no_match} color="bg-db-muted/30" />
            </div>
            <div className="flex h-2.5 rounded-full overflow-hidden bg-db-bg">
              <BarSegment count={checkResults.summary.vulnerable} total={checkResults.devices_checked} color="bg-status-critical" />
              <BarSegment count={checkResults.summary.potential} total={checkResults.devices_checked} color="bg-status-medium" />
              <BarSegment count={checkResults.summary.ok} total={checkResults.devices_checked} color="bg-status-ok" />
              <BarSegment count={checkResults.summary.no_match} total={checkResults.devices_checked} color="bg-db-muted/30" />
            </div>
          </Card>

          {/* Results table */}
          <Card className="p-0 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-db-border text-left">
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted w-8" />
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">IP</th>
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Model</th>
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Firmware</th>
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Status</th>
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Confidence</th>
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted text-right">Advisories</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((r, i) => {
                  const key = `${r.ip}:${r.model}`;
                  const isOpen = expanded.has(key);
                  return (
                    <ResultRow key={`${key}-${i}`} result={r} isOpen={isOpen} onToggle={() => toggleExpand(key)} odd={i % 2 !== 0} />
                  );
                })}
              </tbody>
            </table>
          </Card>

          {/* Upload another */}
          <div className="pt-2">
            <FileUpload
              onFile={handleFile}
              label="Upload a different inventory file to re-run check"
              className="py-4"
            />
          </div>
        </>
      )}
    </div>
  );
}

function ResultRow({
  result,
  isOpen,
  onToggle,
  odd,
}: {
  result: CheckDeviceResult;
  isOpen: boolean;
  onToggle: () => void;
  odd: boolean;
}) {
  return (
    <>
      <tr
        className={`border-b border-db-border/50 cursor-pointer hover:bg-db-bg transition-colors ${odd ? "bg-db-bg/30" : ""}`}
        onClick={onToggle}
      >
        <td className="px-4 py-2 text-db-muted">
          <span className={`inline-block transition-transform ${isOpen ? "rotate-90" : ""}`}>&#9654;</span>
        </td>
        <td className="px-4 py-2 font-mono text-xs">{result.ip}</td>
        <td className="px-4 py-2 font-mono text-xs">{result.model}</td>
        <td className="px-4 py-2 font-mono text-xs">{result.firmware}</td>
        <td className="px-4 py-2"><StatusBadge status={result.status} /></td>
        <td className="px-4 py-2">{result.confidence && <ConfidenceBadge confidence={result.confidence} />}</td>
        <td className="px-4 py-2 text-xs text-db-muted text-right font-mono">{result.advisories?.length || 0}</td>
      </tr>
      {isOpen && result.advisories?.map((adv) => (
        <tr key={adv.id} className="bg-db-bg/60 border-b border-db-border/30">
          <td className="px-4 py-2" />
          <td colSpan={6} className="px-4 py-2">
            <div className="flex items-center gap-3">
              <CvssBadge score={adv.cvss_v3} />
              <Link
                href={`/advisories/detail?id=${adv.id}`}
                className="font-mono text-xs text-status-info hover:text-db-text"
              >
                {adv.id}
              </Link>
              <span className="text-xs text-db-text truncate">{adv.title}</span>
              <div className="flex gap-1.5 ml-auto">
                {adv.cves?.map((cve) => <CveBadge key={cve} cve={cve} />)}
              </div>
            </div>
          </td>
        </tr>
      ))}
    </>
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
  return <div className={`${color}`} style={{ width: `${(count / total) * 100}%` }} />;
}
