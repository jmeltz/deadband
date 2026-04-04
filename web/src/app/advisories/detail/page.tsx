"use client";

import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { useAdvisory } from "@/lib/hooks/useAdvisories";
import { Card } from "@/components/ui/Card";
import { CvssBadge } from "@/components/advisory/CvssBadge";
import { CveBadge } from "@/components/advisory/CveBadge";
import Link from "next/link";

function AdvisoryDetailInner() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") || "";
  const { data: advisory, isLoading, error } = useAdvisory(id);

  if (!id) {
    return (
      <div className="text-sm text-db-muted py-12 text-center">
        No advisory ID specified.
      </div>
    );
  }

  if (isLoading) {
    return <div className="text-sm text-db-muted py-12 text-center">Loading advisory...</div>;
  }

  if (error || !advisory) {
    return (
      <div className="text-sm text-status-critical py-12 text-center">
        Advisory not found.
      </div>
    );
  }

  return (
    <div className="max-w-4xl space-y-6">
      <Link
        href="/advisories"
        className="text-xs text-db-muted hover:text-db-text transition-colors"
      >
        &larr; Back to advisories
      </Link>

      {/* Header */}
      <Card>
        <div className="flex items-start gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <span className="font-mono text-sm text-db-muted">{advisory.id}</span>
              <CvssBadge score={advisory.cvss_v3_max} />
            </div>
            <h2 className="font-heading text-lg font-semibold text-db-text mb-2">
              {advisory.title}
            </h2>
            <div className="flex items-center gap-4 text-xs text-db-muted">
              <span>Vendor: <span className="text-db-text">{advisory.vendor}</span></span>
              <span>Published: <span className="font-mono text-db-text">{advisory.published}</span></span>
            </div>
          </div>
          {advisory.url && (
            <a
              href={advisory.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-status-info hover:text-db-text transition-colors shrink-0"
            >
              CISA Advisory &rarr;
            </a>
          )}
        </div>
      </Card>

      {/* CVEs */}
      {advisory.cves && advisory.cves.length > 0 && (
        <Card>
          <h3 className="font-heading text-sm font-semibold mb-3">CVEs</h3>
          <div className="flex flex-wrap gap-2">
            {advisory.cves.map((cve) => (
              <CveBadge key={cve} cve={cve} />
            ))}
          </div>
        </Card>
      )}

      {/* Affected Products */}
      {advisory.products && advisory.products.length > 0 && (
        <Card>
          <h3 className="font-heading text-sm font-semibold mb-3">Affected Products</h3>
          <div className="space-y-1">
            {advisory.products.map((p, i) => (
              <div key={i} className="text-sm font-mono text-db-text bg-db-bg px-3 py-1.5 rounded">
                {p}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Affected Versions */}
      {advisory.affected_versions && advisory.affected_versions.length > 0 && (
        <Card>
          <h3 className="font-heading text-sm font-semibold mb-3">Affected Versions</h3>
          <div className="space-y-1">
            {advisory.affected_versions.map((v, i) => (
              <div key={i} className="text-sm font-mono text-db-text bg-db-bg px-3 py-1.5 rounded">
                {v}
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

export default function AdvisoryDetailPage() {
  return (
    <Suspense fallback={<div className="text-sm text-db-muted py-12 text-center">Loading...</div>}>
      <AdvisoryDetailInner />
    </Suspense>
  );
}
