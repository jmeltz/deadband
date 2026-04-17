"use client";

import { useAdvisory } from "@/lib/hooks/useAdvisories";
import { SideDrawer } from "@/components/ui/SideDrawer";
import { Card } from "@/components/ui/Card";
import { CvssBadge } from "@/components/advisory/CvssBadge";
import { CveBadge } from "@/components/advisory/CveBadge";
import { KEVBadge, EPSSBar, RiskBadge } from "@/components/advisory/RiskBadge";

interface Props {
  advisoryId: string | null;
  onClose: () => void;
}

export function AdvisoryDetailDrawer({ advisoryId, onClose }: Props) {
  const open = !!advisoryId;

  return (
    <SideDrawer
      open={open}
      onClose={onClose}
      width={640}
      title={
        <span className="font-mono text-sm text-db-text">
          {advisoryId || ""}
        </span>
      }
    >
      {advisoryId && <AdvisoryBody id={advisoryId} />}
    </SideDrawer>
  );
}

function AdvisoryBody({ id }: { id: string }) {
  const { data: advisory, isLoading, error } = useAdvisory(id);

  if (isLoading) {
    return (
      <div className="px-4 py-8 text-center text-xs text-db-muted">
        Loading advisory...
      </div>
    );
  }

  if (error || !advisory) {
    return (
      <div className="px-4 py-8 text-center text-xs text-status-critical">
        Advisory not found.
      </div>
    );
  }

  return (
    <div className="px-4 py-3 space-y-4">
      {/* Header */}
      <Card>
        <div className="flex items-start gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-2 flex-wrap">
              <CvssBadge score={advisory.cvss_v3_max} />
              {advisory.risk_score != null && advisory.risk_score > 0 && (
                <RiskBadge score={advisory.risk_score} />
              )}
              {advisory.kev && <KEVBadge ransomware={advisory.kev_ransomware} />}
            </div>
            <h2 className="font-heading text-base font-semibold text-db-text mb-2">
              {advisory.title}
            </h2>
            <div className="flex items-center gap-4 text-xs text-db-muted flex-wrap">
              <span>
                Vendor: <span className="text-db-text">{advisory.vendor}</span>
              </span>
              <span>
                Published:{" "}
                <span className="font-mono text-db-text">
                  {advisory.published}
                </span>
              </span>
              {advisory.epss_score != null && advisory.epss_score > 0 && (
                <span className="flex items-center gap-1.5">
                  EPSS:{" "}
                  <EPSSBar
                    score={advisory.epss_score}
                    percentile={advisory.epss_percentile || 0}
                  />
                </span>
              )}
            </div>
          </div>
          {advisory.url && (
            <a
              href={advisory.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-status-info hover:text-db-text transition-colors shrink-0"
            >
              CISA &rarr;
            </a>
          )}
        </div>
      </Card>

      {advisory.summary && (
        <Card>
          <h3 className="font-heading text-sm font-semibold mb-2">Summary</h3>
          <p className="text-sm text-db-muted leading-relaxed">
            {advisory.summary}
          </p>
        </Card>
      )}

      {advisory.sectors && advisory.sectors.length > 0 && (
        <Card>
          <h3 className="font-heading text-sm font-semibold mb-3">Background</h3>
          <div className="text-sm">
            <span className="text-db-muted">
              Critical Infrastructure Sectors:{" "}
            </span>
            <span className="text-db-text">{advisory.sectors.join(", ")}</span>
          </div>
        </Card>
      )}

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

      {advisory.weaknesses && advisory.weaknesses.length > 0 && (
        <Card>
          <h3 className="font-heading text-sm font-semibold mb-3">
            Vulnerability Types
          </h3>
          <div className="space-y-2">
            {advisory.weaknesses.map((w) => (
              <div key={w.id} className="flex items-center gap-3">
                <a
                  href={`https://cwe.mitre.org/data/definitions/${w.id.replace("CWE-", "")}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-xs text-status-info hover:text-db-text transition-colors shrink-0"
                >
                  {w.id}
                </a>
                <span className="text-sm text-db-text">{w.name}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {advisory.products && advisory.products.length > 0 && (
        <Card>
          <h3 className="font-heading text-sm font-semibold mb-3">
            Affected Equipment
          </h3>
          <div className="space-y-1">
            {advisory.products.map((p, i) => (
              <div
                key={i}
                className="text-sm font-mono text-db-text bg-db-bg px-3 py-1.5 rounded-sm"
              >
                {p}
              </div>
            ))}
          </div>
        </Card>
      )}

      {advisory.affected_versions && advisory.affected_versions.length > 0 && (
        <Card>
          <h3 className="font-heading text-sm font-semibold mb-3">
            Affected Versions
          </h3>
          <div className="space-y-1">
            {advisory.affected_versions.map((v, i) => (
              <div
                key={i}
                className="text-sm font-mono text-db-text bg-db-bg px-3 py-1.5 rounded-sm"
              >
                {v}
              </div>
            ))}
          </div>
        </Card>
      )}

      {advisory.remediations && advisory.remediations.length > 0 && (
        <Card>
          <h3 className="font-heading text-sm font-semibold mb-3">
            Mitigations &amp; Remediations
          </h3>
          <div className="space-y-3">
            {advisory.remediations.map((rem, i) => (
              <div key={i} className="bg-db-bg rounded-sm p-3">
                <div className="flex items-center gap-2 mb-1">
                  <RemediationBadge category={rem.category} />
                </div>
                <p className="text-sm text-db-muted leading-relaxed">
                  {rem.details}
                </p>
                {rem.url && (
                  <a
                    href={rem.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-status-info hover:text-db-text mt-1 inline-block"
                  >
                    More info &rarr;
                  </a>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

function RemediationBadge({ category }: { category: string }) {
  const labels: Record<string, { label: string; color: string }> = {
    vendor_fix: {
      label: "Vendor Fix",
      color: "bg-status-ok/15 text-status-ok border-status-ok/30",
    },
    workaround: {
      label: "Workaround",
      color: "bg-status-medium/15 text-status-medium border-status-medium/30",
    },
    mitigation: {
      label: "Mitigation",
      color: "bg-status-info/15 text-status-info border-status-info/30",
    },
    none_available: {
      label: "No Fix Available",
      color: "bg-status-critical/15 text-status-critical border-status-critical/30",
    },
  };
  const info = labels[category] || {
    label: category,
    color: "bg-db-border text-db-muted border-db-border",
  };
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[10px] font-mono font-semibold tracking-wide border ${info.color}`}
    >
      {info.label}
    </span>
  );
}
