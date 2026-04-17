"use client";

import { useState } from "react";
import { Card, StatCard } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import {
  usePosture,
  usePostureScan,
  usePostureHost,
  useControlStates,
  useSetControlState,
  useRiskSimulation,
} from "@/lib/hooks/usePosture";
import { useSites } from "@/lib/hooks/useSites";
import { useQueryClient } from "@tanstack/react-query";
import type {
  PostureReport,
  SubnetAnalysis,
  PostureFinding,
  ClassifiedHost,
  DeviceClass,
  RecommendedControl,
} from "@/lib/types";

const classColors: Record<DeviceClass, string> = {
  ot: "bg-db-teal/20 text-db-teal-light border-db-teal/40",
  it: "bg-blue-500/20 text-blue-400 border-blue-500/40",
  network: "bg-gray-500/20 text-gray-400 border-gray-500/40",
  unknown: "bg-amber-500/20 text-amber-400 border-amber-500/40",
};

const classLabels: Record<DeviceClass, string> = {
  ot: "OT",
  it: "IT",
  network: "NET",
  unknown: "UNK",
};

const sevColors: Record<string, string> = {
  critical: "bg-status-critical/20 text-status-critical border-status-critical/40",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/40",
  medium: "bg-status-medium/20 text-status-medium border-status-medium/40",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/40",
};

function RiskBadge({ score }: { score: number }) {
  const color =
    score >= 7
      ? "text-status-critical"
      : score >= 4
        ? "text-orange-400"
        : score >= 2
          ? "text-status-medium"
          : "text-status-ok";
  return (
    <span className={`text-xs font-mono font-semibold ${color}`}>
      {score.toFixed(1)}
    </span>
  );
}

export function FindingsTab() {
  const { data: existing } = usePosture();
  const { data: sites } = useSites();
  const scan = usePostureScan();
  const queryClient = useQueryClient();
  const [showManualScan, setShowManualScan] = useState(false);

  const [cidr, setCidr] = useState("");
  const [selectedSite, setSelectedSite] = useState("");
  const [expandedSubnet, setExpandedSubnet] = useState<string | null>(null);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [selectedHostIP, setSelectedHostIP] = useState<string | null>(null);

  const report: PostureReport | null | undefined =
    scan.report ?? (existing && "id" in existing ? (existing as PostureReport) : null);

  const handleScan = () => {
    if (!cidr) return;
    scan.start({ cidr }).then(() => {
      queryClient.invalidateQueries({ queryKey: ["posture"] });
      queryClient.invalidateQueries({ queryKey: ["posture-reports"] });
    });
  };

  const handleSiteChange = (siteId: string) => {
    setSelectedSite(siteId);
    if (siteId && sites) {
      const site = sites.find((s) => s.id === siteId);
      if (site && site.cidrs.length > 0) {
        setCidr(site.cidrs[0]);
      }
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-heading text-sm font-semibold">
              Network Posture Analysis
            </h3>
            <p className="text-xs text-db-muted mt-0.5">
              Posture analysis runs automatically during device discovery.
              Subnets are scanned with OT-first sensitivity ordering — OT
              devices are never probed with IT ports.
            </p>
          </div>
          <div className="flex items-center gap-2">
            {report && (
              <span className="text-[10px] text-db-muted font-mono">
                {report.cidr} &middot; {report.duration}
              </span>
            )}
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setShowManualScan(!showManualScan)}
            >
              {showManualScan ? "Hide" : "Manual Scan"}
            </Button>
          </div>
        </div>

        {/* Manual scan controls (collapsed by default) */}
        {showManualScan && (
          <div className="mt-3 pt-3 border-t border-db-border">
            <div className="flex items-end gap-3">
              {sites && sites.length > 0 && (
                <div>
                  <label className="block text-xs text-db-muted mb-1">
                    Site
                  </label>
                  <select
                    value={selectedSite}
                    onChange={(e) => handleSiteChange(e.target.value)}
                    className="bg-db-surface border border-db-border px-3 py-2 text-sm text-db-text focus:outline-none"
                  >
                    <option value="">Select site...</option>
                    {sites.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name}
                      </option>
                    ))}
                  </select>
                </div>
              )}
              <div className="flex-1 max-w-xs">
                <label className="block text-xs text-db-muted mb-1">
                  CIDR Range
                </label>
                <input
                  type="text"
                  value={cidr}
                  onChange={(e) => setCidr(e.target.value)}
                  placeholder="10.0.1.0/24"
                  className="w-full bg-db-surface border border-db-border px-3 py-2 text-sm text-db-text font-mono focus:outline-none input-industrial"
                  onKeyDown={(e) => e.key === "Enter" && handleScan()}
                />
              </div>
              <Button
                size="sm"
                onClick={handleScan}
                disabled={!cidr || scan.status === "running"}
              >
                {scan.status === "running" ? "Scanning..." : "Run Posture Scan"}
              </Button>
            </div>
          </div>
        )}

        {/* Progress */}
        {scan.status === "running" && scan.progress.length > 0 && (
          <div className="mt-3 border border-db-border bg-db-bg p-3 max-h-32 overflow-y-auto">
            {scan.progress.map((msg, i) => (
              <div key={i} className="text-xs font-mono text-db-muted">
                {msg}
              </div>
            ))}
          </div>
        )}
        {scan.error && (
          <div className="mt-3 text-xs text-status-critical">{scan.error}</div>
        )}
      </Card>

      {/* Summary stats */}
      {report && (
        <>
          <div className="grid grid-cols-6 gap-4">
            <StatCard
              label="Total Hosts"
              value={report.summary.total_hosts}
            />
            <StatCard
              label="OT Hosts"
              value={report.summary.ot_hosts}
              sub="industrial"
              className="border-db-teal/30"
            />
            <StatCard
              label="IT Hosts"
              value={report.summary.it_hosts}
              sub="enterprise"
            />
            <StatCard
              label="Mixed Subnets"
              value={report.summary.mixed_subnets}
              className={
                report.summary.mixed_subnets > 0
                  ? "border-status-critical/40"
                  : undefined
              }
            />
            <StatCard
              label="Findings"
              value={report.summary.finding_count}
              sub={`${report.summary.critical_count} critical`}
              className={
                report.summary.critical_count > 0
                  ? "border-status-critical/40"
                  : undefined
              }
            />
            <StatCard
              label="Risk Score"
              value={report.summary.overall_score.toFixed(1)}
              sub="out of 10"
              className={
                report.summary.overall_score >= 7
                  ? "border-status-critical/40"
                  : report.summary.overall_score >= 4
                    ? "border-orange-500/40"
                    : undefined
              }
            />
          </div>

          {/* Two-panel layout */}
          <div className="grid grid-cols-2 gap-6">
            {/* Left: Subnet Map */}
            <Card className="p-0 overflow-hidden">
              <div className="px-4 py-3 border-b border-db-border">
                <h3 className="font-heading text-sm font-semibold">
                  Subnet Analysis
                </h3>
                <p className="text-[10px] text-db-muted mt-0.5">
                  {(report.subnets ?? []).length} subnet
                  {(report.subnets ?? []).length !== 1 ? "s" : ""} scanned &middot;{" "}
                  {report.cidr} &middot; {report.duration}
                </p>
              </div>
              <div className="divide-y divide-db-border/50">
                {(report.subnets ?? []).map((sa) => (
                  <SubnetRow
                    key={sa.subnet}
                    subnet={sa}
                    expanded={expandedSubnet === sa.subnet}
                    onToggle={() =>
                      setExpandedSubnet(
                        expandedSubnet === sa.subnet ? null : sa.subnet,
                      )
                    }
                    onHostClick={(ip) => setSelectedHostIP(ip)}
                  />
                ))}
                {(report.subnets ?? []).length === 0 && (
                  <div className="px-4 py-8 text-center text-xs text-db-muted">
                    No subnets found with live hosts.
                  </div>
                )}
              </div>
            </Card>

            {/* Right: Findings & Controls */}
            <Card className="p-0 overflow-hidden">
              <div className="px-4 py-3 border-b border-db-border">
                <h3 className="font-heading text-sm font-semibold">
                  Findings & Compensating Controls
                </h3>
                <p className="text-[10px] text-db-muted mt-0.5">
                  {(report.findings ?? []).length} finding
                  {(report.findings ?? []).length !== 1 ? "s" : ""} &middot; mapped to
                  IEC 62443, NIST CSF 2.0, NERC CIP
                </p>
              </div>
              <div className="divide-y divide-db-border/50">
                {(report.findings ?? []).map((f) => (
                  <FindingRow
                    key={f.id}
                    finding={f}
                    expanded={expandedFinding === f.id}
                    onToggle={() =>
                      setExpandedFinding(
                        expandedFinding === f.id ? null : f.id,
                      )
                    }
                  />
                ))}
                {(report.findings ?? []).length === 0 && (
                  <div className="px-4 py-8 text-center text-xs text-db-muted">
                    No findings detected. Network posture looks clean.
                  </div>
                )}
              </div>
            </Card>
          </div>

          {/* Risk Simulation Panel */}
          <RiskSimulationPanel report={report} />
        </>
      )}

      {/* Host detail modal */}
      {selectedHostIP && (
        <HostDetailModal
          ip={selectedHostIP}
          onClose={() => setSelectedHostIP(null)}
        />
      )}

      {/* Empty state */}
      {!report && scan.status !== "running" && (
        <Card>
          <div className="text-center py-12">
            <p className="text-sm text-db-muted mb-2">
              No posture analysis results yet
            </p>
            <p className="text-xs text-db-muted">
              Run a device discovery scan from the Assets page — posture analysis
              is performed automatically. Or use Manual Scan above for on-demand
              analysis.
            </p>
          </div>
        </Card>
      )}
    </div>
  );
}

function SubnetRow({
  subnet,
  expanded,
  onToggle,
  onHostClick,
}: {
  subnet: SubnetAnalysis;
  expanded: boolean;
  onToggle: () => void;
  onHostClick: (ip: string) => void;
}) {
  const zonePurposeColors: Record<string, string> = {
    ot: "bg-db-teal/20 text-db-teal-light border-db-teal/40",
    it: "bg-blue-500/20 text-blue-400 border-blue-500/40",
    dmz: "bg-orange-500/20 text-orange-400 border-orange-500/40",
    corporate: "bg-gray-500/20 text-gray-400 border-gray-500/40",
    safety: "bg-red-500/20 text-red-400 border-red-500/40",
  };

  return (
    <div>
      <div
        onClick={onToggle}
        className="px-4 py-3 cursor-pointer table-row-hover flex items-center gap-3"
      >
        <span className="text-[10px] text-db-muted w-4">
          {expanded ? "\u25BC" : "\u25B6"}
        </span>
        <div className="w-40">
          <span className="text-xs font-mono text-db-text">
            {subnet.zone || subnet.subnet}
          </span>
          {subnet.zone && (
            <span className="block text-[9px] font-mono text-db-muted">
              {subnet.subnet}
            </span>
          )}
        </div>
        {subnet.zone_purpose && (
          <span
            className={`text-[9px] font-mono px-1.5 py-0.5 border uppercase ${zonePurposeColors[subnet.zone_purpose] || "bg-gray-500/20 text-gray-400 border-gray-500/40"}`}
          >
            {subnet.zone_purpose}
          </span>
        )}
        <div className="flex items-center gap-1.5 flex-1">
          {subnet.ot_count > 0 && (
            <ClassPill cls="ot" count={subnet.ot_count} />
          )}
          {subnet.it_count > 0 && (
            <ClassPill cls="it" count={subnet.it_count} />
          )}
          {subnet.network_count > 0 && (
            <ClassPill cls="network" count={subnet.network_count} />
          )}
          {subnet.unknown_count > 0 && (
            <ClassPill cls="unknown" count={subnet.unknown_count} />
          )}
        </div>
        {subnet.is_mixed && (
          <span className="text-[9px] font-mono px-1.5 py-0.5 bg-status-critical/15 text-status-critical border border-status-critical/30">
            MIXED
          </span>
        )}
        {subnet.is_pure_ot && (
          <span className="text-[9px] font-mono px-1.5 py-0.5 bg-db-teal/15 text-db-teal-light border border-db-teal/30">
            PURE OT
          </span>
        )}
        <RiskBadge score={subnet.risk_score} />
      </div>
      {expanded && (
        <div className="bg-db-bg border-t border-db-border/50 px-4 py-2">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-db-muted">
                <th className="py-1 pr-3 font-medium">IP</th>
                <th className="py-1 pr-3 font-medium">Class</th>
                <th className="py-1 pr-3 font-medium">Services</th>
                <th className="py-1 pr-3 font-medium">Identity</th>
                <th className="py-1 font-medium">Asset</th>
              </tr>
            </thead>
            <tbody>
              {(subnet.hosts ?? []).map((h) => (
                <HostRow key={h.ip} host={h} onClick={() => onHostClick(h.ip)} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function HostRow({ host, onClick }: { host: ClassifiedHost; onClick: () => void }) {
  const identity = host.hostname
    ? host.presumption
      ? `${host.hostname} — ${host.presumption}`
      : host.hostname
    : host.presumption || null;

  return (
    <tr
      className="border-t border-db-border/30 cursor-pointer table-row-hover"
      onClick={onClick}
    >
      <td className="py-1.5 pr-3 font-mono text-db-text">
        {host.ip}
      </td>
      <td className="py-1.5 pr-3">
        <span
          className={`inline-block text-[9px] font-mono px-1.5 py-0.5 border ${classColors[host.device_class]}`}
        >
          {classLabels[host.device_class]}
        </span>
      </td>
      <td className="py-1.5 pr-3">
        <div className="flex flex-wrap gap-1">
          {(host.services ?? []).map((svc) => (
            <span
              key={svc}
              className="text-[9px] font-mono px-1 py-0.5 bg-db-surface border border-db-border text-db-muted"
            >
              {svc}
            </span>
          ))}
        </div>
      </td>
      <td className="py-1.5 pr-3 max-w-xs">
        {identity ? (
          <span
            className="text-[10px] text-db-muted truncate block"
            title={identity}
          >
            {identity}
          </span>
        ) : (
          <span className="text-db-muted/50">{"\u2014"}</span>
        )}
      </td>
      <td className="py-1.5 text-db-muted">
        {host.asset_name || host.vendor
          ? `${host.vendor || ""} ${host.model || ""}`.trim()
          : "\u2014"}
      </td>
    </tr>
  );
}

function ClassPill({
  cls,
  count,
}: {
  cls: DeviceClass;
  count: number;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 border ${classColors[cls]}`}
    >
      {classLabels[cls]}
      <span className="font-semibold">{count}</span>
    </span>
  );
}

function FindingRow({
  finding,
  expanded,
  onToggle,
}: {
  finding: PostureFinding;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div>
      <div
        onClick={onToggle}
        className="px-4 py-3 cursor-pointer table-row-hover flex items-center gap-3"
      >
        <span className="text-[10px] text-db-muted w-4">
          {expanded ? "\u25BC" : "\u25B6"}
        </span>
        <span
          className={`text-[9px] font-mono px-1.5 py-0.5 border uppercase ${sevColors[finding.severity]}`}
        >
          {finding.severity}
        </span>
        <span className="text-xs text-db-text flex-1">{finding.title}</span>
        <span className="text-[10px] font-mono text-db-muted">
          {finding.subnet}
        </span>
      </div>
      {expanded && (
        <div className="bg-db-bg border-t border-db-border/50 px-4 py-3 space-y-3">
          <p className="text-xs text-db-muted leading-relaxed">
            {finding.description}
          </p>

          {/* Evidence */}
          {(finding.evidence ?? []).length > 0 && (
            <div>
              <h5 className="text-[10px] font-medium text-db-muted uppercase tracking-wider mb-1">
                Evidence
              </h5>
              <div className="flex flex-wrap gap-1">
                {(finding.evidence ?? []).map((e, i) => (
                  <span
                    key={i}
                    className="text-[10px] font-mono px-1.5 py-0.5 bg-db-surface border border-db-border text-db-text"
                  >
                    {e}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Compensating controls */}
          {(finding.controls ?? []).length > 0 && (
            <div>
              <h5 className="text-[10px] font-medium text-db-muted uppercase tracking-wider mb-1.5">
                Compensating Controls
              </h5>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-db-muted border-b border-db-border/50">
                    <th className="py-1.5 pr-2 font-medium w-20">Framework</th>
                    <th className="py-1.5 pr-2 font-medium w-28">Control</th>
                    <th className="py-1.5 pr-2 font-medium">Recommendation</th>
                    <th className="py-1.5 font-medium w-20">Priority</th>
                    <th className="py-1.5 font-medium w-16 text-center">
                      Status
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {(finding.controls ?? []).map((c, i) => (
                    <ControlRow
                      key={i}
                      control={c}
                      findingType={finding.type}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ControlRow({
  control,
  findingType,
}: {
  control: RecommendedControl;
  findingType?: string;
}) {
  const { data: controlStates } = useControlStates();
  const setControlState = useSetControlState();

  const currentState = controlStates?.find(
    (cs) => cs.finding_type === findingType && cs.control_id === control.control_id,
  );
  const status = currentState?.status;

  const cycleStatus = () => {
    if (!findingType) return;
    const next =
      !status ? "applied" : status === "applied" ? "planned" : status === "planned" ? "not_applicable" : "";
    setControlState.mutate({
      finding_type: findingType,
      control_id: control.control_id,
      status: next,
    });
  };

  const statusIcon: Record<string, { label: string; cls: string }> = {
    applied: { label: "\u2713", cls: "bg-emerald-500/20 text-emerald-400 border-emerald-500/50" },
    planned: { label: "\u25F7", cls: "bg-amber-500/20 text-amber-400 border-amber-500/50" },
    not_applicable: { label: "\u2014", cls: "bg-gray-500/20 text-gray-500 border-gray-500/50" },
  };
  const si = status ? statusIcon[status] : null;

  const priorityColors: Record<string, string> = {
    immediate: "text-status-critical",
    short_term: "text-orange-400",
    long_term: "text-db-muted",
  };

  const isNA = status === "not_applicable";

  return (
    <tr
      className={`border-t border-db-border/30 ${status === "applied" ? "border-l-2 border-l-emerald-500/60" : status === "planned" ? "border-l-2 border-l-amber-500/60" : ""}`}
    >
      <td className={`py-1.5 pr-2 ${isNA ? "opacity-40 line-through" : ""}`}>
        <span className="text-[10px] font-mono text-db-teal-light">
          {control.framework}
        </span>
      </td>
      <td className={`py-1.5 pr-2 ${isNA ? "opacity-40 line-through" : ""}`}>
        <span className="text-[10px] font-mono text-db-text">
          {control.control_id}
        </span>
        <br />
        <span className="text-[9px] text-db-muted">{control.control_name}</span>
      </td>
      <td className={`py-1.5 pr-2 text-db-muted leading-relaxed ${isNA ? "opacity-40 line-through" : ""}`}>
        {control.recommendation}
      </td>
      <td className={`py-1.5 pr-2 ${isNA ? "opacity-40" : ""}`}>
        <span
          className={`text-[9px] font-mono uppercase ${priorityColors[control.priority] || "text-db-muted"}`}
        >
          {control.priority.replace("_", " ")}
        </span>
      </td>
      <td className="py-1.5 text-center">
        {findingType && (
          <button
            onClick={cycleStatus}
            className={`inline-flex items-center justify-center w-6 h-6 text-[10px] font-mono border cursor-pointer transition-colors ${si ? si.cls : "bg-db-surface border-db-border text-db-muted hover:border-db-teal/40"}`}
            title={
              status
                ? `${status.replace("_", " ")} — click to cycle`
                : "Click to mark as applied"
            }
          >
            {si ? si.label : "\u25CB"}
          </button>
        )}
      </td>
    </tr>
  );
}

function RiskSimulationPanel({ report }: { report: PostureReport }) {
  const { data: sim, isLoading } = useRiskSimulation();
  const { data: controlStates } = useControlStates();

  const appliedCount = controlStates?.filter((cs) => cs.status === "applied").length ?? 0;
  const plannedCount = controlStates?.filter((cs) => cs.status === "planned").length ?? 0;

  if (!sim && !isLoading) return null;
  if (appliedCount === 0 && plannedCount === 0) {
    return (
      <Card>
        <div className="flex items-center gap-3">
          <div className="flex-1">
            <h3 className="font-heading text-sm font-semibold">
              Risk Simulation
            </h3>
            <p className="text-xs text-db-muted mt-0.5">
              Mark compensating controls as &quot;applied&quot; or
              &quot;planned&quot; in the findings panel above to simulate their
              impact on overall risk.
            </p>
          </div>
          <div className="text-right">
            <div className="text-2xl font-mono font-bold text-db-text">
              {report.summary.overall_score.toFixed(1)}
            </div>
            <div className="text-[10px] text-db-muted uppercase">
              Current Risk
            </div>
          </div>
        </div>
      </Card>
    );
  }

  if (isLoading || !sim) {
    return (
      <Card>
        <div className="text-xs text-db-muted text-center py-4">
          Calculating risk simulation...
        </div>
      </Card>
    );
  }

  const pctReduction = sim.original_score > 0
    ? Math.abs(sim.delta / sim.original_score) * 100
    : 0;
  const plannedPctReduction = sim.original_score > 0
    ? Math.abs(sim.planned_delta / sim.original_score) * 100
    : 0;

  const scoreColor = (score: number) =>
    score >= 7
      ? "text-status-critical"
      : score >= 4
        ? "text-orange-400"
        : score >= 2
          ? "text-status-medium"
          : "text-status-ok";

  const barWidth = (score: number) =>
    `${Math.min(100, (score / 10) * 100)}%`;

  return (
    <Card>
      <div className="space-y-4">
        <div>
          <h3 className="font-heading text-sm font-semibold">
            Risk Simulation
          </h3>
          <p className="text-[10px] text-db-muted mt-0.5">
            Projected risk reduction based on {appliedCount} applied
            {plannedCount > 0 && ` and ${plannedCount} planned`} compensating
            control{appliedCount + plannedCount !== 1 ? "s" : ""}
          </p>
        </div>

        {/* Score comparison */}
        <div className="grid grid-cols-3 gap-4">
          <div className="text-center">
            <div className={`text-2xl font-mono font-bold ${scoreColor(sim.original_score)}`}>
              {sim.original_score.toFixed(1)}
            </div>
            <div className="text-[10px] text-db-muted uppercase">Current</div>
          </div>
          <div className="text-center flex flex-col items-center justify-center">
            <div className="text-xs text-db-muted">&rarr;</div>
            <div className="text-xs font-mono text-emerald-400 font-semibold">
              {sim.delta.toFixed(1)} ({pctReduction.toFixed(0)}%)
            </div>
          </div>
          <div className="text-center">
            <div className={`text-2xl font-mono font-bold ${scoreColor(sim.simulated_score)}`}>
              {sim.simulated_score.toFixed(1)}
            </div>
            <div className="text-[10px] text-db-muted uppercase">
              With Applied
            </div>
          </div>
        </div>

        {/* Risk bars */}
        <div className="space-y-2">
          <div>
            <div className="flex items-center justify-between text-[10px] text-db-muted mb-1">
              <span>Current Risk</span>
              <span className="font-mono">{sim.original_score.toFixed(1)}</span>
            </div>
            <div className="h-2 bg-db-surface border border-db-border">
              <div
                className="h-full bg-status-critical/60 transition-all"
                style={{ width: barWidth(sim.original_score) }}
              />
            </div>
          </div>
          <div>
            <div className="flex items-center justify-between text-[10px] text-db-muted mb-1">
              <span>With Applied Controls</span>
              <span className="font-mono text-emerald-400">
                {sim.simulated_score.toFixed(1)}
              </span>
            </div>
            <div className="h-2 bg-db-surface border border-db-border">
              <div
                className="h-full bg-emerald-500/60 transition-all"
                style={{ width: barWidth(sim.simulated_score) }}
              />
            </div>
          </div>
          {plannedCount > 0 && (
            <div>
              <div className="flex items-center justify-between text-[10px] text-db-muted mb-1">
                <span>With Applied + Planned</span>
                <span className="font-mono text-amber-400">
                  {sim.planned_score.toFixed(1)}
                </span>
              </div>
              <div className="h-2 bg-db-surface border border-db-border">
                <div
                  className="h-full bg-amber-500/40 transition-all"
                  style={{ width: barWidth(sim.planned_score) }}
                />
              </div>
            </div>
          )}
        </div>

        {/* Applied controls breakdown */}
        {sim.reductions.length > 0 && (
          <div>
            <h5 className="text-[10px] font-medium text-db-muted uppercase tracking-wider mb-1.5">
              Applied Control Impact
            </h5>
            <div className="space-y-1">
              {sim.reductions.map((r) => (
                <div
                  key={r.control_id}
                  className="flex items-center gap-2 text-xs"
                >
                  <span className="inline-block w-2 h-2 bg-emerald-400/60 border border-emerald-500/40" />
                  <span className="font-mono text-db-text flex-1">
                    {r.control_id}
                  </span>
                  <span className="font-mono text-emerald-400">
                    -{(r.factor * 100).toFixed(0)}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Planned controls preview */}
        {plannedCount > 0 && sim.planned.length > 0 && (
          <div className="border-t border-db-border pt-3">
            <h5 className="text-[10px] font-medium text-db-muted uppercase tracking-wider mb-1.5">
              If You Also Implement...
            </h5>
            <div className="flex flex-wrap gap-1.5">
              {sim.planned.map((id) => (
                <span
                  key={id}
                  className="text-[10px] font-mono px-1.5 py-0.5 bg-amber-500/10 text-amber-400 border border-amber-500/30"
                >
                  {id}
                </span>
              ))}
            </div>
            <p className="text-[10px] text-db-muted mt-1.5">
              Additional reduction to{" "}
              <span className="font-mono text-amber-400 font-semibold">
                {sim.planned_score.toFixed(1)}
              </span>{" "}
              ({plannedPctReduction.toFixed(0)}% total reduction from baseline)
            </p>
          </div>
        )}
      </div>
    </Card>
  );
}

function HostDetailModal({ ip, onClose }: { ip: string; onClose: () => void }) {
  const { data, isLoading } = usePostureHost(ip);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  const host = data?.host;
  const findings = data?.findings ?? [];
  const subnet = data?.subnet;
  const banners = host?.banners ?? [];

  // Port service name lookup
  const portName = (port: number) => {
    const names: Record<number, string> = {
      22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 102: "S7comm",
      135: "RPC", 161: "SNMP", 179: "BGP", 443: "HTTPS", 445: "SMB",
      502: "Modbus", 3389: "RDP", 4840: "OPC UA", 5007: "MELSEC",
      8080: "HTTP-alt", 8443: "HTTPS-alt", 9600: "FINS",
      18245: "GE-SRTP", 44818: "CIP/EIP", 47808: "BACnet",
    };
    return names[port] || `${port}`;
  };

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="absolute inset-0 bg-black/50" />
      <div className="relative w-[520px] max-w-full h-full bg-db-bg border-l border-db-border overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-db-bg border-b border-db-border px-4 py-3 flex items-center justify-between z-10">
          <div className="flex items-center gap-2">
            <span className="text-sm font-mono font-medium text-db-text">
              {ip}
            </span>
            {host && (
              <span
                className={`text-[9px] font-mono px-1.5 py-0.5 border ${classColors[host.device_class]}`}
              >
                {classLabels[host.device_class]}
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            className="text-db-muted hover:text-db-text text-lg leading-none"
          >
            &times;
          </button>
        </div>

        {isLoading ? (
          <div className="px-4 py-8 text-center text-xs text-db-muted">
            Loading host details...
          </div>
        ) : !host ? (
          <div className="px-4 py-8 text-center text-xs text-db-muted">
            Host not found in latest posture report.
          </div>
        ) : (
          <div className="px-4 py-3 space-y-4">
            {/* Identity section */}
            <div>
              <h4 className="text-[10px] font-medium text-db-muted uppercase tracking-wider mb-2">
                Identity
              </h4>
              <div className="space-y-1 text-xs">
                {host.hostname && (
                  <div>
                    <span className="text-db-muted">Hostname: </span>
                    <span className="text-db-text font-mono">{host.hostname}</span>
                  </div>
                )}
                {host.os_guess && (
                  <div>
                    <span className="text-db-muted">OS: </span>
                    <span className="text-db-text">{host.os_guess}</span>
                  </div>
                )}
                {host.presumption && (
                  <div>
                    <span className="text-db-muted">Presumption: </span>
                    <span className="text-db-text">{host.presumption}</span>
                  </div>
                )}
                {(host.vendor || host.model) && (
                  <div>
                    <span className="text-db-muted">Asset: </span>
                    <span className="text-db-text">
                      {[host.vendor, host.model].filter(Boolean).join(" ")}
                    </span>
                  </div>
                )}
                {subnet && (
                  <div>
                    <span className="text-db-muted">
                      {subnet.zone ? "Zone" : "Subnet"}:{" "}
                    </span>
                    <span className="text-db-text font-mono">{subnet.subnet}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Open Ports & Banners */}
            <div>
              <h4 className="text-[10px] font-medium text-db-muted uppercase tracking-wider mb-2">
                Open Ports & Banners
              </h4>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-db-muted border-b border-db-border/50">
                    <th className="py-1 pr-2 font-medium w-16">Port</th>
                    <th className="py-1 pr-2 font-medium w-20">Protocol</th>
                    <th className="py-1 font-medium">Banner</th>
                  </tr>
                </thead>
                <tbody>
                  {(host.open_ports ?? []).map((port) => {
                    const banner = banners.find((b) => b.port === port);
                    return (
                      <tr key={port} className="border-t border-db-border/30">
                        <td className="py-1 pr-2 font-mono text-db-text">
                          {port}
                        </td>
                        <td className="py-1 pr-2 text-db-teal-light font-mono">
                          {portName(port)}
                        </td>
                        <td className="py-1 text-db-muted">
                          {banner ? (
                            <span title={banner.banner}>
                              {banner.banner.length > 80
                                ? banner.banner.slice(0, 80) + "..."
                                : banner.banner}
                            </span>
                          ) : (
                            "\u2014"
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Findings */}
            {findings.length > 0 && (
              <div>
                <h4 className="text-[10px] font-medium text-db-muted uppercase tracking-wider mb-2">
                  Findings ({findings.length})
                </h4>
                <div className="divide-y divide-db-border/50 border border-db-border">
                  {findings.map((f) => (
                    <div key={f.id}>
                      <div
                        onClick={() =>
                          setExpandedFinding(
                            expandedFinding === f.id ? null : f.id,
                          )
                        }
                        className="px-3 py-2 cursor-pointer table-row-hover flex items-center gap-2"
                      >
                        <span className="text-[10px] text-db-muted w-3">
                          {expandedFinding === f.id ? "\u25BC" : "\u25B6"}
                        </span>
                        <span
                          className={`text-[9px] font-mono px-1.5 py-0.5 border uppercase ${sevColors[f.severity]}`}
                        >
                          {f.severity}
                        </span>
                        <span className="text-xs text-db-text flex-1">
                          {f.title}
                        </span>
                      </div>
                      {expandedFinding === f.id && (
                        <div className="px-3 py-2 bg-db-bg border-t border-db-border/50 space-y-2">
                          <p className="text-xs text-db-muted leading-relaxed">
                            {f.description}
                          </p>
                          {(f.controls ?? []).length > 0 && (
                            <table className="w-full text-xs">
                              <thead>
                                <tr className="text-left text-db-muted border-b border-db-border/50">
                                  <th className="py-1 pr-2 font-medium w-20">
                                    Framework
                                  </th>
                                  <th className="py-1 pr-2 font-medium w-28">
                                    Control
                                  </th>
                                  <th className="py-1 pr-2 font-medium">
                                    Recommendation
                                  </th>
                                  <th className="py-1 pr-2 font-medium w-16">
                                    Priority
                                  </th>
                                  <th className="py-1 font-medium w-12 text-center">
                                    Status
                                  </th>
                                </tr>
                              </thead>
                              <tbody>
                                {(f.controls ?? []).map((c, i) => (
                                  <ControlRow
                                    key={i}
                                    control={c}
                                    findingType={f.type}
                                  />
                                ))}
                              </tbody>
                            </table>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Asset link */}
            {host.asset_id && (
              <div>
                <h4 className="text-[10px] font-medium text-db-muted uppercase tracking-wider mb-2">
                  Linked Asset
                </h4>
                <a
                  href={`/assets/detail/${host.asset_id}`}
                  className="text-xs text-db-teal-light hover:underline font-mono"
                >
                  {host.asset_name || host.asset_id} &rarr;
                </a>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
