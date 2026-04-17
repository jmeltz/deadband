"use client";

import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import {
  usePolicies,
  useUpsertPolicy,
  useDeletePolicy,
  useGeneratePolicy,
  useGapAnalysis,
} from "@/lib/hooks/useACL";
import { useSites } from "@/lib/hooks/useSites";
import { useTrafficSummary, useScopingRecommendations } from "@/lib/hooks/useSentinel";
import { useDriftAnalysis } from "@/lib/hooks/useASA";
import type { Policy, PolicyRule, Violation, Zone, ZoneTrafficSummary, ScopingRecommendation, PolicyDrift } from "@/lib/types";

const sevColors: Record<string, string> = {
  critical: "bg-status-critical/20 text-status-critical border-status-critical/40",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/40",
  medium: "bg-status-medium/20 text-status-medium border-status-medium/40",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/40",
};

const purposeColors: Record<string, string> = {
  ot: "bg-db-teal/20 text-db-teal-light border-db-teal/40",
  it: "bg-blue-500/20 text-blue-400 border-blue-500/40",
  dmz: "bg-orange-500/20 text-orange-400 border-orange-500/40",
  corporate: "bg-gray-500/20 text-gray-400 border-gray-500/40",
  safety: "bg-red-500/20 text-red-400 border-red-500/40",
};

export default function ACLPage() {
  const { data: policies } = usePolicies();
  const { data: sites } = useSites();
  const generatePolicy = useGeneratePolicy();
  const deletePolicy = useDeletePolicy();

  const [selectedSiteId, setSelectedSiteId] = useState("");
  const [selectedPolicyId, setSelectedPolicyId] = useState<string | null>(null);

  // Find sites with zones
  const zonedSites = (sites ?? []).filter(
    (s) => s.zones && s.zones.length > 0,
  );

  const selectedPolicy =
    policies?.find((p) => p.id === selectedPolicyId) ?? null;

  const selectedSite = selectedPolicy
    ? sites?.find((s) => s.id === selectedPolicy.site_id)
    : sites?.find((s) => s.id === selectedSiteId);

  const zones = selectedSite?.zones ?? [];

  const handleGenerate = () => {
    if (!selectedSiteId) return;
    generatePolicy.mutate(selectedSiteId, {
      onSuccess: (policy) => {
        setSelectedPolicyId(policy.id);
      },
    });
  };

  const handleDelete = (id: string) => {
    deletePolicy.mutate(id, {
      onSuccess: () => {
        if (selectedPolicyId === id) setSelectedPolicyId(null);
      },
    });
  };

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Header */}
      <Card>
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-heading text-sm font-semibold">
              ACL Policy Modeling
            </h3>
            <p className="text-xs text-db-muted mt-0.5">
              Define zone-to-zone traffic rules and identify gaps between policy
              and posture reality.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <select
              value={selectedSiteId}
              onChange={(e) => {
                setSelectedSiteId(e.target.value);
                setSelectedPolicyId(null);
              }}
              className="bg-db-surface border border-db-border px-3 py-2 text-sm text-db-text focus:outline-none"
            >
              <option value="">Select site...</option>
              {zonedSites.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.zones?.length ?? 0} zones)
                </option>
              ))}
            </select>
            <Button
              size="sm"
              onClick={handleGenerate}
              disabled={
                !selectedSiteId || generatePolicy.isPending
              }
            >
              {generatePolicy.isPending
                ? "Generating..."
                : "Generate Default Policy"}
            </Button>
          </div>
        </div>
      </Card>

      {/* Policy selector */}
      {(policies ?? []).length > 0 && (
        <Card className="p-0 overflow-hidden">
          <div className="px-4 py-3 border-b border-db-border">
            <h3 className="font-heading text-sm font-semibold">Policies</h3>
          </div>
          <div className="divide-y divide-db-border/50">
            {(policies ?? []).map((p) => (
              <div
                key={p.id}
                onClick={() => setSelectedPolicyId(p.id)}
                className={`px-4 py-3 cursor-pointer table-row-hover flex items-center gap-3 ${selectedPolicyId === p.id ? "bg-db-teal-dim/30 border-l-2 border-l-db-teal" : ""}`}
              >
                <div className="flex-1">
                  <span className="text-xs font-medium text-db-text">
                    {p.name}
                  </span>
                  <span className="text-[10px] text-db-muted ml-2">
                    {(p.rules ?? []).length} rules &middot; default:{" "}
                    {p.default_action}
                  </span>
                </div>
                <span className="text-[10px] font-mono text-db-muted">
                  {new Date(p.updated_at).toLocaleDateString()}
                </span>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    handleDelete(p.id);
                  }}
                  className="text-db-muted hover:text-status-critical text-xs"
                >
                  &times;
                </button>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Zone matrix + analysis tabs */}
      {selectedPolicy && zones.length > 0 && (
        <>
          <ZoneMatrixWithTraffic policy={selectedPolicy} zones={zones} siteId={selectedPolicy.site_id} />
          <AnalysisTabs policy={selectedPolicy} />
        </>
      )}

      {/* Empty state */}
      {!selectedPolicy && (policies ?? []).length === 0 && (
        <Card>
          <div className="text-center py-12">
            <p className="text-sm text-db-muted mb-2">
              No ACL policies defined
            </p>
            <p className="text-xs text-db-muted">
              Select a site with zones above and click &quot;Generate Default
              Policy&quot; to create a deny-all baseline with standard OT
              exceptions.
            </p>
          </div>
        </Card>
      )}

      {selectedSiteId && zones.length === 0 && (
        <Card>
          <div className="text-center py-8">
            <p className="text-sm text-db-muted mb-1">
              This site has no zones defined
            </p>
            <p className="text-xs text-db-muted">
              Add zones to this site from the{" "}
              <a href="/sites" className="text-db-teal-light hover:underline">
                Sites page
              </a>{" "}
              first.
            </p>
          </div>
        </Card>
      )}
    </div>
  );
}

function ZoneMatrixWithTraffic({
  policy,
  zones,
  siteId,
}: {
  policy: Policy;
  zones: Zone[];
  siteId: string;
}) {
  const { data: trafficSummary } = useTrafficSummary(siteId);

  // Build traffic lookup: "srcZone|dstZone" -> summary
  const trafficMap = new Map<string, ZoneTrafficSummary>();
  for (const ts of trafficSummary ?? []) {
    trafficMap.set(`${ts.source_zone}|${ts.dest_zone}`, ts);
  }

  return <ZoneMatrix policy={policy} zones={zones} trafficMap={trafficMap} />;
}

function ZoneMatrix({
  policy,
  zones,
  trafficMap,
}: {
  policy: Policy;
  zones: Zone[];
  trafficMap?: Map<string, ZoneTrafficSummary>;
}) {
  // Build rule lookup: source_zone|dest_zone -> rule
  const ruleMap = new Map<string, PolicyRule>();
  for (const r of policy.rules ?? []) {
    ruleMap.set(`${r.source_zone}|${r.dest_zone}`, r);
  }

  const zoneNames = zones.map((z) => z.name);

  return (
    <Card className="p-0 overflow-hidden">
      <div className="px-4 py-3 border-b border-db-border">
        <h3 className="font-heading text-sm font-semibold">
          Zone Traffic Matrix
        </h3>
        <p className="text-[10px] text-db-muted mt-0.5">
          Rows = source zone, Columns = destination zone. Default action:{" "}
          <span className="font-mono uppercase">{policy.default_action}</span>
        </p>
      </div>
      <div className="overflow-x-auto p-4">
        <table className="w-full text-xs border-collapse">
          <thead>
            <tr>
              <th className="p-2 text-left text-db-muted font-medium border border-db-border bg-db-bg">
                Src \ Dst
              </th>
              {zoneNames.map((name) => {
                const z = zones.find((zz) => zz.name === name);
                return (
                  <th
                    key={name}
                    className="p-2 text-center font-medium border border-db-border bg-db-bg"
                  >
                    <span className="text-db-text">{name}</span>
                    {z && (
                      <span
                        className={`block text-[8px] font-mono mt-0.5 px-1 py-0.5 border ${purposeColors[z.purpose] || "text-db-muted border-db-border"}`}
                      >
                        {z.purpose}
                      </span>
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {zoneNames.map((srcName) => {
              const srcZone = zones.find((z) => z.name === srcName);
              return (
                <tr key={srcName}>
                  <td className="p-2 border border-db-border bg-db-bg">
                    <span className="text-db-text font-medium">{srcName}</span>
                    {srcZone && (
                      <span
                        className={`ml-1 text-[8px] font-mono px-1 py-0.5 border ${purposeColors[srcZone.purpose] || "text-db-muted border-db-border"}`}
                      >
                        {srcZone.purpose}
                      </span>
                    )}
                  </td>
                  {zoneNames.map((dstName) => {
                    if (srcName === dstName) {
                      return (
                        <td
                          key={dstName}
                          className="p-2 text-center border border-db-border bg-db-surface/30"
                        >
                          <span className="text-[10px] text-db-muted">
                            &mdash;
                          </span>
                        </td>
                      );
                    }
                    const rule = ruleMap.get(`${srcName}|${dstName}`);
                    const action = rule?.action ?? policy.default_action;
                    const isAllow = action === "allow";
                    const traffic = trafficMap?.get(`${srcName}|${dstName}`);
                    const isDeniedWithTraffic = !isAllow && traffic && traffic.flow_count > 0;

                    return (
                      <td
                        key={dstName}
                        className={`p-2 text-center border border-db-border relative ${isAllow ? "bg-emerald-500/10" : "bg-red-500/10"} ${isDeniedWithTraffic ? "ring-1 ring-inset ring-orange-500/60" : ""}`}
                        title={rule?.description || `Default: ${policy.default_action}`}
                      >
                        <span
                          className={`text-[9px] font-mono font-semibold uppercase ${isAllow ? "text-emerald-400" : "text-red-400"}`}
                        >
                          {action}
                        </span>
                        {rule && (rule.ports ?? []).length > 0 && (
                          <div className="text-[8px] text-db-muted mt-0.5 font-mono">
                            {rule.ports.length <= 3
                              ? rule.ports.join(", ")
                              : `${rule.ports.slice(0, 3).join(", ")}...`}
                          </div>
                        )}
                        {traffic && traffic.flow_count > 0 && (
                          <div className={`text-[8px] mt-0.5 font-mono ${isDeniedWithTraffic ? "text-orange-400" : "text-db-muted"}`}>
                            {traffic.flow_count} flow{traffic.flow_count !== 1 ? "s" : ""}
                          </div>
                        )}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

type AnalysisTab = "gaps" | "drift" | "scoping";

function AnalysisTabs({ policy }: { policy: Policy }) {
  const [tab, setTab] = useState<AnalysisTab>("gaps");
  const { data: violations } = useGapAnalysis(policy.id, { includeFlows: true });
  const { data: drifts } = useDriftAnalysis(policy.id);
  const { data: recommendations } = useScopingRecommendations(policy.id);

  const gapCount = violations?.length ?? 0;
  const driftCount = drifts?.length ?? 0;
  const scopingCount = recommendations?.length ?? 0;

  const tabs: { key: AnalysisTab; label: string; count: number }[] = [
    { key: "gaps", label: "Posture Gaps", count: gapCount },
    { key: "drift", label: "ASA Drift", count: driftCount },
    { key: "scoping", label: "Scoping", count: scopingCount },
  ];

  return (
    <div className="space-y-0">
      <div className="flex border-b border-db-border bg-db-surface">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`px-4 py-2.5 text-xs font-medium transition-colors relative ${
              tab === t.key
                ? "text-db-teal-light border-b-2 border-db-teal"
                : "text-db-muted hover:text-db-text"
            }`}
          >
            {t.label}
            {t.count > 0 && (
              <span className={`ml-1.5 text-[9px] font-mono px-1 py-0.5 border ${
                tab === t.key ? "border-db-teal/40 text-db-teal-light" : "border-db-border text-db-muted"
              }`}>
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>
      {tab === "gaps" && <GapAnalysisPanel policy={policy} />}
      {tab === "drift" && <DriftPanel policyId={policy.id} />}
      {tab === "scoping" && <ScopingPanel policyId={policy.id} />}
    </div>
  );
}

function GapAnalysisPanel({ policy }: { policy: Policy }) {
  const { data: violations, isLoading } = useGapAnalysis(policy.id, { includeFlows: true });

  return (
    <Card className="p-0 overflow-hidden">
      <div className="px-4 py-3 border-b border-db-border">
        <h3 className="font-heading text-sm font-semibold">
          Gap Analysis
        </h3>
        <p className="text-[10px] text-db-muted mt-0.5">
          Compares policy deny rules against actual posture scan results to
          identify open paths that violate the policy.
        </p>
      </div>

      {isLoading ? (
        <div className="px-4 py-8 text-center text-xs text-db-muted">
          Analyzing gaps...
        </div>
      ) : !violations || violations.length === 0 ? (
        <div className="px-4 py-8 text-center text-xs text-db-muted">
          {violations
            ? "No violations found. Policy aligns with current posture."
            : "Run a posture scan first to enable gap analysis."}
        </div>
      ) : (
        <div className="divide-y divide-db-border/50">
          <div className="px-4 py-2 bg-db-bg">
            <span className="text-xs font-medium text-db-text">
              {violations.length} violation
              {violations.length !== 1 ? "s" : ""} found
            </span>
            <span className="text-[10px] text-db-muted ml-2">
              {violations.filter((v) => v.severity === "critical").length}{" "}
              critical &middot;{" "}
              {violations.filter((v) => v.severity === "high").length} high
            </span>
          </div>
          {violations.map((v, i) => (
            <ViolationRow key={i} violation={v} />
          ))}
        </div>
      )}
    </Card>
  );
}

function ViolationRow({ violation }: { violation: Violation }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div>
      <div
        onClick={() => setExpanded(!expanded)}
        className="px-4 py-3 cursor-pointer table-row-hover flex items-center gap-3"
      >
        <span className="text-[10px] text-db-muted w-4">
          {expanded ? "\u25BC" : "\u25B6"}
        </span>
        <span
          className={`text-[9px] font-mono px-1.5 py-0.5 border uppercase ${sevColors[violation.severity] || "text-db-muted border-db-border"}`}
        >
          {violation.severity}
        </span>
        <div className="flex-1">
          <span className="text-xs text-db-text">{violation.description}</span>
        </div>
        {violation.active_flows != null && violation.active_flows > 0 && (
          <span className="text-[9px] font-mono px-1.5 py-0.5 border bg-orange-500/20 text-orange-400 border-orange-500/40">
            {violation.active_flows} active flow{violation.active_flows !== 1 ? "s" : ""}
          </span>
        )}
        <span className="text-[10px] font-mono text-db-muted">
          {violation.violators.length} host
          {violation.violators.length !== 1 ? "s" : ""}
        </span>
      </div>
      {expanded && (
        <div className="bg-db-bg border-t border-db-border/50 px-4 py-3 space-y-3">
          <div className="text-xs text-db-muted leading-relaxed">
            <span className="font-medium text-db-text">Rule: </span>
            {violation.rule.action.toUpperCase()}{" "}
            {violation.rule.source_zone} &rarr; {violation.rule.dest_zone}
            {(violation.rule.ports ?? []).length > 0 && (
              <span className="font-mono">
                {" "}
                ports {violation.rule.ports.join(", ")}
              </span>
            )}
            {(violation.rule.ports ?? []).length === 0 && (
              <span className="font-mono"> all ports</span>
            )}
            {violation.rule.description && (
              <span className="text-db-muted">
                {" "}
                &mdash; {violation.rule.description}
              </span>
            )}
          </div>

          <div>
            <h5 className="text-[10px] font-medium text-db-muted uppercase tracking-wider mb-1.5">
              Violating Hosts
            </h5>
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-db-muted border-b border-db-border/50">
                  <th className="py-1 pr-2 font-medium">IP</th>
                  <th className="py-1 pr-2 font-medium">Hostname</th>
                  <th className="py-1 pr-2 font-medium">Port</th>
                  <th className="py-1 pr-2 font-medium">Source Zone</th>
                  <th className="py-1 font-medium">Dest Zone</th>
                </tr>
              </thead>
              <tbody>
                {violation.violators.map((vh, j) => (
                  <tr key={j} className="border-t border-db-border/30">
                    <td className="py-1 pr-2 font-mono text-db-text">
                      {vh.ip}
                    </td>
                    <td className="py-1 pr-2 text-db-muted">
                      {vh.hostname || "\u2014"}
                    </td>
                    <td className="py-1 pr-2 font-mono text-db-text">
                      {vh.port}
                    </td>
                    <td className="py-1 pr-2 text-db-muted">{vh.source_zone}</td>
                    <td className="py-1 text-db-muted">{vh.dest_zone}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {violation.flow_identities && violation.flow_identities.length > 0 && (
            <div>
              <h5 className="text-[10px] font-medium text-db-muted uppercase tracking-wider mb-1.5">
                Identified Users on This Path
              </h5>
              <div className="flex flex-wrap gap-2">
                {violation.flow_identities.map((fi, k) => (
                  <div key={k} className="text-xs bg-db-surface border border-db-border px-2 py-1">
                    <span className="text-db-text font-medium">{fi.user_name}</span>
                    {fi.department && (
                      <span className="text-db-muted ml-1">({fi.department})</span>
                    )}
                    <span className="text-[10px] font-mono text-db-muted ml-1.5">
                      {fi.flow_count} flow{fi.flow_count !== 1 ? "s" : ""}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const driftTypeColors: Record<string, string> = {
  mismatch: "bg-status-critical/20 text-status-critical border-status-critical/40",
  missing: "bg-orange-500/20 text-orange-400 border-orange-500/40",
  extra: "bg-blue-500/20 text-blue-400 border-blue-500/40",
};

function DriftPanel({ policyId }: { policyId: string }) {
  const { data: drifts, isLoading } = useDriftAnalysis(policyId);
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);

  if (isLoading) {
    return (
      <Card className="p-0 overflow-hidden">
        <div className="px-4 py-3 border-b border-db-border">
          <h3 className="font-heading text-sm font-semibold">ASA Config Drift</h3>
        </div>
        <div className="px-4 py-8 text-center text-xs text-db-muted">Analyzing drift...</div>
      </Card>
    );
  }

  if (!drifts || drifts.length === 0) return null;

  const mismatchCount = drifts.filter((d) => d.drift_type === "mismatch").length;
  const missingCount = drifts.filter((d) => d.drift_type === "missing").length;
  const extraCount = drifts.filter((d) => d.drift_type === "extra").length;

  return (
    <Card className="p-0 overflow-hidden">
      <div className="px-4 py-3 border-b border-db-border">
        <h3 className="font-heading text-sm font-semibold">ASA Config Drift</h3>
        <p className="text-[10px] text-db-muted mt-0.5">
          Compares modeled policy against actual Cisco ASA firewall rules.
        </p>
      </div>
      <div className="divide-y divide-db-border/50">
        <div className="px-4 py-2 bg-db-bg">
          <span className="text-xs font-medium text-db-text">
            {drifts.length} drift item{drifts.length !== 1 ? "s" : ""}
          </span>
          <span className="text-[10px] text-db-muted ml-2">
            {mismatchCount} mismatch &middot; {missingCount} missing &middot; {extraCount} extra
          </span>
        </div>
        {drifts.map((d, i) => (
          <div key={i}>
            <div
              onClick={() => setExpandedIdx(expandedIdx === i ? null : i)}
              className="px-4 py-3 cursor-pointer table-row-hover flex items-center gap-3"
            >
              <span className="text-[10px] text-db-muted w-4">
                {expandedIdx === i ? "\u25BC" : "\u25B6"}
              </span>
              <span
                className={`text-[9px] font-mono px-1.5 py-0.5 border uppercase ${sevColors[d.severity] || "text-db-muted border-db-border"}`}
              >
                {d.severity}
              </span>
              <span
                className={`text-[9px] font-mono px-1.5 py-0.5 border ${driftTypeColors[d.drift_type] || "text-db-muted border-db-border"}`}
              >
                {d.drift_type}
              </span>
              <div className="flex-1">
                <span className="text-xs text-db-text">{d.description}</span>
              </div>
            </div>
            {expandedIdx === i && (
              <div className="bg-db-bg border-t border-db-border/50 px-4 py-3 space-y-3">
                {d.policy_rule?.id && (
                  <div className="text-xs text-db-muted leading-relaxed">
                    <span className="font-medium text-db-text">Policy Rule: </span>
                    {d.policy_rule.action.toUpperCase()}{" "}
                    {d.policy_rule.source_zone} &rarr; {d.policy_rule.dest_zone}
                    {(d.policy_rule.ports ?? []).length > 0 && (
                      <span className="font-mono"> ports {d.policy_rule.ports.join(", ")}</span>
                    )}
                    {(d.policy_rule.ports ?? []).length === 0 && (
                      <span className="font-mono"> all ports</span>
                    )}
                  </div>
                )}
                {d.asa_rules && d.asa_rules.length > 0 && (
                  <div>
                    <h5 className="text-[10px] font-medium text-db-muted uppercase tracking-wider mb-1.5">
                      ASA Rules
                    </h5>
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-left text-db-muted border-b border-db-border/50">
                          <th className="py-1 pr-2 font-medium">ACL</th>
                          <th className="py-1 pr-2 font-medium">Line</th>
                          <th className="py-1 pr-2 font-medium">Action</th>
                          <th className="py-1 pr-2 font-medium">Protocol</th>
                          <th className="py-1 pr-2 font-medium">Source</th>
                          <th className="py-1 pr-2 font-medium">Dest</th>
                          <th className="py-1 pr-2 font-medium">Port</th>
                          <th className="py-1 font-medium">Hits</th>
                        </tr>
                      </thead>
                      <tbody>
                        {d.asa_rules.map((ar, j) => (
                          <tr key={j} className="border-t border-db-border/30">
                            <td className="py-1 pr-2 font-mono text-db-text">{ar.name}</td>
                            <td className="py-1 pr-2 font-mono text-db-muted">{ar.line}</td>
                            <td className="py-1 pr-2">
                              <span className={`font-mono ${ar.action === "permit" ? "text-emerald-400" : "text-red-400"}`}>
                                {ar.action}
                              </span>
                            </td>
                            <td className="py-1 pr-2 font-mono text-db-muted">{ar.protocol}</td>
                            <td className="py-1 pr-2 font-mono text-db-text">
                              {ar.source_addr}{ar.source_mask ? `/${ar.source_mask}` : ""}
                            </td>
                            <td className="py-1 pr-2 font-mono text-db-text">
                              {ar.dest_addr}{ar.dest_mask ? `/${ar.dest_mask}` : ""}
                            </td>
                            <td className="py-1 pr-2 font-mono text-db-muted">
                              {ar.dest_port ? `${ar.port_op || "eq"} ${ar.dest_port}${ar.port_end ? `-${ar.port_end}` : ""}` : "any"}
                            </td>
                            <td className="py-1 font-mono text-db-muted">{ar.hit_count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </Card>
  );
}

function ScopingPanel({ policyId }: { policyId: string }) {
  const { data: recommendations, isLoading } = useScopingRecommendations(policyId);
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);

  if (isLoading) {
    return (
      <Card className="p-0 overflow-hidden">
        <div className="px-4 py-3 border-b border-db-border">
          <h3 className="font-heading text-sm font-semibold">Scoping Recommendations</h3>
        </div>
        <div className="px-4 py-8 text-center text-xs text-db-muted">Loading...</div>
      </Card>
    );
  }

  if (!recommendations || recommendations.length === 0) return null;

  return (
    <Card className="p-0 overflow-hidden">
      <div className="px-4 py-3 border-b border-db-border">
        <h3 className="font-heading text-sm font-semibold">Scoping Recommendations</h3>
        <p className="text-[10px] text-db-muted mt-0.5">
          Suggests tighter replacements for broad allow rules based on observed Sentinel traffic flows.
        </p>
      </div>
      <div className="divide-y divide-db-border/50">
        {recommendations.map((rec, i) => (
          <div key={i}>
            <div
              onClick={() => setExpandedIdx(expandedIdx === i ? null : i)}
              className="px-4 py-3 cursor-pointer table-row-hover flex items-center gap-3"
            >
              <span className="text-[10px] text-db-muted w-4">
                {expandedIdx === i ? "\u25BC" : "\u25B6"}
              </span>
              <div className="flex-1">
                <span className="text-xs text-db-text">
                  {rec.original_rule.source_zone} &rarr; {rec.original_rule.dest_zone}
                </span>
                <span className="text-[10px] text-db-muted ml-2">
                  ALLOW
                  {(rec.original_rule.ports ?? []).length > 0
                    ? ` ports ${rec.original_rule.ports.join(", ")}`
                    : " all ports"}
                </span>
              </div>
              <span className="text-[9px] font-mono px-1.5 py-0.5 border bg-db-teal/20 text-db-teal-light border-db-teal/40">
                {rec.reduction_percent.toFixed(0)}% reduction
              </span>
              <span className="text-[10px] font-mono text-db-muted">
                {rec.suggested_rules.length} suggestion{rec.suggested_rules.length !== 1 ? "s" : ""}
              </span>
            </div>
            {expandedIdx === i && (
              <div className="bg-db-bg border-t border-db-border/50 px-4 py-3 space-y-2">
                {rec.active_impact && (
                  <div className="text-[10px] text-orange-400 mb-2">
                    Active traffic observed — changes may impact live connections.
                  </div>
                )}
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-left text-db-muted border-b border-db-border/50">
                      <th className="py-1 pr-2 font-medium">Source CIDR</th>
                      <th className="py-1 pr-2 font-medium">Dest CIDR</th>
                      <th className="py-1 pr-2 font-medium">Ports</th>
                      <th className="py-1 pr-2 font-medium">Flows</th>
                      <th className="py-1 font-medium">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rec.suggested_rules.map((sr, j) => (
                      <tr key={j} className="border-t border-db-border/30">
                        <td className="py-1 pr-2 font-mono text-db-text">{sr.source_cidr}</td>
                        <td className="py-1 pr-2 font-mono text-db-text">{sr.dest_cidr}</td>
                        <td className="py-1 pr-2 font-mono text-db-text">
                          {sr.ports.length <= 3
                            ? sr.ports.join(", ")
                            : `${sr.ports.slice(0, 3).join(", ")}...`}
                        </td>
                        <td className="py-1 pr-2 font-mono text-db-muted">{sr.flow_count}</td>
                        <td className="py-1 text-db-muted">{sr.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ))}
      </div>
    </Card>
  );
}
