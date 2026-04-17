"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils/cn";

const FRAMEWORKS = [
  { value: "", label: "All Frameworks" },
  { value: "iec62443", label: "IEC 62443" },
  { value: "nist-csf", label: "NIST CSF 2.0" },
  { value: "nerc-cip", label: "NERC CIP" },
];

const CAPABILITY_COLORS: Record<string, string> = {
  discovery: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  matching: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  enrichment: "bg-red-500/15 text-red-400 border-red-500/30",
  diffing: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  version_check: "bg-purple-500/15 text-purple-400 border-purple-500/30",
};

export function FrameworksTab() {
  const [framework, setFramework] = useState("");

  const { data, isLoading, error } = useQuery({
    queryKey: ["compliance", framework],
    queryFn: () => api.complianceMappings(framework || undefined),
  });

  const grouped = data?.mappings.reduce(
    (acc, m) => {
      const key = m.framework;
      if (!acc[key]) acc[key] = [];
      acc[key].push(m);
      return acc;
    },
    {} as Record<string, typeof data.mappings>,
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="font-heading text-sm font-semibold">
            Compliance Mapping
          </h3>
          <p className="text-xs text-db-muted mt-0.5">
            Controls addressed by deadband across IEC 62443, NIST CSF 2.0, and
            NERC CIP frameworks.
          </p>
        </div>
        <div className="flex gap-1">
          {FRAMEWORKS.map((fw) => (
            <button
              key={fw.value}
              onClick={() => setFramework(fw.value)}
              className={cn(
                "px-3 py-1.5 text-xs font-mono rounded-sm border transition-colors",
                framework === fw.value
                  ? "bg-db-teal-dim text-db-teal-light border-db-teal/30"
                  : "bg-db-surface text-db-muted border-db-border hover:text-db-text",
              )}
            >
              {fw.label}
            </button>
          ))}
        </div>
      </div>

      {isLoading && (
        <div className="text-sm text-db-muted font-mono">
          Loading mappings...
        </div>
      )}

      {error && (
        <div className="text-sm text-red-400 font-mono">
          Error loading compliance data
        </div>
      )}

      {grouped &&
        Object.entries(grouped).map(([fw, mappings]) => (
          <section
            key={fw}
            className="bg-db-surface border border-db-border rounded-sm"
          >
            <div className="px-4 py-3 border-b border-db-border">
              <h2 className="text-sm font-semibold text-db-text">{fw}</h2>
              <p className="text-xs text-db-muted mt-0.5">
                {mappings.length} controls mapped
              </p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-db-border">
                    <th className="text-left px-4 py-2 text-[10px] font-mono text-db-muted uppercase tracking-wider">
                      Control ID
                    </th>
                    <th className="text-left px-4 py-2 text-[10px] font-mono text-db-muted uppercase tracking-wider">
                      Control Name
                    </th>
                    <th className="text-left px-4 py-2 text-[10px] font-mono text-db-muted uppercase tracking-wider">
                      Capability
                    </th>
                    <th className="text-left px-4 py-2 text-[10px] font-mono text-db-muted uppercase tracking-wider">
                      Rationale
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {mappings.map((m) => (
                    <tr
                      key={`${m.control_id}-${m.capability}`}
                      className="border-b border-db-border last:border-0 hover:bg-db-teal/[0.02] transition-colors"
                    >
                      <td className="px-4 py-2.5 font-mono text-xs text-db-info whitespace-nowrap">
                        {m.control_id}
                      </td>
                      <td className="px-4 py-2.5 text-xs text-db-text">
                        {m.control_name}
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className={cn(
                            "inline-block px-2 py-0.5 text-[10px] font-mono border rounded-sm",
                            CAPABILITY_COLORS[m.capability] ||
                              "bg-db-border/50 text-db-muted border-db-border",
                          )}
                        >
                          {m.capability}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-xs text-db-muted max-w-md">
                        {m.rationale}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        ))}
    </div>
  );
}
