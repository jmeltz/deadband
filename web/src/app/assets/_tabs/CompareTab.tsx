"use client";

import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { FileUpload } from "@/components/ui/FileUpload";
import { CvssBadge } from "@/components/advisory/CvssBadge";
import { EmptyState } from "@/components/ui/EmptyState";
import { useDiffUpload } from "@/lib/hooks/useDiff";
import type { DiffResponse } from "@/lib/types";

export function CompareTab() {
  const [baseFile, setBaseFile] = useState<File | null>(null);
  const [compareFile, setCompareFile] = useState<File | null>(null);
  const diffUpload = useDiffUpload();
  const result = diffUpload.data as DiffResponse | undefined;

  const runDiff = () => {
    if (!baseFile || !compareFile) return;
    diffUpload.mutate({ baseFile, compareFile });
  };

  return (
    <div className="space-y-4">
      {/* Upload zone */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-db-muted mb-1.5">Base Snapshot</label>
          <FileUpload
            onFile={setBaseFile}
            label="Drop base inventory file"
            className="h-24"
          />
        </div>
        <div>
          <label className="block text-xs text-db-muted mb-1.5">Compare Snapshot</label>
          <FileUpload
            onFile={setCompareFile}
            label="Drop compare inventory file"
            className="h-24"
          />
        </div>
      </div>

      <div className="flex items-center gap-3">
        <Button
          onClick={runDiff}
          disabled={!baseFile || !compareFile || diffUpload.isPending}
          size="sm"
        >
          {diffUpload.isPending ? "Comparing..." : "Compare Snapshots"}
        </Button>
        {baseFile && compareFile && (
          <span className="text-xs text-db-muted">
            {baseFile.name} vs {compareFile.name}
          </span>
        )}
      </div>

      {diffUpload.isError && (
        <Card className="border-status-critical/30">
          <p className="text-sm text-status-critical">
            {diffUpload.error instanceof Error ? diffUpload.error.message : "Diff failed"}
          </p>
        </Card>
      )}

      {result && (
        <>
          {/* Summary */}
          <Card>
            <h3 className="font-heading text-sm font-semibold mb-3">Diff Summary</h3>
            <div className="flex gap-6">
              <DiffStat label="New Devices" value={result.summary.new_devices} color="text-status-ok" />
              <DiffStat label="Removed" value={result.summary.removed_devices} color="text-status-critical" />
              <DiffStat label="FW Changed" value={result.summary.firmware_changes} color="text-status-medium" />
              <DiffStat label="New Vulns" value={result.summary.new_vulnerabilities} color="text-status-critical" />
            </div>
          </Card>

          {/* New devices */}
          {result.new_devices.length > 0 && (
            <Card>
              <h3 className="font-heading text-sm font-semibold mb-3 text-status-ok">
                + New Devices ({result.new_devices.length})
              </h3>
              <div className="space-y-1">
                {result.new_devices.map((d, i) => (
                  <div key={i} className="flex items-center gap-3 text-xs py-1">
                    <span className="font-mono text-db-text w-32">{d.ip}</span>
                    <span className="text-db-muted">{d.vendor}</span>
                    <span className="font-mono text-db-text">{d.model}</span>
                    <span className="font-mono text-db-muted">fw {d.firmware}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Removed devices */}
          {result.removed_devices.length > 0 && (
            <Card>
              <h3 className="font-heading text-sm font-semibold mb-3 text-status-critical">
                - Removed Devices ({result.removed_devices.length})
              </h3>
              <div className="space-y-1">
                {result.removed_devices.map((d, i) => (
                  <div key={i} className="flex items-center gap-3 text-xs py-1 opacity-60">
                    <span className="font-mono text-db-text w-32">{d.ip}</span>
                    <span className="text-db-muted">{d.vendor}</span>
                    <span className="font-mono text-db-text">{d.model}</span>
                    <span className="font-mono text-db-muted">fw {d.firmware}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Firmware changes */}
          {result.firmware_changes.length > 0 && (
            <Card>
              <h3 className="font-heading text-sm font-semibold mb-3 text-status-medium">
                ~ Firmware Changes ({result.firmware_changes.length})
              </h3>
              <div className="space-y-1">
                {result.firmware_changes.map((fc, i) => (
                  <div key={i} className="flex items-center gap-3 text-xs py-1">
                    <span className="font-mono text-db-text w-32">{fc.ip}</span>
                    <span className="font-mono text-db-text">{fc.model}</span>
                    <span className="font-mono text-db-muted">{fc.old_firmware}</span>
                    <span className="text-db-muted">&rarr;</span>
                    <span className="font-mono text-db-text">{fc.new_firmware}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* New vulnerabilities */}
          {result.new_vulnerabilities.length > 0 && (
            <Card>
              <h3 className="font-heading text-sm font-semibold mb-3 text-status-critical">
                ! New Vulnerabilities ({result.new_vulnerabilities.length})
              </h3>
              <div className="space-y-3">
                {result.new_vulnerabilities.map((nv, i) => (
                  <div key={i} className="bg-db-bg rounded-sm p-3">
                    <div className="flex items-center gap-3 text-xs mb-2">
                      <span className="font-mono text-db-text">{nv.ip}</span>
                      <span className="font-mono text-db-text">{nv.model}</span>
                      <span className="font-mono text-db-muted">fw {nv.firmware}</span>
                    </div>
                    <div className="space-y-1 pl-4">
                      {nv.advisories.map((adv) => (
                        <div key={adv.id} className="flex items-center gap-2 text-xs">
                          <CvssBadge score={adv.cvss_v3} />
                          <span className="font-mono text-status-info">{adv.id}</span>
                          <span className="text-db-text truncate">{adv.title}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* All empty */}
          {result.new_devices.length === 0 &&
            result.removed_devices.length === 0 &&
            result.firmware_changes.length === 0 &&
            result.new_vulnerabilities.length === 0 && (
              <EmptyState title="No changes detected" description="The two inventory snapshots are identical." />
            )}
        </>
      )}

      {!result && !diffUpload.isPending && (
        <EmptyState
          title="Compare inventory snapshots"
          description="Upload two inventory files to see what changed — new devices, firmware updates, and newly exposed vulnerabilities."
        />
      )}
    </div>
  );
}

function DiffStat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className={`text-xl font-heading font-bold ${color}`}>{value}</span>
      <span className="text-xs text-db-muted">{label}</span>
    </div>
  );
}
