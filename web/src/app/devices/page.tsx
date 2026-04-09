"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { FileUpload } from "@/components/ui/FileUpload";
import { StatusBadge, ConfidenceBadge } from "@/components/ui/Badge";
import { CvssBadge } from "@/components/advisory/CvssBadge";
import { CveBadge } from "@/components/advisory/CveBadge";
import { KEVBadge, EPSSBar, RiskBadge } from "@/components/advisory/RiskBadge";
import { EmptyState } from "@/components/ui/EmptyState";
import { useCheckUpload } from "@/lib/hooks/useCheck";
import { useDiscover } from "@/lib/hooks/useDiscover";
import { useImportAssets } from "@/lib/hooks/useAssets";
import type { Device, CheckResponse, CheckDeviceResult } from "@/lib/types";
import Link from "next/link";

type InputMode = "upload" | "discover";

export default function DevicesPage() {
  const [inputMode, setInputMode] = useState<InputMode>("upload");
  const [devices, setDevices] = useState<Device[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // Discovery state
  const [cidr, setCidr] = useState("");
  const [scanMode, setScanMode] = useState("auto");
  const [autoCheck, setAutoCheck] = useState(true);
  const { status: discoverStatus, progress, result: discoverResult, error: discoverError, start: startDiscover, reset: resetDiscover } = useDiscover();
  const logRef = useRef<HTMLDivElement>(null);

  // Check state
  const checkUpload = useCheckUpload();
  const qc = useQueryClient();
  const checkResults = qc.getQueryData<CheckResponse>(["check-results"]);

  // Asset import
  const importAssets = useImportAssets();
  const [importResult, setImportResult] = useState<{ added: number; updated: number } | null>(null);

  // Auto-scroll progress log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [progress]);

  // When discovery completes with devices, populate the table
  useEffect(() => {
    if (discoverResult?.devices && discoverResult.devices.length > 0) {
      setDevices(discoverResult.devices);
      // If auto-check was on and results came back, cache them
      if (discoverResult.check_results) {
        qc.setQueryData(["check-results"], discoverResult.check_results);
      }
    }
  }, [discoverResult, qc]);

  const toggleExpand = (key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  // File parsing (supports JSON array and CSV)
  const handleFile = useCallback((f: File) => {
    setFile(f);
    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result as string;
      try {
        const parsed = JSON.parse(text);
        if (Array.isArray(parsed)) {
          const devs = parsed
            .map((d: Record<string, string>) => ({
              ip: d.ip || d.scanned_ip || "",
              vendor: d.vendor || (d.device_name ? "Rockwell Automation" : ""),
              model: d.model || d.device_name || "",
              firmware: d.firmware || d.product_revision || "",
            }))
            .filter((d: Device) => d.ip && d.model);
          setDevices(devs);
          return;
        }
      } catch {
        // Not JSON, try CSV
      }
      const lines = text.split("\n").filter((l) => l.trim() && !l.startsWith("#"));
      if (lines.length > 1) {
        const headers = lines[0].split(",").map((h) => h.trim());
        const isRockwell = headers.includes("Device Name") && headers.includes("Product Revision");
        const devs: Device[] = [];
        for (let i = 1; i < lines.length; i++) {
          const cols = lines[i].split(",").map((c) => c.trim());
          if (isRockwell) {
            const idx = (h: string) => headers.indexOf(h);
            devs.push({
              ip: cols[idx("IP Address")] || cols[idx("Scanned IP")] || "",
              vendor: "Rockwell Automation",
              model: cols[idx("Device Name")] || "",
              firmware: cols[idx("Product Revision")] || "",
            });
          } else if (cols.length >= 4) {
            devs.push({ ip: cols[0], vendor: cols[1], model: cols[2], firmware: cols[3] });
          }
        }
        setDevices(devs.filter((d) => d.ip && d.model));
      }
    };
    reader.readAsText(f);
  }, []);

  const handleDiscover = (e: React.FormEvent) => {
    e.preventDefault();
    if (!cidr.trim()) return;
    startDiscover({ cidr: cidr.trim(), mode: scanMode, auto_check: autoCheck });
  };

  const runCheck = () => {
    if (!file) return;
    checkUpload.mutate({ file });
  };

  // Build merged view: devices + check results
  const resultMap = new Map<string, CheckDeviceResult>();
  if (checkResults) {
    for (const r of checkResults.results) {
      resultMap.set(`${r.ip}:${r.model}`, r);
    }
  }

  const hasCheck = !!checkResults;
  const summary = checkResults?.summary;

  return (
    <div className="max-w-6xl space-y-4">
      {/* Input mode tabs */}
      <div className="flex items-center gap-1 border-b border-db-border">
        <button
          onClick={() => setInputMode("upload")}
          className={`px-4 py-2.5 text-sm font-medium transition-colors relative ${
            inputMode === "upload"
              ? "text-db-teal-light"
              : "text-db-muted hover:text-db-text"
          }`}
        >
          Upload Inventory
          {inputMode === "upload" && (
            <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-db-teal-light" />
          )}
        </button>
        <button
          onClick={() => setInputMode("discover")}
          className={`px-4 py-2.5 text-sm font-medium transition-colors relative ${
            inputMode === "discover"
              ? "text-db-teal-light"
              : "text-db-muted hover:text-db-text"
          }`}
        >
          Network Discovery
          {inputMode === "discover" && (
            <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-db-teal-light" />
          )}
        </button>
      </div>

      {/* Upload panel */}
      {inputMode === "upload" && (
        <FileUpload
          onFile={handleFile}
          label="Drop an inventory file (CSV, JSON, or flat text) to load devices"
        />
      )}

      {/* Discover panel */}
      {inputMode === "discover" && (
        <Card>
          <form onSubmit={handleDiscover} className="flex items-end gap-3">
            <div className="flex-1">
              <label className="block text-xs text-db-muted mb-1.5">CIDR Range</label>
              <input
                type="text"
                value={cidr}
                onChange={(e) => setCidr(e.target.value)}
                placeholder="e.g. 10.0.1.0/24"
                className="w-full bg-db-bg border border-db-border px-3 py-2 text-sm font-mono text-db-text placeholder:text-db-muted focus:outline-none input-industrial"
                disabled={discoverStatus === "running"}
              />
            </div>
            <div>
              <label className="block text-xs text-db-muted mb-1.5">Protocol</label>
              <select
                value={scanMode}
                onChange={(e) => setScanMode(e.target.value)}
                disabled={discoverStatus === "running"}
                className="bg-db-bg border border-db-border px-3 py-2 text-sm text-db-text focus:outline-none input-industrial"
              >
                <option value="auto">Auto (all)</option>
                <option value="cip">CIP (Rockwell)</option>
                <option value="s7">S7 (Siemens)</option>
                <option value="modbus">Modbus TCP</option>
                <option value="melsec">MELSEC (Mitsubishi)</option>
                <option value="bacnet">BACnet/IP</option>
                <option value="fins">FINS (Omron)</option>
                <option value="srtp">GE-SRTP</option>
                <option value="http">HTTP (Legacy)</option>
              </select>
            </div>
            <label className="flex items-center gap-2 text-xs text-db-muted pb-2">
              <input
                type="checkbox"
                checked={autoCheck}
                onChange={(e) => setAutoCheck(e.target.checked)}
                className="rounded border-db-border"
              />
              Auto-check
            </label>
            {discoverStatus === "idle" || discoverStatus === "complete" || discoverStatus === "error" ? (
              <Button type="submit" disabled={!cidr.trim()}>
                Scan
              </Button>
            ) : (
              <Button variant="secondary" disabled>
                Scanning...
              </Button>
            )}
            {(discoverStatus === "complete" || discoverStatus === "error") && (
              <Button variant="ghost" size="sm" onClick={resetDiscover}>
                Reset
              </Button>
            )}
          </form>
        </Card>
      )}

      {/* Discovery progress log */}
      {inputMode === "discover" && (discoverStatus === "running" || progress.length > 0) && (
        <Card className="p-0">
          <div
            ref={logRef}
            className="h-40 overflow-auto p-4 font-mono text-xs leading-relaxed bg-db-bg rounded-sm code-scanline"
          >
            {progress.map((msg, i) => (
              <div key={i} className="text-status-ok/80">
                <span className="text-db-muted select-none">$ </span>
                {msg}
              </div>
            ))}
            {discoverStatus === "running" && (
              <div className="text-db-muted animate-pulse">Scanning...</div>
            )}
          </div>
        </Card>
      )}

      {/* Discovery error */}
      {discoverError && (
        <Card className="border-status-critical/30">
          <p className="text-sm text-status-critical">{discoverError}</p>
        </Card>
      )}

      {/* Check summary bar (when results exist) */}
      {hasCheck && summary && (
        <Card>
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-heading text-sm font-semibold">
              Vulnerability Check — {checkResults.devices_checked} devices
            </h3>
            <span className="text-[10px] text-db-muted font-mono">
              {checkResults.checked_at}
            </span>
          </div>
          <div className="flex gap-6 mb-3">
            <SummaryBlock label="Vulnerable" value={summary.vulnerable} color="bg-status-critical" />
            <SummaryBlock label="Potential" value={summary.potential} color="bg-status-medium" />
            <SummaryBlock label="OK" value={summary.ok} color="bg-status-ok" />
            <SummaryBlock label="No Match" value={summary.no_match} color="bg-db-muted/30" />
          </div>
          <div className="flex h-2 rounded-sm overflow-hidden bg-db-bg">
            <BarSegment count={summary.vulnerable} total={checkResults.devices_checked} color="bg-status-critical" />
            <BarSegment count={summary.potential} total={checkResults.devices_checked} color="bg-status-medium" />
            <BarSegment count={summary.ok} total={checkResults.devices_checked} color="bg-status-ok" />
            <BarSegment count={summary.no_match} total={checkResults.devices_checked} color="bg-db-muted/30" />
          </div>
        </Card>
      )}

      {/* Device table */}
      {devices.length > 0 && (
        <>
          <div className="flex items-center justify-between">
            <span className="text-xs text-db-muted">
              {devices.length} device{devices.length !== 1 ? "s" : ""} loaded
              {file && <> from <span className="font-mono text-db-text">{file.name}</span></>}
              {!file && inputMode === "discover" && discoverStatus === "complete" && " via network discovery"}
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="secondary"
                size="sm"
                disabled={importAssets.isPending}
                onClick={() => {
                  const source = inputMode === "discover" ? "discovery" : "upload";
                  importAssets.mutate({ devices, source }, {
                    onSuccess: (data) => setImportResult(data),
                  });
                }}
              >
                {importAssets.isPending ? "Saving..." : importResult ? `Saved (${importResult.added} new, ${importResult.updated} updated)` : "Save to Assets"}
              </Button>
              {file && (
                <Button
                  onClick={runCheck}
                  disabled={checkUpload.isPending}
                  size="sm"
                >
                  {checkUpload.isPending ? "Checking..." : "Run Vulnerability Check"}
                </Button>
              )}
            </div>
          </div>

          <Card className="p-0 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-db-border text-left">
                  {hasCheck && <th className="px-4 py-2.5 text-xs font-medium text-db-muted w-8" />}
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">IP Address</th>
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Vendor</th>
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Model</th>
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Firmware</th>
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Status</th>
                  {hasCheck && <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Confidence</th>}
                  {hasCheck && <th className="px-4 py-2.5 text-xs font-medium text-db-muted text-right">Advisories</th>}
                </tr>
              </thead>
              <tbody>
                {devices.map((d, i) => {
                  const checkResult = resultMap.get(`${d.ip}:${d.model}`);
                  const key = `${d.ip}:${d.model}:${i}`;
                  const isOpen = expanded.has(key);
                  const hasAdvisories = checkResult && checkResult.advisories?.length > 0;

                  return (
                    <DeviceRow
                      key={key}
                      device={d}
                      checkResult={checkResult}
                      isOpen={isOpen}
                      hasCheck={hasCheck}
                      hasAdvisories={!!hasAdvisories}
                      onToggle={() => hasAdvisories && toggleExpand(key)}
                      odd={i % 2 !== 0}
                    />
                  );
                })}
              </tbody>
            </table>
          </Card>
        </>
      )}

      {/* Empty state */}
      {devices.length === 0 && discoverStatus !== "running" && (
        <EmptyState
          title="No devices loaded"
          description={
            inputMode === "upload"
              ? "Upload a device inventory file (CSV, JSON, or flat text) to get started."
              : "Enter a CIDR range above and scan to discover devices on your network."
          }
        />
      )}
    </div>
  );
}

function DeviceRow({
  device,
  checkResult,
  isOpen,
  hasCheck,
  hasAdvisories,
  onToggle,
  odd,
}: {
  device: Device;
  checkResult?: CheckDeviceResult;
  isOpen: boolean;
  hasCheck: boolean;
  hasAdvisories: boolean;
  onToggle: () => void;
  odd: boolean;
}) {
  return (
    <>
      <tr
        className={`border-b border-db-border/50 table-row-hover ${hasAdvisories ? "cursor-pointer" : ""} ${odd ? "bg-db-bg/30" : ""}`}
        onClick={hasAdvisories ? onToggle : undefined}
      >
        {hasCheck && (
          <td className="px-4 py-2 text-db-muted">
            {hasAdvisories && (
              <span className={`inline-block transition-transform text-[10px] ${isOpen ? "rotate-90" : ""}`}>&#9654;</span>
            )}
          </td>
        )}
        <td className="px-4 py-2 font-mono text-xs">{device.ip}</td>
        <td className="px-4 py-2 text-xs text-db-muted">{device.vendor}</td>
        <td className="px-4 py-2 font-mono text-xs">{device.model}</td>
        <td className="px-4 py-2 font-mono text-xs">{device.firmware}</td>
        <td className="px-4 py-2">
          {checkResult ? (
            <StatusBadge status={checkResult.status} />
          ) : (
            <span className="text-[10px] text-db-muted">—</span>
          )}
        </td>
        {hasCheck && (
          <td className="px-4 py-2">
            {checkResult?.confidence && <ConfidenceBadge confidence={checkResult.confidence} />}
          </td>
        )}
        {hasCheck && (
          <td className="px-4 py-2 text-xs text-db-muted text-right font-mono">
            {checkResult?.advisories?.length || 0}
          </td>
        )}
      </tr>
      {isOpen && checkResult?.advisories?.map((adv) => (
        <tr key={adv.id} className="bg-db-bg/60 border-b border-db-border/30">
          {hasCheck && <td className="px-4 py-2" />}
          <td colSpan={hasCheck ? 7 : 5} className="px-4 py-2">
            <div className="flex items-center gap-3 flex-wrap">
              <RiskBadge score={adv.risk_score} />
              <CvssBadge score={adv.cvss_v3} />
              {adv.kev && <KEVBadge ransomware={adv.kev_ransomware} />}
              <Link
                href={`/advisories/detail?id=${adv.id}`}
                className="font-mono text-xs text-status-info hover:text-db-text"
                onClick={(e) => e.stopPropagation()}
              >
                {adv.id}
              </Link>
              <span className="text-xs text-db-text truncate">{adv.title}</span>
              {adv.epss_score != null && adv.epss_score > 0 && (
                <EPSSBar score={adv.epss_score} percentile={adv.epss_percentile || 0} />
              )}
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
