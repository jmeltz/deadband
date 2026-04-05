"use client";

import { useState, useRef, useEffect } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { StatusBadge } from "@/components/ui/Badge";
import { useDiscover } from "@/lib/hooks/useDiscover";

export default function DiscoverPage() {
  const [cidr, setCidr] = useState("");
  const [mode, setMode] = useState("auto");
  const [autoCheck, setAutoCheck] = useState(true);
  const { status, progress, result, error, start, reset } = useDiscover();
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [progress]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!cidr.trim()) return;
    start({ cidr: cidr.trim(), mode, auto_check: autoCheck });
  };

  return (
    <div className="max-w-4xl space-y-4">
      {/* Discovery form */}
      <Card>
        <h3 className="font-heading text-sm font-semibold mb-3">Network Discovery</h3>
        <form onSubmit={handleSubmit} className="flex items-end gap-3">
          <div className="flex-1">
            <label className="block text-xs text-db-muted mb-1.5">CIDR Range</label>
            <input
              type="text"
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
              placeholder="e.g. 10.0.1.0/24"
              className="w-full bg-db-bg border border-db-border rounded-md px-3 py-2 text-sm font-mono text-db-text placeholder:text-db-muted focus:outline-none focus:border-db-teal"
              disabled={status === "running"}
            />
          </div>
          <div>
            <label className="block text-xs text-db-muted mb-1.5">Mode</label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value)}
              disabled={status === "running"}
              className="bg-db-bg border border-db-border rounded-md px-3 py-2 text-sm text-db-text focus:outline-none focus:border-db-teal"
            >
              <option value="auto">Auto (all protocols)</option>
              <option value="cip">CIP (Rockwell)</option>
              <option value="s7">S7 (Siemens)</option>
              <option value="modbus">Modbus TCP (SE/ABB/+)</option>
              <option value="melsec">MELSEC (Mitsubishi)</option>
              <option value="bacnet">BACnet/IP (Trane/Honeywell)</option>
              <option value="fins">FINS (Omron)</option>
              <option value="srtp">GE-SRTP (Emerson/GE)</option>
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
          {status === "idle" || status === "complete" || status === "error" ? (
            <Button type="submit" disabled={!cidr.trim()}>
              Discover
            </Button>
          ) : (
            <Button variant="secondary" disabled>
              Scanning...
            </Button>
          )}
          {(status === "complete" || status === "error") && (
            <Button variant="ghost" size="sm" onClick={reset}>
              Reset
            </Button>
          )}
        </form>
      </Card>

      {/* Progress log */}
      {(status === "running" || progress.length > 0) && (
        <Card className="p-0">
          <div
            ref={logRef}
            className="h-48 overflow-auto p-4 font-mono text-xs leading-relaxed bg-db-bg rounded-lg"
          >
            {progress.map((msg, i) => (
              <div key={i} className="text-status-ok/80">
                <span className="text-db-muted select-none">$ </span>
                {msg}
              </div>
            ))}
            {status === "running" && (
              <div className="text-db-muted animate-pulse">Scanning...</div>
            )}
          </div>
        </Card>
      )}

      {/* Error */}
      {error && (
        <Card className="border-status-critical/30">
          <p className="text-sm text-status-critical">{error}</p>
        </Card>
      )}

      {/* Discovery results */}
      {status === "complete" && result?.devices && result.devices.length > 0 && (
        <Card className="p-0 overflow-hidden">
          <div className="px-4 py-3 border-b border-db-border">
            <h3 className="font-heading text-sm font-semibold">
              Discovered {result.devices.length} device{result.devices.length !== 1 ? "s" : ""}
            </h3>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-db-border text-left">
                <th className="px-4 py-2.5 text-xs font-medium text-db-muted">IP</th>
                <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Vendor</th>
                <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Model</th>
                <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Firmware</th>
                {result.check_results && (
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Status</th>
                )}
              </tr>
            </thead>
            <tbody>
              {result.devices.map((d, i) => {
                const checkResult = result.check_results?.results?.find(
                  (r) => r.ip === d.ip && r.model === d.model,
                );
                return (
                  <tr
                    key={`${d.ip}-${i}`}
                    className={`border-b border-db-border/50 ${i % 2 !== 0 ? "bg-db-bg/30" : ""}`}
                  >
                    <td className="px-4 py-2 font-mono text-xs">{d.ip}</td>
                    <td className="px-4 py-2 text-xs text-db-muted">{d.vendor}</td>
                    <td className="px-4 py-2 font-mono text-xs">{d.model}</td>
                    <td className="px-4 py-2 font-mono text-xs">{d.firmware}</td>
                    {result.check_results && (
                      <td className="px-4 py-2">
                        {checkResult ? (
                          <StatusBadge status={checkResult.status} />
                        ) : (
                          <span className="text-[10px] text-db-muted">OK</span>
                        )}
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      )}

      {status === "complete" && (!result?.devices || result.devices.length === 0) && (
        <EmptyState
          title="No devices found"
          description="No devices responded on the specified network range."
        />
      )}
    </div>
  );
}
