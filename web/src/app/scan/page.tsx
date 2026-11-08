"use client";

import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { useDiscover } from "@/lib/hooks/useDiscover";

const MODES = [
  { value: "auto", label: "Auto (all protocols)" },
  { value: "cip", label: "CIP / EtherNet/IP (UDP/TCP 44818)" },
  { value: "s7", label: "Siemens S7 + TIA Portal/SNMP (TCP/102)" },
  { value: "modbus", label: "Modbus TCP (TCP/502)" },
  { value: "bacnet", label: "BACnet/IP + Routed MS/TP (UDP/47808)" },
  { value: "opcua", label: "OPC UA (TCP/4840)" },
  { value: "ads", label: "Beckhoff TwinCAT ADS (UDP/48899, TCP/48898)" },
  { value: "sick", label: "SICK SOPAS CoLa-A/B/2 (TCP/2111, 2112, 2122)" },
  { value: "fox", label: "Tridium Niagara Fox/FoxS (TCP/1911, 4911)" },
  { value: "ancillary", label: "Ancillary WCS / BMS / Cold-Chain (HTTP/TLS)" },
  { value: "melsec", label: "Mitsubishi MELSEC (TCP/5007)" },
  { value: "fins", label: "Omron FINS (UDP/9600)" },
  { value: "srtp", label: "Emerson / GE SRTP (TCP/18245)" },
  { value: "haas", label: "Haas CNC (TCP/5051)" },
  { value: "fanuc", label: "Fanuc CNC / Robot (FTP/FOCAS)" },
  { value: "mazak", label: "Mazak Smooth CNC (MTConnect)" },
  { value: "http", label: "Legacy HTTP Banner" },
];

export default function ScanPage() {
  const [cidr, setCidr] = useState("");
  const [mode, setMode] = useState("auto");
  const [autoCheck, setAutoCheck] = useState(true);
  const [includePosture, setIncludePosture] = useState(false);
  const { status, progress, result, error, start, reset } = useDiscover();

  const running = status === "running";

  const handleStart = () => {
    if (!cidr.trim()) return;
    start({ cidr: cidr.trim(), mode, auto_check: autoCheck, include_posture: includePosture });
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <Card>
        <div>
          <h3 className="font-heading text-sm font-semibold">Discovery Scan</h3>
          <p className="text-xs text-db-muted mt-0.5">
            Read-only protocol probes against a CIDR range across PLC, ASRS /
            intralogistics (KNAPP, Beckhoff ADS, SICK SOPAS), HVAC / cold-chain
            (BACnet/IP + routed MS/TP, Niagara Fox, BMS/refrigeration portals),
            and CNC protocols. Zero write operations are performed on any target.
          </p>
        </div>

        <div className="mt-4 grid gap-3">
          <div className="flex flex-col">
            <label className="text-[10px] text-db-muted uppercase tracking-wider mb-1">
              CIDR range
            </label>
            <input
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
              placeholder="10.0.1.0/24"
              disabled={running}
              className="bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text font-mono focus:outline-none w-full max-w-md"
            />
          </div>

          <div className="flex flex-col">
            <label className="text-[10px] text-db-muted uppercase tracking-wider mb-1">
              Mode
            </label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value)}
              disabled={running}
              className="bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none w-full max-w-md"
            >
              {MODES.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </select>
          </div>

          <label className="flex items-center gap-2 text-xs text-db-text">
            <input
              type="checkbox"
              checked={autoCheck}
              onChange={(e) => setAutoCheck(e.target.checked)}
              disabled={running}
            />
            Auto-check discovered devices against advisory DB
          </label>

          <label className="flex items-center gap-2 text-xs text-db-text">
            <input type="checkbox" checked={includePosture} onChange={e => setIncludePosture(e.target.checked)} disabled={running} />
            Include subnet posture scan (additional OT and IT service probes)
          </label>
          <p className="text-xs text-db-muted">To query known assets for missing details or current firmware, use Asset enrichment on the Assets page.</p>

          <div className="flex items-center gap-2 mt-2">
            <Button
              size="sm"
              onClick={handleStart}
              disabled={running || !cidr.trim()}
            >
              {running ? "Scanning..." : "Start Scan"}
            </Button>
            {(status === "complete" || status === "error") && (
              <Button size="sm" onClick={reset}>
                Reset
              </Button>
            )}
            {error && (
              <span className="text-[11px] text-status-critical font-mono">
                {error}
              </span>
            )}
          </div>
        </div>
      </Card>

      {(running || progress.length > 0) && (
        <Card>
          <h4 className="text-[10px] text-db-muted uppercase tracking-wider mb-2">
            Progress
          </h4>
          <pre className="text-[11px] font-mono text-db-text bg-db-bg border border-db-border p-3 max-h-72 overflow-y-auto whitespace-pre-wrap">
            {progress.join("\n") || "Starting…"}
          </pre>
        </Card>
      )}

      {result && status === "complete" && (
        <Card>
          <div className="flex items-center justify-between">
            <h4 className="font-heading text-sm font-semibold">Results</h4>
            <span className="text-[10px] font-mono text-db-muted">
              {result.devices?.length ?? 0} device{(result.devices?.length ?? 0) === 1 ? "" : "s"}
            </span>
          </div>
          {(result.devices?.length ?? 0) === 0 ? (
            <p className="text-xs text-db-muted mt-2">
              No devices found in this CIDR for the selected mode.
            </p>
          ) : (
            <div className="mt-3 border border-db-border overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-db-muted bg-db-bg">
                    <th className="py-1.5 px-2 font-medium">IP</th>
                    <th className="py-1.5 px-2 font-medium">Vendor</th>
                    <th className="py-1.5 px-2 font-medium">Model</th>
                    <th className="py-1.5 px-2 font-medium">Firmware</th>
                  </tr>
                </thead>
                <tbody>
                  {result.devices?.map((d, i) => (
                    <tr key={i} className="border-t border-db-border/50">
                      <td className="py-1.5 px-2 font-mono text-db-text">{d.ip}</td>
                      <td className="py-1.5 px-2 text-db-text">{d.vendor}</td>
                      <td className="py-1.5 px-2 font-mono text-db-text">{d.model}</td>
                      <td className="py-1.5 px-2 font-mono text-db-muted">{d.firmware || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
