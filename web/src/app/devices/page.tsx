"use client";

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { FileUpload } from "@/components/ui/FileUpload";
import { StatusBadge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { useCheckUpload } from "@/lib/hooks/useCheck";
import type { Device, CheckResponse } from "@/lib/types";
import { useRouter } from "next/navigation";

export default function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const checkUpload = useCheckUpload();
  const qc = useQueryClient();
  const router = useRouter();
  const checkResults = qc.getQueryData<CheckResponse>(["check-results"]);

  // Build a lookup from check results
  const statusMap = new Map<string, { status: string; confidence: string }>();
  if (checkResults) {
    for (const r of checkResults.results) {
      statusMap.set(`${r.ip}:${r.model}`, { status: r.status, confidence: r.confidence });
    }
  }

  const handleFile = (f: File) => {
    setFile(f);
    // Parse the file client-side to show in table (we'll also upload it on check)
    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result as string;
      try {
        const parsed = JSON.parse(text);
        if (Array.isArray(parsed)) {
          // Try generic JSON
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
      // Parse CSV simply
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
  };

  const runCheck = () => {
    if (!file) return;
    checkUpload.mutate(
      { file },
      {
        onSuccess: () => router.push("/check"),
      },
    );
  };

  return (
    <div className="max-w-6xl space-y-4">
      <FileUpload onFile={handleFile} />

      {devices.length > 0 && (
        <>
          <div className="flex items-center justify-between">
            <span className="text-xs text-db-muted">
              {devices.length} device{devices.length !== 1 ? "s" : ""} loaded
            </span>
            <Button
              onClick={runCheck}
              disabled={checkUpload.isPending}
              size="sm"
            >
              {checkUpload.isPending ? "Checking..." : "Run Vulnerability Check"}
            </Button>
          </div>

          <Card className="p-0 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-db-border text-left">
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">IP Address</th>
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Vendor</th>
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Model</th>
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Firmware</th>
                  <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Status</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d, i) => {
                  const result = statusMap.get(`${d.ip}:${d.model}`);
                  return (
                    <tr
                      key={`${d.ip}-${d.model}-${i}`}
                      className={`border-b border-db-border/50 ${i % 2 === 0 ? "" : "bg-db-bg/30"}`}
                    >
                      <td className="px-4 py-2 font-mono text-xs">{d.ip}</td>
                      <td className="px-4 py-2 text-xs text-db-muted">{d.vendor}</td>
                      <td className="px-4 py-2 font-mono text-xs">{d.model}</td>
                      <td className="px-4 py-2 font-mono text-xs">{d.firmware}</td>
                      <td className="px-4 py-2">
                        {result ? (
                          <StatusBadge status={result.status} />
                        ) : (
                          <span className="text-[10px] text-db-muted">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </Card>
        </>
      )}

      {devices.length === 0 && !file && (
        <EmptyState
          title="No devices loaded"
          description="Upload a device inventory file (CSV, JSON, or flat text) to get started."
        />
      )}
    </div>
  );
}
