"use client";

import { useState, useEffect, useRef } from "react";
import { useDbStats } from "@/lib/hooks/useDbStats";
import { Card, StatCard } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { formatDate, relativeTime } from "@/lib/utils/format";
import { api, sseStream } from "@/lib/api";
import { useQueryClient } from "@tanstack/react-query";

export function DatabaseTab() {
  const { data: stats, isLoading } = useDbStats();
  const [updating, setUpdating] = useState(false);
  const [progress, setProgress] = useState<string[]>([]);
  const logRef = useRef<HTMLDivElement>(null);
  const qc = useQueryClient();

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [progress]);

  const startUpdate = async () => {
    setUpdating(true);
    setProgress([]);

    try {
      await api.update({});

      const cleanup = sseStream(
        "/api/update/events",
        (data) => {
          try {
            const parsed = JSON.parse(data);
            if (parsed.type === "complete") {
              setUpdating(false);
              qc.invalidateQueries({ queryKey: ["db-stats"] });
              qc.invalidateQueries({ queryKey: ["advisories"] });
              cleanup();
              return;
            }
          } catch {
            // Plain text message
          }
          setProgress((prev) => [...prev, data]);
        },
        () => {
          setUpdating(false);
          qc.invalidateQueries({ queryKey: ["db-stats"] });
        },
      );
    } catch (err) {
      setProgress((prev) => [
        ...prev,
        `Error: ${err instanceof Error ? err.message : "Update failed"}`,
      ]);
      setUpdating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* DB status */}
      <div className="grid grid-cols-2 gap-4">
        <StatCard
          label="Advisories"
          value={isLoading ? "—" : stats?.advisory_count ?? 0}
          sub={stats?.source}
        />
        <StatCard
          label="Last Updated"
          value={stats ? relativeTime(stats.updated) : "—"}
          sub={stats ? formatDate(stats.updated) : undefined}
        />
      </div>

      {/* Update */}
      <Card>
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="font-heading text-sm font-semibold">Advisory Database</h3>
            <p className="text-xs text-db-muted mt-0.5">
              Fetches the deadband-hosted snapshot when available, falls back
              to per-file CISA CSAF.
            </p>
          </div>
          <Button onClick={startUpdate} disabled={updating} size="sm">
            {updating ? "Updating..." : "Update Now"}
          </Button>
        </div>

        {progress.length > 0 && (
          <div
            ref={logRef}
            className="h-40 overflow-auto p-3 font-mono text-xs leading-relaxed bg-db-bg rounded-sm mt-3 code-scanline"
          >
            {progress.map((msg, i) => (
              <div key={i} className={msg.startsWith("Error") ? "text-status-critical" : "text-status-ok/80"}>
                <span className="text-db-muted select-none">$ </span>
                {msg}
              </div>
            ))}
            {updating && (
              <div className="text-db-muted animate-pulse">Updating...</div>
            )}
          </div>
        )}
      </Card>

      {/* About */}
      <Card>
        <h3 className="font-heading text-sm font-semibold mb-2">About</h3>
        <div className="space-y-1 text-xs text-db-muted">
          <p>
            <span className="text-db-text font-medium">deadband v0.5</span> — OT asset inventory & vulnerability scanner
          </p>
          <p>Read-only tool — no configuration changes or write operations on OT devices</p>
        </div>
      </Card>
    </div>
  );
}
