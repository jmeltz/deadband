"use client";

import { useState, useCallback, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, sseStream } from "@/lib/api";
import type { DiscoverJob } from "@/lib/types";

export function useDiscover() {
  const [status, setStatus] = useState<"idle" | "running" | "complete" | "error">("idle");
  const [progress, setProgress] = useState<string[]>([]);
  const [result, setResult] = useState<DiscoverJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const cleanupRef = useRef<(() => void) | null>(null);
  const qc = useQueryClient();

  // The backend imports discovered devices into the asset store inside the
  // discover handler (sse.go). After completion, invalidate every cached
  // query that reads from that store so /assets and the Dashboard refresh
  // without a manual reload.
  const invalidateAfterScan = useCallback(() => {
    qc.invalidateQueries({ queryKey: ["assets"] });
    qc.invalidateQueries({ queryKey: ["asset-summary"] });
    qc.invalidateQueries({ queryKey: ["discover-history"] });
  }, [qc]);

  const start = useCallback(
    async (params: {
      cidr: string;
      mode?: string;
      timeout_ms?: number;
      concurrency?: number;
      auto_check?: boolean;
    }) => {
      setStatus("running");
      setProgress([]);
      setResult(null);
      setError(null);

      try {
        const { job_id } = await api.discover(params);

        cleanupRef.current = sseStream(
          `/api/discover/jobs/${job_id}/events`,
          (data) => {
            try {
              const parsed = JSON.parse(data);
              if (parsed.type === "complete") {
                setResult(parsed);
                setStatus(parsed.status === "error" ? "error" : "complete");
                if (parsed.error) setError(parsed.error);
                invalidateAfterScan();
                return;
              }
            } catch {
              // Plain text progress message
            }
            setProgress((prev) => [...prev, data]);
          },
          () => {
            // SSE stream ended — fetch final status
            api.discoverStatus(job_id).then((job) => {
              setResult(job);
              setStatus(job.status === "error" ? "error" : "complete");
              if (job.error) setError(job.error);
              invalidateAfterScan();
            });
          },
        );
      } catch (err) {
        setStatus("error");
        setError(err instanceof Error ? err.message : "Discovery failed");
      }
    },
    [invalidateAfterScan],
  );

  const reset = useCallback(() => {
    cleanupRef.current?.();
    setStatus("idle");
    setProgress([]);
    setResult(null);
    setError(null);
  }, []);

  return { status, progress, result, error, start, reset };
}
