"use client";

import { useState, useCallback, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { PostureReport } from "@/lib/types";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "";

export function usePosture() {
  return useQuery({
    queryKey: ["posture"],
    queryFn: api.getPosture,
  });
}

export function usePostureReports() {
  return useQuery({
    queryKey: ["posture-reports"],
    queryFn: api.getPostureReports,
  });
}

export function usePostureReport(id: string) {
  return useQuery({
    queryKey: ["posture-report", id],
    queryFn: () => api.getPostureReport(id),
    enabled: !!id,
  });
}

export function usePostureFindings(severity?: string) {
  return useQuery({
    queryKey: ["posture-findings", severity],
    queryFn: () => api.getPostureFindings(severity),
  });
}

export function usePostureControls() {
  return useQuery({
    queryKey: ["posture-controls"],
    queryFn: api.getPostureControls,
  });
}

export function usePostureHost(ip: string | null) {
  return useQuery({
    queryKey: ["posture-host", ip],
    queryFn: () => api.getPostureHost(ip!),
    enabled: !!ip,
  });
}

export function useControlStates() {
  return useQuery({
    queryKey: ["control-states"],
    queryFn: api.getControlStates,
  });
}

export function useSetControlState() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      finding_type: string;
      control_id: string;
      status: string;
      notes?: string;
    }) => api.setControlState(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["control-states"] });
      queryClient.invalidateQueries({ queryKey: ["risk-simulation"] });
    },
  });
}

export function useRiskSimulation(subnet?: string) {
  return useQuery({
    queryKey: ["risk-simulation", subnet],
    queryFn: () => api.simulateRisk(subnet),
  });
}

export function usePostureScan() {
  const [status, setStatus] = useState<"idle" | "running" | "complete" | "error">("idle");
  const [progress, setProgress] = useState<string[]>([]);
  const [report, setReport] = useState<PostureReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const start = useCallback(
    async (params: { cidr: string; timeout_ms?: number; concurrency?: number }) => {
      setStatus("running");
      setProgress([]);
      setReport(null);
      setError(null);

      const controller = new AbortController();
      abortRef.current = controller;

      try {
        const res = await fetch(`${BASE_URL}/api/posture/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(params),
          signal: controller.signal,
        });

        if (!res.ok) {
          const body = await res.json().catch(() => ({ error: res.statusText }));
          throw new Error(body.error || res.statusText);
        }

        const reader = res.body?.getReader();
        if (!reader) throw new Error("No response stream");

        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";

          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const data = line.slice(6);
            try {
              const parsed = JSON.parse(data);
              if (parsed.type === "complete" && parsed.report) {
                setReport(parsed.report);
                setStatus("complete");
              } else if (parsed.type === "error") {
                setError(parsed.message);
                setStatus("error");
              } else if (parsed.type === "progress") {
                setProgress((prev) => [...prev, parsed.message]);
              }
            } catch {
              // skip unparseable lines
            }
          }
        }

        // If we haven't set a final status yet
        setStatus((s) => (s === "running" ? "complete" : s));
      } catch (err) {
        if ((err as Error).name !== "AbortError") {
          setStatus("error");
          setError(err instanceof Error ? err.message : "Posture scan failed");
        }
      }
    },
    [],
  );

  const reset = useCallback(() => {
    abortRef.current?.abort();
    setStatus("idle");
    setProgress([]);
    setReport(null);
    setError(null);
  }, []);

  return { status, progress, report, error, start, reset };
}
