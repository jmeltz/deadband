"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function useASASnapshots(siteId?: string) {
  return useQuery({
    queryKey: ["asa-snapshots", siteId],
    queryFn: () => api.getASASnapshots(siteId),
  });
}

export function useASASnapshot(id: string | null) {
  return useQuery({
    queryKey: ["asa-snapshot", id],
    queryFn: () => api.getASASnapshot(id!),
    enabled: !!id,
  });
}

export function useDriftAnalysis(policyId: string | null) {
  return useQuery({
    queryKey: ["asa-drift", policyId],
    queryFn: () => api.analyzeDrift(policyId!),
    enabled: !!policyId,
  });
}
