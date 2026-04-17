"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function useSentinelSnapshots(siteId?: string) {
  return useQuery({
    queryKey: ["sentinel-snapshots", siteId],
    queryFn: () => api.getSentinelSnapshots(siteId),
  });
}

export function useSentinelSnapshot(id: string | null) {
  return useQuery({
    queryKey: ["sentinel-snapshot", id],
    queryFn: () => api.getSentinelSnapshot(id!),
    enabled: !!id,
  });
}

export function useTrafficSummary(siteId: string | null) {
  return useQuery({
    queryKey: ["traffic-summary", siteId],
    queryFn: () => api.getTrafficSummary(siteId!),
    enabled: !!siteId,
  });
}

export function useScopingRecommendations(policyId: string | null) {
  return useQuery({
    queryKey: ["scoping-recommendations", policyId],
    queryFn: () => api.getScopingRecommendations(policyId!),
    enabled: !!policyId,
  });
}
