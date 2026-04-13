"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function useEnrichmentStats() {
  return useQuery({
    queryKey: ["enrichment-stats"],
    queryFn: () => api.enrichmentStats(),
    staleTime: 5 * 60_000,
  });
}
