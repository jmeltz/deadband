"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function useAssetSummary() {
  return useQuery({
    queryKey: ["asset-summary"],
    queryFn: api.assetSummary,
    staleTime: 30_000,
  });
}
