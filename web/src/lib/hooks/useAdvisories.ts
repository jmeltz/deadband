"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function useAdvisories(params?: {
  page?: number;
  per_page?: number;
  vendor?: string;
  min_cvss?: number;
  q?: string;
  sort?: string;
}) {
  return useQuery({
    queryKey: ["advisories", params],
    queryFn: () => api.advisories(params),
    staleTime: 5 * 60_000,
  });
}

export function useAdvisory(id: string) {
  return useQuery({
    queryKey: ["advisory", id],
    queryFn: () => api.advisory(id),
    staleTime: 5 * 60_000,
    enabled: !!id,
  });
}
