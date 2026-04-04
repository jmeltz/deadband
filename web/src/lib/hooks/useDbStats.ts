"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function useDbStats() {
  return useQuery({
    queryKey: ["db-stats"],
    queryFn: api.dbStats,
    staleTime: 60_000,
  });
}
