"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function usePolicies() {
  return useQuery({
    queryKey: ["acl-policies"],
    queryFn: api.getPolicies,
  });
}

export function useUpsertPolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.upsertPolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["acl-policies"] });
    },
  });
}

export function useDeletePolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.deletePolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["acl-policies"] });
    },
  });
}

export function useGeneratePolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.generateDefaultPolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["acl-policies"] });
    },
  });
}

export function useGapAnalysis(policyId: string | null, opts?: { includeFlows?: boolean; includeAsa?: boolean }) {
  return useQuery({
    queryKey: ["acl-gaps", policyId, opts],
    queryFn: () => api.analyzeGaps(policyId!, opts),
    enabled: !!policyId,
  });
}

export function useSimulatePolicy() {
  return useMutation({
    mutationFn: api.simulatePolicy,
  });
}
