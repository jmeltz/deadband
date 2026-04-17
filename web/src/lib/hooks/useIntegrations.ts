"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

// --- Sentinel configs ---

export function useSentinelConfigs() {
  return useQuery({
    queryKey: ["sentinel-configs"],
    queryFn: api.getSentinelConfigs,
  });
}

export function useUpsertSentinelConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.upsertSentinelConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sentinel-configs"] });
    },
  });
}

export function useDeleteSentinelConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.deleteSentinelConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sentinel-configs"] });
    },
  });
}

export function useTestSentinelConfig() {
  return useMutation({
    mutationFn: api.testSentinelConfig,
  });
}

// --- ASA configs ---

export function useASAConfigs() {
  return useQuery({
    queryKey: ["asa-configs"],
    queryFn: api.getASAConfigs,
  });
}

export function useUpsertASAConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.upsertASAConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["asa-configs"] });
    },
  });
}

export function useDeleteASAConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.deleteASAConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["asa-configs"] });
    },
  });
}

export function useTestASAConfig() {
  return useMutation({
    mutationFn: api.testASAConfig,
  });
}
