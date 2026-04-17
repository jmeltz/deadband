"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function useSites() {
  return useQuery({
    queryKey: ["sites"],
    queryFn: api.getSites,
    staleTime: 30_000,
  });
}

export function useUpsertSite() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: {
      id?: string;
      name: string;
      cidrs: string[];
      description?: string;
      location?: string;
      contact?: string;
      created_at?: string;
      updated_at?: string;
    }) => api.upsertSite(params),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sites"] });
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
  });
}

export function useDeleteSite() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteSite(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sites"] });
    },
  });
}

export function useReassignSites() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.reassignSites(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["asset-summary"] });
    },
  });
}

export function useZones(siteId: string) {
  return useQuery({
    queryKey: ["zones", siteId],
    queryFn: () => api.getZones(siteId),
    enabled: !!siteId,
    staleTime: 30_000,
  });
}

export function useUpsertZone() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: { siteId: string; zone: Partial<import("@/lib/types").Zone> }) =>
      api.upsertZone(params.siteId, params.zone),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["zones", vars.siteId] });
      qc.invalidateQueries({ queryKey: ["sites"] });
    },
  });
}

export function useDeleteZone() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: { siteId: string; zoneId: string }) =>
      api.deleteZone(params.siteId, params.zoneId),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["zones", vars.siteId] });
      qc.invalidateQueries({ queryKey: ["sites"] });
    },
  });
}

export function useImportDBD() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (file: File) => api.importDBD(file),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["sites"] });
      qc.invalidateQueries({ queryKey: ["asset-summary"] });
      qc.invalidateQueries({ queryKey: ["posture"] });
      qc.invalidateQueries({ queryKey: ["posture-reports"] });
    },
  });
}
