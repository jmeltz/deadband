"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function useAssets(params?: {
  vendor?: string;
  site?: string;
  zone?: string;
  criticality?: string;
  tag?: string;
  q?: string;
  sort?: string;
  status?: string;
  vuln_status?: string;
  cve?: string;
}) {
  return useQuery({
    queryKey: ["assets", params],
    queryFn: () => api.assets(params),
    staleTime: 30_000,
  });
}

export function useImportAssets() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: {
      devices: import("@/lib/types").Device[];
      source?: string;
    }) => api.importAssets(params),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
  });
}

export function useUpdateAsset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: {
      id: string;
      patch: Partial<import("@/lib/types").Asset>;
    }) => api.updateAsset(params.id, params.patch),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
  });
}

export function useDeleteAsset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteAsset(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
  });
}

export function useCheckAssets() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: {
      ids?: string[];
      site?: string;
      zone?: string;
      criticality?: string;
    }) => api.checkAssets(params),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
  });
}

export function useBulkUpdateAssets() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: {
      ids: string[];
      add_tags?: string[];
      remove_tags?: string[];
      set_site?: string;
      set_zone?: string;
      set_criticality?: string;
    }) => api.bulkUpdateAssets(params),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
  });
}
