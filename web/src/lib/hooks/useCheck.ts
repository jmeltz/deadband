"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Device, CheckResponse } from "@/lib/types";

export function useCheck() {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: (params: {
      devices: Device[];
      min_confidence?: string;
      min_cvss?: number;
      vendor?: string;
    }) => api.check(params),
    onSuccess: (data: CheckResponse) => {
      qc.setQueryData(["check-results"], data);
    },
  });
}

export function useCheckUpload() {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: (params: {
      file: File;
      format?: string;
      min_confidence?: string;
      min_cvss?: number;
      vendor?: string;
    }) => {
      const { file, ...opts } = params;
      return api.checkUpload(file, opts);
    },
    onSuccess: (data: CheckResponse) => {
      qc.setQueryData(["check-results"], data);
    },
  });
}
