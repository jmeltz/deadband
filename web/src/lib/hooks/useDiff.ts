"use client";

import { useMutation } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function useDiff() {
  return useMutation({
    mutationFn: api.diff,
  });
}

export function useDiffUpload() {
  return useMutation({
    mutationFn: ({ baseFile, compareFile }: { baseFile: File; compareFile: File }) =>
      api.diffUpload(baseFile, compareFile),
  });
}
