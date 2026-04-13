"use client";

import { cn } from "@/lib/utils/cn";
import { useCallback, useState, useRef } from "react";

interface FileUploadProps {
  onFile: (file: File) => void;
  accept?: string;
  label?: string;
  className?: string;
}

export function FileUpload({
  onFile,
  accept = ".csv,.json,.txt,.flat",
  label = "Drop inventory file here or click to browse",
  className,
}: FileUploadProps) {
  const [dragging, setDragging] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(
    (file: File) => {
      setFileName(file.name);
      onFile(file);
    },
    [onFile],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  return (
    <div
      className={cn(
        "border-2 border-dashed rounded-sm px-6 py-8 text-center transition-colors cursor-pointer",
        dragging
          ? "border-db-teal bg-db-teal-dim/30"
          : "border-db-border hover:border-db-muted bg-db-surface/50",
        className,
      )}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
      onClick={() => inputRef.current?.click()}
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) handleFile(file);
        }}
      />
      {fileName ? (
        <div className="flex items-center justify-center gap-2">
          <svg
            className="w-4 h-4 text-status-ok"
            viewBox="0 0 16 16"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <path d="M3 8l3 3 7-7" />
          </svg>
          <span className="text-sm font-mono text-db-text">{fileName}</span>
        </div>
      ) : (
        <p className="text-sm text-db-muted">{label}</p>
      )}
    </div>
  );
}
