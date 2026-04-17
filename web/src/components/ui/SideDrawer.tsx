"use client";

import { useEffect } from "react";

interface SideDrawerProps {
  open: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  children: React.ReactNode;
  width?: number;
}

export function SideDrawer({
  open,
  onClose,
  title,
  children,
  width = 520,
}: SideDrawerProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="absolute inset-0 bg-black/50" />
      <div
        className="relative max-w-full h-full bg-db-bg border-l border-db-border overflow-y-auto"
        style={{ width }}
      >
        <div className="sticky top-0 bg-db-bg border-b border-db-border px-4 py-3 flex items-center justify-between z-10">
          <div className="min-w-0 flex-1">{title}</div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="text-db-muted hover:text-db-text text-lg leading-none ml-2"
          >
            &times;
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
