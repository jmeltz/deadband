import { cn } from "@/lib/utils/cn";
import type { Status, Confidence } from "@/lib/types";

export function StatusBadge({ status }: { status: Status | string }) {
  const s = status.toUpperCase();
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-semibold font-mono tracking-wide",
        s === "VULNERABLE" && "bg-status-critical/15 text-status-critical border border-status-critical/30 badge-glow-critical",
        s === "POTENTIAL" && "bg-status-medium/15 text-status-medium border border-status-medium/30",
        s === "OK" && "bg-status-ok/15 text-status-ok border border-status-ok/30",
      )}
    >
      {s}
    </span>
  );
}

export function ConfidenceBadge({ confidence }: { confidence: Confidence | string }) {
  const c = confidence.toUpperCase();
  return (
    <span
      className={cn(
        "inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-mono tracking-wider",
        c === "HIGH" && "bg-status-critical/10 text-status-critical border border-status-critical/30",
        c === "MEDIUM" && "bg-status-medium/10 text-status-medium border border-status-medium/30",
        c === "LOW" && "bg-db-border text-db-muted border border-db-border",
      )}
    >
      {c}
    </span>
  );
}
