import { cn } from "@/lib/utils/cn";

function riskLabel(score: number): string {
  if (score >= 90) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 30) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
}

function riskColor(score: number): string {
  if (score >= 90) return "bg-status-critical/15 text-status-critical border-status-critical/30";
  if (score >= 60) return "bg-status-high/15 text-status-high border-status-high/30";
  if (score >= 30) return "bg-status-medium/15 text-status-medium border-status-medium/30";
  if (score > 0) return "bg-status-low/15 text-status-low border-status-low/30";
  return "bg-db-border/50 text-db-muted border-db-border";
}

export function RiskBadge({ score }: { score: number }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0.5 rounded-sm text-[10px] font-mono font-semibold tracking-wide border",
        riskColor(score),
      )}
    >
      {riskLabel(score)}
    </span>
  );
}

export function KEVBadge({ ransomware }: { ransomware?: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0.5 rounded-sm text-[10px] font-mono font-semibold tracking-wide border",
        ransomware
          ? "bg-status-critical/15 text-status-critical border-status-critical/30"
          : "bg-status-high/15 text-status-high border-status-high/30",
      )}
    >
      <svg viewBox="0 0 16 16" className="w-3 h-3 fill-current" aria-hidden>
        <path d="M8 0L1 4v4c0 4.4 3 8.5 7 9.6 4-1.1 7-5.2 7-9.6V4L8 0zm0 2.2l5 2.8v3c0 3.5-2.3 6.7-5 7.8-2.7-1.1-5-4.3-5-7.8V5l5-2.8z" />
      </svg>
      KEV{ransomware ? " + Ransomware" : ""}
    </span>
  );
}

export function EPSSBar({ score, percentile }: { score: number; percentile: number }) {
  const pct = Math.round(score * 100);
  const barColor =
    score >= 0.5 ? "bg-status-critical" :
    score >= 0.1 ? "bg-status-high" :
    score >= 0.01 ? "bg-status-medium" :
    "bg-status-low";

  return (
    <div className="inline-flex items-center gap-2 min-w-[120px]">
      <div className="flex-1 h-1.5 bg-db-bg rounded-full overflow-hidden">
        <div
          className={cn("h-full rounded-full transition-all", barColor)}
          style={{ width: `${Math.max(score * 100, 2)}%` }}
        />
      </div>
      <span className="text-[10px] font-mono text-db-muted whitespace-nowrap">
        {pct}% <span className="opacity-60">({Math.round(percentile * 100)}th)</span>
      </span>
    </div>
  );
}
