import { cn } from "@/lib/utils/cn";
import { cvssToSeverity, severityBgColor } from "@/lib/utils/cvss";

export function CvssBadge({ score }: { score: number }) {
  const severity = cvssToSeverity(score);
  return (
    <span
      className={cn(
        "inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono font-semibold",
        severityBgColor(severity),
      )}
    >
      {score.toFixed(1)}
    </span>
  );
}
