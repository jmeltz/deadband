export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

export function cvssToSeverity(score: number): Severity {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
}

export function severityColor(severity: Severity): string {
  switch (severity) {
    case "CRITICAL":
      return "text-status-critical";
    case "HIGH":
      return "text-status-high";
    case "MEDIUM":
      return "text-status-medium";
    case "LOW":
      return "text-status-low";
    default:
      return "text-db-muted";
  }
}

export function severityBgColor(severity: Severity): string {
  switch (severity) {
    case "CRITICAL":
      return "bg-status-critical/15 text-status-critical";
    case "HIGH":
      return "bg-status-high/15 text-status-high";
    case "MEDIUM":
      return "bg-status-medium/15 text-status-medium";
    case "LOW":
      return "bg-status-low/15 text-status-low";
    default:
      return "bg-db-border text-db-muted";
  }
}
