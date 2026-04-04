export function CveBadge({ cve }: { cve: string }) {
  return (
    <a
      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-mono bg-db-surface border border-db-border text-status-info hover:text-db-text hover:border-db-muted transition-colors"
    >
      {cve}
    </a>
  );
}
