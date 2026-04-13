import { cn } from "@/lib/utils/cn";

interface CardProps {
  children: React.ReactNode;
  className?: string;
}

export function Card({ children, className }: CardProps) {
  return (
    <div
      className={cn(
        "rounded-sm border border-db-border bg-db-surface p-4 card-hover card-accent card-shine",
        className,
      )}
    >
      {children}
    </div>
  );
}

interface StatCardProps {
  label: string;
  value: string | number;
  sub?: string;
  className?: string;
}

export function StatCard({ label, value, sub, className }: StatCardProps) {
  return (
    <Card className={cn("flex flex-col gap-1", className)}>
      <span className="text-xs text-db-muted font-medium uppercase tracking-wider">
        {label}
      </span>
      <span className="text-2xl font-heading font-semibold text-db-text">
        {value}
      </span>
      {sub && (
        <span className="text-xs text-db-muted font-mono">{sub}</span>
      )}
    </Card>
  );
}
