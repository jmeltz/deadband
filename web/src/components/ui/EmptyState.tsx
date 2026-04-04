interface EmptyStateProps {
  title: string;
  description?: string;
  children?: React.ReactNode;
}

export function EmptyState({ title, description, children }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-12 h-12 rounded-full bg-db-surface border border-db-border flex items-center justify-center mb-4">
        <svg
          className="w-5 h-5 text-db-muted"
          viewBox="0 0 16 16"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
        >
          <rect x="2" y="2" width="12" height="12" rx="2" />
          <path d="M6 8h4M8 6v4" />
        </svg>
      </div>
      <h3 className="text-sm font-medium text-db-text mb-1">{title}</h3>
      {description && (
        <p className="text-xs text-db-muted max-w-sm">{description}</p>
      )}
      {children && <div className="mt-4">{children}</div>}
    </div>
  );
}
