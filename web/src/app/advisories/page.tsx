"use client";

import { useState, useRef, useEffect, Suspense } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useSearchParams, useRouter, usePathname } from "next/navigation";
import { useAdvisories } from "@/lib/hooks/useAdvisories";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { CvssBadge } from "@/components/advisory/CvssBadge";
import { EmptyState } from "@/components/ui/EmptyState";
import { api, sseStream } from "@/lib/api";
import { AdvisoryDetailDrawer } from "./_components/AdvisoryDetailDrawer";

type SortField = "published" | "cvss" | "id" | "vendor";
type SortDir = "asc" | "desc";

const defaultSortDir: Record<SortField, SortDir> = {
  published: "desc",
  cvss: "desc",
  id: "desc",
  vendor: "asc",
};

function AdvisoriesContent() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const selectedAdvisory = searchParams.get("advisory");

  const openAdvisory = (id: string) => {
    const params = new URLSearchParams(searchParams.toString());
    params.set("advisory", id);
    router.replace(`${pathname}?${params.toString()}`, { scroll: false });
  };

  const closeAdvisory = () => {
    const params = new URLSearchParams(searchParams.toString());
    params.delete("advisory");
    const qs = params.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  };

  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [vendor, setVendor] = useState("");
  const [minCvss, setMinCvss] = useState<number | "">("");
  const [sortField, setSortField] = useState<SortField>("published");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const perPage = 25;

  // Update state
  const [updating, setUpdating] = useState(false);
  const [updateProgress, setUpdateProgress] = useState<string[]>([]);
  const logRef = useRef<HTMLDivElement>(null);
  const qc = useQueryClient();

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [updateProgress]);

  const startUpdate = async () => {
    setUpdating(true);
    setUpdateProgress([]);
    try {
      await api.update({});
      const cleanup = sseStream(
        "/api/update/events",
        (data) => {
          try {
            const parsed = JSON.parse(data);
            if (parsed.type === "complete") {
              setUpdating(false);
              qc.invalidateQueries({ queryKey: ["db-stats"] });
              qc.invalidateQueries({ queryKey: ["advisories"] });
              cleanup();
              return;
            }
          } catch {
            // Plain text message
          }
          setUpdateProgress((prev) => [...prev, data]);
        },
        () => {
          setUpdating(false);
          qc.invalidateQueries({ queryKey: ["db-stats"] });
          qc.invalidateQueries({ queryKey: ["advisories"] });
        },
      );
    } catch (err) {
      setUpdateProgress((prev) => [
        ...prev,
        `Error: ${err instanceof Error ? err.message : "Update failed"}`,
      ]);
      setUpdating(false);
    }
  };

  const { data, isLoading } = useAdvisories({
    page,
    per_page: perPage,
    q: search || undefined,
    vendor: vendor || undefined,
    min_cvss: minCvss !== "" ? minCvss : undefined,
    sort: `${sortField}:${sortDir}`,
  });

  const totalPages = data ? Math.ceil(data.total / perPage) : 0;

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDir(defaultSortDir[field]);
    }
    setPage(1);
  };

  const activeFilterCount =
    (search ? 1 : 0) + (vendor ? 1 : 0) + (minCvss !== "" ? 1 : 0);

  const clearFilters = () => {
    setSearch("");
    setVendor("");
    setMinCvss("");
    setPage(1);
  };

  return (
    <div className="max-w-6xl space-y-4">
      {/* Update progress */}
      {updateProgress.length > 0 && (
        <Card className="p-0">
          <div
            ref={logRef}
            className="h-32 overflow-auto p-4 font-mono text-xs leading-relaxed bg-db-bg rounded-sm code-scanline"
          >
            {updateProgress.map((msg, i) => (
              <div key={i} className={msg.startsWith("Error") ? "text-status-critical" : "text-status-ok/80"}>
                <span className="text-db-muted select-none">$ </span>
                {msg}
              </div>
            ))}
            {updating && (
              <div className="text-db-muted animate-pulse">Updating...</div>
            )}
          </div>
        </Card>
      )}

      {/* Filter bar */}
      <div className="flex items-end gap-3">
        <div className="flex-1">
          <label className="block text-xs text-db-muted mb-1">Search</label>
          <input
            type="text"
            placeholder="Advisory ID, title, CVE..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            className="w-full bg-db-surface border border-db-border px-3 py-2 text-sm text-db-text placeholder:text-db-muted focus:outline-none input-industrial"
          />
        </div>
        <div className="w-44">
          <label className="block text-xs text-db-muted mb-1">Vendor</label>
          <input
            type="text"
            placeholder="Filter vendor..."
            value={vendor}
            onChange={(e) => {
              setVendor(e.target.value);
              setPage(1);
            }}
            className="w-full bg-db-surface border border-db-border px-3 py-2 text-sm text-db-text placeholder:text-db-muted focus:outline-none input-industrial"
          />
        </div>
        <div className="w-28">
          <label className="block text-xs text-db-muted mb-1">Min CVSS</label>
          <input
            type="number"
            min={0}
            max={10}
            step={0.1}
            placeholder="0.0"
            value={minCvss}
            onChange={(e) => {
              setMinCvss(e.target.value ? parseFloat(e.target.value) : "");
              setPage(1);
            }}
            className="w-full bg-db-surface border border-db-border px-3 py-2 text-sm font-mono text-db-text placeholder:text-db-muted focus:outline-none input-industrial"
          />
        </div>
        {activeFilterCount > 0 && (
          <Button variant="ghost" size="sm" onClick={clearFilters}>
            Clear ({activeFilterCount})
          </Button>
        )}
        <Button
          variant="secondary"
          size="sm"
          onClick={startUpdate}
          disabled={updating}
        >
          {updating ? "Updating..." : "Fetch Latest"}
        </Button>
      </div>

      {/* Active filter chips */}
      {activeFilterCount > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          {search && (
            <FilterChip label={`Search: "${search}"`} onRemove={() => { setSearch(""); setPage(1); }} />
          )}
          {vendor && (
            <FilterChip label={`Vendor: ${vendor}`} onRemove={() => { setVendor(""); setPage(1); }} />
          )}
          {minCvss !== "" && (
            <FilterChip label={`CVSS ≥ ${minCvss}`} onRemove={() => { setMinCvss(""); setPage(1); }} />
          )}
        </div>
      )}

      {/* Results count */}
      {data && (
        <p className="text-xs text-db-muted">
          {data.total} advisory{data.total !== 1 ? "ies" : "y"} found
          {activeFilterCount > 0 && " (filtered)"}
        </p>
      )}

      {/* Table */}
      {isLoading ? (
        <div className="text-sm text-db-muted py-12 text-center">Loading advisories...</div>
      ) : !data?.advisories.length ? (
        <EmptyState
          title="No advisories found"
          description="Try adjusting your search or filters, or update the advisory database in Settings."
        />
      ) : (
        <Card className="p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-db-border text-left">
                <SortableHeader field="id" label="ID" current={sortField} dir={sortDir} onSort={handleSort} />
                <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Title</th>
                <SortableHeader field="vendor" label="Vendor" current={sortField} dir={sortDir} onSort={handleSort} />
                <SortableHeader field="cvss" label="CVSS" current={sortField} dir={sortDir} onSort={handleSort} className="text-right" />
                <th className="px-4 py-2.5 text-xs font-medium text-db-muted text-right">CVEs</th>
                <SortableHeader field="published" label="Published" current={sortField} dir={sortDir} onSort={handleSort} className="text-right" />
              </tr>
            </thead>
            <tbody>
              {data.advisories.map((a, i) => (
                <tr
                  key={a.id}
                  onClick={() => openAdvisory(a.id)}
                  className={`border-b border-db-border/50 table-row-hover transition-colors cursor-pointer ${i % 2 === 0 ? "" : "bg-db-bg/30"}`}
                >
                  <td className="px-4 py-2.5 font-mono text-xs text-status-info">
                    {a.id}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-db-text max-w-md truncate">
                    {a.title}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-db-muted">{a.vendor}</td>
                  <td className="px-4 py-2.5 text-right">
                    <CvssBadge score={a.cvss_v3_max} />
                  </td>
                  <td className="px-4 py-2.5 text-xs text-db-muted text-right font-mono">
                    {a.cves?.length || 0}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-db-muted text-right font-mono">
                    {a.published}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <Button
            variant="secondary"
            size="sm"
            disabled={page <= 1}
            onClick={() => setPage((p) => p - 1)}
          >
            Previous
          </Button>
          <span className="text-xs text-db-muted font-mono">
            {page} / {totalPages}
          </span>
          <Button
            variant="secondary"
            size="sm"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => p + 1)}
          >
            Next
          </Button>
        </div>
      )}

      <AdvisoryDetailDrawer
        advisoryId={selectedAdvisory}
        onClose={closeAdvisory}
      />
    </div>
  );
}

function SortableHeader({
  field,
  label,
  current,
  dir,
  onSort,
  className = "",
}: {
  field: SortField;
  label: string;
  current: SortField;
  dir: SortDir;
  onSort: (f: SortField) => void;
  className?: string;
}) {
  const active = current === field;
  return (
    <th
      className={`px-4 py-2.5 text-xs font-medium cursor-pointer select-none transition-colors hover:text-db-text ${
        active ? "text-db-teal-light" : "text-db-muted"
      } ${className}`}
      onClick={() => onSort(field)}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {active && (
          <span className="text-[10px]">{dir === "asc" ? "▲" : "▼"}</span>
        )}
        {!active && (
          <span className="text-[10px] opacity-30">▼</span>
        )}
      </span>
    </th>
  );
}

function FilterChip({ label, onRemove }: { label: string; onRemove: () => void }) {
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-1 text-xs font-mono bg-db-surface border border-db-border rounded-sm text-db-muted">
      {label}
      <button
        onClick={onRemove}
        className="text-db-muted hover:text-status-critical transition-colors leading-none"
      >
        ×
      </button>
    </span>
  );
}

export default function AdvisoriesPage() {
  return (
    <Suspense>
      <AdvisoriesContent />
    </Suspense>
  );
}
