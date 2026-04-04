"use client";

import { useState } from "react";
import { useAdvisories } from "@/lib/hooks/useAdvisories";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { CvssBadge } from "@/components/advisory/CvssBadge";
import { EmptyState } from "@/components/ui/EmptyState";
import Link from "next/link";

export default function AdvisoriesPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [vendor, setVendor] = useState("");
  const [sort, setSort] = useState("published");
  const perPage = 25;

  const { data, isLoading } = useAdvisories({
    page,
    per_page: perPage,
    q: search || undefined,
    vendor: vendor || undefined,
    sort,
  });

  const totalPages = data ? Math.ceil(data.total / perPage) : 0;

  return (
    <div className="max-w-6xl space-y-4">
      {/* Filters */}
      <div className="flex items-center gap-3">
        <input
          type="text"
          placeholder="Search advisories, CVEs..."
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
          className="flex-1 bg-db-surface border border-db-border rounded-md px-3 py-2 text-sm text-db-text placeholder:text-db-muted focus:outline-none focus:border-db-teal"
        />
        <input
          type="text"
          placeholder="Filter vendor..."
          value={vendor}
          onChange={(e) => {
            setVendor(e.target.value);
            setPage(1);
          }}
          className="w-48 bg-db-surface border border-db-border rounded-md px-3 py-2 text-sm text-db-text placeholder:text-db-muted focus:outline-none focus:border-db-teal"
        />
        <select
          value={sort}
          onChange={(e) => setSort(e.target.value)}
          className="bg-db-surface border border-db-border rounded-md px-3 py-2 text-sm text-db-text focus:outline-none focus:border-db-teal"
        >
          <option value="published">Published</option>
          <option value="cvss">CVSS</option>
          <option value="id">ID</option>
        </select>
      </div>

      {/* Stats bar */}
      {data && (
        <p className="text-xs text-db-muted">
          Showing {data.advisories.length} of {data.total} advisories
        </p>
      )}

      {/* Table */}
      {isLoading ? (
        <div className="text-sm text-db-muted py-12 text-center">Loading advisories...</div>
      ) : !data?.advisories.length ? (
        <EmptyState
          title="No advisories found"
          description="Try adjusting your search or filters, or update the advisory database."
        />
      ) : (
        <Card className="p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-db-border text-left">
                <th className="px-4 py-2.5 text-xs font-medium text-db-muted">ID</th>
                <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Title</th>
                <th className="px-4 py-2.5 text-xs font-medium text-db-muted">Vendor</th>
                <th className="px-4 py-2.5 text-xs font-medium text-db-muted text-right">CVSS</th>
                <th className="px-4 py-2.5 text-xs font-medium text-db-muted text-right">CVEs</th>
                <th className="px-4 py-2.5 text-xs font-medium text-db-muted text-right">Published</th>
              </tr>
            </thead>
            <tbody>
              {data.advisories.map((a, i) => (
                <tr
                  key={a.id}
                  className={`border-b border-db-border/50 hover:bg-db-bg transition-colors ${i % 2 === 0 ? "" : "bg-db-bg/30"}`}
                >
                  <td className="px-4 py-2.5">
                    <Link
                      href={`/advisories/detail?id=${a.id}`}
                      className="font-mono text-xs text-status-info hover:text-db-text transition-colors"
                    >
                      {a.id}
                    </Link>
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
          <span className="text-xs text-db-muted">
            Page {page} of {totalPages}
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
    </div>
  );
}
