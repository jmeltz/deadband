"use client";

import { useState, useMemo, useCallback } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import {
  useAssets,
  useUpdateAsset,
  useDeleteAsset,
  useBulkUpdateAssets,
} from "@/lib/hooks/useAssets";
import type { Asset, Criticality } from "@/lib/types";

type SortKey =
  | "ip"
  | "vendor"
  | "model"
  | "firmware"
  | "name"
  | "site"
  | "zone"
  | "criticality"
  | "last_seen";

export default function AssetsPage() {
  // Filters
  const [search, setSearch] = useState("");
  const [vendorFilter, setVendorFilter] = useState("");
  const [siteFilter, setSiteFilter] = useState("");
  const [zoneFilter, setZoneFilter] = useState("");
  const [critFilter, setCritFilter] = useState("");
  const [tagFilter, setTagFilter] = useState("");

  // Sort
  const [sortKey, setSortKey] = useState<SortKey>("last_seen");
  const [sortAsc, setSortAsc] = useState(false);

  // Selection
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // Editing
  const [editingId, setEditingId] = useState<string | null>(null);

  // Bulk action panel
  const [bulkTag, setBulkTag] = useState("");
  const [bulkSite, setBulkSite] = useState("");
  const [bulkZone, setBulkZone] = useState("");
  const [bulkCrit, setBulkCrit] = useState("");

  const sortParam = `${sortKey}:${sortAsc ? "asc" : "desc"}`;
  const { data, isLoading } = useAssets({
    q: search || undefined,
    vendor: vendorFilter || undefined,
    site: siteFilter || undefined,
    zone: zoneFilter || undefined,
    criticality: critFilter || undefined,
    tag: tagFilter || undefined,
    sort: sortParam,
  });

  const updateAsset = useUpdateAsset();
  const deleteAsset = useDeleteAsset();
  const bulkUpdate = useBulkUpdateAssets();

  const assets = data?.assets ?? [];
  const facets = useMemo(
    () => ({
      sites: data?.sites ?? [],
      zones: data?.zones ?? [],
      tags: data?.tags ?? [],
    }),
    [data],
  );

  // Distinct vendors from current results for filter dropdown
  const vendors = useMemo(() => {
    const set = new Set<string>();
    for (const a of assets) if (a.vendor) set.add(a.vendor);
    return Array.from(set).sort();
  }, [assets]);

  const toggleSort = useCallback(
    (key: SortKey) => {
      if (sortKey === key) {
        setSortAsc(!sortAsc);
      } else {
        setSortKey(key);
        setSortAsc(true);
      }
    },
    [sortKey, sortAsc],
  );

  const toggleSelect = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (selected.size === assets.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(assets.map((a) => a.id)));
    }
  };

  const handleBulkApply = () => {
    const ids = Array.from(selected);
    if (ids.length === 0) return;
    const params: Parameters<typeof bulkUpdate.mutate>[0] = { ids };
    if (bulkTag) params.add_tags = [bulkTag];
    if (bulkSite) params.set_site = bulkSite;
    if (bulkZone) params.set_zone = bulkZone;
    if (bulkCrit) params.set_criticality = bulkCrit;
    bulkUpdate.mutate(params, {
      onSuccess: () => {
        setBulkTag("");
        setBulkSite("");
        setBulkZone("");
        setBulkCrit("");
      },
    });
  };

  const handleDelete = (id: string) => {
    deleteAsset.mutate(id);
    setSelected((prev) => {
      const next = new Set(prev);
      next.delete(id);
      return next;
    });
  };

  const SortHeader = ({
    label,
    field,
    className,
  }: {
    label: string;
    field: SortKey;
    className?: string;
  }) => (
    <th
      className={`px-3 py-2.5 text-xs font-medium text-db-muted cursor-pointer select-none hover:text-db-text transition-colors ${className ?? ""}`}
      onClick={() => toggleSort(field)}
    >
      {label}
      {sortKey === field && (
        <span className="ml-1 text-db-teal-light">
          {sortAsc ? "\u25B2" : "\u25BC"}
        </span>
      )}
    </th>
  );

  return (
    <div className="max-w-7xl space-y-4">
      {/* Search + Filters */}
      <Card className="space-y-3">
        <div className="flex items-center gap-3">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search assets..."
            className="flex-1 bg-db-bg border border-db-border px-3 py-1.5 text-sm text-db-text placeholder:text-db-muted focus:outline-none input-industrial"
          />
          <FilterSelect
            value={vendorFilter}
            onChange={setVendorFilter}
            placeholder="Vendor"
            options={vendors}
          />
          <FilterSelect
            value={siteFilter}
            onChange={setSiteFilter}
            placeholder="Site"
            options={facets.sites}
          />
          <FilterSelect
            value={zoneFilter}
            onChange={setZoneFilter}
            placeholder="Zone"
            options={facets.zones}
          />
          <FilterSelect
            value={critFilter}
            onChange={setCritFilter}
            placeholder="Criticality"
            options={["critical", "high", "medium", "low"]}
          />
          <FilterSelect
            value={tagFilter}
            onChange={setTagFilter}
            placeholder="Tag"
            options={facets.tags}
          />
          {(vendorFilter ||
            siteFilter ||
            zoneFilter ||
            critFilter ||
            tagFilter ||
            search) && (
            <button
              onClick={() => {
                setSearch("");
                setVendorFilter("");
                setSiteFilter("");
                setZoneFilter("");
                setCritFilter("");
                setTagFilter("");
              }}
              className="text-xs text-db-muted hover:text-db-text"
            >
              Clear
            </button>
          )}
        </div>
      </Card>

      {/* Bulk actions */}
      {selected.size > 0 && (
        <Card className="flex items-center gap-3 flex-wrap">
          <span className="text-xs text-db-muted">
            {selected.size} selected
          </span>
          <div className="h-4 w-px bg-db-border" />
          <input
            type="text"
            value={bulkTag}
            onChange={(e) => setBulkTag(e.target.value)}
            placeholder="Add tag..."
            className="bg-db-bg border border-db-border px-2 py-1 text-xs text-db-text w-28 focus:outline-none input-industrial"
          />
          <input
            type="text"
            value={bulkSite}
            onChange={(e) => setBulkSite(e.target.value)}
            placeholder="Set site..."
            className="bg-db-bg border border-db-border px-2 py-1 text-xs text-db-text w-28 focus:outline-none input-industrial"
          />
          <input
            type="text"
            value={bulkZone}
            onChange={(e) => setBulkZone(e.target.value)}
            placeholder="Set zone..."
            className="bg-db-bg border border-db-border px-2 py-1 text-xs text-db-text w-28 focus:outline-none input-industrial"
          />
          <select
            value={bulkCrit}
            onChange={(e) => setBulkCrit(e.target.value)}
            className="bg-db-bg border border-db-border px-2 py-1 text-xs text-db-text focus:outline-none input-industrial"
          >
            <option value="">Criticality...</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <Button
            size="sm"
            onClick={handleBulkApply}
            disabled={!bulkTag && !bulkSite && !bulkZone && !bulkCrit}
          >
            Apply
          </Button>
          <button
            onClick={() => setSelected(new Set())}
            className="text-xs text-db-muted hover:text-db-text ml-auto"
          >
            Deselect all
          </button>
        </Card>
      )}

      {/* Summary */}
      {data && (
        <div className="flex items-center justify-between">
          <span className="text-xs text-db-muted">
            {data.total} asset{data.total !== 1 ? "s" : ""}
          </span>
        </div>
      )}

      {/* Asset table */}
      {assets.length > 0 && (
        <Card className="p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-db-border text-left">
                  <th className="px-3 py-2.5 w-8">
                    <input
                      type="checkbox"
                      checked={
                        selected.size === assets.length && assets.length > 0
                      }
                      onChange={toggleAll}
                      className="rounded border-db-border"
                    />
                  </th>
                  <SortHeader label="IP Address" field="ip" />
                  <SortHeader label="Vendor" field="vendor" />
                  <SortHeader label="Model" field="model" />
                  <SortHeader label="Firmware" field="firmware" />
                  <SortHeader label="Name" field="name" />
                  <SortHeader label="Site" field="site" />
                  <SortHeader label="Zone" field="zone" />
                  <SortHeader label="Criticality" field="criticality" />
                  <th className="px-3 py-2.5 text-xs font-medium text-db-muted">
                    Tags
                  </th>
                  <SortHeader
                    label="Last Seen"
                    field="last_seen"
                    className="text-right"
                  />
                  <th className="px-3 py-2.5 w-8" />
                </tr>
              </thead>
              <tbody>
                {assets.map((asset, i) => (
                  <AssetRow
                    key={asset.id}
                    asset={asset}
                    isSelected={selected.has(asset.id)}
                    onToggleSelect={() => toggleSelect(asset.id)}
                    isEditing={editingId === asset.id}
                    onEdit={() =>
                      setEditingId(editingId === asset.id ? null : asset.id)
                    }
                    onSave={(patch) => {
                      updateAsset.mutate(
                        { id: asset.id, patch },
                        { onSuccess: () => setEditingId(null) },
                      );
                    }}
                    onDelete={() => handleDelete(asset.id)}
                    odd={i % 2 !== 0}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Empty state */}
      {!isLoading && assets.length === 0 && (
        <EmptyState
          title="No assets"
          description="Discover devices on the Devices page, then save them as assets to manage here."
        />
      )}
    </div>
  );
}

// --- Sub-components ---

function AssetRow({
  asset,
  isSelected,
  onToggleSelect,
  isEditing,
  onEdit,
  onSave,
  onDelete,
  odd,
}: {
  asset: Asset;
  isSelected: boolean;
  onToggleSelect: () => void;
  isEditing: boolean;
  onEdit: () => void;
  onSave: (patch: Partial<Asset>) => void;
  onDelete: () => void;
  odd: boolean;
}) {
  const [name, setName] = useState(asset.name);
  const [site, setSite] = useState(asset.site);
  const [zone, setZone] = useState(asset.zone);
  const [crit, setCrit] = useState(asset.criticality);
  const [tags, setTags] = useState(asset.tags.join(", "));
  const [notes, setNotes] = useState(asset.notes);

  const handleSave = () => {
    onSave({
      name,
      site,
      zone,
      criticality: crit,
      tags: tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
      notes,
    });
  };

  if (isEditing) {
    return (
      <>
        <tr
          className={`border-b border-db-border/50 ${odd ? "bg-db-bg/30" : ""}`}
        >
          <td className="px-3 py-2">
            <input
              type="checkbox"
              checked={isSelected}
              onChange={onToggleSelect}
              className="rounded border-db-border"
            />
          </td>
          <td className="px-3 py-2 font-mono text-xs">{asset.ip}</td>
          <td className="px-3 py-2 text-xs text-db-muted">{asset.vendor}</td>
          <td className="px-3 py-2 font-mono text-xs">{asset.model}</td>
          <td className="px-3 py-2 font-mono text-xs">{asset.firmware}</td>
          <td className="px-3 py-1" colSpan={6}>
            <div className="flex items-center gap-2">
              <Button size="sm" onClick={handleSave}>
                Save
              </Button>
              <Button size="sm" variant="ghost" onClick={onEdit}>
                Cancel
              </Button>
              <button
                onClick={onDelete}
                className="text-xs text-status-critical/70 hover:text-status-critical ml-auto"
              >
                Delete
              </button>
            </div>
          </td>
          <td />
        </tr>
        <tr className="border-b border-db-border/50 bg-db-bg/60">
          <td />
          <td colSpan={11} className="px-3 py-3">
            <div className="grid grid-cols-3 gap-3">
              <EditField label="Name" value={name} onChange={setName} />
              <EditField label="Site" value={site} onChange={setSite} />
              <EditField label="Zone" value={zone} onChange={setZone} />
              <div>
                <label className="block text-[10px] text-db-muted mb-1">
                  Criticality
                </label>
                <select
                  value={crit}
                  onChange={(e) => setCrit(e.target.value as Criticality)}
                  className="w-full bg-db-bg border border-db-border px-2 py-1 text-xs text-db-text focus:outline-none input-industrial"
                >
                  <option value="">None</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <EditField
                label="Tags (comma-separated)"
                value={tags}
                onChange={setTags}
              />
              <EditField label="Notes" value={notes} onChange={setNotes} />
            </div>
          </td>
        </tr>
      </>
    );
  }

  return (
    <tr
      className={`border-b border-db-border/50 table-row-hover cursor-pointer ${odd ? "bg-db-bg/30" : ""}`}
      onClick={onEdit}
    >
      <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
        <input
          type="checkbox"
          checked={isSelected}
          onChange={onToggleSelect}
          className="rounded border-db-border"
        />
      </td>
      <td className="px-3 py-2 font-mono text-xs">{asset.ip}</td>
      <td className="px-3 py-2 text-xs text-db-muted">{asset.vendor}</td>
      <td className="px-3 py-2 font-mono text-xs">{asset.model}</td>
      <td className="px-3 py-2 font-mono text-xs">{asset.firmware}</td>
      <td className="px-3 py-2 text-xs">
        {asset.name || (
          <span className="text-db-muted/50 italic">unnamed</span>
        )}
      </td>
      <td className="px-3 py-2 text-xs text-db-muted">{asset.site}</td>
      <td className="px-3 py-2 text-xs text-db-muted">{asset.zone}</td>
      <td className="px-3 py-2">
        {asset.criticality && <CritBadge value={asset.criticality} />}
      </td>
      <td className="px-3 py-2">
        <div className="flex gap-1 flex-wrap">
          {asset.tags?.map((t) => (
            <span
              key={t}
              className="px-1.5 py-0.5 text-[10px] bg-db-teal-dim text-db-teal-light rounded-sm"
            >
              {t}
            </span>
          ))}
        </div>
      </td>
      <td className="px-3 py-2 text-[10px] text-db-muted text-right font-mono whitespace-nowrap">
        {asset.last_seen
          ? new Date(asset.last_seen).toLocaleDateString()
          : ""}
      </td>
      <td className="px-3 py-2 text-center">
        <span className="text-[10px] text-db-muted">&#9998;</span>
      </td>
    </tr>
  );
}

function EditField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div>
      <label className="block text-[10px] text-db-muted mb-1">{label}</label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full bg-db-bg border border-db-border px-2 py-1 text-xs text-db-text focus:outline-none input-industrial"
      />
    </div>
  );
}

function FilterSelect({
  value,
  onChange,
  placeholder,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  options: string[];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="bg-db-bg border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none input-industrial min-w-[90px]"
    >
      <option value="">{placeholder}</option>
      {options.map((o) => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </select>
  );
}

function CritBadge({ value }: { value: string }) {
  const colors: Record<string, string> = {
    critical: "bg-status-critical/20 text-status-critical border-status-critical/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-status-medium/20 text-status-medium border-status-medium/30",
    low: "bg-status-ok/20 text-status-ok border-status-ok/30",
  };
  return (
    <span
      className={`px-1.5 py-0.5 text-[10px] rounded-sm border ${colors[value] ?? "bg-db-surface text-db-muted border-db-border"}`}
    >
      {value}
    </span>
  );
}
