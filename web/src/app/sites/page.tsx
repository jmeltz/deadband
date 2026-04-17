"use client";

import { useState, useCallback } from "react";
import { Card, StatCard } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import {
  useSites,
  useUpsertSite,
  useDeleteSite,
  useReassignSites,
  useUpsertZone,
  useDeleteZone,
} from "@/lib/hooks/useSites";
import type { Site, Zone, ZonePurpose } from "@/lib/types";

const purposeColors: Record<ZonePurpose, string> = {
  ot: "bg-db-teal/20 text-db-teal-light border-db-teal/40",
  it: "bg-blue-500/20 text-blue-400 border-blue-500/40",
  dmz: "bg-orange-500/20 text-orange-400 border-orange-500/40",
  corporate: "bg-gray-500/20 text-gray-400 border-gray-500/40",
  safety: "bg-red-500/20 text-red-400 border-red-500/40",
};

const purposeLabels: Record<ZonePurpose, string> = {
  ot: "OT",
  it: "IT",
  dmz: "DMZ",
  corporate: "Corporate",
  safety: "Safety",
};

export default function SitesPage() {
  const { data: sites, isLoading } = useSites();
  const upsertSite = useUpsertSite();
  const deleteSite = useDeleteSite();
  const reassignSites = useReassignSites();

  const [editingId, setEditingId] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [reassignResult, setReassignResult] = useState<number | null>(null);
  const [expandedSite, setExpandedSite] = useState<string | null>(null);

  // Form state
  const [name, setName] = useState("");
  const [cidrs, setCidrs] = useState("");
  const [description, setDescription] = useState("");
  const [location, setLocation] = useState("");
  const [contact, setContact] = useState("");

  const resetForm = () => {
    setName("");
    setCidrs("");
    setDescription("");
    setLocation("");
    setContact("");
    setEditingId(null);
    setShowForm(false);
  };

  const startEdit = useCallback((s: Site) => {
    setEditingId(s.id);
    setName(s.name);
    setCidrs(s.cidrs.join(", "));
    setDescription(s.description || "");
    setLocation(s.location || "");
    setContact(s.contact || "");
    setShowForm(true);
  }, []);

  const handleSubmit = () => {
    const cidrList = cidrs
      .split(",")
      .map((c) => c.trim())
      .filter(Boolean);
    if (!name || cidrList.length === 0) return;

    upsertSite.mutate(
      {
        ...(editingId ? { id: editingId } : {}),
        name,
        cidrs: cidrList,
        description: description || undefined,
        location: location || undefined,
        contact: contact || undefined,
      },
      { onSuccess: resetForm },
    );
  };

  const handleDelete = (id: string) => {
    deleteSite.mutate(id);
  };

  const handleReassign = () => {
    reassignSites.mutate(undefined, {
      onSuccess: (data) => {
        setReassignResult(data.reassigned);
        setTimeout(() => setReassignResult(null), 5000);
      },
    });
  };

  const totalCidrs = sites?.reduce((n, s) => n + s.cidrs.length, 0) ?? 0;

  return (
    <div className="max-w-4xl space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <StatCard
          label="Sites"
          value={isLoading ? "\u2014" : sites?.length ?? 0}
        />
        <StatCard
          label="Subnets"
          value={isLoading ? "\u2014" : totalCidrs}
          sub="total CIDRs defined"
        />
        <StatCard
          label="Auto-Assign"
          value={reassignResult !== null ? reassignResult : "\u2014"}
          sub={
            reassignResult !== null
              ? "assets reassigned"
              : "run reassign to update"
          }
        />
      </div>

      {/* Actions */}
      <Card>
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="font-heading text-sm font-semibold">
              Site Management
            </h3>
            <p className="text-xs text-db-muted mt-0.5">
              Define network sites with CIDR subnets to auto-assign assets
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="secondary"
              onClick={handleReassign}
              disabled={reassignSites.isPending || !sites?.length}
            >
              {reassignSites.isPending ? "Reassigning..." : "Reassign All Assets"}
            </Button>
            <Button
              size="sm"
              onClick={() => {
                resetForm();
                setShowForm(true);
              }}
            >
              Add Site
            </Button>
          </div>
        </div>

        {/* Add/Edit form */}
        {showForm && (
          <div className="border border-db-border bg-db-bg p-4 mt-3 space-y-3">
            <h4 className="text-xs font-medium text-db-muted uppercase tracking-wider">
              {editingId ? "Edit Site" : "New Site"}
            </h4>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-db-muted mb-1">
                  Name *
                </label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Plant A"
                  className="w-full bg-db-surface border border-db-border px-3 py-2 text-sm text-db-text focus:outline-none input-industrial"
                />
              </div>
              <div>
                <label className="block text-xs text-db-muted mb-1">
                  CIDRs * (comma-separated)
                </label>
                <input
                  type="text"
                  value={cidrs}
                  onChange={(e) => setCidrs(e.target.value)}
                  placeholder="10.0.1.0/24, 10.0.2.0/24"
                  className="w-full bg-db-surface border border-db-border px-3 py-2 text-sm text-db-text focus:outline-none input-industrial"
                />
              </div>
              <div>
                <label className="block text-xs text-db-muted mb-1">
                  Description
                </label>
                <input
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Main production facility"
                  className="w-full bg-db-surface border border-db-border px-3 py-2 text-sm text-db-text focus:outline-none input-industrial"
                />
              </div>
              <div>
                <label className="block text-xs text-db-muted mb-1">
                  Location
                </label>
                <input
                  type="text"
                  value={location}
                  onChange={(e) => setLocation(e.target.value)}
                  placeholder="Chicago, IL"
                  className="w-full bg-db-surface border border-db-border px-3 py-2 text-sm text-db-text focus:outline-none input-industrial"
                />
              </div>
              <div>
                <label className="block text-xs text-db-muted mb-1">
                  Contact
                </label>
                <input
                  type="text"
                  value={contact}
                  onChange={(e) => setContact(e.target.value)}
                  placeholder="ops@example.com"
                  className="w-full bg-db-surface border border-db-border px-3 py-2 text-sm text-db-text focus:outline-none input-industrial"
                />
              </div>
            </div>
            <div className="flex items-center gap-2 pt-1">
              <Button
                size="sm"
                onClick={handleSubmit}
                disabled={!name || !cidrs || upsertSite.isPending}
              >
                {upsertSite.isPending
                  ? "Saving..."
                  : editingId
                    ? "Update Site"
                    : "Create Site"}
              </Button>
              <Button size="sm" variant="ghost" onClick={resetForm}>
                Cancel
              </Button>
            </div>
          </div>
        )}
      </Card>

      {/* Sites list */}
      <Card className="p-0 overflow-hidden">
        <div className="divide-y divide-db-border/50">
          {isLoading ? (
            <div className="px-4 py-8 text-center text-xs text-db-muted">
              Loading...
            </div>
          ) : !sites?.length ? (
            <div className="px-4 py-8 text-center text-xs text-db-muted">
              No sites defined. Click &ldquo;Add Site&rdquo; to create one.
            </div>
          ) : (
            sites.map((s) => (
              <SiteRow
                key={s.id}
                site={s}
                expanded={expandedSite === s.id}
                onToggle={() =>
                  setExpandedSite(expandedSite === s.id ? null : s.id)
                }
                onEdit={() => startEdit(s)}
                onDelete={() => handleDelete(s.id)}
                deleteDisabled={deleteSite.isPending}
              />
            ))
          )}
        </div>
      </Card>
    </div>
  );
}

function SiteRow({
  site,
  expanded,
  onToggle,
  onEdit,
  onDelete,
  deleteDisabled,
}: {
  site: Site;
  expanded: boolean;
  onToggle: () => void;
  onEdit: () => void;
  onDelete: () => void;
  deleteDisabled: boolean;
}) {
  const zones = site.zones ?? [];
  const zoneCount = zones.length;

  return (
    <div>
      <div
        onClick={onToggle}
        className="px-4 py-3 cursor-pointer table-row-hover flex items-center gap-3"
      >
        <span className="text-[10px] text-db-muted w-4">
          {expanded ? "\u25BC" : "\u25B6"}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-db-text">
              {site.name}
            </span>
            <span className="text-[10px] text-db-muted">
              {zoneCount} zone{zoneCount !== 1 ? "s" : ""}
            </span>
          </div>
          <div className="flex flex-wrap gap-1 mt-1">
            {site.cidrs.map((c) => (
              <span
                key={c}
                className="inline-block text-[10px] font-mono px-1.5 py-0.5 bg-db-teal-dim text-db-teal-light border border-db-teal/30"
              >
                {c}
              </span>
            ))}
          </div>
        </div>
        {site.description && (
          <span className="text-[10px] text-db-muted max-w-48 truncate">
            {site.description}
          </span>
        )}
        <div
          className="flex items-center gap-2"
          onClick={(e) => e.stopPropagation()}
        >
          <button
            onClick={onEdit}
            className="text-[10px] text-db-teal-light hover:text-db-teal-light/80 transition-colors"
          >
            Edit
          </button>
          <button
            onClick={onDelete}
            className="text-[10px] text-status-critical hover:text-status-critical/80 transition-colors"
            disabled={deleteDisabled}
          >
            Delete
          </button>
        </div>
      </div>

      {expanded && (
        <div className="bg-db-bg border-t border-db-border/50 px-4 py-3">
          <ZonesSection siteId={site.id} zones={zones} />
        </div>
      )}
    </div>
  );
}

function ZonesSection({ siteId, zones }: { siteId: string; zones: Zone[] }) {
  const upsertZone = useUpsertZone();
  const deleteZone = useDeleteZone();
  const [showForm, setShowForm] = useState(false);
  const [editingZone, setEditingZone] = useState<Zone | null>(null);

  const [zName, setZName] = useState("");
  const [zCidrs, setZCidrs] = useState("");
  const [zPurpose, setZPurpose] = useState<ZonePurpose>("ot");
  const [zSecLevel, setZSecLevel] = useState(0);
  const [zDesc, setZDesc] = useState("");

  const resetForm = () => {
    setZName("");
    setZCidrs("");
    setZPurpose("ot");
    setZSecLevel(0);
    setZDesc("");
    setEditingZone(null);
    setShowForm(false);
  };

  const startEditZone = (z: Zone) => {
    setEditingZone(z);
    setZName(z.name);
    setZCidrs(z.cidrs.join(", "));
    setZPurpose(z.purpose as ZonePurpose);
    setZSecLevel(z.security_level);
    setZDesc(z.description || "");
    setShowForm(true);
  };

  const handleSubmit = () => {
    const cidrList = zCidrs
      .split(",")
      .map((c) => c.trim())
      .filter(Boolean);
    if (!zName || cidrList.length === 0) return;

    upsertZone.mutate(
      {
        siteId,
        zone: {
          ...(editingZone ? { id: editingZone.id } : {}),
          name: zName,
          cidrs: cidrList,
          purpose: zPurpose,
          security_level: zSecLevel,
          description: zDesc || undefined,
        },
      },
      { onSuccess: resetForm },
    );
  };

  const handleDeleteZone = (zoneId: string) => {
    deleteZone.mutate({ siteId, zoneId });
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-[10px] font-medium text-db-muted uppercase tracking-wider">
          Zones
        </h4>
        <Button
          size="sm"
          variant="secondary"
          onClick={() => {
            resetForm();
            setShowForm(true);
          }}
        >
          Add Zone
        </Button>
      </div>

      {/* Zone form */}
      {showForm && (
        <div className="border border-db-border bg-db-surface p-3 space-y-2">
          <h5 className="text-[10px] font-medium text-db-muted uppercase tracking-wider">
            {editingZone ? "Edit Zone" : "New Zone"}
          </h5>
          <div className="grid grid-cols-3 gap-2">
            <div>
              <label className="block text-[10px] text-db-muted mb-0.5">
                Name *
              </label>
              <input
                type="text"
                value={zName}
                onChange={(e) => setZName(e.target.value)}
                placeholder="Process Control"
                className="w-full bg-db-bg border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none input-industrial"
              />
            </div>
            <div>
              <label className="block text-[10px] text-db-muted mb-0.5">
                CIDRs * (comma-separated)
              </label>
              <input
                type="text"
                value={zCidrs}
                onChange={(e) => setZCidrs(e.target.value)}
                placeholder="10.0.1.0/24"
                className="w-full bg-db-bg border border-db-border px-2 py-1.5 text-xs text-db-text font-mono focus:outline-none input-industrial"
              />
            </div>
            <div>
              <label className="block text-[10px] text-db-muted mb-0.5">
                Purpose
              </label>
              <select
                value={zPurpose}
                onChange={(e) => setZPurpose(e.target.value as ZonePurpose)}
                className="w-full bg-db-bg border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none"
              >
                <option value="ot">OT</option>
                <option value="it">IT</option>
                <option value="dmz">DMZ</option>
                <option value="corporate">Corporate</option>
                <option value="safety">Safety</option>
              </select>
            </div>
            <div>
              <label className="block text-[10px] text-db-muted mb-0.5">
                Security Level (SL-T: 0-4)
              </label>
              <input
                type="range"
                min={0}
                max={4}
                value={zSecLevel}
                onChange={(e) => setZSecLevel(Number(e.target.value))}
                className="w-full"
              />
              <span className="text-[10px] text-db-muted">SL-{zSecLevel}</span>
            </div>
            <div>
              <label className="block text-[10px] text-db-muted mb-0.5">
                Description
              </label>
              <input
                type="text"
                value={zDesc}
                onChange={(e) => setZDesc(e.target.value)}
                placeholder="PLC / SCADA network"
                className="w-full bg-db-bg border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none input-industrial"
              />
            </div>
          </div>
          <div className="flex items-center gap-2 pt-1">
            <Button
              size="sm"
              onClick={handleSubmit}
              disabled={!zName || !zCidrs || upsertZone.isPending}
            >
              {upsertZone.isPending
                ? "Saving..."
                : editingZone
                  ? "Update Zone"
                  : "Create Zone"}
            </Button>
            <Button size="sm" variant="ghost" onClick={resetForm}>
              Cancel
            </Button>
          </div>
        </div>
      )}

      {/* Zone table */}
      {zones.length > 0 ? (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-db-muted border-b border-db-border/50">
              <th className="py-1.5 pr-3 font-medium">Name</th>
              <th className="py-1.5 pr-3 font-medium">CIDRs</th>
              <th className="py-1.5 pr-3 font-medium">Purpose</th>
              <th className="py-1.5 pr-3 font-medium">SL-T</th>
              <th className="py-1.5 pr-3 font-medium">Description</th>
              <th className="py-1.5 font-medium w-16">Actions</th>
            </tr>
          </thead>
          <tbody>
            {zones.map((z) => (
              <tr key={z.id} className="border-t border-db-border/30">
                <td className="py-1.5 pr-3 text-db-text font-medium">
                  {z.name}
                </td>
                <td className="py-1.5 pr-3">
                  <div className="flex flex-wrap gap-1">
                    {z.cidrs.map((c) => (
                      <span
                        key={c}
                        className="text-[10px] font-mono px-1 py-0.5 bg-db-surface border border-db-border text-db-muted"
                      >
                        {c}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="py-1.5 pr-3">
                  <span
                    className={`inline-block text-[9px] font-mono px-1.5 py-0.5 border uppercase ${purposeColors[z.purpose as ZonePurpose] || "bg-gray-500/20 text-gray-400 border-gray-500/40"}`}
                  >
                    {purposeLabels[z.purpose as ZonePurpose] || z.purpose}
                  </span>
                </td>
                <td className="py-1.5 pr-3 text-db-muted font-mono">
                  SL-{z.security_level}
                </td>
                <td className="py-1.5 pr-3 text-db-muted">
                  {z.description || "\u2014"}
                </td>
                <td className="py-1.5">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => startEditZone(z)}
                      className="text-[10px] text-db-teal-light hover:text-db-teal-light/80"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleDeleteZone(z.id)}
                      className="text-[10px] text-status-critical hover:text-status-critical/80"
                      disabled={deleteZone.isPending}
                    >
                      Del
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="text-[10px] text-db-muted text-center py-2">
          No zones defined. Add zones to enable zone-aware posture analysis.
        </div>
      )}
    </div>
  );
}
