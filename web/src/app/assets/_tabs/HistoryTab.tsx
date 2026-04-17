"use client";

import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import {
  useDiscoverHistory,
  useSchedules,
  useCreateSchedule,
  useDeleteSchedule,
} from "@/lib/hooks/useDiscoverHistory";
import { formatDateTime, relativeTime } from "@/lib/utils/format";

export function HistoryTab() {
  return (
    <div className="grid grid-cols-2 gap-6">
      <DiscoverHistoryPanel />
      <SchedulePanel />
    </div>
  );
}

function DiscoverHistoryPanel() {
  const { data: history, isLoading } = useDiscoverHistory();
  const jobs = history ?? [];

  return (
    <Card>
      <h3 className="font-heading text-sm font-semibold mb-3">Discovery History</h3>
      {isLoading && <p className="text-xs text-db-muted">Loading...</p>}
      {jobs.length === 0 && !isLoading && (
        <EmptyState
          title="No discovery runs"
          description="Run a network scan from the Discover tab to see history here."
        />
      )}
      <div className="space-y-1">
        {jobs.slice(0, 20).map((j) => (
          <div key={j.id} className="flex items-center gap-2 py-1.5 text-xs">
            <span
              className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                j.status === "complete" ? "bg-status-ok" : "bg-status-critical"
              }`}
            />
            <span className="font-mono text-db-muted w-28 shrink-0">{j.cidr}</span>
            <span className="text-db-text">
              {j.device_count} device{j.device_count !== 1 ? "s" : ""}
            </span>
            {j.new_count > 0 && (
              <span className="text-status-ok">+{j.new_count}</span>
            )}
            {j.updated_count > 0 && (
              <span className="text-status-medium">~{j.updated_count}</span>
            )}
            <span className="text-db-muted font-mono ml-auto text-[10px]">{j.duration}</span>
            <span className="text-db-muted text-[10px]">
              {j.started_at ? relativeTime(j.started_at) : ""}
            </span>
          </div>
        ))}
      </div>
    </Card>
  );
}

function SchedulePanel() {
  const { data: schedules, isLoading } = useSchedules();
  const createSchedule = useCreateSchedule();
  const deleteSchedule = useDeleteSchedule();

  const [newCidr, setNewCidr] = useState("");
  const [newInterval, setNewInterval] = useState("24h");
  const [newAutoCheck, setNewAutoCheck] = useState(true);

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCidr.trim()) return;
    createSchedule.mutate(
      {
        cidr: newCidr.trim(),
        mode: "auto",
        interval: newInterval,
        auto_check: newAutoCheck,
        enabled: true,
      },
      { onSuccess: () => setNewCidr("") },
    );
  };

  return (
    <Card>
      <h3 className="font-heading text-sm font-semibold mb-3">Scheduled Scans</h3>

      {/* Existing schedules */}
      {isLoading && <p className="text-xs text-db-muted">Loading...</p>}
      {schedules && schedules.length > 0 && (
        <div className="space-y-2 mb-4">
          {schedules.map((s) => (
            <div key={s.id} className="flex items-center gap-2 py-1.5 text-xs">
              <span
                className={`w-1.5 h-1.5 rounded-full shrink-0 ${s.enabled ? "bg-status-ok" : "bg-db-muted"}`}
              />
              <span className="font-mono text-db-text">{s.cidr}</span>
              <span className="text-db-muted">every {s.interval}</span>
              {s.auto_check && <span className="text-db-teal-light text-[10px]">+check</span>}
              {s.next_run && (
                <span className="text-[10px] text-db-muted ml-auto">
                  next: {formatDateTime(s.next_run)}
                </span>
              )}
              <button
                onClick={() => deleteSchedule.mutate(s.id)}
                className="text-[10px] text-status-critical/50 hover:text-status-critical ml-2"
              >
                delete
              </button>
            </div>
          ))}
        </div>
      )}

      {/* New schedule form */}
      <form onSubmit={handleCreate} className="flex items-end gap-2">
        <div className="flex-1">
          <label className="block text-[10px] text-db-muted mb-1">CIDR</label>
          <input
            type="text"
            value={newCidr}
            onChange={(e) => setNewCidr(e.target.value)}
            placeholder="10.0.1.0/24"
            className="w-full bg-db-bg border border-db-border px-2 py-1 text-xs font-mono text-db-text focus:outline-none input-industrial"
          />
        </div>
        <div>
          <label className="block text-[10px] text-db-muted mb-1">Interval</label>
          <select
            value={newInterval}
            onChange={(e) => setNewInterval(e.target.value)}
            className="bg-db-bg border border-db-border px-2 py-1 text-xs text-db-text focus:outline-none input-industrial"
          >
            <option value="1h">Every hour</option>
            <option value="6h">Every 6 hours</option>
            <option value="24h">Daily</option>
            <option value="weekly">Weekly</option>
          </select>
        </div>
        <label className="flex items-center gap-1 text-[10px] text-db-muted pb-1">
          <input
            type="checkbox"
            checked={newAutoCheck}
            onChange={(e) => setNewAutoCheck(e.target.checked)}
            className="rounded border-db-border"
          />
          Auto-check
        </label>
        <Button type="submit" size="sm" disabled={!newCidr.trim() || createSchedule.isPending}>
          Add
        </Button>
      </form>
    </Card>
  );
}
