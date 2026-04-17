"use client";

import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import {
  useSentinelConfigs,
  useUpsertSentinelConfig,
  useDeleteSentinelConfig,
  useTestSentinelConfig,
  useASAConfigs,
  useUpsertASAConfig,
  useDeleteASAConfig,
  useTestASAConfig,
} from "@/lib/hooks/useIntegrations";
import { useSites } from "@/lib/hooks/useSites";
import type { SentinelConfig, ASAConfig } from "@/lib/types";

type SubTab = "sentinel" | "asa";

export function IntegrationsTab() {
  const [tab, setTab] = useState<SubTab>("sentinel");

  return (
    <div className="space-y-6">
      <Card>
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-heading text-sm font-semibold">Integrations</h3>
            <p className="text-xs text-db-muted mt-0.5">
              Connect external data sources for traffic flow analysis and
              firewall config auditing.
            </p>
          </div>
          <div className="flex gap-1">
            <button
              onClick={() => setTab("sentinel")}
              className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                tab === "sentinel"
                  ? "bg-db-teal-dim text-db-teal-light"
                  : "text-db-muted hover:text-db-text"
              }`}
            >
              Microsoft Sentinel
            </button>
            <button
              onClick={() => setTab("asa")}
              className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                tab === "asa"
                  ? "bg-db-teal-dim text-db-teal-light"
                  : "text-db-muted hover:text-db-text"
              }`}
            >
              Cisco ASA
            </button>
          </div>
        </div>
      </Card>

      {tab === "sentinel" ? <SentinelPanel /> : <ASAPanel />}
    </div>
  );
}

function SentinelPanel() {
  const { data: configs } = useSentinelConfigs();
  const { data: sites } = useSites();
  const upsert = useUpsertSentinelConfig();
  const remove = useDeleteSentinelConfig();
  const test = useTestSentinelConfig();

  const [editing, setEditing] = useState<Partial<SentinelConfig> | null>(null);
  const [testResult, setTestResult] = useState<Record<string, { status: string; error?: string }>>({});

  const handleSave = () => {
    if (!editing) return;
    upsert.mutate(editing, {
      onSuccess: () => setEditing(null),
    });
  };

  const handleTest = (id: string) => {
    setTestResult((prev) => ({ ...prev, [id]: { status: "testing" } }));
    test.mutate(id, {
      onSuccess: (res) => setTestResult((prev) => ({ ...prev, [id]: res })),
      onError: (err) =>
        setTestResult((prev) => ({
          ...prev,
          [id]: { status: "error", error: String(err) },
        })),
    });
  };

  return (
    <>
      <Card className="p-0 overflow-hidden">
        <div className="px-4 py-3 border-b border-db-border flex items-center justify-between">
          <h3 className="font-heading text-sm font-semibold">
            Sentinel Connections
          </h3>
          <Button size="sm" onClick={() => setEditing({ enabled: true })}>
            Add Connection
          </Button>
        </div>

        {(configs ?? []).length === 0 && !editing ? (
          <div className="px-4 py-8 text-center text-xs text-db-muted">
            No Sentinel connections configured. Add one to start querying
            traffic flow data from Azure Log Analytics.
          </div>
        ) : (
          <div className="divide-y divide-db-border/50">
            {(configs ?? []).map((cfg) => (
              <div
                key={cfg.id}
                className="px-4 py-3 flex items-center gap-3 table-row-hover"
              >
                <div className="flex-1">
                  <span className="text-xs font-medium text-db-text">
                    {cfg.name || "Unnamed"}
                  </span>
                  <span className="text-[10px] text-db-muted ml-2">
                    {sites?.find((s) => s.id === cfg.site_id)?.name || cfg.site_id}
                  </span>
                  <div className="text-[10px] font-mono text-db-muted mt-0.5">
                    Workspace: {cfg.workspace_id.slice(0, 12)}...
                  </div>
                </div>
                <span
                  className={`text-[9px] font-mono px-1.5 py-0.5 border ${
                    cfg.enabled
                      ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                      : "bg-gray-500/20 text-gray-400 border-gray-500/40"
                  }`}
                >
                  {cfg.enabled ? "enabled" : "disabled"}
                </span>
                {testResult[cfg.id] && (
                  <span
                    className={`text-[9px] font-mono px-1.5 py-0.5 border ${
                      testResult[cfg.id].status === "ok"
                        ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                        : testResult[cfg.id].status === "testing"
                          ? "bg-blue-500/20 text-blue-400 border-blue-500/40"
                          : "bg-red-500/20 text-red-400 border-red-500/40"
                    }`}
                  >
                    {testResult[cfg.id].status === "testing"
                      ? "testing..."
                      : testResult[cfg.id].status === "ok"
                        ? "connected"
                        : "failed"}
                  </span>
                )}
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => handleTest(cfg.id)}
                >
                  Test
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setEditing(cfg)}
                >
                  Edit
                </Button>
                <button
                  onClick={() => remove.mutate(cfg.id)}
                  className="text-db-muted hover:text-status-critical text-xs"
                >
                  &times;
                </button>
              </div>
            ))}
          </div>
        )}
      </Card>

      {editing && (
        <Card>
          <h4 className="text-xs font-semibold text-db-text mb-3">
            {editing.id ? "Edit" : "New"} Sentinel Connection
          </h4>
          <div className="grid grid-cols-2 gap-3">
            <label className="block">
              <span className="text-[10px] text-db-muted uppercase tracking-wider">
                Name
              </span>
              <input
                className="mt-1 w-full bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none focus:border-db-teal"
                value={editing.name ?? ""}
                onChange={(e) =>
                  setEditing({ ...editing, name: e.target.value })
                }
              />
            </label>
            <label className="block">
              <span className="text-[10px] text-db-muted uppercase tracking-wider">
                Site
              </span>
              <select
                className="mt-1 w-full bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none"
                value={editing.site_id ?? ""}
                onChange={(e) =>
                  setEditing({ ...editing, site_id: e.target.value })
                }
              >
                <option value="">Select site...</option>
                {(sites ?? []).map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="text-[10px] text-db-muted uppercase tracking-wider">
                Tenant ID
              </span>
              <input
                className="mt-1 w-full bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text font-mono focus:outline-none focus:border-db-teal"
                value={editing.tenant_id ?? ""}
                onChange={(e) =>
                  setEditing({ ...editing, tenant_id: e.target.value })
                }
              />
            </label>
            <label className="block">
              <span className="text-[10px] text-db-muted uppercase tracking-wider">
                Client ID
              </span>
              <input
                className="mt-1 w-full bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text font-mono focus:outline-none focus:border-db-teal"
                value={editing.client_id ?? ""}
                onChange={(e) =>
                  setEditing({ ...editing, client_id: e.target.value })
                }
              />
            </label>
            <label className="block">
              <span className="text-[10px] text-db-muted uppercase tracking-wider">
                Client Secret
              </span>
              <input
                type="password"
                className="mt-1 w-full bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text font-mono focus:outline-none focus:border-db-teal"
                value={editing.client_secret ?? ""}
                onChange={(e) =>
                  setEditing({ ...editing, client_secret: e.target.value })
                }
              />
            </label>
            <label className="block">
              <span className="text-[10px] text-db-muted uppercase tracking-wider">
                Workspace ID
              </span>
              <input
                className="mt-1 w-full bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text font-mono focus:outline-none focus:border-db-teal"
                value={editing.workspace_id ?? ""}
                onChange={(e) =>
                  setEditing({ ...editing, workspace_id: e.target.value })
                }
              />
            </label>
          </div>
          <label className="flex items-center gap-2 mt-3">
            <input
              type="checkbox"
              checked={editing.enabled ?? true}
              onChange={(e) =>
                setEditing({ ...editing, enabled: e.target.checked })
              }
              className="accent-db-teal"
            />
            <span className="text-xs text-db-text">Enabled</span>
          </label>
          <div className="flex gap-2 mt-4">
            <Button size="sm" onClick={handleSave} disabled={upsert.isPending}>
              {upsert.isPending ? "Saving..." : "Save"}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setEditing(null)}
            >
              Cancel
            </Button>
          </div>
        </Card>
      )}
    </>
  );
}

function ASAPanel() {
  const { data: configs } = useASAConfigs();
  const { data: sites } = useSites();
  const upsert = useUpsertASAConfig();
  const remove = useDeleteASAConfig();
  const test = useTestASAConfig();

  const [editing, setEditing] = useState<Partial<ASAConfig> | null>(null);
  const [testResult, setTestResult] = useState<Record<string, { status: string; error?: string }>>({});

  const handleSave = () => {
    if (!editing) return;
    upsert.mutate(editing, {
      onSuccess: () => setEditing(null),
    });
  };

  const handleTest = (id: string) => {
    setTestResult((prev) => ({ ...prev, [id]: { status: "testing" } }));
    test.mutate(id, {
      onSuccess: (res) => setTestResult((prev) => ({ ...prev, [id]: res })),
      onError: (err) =>
        setTestResult((prev) => ({
          ...prev,
          [id]: { status: "error", error: String(err) },
        })),
    });
  };

  return (
    <>
      <Card className="p-0 overflow-hidden">
        <div className="px-4 py-3 border-b border-db-border flex items-center justify-between">
          <h3 className="font-heading text-sm font-semibold">
            ASA Connections
          </h3>
          <Button
            size="sm"
            onClick={() => setEditing({ enabled: true, port: 22 })}
          >
            Add Connection
          </Button>
        </div>

        {(configs ?? []).length === 0 && !editing ? (
          <div className="px-4 py-8 text-center text-xs text-db-muted">
            No ASA connections configured. Add one to pull live firewall
            configurations via SSH.
          </div>
        ) : (
          <div className="divide-y divide-db-border/50">
            {(configs ?? []).map((cfg) => (
              <div
                key={cfg.id}
                className="px-4 py-3 flex items-center gap-3 table-row-hover"
              >
                <div className="flex-1">
                  <span className="text-xs font-medium text-db-text">
                    {cfg.name || "Unnamed"}
                  </span>
                  <span className="text-[10px] text-db-muted ml-2">
                    {sites?.find((s) => s.id === cfg.site_id)?.name || cfg.site_id}
                  </span>
                  <div className="text-[10px] font-mono text-db-muted mt-0.5">
                    {cfg.host}:{cfg.port} &middot; {cfg.username}
                  </div>
                </div>
                <span
                  className={`text-[9px] font-mono px-1.5 py-0.5 border ${
                    cfg.enabled
                      ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                      : "bg-gray-500/20 text-gray-400 border-gray-500/40"
                  }`}
                >
                  {cfg.enabled ? "enabled" : "disabled"}
                </span>
                {testResult[cfg.id] && (
                  <span
                    className={`text-[9px] font-mono px-1.5 py-0.5 border ${
                      testResult[cfg.id].status === "ok"
                        ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                        : testResult[cfg.id].status === "testing"
                          ? "bg-blue-500/20 text-blue-400 border-blue-500/40"
                          : "bg-red-500/20 text-red-400 border-red-500/40"
                    }`}
                  >
                    {testResult[cfg.id].status === "testing"
                      ? "testing..."
                      : testResult[cfg.id].status === "ok"
                        ? "connected"
                        : "failed"}
                  </span>
                )}
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => handleTest(cfg.id)}
                >
                  Test
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setEditing(cfg)}
                >
                  Edit
                </Button>
                <button
                  onClick={() => remove.mutate(cfg.id)}
                  className="text-db-muted hover:text-status-critical text-xs"
                >
                  &times;
                </button>
              </div>
            ))}
          </div>
        )}
      </Card>

      {editing && (
        <Card>
          <h4 className="text-xs font-semibold text-db-text mb-3">
            {editing.id ? "Edit" : "New"} ASA Connection
          </h4>
          <div className="grid grid-cols-2 gap-3">
            <label className="block">
              <span className="text-[10px] text-db-muted uppercase tracking-wider">
                Name
              </span>
              <input
                className="mt-1 w-full bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none focus:border-db-teal"
                value={editing.name ?? ""}
                onChange={(e) =>
                  setEditing({ ...editing, name: e.target.value })
                }
              />
            </label>
            <label className="block">
              <span className="text-[10px] text-db-muted uppercase tracking-wider">
                Site
              </span>
              <select
                className="mt-1 w-full bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none"
                value={editing.site_id ?? ""}
                onChange={(e) =>
                  setEditing({ ...editing, site_id: e.target.value })
                }
              >
                <option value="">Select site...</option>
                {(sites ?? []).map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="text-[10px] text-db-muted uppercase tracking-wider">
                Host
              </span>
              <input
                className="mt-1 w-full bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text font-mono focus:outline-none focus:border-db-teal"
                placeholder="10.0.1.1"
                value={editing.host ?? ""}
                onChange={(e) =>
                  setEditing({ ...editing, host: e.target.value })
                }
              />
            </label>
            <label className="block">
              <span className="text-[10px] text-db-muted uppercase tracking-wider">
                Port
              </span>
              <input
                type="number"
                className="mt-1 w-full bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text font-mono focus:outline-none focus:border-db-teal"
                value={editing.port ?? 22}
                onChange={(e) =>
                  setEditing({ ...editing, port: Number(e.target.value) })
                }
              />
            </label>
            <label className="block">
              <span className="text-[10px] text-db-muted uppercase tracking-wider">
                Username
              </span>
              <input
                className="mt-1 w-full bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text focus:outline-none focus:border-db-teal"
                value={editing.username ?? ""}
                onChange={(e) =>
                  setEditing({ ...editing, username: e.target.value })
                }
              />
            </label>
            <label className="block">
              <span className="text-[10px] text-db-muted uppercase tracking-wider">
                Password
              </span>
              <input
                type="password"
                className="mt-1 w-full bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text font-mono focus:outline-none focus:border-db-teal"
                value={editing.password ?? ""}
                onChange={(e) =>
                  setEditing({ ...editing, password: e.target.value })
                }
              />
            </label>
            <label className="block">
              <span className="text-[10px] text-db-muted uppercase tracking-wider">
                Enable Password
              </span>
              <input
                type="password"
                className="mt-1 w-full bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text font-mono focus:outline-none focus:border-db-teal"
                value={editing.enable_password ?? ""}
                onChange={(e) =>
                  setEditing({
                    ...editing,
                    enable_password: e.target.value,
                  })
                }
              />
            </label>
            <label className="block">
              <span className="text-[10px] text-db-muted uppercase tracking-wider">
                SSH Key Path
              </span>
              <input
                className="mt-1 w-full bg-db-surface border border-db-border px-2 py-1.5 text-xs text-db-text font-mono focus:outline-none focus:border-db-teal"
                placeholder="~/.ssh/id_rsa"
                value={editing.key_path ?? ""}
                onChange={(e) =>
                  setEditing({ ...editing, key_path: e.target.value })
                }
              />
            </label>
          </div>
          <label className="flex items-center gap-2 mt-3">
            <input
              type="checkbox"
              checked={editing.enabled ?? true}
              onChange={(e) =>
                setEditing({ ...editing, enabled: e.target.checked })
              }
              className="accent-db-teal"
            />
            <span className="text-xs text-db-text">Enabled</span>
          </label>
          <div className="flex gap-2 mt-4">
            <Button size="sm" onClick={handleSave} disabled={upsert.isPending}>
              {upsert.isPending ? "Saving..." : "Save"}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setEditing(null)}
            >
              Cancel
            </Button>
          </div>
        </Card>
      )}
    </>
  );
}
