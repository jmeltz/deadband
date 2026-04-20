const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "";

class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new ApiError(res.status, body.error || res.statusText);
  }

  return res.json();
}

export const api = {
  health: () => request<import("./types").HealthResponse>("/api/health"),

  dbStats: () => request<import("./types").DbStats>("/api/db/stats"),

  advisories: (params?: {
    page?: number;
    per_page?: number;
    vendor?: string;
    min_cvss?: number;
    q?: string;
    sort?: string;
  }) => {
    const search = new URLSearchParams();
    if (params?.page) search.set("page", String(params.page));
    if (params?.per_page) search.set("per_page", String(params.per_page));
    if (params?.vendor) search.set("vendor", params.vendor);
    if (params?.min_cvss) search.set("min_cvss", String(params.min_cvss));
    if (params?.q) search.set("q", params.q);
    if (params?.sort) search.set("sort", params.sort);
    return request<import("./types").AdvisoryListResponse>(
      `/api/advisories?${search}`,
    );
  },

  advisory: (id: string) =>
    request<import("./types").Advisory>(`/api/advisories/${id}`),

  check: (body: {
    devices: import("./types").Device[];
    min_confidence?: string;
    min_cvss?: number;
    vendor?: string;
  }) =>
    request<import("./types").CheckResponse>("/api/check", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  checkUpload: async (file: File, opts?: { format?: string; min_confidence?: string; min_cvss?: number; vendor?: string }) => {
    const form = new FormData();
    form.append("file", file);
    if (opts?.format) form.append("format", opts.format);
    if (opts?.min_confidence) form.append("min_confidence", opts.min_confidence);
    if (opts?.min_cvss) form.append("min_cvss", String(opts.min_cvss));
    if (opts?.vendor) form.append("vendor", opts.vendor);

    const res = await fetch(`${BASE_URL}/api/check/upload`, {
      method: "POST",
      body: form,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: res.statusText }));
      throw new ApiError(res.status, body.error || res.statusText);
    }
    return res.json() as Promise<import("./types").CheckResponse>;
  },

  discover: (body: {
    cidr: string;
    mode?: string;
    timeout_ms?: number;
    concurrency?: number;
    auto_check?: boolean;
  }) =>
    request<{ job_id: string; status: string }>("/api/discover", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  discoverStatus: (id: string) =>
    request<import("./types").DiscoverJob>(`/api/discover/jobs/${id}`),

  diff: (body: {
    base_devices: import("./types").Device[];
    compare_devices: import("./types").Device[];
    min_confidence?: string;
    min_cvss?: number;
    vendor?: string;
  }) =>
    request<import("./types").DiffResponse>("/api/diff", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  diffUpload: async (baseFile: File, compareFile: File) => {
    const form = new FormData();
    form.append("base", baseFile);
    form.append("compare", compareFile);
    const res = await fetch(`${BASE_URL}/api/diff/upload`, {
      method: "POST",
      body: form,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: res.statusText }));
      throw new ApiError(res.status, body.error || res.statusText);
    }
    return res.json() as Promise<import("./types").DiffResponse>;
  },

  update: (body?: { since?: string; source?: string }) =>
    request<{ status: string }>("/api/update", {
      method: "POST",
      body: JSON.stringify(body || {}),
    }),

  enrichmentStats: () =>
    request<import("./types").EnrichmentStats>("/api/enrichment/stats"),

  assets: (params?: {
    vendor?: string;
    site?: string;
    zone?: string;
    criticality?: string;
    tag?: string;
    q?: string;
    sort?: string;
    status?: string;
    vuln_status?: string;
    cve?: string;
  }) => {
    const search = new URLSearchParams();
    if (params?.vendor) search.set("vendor", params.vendor);
    if (params?.site) search.set("site", params.site);
    if (params?.zone) search.set("zone", params.zone);
    if (params?.criticality) search.set("criticality", params.criticality);
    if (params?.tag) search.set("tag", params.tag);
    if (params?.q) search.set("q", params.q);
    if (params?.sort) search.set("sort", params.sort);
    if (params?.status) search.set("status", params.status);
    if (params?.vuln_status) search.set("vuln_status", params.vuln_status);
    if (params?.cve) search.set("cve", params.cve);
    return request<import("./types").AssetListResponse>(
      `/api/assets?${search}`,
    );
  },

  getAsset: (id: string) =>
    request<import("./types").Asset>(`/api/assets/${id}`),

  checkAssets: (body: {
    ids?: string[];
    site?: string;
    zone?: string;
    criticality?: string;
  }) =>
    request<import("./types").CheckAssetsResponse>("/api/assets/check", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  importAssets: (body: {
    devices: import("./types").Device[];
    source?: string;
  }) =>
    request<import("./types").AssetImportResult>("/api/assets", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  updateAsset: (id: string, patch: Partial<import("./types").Asset>) =>
    request<import("./types").Asset>(`/api/assets/${id}`, {
      method: "PUT",
      body: JSON.stringify(patch),
    }),

  deleteAsset: (id: string) =>
    request<{ status: string }>(`/api/assets/${id}`, {
      method: "DELETE",
    }),

  bulkUpdateAssets: (body: {
    ids: string[];
    add_tags?: string[];
    remove_tags?: string[];
    set_site?: string;
    set_zone?: string;
    set_criticality?: string;
  }) =>
    request<{ updated: number }>("/api/assets/bulk", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  assetSummary: () =>
    request<import("./types").AssetSummary>("/api/assets/summary"),

  assetExportUrl: (format: "csv" | "json" | "dbd" = "csv") =>
    `${BASE_URL}/api/assets/export?format=${format}`,

  importDBD: async (file: File) => {
    const res = await fetch(`${BASE_URL}/api/assets/import/dbd`, {
      method: "POST",
      body: file,
      headers: { "Content-Type": "text/csv" },
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: res.statusText }));
      throw new ApiError(res.status, body.error || res.statusText);
    }
    return res.json() as Promise<import("./types").DBDImportResult>;
  },

  // Sites
  getSites: () =>
    request<import("./types").Site[]>("/api/sites"),

  getSite: (id: string) =>
    request<import("./types").Site>(`/api/sites/${id}`),

  upsertSite: (body: Partial<import("./types").Site>) =>
    request<import("./types").Site>("/api/sites", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  deleteSite: (id: string) =>
    request<{ status: string }>(`/api/sites/${id}`, {
      method: "DELETE",
    }),

  reassignSites: () =>
    request<{ reassigned: number }>("/api/sites/reassign", {
      method: "POST",
    }),

  // Zones
  getZones: (siteId: string) =>
    request<import("./types").Zone[]>(`/api/sites/${siteId}/zones`),

  upsertZone: (siteId: string, zone: Partial<import("./types").Zone>) =>
    request<import("./types").Zone>(`/api/sites/${siteId}/zones`, {
      method: "POST",
      body: JSON.stringify(zone),
    }),

  deleteZone: (siteId: string, zoneId: string) =>
    request<{ status: string }>(`/api/sites/${siteId}/zones/${zoneId}`, {
      method: "DELETE",
    }),

  discoverHistory: () =>
    request<import("./types").JobRecord[]>("/api/discover/history"),

  discoverHistoryDetail: (id: string) =>
    request<import("./types").JobRecord>(`/api/discover/history/${id}`),

  getSchedules: () =>
    request<import("./types").DiscoverSchedule[]>("/api/discover/schedules"),

  createSchedule: (body: Partial<import("./types").DiscoverSchedule>) =>
    request<import("./types").DiscoverSchedule>("/api/discover/schedule", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  deleteSchedule: (id: string) =>
    request<{ status: string }>(`/api/discover/schedule/${id}`, {
      method: "DELETE",
    }),

  // Posture
  getPosture: () =>
    request<import("./types").PostureReport>("/api/posture"),

  getPostureReports: () =>
    request<import("./types").PostureReportSummary[]>("/api/posture/reports"),

  getPostureReport: (id: string) =>
    request<import("./types").PostureReport>(`/api/posture/reports/${id}`),

  getPostureFindings: (severity?: string) => {
    const search = new URLSearchParams();
    if (severity) search.set("severity", severity);
    return request<import("./types").PostureFinding[]>(
      `/api/posture/findings?${search}`,
    );
  },

  getPostureControls: () =>
    request<Record<string, import("./types").RecommendedControl[]>>("/api/posture/controls"),

  getPostureHost: (ip: string) =>
    request<import("./types").HostPostureDetail>(`/api/posture/host/${ip}`),

  complianceMappings: (framework?: string) => {
    const search = new URLSearchParams();
    if (framework) search.set("framework", framework);
    return request<import("./types").ComplianceMappingsResponse>(
      `/api/compliance/mappings?${search}`,
    );
  },

  // Control states + risk simulation
  getControlStates: () =>
    request<import("./types").ControlState[]>("/api/posture/control-states"),

  setControlState: (body: {
    finding_type: string;
    control_id: string;
    status: string;
    notes?: string;
  }) =>
    request<import("./types").ControlState[]>("/api/posture/control-states", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  simulateRisk: (subnet?: string) =>
    request<import("./types").WhatIfResult>("/api/posture/simulate", {
      method: "POST",
      body: JSON.stringify({ subnet: subnet || "" }),
    }),

  // ACL policies
  getPolicies: () =>
    request<import("./types").Policy[]>("/api/acl/policies"),

  upsertPolicy: (body: Partial<import("./types").Policy>) =>
    request<import("./types").Policy>("/api/acl/policies", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  deletePolicy: (id: string) =>
    request<{ status: string }>(`/api/acl/policies/${id}`, {
      method: "DELETE",
    }),

  generateDefaultPolicy: (siteId: string) =>
    request<import("./types").Policy>("/api/acl/policies/generate", {
      method: "POST",
      body: JSON.stringify({ site_id: siteId }),
    }),

  analyzeGaps: (policyId: string, opts?: { includeFlows?: boolean; includeAsa?: boolean }) => {
    const search = new URLSearchParams();
    if (opts?.includeFlows) search.set("include_flows", "true");
    if (opts?.includeAsa) search.set("include_asa", "true");
    const qs = search.toString();
    return request<import("./types").Violation[]>(
      `/api/acl/policies/${policyId}/analyze${qs ? `?${qs}` : ""}`,
      { method: "POST" },
    );
  },

  simulatePolicy: (body: {
    site_id: string;
    policy_id: string;
    planned_policy: import("./types").Policy;
    flow_window?: "24h" | "7d" | "30d";
    include_observed?: boolean;
    include_implied?: boolean;
  }) =>
    request<import("./types").SimulationResponse>("/api/acl/simulate", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // Integrations — Sentinel
  getSentinelConfigs: () =>
    request<import("./types").SentinelConfig[]>("/api/integrations/sentinel"),

  upsertSentinelConfig: (body: Partial<import("./types").SentinelConfig>) =>
    request<import("./types").SentinelConfig>("/api/integrations/sentinel", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  deleteSentinelConfig: (id: string) =>
    request<{ status: string }>(`/api/integrations/sentinel/${id}`, {
      method: "DELETE",
    }),

  testSentinelConfig: (id: string) =>
    request<{ status: string; error?: string }>(
      `/api/integrations/sentinel/${id}/test`,
      { method: "POST" },
    ),

  querySentinel: (id: string) =>
    request<{ status: string }>(`/api/integrations/sentinel/${id}/query`, {
      method: "POST",
    }),

  // Integrations — ASA
  getASAConfigs: () =>
    request<import("./types").ASAConfig[]>("/api/integrations/asa"),

  upsertASAConfig: (body: Partial<import("./types").ASAConfig>) =>
    request<import("./types").ASAConfig>("/api/integrations/asa", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  deleteASAConfig: (id: string) =>
    request<{ status: string }>(`/api/integrations/asa/${id}`, {
      method: "DELETE",
    }),

  testASAConfig: (id: string) =>
    request<{ status: string; error?: string }>(
      `/api/integrations/asa/${id}/test`,
      { method: "POST" },
    ),

  collectASA: (id: string) =>
    request<{ status: string }>(`/api/integrations/asa/${id}/collect`, {
      method: "POST",
    }),

  // Sentinel data views
  getSentinelSnapshots: (siteId?: string) => {
    const search = new URLSearchParams();
    if (siteId) search.set("site_id", siteId);
    return request<import("./types").SentinelSnapshot[]>(
      `/api/sentinel/snapshots?${search}`,
    );
  },

  getSentinelSnapshot: (id: string) =>
    request<import("./types").SentinelSnapshot>(`/api/sentinel/snapshots/${id}`),

  getTrafficSummary: (siteId: string) =>
    request<import("./types").ZoneTrafficSummary[]>(
      `/api/sentinel/traffic-summary?site_id=${siteId}`,
    ),

  getScopingRecommendations: (policyId: string) =>
    request<import("./types").ScopingRecommendation[]>(
      "/api/sentinel/scoping",
      { method: "POST", body: JSON.stringify({ policy_id: policyId }) },
    ),

  // ASA data views
  getASASnapshots: (siteId?: string) => {
    const search = new URLSearchParams();
    if (siteId) search.set("site_id", siteId);
    return request<import("./types").ASASnapshot[]>(
      `/api/asa/snapshots?${search}`,
    );
  },

  getASASnapshot: (id: string) =>
    request<import("./types").ASASnapshot>(`/api/asa/snapshots/${id}`),

  analyzeDrift: (policyId: string, snapshotId?: string) =>
    request<import("./types").PolicyDrift[]>("/api/asa/drift", {
      method: "POST",
      body: JSON.stringify({ policy_id: policyId, snapshot_id: snapshotId }),
    }),
};

export function sseStream(
  path: string,
  onMessage: (data: string) => void,
  onDone?: () => void,
): () => void {
  const es = new EventSource(`${BASE_URL}${path}`);
  es.onmessage = (e) => {
    onMessage(e.data);
  };
  es.onerror = () => {
    es.close();
    onDone?.();
  };
  return () => es.close();
}
