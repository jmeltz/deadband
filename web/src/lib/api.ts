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
    request<import("./types").DiscoverJob>(`/api/discover/${id}`),

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
