export interface Device {
  ip: string;
  vendor: string;
  model: string;
  firmware: string;
}

export interface Advisory {
  id: string;
  title: string;
  vendor: string;
  products: string[];
  affected_versions: string[];
  cvss_v3_max: number;
  cves: string[];
  url: string;
  published: string;
  first_seen?: string;
  last_seen?: string;
}

export type Confidence = "HIGH" | "MEDIUM" | "LOW";
export type Status = "VULNERABLE" | "POTENTIAL" | "OK";

export interface CheckAdvisory {
  id: string;
  cves: string[];
  cvss_v3: number;
  title: string;
  url: string;
}

export interface CheckDeviceResult {
  ip: string;
  vendor: string;
  model: string;
  firmware: string;
  status: Status;
  confidence: Confidence;
  advisories: CheckAdvisory[];
}

export interface CheckSummary {
  vulnerable: number;
  potential: number;
  ok: number;
  no_match: number;
}

export interface CheckResponse {
  checked_at: string;
  db_updated: string;
  devices_checked: number;
  results: CheckDeviceResult[];
  summary: CheckSummary;
}

export interface DiffDevice {
  ip: string;
  vendor: string;
  model: string;
  firmware: string;
}

export interface DiffFWChange {
  ip: string;
  vendor: string;
  model: string;
  old_firmware: string;
  new_firmware: string;
}

export interface DiffNewVuln {
  ip: string;
  model: string;
  firmware: string;
  advisories: CheckAdvisory[];
}

export interface DiffSummary {
  new_devices: number;
  removed_devices: number;
  firmware_changes: number;
  new_vulnerabilities: number;
}

export interface DiffResponse {
  compared_at: string;
  summary: DiffSummary;
  new_devices: DiffDevice[];
  removed_devices: DiffDevice[];
  firmware_changes: DiffFWChange[];
  new_vulnerabilities: DiffNewVuln[];
}

export interface DbStats {
  advisory_count: number;
  updated: string;
  source: string;
  previous_updated: string | null;
  added_since_last: number;
  chronic_count: number;
  vendors: Record<string, number>;
}

export interface AdvisoryListResponse {
  total: number;
  page: number;
  per_page: number;
  advisories: Advisory[];
}

export interface HealthResponse {
  status: string;
  version: string;
  db_loaded: boolean;
}

export interface DiscoverJob {
  job_id: string;
  status: "running" | "complete" | "error";
  error?: string;
  devices?: Device[];
  check_results?: CheckResponse;
  progress?: string[];
}
