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
  summary?: string;
  weaknesses?: Weakness[];
  sectors?: string[];
  remediations?: Remediation[];
  first_seen?: string;
  last_seen?: string;
  kev?: boolean;
  kev_ransomware?: boolean;
  epss_score?: number;
  epss_percentile?: number;
  risk_score?: number;
}

export interface Weakness {
  id: string;
  name: string;
}

export interface Remediation {
  category: string;
  details: string;
  url?: string;
}

export type Confidence = "HIGH" | "MEDIUM" | "LOW";
export type Status = "VULNERABLE" | "POTENTIAL" | "OK";

export interface CheckAdvisory {
  id: string;
  cves: string[];
  cvss_v3: number;
  title: string;
  url: string;
  kev: boolean;
  kev_ransomware?: boolean;
  epss_score?: number;
  epss_percentile?: number;
  risk_score: number;
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

export interface EnrichmentStats {
  kev_count: number;
  kev_date: string;
  epss_count: number;
  epss_date: string;
  epss_version: string;
}

export interface ControlMapping {
  framework: string;
  control_id: string;
  control_name: string;
  capability: string;
  rationale: string;
}

export interface ComplianceMappingsResponse {
  frameworks: string[];
  mappings: ControlMapping[];
}

export type Criticality = "critical" | "high" | "medium" | "low" | "";

export interface Asset {
  id: string;
  ip: string;
  vendor: string;
  model: string;
  firmware: string;
  name: string;
  site: string;
  zone: string;
  criticality: Criticality;
  tags: string[];
  notes: string;
  first_seen: string;
  last_seen: string;
  source: string;
}

export interface AssetListResponse {
  total: number;
  assets: Asset[];
  sites: string[];
  zones: string[];
  tags: string[];
}

export interface AssetImportResult {
  added: number;
  updated: number;
  total: number;
}

export interface DiscoverJob {
  job_id: string;
  status: "running" | "complete" | "error";
  error?: string;
  devices?: Device[];
  check_results?: CheckResponse;
  progress?: string[];
}
