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

export interface AssetVulnAdvisory {
  id: string;
  title: string;
  cves: string[];
  cvss_v3: number;
  kev: boolean;
  risk_score: number;
}

export interface AssetVulnState {
  checked_at: string;
  status: "VULNERABLE" | "POTENTIAL" | "OK";
  confidence: string;
  risk_score: number;
  advisories: AssetVulnAdvisory[];
  cve_count: number;
  kev_count: number;
}

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
  // Hardware identity
  serial?: string;
  mac?: string;
  hostname?: string;
  order_number?: string;
  protocol?: string;
  port?: number;
  slot?: number;
  // Lifecycle
  status: string;
  // Vulnerability state
  vuln_state?: AssetVulnState;
}

export interface CheckAssetsResponse {
  checked: number;
  vulnerable: number;
  potential: number;
  ok: number;
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

export interface JobRecord {
  id: string;
  cidr: string;
  mode: string;
  status: string;
  error?: string;
  started_at: string;
  completed_at?: string;
  device_count: number;
  new_count: number;
  updated_count: number;
  duration?: string;
}

export interface DiscoverSchedule {
  id: string;
  cidr: string;
  mode: string;
  interval: string;
  auto_check: boolean;
  enabled: boolean;
  last_run?: string;
  next_run?: string;
}

export type ZonePurpose = "ot" | "it" | "dmz" | "corporate" | "safety";

export interface Zone {
  id: string;
  name: string;
  cidrs: string[];
  purpose: ZonePurpose;
  security_level: number; // IEC 62443 SL-T: 0-4
  description?: string;
}

export interface Site {
  id: string;
  name: string;
  cidrs: string[];
  zones?: Zone[];
  description?: string;
  location?: string;
  contact?: string;
  created_at: string;
  updated_at: string;
}

export interface DBDImportResult {
  sites_imported: number;
  assets_added: number;
  assets_updated: number;
  total_assets: number;
  posture_imported: number;
}

// --- Posture Analysis ---

export type DeviceClass = "ot" | "it" | "network" | "unknown";

export interface BannerResult {
  port: number;
  proto: string;
  banner: string;
  product?: string;
  version?: string;
}

export interface ClassifiedHost {
  ip: string;
  device_class: DeviceClass;
  open_ports: number[];
  services: string[];
  asset_id?: string;
  asset_name?: string;
  vendor?: string;
  model?: string;
  hostname?: string;
  os_guess?: string;
  presumption?: string;
  banners?: BannerResult[];
}

export interface SubnetAnalysis {
  subnet: string;
  total_hosts: number;
  ot_count: number;
  it_count: number;
  network_count: number;
  unknown_count: number;
  hosts: ClassifiedHost[];
  is_pure_ot: boolean;
  is_mixed: boolean;
  risk_score: number;
  zone?: string;
  zone_purpose?: string;
}

export interface RecommendedControl {
  framework: string;
  control_id: string;
  control_name: string;
  recommendation: string;
  priority: string;
}

export interface PostureFinding {
  id: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  subnet: string;
  title: string;
  description: string;
  evidence: string[];
  controls: RecommendedControl[];
}

export interface PostureSummary {
  total_hosts: number;
  ot_hosts: number;
  it_hosts: number;
  network_hosts: number;
  unknown_hosts: number;
  subnets_scanned: number;
  mixed_subnets: number;
  finding_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  overall_score: number;
}

export interface PostureReport {
  id: string;
  cidr: string;
  scanned_at: string;
  duration: string;
  subnets: SubnetAnalysis[];
  findings: PostureFinding[];
  summary: PostureSummary;
}

export interface PostureReportSummary {
  id: string;
  cidr: string;
  scanned_at: string;
  duration: string;
  summary: PostureSummary;
}

export interface SiteSummary {
  total: number;
  vulnerable: number;
}

export interface CVECount {
  cve: string;
  affected_assets: number;
}

export interface HostPostureDetail {
  host: ClassifiedHost;
  findings: PostureFinding[];
  subnet: SubnetAnalysis;
}

export interface AssetSummary {
  total_assets: number;
  by_status: Record<string, number>;
  by_criticality: Record<string, number>;
  by_vuln_status: Record<string, number>;
  by_site: Record<string, SiteSummary>;
  top_cves: CVECount[];
  kev_affected_assets: number;
  stale_assets: number;
  last_check?: string;
}

// --- Controls Modeling ---

export type ControlStatus = "applied" | "planned" | "not_applicable";

export interface ControlState {
  finding_type: string;
  control_id: string;
  status: ControlStatus;
  notes?: string;
  updated_at: string;
}

export interface RiskReduction {
  control_id: string;
  factor: number;
}

export interface WhatIfResult {
  original_score: number;
  simulated_score: number;
  delta: number;
  applied: string[];
  planned: string[];
  planned_score: number;
  planned_delta: number;
  reductions: RiskReduction[];
}

// --- ACL Policy Modeling ---

export interface PolicyRule {
  id: string;
  source_zone: string;
  dest_zone: string;
  ports: number[];
  action: "allow" | "deny";
  description?: string;
}

export interface Policy {
  id: string;
  site_id: string;
  name: string;
  rules: PolicyRule[];
  default_action: "deny" | "allow";
  created_at: string;
  updated_at: string;
}

export interface ViolatorHost {
  ip: string;
  hostname?: string;
  port: number;
  source_zone: string;
  dest_zone: string;
}

export interface Violation {
  rule: PolicyRule;
  violators: ViolatorHost[];
  severity: string;
  description: string;
  active_flows?: number;
  flow_identities?: FlowIdentity[];
}

export interface FlowIdentity {
  user_name: string;
  department: string;
  flow_count: number;
}

// --- Integration Configs ---

export interface SentinelConfig {
  id: string;
  site_id: string;
  name: string;
  tenant_id: string;
  client_id: string;
  client_secret: string;
  workspace_id: string;
  default_query?: string;
  enabled: boolean;
  last_query_at?: string;
}

export interface ASAConfig {
  id: string;
  site_id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  password: string;
  key_path?: string;
  enable_password?: string;
  enabled: boolean;
  last_collect_at?: string;
}

// --- Sentinel Flow Data ---

export interface FlowRecord {
  observed_at: string;
  ingested_at: string;
  source_addr: string;
  dest_addr: string;
  dest_port: number;
  protocol: string;
  source_zone: string;
  dest_zone: string;
  connection_count: number;
  action: string;
  kind: "observed" | "implied" | string;
  source_id: string;
  source_hash: string;
  enrichment?: Record<string, string>;
}

/** @deprecated use FlowRecord */
export type SentinelFlow = FlowRecord;

export interface SentinelSnapshot {
  id: string;
  site_id: string;
  config_id: string;
  queried_at: string;
  flow_count: number;
  flows: FlowRecord[];
}

// --- ACL simulation ---

export interface FlowVerdict {
  flow: FlowRecord;
  matched_rule_id: string;
  action: "permit" | "deny" | string;
  reason: string;
}

export interface DiffSummary {
  total: number;
  permit: number;
  deny: number;
  implied: number;
}

export interface ZoneCount {
  source_zone: string;
  dest_zone: string;
  count: number;
}

export interface UnchangedAggregate {
  count: number;
  by_zone: ZoneCount[];
}

export interface DiffResult {
  newly_denied: FlowVerdict[];
  newly_allowed: FlowVerdict[];
  unchanged: UnchangedAggregate;
}

export interface SimulationResponse {
  current: DiffSummary;
  planned: DiffSummary;
  diff: DiffResult;
}

export interface ZoneTrafficSummary {
  source_zone: string;
  dest_zone: string;
  flow_count: number;
  unique_ips: number;
  top_ports: number[];
  has_identity: boolean;
}

export interface SuggestedRule {
  source_cidr: string;
  dest_cidr: string;
  ports: number[];
  flow_count: number;
  description: string;
}

export interface ScopingRecommendation {
  original_rule: PolicyRule;
  suggested_rules: SuggestedRule[];
  reduction_percent: number;
  active_impact: boolean;
}

// --- ASA Data ---

export interface ASAACLRule {
  name: string;
  line: number;
  action: string;
  protocol: string;
  source_addr: string;
  source_mask?: string;
  dest_addr: string;
  dest_mask?: string;
  dest_port?: string;
  port_op?: string;
  port_end?: string;
  object_group?: string;
  hit_count: number;
  logging: boolean;
}

export interface ASAInterface {
  name: string;
  nameif: string;
  ip: string;
  mask: string;
  security_level: number;
}

export interface ASAConnection {
  protocol: string;
  source_ip: string;
  source_port: number;
  dest_ip: string;
  dest_port: number;
  flags?: string;
  idle_time?: string;
}

export interface ASARoute {
  interface: string;
  destination: string;
  mask: string;
  gateway: string;
  metric: number;
}

export interface ASANATRule {
  section: string;
  interface: string;
  real_source: string;
  mapped_source: string;
  real_dest?: string;
  mapped_dest?: string;
}

export interface ASACollectionResult {
  interfaces: ASAInterface[];
  acl_rules: ASAACLRule[];
  connections: ASAConnection[];
  routes: ASARoute[];
  nat_rules: ASANATRule[];
  object_groups: { type: string; name: string; members: string[] }[];
  access_groups: { acl_name: string; interface: string; direction: string }[];
  version?: string;
}

export interface ASASnapshot {
  id: string;
  site_id: string;
  config_id: string;
  collected_at: string;
  duration: string;
  result: ASACollectionResult;
}

export interface PolicyDrift {
  policy_rule: PolicyRule;
  asa_rules: ASAACLRule[];
  drift_type: "missing" | "extra" | "mismatch";
  description: string;
  severity: string;
}
