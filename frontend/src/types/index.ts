export interface ScanTask {
  task_id: string;
  task_type: string;
  engine: string;
  status: 'running' | 'completed' | 'stopped' | 'failed';
  current_step: number;
  step1_assets: number;
  step2_vulns: number;
  step3_hosts: number;
  step4_icp: number;
  output_dir: string | null;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
}

export interface StatsResponse {
  template_count: number;
  task_count: number;
  asset_count: number;
  vuln_count: number;
  host_count: number;
  icp_count: number;
  cache_count: number;
  active_cache_count: number;
  schema_version: number;
  severity_dist: Record<string, number>;
  recent_tasks: Record<string, unknown>[];
}

export interface TemplateItem {
  template_id: string;
  name: string;
  severity: string | null;
  fofa_query: string | null;
  file_path: string | null;
  created_at: string | null;
  updated_at: string | null;
  asset_count: number;
  hit_count: number;
  domain_count: number;
  icp_count: number;
}

export interface TemplateListResponse {
  items: TemplateItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface TemplateDetail {
  template_id: string;
  name: string;
  severity: string | null;
  tags: string | null;
  fofa_query: string | null;
  file_path: string | null;
  api_truncated: boolean;
  created_at: string | null;
  updated_at: string | null;
  tasks: ScanTask[];
  icp_summary: {
    ips_queried: number;
    ips_with_data: number;
    domains_found: number;
    domains_with_icp: number;
    icp_api_supplement: number;
  };
}

export interface Asset {
  asset_id: string;
  task_id: string;
  url: string;
  host: string | null;
  port: number | null;
  scheme: string | null;
  title: string | null;
  engine: string | null;
  discovered_at: string | null;
  icp_number: string | null;
  icp_company: string | null;
  icp_domain: string | null;
}

export interface HostEntry {
  host_result_id: string;
  task_id: string;
  template_name: string;
  host: string;
  is_ip: boolean;
  extracted_at: string | null;
}

export interface ICPResult {
  icp_result_id: string;
  task_id: string;
  ip_address: string | null;
  domain: string | null;
  icp_number: string | null;
  source: string | null;
  company: string | null;
  queried_at: string | null;
  asset_id: string | null;
}

export interface VulnResult {
  result_id: string;
  task_id: string;
  protocol: string | null;
  severity: string | null;
  matched_url: string;
  raw_line: string | null;
  scanned_at: string | null;
}

export interface VulnerabilityItem {
  vuln_name: string | null;
  severity: string | null;
  asset: string | null;
  scanned_at: string | null;
  icp_domain: string | null;
  icp_number: string | null;
  icp_company: string | null;
}

export interface VulnerabilityListResponse {
  items: VulnerabilityItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface ScanLog {
  id: number;
  task_id: string;
  step: number | null;
  level: string;
  message: string;
  created_at: string | null;
}

export interface TaskListResponse {
  items: ScanTask[];
  total: number;
}

export interface ScanTriggerRequest {
  type: 'categorized' | 'categorized-incremental';
  engine: 'fofa' | 'hunter';
  poc?: string;
  region?: string;
}

export interface ScanTriggerResponse {
  task_id: string;
  status: string;
}

export interface ICPQueryRequest {
  search: string;
}

export interface ICPQueryResponse {
  items: Record<string, unknown>[];
  total: number;
  search: string;
}

export interface ConfigData {
  path: string;
  content: string;
}

export interface SSEProgressEvent {
  step: number | null;
  message: string;
  current: number | null;
  total: number | null;
}

export interface SSELogEvent {
  id: number;
  step: number | null;
  level: string;
  message: string;
  created_at: string | null;
}
