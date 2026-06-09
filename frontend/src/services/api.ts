import type {
  StatsResponse,
  TemplateListResponse,
  TemplateDetail,
  Asset,
  HostEntry,
  ICPResult,
  VulnResult,
  VulnerabilityListResponse,
  TaskListResponse,
  ScanTask,
  ScanTriggerRequest,
  ScanTriggerResponse,
  ScanLog,
  ICPQueryResponse,
  ConfigData,
} from '../types';

const API_BASE = '/api';

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

// System
export const getHealth = () => fetchJSON<{ status: string }>('/health');
export const getStats = () => fetchJSON<StatsResponse>('/stats');
export const getSeverity = () => fetchJSON<Record<string, number>>('/severity');

// Templates
export const getTemplates = (
  params: Record<string, string | number> = {}
) => {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v) qs.set(k, String(v)); });
  return fetchJSON<TemplateListResponse>(`/templates?${qs}`);
};

export const getTemplateDetail = (id: string) =>
  fetchJSON<TemplateDetail>(`/templates/${id}`);

export const getTemplateUrls = (id: string, taskId?: string) =>
  fetchJSON<Asset[]>(`/templates/${id}/urls${taskId ? `?task_id=${taskId}` : ''}`);

export const getTemplateDomains = (id: string, taskId?: string) =>
  fetchJSON<HostEntry[]>(`/templates/${id}/domains${taskId ? `?task_id=${taskId}` : ''}`);

export const getTemplateICP = (id: string, taskId?: string) =>
  fetchJSON<ICPResult[]>(`/templates/${id}/icp${taskId ? `?task_id=${taskId}` : ''}`);

export const getTemplateVulns = (id: string, taskId?: string) =>
  fetchJSON<VulnResult[]>(`/templates/${id}/vulns${taskId ? `?task_id=${taskId}` : ''}`);

// Tasks
export const getTasks = (limit = 20, offset = 0) =>
  fetchJSON<TaskListResponse>(`/tasks?limit=${limit}&offset=${offset}`);

// Scans
export const triggerScan = (data: ScanTriggerRequest) =>
  fetchJSON<ScanTriggerResponse>('/scans', {
    method: 'POST',
    body: JSON.stringify(data),
  });

export const getScanStatus = (taskId: string) =>
  fetchJSON<ScanTask>(`/scans/${taskId}`);

export const getScanLogs = (taskId: string, since = 0, limit = 200) =>
  fetchJSON<ScanLog[]>(`/scans/${taskId}/logs?since=${since}&limit=${limit}`);

export const stopScan = (taskId: string) =>
  fetchJSON<{ task_id: string; status: string }>(`/scans/${taskId}/stop`, {
    method: 'POST',
  });

export const resumeScan = (taskId: string) =>
  fetchJSON<{ task_id: string; status: string }>(`/scans/${taskId}/resume`, {
    method: 'POST',
  });

export const deleteScanLogs = (taskId: string) =>
  fetchJSON<{ task_id: string; deleted: number }>(`/scans/${taskId}/logs`, {
    method: 'DELETE',
  });

export const deleteScanTask = (taskId: string) =>
  fetchJSON<{ task_id: string; deleted: Record<string, number> }>(`/scans/${taskId}`, {
    method: 'DELETE',
  });

// ICP
export const queryICP = (search: string) =>
  fetchJSON<ICPQueryResponse>('/icp/query', {
    method: 'POST',
    body: JSON.stringify({ search }),
  });

// Vulnerabilities
export const getVulnerabilities = (
  params: Record<string, string | number> = {}
) => {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v) qs.set(k, String(v)); });
  return fetchJSON<VulnerabilityListResponse>(`/vulnerabilities?${qs}`);
};

export const getVulnerabilitiesExport = (
  params: Record<string, string> = {}
) => {
  const qs = new URLSearchParams(params);
  return `${API_BASE}/vulnerabilities/export?${qs}`;
};

// Config
export const getConfig = (source: 'env' | 'local' = 'env') =>
  fetchJSON<ConfigData>(`/config?source=${source}`);

export const updateConfig = (content: string, source: 'env' | 'local' = 'env') =>
  fetchJSON<{ path: string; saved: boolean; backup: string; source: string }>(`/config?source=${source}`, {
    method: 'PUT',
    body: JSON.stringify({ content }),
  });

// Proxy Pool
export const getProxyStatus = () =>
  fetchJSON<import('../types').ProxyStatusResponse>('/proxy/status');

export const testProxy = (url: string) =>
  fetchJSON<import('../types').ProxyTestResponse>('/proxy/test', {
    method: 'POST',
    body: JSON.stringify({ url }),
  });

export const addProxy = (url: string) =>
  fetchJSON<{ message: string; url: string; total: number }>('/proxy/add', {
    method: 'POST',
    body: JSON.stringify({ url }),
  });

export const removeProxy = (url: string) =>
  fetchJSON<{ message: string; url: string; total: number }>('/proxy/remove', {
    method: 'DELETE',
    body: JSON.stringify({ url }),
  });

export const updateProxyToggles = (toggles: Record<string, boolean | null>) =>
  fetchJSON<{ message: string; toggles: Record<string, string> }>('/proxy/toggle', {
    method: 'PUT',
    body: JSON.stringify(toggles),
  });

export const batchTestProxies = (urls: string[]) =>
  fetchJSON<import('../types').ProxyBatchTestResponse>('/proxy/batch-test', {
    method: 'POST',
    body: JSON.stringify({ urls }),
  });

export const batchAddProxies = (urls: string[], testBeforeAdd: boolean = false) =>
  fetchJSON<import('../types').ProxyBatchAddResponse>('/proxy/batch-add', {
    method: 'POST',
    body: JSON.stringify({ urls, test_before_add: testBeforeAdd }),
  });
