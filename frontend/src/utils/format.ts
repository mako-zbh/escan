export function formatDateTime(iso: string | null): string {
  if (!iso) return '-';
  const d = new Date(iso);
  return d.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function formatShortDate(iso: string | null): string {
  if (!iso) return '-';
  const d = new Date(iso);
  return d.toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function truncate(str: string, len = 60): string {
  if (!str) return '';
  return str.length > len ? str.slice(0, len) + '...' : str;
}

export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function severityBadgeClass(severity: string | null): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'badge-critical';
    case 'high': return 'badge-high';
    case 'medium': return 'badge-medium';
    case 'low': return 'badge-low';
    case 'info': return 'badge-info';
    default: return 'badge-default';
  }
}

export function severityColor(severity: string | null): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return '#dc2626';
    case 'high': return '#ea580c';
    case 'medium': return '#ca8a04';
    case 'low': return '#2563eb';
    case 'info': return '#6b7280';
    default: return '#9ca3af';
  }
}
