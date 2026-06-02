import { useEffect, useState, useCallback } from 'react';
import { getVulnerabilities, getVulnerabilitiesExport } from '../services/api';
import FilterBar from '../components/FilterBar';
import Pagination from '../components/Pagination';
import { severityBadgeClass, formatDateTime } from '../utils/format';
import type { VulnerabilityItem } from '../types';

const PAGE_SIZE = 40;

export default function Vulnerabilities() {
  const [items, setItems] = useState<VulnerabilityItem[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [hasIcp, setHasIcp] = useState('');
  const [loading, setLoading] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getVulnerabilities({ limit: PAGE_SIZE, offset, search, severity, has_icp: hasIcp });
      setItems(res.items);
      setTotal(res.total);
    } finally {
      setLoading(false);
    }
  }, [offset, search, severity, hasIcp]);

  useEffect(() => { fetchData(); }, [fetchData]);

  return (
    <div>
      <div className="page-header">
        <h2>漏洞概览</h2>
        <a
          href={getVulnerabilitiesExport({ severity, search, has_icp: hasIcp })}
          className="btn btn-primary"
          target="_blank"
          rel="noopener"
        >
          导出 CSV
        </a>
      </div>

      <FilterBar
        search={search}
        severity={severity}
        hasIcp={hasIcp}
        onSearchChange={v => { setSearch(v); setOffset(0); }}
        onSeverityChange={v => { setSeverity(v); setOffset(0); }}
        onHasIcpChange={v => { setHasIcp(v); setOffset(0); }}
      />

      <div className="scroll-table">
        <table className="table">
          <thead>
            <tr>
              <th>漏洞名称</th>
              <th>级别</th>
              <th>资产 URL</th>
              <th>ICP 域名</th>
              <th>备案号</th>
              <th>备案主体</th>
              <th>扫描时间</th>
            </tr>
          </thead>
          <tbody>
            {loading && <tr><td colSpan={7} className="text-muted">加载中...</td></tr>}
            {!loading && items.length === 0 && <tr><td colSpan={7} className="text-muted">暂无数据</td></tr>}
            {items.map((v, i) => (
              <tr key={i}>
                <td className="fw-500">{v.vuln_name || '-'}</td>
                <td><span className={`badge ${severityBadgeClass(v.severity)}`}>{v.severity || '-'}</span></td>
                <td className="fw-mono" title={v.asset ?? ''}>{(v.asset || '').length > 60 ? (v.asset || '').slice(0, 60) + '...' : (v.asset || '-')}</td>
                <td>{v.icp_domain || '-'}</td>
                <td>{v.icp_number || '-'}</td>
                <td>{v.icp_company || '-'}</td>
                <td>{formatDateTime(v.scanned_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Pagination total={total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
    </div>
  );
}
