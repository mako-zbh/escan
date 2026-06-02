import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import {
  getTemplateDetail,
  getTemplateUrls,
  getTemplateDomains,
  getTemplateICP,
  getTemplateVulns,
} from '../services/api';
import { severityBadgeClass, formatDateTime } from '../utils/format';
import type { TemplateDetail, Asset, HostEntry, ICPResult, VulnResult } from '../types';

type Tab = 'urls' | 'domains' | 'icp' | 'vulns';

export default function TemplateDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [detail, setDetail] = useState<TemplateDetail | null>(null);
  const [tab, setTab] = useState<Tab>('urls');
  const [urls, setUrls] = useState<Asset[]>([]);
  const [domains, setDomains] = useState<HostEntry[]>([]);
  const [icp, setIcp] = useState<ICPResult[]>([]);
  const [vulns, setVulns] = useState<VulnResult[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!id) return;
    getTemplateDetail(id).then(setDetail).catch(() => {});
  }, [id]);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    const fetcher = tab === 'urls' ? getTemplateUrls
      : tab === 'domains' ? getTemplateDomains
      : tab === 'icp' ? getTemplateICP
      : getTemplateVulns;
    const setter = tab === 'urls' ? setUrls
      : tab === 'domains' ? setDomains
      : tab === 'icp' ? setIcp
      : setVulns;
    fetcher(id).then(d => { setter(d); setLoading(false); }).catch(() => setLoading(false));
  }, [id, tab]);

  if (!detail) return <p className="text-muted">加载中...</p>;

  const tabs: { key: Tab; label: string; count: number }[] = [
    { key: 'urls', label: '资产 URL', count: detail.tasks.reduce((s, t) => s + t.step1_assets, 0) },
    { key: 'domains', label: '域名 / IP', count: detail.tasks.reduce((s, t) => s + t.step3_hosts, 0) },
    { key: 'icp', label: 'ICP 备案', count: detail.icp_summary.domains_with_icp },
    { key: 'vulns', label: '漏洞结果', count: detail.tasks.reduce((s, t) => s + t.step2_vulns, 0) },
  ];

  return (
    <div>
      <div className="detail-header">
        <h2>{detail.name}</h2>
        <span className={`badge ${severityBadgeClass(detail.severity)}`} style={{ fontSize: 14 }}>{detail.severity || '-'}</span>
      </div>
      {detail.fofa_query && <p className="text-muted" style={{ marginTop: 4 }}>FOFA: {detail.fofa_query}</p>}
      {detail.file_path && <p className="text-muted">文件: {detail.file_path}</p>}

      <div className="tabs">
        {tabs.map(t => (
          <button key={t.key} className={`tab ${tab === t.key ? 'tab-active' : ''}`} onClick={() => setTab(t.key)}>
            {t.label} ({t.count})
          </button>
        ))}
      </div>

      <div className="tab-content">
        {loading && <p className="text-muted">加载中...</p>}
        {!loading && tab === 'urls' && (
          <div className="scroll-table">
            <table className="table">
              <thead><tr><th>URL</th><th>Host</th><th>端口</th><th>标题</th><th>ICP 备案</th><th>备案主体</th></tr></thead>
              <tbody>
                {urls.map(a => (
                  <tr key={a.asset_id}>
                    <td className="fw-mono" title={a.url}>{a.url.length > 80 ? a.url.slice(0, 80) + '...' : a.url}</td>
                    <td>{a.host || '-'}</td>
                    <td>{a.port ?? '-'}</td>
                    <td>{a.title || '-'}</td>
                    <td>{a.icp_number || '-'}</td>
                    <td>{a.icp_company || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {!loading && tab === 'domains' && (
          <table className="table">
            <thead><tr><th>Host</th><th>类型</th></tr></thead>
            <tbody>
              {domains.map(h => (
                <tr key={h.host_result_id}>
                  <td className="fw-mono">{h.host}</td>
                  <td>{h.is_ip ? 'IP' : '域名'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {!loading && tab === 'icp' && (
          <table className="table">
            <thead><tr><th>IP</th><th>域名</th><th>备案号</th><th>备案主体</th><th>数据源</th></tr></thead>
            <tbody>
              {icp.map(r => (
                <tr key={r.icp_result_id}>
                  <td className="fw-mono">{r.ip_address || '-'}</td>
                  <td>{r.domain || '-'}</td>
                  <td>{r.icp_number || '-'}</td>
                  <td>{r.company || '-'}</td>
                  <td>{r.source || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {!loading && tab === 'vulns' && (
          <table className="table">
            <thead><tr><th>级别</th><th>URL</th><th>协议</th><th>时间</th></tr></thead>
            <tbody>
              {vulns.map(v => (
                <tr key={v.result_id}>
                  <td><span className={`badge ${severityBadgeClass(v.severity)}`}>{v.severity || '-'}</span></td>
                  <td className="fw-mono">{v.matched_url}</td>
                  <td>{v.protocol || '-'}</td>
                  <td>{formatDateTime(v.scanned_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
