import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { getTemplates } from '../services/api';
import FilterBar from '../components/FilterBar';
import Pagination from '../components/Pagination';
import { severityBadgeClass } from '../utils/format';
import type { TemplateItem } from '../types';

const PAGE_SIZE = 30;

export default function Templates() {
  const navigate = useNavigate();
  const [items, setItems] = useState<TemplateItem[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [hasIcp, setHasIcp] = useState('');
  const [loading, setLoading] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getTemplates({ limit: PAGE_SIZE, offset, search, severity, has_icp: hasIcp });
      setItems(res.items);
      setTotal(res.total);
    } finally {
      setLoading(false);
    }
  }, [offset, search, severity, hasIcp]);

  useEffect(() => { fetchData(); }, [fetchData]);

  return (
    <div>
      <h2>模板库</h2>

      <FilterBar
        search={search}
        severity={severity}
        hasIcp={hasIcp}
        onSearchChange={v => { setSearch(v); setOffset(0); }}
        onSeverityChange={v => { setSeverity(v); setOffset(0); }}
        onHasIcpChange={v => { setHasIcp(v); setOffset(0); }}
      />

      <table className="table">
        <thead>
          <tr>
            <th>模板名称</th>
            <th>级别</th>
            <th className="num">资产数</th>
            <th className="num">命中数</th>
            <th className="num">域名数</th>
            <th className="num">ICP 备案</th>
          </tr>
        </thead>
        <tbody>
          {loading && <tr><td colSpan={6} className="text-muted">加载中...</td></tr>}
          {!loading && items.length === 0 && <tr><td colSpan={6} className="text-muted">暂无数据</td></tr>}
          {items.map(t => (
            <tr key={t.template_id} className="clickable" onClick={() => navigate(`/templates/${t.template_id}`)}>
              <td className="fw-500">{t.name}</td>
              <td><span className={`badge ${severityBadgeClass(t.severity)}`}>{t.severity || '-'}</span></td>
              <td className="num">{t.asset_count}</td>
              <td className="num">{t.hit_count}</td>
              <td className="num">{t.domain_count}</td>
              <td className="num">{t.icp_count}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <Pagination total={total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
    </div>
  );
}
