import { useEffect, useState } from 'react';
import { getStats, getSeverity } from '../services/api';
import StatsCard from '../components/StatsCard';
import SeverityChart from '../components/SeverityChart';
import type { StatsResponse } from '../types';

export default function Dashboard() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [severity, setSeverity] = useState<Record<string, number>>({});

  useEffect(() => {
    getStats().then(setStats).catch(() => {});
    getSeverity().then(setSeverity).catch(() => {});
  }, []);

  return (
    <div>
      <h2>仪表盘</h2>
      <div className="stats-grid">
        <StatsCard title="模板总数" value={stats?.template_count ?? '...'} icon="T" loading={!stats} />
        <StatsCard title="扫描任务" value={stats?.task_count ?? '...'} icon="S" loading={!stats} />
        <StatsCard title="发现资产" value={stats?.asset_count ?? '...'} icon="A" loading={!stats} />
        <StatsCard title="漏洞数量" value={stats?.vuln_count ?? '...'} icon="V" loading={!stats} />
        <StatsCard title="ICP 备案" value={stats?.icp_count ?? '...'} icon="I" loading={!stats} />
        <StatsCard title="活跃缓存" value={stats?.active_cache_count ?? '...'} icon="C" loading={!stats} />
      </div>

      <div className="grid-2" style={{ marginTop: 24 }}>
        <div className="card">
          <h3>漏洞级别分布</h3>
          {Object.keys(severity).length > 0 ? (
            <SeverityChart data={severity} />
          ) : (
            <p className="text-muted">暂无漏洞数据</p>
          )}
        </div>
        <div className="card">
          <h3>最近任务</h3>
          {stats?.recent_tasks?.length ? (
            <table className="table">
              <thead><tr><th>任务</th><th>类型</th><th>状态</th><th>漏洞</th></tr></thead>
              <tbody>
                {stats.recent_tasks.slice(0, 5).map((t: Record<string, unknown>) => (
                  <tr key={t.task_id as string}>
                    <td title={t.task_id as string}>...{(t.task_id as string).slice(-8)}</td>
                    <td>{t.task_type as string}</td>
                    <td><span className="badge badge-default">{t.status as string}</span></td>
                    <td>{t.vulns as number}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-muted">暂无任务记录</p>
          )}
        </div>
      </div>
    </div>
  );
}
