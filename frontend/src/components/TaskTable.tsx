import type { ScanTask } from '../types';
import { formatShortDate, truncate } from '../utils/format';

interface Props {
  tasks: ScanTask[];
  onStop: (id: string) => void;
  onResume: (id: string) => void;
  onDelete: (id: string) => void;
  onViewLogs: (id: string) => void;
}

const statusMap: Record<string, string> = {
  running: '运行中',
  completed: '已完成',
  stopped: '已停止',
  failed: '失败',
};

export default function TaskTable({ tasks, onStop, onResume, onDelete, onViewLogs }: Props) {
  if (tasks.length === 0) return <p className="text-muted">暂无扫描任务</p>;

  return (
    <table className="table">
      <thead>
        <tr>
          <th>任务 ID</th>
          <th>类型</th>
          <th>引擎</th>
          <th>状态</th>
          <th>资产</th>
          <th>漏洞</th>
          <th>主机</th>
          <th>ICP</th>
          <th>开始时间</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        {tasks.map(t => (
          <tr key={t.task_id}>
            <td title={t.task_id}>...{t.task_id.slice(-8)}</td>
            <td>{t.task_type}</td>
            <td>{t.engine}</td>
            <td><span className={`badge ${t.status === 'running' ? 'badge-info' : t.status === 'completed' ? 'badge-high' : t.status === 'failed' ? 'badge-critical' : 'badge-default'}`}>{statusMap[t.status] || t.status}</span></td>
            <td>{t.step1_assets}</td>
            <td>{t.step2_vulns}</td>
            <td>{t.step3_hosts}</td>
            <td>{t.step4_icp}</td>
            <td>{formatShortDate(t.started_at)}</td>
            <td className="table-actions">
              {(t.status === 'running') && (
                <button className="btn btn-sm btn-warning" onClick={() => onStop(t.task_id)}>停止</button>
              )}
              {t.status === 'stopped' && (
                <button className="btn btn-sm btn-info" onClick={() => onResume(t.task_id)}>继续</button>
              )}
              <button className="btn btn-sm" onClick={() => onViewLogs(t.task_id)}>日志</button>
              {t.status !== 'running' && (
                <button className="btn btn-sm btn-danger" onClick={() => onDelete(t.task_id)}>删除</button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
