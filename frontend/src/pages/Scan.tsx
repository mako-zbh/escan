import { useEffect, useState, useCallback, useRef } from 'react';
import { getTasks, triggerScan, stopScan, resumeScan, deleteScanTask, getScanLogs } from '../services/api';
import { useSSE } from '../hooks/useSSE';
import { useSSELogs } from '../hooks/useSSELogs';
import TaskTable from '../components/TaskTable';
import LogViewer from '../components/LogViewer';
import ConfirmDialog from '../components/ConfirmDialog';
import { useToast } from '../components/Toast';
import type { ScanTask, ScanLog } from '../types';

export default function Scan() {
  const { showToast } = useToast();
  const [tasks, setTasks] = useState<ScanTask[]>([]);
  const [scanType, setScanType] = useState('categorized');
  const [engine, setEngine] = useState('fofa');
  const [poc, setPoc] = useState('');
  const [region, setRegion] = useState('');

  // Polling / SSE
  const activeTask = tasks.find(t => t.status === 'running');
  const { data: progress } = useSSE(activeTask?.task_id ?? null);
  const { logs: sseLogs, connected: sseConnected } = useSSELogs(activeTask?.task_id ?? null);

  // Log viewer state
  const [logViewerTask, setLogViewerTask] = useState<string | null>(null);
  const [logViewerLogs, setLogViewerLogs] = useState<ScanLog[]>([]);
  const pollRef = useRef<ReturnType<typeof setInterval>>();

  // Confirm dialog
  const [confirm, setConfirm] = useState<{ title: string; message: string; action: () => void } | null>(null);

  const loadTasks = useCallback(async () => {
    try {
      const res = await getTasks(20, 0);
      setTasks(res.items);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { loadTasks(); }, [loadTasks]);

  // Poll tasks every 5s when there are running tasks
  useEffect(() => {
    if (tasks.some(t => t.status === 'running')) {
      pollRef.current = setInterval(loadTasks, 5000);
      return () => clearInterval(pollRef.current);
    }
  }, [tasks, loadTasks]);

  const handleTrigger = async () => {
    try {
      const res = await triggerScan({
        type: scanType as 'categorized' | 'categorized-incremental',
        engine: engine as 'fofa' | 'hunter',
        poc: poc || undefined,
        region: region || undefined,
      });
      showToast(`扫描已启动: ${res.task_id.slice(-8)}`, 'success');
      loadTasks();
    } catch (e) {
      showToast(`启动失败: ${e instanceof Error ? e.message : e}`, 'error');
    }
  };

  const handleStop = (taskId: string) => {
    setConfirm({ title: '停止扫描', message: `确认停止任务 ${taskId.slice(-8)}？`, action: async () => {
      await stopScan(taskId);
      showToast('扫描已停止', 'info');
      loadTasks();
      setConfirm(null);
    }});
  };

  const handleResume = (taskId: string) => {
    setConfirm({ title: '继续扫描', message: `确认继续任务 ${taskId.slice(-8)}？`, action: async () => {
      await resumeScan(taskId);
      showToast('扫描已恢复', 'info');
      loadTasks();
      setConfirm(null);
    }});
  };

  const handleDelete = (taskId: string) => {
    setConfirm({ title: '删除任务', message: `确认删除任务 ${taskId.slice(-8)}？此操作不可恢复。`, action: async () => {
      await deleteScanTask(taskId);
      showToast('任务已删除', 'info');
      loadTasks();
      setConfirm(null);
    }});
  };

  const handleViewLogs = async (taskId: string) => {
    setLogViewerTask(taskId);
    if (taskId === activeTask?.task_id) {
      // Use SSE log data
      setLogViewerLogs(sseLogs as unknown as ScanLog[]);
    } else {
      try {
        const logs = await getScanLogs(taskId, 0, 500);
        setLogViewerLogs(logs);
      } catch {
        setLogViewerLogs([]);
      }
    }
  };

  // Sync SSE logs to log viewer when watching active task
  useEffect(() => {
    if (logViewerTask && logViewerTask === activeTask?.task_id) {
      setLogViewerLogs(sseLogs as unknown as ScanLog[]);
    }
  }, [sseLogs, logViewerTask, activeTask]);

  return (
    <div>
      <h2>扫描任务</h2>

      <div className="card" style={{ marginBottom: 24 }}>
        <h3>启动新扫描</h3>
        <div className="form-row">
          <select className="input" value={scanType} onChange={e => setScanType(e.target.value)}>
            <option value="categorized">分类扫描 (Categorized)</option>
            <option value="categorized-incremental">增量扫描 (Incremental)</option>
          </select>
          <select className="input" value={engine} onChange={e => setEngine(e.target.value)}>
            <option value="fofa">FOFA</option>
            <option value="hunter">Hunter</option>
          </select>
          <input className="input" placeholder="POC 目录 (可选)" value={poc} onChange={e => setPoc(e.target.value)} />
          <input className="input" placeholder="地域 (可选, 如 CN/北京)" value={region} onChange={e => setRegion(e.target.value)} style={{ width: 160 }} />
          <button className="btn btn-primary" onClick={handleTrigger}>启动扫描</button>
        </div>
      </div>

      <h3>任务列表</h3>
      {activeTask && progress && (
        <div className="card" style={{ marginBottom: 16, borderColor: 'var(--primary)' }}>
          <p className="fw-500">
            任务 {activeTask.task_id.slice(-8)} 运行中: {progress.message}
          </p>
        </div>
      )}
      <TaskTable
        tasks={tasks}
        onStop={handleStop}
        onResume={handleResume}
        onDelete={handleDelete}
        onViewLogs={handleViewLogs}
      />

      {logViewerTask && (
        <LogViewer
          logs={logViewerLogs as unknown as import('../types').SSELogEvent[]}
          connected={logViewerTask === activeTask?.task_id ? sseConnected : false}
          onClose={() => setLogViewerTask(null)}
        />
      )}

      <ConfirmDialog
        open={!!confirm}
        title={confirm?.title ?? ''}
        message={confirm?.message ?? ''}
        onConfirm={() => confirm?.action()}
        onCancel={() => setConfirm(null)}
      />
    </div>
  );
}
