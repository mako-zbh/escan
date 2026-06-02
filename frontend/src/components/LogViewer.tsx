import { useEffect, useRef } from 'react';
import type { SSELogEvent } from '../types';

interface Props {
  logs: SSELogEvent[];
  connected: boolean;
  onClose: () => void;
}

const levelClass: Record<string, string> = {
  ERROR: 'log-error',
  WARNING: 'log-warning',
};

export default function LogViewer({ logs, connected, onClose }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="modal-overlay" onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal modal-lg">
        <div className="modal-header">
          <h3>扫描日志 {connected && <span className="badge badge-info live-dot">实时</span>}</h3>
          <button className="btn btn-sm" onClick={onClose}>关闭</button>
        </div>
        <div className="log-container">
          {logs.length === 0 && <p className="text-muted">暂无日志...</p>}
          {logs.map(log => (
            <div key={log.id} className={`log-line ${levelClass[log.level] || ''}`}>
              <span className="log-time">{log.created_at ? new Date(log.created_at).toLocaleTimeString('zh-CN') : ''}</span>
              <span className={`log-level ${levelClass[log.level] || ''}`}>[{log.level}]</span>
              <span className="log-msg">{log.message}</span>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  );
}
