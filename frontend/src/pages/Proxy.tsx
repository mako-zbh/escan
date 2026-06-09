import { useEffect, useState, useCallback } from 'react';
import {
  getProxyStatus, testProxy, addProxy, removeProxy, updateProxyToggles,
  batchTestProxies, batchAddProxies,
} from '../services/api';
import { useToast } from '../components/Toast';
import type { ProxyStatusResponse, ProxyBatchTestResult } from '../types';

const TOGGLE_DEFAULTS = { fofa: false, hunter: false, nuclei: false, icp: false, deepseek: false };

export default function Proxy() {
  const { showToast } = useToast();
  const [status, setStatus] = useState<ProxyStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [addUrl, setAddUrl] = useState('');
  const [testing, setTesting] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<Record<string, { ok: boolean; ms: number; error?: string }>>({});
  // Batch state
  const [batchInput, setBatchInput] = useState('');
  const [testBeforeAdd, setTestBeforeAdd] = useState(false);
  const [batchTesting, setBatchTesting] = useState(false);
  const [batchAdding, setBatchAdding] = useState(false);
  const [batchResults, setBatchResults] = useState<ProxyBatchTestResult[] | null>(null);
  const [toggles, setToggles] = useState(TOGGLE_DEFAULTS);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const s = await getProxyStatus();
      setStatus(s);
      setToggles(s.toggles ?? TOGGLE_DEFAULTS);
    } catch { /*  */}
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleAdd = async () => {
    const url = addUrl.trim();
    if (!url) return;
    try {
      await addProxy(url);
      showToast('代理已添加', 'success');
      setAddUrl('');
      load();
    } catch (e) {
      showToast(`添加失败: ${e instanceof Error ? e.message : e}`, 'error');
    }
  };

  const handleRemove = async (url: string) => {
    try {
      await removeProxy(url);
      showToast('代理已删除', 'success');
      load();
    } catch (e) {
      showToast(`删除失败: ${e instanceof Error ? e.message : e}`, 'error');
    }
  };

  const handleTest = async (url: string) => {
    setTesting(url);
    try {
      const r = await testProxy(url);
      setTestResult(prev => ({ ...prev, [url]: { ok: r.success, ms: r.latency_ms, error: r.error ?? undefined } }));
    } catch {
      setTestResult(prev => ({ ...prev, [url]: { ok: false, ms: 0, error: '请求失败' } }));
    }
    setTesting(null);
  };

  const handleToggleSave = async () => {
    setSaving(true);
    try {
      const body: Record<string, boolean | null> = {};
      for (const [k, v] of Object.entries(toggles)) {
        body[k] = v ? true : false;
      }
      await updateProxyToggles(body);
      showToast('开关已保存', 'success');
    } catch (e) {
      showToast(`保存失败: ${e instanceof Error ? e.message : e}`, 'error');
    }
    setSaving(false);
  };

  // --- Batch handlers ---
  const batchUrls = batchInput.split('\n').map(l => l.trim()).filter(Boolean);

  const handleBatchTest = async () => {
    if (batchUrls.length === 0) return;
    setBatchTesting(true);
    setBatchResults(null);
    try {
      const r = await batchTestProxies(batchUrls);
      setBatchResults(r.results);
      showToast(
        `验证完成: ${r.success_count}/${r.total} 可用`,
        r.success_count > 0 ? 'success' : 'error',
      );
    } catch (e) {
      showToast(`批量验证失败: ${e instanceof Error ? e.message : e}`, 'error');
    }
    setBatchTesting(false);
  };

  const handleBatchAdd = async () => {
    if (batchUrls.length === 0) return;
    setBatchAdding(true);
    try {
      const r = await batchAddProxies(batchUrls, testBeforeAdd);
      showToast(r.message, r.added > 0 ? 'success' : 'info');
      setBatchInput('');
      setBatchResults(null);
      load();
    } catch (e) {
      showToast(`批量添加失败: ${e instanceof Error ? e.message : e}`, 'error');
    }
    setBatchAdding(false);
  };

  if (loading) return <p className="text-muted">加载中...</p>;

  const proxies = status?.proxies ?? [];
  const available = status?.available ?? 0;

  return (
    <div>
      <h2>代理池管理</h2>

      {/* Stats bar */}
      <div className="stats-grid" style={{ marginBottom: 20 }}>
        <div className="card" style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--primary)' }}>{status?.total ?? 0}</div>
          <div className="text-muted" style={{ fontSize: 12 }}>总数</div>
        </div>
        <div className="card" style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--success)' }}>{available}</div>
          <div className="text-muted" style={{ fontSize: 12 }}>可用</div>
        </div>
        <div className="card" style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700, color: status?.in_cooldown ? 'var(--danger)' : 'var(--text-primary)' }}>{status?.in_cooldown ?? 0}</div>
          <div className="text-muted" style={{ fontSize: 12 }}>冷却中</div>
        </div>
        <div className="card" style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{status?.strategy ?? '-'}</div>
          <div className="text-muted" style={{ fontSize: 12 }}>策略</div>
        </div>
        <div className="card" style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: status?.pool_loaded ? 'var(--success)' : 'var(--text-muted)' }}>
            {status?.pool_loaded ? '运行中' : '未加载'}
          </div>
          <div className="text-muted" style={{ fontSize: 12 }}>池状态</div>
        </div>
      </div>

      {/* Add proxy */}
      <div className="card" style={{ marginBottom: 20 }}>
        <h3>添加代理</h3>
        <div className="form-row">
          <input
            className="input"
            placeholder="http://host:port 或 socks5://host:port"
            value={addUrl}
            onChange={e => setAddUrl(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') handleAdd(); }}
            style={{ flex: 1 }}
          />
          <button className="btn btn-primary" onClick={handleAdd} disabled={!addUrl.trim()}>添加</button>
        </div>
      </div>

      {/* Batch add */}
      <div className="card" style={{ marginBottom: 20 }}>
        <h3>批量添加代理</h3>
        <p className="text-muted" style={{ marginBottom: 8, fontSize: 13 }}>
          每行一个代理 URL，支持 http/https/socks5 协议
        </p>
        <textarea
          className="input"
          placeholder={`http://user:pass@host:port\nhttp://host:port\nsocks5://host:port`}
          value={batchInput}
          onChange={e => setBatchInput(e.target.value)}
          rows={6}
          style={{ width: '100%', resize: 'vertical', fontFamily: 'var(--mono)', fontSize: 12 }}
        />
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginTop: 12, flexWrap: 'wrap' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 13 }}>
            <input
              type="checkbox"
              checked={testBeforeAdd}
              onChange={e => setTestBeforeAdd(e.target.checked)}
            />
            添加前先验证连通性
          </label>
          <div style={{ display: 'flex', gap: 8, marginLeft: 'auto' }}>
            <button
              className="btn btn-info"
              onClick={handleBatchTest}
              disabled={batchUrls.length === 0 || batchTesting}
            >
              {batchTesting ? '验证中...' : '批量验证'}
            </button>
            <button
              className="btn btn-primary"
              onClick={handleBatchAdd}
              disabled={batchUrls.length === 0 || batchAdding}
            >
              {batchAdding ? '添加中...' : '批量添加'}
            </button>
          </div>
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
          共 {batchUrls.length} 个 URL
        </div>

        {/* Batch results */}
        {batchResults && batchResults.length > 0 && (
          <div style={{ marginTop: 16 }}>
            <table className="table" style={{ fontSize: 12 }}>
              <thead>
                <tr>
                  <th>代理 URL</th>
                  <th style={{ width: 80 }}>状态</th>
                  <th style={{ width: 80 }}>延迟</th>
                  <th>错误</th>
                </tr>
              </thead>
              <tbody>
                {batchResults.map(r => (
                  <tr key={r.url}>
                    <td className="fw-mono">{r.url}</td>
                    <td>
                      <span className={`badge ${r.success ? 'badge-high' : 'badge-warning'}`}>
                        {r.success ? '✓ 可用' : '✗ 失败'}
                      </span>
                    </td>
                    <td>
                      {r.success ? (
                        <span style={{ fontFamily: 'var(--mono)', color: 'var(--success)' }}>
                          {r.latency_ms}ms
                        </span>
                      ) : (
                        <span className="text-muted">-</span>
                      )}
                    </td>
                    <td className="text-muted" style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.error ?? '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="text-muted" style={{ fontSize: 12, marginTop: 4 }}>
              可用: {batchResults.filter(r => r.success).length} / 总计: {batchResults.length}
            </div>
          </div>
        )}
      </div>

      {/* Proxy list */}
      <div className="card" style={{ marginBottom: 20 }}>
        <h3>
          代理列表
          {proxies.length > 0 && (
            <span className="text-muted" style={{ fontSize: 13, marginLeft: 12 }}>
              文件: {status?.file_path ?? '-'}
            </span>
          )}
        </h3>
        {proxies.length === 0 ? (
          <p className="text-muted">暂无代理 — 请添加代理 URL 或编辑 proxies.txt</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>代理 URL</th>
                <th>失败次数</th>
                <th>状态</th>
                <th>延迟</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {proxies.map(p => {
                const tr = testResult[p.url];
                const cool = p.in_cooldown;
                return (
                  <tr key={p.url}>
                    <td className="fw-mono" style={{ fontSize: 12 }}>
                      {p.url}
                      {cool && (
                        <span className="badge badge-warning" style={{ marginLeft: 8 }}>
                          冷却 {p.cooldown_remaining.toFixed(0)}s
                        </span>
                      )}
                    </td>
                    <td>{p.failures}</td>
                    <td>
                      <span className={`badge ${cool ? 'badge-warning' : 'badge-high'}`}>
                        {cool ? '冷却中' : '可用'}
                      </span>
                    </td>
                    <td>
                      {testing === p.url ? (
                        <span className="text-muted">测试中...</span>
                      ) : tr ? (
                        tr.ok ? (
                          <span style={{ color: 'var(--success)', fontFamily: 'var(--mono)' }}>{tr.ms}ms</span>
                        ) : (
                          <span className="text-muted" title={tr.error}>失败</span>
                        )
                      ) : (
                        <span className="text-muted">-</span>
                      )}
                    </td>
                    <td className="table-actions">
                      <button
                        className="btn btn-sm btn-info"
                        onClick={() => handleTest(p.url)}
                        disabled={testing === p.url}
                      >
                        {testing === p.url ? '...' : '测试'}
                      </button>
                      <button className="btn btn-sm btn-danger" onClick={() => handleRemove(p.url)}>删除</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Component toggles */}
      <div className="card">
        <h3>组件开关</h3>
        <p className="text-muted" style={{ marginBottom: 16 }}>
          启用后对应组件将通过代理池发起请求；ICP 政府查询始终直连。
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 16 }}>
          {[
            { key: 'fofa', label: 'FOFA 资产查询', desc: 'FOFA API / 代理接口' },
            { key: 'hunter', label: 'Hunter 资产查询', desc: '奇安信鹰图 API / 代理接口' },
            { key: 'nuclei', label: 'Nuclei 漏洞扫描', desc: 'nuclei -p 标志' },
            { key: 'icp', label: 'ICP IP 反查', desc: '爱站 aizhan / ip138' },
            { key: 'deepseek', label: 'DeepSeek AI', desc: 'POC 模板生成 API' },
          ].map(({ key, label, desc }) => (
            <label key={key} style={{ display: 'flex', alignItems: 'center', gap: 12, cursor: 'pointer' }}>
              <div className="toggle-switch">
                <input
                  type="checkbox"
                  checked={(toggles as Record<string, boolean>)[key] ?? false}
                  onChange={e => setToggles(prev => ({ ...prev, [key]: e.target.checked }))}
                />
                <span className="toggle-slider" />
              </div>
              <div>
                <div style={{ fontWeight: 500 }}>{label}</div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{desc}</div>
              </div>
            </label>
          ))}
        </div>
        <button className="btn btn-primary" onClick={handleToggleSave} disabled={saving}>
          {saving ? '保存中...' : '保存开关'}
        </button>
      </div>
    </div>
  );
}
