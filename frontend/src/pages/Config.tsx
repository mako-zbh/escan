import { useEffect, useState, useCallback } from 'react';
import { getConfig, updateConfig } from '../services/api';
import { useToast } from '../components/Toast';

type ConfigSource = 'env' | 'local';

export default function Config() {
  const { showToast } = useToast();
  const [source, setSource] = useState<ConfigSource>('env');
  const [content, setContent] = useState('');
  const [filePath, setFilePath] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [changedLines, setChangedLines] = useState<number>(0);

  const load = useCallback(async (src: ConfigSource) => {
    setLoading(true);
    try {
      const d = await getConfig(src);
      setContent(d.content);
      setFilePath(d.path);
      setDirty(false);
      setChangedLines(0);
    } catch (e) {
      showToast(`加载失败: ${e instanceof Error ? e.message : e}`, 'error');
    }
    setLoading(false);
  }, [showToast]);

  useEffect(() => { load(source); }, [source, load]);

  const handleChange = (val: string) => {
    const oldLines = content.split('\n').filter(l => l.trim() && !l.startsWith('#'));
    const newLines = val.split('\n').filter(l => l.trim() && !l.startsWith('#'));
    const oldSet = new Set(oldLines);
    const newSet = new Set(newLines);
    // Count added/removed non-empty non-comment lines as "changes"
    const changes = [...newLines].filter(l => !oldSet.has(l)).length +
                    [...oldLines].filter(l => !newSet.has(l)).length;
    setContent(val);
    setDirty(val !== content);
    setChangedLines(changes);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await updateConfig(content, source);
      const label = source === 'local' ? '.env.local' : '.env';
      showToast(`${label} 已保存 (备份: ${res.backup})`, 'success');
      setDirty(false);
      setChangedLines(0);
    } catch (e) {
      showToast(`保存失败: ${e instanceof Error ? e.message : e}`, 'error');
    }
    setSaving(false);
  };

  const fileName = source === 'local' ? '.env.local' : '.env';
  const fileLabel = source === 'local' ? '本地配置（覆盖默认值）' : '默认配置';
  const fileHint = source === 'local'
    ? '仅保存密钥/覆盖项，未设置项将回退到 .env 默认值'
    : '保存后可提交到 git（不含密钥）';

  return (
    <div>
      <h2>配置管理</h2>

      {/* File tabs */}
      <div className="config-tabs" style={{ display: 'flex', gap: 0, marginBottom: 12, borderBottom: '2px solid var(--border)' }}>
        <button
          className={`config-tab ${source === 'env' ? 'active' : ''}`}
          onClick={() => setSource('env')}
          style={{
            padding: '8px 20px',
            border: 'none',
            background: source === 'env' ? 'var(--bg-card)' : 'transparent',
            color: source === 'env' ? 'var(--primary)' : 'var(--text-secondary)',
            fontWeight: source === 'env' ? 600 : 400,
            borderBottom: source === 'env' ? '2px solid var(--primary)' : '2px solid transparent',
            marginBottom: -2,
            cursor: 'pointer',
            fontSize: 14,
            borderRadius: '4px 4px 0 0',
          }}
        >
          .env（默认）
        </button>
        <button
          className={`config-tab ${source === 'local' ? 'active' : ''}`}
          onClick={() => setSource('local')}
          style={{
            padding: '8px 20px',
            border: 'none',
            background: source === 'local' ? 'var(--bg-card)' : 'transparent',
            color: source === 'local' ? 'var(--primary)' : 'var(--text-secondary)',
            fontWeight: source === 'local' ? 600 : 400,
            borderBottom: source === 'local' ? '2px solid var(--primary)' : '2px solid transparent',
            marginBottom: -2,
            cursor: 'pointer',
            fontSize: 14,
            borderRadius: '4px 4px 0 0',
          }}
        >
          .env.local（覆盖）
        </button>
      </div>

      {loading ? (
        <p className="text-muted">加载中...</p>
      ) : (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <div>
              <span className="text-muted" style={{ fontSize: 12 }}>
                文件: {filePath}
              </span>
              {dirty && (
                <span className="badge badge-warning" style={{ marginLeft: 8 }}>
                  {changedLines > 0 ? `已修改 ${changedLines} 项` : '未保存'}
                </span>
              )}
            </div>
            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{fileHint}</span>
          </div>

          <textarea
            className="input config-editor"
            value={content}
            onChange={e => handleChange(e.target.value)}
            spellCheck={false}
            placeholder={`# ${fileName}\n# ${fileLabel}\nKEY=VALUE`}
            style={{
              width: '100%',
              minHeight: 400,
              fontFamily: 'var(--mono)',
              fontSize: 13,
              lineHeight: 1.6,
              tabSize: 2,
              resize: 'vertical',
            }}
          />

          <div style={{ display: 'flex', gap: 12, marginTop: 12, alignItems: 'center' }}>
            <button className="btn btn-primary" onClick={handleSave} disabled={saving || !dirty}>
              {saving ? '保存中...' : '保存配置'}
            </button>
            <button className="btn" onClick={() => { setContent(content); setDirty(false); setChangedLines(0); load(source); }}
                    disabled={!dirty}>
              撤销更改
            </button>
            <span style={{ fontSize: 12, color: 'var(--text-secondary)', marginLeft: 'auto' }}>
              共 {content.split('\n').length} 行
            </span>
          </div>
        </>
      )}
    </div>
  );
}
