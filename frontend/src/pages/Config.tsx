import { useEffect, useState } from 'react';
import { getConfig, updateConfig } from '../services/api';
import { useToast } from '../components/Toast';

export default function Config() {
  const { showToast } = useToast();
  const [content, setContent] = useState('');
  const [originalPath, setOriginalPath] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getConfig()
      .then(d => { setContent(d.content); setOriginalPath(d.path); })
      .catch(e => showToast(`加载失败: ${e.message}`, 'error'))
      .finally(() => setLoading(false));
  }, [showToast]);

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await updateConfig(content);
      showToast(`已保存 (备份: ${res.backup})`, 'success');
    } catch (e) {
      showToast(`保存失败: ${e instanceof Error ? e.message : e}`, 'error');
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <p className="text-muted">加载中...</p>;

  return (
    <div>
      <h2>配置管理</h2>
      <p className="text-muted" style={{ marginBottom: 12 }}>文件: {originalPath}</p>
      <textarea
        className="input config-editor"
        value={content}
        onChange={e => setContent(e.target.value)}
        spellCheck={false}
      />
      <button className="btn btn-primary" onClick={handleSave} disabled={saving} style={{ marginTop: 12 }}>
        {saving ? '保存中...' : '保存配置'}
      </button>
    </div>
  );
}
