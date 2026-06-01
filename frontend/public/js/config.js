let _configOriginalContent = '';

document.getElementById('btnConfigOpen').addEventListener('click', openConfigModal);
document.getElementById('configModalSave').addEventListener('click', saveConfig);

async function openConfigModal() {
  const modal = document.getElementById('configModal');
  const editor = document.getElementById('configEditor');
  const status = document.getElementById('configModalStatus');

  editor.value = '';
  status.textContent = '加载中…';
  status.className = 'config-modal-status';
  modal.style.display = 'block';

  try {
    const data = await fetchAPI('/config');
    document.getElementById('configModalPath').textContent = data.path || '';
    editor.value = data.content || '';
    _configOriginalContent = data.content || '';
    status.textContent = '';
  } catch (e) {
    status.textContent = '加载失败: ' + e.message;
    status.className = 'config-modal-status error';
  }
}

function closeConfigModal() {
  const editor = document.getElementById('configEditor');
  if (editor.value !== _configOriginalContent) {
    if (!Utils.confirm('内容已修改，确定不保存就关闭吗？')) return;
  }
  document.getElementById('configModal').style.display = 'none';
}

async function saveConfig() {
  const editor = document.getElementById('configEditor');
  const status = document.getElementById('configModalStatus');
  const btn = document.getElementById('configModalSave');
  const content = editor.value;

  btn.disabled = true;
  btn.textContent = '保存中…';
  status.textContent = '';
  status.className = 'config-modal-status';

  try {
    const res = await fetch(API_BASE + '/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    const data = await res.json();
    _configOriginalContent = content;
    status.textContent = '已保存' + (data.backup ? '（备份: ' + data.backup + '）' : '');
    status.className = 'config-modal-status success';
    Utils.showToast('配置文件已保存', 'success');
  } catch (e) {
    status.textContent = '保存失败: ' + e.message;
    status.className = 'config-modal-status error';
    Utils.showToast('保存失败: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = '保存';
  }
}
