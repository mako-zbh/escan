// --- Config file editor ---

var _configOriginalContent = '';

document.getElementById('btnConfigOpen').addEventListener('click', openConfigModal);

async function openConfigModal() {
  var modal = document.getElementById('configModal');
  var editor = document.getElementById('configEditor');
  var status = document.getElementById('configModalStatus');

  editor.value = '';
  status.textContent = '加载中...';
  status.className = 'config-modal-status';
  modal.style.display = 'block';

  try {
    var data = await fetchAPI('/config');
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
  var editor = document.getElementById('configEditor');
  var current = editor.value;
  if (current !== _configOriginalContent) {
    if (!confirm('内容已修改，确定不保存就关闭吗？')) return;
  }
  document.getElementById('configModal').style.display = 'none';
}

document.getElementById('configModalSave').addEventListener('click', saveConfig);

async function saveConfig() {
  var editor = document.getElementById('configEditor');
  var status = document.getElementById('configModalStatus');
  var btn = document.getElementById('configModalSave');
  var content = editor.value;

  btn.disabled = true;
  btn.textContent = '保存中...';
  status.textContent = '';
  status.className = 'config-modal-status';

  try {
    var res = await fetch(API_BASE + '/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: content }),
    });
    if (!res.ok) {
      var err = await res.json().catch(function() { return { error: res.statusText }; });
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    var data = await res.json();
    _configOriginalContent = content;
    status.textContent = '已保存' + (data.backup ? '（备份: ' + data.backup + '）' : '');
    status.className = 'config-modal-status success';
  } catch (e) {
    status.textContent = '保存失败: ' + e.message;
    status.className = 'config-modal-status error';
  } finally {
    btn.disabled = false;
    btn.textContent = '保存';
  }
}
