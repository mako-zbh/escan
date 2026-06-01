document.getElementById('btnIcpQuery').addEventListener('click', openIcpQueryModal);

function openIcpQueryModal() {
  document.getElementById('icpQueryModal').style.display = 'block';
  document.getElementById('icpQuerySearch').focus();
}

function closeIcpQueryModal() {
  document.getElementById('icpQueryModal').style.display = 'none';
}

async function doIcpQuery() {
  const search = document.getElementById('icpQuerySearch').value.trim();
  if (!search) return;

  const btn = document.getElementById('icpQueryBtn');
  const status = document.getElementById('icpQueryStatus');
  const tbody = document.querySelector('#icpQueryTable tbody');

  btn.disabled = true;
  btn.textContent = '查询中…';
  status.textContent = '';
  tbody.innerHTML = '';

  try {
    const res = await fetch(API_BASE + '/icp/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ search }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    const data = await res.json();

    if (data.items && data.items.length) {
      status.textContent = '共 ' + data.total + ' 条结果';
      status.className = 'icp-query-status';

      tbody.innerHTML = data.items.map(r => {
        return '<tr>' +
          '<td>' + Utils.escapeHtml(r.domain || '-') + '</td>' +
          '<td title="' + Utils.escapeHtml(r.unitName || '') + '">' + Utils.escapeHtml(Utils.truncate(r.unitName, 30)) + '</td>' +
          '<td>' + Utils.escapeHtml(r.mainLicence || '-') + '</td>' +
          '<td>' + Utils.escapeHtml(r.natureName || '-') + '</td>' +
          '<td>' + Utils.escapeHtml(r.leaderName || '-') + '</td>' +
          '<td class="icp-query-time">' + Utils.escapeHtml(r.updateRecordTime || '-') + '</td>' +
          '</tr>';
      }).join('');
    } else {
      status.textContent = data.error || '未找到备案信息';
      status.className = 'icp-query-status error';
      tbody.innerHTML = '<tr><td colspan="6" class="placeholder">未找到备案信息</td></tr>';
    }
  } catch (e) {
    status.textContent = '查询失败: ' + e.message;
    status.className = 'icp-query-status error';
    Utils.showToast('ICP 查询失败: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = '查询';
  }
}
