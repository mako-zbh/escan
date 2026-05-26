// --- ICP 备案直接查询 ---

document.getElementById('btnIcpQuery').addEventListener('click', openIcpQueryModal);

function openIcpQueryModal() {
  document.getElementById('icpQueryModal').style.display = 'block';
  document.getElementById('icpQuerySearch').focus();
}

function closeIcpQueryModal() {
  document.getElementById('icpQueryModal').style.display = 'none';
}

async function doIcpQuery() {
  var search = document.getElementById('icpQuerySearch').value.trim();
  if (!search) return;

  var btn = document.getElementById('icpQueryBtn');
  var status = document.getElementById('icpQueryStatus');
  var tbody = document.querySelector('#icpQueryTable tbody');

  btn.disabled = true;
  btn.textContent = '查询中...';
  status.textContent = '';
  tbody.innerHTML = '';

  try {
    var res = await fetch(API_BASE + '/icp/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ search: search }),
    });
    if (!res.ok) {
      var err = await res.json().catch(function() { return { error: res.statusText }; });
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    var data = await res.json();

    if (data.items && data.items.length) {
      status.textContent = '共 ' + data.total + ' 条结果';
      status.className = 'icp-query-status';

      tbody.innerHTML = data.items.map(function(r) {
        return '<tr>' +
          '<td>' + escapeHtml(r.domain || '-') + '</td>' +
          '<td title="' + escapeHtml(r.unitName || '') + '">' + escapeHtml(truncate(r.unitName, 30)) + '</td>' +
          '<td>' + escapeHtml(r.mainLicence || '-') + '</td>' +
          '<td>' + escapeHtml(r.natureName || '-') + '</td>' +
          '<td>' + escapeHtml(r.leaderName || '-') + '</td>' +
          '<td class="icp-query-time">' + escapeHtml(r.updateRecordTime || '-') + '</td>' +
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
  } finally {
    btn.disabled = false;
    btn.textContent = '查询';
  }
}
