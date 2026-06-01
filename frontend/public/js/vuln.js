let vulnPage = 0;
const vulnPageSize = 50;
let vulnTab = 'all';

document.getElementById('btnVulnOverview').addEventListener('click', openVulnModal);
document.getElementById('btnExportCSV').addEventListener('click', exportVulnCSV);

document.querySelectorAll('#vulnTabs .vuln-tab').forEach(el => {
  el.addEventListener('click', () => {
    vulnTab = el.dataset.tab;
    vulnPage = 0;
    document.querySelectorAll('#vulnTabs .vuln-tab').forEach(t => {
      t.classList.toggle('active', t.dataset.tab === vulnTab);
    });
    loadVulnTable();
  });
});

document.getElementById('vulnSeverityFilter').addEventListener('change', () => {
  vulnPage = 0;
  loadVulnTable();
});

document.getElementById('vulnSearch').addEventListener('input', Utils.debounce(() => {
  vulnPage = 0;
  loadVulnTable();
}, 400));

function openVulnModal() {
  document.getElementById('vulnModal').style.display = 'block';
  vulnPage = 0;
  loadVulnTable();
}

function closeVulnModal() {
  document.getElementById('vulnModal').style.display = 'none';
}

function _vulnParams() {
  const sev = document.getElementById('vulnSeverityFilter').value;
  const search = document.getElementById('vulnSearch').value;
  const offset = vulnPage * vulnPageSize;

  const params = new URLSearchParams({ limit: vulnPageSize, offset });
  if (sev) params.set('severity', sev);
  if (search) params.set('search', search);
  if (vulnTab === 'icp') params.set('has_icp', '1');

  return params;
}

async function loadVulnTable() {
  try {
    const data = await fetchAPI('/vulnerabilities?' + _vulnParams());
    renderVulnTable(data.items);
    renderVulnPagination(data.total);
  } catch (e) {
    document.querySelector('#vulnTable tbody').innerHTML =
      '<tr><td colspan="7" class="placeholder">加载失败: ' + Utils.escapeHtml(e.message) + '</td></tr>';
  }
}

function renderVulnTable(items) {
  const tbody = document.querySelector('#vulnTable tbody');
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="placeholder">暂无数据</td></tr>';
    return;
  }

  tbody.innerHTML = items.map(r => {
    const tm = r.scanned_at ? new Date(r.scanned_at).toLocaleString('zh-CN') : '-';
    const sev = r.severity || '-';
    return '<tr>' +
      '<td title="' + Utils.escapeHtml(r.vuln_name || '') + '">' + Utils.escapeHtml(Utils.truncate(r.vuln_name, 35)) + '</td>' +
      '<td><span class="severity severity-' + sev + '">' + sev + '</span></td>' +
      '<td><a href="' + Utils.escapeHtml(r.asset || '') + '" target="_blank" class="detail-link">' + Utils.escapeHtml(Utils.truncate(r.asset, 50)) + '</a></td>' +
      '<td>' + Utils.escapeHtml(r.icp_domain || '-') + '</td>' +
      '<td>' + Utils.escapeHtml(r.icp_number || '-') + '</td>' +
      '<td title="' + Utils.escapeHtml(r.icp_company || '') + '">' + Utils.escapeHtml(Utils.truncate(r.icp_company, 25)) + '</td>' +
      '<td class="vuln-time">' + tm + '</td>' +
      '</tr>';
  }).join('');
}

function renderVulnPagination(total) {
  const totalPages = Math.ceil(total / vulnPageSize) || 1;
  document.getElementById('vulnTotal').textContent = '共 ' + total + ' 条';

  const html =
    '<button ' + (vulnPage === 0 ? 'disabled' : '') + ' onclick="vulnGoPage(0)">首页</button>' +
    '<button ' + (vulnPage === 0 ? 'disabled' : '') + ' onclick="vulnGoPage(' + (vulnPage - 1) + ')">上一页</button>' +
    '<span class="page-info">' + (vulnPage + 1) + ' / ' + totalPages + '</span>' +
    '<button ' + (vulnPage >= totalPages - 1 ? 'disabled' : '') + ' onclick="vulnGoPage(' + (vulnPage + 1) + ')">下一页</button>' +
    '<button ' + (vulnPage >= totalPages - 1 ? 'disabled' : '') + ' onclick="vulnGoPage(' + (totalPages - 1) + ')">末页</button>';
  document.getElementById('vulnPagination').innerHTML = html;
}

function vulnGoPage(page) {
  vulnPage = page;
  loadVulnTable();
}

function exportVulnCSV() {
  const url = API_BASE + '/vulnerabilities/export?' + _vulnParams();
  const a = document.createElement('a');
  a.href = url;
  a.download = 'vulnerabilities.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}
