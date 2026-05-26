// --- Vulnerability Overview ---

var vulnPage = 0;
var vulnPageSize = 50;
var vulnTab = 'all';  // 'all' | 'icp'

document.getElementById('btnVulnOverview').addEventListener('click', openVulnModal);

// Tab switching
document.querySelectorAll('#vulnTabs .vuln-tab').forEach(function(el) {
  el.addEventListener('click', function() {
    vulnTab = el.dataset.tab;
    vulnPage = 0;
    document.querySelectorAll('#vulnTabs .vuln-tab').forEach(function(t) {
      t.classList.toggle('active', t.dataset.tab === vulnTab);
    });
    loadVulnTable();
  });
});

document.getElementById('vulnSeverityFilter').addEventListener('change', function() {
  vulnPage = 0;
  loadVulnTable();
});

document.getElementById('vulnSearch').addEventListener('input', debounceVuln(function() {
  vulnPage = 0;
  loadVulnTable();
}, 400));

function debounceVuln(fn, ms) {
  var t;
  return function() { clearTimeout(t); t = setTimeout(fn, ms); };
}

function openVulnModal() {
  document.getElementById('vulnModal').style.display = 'block';
  vulnPage = 0;
  loadVulnTable();
}

function closeVulnModal() {
  document.getElementById('vulnModal').style.display = 'none';
}

function _vulnParams() {
  var sev = document.getElementById('vulnSeverityFilter').value;
  var search = document.getElementById('vulnSearch').value;
  var offset = vulnPage * vulnPageSize;

  var params = new URLSearchParams({ limit: vulnPageSize, offset: offset });
  if (sev) params.set('severity', sev);
  if (search) params.set('search', search);
  if (vulnTab === 'icp') params.set('has_icp', '1');

  return params;
}

async function loadVulnTable() {
  try {
    var data = await fetchAPI('/vulnerabilities?' + _vulnParams());
    renderVulnTable(data.items);
    renderVulnPagination(data.total);
  } catch (e) {
    document.querySelector('#vulnTable tbody').innerHTML =
      '<tr><td colspan="7" class="placeholder">加载失败: ' + e.message + '</td></tr>';
  }
}

function renderVulnTable(items) {
  var tbody = document.querySelector('#vulnTable tbody');
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="placeholder">暂无数据</td></tr>';
    return;
  }

  tbody.innerHTML = items.map(function(r) {
    var tm = r.scanned_at ? new Date(r.scanned_at).toLocaleString('zh-CN') : '-';
    var sev = r.severity || '-';
    return '<tr>' +
      '<td title="' + escapeHtml(r.vuln_name || '') + '">' + escapeHtml(truncate(r.vuln_name, 35)) + '</td>' +
      '<td><span class="severity severity-' + sev + '">' + sev + '</span></td>' +
      '<td><a href="' + escapeHtml(r.asset || '') + '" target="_blank" class="detail-link">' + escapeHtml(truncate(r.asset, 50)) + '</a></td>' +
      '<td>' + escapeHtml(r.icp_domain || '-') + '</td>' +
      '<td>' + escapeHtml(r.icp_number || '-') + '</td>' +
      '<td title="' + escapeHtml(r.icp_company || '') + '">' + escapeHtml(truncate(r.icp_company, 25)) + '</td>' +
      '<td class="vuln-time">' + tm + '</td>' +
      '</tr>';
  }).join('');
}

function renderVulnPagination(total) {
  var totalPages = Math.ceil(total / vulnPageSize) || 1;
  document.getElementById('vulnTotal').textContent = '共 ' + total + ' 条';

  var html = '';
  html += '<button ' + (vulnPage === 0 ? 'disabled' : '') + ' onclick="vulnGoPage(0)">首页</button>';
  html += '<button ' + (vulnPage === 0 ? 'disabled' : '') + ' onclick="vulnGoPage(' + (vulnPage - 1) + ')">上一页</button>';
  html += '<span class="page-info">' + (vulnPage + 1) + ' / ' + totalPages + '</span>';
  html += '<button ' + (vulnPage >= totalPages - 1 ? 'disabled' : '') + ' onclick="vulnGoPage(' + (vulnPage + 1) + ')">下一页</button>';
  html += '<button ' + (vulnPage >= totalPages - 1 ? 'disabled' : '') + ' onclick="vulnGoPage(' + (totalPages - 1) + ')">末页</button>';
  document.getElementById('vulnPagination').innerHTML = html;
}

function vulnGoPage(page) {
  vulnPage = page;
  loadVulnTable();
}

// --- CSV Export ---

document.getElementById('btnExportCSV').addEventListener('click', exportVulnCSV);

function exportVulnCSV() {
  var url = API_BASE + '/vulnerabilities/export?' + _vulnParams();
  var a = document.createElement('a');
  a.href = url;
  a.download = 'vulnerabilities.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}
