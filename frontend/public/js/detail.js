let currentTemplateId = null;
let currentSubTab = 'urls';

async function loadTemplateDetail(id, name) {
  currentTemplateId = id;
  document.getElementById('detailTitle').textContent = truncate(name, 50);
  document.getElementById('detailPanel').style.display = 'flex';

  try {
    const data = await fetchAPI(`/templates/${id}`);
    renderDetailStats(data);
  } catch (e) {
    document.getElementById('detailStats').innerHTML =
      `<div class="placeholder">加载失败: ${e.message}</div>`;
  }

  setSubTab(currentSubTab);
}

function renderDetailStats(data) {
  // aggregate across tasks
  let totalAssets = 0, totalHits = 0, totalHosts = 0, totalIcpQueried = 0;
  (data.tasks || []).forEach(t => {
    totalAssets += t.asset_count || 0;
    totalHits += t.hits_found || 0;
    totalHosts += t.hosts_extracted || 0;
    totalIcpQueried += t.icp_queried ? 1 : 0;
  });

  const icpInfo = data.icp_summary || {};
  const hitRate = totalAssets > 0 ? Math.round(totalHits / totalAssets * 100) : 0;

  document.getElementById('detailStats').innerHTML = `
    <div class="detail-stat"><div class="value">${totalAssets}</div><div class="label">资产数</div></div>
    <div class="detail-stat"><div class="value">${totalHits}</div><div class="label">命中数</div></div>
    <div class="detail-stat"><div class="value">${hitRate}%</div><div class="label">命中率</div></div>
    <div class="detail-stat"><div class="value">${totalHosts}</div><div class="label">提取主机</div></div>
    <div class="detail-stat"><div class="value">${icpInfo.ips_with_data || 0}</div><div class="label">有数据 IP</div></div>
    <div class="detail-stat"><div class="value">${icpInfo.domains_with_icp || 0}</div><div class="label">有备案域名</div></div>
    <div class="detail-stat"><div class="value">${icpInfo.domains_found || 0}</div><div class="label">发现域名</div></div>
  `;
}

function setSubTab(tab) {
  currentSubTab = tab;
  document.querySelectorAll('.sub-tab').forEach(el => {
    el.classList.toggle('active', el.dataset.tab === tab);
  });
  if (!currentTemplateId) return;
  loadSubTabData(tab);
}

async function loadSubTabData(tab) {
  const wrap = document.getElementById('detailTableWrap');
  try {
    const data = await fetchAPI(`/templates/${currentTemplateId}/${tab}`);
    renderDetailTable(tab, data);
  } catch (e) {
    wrap.innerHTML = `<div class="placeholder">加载失败: ${e.message}</div>`;
  }
}

function renderDetailTable(tab, data) {
  const cols = {
    urls: ['url', 'host', 'port', 'scheme', 'title', 'engine', 'icp_number', 'icp_company'],
    domains: ['host', 'template_name', 'is_ip'],
    icp: ['domain', 'company', 'icp_number', 'ip_address', 'source'],
    vulns: ['matched_url', 'severity', 'protocol', 'scanned_at'],
  };
  const labels = {
    urls: ['URL', 'Host', 'Port', '协议', '标题', '来源', 'ICP 号', '备案单位'],
    domains: ['Host', '模板名', 'IP?'],
    icp: ['域名', '主办单位', 'ICP 号', 'IP', '来源'],
    vulns: ['命中 URL', '严重度', '协议', '扫描时间'],
  };

  const columns = cols[tab] || [];
  const headers = labels[tab] || [];

  if (!data.length) {
    document.getElementById('detailTable').innerHTML =
      '<thead></thead><tbody><tr><td class="placeholder">暂无数据</td></tr></tbody>';
    return;
  }

  let html = '<thead><tr>';
  headers.forEach(h => { html += `<th>${h}</th>`; });
  html += '</tr></thead><tbody>';

  data.forEach(row => {
    html += '<tr>';
    columns.forEach(col => {
      let val = row[col];
      if (col === 'severity') {
        val = `<span class="severity severity-${val || 'info'}">${val || '-'}</span>`;
      } else if (col === 'is_ip') {
        val = val ? '是' : '否';
      } else if (col === 'url' || col === 'matched_url') {
        val = `<a href="${escapeHtml(val || '')}" target="_blank" class="detail-link">${escapeHtml(truncate(val, 60))}</a>`;
      } else {
        val = escapeHtml(String(val ?? '-'));
        if (val.length > 60) val = val.slice(0, 60) + '...';
      }
      html += `<td>${val}</td>`;
    });
    html += '</tr>';
  });

  html += '</tbody>';
  document.getElementById('detailTable').innerHTML = html;
}

function goBack() {
  currentTemplateId = null;
  document.getElementById('detailTitle').textContent = '选择模板查看详情';
  document.getElementById('detailStats').innerHTML = '';
  document.getElementById('detailTable').innerHTML = '<thead></thead><tbody></tbody>';
  document.querySelectorAll('#templateTable tbody tr').forEach(tr => tr.classList.remove('selected'));
}
