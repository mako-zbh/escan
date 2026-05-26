let templatePage = 0;
const PAGE_SIZE = 30;

async function loadTemplates(page = 0) {
  templatePage = page;
  const sev = document.getElementById('severityFilter')?.value || '';
  const search = document.getElementById('templateSearch')?.value || '';
  const icp = document.getElementById('icpFilter')?.value || '';
  const offset = page * PAGE_SIZE;

  const params = new URLSearchParams({ limit: PAGE_SIZE, offset });
  if (sev) params.set('severity', sev);
  if (search) params.set('search', search);
  if (icp) params.set('has_icp', icp);

  try {
    const data = await fetchAPI(`/templates?${params}`);
    renderTemplateTable(data.items);
    renderPagination(data.total);
  } catch (e) {
    document.querySelector('#templateTable tbody').innerHTML =
      `<tr><td colspan="6" class="placeholder">加载失败: ${e.message}</td></tr>`;
  }
}

function renderTemplateTable(items) {
  const tbody = document.querySelector('#templateTable tbody');
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="placeholder">暂无数据</td></tr>';
    return;
  }

  tbody.innerHTML = items.map(item => `
    <tr data-template-id="${escapeHtml(item.template_id)}" onclick="selectTemplate('${escapeHtml(item.template_id)}', '${escapeHtml(item.name)}')">
      <td title="${escapeHtml(item.name)}">${escapeHtml(truncate(item.name, 40))}</td>
      <td><span class="severity severity-${item.severity || 'info'}">${item.severity || '-'}</span></td>
      <td>${item.asset_count}</td>
      <td>${item.hit_count}</td>
      <td>${item.domain_count}</td>
      <td>${item.icp_count}</td>
    </tr>
  `).join('');
}

function renderPagination(total) {
  const totalPages = Math.ceil(total / PAGE_SIZE);
  const el = document.getElementById('templatePagination');
  el.innerHTML = `
    <button ${templatePage === 0 ? 'disabled' : ''} onclick="loadTemplates(0)">首页</button>
    <button ${templatePage === 0 ? 'disabled' : ''} onclick="loadTemplates(${templatePage - 1})">上一页</button>
    <span class="page-info">${templatePage + 1} / ${totalPages || 1} (共 ${total} 条)</span>
    <button ${templatePage >= totalPages - 1 ? 'disabled' : ''} onclick="loadTemplates(${templatePage + 1})">下一页</button>
    <button ${templatePage >= totalPages - 1 ? 'disabled' : ''} onclick="loadTemplates(${totalPages - 1})">末页</button>
  `;
}

function selectTemplate(id, name) {
  document.querySelectorAll('#templateTable tbody tr').forEach(tr => {
    tr.classList.toggle('selected', tr.dataset.templateId === id);
  });
  loadTemplateDetail(id, name);
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function truncate(str, len) {
  if (!str) return '';
  return str.length > len ? str.slice(0, len) + '...' : str;
}
