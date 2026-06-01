let scanPanelOpen = false;
let scanPollTimer = null;
const taskLogCache = {};
let openLogTaskId = null;
let logPollTimer = null;

const STEP_NAMES = [null, '资产收集', '模板扫描', '主机提取', 'ICP 查询'];

document.getElementById('btnScanToggle').addEventListener('click', toggleScanPanel);
document.getElementById('btnScanStart').addEventListener('click', triggerScan);

function toggleScanPanel() {
  scanPanelOpen = !scanPanelOpen;
  const panel = document.getElementById('scanPanel');
  const btn = document.getElementById('btnScanToggle');

  if (scanPanelOpen) {
    panel.style.display = 'block';
    btn.textContent = '收起扫描';
    loadAllTasks();
    startPolling();
  } else {
    panel.style.display = 'none';
    btn.textContent = '执行扫描';
    stopPolling();
  }
}

async function triggerScan() {
  const type = document.getElementById('scanType').value;
  const engine = document.getElementById('scanEngine').value;
  const poc = document.getElementById('scanPoc').value.trim();
  const region = document.getElementById('scanRegion').value.trim();
  const btn = document.getElementById('btnScanStart');
  btn.disabled = true;
  btn.textContent = '启动中…';

  try {
    const res = await fetch(API_BASE + '/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, engine, poc: poc || null, region: region || null }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    const data = await res.json();
    btn.textContent = '已提交 (' + data.task_id.slice(0, 8) + '…)';
    setTimeout(() => { btn.disabled = false; btn.textContent = '开始扫描'; }, 2000);
    if (data.task_id) taskLogCache[data.task_id] = { lastLogId: 0, logs: [] };
    loadAllTasks();
  } catch (e) {
    Utils.showToast('扫描启动失败: ' + e.message, 'error');
    btn.disabled = false;
    btn.textContent = '开始扫描';
  }
}

// --- Polling ---

function startPolling() {
  stopPolling();
  scanPollTimer = setInterval(function() {
    loadAllTasks().then(function() {
      // 为运行中的任务拉取日志预览
      var rows = document.querySelectorAll('.scan-task-item');
      rows.forEach(function(row) {
        var status = row.dataset.status;
        if (status === 'running' || status === 'started') {
          fetchLogsSince(row.dataset.taskId);
        }
      });
      if (openLogTaskId) refreshLogDetail(openLogTaskId);
    });
  }, 3000);
}

function stopPolling() {
  if (scanPollTimer) {
    clearInterval(scanPollTimer);
    scanPollTimer = null;
  }
}

// --- Load task list ---

async function loadAllTasks() {
  const el = document.getElementById('scanTaskList');
  try {
    const data = await fetchAPI('/tasks?limit=10');
    if (!data.length) {
      el.innerHTML = '<div class="placeholder">暂无扫描任务</div>';
      return;
    }
    // Bulk-fetch logs only for running/started tasks (efficient batch)
    const runningTasks = data.filter(t => t.status === 'running' || t.status === 'started');
    for (const t of runningTasks) {
      await fetchLogsSince(t.task_id);
    }
    el.innerHTML = data.map(renderTaskItem).join('');
  } catch (e) {
    el.innerHTML = '<div class="placeholder">加载失败: ' + Utils.escapeHtml(e.message) + '</div>';
  }
}

function renderTaskItem(t) {
  const statusMap = { running: '运行中', completed: '已完成', failed: '失败', started: '等待中', stopped: '已停止' };
  const typeMap = { categorized: '分类全量', 'categorized-incremental': '增量分类' };
  const stepNames = ['', '资产收集', '模板扫描', '主机提取', 'ICP 查询'];

  let actions = '<button class="btn btn-ghost" onclick="toggleLogDetail(\'' + Utils.escapeHtml(t.task_id) + '\')">查看日志</button>';

  if (t.status === 'running' || t.status === 'started') {
    actions += ' <button class="btn btn-danger" onclick="stopScan(\'' + Utils.escapeHtml(t.task_id) + '\')">停止</button>';
  }
  if (t.status === 'stopped') {
    actions += ' <button class="btn btn-primary" onclick="resumeScan(\'' + Utils.escapeHtml(t.task_id) + '\')">继续</button>';
  }

  actions += ' <button class="btn btn-ghost" onclick="deleteTaskLogs(\'' + Utils.escapeHtml(t.task_id) + '\')">清空日志</button>';
  actions += ' <button class="btn btn-danger" onclick="deleteScanTask(\'' + Utils.escapeHtml(t.task_id) + '\')">删除任务</button>';

  const cs = t.current_step || 0;
  const stepLabels = ['资产', '扫描', '主机', 'ICP'];
  const stepCounts = [t.step1_assets, t.step2_vulns, t.step3_hosts, t.step4_icp];

  // 当前步骤摘要
  let stepSummary = '';
  if (t.status === 'running' && cs > 0 && cs <= 4) {
    stepSummary = '<div class="scan-step-summary">Step ' + cs + ' — ' + stepNames[cs] + '</div>';
  }

  let dots = '';
  for (let i = 0; i < 4; i++) {
    let cls = '';
    if (t.status === 'completed') cls = 'done';
    else if (t.status === 'failed') cls = 'failed';
    else if (t.status === 'stopped') cls = (cs > i + 1) ? 'done' : (cs === i + 1 ? 'stopped' : '');
    else if (cs > i + 1) cls = 'done';
    else if (cs === i + 1) cls = 'active';
    dots += '<div class="scan-step-dot ' + cls + '" title="' + stepLabels[i] + ': ' + (stepCounts[i] || 0) + '"></div>';
  }

  // 日志预览：取最近的模板级进度日志（过滤掉纯粹的 FOFA 错误/retry 日志）
  const cache = taskLogCache[t.task_id];
  const allLogs = (cache && cache.logs) ? cache.logs : [];
  const previewLogs = allLogs
    .filter(function(l) {
      const m = l.message || '';
      // 过滤掉纯错误日志（FOFA 查询失败、retry 等），保留进度日志
      if (m.indexOf('失败') !== -1 && m.indexOf('FOFA') !== -1) return false;
      if (m.indexOf('重试') !== -1) return false;
      return true;
    })
    .slice(-4);

  let logPreview = '';
  if (previewLogs.length) {
    logPreview = previewLogs.map(function(l) {
      return '<div class="scan-log-preview">' + Utils.escapeHtml(Utils.truncate(l.message, 80)) + '</div>';
    }).join('');
  }

  const timeStr = t.started_at ? new Date(t.started_at).toLocaleString('zh-CN') : '';

  return [
    '<div class="scan-task-item" data-task-id="' + Utils.escapeHtml(t.task_id) + '" data-status="' + t.status + '">',
    '<div class="scan-task-main">',
    '<div class="scan-task-left">',
    '<span class="scan-task-type">' + (typeMap[t.task_type] || t.task_type) + '</span>',
    '<span class="scan-task-id" title="' + Utils.escapeHtml(t.task_id) + '">' + t.task_id.slice(0, 8) + '</span>',
    '<span class="scan-status ' + t.status + '">' + (statusMap[t.status] || t.status) + '</span>',
    '</div>',
    '<div class="scan-task-steps">' + dots + '</div>',
    '<span class="scan-task-time">' + timeStr + '</span>',
    '</div>',
    stepSummary,
    logPreview,
    '<div class="scan-task-actions">', actions, '</div>',
    '</div>'
  ].join('');
}

// --- Log fetching ---

async function fetchLogsSince(taskId) {
  const cache = taskLogCache[taskId] || { lastLogId: 0, logs: [] };
  try {
    const data = await fetchAPI('/scans/' + taskId + '/logs?since=' + cache.lastLogId);
    if (data && data.length) {
      if (!cache.logs) cache.logs = [];
      cache.logs = cache.logs.concat(data);
      cache.lastLogId = data[data.length - 1].id;
      taskLogCache[taskId] = cache;
      if (openLogTaskId === taskId) refreshLogDetail(taskId);
    }
  } catch (e) { /* silent */ }
}

// --- Log detail modal ---

function toggleLogDetail(taskId) {
  if (openLogTaskId === taskId) {
    closeLogDetail();
  } else {
    showLogDetail(taskId);
  }
}

function showLogDetail(taskId) {
  openLogTaskId = taskId;
  let modal = document.getElementById('logDetailModal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'logDetailModal';
    modal.className = 'modal';
    modal.innerHTML = [
      '<div class="modal-mask" onclick="closeLogDetail()"></div>',
      '<div class="modal-content modal-log">',
      '<div class="modal-header">',
      '<span class="modal-title">扫描日志</span>',
      '<div class="modal-header-actions">',
      '<button class="btn btn-danger" id="logModalClearBtn">清空日志</button>',
      '<button class="modal-close" onclick="closeLogDetail()">×</button>',
      '</div>',
      '</div>',
      '<div class="modal-log-body" id="logModalBody"></div>',
      '</div>'
    ].join('');
    document.body.appendChild(modal);
  }
  modal.style.display = 'block';
  document.getElementById('logModalClearBtn').onclick = () => deleteTaskLogs(taskId);
  refreshLogDetail(taskId);
}

function refreshLogDetail(taskId) {
  const body = document.getElementById('logModalBody');
  const cache = taskLogCache[taskId];
  if (!cache || !cache.logs || !cache.logs.length) {
    body.innerHTML = '<div class="placeholder">暂无日志</div>';
    return;
  }

  // 合并连续相同日志：相同 message + level → 显示重复次数
  const collapsed = [];
  for (const l of cache.logs) {
    const last = collapsed[collapsed.length - 1];
    if (last && last.message === l.message && last.level === l.level) {
      last.count = (last.count || 1) + 1;
      last.lastTime = l.created_at;
    } else {
      collapsed.push({ message: l.message, level: l.level, created_at: l.created_at, count: 1 });
    }
  }

  body.innerHTML = collapsed.map(l => {
    const cls = l.level === 'ERROR' ? 'error' : l.level === 'WARNING' ? 'warn' : '';
    const tm = l.created_at ? new Date(l.created_at).toLocaleTimeString('zh-CN') : '';
    const repeat = l.count > 1 ? ' <span class="log-repeat">×' + l.count + '</span>' : '';
    return '<div class="log-line ' + cls + '"><span class="log-time">' + tm + '</span><span class="log-msg">' + Utils.escapeHtml(l.message) + '</span>' + repeat + '</div>';
  }).join('');
  body.scrollTop = body.scrollHeight;
}

function closeLogDetail() {
  openLogTaskId = null;
  const modal = document.getElementById('logDetailModal');
  if (modal) modal.style.display = 'none';
}

// --- Stop / Resume ---

async function stopScan(taskId) {
  if (!Utils.confirm('确定要停止这个扫描任务吗？已完成的步骤不会丢失，之后可以继续。')) return;
  try {
    const res = await fetch(API_BASE + '/scans/' + taskId + '/stop', { method: 'POST' });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    loadAllTasks();
  } catch (e) {
    Utils.showToast('停止失败: ' + e.message, 'error');
  }
}

async function resumeScan(taskId) {
  try {
    const res = await fetch(API_BASE + '/scans/' + taskId + '/resume', { method: 'POST' });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    const data = await res.json();
    taskLogCache[taskId] = { lastLogId: 0, logs: [] };
    loadAllTasks();
  } catch (e) {
    Utils.showToast('继续扫描失败: ' + e.message, 'error');
  }
}

// --- Delete ---

async function deleteTaskLogs(taskId) {
  if (!Utils.confirm('确定要清空该任务的所有日志吗？')) return;
  try {
    const res = await fetch(API_BASE + '/scans/' + taskId + '/logs', { method: 'DELETE' });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    taskLogCache[taskId] = { lastLogId: 0, logs: [] };
    if (openLogTaskId === taskId) refreshLogDetail(taskId);
    loadAllTasks();
  } catch (e) {
    Utils.showToast('清空日志失败: ' + e.message, 'error');
  }
}

async function deleteScanTask(taskId) {
  if (!Utils.confirm('确定要删除该扫描任务及其所有关联数据（资产、扫描结果、ICP 等）？此操作不可撤销。')) return;
  try {
    if (openLogTaskId === taskId) closeLogDetail();
    const res = await fetch(API_BASE + '/scans/' + taskId, { method: 'DELETE' });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    delete taskLogCache[taskId];
    loadAllTasks();
  } catch (e) {
    Utils.showToast('删除任务失败: ' + e.message, 'error');
  }
}
