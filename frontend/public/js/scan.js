let scanPanelOpen = false;
let scanPollTimer = null;
let taskLogCache = {};
let openLogTaskId = null;

const STEP_NAMES = [null, '资产收集', '模板扫描', '主机提取', 'ICP 查询'];

function toggleScanPanel() {
  scanPanelOpen = !scanPanelOpen;
  var panel = document.getElementById('scanPanel');
  var btn = document.getElementById('btnScanToggle');

  if (scanPanelOpen) {
    panel.style.display = 'block';
    btn.classList.add('active');
    btn.textContent = '收起扫描';
    loadAllTasks();
    pollAllTasks();
  } else {
    panel.style.display = 'none';
    btn.classList.remove('active');
    btn.textContent = '执行扫描';
    stopPolling();
  }
}

document.getElementById('btnScanToggle').addEventListener('click', toggleScanPanel);

async function triggerScan() {
  var type = document.getElementById('scanType').value;
  var engine = document.getElementById('scanEngine').value;
  var poc = document.getElementById('scanPoc').value.trim();
  var btn = document.getElementById('btnScanStart');
  btn.disabled = true;
  btn.textContent = '启动中...';

  try {
    var res = await fetch(API_BASE + '/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: type, engine: engine, poc: poc || null }),
    });
    if (!res.ok) {
      var err = await res.json().catch(function() { return { error: res.statusText }; });
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    var data = await res.json();
    btn.textContent = '已提交 (' + data.task_id.slice(0, 8) + '...)';
    setTimeout(function() { btn.disabled = false; btn.textContent = '开始扫描'; }, 2000);
    if (data.task_id) taskLogCache[data.task_id] = { lastLogId: 0, logs: [] };
    loadAllTasks();
  } catch (e) {
    alert('扫描启动失败: ' + e.message);
    btn.disabled = false;
    btn.textContent = '开始扫描';
  }
}

document.getElementById('btnScanStart').addEventListener('click', triggerScan);

// --- Polling ---

function pollAllTasks() {
  stopPolling();
  scanPollTimer = setInterval(function() {
    loadAllTasks().then(function() {
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
  if (scanPollTimer) { clearInterval(scanPollTimer); scanPollTimer = null; }
}

// --- Load task list ---

async function loadAllTasks() {
  var el = document.getElementById('scanTaskList');
  try {
    var data = await fetchAPI('/tasks?limit=10');
    if (!data.length) {
      el.innerHTML = '<div class="placeholder">暂无扫描任务</div>';
      return;
    }
    el.innerHTML = data.map(renderTaskItem).join('');
  } catch (e) {
    el.innerHTML = '<div class="placeholder">加载失败: ' + e.message + '</div>';
  }
}

function renderTaskItem(t) {
  var statusMap = { running: '运行中', completed: '已完成', failed: '失败', started: '等待中', stopped: '已停止' };
  var typeMap = { categorized: '分类全量', 'categorized-incremental': '增量分类' };

  var actions = '<button class="scan-log-btn" onclick="toggleLogDetail(\'' + escapeHtml(t.task_id) + '\')">查看日志</button>';

  if (t.status === 'running' || t.status === 'started') {
    actions += ' <button class="scan-stop-btn" onclick="stopScan(\'' + escapeHtml(t.task_id) + '\')">停止</button>';
  }
  if (t.status === 'stopped') {
    actions += ' <button class="scan-resume-btn" onclick="resumeScan(\'' + escapeHtml(t.task_id) + '\')">继续</button>';
  }

  actions += ' <button class="scan-delete-logs-btn" onclick="deleteTaskLogs(\'' + escapeHtml(t.task_id) + '\')">清空日志</button>';
  actions += ' <button class="scan-delete-task-btn" onclick="deleteScanTask(\'' + escapeHtml(t.task_id) + '\')">删除任务</button>';

  var cs = t.current_step || 0;
  var stepLabels = ['资产', '扫描', '主机', 'ICP'];
  var stepCounts = [t.step1_assets, t.step2_vulns, t.step3_hosts, t.step4_icp];

  var dots = '';
  for (var i = 0; i < 4; i++) {
    var cls = '';
    if (t.status === 'completed') cls = 'done';
    else if (t.status === 'failed') cls = 'failed';
    else if (t.status === 'stopped') cls = (cs > i + 1) ? 'done' : (cs === i + 1 ? 'stopped' : '');
    else if (cs > i + 1) cls = 'done';
    else if (cs === i + 1) cls = 'active';
    dots += '<div class="scan-step-dot ' + cls + '" title="' + stepLabels[i] + ': ' + (stepCounts[i] || 0) + '"></div>';
  }

  var cache = taskLogCache[t.task_id];
  var previewLogs = (cache && cache.logs) ? cache.logs.slice(-2) : [];
  var logPreview = '';
  if (previewLogs.length && (t.status === 'running' || t.status === 'stopped')) {
    logPreview = previewLogs.map(function(l) {
      return '<div class="scan-log-preview">' + escapeHtml(l.message) + '</div>';
    }).join('');
  }

  var timeStr = t.started_at ? new Date(t.started_at).toLocaleString('zh-CN') : '';

  return [
    '<div class="scan-task-item" data-task-id="' + escapeHtml(t.task_id) + '" data-status="' + t.status + '">',
    '<div class="scan-task-main">',
    '<div class="scan-task-left">',
    '<span class="scan-task-type">' + (typeMap[t.task_type] || t.task_type) + '</span>',
    '<span class="scan-task-id" title="' + escapeHtml(t.task_id) + '">' + t.task_id.slice(0, 8) + '</span>',
    '<span class="scan-status ' + t.status + '">' + (statusMap[t.status] || t.status) + '</span>',
    '</div>',
    '<div class="scan-task-steps">' + dots + '</div>',
    '<span class="scan-task-time">' + timeStr + '</span>',
    '</div>',
    logPreview,
    '<div class="scan-task-actions">', actions, '</div>',
    '</div>'
  ].join('');
}

// --- Log fetching ---

async function fetchLogsSince(taskId) {
  var cache = taskLogCache[taskId] || { lastLogId: 0, logs: [] };
  try {
    var data = await fetchAPI('/scans/' + taskId + '/logs?since=' + cache.lastLogId);
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
  if (openLogTaskId === taskId) { closeLogDetail(); }
  else { showLogDetail(taskId); }
}

function showLogDetail(taskId) {
  openLogTaskId = taskId;
  var modal = document.getElementById('logDetailModal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'logDetailModal';
    modal.className = 'log-modal';
    modal.innerHTML = [
      '<div class="log-modal-mask" onclick="closeLogDetail()"></div>',
      '<div class="log-modal-content">',
      '<div class="log-modal-header">',
      '<span class="log-modal-title">扫描日志</span>',
      '<div class="log-modal-header-actions">',
      '<button class="log-modal-clear-btn" id="logModalClearBtn">清空日志</button>',
      '<button class="log-modal-close" onclick="closeLogDetail()">×</button>',
      '</div>',
      '</div>',
      '<div class="log-modal-body" id="logModalBody"></div>',
      '</div>'
    ].join('');
    document.body.appendChild(modal);
  }
  modal.style.display = 'block';
  document.getElementById('logModalClearBtn').onclick = function() { deleteTaskLogs(taskId); };
  refreshLogDetail(taskId);
}

function refreshLogDetail(taskId) {
  var body = document.getElementById('logModalBody');
  var cache = taskLogCache[taskId];
  if (!cache || !cache.logs || !cache.logs.length) {
    body.innerHTML = '<div class="placeholder">暂无日志</div>';
    return;
  }
  body.innerHTML = cache.logs.map(function(l) {
    var cls = l.level === 'ERROR' ? 'error' : l.level === 'WARNING' ? 'warn' : '';
    var tm = l.created_at ? new Date(l.created_at).toLocaleTimeString('zh-CN') : '';
    return '<div class="log-line ' + cls + '"><span class="log-time">' + tm + '</span><span class="log-msg">' + escapeHtml(l.message) + '</span></div>';
  }).join('');
  body.scrollTop = body.scrollHeight;
}

function closeLogDetail() {
  openLogTaskId = null;
  var modal = document.getElementById('logDetailModal');
  if (modal) modal.style.display = 'none';
}

// --- Stop / Resume ---

async function stopScan(taskId) {
  if (!confirm('确定要停止这个扫描任务吗？已完成的步骤不会丢失，之后可以继续。')) return;
  try {
    var res = await fetch(API_BASE + '/scans/' + taskId + '/stop', { method: 'POST' });
    if (!res.ok) {
      var err = await res.json().catch(function() { return { error: res.statusText }; });
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    loadAllTasks();
  } catch (e) {
    alert('停止失败: ' + e.message);
  }
}

async function resumeScan(taskId) {
  var btn = document.querySelector('.scan-resume-btn[onclick*="' + taskId + '"]');
  if (btn) { btn.disabled = true; btn.textContent = '启动中...'; }
  try {
    var res = await fetch(API_BASE + '/scans/' + taskId + '/resume', { method: 'POST' });
    if (!res.ok) {
      var err = await res.json().catch(function() { return { error: res.statusText }; });
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    var data = await res.json();
    taskLogCache[taskId] = { lastLogId: 0, logs: [] };
    loadAllTasks();
  } catch (e) {
    alert('继续扫描失败: ' + e.message);
    if (btn) { btn.disabled = false; btn.textContent = '继续'; }
  }
}

// --- Delete ---

async function deleteTaskLogs(taskId) {
  if (!confirm('确定要清空该任务的所有日志吗？')) return;
  try {
    var res = await fetch(API_BASE + '/scans/' + taskId + '/logs', { method: 'DELETE' });
    if (!res.ok) {
      var err = await res.json().catch(function() { return { error: res.statusText }; });
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    var data = await res.json();
    taskLogCache[taskId] = { lastLogId: 0, logs: [] };
    if (openLogTaskId === taskId) refreshLogDetail(taskId);
    loadAllTasks();
  } catch (e) {
    alert('清空日志失败: ' + e.message);
  }
}

async function deleteScanTask(taskId) {
  if (!confirm('确定要删除该扫描任务及其所有关联数据（资产、扫描结果、ICP 等）？此操作不可撤销。')) return;
  try {
    if (openLogTaskId === taskId) closeLogDetail();
    var res = await fetch(API_BASE + '/scans/' + taskId, { method: 'DELETE' });
    if (!res.ok) {
      var err = await res.json().catch(function() { return { error: res.statusText }; });
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    delete taskLogCache[taskId];
    loadAllTasks();
  } catch (e) {
    alert('删除任务失败: ' + e.message);
  }
}
