(function init() {
  loadStats();
  initSeverityPie();
  loadTemplates(0);

  document.getElementById('icpFilter').addEventListener('change', () => loadTemplates(0));
  document.getElementById('severityFilter').addEventListener('change', () => loadTemplates(0));
  document.getElementById('templateSearch').addEventListener('input', Utils.debounce(() => loadTemplates(0), 300));

  document.querySelectorAll('.sub-tab').forEach(el => {
    el.addEventListener('click', () => setSubTab(el.dataset.tab));
  });

  document.getElementById('backBtn').addEventListener('click', goBack);
  document.getElementById('detailPanel').style.display = 'none';
})();
