(function init() {
  // stat cards
  loadStats();

  // severity pie
  initSeverityPie();

  // template library
  loadTemplates(0);

  // filter / search listeners
  document.getElementById('icpFilter').addEventListener('change', () => loadTemplates(0));
  document.getElementById('severityFilter').addEventListener('change', () => loadTemplates(0));
  document.getElementById('templateSearch').addEventListener('input', debounce(() => loadTemplates(0), 300));

  // sub-tab clicks
  document.querySelectorAll('.sub-tab').forEach(el => {
    el.addEventListener('click', () => setSubTab(el.dataset.tab));
  });

  // back button
  document.getElementById('backBtn').addEventListener('click', goBack);

  // hide detail panel initially
  document.getElementById('detailPanel').style.display = 'none';
})();

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}
