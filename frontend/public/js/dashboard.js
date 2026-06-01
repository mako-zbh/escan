async function loadStats() {
  try {
    const data = await fetchAPI('/stats');
    const setStat = (id, val) => {
      const el = document.getElementById(id);
      el.classList.remove('skeleton');
      el.textContent = val || 0;
    };
    setStat('statTemplates', data.template_count);
    setStat('statAssets', data.asset_count);
    setStat('statHosts', data.host_count);
    setStat('statIcp', data.icp_count);
  } catch (e) {
    console.warn('Stats load failed:', e.message);
  }
}

function initSeverityPie() {
  const el = document.getElementById('severityPieChart');
  if (!el) return;
  if (typeof echarts === 'undefined') {
    console.warn('ECharts not loaded yet, retrying on load');
    window.addEventListener('load', initSeverityPie, { once: true });
    return;
  }
  const chart = echarts.init(el);

  fetchAPI('/severity').then(data => {
    const colors = {
      critical: '#dc2626', high: '#f97316', medium: '#eab308',
      low: '#3b82f6', info: '#9ca3af'
    };
    chart.setOption({
      title: { text: '严重性分布', left: 'center', textStyle: { color: '#1a1a2a', fontSize: 13 } },
      tooltip: { trigger: 'item' },
      series: [{
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['50%', '60%'],
        label: { color: '#6b7280', fontSize: 11 },
        data: Object.entries(data).map(([k, v]) => ({
          value: v, name: k, itemStyle: { color: colors[k] || '#888' }
        }))
      }]
    });
  }).catch(e => console.warn('Severity chart failed:', e.message));

  window.addEventListener('resize', () => chart.resize());
}
