// --- Chart tick (left purple card) ---
(function () {
  const el = document.getElementById('trafficChart');
  if (!el || !window.__WG_CHART__) return;

  const ctx = el.getContext('2d');
  const labels = [], rx = [], tx = [];
  let last = null;

  const chart = new Chart(ctx, {
    type: 'line',
    data: { labels, datasets: [
      { label: 'RX (B/s)', data: rx, fill: true, tension: 0.35 },
      { label: 'TX (B/s)', data: tx, fill: true, tension: 0.35 }
    ]},
    options: {
      animation: false, responsive: true,
      scales: { y: { beginAtZero: true } },
      plugins: { legend: { display: true } }
    }
  });

  async function tick() {
    try {
      const r = await fetch(window.__WG_CHART__.metricsUrl);
      if (!r.ok) return;
      const j = await r.json(); // {ts, rx, tx} cumulés
      if (last) {
        const dt = j.ts - last.ts;
        if (dt > 0) {
          const vRx = Math.max(0, (j.rx - last.rx) / dt);
          const vTx = Math.max(0, (j.tx - last.tx) / dt);
          const t = new Date(j.ts * 1000).toLocaleTimeString();
          labels.push(t); rx.push(vRx); tx.push(vTx);
          if (labels.length > 60) { labels.shift(); rx.shift(); tx.shift(); }
          chart.update();
        }
      }
      last = j;
    } catch (_) {}
  }
  setInterval(tick, 1000);
})();

// --- Buttons (start/stop/restart) in right pane ---
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-action="hit"]');
  if (!btn) return;
  e.preventDefault();
  btn.classList.add('disabled');
  try {
    const url = btn.getAttribute('data-url');
    await fetch(url, { method: 'GET' });
    location.reload();
  } catch (_) {
    btn.classList.remove('disabled');
  }
});
