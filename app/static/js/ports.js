(function () {
  const $ = (id) => document.getElementById(id);
  const form = $('port-form'), ipEl = $('port-ip'), numEl = $('port-num'), btn = $('port-submit'), common = $('port-common');
  const results = $('port-results'), err = $('port-error');
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const base = form.action.replace(/\/check$/, '');
  const cls = { open: 'st-ok', closed: 'st-bad', filtered: 'st-warn', error: 'st-bad' };

  fetch(base + '/myip').then((r) => r.json()).then((d) => {
    ipEl.value = d.ip + (d.public ? '' : ' (not a public address)');
  }).catch(() => { ipEl.value = 'unknown'; });

  async function run(body) {
    btn.disabled = common.disabled = true; err.classList.add('hidden');
    try {
      const r = await fetch(form.action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const data = await r.json();
      if (!r.ok) throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail));
      results.innerHTML = '<table><thead><tr><th>Port</th><th>Service</th><th>State</th><th>Time</th></tr></thead><tbody>' +
        data.results.map((x) => `<tr><td class="mono">${x.port}</td><td>${esc(x.service || '')}</td><td class="mono ${cls[x.state] || ''}">${esc(x.state)}</td><td class="mono text-slate-400">${x.ms != null ? x.ms + ' ms' : ''}</td></tr>`).join('') + '</tbody></table>';
      results.classList.remove('hidden');
    } catch (e) {
      results.classList.add('hidden'); err.textContent = e.message; err.classList.remove('hidden');
    } finally { btn.disabled = common.disabled = false; }
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const port = parseInt(numEl.value, 10);
    if (!(port >= 1 && port <= 65535)) { err.textContent = 'Enter a port between 1 and 65535.'; err.classList.remove('hidden'); return; }
    run({ port });
  });
  common.addEventListener('click', () => run({ common: true }));
})();
