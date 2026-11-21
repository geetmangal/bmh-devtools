(function () {
  const $ = (id) => document.getElementById(id);
  const form = $('rdns-form'), ipEl = $('rdns-ip'), btn = $('rdns-submit');
  const summary = $('rdns-summary'), results = $('rdns-results'), note = $('rdns-note'), err = $('rdns-error');
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const p = new URLSearchParams(location.search);
  if (p.get('ip')) ipEl.value = p.get('ip');

  function render(d) {
    const cls = d.fcrdns ? 'st-ok' : (d.ptr.length ? 'st-warn' : 'st-bad');
    summary.innerHTML = `<div class="card p-4"><div class="font-semibold mono">${esc(d.ip)}</div><div class="text-sm text-slate-400 mono">${esc(d.reverse_name)}</div><div class="mt-2 ${cls}">${esc(d.summary)}</div></div>`;
    summary.classList.remove('hidden');
    if (d.ptr.length) {
      results.innerHTML = '<table><thead><tr><th>PTR hostname</th><th>Resolves to</th><th>FCrDNS</th></tr></thead><tbody>' +
        d.ptr.map((r) => `<tr><td class="mono">${esc(r.hostname)}${r.generic ? '<div class="text-xs st-warn">looks like a generic ISP name</div>' : ''}</td><td class="mono text-slate-400">${r.forward_ips.map(esc).join('<br>') || '<span class="st-mute">no address</span>'}</td><td class="${r.forward_confirmed ? 'st-ok' : 'st-bad'}">${r.forward_confirmed ? 'match' : 'no match'}</td></tr>`).join('') + '</tbody></table>';
      results.classList.remove('hidden');
    } else { results.classList.add('hidden'); }
    let html = esc(d.mail_note);
    if (d.guide_url) html += ` <a href="${esc(d.guide_url)}">How to set a PTR record on a VPS</a>.`;
    note.innerHTML = html; note.classList.remove('hidden');
  }

  async function run() {
    const ip = ipEl.value.trim();
    if (!ip) return;
    btn.disabled = true; err.classList.add('hidden');
    try {
      const r = await fetch(form.action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) });
      const data = await r.json();
      if (!r.ok) throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail));
      render(data);
      history.replaceState(null, '', '?' + new URLSearchParams({ ip }));
    } catch (e) {
      [summary, results, note].forEach((x) => x.classList.add('hidden'));
      err.textContent = e.message; err.classList.remove('hidden');
    } finally { btn.disabled = false; }
  }

  form.addEventListener('submit', (e) => { e.preventDefault(); run(); });
  if (ipEl.value) run();
})();
