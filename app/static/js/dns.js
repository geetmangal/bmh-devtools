(function () {
  const $ = (id) => document.getElementById(id);
  const form = $('dns-form'), nameEl = $('dns-name'), typeEl = $('dns-type'), auto = $('dns-auto');
  const summary = $('dns-summary'), authBox = $('dns-auth'), results = $('dns-results'), err = $('dns-error'), btn = $('dns-submit');
  let timer = null;
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const flag = (cc) => cc && cc.length === 2 ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0))) : '';
  const statusCls = (r) => r.status === 'ok' ? (r.matches_authoritative ? 'st-ok' : 'st-warn') : (r.status === 'nxdomain' ? 'st-warn' : 'st-bad');

  // prefill from ?name=&type=
  const p = new URLSearchParams(location.search);
  if (p.get('name')) nameEl.value = p.get('name');
  if (p.get('type')) typeEl.value = p.get('type').toUpperCase();

  async function run() {
    const name = nameEl.value.trim(), type = typeEl.value;
    if (!name) return;
    btn.disabled = true; err.classList.add('hidden');
    try {
      const r = await fetch(form.action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, type }) });
      const data = await r.json();
      if (!r.ok) throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail));
      render(data);
      history.replaceState(null, '', '?' + new URLSearchParams({ name, type }));
    } catch (e) {
      err.textContent = e.message; err.classList.remove('hidden');
    } finally { btn.disabled = false; }
  }

  function render(d) {
    const s = d.summary, pct = s.total ? Math.round(100 * s.propagated / s.total) : 0;
    const cls = pct === 100 ? 'st-ok' : pct >= 50 ? 'st-warn' : 'st-bad';
    summary.innerHTML = `<div class="card p-4 flex flex-wrap items-center gap-4"><div class="text-3xl font-bold ${cls}">${s.propagated}/${s.total}</div><div><div class="font-semibold">${esc(d.name)} <span class="mono text-slate-400">${esc(d.type)}</span></div><div class="text-sm text-slate-400">resolvers match the authoritative answer. Checked at ${esc(d.queried_at)}</div></div><div class="flex-1 h-2 rounded bg-slate-800 min-w-[120px]"><div class="h-2 rounded bg-orange-500" style="width:${pct}%"></div></div></div>`;
    summary.classList.remove('hidden');
    const a = d.authoritative || {};
    authBox.innerHTML = `<span class="font-semibold">Authoritative</span> ${a.zone ? `zone <span class="mono">${esc(a.zone)}</span> via <span class="mono">${esc(a.label || '').replace('authoritative: ', '')}</span>` : '<span class="st-mute">could not be determined</span>'}: ` +
      (a.answers && a.answers.length ? `<span class="mono st-ok">${a.answers.map(esc).join(', ')}</span>${a.ttl != null ? ` <span class="st-mute">TTL ${a.ttl}</span>` : ''}` : `<span class="st-warn">${esc(a.status || 'no answer')}</span>`);
    authBox.classList.remove('hidden');
    let rows = d.resolvers.map((r) => `<tr><td>${flag(r.country)} ${esc(r.label)}<div class="mono text-xs text-slate-500">${esc(r.ip)}</div></td><td class="mono ${statusCls(r)}">${r.status === 'ok' ? (r.answers.length ? r.answers.map(esc).join('<br>') : '<span class="st-mute">no records</span>') : esc(r.status.toUpperCase())}</td><td class="mono text-slate-400">${r.ttl ?? ''}</td><td class="mono text-slate-400">${r.rtt_ms != null ? r.rtt_ms + ' ms' : ''}</td><td class="${statusCls(r)}">${r.status === 'ok' ? (r.matches_authoritative ? 'match' : 'differs') : r.status}</td></tr>`).join('');
    results.innerHTML = `<table><thead><tr><th>Resolver</th><th>Answer</th><th>TTL</th><th>RTT</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`;
    results.classList.remove('hidden');
  }

  form.addEventListener('submit', (e) => { e.preventDefault(); run(); });
  auto.addEventListener('change', () => {
    if (timer) { clearInterval(timer); timer = null; }
    if (auto.checked) { run(); timer = setInterval(run, 30000); }
  });
  if (nameEl.value) run();
})();
