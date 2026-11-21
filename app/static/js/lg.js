(function () {
  const $ = (id) => document.getElementById(id);
  const form = $('lg-form'), targetEl = $('lg-target'), toolEl = $('lg-tool'), btn = $('lg-submit');
  const summary = $('lg-summary'), results = $('lg-results'), raw = $('lg-raw'), err = $('lg-error');
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const api = form.action.replace(/\/lg\/run$/, '/lg');

  const p = new URLSearchParams(location.search);
  if (p.get('target')) targetEl.value = p.get('target');
  if (['ping', 'traceroute', 'bgp'].includes(p.get('tool'))) toolEl.value = p.get('tool');

  function hide() { [summary, results, raw, err].forEach((e) => e.classList.add('hidden')); }

  function renderPing(d) {
    const s = d.summary || {}, r = s.rtt_ms;
    const cls = d.reachable ? (s.loss_pct > 0 ? 'st-warn' : 'st-ok') : 'st-bad';
    summary.innerHTML = `<div class="card p-4"><div class="font-semibold">Ping ${esc(d.target)} <span class="mono text-slate-400">${esc(d.resolved_ip)}</span></div>` +
      `<div class="text-sm text-slate-400">${esc(d.source.label)}</div>` +
      `<div class="mt-2 mono ${cls}">${s.received != null ? `${s.received}/${s.sent} replies, ${s.loss_pct}% loss` : (d.timed_out ? 'timed out' : 'no result')}` +
      `${r ? ` &middot; rtt min/avg/max ${r.min}/${r.avg}/${r.max} ms` : ''}</div></div>`;
    summary.classList.remove('hidden');
  }

  function renderTrace(d) {
    summary.innerHTML = `<div class="card p-4"><div class="font-semibold">Traceroute ${esc(d.target)} <span class="mono text-slate-400">${esc(d.resolved_ip)}</span></div>` +
      `<div class="text-sm text-slate-400">${esc(d.source.label)} &middot; max ${d.max_hops} hops</div>` +
      `<div class="mt-2 ${d.reached ? 'st-ok' : 'st-warn'}">${d.reached ? 'Destination reached' : 'Destination did not answer (filtered or timed out)'}</div></div>`;
    summary.classList.remove('hidden');
    results.innerHTML = '<table><thead><tr><th>Hop</th><th>Address</th><th>RTT</th></tr></thead><tbody>' +
      d.hops.map((h) => `<tr><td class="mono">${h.hop}</td><td class="mono">${h.ip ? esc(h.ip) : '<span class="st-mute">*</span>'}</td><td class="mono text-slate-400">${h.rtt_ms != null ? h.rtt_ms + ' ms' : ''}</td></tr>`).join('') + '</tbody></table>';
    results.classList.remove('hidden');
  }

  function renderBgp(d) {
    summary.innerHTML = `<div class="card p-4"><div class="font-semibold">BGP route for ${esc(d.target)} <span class="mono text-slate-400">${esc(d.ip)}</span></div>` +
      `<div class="text-sm text-slate-400">${esc(d.source.name)}. ${esc(d.source.note)}</div>` +
      `<div class="mt-2 mono ${d.announced ? 'st-ok' : 'st-bad'}">Prefix ${esc(d.prefix || 'unknown')} ${d.announced ? 'announced' : 'not announced'}</div>` +
      `<div class="mt-1 text-sm">Origin: ${(d.origin_asns || []).map((a) => `<span class="mono">${esc(a.asn)}</span> ${esc(a.holder || '')}`).join(', ') || '<span class="st-mute">unknown</span>'}</div></div>`;
    summary.classList.remove('hidden');
    results.innerHTML = '<table><thead><tr><th>Collector</th><th>AS path</th></tr></thead><tbody>' +
      (d.paths || []).map((x) => `<tr><td class="text-slate-400">${esc(x.collector)} ${esc(x.location)}</td><td class="mono">${esc(x.as_path)}</td></tr>`).join('') + '</tbody></table>';
    results.classList.remove('hidden');
  }

  async function run() {
    const target = targetEl.value.trim(), tool = toolEl.value;
    if (!target) return;
    btn.disabled = true; btn.textContent = 'Running...'; hide();
    try {
      const url = tool === 'bgp' ? api + '/bgp' : api + '/run';
      const body = tool === 'bgp' ? { target } : { target, tool };
      const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const data = await r.json();
      if (!r.ok) throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail));
      if (tool === 'bgp') renderBgp(data);
      else {
        (tool === 'ping' ? renderPing : renderTrace)(data);
        raw.textContent = data.output; raw.classList.remove('hidden');
      }
      history.replaceState(null, '', '?' + new URLSearchParams({ target, tool }));
    } catch (e) {
      err.textContent = e.message; err.classList.remove('hidden');
    } finally { btn.disabled = false; btn.textContent = 'Run'; }
  }

  form.addEventListener('submit', (e) => { e.preventDefault(); run(); });
})();
