(function () {
  const $ = (id) => document.getElementById(id);
  const form = $('whois-form'), q = $('whois-query'), btn = $('whois-submit');
  const summary = $('whois-summary'), results = $('whois-results'), err = $('whois-error');
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const row = (k, v) => v == null || v === '' || (Array.isArray(v) && !v.length) ? '' : `<tr><th class="w-44 align-top">${esc(k)}</th><td class="mono">${Array.isArray(v) ? v.map(esc).join('<br>') : esc(v)}</td></tr>`;

  const p = new URLSearchParams(location.search);
  if (p.get('query')) q.value = p.get('query');

  function render(d) {
    summary.innerHTML = `<div class="card p-4"><div class="font-semibold">${esc(d.registered_domain || d.name || d.query)} <span class="mono text-slate-400">${esc(d.type)}</span></div><div class="text-sm text-slate-400">Source: ${esc(d.protocol.toUpperCase())} ${esc(d.source || '')}</div></div>`;
    summary.classList.remove('hidden');
    let rows = '';
    if (d.protocol === 'whois') {
      results.innerHTML = `<pre class="snippet mono text-xs p-3 overflow-x-auto">${esc(d.raw)}</pre>`;
    } else {
      const ev = d.events || {};
      if (d.type === 'domain') {
        rows = row('Domain', d.name) + row('Status', d.status) + row('Registered', ev.registration) + row('Expires', ev.expiration) +
          row('Last changed', ev.last_changed) + row('Nameservers', d.nameservers) + row('DNSSEC', d.dnssec ? 'signed' : 'not signed');
      } else {
        rows = row('Network name', d.name) + row('Handle', d.handle) + row('Range', d.start && d.end ? d.start + ' - ' + d.end : '') +
          row('CIDR', d.cidr) + row('Type', d.network_type) + row('Country', d.country) + row('Status', d.status) +
          row('Registered', ev.registration) + row('Last changed', ev.last_changed);
      }
      (d.entities || []).forEach((e) => { rows += row((e.roles || []).join(', ') || 'entity', [e.name, e.handle, e.iana_id ? 'IANA ID ' + e.iana_id : ''].filter(Boolean).join(' / ')); });
      results.innerHTML = `<table><tbody>${rows}</tbody></table>`;
    }
    results.classList.remove('hidden');
  }

  async function run() {
    const query = q.value.trim();
    if (!query) return;
    btn.disabled = true; err.classList.add('hidden');
    try {
      const r = await fetch(form.action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query }) });
      const data = await r.json();
      if (!r.ok) throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail));
      render(data);
      history.replaceState(null, '', '?' + new URLSearchParams({ query }));
    } catch (e) {
      summary.classList.add('hidden'); results.classList.add('hidden');
      err.textContent = e.message; err.classList.remove('hidden');
    } finally { btn.disabled = false; }
  }

  form.addEventListener('submit', (e) => { e.preventDefault(); run(); });
  if (q.value) run();
})();
