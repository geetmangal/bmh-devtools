(function () {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const form = $('tt-form'), urlEl = $('tt-url'), btn = $('tt-submit'), err = $('tt-error');
  const PHASES = [['dns_ms', 'DNS', '#60a5fa'], ['tcp_ms', 'TCP connect', '#a78bfa'], ['tls_ms', 'TLS handshake', '#f472b6'], ['ttfb_ms', 'TTFB (wait)', '#fb923c'], ['download_ms', 'Download', '#4ade80']];
  const q = new URLSearchParams(location.search).get('url'); if (q) urlEl.value = q;

  async function run() {
    const url = urlEl.value.trim(); if (!url) return;
    btn.disabled = true; btn.textContent = 'Measuring (3 samples)...'; err.classList.add('hidden');
    try {
      const r = await fetch(form.action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
      const d = await r.json();
      if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : JSON.stringify(d.detail));
      render(d); history.replaceState(null, '', '?url=' + encodeURIComponent(url));
    } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); }
    finally { btn.disabled = false; btn.textContent = 'Check'; }
  }

  function tile(label, value, cls = '') { return `<div class="card p-3"><div class="text-xs text-slate-400">${label}</div><div class="text-xl font-bold mono ${cls}">${value}</div></div>`; }

  function render(d) {
    const t = d.timing, s = d.ssl, c = s && s.certificate;
    const ttfb = t.ttfb_ms ? t.ttfb_ms.min : null;
    const ttfbCls = ttfb == null ? '' : ttfb < 200 ? 'st-ok' : ttfb < 500 ? 'st-warn' : 'st-bad';
    const stCls = d.status < 300 ? 'st-ok' : d.status < 400 ? 'st-warn' : 'st-bad';
    $('tt-overview').innerHTML = tile('HTTP status', `${d.status} <span class="text-sm font-normal">${esc(d.reason)}</span>`, stCls) +
      tile('TTFB min / avg', ttfb == null ? 'n/a' : `${ttfb} <span class="text-sm">/ ${t.ttfb_ms.avg} ms</span>`, ttfbCls) +
      tile('Total (first sample)', `${d.timing_first_sample.total_ms} <span class="text-sm">ms</span>`) +
      tile('Server', `<span class="text-base">${esc(d.server || 'hidden')}</span><div class="text-xs text-slate-400 font-normal">${esc(d.http_version)}${s ? (s.http2_supported ? ', h2 available' : '') : ''} &middot; ${esc(d.ip)}</div>`);
    $('tt-overview').classList.remove('hidden');

    // waterfall from first sample (sequential phases)
    const fs = d.timing_first_sample; const total = Math.max(1, fs.total_ms); let offset = 0;
    let bars = PHASES.map(([k, label, color]) => {
      const v = fs[k] || 0, left = (offset / total) * 100, w = Math.max(0.5, (v / total) * 100); offset += v;
      const st = t[k];
      return `<div class="grid grid-cols-[110px_1fr_150px] sm:grid-cols-[140px_1fr_170px] items-center gap-2 text-xs py-1"><div class="text-slate-300">${label}</div><div class="h-5 bg-slate-800 rounded relative"><div class="absolute h-5 rounded" style="left:${left}%;width:${w}%;background:${color}"></div></div><div class="mono text-slate-400 text-right">${v.toFixed(1)} ms${st ? ` <span class="text-slate-500">(min ${st.min})</span>` : ''}</div></div>`;
    }).join('');
    $('tt-waterfall').innerHTML = `<h2 class="font-bold mb-2">Request waterfall <span class="text-xs font-normal text-slate-400">${esc(d.final_url)} &middot; ${d.samples} samples &middot; ${d.response_bytes.toLocaleString()} bytes${d.truncated ? ' (capped at 1 MiB)' : ''}</span></h2>${bars}`;
    $('tt-waterfall').classList.remove('hidden');

    const rd = $('tt-redirects');
    if (d.redirects && d.redirects.length) {
      rd.innerHTML = `<h2 class="font-bold mb-2">Redirect chain (${d.redirects.length})</h2>` + d.redirects.map((r, i) => `<div class="mono text-xs py-1 break-all">${i + 1}. <span class="st-warn">${r.status}</span> ${esc(r.url)} &rarr; ${esc(r.location)} <span class="text-slate-500">${r.ms} ms</span></div>`).join('') + `<div class="mono text-xs py-1 break-all">${d.redirects.length + 1}. <span class="${stCls}">${d.status}</span> ${esc(d.final_url)}</div>`;
      rd.classList.remove('hidden');
    } else rd.classList.add('hidden');

    const sslBox = $('tt-ssl');
    if (s) {
      const yn = (b, good = true) => b ? `<span class="${good ? 'st-ok' : 'st-bad'}">yes</span>` : `<span class="${good ? 'st-bad' : 'st-ok'}">no</span>`;
      const row = (k, v) => `<tr><th class="text-slate-400 whitespace-nowrap">${k}</th><td class="mono break-all">${v}</td></tr>`;
      let rows = row('TLS version', esc(s.tls_version)) + row('Cipher', `${esc(s.cipher)} (${s.cipher_bits} bit)`) + row('ALPN / HTTP/2', `${esc(s.alpn_preferred || 'none')} ${s.http2_supported ? '<span class="st-ok">h2 supported</span>' : ''}`) + row('Chain length', s.chain_length ?? 'unknown') + row('Chain verified', yn(!s.verification_error)) + (s.verification_error ? row('Verification error', `<span class="st-bad">${esc(s.verification_error)}</span>`) : '');
      if (c) {
        const dCls = c.expired ? 'st-bad' : c.days_remaining < 14 ? 'st-warn' : 'st-ok';
        rows += row('Subject CN', esc(c.common_name)) + row('Issuer', esc(c.issuer.organizationName || c.issuer.commonName) + (c.issuer.commonName ? ` <span class="text-slate-500">(${esc(c.issuer.commonName)})</span>` : '')) +
          row('Valid from', esc(c.not_before.slice(0, 10))) + row('Expires', `${esc(c.not_after.slice(0, 10))} <span class="${dCls}">${c.expired ? 'EXPIRED' : c.days_remaining + ' days left'}</span>`) +
          row('Hostname matches', yn(c.hostname_matches)) + row('Self-signed', yn(c.self_signed, false)) + row('Signature', `${esc(c.signature_algorithm_oid)}`) + row('Public key', `${esc(c.public_key_type)} ${c.public_key_bits || ''}`) +
          row('SAN (' + c.san.length + ')', c.san.map(esc).join('<br>')) + row('OCSP responder', c.ocsp_responders.map(esc).join('<br>') || 'none') + row('SHA-256', `<span class="text-xs">${esc(c.sha256_fingerprint)}</span>`);
      }
      rows += row('HSTS', d.security.hsts ? `<span class="st-ok">${esc(d.security.hsts)}</span>` : '<span class="st-warn">not set</span>');
      sslBox.innerHTML = `<h2 class="font-bold mb-2">SSL / TLS</h2><table><tbody>${rows}</tbody></table>`; sslBox.classList.remove('hidden');
    } else { sslBox.innerHTML = `<h2 class="font-bold mb-2">SSL / TLS</h2><p class="st-warn">Plain HTTP: no TLS. ${d.security.hsts ? '' : 'Consider serving over HTTPS.'}</p>`; sslBox.classList.remove('hidden'); }

    const hb = $('tt-headers');
    hb.innerHTML = `<h2 class="font-bold mb-2">Response headers</h2><table><tbody>${Object.entries(d.headers).map(([k, v]) => `<tr><th class="text-slate-400 whitespace-nowrap">${esc(k)}</th><td class="mono break-all text-xs">${esc(v)}</td></tr>`).join('') || '<tr><td class="st-mute">none captured</td></tr>'}</tbody></table>`;
    hb.classList.remove('hidden');
  }
  form.addEventListener('submit', (e) => { e.preventDefault(); run(); });
  if (urlEl.value) run();
})();
