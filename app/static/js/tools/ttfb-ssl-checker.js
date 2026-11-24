import { h, $, plural, fmtMs } from '../ui/dom.js';
import { initTool, qParam } from '../ui/tool.js';
import { verdict } from '../ui/verdict.js';
import { checkCard } from '../ui/card.js';
import { gauge } from '../ui/gauge.js';
import { waterfall } from '../ui/waterfall.js';
import { tree } from '../ui/tree.js';
import { keyValueTable, dataTable } from '../ui/table.js';

const urlEl = $('#tt-url');
const PHASES = [['dns_ms', 'DNS lookup'], ['tcp_ms', 'TCP connect'], ['tls_ms', 'TLS handshake'], ['ttfb_ms', 'Time to first byte'], ['download_ms', 'Download']];

function grade(d) {
  let score = 100; const c = d.ssl && d.ssl.certificate, ttfb = d.timing.ttfb_ms ? d.timing.ttfb_ms.min : null;
  if (ttfb != null) score -= ttfb > 800 ? 35 : ttfb > 500 ? 20 : ttfb > 200 ? 8 : 0;
  if (!d.ssl) score -= 30;
  if (c) {
    if (c.expired) score -= 50; else if (c.days_remaining < 14) score -= 25; else if (c.days_remaining < 30) score -= 10;
    if (!c.hostname_matches) score -= 30;
  }
  if (d.ssl && d.ssl.verification_error) score -= 30;
  if (d.status >= 400) score -= 30;
  if (d.ssl && !d.security.hsts) score -= 5;
  score = Math.max(0, score);
  const letter = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 50 ? 'D' : 'F';
  return { score, letter, status: score >= 80 ? 'ok' : score >= 50 ? 'warn' : 'bad' };
}

function render(d) {
  const t = d.timing, fs = d.timing_first_sample, s = d.ssl, c = s && s.certificate;
  const ttfb = t.ttfb_ms ? t.ttfb_ms.min : null;
  const g = grade(d);
  const ttfbStatus = ttfb == null ? 'info' : ttfb < 200 ? 'ok' : ttfb < 500 ? 'warn' : 'bad';
  const host = (() => { try { return new URL(d.final_url).hostname; } catch { return 'this site'; } })();
  const problems = [];
  if (ttfbStatus === 'bad') problems.push('the server is slow to respond');
  if (c && c.expired) problems.push('the certificate has expired');
  else if (c && c.days_remaining < 30) problems.push(`the certificate expires in ${c.days_remaining} days`);
  if (c && !c.hostname_matches) problems.push('the certificate does not match the hostname');
  if (!s) problems.push('the site is not using HTTPS');
  if (d.status >= 400) problems.push(`it returns HTTP ${d.status}`);
  const summary = `${host} answered ${d.status} ${d.reason} with the first byte after ${ttfb == null ? 'an unknown time' : fmtMs(ttfb)}, measured from India${problems.length ? '; but ' + problems.join(' and ') : '. No problems found'}.`;
  const out = [verdict({ status: g.status, grade: g.letter, score: g.score, title: g.status === 'ok' ? 'Fast and secure' : g.status === 'warn' ? 'Works, with things to fix' : 'Needs attention', summary, meta: `${d.final_url} - ${d.ip} - ${d.http_version}` })];

  // speed
  const phases = PHASES.map(([k, label]) => ({ label, ms: fs[k] || 0, note: t[k] ? `min ${t[k].min}` : '' }));
  out.push(checkCard({
    status: ttfbStatus, title: ttfb == null ? 'Response speed' : `Time to first byte: ${fmtMs(ttfb)} (best of ${d.samples})`,
    body: waterfall({ phases }),
    meaning: ttfbStatus === 'ok' ? 'The server starts answering quickly. Total time also depends on the page size and the visitor\'s distance.' : ttfbStatus === 'warn' ? 'Acceptable, but there is room to be faster. The time to first byte is how long the server takes to start replying once the request arrives.' : 'The server takes long to start replying. Slow code or database queries, no caching, an overloaded server or a faraway origin are the usual causes.',
    fix: ttfbStatus === 'ok' ? null : { steps: ['Turn on page caching (a caching plugin, or a CDN in front of the site).', 'Check slow database queries and PHP/app workers; add memory or CPU if the server is busy.', 'Host closer to your visitors: for Indian audiences a server in India removes 150 to 250 ms per round trip compared with Europe or the US.'] },
    details: dataTable(['Phase', 'First sample', 'Min', 'Avg'], PHASES.map(([k, l]) => [l, (fs[k] || 0).toFixed(1) + ' ms', t[k] ? t[k].min + ' ms' : '', t[k] ? t[k].avg + ' ms' : '']).concat([['Total (first sample)', fs.total_ms + ' ms', '', '']]), { mono: [1, 2, 3] }),
  }));

  // http status + redirects
  const redir = d.redirects || [];
  out.push(checkCard({
    status: d.status < 300 ? 'ok' : d.status < 400 ? 'warn' : 'bad', title: `HTTP ${d.status} ${d.reason}${redir.length ? ` after ${plural(redir.length, 'redirect')}` : ''}`,
    meaning: d.status < 300 ? 'The page loaded normally.' : d.status < 400 ? 'The final answer is itself a redirect.' : d.status < 500 ? 'The server says the request is wrong or not allowed (for example the page does not exist: 404).' : 'The server hit an error while handling the request.',
    fix: d.status >= 400 ? { steps: ['Open the URL in a browser to confirm what visitors see.', 'Check the web server and application error logs around this time.'] } : null,
    details: redir.length ? h('div', { class: 'mono text-xs space-y-1' }, ...redir.map((r, i) => h('div', { class: 'break-all' }, `${i + 1}. ${r.status} ${r.url} -> ${r.location} (${r.ms} ms)`)), h('div', { class: 'break-all' }, `${redir.length + 1}. ${d.status} ${d.final_url}`)) : null,
  }));

  // certificate
  if (s && c) {
    const dleft = c.days_remaining, cs = c.expired ? 'bad' : dleft < 14 ? 'bad' : dleft < 30 ? 'warn' : 'ok';
    const chain = {
      label: c.issuer.commonName || c.issuer.organizationName || 'Issuing authority', badge: 'issuer', status: s.verification_error ? 'bad' : 'ok',
      sub: `${s.chain_length != null ? plural(s.chain_length, 'certificate') + ' sent by the server' : 'chain length unknown'}${s.verification_error ? '; verification failed' : '; trusted'}`,
      children: [{ label: c.common_name, badge: 'your site', status: c.hostname_matches ? 'ok' : 'bad', sub: `${c.san.length} names (SAN), ${c.public_key_type} ${c.public_key_bits || ''}`.trim() }],
    };
    out.push(checkCard({
      status: cs, title: c.expired ? 'The SSL certificate has expired' : `SSL certificate is valid for ${plural(dleft, 'more day')}`,
      body: h('div', { class: 'flex flex-wrap items-center gap-6' }, gauge({ value: Math.max(0, Math.min(dleft, 90)), max: 90, label: c.expired ? '0' : String(dleft), unit: 'days left', status: cs, semi: true, size: 150, sr: `${c.expired ? 'expired' : dleft + ' days until the certificate expires'}` }), h('div', { class: 'flex-1 min-w-[16rem]' }, tree(chain))),
      meaning: c.expired ? 'Browsers show a full-page security warning for an expired certificate, and many visitors will leave.' : dleft < 30 ? 'The certificate runs out soon. If it does not renew automatically, visitors will see a security warning.' : 'The certificate is within its validity period and issued by a recognised authority.',
      fix: cs === 'ok' ? null : { steps: ['Renew or reissue the certificate (Let\'s Encrypt certificates last 90 days and should renew automatically).', 'If you use certbot, test renewal and check the timer or cron job is running.', 'Reload the web server afterwards so it serves the new certificate.'], code: 'sudo certbot renew --dry-run', codeLabel: 'Copy command' },
      details: keyValueTable([['Subject CN', c.common_name], ['Issuer', `${c.issuer.organizationName || ''} ${c.issuer.commonName ? '(' + c.issuer.commonName + ')' : ''}`.trim()], ['Valid from', c.not_before.slice(0, 10)], ['Expires', c.not_after.slice(0, 10)], ['Signature', c.signature_algorithm_oid], ['Public key', `${c.public_key_type} ${c.public_key_bits || ''}`], [`SAN (${c.san.length})`, c.san], ['OCSP responder', c.ocsp_responders.join(', ') || 'none'], ['SHA-256', c.sha256_fingerprint]]),
    }));
    out.push(checkCard({
      status: c.hostname_matches ? 'ok' : 'bad', title: c.hostname_matches ? `The certificate covers ${host}` : `The certificate does not cover ${host}`,
      meaning: c.hostname_matches ? 'The name in the address bar appears in the certificate\'s list of names (SAN), so browsers accept it.' : 'The certificate lists other names. Browsers show a warning because they cannot tell it belongs to this site.',
      fix: c.hostname_matches ? null : { steps: [`Reissue the certificate so that ${host} is one of its names.`, 'Make sure the web server (or virtual host) for this name loads that certificate.'] },
      details: c.san,
    }));
    if (s.verification_error || c.self_signed) {
      out.push(checkCard({ status: 'bad', title: c.self_signed ? 'The certificate is self-signed' : 'The certificate chain could not be verified',
        meaning: 'Browsers only trust certificates that chain up to an authority they know. A missing intermediate certificate or a self-signed one causes warnings or errors in some clients.',
        fix: { steps: ['Install the full chain (your certificate plus the intermediate certificates from the issuer) on the server.', 'For a self-signed certificate, replace it with one from a public authority such as Let\'s Encrypt.'] },
        details: s.verification_error || 'self-signed' }));
    }
    out.push(checkCard({
      status: s.tls_version === 'TLSv1.3' || s.tls_version === 'TLSv1.2' ? 'ok' : 'warn', title: `Connection uses ${s.tls_version}`,
      meaning: 'TLS encrypts the connection. TLS 1.3 and 1.2 are current; older versions are no longer considered safe.',
      fix: s.tls_version === 'TLSv1.3' || s.tls_version === 'TLSv1.2' ? null : { steps: ['Disable TLS 1.0 and 1.1 in the web server configuration and enable TLS 1.2 and 1.3.'] },
      details: keyValueTable([['TLS version', s.tls_version], ['Cipher', `${s.cipher} (${s.cipher_bits} bit)`], ['ALPN', s.alpn_preferred || 'none'], ['HTTP/2', s.http2_supported ? 'supported' : 'not offered']]),
    }));
    out.push(checkCard({
      status: d.security.hsts ? 'ok' : 'warn', title: d.security.hsts ? 'HSTS is on' : 'HSTS is not set',
      meaning: d.security.hsts ? 'The site tells browsers to always use HTTPS, which blocks downgrade attacks.' : 'HSTS makes browsers use HTTPS only. Without it, a first visit over plain HTTP can be intercepted.',
      fix: d.security.hsts ? null : { steps: ['Once HTTPS works everywhere on the site, send the header below from the web server.'], code: 'Strict-Transport-Security: max-age=31536000; includeSubDomains', codeLabel: 'Copy header' },
      details: d.security.hsts || null,
    }));
  } else {
    out.push(checkCard({ status: 'bad', title: 'This URL is plain HTTP: no encryption', meaning: 'Traffic can be read or changed on the way, and browsers label the page "Not secure".',
      fix: { steps: ['Install a certificate (Let\'s Encrypt is free) and serve the site over HTTPS.', 'Redirect all http:// requests to https:// and then enable HSTS.'] } }));
  }
  out.push(checkCard({ status: 'info', title: `Server: ${d.server || 'hidden'}`, meaning: `Response size ${d.response_bytes.toLocaleString()} bytes${d.truncated ? ' (capped at 1 MiB)' : ''}.`,
    details: keyValueTable(Object.entries(d.headers).map(([k, v]) => [k, v])) }));
  return out;
}

initTool({
  form: '#tt-form',
  run: (ctx) => ctx.api('/http/check', { url: urlEl.value.trim() }),
  render,
  state: () => ({ q: urlEl.value.trim() }),
  prefill: (p) => { const q = qParam(p, 'url'); if (q) urlEl.value = q; return !!q; },
});
