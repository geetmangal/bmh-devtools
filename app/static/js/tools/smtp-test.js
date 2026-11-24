import { h, $, fmtMs, pill } from '../ui/dom.js';
import { initTool, qParam } from '../ui/tool.js';
import { checkCard } from '../ui/card.js';
import { timeline } from '../ui/timeline.js';
import { gauge } from '../ui/gauge.js';
import { keyValueTable } from '../ui/table.js';
import { findingCards, resultVerdict, cleanDomain } from '../ui/findings.js';

const hostEl = $('#tool-input'), portEl = $('#tool-port');

function render(res) {
  const d = res.data || {};
  if (d.enabled === false || d.applicable === false) {
    return [h('div', { class: 'card p-4' }, h('div', { class: 'font-semibold' }, 'Mail server tests are unavailable from our server'),
      h('p', { class: 'text-sm text-mute mt-1' }, 'Many networks block outbound mail ports, so this test is switched off on this site. You can still check the other parts of your email setup:'),
      h('ul', { class: 'text-sm mt-2 list-disc pl-5 space-y-0.5' }, [['mx-lookup', 'MX lookup'], ['spf-checker', 'SPF checker'], ['dmarc-checker', 'DMARC checker'], ['domain-health', 'Domain health']].map(([s, t]) => h('li', null, h('a', { href: `${location.pathname.replace(/[^/]+\/?$/, '')}${s}` }, t)))))];
  }
  const out = [resultVerdict(res)];
  const steps = (d.steps || []).map((s) => ({ label: s.step, sub: s.detail || '', ms: s.ms, status: s.ok ? 'ok' : 'bad', note: s.ok ? null : 'failed' }));
  if (steps.length) out.push(checkCard({ status: steps.every((s) => s.status === 'ok') ? 'ok' : 'bad', title: `Conversation with ${d.host}:${d.port}${d.total_ms != null ? ` (${fmtMs(d.total_ms)} in total)` : ''}`,
    body: timeline({ steps }),
    meaning: 'Each step is one message exchanged with the mail server. A step that fails shows where delivery would break; slow steps show where time goes.',
    details: d.banner ? `Banner: ${d.banner}` : undefined }));
  const t = d.tls;
  if (t) {
    const days = t.cert?.days_left;
    const s = days == null ? 'info' : days > 30 ? 'ok' : days > 7 ? 'warn' : 'bad';
    out.push(checkCard({ status: t.trusted === false ? 'bad' : s, title: `Encryption: ${t.version || 'not offered'}`,
      body: h('div', { class: 'flex flex-wrap items-center gap-5' },
        days != null ? gauge({ value: Math.max(0, Math.min(days, 90)), max: 90, label: String(days), unit: 'days left', status: s, semi: true, size: 150, sr: `Certificate expires in ${days} days` }) : null,
        keyValueTable([['Protocol', t.version], ['Cipher', t.cipher], ['Certificate trusted', t.trusted == null ? null : t.trusted ? 'yes' : 'no'], ['Issuer', t.cert?.issuer], ['Subject', t.cert?.subject], ['Expires', t.cert?.not_after]])),
      meaning: 'A valid, trusted certificate that is not about to expire lets other mail servers encrypt delivery to you. Expiry is the most common reason for sudden TLS failures.',
      fix: days != null && days <= 30 ? { steps: ['Renew the certificate and reload the mail server. If you use automatic renewal, check why it has not run.'] } : null }));
  }
  out.push(...findingCards(res.findings));
  return out;
}

initTool({
  form: '#tool-form',
  run: (ctx) => ctx.api('/smtp/check', { host: cleanDomain(hostEl.value), port: Number(portEl?.value || 25) }, { heavy: true }),
  render,
  state: (d) => ({ q: cleanDomain(hostEl.value), port: portEl?.value || '25' }),
  prefill: (p) => { const q = qParam(p, 'host'); if (q) hostEl.value = q; if (portEl && ['25', '587', '2525'].includes(p.get('port'))) portEl.value = p.get('port'); return !!q; },
});
void pill;
