import { h, $, srOnly, pill } from '../ui/dom.js';
import { checkCard } from '../ui/card.js';
import { tiles } from '../ui/tiles.js';
import { domainTool, findingCards, resultVerdict, stat, nextSteps } from '../ui/findings.js';

const selEl = $('#tool-selector');

/** Key-strength meter: bits against the 1024 (weak) and 2048 (recommended) marks. */
function keyMeter(bits, type) {
  if (type && type !== 'rsa') return h('div', { class: 'text-sm' }, `${type} key: modern and compact, no RSA size to compare.`);
  const status = bits >= 2048 ? 'ok' : bits >= 1024 ? 'warn' : 'bad';
  const word = bits >= 2048 ? 'Strong' : bits >= 1024 ? 'Acceptable but aging' : 'Too weak';
  const pct = Math.min(100, (bits / 4096) * 100);
  const mark = (b, l) => h('span', { class: 'absolute top-0 h-3 border-l border-ink', style: `left:${(b / 4096) * 100}%` }, h('span', { class: 'absolute top-3.5 -translate-x-1/2 text-[10px] text-mute whitespace-nowrap' }, l));
  return h('div', null,
    h('div', { class: 'flex items-center gap-3 mb-2' }, h('span', { class: 'text-2xl font-bold mono' }, `${bits} bit`), pill(status, word)),
    h('div', { class: 'relative h-3 mb-6', 'aria-hidden': 'true' }, h('div', { class: 'bar-track h-3 w-full' }, h('div', { class: 'h-3 rounded-full', style: `width:${pct}%;background:var(--${status})` })), mark(1024, '1024'), mark(2048, '2048')),
    srOnly(`RSA key of ${bits} bits. ${word}. 2048 or more is recommended.`));
}

function render(res) {
  const d = res.data || {};
  const out = [resultVerdict(res)];
  const sels = d.selectors || [];
  if (sels.length) {
    out.push(h('div', { class: 'flex flex-wrap gap-2' }, stat('Selectors tried', String(d.probed ?? sels.length)), stat('Keys found', String(d.found_count ?? sels.filter((s) => s.found).length))));
    out.push(checkCard({
      status: (d.found_count || 0) > 0 ? 'ok' : 'warn', title: d.mode === 'single' ? `Selector "${d.selector}"` : 'Selector grid',
      body: tiles({ min: '8.5rem', items: sels.map((s) => ({
        label: s.selector, sub: s.found ? (s.key_type === 'rsa' ? `${s.bits} bit` : s.key_type) : s.hint || null,
        status: s.found ? (s.revoked ? 'warn' : 'ok') : 'mute', word: s.found ? (s.revoked ? 'Revoked' : 'Found') : 'Not found', title: s.name })) }),
      meaning: 'A selector is a label your mail provider chose. The public key lives at selector._domainkey.your-domain. We can only find keys at selector names we try; a "not found" tile means that name has no key, not that DKIM is off.',
      fix: (d.found_count || 0) === 0 ? { steps: ['Find the selector in a real message you sent: open its headers and look at the s= value in the DKIM-Signature line.', 'Enter it in the selector box above and check again.'] } : null,
    }));
    const keys = sels.filter((s) => s.found && s.bits);
    keys.forEach((s) => out.push(checkCard({ status: s.bits >= 2048 ? 'ok' : 'warn', title: `Key strength for ${s.selector}`, body: keyMeter(s.bits, s.key_type),
      meaning: '2048-bit RSA is the recommended size. 1024-bit keys still work but can be forged with enough computing power.',
      fix: s.bits < 2048 ? { steps: ['Generate a new 2048-bit key in your mail provider, publish it under a new selector, then switch signing over and remove the old record.'] } : null })));
  }
  out.push(...findingCards(res.findings));
  out.push(nextSteps([{ slug: 'dmarc-checker', q: res.target, text: 'Now check DMARC' }, { slug: 'domain-health', q: res.target, text: 'Run the full domain health report' }]));
  return out;
}

domainTool({
  endpoint: '/mail/dkim', render,
  heavy: () => !selEl.value.trim(),
  body: () => (selEl.value.trim() ? { selector: selEl.value.trim() } : {}),
  state: (d) => ({ q: d.target, ...(selEl.value.trim() ? { selector: selEl.value.trim() } : {}) }),
  after: (p) => { if (p.get('selector')) selEl.value = p.get('selector'); },
});
