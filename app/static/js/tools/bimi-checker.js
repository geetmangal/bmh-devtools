import { h } from '../ui/dom.js';
import { codeBlock } from '../ui/card.js';
import { domainTool, findingCards, resultVerdict, stat, nextSteps } from '../ui/findings.js';

function render(res) {
  const d = res.data || {};
  const out = [resultVerdict(res)];
  if (d.record) {
    out.push(h('div', { class: 'flex flex-wrap gap-2' },
      stat('Logo (l=)', d.logo ? 'set' : 'none', d.logo ? 'link published' : 'no logo link'),
      stat('Certificate (a=)', d.vmc ? 'linked' : 'none', d.vmc ? 'VMC or CMC link' : 'needed for Gmail'),
      stat('DMARC enforced', d.dmarc_enforced ? 'yes' : 'no', d.dmarc_enforced ? 'quarantine or reject at 100%' : 'BIMI is ignored until it is')));
    out.push(h('div', null, h('div', { class: 'text-xs text-mute mb-1' }, `Published record${d.found_at && d.found_at !== res.target ? ' (inherited from ' + d.found_at + ')' : ''}`), codeBlock(d.record, 'Copy')));
    if (d.logo) out.push(h('p', { class: 'text-sm' }, h('span', { class: 'text-mute' }, 'Logo address: '), h('span', { class: 'mono break-all' }, d.logo)));
    if (d.vmc) out.push(h('p', { class: 'text-sm' }, h('span', { class: 'text-mute' }, 'Certificate address: '), h('span', { class: 'mono break-all' }, d.vmc)));
    out.push(h('p', { class: 'text-xs text-mute' }, 'We read DNS only. The SVG file and the certificate are not downloaded or validated.'));
  }
  out.push(...findingCards(res.findings));
  out.push(nextSteps([{ slug: 'dmarc-checker', q: res.target, text: 'Check DMARC' }, { slug: 'domain-health', q: res.target, text: 'Full domain health report' }]));
  return out;
}

domainTool({ endpoint: '/mail/bimi', render });
