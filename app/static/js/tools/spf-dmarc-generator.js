// SPF & DMARC record generator: everything happens in the browser. No network call is made and nothing is stored.
// The pure builders live in ../ui/spfdmarc.js. initTool dispatches bmh:result (ok / warn) after each build.
import { h, $, $$, plural } from '../ui/dom.js';
import { initTool, qParam } from '../ui/tool.js';
import { verdict } from '../ui/verdict.js';
import { checkCard, codeBlock } from '../ui/card.js';
import { nextSteps } from '../ui/findings.js';
import { buildSpf, buildDmarc, bareDomain } from '../ui/spfdmarc.js';

const domainEl = $('#gen-domain');
const val = (id) => ($(id) ? $(id).value : '');

function read() {
  const domain = bareDomain(domainEl.value);
  return {
    domain,
    spf: { includes: $$('#spf-providers input[data-include]:checked').map((c) => c.dataset.include), a: $('#spf-a').checked, mx: $('#spf-mx').checked, ip4: val('#spf-ip4'), ip6: val('#spf-ip6'), extraIncludes: val('#spf-include'), all: val('#spf-all') },
    dmarc: { p: val('#dm-p'), sp: val('#dm-sp'), pct: val('#dm-pct'), rua: val('#dm-rua'), ruf: val('#dm-ruf'), adkim: val('#dm-adkim'), aspf: val('#dm-aspf'), fo: val('#dm-fo'), domain },
  };
}

function recordBlock({ title, host, type, record, strings, note }) {
  const split = strings.length > 1 ? h('div', { class: 'mt-2' }, h('div', { class: 'text-xs text-mute mb-1' }, `Longer than 255 characters: if your DNS panel does not split it, publish ${strings.length} strings`), codeBlock(strings.map((s) => `"${s}"`).join(' '), 'Copy split')) : null;
  return h('section', { class: 'card p-4 space-y-2' },
    h('h2', { class: 'text-lg font-bold' }, title),
    h('dl', { class: 'grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm' },
      h('dt', { class: 'text-mute' }, 'Type'), h('dd', { class: 'mono' }, type),
      h('dt', { class: 'text-mute' }, 'Name / host'), h('dd', { class: 'mono break-all' }, host)),
    h('div', { class: 'text-xs text-mute' }, 'Value'),
    codeBlock(record, 'Copy value'), split, note ? h('p', { class: 'text-xs text-mute' }, note) : null);
}

function warnCard(w) {
  return checkCard({ status: w.status === 'bad' ? 'bad' : w.status === 'warn' ? 'warn' : 'info', title: w.title, meaning: w.meaning });
}

function render(d) {
  const { spf, dmarc, domain } = d;
  const all = [...spf.warnings.map((w) => ({ ...w, kind: 'SPF' })), ...dmarc.warnings.map((w) => ({ ...w, kind: 'DMARC' }))];
  const worst = all.some((w) => w.status === 'bad') ? 'bad' : all.some((w) => w.status === 'warn') ? 'warn' : 'ok';
  const spfNote = `${spf.exact ? '' : 'At least '}${plural(spf.lookups, 'DNS lookup')} of 10 allowed${spf.exact ? '' : ' (nested includes add more)'}`;
  const out = [verdict({
    status: worst, title: worst === 'ok' ? 'Records ready to publish' : worst === 'warn' ? 'Ready, with things to check' : 'Fix the errors below',
    summary: `SPF: ${spf.length} characters, ${spfNote}. DMARC policy: p=${dmarc.p}${dmarc.pct !== 100 ? ` for ${dmarc.pct}% of mail` : ''}.`, meta: domain || 'example.com',
  })];
  out.push(recordBlock({ title: 'SPF record', type: 'TXT', host: domain ? `${domain}  (or @ in most DNS panels)` : '@  (the domain itself)', record: spf.record, strings: spf.strings,
    note: 'Publish exactly one SPF record per domain. If one already exists, merge the entries into it instead of adding a second.' }));
  out.push(recordBlock({ title: 'DMARC record', type: 'TXT', host: `_dmarc  (full name ${dmarc.fqdn})`, record: dmarc.record, strings: dmarc.strings,
    note: 'Some DNS panels want only _dmarc, others the full name; they add the domain themselves, so do not type it twice.' }));
  if (all.length) out.push(...all.map((w) => warnCard({ ...w, title: `${w.kind}: ${w.title}` })));
  out.push(nextSteps([{ slug: 'spf-checker', q: domain, text: 'Check the published SPF record' }, { slug: 'dmarc-checker', q: domain, text: 'Check the DMARC record' }, { slug: 'dkim-checker', q: domain, text: 'Check DKIM' }], 'After publishing:'));
  return out;
}

const tool = initTool({
  form: '#gen-form',
  run: async () => read(),
  render,
  state: (d) => (d.domain ? { q: d.domain } : {}),
  prefill: (p) => { const q = qParam(p, 'domain'); if (q) domainEl.value = bareDomain(q); return !!q; },
  autoCacheNote: false,
});

// Live output: rebuild shortly after every change; also build once on load.
let timer = null;
$('#gen-form').addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => tool.execute(), 250); });
$('#gen-form').addEventListener('change', () => { clearTimeout(timer); timer = setTimeout(() => tool.execute(), 100); });
if (!qParam(new URLSearchParams(location.search), 'domain')) tool.execute();
