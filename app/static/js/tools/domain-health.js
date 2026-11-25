import { h, $, clear, icon, statusOf, srOnly, plural } from '../ui/dom.js';
import { initTool, qParam } from '../ui/tool.js';
import { progressBar } from '../ui/stream.js';
import { radar } from '../ui/radar.js';
import { verdict } from '../ui/verdict.js';
import { findingCard, st, bySeverity, cleanDomain, toolLink } from '../ui/findings.js';

const input = $('#tool-input');
const LABEL = { mx: 'Mail servers (MX)', spf: 'SPF', dmarc: 'DMARC', dkim: 'DKIM', bimi: 'BIMI', mta_sts: 'MTA-STS', tlsrpt: 'TLS reports', dnsrec: 'DNS records', dnsbl: 'Blocklists', smtp: 'Mail server connection' };
const TOOL = { mx: 'mx-lookup', spf: 'spf-checker', dmarc: 'dmarc-checker', dkim: 'dkim-checker', dnsrec: 'dns-lookup', dnsbl: 'blacklist-check', smtp: 'smtp-test' };

function row(name, r, domain) {
  const s = st(r.status), o = statusOf(s);
  return h('li', { class: 'card-flat px-3 py-2 flex items-start gap-3' },
    h('span', { class: `${o.cls} mt-0.5` }, icon(s, 16)),
    h('div', { class: 'min-w-0 flex-1' }, h('div', { class: 'text-sm font-semibold' }, LABEL[name] || name, h('span', { class: `ml-2 text-xs ${o.cls}` }, o.word)), h('div', { class: 'text-sm text-mute' }, r.summary || '')),
    TOOL[name] ? toolLink(TOOL[name], domain, 'Details') : null);
}

const gradeStatus = (g) => (g === 'A' || g === 'B' ? 'ok' : g === 'C' ? 'warn' : 'bad');

const tool = initTool({
  form: '#tool-form',
  async run(ctx) {
    const domain = cleanDomain(input.value);
    const list = h('ul', { class: 'list-none m-0 p-0 space-y-2' });
    const bar = progressBar({ total: 10, noun: 'checks done' });
    const liveEl = h('div', { class: 'space-y-3', 'aria-live': 'polite' }, bar.el, list);
    let summary = null;
    await ctx.stream('/health/domain', { domain }, {
      onStart: () => clear(ctx.out).append(liveEl),
      onItem: (o) => {
        if (o.type === 'check') { list.append(row(o.name, o.result, domain)); bar.update(o.done ?? list.children.length, o.total ?? 10); }
        else if (o.type === 'summary') summary = o.summary;
      },
    });
    if (!summary) throw new Error('The check ended before it finished. Please try again.');
    bar.finish();
    const res = { ...summary };
    Object.defineProperty(res, '_live', { value: list, enumerable: false });
    return res;
  },
  render(s) {
    const domain = s.domain;
    const areas = s.areas || [];
    const fixes = [...(s.fixes || [])].sort(bySeverity);
    const gs = gradeStatus(s.grade);
    const capRaw = Array.isArray(s.capped_by) ? s.capped_by : s.capped_by && typeof s.capped_by === 'object' ? Object.values(s.capped_by) : s.capped_by ? [s.capped_by] : [];
    const cap = capRaw.map((x) => (typeof x === 'string' ? x : x?.label || x?.reason || x?.title || x?.name || JSON.stringify(x)));
    const out = [verdict({ status: gs, grade: s.grade, score: s.score, title: s.grade <= 'B' ? 'Email setup looks healthy' : s.grade === 'C' ? 'Several things to improve' : 'Important problems to fix', meta: domain,
      summary: `${domain} scores ${s.score} out of 100 (grade ${s.grade}).${cap.length ? ' The grade is capped because of: ' + cap.join(', ') + '.' : ''} ${fixes.length ? plural(fixes.length, 'thing') + ' to fix, worst first, below.' : 'Nothing needs fixing.'}` })];
    if (areas.length >= 3) {
      out.push(h('div', { class: 'card p-4 grid gap-4 sm:grid-cols-[auto_1fr] items-center' },
        radar({ axes: areas.map((a) => ({ label: a.label, value: a.score })) }),
        h('ul', { class: 'list-none m-0 p-0 space-y-1.5' }, areas.map((a) => h('li', { class: 'flex items-center gap-2 text-sm' },
          h('span', { class: `pill ${statusOf(gradeStatus(a.grade)).pill}` }, a.grade), h('span', { class: 'flex-1' }, a.label), h('span', { class: 'mono text-mute' }, String(Math.round(a.score))))))),
        srOnly(areas.map((a) => `${a.label}: grade ${a.grade}, ${Math.round(a.score)} out of 100`).join('; ')));
    }
    if (fixes.length) out.push(h('section', { class: 'space-y-3' }, h('h2', { class: 'text-lg font-bold' }, 'What to fix, most important first'), ...fixes.map((f) => findingCard(f, { prefix: f.check ? `${LABEL[f.check] || f.check}:` : '' }))));
    out.push(h('details', { class: 'card p-4 tech' }, h('summary', { class: 'font-semibold cursor-pointer' }, 'All checks'), h('div', { class: 'mt-3' }, s._live)));
    return out;
  },
  state: (s) => ({ q: s.domain || cleanDomain(input.value) }),
  prefill: (p) => { const q = qParam(p, 'domain'); if (q) input.value = q; return !!q; },
});
void tool;
