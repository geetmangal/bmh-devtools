import { h, $, clear, icon, statusOf, srOnly } from '../ui/dom.js';
import { initTool, qParam } from '../ui/tool.js';
import { progressBar } from '../ui/stream.js';
import { donut } from '../ui/tiles.js';
import { checkCard } from '../ui/card.js';
import { findingCards, resultVerdict, stat, nextSteps } from '../ui/findings.js';

const input = $('#tool-input');
const ROW_STATUS = { listed: 'bad', clear: 'ok', skipped: 'mute', timeout: 'warn', error: 'warn' };
const WORD = { listed: 'Listed', clear: 'Not listed', skipped: 'Skipped', timeout: 'No answer', error: 'Error' };
const RANK = { listed: 0, timeout: 1, error: 1, skipped: 2, clear: 3 };

function tile(row) {
  const s = ROW_STATUS[row.status] || 'mute', o = statusOf(s);
  return h('li', { class: `tile ${o.tile}`, title: row.reason || row.query || null },
    h('div', { class: 'flex items-center gap-1.5 text-sm font-semibold' }, h('span', { class: o.cls }, icon(s, 14)), h('span', { class: 'truncate' }, row.name)),
    h('div', { class: `text-xs ${o.cls}` }, WORD[row.status] || row.status, row.status === 'listed' && row.code ? ` (${row.code})` : ''),
    row.status === 'listed' && row.reason ? h('div', { class: 'text-xs text-mute' }, row.reason) : null,
    row.status === 'skipped' && row.note ? h('div', { class: 'text-xs text-mute' }, row.note) : null,
    row.status === 'listed' && row.delist_url ? h('a', { class: 'text-xs', href: row.delist_url, target: '_blank', rel: 'noopener noreferrer' }, 'How to get delisted') : null,
    row.status === 'timeout' ? h('div', { class: 'text-xs text-mute' }, 'The list did not answer in time.') : null);
}

function live() {
  const rows = [], bar = progressBar({ total: 0, noun: 'lists checked' });
  const grid = h('ul', { class: 'grid gap-2 list-none m-0 p-0', style: 'grid-template-columns:repeat(auto-fill,minmax(11rem,1fr))' });
  const count = h('div', { class: 'text-sm', 'aria-live': 'polite' }, 'Checking...');
  const el = h('div', { class: 'space-y-3' }, bar.el, count, grid);
  return {
    el, rows,
    add(o) {
      rows.push(o.row); grid.append(tile(o.row)); bar.update(o.done, o.total);
      const n = rows.filter((r) => r.status === 'listed').length;
      count.textContent = `${n} listing${n === 1 ? '' : 's'} found so far, ${o.done} of ${o.total} lists checked.`;
    },
    finish() {
      bar.finish();
      clear(grid).append(...[...rows].sort((a, b) => (RANK[a.status] ?? 9) - (RANK[b.status] ?? 9)).map(tile));
    },
  };
}

const tool = initTool({
  form: '#tool-form',
  async run(ctx) {
    const lv = live();
    let summary = null;
    await ctx.stream('/dnsbl/check', { target: input.value.trim() }, {
      onStart: () => clear(ctx.out).append(lv.el),
      onItem: (o) => { if (o.type === 'list') lv.add(o); else if (o.type === 'summary') summary = o.result; },
    });
    if (!summary) throw new Error('The check ended before it finished. Please try again.');
    lv.finish();
    const res = { ...summary };
    Object.defineProperty(res, '_live', { value: lv, enumerable: false });
    return res;
  },
  render(res) {
    const c = res.data?.counts || {};
    const checked = c.checked ?? (c.listed || 0) + (c.clear || 0);
    const out = [resultVerdict(res),
      h('div', { class: 'card p-4 flex flex-wrap items-center gap-5' },
        donut({ segments: [{ value: c.listed || 0, status: 'bad', label: 'listed' }, { value: c.clear || 0, status: 'ok', label: 'not listed' }, { value: (c.skipped || 0), status: 'mute', label: 'skipped' }, { value: (c.timeout || 0) + (c.error || 0), status: 'warn', label: 'no answer' }],
          center: `${c.listed || 0}/${checked}`, caption: 'listed on N of M lists checked', size: 130 }),
        h('div', { class: 'flex flex-wrap gap-2' }, stat('Listed', String(c.listed || 0)), stat('Not listed', String(c.clear || 0)), stat('Skipped', String(c.skipped || 0), 'not applicable'), stat('No answer', String((c.timeout || 0) + (c.error || 0)))),
        srOnly(`Listed on ${c.listed || 0} of ${checked} blocklists checked.`)),
      res._live.el,
      ...findingCards(res.findings)];
    out.push(nextSteps([/^[0-9a-f:.]+$/i.test(res.target || '') ? { slug: 'reverse-dns-lookup', q: res.target, text: 'Now check reverse DNS for this IP' } : { slug: 'spf-checker', q: res.target, text: 'Now check SPF' }, { slug: 'domain-health', q: res.target, text: 'Full domain health report' }]));
    return out;
  },
  state: (d) => ({ q: d.target || input.value.trim() }),
  prefill: (p) => { const q = qParam(p, 'target', 'ip', 'domain'); if (q) input.value = q; return !!q; },
});
void tool; void checkCard;
