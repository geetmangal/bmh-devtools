import { h, $, plural, pill } from '../ui/dom.js';
import { initTool, qParam, config } from '../ui/tool.js';
import { checkCard } from '../ui/card.js';
import { gauge } from '../ui/gauge.js';
import { dataTable } from '../ui/table.js';
import { findingCards, resultVerdict, stat, partialNote, nextSteps } from '../ui/findings.js';
import { asGraph } from '../viz/asgraph.js';

const input = $('#tool-input');
const asnOf = (v) => { const m = /^\s*(?:as)?\s*(\d{1,10})\s*$/i.exec(v || ''); return m ? m[1] : null; };

const RPKI = { valid: ['ok', 'Valid'], invalid: ['bad', 'Invalid'], unknown: ['mute', 'No ROA'], 'not-found': ['mute', 'No ROA'] };
const rpkiPill = (r) => { const k = typeof r === 'string' ? r : r?.state || r?.status; const [s, w] = RPKI[k] || ['mute', k || 'Not checked']; return pill(s, w); };

const PAGE = 50;
const rpkiKey = (r) => (typeof r === 'string' ? r : r?.state || r?.status || '');
const rpkiText = (r) => { const k = rpkiKey(r); return `${k} ${(RPKI[k] || [])[1] || ''}`.toLowerCase(); };

/** Prefix table: first 50 rows, "Show 50 more" / "Show all", live filter by prefix text or RPKI state. Keeps the RPKI chips. */
function prefixTable(list) {
  const rows = list.map((x) => ({
    hay: `${x.prefix} ${rpkiText(x.rpki)}`.toLowerCase(),
    cells: [h('a', { href: `${config.prefix}/bgp-prefix-lookup?q=${encodeURIComponent(x.prefix)}` }, x.prefix), rpkiPill(x.rpki), (x.first_seen || '').slice(0, 10)],
  }));
  let shown = PAGE, query = '';
  const body = h('div');
  const counter = h('p', { class: 'text-sm text-mute', role: 'status', 'aria-live': 'polite', 'aria-atomic': 'true' });
  const filterEl = h('input', { type: 'search', class: 'mono', placeholder: 'Filter by prefix or RPKI state (valid, invalid, no roa)', 'aria-label': 'Filter prefixes by prefix text or RPKI state', autocomplete: 'off', spellcheck: 'false' });
  const moreBtn = h('button', { type: 'button', class: 'btn btn-ghost btn-sm' });
  const allBtn = h('button', { type: 'button', class: 'btn btn-ghost btn-sm' });
  const bar = h('div', { class: 'flex flex-wrap items-center gap-2' }, moreBtn, allBtn);
  const draw = () => {
    const terms = query.split(/\s+/).filter(Boolean);
    const match = terms.length ? rows.filter((r) => terms.every((t) => r.hay.includes(t))) : rows;
    const vis = match.slice(0, shown);
    body.replaceChildren(vis.length ? dataTable(['Prefix', 'Route validation (RPKI)', 'First seen'], vis.map((r) => r.cells), { mono: [0] }) : h('p', { class: 'text-sm text-mute' }, 'No prefixes match this filter.'));
    const left = match.length - vis.length;
    counter.textContent = `Showing ${vis.length} of ${match.length}${match.length !== rows.length ? ` (filtered from ${rows.length})` : ''}`;
    moreBtn.textContent = `Show ${Math.min(PAGE, left)} more`;
    moreBtn.setAttribute('aria-label', `Show ${Math.min(PAGE, left)} more prefixes`);
    allBtn.textContent = `Show all (${match.length})`;
    allBtn.setAttribute('aria-label', `Show all ${match.length} prefixes`);
    bar.style.display = left <= 0 ? 'none' : '';
  };
  moreBtn.addEventListener('click', () => { shown += PAGE; draw(); });
  allBtn.addEventListener('click', () => { shown = rows.length; draw(); });
  filterEl.addEventListener('input', () => { query = filterEl.value.trim().toLowerCase(); shown = PAGE; draw(); });
  draw();
  return h('div', { class: 'space-y-2' }, rows.length > PAGE ? filterEl : null, counter, body, bar);
}

function render(res) {
  const p = res.prefixes || {}, nb = res.neighbours || {}, rp = res.rpki || {}, pdb = res.peeringdb || {};
  const out = [resultVerdict({ ...res }, { meta: `AS${res.asn}${res.holder ? ' - ' + res.holder : res.name ? ' - ' + res.name : ''}` })];
  const cov = rp.covered_pct;
  out.push(h('div', { class: 'card p-4 flex flex-wrap items-center gap-5' },
    cov != null ? gauge({ value: cov, max: 100, label: `${Math.round(cov)}%`, unit: 'RPKI covered', status: cov >= 90 ? 'ok' : cov >= 50 ? 'warn' : 'bad', semi: true, size: 150, sr: `${Math.round(cov)} percent of checked prefixes have a ROA` }) : null,
    h('div', { class: 'flex flex-wrap gap-2' },
      stat('Prefixes', p.count != null ? String(p.count) : 'n/a', p.count != null ? `${p.v4 ?? 0} IPv4, ${p.v6 ?? 0} IPv6` : 'not available right now'),
      stat('Upstreams', nb.counts ? String(nb.counts.left ?? (nb.upstreams || []).length) : 'n/a', 'networks it buys transit from'),
      stat('Downstreams', nb.counts ? String(nb.counts.right ?? (nb.downstreams || []).length) : 'n/a'),
      stat('Internet exchanges', pdb.ix_count != null ? String(pdb.ix_count) : 'n/a', pdb.unique_ix != null ? `${pdb.unique_ix} distinct` : null))));
  const pn = partialNote(res); if (pn) out.push(pn);

  if (res.graph && (res.graph.nodes || []).length > 1) {
    out.push(checkCard({ status: 'info', title: 'Who it connects to',
      body: asGraph({ graph: res.graph, onPivot: (asn) => { input.value = 'AS' + asn; tool.execute(); } }),
      meaning: 'Upstreams are networks this AS pays to reach the rest of the internet. Downstreams are its customers. Peers swap traffic for free. Bigger circles are neighbours seen by more route-collector peers.' }));
  }
  if ((p.list || []).length) {
    out.push(checkCard({ status: 'info', title: `Announced prefixes (${p.list.length}${p.truncated ? '+, list cut off' : ''})`,
      body: prefixTable(p.list),
      meaning: 'Each line is a block of IP addresses this AS tells the internet it can deliver to. A "Valid" mark means a signed record (ROA) confirms the AS is allowed to announce it.' }));
  }
  const ix = pdb.ix_list || [];
  if (ix.length || (pdb.facilities || []).length) {
    out.push(checkCard({ status: 'info', title: `Where it connects: ${plural(ix.length, 'exchange')}, ${plural((pdb.facilities || []).length, 'facility', 'facilities')}`,
      body: h('div', { class: 'space-y-3' },
        ix.length ? dataTable(['Exchange', 'City', 'Speed', 'Route server'], ix.map((x) => [x.name, [x.city, x.country].filter(Boolean).join(', '), x.speed ? `${x.speed >= 1000 ? x.speed / 1000 + ' Gbit/s' : x.speed + ' Mbit/s'}` : '', x.is_rs_peer ? 'yes' : 'no'])) : null,
        (pdb.facilities || []).length ? dataTable(['Facility', 'City'], pdb.facilities.map((x) => [x.name, [x.city, x.country].filter(Boolean).join(', ')])) : null),
      meaning: 'Internet exchanges and data centres where this network is present, from PeeringDB (a self-reported public database).' }));
  }
  out.push(...findingCards(res.findings));
  if ((res.notes || []).length) out.push(h('p', { class: 'text-xs text-mute' }, res.notes.join(' ')));
  out.push(nextSteps([{ slug: 'bgp-prefix-lookup', q: (p.list || [])[0]?.prefix, text: 'Look up a prefix' }, { slug: 'looking-glass', text: 'Trace the path from India' }]));
  return out;
}

const tool = initTool({
  heavy: true, // Turnstile: prefill only, the visitor presses the button
  form: '#tool-form',
  run: (ctx) => { const n = asnOf(input.value); if (!n) throw new Error('Enter an AS number such as AS13335 or 13335.'); return ctx.api(`/asn/${n}`, null, { heavy: true }); },
  render,
  state: (d) => ({ q: 'AS' + d.asn }),
  prefill: (p) => { const q = qParam(p, 'asn'); if (q) input.value = q; return !!asnOf(q); },
});
