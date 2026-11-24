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
      body: dataTable(['Prefix', 'Route validation (RPKI)', 'First seen'], p.list.map((x) => [h('a', { href: `${config.prefix}/bgp-prefix-lookup?q=${encodeURIComponent(x.prefix)}` }, x.prefix), rpkiPill(x.rpki), (x.first_seen || '').slice(0, 10)]), { mono: [0] }),
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
  form: '#tool-form',
  run: (ctx) => { const n = asnOf(input.value); if (!n) throw new Error('Enter an AS number such as AS13335 or 13335.'); return ctx.api(`/asn/${n}`, null, { heavy: true }); },
  render,
  state: (d) => ({ q: 'AS' + d.asn }),
  prefill: (p) => { const q = qParam(p, 'asn'); if (q) input.value = q; return !!asnOf(q); },
});
