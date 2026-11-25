import { h, $, plural } from '../ui/dom.js';
import { initTool, qParam } from '../ui/tool.js';
import { verdict } from '../ui/verdict.js';
import { checkCard } from '../ui/card.js';
import { gauge } from '../ui/gauge.js';
import { tiles } from '../ui/tiles.js';
import { dataTable } from '../ui/table.js';

const nameEl = $('#dns-name'), typeEl = $('#dns-type'), auto = $('#dns-auto');
const flag = (cc) => (cc && cc.length === 2 ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0))) : '');

function resolverState(r) {
  if (r.status === 'ok') return r.matches_authoritative ? { status: 'ok', word: 'Match' } : { status: 'warn', word: 'Differs' };
  if (r.status === 'nxdomain') return { status: 'warn', word: 'No such name' };
  return { status: 'bad', word: 'Error' };
}

function render(d) {
  const s = d.summary, total = s.total || 0, pct = total ? Math.round((100 * s.propagated) / total) : 0;
  const a = d.authoritative || {};
  const hasAuth = a.answers && a.answers.length;
  const differing = d.resolvers.filter((r) => r.status === 'ok' && !r.matches_authoritative);
  const failed = d.resolvers.filter((r) => r.status !== 'ok' && r.status !== 'nxdomain');
  const status = !hasAuth ? 'info' : pct === 100 ? 'ok' : pct >= 50 ? 'warn' : 'bad';
  const what = hasAuth ? `the ${d.type} ${a.answers.length > 1 ? 'records' : 'record'} for ${d.name}` : `${d.name}`;
  const summary = !hasAuth
    ? `The authoritative nameserver has no ${d.type} record for ${d.name}, so there is nothing to compare resolvers against yet.`
    : pct === 100 ? `All ${total} resolvers already return the same ${d.type} answer as the authoritative nameserver: the change has fully propagated.`
      : `${s.propagated} of ${total} resolvers already see ${what} as published; the rest still hold an older or different answer.`;

  const out = [];
  out.push(verdict({ status, title: !hasAuth ? 'No answer to compare' : pct === 100 ? 'Fully propagated' : `${pct}% propagated`, summary, meta: `${d.name} ${d.type} - checked ${d.queried_at}` }));

  const tileEls = tiles({ items: d.resolvers.map((r) => { const st = resolverState(r); return { label: `${flag(r.country)} ${r.label}`.trim(), sub: r.status === 'ok' ? (r.answers.length ? r.answers.join(', ') : 'no records') : r.status, status: st.status, word: st.word, title: r.ip }; }) });
  const table = dataTable(['Resolver', 'Answer', 'TTL', 'RTT', 'Status'], d.resolvers.map((r) => [`${r.label} (${r.ip})`, r.status === 'ok' ? (r.answers.join(', ') || 'no records') : r.status.toUpperCase(), r.ttl ?? '', r.rtt_ms != null ? r.rtt_ms + ' ms' : '', resolverState(r).word]), { mono: [1, 2, 3] });
  out.push(checkCard({
    status, title: `${plural(s.propagated, 'resolver')} out of ${total} match`,
    body: h('div', { class: 'flex flex-wrap items-center gap-5' }, gauge({ value: s.propagated, max: total || 1, label: pct + '%', unit: 'consistent', status, sr: `${s.propagated} of ${total} resolvers match the authoritative answer` }), h('div', { class: 'flex-1 min-w-[16rem]' }, tileEls)),
    meaning: 'Public resolvers keep an answer in cache until its TTL runs out. A resolver that "differs" is either still holding the old record or sees something different from the authoritative server.',
    details: table,
  }));

  out.push(checkCard({
    status: hasAuth ? 'ok' : 'warn',
    title: hasAuth ? 'The authoritative nameserver answers' : 'The authoritative nameserver gave no answer',
    meaning: hasAuth
      ? `The nameserver that owns ${a.zone || 'the zone'} says ${d.name} has ${a.answers.join(', ')}${a.ttl != null ? ` with a TTL of ${a.ttl} seconds` : ''}. This is the answer every resolver should end up with.`
      : `We could not get a ${d.type} answer from the zone's own nameserver (${a.status || 'no answer'}). Check that the record exists at your DNS provider and that the domain's nameservers are set correctly at the registrar.`,
    fix: hasAuth ? null : { steps: ['Open your DNS provider\'s control panel and confirm the record exists with the right name and type.', 'Check the domain\'s nameservers at the registrar match the provider you edited (use the WHOIS tool).', 'Run the check again after saving.'] },
    details: { zone: a.zone, via: a.label, answers: a.answers, ttl: a.ttl, status: a.status },
  }));

  if (differing.length) {
    const ttl = a.ttl;
    out.push(checkCard({
      status: 'warn', title: `${plural(differing.length, 'resolver')} still show a different answer`,
      meaning: `Those resolvers have not refreshed yet.${ttl != null ? ` Your record's TTL is ${ttl} seconds, so most should catch up within about ${ttl >= 3600 ? Math.round(ttl / 3600) + ' hour(s)' : Math.max(1, Math.round(ttl / 60)) + ' minute(s)'} of the change.` : ''} Nothing is broken; this is normal caching.`,
      fix: { steps: ['Wait for the TTL to expire, then re-run this check (tick "Auto-refresh" to watch it).', 'Before your next change, lower the TTL to 300 seconds a day in advance, then raise it again afterwards.', 'On your own computer, flush the local DNS cache if a browser still shows the old site.'] },
      details: differing.map((r) => `${r.label} (${r.ip}): ${r.answers.join(', ') || 'no records'} ttl=${r.ttl ?? '?'}`).join('\n'),
    }));
  }
  if (failed.length) {
    out.push(checkCard({ status: 'warn', title: `${plural(failed.length, 'resolver')} did not answer in time`, meaning: 'A resolver that times out or refuses the query tells you nothing about your record; it is usually a network hiccup on that resolver, not a DNS problem on your side.', details: failed.map((r) => `${r.label}: ${r.status}`).join('\n') }));
  }
  return out;
}

let timer = null;
const tool = initTool({
  form: '#dns-form',
  run: (ctx) => ctx.api('/dns/propagation', { name: nameEl.value.trim(), type: typeEl.value }),
  render,
  state: (d) => ({ q: d.name, type: d.type }),
  prefill: (p) => { const q = qParam(p, 'name'); if (p.get('type')) typeEl.value = p.get('type').toUpperCase(); if (q) nameEl.value = q; return !!q; },
});
auto.addEventListener('change', () => {
  if (timer) { clearInterval(timer); timer = null; }
  if (auto.checked && nameEl.value.trim()) { tool.execute(); timer = setInterval(() => tool.execute(), 30000); }
});
