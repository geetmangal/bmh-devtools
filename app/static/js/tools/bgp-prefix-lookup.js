import { h, $, plural, pill, srOnly } from '../ui/dom.js';
import { initTool, qParam } from '../ui/tool.js';
import { checkCard } from '../ui/card.js';
import { gauge } from '../ui/gauge.js';
import { dataTable } from '../ui/table.js';
import { findingCards, resultVerdict, stat, partialNote, nextSteps } from '../ui/findings.js';
import { worldMap } from '../viz/worldmap.js';

const input = $('#tool-input');
const RPKI = { valid: ['ok', 'Valid'], invalid: ['bad', 'Invalid'], unknown: ['mute', 'No ROA'], 'not-found': ['mute', 'No ROA'] };

function originCard(o) {
  const k = o.rpki?.state, [s, w] = RPKI[k] || ['mute', k || 'Not checked'];
  const roas = o.rpki?.roas || [];
  return checkCard({
    status: s, title: `Origin AS${o.asn}${o.holder || o.name ? ' - ' + (o.holder || o.name) : ''}: route validation ${w}`,
    body: h('div', { class: 'space-y-2' }, pill(s, `RPKI ${w}`), o.rpki?.reason ? h('p', { class: 'text-sm' }, o.rpki.reason) : null,
      roas.length ? dataTable(['ROA origin', 'Prefix', 'Max length', 'Result'], roas.map((r) => [`AS${r.origin}`, r.prefix, r.max_length, r.validity]), { mono: [0, 1] }) : null),
    meaning: 'RPKI lets the owner of an IP block publish a signed record (a ROA) saying which AS may announce it. "Valid" means the announcement matches such a record, "Invalid" means it conflicts with one, and "No ROA" means nothing is published, so networks cannot tell a hijack from the real thing.',
    fix: k === 'invalid' ? { steps: ['Check that the origin AS and the announced length match your ROA, or create or update the ROA at your RIR portal.'] } : k === 'unknown' || k === 'not-found' ? { steps: ['Create a ROA for this prefix at your regional registry (ARIN, RIPE, APNIC, LACNIC or AFRINIC).'] } : null,
  });
}

function visibility(v) {
  const cols = v.collectors || [];
  const seen = v.seen_collectors ?? cols.filter((c) => c.is_seen).length, total = v.total_collectors ?? cols.length;
  const pct = total ? (seen / total) * 100 : 0;
  const s = pct >= 80 ? 'ok' : pct >= 40 ? 'warn' : 'bad';
  return checkCard({
    status: total ? s : 'info', title: `Visible on ${seen} of ${total} route collectors`,
    body: h('div', { class: 'space-y-3' },
      h('div', { class: 'flex flex-wrap items-center gap-5' }, gauge({ value: seen, max: Math.max(total, 1), label: `${seen}/${total}`, unit: 'collectors', status: s, semi: true, size: 150, sr: `Seen by ${seen} of ${total} route collectors` }),
        h('p', { class: 'text-sm max-w-md' }, pct >= 80 ? 'Most vantage points see this route, so it is widely reachable.' : pct >= 40 ? 'Only part of the internet sees this route. Some networks may filter it.' : 'Few vantage points see this route. It may be filtered widely or only recently announced.')),
      worldMap({
        points: cols.filter((c) => c.lat != null && !c.no_data).map((c) => ({ lat: c.lat, lon: c.lon, status: c.is_seen ? 'ok' : 'mute', ring: !c.is_seen, label: `${c.name}${c.city ? ' (' + c.city + ')' : ''}`, sub: c.is_seen ? `sees it (${c.seen}/${c.total} peers)` : 'does not see it' })),
        legend: [{ status: 'ok', label: 'Collector sees the route' }, { status: 'mute', label: 'Collector does not see it', ring: true }],
        caption: 'RIPE RIS route collectors. Positions are approximate.', sr: `${seen} of ${total} route collectors see this prefix.` })),
    meaning: 'Route collectors are listening posts run by RIPE that record what each large network announces. The more of them see a route, the more of the internet can reach it.',
  });
}

function history(hs) {
  const tl = hs?.timeline || [];
  if (!tl.length) return null;
  const t0 = Math.min(...tl.map((x) => Date.parse(x.start))), t1 = Math.max(...tl.map((x) => Date.parse(x.end)), t0 + 1);
  const rows = [...new Set(tl.map((x) => x.origin))];
  const palette = ['var(--accent)', 'var(--ok)', 'var(--warn)', 'var(--bad)'];
  return checkCard({
    status: rows.length > 1 ? 'warn' : 'info', title: `Origin over the last ${hs.days || 30} days`,
    body: h('div', { class: 'space-y-1.5' },
      rows.map((o, i) => h('div', { class: 'grid grid-cols-[5.5rem_1fr] items-center gap-2' }, h('span', { class: 'text-xs mono' }, `AS${o}`),
        h('div', { class: 'relative h-3 bar-track', 'aria-hidden': 'true' }, tl.filter((x) => x.origin === o).map((x) => h('div', { class: 'absolute h-3 rounded-sm', title: `${x.prefix} ${x.start.slice(0, 10)} to ${x.end.slice(0, 10)}`, style: `left:${((Date.parse(x.start) - t0) / (t1 - t0)) * 100}%;width:${Math.max(1.5, ((Date.parse(x.end) - Date.parse(x.start)) / (t1 - t0)) * 100)}%;background:${palette[i % 4]}` }))))),
      h('div', { class: 'flex justify-between text-xs text-mute pl-[6rem]' }, h('span', null, new Date(t0).toISOString().slice(0, 10)), h('span', null, new Date(t1).toISOString().slice(0, 10))),
      srOnly(tl.map((x) => `AS${x.origin} announced ${x.prefix} from ${x.start.slice(0, 10)} to ${x.end.slice(0, 10)}`).join('; '))),
    meaning: 'Each bar is a period when that AS announced the prefix. A new origin appearing, or two at once, can be a legitimate move between providers or a hijack worth investigating.',
  });
}

function asPaths(paths, origin) {
  const top = (paths || []).slice(0, 6);
  if (!top.length) return null;
  return checkCard({
    status: 'info', title: 'How traffic reaches it (AS paths)',
    body: h('ol', { class: 'list-none m-0 p-0 space-y-2' }, top.map((p) => h('li', { class: 'flex flex-wrap items-center gap-1' },
      ...p.path.flatMap((a, i) => [i ? h('span', { class: 'text-mute', 'aria-hidden': 'true' }, '→') : null, h('span', { class: `pill ${i === p.path.length - 1 ? 'pill-ok' : 'pill-info'} mono` }, `AS${a}`)]),
      h('span', { class: 'text-xs text-mute ml-2' }, `${plural(p.count || 0, 'peer')}${p.prepended ? ', prepended' : ''}`)))),
    meaning: 'Each line is a route seen by collectors, from the collector\'s side on the left to the origin on the right. Shorter paths are usually preferred.',
  });
}

function render(res) {
  const out = [resultVerdict(res, { meta: res.prefix || res.queried })];
  out.push(h('div', { class: 'flex flex-wrap gap-2' },
    stat('Prefix', res.prefix || res.queried), stat('Origin', (res.origins || []).map((o) => 'AS' + o.asn).join(', ') || 'none'),
    stat('First announced', res.first_seen?.time ? res.first_seen.time.slice(0, 10) : 'n/a', res.first_seen?.origin ? `by AS${res.first_seen.origin}` : null), stat('More specifics', String(res.more_specifics_total ?? (res.more_specifics || []).length))));
  const pn = partialNote(res); if (pn) out.push(pn);
  (res.origins || []).forEach((o) => out.push(originCard(o)));
  if (res.visibility && (res.visibility.collectors || []).length) out.push(visibility(res.visibility));
  const hist = history(res.history); if (hist) out.push(hist);
  const ap = asPaths(res.as_paths); if (ap) out.push(ap);
  const rel = (title, list) => (list && list.length ? checkCard({ status: 'info', title: `${title} (${list.length})`, body: dataTable(['Prefix', 'Origin'], list.slice(0, 50).map((x) => [typeof x === 'string' ? x : x.prefix, (x.origin ?? x.asn) != null ? 'AS' + (x.origin ?? x.asn) : '']), { mono: [0, 1] }),
    meaning: title === 'Less specific prefixes' ? 'Larger blocks that contain this one.' : 'Smaller blocks inside this one, announced separately.' }) : null);
  out.push(rel('Less specific prefixes', res.less_specifics), rel('More specific prefixes', res.more_specifics));
  out.push(...findingCards(res.findings));
  out.push(nextSteps([(res.origins || [])[0] ? { slug: 'asn-lookup', q: 'AS' + res.origins[0].asn, text: `Look up AS${res.origins[0].asn}` } : null, { slug: 'looking-glass', text: 'Trace the path from India' }]));
  return out;
}

initTool({
  form: '#tool-form',
  run: (ctx) => { const q = input.value.trim(); if (!q) throw new Error('Enter an IP address or prefix such as 1.1.1.0/24.'); return ctx.api(`/prefix/${encodeURIComponent(q).replace(/%2F/gi, '/')}`, null, { heavy: true }); },
  render,
  state: (d) => ({ q: d.prefix || d.queried || input.value.trim() }),
  prefill: (p) => { const q = qParam(p, 'prefix'); if (q) input.value = q; return !!q; },
});
