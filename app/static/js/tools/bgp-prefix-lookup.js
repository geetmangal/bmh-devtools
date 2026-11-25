// BGP Prefix Lookup v3: verdict on top, then five deep-linkable tabs (#overview #connectivity #whois #dns #validation).
// Overview/Connectivity/Validation come from GET /prefix/{prefix}; Whois (GET /prefix-whois) and DNS (POST /prefix-rdns)
// load lazily the first time their tab opens. Every API key may be null or missing: panels show a friendly
// "not available" instead of breaking.
import { h, $, plural, pill, srOnly, icon, copyText } from '../ui/dom.js';
import { initTool, qParam } from '../ui/tool.js';
import { checkCard, codeBlock } from '../ui/card.js';
import { gauge } from '../ui/gauge.js';
import { dataTable } from '../ui/table.js';
import { findingCards, resultVerdict, partialNote, nextSteps } from '../ui/findings.js';
import { skeletonCards } from '../ui/stream.js';
import { worldMap } from '../viz/worldmap.js';
import { pathGraph, asnHref } from '../viz/pathgraph.js';
import { ptrGrid } from '../viz/ptrgrid.js';
import { tabs } from '../ui/tabs.js';
import { cacheNote } from '../ui/cachenote.js';

const input = $('#tool-input');
const RPKI = { valid: ['ok', 'Valid'], invalid: ['bad', 'Invalid'], unknown: ['warn', 'No ROA'], 'not-found': ['warn', 'No ROA'] };
const IRR_WORD = { match: ['ok', 'Matches'], mismatch: ['warn', 'Mismatch'], missing: ['warn', 'No route object'], unknown: ['mute', 'Not available'] };
const pfxPath = (p) => encodeURIComponent(p).replace(/%2F/gi, '/');
const lenOf = (p) => { const m = /\/(\d+)$/.exec(p || ''); return m ? Number(m[1]) : null; };
const asLink = (asn, text) => h('a', { href: asnHref(asn), ...(document.documentElement.dataset.embed ? { target: '_blank', rel: 'noopener' } : {}) }, text || `AS${asn}`);
const na = (text = 'not available') => h('span', { class: 'text-mute font-normal' }, text);
const val = (v) => (v == null || v === '' ? na() : String(v));

function notAvailable(title, text) {
  return h('div', { class: 'card p-4 flex items-start gap-3' }, h('span', { class: 'st-mute mt-0.5' }, icon('info', 20)),
    h('div', null, h('div', { class: 'font-semibold' }, title), h('p', { class: 'text-sm text-mute mt-0.5' }, text || 'This data source did not answer. The rest of the report is unaffected. Try again in a minute.')));
}

function copyBtn(text, label = 'Copy') {
  const b = h('button', { type: 'button', class: 'btn btn-ghost btn-sm' }, icon('copy', 13), ' ', label);
  b.addEventListener('click', async () => { const ok = await copyText(text); b.replaceChildren(icon(ok ? 'check' : 'bad', 13), ok ? ' Copied' : ' Copy failed'); setTimeout(() => b.replaceChildren(icon('copy', 13), ' ', label), 1800); });
  return b;
}

function ageText(days) {
  if (days == null) return '';
  if (days < 60) return `${days} days`;
  const y = Math.floor(days / 365), m = Math.floor((days % 365) / 30);
  return y ? `${plural(y, 'year')}${m ? ` ${plural(m, 'month')}` : ''}` : plural(Math.floor(days / 30), 'month');
}

/* ------------------------------------------------------------------ Overview */

function healthRow({ label, status, text, tab, linkText }) {
  const ic = h('span', null), txt = h('span', { class: 'text-sm text-mute min-w-0 flex-1' });
  const wrap = h('li', { class: 'health-row' }, ic, h('span', { class: 'font-semibold w-36 shrink-0' }, label), txt,
    tab ? h('a', { href: '#' + tab, class: 'text-sm font-semibold whitespace-nowrap' }, linkText || 'Details') : null);
  const set = (s, t) => { ic.className = `st-${s === 'info' ? 'mute' : s}`; ic.replaceChildren(icon(s, 18)); txt.textContent = t; wrap.dataset.status = s; };
  set(status, text);
  return { el: wrap, set };
}

function rpkiSummary(res) {
  const k = res.validation?.summary?.rpki ?? res.origins?.[0]?.rpki?.state;
  return k || null;
}

function passport(res) {
  const ov = res.overview;
  const row = (k, v) => h('div', null, h('dt', null, k), h('dd', null, v));
  const sz = ov?.size;
  const sizeText = sz && sz.addresses != null ? `${Number(sz.addresses).toLocaleString('en')} addresses${sz.slash24s ? ` (${plural(sz.slash24s, '/24 block')})` : sz.slash48s ? ` (${plural(sz.slash48s, '/48 block')})` : ''}` : null;
  const kids = [
    row('Holder', val(ov?.holder)), row('Network name', val(ov?.netname)), row('Registry (RIR)', val(ov?.rir)), row('Country', val(ov?.country)),
    row('Registered', ov?.registered ? h('span', null, ov.registered, ov.age_days != null ? h('span', { class: 'text-mute font-normal' }, ` (${ageText(ov.age_days)} ago)`) : null) : na()),
    row('Registry status', ov?.reg_status ? h('span', null, h('span', { class: 'pill pill-info' }, ov.reg_status), ov.reg_status_meaning ? h('span', { class: 'block text-xs text-mute font-normal mt-1' }, ov.reg_status_meaning) : null) : na()),
    row('Size', sizeText ? sizeText : na()),
    row('First announced', res.first_seen?.time ? h('span', null, res.first_seen.time.slice(0, 10), res.first_seen.origin != null ? h('span', { class: 'text-mute font-normal' }, ` by AS${res.first_seen.origin}`) : null) : na()),
    row('Origin AS', (res.origins || []).length ? h('span', { class: 'flex flex-wrap gap-x-3 gap-y-1' }, res.origins.map((o) => h('span', null, asLink(o.asn), ' ', o.rpki?.state ? pill((RPKI[o.rpki.state] || ['mute'])[0], `RPKI ${(RPKI[o.rpki.state] || [0, o.rpki.state])[1]}`) : null))) : na('not announced')),
    row('Abuse contact', ov?.abuse_email ? h('a', { href: `mailto:${ov.abuse_email}` }, ov.abuse_email) : na()),
  ];
  return h('section', { class: 'card p-4 space-y-3', 'aria-labelledby': 'passport-h' },
    h('h3', { id: 'passport-h', class: 'font-semibold' }, 'Prefix passport'),
    ov ? null : h('p', { class: 'text-sm text-mute' }, 'Registry details (holder, country, registration date) are not available right now. The routing facts below are unaffected.'),
    h('dl', { class: 'kv-grid' }, kids));
}

function healthList(res, dnsRow) {
  const rows = [];
  const origins = res.origins || [], ann = res.announced ?? origins.length > 0;
  rows.push(healthRow({ label: 'Announced', status: ann ? 'ok' : 'bad', text: ann ? `Originated by ${origins.map((o) => 'AS' + o.asn).join(', ') || 'an AS'}.` : 'No AS announces this prefix right now.' }));
  const v = res.visibility, cols = v?.collectors || [], tot = v?.total_collectors ?? cols.length, seen = v?.seen_collectors ?? cols.filter((c) => c.is_seen).length;
  if (tot) { const pct = (seen / tot) * 100; rows.push(healthRow({ label: 'Visibility', status: pct >= 80 ? 'ok' : pct >= 40 ? 'warn' : 'bad', text: `Seen by ${seen} of ${tot} route collectors.`, tab: 'connectivity', linkText: 'See the map' })); }
  else rows.push(healthRow({ label: 'Visibility', status: 'mute', text: 'Collector data is not available.', tab: 'connectivity' }));
  const up = res.connectivity?.upstreams;
  if (up) rows.push(healthRow({ label: 'Upstreams', status: up.length > 1 ? 'ok' : up.length === 1 ? 'warn' : 'mute', text: up.length ? `${plural(up.length, 'upstream network')}${up.length === 1 ? ' (a single point of failure)' : ''}.` : 'No upstream seen.', tab: 'connectivity', linkText: 'Open graph' }));
  const rk = rpkiSummary(res);
  rows.push(healthRow({ label: 'RPKI', status: rk === 'valid' ? 'ok' : rk === 'invalid' ? 'bad' : rk ? 'warn' : 'mute', text: rk === 'valid' ? 'A ROA authorises this origin.' : rk === 'invalid' ? 'A ROA exists but conflicts with the announcement.' : rk ? 'No ROA covers this prefix.' : 'Not checked.', tab: 'validation' }));
  const irr = res.validation?.summary?.irr, [is, iw] = IRR_WORD[irr] || IRR_WORD.unknown;
  rows.push(healthRow({ label: 'IRR route object', status: is, text: irr === 'match' ? 'A route object lists the BGP origin.' : irr === 'mismatch' ? 'Route objects exist but none lists the BGP origin.' : irr === 'missing' ? 'No route object found in any registry.' : iw + '.', tab: 'validation' }));
  rows.push(dnsRow);
  return h('section', { class: 'card overflow-hidden', 'aria-labelledby': 'health-h' },
    h('h3', { id: 'health-h', class: 'font-semibold px-4 pt-3 pb-1' }, 'Health checklist'),
    h('ul', { class: 'list-none m-0 p-0' }, rows.map((r) => r.el)));
}

const norm = (x) => (typeof x === 'string' ? { prefix: x, origin: null } : { prefix: x.prefix, origin: x.origin ?? x.asn ?? null });
const byLen = (a, b) => (lenOf(a.prefix) ?? 0) - (lenOf(b.prefix) ?? 0) || String(a.prefix).localeCompare(String(b.prefix));

function nesting(res) {
  if (res.less_specifics == null && res.more_specifics == null) return null;
  const less = (res.less_specifics || []).map(norm).sort(byLen).slice(-4), more = (res.more_specifics || []).map(norm).sort(byLen);
  const moreTotal = res.more_specifics_total ?? more.length;
  const label = (x, extra) => h('div', { class: 'nest-label' }, h('strong', { class: 'mono' }, x.prefix), x.origin != null ? h('span', { class: 'text-mute' }, `AS${x.origin}`) : null, extra ? h('span', { class: 'pill pill-info' }, extra) : null);
  let node = h('div', { class: 'nest nest-this' }, label({ prefix: res.prefix || res.queried, origin: (res.origins || [])[0]?.asn ?? null }, 'this prefix'),
    more.length ? h('div', { class: 'flex flex-wrap gap-1.5' }, more.slice(0, 12).map((m) => h('span', { class: 'chip mono' }, m.prefix, m.origin != null ? h('span', { class: 'text-mute' }, `AS${m.origin}`) : null)),
      moreTotal > 12 ? h('span', { class: 'text-xs text-mute self-center' }, `+${moreTotal - 12} more`) : null) : h('p', { class: 'text-xs text-mute' }, 'No more-specific routes inside it.'));
  for (let i = less.length - 1; i >= 0; i--) node = h('div', { class: 'nest' }, label(less[i], 'less specific'), node);
  const full = (title, list) => (list.length ? h('details', { class: 'mt-3' }, h('summary', { class: 'text-sm font-semibold text-mute' }, `${title} (${list.length})`),
    h('div', { class: 'mt-2' }, dataTable(['Prefix', 'Origin'], list.slice(0, 50).map((x) => [x.prefix, x.origin != null ? 'AS' + x.origin : '']), { mono: [0, 1] }))) : null);
  return checkCard({ status: 'info', title: 'Where it sits: nesting of related routes',
    body: h('div', null, node, full('All less specific prefixes', (res.less_specifics || []).map(norm)), full('All more specific prefixes', (res.more_specifics || []).map(norm))),
    meaning: 'Each box is a block that contains the one inside it. Traffic always follows the most specific route, so a smaller block announced by another network can steal part of a range.' });
}

// Which tab shows a report finding. Unknown ids land in Overview so nothing is lost.
const tabOf = (id) => (/^(rpki|irr|roa)(-|$)/.test(id || '') ? 'validation' : /^(visibility|moas|more-specific-other-as|origin-change)$/.test(id || '') ? 'connectivity' : 'overview');
const findingsFor = (res, tab) => (res.findings || []).filter((f) => tabOf(f.id) === tab);
const F_ST = { fail: 'bad', warn: 'warn', pass: 'ok', info: 'info' };
const SEV = { bad: 4, warn: 3, ok: 2, info: 1, mute: 0 };
const worstOf = (list) => list.reduce((a, b) => ((SEV[b] ?? 0) > (SEV[a] ?? 0) ? b : a), 'mute');
// Badge from the statuses of everything a tab renders (cards + findings). Text counts the items at the worst level.
function tabBadge(cardSts, findSts, okText) {
  const all = [...cardSts, ...findSts], st = worstOf(all);
  if (st === 'bad' || st === 'warn') { const n = Math.max(cardSts.filter((x) => x === st).length, findSts.filter((x) => x === st).length, 1); return { status: st, text: plural(n, st === 'bad' ? 'problem' : 'warning') }; }
  return { status: st, text: st === 'mute' ? 'n/a' : okText };
}

function overviewPanel(res, dnsRow) {
  const out = [passport(res), healthList(res, dnsRow)];
  const n = nesting(res); if (n) out.push(n);
  out.push(...findingCards(findingsFor(res, 'overview')));
  return out;
}

/* ------------------------------------------------------------------ Connectivity */

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

function asPaths(paths) {
  const top = (paths || []).slice(0, 20);
  if (!top.length) return null;
  return h('details', { class: 'card p-4' },
    h('summary', { class: 'font-semibold' }, `AS path list (${top.length})`),
    h('ol', { class: 'list-none m-0 p-0 space-y-2 mt-3' }, top.map((p) => h('li', { class: 'flex flex-wrap items-center gap-1' },
      ...p.path.flatMap((a, i) => [i ? h('span', { class: 'text-mute', 'aria-hidden': 'true' }, '→') : null, h('span', { class: `pill ${i === p.path.length - 1 ? 'pill-ok' : 'pill-info'} mono` }, `AS${a}`)]),
      h('span', { class: 'text-xs text-mute ml-2' }, `${plural(p.count || 0, 'peer')}${p.prepended ? ', prepended' : ''}`)))),
    h('p', { class: 'text-sm mt-3' }, 'Each line is a route seen by collectors, from the collector\'s side on the left to the origin on the right. Shorter paths are usually preferred.'));
}

const meter = (pct, label) => h('div', { class: 'flex items-center gap-2 min-w-[8rem]' },
  h('div', { class: 'meter flex-1', role: 'img', 'aria-label': label }, h('span', { style: `width:${Math.max(2, Math.min(100, pct))}%` })), h('span', { class: 'text-xs mono w-10 text-right' }, `${Math.round(pct)}%`));

function upstreamCard(c) {
  const up = [...(c.upstreams || [])].sort((a, b) => (b.share || 0) - (a.share || 0));
  if (!up.length) return null;
  return checkCard({ status: up.length === 1 ? 'warn' : 'info', title: `Upstreams (${up.length}): who hands the traffic to the origin`,
    body: dataTable(['Network', 'Share of paths', 'Paths', ''], up.map((u) => [
      h('span', null, asLink(u.asn), u.name ? ` ${u.name}` : ''),
      meter((u.share || 0) * 100, `${Math.round((u.share || 0) * 100)} percent of paths`),
      String(u.paths ?? ''), u.tier1 ? h('span', { class: 'pill pill-info' }, 'Tier-1') : ''])),
    meaning: 'An upstream is the network directly next to the origin on a path: the provider this prefix is announced through. The share is the part of the collected paths that run through it. A Tier-1 network reaches the whole internet without paying anyone for transit.',
    fix: up.length === 1 ? { steps: ['Only one upstream carries this prefix. If that provider has an outage the prefix disappears. Add a second transit provider and announce the prefix to both.'] } : null });
}

function lengthCard(c) {
  const pl = c.path_length;
  const hist = pl?.hist ? Object.entries(pl.hist).map(([k, v]) => [Number(k), v]).sort((a, b) => a[0] - b[0]) : [];
  if (!hist.length) return null;
  const max = Math.max(...hist.map((x) => x[1]));
  const prep = c.prepending || [];
  return checkCard({ status: 'info', title: `Path length: ${pl.min ?? '?'} to ${pl.max ?? '?'} networks, median ${pl.median ?? '?'}`,
    body: h('div', { class: 'space-y-2' },
      h('div', { class: 'space-y-1', role: 'list', 'aria-label': 'Number of paths by length' }, hist.map(([len, n]) => h('div', { class: 'grid grid-cols-[4.5rem_1fr_2.5rem] items-center gap-2 text-sm', role: 'listitem' },
        h('span', { class: 'mono' }, `${len} ASes`), h('div', { class: 'meter' }, h('span', { style: `width:${Math.max(2, (n / max) * 100)}%` })), h('span', { class: 'mono text-right' }, String(n))))),
      prep.length ? h('p', { class: 'text-sm' }, h('strong', null, 'Prepending: '), prep.map((p) => `AS${p.asn} repeats itself up to ${p.max_repeat} times on ${plural(p.paths, 'path')}`).join('; '), '.') : null),
    meaning: 'Each bar counts the collected paths with that many networks between the collector and the origin. Short paths mean the prefix is close to the big networks. Prepending is when an AS repeats its own number on purpose to make a path look longer so that it is chosen less often.' });
}

function connectivityPanel(res) {
  const c = res.connectivity, out = [];
  if (!c || !(c.graph?.nodes || []).length) out.push(notAvailable('Path graph not available', 'The looking-glass paths for this prefix could not be loaded, or the prefix is not announced. The visibility map below may still be shown.'));
  else {
    out.push(h('div', { class: 'flex flex-wrap gap-2', 'data-stats': '' }, [['Paths seen', c.paths_total], ['Collector peers', c.collector_peers], ['Upstreams', (c.upstreams || []).length]].filter((x) => x[1] != null).map(([k, v]) => h('div', { class: 'card-flat px-3 py-2 min-w-[7rem]' }, h('div', { class: 'text-xs text-mute' }, k), h('div', { class: 'text-xl font-bold mono leading-tight' }, String(v))))));
    out.push(checkCard({ status: 'info', title: 'How the internet reaches this prefix',
      body: pathGraph({ graph: c.graph, pathsTotal: c.paths_total }),
      meaning: 'Read it from left to right: route collectors (left) learn the prefix through transit networks and finally through the upstream next to the origin (right). Hover or focus a network to see every route from it to the origin. Click it to open its ASN report.' }));
    const u = upstreamCard(c); if (u) out.push(u);
    const l = lengthCard(c); if (l) out.push(l);
  }
  if (res.visibility && (res.visibility.collectors || []).length) out.push(visibility(res.visibility));
  const hist = history(res.history); if (hist) out.push(hist);
  const ap = asPaths(res.as_paths); if (ap) out.push(ap);
  out.push(...findingCards(findingsFor(res, 'connectivity')));
  return out;
}

/* ------------------------------------------------------------------ Whois (lazy GET) */

function kvBlock(title, block, { mono = true } = {}) {
  const rows = (block || []).filter((r) => r && r.key);
  if (!rows.length) return null;
  return h('section', { class: 'card p-4 space-y-2' }, h('h3', { class: 'font-semibold mono break-all' }, title),
    h('div', { class: 'overflow-x-auto' }, h('table', null, h('tbody', null, rows.map((r) => h('tr', null,
      h('th', { scope: 'row', class: 'w-36 whitespace-nowrap mono', title: r.meaning || null }, r.key),
      h('td', { class: `${mono ? 'mono ' : ''}break-all` }, r.value ?? '', r.meaning ? h('span', { class: 'block text-xs text-mute font-sans mt-0.5' }, r.meaning) : null)))))));
}

function whoisPanel(d, setBadge) {
  const out = [];
  const records = d.records || [], irr = d.irr_records || [];
  const n = records.reduce((a, b) => a + (b || []).length, 0);
  const g0 = d.geofeed, wsts = [d.abuse_email ? 'ok' : 'warn', records.length ? 'ok' : 'warn', g0 ? (g0.error ? 'warn' : (g0.rows || []).length ? 'ok' : 'info') : 'info'];
  setBadge(worstOf(wsts) === 'warn' ? { status: 'warn', text: plural(wsts.filter((x) => x === 'warn').length, 'warning') } : { status: worstOf(wsts), text: plural(records.length, 'object') });
  out.push(d.abuse_email
    ? h('section', { class: 'card p-4 flex flex-wrap items-center gap-3' }, h('span', { class: 'st-ok' }, icon('shield', 22)),
      h('div', { class: 'min-w-0 flex-1' }, h('div', { class: 'text-xs uppercase tracking-wide text-mute font-bold' }, 'Abuse contact'), h('a', { href: `mailto:${d.abuse_email}`, class: 'font-semibold mono break-all' }, d.abuse_email),
        h('p', { class: 'text-sm text-mute' }, 'Report spam, attacks or hijacks of this block here. It is the contact the registry lists for the network.')), copyBtn(d.abuse_email, 'Copy address'))
    : checkCard({ status: 'warn', title: 'No abuse contact found for this prefix', meaning: 'Registries ask every network to publish a contact for abuse reports. None was found in the data we could read.', fix: { steps: ['Look up the block at the registry that holds it (the RIR shown in the Overview tab) and use its contact form.'] } }));
  if (!records.length) out.push(notAvailable('No registry objects returned', 'The registry data for this prefix could not be read right now.'));
  records.forEach((b) => { const first = (b || [])[0]; const c = kvBlock(first ? `${first.key}: ${first.value}` : 'Object', b); if (c) out.push(c); });
  if (irr.length) out.push(h('details', { class: 'card p-4' }, h('summary', { class: 'font-semibold' }, `Route objects in routing registries (${irr.length})`),
    h('div', { class: 'space-y-3 mt-3' }, irr.map((b) => kvBlock((b || [])[0] ? `${b[0].key}: ${b[0].value}` : 'Object', b)).filter(Boolean))));
  const g = d.geofeed;
  out.push(g
    ? checkCard({ status: g.error ? 'warn' : (g.rows || []).length ? 'ok' : 'info', title: g.error ? 'Geofeed could not be read' : (g.rows || []).length ? 'Geofeed lists this prefix' : 'A geofeed exists but does not cover this prefix',
      body: h('div', { class: 'space-y-2' }, g.url ? h('p', { class: 'text-sm mono break-all' }, g.url) : null, g.error ? h('p', { class: 'text-sm' }, g.error) : null,
        (g.rows || []).length ? dataTable(['Prefix', 'Country', 'Region', 'City', 'ZIP'], g.rows.map((r) => [r.prefix, r.country, r.region, r.city, r.zip]), { mono: [0] }) : null),
      meaning: 'A geofeed (RFC 8805) is a public file in which the network owner says in which country and city each block is used. Geolocation databases read it, so a wrong or missing entry is why a site shows the wrong location for your IPs.' })
    : checkCard({ status: 'info', title: 'No geofeed published', meaning: 'This block has no geofeed link in its registry record, so geolocation databases guess the location. Publishing one lets you set the country and city yourself.' }));
  if (d.raw) out.push(h('details', { class: 'card p-4' }, h('summary', { class: 'font-semibold' }, `Raw WHOIS text (${n} fields)`), h('div', { class: 'mt-3' }, codeBlock(d.raw, 'Copy raw'))));
  out.push(h('p', { class: 'text-xs text-mute' }, `Authorities: ${(d.authorities || []).join(', ') || 'n/a'}${d.fetched_at ? ` · fetched ${d.fetched_at.slice(0, 19).replace('T', ' ')} UTC` : ''}.`));
  out.push(cacheNote(d.cache));
  return out.filter(Boolean);
}

/* ------------------------------------------------------------------ DNS (lazy heavy POST) */

function blockLabel(prefix, i, blocks) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(prefix || '');
  if (!m) return `Block ${i + 1} of ${blocks}`;
  const [a, b, c, dd] = m.slice(1, 5).map(Number), len = Number(m[5]), n = ((a * 256 + b) * 256 + c) * 256 + dd, size = 2 ** (32 - len);
  const base = Math.floor(n / size) * size + i * 256;
  const o = [Math.floor(base / 16777216) % 256, Math.floor(base / 65536) % 256, Math.floor(base / 256) % 256, 0];
  return `${o.join('.')}/24 (block ${i + 1} of ${blocks})`;
}

// Worst of the cards the DNS tab renders: delegation (missing or with unreachable name servers) and the PTR scan.
function dnsBadge(d) {
  const s = d.stats || {}, dl = d.delegations || [], sts = [];
  sts.push(!dl.length ? 'warn' : dl.some((z) => (z.ns_problems || []).length) ? 'warn' : 'info');
  if ((d.rows || []).length) sts.push(!s.with_ptr || (s.fcrdns_ok || 0) < s.with_ptr ? 'warn' : 'ok');
  const st = worstOf(sts);
  if (st === 'warn') return { status: 'warn', text: plural(sts.filter((x) => x === 'warn').length, 'warning') };
  return (d.rows || []).length ? { status: st, text: `${s.with_ptr} PTR` } : { status: st, text: 'zones' };
}

const NS_PROBLEM = { not_fqdn: 'not a full hostname', no_address: 'has no A or AAAA record' };

function delegationCard(d) {
  const dl = d.delegations || [];
  if (!dl.length) return checkCard({ status: 'warn', title: 'No reverse DNS delegation found', meaning: 'Reverse DNS (in-addr.arpa or ip6.arpa) tells the internet which name belongs to an IP. No name servers are delegated for this block, so nobody can publish PTR records for it.', fix: { steps: ['Ask your upstream provider or RIR to delegate the reverse zone to your DNS servers, or ask them to set the PTR records for you.'] } });
  const bad = dl.flatMap((z) => (z.ns_problems || []).map((p) => ({ zone: z.zone, ...p })));
  const nsCell = (z) => { const probs = new Map((z.ns_problems || []).map((p) => [p.ns, p.problem])); return (z.ns || []).length ? h('span', null, ...z.ns.flatMap((x, i) => [i ? h('br') : null, x, probs.has(x) ? h('span', { class: 'text-xs st-warn font-sans' }, ` (${NS_PROBLEM[probs.get(x)] || 'problem'})`) : null])) : h('span', { class: 'text-mute' }, 'none'); };
  return checkCard({ status: bad.length ? 'warn' : 'info', title: bad.length ? `Reverse zone delegation (${dl.length}): ${plural(bad.length, 'name server')} cannot be reached from outside` : `Reverse zone delegation (${dl.length})`,
    body: dataTable(['Zone', 'Name servers', 'DNSSEC'], dl.map((z) => [z.zone, z.error ? pill('warn', `Lookup failed (${z.error}), try again`) : nsCell(z), z.ds === true ? pill('ok', 'Signed (DS)') : z.ds === false ? pill('mute', 'Not signed') : pill('mute', 'Unknown')]), { mono: [0, 1] }),
    meaning: bad.length ? 'This name server name is not a full hostname, so resolvers outside your network cannot reach it; reverse lookups then fail or depend on caches. (A name server with no address record has the same effect.) The registry hands the reverse zone to these name servers, and they answer for every PTR in it.'
      : 'The registry hands the reverse zone to these name servers, and they answer for every PTR in it. A DS record means the zone is DNSSEC-signed, which stops forged answers.',
    fix: bad.length ? { steps: ['At your RIR (MyAPNIC / IRINN) set the reverse DNS name servers to fully-qualified names like ns1.example.com that answer for the zone.', `Make sure each name server has an A or AAAA record: ${bad.map((b) => b.ns).join(', ')}.`] } : null });
}

function dnsPanel(ctx, prefix, setBadge, done) {
  const holder = h('div', { class: 'space-y-4' });
  const fetchBlock = (block) => ctx.api('/prefix-rdns', { prefix, block }, { heavy: true });
  function paint(d) {
    const s = d.stats || {}, out = [];
    setBadge(dnsBadge(d)); if (done) done(d);
    if (d.blocks > 1) {
      const sel = h('select', { id: 'ptr-block', class: 'mt-1 mono max-w-md', 'aria-label': 'Choose which /24 block to scan' }, Array.from({ length: d.blocks }, (_, i) => h('option', { value: String(i), selected: i === (d.block || 0) ? true : null }, blockLabel(prefix, i, d.blocks))));
      sel.addEventListener('change', () => load(Number(sel.value)));
      out.push(h('div', { class: 'card p-4' }, h('label', { class: 'block text-sm font-semibold', for: 'ptr-block' }, `This prefix spans ${d.blocks} blocks of 256 addresses. Scan block:`), sel));
    }
    out.push(delegationCard(d));
    if (d.note) out.push(h('p', { class: 'card-flat px-3 py-2 text-sm', role: 'status' }, d.note));
    if ((d.rows || []).length) {
      if (d.partial) out.push(h('p', { class: 'card-flat px-3 py-2 text-sm', role: 'status' }, 'The scan hit its time limit. Squares without a record may simply not have been checked.'));
      out.push(checkCard({ status: !s.with_ptr ? 'warn' : (s.fcrdns_ok || 0) < s.with_ptr ? 'warn' : 'ok',
        title: `${s.with_ptr ?? 0} of ${s.scanned ?? 256} addresses have a PTR record, ${s.fcrdns_ok ?? 0} forward-confirmed`,
        body: ptrGrid({ rows: d.rows, stats: s, base: d.base }),
        meaning: 'A PTR record maps an IP back to a name. Mail servers and security tools check it: the name should resolve forward to the same IP (forward-confirmed reverse DNS, FCrDNS). Auto-generated names such as 160-22-108-5.provider.net are accepted by some checks but rejected by strict mail filters.',
        fix: !s.with_ptr || (s.fcrdns_ok || 0) < s.with_ptr ? { steps: ['For every IP that sends mail, set a PTR to a name you control and make that name\'s A record point back to the same IP.', 'Ask the provider that delegates the reverse zone if you cannot edit it yourself.'] } : null }));
    }
    out.push(cacheNote(d.cache));
    holder.replaceChildren(...out.filter(Boolean));
  }
  async function load(block) {
    holder.replaceChildren(skeletonCards(2));
    try { paint(await fetchBlock(block)); } catch (e) {
      const retry = h('button', { type: 'button', class: 'btn btn-ghost btn-sm mt-2' }, 'Try again'); retry.addEventListener('click', () => load(block));
      holder.replaceChildren(h('div', { class: 'card p-4', role: 'alert' }, h('div', { class: 'font-semibold st-bad' }, 'The reverse DNS scan failed'), h('p', { class: 'text-sm mt-0.5' }, e.message || String(e)), retry));
    }
  }
  return fetchBlock(0).then((d) => { paint(d); return holder; });
}

/* ------------------------------------------------------------------ Validation */

function lengthRule(roaLen, maxLen, annLen, bits, label) {
  if (roaLen == null || maxLen == null) return null;
  const lo = Math.max(0, Math.min(roaLen, annLen ?? roaLen) - 2), hi = Math.min(bits, Math.max(maxLen, annLen ?? maxLen) + 2);
  const cells = []; for (let n = lo; n <= hi && cells.length < 40; n++) {
    const allowed = n >= roaLen && n <= maxLen, longer = annLen != null && n > annLen && allowed;
    cells.push(h('span', { class: `${allowed ? (longer ? 'len-max' : 'len-roa') : ''}${n === annLen ? ' len-now' : ''}`.trim(), title: `/${n}${allowed ? ' allowed by the ROA' : ' not covered by the ROA'}${n === annLen ? ' (announced)' : ''}` }, `/${n}`));
  }
  return h('div', null, label ? h('div', { class: 'text-xs font-semibold mono mb-1' }, label) : null,
    h('div', { class: 'lenrule', role: 'img', 'aria-label': `${label ? label + ': ' : ''}ROA allows /${roaLen} to /${maxLen}; announced /${annLen ?? '?'}` }, cells));
}

function rpkiCard(r, res) {
  const [s, w] = RPKI[r.state] || ['mute', r.state || 'Not checked'];
  const ann = lenOf(res.prefix || res.queried), bits = /:/.test(res.prefix || '') ? 128 : 32;
  const origin = (res.origins || []).find((o) => o.asn === r.asn);
  const roas = r.roas || [];
  const bars = roas.slice(0, 4).map((x) => lengthRule(lenOf(x.prefix), x.max_length, ann, bits, `AS${x.origin} · ${x.prefix}${x.max_length != null ? ` max /${x.max_length}` : ''}`));
  return checkCard({
    status: s, title: `Origin AS${r.asn}${origin?.holder || origin?.name ? ' - ' + (origin.holder || origin.name) : ''}: route validation ${w}`,
    body: h('div', { class: 'space-y-3' }, h('div', { class: 'flex flex-wrap items-center gap-2' }, pill(s, `RPKI ${w}`), r.maxlength_loose ? pill('warn', 'Loose max length') : null),
      r.reason ? h('p', { class: 'text-sm' }, r.reason) : null,
      roas.length ? dataTable(['ROA origin', 'Prefix', 'Max length', 'Result'], roas.map((x) => [`AS${x.origin}`, x.prefix, x.max_length != null ? `/${x.max_length}` : '', x.validity]), { mono: [0, 1] }) : null,
      ...bars,
      bars.some(Boolean) ? h('p', { class: 'text-xs text-mute' }, `Green: lengths the ROA allows. Outlined: what is announced (/${ann ?? '?'}). Amber: longer lengths the ROA allows beyond what is announced.`) : null),
    meaning: 'RPKI lets the owner of an IP block publish a signed record (a ROA) saying which AS may announce it and how long a prefix it may use (max length). "Valid" means the announcement matches a ROA, "Invalid" means it conflicts with one, and "No ROA" means nothing is published, so networks cannot tell a hijack from the real thing.',
    fix: r.state === 'invalid' ? { steps: ['Check that the origin AS and the announced length match your ROA, or create or update the ROA at your RIR portal.'] }
      : r.state === 'unknown' || r.state === 'not-found' ? { steps: ['Create a ROA for this prefix at your regional registry (ARIN, RIPE, APNIC, LACNIC or AFRINIC).'] }
        : r.maxlength_loose ? { steps: ['The ROA allows longer prefixes than you announce. An attacker can announce a more specific route that still looks valid. Set the max length to exactly the length you announce.'] } : null,
  });
}

function irrMatrix(irr, res) {
  const objs = irr.objects || [], rpkiRoutes = irr.rpki_routes || [];
  const sources = [...new Set([...(irr.sources || []), ...objs.map((o) => o.source)])];
  const origins = new Set((res.origins || []).map((o) => o.asn));
  const pres = [], toggles = [];
  const cell = (list) => (list.length ? h('div', { class: 'space-y-1.5' }, list) : h('span', { class: 'text-mute text-sm' }, 'no route object'));
  const chip = (o) => {
    const ok = o.matches_bgp === true, cls = ok ? 'irr-ok' : o.exact ? 'irr-bad' : 'irr-cover';
    const word = ok ? 'matches the BGP origin' : o.exact ? 'different origin than BGP' : 'covering route';
    const pre = o.rpsl ? h('pre', { class: 'snippet mono text-xs mt-1', hidden: true }, o.rpsl) : null;
    const b = h('button', { type: 'button', class: `irr-chip ${cls}`, 'aria-expanded': 'false', title: o.rpsl ? 'Show the raw RPSL object' : null }, h('span', { class: 'mono' }, `${o.prefix} → AS${o.asn}`), h('span', { class: 'font-normal' }, `· ${word}`), o.rpki_status ? h('span', { class: 'font-normal' }, `· RPKI ${String(o.rpki_status).toLowerCase()}`) : null);
    if (pre) { pres.push(pre); toggles.push(b); b.addEventListener('click', () => { pre.hidden = !pre.hidden; b.setAttribute('aria-expanded', String(!pre.hidden)); }); }
    return h('div', null, b, pre);
  };
  const rpkiCell = rpkiRoutes.map((r) => { const ok = origins.has(r.asn); return h('span', { class: `irr-chip ${ok ? 'irr-ok' : 'irr-bad'} cursor-default mr-1.5` }, h('span', { class: 'mono' }, `${r.prefix} → AS${r.asn}`), h('span', { class: 'font-normal' }, `· max /${r.max_length ?? '?'} · ${ok ? 'matches the BGP origin' : 'different origin than BGP'}`)); });
  const rows = [['RPKI (signed ROA)', cell(rpkiCell)], ...sources.map((s) => [s, cell(objs.filter((o) => o.source === s).map(chip))])];
  const all = h('button', { type: 'button', class: 'btn btn-ghost btn-sm' }, 'Show raw RPSL for all'); let open = false;
  all.addEventListener('click', () => { open = !open; pres.forEach((p) => { p.hidden = !open; }); toggles.forEach((b) => b.setAttribute('aria-expanded', String(open))); all.textContent = open ? 'Hide raw RPSL' : 'Show raw RPSL for all'; });
  return h('div', { class: 'space-y-2' },
    dataTable(['Registry', 'Route objects for this prefix'], rows, { mono: [0] }),
    h('div', { class: 'flex flex-wrap items-center gap-3 text-xs text-mute' }, pres.length ? all : null,
      h('span', null, 'Green = lists the origin seen in BGP. Red = lists a different origin. Dashed = a covering (larger) route object.')));
}

function irrCards(res) {
  const v = res.validation, irr = v?.irr, sum = v?.summary?.irr, out = [];
  if (!irr || irr.available === false) return [notAvailable('IRR data not available', 'The IRR Explorer service did not answer, so route objects could not be compared with the BGP origin.')];
  const origin = (res.origins || []).map((o) => 'AS' + o.asn).join(', ') || 'the origin';
  const [s, w] = IRR_WORD[sum] || IRR_WORD.unknown;
  out.push(checkCard({ status: s, title: sum === 'match' ? `IRR route objects match ${origin}` : sum === 'mismatch' ? `IRR route objects do not list ${origin}` : sum === 'missing' ? 'No IRR route object found for this prefix' : `IRR comparison: ${w}`,
    body: irrMatrix(irr, res),
    meaning: 'IRR databases (RADB, RIPE, APNIC and others) hold "route objects": records saying which AS may announce a prefix. Many transit providers build their filters from them. If the object lists a different AS than the one announcing in BGP, some providers will drop the route.',
    fix: sum === 'mismatch' ? { steps: [`Create or update the route object at the registry that is marked red so it names ${origin}.`, 'Delete stale route objects that name an AS that no longer announces this prefix.'] } : sum === 'missing' ? { steps: [`Create a route object for this prefix with origin ${origin} in the IRR your upstream uses (often the RIR\'s own database or RADB).`] } : null }));
  const msgs = irr.messages || [];
  if (msgs.length) {
    const map = { success: 'ok', warning: 'warn', danger: 'bad', error: 'bad', info: 'info' };
    out.push(checkCard({ status: map[irr.category] || 'info', title: `IRR Explorer messages (${msgs.length})`,
      body: h('ul', { class: 'list-none m-0 p-0 space-y-2' }, msgs.map((m) => h('li', { class: 'flex flex-wrap items-start gap-2' }, pill(map[m.category] || 'info', m.category || 'info'), h('span', { class: 'text-sm min-w-0 flex-1' }, m.text)))),
      meaning: 'These are the observations IRR Explorer (a public tool run by the NLNOG community) makes when it compares IRR, RPKI and BGP data. Warnings mean a provider that filters strictly may reject the route.' }));
  }
  return out;
}

function validationPanel(res) {
  const out = [], v = res.validation;
  const rp = v?.rpki && v.rpki.length ? v.rpki : (res.origins || []).filter((o) => o.rpki).map((o) => ({ asn: o.asn, state: o.rpki.state, reason: o.rpki.reason, roas: o.rpki.roas, maxlength_loose: false }));
  if (!rp.length) out.push(notAvailable('RPKI result not available', 'No origin was found to validate, or the RPKI service did not answer.'));
  rp.forEach((r) => out.push(rpkiCard(r, res)));
  if (v) out.push(...irrCards(res)); else out.push(notAvailable('IRR comparison not available', 'The IRR route-object check did not run for this report.'));
  out.push(...findingCards(findingsFor(res, 'validation')));
  return out;
}

/* ------------------------------------------------------------------ Page */

function badges(res) {
  const rk = rpkiSummary(res), irr = res.validation?.summary?.irr;
  const vis = res.visibility, tot = vis?.total_collectors ?? (vis?.collectors || []).length, seen = vis?.seen_collectors ?? (vis?.collectors || []).filter((c) => c.is_seen).length;
  const up = res.connectivity?.upstreams, fs = (tab) => findingsFor(res, tab).map((f) => F_ST[f.status] || 'info');
  // Validation: RPKI card(s), IRR card (+ IRR Explorer messages) and the rpki-/irr-/roa- findings.
  const v = res.validation, rpkiSts = (v?.rpki?.length ? v.rpki.map((r) => r.state) : (res.origins || []).filter((o) => o.rpki).map((o) => o.rpki.state)).map((k) => (RPKI[k] || ['mute'])[0]);
  const irrMsg = { success: 'ok', warning: 'warn', danger: 'bad', error: 'bad' }, msgSts = (v?.irr?.messages || []).map((m) => irrMsg[m.category] || 'info');
  const valCards = [...rpkiSts, ...(v ? [(IRR_WORD[irr] || IRR_WORD.unknown)[0], ...(msgSts.length ? [worstOf(msgSts)] : [])] : [])];
  const validation = tabBadge(valCards, fs('validation'), rk === 'valid' ? 'RPKI valid' : 'OK');
  // Connectivity: visibility gauge, upstream card, origin-history card + connectivity findings.
  const pct = tot ? seen / tot : null, hs = res.history?.timeline || [];
  const conCards = [...(pct == null ? [] : [pct >= 0.8 ? 'ok' : pct >= 0.4 ? 'warn' : 'bad']), ...(up && up.length ? [up.length === 1 ? 'warn' : 'info'] : []), ...(hs.length ? [new Set(hs.map((x) => x.origin)).size > 1 ? 'warn' : 'info'] : [])];
  const connectivity = tabBadge(conCards, fs('connectivity'), up && up.length ? plural(up.length, 'upstream') : `${seen}/${tot} seen`);
  const ovSt = res.status === 'fail' ? 'bad' : res.status === 'warn' ? 'warn' : res.status === 'pass' ? 'ok' : 'info';
  const ov = worstOf([ovSt, validation.status === 'mute' ? 'info' : validation.status, connectivity.status === 'mute' ? 'info' : connectivity.status, ...fs('overview')]);
  return {
    overview: { status: ov, text: res.announced === false ? 'not announced' : ov === 'ok' ? 'OK' : ov === 'warn' ? 'check' : ov === 'bad' ? 'issues' : '' },
    connectivity, whois: { status: 'mute', text: '' }, dns: { status: 'mute', text: '' }, validation,
  };
}

function render(res, ctx) {
  const prefix = res.prefix || res.queried;
  const out = [resultVerdict(res, { meta: prefix })];
  const pn = partialNote(res); if (pn) out.push(pn);
  const b = badges(res);
  const dnsRow = healthRow({ label: 'Reverse DNS', status: 'mute', text: 'Not checked yet. Open the DNS tab to scan the PTR records.', tab: 'dns', linkText: 'Open DNS tab' });
  const overview = overviewPanel(res, dnsRow);
  const T = tabs({ label: 'Prefix report sections', items: [
    { id: 'overview', label: 'Overview', badge: b.overview, load: () => [].concat(overview, cacheNote(res.cache) || []) },
    { id: 'connectivity', label: 'Connectivity', badge: b.connectivity, load: () => [].concat(connectivityPanel(res), cacheNote(res.cache) || []) },
    { id: 'whois', label: 'Whois', badge: b.whois, load: async ({ setBadge }) => whoisPanel(await ctx.api(`/prefix-whois/${pfxPath(prefix)}`), setBadge) },
    { id: 'dns', label: 'DNS', badge: b.dns, load: ({ setBadge }) => dnsPanel(ctx, prefix, setBadge, (d) => {
      const s = d.stats || {};
      if ((d.rows || []).length) dnsRow.set(!s.with_ptr ? 'warn' : (s.fcrdns_ok || 0) < s.with_ptr ? 'warn' : 'ok', `${s.with_ptr ?? 0} of ${s.scanned ?? 256} addresses have a PTR record, ${s.fcrdns_ok ?? 0} forward-confirmed.`);
      else dnsRow.set('info', 'Only the reverse delegation is shown for this prefix.');
    }) },
    { id: 'validation', label: 'Validation', badge: b.validation, load: () => [].concat(validationPanel(res), cacheNote(res.cache) || []) },
  ] });
  out.push(T.el);
  out.push(nextSteps([(res.origins || [])[0] ? { slug: 'asn-lookup', q: 'AS' + res.origins[0].asn, text: `Look up AS${res.origins[0].asn}` } : null, { slug: 'looking-glass', text: 'Trace the path from India' }]));
  return out;
}

initTool({
  heavy: true, // Turnstile: prefill only, the visitor presses the button
  form: '#tool-form',
  run: (ctx) => { const q = input.value.trim(); if (!q) throw new Error('Enter an IP address or prefix such as 1.1.1.0/24.'); return ctx.api(`/prefix/${pfxPath(q)}`, null, { heavy: true }); },
  render,
  autoCacheNote: false, // each tab shows its own note (the DNS and Whois tabs use their own endpoints)
  state: (d) => ({ q: d.prefix || d.queried || input.value.trim() }),
  prefill: (p) => { const q = qParam(p, 'prefix'); if (q) input.value = q; return !!q; },
});
