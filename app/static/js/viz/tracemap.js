// Traceroute visuals: a hop timeline coloured by ASN segment (hopTimeline) and a map of the path (traceMap).
// Hops come from POST /lg/run after server-side enrichment: {hop, ip, rtt_ms, asn, as_name, city, country, lat, lon, private, timeout}.
import { h, srOnly, icon, fmtMs, clamp } from '../ui/dom.js';
import { worldMap } from './worldmap.js';

// Mid-tone categorical colours that read on both the light and the dark surface. Each ASN also shows its name,
// so colour is never the only signal.
export const SEG_COLORS = ['#3b6bff', '#e8590c', '#0b9a6e', '#a23fd0', '#d6336c', '#0c8599', '#b08900', '#5c7cfa'];
const NO_ASN = 'var(--mute)';

function segmentKey(hop) { return hop.private ? 'private' : hop.asn != null ? String(hop.asn) : null; }

/** Map every hop to its segment colour; returns {colorOf(hop), legend[]}. */
export function segmentPalette(hops, segments) {
  const colors = new Map();
  const legend = [];
  (segments || []).forEach((s, i) => {
    const key = s.private ? 'private' : String(s.asn);
    if (!colors.has(key)) colors.set(key, s.private ? 'var(--mute)' : SEG_COLORS[colors.size % SEG_COLORS.length]);
    legend.push({ ...s, color: colors.get(key) });
  });
  hops.forEach((x) => { const k = segmentKey(x); if (k && !colors.has(k)) colors.set(k, SEG_COLORS[colors.size % SEG_COLORS.length]); });
  return { colorOf: (x) => colors.get(segmentKey(x)) || NO_ASN, legend };
}

const where = (x) => [x.city, x.country].filter(Boolean).join(', ');

/** hopTimeline({ hops, segments, destination }) */
export function hopTimeline({ hops = [], segments = [], destination } = {}) {
  const { colorOf, legend } = segmentPalette(hops, segments);
  const max = Math.max(1, ...hops.map((x) => x.rtt_ms || 0));
  let prev = 0;
  const rows = hops.map((x) => {
    const jump = x.rtt_ms != null && prev > 0 && x.rtt_ms - prev > 60;
    if (x.rtt_ms != null) prev = x.rtt_ms;
    const col = colorOf(x);
    const title = x.private ? 'Private network (address hidden)' : x.ip || '*';
    const sub = x.private ? 'inside the provider network' : x.asn != null ? `AS${x.asn}${x.as_name ? ' ' + x.as_name : ''}${where(x) ? ' - ' + where(x) : ''}` : x.ip ? 'network not identified' : 'no reply';
    const pct = x.rtt_ms == null ? 0 : clamp((x.rtt_ms / max) * 100, 2, 100);
    return h('li', { class: 'grid grid-cols-[1.75rem_minmax(0,1fr)_minmax(3rem,38%)_4.5rem] sm:grid-cols-[2rem_minmax(0,16rem)_1fr_5.5rem] items-center gap-x-3 py-1.5 border-l-4 pl-2', style: `border-color:${col}` },
      h('span', { class: 'text-xs text-mute mono' }, String(x.hop)),
      h('div', { class: 'min-w-0' },
        h('div', { class: 'text-sm font-medium truncate mono' }, title, x.ip && x.ip === destination ? h('span', { class: 'pill pill-info ml-2' }, 'destination') : null),
        h('div', { class: 'text-xs text-mute truncate' }, sub)),
      h('div', { class: 'bar-track h-2.5', 'aria-hidden': 'true' }, h('div', { class: 'h-2.5 rounded-full', style: `width:${pct}%;background:${col}` })),
      h('div', { class: `mono text-xs text-right ${x.rtt_ms == null ? 'text-mute' : ''}` }, x.rtt_ms == null ? '*' : fmtMs(x.rtt_ms),
        jump ? h('div', { class: 'st-warn inline-flex items-center gap-1 justify-end' }, icon('warn', 12), 'jump') : null));
  });
  const key = legend.length ? h('ul', { class: 'flex flex-wrap gap-x-4 gap-y-1 text-xs list-none m-0 p-0 mb-2' }, legend.map((s) =>
    h('li', { class: 'inline-flex items-center gap-1.5' }, h('span', { class: 'inline-block w-3 h-3 rounded-sm', style: `background:${s.color}`, 'aria-hidden': 'true' }),
      `${s.label} (hop${s.start_hop === s.end_hop ? ' ' + s.start_hop : 's ' + s.start_hop + '-' + s.end_hop})`))) : null;
  return h('div', null, key, h('ol', { class: 'list-none m-0 p-0 space-y-0.5' }, rows),
    srOnly(hops.map((x) => `Hop ${x.hop}: ${x.private ? 'private network' : x.ip || 'no reply'}${x.asn != null ? ', AS' + x.asn : ''}${x.rtt_ms != null ? ', ' + fmtMs(x.rtt_ms) : ''}`).join('; ')));
}

/** traceMap(hops): numbered dots joined by a dashed line. Private and unlocated hops are skipped. Returns null if nothing to draw. */
export function traceMap(hops, { source } = {}) {
  const pts = hops.filter((x) => !x.private && Number.isFinite(x.lat) && Number.isFinite(x.lon))
    .map((x) => ({ lat: x.lat, lon: x.lon, n: x.hop, status: 'info', label: `Hop ${x.hop}: ${x.ip}`, sub: `${x.asn != null ? 'AS' + x.asn + ' ' : ''}${where(x)}` }));
  const all = [...(source ? [{ lat: source.lat, lon: source.lon, status: 'ok', label: source.label, n: 0 }] : []), ...pts];
  if (all.length < 1) return null;
  return worldMap({
    points: all.map((p) => ({ ...p, n: p.n || undefined })),
    lines: [all],
    legend: [...(source ? [{ status: 'ok', label: 'Our network (Noida)' }] : []), { status: 'info', label: 'Hop, numbered in order' }],
    caption: 'Hop locations come from IP geolocation and are approximate: a router address can be registered far from where the router stands.',
    sr: `Path map with ${pts.length} located hops: ${pts.map((p) => `${p.n} ${p.sub}`).join('; ')}`,
  });
}
