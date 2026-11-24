// World map in pure SVG. The land outline is one equirectangular path (app/static/viz/land-110m.svgpath.txt, built
// by scripts/build_worldmap.py from Natural Earth data, public domain) in a 720 x 360 box: x = (lon + 180) * 2,
// y = (90 - lat) * 2. The outline is fetched from our own origin (the CSP allows no other).
import { h, svg, srOnly, statusOf, STATUS } from '../ui/dom.js';

const cfg = (() => { try { return JSON.parse(document.getElementById('toolbox-config').textContent); } catch { return { prefix: '/tools' }; } })();
export const MAP_W = 720, MAP_H = 360;
export const project = (lat, lon) => [(lon + 180) * 2, (90 - lat) * 2];

let landP = null;
function loadLand() {
  if (!landP) landP = fetch(`${cfg.prefix}/static/viz/land-110m.svgpath.txt`).then((r) => (r.ok ? r.text() : '')).catch(() => '');
  return landP;
}

const ATTRIBUTION = 'Land outlines: Natural Earth (public domain).';

/**
 * worldMap({ points: [{lat, lon, status, label, sub, ring, n}], lines: [[{lat, lon}, ...]], legend: [{status, label, ring}], caption, sr })
 *  points: filled circle in the status colour; ring: true draws a hollow circle (used for "not seen"). n numbers a hop.
 *  lines: polylines (a traceroute path). legend: words for the colours, so colour is never the only signal.
 */
export function worldMap({ points = [], lines = [], legend = [], caption = '', sr = '' } = {}) {
  const valid = points.filter((p) => Number.isFinite(p.lat) && Number.isFinite(p.lon));
  const land = svg('path', { d: '', fill: 'var(--surface2)', stroke: 'var(--line)', 'stroke-width': 0.6, 'stroke-linejoin': 'round' });
  loadLand().then((d) => { if (d) land.setAttribute('d', d.trim()); });
  const lineEls = lines.map((ln) => {
    const pts = ln.filter((p) => Number.isFinite(p.lat) && Number.isFinite(p.lon)).map((p) => project(p.lat, p.lon).map((v) => v.toFixed(1)).join(','));
    return pts.length > 1 ? svg('polyline', { points: pts.join(' '), fill: 'none', stroke: 'var(--accent)', 'stroke-width': 1.6, 'stroke-linejoin': 'round', 'stroke-dasharray': '4 3', opacity: 0.85 }) : null;
  });
  const dots = valid.map((p) => {
    const [x, y] = project(p.lat, p.lon), c = statusOf(p.status).color;
    const g = svg('g', null,
      svg('circle', { cx: x.toFixed(1), cy: y.toFixed(1), r: p.n ? 6.5 : 5, fill: p.ring ? 'var(--surface)' : c, stroke: p.ring ? c : 'var(--surface)', 'stroke-width': p.ring ? 2 : 1.5 }),
      p.n ? svg('text', { x: x.toFixed(1), y: (y + 2.8).toFixed(1), 'text-anchor': 'middle', 'font-size': 7.5, 'font-weight': 700, fill: p.ring ? c : '#fff' }, String(p.n)) : null,
      svg('title', null, `${p.label}${p.sub ? ' - ' + p.sub : ''}`));
    return g;
  });
  const words = legend.length ? h('ul', { class: 'flex flex-wrap gap-x-4 gap-y-1 text-xs list-none m-0 p-0 mt-1' }, legend.map((l) => {
    const c = statusOf(l.status).color;
    return h('li', { class: 'inline-flex items-center gap-1.5' },
      h('span', { class: 'inline-block w-2.5 h-2.5 rounded-full', style: l.ring ? `border:2px solid ${c}` : `background:${c}`, 'aria-hidden': 'true' }), l.label);
  })) : null;
  return h('figure', { class: 'm-0' },
    svg('svg', { viewBox: `0 8 ${MAP_W} ${MAP_H - 68}`, width: '100%', role: 'img', 'aria-label': sr || `World map with ${valid.length} marked locations`, class: 'rounded-xl border border-line bg-surface', style: 'max-height:420px' },
      land, ...lineEls, ...dots),
    words,
    h('figcaption', { class: 'text-xs text-mute mt-1' }, caption ? caption + ' ' : '', ATTRIBUTION),
    srOnly(sr || valid.map((p) => `${p.label}${p.sub ? ' ' + p.sub : ''}`).join('; ')));
}

export { STATUS };
