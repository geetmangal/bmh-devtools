// Grid of status tiles plus a summary donut. Each tile shows an icon and a word as well as colour.
import { h, svg, icon, srOnly, statusOf, STATUS } from './dom.js';

/** tiles({ items: [{label, sub, status, title}], min }) */
export function tiles({ items = [], min = '9.5rem' } = {}) {
  return h('ul', { class: 'grid gap-2 list-none m-0 p-0', style: `grid-template-columns:repeat(auto-fill,minmax(${min},1fr))` },
    items.map((it) => {
      const s = statusOf(it.status);
      return h('li', { class: `tile ${s.tile}`, title: it.title || null },
        h('div', { class: 'flex items-center gap-1.5 text-sm font-semibold' }, h('span', { class: s.cls }, icon(it.status || 'mute', 14)), h('span', { class: 'truncate' }, it.label)),
        it.sub ? h('div', { class: 'text-xs text-mute mono truncate' }, it.sub) : null,
        h('div', { class: `text-xs ${s.cls}` }, it.word || s.word));
    }));
}

/** donut({ segments: [{value, status, label}], center, size }) */
export function donut({ segments = [], center = '', caption = '', size = 120 } = {}) {
  const total = segments.reduce((a, s) => a + s.value, 0) || 1;
  const stroke = 16, r = (size - stroke) / 2, c = 2 * Math.PI * r;
  let off = 0;
  const arcs = segments.filter((s) => s.value > 0).map((s) => {
    const len = (s.value / total) * c;
    const el = svg('circle', { cx: size / 2, cy: size / 2, r, fill: 'none', stroke: statusOf(s.status).color, 'stroke-width': stroke, 'stroke-dasharray': `${len.toFixed(2)} ${(c - len).toFixed(2)}`, 'stroke-dashoffset': (-off).toFixed(2), transform: `rotate(-90 ${size / 2} ${size / 2})` });
    off += len; return el;
  });
  const legend = segments.map((s) => `${s.value} ${s.label || statusOf(s.status).word}`).join(', ');
  return h('figure', { class: 'm-0 flex items-center gap-4' },
    svg('svg', { viewBox: `0 0 ${size} ${size}`, width: size, height: size, role: 'img', 'aria-label': `${center} ${caption}. ${legend}`, class: 'flex-none' },
      svg('circle', { cx: size / 2, cy: size / 2, r, fill: 'none', stroke: 'var(--line)', 'stroke-width': stroke }), ...arcs,
      svg('text', { x: size / 2, y: size / 2 + 5, 'text-anchor': 'middle', 'font-size': size / 5, 'font-weight': 700, fill: 'var(--ink)' }, String(center))),
    h('figcaption', { class: 'text-sm' }, caption ? h('div', { class: 'font-semibold mb-1' }, caption) : null,
      h('ul', { class: 'list-none m-0 p-0 space-y-0.5' }, segments.map((s) => h('li', { class: 'flex items-center gap-2' }, h('span', { class: 'inline-block w-2.5 h-2.5 rounded-full', style: `background:${statusOf(s.status).color}` }), `${s.value} ${s.label || statusOf(s.status).word}`)))),
    srOnly(legend));
}

export { STATUS };
