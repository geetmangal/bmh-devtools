// n-axis radar chart (used later by the domain health report). Values 0-100.
import { h, svg, srOnly, clamp } from './dom.js';

/** radar({ axes: [{label, value}], size, status }) */
export function radar({ axes = [], size = 280, color = 'var(--accent)' } = {}) {
  const n = axes.length;
  if (n < 3) return h('div');
  const cx = size / 2, cy = size / 2, R = size / 2 - 46;
  const pt = (i, v) => { const a = -Math.PI / 2 + (2 * Math.PI * i) / n; return [cx + Math.cos(a) * R * v, cy + Math.sin(a) * R * v]; };
  const poly = (v) => axes.map((_, i) => pt(i, v).join(',')).join(' ');
  const shape = axes.map((a, i) => pt(i, clamp(a.value / 100, 0, 1)).join(',')).join(' ');
  const labels = axes.map((a, i) => {
    const [x, y] = pt(i, 1.2);
    const anchor = Math.abs(x - cx) < 6 ? 'middle' : x > cx ? 'start' : 'end';
    return svg('text', { x, y: y + 4, 'text-anchor': anchor, 'font-size': 11, fill: 'var(--ink)' }, `${a.label} ${Math.round(a.value)}`);
  });
  return h('figure', { class: 'm-0' },
    svg('svg', { viewBox: `0 0 ${size} ${size}`, width: '100%', style: `max-width:${size}px`, role: 'img', 'aria-label': 'Radar chart: ' + axes.map((a) => `${a.label} ${Math.round(a.value)} of 100`).join(', ') },
      ...[0.25, 0.5, 0.75, 1].map((v) => svg('polygon', { points: poly(v), fill: 'none', stroke: 'var(--line)', 'stroke-width': 1 })),
      ...axes.map((_, i) => svg('line', { x1: cx, y1: cy, x2: pt(i, 1)[0], y2: pt(i, 1)[1], stroke: 'var(--line)', 'stroke-width': 1 })),
      svg('polygon', { points: shape, fill: color, 'fill-opacity': 0.2, stroke: color, 'stroke-width': 2 }),
      ...axes.map((a, i) => svg('circle', { cx: pt(i, clamp(a.value / 100, 0, 1))[0], cy: pt(i, clamp(a.value / 100, 0, 1))[1], r: 3.5, fill: color })),
      ...labels),
    srOnly(axes.map((a) => `${a.label}: ${Math.round(a.value)} out of 100`).join('; ')));
}
