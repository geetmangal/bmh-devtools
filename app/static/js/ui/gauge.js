// Ring and semicircle gauges (pure SVG). Always include a text equivalent for screen readers.
import { h, svg, srOnly, statusOf, clamp } from './dom.js';

/**
 * gauge({ value, max, label, unit, status, semi, size, sr })
 * value/max drive the arc; label is the big centre text (defaults to value); unit is the small caption.
 */
export function gauge({ value = 0, max = 100, label, unit = '', status = 'info', semi = false, size = 120, sr } = {}) {
  const pct = clamp(max ? value / max : 0, 0, 1);
  const stroke = Math.round(size / 10), r = (size - stroke) / 2, cx = size / 2, cy = semi ? size / 2 + 2 : size / 2;
  const color = statusOf(status).color;
  const arcLen = semi ? Math.PI * r : 2 * Math.PI * r;
  const dash = `${(arcLen * pct).toFixed(2)} ${arcLen.toFixed(2)}`;
  const path = semi
    ? `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`
    : `M ${cx} ${cy - r} A ${r} ${r} 0 1 1 ${cx - 0.01} ${cy - r}`;
  const height = semi ? size / 2 + stroke : size;
  const text = String(label ?? value);
  const root = svg('svg', { viewBox: `0 0 ${size} ${height}`, width: size, height, role: 'img', 'aria-label': sr || `${text} ${unit}`.trim(), class: 'flex-none' },
    svg('path', { d: path, fill: 'none', stroke: 'var(--line)', 'stroke-width': stroke, 'stroke-linecap': 'round' }),
    svg('path', { d: path, fill: 'none', stroke: color, 'stroke-width': stroke, 'stroke-linecap': 'round', 'stroke-dasharray': dash }),
    svg('text', { x: cx, y: semi ? cy - 4 : cy + 2, 'text-anchor': 'middle', 'font-size': size / 4.2, 'font-weight': 700, fill: 'var(--ink)' }, text),
    unit ? svg('text', { x: cx, y: semi ? cy + stroke : cy + size / 7, 'text-anchor': 'middle', 'font-size': size / 11, fill: 'var(--mute)' }, unit) : null);
  return h('figure', { class: 'inline-block m-0' }, root, srOnly(sr || `${text} ${unit}`.trim()));
}
