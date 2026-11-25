// Verdict header: a big status ring (or A-F grade) plus one plain-English sentence.
import { h, svg, icon, iconPath, srOnly, statusOf, clamp } from './dom.js';

const RING_ICON = { ok: 'ok', warn: 'warn', bad: 'bad', info: 'info', mute: 'mute' };

function ring({ status, grade, score }) {
  const size = 84, stroke = 8, r = (size - stroke) / 2, c = 2 * Math.PI * r;
  const col = statusOf(status).color;
  const pct = score == null ? 1 : clamp(score / 100, 0, 1);
  const inner = grade
    ? svg('text', { x: size / 2, y: size / 2 + 11, 'text-anchor': 'middle', 'font-size': 32, 'font-weight': 800, fill: col }, grade)
    : svg('path', { d: iconPath(RING_ICON[status] || 'mute'), fill: 'none', stroke: col, 'stroke-width': 2.2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', transform: `translate(${size / 2 - 14} ${size / 2 - 14}) scale(1.17)` });
  return svg('svg', { viewBox: `0 0 ${size} ${size}`, width: size, height: size, 'aria-hidden': 'true', class: 'verdict-ring', focusable: 'false' },
    svg('circle', { cx: size / 2, cy: size / 2, r, fill: 'none', stroke: 'var(--line)', 'stroke-width': stroke }),
    svg('circle', { cx: size / 2, cy: size / 2, r, fill: 'none', stroke: col, 'stroke-width': stroke, 'stroke-linecap': 'round', 'stroke-dasharray': `${(c * pct).toFixed(1)} ${c.toFixed(1)}`, transform: `rotate(-90 ${size / 2} ${size / 2})` }),
    inner);
}

/**
 * verdict({ status, grade, score, title, summary, meta })
 *  status: ok | warn | bad | info; grade: 'A'..'F' (optional); score 0-100 fills the ring (optional);
 *  title: short headline (the word shown next to the ring); summary: one plain-English sentence; meta: small caption.
 */
export function verdict({ status = 'info', grade, score, title, summary, meta } = {}) {
  const s = statusOf(status);
  return h('section', { class: 'card verdict', role: 'group', 'aria-label': 'Result summary' },
    ring({ status, grade, score }),
    h('div', { class: 'min-w-0' },
      h('div', { class: `flex items-center gap-2 font-bold text-lg ${s.cls}` }, icon(status, 18), h('span', null, title || s.word)),
      h('p', { class: 'mt-0.5 text-ink' }, summary),
      meta ? h('p', { class: 'text-xs text-mute mt-1 mono break-all' }, meta) : null,
      srOnly(`Status: ${s.word}${grade ? `, grade ${grade}` : ''}.`)));
}
