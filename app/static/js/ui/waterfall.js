// Stacked timing bar (DNS / connect / TLS / TTFB / download) with a legend that carries the numbers.
import { h, srOnly, fmtMs } from './dom.js';

export const PHASE_COLORS = ['#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#06b6d4'];

/** waterfall({ phases: [{label, ms, color?, note?}] }) */
export function waterfall({ phases = [] } = {}) {
  const total = Math.max(0.001, phases.reduce((a, p) => a + (p.ms || 0), 0));
  const col = (p, i) => p.color || PHASE_COLORS[i % PHASE_COLORS.length];
  return h('div', null,
    h('div', { class: 'flex h-6 w-full overflow-hidden rounded-lg bg-surface2', role: 'img', 'aria-label': 'Request timing, stacked by phase' },
      phases.map((p, i) => h('div', { style: `width:${Math.max(0.6, ((p.ms || 0) / total) * 100)}%;background:${col(p, i)}`, title: `${p.label}: ${fmtMs(p.ms)}` }))),
    h('div', { class: 'mt-1 flex justify-between text-xs text-mute mono' }, h('span', null, '0'), h('span', null, `total ${fmtMs(total)}`)),
    h('ul', { class: 'mt-3 grid gap-x-6 gap-y-1.5 list-none m-0 p-0 sm:grid-cols-2' }, phases.map((p, i) =>
      h('li', { class: 'flex items-center gap-2 text-sm' },
        h('span', { class: 'inline-block w-3 h-3 rounded-sm flex-none', style: `background:${col(p, i)}`, 'aria-hidden': 'true' }),
        h('span', null, p.label), h('span', { class: 'ml-auto mono' }, fmtMs(p.ms)),
        p.note ? h('span', { class: 'text-xs text-mute mono' }, p.note) : null))),
    srOnly('Timing: ' + phases.map((p) => `${p.label} ${fmtMs(p.ms)}`).join(', ') + `. Total ${fmtMs(total)}.`));
}
