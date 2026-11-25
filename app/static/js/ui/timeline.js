// Step timelines. timeline(): steps with a latency bar each (hop lists, SMTP conversation, request phases).
// dateline(): a horizontal date axis (WHOIS created -> updated -> expires).
import { h, srOnly, statusOf, fmtMs, clamp } from './dom.js';

/**
 * timeline({ steps: [{label, sub, ms, status, note}], unit })
 * Each step is a row: marker on a connector line, label, a bar proportional to ms, the value.
 * ms == null renders an empty bar with the note (for example "no reply").
 */
export function timeline({ steps = [], sr } = {}) {
  const max = Math.max(1, ...steps.map((s) => s.ms || 0));
  const rows = steps.map((s, i) => {
    const st = statusOf(s.status || (s.ms == null ? 'mute' : 'info'));
    const pct = s.ms == null ? 0 : clamp((s.ms / max) * 100, 2, 100);
    return h('li', { class: 'grid grid-cols-[1.25rem_minmax(0,11rem)_1fr_auto] sm:grid-cols-[1.25rem_minmax(0,16rem)_1fr_5.5rem] items-center gap-x-3 py-1.5 relative' },
      h('span', { class: 'relative flex justify-center' },
        i < steps.length - 1 ? h('span', { class: 'absolute top-3 left-1/2 w-0.5 h-[calc(100%+0.75rem)] -translate-x-1/2 bg-line', 'aria-hidden': 'true' }) : null,
        h('span', { class: 'relative w-3 h-3 rounded-full border-2 border-surface', style: `background:${st.color}`, 'aria-hidden': 'true' })),
      h('div', { class: 'min-w-0' }, h('div', { class: 'text-sm font-medium truncate mono' }, s.label), s.sub ? h('div', { class: 'text-xs text-mute truncate' }, s.sub) : null),
      h('div', { class: 'bar-track h-2.5', 'aria-hidden': 'true' }, h('div', { class: 'h-2.5 rounded-full', style: `width:${pct}%;background:${st.color}` })),
      h('div', { class: `mono text-xs text-right ${s.ms == null ? 'text-mute' : ''}` }, s.ms == null ? (s.note || 'n/a') : fmtMs(s.ms), s.ms != null && s.note ? h('div', { class: 'text-mute' }, s.note) : null));
  });
  return h('div', null,
    h('ol', { class: 'list-none m-0 p-0' }, rows),
    srOnly(sr || steps.map((s) => `${s.label}: ${s.ms == null ? s.note || 'no data' : fmtMs(s.ms)}`).join('; ')));
}

/** dateline({ points: [{label, date: Date|string, status}], now }) */
export function dateline({ points = [], now = new Date(), sr } = {}) {
  const pts = points.filter((p) => p.date && !isNaN(new Date(p.date))).map((p) => ({ ...p, t: +new Date(p.date) }));
  if (!pts.length) return h('div');
  const t0 = Math.min(...pts.map((p) => p.t), +now), t1 = Math.max(...pts.map((p) => p.t), +now);
  const span = Math.max(1, t1 - t0), pos = (t) => clamp(((t - t0) / span) * 100, 1, 99);
  const fmt = (t) => new Date(t).toISOString().slice(0, 10);
  const nowPct = pos(+now);
  const lab = (pct) => (pct > 85 ? 'translateX(-100%)' : pct < 15 ? 'translateX(0)' : 'translateX(-50%)');
  const align = (pct) => (pct > 85 ? 'right' : pct < 15 ? 'left' : 'center');
  return h('div', { class: 'pt-7 pb-24 px-3' },
    h('div', { class: 'relative h-1.5 rounded-full bg-line', 'aria-hidden': 'true' },
      h('div', { class: 'absolute h-1.5 rounded-full bg-accent opacity-60', style: `left:0;width:${nowPct}%` }),
      h('div', { class: 'absolute w-0.5 bg-ink', style: `left:${nowPct}%;top:-0.7rem;height:1.1rem` }),
      h('div', { class: 'absolute text-[10px] text-mute whitespace-nowrap', style: `left:${nowPct}%;top:-1.9rem;transform:${lab(nowPct)}` }, 'today'),
      ...pts.map((p, i) => { const pc = pos(p.t); return h('div', { class: 'absolute', style: `left:${pc}%;top:-0.4rem` },
        h('span', { class: 'block w-3.5 h-3.5 rounded-full border-2 border-surface -translate-x-1/2', style: `background:${statusOf(p.status || 'info').color}` }),
        h('div', { class: 'absolute whitespace-nowrap text-xs', style: `left:0;top:${i % 2 ? '4.4rem' : '1.4rem'};transform:${lab(pc)};text-align:${align(pc)}` }, h('div', { class: 'font-semibold' }, p.label), h('div', { class: 'mono text-mute' }, fmt(p.t)))); })),
    srOnly(sr || pts.map((p) => `${p.label} ${fmt(p.t)}`).join(', ')));
}
