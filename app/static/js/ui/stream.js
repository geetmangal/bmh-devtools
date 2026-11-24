// Streaming helpers for later phases (blacklist, health report): read an NDJSON fetch response item by item,
// show "12/52 checked" progress and skeleton cards while results arrive.
import { h } from './dom.js';

/** readNdjson(response, onItem) - calls onItem(obj) for every complete JSON line; resolves when the stream ends. */
export async function readNdjson(response, onItem) {
  if (!response.body || !response.body.getReader) {
    // No streaming support: fall back to parsing the whole body.
    (await response.text()).split('\n').filter(Boolean).forEach((l) => onItem(JSON.parse(l)));
    return;
  }
  const reader = response.body.getReader(), dec = new TextDecoder();
  let buf = '';
  for (;;) {
    const { value, done } = await reader.read();
    buf += dec.decode(value || new Uint8Array(), { stream: !done });
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
      if (line) onItem(JSON.parse(line));
    }
    if (done) break;
  }
  if (buf.trim()) onItem(JSON.parse(buf));
}

/** progressBar({ total, noun }) -> { el, update(done, total?), finish() } */
export function progressBar({ total = 0, noun = 'checked' } = {}) {
  const label = h('span', { class: 'text-sm mono' });
  const fill = h('div', { class: 'h-2 rounded-full bg-accent transition-all', style: 'width:0%' });
  const el = h('div', { class: 'card p-3', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': String(total), 'aria-valuenow': '0' },
    h('div', { class: 'flex justify-between mb-1.5' }, label), h('div', { class: 'bar-track h-2' }, fill));
  const update = (done, t = total) => {
    total = t; const pct = total ? Math.round((done / total) * 100) : 0;
    label.textContent = `${done}/${total} ${noun}`;
    fill.style.width = pct + '%';
    el.setAttribute('aria-valuemax', String(total)); el.setAttribute('aria-valuenow', String(done));
  };
  update(0, total);
  return { el, update, finish() { update(total, total); } };
}

/** n placeholder cards shaped like check cards. */
export function skeletonCards(n = 3) {
  return h('div', { class: 'space-y-3', 'aria-hidden': 'true' }, Array.from({ length: n }, () =>
    h('div', { class: 'card p-4' }, h('div', { class: 'skeleton h-4 w-1/3 mb-3' }), h('div', { class: 'skeleton h-3 w-full mb-2' }), h('div', { class: 'skeleton h-3 w-2/3' }))));
}
