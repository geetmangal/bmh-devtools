// Tiny DOM helpers shared by the results kit. No innerHTML anywhere: text always goes through createTextNode,
// so API data (hostnames, banners, headers) can never inject markup.
const SVG_NS = 'http://www.w3.org/2000/svg';

function apply(el, attrs) {
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.setAttribute('class', v);
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

/** h('div', {class:'x'}, 'text', childEl, ...) */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  apply(el, attrs);
  append(el, children);
  return el;
}

/** svg('circle', {cx: 5, ...}, ...children) */
export function svg(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  apply(el, attrs);
  append(el, children);
  return el;
}

export const $ = (sel, root = document) => (sel instanceof Element ? sel : root.querySelector(sel));
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }

/** Visually hidden text for screen readers (every chart gets one). */
export const srOnly = (text) => h('span', { class: 'sr-only' }, text);

export const fmtMs = (n) => (n == null ? 'n/a' : n >= 1000 ? (n / 1000).toFixed(2) + ' s' : (n < 10 ? n.toFixed(1) : Math.round(n)) + ' ms');
export const plural = (n, one, many) => `${n} ${n === 1 ? one : many || one + 's'}`;
export const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));

/** Status vocabulary used everywhere: always an icon AND a word, never colour alone. */
export const STATUS = {
  ok: { word: 'Pass', cls: 'st-ok', pill: 'pill-ok', tile: 'tile-ok', color: 'var(--ok)' },
  warn: { word: 'Warning', cls: 'st-warn', pill: 'pill-warn', tile: 'tile-warn', color: 'var(--warn)' },
  bad: { word: 'Fail', cls: 'st-bad', pill: 'pill-bad', tile: 'tile-bad', color: 'var(--bad)' },
  info: { word: 'Info', cls: 'st-mute', pill: 'pill-info', tile: 'tile-mute', color: 'var(--accent)' },
  mute: { word: 'Unknown', cls: 'st-mute', pill: 'pill-mute', tile: 'tile-mute', color: 'var(--mute)' },
};
export const statusOf = (s) => STATUS[s] || STATUS.mute;

const ICON_PATHS = {
  ok: 'M5 13l4 4L19 7',
  warn: 'M12 8v5M12 17h.01M10.3 3.9L2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
  bad: 'M6 6l12 12M18 6L6 18',
  info: 'M12 8h.01M11 12h1v5h1',
  mute: 'M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7M12 17h.01',
  copy: 'M9 9h10v10H9zM5 15V5h10',
  check: 'M5 13l4 4L19 7',
  chevron: 'M6 9l6 6 6-6',
  share: 'M4 12v7h16v-7M12 3v12M8 7l4-4 4 4',
  print: 'M6 9V3h12v6M6 18H4v-7h16v7h-2M7 14h10v7H7z',
  json: 'M8 4c-2 0-3 1-3 3v2c0 1-1 2-2 3 1 1 2 2 2 3v2c0 2 1 3 3 3M16 4c2 0 3 1 3 3v2c0 1 1 2 2 3-1 1-2 2-2 3v2c0 2-1 3-3 3',
  lock: 'M6 11h12v9H6zM8 11V8a4 4 0 0 1 8 0v3',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
  clock: 'M12 7v5l3 2M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z',
  globe: 'M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z',
};

export const iconPath = (name) => ICON_PATHS[name] || ICON_PATHS.mute;

/** icon('ok') -> inline 16px SVG (stroke currentColor). */
export function icon(name, size = 16, cls = '') {
  return svg('svg', { viewBox: '0 0 24 24', width: size, height: size, fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false', class: cls },
    svg('path', { d: ICON_PATHS[name] || ICON_PATHS.mute }));
}

/** Status pill: icon + word (+ optional label). */
export function pill(status, label) {
  const s = statusOf(status);
  return h('span', { class: `pill ${s.pill}` }, icon(status in ICON_PATHS ? status : 'mute', 12), label || s.word);
}

export async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch { /* fall through */ }
  const ta = h('textarea', { 'aria-hidden': 'true', style: 'position:fixed;left:-9999px' }, text);
  document.body.append(ta); ta.select();
  let ok = false; try { ok = document.execCommand('copy'); } catch { /* ignore */ }
  ta.remove(); return ok;
}

/** Safe storage: returns null / ignores failures (private windows, blocked cookies, iframes). */
export const store = {
  get(area, k) { try { return window[area].getItem(k); } catch { return null; } },
  set(area, k, v) { try { window[area].setItem(k, v); } catch { /* ignore */ } },
  del(area, k) { try { window[area].removeItem(k); } catch { /* ignore */ } },
};
