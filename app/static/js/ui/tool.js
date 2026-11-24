// Shared tool runner: wires a form to run()/render(), handles busy state, errors, ?q= autorun, URL state,
// the share bar and the Expert-only raw JSON panel, and calls the JSON API (with Turnstile for heavy tools).
import { h, clear, icon, $ } from './dom.js';
import { heavyFetch } from './turnstile.js';
import { skeletonCards } from './stream.js';
import { shareBar } from './share.js';
import { rawJson } from './card.js';

const cfg = (() => { try { return JSON.parse(document.getElementById('toolbox-config').textContent); } catch { return { api: '/tools/api/v1' }; } })();
const embedHost = () => (document.documentElement.dataset.embed ? (document.body.dataset.embedHost || 'embed') : null);

export function errorMessage(data, status) {
  if (data && typeof data.detail === 'string') return data.detail;
  if (data && data.detail) return JSON.stringify(data.detail);
  if (status === 429) return 'Too many requests. Please wait a few seconds and try again.';
  if (status === 403) return 'The human check did not pass. Reload the page and try again.';
  return `The server answered with an error (${status}).`;
}

/** POST JSON to the tools API. path is relative to /tools/api/v1. Throws Error(message) on failure. */
export async function api(path, body, { heavy = false, container } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  const eh = embedHost(); if (eh) headers['X-Tools-Embed'] = eh;
  const init = { method: 'POST', headers, body: JSON.stringify(body) };
  const url = cfg.api + path;
  const r = heavy ? await heavyFetch(url, init, container) : await fetch(url, init);
  const data = await r.json().catch(() => null);
  if (!r.ok) throw new Error(errorMessage(data, r.status));
  return data;
}

export const apiGet = async (path) => { const r = await fetch(cfg.api + path); return r.json(); };

export function errorCard(message) {
  return h('div', { class: 'card p-4 flex items-start gap-3', role: 'alert' }, h('span', { class: 'st-bad mt-0.5' }, icon('bad', 20)),
    h('div', null, h('div', { class: 'font-semibold st-bad' }, "That didn't work"), h('p', { class: 'text-sm mt-0.5' }, message)));
}

/**
 * initTool({ form, run, render, state, prefill, buttons, busyText })
 *  run(ctx)   -> data (use ctx.api(path, body, {heavy}))
 *  render(data, ctx) -> Node | Node[]  (verdict, cards, ...)
 *  state(data) -> object of URL params to keep in the address bar (always includes q for sharing)
 *  prefill(params) -> truthy when the page should run immediately (e.g. ?q=example.com)
 */
export function initTool({ form, results = '#results', run, render, state, prefill, buttons = [], autorunDelay = 0 }) {
  const formEl = $(form), out = $(results);
  let last = null, token = 0;
  const btns = () => [...formEl.querySelectorAll('button')].concat(buttons.map((b) => $(b)).filter(Boolean));

  const ctx = { out, api: (p, b, o = {}) => api(p, b, { container: out, ...o }), params: new URLSearchParams(location.search) };

  async function execute(extra) {
    const my = ++token;
    btns().forEach((b) => { b.disabled = true; });
    out.setAttribute('aria-busy', 'true');
    clear(out).append(skeletonCards(2));
    try {
      const data = await run({ ...ctx, ...(extra || {}) });
      if (my !== token) return;
      last = data;
      const nodes = [].concat(await render(data, ctx)).filter(Boolean);
      clear(out);
      out.append(...nodes, h('div', { class: 'mt-2 space-y-3' }, rawJson(data), shareBar({ getJson: () => last })));
      if (state && !document.documentElement.dataset.embed) {
        const q = new URLSearchParams(state(data));
        try { history.replaceState(null, '', '?' + q.toString()); } catch { /* sandboxed frames */ }
      }
    } catch (e) {
      if (my !== token) return;
      clear(out).append(errorCard(e.message || String(e)));
    } finally {
      if (my === token) { btns().forEach((b) => { b.disabled = false; }); out.setAttribute('aria-busy', 'false'); }
    }
  }

  formEl.addEventListener('submit', (e) => { e.preventDefault(); execute(); });
  if (prefill && prefill(ctx.params)) setTimeout(() => execute(), autorunDelay);
  return { execute, ctx, get last() { return last; } };
}

/** First non-empty value among ?q and legacy parameter names. */
export const qParam = (p, ...legacy) => [ 'q', ...legacy ].map((k) => p.get(k)).find((v) => v && v.trim()) || '';
