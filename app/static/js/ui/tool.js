// Shared tool runner: wires a form to run()/render(), handles busy state, errors, ?q= autorun, URL state,
// the share bar and the Expert-only raw JSON panel, and calls the JSON API (with Turnstile for heavy tools).
import { h, clear, icon, $ } from './dom.js';
import { heavyFetch } from './turnstile.js';
import { skeletonCards, readNdjson } from './stream.js';
import { shareBar } from './share.js';
import { rawJson } from './card.js';
import { cacheNote } from './cachenote.js';

const cfg = (() => { try { return JSON.parse(document.getElementById('toolbox-config').textContent); } catch { return { api: '/tools/api/v1', prefix: '/tools' }; } })();
const embedHost = () => (document.documentElement.dataset.embed ? (document.body.dataset.embedHost || 'embed') : null);
export const config = cfg;

export function errorMessage(data, status) {
  if (data && data.error === 'target_busy') return 'This target is being checked by a lot of people right now. Please wait a minute and try again.';
  if (data && typeof data.detail === 'string') return data.detail;
  if (data && data.detail) return JSON.stringify(data.detail);
  if (status === 429) return 'Too many requests. Please wait a few seconds and try again.';
  if (data && data.error === 'turnstile_required') return data.message || 'Please complete the human check and run the test again.';
  if (data && data.error === 'turnstile_unavailable') return data.message || 'The verification service is unreachable. Please try again shortly.';
  if (status === 403) return 'The human check did not pass. Reload the page and try again.';
  return `The server answered with an error (${status}).`;
}

function request(path, body, heavy, container, extraHeaders) {
  const headers = { ...(extraHeaders || {}) };
  const eh = embedHost(); if (eh) headers['X-Tools-Embed'] = eh;
  const init = body == null ? { method: 'GET', headers } : { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  const url = cfg.api + path;
  return heavy ? heavyFetch(url, init, container) : fetch(url, init);
}

/** POST JSON (or GET when body is null) to the tools API. path is relative to /tools/api/v1. Throws Error(message) on failure. */
export async function api(path, body, { heavy = false, container, headers } = {}) {
  const r = await request(path, body, heavy, container, headers);
  const data = await r.json().catch(() => null);
  if (!r.ok) throw new Error(errorMessage(data, r.status));
  return data;
}

/**
 * POST and read an NDJSON stream. onItem(obj) runs for every line; onStart() once the server accepted the request
 * (use it to replace the skeleton). Lines of {type: 'error'} throw so the page shows the normal error card.
 */
export async function apiStream(path, body, { heavy = true, container, onItem, onStart } = {}) {
  const r = await request(path, body, heavy, container);
  if (!r.ok) throw new Error(errorMessage(await r.json().catch(() => null), r.status));
  if (onStart) onStart();
  await readNdjson(r, (o) => { if (o && o.type === 'error') throw new Error(o.message || 'The check failed.'); onItem(o); });
}

export const apiGet = (path, opts = {}) => api(path, null, opts);

export function errorCard(message) {
  return h('div', { class: 'card p-4 flex items-start gap-3', role: 'alert' }, h('span', { class: 'st-bad mt-0.5' }, icon('bad', 20)),
    h('div', null, h('div', { class: 'font-semibold st-bad' }, "That didn't work"), h('p', { class: 'text-sm mt-0.5' }, message)));
}

/**
 * initTool({ form, run, render, state, prefill, buttons })
 *  run(ctx)   -> data (use ctx.api(path, body, {heavy}) or ctx.stream(path, body, {onItem, onStart}))
 *  render(data, ctx) -> Node | Node[]  (verdict, cards, ...)
 *  state(data) -> object of URL params to keep in the address bar (always includes q for sharing)
 *  prefill(params) -> truthy when the page should run immediately (e.g. ?q=example.com)
 */
export function initTool({ form, results = '#results', run, render, state, prefill, buttons = [], autorunDelay = 0, shareExtra, autoCacheNote = true }) {
  const formEl = $(form), out = $(results);
  let last = null, token = 0;
  const btns = () => [...formEl.querySelectorAll('button')].concat(buttons.map((b) => $(b)).filter(Boolean));

  const ctx = {
    out, params: new URLSearchParams(location.search),
    api: (p, b, o = {}) => api(p, b, { container: out, ...o }),
    stream: (p, b, o = {}) => apiStream(p, b, { container: out, ...o }),
  };

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
      out.append(...nodes, ...(autoCacheNote ? [cacheNote(data && data.cache)].filter(Boolean) : []), h('div', { class: 'mt-2 space-y-3' }, rawJson(data), shareBar({ getJson: () => last, ...(shareExtra || {}) })));
      if (state && !document.documentElement.dataset.embed) {
        const q = new URLSearchParams(state(data));
        try { history.replaceState(null, '', '?' + q.toString() + location.hash); } catch { /* sandboxed frames */ }
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
