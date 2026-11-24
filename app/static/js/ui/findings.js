// Shared glue between the mail/BGP engines and the results kit: map engine statuses to the kit's, turn findings
// into 4-layer check cards, and wire the one-domain-input tool page (#tool-form / #tool-input).
//   engine findings: {id, status: pass|info|warn|fail, title, meaning, fix: [steps] | "text", fix_record, details}
import { h, $ } from './dom.js';
import { initTool, qParam } from './tool.js';
import { verdict } from './verdict.js';
import { checkCard } from './card.js';

/** pass|warn|fail|info|error -> ok|warn|bad|info|bad */
export const st = (s) => ({ pass: 'ok', ok: 'ok', warn: 'warn', fail: 'bad', bad: 'bad', info: 'info', error: 'bad' }[s] || 'mute');
const RANK = { fail: 0, error: 0, warn: 1, info: 2, pass: 3 };
export const bySeverity = (a, b) => (RANK[a.status] ?? 4) - (RANK[b.status] ?? 4);
export const VERDICT_TITLE = { pass: 'Looks good', warn: 'Needs attention', fail: 'Problems found', info: 'For your information', error: 'The check failed' };

const hasKeys = (o) => o && typeof o === 'object' && Object.keys(o).length > 0;

/** One finding -> check card (meaning / how to fix with a copy-paste record / technical details collapsed). */
export function findingCard(f, { prefix = '', body } = {}) {
  const steps = Array.isArray(f.fix) ? f.fix : (f.fix ? [f.fix] : []);
  const fix = steps.length || f.fix_record ? { steps, code: f.fix_record || null, codeLabel: 'Copy record' } : null;
  return checkCard({ status: st(f.status), title: (prefix ? prefix + ' ' : '') + f.title, meaning: f.meaning, fix, details: hasKeys(f.details) ? f.details : undefined, body });
}

/** All findings, worst first. `pass` findings are kept (a green tick is information too). */
export function findingCards(findings, opts) {
  return [...(findings || [])].sort(bySeverity).map((f) => findingCard(f, opts));
}

/** Verdict header for a mail-check result ({status, score, summary, target}). */
export function resultVerdict(res, { title, meta } = {}) {
  return verdict({ status: st(res.status), score: res.score, title: title || VERDICT_TITLE[res.status] || 'Result', summary: res.summary || '', meta: meta ?? res.target });
}

/** Reduce what a visitor typed to a bare domain: https://www.example.com/path, user@example.com, "example.com." */
export function cleanDomain(v) {
  let s = String(v || '').trim().toLowerCase();
  if (s.includes('@') && !s.includes('//')) s = s.split('@').pop();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[/?#]/)[0].replace(/:\d+$/, '').replace(/\.$/, '');
  return s;
}

/**
 * domainTool({ endpoint, render, heavy, extra, state }) - the common page: one input (#tool-input), POST {domain} to
 * the endpoint, ?q= prefills and autoruns, the address bar keeps ?q=.
 */
export function domainTool({ endpoint, render, heavy = false, body, state, form = '#tool-form', input = '#tool-input', after }) {
  const el = $(input);
  const tool = initTool({
    form,
    run: (ctx) => ctx.api(endpoint, { domain: cleanDomain(el.value), ...(body ? body() : {}) }, { heavy: typeof heavy === 'function' ? heavy() : heavy }),
    render,
    state: state || ((d) => ({ q: d.target || cleanDomain(el.value) })),
    prefill: (p) => { const q = qParam(p, 'domain'); if (q) el.value = q; if (after) after(p); return !!q; },
  });
  return tool;
}

/** A small labelled stat box used in headers. */
export function stat(label, value, sub) {
  return h('div', { class: 'card-flat px-3 py-2 min-w-[7rem]' },
    h('div', { class: 'text-xs text-mute' }, label), h('div', { class: 'text-xl font-bold mono leading-tight' }, value), sub ? h('div', { class: 'text-xs text-mute' }, sub) : null);
}

/** Link to another toolbox tool for the same input. */
export function toolLink(slug, q, text, extra = {}) {
  const cfg = (() => { try { return JSON.parse(document.getElementById('toolbox-config').textContent); } catch { return { prefix: '/tools' }; } })();
  return h('a', { href: `${cfg.prefix}/${slug}?${new URLSearchParams({ q, ...extra }).toString()}`, class: 'text-sm' }, text);
}

const MISSING_WORD = { prefixes: 'the list of announced prefixes', neighbours: 'neighbour data', peeringdb: 'PeeringDB details', ix: 'internet exchange data', facilities: 'facility data', rpki: 'some route validation results', overview: 'the AS overview', visibility: 'collector visibility', history: 'routing history', paths: 'AS paths' };

/** Notice shown when a BGP report came back partial (an upstream data source was slow or rate limited). */
export function partialNote(res) {
  if (!res.partial) return null;
  const miss = (res.missing || []).map((k) => MISSING_WORD[k] || k);
  return h('div', { class: 'card-flat px-3 py-2 text-sm', role: 'status' }, h('strong', null, 'Some data was not available. '),
    miss.length ? `Missing: ${miss.join(', ')}. ` : '', 'The public data sources we use were slow or rate limited. The rest of this report is still accurate; try again in a minute for the full picture.');
}
