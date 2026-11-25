// Check card with four layers: (1) status icon + plain title, (2) "What this means", (3) "How to fix"
// (steps, optional copy-paste code block, optional provider tabs), (4) "Technical details", collapsed.
// Beginner mode shows layers 1-3; Expert mode opens layer 4 and adds the raw JSON panel (see rawJson).
import { h, icon, pill, statusOf, copyText } from './dom.js';
import { getMode } from './mode.js';

export function codeBlock(code, label = 'Copy') {
  const btn = h('button', { type: 'button', class: 'btn btn-ghost btn-sm' }, icon('copy', 13), ' ', label);
  btn.addEventListener('click', async () => {
    const ok = await copyText(code);
    btn.replaceChildren(icon(ok ? 'check' : 'bad', 13), ok ? ' Copied' : ' Copy failed');
    setTimeout(() => btn.replaceChildren(icon('copy', 13), ' ', label), 1800);
  });
  return h('div', { class: 'code-block' }, h('pre', { class: 'snippet mono', tabindex: '0' }, code), btn);
}

function steps(list) {
  return h('ol', { class: 'list-decimal pl-5 space-y-1 text-sm' }, list.map((s) => h('li', null, s)));
}

function fixBlock(fix) {
  const kids = [];
  if (fix.steps && fix.steps.length) kids.push(steps(fix.steps));
  if (fix.code) kids.push(codeBlock(fix.code, fix.codeLabel || 'Copy'));
  if (fix.tabs && fix.tabs.length) {
    const panels = fix.tabs.map((t) => h('div', { role: 'tabpanel', hidden: true }, t.steps ? steps(t.steps) : null, t.code ? codeBlock(t.code) : null));
    const btns = fix.tabs.map((t, i) => h('button', { type: 'button', role: 'tab', class: 'ptab', 'aria-selected': 'false' }, t.label));
    const select = (i) => { btns.forEach((b, j) => b.setAttribute('aria-selected', String(i === j))); panels.forEach((p, j) => { p.hidden = i !== j; }); };
    btns.forEach((b, i) => b.addEventListener('click', () => select(i)));
    btns.forEach((b, i) => b.addEventListener('keydown', (e) => { if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { const n = (i + (e.key === 'ArrowRight' ? 1 : -1) + btns.length) % btns.length; btns[n].focus(); select(n); } }));
    select(0);
    kids.push(h('div', null, h('div', { class: 'ptabs', role: 'tablist', 'aria-label': 'Where do you manage DNS?' }, btns), ...panels));
  }
  return kids;
}

/** Collapsible "Technical details": string (monospace), Element, or any JSON-able value. */
export function techDetails(details, label = 'Technical details') {
  const body = details instanceof Node ? details
    : h('pre', { class: 'snippet mono text-xs', tabindex: '0' }, typeof details === 'string' ? details : JSON.stringify(details, null, 2));
  const d = h('details', { class: 'tech' }, h('summary', { class: 'text-sm font-semibold text-mute' }, label), h('div', { class: 'mt-2' }, body));
  d.open = getMode() === 'expert';
  return d;
}

/** Panel shown only in Expert mode: the raw API response. */
export function rawJson(data, label = 'Raw JSON') {
  return h('details', { class: 'tech expert-only card-flat p-3' }, h('summary', { class: 'text-sm font-semibold text-mute' }, label),
    h('pre', { class: 'snippet mono text-xs mt-2 max-h-96 overflow-auto', tabindex: '0' }, JSON.stringify(data, null, 2)));
}

/**
 * checkCard({ status, title, meaning, fix: {steps, code, codeLabel, tabs}, details, body })
 * `body` is extra content shown under the title (a mini chart, a table).
 */
export function checkCard({ status = 'info', title, meaning, fix, details, body } = {}) {
  const s = statusOf(status);
  const sections = [];
  if (body) sections.push(body);
  if (meaning) sections.push(h('div', null, h('div', { class: 'check-label' }, 'What this means'), h('p', { class: 'text-sm' }, meaning)));
  if (fix && (fix.steps || fix.code || fix.tabs)) sections.push(h('div', { class: 'space-y-2' }, h('div', { class: 'check-label' }, 'How to fix'), ...fixBlock(fix)));
  if (details != null) sections.push(techDetails(details));
  return h('article', { class: 'card check-card' },
    h('div', { class: 'check-head' },
      h('span', { class: `mt-0.5 ${s.cls}` }, icon(status, 20)),
      h('div', { class: 'min-w-0 flex-1' }, h('h3', { class: 'font-semibold leading-snug' }, title)),
      pill(status)),
    sections.length ? h('div', { class: 'check-body' }, sections) : null);
}
