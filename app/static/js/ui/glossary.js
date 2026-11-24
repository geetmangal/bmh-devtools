// Glossary tooltips. Definitions come from <script type="application/json" id="glossary"> (app/data/glossary.json).
//  - <abbr data-term="rpki">RPKI</abbr>  (or term('rpki')) gets a dotted underline and an accessible popover.
//  - Inside any element with class "gloss-scope", the first occurrence of each glossary term that has a
//    "match" list is wrapped automatically (also for content rendered later, via a MutationObserver).
import { h } from './dom.js';

let G = null;
function glossary() {
  if (G) return G;
  try { G = JSON.parse(document.getElementById('glossary').textContent) || {}; } catch { G = {}; }
  return G;
}

/** term('rpki') or term('rpki', 'route validation') -> <abbr> element. */
export function term(key, text) {
  const e = glossary()[key];
  return h('abbr', { 'data-term': key, tabindex: '0', title: null, 'aria-label': e ? `${text || e.name}: ${e.full || e.name}. Press Enter for the definition.` : null }, text || (e && e.name) || key);
}

let pop = null, active = null;
function popover() {
  if (pop) return pop;
  pop = h('div', { class: 'gloss-pop', role: 'tooltip', id: 'gloss-pop', hidden: true });
  document.body.append(pop);
  return pop;
}
function show(el) {
  const e = glossary()[el.dataset.term];
  if (!e) return;
  const p = popover();
  p.replaceChildren(h('div', { class: 'font-semibold mb-0.5' }, e.full && e.full !== e.name ? `${e.name}: ${e.full}` : e.name), h('div', null, e.def));
  p.hidden = false; active = el; el.setAttribute('aria-describedby', 'gloss-pop');
  const r = el.getBoundingClientRect(), pw = p.offsetWidth;
  const left = Math.max(8, Math.min(window.scrollX + r.left, window.scrollX + document.documentElement.clientWidth - pw - 8));
  p.style.left = left + 'px'; p.style.top = (window.scrollY + r.bottom + 6) + 'px';
}
function hide() { if (pop) pop.hidden = true; if (active) active.removeAttribute('aria-describedby'); active = null; }

const SKIP = new Set(['ABBR', 'A', 'PRE', 'CODE', 'TEXTAREA', 'INPUT', 'BUTTON', 'SCRIPT', 'STYLE', 'SELECT', 'H1', 'H2', 'H3', 'SVG', 'SUMMARY']);

function markScope(scope) {
  const g = glossary(), lookup = new Map();
  for (const [key, e] of Object.entries(g)) (e.match || []).forEach((m) => lookup.set(m, key));
  if (!lookup.size) return;
  const alt = [...lookup.keys()].sort((a, b) => b.length - a.length).map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const re = new RegExp(`(?<![\\w-])(${alt.join('|')})(?![\\w-])`);
  const done = new Set([...scope.querySelectorAll('abbr[data-term]')].map((a) => a.dataset.term));
  const walker = document.createTreeWalker(scope, NodeFilter.SHOW_TEXT, {
    acceptNode(n) {
      for (let p = n.parentElement; p && p !== scope.parentElement; p = p.parentElement) {
        if (SKIP.has(p.tagName.toUpperCase()) || p.classList.contains('mono') || p.classList.contains('no-gloss')) return NodeFilter.FILTER_REJECT;
      }
      return n.nodeValue.trim() ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
    },
  });
  const nodes = []; while (walker.nextNode()) nodes.push(walker.currentNode);
  for (const n of nodes) {
    let node = n;
    for (;;) {
      const m = re.exec(node.nodeValue);
      if (!m) break;
      const key = lookup.get(m[1]);
      if (done.has(key)) {
        // Skip this occurrence but keep scanning the remainder of the node.
        const rest = node.splitText(m.index + m[0].length); node = rest; continue;
      }
      done.add(key);
      const after = node.splitText(m.index);
      const rest = after.splitText(m[0].length);
      after.replaceWith(term(key, m[0]));
      node = rest;
    }
  }
}

export function markTerms(root = document) {
  (root.matches && root.matches('.gloss-scope') ? [root] : [...root.querySelectorAll('.gloss-scope')]).forEach(markScope);
}

export function initGlossary() {
  if (!Object.keys(glossary()).length) return;
  const onEnter = (ev) => { const a = ev.target.closest && ev.target.closest('abbr[data-term]'); if (a) show(a); };
  const onLeave = (ev) => { const a = ev.target.closest && ev.target.closest('abbr[data-term]'); if (a && a === active) hide(); };
  document.addEventListener('mouseover', onEnter);
  document.addEventListener('mouseout', onLeave);
  document.addEventListener('focusin', onEnter);
  document.addEventListener('focusout', onLeave);
  document.addEventListener('click', (ev) => {
    const a = ev.target.closest && ev.target.closest('abbr[data-term]');
    if (a) { if (active === a && pop && !pop.hidden) hide(); else show(a); } else hide();
  });
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') hide();
    if (ev.key === 'Enter' && ev.target.matches && ev.target.matches('abbr[data-term]')) show(ev.target);
  });
  document.querySelectorAll('.gloss-scope').forEach((scope) => {
    markScope(scope);
    let queued = false;
    const mo = new MutationObserver(() => {
      if (queued) return; queued = true;
      requestAnimationFrame(() => { queued = false; mo.disconnect(); markScope(scope); mo.observe(scope, { childList: true, subtree: true }); });
    });
    mo.observe(scope, { childList: true, subtree: true });
  });
}
