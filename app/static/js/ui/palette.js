// Command palette (native <dialog>), loaded lazily by shell.js on first open.
// Rows: "Run <tool> on <value>" (detect.js routing), Recent tools (empty input), then all tools grouped by category.
// Built with DOM APIs only (textContent), never innerHTML.
import { h, clear } from './dom.js';
import { detect, chipsFor, route, paramsFor, TYPE_LABEL } from './detect.js';
import { getRecent } from './recent.js';

let built = null;
let opener = null;

const href = (cfg, slug, params) => `${cfg.prefix}/${slug}?${new URLSearchParams(params).toString()}`;
const plain = (cfg, slug) => `${cfg.prefix}/${slug}`;
const hay = (t) => [t.name, t.short, t.category_label, ...(t.keywords || [])].join(' ').toLowerCase();

function build(dlg, cfg) {
  const input = h('input', { type: 'text', role: 'combobox', 'aria-label': 'Search tools', 'aria-autocomplete': 'list', 'aria-expanded': 'true', 'aria-controls': 'palette-list', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', placeholder: 'Search tools, or paste an IP, domain, ASN, prefix or URL' });
  const list = h('ul', { id: 'palette-list', class: 'palette-list', role: 'listbox', 'aria-label': 'Results' });
  const wrap = h('div', { class: 'palette-input' }, input);
  const foot = h('div', { class: 'palette-foot', 'aria-hidden': 'true' },
    h('span', {}, 'Up/Down to move'), h('span', {}, 'Enter to open'), h('span', {}, 'Esc to close'));
  dlg.append(wrap, list, foot);
  const state = { rows: [], idx: -1 };

  const setActive = (i) => {
    state.rows.forEach((r, n) => r.setAttribute('aria-selected', String(n === i)));
    state.idx = i;
    const r = state.rows[i];
    if (r) { input.setAttribute('aria-activedescendant', r.id); if (r.scrollIntoView) r.scrollIntoView({ block: 'nearest' }); } else input.removeAttribute('aria-activedescendant');
  };
  const addRow = (parent, label, hint, url) => {
    const li = h('li', { role: 'option', id: `pal-opt-${state.rows.length}`, class: 'palette-row', 'aria-selected': 'false', 'data-href': url }, h('span', {}, label));
    if (hint) li.append(h('small', {}, hint));
    li.addEventListener('mousemove', () => { const n = state.rows.indexOf(li); if (n !== state.idx) setActive(n); });
    li.addEventListener('click', () => { location.href = url; });
    state.rows.push(li);
    parent.append(li);
  };
  const group = (title) => { list.append(h('li', { role: 'presentation', class: 'palette-group' }, title)); };

  const render = () => {
    clear(list); state.rows = []; state.idx = -1;
    const q = input.value.trim(), ql = q.toLowerCase();
    const det = detect(q);
    if (det.type !== 'empty' && det.type !== 'unknown') {
      const best = route(det, cfg.tools);
      const cand = chipsFor(det, cfg.tools);
      const ordered = (best ? [cfg.tools.find((t) => t.slug === best.slug), ...cand.filter((t) => t.slug !== best.slug)] : cand).filter(Boolean).slice(0, 3);
      if (ordered.length) {
        group(`Looks like ${TYPE_LABEL[det.type] || det.type}`);
        ordered.forEach((t) => {
          const params = best && t.slug === best.slug ? best.params : paramsFor(t.slug, det);
          addRow(list, `Run ${t.name} on ${q}`, t.category_label, href(cfg, t.slug, params));
        });
      }
    }
    if (!q) {
      const rec = getRecent().map((s) => cfg.tools.find((t) => t.slug === s)).filter(Boolean);
      if (rec.length) { group('Recent'); rec.forEach((t) => addRow(list, t.name, t.category_label, plain(cfg, t.slug))); }
    }
    const matches = cfg.tools.filter((t) => !ql || hay(t).includes(ql));
    const order = [];
    matches.forEach((t) => { if (!order.includes(t.category_label)) order.push(t.category_label); });
    order.forEach((cat) => {
      group(cat);
      matches.filter((t) => t.category_label === cat).forEach((t) => addRow(list, t.name, t.short, plain(cfg, t.slug)));
    });
    if (!state.rows.length) list.append(h('li', { role: 'presentation', class: 'palette-empty' }, 'No matching tools.'));
    else setActive(0);
  };

  input.addEventListener('input', render);
  input.addEventListener('keydown', (e) => {
    const n = state.rows.length;
    if (e.key === 'ArrowDown') { e.preventDefault(); if (n) setActive((state.idx + 1) % n); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); if (n) setActive((state.idx - 1 + n) % n); }
    else if ((e.key === 'Home' || e.key === 'End') && (!input.value || e.ctrlKey)) { e.preventDefault(); if (n) setActive(e.key === 'Home' ? 0 : n - 1); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      const r = state.rows[state.idx];
      if (r) location.href = r.dataset.href;
    }
  });
  dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });
  dlg.addEventListener('close', () => { const o = opener; opener = null; if (o && o.focus) o.focus(); });
  return { input, render };
}

export function openPalette(cfg, from) {
  const dlg = document.getElementById('palette');
  if (!dlg || typeof dlg.showModal !== 'function') { location.href = `${cfg.prefix}/`; return; }
  if (dlg.open) return;
  if (!built) built = build(dlg, cfg);
  opener = from || document.activeElement;
  built.input.value = '';
  built.render();
  dlg.showModal();
  built.input.focus();
}
