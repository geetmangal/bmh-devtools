// Toolbox shell: command bar (detect + chips + Enter routing), theme toggle, tab-rail keyboard navigation,
// Beginner/Expert toggle, glossary, the "Embed this tool" drawer, and (inside an iframe) the resize messenger.
import { h, $, $$, store, copyText, clear } from './ui/dom.js';
import { initMode } from './ui/mode.js';
import { initGlossary } from './ui/glossary.js';
import { detect, chipsFor, route, paramsFor, TYPE_LABEL } from './ui/detect.js';
import { pushRecent } from './ui/recent.js';

const cfg = (() => { try { return JSON.parse(document.getElementById('toolbox-config').textContent); } catch { return { prefix: '/tools', tools: [] }; } })();
const root = document.documentElement;

// ---------- theme ----------
function applyThemeUi() {
  const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
  $$('[data-theme-toggle]').forEach((b) => b.setAttribute('aria-pressed', String(dark)));
  $$('[data-theme-icon]').forEach((i) => { i.classList.toggle('hidden', (i.dataset.themeIcon === 'sun') !== dark); });
}
function initTheme() {
  applyThemeUi();
  $$('[data-theme-toggle]').forEach((b) => b.addEventListener('click', () => {
    const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
    const next = dark ? 'light' : 'dark';
    root.dataset.theme = next; store.set('localStorage', 'bmh-theme', next); applyThemeUi();
  }));
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyThemeUi);
}

// ---------- command bar ----------
const toolHref = (slug, params) => `${cfg.prefix}/${slug}?${new URLSearchParams(params).toString()}`;

function initCommandBar() {
  const form = $('#cmdbar'), input = $('#cmd-input'), chips = $('#cmd-chips');
  if (!form || !input) return;
  const render = () => {
    const det = detect(input.value);
    clear(chips);
    if (det.type === 'empty') return;
    if (det.type === 'unknown') { chips.append(h('span', { class: 'text-sm text-mute' }, 'Not sure what that is yet. Try an IP, domain, prefix, AS number, email or URL.')); return; }
    const best = route(det, cfg.tools);
    if (det.prefix && !best) { chips.append(h('span', { class: 'text-sm text-mute' }, `The ${det.prefix}: lookup is not available yet. More tools are on the way.`)); return; }
    chips.append(h('span', { class: 'text-xs text-mute' }, `Looks like ${TYPE_LABEL[det.type] || det.type}:`));
    const list = chipsFor(det, cfg.tools);
    const shown = best ? [cfg.tools.find((t) => t.slug === best.slug), ...list.filter((t) => t.slug !== best.slug)].filter(Boolean) : list;
    shown.forEach((t) => {
      const isBest = best && t.slug === best.slug;
      const params = isBest ? best.params : paramsFor(t.slug, det);
      chips.append(h('a', { class: `chip${isBest ? ' is-best' : ''}`, href: toolHref(t.slug, params) }, t.name));
    });
    if (!shown.length) chips.append(h('span', { class: 'text-sm text-mute' }, 'No tool for that yet. More are on the way.'));
  };
  input.addEventListener('input', render);
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const det = detect(input.value), r = route(det, cfg.tools);
    if (r) { location.href = toolHref(r.slug, r.params); return; }
    render();
    if (det.type !== 'empty') chips.append(h('span', { class: 'text-sm st-warn' }, 'That lookup is not available yet.'));
  });
  if (input.value) render();
}

// ---------- command palette (lazy) + recents ----------
function initPalette() {
  const open = async (from) => { try { (await import('./ui/palette.js')).openPalette(cfg, from); } catch { location.href = `${cfg.prefix}/`; } };
  $$('[data-palette-open]').forEach((b) => b.addEventListener('click', () => open(b)));
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === 'k') { e.preventDefault(); open(document.activeElement); return; }
    if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
    const a = document.activeElement, tag = a && a.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || (a && a.isContentEditable)) return;
    if (document.querySelector('dialog[open]')) return;
    e.preventDefault();
    const hub = document.getElementById('hub-filter');
    if (hub) hub.focus(); else open(a);
  });
  const slug = document.body.dataset.toolSlug;
  if (slug && !root.dataset.embed) pushRecent(slug);
}

// ---------- tab rail: arrow keys move between tabs ----------
function initTabs() {
  const tabs = $$('.tabrail a.tab');
  tabs.forEach((t, i) => t.addEventListener('keydown', (e) => {
    const d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (d) { e.preventDefault(); tabs[(i + d + tabs.length) % tabs.length].focus(); }
    if (e.key === 'Home') { e.preventDefault(); tabs[0].focus(); }
    if (e.key === 'End') { e.preventDefault(); tabs[tabs.length - 1].focus(); }
  }));
  const cur = $('.tabrail a[aria-current="page"]');
  if (cur && cur.scrollIntoView) cur.scrollIntoView({ block: 'nearest', inline: 'center' });
}

// ---------- embed drawer ----------
function initEmbedDrawer() {
  const box = $('#embed');
  if (!box) return;
  const { slug, name, toolUrl, embedBase, embedJs, localBase } = box.dataset;
  const el = { drawer: $('#embed-drawer'), theme: $('#embed-theme'), accent: $('#embed-accent'), height: $('#embed-height'), script: $('#embed-script'), snippet: $('#embed-snippet'), copy: $('#embed-copy'), preview: $('#embed-preview') };
  let kind = 'iframe', accentTouched = false;
  const query = (base) => {
    const p = new URLSearchParams({ theme: el.theme.value });
    if (accentTouched) p.set('accent', el.accent.value);
    return base + slug + '?' + p.toString();
  };
  const build = () => {
    if (kind === 'link') {
      el.snippet.textContent = `<a href="${toolUrl}" title="${name} by BookMyHost">${name}</a> - free tool by <a href="https://www.bookmyhost.com/">BookMyHost</a>`;
      return;
    }
    const hgt = Math.min(1200, Math.max(240, parseInt(el.height.value, 10) || 420));
    const lines = [
      `<iframe src="${query(embedBase)}" loading="lazy" title="${name}" data-bmh-tool="${slug}" style="width:100%;border:0;min-height:${hgt}px"></iframe>`,
      `<p style="font:12px sans-serif">Free <a href="${toolUrl}">${name}</a> by <a href="https://www.bookmyhost.com/">BookMyHost</a></p>`,
    ];
    if (el.script.checked) lines.push(`<script src="${embedJs}" async></script>`);
    el.snippet.textContent = lines.join('\n');
    el.preview.style.minHeight = hgt + 'px';
  };
  const preview = () => { if (kind === 'iframe' && el.drawer.open) el.preview.src = query(localBase); };
  $$('[data-embed-kind]', box).forEach((b) => b.addEventListener('click', () => {
    kind = b.dataset.embedKind;
    $$('[data-embed-kind]', box).forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
    $$('[data-embed-options]', box).forEach((o) => { o.hidden = kind === 'link'; });
    build();
  }));
  [el.theme, el.height, el.script].forEach((i) => i.addEventListener('input', () => { build(); preview(); }));
  el.accent.addEventListener('input', () => { accentTouched = true; build(); preview(); });
  el.drawer.addEventListener('toggle', preview);
  el.copy.addEventListener('click', async () => {
    const ok = await copyText(el.snippet.textContent);
    el.copy.textContent = ok ? 'Copied' : 'Copy failed'; setTimeout(() => { el.copy.textContent = 'Copy snippet'; }, 1600);
  });
  build();
  if (location.hash === '#embed') el.drawer.open = true;
}

// ---------- inside an iframe: tell the parent our height ({type:'bmh-tools:resize', height}) ----------
function initEmbedChild() {
  if (!root.dataset.embed || window.parent === window) return;
  let last = 0;
  const post = (force) => {
    const height = Math.ceil(document.documentElement.getBoundingClientRect().height);
    if (height === last && force !== true) return; last = height;
    window.parent.postMessage({ type: 'bmh-tools:resize', height }, '*');
  };
  new ResizeObserver(() => post()).observe(document.body);
  post();
  // The parent's embed.js may load after us (async): repeat the current height a few times.
  [400, 1200, 3000].forEach((ms) => setTimeout(() => post(true), ms));
}

initMode();
initTheme();
initCommandBar();
initTabs();
initPalette();
initEmbedDrawer();
initEmbedChild();
initGlossary();
