/* Hub page: filter tools by text + category chip (AND), fill "Recently used". Text is set via textContent only. */
import { getRecent } from './ui/recent.js';

const cfg = (() => { try { return JSON.parse(document.getElementById('toolbox-config').textContent); } catch { return { prefix: '/tools', tools: [] }; } })();
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const input = $('#hub-filter');
const chips = $$('.chip-cat');
const cards = $$('.tool-card[data-search]');
const count = $('#hub-count');
const empty = $('#hub-empty');
let cat = 'all';

function apply() {
  const q = (input ? input.value : '').trim().toLowerCase();
  const words = q.split(/\s+/).filter(Boolean);
  let n = 0;
  for (const c of cards) {
    const ok = (cat === 'all' || c.dataset.cat === cat) && words.every((w) => c.dataset.search.includes(w));
    c.hidden = !ok;
    if (ok) n++;
  }
  for (const sub of $$('[data-sub]')) sub.hidden = !$$('.tool-card', sub).some((c) => !c.hidden);
  for (const sec of $$('.hub-sec')) {
    const vis = $$('.tool-card', sec).filter((c) => !c.hidden).length;
    sec.hidden = vis === 0;
    const sc = $('[data-sec-count]', sec);
    if (sc) sc.textContent = String(vis);
  }
  if (count) count.textContent = `${n} ${n === 1 ? 'tool' : 'tools'}`;
  if (empty) empty.hidden = n !== 0;
}

if (input) input.addEventListener('input', apply);
for (const b of chips) {
  b.addEventListener('click', () => {
    cat = b.dataset.chip;
    for (const o of chips) o.setAttribute('aria-pressed', o === b ? 'true' : 'false');
    apply();
  });
}

const omniLink = $('#hub-empty-omni');
if (omniLink) {
  omniLink.addEventListener('click', (e) => {
    e.preventDefault();
    const o = $('#cmd-input');
    if (o) o.focus();
  });
}

(function recents() {
  const box = $('#hub-recent');
  const list = $('#hub-recent-list');
  if (!box || !list) return;
  let slugs = [];
  try { slugs = getRecent() || []; } catch { slugs = []; }
  const byslug = new Map((cfg.tools || []).map((t) => [t.slug, t]));
  let shown = 0;
  for (const s of slugs) {
    const t = byslug.get(s);
    if (!t || shown >= 4) continue;
    const a = document.createElement('a');
    a.className = 'chip-link';
    a.href = `${cfg.prefix}/${t.slug}`;
    a.textContent = t.name;
    list.appendChild(a);
    shown++;
  }
  if (shown) box.hidden = false;
})();

apply();
