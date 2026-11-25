// Accessible tabs for result pages (WAI-ARIA tabs pattern, manual activation).
//  - role=tablist/tab/tabpanel, aria-selected + aria-controls, roving tabindex, Left/Right/Home/End move focus,
//    Enter/Space (a normal button click) opens the tab. Manual activation on purpose: a heavy lazy tab must not run
//    just because someone arrowed past it.
//  - The URL hash (#overview, #dns ...) follows the tab; Back/Forward and plain <a href="#dns"> links work.
//  - Every panel is built lazily on first open: skeleton while loading, a Retry button when the loader throws.
//  - Each tab carries a status dot and a short text badge (the word is always there, never colour alone).
import { h, srOnly } from './dom.js';
import { skeletonCards } from './stream.js';

const WORD = { ok: 'good', warn: 'needs attention', bad: 'problem', info: 'information', mute: 'not checked' };

/**
 * tabs({ items, label, hash, initial })
 *  items: [{ id, label, badge: {status, text}, load: ({panel, setBadge}) => Node | Node[] | Promise<...> }]
 * returns { el, select(id, {focus}), setBadge(id, {status, text}), current(), isLoaded(id), reload(id), destroy() }
 */
export function tabs({ items, label = 'Result sections', hash = true, initial } = {}) {
  const uid = Math.random().toString(36).slice(2, 8);
  const ids = items.map((i) => i.id);
  const status = Object.fromEntries(ids.map((i) => [i, 'idle']));
  const rail = h('div', { class: 'xtabs', role: 'tablist', 'aria-label': label });
  const el = h('div', { class: 'xtabs-root' }, rail);
  const btn = {}, panel = {}, dot = {}, txt = {}, sr = {};
  let cur = null;

  items.forEach((it) => {
    dot[it.id] = h('span', { class: 'xdot', 'aria-hidden': 'true' });
    txt[it.id] = h('span', { class: 'xbadge' });
    sr[it.id] = srOnly('');
    btn[it.id] = h('button', { type: 'button', role: 'tab', class: 'xtab', id: `${uid}-t-${it.id}`, 'aria-controls': `${uid}-p-${it.id}`, 'aria-selected': 'false', tabindex: '-1', 'data-tab': it.id },
      dot[it.id], h('span', null, it.label), txt[it.id], sr[it.id]);
    panel[it.id] = h('div', { role: 'tabpanel', class: 'xpanel space-y-4', id: `${uid}-p-${it.id}`, 'aria-labelledby': `${uid}-t-${it.id}`, tabindex: '0', hidden: true });
    rail.append(btn[it.id]);
    el.append(panel[it.id]);
    btn[it.id].addEventListener('click', () => select(it.id, { focus: false }));
  });

  function setBadge(id, b) {
    if (!btn[id]) return;
    const s = b && b.status ? b.status : 'mute';
    dot[id].setAttribute('class', `xdot xdot-${s}`);
    txt[id].textContent = (b && b.text) || '';
    sr[id].textContent = b && b.text ? `, ${WORD[s] || ''}` : '';
  }
  items.forEach((it) => setBadge(it.id, it.badge));

  function scrollRailTo(id) {
    const b = btn[id], r = rail;
    if (!b || r.scrollWidth <= r.clientWidth) return;
    r.scrollLeft = Math.max(0, b.offsetLeft - (r.clientWidth - b.offsetWidth) / 2);
  }

  async function ensure(id) {
    if (status[id] === 'loading' || status[id] === 'done') return;
    const it = items.find((x) => x.id === id), p = panel[id];
    status[id] = 'loading';
    p.setAttribute('aria-busy', 'true');
    p.replaceChildren(skeletonCards(1));
    try {
      const out = await it.load({ panel: p, setBadge: (b) => setBadge(id, b) });
      p.replaceChildren(...[].concat(out).filter(Boolean));
      status[id] = 'done';
    } catch (e) {
      status[id] = 'idle';
      const retry = h('button', { type: 'button', class: 'btn btn-ghost btn-sm mt-2' }, 'Try again');
      retry.addEventListener('click', () => ensure(id));
      p.replaceChildren(h('div', { class: 'card p-4', role: 'alert' },
        h('div', { class: 'font-semibold st-bad' }, `${it.label} could not be loaded`),
        h('p', { class: 'text-sm mt-0.5' }, (e && e.message) || 'Something went wrong. Please try again.'), retry));
    } finally { p.setAttribute('aria-busy', 'false'); }
  }

  function writeHash(id) {
    if (!hash) return;
    try { if (location.hash !== '#' + id) location.hash = id; } catch { /* sandboxed frame: tabs still work, just no deep link */ }
  }

  function select(id, { focus = false, fromHash = false } = {}) {
    if (!btn[id]) id = ids[0];
    cur = id;
    ids.forEach((i) => {
      const on = i === id;
      btn[i].setAttribute('aria-selected', String(on));
      btn[i].tabIndex = on ? 0 : -1;
      panel[i].hidden = !on;
    });
    scrollRailTo(id);
    if (focus) btn[id].focus();
    if (!fromHash && !(id === ids[0] && !location.hash)) writeHash(id);
    return ensure(id);
  }

  rail.addEventListener('keydown', (e) => {
    const i = ids.indexOf(document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.tab : '');
    if (i < 0) return;
    const to = { ArrowRight: (i + 1) % ids.length, ArrowLeft: (i - 1 + ids.length) % ids.length, Home: 0, End: ids.length - 1 }[e.key];
    if (to == null) return;
    e.preventDefault();
    btn[ids[to]].focus();
    scrollRailTo(ids[to]);
  });

  const fromLocation = () => { const k = (location.hash || '').replace(/^#/, '').toLowerCase(); return ids.includes(k) ? k : null; };
  const onHash = () => {
    if (!el.isConnected) { window.removeEventListener('hashchange', onHash); return; }
    const k = fromLocation();
    if (k && k !== cur) { select(k, { fromHash: true }); }
    else if (!k && cur !== ids[0]) select(ids[0], { fromHash: true });
  };
  if (hash) window.addEventListener('hashchange', onHash);

  // Opening happens after the caller inserted `el` into the page, so the first panel's loader sees a live DOM.
  queueMicrotask(() => select((hash && fromLocation()) || initial || ids[0], { fromHash: true }));

  return {
    el, select, setBadge,
    current: () => cur,
    isLoaded: (id) => status[id] === 'done',
    reload: (id) => { status[id] = 'idle'; return cur === id ? ensure(id) : null; },
    destroy: () => window.removeEventListener('hashchange', onHash),
  };
}
